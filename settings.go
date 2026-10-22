//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// profileProtectedFields are columns that cannot be updated via the profile API.
var profileProtectedFields = map[string]bool{
	"id": true, "password_hash": true, "created_at": true, "updated_at": true,
	"role": true, "verified": true, "deactivated_at": true,
	"password_change_required": true,
}

// defaultProfileFields are the _benmore_users columns a user may edit on
// their own row with no app.yaml declaration: display identity only.
// Identifiers (email, username, phone) have their own proof-gated paths.
var defaultProfileFields = []string{
	"first_name", "last_name", "name", "display_name",
	"avatar", "avatar_url", "bio", "timezone", "locale",
}

// profileEditableFieldList is the ordered allowlist for PATCH
// /api/_auth/profile: the framework defaults, then auth.signup_fields (the
// user already chose those at signup), then auth.profile_fields. Protected
// and sensitive columns are removed even when an app lists them, and so is
// every column a public signup may not set (signupFieldRefusal: account
// state such as email_grandfathered or last_login_at, and the groups: tenant
// key, role and active columns): signup drops them, so the next request must
// not be able to write them either.
func profileEditableFieldList(app *App) []string {
	fields := append([]string(nil), defaultProfileFields...)
	var group *GroupConfig
	if app != nil && app.Design != nil {
		for _, key := range []string{"signup_fields", "profile_fields"} {
			fields = append(fields, splitCommaList(app.Design.Auth[key])...)
		}
	}
	if app != nil {
		group = app.Group
	}
	seen := map[string]bool{}
	out := fields[:0]
	for _, f := range fields {
		switch f {
		case "email", "username", "phone", "password", "current_password":
			continue
		}
		if seen[f] || profileProtectedFields[f] || isSensitiveUserColumn(f) || signupFieldRefusal(f, group) != "" {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}

// profileFieldsRefused returns the existing _benmore_users columns in updates
// that the caller may not set: not on the allowlist and not merely sent back
// with their stored value. Email and current_password have their own gate;
// protected, sensitive and unknown columns keep being dropped as before.
func profileFieldsRefused(app *App, userID int64, updates map[string]any, validCols map[string]bool) []string {
	editable := map[string]bool{}
	for _, f := range profileEditableFieldList(app) {
		editable[f] = true
	}
	var stored map[string]any
	var refused []string
	for field, val := range updates {
		if field == "email" || field == "current_password" || editable[field] ||
			profileProtectedFields[field] || isSensitiveUserColumn(field) || !validCols[field] {
			continue
		}
		if stored == nil {
			if stored = LoadUserFields(app.DB, userID); stored == nil {
				stored = map[string]any{}
			}
		}
		if current, ok := stored[field]; ok && profileValueUnchanged(current, val) {
			continue
		}
		refused = append(refused, field)
	}
	sort.Strings(refused)
	return refused
}

// profileValueUnchanged reports whether a JSON value equals the stored column
// value (form-style clients send numbers and NULLs back as strings).
func profileValueUnchanged(stored, sent any) bool {
	text := func(v any) string {
		switch t := v.(type) {
		case nil:
			return ""
		case bool:
			if t {
				return "1"
			}
			return "0"
		case float64:
			return strconv.FormatFloat(t, 'f', -1, 64)
		case int64:
			return strconv.FormatInt(t, 10)
		case []byte:
			return string(t)
		case string:
			return t
		}
		return fmt.Sprint(v)
	}
	switch sent.(type) {
	case map[string]any, []any:
		return false
	}
	return text(stored) == text(sent)
}

// RegisterSettingsRoutes adds the settings/account management page and Profile API.
func RegisterSettingsRoutes(mux appRouteRegistrar, app *App) {
	EnsureAuditLogTable(app.DB) // password changes audit in their own transaction
	ensureEmailChangesTable(app.DB)
	registerSettingsRoutes(mux, app)
}

func accountSettingsDisabled(w http.ResponseWriter, r *http.Request, app *App) bool {
	if app.FeatureEnabled("account_settings") {
		return false
	}
	http.NotFound(w, r)
	return true
}

func accountSettingsMFASetupDisabled(w http.ResponseWriter, r *http.Request, app *App) bool {
	if app.FeatureEnabled("account_settings") {
		return false
	}
	if _, _, fromSetup, err := mfaCallerIdentity(app, r); err == nil && fromSetup {
		return false // only login's setup-token identity may enroll while self-service is off
	}
	return accountSettingsDisabled(w, r, app)
}

func registerSettingsRoutes(mux appRouteRegistrar, app *App) {
	registerEmailChangeConfirmRoutes(mux, app)

	// Profile API: GET /api/_auth/profile - returns all non-sensitive user fields
	mux.HandleFunc("GET /api/_auth/profile", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		userMap := LoadUserFields(app.DB, session.UserID)
		if userMap == nil {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "user not found"})
			return
		}
		// Multi-role payload (v2.7.54+). The legacy `role` field stays
		// for back-compat - every client that read it before keeps
		// working. `roles` is the full set the auth layer evaluates,
		// `permissions` is the unioned scope catalog (one entry per
		// "resource:action" token), `primary_role` mirrors the column
		// on _benmore_users.
		userMap["roles"] = session.Roles
		userMap["primary_role"] = session.Role
		if session.Permissions != nil {
			userMap["permissions"] = session.Permissions
		} else {
			userMap["permissions"] = []string{}
		}
		httpJSON(w, http.StatusOK, userMap)
	})

	// Public user-lookup APIs (v2.7.11). Every multi-user app - chat,
	// comments, collaborative anything - needs to display "user X said
	// foo" / "this is from user Y" / "show whose turn it is." Without
	// these endpoints every agent invents the same custom flow (e.g.
	// `get-user.yaml`) per app, the docs warn about doing it wrong, and
	// nobody filters sensitive columns correctly. Centralize the safe
	// shape:
	//
	//   GET /api/_auth/users           → list of public-safe user rows
	//   GET /api/_auth/users/{id}      → one public-safe user row
	//
	// "Public-safe" means: every column EXCEPT those flagged by
	// isSensitiveUserColumn (password_hash, totp_secret, *_token, etc).
	// `email` and `phone` are intentionally INCLUDED - they're already
	// returned for the authed user via /api/_auth/profile, and chat /
	// mention UIs commonly need them (for "@" autocomplete, gravatar
	// hashes, etc). Apps that consider those private should either
	// rename the columns to start with `private_` (caught by the
	// sensitive-column heuristic) or layer their own auth in front.
	//
	// Both endpoints require an authenticated session. Anonymous
	// visitors can't enumerate user lists - set features.ws_anonymous
	// or features.docs to handle anonymous read needs explicitly.
	mux.HandleFunc("GET /api/_auth/users", func(w http.ResponseWriter, r *http.Request) {
		if accountSettingsDisabled(w, r, app) {
			return
		}
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		mode := userDirectoryMode(app)
		if mode == "off" {
			http.NotFound(w, r)
			return
		}
		// Soft pagination - large user tables shouldn't dump everything.
		limit := 100
		if q := r.URL.Query().Get("limit"); q != "" {
			if n, err := strconv.Atoi(q); err == nil && n > 0 && n <= 500 {
				limit = n
			}
		}
		offset := 0
		if q := r.URL.Query().Get("offset"); q != "" {
			if n, err := strconv.Atoi(q); err == nil && n >= 0 {
				offset = n
			}
		}
		// Visibility gate - pre-filter, then build the SQL.
		query, args, ok := buildUserListQuery(app, session, mode, limit, offset)
		if !ok {
			// Mode says non-admin can't list at all. Returning an empty
			// list (not 403) so clients can branch on the response shape
			// without branching on auth state.
			httpJSON(w, http.StatusOK, map[string]any{"users": []any{}, "limit": limit, "offset": offset})
			return
		}
		rows, err := app.DB.Query(query, args...)
		if err != nil {
			serverErrorJSON(w, r, app, "_auth users", err, "query failed")
			return
		}
		defer rows.Close()
		out := make([]map[string]any, 0, limit)
		for rows.Next() {
			var id int64
			if err := rows.Scan(&id); err != nil {
				continue
			}
			if u := loadUserForJSON(app, id); u != nil {
				out = append(out, directoryUserRow(session, id, u))
			}
		}
		httpJSON(w, http.StatusOK, map[string]any{"users": out, "limit": limit, "offset": offset, "mode": mode})
	})

	mux.HandleFunc("GET /api/_auth/users/{id}", func(w http.ResponseWriter, r *http.Request) {
		if accountSettingsDisabled(w, r, app) {
			return
		}
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		mode := userDirectoryMode(app)
		if mode == "off" {
			http.NotFound(w, r)
			return
		}
		idStr := r.PathValue("id")
		id, err := strconv.ParseInt(idStr, 10, 64)
		if err != nil || id <= 0 {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid user id"})
			return
		}
		// Visibility gate. Cross-tenant / non-permitted lookups return 404
		// (not 403), matching the framework's own posture - don't leak
		// existence of rows the caller can't see. Self-lookup always
		// permitted regardless of mode (a user can always see themselves).
		if !canSeeUser(app, session, mode, id) {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "user not found"})
			return
		}
		// Same deactivated-account hiding as the list endpoint. Returning
		// 404 (not "deactivated") avoids leaking account state to a
		// random lookup.
		var deactivatedAt sql.NullString
		err = app.DB.QueryRow("SELECT deactivated_at FROM _benmore_users WHERE id = ?", id).Scan(&deactivatedAt)
		if err != nil || (deactivatedAt.Valid && deactivatedAt.String != "") {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "user not found"})
			return
		}
		u := loadUserForJSON(app, id)
		if u == nil {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "user not found"})
			return
		}
		httpJSON(w, http.StatusOK, directoryUserRow(session, id, u))
	})

	// Profile API: PATCH /api/_auth/profile - update non-sensitive user fields
	mux.HandleFunc("PATCH /api/_auth/profile", func(w http.ResponseWriter, r *http.Request) {
		if accountSettingsDisabled(w, r, app) {
			return
		}
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !requireAccountManagement(w, session) {
			return
		}
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}

		var updates map[string]any
		if err := json.NewDecoder(r.Body).Decode(&updates); err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
			return
		}

		// Validate field names against actual schema (prevents SQL injection via column names)
		validCols := make(map[string]bool)
		colRows, _ := app.DB.Query("SELECT name FROM pragma_table_info('_benmore_users')")
		if colRows != nil {
			for colRows.Next() {
				var name string
				colRows.Scan(&name)
				validCols[name] = true
			}
			colRows.Close()
		}

		// Only declared profile fields are self-service. Other user
		// columns (plan, tier, credits, tenant bindings) are authorization
		// inputs - `<page require="plan:pro">` gates on them - so a user
		// must not be able to set their own. Refuse before any side effect
		// (including the email-change mail below). A column sent back
		// unchanged is tolerated so GET→edit→PATCH round-trips keep working.
		if refused := profileFieldsRefused(app, session.UserID, updates, validCols); len(refused) > 0 {
			httpJSON(w, http.StatusForbidden, map[string]any{
				"error":  "profile fields not editable: " + strings.Join(refused, ", "),
				"fields": refused,
				"hint":   "PATCH /api/_auth/profile writes only " + strings.Join(profileEditableFieldList(app), ", ") + ". List other self-service columns in app.yaml auth.profile_fields (comma-separated); set privileged columns such as plan from a server-side flow or admin tool.",
			})
			return
		}

		// Email change requires the current password - same posture as
		// the form-based /settings/profile endpoint. Without this, a
		// momentary cookie-theft / XSS becomes account-takeover via
		// email change → password reset to the attacker's address.
		newEmailRaw, changingEmail := updates["email"]
		newEmail, _ := newEmailRaw.(string)
		if changingEmail && newEmail != session.Email {
			// Before the password is looked at: a support session must not
			// be able to test guesses of it here either.
			if delegatedIdentitySession(app, session) {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": delegatedIdentityRefusal})
				return
			}
			currentPassword, _ := updates["current_password"].(string)
			if currentPassword == "" {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": "current_password required to change email"})
				return
			}
			if ok, locked := currentPasswordMatches(app, session.UserID, currentPassword); !ok {
				if locked {
					httpJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many attempts, try again in 15 minutes"})
					return
				}
				httpJSON(w, http.StatusForbidden, map[string]any{"error": "incorrect password"})
				return
			}
		}
		delete(updates, "current_password") // not a column
		// The email itself is never written here: a change must be proven
		// from the new inbox first (settings_email_change.go).
		pendingEmail := ""
		if changingEmail && newEmail != session.Email {
			if err := requestEmailChange(app, r, session.UserID, strings.TrimSpace(newEmail)); err != nil {
				status := http.StatusBadGateway
				if errors.Is(err, errEmailInUse) {
					status = http.StatusConflict
				} else if errors.Is(err, errEmailChangeUnsupported) {
					status = http.StatusForbidden
				} else if errors.Is(err, errEmailChangeThrottled) {
					status = http.StatusTooManyRequests
				}
				var failure *emailChangeFailure
				if errors.As(err, &failure) {
					serverErrorJSONBody(w, r, app, status, "email change", failure.cause, map[string]any{"error": failure.msg})
					return
				}
				httpJSON(w, status, map[string]any{"error": err.Error()})
				return
			}
			pendingEmail = strings.TrimSpace(newEmail)
		}
		delete(updates, "email")

		// Filter out protected fields, sensitive columns by name, AND
		// validate the field exists on the table. Track dropped fields
		// so the response surfaces them - pre-2.7.31 we silently
		// dropped any unknown column (an earlier app build: PATCH avatar_url
		// returned 200 OK with no indication the field had been
		// dropped because `_benmore_users` didn't have an avatar_url
		// column). Agents writing UI now see exactly which fields the
		// schema doesn't accept and can add them to schema.prisma.
		var setClauses []string
		var values []any
		var droppedProtected []string
		var droppedSensitive []string
		var droppedUnknown []string
		for field, val := range updates {
			if profileProtectedFields[field] {
				droppedProtected = append(droppedProtected, field)
				continue
			}
			if isSensitiveUserColumn(field) {
				droppedSensitive = append(droppedSensitive, field)
				continue
			}
			if !validCols[field] {
				droppedUnknown = append(droppedUnknown, field)
				continue
			}
			setClauses = append(setClauses, field+" = ?")
			values = append(values, val)
		}

		if len(setClauses) == 0 && pendingEmail != "" {
			httpJSON(w, http.StatusAccepted, map[string]any{
				"status":        "pending_verification",
				"pending_email": pendingEmail,
				"message":       "We sent a confirmation link to the new address. The email changes when you open it.",
			})
			return
		}
		if len(setClauses) == 0 {
			resp := map[string]any{
				"error": "no valid fields to update",
			}
			if len(droppedProtected) > 0 {
				resp["dropped_protected"] = droppedProtected
			}
			if len(droppedSensitive) > 0 {
				resp["dropped_sensitive"] = droppedSensitive
			}
			if len(droppedUnknown) > 0 {
				resp["dropped_unknown"] = droppedUnknown
				resp["hint"] = "fields not present on _benmore_users - add them to your schema.prisma model User block and push. The framework refuses to silently auto-extend the user table to keep the schema authoritative."
			}
			httpJSON(w, http.StatusBadRequest, resp)
			return
		}

		values = append(values, session.UserID)
		sqlStr := fmt.Sprintf("UPDATE _benmore_users SET %s WHERE id = ?", strings.Join(setClauses, ", "))
		if _, err := app.DB.Exec(sqlStr, values...); err != nil {
			serverErrorJSON(w, r, app, "profile update", err, "update failed")
			return
		}

		// Return updated profile. Surface any dropped fields so the
		// caller sees what was actually persisted vs what the request
		// asked for - closes the silent-drop footgun for unknown
		// columns while keeping the graceful-degradation behavior for
		// existing callers that DID send a usable subset.
		userMap := LoadUserFields(app.DB, session.UserID)
		if pendingEmail != "" {
			if userMap == nil {
				userMap = map[string]any{}
			}
			userMap["_email_change"] = map[string]any{"status": "pending_verification", "pending_email": pendingEmail}
		}
		if len(droppedProtected)+len(droppedSensitive)+len(droppedUnknown) > 0 {
			meta := map[string]any{}
			if len(droppedProtected) > 0 {
				meta["dropped_protected"] = droppedProtected
			}
			if len(droppedSensitive) > 0 {
				meta["dropped_sensitive"] = droppedSensitive
			}
			if len(droppedUnknown) > 0 {
				meta["dropped_unknown"] = droppedUnknown
				meta["hint"] = "some fields aren't present on _benmore_users - add them to your schema.prisma model User block and push. The framework keeps the schema authoritative on purpose."
			}
			if userMap == nil {
				userMap = map[string]any{}
			}
			userMap["_dropped"] = meta
		}
		httpJSON(w, http.StatusOK, userMap)
	})

	// Change password
	mux.HandleFunc("POST /settings/password", func(w http.ResponseWriter, r *http.Request) {
		if accountSettingsDisabled(w, r, app) {
			return
		}
		session := getSession(app, r)
		if session == nil {
			http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
			return
		}
		if !accountManagementSession(session) || delegatedIdentitySession(app, session) {
			httpError(w, "Sign in directly to change your password", http.StatusForbidden)
			return
		}
		r.ParseForm()
		if !validateCSRF(r) {
			httpError(w, "Invalid CSRF", http.StatusForbidden)
			return
		}

		current := r.FormValue("current_password")
		newPass := r.FormValue("new_password")
		confirm := r.FormValue("confirm_password")

		if current == "" || newPass == "" {
			settingsRedirect(w, r, app, "All password fields are required")
			return
		}
		if newPass != confirm {
			settingsRedirect(w, r, app, "New passwords don't match")
			return
		}
		if msg := validatePasswordComplexity(newPass); msg != "" {
			settingsRedirect(w, r, app, msg)
			return
		}

		// Verify current password
		proofHash, locked := currentPasswordProof(app, session.UserID, current)
		if proofHash == "" {
			if locked {
				settingsRedirect(w, r, app, "Too many attempts. Try again in 15 minutes.")
				return
			}
			settingsRedirect(w, r, app, "Current password is incorrect")
			return
		}

		// Set the new password and revoke everything the old one could have
		// produced - other sessions, API tokens (bmr_/bma_), OAuth codes,
		// reset links, a pending email change - in one transaction, the same
		// set the reset path revokes. Only this session survives. A partial
		// failure rolls back, so the old password never outlives a
		// half-applied change.
		newHash, err := generateBcryptHash([]byte(newPass))
		if err != nil {
			settingsRedirect(w, r, app, "Unable to change password")
			return
		}
		// revoke_passkeys=1 also removes every passkey (opt-in, like keeping
		// the TOTP factor on an ordinary change).
		revokePasskeys := formFlagTrue(r.FormValue("revoke_passkeys"))
		userEmail, err := changeSignedInPasswordWith(app, session, proofHash, string(newHash), revokePasskeys)
		if err != nil {
			log.Printf("settings: password change for user %d: %v", session.UserID, err)
			settingsRedirect(w, r, app, "Unable to change password")
			return
		}
		invalidateRequestSession(r)

		// On a hosted platform, mirror the new hash so a password change in
		// /settings stays in sync with the CLI login credential, and revoke
		// the platform tokens the old password could have minted. No-op in a
		// self-hosted build.
		if userEmail != "" {
			platformPasswordChanged(app, userEmail, string(newHash), false)
		}

		settingsRedirect(w, r, app, "success:Password updated successfully")
	})

	// Update profile
	mux.HandleFunc("POST /settings/profile", func(w http.ResponseWriter, r *http.Request) {
		if accountSettingsDisabled(w, r, app) {
			return
		}
		session := getSession(app, r)
		if session == nil {
			http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
			return
		}
		if !accountManagementSession(session) || delegatedIdentitySession(app, session) {
			httpError(w, "Sign in directly to change your email", http.StatusForbidden)
			return
		}
		r.ParseForm()
		if !validateCSRF(r) {
			httpError(w, "Invalid CSRF", http.StatusForbidden)
			return
		}

		newEmail := strings.TrimSpace(r.FormValue("email"))
		if newEmail == "" {
			settingsRedirect(w, r, app, "Email is required")
			return
		}

		// Email change is a high-value action - require the current
		// password. Without this, a momentary session hijack (XSS,
		// stolen-cookie) becomes account takeover: attacker rewrites
		// email to their own, password-reset to the new address.
		currentPassword := r.FormValue("current_password")
		if currentPassword == "" {
			settingsRedirect(w, r, app, "Enter your current password to change email")
			return
		}
		if ok, locked := currentPasswordMatches(app, session.UserID, currentPassword); !ok {
			if locked {
				settingsRedirect(w, r, app, "Too many attempts. Try again in 15 minutes.")
				return
			}
			settingsRedirect(w, r, app, "Incorrect password")
			return
		}

		if strings.EqualFold(newEmail, session.Email) {
			settingsRedirect(w, r, app, "That is already your email")
			return
		}
		// Never applied here: the new inbox must confirm first.
		if err := requestEmailChange(app, r, session.UserID, newEmail); err != nil {
			var failure *emailChangeFailure
			if errors.As(err, &failure) {
				noteServerError(r, "email change", failure.cause)
			}
			settingsRedirect(w, r, app, err.Error())
			return
		}
		settingsRedirect(w, r, app, "success:We sent a confirmation link to "+newEmail+". Your email changes when you open it.")
	})

	// Delete account
	mux.HandleFunc("POST /settings/delete-account", func(w http.ResponseWriter, r *http.Request) {
		if accountSettingsDisabled(w, r, app) {
			return
		}
		session := getSession(app, r)
		if session == nil {
			http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
			return
		}
		r.ParseForm()
		if !validateCSRF(r) {
			httpError(w, "Invalid CSRF", http.StatusForbidden)
			return
		}
		// Irreversible: only the user's own unscoped login, never an API
		// token, scoped session, act-as or support session.
		if !directLoginSession(app, session) {
			httpError(w, "Sign in directly to delete your account", http.StatusForbidden)
			return
		}

		confirm := r.FormValue("confirm")
		if confirm != "DELETE" {
			settingsRedirect(w, r, app, "Type DELETE to confirm account deletion")
			return
		}

		// Every framework credential and identifier goes, atomically; the
		// row is left as a non-login tombstone (deleteOwnAccount).
		if err := deleteOwnAccount(app, session); err != nil {
			log.Printf("settings: account deletion for user %d: %v", session.UserID, err)
			settingsRedirect(w, r, app, "Unable to delete the account")
			return
		}
		invalidateRequestSession(r)

		clearSessionCookies(w, app.DevMode)
		http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
	})
}

// directoryUserRow is a user row as the directory shows it to session.
// password_change_required marks an account that still holds a temporary
// password - often a shared default from provisioning - so listing it told
// any caller who passed the directory mode which accounts to try that
// password on. Only an admin (who manages accounts) and the account itself
// see it.
func directoryUserRow(session *Session, userID int64, row map[string]any) map[string]any {
	if session == nil || !(session.IsAdmin() || session.UserID == userID) {
		delete(row, "password_change_required")
	}
	return row
}

// userDirectoryMode returns the effective access mode for the
// /api/_auth/users endpoints. v2.7.12+: routes through the unified
// `access:` config in app.yaml (treats `_benmore_users` as just
// another table). Falls back to "admin" - PRIVATE by default; only
// admins can list / look up other users, self-lookup always works.
//
// Values: anon · everyone · self · group · admin · role:<name>[,<name>] · off
// Anything unrecognized falls back to "admin" (fail-closed).
func userDirectoryMode(app *App) string {
	if app == nil {
		return "admin"
	}
	// The user-lookup endpoint is keyed under the framework's own
	// `_benmore_users` table in the access: config. Developers write:
	//   access:
	//     _benmore_users:
	//       read: group        # multi-tenant directory
	//
	// Pass hasUID=false so the implicit default falls through to
	// `admin` (private-by-default for user directories) rather than
	// `self`. _benmore_users has an `id` column but the row IS the
	// user - there's no "user_id" foreign key to scope by.
	mode := app.Access.ModeFor("_benmore_users", OpRead, false, false)
	switch mode {
	case "anon", "everyone", "self", "group", "admin", "off":
		return mode
	}
	if strings.HasPrefix(mode, "role:") {
		return mode
	}
	return "admin"
}

// buildUserListQuery composes the SQL + args for the user list under
// the given visibility mode. The boolean return is `permitted` - false
// means the requester isn't allowed to list at all (handler returns an
// empty list, not 403, so client code can branch on shape).
//
// Modes:
//
//	"off"       - never reached (handler short-circuits)
//	"admin"     - admin sees everyone; non-admin sees only themselves
//	"self"      - everyone sees only themselves
//	"group"     - JOIN to the membership table on the requester's group
//	              column; admin bypasses and sees everyone
//	"everyone"  - everyone sees everyone (chat-style apps opt in)
//	"role:a,b"  - a caller holding a listed role GLOBALLY (or an admin) sees
//	              everyone; anyone else sees only themselves
func buildUserListQuery(app *App, session *Session, mode string, limit, offset int) (string, []any, bool) {
	deactivatedClause := "(deactivated_at IS NULL OR deactivated_at = '')"
	isAdmin := session != nil && session.IsAdmin()

	// role:<roles> is `admin` with a wider set of roles. The mode was accepted
	// (userDirectoryMode) but had no branch here, so the list was empty for
	// everyone, admins included.
	if strings.HasPrefix(mode, "role:") {
		if userDirectoryRoleHolder(app, session, mode) {
			mode = "everyone"
		} else {
			mode = "self"
		}
	}

	switch mode {
	case "self":
		// Always allowed, but only returns the caller.
		return "SELECT id FROM _benmore_users WHERE id = ? AND " + deactivatedClause + " ORDER BY id LIMIT ? OFFSET ?",
			[]any{session.UserID, limit, offset}, true

	case "admin":
		if isAdmin {
			return "SELECT id FROM _benmore_users WHERE " + deactivatedClause + " ORDER BY id LIMIT ? OFFSET ?",
				[]any{limit, offset}, true
		}
		// Non-admin: collapse to self-only, same shape as `self` mode.
		return "SELECT id FROM _benmore_users WHERE id = ? AND " + deactivatedClause + " ORDER BY id LIMIT ? OFFSET ?",
			[]any{session.UserID, limit, offset}, true

	case "group":
		if isAdmin {
			return "SELECT id FROM _benmore_users WHERE " + deactivatedClause + " ORDER BY id LIMIT ? OFFSET ?",
				[]any{limit, offset}, true
		}
		if app.Group == nil || app.Group.Table == "" || app.Group.Key == "" || app.Group.UserField == "" || !session.HasGroup() {
			// Mode says "group" but app isn't actually multi-tenant. Fail
			// closed - return self only rather than leaking everyone.
			return "SELECT id FROM _benmore_users WHERE id = ? AND " + deactivatedClause + " ORDER BY id LIMIT ? OFFSET ?",
				[]any{session.UserID, limit, offset}, true
		}
		// Members of the requester's group: the membership rows of that group
		// matched to accounts (userDirectoryMemberMatch). Names come from
		// app.yaml and are written as quoted identifiers.
		q := fmt.Sprintf(
			"SELECT u.id FROM _benmore_users u WHERE EXISTS (SELECT 1 FROM %s m WHERE m.%s = ?%s AND %s) AND (u.deactivated_at IS NULL OR u.deactivated_at = '') ORDER BY u.id LIMIT ? OFFSET ?",
			quoteIdent(app.Group.Table), quoteIdent(app.Group.Key),
			membershipLiveConds(app.Group, app.Group.Table, "m", dbColumnChecker(app.DB, app.Group.Table)),
			userDirectoryMemberMatch(app.Group, "u", "m"),
		)
		return q, []any{session.GroupID, limit, offset}, true

	case "everyone":
		return "SELECT id FROM _benmore_users WHERE " + deactivatedClause + " ORDER BY id LIMIT ? OFFSET ?",
			[]any{limit, offset}, true
	}
	// Unknown mode - fail closed.
	return "", nil, false
}

// userDirectoryRoleHolder reports whether the caller passes a `role:<roles>`
// directory mode: an admin, or a holder of a listed role from a global source
// (the users.role column or a group_id IS NULL grant). _benmore_users has no
// tenant column, so a role held only inside one tenant (the membership role
// or a group-scoped grant) does not open every tenant's users: the rule
// tableModeAllowed applies to any un-grouped table.
func userDirectoryRoleHolder(app *App, session *Session, mode string) bool {
	if session == nil {
		return false
	}
	return session.IsAdmin() || sessionHoldsGlobalRole(app, session, splitCommaList(strings.TrimPrefix(mode, "role:")))
}

// userDirectoryMemberMatch is the SQL condition "users row <u> is the member
// membership row <m> names". An email column names the member's address,
// under whatever column name (it used to be compared with a users column of
// the SAME name, which exists only when the field is literally `email`); any
// other column names the user id. An address counts only for an account that
// proved it, here as everywhere a membership is matched by address.
func userDirectoryMemberMatch(group *GroupConfig, u, m string) string {
	byAddress := fmt.Sprintf("(%s.%s = %s.email AND %s)", m, quoteIdent(group.UserField), u, emailTrustedSQL(u))
	if emailKeyedColumn(group.UserField) {
		return byAddress
	}
	return fmt.Sprintf("(%s.%s = %s.id OR %s)", m, quoteIdent(group.UserField), u, byAddress)
}

// canSeeUser returns true when the requester is permitted to look up
// the given target user id under the active visibility mode. Self
// lookups are always permitted (you can see yourself even in `off`
// mode, because /api/_auth/profile would return the same data).
func canSeeUser(app *App, session *Session, mode string, targetID int64) bool {
	if session == nil {
		return false
	}
	if targetID == session.UserID {
		return true
	}
	isAdmin := session.IsAdmin()
	switch mode {
	case "self":
		return false
	case "admin":
		return isAdmin
	case "group":
		if isAdmin {
			return true
		}
		if app.Group == nil || app.Group.Table == "" || app.Group.Key == "" || app.Group.UserField == "" || !session.HasGroup() {
			return false
		}
		// Check membership: does the target user share the requester's group?
		var n int
		q := fmt.Sprintf(
			"SELECT COUNT(*) FROM %s m JOIN _benmore_users u ON %s WHERE u.id = ? AND m.%s = ?%s",
			quoteIdent(app.Group.Table), userDirectoryMemberMatch(app.Group, "u", "m"), quoteIdent(app.Group.Key),
			membershipLiveConds(app.Group, app.Group.Table, "m", dbColumnChecker(app.DB, app.Group.Table)),
		)
		if err := app.DB.QueryRow(q, targetID, session.GroupID).Scan(&n); err != nil {
			return false
		}
		return n > 0
	case "everyone":
		return true
	}
	if strings.HasPrefix(mode, "role:") {
		return userDirectoryRoleHolder(app, session, mode)
	}
	return false
}

// settingsRedirect redirects to the settings page with an error or success message.
// Messages prefixed with "success:" are passed as ?success=, others as ?error=.
func settingsRedirect(w http.ResponseWriter, r *http.Request, app *App, msg string) {
	settingsPath := app.Paths.Settings
	if strings.HasPrefix(msg, "success:") {
		http.Redirect(w, r, settingsPath+"?success="+url.QueryEscape(strings.TrimPrefix(msg, "success:")), http.StatusSeeOther)
	} else {
		http.Redirect(w, r, settingsPath+"?error="+url.QueryEscape(msg), http.StatusSeeOther)
	}
}
