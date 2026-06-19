//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// profileProtectedFields are columns that cannot be updated via the profile API.
var profileProtectedFields = map[string]bool{
	"id": true, "password_hash": true, "created_at": true, "updated_at": true,
	"role": true, "verified": true, "deactivated_at": true,
}

// RegisterSettingsRoutes adds the settings/account management page and Profile API.
func RegisterSettingsRoutes(mux *http.ServeMux, app *App) {

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
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
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
				out = append(out, u)
			}
		}
		httpJSON(w, http.StatusOK, map[string]any{"users": out, "limit": limit, "offset": offset, "mode": mode})
	})

	mux.HandleFunc("GET /api/_auth/users/{id}", func(w http.ResponseWriter, r *http.Request) {
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
		httpJSON(w, http.StatusOK, u)
	})

	// Profile API: PATCH /api/_auth/profile - update non-sensitive user fields
	mux.HandleFunc("PATCH /api/_auth/profile", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
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

		// Email change requires the current password - same posture as
		// the form-based /settings/profile endpoint. Without this, a
		// momentary cookie-theft / XSS becomes account-takeover via
		// email change → password reset to the attacker's address.
		newEmailRaw, changingEmail := updates["email"]
		newEmail, _ := newEmailRaw.(string)
		if changingEmail && newEmail != session.Email {
			currentPassword, _ := updates["current_password"].(string)
			if currentPassword == "" {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": "current_password required to change email"})
				return
			}
			var currentHash string
			app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = ?", session.UserID).Scan(&currentHash)
			if currentHash == "" || bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(currentPassword)) != nil {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": "incorrect password"})
				return
			}
		}
		delete(updates, "current_password") // not a column

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
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "update failed"})
			return
		}

		// If email changed: revoke all other sessions and notify the
		// old address - mirror the form-handler posture so the API and
		// HTML paths can't be played against each other.
		if changingEmail && newEmail != session.Email {
			app.DB.Exec("UPDATE _benmore_sessions SET email = ? WHERE id = ?", newEmail, session.ID)
			app.DB.Exec("DELETE FROM _benmore_sessions WHERE user_id = ? AND id != ?", session.UserID, session.ID)
			if session.Email != "" {
				go SendEmail(app.Dir, session.Email, "Your email was changed",
					fmt.Sprintf("Your account email was changed to %s. If this wasn't you, contact support immediately.", newEmail))
			}
		}

		// Return updated profile. Surface any dropped fields so the
		// caller sees what was actually persisted vs what the request
		// asked for - closes the silent-drop footgun for unknown
		// columns while keeping the graceful-degradation behavior for
		// existing callers that DID send a usable subset.
		userMap := LoadUserFields(app.DB, session.UserID)
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
		var currentHash string
		app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = ?", session.UserID).Scan(&currentHash)
		if err := bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(current)); err != nil {
			settingsRedirect(w, r, app, "Current password is incorrect")
			return
		}

		// Set new password
		newHash, _ := generateBcryptHash([]byte(newPass))
		app.DB.Exec("UPDATE _benmore_users SET password_hash = ? WHERE id = ?", string(newHash), session.UserID)

		// On a hosted platform, mirror the new hash so a password change in
		// /settings stays in sync with the CLI login credential. No-op in a
		// self-hosted build.
		var userEmail string
		app.DB.QueryRow("SELECT COALESCE(email, '') FROM _benmore_users WHERE id = ?", session.UserID).Scan(&userEmail)
		if userEmail != "" {
			syncPlatformUserFromDashboard(app, userEmail, string(newHash))
		}

		// Invalidate all other sessions (security: password change kills stale sessions)
		app.DB.Exec("DELETE FROM _benmore_sessions WHERE user_id = ? AND id != ?", session.UserID, session.ID)

		settingsRedirect(w, r, app, "success:Password updated successfully")
	})

	// Update profile
	mux.HandleFunc("POST /settings/profile", func(w http.ResponseWriter, r *http.Request) {
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
		var currentHash string
		app.DB.QueryRow("SELECT password_hash FROM _benmore_users WHERE id = ?", session.UserID).Scan(&currentHash)
		if currentHash == "" || bcrypt.CompareHashAndPassword([]byte(currentHash), []byte(currentPassword)) != nil {
			settingsRedirect(w, r, app, "Incorrect password")
			return
		}

		// Check if email is taken by someone else
		var otherID int64
		err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = ? AND id != ?", newEmail, session.UserID).Scan(&otherID)
		if err == nil {
			settingsRedirect(w, r, app, "That email is already in use")
			return
		}

		// Capture the old email so we can notify it of the change.
		var oldEmail string
		app.DB.QueryRow("SELECT email FROM _benmore_users WHERE id = ?", session.UserID).Scan(&oldEmail)

		app.DB.Exec("UPDATE _benmore_users SET email = ? WHERE id = ?", newEmail, session.UserID)

		// Revoke ALL the user's other sessions on email change - the
		// new address controls password reset, so any other tab should
		// re-auth before continuing.
		app.DB.Exec("DELETE FROM _benmore_sessions WHERE user_id = ? AND id != ?", session.UserID, session.ID)

		// Update current session to reflect new email.
		DeleteSessionFromDB(app.DB, session.ID)
		sessionID := CreateSession(app.DB, session.UserID, newEmail, session.GroupID, app.SessionDuration)
		http.SetCookie(w, sessionCookie(sessionID, app.DevMode, app.SessionDuration))

		// Notify the old address of the change (best-effort).
		if oldEmail != "" && oldEmail != newEmail {
			go SendEmail(app.Dir, oldEmail, "Your email was changed",
				fmt.Sprintf("Your account email was changed to %s. If this wasn't you, contact support immediately.", newEmail))
		}

		settingsRedirect(w, r, app, "success:Email updated successfully")
	})

	// Delete account
	mux.HandleFunc("POST /settings/delete-account", func(w http.ResponseWriter, r *http.Request) {
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

		confirm := r.FormValue("confirm")
		if confirm != "DELETE" {
			settingsRedirect(w, r, app, "Type DELETE to confirm account deletion")
			return
		}

		// Delete sessions
		app.DB.Exec("DELETE FROM _benmore_sessions WHERE user_id = ?", session.UserID)
		// Delete user
		app.DB.Exec("DELETE FROM _benmore_users WHERE id = ?", session.UserID)

		http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
	})
}

// userDirectoryMode returns the effective access mode for the
// /api/_auth/users endpoints. v2.7.12+: routes through the unified
// `access:` config in app.yaml (treats `_benmore_users` as just
// another table). Falls back to "admin" - PRIVATE by default; only
// admins can list / look up other users, self-lookup always works.
//
// Values: anon · everyone · self · group · admin · role:<name> · off
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
func buildUserListQuery(app *App, session *Session, mode string, limit, offset int) (string, []any, bool) {
	deactivatedClause := "(deactivated_at IS NULL OR deactivated_at = '')"
	isAdmin := session != nil && session.IsAdmin()

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
		// JOIN to membership table on the user identifier column (typically
		// `email`) and filter by the requester's group id. Names come from
		// app.yaml (developer-trusted), interpolated like the rest of crud.go.
		q := fmt.Sprintf(
			"SELECT u.id FROM _benmore_users u WHERE u.%s IN (SELECT m.%s FROM %s m WHERE m.%s = ?) AND (u.deactivated_at IS NULL OR u.deactivated_at = '') ORDER BY u.id LIMIT ? OFFSET ?",
			app.Group.UserField, app.Group.UserField, app.Group.Table, app.Group.Key,
		)
		return q, []any{session.GroupID, limit, offset}, true

	case "everyone":
		return "SELECT id FROM _benmore_users WHERE " + deactivatedClause + " ORDER BY id LIMIT ? OFFSET ?",
			[]any{limit, offset}, true
	}
	// Unknown mode - fail closed.
	return "", nil, false
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
			"SELECT COUNT(*) FROM %s m JOIN _benmore_users u ON u.%s = m.%s WHERE u.id = ? AND m.%s = ?",
			app.Group.Table, app.Group.UserField, app.Group.UserField, app.Group.Key,
		)
		if err := app.DB.QueryRow(q, targetID, session.GroupID).Scan(&n); err != nil {
			return false
		}
		return n > 0
	case "everyone":
		return true
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
