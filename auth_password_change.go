//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

const passwordChangePagePath = "/auth/change-password"
const passwordChangeAPIPath = "/api/_auth/change-password"

// This identity deliberately is not a Session: it can only replace a temporary
// password. Normal session, API-token and edge resolution deny pending users.
type passwordChangeIdentity struct {
	UserID                 int64
	Email, Hash, SessionID string
}

func pendingPasswordChange(app *App, r *http.Request) *passwordChangeIdentity {
	if app == nil || app.DB == nil {
		return nil
	}
	token := authRawSessionID(r)
	key, ok := presentedSessionKey(token)
	if !ok {
		return nil
	}
	// SessionID is the row's stored id (the hashed key, or a legacy raw id
	// not yet rekeyed); the later checks address the row by it.
	p := &passwordChangeIdentity{}
	err := app.DB.QueryRow(`SELECT s.id, u.id, COALESCE(u.email,''), COALESCE(u.password_hash,'')
		FROM _benmore_sessions s JOIN _benmore_users u ON u.id=s.user_id
		WHERE s.id IN (?, ?) AND datetime(s.expires_at)>datetime('now')
		AND COALESCE(u.password_change_required,0)<>0
		AND COALESCE(u.deactivated_at,'')=''`, key, token).Scan(&p.SessionID, &p.UserID, &p.Email, &p.Hash)
	if err != nil {
		return nil
	}
	return p
}

// passwordChangeMiddleware routes an account that must replace a temporary
// password to the change page. It is a navigation gate: every session, API
// token and edge lookup already refuses a pending account, so nothing behind
// it grants that account access. That makes two shortcuts safe:
//   - static assets (public, CDN-cached bundles and files) skip the check;
//   - a request whose credential resolves to a normal session is not
//     pending (getSession refuses pending accounts), and resolving it here
//     fills the per-request cache the handler and request log then use.
//
// Only a credential that resolves to nothing pays for the pending lookup.
func passwordChangeMiddleware(next http.Handler, app *App) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isStaticPath(r.URL.Path) || authRawSessionID(r) == "" || getSession(app, r) != nil || pendingPasswordChange(app, r) == nil {
			next.ServeHTTP(w, r)
			return
		}
		allowed := r.Method == http.MethodGet && (r.URL.Path == passwordChangePagePath || r.URL.Path == "/api/_csrf") ||
			r.Method == http.MethodPost && (r.URL.Path == passwordChangeAPIPath || r.URL.Path == app.Paths.Logout) ||
			(r.Method == http.MethodGet || r.Method == http.MethodPost) && r.URL.Path == app.Paths.ResetPassword
		if allowed {
			next.ServeHTTP(w, r)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		if strings.HasPrefix(r.URL.Path, "/api/") || wantsJSON(r) || isBearerAuth(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "password_change_required", "redirect": passwordChangePagePath})
			return
		}
		if isHTMX(r) {
			w.Header().Set("HX-Redirect", passwordChangePagePath)
			w.WriteHeader(http.StatusForbidden)
			return
		}
		http.Redirect(w, r, passwordChangePagePath, http.StatusSeeOther)
	})
}

func registerPasswordChangeRoutes(mux *http.ServeMux, app *App) {
	EnsureAuditLogTable(app.DB)
	registerPasswordChangeHandlers(mux, app)
}

func registerPasswordChangeHandlers(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("GET "+passwordChangePagePath, func(w http.ResponseWriter, r *http.Request) {
		p := pendingPasswordChange(app, r)
		if p == nil {
			http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
			return
		}
		renderPasswordChange(w, r, app, "", http.StatusOK)
	})
	mux.HandleFunc("POST "+passwordChangeAPIPath, func(w http.ResponseWriter, r *http.Request) {
		handleRequiredPasswordChange(w, r, app)
	})
}

func handleRequiredPasswordChange(w http.ResponseWriter, r *http.Request, app *App) {
	w.Header().Set("Cache-Control", "no-store")
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
	mergeJSONBodyIntoForm(r)
	p := pendingPasswordChange(app, r)
	if p == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "password change requires a pending login session"})
		return
	}
	if !requireCSRF(w, r) {
		return
	}
	fail := func(message string, status int) {
		if wantsJSON(r) {
			httpJSON(w, status, map[string]any{"error": message})
			return
		}
		renderPasswordChange(w, r, app, message, status)
	}
	failInternal := func(err error) {
		fail(serverErrorMessage(w, r, app, "password change", err, "Unable to change password"), http.StatusInternalServerError)
	}
	// Delegated, scoped and support sessions may not manage credentials.
	var valid int
	err := app.DB.QueryRow(`SELECT 1 FROM _benmore_sessions WHERE id=? AND user_id=?
		AND COALESCE(is_impersonation,0)=0 AND COALESCE(acting_as_group,'')=''
		AND COALESCE(scopes,'') IN ('','*')`, p.SessionID, p.UserID).Scan(&valid)
	if err != nil {
		fail("Sign in directly to change your password", http.StatusForbidden)
		return
	}
	current, newPass, confirm := r.FormValue("current_password"), r.FormValue("new_password"), r.FormValue("confirm_password")
	key := passwordProofKey(p.UserID)
	defer lockAttempt(key)() // serialize this account's check→verify→record (lockout race)
	if isAccountLocked(app.DB, key) {
		fail("Too many attempts. Try again in 15 minutes.", http.StatusTooManyRequests)
		return
	}
	if len(current) > maxPasswordLength || bcrypt.CompareHashAndPassword([]byte(p.Hash), []byte(current)) != nil {
		recordLoginAttempt(app.DB, key, false)
		fail("Current password is incorrect", http.StatusForbidden)
		return
	}
	if len(newPass) > maxBcryptBytes {
		fail("Password must be at most 72 bytes", http.StatusBadRequest)
		return
	}
	if newPass != confirm {
		fail("New passwords do not match", http.StatusBadRequest)
		return
	}
	if msg := validatePasswordComplexity(newPass); msg != "" {
		fail(msg, http.StatusBadRequest)
		return
	}
	if bcrypt.CompareHashAndPassword([]byte(p.Hash), []byte(newPass)) == nil {
		fail("Choose a different password from the temporary password", http.StatusBadRequest)
		return
	}
	hash, err := generateBcryptHash([]byte(newPass))
	if err != nil {
		failInternal(err)
		return
	}
	tx, err := app.DB.Begin()
	if err != nil {
		failInternal(err)
		return
	}
	defer tx.Rollback()
	// Recheck the proof after hashing: a concurrent reset, logout or expiry must
	// not authorize this write. The conditional update also makes replay fail.
	result, err := tx.Exec(`UPDATE _benmore_users SET password_hash=?,password_change_required=0
		WHERE id=? AND password_hash=? AND COALESCE(password_change_required,0)<>0
		AND COALESCE(deactivated_at,'')=''
		AND EXISTS (SELECT 1 FROM _benmore_sessions WHERE id=? AND user_id=?
		AND datetime(expires_at)>datetime('now') AND COALESCE(is_impersonation,0)=0
		AND COALESCE(acting_as_group,'')='' AND COALESCE(scopes,'') IN ('','*'))`,
		string(hash), p.UserID, p.Hash, p.SessionID, p.UserID)
	if err != nil {
		failInternal(err)
		return
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		fail("Login expired or credentials changed. Sign in again.", http.StatusConflict)
		return
	}
	if err := revokePasswordCredentials(tx, p.UserID); err != nil {
		failInternal(err)
		return
	}
	// A temporary password means someone else reset this account (an
	// operator, or a flow that can't reach passkeys). Passkey sign-in is
	// refused only while the change is pending, so a key planted before the
	// reset would sign in again the moment the owner finished it.
	if _, err := revokeAccountPasskeys(tx, p.UserID); err != nil {
		failInternal(err)
		return
	}
	if _, err := tx.Exec(`INSERT INTO _benmore_audit_log(action,table_name,row_id,user_id,user_email)
		VALUES ('required_password_change','_benmore_users',?,?,?)`, p.UserID, p.UserID, p.Email); err != nil {
		failInternal(err)
		return
	}
	if err := tx.Commit(); err != nil {
		failInternal(err)
		return
	}
	recordLoginAttempt(app.DB, key, true)
	invalidateRequestSession(r)
	revokeEdgeGrantsAfterCredentialChange(app, p.UserID)
	platformPasswordChanged(app, p.Email, string(hash), false)
	clearSessionCookies(w, app.DevMode)
	if wantsJSON(r) {
		httpJSON(w, http.StatusOK, map[string]any{"ok": true, "redirect": app.Paths.Login})
		return
	}
	http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
}

// passwordProofKey is the per-account lockout key for current-password proofs
// made while signed in: the required change, settings changes, and
// impersonation / step-in re-auth share one budget.
func passwordProofKey(userID int64) string {
	return fmt.Sprintf("password-change:%d", userID)
}

// currentPasswordMatches checks a signed-in account's current password under
// passwordProofKey's lockout, so a stolen session can't guess the password
// without limit. locked means the proof was refused without being checked.
func currentPasswordMatches(app *App, userID int64, password string) (ok, locked bool) {
	hash, locked := currentPasswordProof(app, userID, password)
	return hash != "", locked
}

// Keep the verified hash so a credential write can compare it atomically after
// expensive bcrypt work. A boolean proof cannot detect an intervening reset.
func currentPasswordProof(app *App, userID int64, password string) (hash string, locked bool) {
	key := passwordProofKey(userID)
	defer lockAttempt(key)() // serialize this account's check→verify→record (lockout race)
	if isAccountLocked(app.DB, key) {
		return "", true
	}
	app.DB.QueryRow("SELECT COALESCE(password_hash, '') FROM _benmore_users WHERE id = ?", userID).Scan(&hash)
	if hash == "" || len(password) > maxPasswordLength || bcrypt.CompareHashAndPassword([]byte(hash), []byte(password)) != nil {
		recordLoginAttempt(app.DB, key, false)
		return "", false
	}
	recordLoginAttempt(app.DB, key, true)
	return hash, false
}

// changeSignedInPassword stores a new password hash for the signed-in caller
// and, atomically with it, revokes every other credential the old password
// could have produced (revokePasswordCredentialsExcept keeps only the
// session that proved it). Returns the account email for the platform sync.
func changeSignedInPassword(app *App, session *Session, proofHash, newHash string) (string, error) {
	return changeSignedInPasswordWith(app, session, proofHash, newHash, false)
}

// changeSignedInPasswordWith is changeSignedInPassword that can also remove
// every passkey in the same transaction. Like the TOTP factor, passkeys
// survive an ordinary change made from a proven session; the person opts in
// (revoke_passkeys) when the change is a response to a suspected compromise.
func changeSignedInPasswordWith(app *App, session *Session, proofHash, newHash string, revokePasskeys bool) (string, error) {
	if session == nil || proofHash == "" {
		return "", fmt.Errorf("current password proof required")
	}
	tx, err := app.DB.Begin()
	if err != nil {
		return "", err
	}
	defer tx.Rollback()
	var email string
	if err := tx.QueryRow("SELECT COALESCE(email, '') FROM _benmore_users WHERE id = ?", session.UserID).Scan(&email); err != nil {
		return "", err
	}
	result, err := tx.Exec(`UPDATE _benmore_users SET password_hash=?
		WHERE id=? AND password_hash=? AND COALESCE(password_change_required,0)=0
		AND COALESCE(deactivated_at,'')=''
		AND EXISTS (SELECT 1 FROM _benmore_sessions WHERE id=? AND user_id=?
		AND datetime(expires_at)>datetime('now') AND COALESCE(is_impersonation,0)=0
		AND COALESCE(acting_as_group,'')='' AND COALESCE(scopes,'') IN ('','*'))`,
		newHash, session.UserID, proofHash, session.ID, session.UserID)
	if err != nil {
		return "", err
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return "", fmt.Errorf("login expired or credentials changed; sign in again")
	}
	if err := revokePasswordCredentialsExcept(tx, session.UserID, session.ID); err != nil {
		return "", err
	}
	if revokePasskeys {
		if _, err := revokeAccountPasskeys(tx, session.UserID); err != nil {
			return "", err
		}
	}
	if _, err := tx.Exec(`INSERT INTO _benmore_audit_log(action,table_name,row_id,user_id,user_email)
		VALUES ('password_change','_benmore_users',?,?,?)`, session.UserID, session.UserID, email); err != nil {
		return "", err
	}
	if err := tx.Commit(); err != nil {
		return "", err
	}
	revokeEdgeGrantsAfterCredentialChange(app, session.UserID)
	return email, nil
}

// Password replacement invalidates all reusable app credentials. Optional OAuth
// tables may not exist in apps that do not expose an OAuth provider.
func revokePasswordCredentials(tx *sql.Tx, userID int64) error {
	return revokePasswordCredentialsExcept(tx, userID, "")
}

// revokePasswordCredentialsExcept is revokePasswordCredentials that keeps one
// login session alive: a signed-in password change keeps the session that
// proved the old password, and every other session, API token, OAuth code and
// connector grant the old password could have produced dies with it.
func revokePasswordCredentialsExcept(tx *sql.Tx, userID int64, keepSessionID string) error {
	if err := revokeUserAccessExcept(tx, userID, keepSessionID); err != nil {
		return err
	}
	return cancelPendingRecovery(tx, userID)
}

// revokeUserAccessExcept ends every way the account can act in this app: its
// sessions (but keepSessionID), API tokens, OAuth codes and MCP connector
// grants. An approved command that removes a member uses it as is
// (app_mcp_command_revoke.go); a password change adds the recovery cleanup.
func revokeUserAccessExcept(tx *sql.Tx, userID int64, keepSessionID string) error {
	for _, table := range []string{"_benmore_sessions", "_benmore_signin_challenges", "_benmore_api_tokens", "_benmore_oauth_codes"} {
		var exists int
		if err := tx.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			continue
		}
		query, args := "DELETE FROM "+table+" WHERE user_id=?", []any{userID}
		if table == "_benmore_sessions" && keepSessionID != "" {
			query += " AND id<>?"
			args = append(args, keepSessionID)
		}
		if _, err := tx.Exec(query, args...); err != nil {
			return err
		}
	}
	return revokeAppMCPUserGrants(tx, userID)
}

// cancelPendingRecovery ends the account changes that were authorized by the
// old credential and are still waiting to complete: unused reset links and a
// pending email change. Without this, whoever held the old password keeps a
// way back in (confirm the email change, then reset through the new inbox).
func cancelPendingRecovery(x interface {
	Exec(string, ...any) (sql.Result, error)
	QueryRow(string, ...any) *sql.Row
}, userID int64) error {
	for _, step := range []struct{ table, query string }{
		{"_benmore_password_resets", "UPDATE _benmore_password_resets SET used=1 WHERE type='reset' AND email=(SELECT email FROM _benmore_users WHERE id=?) COLLATE NOCASE"},
		{"_benmore_email_changes", "DELETE FROM _benmore_email_changes WHERE user_id=?"},
	} {
		var exists int
		if err := x.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", step.table).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			continue
		}
		if _, err := x.Exec(step.query, userID); err != nil {
			return err
		}
	}
	return nil
}

func renderPasswordChange(w http.ResponseWriter, r *http.Request, app *App, message string, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	// Not no-referrer: that makes the browser send Origin: null on this
	// page's own form POST.
	w.Header().Set("Referrer-Policy", "same-origin")
	denyFraming(w)
	w.WriteHeader(status)
	page := template.Must(template.New("password-change").Parse(passwordChangeHTML))
	_ = page.Execute(w, map[string]string{"Error": message, "CSRF": authMintCSRFToken(authRawSessionID(r)), "Action": passwordChangeAPIPath, "Logout": app.Paths.Logout})
}

const passwordChangeHTML = `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Choose your password</title>
<style>body{font:16px system-ui,sans-serif;max-width:28rem;margin:8vh auto;padding:1.5rem;color:#172033;background:#f8fafc}h1{font-size:1.8rem}label{display:block;margin:1rem 0}input{display:block;width:100%;box-sizing:border-box;padding:.7rem;margin-top:.4rem;border:1px solid #94a3b8;border-radius:.35rem;font:inherit}button{padding:.7rem 1rem;font:inherit;cursor:pointer}p{line-height:1.5}[role=alert]{color:#a11225}</style></head>
<body><main><h1>Choose your password</h1><p>Replace your temporary password to continue. Use at least 8 characters, including an uppercase letter and a special character.</p>
{{if .Error}}<p role="alert">{{.Error}}</p>{{end}}
<form method="post" action="{{.Action}}"><input type="hidden" name="_csrf" value="{{.CSRF}}">
<label>Current password<input type="password" name="current_password" autocomplete="current-password" maxlength="72" required autofocus></label>
<label>New password<input type="password" name="new_password" autocomplete="new-password" minlength="8" maxlength="72" required></label>
<label>Confirm new password<input type="password" name="confirm_password" autocomplete="new-password" minlength="8" maxlength="72" required></label>
<button type="submit">Save password and sign in</button></form>
<form method="post" action="{{.Logout}}"><input type="hidden" name="_csrf" value="{{.CSRF}}"><p><button type="submit">Sign out</button></p></form></main></body></html>`

// revokeEdgeGrantsAfterCredentialChange ends the account's edge (paste) grants
// once a password change, reset or claim - or the erasure of the account -
// has committed. Grants live in the platform database, outside the app
// transaction, so this runs after COMMIT; a failure is logged rather than
// undoing the credential change.
func revokeEdgeGrantsAfterCredentialChange(app *App, userID int64) {
	if err := revokeEdgeGrantsForUser(app, userID); err != nil {
		log.Printf("edge grants: revoke for user %d after credential change: %v", userID, err)
	}
}
