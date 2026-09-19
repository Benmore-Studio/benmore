//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"html/template"
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
	id := authRawSessionID(r)
	if id == "" {
		return nil
	}
	p := &passwordChangeIdentity{SessionID: id}
	err := app.DB.QueryRow(`SELECT u.id, COALESCE(u.email,''), COALESCE(u.password_hash,'')
		FROM _benmore_sessions s JOIN _benmore_users u ON u.id=s.user_id
		WHERE s.id=? AND datetime(s.expires_at)>datetime('now')
		AND COALESCE(u.password_change_required,0)<>0
		AND COALESCE(u.deactivated_at,'')=''`, id).Scan(&p.UserID, &p.Email, &p.Hash)
	if err != nil {
		return nil
	}
	return p
}

func passwordChangeMiddleware(next http.Handler, app *App) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if pendingPasswordChange(app, r) == nil {
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
	key := fmt.Sprintf("password-change:%d", p.UserID)
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
		fail("Unable to change password", http.StatusInternalServerError)
		return
	}
	tx, err := app.DB.Begin()
	if err != nil {
		fail("Unable to change password", http.StatusInternalServerError)
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
		fail("Unable to change password", http.StatusInternalServerError)
		return
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		fail("Login expired or credentials changed. Sign in again.", http.StatusConflict)
		return
	}
	if err := revokePasswordCredentials(tx, p.UserID); err != nil {
		fail("Unable to change password", http.StatusInternalServerError)
		return
	}
	if _, err := tx.Exec(`INSERT INTO _benmore_audit_log(action,table_name,row_id,user_id,user_email)
		VALUES ('required_password_change','_benmore_users',?,?,?)`, p.UserID, p.UserID, p.Email); err != nil {
		fail("Unable to change password", http.StatusInternalServerError)
		return
	}
	if err := tx.Commit(); err != nil {
		fail("Unable to change password", http.StatusInternalServerError)
		return
	}
	recordLoginAttempt(app.DB, key, true)
	syncPlatformUserFromDashboard(app, p.Email, string(hash))
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName, Path: "/", MaxAge: -1, HttpOnly: true, Secure: !app.DevMode, SameSite: http.SameSiteLaxMode})
	if wantsJSON(r) {
		httpJSON(w, http.StatusOK, map[string]any{"ok": true, "redirect": app.Paths.Login})
		return
	}
	http.Redirect(w, r, app.Paths.Login, http.StatusSeeOther)
}

// Password replacement invalidates all reusable app credentials. Optional OAuth
// tables may not exist in apps that do not expose an OAuth provider.
func revokePasswordCredentials(tx *sql.Tx, userID int64) error {
	for _, table := range []string{"_benmore_sessions", "_benmore_api_tokens", "_benmore_oauth_codes"} {
		var exists int
		if err := tx.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", table).Scan(&exists); err != nil {
			return err
		}
		if exists == 0 {
			continue
		}
		if _, err := tx.Exec("DELETE FROM "+table+" WHERE user_id=?", userID); err != nil {
			return err
		}
	}
	var resetTable int
	if err := tx.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_benmore_password_resets'").Scan(&resetTable); err != nil {
		return err
	}
	if resetTable != 0 {
		if _, err := tx.Exec("UPDATE _benmore_password_resets SET used=1 WHERE type='reset' AND email=(SELECT email FROM _benmore_users WHERE id=?) COLLATE NOCASE", userID); err != nil {
			return err
		}
	}
	return nil
}

func renderPasswordChange(w http.ResponseWriter, r *http.Request, app *App, message string, status int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "no-referrer")
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
