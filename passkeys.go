//go:build !cli

package main

// Passkey (WebAuthn) sign-in for app users. On by default; `auth.passkeys:
// false` in app.yaml turns every route off.
//
//	POST   /api/_auth/passkeys/register/options   creation options (signed in)
//	POST   /api/_auth/passkeys/register           save a new passkey (signed in)
//	GET    /api/_auth/passkeys                    the caller's passkeys
//	DELETE /api/_auth/passkeys/{id}               remove one (signed in)
//	DELETE /api/_auth/passkeys                    remove all of them (signed in)
//	POST   /api/_auth/passkeys/login/options      request options (anyone)
//	POST   /api/_auth/passkeys/login              sign in with a passkey
//
// The browser side is bm.auth.passkey.register() / .signIn(). Challenges are
// carried in a short, HMAC-signed, purpose-bound cookie and a hashed database
// nonce that is consumed exactly once. Adding or removing a passkey needs the person's own
// direct sign-in (not an API token, scoped session, impersonation or act-as)
// and CSRF, like other credential changes; adding one also needs the current
// password or an authenticator code, as MFA enrollment does, unless the
// browser session comes from a sign-in made in the last ten minutes
// (recentDirectSignIn; an OAuth-only account has no password to give). A password
// reset or a claim of an unverified address removes every passkey
// (revokeAccountPasskeys). A passkey sign-in requires user
// verification (biometric or PIN), so it satisfies the configured MFA factor;
// apps with auth.otp still require the separate email or SMS code.

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const (
	flowCookiePasskey   = "_benmore_passkey"
	passkeyChallengeTTL = 300 // seconds
	passkeyMaxPerUser   = 20
)

func passkeysEnabled(app *App) bool {
	if app == nil || app.Design != nil && app.Design.Auth["passkeys"] == "false" {
		return false
	}
	// auth.oauth_only makes the identity provider the only way in, so a
	// passkey (which signs in without it) needs an explicit opt-in there.
	if oauthOnly(app) {
		setting, _ := canonicalAuthFlag(app.Design.Auth["passkeys"])
		return setting == "true"
	}
	return true
}

func consumePasskeyChallenge(db *sql.DB, challenge []byte, purpose string, userID int64, rpID, origin string, now time.Time) bool {
	if db == nil || len(challenge) != 32 || purpose != "register" && purpose != "login" || rpID == "" || origin == "" {
		return false
	}
	digest := sha256.Sum256(challenge)
	res, err := db.Exec(`DELETE FROM _benmore_passkey_challenges
		WHERE challenge_hash=? AND purpose=? AND user_id=? AND rp_id=? AND origin=? AND expires_at>?`,
		hex.EncodeToString(digest[:]), purpose, userID, rpID, origin, now.Unix())
	if err != nil {
		return false
	}
	n, err := res.RowsAffected()
	return err == nil && n == 1
}

func EnsurePasskeysTable(db *sql.DB) error {
	// A passkey is added and removed with its audit row in one transaction
	// (account_audit.go), so the log exists wherever this table does.
	EnsureAuditLogTable(db)
	_, err := db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_passkeys (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		credential_id TEXT NOT NULL UNIQUE,
		public_key BLOB NOT NULL,
		alg INTEGER NOT NULL,
		sign_count INTEGER NOT NULL DEFAULT 0,
		name TEXT NOT NULL DEFAULT '',
		created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_used_at DATETIME
	)`)
	if err == nil {
		_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_benmore_passkeys_user ON _benmore_passkeys(user_id)`)
	}
	if err == nil {
		// user_handle: the WebAuthn user.id the authenticator was given when
		// the passkey was registered, so sign-in keeps accepting it when the
		// key it was derived from changes (a rotated server secret, a store
		// moved to another process). NULL for passkeys registered before the
		// column existed: their handle is derived (passkeyUserHandle).
		var n int
		if err = db.QueryRow(`SELECT COUNT(*) FROM pragma_table_info('_benmore_passkeys') WHERE name = 'user_handle'`).Scan(&n); err == nil && n == 0 {
			_, err = db.Exec(`ALTER TABLE _benmore_passkeys ADD COLUMN user_handle TEXT`)
		}
	}
	if err == nil {
		_, err = db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_passkey_challenges (
			challenge_hash TEXT PRIMARY KEY,
			purpose TEXT NOT NULL CHECK(purpose IN ('register','login')),
			user_id INTEGER NOT NULL,
			rp_id TEXT NOT NULL,
			origin TEXT NOT NULL,
			source_hash TEXT NOT NULL,
			expires_at INTEGER NOT NULL
		)`)
		if err == nil {
			_, err = db.Exec(`CREATE INDEX IF NOT EXISTS idx_benmore_passkey_challenges_source ON _benmore_passkey_challenges(source_hash,rp_id,expires_at)`)
		}
	}
	return err
}

// revokeAccountPasskeys deletes every passkey of userID through x (normally
// the transaction that replaces or claims the account's credentials). A
// passkey is a full sign-in on its own, so a password reset or a claim of an
// unverified address that left it in place handed the account back to
// whoever registered it - for example someone who signed up as the address
// before its owner did. Apps without the passkeys table have nothing to do.
func revokeAccountPasskeys(x interface {
	Exec(string, ...any) (sql.Result, error)
	QueryRow(string, ...any) *sql.Row
}, userID int64) (int64, error) {
	var exists int
	if err := x.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_benmore_passkeys'").Scan(&exists); err != nil {
		return 0, err
	}
	if exists == 0 {
		return 0, nil
	}
	res, err := x.Exec("DELETE FROM _benmore_passkeys WHERE user_id = ?", userID)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return n, nil
}

// RegisterPasskeyRoutes creates the table and mounts the routes.
func RegisterPasskeyRoutes(mux appRouteRegistrar, app *App) {
	_ = EnsurePasskeysTable(app.DB)
	registerPasskeyRoutes(mux, app)
}

func registerPasskeyRoutes(mux appRouteRegistrar, app *App) {
	accountSettings := func(next http.HandlerFunc) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			if accountSettingsDisabled(w, r, app) {
				return
			}
			next(w, r)
		}
	}
	mux.HandleFunc("POST /api/_auth/passkeys/register/options", accountSettings(passkeyRegisterOptions(app)))
	mux.HandleFunc("POST /api/_auth/passkeys/register", accountSettings(passkeyRegister(app)))
	mux.HandleFunc("GET /api/_auth/passkeys", accountSettings(passkeyList(app)))
	mux.HandleFunc("DELETE /api/_auth/passkeys/{id}", accountSettings(passkeyDelete(app)))
	mux.HandleFunc("DELETE /api/_auth/passkeys", accountSettings(passkeyDeleteAll(app)))
	mux.HandleFunc("POST /api/_auth/passkeys/login/options", passkeyLoginOptions(app))
	mux.HandleFunc("POST /api/_auth/passkeys/login", passkeyLogin(app))
}

// passkeyRP is the relying party for this request: the host the browser is
// on (an app subdomain or its custom domain) and its exact origin.
func passkeyRP(r *http.Request) (rpID, origin string) {
	host := r.Host
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(host), protoOf(r) + "://" + r.Host
}

func passkeyJSONError(w http.ResponseWriter, status int, msg string) {
	httpJSON(w, status, map[string]any{"ok": false, "error": msg})
}

// passkeyServerError is passkeyJSONError for a server-side failure: err is
// kept server-side (serverErrorJSONBody) and the answer gains a request id.
func passkeyServerError(w http.ResponseWriter, r *http.Request, app *App, err error, msg string) {
	serverErrorJSONBody(w, r, app, http.StatusInternalServerError, "passkeys", err, map[string]any{"ok": false, "error": msg})
}

// passkeyUserHandle is the opaque per-user id handed to the authenticator
// (WebAuthn user.id): stable for the app, not the row id or the email.
func passkeyUserHandle(app *App, userID int64) []byte {
	return passkeyUserHandleWith(serverSecret, tempCookieAudience(app), userID)
}

// passkeyUserHandleWith is passkeyUserHandle under an explicit secret and
// audience (the app directory, absolute).
func passkeyUserHandleWith(secret, audience string, userID int64) []byte {
	mac := tempCookieMACWith(secret, audience, "passkey-user|"+strconv.FormatInt(userID, 10))
	if len(mac) > 32 {
		mac = mac[:32]
	}
	return []byte(mac)
}

func newPasskeyChallenge(w http.ResponseWriter, r *http.Request, app *App, purpose string, userID int64) ([]byte, error) {
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return nil, err
	}
	rpID, origin := passkeyRP(r)
	if rpID == "" || origin == "" || purpose != "register" && purpose != "login" {
		return nil, errors.New("invalid passkey challenge scope")
	}
	now := time.Now()
	tx, err := app.DB.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`DELETE FROM _benmore_passkey_challenges WHERE expires_at <= ?`, now.Unix()); err != nil {
		return nil, err
	}
	// Per client address, IPv6 by /64 (clientRateBucket) like every other
	// per-address limit: keyed on the full address, one /64 had a fresh
	// budget of pending challenges for every address in it.
	sourceHash := tempCookieMAC(app, "passkey-source|"+clientRateBucket(clientIP(r)))
	var pending int
	if err := tx.QueryRow(`SELECT COUNT(*) FROM _benmore_passkey_challenges WHERE source_hash=? AND rp_id=? AND expires_at>?`, sourceHash, rpID, now.Unix()).Scan(&pending); err != nil {
		return nil, err
	}
	if pending >= 20 {
		return nil, errors.New("too many pending passkey challenges")
	}
	digest := sha256.Sum256(challenge)
	if _, err := tx.Exec(`INSERT INTO _benmore_passkey_challenges(challenge_hash,purpose,user_id,rp_id,origin,source_hash,expires_at) VALUES(?,?,?,?,?,?,?)`,
		hex.EncodeToString(digest[:]), purpose, userID, rpID, origin, sourceHash, now.Add(passkeyChallengeTTL*time.Second).Unix()); err != nil {
		return nil, err
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	value := purpose + ":" + strconv.FormatInt(userID, 10) + ":" + strconv.FormatInt(now.Unix(), 10) + ":" + b64urlEncode(challenge)
	setFlowCookie(w, flowCookiePasskey, signTempCookieFor(app, tempCookiePasskey, value), !app.DevMode, passkeyChallengeTTL)
	return challenge, nil
}

// takePasskeyChallenge returns the challenge issued for purpose (and user) and
// clears it, so each challenge is used at most once.
func takePasskeyChallenge(w http.ResponseWriter, r *http.Request, app *App, purpose string, userID int64) ([]byte, bool) {
	c, err := requestFlowCookie(r, flowCookiePasskey)
	clearFlowCookie(w, flowCookiePasskey)
	if err != nil {
		return nil, false
	}
	value := verifyTempCookieFor(app, tempCookiePasskey, c.Value)
	parts := strings.SplitN(value, ":", 4)
	if len(parts) != 4 || parts[0] != purpose || parts[1] != strconv.FormatInt(userID, 10) {
		return nil, false
	}
	issued, err := strconv.ParseInt(parts[2], 10, 64)
	now := time.Now().Unix()
	if err != nil || issued > now || now-issued > passkeyChallengeTTL {
		return nil, false
	}
	challenge, err := b64url(parts[3])
	if err != nil || len(challenge) != 32 {
		return nil, false
	}
	rpID, origin := passkeyRP(r)
	if !consumePasskeyChallenge(app.DB, challenge, purpose, userID, rpID, origin, time.Unix(now, 0)) {
		return nil, false
	}
	return challenge, true
}

// passkeyCredentialChange gates adding/removing a passkey: a signed-in direct
// session plus CSRF. Returns the session or writes the refusal.
func passkeyCredentialChange(w http.ResponseWriter, r *http.Request, app *App) *Session {
	if !passkeysEnabled(app) {
		http.NotFound(w, r)
		return nil
	}
	sess := getSession(app, r)
	if sess == nil || sess.UserID <= 0 {
		passkeyJSONError(w, http.StatusUnauthorized, "sign in first")
		return nil
	}
	if !directLoginSession(app, sess) {
		passkeyJSONError(w, http.StatusForbidden, "passkeys can be changed only from your own direct sign-in (not an API token, scoped session, impersonation or act-as)")
		return nil
	}
	if !validateCSRF(r) {
		passkeyJSONError(w, http.StatusForbidden, "missing or expired CSRF token")
		return nil
	}
	return sess
}

// passkeyRegistrationProven requires a fresh proof of the account before a
// passkey is added, as MFA enrollment does: the current password, or a code
// from the account's enrolled second factor. A passkey signs in on its own
// and skips the TOTP step, so without this a stolen or XSS-driven session
// could plant the attacker's own key and keep the account after the session
// ends. A browser session from a sign-in made in the last ten minutes is the
// proof on its own when neither is sent (recentDirectSignIn): someone who
// signed up with Google has a random password and no second factor. A
// password or code that is sent is always checked. Only the options call
// needs it: registration consumes the challenge this call issues for this
// user. Writes the refusal and returns false.
func passkeyRegistrationProven(w http.ResponseWriter, r *http.Request, app *App, sess *Session) bool {
	var body struct {
		Password        string `json:"password"`
		CurrentPassword string `json:"current_password"`
		MFACode         string `json:"mfa_code"`
	}
	json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body)
	password := body.Password
	if password == "" {
		password = body.CurrentPassword
	}
	code := strings.TrimSpace(body.MFACode)
	if password == "" && code == "" { // a form post (CSRF parsing already read it)
		password, code = r.PostFormValue("password"), strings.TrimSpace(r.PostFormValue("mfa_code"))
	}
	switch {
	case password != "":
		ok, locked := currentPasswordMatches(app, sess.UserID, password)
		if locked {
			passkeyJSONError(w, http.StatusTooManyRequests, "too many attempts, try again in 15 minutes")
			return false
		}
		if !ok {
			passkeyJSONError(w, http.StatusForbidden, "incorrect password")
			return false
		}
		return true
	case code != "" && CheckMFA(app.DB, sess.UserID):
		key := mfaLockKey(sess.UserID)
		defer lockAttempt(key)()
		if isAccountLocked(app.DB, key) {
			passkeyJSONError(w, http.StatusTooManyRequests, "too many attempts, try again in 15 minutes")
			return false
		}
		if !ValidateMFACode(app.DB, sess.UserID, code) {
			recordLoginAttempt(app.DB, key, false)
			passkeyJSONError(w, http.StatusForbidden, "invalid MFA code")
			return false
		}
		recordLoginAttempt(app.DB, key, true)
		return true
	case recentDirectSignIn(app, r, sess):
		return true
	}
	passkeyJSONError(w, http.StatusBadRequest, "confirm it's you: send your current password (or an authenticator code), or sign in again, to add a passkey")
	return false
}

func passkeyRegisterOptions(app *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := passkeyCredentialChange(w, r, app)
		if sess == nil {
			return
		}
		if !passkeyRegistrationProven(w, r, app, sess) {
			return
		}
		challenge, err := newPasskeyChallenge(w, r, app, "register", sess.UserID)
		if err != nil {
			passkeyServerError(w, r, app, err, "could not start passkey setup")
			return
		}
		rpID, _ := passkeyRP(r)
		exclude := []map[string]any{}
		rows, err := app.DB.Query(`SELECT credential_id FROM _benmore_passkeys WHERE user_id = ?`, sess.UserID)
		if err == nil {
			for rows.Next() {
				var id string
				if rows.Scan(&id) == nil {
					exclude = append(exclude, map[string]any{"type": "public-key", "id": id})
				}
			}
			rows.Close()
		}
		name := sess.Email
		if name == "" {
			name = "user " + strconv.FormatInt(sess.UserID, 10)
		}
		rpName := rpID
		if app.Design != nil {
			if n := strings.TrimSpace(app.Design.SEO["site_name"]); n != "" {
				rpName = n
			}
		}
		httpJSON(w, http.StatusOK, map[string]any{
			"challenge": b64urlEncode(challenge),
			"rp":        map[string]any{"id": rpID, "name": rpName},
			"user":      map[string]any{"id": b64urlEncode(passkeyUserHandle(app, sess.UserID)), "name": name, "displayName": name},
			"pubKeyCredParams": []map[string]any{
				{"type": "public-key", "alg": coseAlgES256},
				{"type": "public-key", "alg": coseAlgEdDSA},
				{"type": "public-key", "alg": coseAlgRS256},
			},
			"timeout":     passkeyChallengeTTL * 1000,
			"attestation": "none",
			"authenticatorSelection": map[string]any{
				"residentKey": "required", "requireResidentKey": true, "userVerification": "required",
			},
			"excludeCredentials": exclude,
		})
	}
}

type passkeyCredentialJSON struct {
	ID       string `json:"id"`
	RawID    string `json:"rawId"`
	Type     string `json:"type"`
	Name     string `json:"name"`
	Response struct {
		ClientDataJSON    string `json:"clientDataJSON"`
		AttestationObject string `json:"attestationObject"`
		AuthenticatorData string `json:"authenticatorData"`
		Signature         string `json:"signature"`
		UserHandle        string `json:"userHandle"`
	} `json:"response"`
}

func decodePasskeyCredential(w http.ResponseWriter, r *http.Request) (*passkeyCredentialJSON, bool) {
	var body passkeyCredentialJSON
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&body); err != nil || body.Type != "public-key" || body.RawID == "" {
		passkeyJSONError(w, http.StatusBadRequest, "send the credential from navigator.credentials (bm.auth.passkey does this)")
		return nil, false
	}
	return &body, true
}

func passkeyRegister(app *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := passkeyCredentialChange(w, r, app)
		if sess == nil {
			return
		}
		challenge, ok := takePasskeyChallenge(w, r, app, "register", sess.UserID)
		if !ok {
			passkeyJSONError(w, http.StatusBadRequest, "passkey setup expired; start again")
			return
		}
		body, ok := decodePasskeyCredential(w, r)
		if !ok {
			return
		}
		clientData, err1 := b64url(body.Response.ClientDataJSON)
		attestation, err2 := b64url(body.Response.AttestationObject)
		rawID, err3 := b64url(body.RawID)
		if err1 != nil || err2 != nil || err3 != nil {
			passkeyJSONError(w, http.StatusBadRequest, "malformed credential encoding")
			return
		}
		rpID, origin := passkeyRP(r)
		reg, err := verifyWebAuthnRegistration(clientData, attestation, challenge, rpID, origin)
		if err != nil {
			passkeyJSONError(w, http.StatusBadRequest, err.Error())
			return
		}
		if !webauthnEqualID(reg.CredentialID, rawID) {
			passkeyJSONError(w, http.StatusBadRequest, "credential id does not match the authenticator data")
			return
		}
		name := strings.TrimSpace(body.Name)
		if len(name) > 64 {
			name = name[:64]
		}
		if name == "" {
			name = "Passkey"
		}
		tx, err := app.DB.Begin()
		if err != nil {
			passkeyServerError(w, r, app, err, "could not save the passkey")
			return
		}
		defer tx.Rollback()
		// The user handle the authenticator was just given is kept with the
		// passkey, so sign-in keeps accepting it if the derivation's key
		// changes (a rotated server secret, a store moved to another process).
		res, err := tx.Exec(`INSERT INTO _benmore_passkeys (user_id, credential_id, public_key, alg, sign_count, name, user_handle)
			SELECT ?, ?, ?, ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM _benmore_passkeys WHERE user_id=?) < ?`,
			sess.UserID, b64urlEncode(reg.CredentialID), reg.PublicKey, reg.Alg, reg.SignCount, name, string(passkeyUserHandle(app, sess.UserID)), sess.UserID, passkeyMaxPerUser)
		if err != nil {
			if strings.Contains(err.Error(), "UNIQUE") {
				passkeyJSONError(w, http.StatusConflict, "this passkey is already registered")
				return
			}
			passkeyServerError(w, r, app, err, "could not save the passkey")
			return
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			passkeyJSONError(w, http.StatusConflict, fmt.Sprintf("you already have %d passkeys; remove one first", passkeyMaxPerUser))
			return
		}
		id, _ := res.LastInsertId()
		if err := auditAccountEvent(tx, app, accountAuditPasskeyAdded, strconv.FormatInt(id, 10), sess, nil, map[string]any{"name": name}); err != nil {
			passkeyServerError(w, r, app, err, "could not save the passkey")
			return
		}
		if err := tx.Commit(); err != nil {
			passkeyServerError(w, r, app, err, "could not save the passkey")
			return
		}
		httpJSON(w, http.StatusOK, map[string]any{"ok": true, "passkey": map[string]any{"id": id, "name": name}})
	}
}

func passkeyList(app *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !passkeysEnabled(app) {
			http.NotFound(w, r)
			return
		}
		sess := getSession(app, r)
		if sess == nil || sess.UserID <= 0 {
			passkeyJSONError(w, http.StatusUnauthorized, "sign in first")
			return
		}
		// The account's sign-in keys, like its sessions and tokens: a scoped
		// credential lists none of them (changes already need a direct
		// sign-in). The embedded dashboard's own browser session keeps its
		// profile page's list (platformPageSession: a marker, not app scopes).
		if !platformPageSession(app, sess) && !requireAccountManagement(w, sess) {
			return
		}
		rows, err := queryMetadataRows(app.DB, `SELECT id, name, created_at, last_used_at FROM _benmore_passkeys WHERE user_id = ? ORDER BY id`, sess.UserID)
		if err != nil {
			rows = []map[string]any{}
		}
		httpJSON(w, http.StatusOK, map[string]any{"passkeys": rows})
	}
}

func passkeyDelete(app *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := passkeyCredentialChange(w, r, app)
		if sess == nil {
			return
		}
		id, err := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err != nil {
			passkeyJSONError(w, http.StatusNotFound, "passkey not found")
			return
		}
		tx, err := app.DB.Begin()
		if err != nil {
			passkeyServerError(w, r, app, err, "could not remove the passkey")
			return
		}
		defer tx.Rollback()
		res, err := tx.Exec(`DELETE FROM _benmore_passkeys WHERE id = ? AND user_id = ?`, id, sess.UserID)
		if err != nil {
			passkeyServerError(w, r, app, err, "could not remove the passkey")
			return
		}
		if n, _ := res.RowsAffected(); n != 1 {
			passkeyJSONError(w, http.StatusNotFound, "passkey not found")
			return
		}
		if err = auditAccountEvent(tx, app, accountAuditPasskeyRemoved, strconv.FormatInt(id, 10), sess, nil, nil); err == nil {
			err = tx.Commit()
		}
		if err != nil {
			passkeyServerError(w, r, app, err, "could not remove the passkey")
			return
		}
		httpJSON(w, http.StatusOK, map[string]any{"ok": true})
	}
}

// passkeyDeleteAll removes every passkey of the caller: the "sign out every
// passkey" control for someone who suspects a key was added without them.
func passkeyDeleteAll(app *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess := passkeyCredentialChange(w, r, app)
		if sess == nil {
			return
		}
		tx, err := app.DB.Begin()
		if err != nil {
			passkeyServerError(w, r, app, err, "could not remove passkeys")
			return
		}
		defer tx.Rollback()
		n, err := revokeAccountPasskeys(tx, sess.UserID)
		if err == nil {
			err = auditAccountEvent(tx, app, accountAuditPasskeysRemovedAll, "", sess, nil, map[string]any{"removed": n})
		}
		if err == nil {
			err = tx.Commit()
		}
		if err != nil {
			passkeyServerError(w, r, app, err, "could not remove passkeys")
			return
		}
		httpJSON(w, http.StatusOK, map[string]any{"ok": true, "removed": n})
	}
}

func passkeyLoginOptions(app *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !passkeysEnabled(app) {
			http.NotFound(w, r)
			return
		}
		if !validateCSRF(r) {
			passkeyJSONError(w, http.StatusForbidden, "missing or expired CSRF token")
			return
		}
		challenge, err := newPasskeyChallenge(w, r, app, "login", 0)
		if err != nil {
			passkeyServerError(w, r, app, err, "could not start passkey sign-in")
			return
		}
		rpID, _ := passkeyRP(r)
		httpJSON(w, http.StatusOK, map[string]any{
			"challenge":        b64urlEncode(challenge),
			"rpId":             rpID,
			"timeout":          passkeyChallengeTTL * 1000,
			"userVerification": "required",
			"allowCredentials": []any{},
		})
	}
}

var errPasskeySignIn = errors.New("passkey sign-in failed")

func passkeyLogin(app *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !passkeysEnabled(app) {
			http.NotFound(w, r)
			return
		}
		if !validateCSRF(r) {
			passkeyJSONError(w, http.StatusForbidden, "missing or expired CSRF token")
			return
		}
		ip := clientIP(r)
		ipKey := authIPLockKey(ip)
		if authIsIPLocked(app.DB, ip) {
			passkeyJSONError(w, http.StatusTooManyRequests, "Too many failed attempts from this network. Try again in 15 minutes.")
			return
		}
		challenge, ok := takePasskeyChallenge(w, r, app, "login", 0)
		if !ok {
			passkeyJSONError(w, http.StatusBadRequest, "passkey sign-in expired; try again")
			return
		}
		body, ok := decodePasskeyCredential(w, r)
		if !ok {
			return
		}
		fail := func() {
			recordLoginAttempt(app.DB, ipKey, false)
			passkeyJSONError(w, http.StatusUnauthorized, errPasskeySignIn.Error())
		}
		rawID, err := b64url(body.RawID)
		clientData, err2 := b64url(body.Response.ClientDataJSON)
		authData, err3 := b64url(body.Response.AuthenticatorData)
		sig, err4 := b64url(body.Response.Signature)
		if err != nil || err2 != nil || err3 != nil || err4 != nil {
			fail()
			return
		}
		var (
			pkID, userID int64
			publicKey    []byte
			signCount    int64
			storedHandle string
		)
		if err := app.DB.QueryRow(`SELECT id, user_id, public_key, sign_count, COALESCE(user_handle, '') FROM _benmore_passkeys WHERE credential_id = ?`,
			b64urlEncode(rawID)).Scan(&pkID, &userID, &publicKey, &signCount, &storedHandle); err != nil {
			fail()
			return
		}
		if signCount < 0 || signCount > int64(^uint32(0)) {
			fail()
			return
		}
		if body.Response.UserHandle != "" {
			userHandle, err := b64url(body.Response.UserHandle)
			want := passkeyUserHandle(app, userID)
			if storedHandle != "" {
				want = []byte(storedHandle)
			}
			if err != nil || subtle.ConstantTimeCompare(userHandle, want) != 1 {
				fail()
				return
			}
		}
		rpID, origin := passkeyRP(r)
		newCount, err := verifyWebAuthnAssertion(clientData, authData, sig, publicKey, challenge, rpID, origin, uint32(signCount))
		if err != nil {
			fail()
			return
		}
		var email, loginValue string
		var deactivated sql.NullString
		var pendingPasswordChange, verified int
		identifier := authIdentifier(app)
		query := `SELECT COALESCE(email, ''), deactivated_at, COALESCE(password_change_required,0), COALESCE(verified,0), COALESCE(` + quoteIdent(identifier) + `,'') FROM _benmore_users WHERE id = ?`
		if err := app.DB.QueryRow(query, userID).Scan(&email, &deactivated, &pendingPasswordChange, &verified, &loginValue); err != nil ||
			accountDeactivated(deactivated) {
			fail()
			return
		}
		if pendingPasswordChange != 0 {
			passkeyJSONError(w, http.StatusForbidden, "password_change_required")
			return
		}
		if app.Design != nil && app.Design.Auth["require_verified"] == "true" && verified == 0 {
			passkeyJSONError(w, http.StatusForbidden, "email_verification_required")
			return
		}
		if email != "" {
			if allowed, reason := emailAllowedForApp(app, email); !allowed {
				passkeyJSONError(w, http.StatusForbidden, reason)
				return
			}
		}
		if _, stop := grandfatheredSignInNeedsProof(app, r, userID); stop {
			passkeyJSONError(w, http.StatusForbidden, grandfatheredVerifyMessage)
			return
		}
		// Resolved before the transaction: it reads through the pool.
		groupID := ResolveGroupID(app.DB, app.Group, email)
		tx, err := app.DB.Begin()
		if err != nil {
			fail()
			return
		}
		defer tx.Rollback()
		requireVerified := 0
		if app.Design != nil && app.Design.Auth["require_verified"] == "true" {
			requireVerified = 1
		}
		res, err := tx.Exec(`UPDATE _benmore_passkeys SET sign_count=?,last_used_at=datetime('now')
			WHERE id=? AND sign_count=? AND EXISTS (SELECT 1 FROM _benmore_users u WHERE u.id=?
			AND `+accountActiveSQL("u")+` AND COALESCE(u.password_change_required,0)=0
			AND COALESCE(u.email,'')=? AND (?=0 OR COALESCE(u.verified,0)<>0))`,
			int64(newCount), pkID, signCount, userID, email, requireVerified)
		if err != nil {
			fail()
			return
		}
		if n, err := res.RowsAffected(); err != nil || n != 1 {
			fail()
			return
		}
		if _, err := tx.Exec(`UPDATE _benmore_users SET last_login_at=datetime('now') WHERE id=? AND `+accountActiveSQL("")+` AND COALESCE(password_change_required,0)=0`, userID); err != nil {
			fail()
			return
		}
		// When the ceremony ends in a session (no auth.otp step, no enrollment
		// due) the session is written in this transaction, behind the
		// sign_count compare-and-swap. It used to be inserted after the commit,
		// so a password reset (which deletes the passkeys and revokes every
		// session) landing in between left a session behind.
		var sessionID string
		if !otpLoginEnabled(app) {
			needsEnrollment, err := needsMFAEnrollmentWith(app, tx, userID)
			if err != nil {
				fail()
				return
			}
			if !needsEnrollment {
				if sessionID, err = createSignInSessionTx(tx, userID, email, groupID, app.SessionDuration); err != nil {
					fail()
					return
				}
			}
		}
		if err := tx.Commit(); err != nil {
			fail()
			return
		}
		recordLoginAttempt(app.DB, ipKey, true)
		FireUserHooks(app, "update", userID)

		// auth.otp is a distinct proof step from the passkey ceremony. It must
		// still be completed before a session is issued.
		if otpLoginEnabled(app) {
			startLoginOTP(w, r, app, userID, email, loginValue)
			return
		}
		// A passkey stands in for the TOTP step of an enrolled account, but
		// does not enroll one: an account whose role is listed in
		// auth.require_mfa_for_roles and has no factor gets the setup grant a
		// password or social sign-in gets, never a session (the transaction
		// above wrote none).
		if sessionID == "" {
			token := mintMFASetupToken(app, userID, email)
			if token == "" {
				passkeyJSONError(w, http.StatusUnauthorized, "credentials changed; sign in again")
				return
			}
			setFlowCookie(w, flowCookieMFASetup, token, !app.DevMode, int(mfaSetupTokenTTL.Seconds()))
			httpJSON(w, http.StatusOK, map[string]any{"mfa_setup_required": true, "redirect": mfaSetupPagePath(app)})
			return
		}

		AttachSessionContext(app.DB, sessionID, r)
		http.SetCookie(w, sessionCookie(sessionID, app.DevMode, app.SessionDuration))
		redirectTo := "/"
		if app.Design != nil {
			if rd := app.Design.Auth["redirect"]; rd != "" {
				redirectTo = rd
			}
		}
		httpJSON(w, http.StatusOK, map[string]any{"ok": true, "user": loadUserForJSON(app, userID), "redirect": redirectTo})
	}
}
