//go:build !cli

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// The session table must not hold usable credentials: a backup, the SQL
// console or query_db reading _benmore_sessions (or the audit rows and
// impersonation records that name a session) must not yield a live login.
func TestSessionIDsAreStoredHashed(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	mux := http.NewServeMux()
	RegisterAuthRoutes(mux, app)
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	seed := func(email, role string) int64 {
		res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES (?, ?, ?, ?, 1)", strings.Split(email, "@")[0], email, string(hash), role)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	uid := seed("member@example.com", "user")
	adminID := seed("admin@example.com", "admin")

	call := func(method, path, token string, bearer bool, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json")
		if bearer {
			r.Header.Set("Authorization", "Bearer "+token)
		} else if token != "" {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
			r.Header.Set("X-CSRF-Token", authMintCSRFToken(token))
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	signedInAs := func(token string, bearer bool) string {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		if bearer {
			r.Header.Set("Authorization", "Bearer "+token)
		} else {
			r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		}
		if s := getSession(app, r); s != nil {
			return s.Email
		}
		return ""
	}
	// assertNoCredentialAtRest fails if any stored session column still
	// holds a working token.
	assertNoCredentialAtRest := func(tokens ...string) {
		t.Helper()
		for _, tok := range tokens {
			var n int
			app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE id=? OR impersonator_session_id=?", tok, tok).Scan(&n)
			var audit int
			app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_audit_log WHERE row_id=?", tok).Scan(&audit)
			if n != 0 || audit != 0 {
				t.Fatalf("session token stored in the clear (sessions=%d audit=%d)", n, audit)
			}
		}
	}

	// New sessions: the row holds only the token's hash.
	token := CreateSession(app.DB, uid, "member@example.com", "", time.Hour)
	var stored string
	if err := app.DB.QueryRow("SELECT id FROM _benmore_sessions WHERE user_id=?", uid).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if stored == token || stored != sessionStorageKey(token) {
		t.Fatalf("session row id = %q, want the token's SHA-256 key", stored)
	}
	assertNoCredentialAtRest(token)
	if got := signedInAs(token, false); got != "member@example.com" {
		t.Fatalf("cookie token did not authenticate: %q", got)
	}
	if got := signedInAs(token, true); got != "member@example.com" {
		t.Fatalf("bearer token did not authenticate: %q", got)
	}
	// What a database reader sees is not a credential, with or without the
	// prefix.
	for _, leaked := range []string{stored, strings.TrimPrefix(stored, sessionKeyPrefix)} {
		if got := signedInAs(leaked, false); got != "" {
			t.Fatalf("stored id %q authenticated as %q", leaked, got)
		}
		if got := signedInAs(leaked, true); got != "" {
			t.Fatalf("stored id %q authenticated over bearer as %q", leaked, got)
		}
	}

	// The session list keeps its short id: the first 12 hex digits of the
	// token's SHA-256, the same value clients held before hashing.
	sum := sha256.Sum256([]byte(token))
	wantOpaque := hex.EncodeToString(sum[:])[:12]
	w := call(http.MethodGet, "/api/_auth/sessions", token, false, "")
	var listed struct {
		Sessions []map[string]any `json:"sessions"`
	}
	json.Unmarshal(w.Body.Bytes(), &listed)
	if w.Code != http.StatusOK || len(listed.Sessions) != 1 || listed.Sessions[0]["id"] != wantOpaque || listed.Sessions[0]["current"] != true {
		t.Fatalf("session list = %d %s, want id %s marked current", w.Code, w.Body.String(), wantOpaque)
	}
	second := CreateSession(app.DB, uid, "member@example.com", "", time.Hour)
	sum2 := sha256.Sum256([]byte(second))
	if w := call(http.MethodDelete, "/api/_auth/sessions/"+hex.EncodeToString(sum2[:])[:12], token, false, ""); w.Code != http.StatusOK {
		t.Fatalf("revoke by listed id = %d %s", w.Code, w.Body.String())
	}
	if signedInAs(second, false) != "" {
		t.Fatal("revoked session still authenticates")
	}

	// Logout removes the hashed row.
	if w := call(http.MethodPost, app.Paths.Logout, token, false, ""); w.Code >= 400 {
		t.Fatalf("logout = %d %s", w.Code, w.Body.String())
	}
	if signedInAs(token, false) != "" {
		t.Fatal("session survived logout")
	}

	// Impersonation records the admin session by key, and ending it hands
	// the admin a working session again without any raw id at rest.
	adminToken := CreateSession(app.DB, adminID, "admin@example.com", "", time.Hour)
	w = call(http.MethodPost, "/api/_auth/impersonate", adminToken, false, `{"user_id":`+jsonInt(uid)+`,"password":"`+fixturePassword+`"}`)
	if w.Code != http.StatusOK {
		t.Fatalf("impersonate = %d %s", w.Code, w.Body.String())
	}
	var started map[string]any
	json.Unmarshal(w.Body.Bytes(), &started)
	impToken, _ := started["token"].(string)
	var impersonator string
	app.DB.QueryRow("SELECT impersonator_session_id FROM _benmore_sessions WHERE id=?", sessionStorageKey(impToken)).Scan(&impersonator)
	if impersonator != sessionStorageKey(adminToken) {
		t.Fatalf("impersonation row names admin session %q, want its key", impersonator)
	}
	assertNoCredentialAtRest(adminToken, impToken)
	// An impersonation past its expiry can't hand the admin session back,
	// even before the cleanup sweep deletes the row.
	var impExpiry string
	app.DB.QueryRow("SELECT expires_at FROM _benmore_sessions WHERE id=?", sessionStorageKey(impToken)).Scan(&impExpiry)
	auditExec(t, app.DB, "UPDATE _benmore_sessions SET expires_at=datetime('now','-1 minute') WHERE id=?", sessionStorageKey(impToken))
	if w := call(http.MethodPost, "/api/_auth/end-impersonation", impToken, false, ""); w.Code == http.StatusOK {
		t.Fatalf("expired impersonation restored the admin session: %s", w.Body.String())
	}
	auditExec(t, app.DB, "UPDATE _benmore_sessions SET expires_at=? WHERE id=?", impExpiry, sessionStorageKey(impToken))
	w = call(http.MethodPost, "/api/_auth/end-impersonation", impToken, false, "")
	if w.Code != http.StatusOK {
		t.Fatalf("end impersonation = %d %s", w.Code, w.Body.String())
	}
	var restored string
	for _, c := range w.Result().Cookies() {
		// A plain-HTTP request gets the unprefixed development name.
		if c.Name == sessionCookieNameFor(false) {
			restored = c.Value
		}
	}
	if restored == "" || signedInAs(restored, false) != "admin@example.com" {
		t.Fatalf("restored admin cookie %q does not authenticate", restored)
	}
	if signedInAs(impToken, false) != "" {
		t.Fatal("impersonation session survived its end")
	}
	if w := call(http.MethodPost, "/api/_auth/end-impersonation", impToken, false, ""); w.Code == http.StatusOK {
		t.Fatalf("ended impersonation restored twice: %s", w.Body.String())
	}
	assertNoCredentialAtRest(restored)
}

// Rows written before hashing (or by an older process sharing the database)
// keep working: startup rekeys them along with every reference, and a row
// that appears later is rekeyed on first use.
func TestLegacySessionIDsAreRekeyedWithoutSignOut(t *testing.T) {
	app, _ := auditApp(t)
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES ('legacy', 'legacy@example.com', ?, 'user', 1)", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	const adminRaw, impRaw = "legacy-admin-token", "legacy-impersonation-token"
	auditExec(t, app.DB, "INSERT INTO _benmore_sessions (id, user_id, email, expires_at) VALUES (?, ?, 'legacy@example.com', ?)", adminRaw, uid, expires)
	auditExec(t, app.DB, "INSERT INTO _benmore_sessions (id, user_id, email, expires_at, is_impersonation, impersonator_session_id) VALUES (?, ?, 'legacy@example.com', ?, 1, ?)", impRaw, uid, expires, adminRaw)
	auditExec(t, app.DB, "INSERT INTO _benmore_audit_log (action, table_name, row_id) VALUES ('act_as_start', '_benmore_sessions', ?)", adminRaw)
	// A dead reference (its admin session already gone) is hashed too.
	auditExec(t, app.DB, "UPDATE _benmore_sessions SET impersonator_session_id='expired-admin-token' WHERE id=?", impRaw)
	auditExec(t, app.DB, "INSERT INTO _benmore_sessions (id, user_id, email, expires_at, is_impersonation, impersonator_session_id) VALUES ('legacy-second-imp', ?, 'legacy@example.com', ?, 1, ?)", uid, expires, adminRaw)

	EnsureSessionsTable(app.DB)
	EnsureSessionsTable(app.DB) // idempotent: an already-hashed id is never hashed again

	for _, raw := range []string{adminRaw, impRaw, "legacy-second-imp", "expired-admin-token"} {
		var n int
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE id=? OR impersonator_session_id=?", raw, raw).Scan(&n)
		var audit int
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_audit_log WHERE row_id=?", raw).Scan(&audit)
		if n != 0 || audit != 0 {
			t.Fatalf("raw id %q still stored after startup (sessions=%d audit=%d)", raw, n, audit)
		}
	}
	var ref, auditRef string
	app.DB.QueryRow("SELECT impersonator_session_id FROM _benmore_sessions WHERE id=?", sessionStorageKey("legacy-second-imp")).Scan(&ref)
	app.DB.QueryRow("SELECT row_id FROM _benmore_audit_log WHERE action='act_as_start'").Scan(&auditRef)
	if ref != sessionStorageKey(adminRaw) || auditRef != sessionStorageKey(adminRaw) {
		t.Fatalf("references not rekeyed with their session: impersonator=%q audit=%q", ref, auditRef)
	}
	if s := GetSessionFromDB(app.DB, adminRaw); s == nil || s.ID != sessionStorageKey(adminRaw) {
		t.Fatalf("legacy token no longer signs in after startup: %+v", s)
	}

	// A raw row written after startup still signs in, and is rekeyed then.
	const straggler = "written-by-an-older-process"
	auditExec(t, app.DB, "INSERT INTO _benmore_sessions (id, user_id, email, expires_at) VALUES (?, ?, 'legacy@example.com', ?)", straggler, uid, expires)
	s := GetSessionFromDB(app.DB, straggler)
	if s == nil || s.ID != sessionStorageKey(straggler) {
		t.Fatalf("straggler session = %+v, want it found and rekeyed", s)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE id=?", straggler).Scan(&n)
	if n != 0 {
		t.Fatal("straggler row kept its raw id after use")
	}
	if GetSessionFromDB(app.DB, straggler) == nil {
		t.Fatal("straggler session lost after rekey")
	}
}

func jsonInt(n int64) string {
	b, _ := json.Marshal(n)
	return string(b)
}
