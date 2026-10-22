//go:build !cli

package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Nothing bounded how many API tokens one account could mint. A signed-in
// account (a script holding its session) could add rows until the app's
// database reached its storage ceiling and every other user's writes failed.
func TestAPITokensPerAccountAreCapped(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	app := &App{Dir: dir, DB: db, Stop: make(chan struct{}), SessionDuration: time.Hour}
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureAPITokensTable(db)
	appOAuthEnsureTables(app)
	mustExec(t, db, `INSERT INTO _benmore_users (id, username, email, verified) VALUES (1, 'alice', 'alice@example.com', 1), (2, 'bob', 'bob@example.com', 1)`)
	mustExec(t, db, `INSERT INTO _benmore_oauth_clients (client_id, name, redirect_uris, scopes) VALUES ('app_test1', 'Assistant', '["https://client.example/cb"]', '*')`)

	future := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-24 * time.Hour).UTC().Format(time.RFC3339)
	// One short of the cap, half of them with an expiry still ahead; expired
	// rows waiting for the sweep do not count.
	for i := 0; i < maxAPITokensPerUser-1; i++ {
		var expires any
		if i%2 == 0 {
			expires = future
		}
		mustExecArgs(t, db, `INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes, expires_at) VALUES (1, 'seed', ?, '*', ?)`, fmt.Sprintf("live-%d", i), expires)
	}
	for i := 0; i < 30; i++ {
		mustExecArgs(t, db, `INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes, expires_at) VALUES (1, 'old', ?, '*', ?)`, fmt.Sprintf("expired-%d", i), past)
	}
	live := func(uid int64) int {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM _benmore_api_tokens WHERE user_id = ? AND (expires_at IS NULL OR datetime(expires_at) > datetime('now'))`, uid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	create := func(uid int64, email string) *httptest.ResponseRecorder {
		token := CreateSession(db, uid, email, "", time.Hour)
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/api-tokens", strings.NewReader(`{"name":"ci","scopes":"*"}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", authMintCSRFToken(token))
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
		w := httptest.NewRecorder()
		handleCreateAPIToken(w, r, app)
		return w
	}
	exchange := func(uid int64, code string) *httptest.ResponseRecorder {
		verifier := "test-verifier-string-with-enough-entropy-123456"
		sum := sha256.Sum256([]byte(verifier))
		mustExecArgs(t, db, `INSERT INTO _benmore_oauth_codes
			(client_id, user_id, code, code_challenge, code_challenge_method, redirect_uri, resource, scopes, expires_at)
			VALUES ('app_test1', ?, ?, ?, 'S256', 'https://client.example/cb', '', '*', ?)`,
			uid, hashAPIToken(code), base64.RawURLEncoding.EncodeToString(sum[:]), time.Now().Add(5*time.Minute).UTC().Format(time.RFC3339))
		form := url.Values{"grant_type": {"authorization_code"}, "code": {code}, "client_id": {"app_test1"},
			"redirect_uri": {"https://client.example/cb"}, "code_verifier": {verifier}}
		r := httptest.NewRequest(http.MethodPost, "https://app.example.test/oauth/token", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		w := httptest.NewRecorder()
		appOAuthToken(w, r, app)
		return w
	}

	if w := create(1, "alice@example.com"); w.Code != http.StatusOK || live(1) != maxAPITokensPerUser {
		t.Fatalf("the token that reaches the cap: %d %s (%d live)", w.Code, w.Body.String(), live(1))
	}
	if w := create(1, "alice@example.com"); w.Code != http.StatusConflict || !strings.Contains(w.Body.String(), "api_token_limit") {
		t.Errorf("a token past the cap: %d %s", w.Code, w.Body.String())
	}
	// A token an OAuth client is issued counts against the same cap; the
	// code is spent either way.
	if w := exchange(1, "code-over"); w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "access_denied") {
		t.Errorf("an OAuth token past the cap: %d %s", w.Code, w.Body.String())
	}
	var codes int
	db.QueryRow(`SELECT COUNT(*) FROM _benmore_oauth_codes`).Scan(&codes)
	if codes != 0 {
		t.Errorf("the refused exchange left its code usable")
	}
	if n := live(1); n != maxAPITokensPerUser {
		t.Fatalf("the account holds %d live tokens, cap %d", n, maxAPITokensPerUser)
	}

	// Another account is not affected, and revoking one makes room.
	if w := create(2, "bob@example.com"); w.Code != http.StatusOK {
		t.Errorf("another account was refused: %d %s", w.Code, w.Body.String())
	}
	if w := exchange(2, "code-bob"); w.Code != http.StatusOK {
		t.Errorf("another account's OAuth exchange was refused: %d %s", w.Code, w.Body.String())
	}
	mustExec(t, db, `DELETE FROM _benmore_api_tokens WHERE token_hash = 'live-0'`)
	if w := exchange(1, "code-room"); w.Code != http.StatusOK || live(1) != maxAPITokensPerUser {
		t.Errorf("after a revocation the exchange: %d %s (%d live)", w.Code, w.Body.String(), live(1))
	}
	// GetSessionFromAPIToken-style background writes are not in play here,
	// but the token list must still answer at the cap.
	if n := live(2); n != 2 {
		t.Errorf("the other account holds %d tokens, want 2", n)
	}
}
