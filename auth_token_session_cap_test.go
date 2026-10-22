//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// POST /api/_auth/token leaves a session row behind on every call, each
// good for the app's whole session lifetime. A client that signs in again
// instead of keeping its token (or anyone holding the password) grew the
// account's sessions without bound. The exchange still always answers; the
// account's oldest token-exchange sessions beyond the cap end.
func TestTokenExchangeSessionsPerAccountAreCapped(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	app := &App{Dir: dir, DB: db, Stop: make(chan struct{}), SessionDuration: time.Hour, Paths: DiscoverAuthPaths(nil)}
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureLoginAttemptsTable(db)
	EnsureAuditLogTable(db)
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	mustExecArgs(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash, verified) VALUES
		(1, 'worker', 'worker@example.com', ?, 1), (2, 'other', 'other@example.com', ?, 1), (3, 'desk', 'desk@example.com', ?, 1)`, string(hash), string(hash), string(hash))
	mustExec(t, db, `UPDATE _benmore_users SET role = 'admin' WHERE id = 3`)

	expires := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	seed := func(key string, uid int64, created string, loginAt int64, impersonation int, scopes string) {
		t.Helper()
		mustExecArgs(t, db, `INSERT INTO _benmore_sessions (id, user_id, email, expires_at, created_at, login_at, is_impersonation, impersonator_user_id, scopes)
			VALUES (?, ?, 'x@example.com', ?, ?, ?, ?, ?, ?)`, sessionStorageKey(key), uid, expires, created, loginAt, impersonation, 3*impersonation, scopes)
	}
	// One short of the cap from earlier exchanges, the first of them the oldest.
	seed("exchange-oldest", 1, "2026-01-01 00:00:00", 0, 0, "")
	for i := 1; i < maxTokenSessionsPerUser-1; i++ {
		seed("exchange-"+time.Duration(i).String(), 1, "2026-01-02 00:00:00", 0, 0, "notes:read")
	}
	// Older than all of them, and none of them a token-exchange session: the
	// person's own sign-ins, a support session, a dashboard embed.
	seed("browser-1", 1, "2025-06-01 00:00:00", 1750000000, 0, "")
	seed("browser-2", 1, "2025-06-02 00:00:00", 1750000001, 0, "")
	seed("support", 1, "2025-06-03 00:00:00", 0, 1, "")
	seed("embed", 1, "2025-06-04 00:00:00", 0, 0, "embed")
	seed("others-exchange", 2, "2025-01-01 00:00:00", 0, 0, "")

	exchangeSessions := func(uid int64) int {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM _benmore_sessions WHERE user_id = ? AND COALESCE(login_at, 0) = 0
			AND COALESCE(is_impersonation, 0) = 0 AND COALESCE(scopes, '') <> 'embed'`, uid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	exists := func(key string) bool {
		t.Helper()
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM _benmore_sessions WHERE id = ?`, sessionStorageKey(key)).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n == 1
	}
	exchange := func() string {
		t.Helper()
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/token", strings.NewReader(`{"email":"worker@example.com","password":"`+fixturePassword+`"}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		handleTokenAuth(w, r, app)
		var out struct {
			Token string `json:"token"`
		}
		if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &out) != nil || out.Token == "" {
			t.Fatalf("token exchange: %d %s", w.Code, w.Body.String())
		}
		return out.Token
	}

	first := exchange()
	if n := exchangeSessions(1); n != maxTokenSessionsPerUser {
		t.Fatalf("at the cap the account holds %d token-exchange sessions, want %d", n, maxTokenSessionsPerUser)
	}
	if !exists("exchange-oldest") {
		t.Fatal("a session was ended before the cap was passed")
	}
	second := exchange()
	if n := exchangeSessions(1); n != maxTokenSessionsPerUser {
		t.Errorf("past the cap the account holds %d token-exchange sessions, want %d", n, maxTokenSessionsPerUser)
	}
	if exists("exchange-oldest") {
		t.Error("the oldest token-exchange session outlived the cap")
	}
	for _, token := range []string{first, second} {
		if GetSessionFromDB(db, token) == nil {
			t.Error("a session just issued by the exchange does not resolve")
		}
	}
	for _, kept := range []string{"browser-1", "browser-2", "support", "embed", "others-exchange"} {
		if !exists(kept) {
			t.Errorf("the cap ended %q, which is not one of the account's token-exchange sessions", kept)
		}
	}
}
