//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func ipv6LockoutApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	app := &App{Dir: dir, DB: db}
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureLoginAttemptsTable(db)
	EnsureAPITokensTable(db)
	EnsureMFAColumns(db)
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}
	app.SessionDuration = time.Hour
	return app
}

// The per-IP failed sign-in cap stops a spray that rotates the account on
// every request. An IPv6 client is routinely handed a whole /64, so keying the
// cap on the full address let it pick a fresh address per guess and never
// reach the cap.
func TestSignInIPLockCountsIPv6ByPrefix(t *testing.T) {
	app := ipv6LockoutApp(t)
	hash, err := generateBcryptHash([]byte("Spray!Target1"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, verified) VALUES ('target', 'target@example.com', ?, 1)", string(hash)); err != nil {
		t.Fatal(err)
	}
	exchange := func(ip, email, password string) int {
		body, _ := json.Marshal(map[string]string{"email": email, "password": password})
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/token", strings.NewReader(string(body)))
		r.RemoteAddr = net.JoinHostPort(ip, "4000")
		w := httptest.NewRecorder()
		handleTokenAuth(w, r, app)
		return w.Code
	}
	// A spray: one failed guess per account, each from a fresh address in
	// one /64, so no per-account lock is involved. The first goes through
	// the handler; the rest are recorded the way it records them.
	if code := exchange("2001:db8:5:6::1", "nobody@example.com", "Wrong!Guess1"); code != http.StatusUnauthorized {
		t.Fatalf("first guess: %d", code)
	}
	for i := 2; i <= authIPLoginLimit; i++ {
		recordLoginAttempt(app.DB, authIPLockKey("2001:db8:5:6::"+itoa4(i)), false)
	}
	if code := exchange("2001:db8:5:6::ffff", "target@example.com", "Spray!Target1"); code != http.StatusTooManyRequests {
		t.Fatalf("a fresh address in the same /64 was not held to the network's cap: %d", code)
	}
	if code := exchange("2001:db8:5:7::1", "target@example.com", "Spray!Target1"); code != http.StatusOK {
		t.Fatalf("control from another /64: %d", code)
	}
	if authIPLockKey("2001:db8:5:6::1") != authIPLockKey("2001:db8:5:6:aaaa:bbbb:cccc:dddd") {
		t.Fatal("two addresses of one /64 have different lock keys")
	}
	if authIPLockKey("192.0.2.1") == authIPLockKey("192.0.2.2") {
		t.Fatal("IPv4 addresses must stay separate")
	}
}

func itoa4(n int) string {
	const digits = "0123456789abcdef"
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%16]}, b...)
		n /= 16
	}
	return string(b)
}
