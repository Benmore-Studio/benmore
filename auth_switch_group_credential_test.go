//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// POST /api/_switch_group stores the chosen tenant on the session row. An API
// token has no row, so the UPDATE matched nothing and the endpoint still
// answered with its success redirect; the token kept resolving to the
// member's oldest tenant, and a script that "switched" to tenant B before
// writing put its rows into tenant A, where A's members read them.
func TestSwitchGroupRefusesCredentialsWithoutASessionRow(t *testing.T) {
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
	EnsureAPITokensTable(db)
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, "CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, user_id INTEGER)")
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "user_id"}
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}
	app.SessionDuration = time.Hour
	res, err := db.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('m', 'm@example.com', 'user', 1)")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	mustExec(t, db, "INSERT INTO members (org_id, user_id) VALUES ('tenant-a', "+itoaInt(uid)+"), ('tenant-b', "+itoaInt(uid)+")")
	apiToken := "bmr_" + generateToken(32)
	if _, err := db.Exec("INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES (?, 'script', ?, '*')", uid, hashToken(apiToken)); err != nil {
		t.Fatal(err)
	}
	switchTo := func(bearer, group string) int {
		form := url.Values{"group_id": {group}, "_csrf": {authMintCSRFToken("")}}
		r := httptest.NewRequest(http.MethodPost, "/api/_switch_group", strings.NewReader(form.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		handleSwitchGroup(w, r, app)
		return w.Code
	}
	tenant := func(bearer string) string {
		r := httptest.NewRequest(http.MethodGet, "/api/notes", nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		if s := getSession(app, r); s != nil {
			return s.EffectiveGroupID()
		}
		return "?"
	}

	if code := switchTo(apiToken, "tenant-b"); code < 400 {
		t.Fatalf("an API token was told it switched tenant (%d) while it still resolves to %q", code, tenant(apiToken))
	}

	// Control: a session token switches.
	sessionToken := CreateSession(db, uid, "m@example.com", "tenant-a", time.Hour)
	if code := switchTo(sessionToken, "tenant-b"); code != http.StatusSeeOther {
		t.Fatalf("session switch: %d", code)
	}
	if got := tenant(sessionToken); got != "tenant-b" {
		t.Fatalf("session tenant after switch = %q", got)
	}
}

func itoaInt(n int64) string {
	const digits = "0123456789"
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{digits[n%10]}, b...)
		n /= 10
	}
	return string(b)
}
