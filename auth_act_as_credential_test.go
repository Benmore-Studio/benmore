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
)

func actAsCredentialApp(t *testing.T) (*App, *http.ServeMux) {
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
	EnsureAuditLogTable(db)
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE members (id INTEGER PRIMARY KEY, org_id INTEGER, user_id INTEGER)"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO members (org_id, user_id) VALUES (7, 900)"); err != nil {
		t.Fatal(err)
	}
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "user_id"}
	app.Paths = DiscoverAuthPaths(nil)
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}
	app.SessionDuration = time.Hour
	mux := http.NewServeMux()
	registerAuthRoutes(mux, app)
	return app, mux
}

// Step-in is stored on the session row. An API token (or an edge identity)
// has no row, so the UPDATE matched nothing, yet the endpoint answered
// "acting_as": a tool that stepped in to work as one tenant kept the
// cross-tenant bypass and read or wrote every tenant's rows.
func TestActAsRefusesCredentialsWithoutASessionRow(t *testing.T) {
	app, mux := actAsCredentialApp(t)
	hash, err := generateBcryptHash([]byte("Admin!Pass1"))
	if err != nil {
		t.Fatal(err)
	}
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES ('boss', 'boss@example.com', ?, 'admin', 1)", string(hash))
	if err != nil {
		t.Fatal(err)
	}
	adminID, _ := res.LastInsertId()
	apiToken := "bmr_" + generateToken(32)
	if _, err := app.DB.Exec("INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES (?, 'tool', ?, '*')", adminID, hashToken(apiToken)); err != nil {
		t.Fatal(err)
	}
	stepIn := func(bearer string) (int, map[string]any) {
		body, _ := json.Marshal(map[string]string{"group_id": "7", "password": "Admin!Pass1"})
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/act_as", strings.NewReader(string(body)))
		r.Header.Set("Authorization", "Bearer "+bearer)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		var out map[string]any
		_ = json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	bypassAfter := func(bearer string) bool {
		r := httptest.NewRequest(http.MethodGet, "/api/_auth/act_as", nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		s := getSession(app, r)
		return s != nil && s.IsAdminBypass()
	}

	code, out := stepIn(apiToken)
	if code == http.StatusOK || out["status"] == "acting_as" {
		t.Fatalf("an API token was told it stepped in (%d %v)", code, out)
	}
	if !bypassAfter(apiToken) {
		t.Fatal("fixture: the API token should still be an admin bypass")
	}
	var audited int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'act_as_start'").Scan(&audited)
	if audited != 0 {
		t.Fatal("a step-in that did not happen was audited as started")
	}

	// Control: a session token (cookie or Bearer) holds act-as.
	sessionToken := CreateSession(app.DB, adminID, "boss@example.com", "", time.Hour)
	if code, out := stepIn(sessionToken); code != http.StatusOK || out["status"] != "acting_as" {
		t.Fatalf("session token step-in: %d %v", code, out)
	}
	if bypassAfter(sessionToken) {
		t.Fatal("a stepped-in session still bypasses tenant scoping")
	}
}
