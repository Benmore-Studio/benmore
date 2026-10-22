//go:build !cli && !windows

package main

import (
	"database/sql"
	"github.com/mattn/go-sqlite3"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestAppMCPPrivateReadRetainsOriginalGrantAuthority(t *testing.T) {
	app, uid, _ := appMCPGrantFixture(t)
	now := time.Now()
	pair := fixtureGrant(t, app, uid, now)
	source := httptest.NewRequest(http.MethodGet, "/api/notes", nil)
	source.Header.Set("Cookie", "session=ambient")
	source.Header.Set("Authorization", "Bearer ambient")
	source.Header.Set("X-Benmore-Edge-User", "999")
	request, policy, err := newAppMCPNativeRequest(app, source, pair.AccessToken, grantFixtureResource, "list_notes")
	if err != nil {
		t.Fatal(err)
	}
	if len(request.Header) != 0 {
		t.Fatal("ambient credentials retained")
	}
	actor := getSession(policy, request)
	if actor == nil || actor.UserID != uid || actor.GroupID != "17" || actor.IsAdminBypass() {
		t.Fatalf("wrong authority: %+v", actor)
	}
	auditExec(t, app.DB, "INSERT INTO notes(user_id,title) VALUES (?, 'mine'),(999,'other')", uid)
	recorder := httptest.NewRecorder()
	handleList(recorder, request, policy, "notes")
	if recorder.Code != 200 || recorder.Body.String() == "[]\n" {
		t.Fatalf("native read failed: %d %s", recorder.Code, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "other") {
		t.Fatal("canonical read leaked another user's row")
	}
	recorder = httptest.NewRecorder()
	handleRead(recorder, request, policy, "notes")
	if recorder.Code != http.StatusForbidden {
		t.Fatal("list authority used for read handler")
	}
	if err := revokeAppMCPGrant(app, pair.GrantID); err != nil {
		t.Fatal(err)
	}
	// Public read access cannot turn invalid private authority into anonymous access.
	app.Access.rules["notes"]["all"] = "anon"
	recorder = httptest.NewRecorder()
	handleList(recorder, request, policy, "notes")
	if recorder.Code != http.StatusForbidden || getSession(policy, request) != nil {
		t.Fatalf("revoked context fell back: %d %s", recorder.Code, recorder.Body.String())
	}
}
func TestAppMCPPrivateReadRejectsRetargetingAndPublicForgery(t *testing.T) {
	app, uid, _ := appMCPGrantFixture(t)
	pair := fixtureGrant(t, app, uid, time.Now())
	source := httptest.NewRequest(http.MethodGet, "/api/notes", nil)
	source.Header.Set("X-Benmore-MCP-Grant", pair.GrantID)
	if actor := getSession(app, source); actor != nil {
		t.Fatal("public header created grant context")
	}
	request, policy, err := newAppMCPNativeRequest(app, source, pair.AccessToken, grantFixtureResource, "list_notes")
	if err != nil {
		t.Fatal(err)
	}
	request.URL.Path = "/api/orgdocs"
	recorder := httptest.NewRecorder()
	handleList(recorder, request, policy, "orgdocs")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("retargeted context accepted: %d", recorder.Code)
	}
	source.Method = http.MethodPost
	if _, _, err := newAppMCPNativeRequest(app, source, pair.AccessToken, grantFixtureResource, "list_notes"); err == nil {
		t.Fatal("read identity minted for mutation")
	}
	source.Method = http.MethodGet
	if _, _, err := newAppMCPNativeRequest(app, source, pair.RefreshToken, grantFixtureResource, "list_notes"); err == nil {
		t.Fatal("refresh credential created native authority")
	}
	if _, _, err := newAppMCPNativeRequest(app, source, pair.AccessToken, "https://other.example/api/_mcp", "list_notes"); err == nil {
		t.Fatal("wrong audience created native authority")
	}
}

func TestAppMCPPrivateReadAdminRemainsInPinnedTenant(t *testing.T) {
	app, uid, _ := appMCPGrantFixture(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE orgdocs (id INTEGER PRIMARY KEY);\n")
	writeTestFile(t, app.Dir, "mcp.yaml", strings.ReplaceAll(appMCPManifestFixture(), "notes", "orgdocs"))
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP = config.mcp
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{"admin": {Scopes: "orgdocs:read"}}}
	auditExec(t, app.DB, "UPDATE _benmore_users SET role='admin' WHERE id=?", uid)
	auditExec(t, app.DB, "INSERT INTO orgdocs VALUES (3,'17','pinned-17'),(4,'29','other-29')")
	pair, err := createAppMCPGrant(app, uid, "17", "client-fixture", grantFixtureResource, "orgdocs:read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	request, policy, err := newAppMCPNativeRequest(app, httptest.NewRequest(http.MethodGet, "/api/orgdocs?group_id=29&user_id=999", nil), pair.AccessToken, grantFixtureResource, "list_orgdocs")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	handleList(recorder, request, policy, "orgdocs")
	if recorder.Code != 200 || !strings.Contains(recorder.Body.String(), "pinned-17") || strings.Contains(recorder.Body.String(), "other-29") {
		t.Fatalf("admin tenant isolation: %d %s", recorder.Code, recorder.Body.String())
	}
	auditExec(t, app.DB, "DELETE FROM members WHERE org_id='17'")
	recorder = httptest.NewRecorder()
	handleList(recorder, request, policy, "orgdocs")
	if recorder.Code != http.StatusForbidden {
		t.Fatalf("lost tenant membership authorized: %d %s", recorder.Code, recorder.Body.String())
	}
}

// A native SQLite view expires access at the third lookup, after the two
// initial CRUD gates, without writing through the protected connection.
func TestAppMCPPrivateReadDeniesInvalidationAfterInitialGate(t *testing.T) {
	for _, operation := range []string{"table.list", "table.read"} {
		t.Run(operation, func(t *testing.T) {
			app, uid, _ := appMCPGrantFixture(t)
			if operation == "table.read" {
				writeTestFile(t, app.Dir, "mcp.yaml", strings.Replace(appMCPManifestFixture(), "table.list", "table.read", 1))
				reviewAppMCPFixture(t, app.Dir)
				config, err := loadRuntimeConfig(app.Dir)
				if err != nil {
					t.Fatal(err)
				}
				app.MCP = config.mcp
			}
			pair := fixtureGrant(t, app, uid, time.Now())
			auditExec(t, app.DB, "INSERT INTO notes(id,user_id,title) VALUES (1,999,'forbidden-row'),(2,?,'owned-row')", uid)
			path := "/api/notes"
			if operation == "table.read" {
				path += "/1"
			}
			if err := app.DB.Close(); err != nil {
				t.Fatal(err)
			}
			lookups := 0
			name := "mcp-expire-" + generateToken(8)
			sql.Register(name, &sqlite3.SQLiteDriver{ConnectHook: func(conn *sqlite3.SQLiteConn) error {
				return conn.RegisterFunc("mcp_access_expiry", func(kind string, expiry int64) int64 {
					if kind == "access" {
						lookups++
						if lookups >= 3 {
							return 0
						}
					}
					return expiry
				}, false)
			}})
			db, err := sql.Open(name, filepath.Join(app.Dir, "data.db")+"?_journal_mode=WAL")
			if err != nil {
				t.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			app.DB = db
			auditExec(t, db, "ALTER TABLE _benmore_mcp_credentials RENAME TO stored_credentials")
			auditExec(t, db, `CREATE VIEW _benmore_mcp_credentials AS SELECT token_hash,grant_id,kind,mcp_access_expiry(kind,expires_at) AS expires_at,used FROM stored_credentials`)
			request, policy, err := newAppMCPNativeRequest(app, httptest.NewRequest(http.MethodGet, path, nil), pair.AccessToken, grantFixtureResource, "list_notes")
			if err != nil {
				t.Fatal(err)
			}
			// Request construction resolves the grant too; measure only the
			// canonical CRUD authorization gates under test below.
			lookups = 0
			recorder := httptest.NewRecorder()
			if operation == "table.list" {
				handleList(recorder, request, policy, "notes")
			} else {
				handleRead(recorder, request, policy, "notes")
			}
			if lookups != 3 || recorder.Code != http.StatusForbidden || strings.Contains(recorder.Body.String(), "forbidden-row") {
				t.Fatalf("mid-request invalidation leaked: lookups=%d status=%d body=%s", lookups, recorder.Code, recorder.Body.String())
			}
		})
	}
}
