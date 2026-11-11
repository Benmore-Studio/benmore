//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// testingResetApp is an app in testing mode: one admin, a `notes` table with
// two rows and three audit rows. hipaa installs the append-only triggers a
// `compliance: hipaa` app carries.
func testingResetApp(t *testing.T, hipaa bool) (*App, *http.ServeMux, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureFeedbackTables(db)
	EnsureAuditLogTable(db)
	EnsureReadAuditTable(db)
	for _, stmt := range []string{
		`CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT NOT NULL UNIQUE)`,
		`INSERT INTO notes (id, title) VALUES (1, 'kept one'), (2, 'kept two')`,
		`INSERT INTO _benmore_users (username, email, role, verified) VALUES ('root', 'root@example.com', 'admin', 1)`,
		`INSERT INTO _benmore_audit_log (action, table_name, row_id, user_email) VALUES
			('insert', 'notes', '1', 'root@example.com'), ('insert', 'notes', '2', 'root@example.com'), ('update', 'notes', '2', 'root@example.com')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Design: &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{}}}
	t.Cleanup(app.Shutdown)
	if hipaa {
		app.Design.Compliance = complianceHIPAA
		ensureAuditAppendOnly(app)
	}
	mux := http.NewServeMux()
	registerDemoRoutes(mux, app, "visitor-pass")
	return app, mux, CreateSession(db, 1, "root@example.com", "", time.Hour)
}

// testingResetPost sends the admin panel's "Reset & Reseed" request.
func testingResetPost(t *testing.T, mux *http.ServeMux, sid string) (int, map[string]any) {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, "/api/_testing/reset", strings.NewReader(`{}`))
	r.Host = "app.example.test"
	r.Header.Set("Origin", "http://app.example.test")
	r.Header.Set("Content-Type", "application/json")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	r.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	body := map[string]any{}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("reset answered %d with a non-JSON body: %s", w.Code, w.Body.String())
	}
	return w.Code, body
}

func testingResetTitles(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT title FROM notes ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	titles := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		titles = append(titles, s)
	}
	return titles
}

func testingResetAuditTriggers(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='trigger' AND tbl_name IN ('_benmore_audit_log','_benmore_read_audit')`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	names := []string{}
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		names = append(names, s)
	}
	sort.Strings(names)
	return names
}

func testingResetCount(t *testing.T, db *sql.DB, query string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// POST /api/_testing/reset ran every seeds.sql statement on the pool with its
// error dropped and no guard on framework tables: on a `compliance: hipaa` app
// a seed that dropped an append-only trigger and deleted from
// _benmore_audit_log emptied the audit log, and the reset answered success.
// A seed naming an audit table (or any framework table, or DDL) now refuses
// the whole reset before a row is touched.
func TestTestingResetRefusesSeedsNamingAuditTable(t *testing.T) {
	cases := []struct {
		name  string
		hipaa bool
		seeds string
		want  string // text the answer's error must carry
	}{
		{"hipaa: drop the delete trigger then empty the log", true,
			"INSERT INTO notes (id, title) VALUES (9, 'seeded');\nDROP TRIGGER _benmore_audit_log_no_delete;\nDELETE FROM _benmore_audit_log;\n", "append-only"},
		{"hipaa: delete only (the trigger stops it; the reset must still fail)", true,
			"INSERT INTO notes (id, title) VALUES (9, 'seeded');\nDELETE FROM _benmore_audit_log;\n", "append-only"},
		{"hipaa: a trigger that discards new read-audit rows", true,
			"CREATE TRIGGER s BEFORE INSERT ON _benmore_read_audit BEGIN SELECT RAISE(IGNORE); END;\n", "append-only"},
		{"hipaa: forge a row", true,
			"INSERT INTO _benmore_audit_log (action, table_name) VALUES ('forged', 'notes');\n", "append-only"},
		{"no compliance key: framework tables are still not seed targets", false,
			"INSERT INTO notes (id, title) VALUES (9, 'seeded');\nDELETE FROM _benmore_audit_log;\n", "seed statement 2"},
		{"no compliance key: schema changes are not seeds", false,
			"INSERT INTO notes (id, title) VALUES (9, 'seeded');\nDROP TABLE _benmore_audit_log;\n", "seed statement 2"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			app, mux, sid := testingResetApp(t, c.hipaa)
			triggers := testingResetAuditTriggers(t, app.DB)
			if c.hipaa && len(triggers) != 6 {
				t.Fatalf("fixture has %d append-only triggers, want 6: %v", len(triggers), triggers)
			}
			if err := os.WriteFile(filepath.Join(app.Dir, "seeds.sql"), []byte(c.seeds), 0o644); err != nil {
				t.Fatal(err)
			}
			code, body := testingResetPost(t, mux, sid)
			if code != http.StatusUnprocessableEntity {
				t.Errorf("status %d, want 422 (%v)", code, body)
			}
			if msg, _ := body["error"].(string); !strings.Contains(msg, c.want) {
				t.Errorf("error %q does not name the refusal (%q)", msg, c.want)
			}
			if body["status"] == "reset" || body["seeds"] == true {
				t.Errorf("a refused reset answered success: %v", body)
			}
			if n := testingResetCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action IN ('insert','update')`); n != 3 {
				t.Errorf("%d of the 3 audit rows survive", n)
			}
			if n := testingResetCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'forged'`); n != 0 {
				t.Errorf("the seed forged %d audit rows", n)
			}
			if got := testingResetAuditTriggers(t, app.DB); strings.Join(got, ",") != strings.Join(triggers, ",") {
				t.Errorf("audit triggers changed: %v, want %v", got, triggers)
			}
			if n := testingResetCount(t, app.DB, `SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_benmore_audit_log'`); n != 1 {
				t.Error("the audit table is gone")
			}
			// Nothing half-applied: the refused reset cleared no app table
			// and ran no earlier seed statement.
			if got := testingResetTitles(t, app.DB); strings.Join(got, "|") != "kept one|kept two" {
				t.Errorf("app rows after a refused reset: %v", got)
			}
		})
	}
}

// A seed statement that fails used to be skipped: the tables were already
// cleared, the statements before and after it ran, and the reset answered
// {"status":"reset","seeds":true}. The reset is now one transaction: the
// answer names the failing statement and the data is as it was.
func TestTestingResetReportsFailedSeedAndRollsBack(t *testing.T) {
	for name, c := range map[string]struct{ seeds, want string }{
		"unknown table":     {"INSERT INTO notes (id, title) VALUES (9, 'first');\nINSERT INTO no_such_table (x) VALUES (1);\nINSERT INTO notes (id, title) VALUES (10, 'third');\n", "seed statement 2"},
		"unique violation":  {"INSERT INTO notes (id, title) VALUES (9, 'dup');\nINSERT INTO notes (id, title) VALUES (10, 'ok');\nINSERT INTO notes (id, title) VALUES (11, 'dup');\n", "seed statement 3"},
		"commits mid-reset": {"INSERT INTO notes (id, title) VALUES (9, 'first');\nCOMMIT;\nINSERT INTO no_such_table (x) VALUES (1);\n", "seed statement 2"},
	} {
		t.Run(name, func(t *testing.T) {
			app, mux, sid := testingResetApp(t, false)
			if err := os.WriteFile(filepath.Join(app.Dir, "seeds.sql"), []byte(c.seeds), 0o644); err != nil {
				t.Fatal(err)
			}
			code, body := testingResetPost(t, mux, sid)
			if code != http.StatusUnprocessableEntity {
				t.Errorf("status %d, want 422 (%v)", code, body)
			}
			if msg, _ := body["error"].(string); !strings.Contains(msg, c.want) {
				t.Errorf("error %q does not name the failing statement (%q)", msg, c.want)
			}
			if msg, _ := body["error"].(string); strings.Contains(msg, "INSERT INTO") {
				t.Errorf("error quotes the seed SQL: %q", msg)
			}
			if body["status"] == "reset" || body["seeds"] == true {
				t.Errorf("a failed reset answered success: %v", body)
			}
			if got := testingResetTitles(t, app.DB); strings.Join(got, "|") != "kept one|kept two" {
				t.Errorf("app rows after a failed reset: %v (want the rows from before it)", got)
			}
			if n := testingResetCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'data_reset_seed'`); n != 0 {
				t.Errorf("a failed reset recorded %d reset audit rows", n)
			}
		})
	}
}

// An ordinary seeds.sql still clears the app tables and reseeds them, with
// accounts and sessions kept. A semicolon inside a string literal or a
// comment no longer splits a statement, and the reset is recorded.
func TestTestingResetRunsOrdinarySeeds(t *testing.T) {
	for _, hipaa := range []bool{false, true} {
		app, mux, sid := testingResetApp(t, hipaa)
		seeds := "-- demo rows; reloaded by the admin panel\n" +
			"INSERT INTO notes (id, title) VALUES (5, 'milk; eggs');\n" +
			"/* second; row */ INSERT INTO notes (id, title) VALUES (6, 'plain');\n"
		if err := os.WriteFile(filepath.Join(app.Dir, "seeds.sql"), []byte(seeds), 0o644); err != nil {
			t.Fatal(err)
		}
		code, body := testingResetPost(t, mux, sid)
		if code != http.StatusOK || body["status"] != "reset" || body["seeds"] != true {
			t.Fatalf("hipaa=%v: reset answered %d %v", hipaa, code, body)
		}
		if n, _ := body["tables_cleared"].(float64); n != 1 {
			t.Errorf("hipaa=%v: tables_cleared %v, want 1 (notes; framework tables are not counted)", hipaa, body["tables_cleared"])
		}
		if got := testingResetTitles(t, app.DB); strings.Join(got, "|") != "milk; eggs|plain" {
			t.Errorf("hipaa=%v: rows after reset: %v", hipaa, got)
		}
		if n := testingResetCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_users`); n != 1 {
			t.Errorf("hipaa=%v: reset left %d accounts, want 1", hipaa, n)
		}
		if GetSessionFromDB(app.DB, sid) == nil {
			t.Errorf("hipaa=%v: the admin's session did not survive the reset", hipaa)
		}
		if n := testingResetCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action IN ('insert','update')`); n != 3 {
			t.Errorf("hipaa=%v: %d of the 3 earlier audit rows survive", hipaa, n)
		}
		var email, values string
		if err := app.DB.QueryRow(`SELECT user_email, new_values FROM _benmore_audit_log WHERE action = 'data_reset_seed'`).Scan(&email, &values); err != nil {
			t.Fatalf("hipaa=%v: the reset left no audit row: %v", hipaa, err)
		}
		if email != "root@example.com" || !strings.Contains(values, `"seeds_run":2`) || !strings.Contains(values, `"notes":2`) {
			t.Errorf("hipaa=%v: reset audit row %s %s", hipaa, email, values)
		}

		// No seeds.sql: clear only, as before.
		if err := os.Remove(filepath.Join(app.Dir, "seeds.sql")); err != nil {
			t.Fatal(err)
		}
		code, body = testingResetPost(t, mux, sid)
		if code != http.StatusOK || body["status"] != "cleared" || body["seeds"] != false {
			t.Fatalf("hipaa=%v: reset without seeds.sql answered %d %v", hipaa, code, body)
		}
		if got := testingResetTitles(t, app.DB); len(got) != 0 {
			t.Errorf("hipaa=%v: rows after a clear-only reset: %v", hipaa, got)
		}
	}
}

// The reset stays an admin-console action behind CSRF.
func TestTestingResetStillNeedsAdminAndCSRF(t *testing.T) {
	app, mux, sid := testingResetApp(t, false)
	if _, err := app.DB.Exec(`INSERT INTO _benmore_users (username, email, role, verified) VALUES ('member', 'member@example.com', 'user', 1)`); err != nil {
		t.Fatal(err)
	}
	member := CreateSession(app.DB, 2, "member@example.com", "", time.Hour)
	if code, body := testingResetPost(t, mux, member); code != http.StatusForbidden {
		t.Errorf("a member reset the app: %d %v", code, body)
	}
	r := httptest.NewRequest(http.MethodPost, "/api/_testing/reset", strings.NewReader(`{}`))
	r.Host = "app.example.test"
	r.Header.Set("Origin", "http://app.example.test")
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusForbidden {
		t.Errorf("an admin post without the CSRF token: %d %s", w.Code, w.Body.String())
	}
	if got := testingResetTitles(t, app.DB); strings.Join(got, "|") != "kept one|kept two" {
		t.Errorf("a refused caller changed the data: %v", got)
	}
}
