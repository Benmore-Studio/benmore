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
)

// newOwnedImportApp is an app with the scaffold's owner-scoped shape (notes
// with a required user_id) plus two app users.
func newOwnedImportApp(t *testing.T) (*App, *http.ServeMux, string, func()) {
	t.Helper()
	app, cleanup := newImportTestApp(t)
	mustExec(t, app.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT, user_id INTEGER NOT NULL)`)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email, password_hash, role) VALUES (41, 'ada', 'Ada@Example.com', 'x', 'user')`)
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email, password_hash, role, deactivated_at) VALUES (42, 'gone', 'gone@example.com', 'x', 'user', datetime('now'))`)
	EnsureAuditLogTable(app.DB)
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	prev := serverSecret
	serverSecret = "test-secret-for-import-owner-000000000"
	token := mintImportOwnerToken(app, time.Now().Add(5*time.Minute), "owner@example.com")
	return app, mux, token, func() { serverSecret = prev; cleanup() }
}

func ownerImportCreateBody(table, content, owner string) string {
	sum := sha256.Sum256([]byte(content))
	req := map[string]any{"table": table, "format": "csv", "bytes": len(content), "sha256": hex.EncodeToString(sum[:])}
	if owner != "" {
		req["owner"] = owner
	}
	body, _ := json.Marshal(req)
	return string(body)
}

// driveOwnerTokenImport runs create, chunk, commit and polls to a terminal
// state with an owner token. It returns the create response when create is
// refused.
func driveOwnerTokenImport(t *testing.T, mux *http.ServeMux, token, table, content, owner string) (createCode int, createBody, state, errText string) {
	t.Helper()
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, ownerTokenRequest("POST", "/api/_import", ownerImportCreateBody(table, content, owner), token))
	if rec.Code != http.StatusOK {
		return rec.Code, rec.Body.String(), "", ""
	}
	var created struct {
		ImportID string `json:"import_id"`
	}
	json.Unmarshal(rec.Body.Bytes(), &created)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, ownerTokenRequest("PUT", "/api/_import/"+created.ImportID+"/chunk/0", content, token))
	if rec.Code != http.StatusOK {
		t.Fatalf("chunk = %d %s", rec.Code, rec.Body.String())
	}
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, ownerTokenRequest("POST", "/api/_import/"+created.ImportID+"/commit", "", token))
	if rec.Code != http.StatusAccepted {
		t.Fatalf("commit = %d %s", rec.Code, rec.Body.String())
	}
	for i := 0; i < 200; i++ {
		rec = httptest.NewRecorder()
		mux.ServeHTTP(rec, ownerTokenRequest("GET", "/api/_import/"+created.ImportID, "", token))
		var st struct {
			State string `json:"state"`
			Error string `json:"error"`
		}
		json.Unmarshal(rec.Body.Bytes(), &st)
		if st.State == "completed" || st.State == "failed" {
			return http.StatusOK, "", st.State, st.Error
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("import did not reach a terminal state")
	return
}

// L9: an owner-token import into a table whose user_id is required used to be
// accepted, uploaded and then fail row 1 with "NOT NULL constraint failed".
// It must be refused at create, naming --owner.
func TestImportOwnerTokenRequiredOwnerRefusedBeforeUpload(t *testing.T) {
	app, mux, token, cleanup := newOwnedImportApp(t)
	defer cleanup()

	code, body, _, _ := driveOwnerTokenImport(t, mux, token, "notes", "body\nfirst\n", "")
	if code != http.StatusBadRequest || !strings.Contains(body, "--owner") || strings.Contains(body, "NOT NULL constraint") {
		t.Fatalf("create without owner = %d %s; want 400 naming --owner", code, body)
	}
	var sessions int
	app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_imports`).Scan(&sessions)
	if sessions != 0 {
		t.Fatalf("a refused create left %d import sessions", sessions)
	}
}

func TestImportOwnerTokenAssignsChosenOwner(t *testing.T) {
	app, mux, token, cleanup := newOwnedImportApp(t)
	defer cleanup()

	// Case-insensitive like sign-in; the stored email is what gets recorded.
	_, body, state, errText := driveOwnerTokenImport(t, mux, token, "notes", "body\nfirst\nsecond\n", "ada@example.com")
	if state != "completed" {
		t.Fatalf("import with owner = %q %q %s", state, errText, body)
	}
	var total, owned int
	app.DB.QueryRow(`SELECT COUNT(*), SUM(user_id = 41) FROM notes`).Scan(&total, &owned)
	if total != 2 || owned != 2 {
		t.Fatalf("notes total=%d owned by 41=%d; want every row owned by the chosen user", total, owned)
	}
	var email, values string
	if err := app.DB.QueryRow(`SELECT user_email, new_values FROM _benmore_audit_log WHERE action='import' ORDER BY id DESC LIMIT 1`).Scan(&email, &values); err != nil {
		t.Fatal(err)
	}
	if email != "owner@example.com" || !strings.Contains(values, `"owner_user_id":41`) || !strings.Contains(values, "Ada@Example.com") {
		t.Fatalf("audit actor=%q values=%s; want the token subject plus the chosen owner", email, values)
	}
}

func TestImportOwnerRefusals(t *testing.T) {
	app, mux, token, cleanup := newOwnedImportApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE tags (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)`)

	for _, c := range []struct {
		name, table, owner, want string
	}{
		{"unknown user", "notes", "nobody@example.com", "not a user of this app"},
		{"deactivated user", "notes", "gone@example.com", "deactivated"},
		{"no owner column", "tags", "ada@example.com", "user_id owner column"},
		{"not an email", "notes", "41", "email address"},
	} {
		t.Run(c.name, func(t *testing.T) {
			code, body, _, _ := driveOwnerTokenImport(t, mux, token, c.table, "body\nx\n", c.owner)
			if code != http.StatusBadRequest || !strings.Contains(body, c.want) {
				t.Fatalf("create = %d %s; want 400 containing %q", code, body, c.want)
			}
		})
	}

	// Mode B keeps the dump's own user_id values.
	sqlBody := `{"format":"sql","bytes":10,"sha256":"` + strings.Repeat("a", 64) + `","owner":"ada@example.com"}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, ownerTokenRequest("POST", "/api/_import", sqlBody, token))
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "CSV/NDJSON") {
		t.Fatalf("sql restore with owner = %d %s", rec.Code, rec.Body.String())
	}

	// An admin session owns what it imports; user_id stays protected from it.
	sess := seedAdminSession(t, app)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedRequest("POST", "/api/_import", ownerImportCreateBody("notes", "body\nx\n", "ada@example.com"), sess))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "owner token") {
		t.Fatalf("admin session with owner = %d %s; want 403", rec.Code, rec.Body.String())
	}
	// Without owner, the admin still imports and owns the rows (unchanged).
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedRequest("POST", "/api/_import", ownerImportCreateBody("notes", "body\nx\n", ""), sess))
	if rec.Code != http.StatusOK {
		t.Fatalf("admin session import into notes = %d %s; want 200", rec.Code, rec.Body.String())
	}
}

// A staging session is resumed only for the same chosen owner, so a re-run
// with a different --owner never inherits the first owner.
func TestImportOwnerIsPartOfResumeIdentity(t *testing.T) {
	app, mux, token, cleanup := newOwnedImportApp(t)
	defer cleanup()
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email, password_hash, role) VALUES (43, 'bo', 'bo@example.com', 'x', 'user')`)

	ids := map[string]bool{}
	for _, owner := range []string{"ada@example.com", "bo@example.com", "ada@example.com"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, ownerTokenRequest("POST", "/api/_import", ownerImportCreateBody("notes", "body\nx\n", owner), token))
		if rec.Code != http.StatusOK {
			t.Fatalf("create(%s) = %d %s", owner, rec.Code, rec.Body.String())
		}
		var created struct {
			ImportID string `json:"import_id"`
		}
		json.Unmarshal(rec.Body.Bytes(), &created)
		ids[created.ImportID] = true
	}
	if len(ids) != 2 {
		t.Fatalf("got %d distinct sessions for owners ada, bo, ada; want 2 (ada resumed, bo separate)", len(ids))
	}
}

// The owner is re-checked in the load transaction: an account deactivated
// between create and commit fails the load with zero rows.
func TestRunImportRefusesOwnerDeactivatedAfterCreate(t *testing.T) {
	app, _, _, cleanup := newOwnedImportApp(t)
	defer cleanup()

	content := "body\nx\n"
	sum := stageString(t, app, "owner0001", content)
	mustExecArgs(t, app.DB, `INSERT INTO _benmore_imports (id, table_name, format, bytes_total, sha256, state, created_by, owner_user_id, owner_email)
		VALUES ('owner0001', 'notes', 'csv', ?, ?, 'running', 0, 42, 'gone@example.com')`, len(content), sum)
	sess, err := loadImportSession(app.DB, "owner0001")
	if err != nil {
		t.Fatal(err)
	}
	err = runImport(app, sess)
	if err == nil || !strings.Contains(err.Error(), "no longer exists or was deactivated") {
		t.Fatalf("runImport = %v; want the owner re-check to refuse", err)
	}
	var n int
	app.DB.QueryRow(`SELECT COUNT(*) FROM notes`).Scan(&n)
	if n != 0 {
		t.Fatalf("notes has %d rows after a refused load", n)
	}
}

// A session created before the owner check existed (or by another client)
// still fails with the clear message at load time, not a NOT NULL error.
func TestRunImportRequiredOwnerMessageAtLoad(t *testing.T) {
	app, _, _, cleanup := newOwnedImportApp(t)
	defer cleanup()

	content := "body\nx\n"
	sum := stageString(t, app, "owner0002", content)
	mustExecArgs(t, app.DB, `INSERT INTO _benmore_imports (id, table_name, format, bytes_total, sha256, state, created_by)
		VALUES ('owner0002', 'notes', 'csv', ?, ?, 'running', 0)`, len(content), sum)
	sess, err := loadImportSession(app.DB, "owner0002")
	if err != nil {
		t.Fatal(err)
	}
	err = runImport(app, sess)
	if err == nil || !strings.Contains(err.Error(), "--owner") {
		t.Fatalf("runImport = %v; want the --owner refusal", err)
	}
}
