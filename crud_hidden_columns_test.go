//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

// Sensitive-named app columns were stripped from create responses and
// ?fields= projections but returned verbatim by every SELECT * read, so a
// `stripe_secret` the create response hid came straight back from a list.
func TestSensitiveColumnsHiddenOnEveryReadSurface(t *testing.T) {
	dir := t.TempDir()
	// Open the database the way production does (WAL, busy timeout, BEGIN
	// IMMEDIATE): the app's background writers share it, and a default DSN
	// lets a write fail with "database is locked".
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	crudScopeMustExec(t, db, `CREATE TABLE projects (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)`)
	crudScopeMustExec(t, db, `CREATE TABLE integrations (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER,
		project_id INTEGER REFERENCES projects(id), name TEXT, stripe_secret TEXT, webhook_token TEXT,
		internal_notes TEXT, publishable_key TEXT, public_signing_key TEXT, api_key TEXT, playbook_key TEXT, wants_secret INTEGER)`)
	crudScopeMustExec(t, db, `INSERT INTO projects (user_id, title) VALUES (1, 'p')`)
	crudScopeMustExec(t, db, `INSERT INTO integrations (user_id, project_id, name, stripe_secret, webhook_token, internal_notes, publishable_key, public_signing_key, api_key, playbook_key, wants_secret)
		VALUES (1, 1, 'stripe', 'sk-live-hidden', 'whk-hidden', 'ops-notes', 'pk-visible', 'sig-visible', 'api-hidden', 'stripe_key_test', 1)`)

	cols := []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "project_id"}, {Name: "name"},
		{Name: "stripe_secret", Type: "TEXT"}, {Name: "webhook_token", Type: "TEXT"}, {Name: "internal_notes", Type: "TEXT"},
		{Name: "publishable_key", Type: "TEXT"}, {Name: "public_signing_key", Type: "TEXT"}, {Name: "api_key", Type: "TEXT"},
		{Name: "playbook_key", Type: "TEXT"}, {Name: "wants_secret", Type: "INTEGER"}}
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		JoinMap: BuildJoinMap(db),
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"projects":     {"all": "self"},
			"integrations": {"all": "self"},
		}},
		Tables: []Table{
			{Name: "projects", Columns: []Column{{Name: "id", PK: true}, {Name: "user_id"}, {Name: "title"}}},
			{Name: "integrations", Columns: cols},
		},
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	token := createCrudScopeSession(t, app, "owner@example.com", "user", "", "")

	check := func(surface string, row map[string]any) {
		t.Helper()
		for _, hidden := range []string{"stripe_secret", "webhook_token", "api_key"} {
			if v, ok := row[hidden]; ok {
				t.Fatalf("%s exposed %s=%v", surface, hidden, v)
			}
		}
		// Lookup keys, flags and notes are data, not credentials.
		for _, visible := range []string{"publishable_key", "public_signing_key", "name", "internal_notes", "playbook_key", "wants_secret"} {
			if _, ok := row[visible]; !ok {
				t.Fatalf("%s dropped intentionally public column %s: %#v", surface, visible, row)
			}
		}
	}
	getRows := func(path string) []map[string]any {
		t.Helper()
		rec := crudScopeRequest(t, mux, http.MethodGet, path, token, nil)
		if rec.Code != http.StatusOK {
			t.Fatalf("GET %s status=%d body=%s", path, rec.Code, rec.Body.String())
		}
		var rows []map[string]any
		mustDecodeBody(t, rec, &rows)
		if len(rows) != 1 {
			t.Fatalf("GET %s returned %d rows", path, len(rows))
		}
		return rows
	}

	check("list", getRows("/api/integrations")[0])
	var cursor map[string]any
	mustDecodeBody(t, crudScopeRequest(t, mux, http.MethodGet, "/api/integrations?cursor=0", token, nil), &cursor)
	check("cursor list", cursor["data"].([]any)[0].(map[string]any))
	var one map[string]any
	mustDecodeBody(t, crudScopeRequest(t, mux, http.MethodGet, "/api/integrations/1", token, nil), &one)
	check("read", one)
	project := getRows("/api/projects?include=integrations")[0]
	children, ok := project["integrations"].([]any)
	if !ok || len(children) != 1 {
		t.Fatalf("child include missing: %#v", project)
	}
	check("include", children[0].(map[string]any))

	rec := crudScopeRequest(t, mux, http.MethodPost, "/api/integrations", token, map[string]any{
		"project_id": 1, "name": "second", "stripe_secret": "sk-new-hidden", "publishable_key": "pk-2", "public_signing_key": "sig-2",
	})
	if rec.Code != http.StatusOK {
		t.Fatalf("create status=%d body=%s", rec.Code, rec.Body.String())
	}
	var created map[string]any
	mustDecodeBody(t, rec, &created)
	check("create", created)

	// A projection cannot ask for a hidden column either.
	if row := getRows("/api/integrations?fields=id,stripe_secret&where[name]=stripe")[0]; row["stripe_secret"] != nil {
		t.Fatalf("?fields= exposed stripe_secret: %#v", row)
	}
	if row := getRows("/api/integrations?fields=id,publishable_key&where[name]=stripe")[0]; row["publishable_key"] != "pk-visible" {
		t.Fatalf("?fields= dropped publishable_key: %#v", row)
	}
}

// A *_hash column is a credential only when it hashes one (a code, token,
// password...). Content checksums are ordinary data apps display and compare;
// hiding them broke change-ledger style apps in 2.7.237.
func TestHashColumnsHiddenOnlyForCredentials(t *testing.T) {
	for _, col := range []string{"password_hash", "code_hash", "otp_code_hash", "token_hash", "reset_hash", "api_key_hash", "pin_hash", "session_hash"} {
		if !appSecretColumn(nil, "t", col) {
			t.Errorf("%s must stay hidden", col)
		}
	}
	for _, col := range []string{"content_hash", "question_text_hash", "payload_hash", "file_hash", "commit_hash", "image_hash", "blur_hash"} {
		if appSecretColumn(nil, "t", col) {
			t.Errorf("%s is a checksum, not a credential; it must be returned", col)
		}
	}
}
