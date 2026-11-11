//go:build !cli && !windows

package main

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"
)

// versioned:, encrypted fields, workflows.yaml and computed.yaml act on the
// app's own tables only. These tests write each file the way an author would
// (the write gate) and load a real app that already carries one (a deployed
// file the gate never saw).

const frameworkTableSchema = `model Note {
  id        Int      @id @default(autoincrement())
  title     String
  body      String   @default("")
  status    String   @default("draft")
  titleLen  Int      @default(0) @map("title_len")
  sessions  Int      @default(0)
  userId    Int      @default(0) @map("user_id")
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @default(now()) @updatedAt @map("updated_at")
}
`

// frameworkTableSources name a framework table in each of the four files,
// next to an entry on the app's own table that must keep working.
var frameworkTableSources = map[string]string{
	"app.yaml": `site_name: "Framework tables"
auth:
  identifier: email
access:
  notes: everyone
  _benmore_users:
    read: everyone
    update: everyone
versioned: [notes, _benmore_users]
encrypted:
  _benmore_sessions: [email]
`,
	"encrypted.yaml": `tables:
  notes:
    fields: [body]
  _benmore_users:
    fields: [email]
`,
	"workflows.yaml": `note_status:
  table: notes
  field: status
  initial: draft
  transitions:
    draft:
      done: {}
promote:
  table: _benmore_users
  field: role
  initial: user
  transitions:
    user:
      admin: {}
`,
	"computed.yaml": `notes:
  title_len:
    expr: "length(title)"
  sessions:
    sql: "SELECT COUNT(*) FROM notes WHERE user_id = ?"
    triggers:
      - table: notes
        on: [insert]
        fk: user_id
      - table: _benmore_sessions
        on: [insert, delete]
        fk: user_id
_benmore_users:
  role:
    expr: "'admin'"
`,
}

func frameworkTableDir(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.prisma", frameworkTableSchema)
	writeTestFile(t, dir, "app.yaml", "site_name: \"Framework tables\"\nauth:\n  identifier: email\n")
	for name, body := range files {
		writeTestFile(t, dir, name, body)
	}
	return dir
}

// configTriggersOnFrameworkTables lists the triggers config installs
// (history, encryption, computed) that sit on a framework table.
func configTriggersOnFrameworkTables(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name, tbl_name FROM sqlite_master WHERE type='trigger' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name, table string
		if err := rows.Scan(&name, &table); err != nil {
			t.Fatal(err)
		}
		for _, prefix := range []string{"_benmore_ver_", "_benmore_enc_", "_benmore_cf_"} {
			if strings.HasPrefix(name, prefix) && frameworkOwnedTableName(table) {
				out = append(out, name+" on "+table)
			}
		}
	}
	return out
}

// The write gate (write_file, push, deploy) and `benmore check` refuse each of
// the four files when it names a framework table, and accept the same entry
// on a table of the app.
func TestConfigNamingAFrameworkTableIsRefusedAtWrite(t *testing.T) {
	for _, c := range []struct{ name, file, framework, own, want string }{
		{"versioned", "app.yaml",
			"versioned: [_benmore_users]\n", "versioned: [notes]\n",
			`app.yaml: versioned lists "_benmore_users"`},
		{"versioned sqlite", "app.yaml",
			"versioned: [sqlite_sequence]\n", "versioned: [notes]\n",
			`app.yaml: versioned lists "sqlite_sequence"`},
		{"inline encrypted", "app.yaml",
			"encrypted:\n  _benmore_users: [email]\n", "encrypted:\n  notes: [body]\n",
			`app.yaml: encrypted fields name the table "_benmore_users"`},
		{"encrypted.yaml", "encrypted.yaml",
			"tables:\n  _benmore_users:\n    fields: [first_name]\n", "tables:\n  notes:\n    fields: [body]\n",
			`encrypted.yaml: encrypted fields name the table "_benmore_users"`},
		{"workflow", "workflows.yaml",
			"promote:\n  table: _benmore_users\n  field: role\n  transitions:\n    user:\n      admin: {}\n",
			"note_status:\n  table: notes\n  field: status\n  initial: draft\n  transitions:\n    draft:\n      done: {}\n",
			"workflows.yaml promote: `table:` \"_benmore_users\" is a framework table"},
		{"workflow on sessions", "workflows.yaml",
			"expire:\n  table: _BENMORE_SESSIONS\n  field: scopes\n  transitions:\n    a:\n      b: {}\n",
			"note_status:\n  table: notes\n  field: status\n  initial: draft\n  transitions:\n    draft:\n      done: {}\n",
			"workflows.yaml expire: `table:` \"_BENMORE_SESSIONS\" is a framework table"},
		{"computed field", "computed.yaml",
			"_benmore_users:\n  role:\n    expr: \"'admin'\"\n", "notes:\n  title_len:\n    expr: \"length(title)\"\n",
			"computed.yaml: _benmore_users.role is a computed field on a framework table"},
		{"computed field, list form", "computed.yaml",
			"fields:\n  - table: _benmore_users\n    column: role\n    expr: \"'admin'\"\n", "fields:\n  - table: notes\n    column: title_len\n    expr: \"length(title)\"\n",
			"computed.yaml: _benmore_users.role is a computed field on a framework table"},
		{"computed trigger", "computed.yaml",
			"notes:\n  sessions:\n    sql: \"SELECT COUNT(*) FROM notes WHERE user_id = ?\"\n    triggers:\n      - table: _benmore_sessions\n        on: [insert]\n        fk: user_id\n",
			"notes:\n  sessions:\n    sql: \"SELECT COUNT(*) FROM notes WHERE user_id = ?\"\n    triggers:\n      - table: notes\n        on: [insert]\n        fk: user_id\n",
			`computed.yaml: notes.sessions recalculates on changes to "_benmore_sessions", a framework table`},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := frameworkTableDir(t, nil)
			base := ""
			if c.file == "app.yaml" {
				base = "site_name: \"Framework tables\"\nauth:\n  identifier: email\n"
			}
			if msg := ValidateOnWriteIn(dir, c.file, base+c.own); msg != "" {
				t.Fatalf("the same entry on the app's own table is refused: %s", msg)
			}
			msg := ValidateOnWriteIn(dir, c.file, base+c.framework)
			if !strings.Contains(msg, c.want) {
				t.Fatalf("write gate answered %q, want it to say %q", msg, c.want)
			}
			if !strings.Contains(msg, "never a framework table (_benmore_*) or one of SQLite's own (sqlite_*)") {
				t.Errorf("the refusal does not state the rule: %s", msg)
			}
			// `benmore check` reports the file an app already carries.
			writeTestFile(t, dir, c.file, base+c.framework)
			found := false
			for _, f := range RunSourceCheck(dir, "").Findings {
				if f.Severity == "error" && f.File == c.file && strings.Contains(f.Message, c.want) {
					found = true
				}
			}
			if !found {
				t.Errorf("benmore check has no error on %s saying %q", c.file, c.want)
			}
		})
	}
}

// A deployed app whose files name framework tables loads, and those entries
// do nothing: no history table, no trigger on a framework table, no transition
// route. The entries on the app's own table in the same files keep working,
// and the load says which entries it ignored.
func TestDeployedConfigNamingAFrameworkTableIsIgnoredAtLoad(t *testing.T) {
	dir := frameworkTableDir(t, nil)
	// A database that already has the framework's tables, as a deployed app's
	// does: on a new one the framework tables do not exist yet when history,
	// encryption and computed triggers are installed.
	first, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureUsersTable(first.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(first.DB)
	first.Shutdown()

	for name, body := range frameworkTableSources {
		writeTestFile(t, dir, name, body)
	}
	logs := guardCaptureLog(t)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("an app whose config names framework tables does not load: %v", err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")

	if on := configTriggersOnFrameworkTables(t, app.DB); len(on) != 0 {
		t.Errorf("config installed triggers on framework tables: %v", on)
	}
	var history int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = '_benmore_users_history'`).Scan(&history); err != nil || history != 0 {
		t.Errorf("_benmore_users_history exists (%d, %v): a copy of every changed account row, password hash included", history, err)
	}

	// The same files' entries on the app's own table are in force.
	for _, trigger := range []string{"_benmore_ver_notes_update", "_benmore_enc_notes_body_insert", "_benmore_cf_notes_title_len_insert", "_benmore_cf_notes_sessions_notes_insert"} {
		var n int
		if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name = ?`, trigger).Scan(&n); err != nil || n != 1 {
			t.Errorf("trigger %s on the app's own table is missing (%d, %v)", trigger, n, err)
		}
	}
	if wf := GetWorkflowForTable(app, "notes"); wf == nil {
		t.Error("the workflow on notes is not loaded")
	}
	if wf := GetWorkflowForTable(app, "_benmore_users"); wf != nil {
		t.Error("a workflow on _benmore_users is loaded")
	}

	// Sign-up and a later change of the account leave role and email alone.
	member := createCrudScopeSession(t, app, "member@example.com", "user", "", "")
	other := createCrudScopeSession(t, app, "other@example.com", "user", "", "")
	_ = other
	if _, err := app.DB.Exec(`UPDATE _benmore_users SET last_login_at = datetime('now')`); err != nil {
		t.Fatal(err)
	}
	// The transition route of the ignored workflow does not exist: with it, and
	// the access rule above, any signed-in user made any account an admin.
	for _, id := range []string{"1", "2"} {
		rec := crudScopeRequest(t, mux, http.MethodPost, "/api/_benmore_users/"+id+"/transition", member, map[string]any{"to": "admin"})
		if rec.Code != http.StatusNotFound {
			t.Errorf("POST /api/_benmore_users/%s/transition: %d %s", id, rec.Code, rec.Body.String())
		}
	}
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/_benmore_users/1/versions", member, nil); rec.Code != http.StatusNotFound {
		t.Errorf("GET /api/_benmore_users/1/versions: %d %s", rec.Code, rec.Body.String())
	}
	rows, err := app.DB.Query(`SELECT email, role FROM _benmore_users ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var accounts []string
	for rows.Next() {
		var email, role string
		if err := rows.Scan(&email, &role); err != nil {
			t.Fatal(err)
		}
		accounts = append(accounts, email+" "+role)
	}
	if got := strings.Join(accounts, ", "); got != "member@example.com user, other@example.com user" {
		t.Errorf("accounts after sign-up and an update: %s", got)
	}

	// The workflow on the app's own table still moves a row.
	if _, err := app.DB.Exec(`INSERT INTO notes (title, user_id) VALUES ('first', 1)`); err != nil {
		t.Fatal(err)
	}
	if rec := crudScopeRequest(t, mux, http.MethodPost, "/api/notes/1/transition", member, map[string]any{"to": "done"}); rec.Code != http.StatusOK {
		t.Errorf("POST /api/notes/1/transition: %d %s", rec.Code, rec.Body.String())
	}
	var titleLen int
	var body string
	if err := app.DB.QueryRow(`SELECT title_len, body FROM notes WHERE id = 1`).Scan(&titleLen, &body); err != nil || titleLen != 5 {
		t.Errorf("notes.title_len = %d (%v), want 5: the computed field on the app's own table", titleLen, err)
	}

	for _, want := range []string{
		`VERSIONING NOT RUNNING: app.yaml: versioned lists "_benmore_users"`,
		`ENCRYPTION NOT RUNNING: encrypted.yaml: encrypted fields name the table "_benmore_users"`,
		`ENCRYPTION NOT RUNNING: app.yaml: encrypted fields name the table "_benmore_sessions"`,
		"WARNING: workflows.yaml promote: `table:` \"_benmore_users\" is a framework table",
		"COMPUTED NOT RUNNING: computed.yaml: _benmore_users.role is a computed field on a framework table",
		`COMPUTED NOT RUNNING: computed.yaml: notes.sessions recalculates on changes to "_benmore_sessions", a framework table`,
	} {
		if !strings.Contains(logs.String(), want) {
			t.Errorf("the load did not log %q", want)
		}
	}
}

// A database on which an earlier load installed such triggers loses them at
// the next load, also when the files name nothing but framework tables (the
// encryption installer replaces its triggers only while a field is still
// configured). What that configuration stored stays: the history table and
// its rows are not dropped.
func TestLoadRemovesConfigTriggersFromFrameworkTables(t *testing.T) {
	dir := frameworkTableDir(t, nil)
	first, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := EnsureUsersTable(first.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(first.DB)
	if err := InstallEncryptionTriggers(first.DB, &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"_benmore_users": {{Column: "email"}}}}); err != nil {
		t.Fatal(err)
	}
	if err := InstallVersioningTriggers(first.DB, &VersionedConfig{Tables: []string{"_benmore_users"}}); err != nil {
		t.Fatal(err)
	}
	if err := installComputedTriggersChecked(first.DB, &ComputedFieldConfig{Fields: map[string]map[string]*ComputedField{
		"_benmore_users": {"role": {Table: "_benmore_users", Column: "role", Expr: "'admin'"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if on := configTriggersOnFrameworkTables(t, first.DB); len(on) != 6 {
		t.Fatalf("setup: %d config triggers on framework tables, want 6 (2 each): %v", len(on), on)
	}
	first.Shutdown()

	writeTestFile(t, dir, "app.yaml", "site_name: \"Framework tables\"\nauth:\n  identifier: email\nversioned: [_benmore_users]\n")
	writeTestFile(t, dir, "encrypted.yaml", "tables:\n  _benmore_users:\n    fields: [email]\n")
	writeTestFile(t, dir, "computed.yaml", "_benmore_users:\n  role:\n    expr: \"'admin'\"\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(app.Shutdown)
	if on := configTriggersOnFrameworkTables(t, app.DB); len(on) != 0 {
		t.Errorf("config triggers left on framework tables: %v", on)
	}
	createCrudScopeSession(t, app, "member@example.com", "user", "", "")
	if _, err := app.DB.Exec(`UPDATE _benmore_users SET last_login_at = datetime('now'), email = email`); err != nil {
		t.Fatal(err)
	}
	var email, role string
	var versions int
	if err := app.DB.QueryRow(`SELECT email, role FROM _benmore_users`).Scan(&email, &role); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_users_history`).Scan(&versions); err != nil {
		t.Fatalf("the history table an earlier configuration created is gone: %v", err)
	}
	if email != "member@example.com" || role != "user" || versions != 0 {
		t.Errorf("after a sign-up and an update: email %q, role %q, %d history rows; want the plain address, user, none", email, role, versions)
	}
}

// On a new database the framework's tables do not exist when history,
// encryption and computed triggers are installed. An app whose config names
// one could not start there at all; it loads now, with the entries ignored.
func TestConfigNamingAFrameworkTableLoadsOnANewDatabase(t *testing.T) {
	for name, body := range frameworkTableSources {
		if name == "workflows.yaml" {
			continue // a workflow installs nothing at load
		}
		t.Run(name, func(t *testing.T) {
			app, err := loadApp(frameworkTableDir(t, map[string]string{name: body}))
			if err != nil {
				t.Fatalf("load on a new database: %v", err)
			}
			t.Cleanup(app.Shutdown)
			if on := configTriggersOnFrameworkTables(t, app.DB); len(on) != 0 {
				t.Errorf("config installed triggers on framework tables: %v", on)
			}
		})
	}
}

// A file that names only framework tables is a file that declares nothing,
// not a broken one: the readers every consumer uses return no entry for it.
func TestConfigReadersDropFrameworkTables(t *testing.T) {
	if cfg, err := parseVersionedSection([]any{"_benmore_users", "sqlite_sequence"}); err != nil || cfg != nil {
		t.Errorf("versioned: %+v, %v", cfg, err)
	}
	if cfg, err := parseVersionedSection([]any{"notes", "_benmore_users"}); err != nil || cfg == nil || strings.Join(cfg.Tables, ",") != "notes" {
		t.Errorf("versioned with an own table: %+v, %v", cfg, err)
	}
	if cfg := parseEncryptedFieldsConfig([]byte("tables:\n  _benmore_users:\n    fields: [email]\n"), []byte("encrypted:\n  _benmore_sessions: [email]\n")); cfg != nil {
		t.Errorf("encrypted: %+v", cfg.Fields)
	}
	wf, err := parseWorkflowsYAML([]byte("promote:\n  table: _benmore_users\n  field: role\n  transitions:\n    user:\n      admin: {}\n"))
	if err != nil || (wf != nil && len(wf.Workflows) != 0) {
		t.Errorf("workflows: %+v, %v", wf, err)
	}
	computed, err := checkComputedDocument([]byte("_benmore_users:\n  role:\n    expr: \"'admin'\"\n"))
	if err != nil || len(computedFields(computed)) != 0 {
		t.Errorf("computed: %+v, %v", computedFields(computed), err)
	}
	// A trigger on a framework table is dropped; the field and its other
	// trigger stay.
	computed, err = checkComputedDocument([]byte(frameworkTableSources["computed.yaml"]))
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, cf := range computedFields(computed) {
		for _, trigger := range cf.Triggers {
			kept = append(kept, cf.Table+"."+cf.Column+"<-"+trigger.Table)
		}
		if len(cf.Triggers) == 0 {
			kept = append(kept, cf.Table+"."+cf.Column)
		}
	}
	if got := strings.Join(kept, " "); got != "notes.sessions<-notes notes.title_len" {
		t.Errorf("computed fields kept: %s", got)
	}
}
