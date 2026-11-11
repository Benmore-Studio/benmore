//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The inserts the framework builds itself (bulk import Mode A, the founding
// membership of /api/_groups/create, the member-of auto-join) start a row in
// its workflow's `initial` state, like every request-driven create.

// newWorkflowImportApp: docs has a nullable state column with no default,
// tickets a NOT NULL one with no default (the shape testdata/workflow_null_state
// supports for API creates), plain has a workflow that declares no `initial`.
func newWorkflowImportApp(t *testing.T) (*App, int64, string) {
	t.Helper()
	app := newGateApp(t,
		`CREATE TABLE docs (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, status TEXT, user_id INTEGER)`,
		`CREATE TABLE tickets (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, note TEXT, status TEXT NOT NULL, user_id INTEGER)`,
		`CREATE TABLE plain (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, status TEXT DEFAULT 'column-default')`,
	)
	EnsureImportsTable(app)
	EnsureJobsTable(app.DB)
	EnsureWebhooksTable(app.DB)
	app.Workflows = &WorkflowConfig{Workflows: map[string]*Workflow{
		"docs": {
			Name: "docs", Table: "docs", Field: "status", Initial: "draft",
			States:      []string{"draft", "review", "published"},
			Transitions: map[string]map[string]Transition{"draft": {"review": {}}, "review": {"published": {Role: "admin"}}},
		},
		"tickets": {
			Name: "tickets", Table: "tickets", Field: "status", Initial: "new",
			States:      []string{"new", "closed"},
			Transitions: map[string]map[string]Transition{"new": {"closed": {}}},
		},
		"plain": {
			Name: "plain", Table: "plain", Field: "status",
			States:      []string{"open", "done"},
			Transitions: map[string]map[string]Transition{"open": {"done": {}}},
		},
	}}
	uid, sid := gateUser(t, app, "importer@example.com")
	return app, uid, sid
}

func runWorkflowImport(t *testing.T, app *App, id, table, format, content string, owner int64) error {
	t.Helper()
	sum := stageString(t, app, id, content)
	sess := &importSession{
		ID: id, TableName: table, Format: format,
		BytesTotal: int64(len(content)), SHA256: sum, CreatedBy: owner,
	}
	insertSession(t, app, sess)
	return runImport(app, sess)
}

// tableStates lists "<title>=<state>" per row, NULL spelled out.
func tableStates(t *testing.T, app *App, table string) string {
	t.Helper()
	rows, err := app.DB.Query("SELECT COALESCE(title, '-'), COALESCE(status, 'NULL') FROM " + table + " ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var title, status string
		if err := rows.Scan(&title, &status); err != nil {
			t.Fatal(err)
		}
		got = append(got, title+"="+status)
	}
	return strings.Join(got, " ")
}

func workflowTransition(app *App, wf *Workflow, sid, id, to string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", "https://app.example.com/api/"+wf.Table+"/"+id+"/transition", strings.NewReader(`{"to":"`+to+`"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+sid)
	r.SetPathValue("id", id)
	w := httptest.NewRecorder()
	handleTransition(w, r, app, wf)
	return w
}

// Reviewer repro (round 1110, state F3): a CSV with only `title` left a
// nullable state column NULL (a row no transition leaves) and could not load
// at all into a NOT NULL one.
func TestRunImportStartsRowsInWorkflowInitial(t *testing.T) {
	app, uid, sid := newWorkflowImportApp(t)
	csv := "title\nimported-1\nimported-2\n"

	if err := runWorkflowImport(t, app, "wfimport0001", "docs", "csv", csv, uid); err != nil {
		t.Fatalf("import into a nullable state column: %v", err)
	}
	if got, want := tableStates(t, app, "docs"), "imported-1=draft imported-2=draft"; got != want {
		t.Fatalf("docs after import = %q, want %q", got, want)
	}
	if err := runWorkflowImport(t, app, "wfimport0002", "tickets", "csv", csv, uid); err != nil {
		t.Fatalf("import into a NOT NULL state column with no default: %v", err)
	}
	if got, want := tableStates(t, app, "tickets"), "imported-1=new imported-2=new"; got != want {
		t.Fatalf("tickets after import = %q, want %q", got, want)
	}
	// The importer owns the rows, next to the state the framework wrote.
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM docs WHERE user_id = ?", uid); got != "2" {
		t.Fatalf("imported docs owned by the importer = %s, want 2", got)
	}

	// An imported row is a working workflow row: it leaves `initial` through
	// the transition endpoint.
	if w := workflowTransition(app, app.Workflows.Workflows["docs"], sid, "1", "review"); w.Code != http.StatusOK {
		t.Fatalf("transition of an imported row: %d %s", w.Code, w.Body.String())
	}
	if got, want := tableStates(t, app, "docs"), "imported-1=review imported-2=draft"; got != want {
		t.Fatalf("docs after the transition = %q, want %q", got, want)
	}
}

// NDJSON takes the per-row statement when an object leaves a key out; the
// state is written there too, an object that names the state column cannot
// choose it, and an empty object is a row in `initial`.
func TestRunImportNDJSONStartsRowsInWorkflowInitial(t *testing.T) {
	app, uid, _ := newWorkflowImportApp(t)
	content := `{"title":"full","note":"n"}` + "\n" +
		`{"title":"no-note"}` + "\n" +
		`{"title":"names-a-state","note":"n","status":"closed"}` + "\n" +
		`{}` + "\n"
	if err := runWorkflowImport(t, app, "wfimport0003", "tickets", "ndjson", content, uid); err != nil {
		t.Fatalf("ndjson import: %v", err)
	}
	if got, want := tableStates(t, app, "tickets"), "full=new no-note=new names-a-state=new -=new"; got != want {
		t.Fatalf("tickets after import = %q, want %q", got, want)
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM tickets WHERE user_id = ?", uid); got != "4" {
		t.Fatalf("imported tickets owned by the importer = %s, want 4", got)
	}
	// An owner-token import has no app user: no owner column, state still set.
	if err := runWorkflowImport(t, app, "wfimport0004", "docs", "ndjson", `{"title":"unowned"}`+"\n"+`{}`+"\n", 0); err != nil {
		t.Fatalf("unowned ndjson import: %v", err)
	}
	if got, want := tableStates(t, app, "docs"), "unowned=draft -=draft"; got != want {
		t.Fatalf("docs after import = %q, want %q", got, want)
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM docs WHERE user_id IS NOT NULL"); got != "0" {
		t.Fatalf("an owner-token import assigned an owner to %s rows", got)
	}
}

// What must not change: a file still cannot name the state column, and a
// workflow that declares no `initial` leaves the column to its default.
func TestRunImportWorkflowStateStaysOutOfTheFile(t *testing.T) {
	app, uid, _ := newWorkflowImportApp(t)

	err := runWorkflowImport(t, app, "wfimport0005", "docs", "csv", "title,status\nx,published\n", uid)
	if err == nil || !strings.Contains(err.Error(), `"status" is not an importable column`) {
		t.Fatalf("a CSV naming the state column = %v, want a not-importable refusal", err)
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM docs"); got != "0" {
		t.Fatalf("a refused file left %s rows", got)
	}
	if err := validateImportColumns(app.DB, "docs", app, []string{"title", "status"}); err == nil {
		t.Fatal("declaring the state column at create must stay refused")
	}

	if err := runWorkflowImport(t, app, "wfimport0006", "plain", "csv", "title\na\n", 0); err != nil {
		t.Fatalf("import into a workflow table without initial: %v", err)
	}
	if got, want := tableStates(t, app, "plain"), "a=column-default"; got != want {
		t.Fatalf("plain after import = %q, want %q", got, want)
	}

	// A workflow whose field the table does not have never reaches the INSERT.
	app.Workflows.Workflows["plain"].Field = "stage"
	app.Workflows.Workflows["plain"].Initial = "open"
	if err := runWorkflowImport(t, app, "wfimport0007", "plain", "csv", "title\nb\n", 0); err != nil {
		t.Fatalf("import with a workflow naming a missing column: %v", err)
	}
	if got, want := tableStates(t, app, "plain"), "a=column-default b=column-default"; got != want {
		t.Fatalf("plain after import = %q, want %q", got, want)
	}
}

// The state is a bound value placed before the generated UUID expressions of
// an existing Prisma table, on the prepared statement and on the per-row one.
func TestRunImportWorkflowInitialWithGeneratedUUIDColumns(t *testing.T) {
	const schema = `model Item {
 id String @id @default(uuid())
 userId Int?
 name String
 note String?
 reference String? @default(uuid())
 status String
}`
	for _, format := range []string{"csv", "ndjson"} {
		t.Run(format, func(t *testing.T) {
			app := newGateApp(t, fmt.Sprintf(`CREATE TABLE items (id TEXT PRIMARY KEY DEFAULT %s, user_id INTEGER, name TEXT NOT NULL, note TEXT, reference TEXT DEFAULT %s, status TEXT NOT NULL)`, oldPrismaUUIDDefault, oldPrismaUUIDDefault))
			EnsureImportsTable(app)
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(schema), 0600); err != nil {
				t.Fatal(err)
			}
			tables, deferred, err := LoadSchema(app.DB, dir)
			if err != nil {
				t.Fatal(err)
			}
			if err := ApplyDeferredDDL(app.DB, deferred); err != nil {
				t.Fatal(err)
			}
			app.Tables = tables
			app.UUIDTables = DetectUUIDTables(app.Tables)
			app.Workflows = &WorkflowConfig{Workflows: map[string]*Workflow{"items": {
				Name: "items", Table: "items", Field: "status", Initial: "queued",
				States: []string{"queued", "done"}, Transitions: map[string]map[string]Transition{"queued": {"done": {}}},
			}}}
			uid, _ := gateUser(t, app, "uuid-importer@example.com")

			content := "name,note\nfirst,n\nsecond,n\n"
			if format == "ndjson" {
				content = `{"name":"first","note":"n"}` + "\n" + `{"name":"second"}` + "\n"
			}
			if err := runWorkflowImport(t, app, "wfimportuuid1", "items", format, content, uid); err != nil {
				t.Fatalf("import: %v", err)
			}
			rows, err := app.DB.Query(`SELECT id, reference, status, user_id, name FROM items ORDER BY name`)
			if err != nil {
				t.Fatal(err)
			}
			defer rows.Close()
			var names []string
			for rows.Next() {
				var id, reference, status, name string
				var owner int64
				if err := rows.Scan(&id, &reference, &status, &owner, &name); err != nil {
					t.Fatal(err)
				}
				if !uuid4Pattern.MatchString(id) || !uuid4Pattern.MatchString(reference) {
					t.Errorf("%s: generated values are not UUID v4: id=%q reference=%q", name, id, reference)
				}
				if status != "queued" || owner != uid {
					t.Errorf("%s: status=%q owner=%d, want queued and %d", name, status, owner, uid)
				}
				names = append(names, name)
			}
			if strings.Join(names, " ") != "first second" {
				t.Fatalf("imported rows = %v, want first and second", names)
			}
		})
	}
}

// newWorkflowBootstrapApp is newBootstrapTestApp with a workflow on the
// membership table; stateDDL declares its state column.
func newWorkflowBootstrapApp(t *testing.T, stateDDL string) (*App, string) {
	t.Helper()
	app, uid, cleanup := newBootstrapTestApp(t, "user_id")
	t.Cleanup(cleanup)
	mustExec(t, app.DB, "DROP TABLE company_members")
	mustExec(t, app.DB, "CREATE TABLE company_members (id INTEGER PRIMARY KEY AUTOINCREMENT, company_id INTEGER NOT NULL, email TEXT, user_id INTEGER, member_role TEXT, "+stateDDL+")")
	app.Workflows = &WorkflowConfig{Workflows: map[string]*Workflow{"membership": {
		Name: "membership", Table: "company_members", Field: "standing", Initial: "active",
		States:      []string{"active", "suspended"},
		Transitions: map[string]map[string]Transition{"active": {"suspended": {Role: "company_admin"}}},
	}}}
	return app, CreateSession(app.DB, uid, "founder@example.com", "", time.Hour)
}

// By trace in the same finding: the founding membership row of
// /api/_groups/create skipped the workflow's initial state.
func TestGroupBootstrapFoundingMembershipStartsInWorkflowInitial(t *testing.T) {
	for name, stateDDL := range map[string]string{
		"nullable": "standing TEXT",
		"not_null": "standing TEXT NOT NULL",
		"default":  "standing TEXT NOT NULL DEFAULT 'suspended'",
	} {
		t.Run(name, func(t *testing.T) {
			app, sid := newWorkflowBootstrapApp(t, stateDDL)
			if w := bootstrapAs(app, sid, `{"name":"Acme"}`); w.Code != http.StatusOK {
				t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
			}
			var standing sql.NullString
			var role string
			if err := app.DB.QueryRow("SELECT standing, member_role FROM company_members").Scan(&standing, &role); err != nil {
				t.Fatalf("founding membership row: %v", err)
			}
			if standing.String != "active" || role != "company_admin" {
				t.Fatalf("founding membership standing=%q (valid=%v) role=%q, want active and company_admin", standing.String, standing.Valid, role)
			}
		})
	}
}

// A workflow over a column the bootstrap writes itself (the founding role)
// does not replace that value.
func TestGroupBootstrapKeepsFoundingRoleUnderAWorkflow(t *testing.T) {
	app, sid := newWorkflowBootstrapApp(t, "standing TEXT")
	app.Workflows.Workflows["membership"].Field = "member_role"
	app.Workflows.Workflows["membership"].Initial = "member"
	if w := bootstrapAs(app, sid, `{"name":"Acme"}`); w.Code != http.StatusOK {
		t.Fatalf("bootstrap: %d %s", w.Code, w.Body.String())
	}
	if got := gateScalar(t, app, "SELECT member_role FROM company_members"); got != "company_admin" {
		t.Fatalf("founding role = %q, want company_admin", got)
	}
}

// newWorkflowMemberOfApp: rooms is the member-of parent of room_members, and
// room_members carries a workflow; stateDDL declares its state column.
func newWorkflowMemberOfApp(t *testing.T, stateDDL string) (*App, *http.ServeMux, string, int64) {
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
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	crudScopeMustExec(t, db, `CREATE TABLE rooms (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT)`)
	crudScopeMustExec(t, db, `CREATE TABLE room_members (id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER, member_id INTEGER, `+stateDDL+`, UNIQUE(room_id, member_id))`)
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Access: accessFromYAML(t, "access:\n  rooms: member-of:room_members(room_id, member_id)\n"),
		Workflows: &WorkflowConfig{Workflows: map[string]*Workflow{"room_members": {
			Name: "room_members", Table: "room_members", Field: "standing", Initial: "active",
			States:      []string{"active", "muted"},
			Transitions: map[string]map[string]Transition{"active": {"muted": {Role: "admin"}}},
		}}},
	}
	for _, name := range []string{"rooms", "room_members"} {
		cols, err := GetTableColumns(db, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	app.JoinMap = BuildJoinMap(db)
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "http://localhost")
	sid := createCrudScopeSession(t, app, "founder@example.com", "user", "", "")
	var uid int64
	if err := db.QueryRow("SELECT id FROM _benmore_users WHERE email = 'founder@example.com'").Scan(&uid); err != nil {
		t.Fatal(err)
	}
	return app, mux, sid, uid
}

// By trace in the same finding: the member-of auto-join skipped the
// workflow's initial state. With a NOT NULL state column the join failed, so
// a single create left its creator unable to read the room and a batch or
// transaction create was refused.
func TestMemberOfAutoJoinStartsInWorkflowInitial(t *testing.T) {
	for name, stateDDL := range map[string]string{
		"nullable": "standing TEXT",
		"not_null": "standing TEXT NOT NULL",
	} {
		t.Run(name, func(t *testing.T) {
			app, mux, sid, uid := newWorkflowMemberOfApp(t, stateDDL)

			single := crudScopeRequest(t, mux, http.MethodPost, "/api/rooms", sid, map[string]any{"title": "single"})
			if single.Code != http.StatusOK || single.Header().Get("X-Member-Of-AutoJoin") != "" {
				t.Fatalf("single create: %d %s (auto-join header %q)", single.Code, single.Body.String(), single.Header().Get("X-Member-Of-AutoJoin"))
			}
			assertStatus(t, mux, http.MethodPost, "/api/rooms/batch", sid, []any{map[string]any{"title": "batch"}}, http.StatusOK)
			assertStatus(t, mux, http.MethodPost, "/api/_transaction", sid, map[string]any{"operations": []any{
				map[string]any{"table": "rooms", "action": "insert", "data": map[string]any{"title": "transaction"}},
			}}, http.StatusOK)

			if n := memberOfCount(t, app, "SELECT COUNT(*) FROM room_members WHERE member_id = ? AND standing = 'active'", uid); n != 3 {
				t.Fatalf("auto-joined memberships in the initial state = %d, want 3 (rows: %d)", n, memberOfCount(t, app, "SELECT COUNT(*) FROM room_members"))
			}
			// The creator reads every room back through those memberships.
			list := crudScopeRequest(t, mux, http.MethodGet, "/api/rooms", sid, nil)
			for _, title := range []string{"single", "batch", "transaction"} {
				if !strings.Contains(list.Body.String(), `"`+title+`"`) {
					t.Fatalf("creator cannot read room %q back: %d %s", title, list.Code, list.Body.String())
				}
			}
		})
	}
}
