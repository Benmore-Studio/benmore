//go:build !cli && !windows

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ownedTaskFlow is the hook-parity task command with an `owns:` declaration.
// Mixed case on purpose: SQLite folds identifier case, so must the match.
func ownedTaskFlow(owns string) string {
	flow := strings.Replace(hookTaskFlow, "  writes: [tasks, activities]\n", "  writes: [tasks, activities]\n"+owns, 1)
	if flow == hookTaskFlow && owns != "" {
		panic("fixture has no writes line")
	}
	return flow
}

const ownedTaskDecl = "  owns: [Tasks.STATUS, tasks.completed_by]\n"

type ownedFieldFixture struct {
	app   *App
	mux   *http.ServeMux
	user  string
	admin string
	sid   string
}

func newOwnedFieldFixture(t *testing.T, owns string) *ownedFieldFixture {
	t.Helper()
	app, sid, _ := newCommandProviderTaskFixtureWithPolicies(t, ownedTaskFlow(owns), "")
	f := &ownedFieldFixture{app: app, sid: sid, mux: buildAppMux(app, true, "http://localhost")}
	f.user = createCrudScopeSession(t, app, "editor2@example.com", "editor", "17", "")
	f.admin = createCrudScopeSession(t, app, "boss@example.com", "admin", "17", "")
	// The fixture only defines the editor role; give admin the same table scopes so
	// the refusal under test is ownership, not a missing scope.
	app.Roles.Roles["admin"] = RoleDef{Scopes: "tasks:read tasks:write activities:read activities:write"}
	for _, email := range []string{"editor2@example.com", "boss@example.com"} {
		if _, err := app.DB.Exec(`INSERT INTO members(org_id,email,user_id) SELECT '17',email,id FROM _benmore_users WHERE email=?`, email); err != nil {
			t.Fatal(err)
		}
	}
	return f
}

func (f *ownedFieldFixture) ownedBody(t *testing.T, rec *httptest.ResponseRecorder, field string) {
	t.Helper()
	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want 403: %s", rec.Code, rec.Body.String())
	}
	var out map[string]string
	mustDecodeBody(t, rec, &out)
	if out["error"] != "field_owned_by_command" || out["command"] != "complete_item" || !strings.EqualFold(out["field"], field) {
		t.Fatalf("body = %v, want field_owned_by_command for %s from complete_item", out, field)
	}
}

func (f *ownedFieldFixture) task(t *testing.T) (title, status string, completedBy any) {
	t.Helper()
	if err := f.app.DB.QueryRow(`SELECT title,status,completed_by FROM tasks WHERE id=1`).Scan(&title, &status, &completedBy); err != nil {
		t.Fatal(err)
	}
	return
}

func rawOwnedRequest(mux *http.ServeMux, method, path, token, contentType, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Authorization", "Bearer "+token)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

func TestCommandOwnedFieldsRefuseEveryGenericWritePath(t *testing.T) {
	f := newOwnedFieldFixture(t, ownedTaskDecl)
	for _, who := range []struct{ name, token string }{{"member", f.user}, {"admin", f.admin}} {
		t.Run(who.name, func(t *testing.T) {
			// PATCH of an owned field (lower-case request key vs mixed-case declaration).
			rec := crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", who.token, map[string]any{"status": "hacked"})
			f.ownedBody(t, rec, "tasks.status")
			rec = crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", who.token, map[string]any{"title": "ok", "Completed_By": 5})
			f.ownedBody(t, rec, "tasks.Completed_By")
			if title, status, by := f.task(t); title != "Source-backed task" || status != "open" || by != nil {
				t.Fatalf("a refused update changed the row: %q %q %v", title, status, by)
			}

			// Create names the owned field.
			rec = crudScopeRequest(t, f.mux, http.MethodPost, "/api/tasks", who.token, map[string]any{"project_id": 7, "title": "new", "status": "done"})
			f.ownedBody(t, rec, "tasks.status")
			rec = rawOwnedRequest(f.mux, http.MethodPost, "/api/tasks", who.token, "application/x-www-form-urlencoded", "project_id=7&title=new&status=done")
			f.ownedBody(t, rec, "tasks.status")

			// Batch create (any item) and batch update.
			rec = crudScopeRequest(t, f.mux, http.MethodPost, "/api/tasks/batch", who.token, []map[string]any{
				{"project_id": 7, "title": "a", "status": "open"}, {"project_id": 7, "title": "b", "status": "done"}})
			f.ownedBody(t, rec, "tasks.status")
			rec = crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/batch", who.token, map[string]any{"ids": []int{1}, "fields": map[string]string{"status": "done"}})
			f.ownedBody(t, rec, "tasks.status")

			// Streaming ingest refuses the whole stream.
			rec = rawOwnedRequest(f.mux, http.MethodPost, "/api/tasks/ingest", who.token, "application/x-ndjson",
				`{"project_id":7,"title":"n1","status":"open"}`+"\n"+`{"project_id":7,"title":"n2","status":"done"}`+"\n")
			f.ownedBody(t, rec, "tasks.status")

			// Atomic transaction, insert and update.
			rec = crudScopeRequest(t, f.mux, http.MethodPost, "/api/_transaction", who.token, map[string]any{"operations": []map[string]any{
				{"table": "tasks", "action": "insert", "data": map[string]any{"project_id": 7, "title": "t", "status": "done"}}}})
			f.ownedBody(t, rec, "tasks.status")
			rec = crudScopeRequest(t, f.mux, http.MethodPost, "/api/_transaction", who.token, map[string]any{"operations": []map[string]any{
				{"table": "tasks", "action": "update", "id": 1, "data": map[string]any{"status": "done"}}}})
			f.ownedBody(t, rec, "tasks.status")

			var n int
			if err := f.app.DB.QueryRow(`SELECT count(*) FROM tasks`).Scan(&n); err != nil || n != 1 {
				t.Fatalf("refused writes left %d rows (err %v), want the single seeded task", n, err)
			}
		})
	}
}

func TestCommandOwnedFieldsLeaveOtherMetadataEditable(t *testing.T) {
	f := newOwnedFieldFixture(t, ownedTaskDecl)
	rec := crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", f.user, map[string]any{"title": "renamed"})
	if rec.Code != http.StatusOK {
		t.Fatalf("update of an unowned field: %d %s", rec.Code, rec.Body.String())
	}
	rec = crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/batch", f.user, map[string]any{"ids": []int{1}, "fields": map[string]string{"title": "batched"}})
	if rec.Code != http.StatusOK {
		t.Fatalf("batch update of an unowned field: %d %s", rec.Code, rec.Body.String())
	}
	// Another table is untouched by the declaration.
	rec = crudScopeRequest(t, f.mux, http.MethodPost, "/api/activities", f.user, map[string]any{"task_id": 1, "actor_user_id": 1, "actor_email": "a@example.com", "event": "note"})
	if rec.Code == http.StatusForbidden && strings.Contains(rec.Body.String(), "field_owned_by_command") {
		t.Fatalf("an unowned table was refused: %s", rec.Body.String())
	}
	if title, _, _ := f.task(t); title != "batched" {
		t.Fatalf("title = %q", title)
	}
}

func TestCommandOwnedFieldsCreateWithFieldUnsetUsesDefault(t *testing.T) {
	// Own only the nullable completed_at: a create that never names it succeeds
	// and the column keeps its default (NULL).
	f := newOwnedFieldFixture(t, "  owns: [tasks.completed_at]\n")
	rec := crudScopeRequest(t, f.mux, http.MethodPost, "/api/tasks", f.user, map[string]any{"project_id": 7, "title": "fresh", "status": "open"})
	if rec.Code != http.StatusOK && rec.Code != http.StatusCreated {
		t.Fatalf("create without the owned field: %d %s", rec.Code, rec.Body.String())
	}
	var at any
	if err := f.app.DB.QueryRow(`SELECT completed_at FROM tasks WHERE title='fresh'`).Scan(&at); err != nil || at != nil {
		t.Fatalf("completed_at = %v err %v, want NULL default", at, err)
	}
	rec = crudScopeRequest(t, f.mux, http.MethodPost, "/api/tasks", f.user, map[string]any{"project_id": 7, "title": "x", "status": "open", "completed_at": "2020-01-01"})
	f.ownedBody(t, rec, "tasks.completed_at")
}

func TestCommandOwnedFieldsCommandApplyStillWritesAndOtherFlowsAreNotBlocked(t *testing.T) {
	f := newOwnedFieldFixture(t, ownedTaskDecl)
	readback, err := runHookedCommand(t, f.app, f.sid)
	if err != nil {
		t.Fatalf("the owning command's own apply: %v", err)
	}
	if readback["status"] != "done" {
		t.Fatalf("readback = %#v", readback)
	}
	if _, status, by := f.task(t); status != "done" || by == nil {
		t.Fatalf("command did not write its owned fields: %q %v", status, by)
	}
	// Generic CRUD still cannot rewrite them afterwards.
	rec := crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", f.admin, map[string]any{"status": "open"})
	f.ownedBody(t, rec, "tasks.status")
}

func TestCommandOwnedFieldsReloadRemovesRestriction(t *testing.T) {
	f := newOwnedFieldFixture(t, ownedTaskDecl)
	rec := crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", f.user, map[string]any{"status": "x"})
	f.ownedBody(t, rec, "tasks.status")

	writeTestFile(t, f.app.Dir, "flows/complete_item.yaml", ownedTaskFlow(""))
	reviewAppMCPFixture(t, f.app.Dir)
	if err := reloadAppConfig(f.app); err != nil {
		t.Fatalf("reload without owns: %v", err)
	}
	rec = crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", f.user, map[string]any{"status": "x"})
	if rec.Code != http.StatusOK {
		t.Fatalf("restriction survived removal of the declaration: %d %s", rec.Code, rec.Body.String())
	}

	// ...and a reload that adds it back restores the restriction.
	writeTestFile(t, f.app.Dir, "flows/complete_item.yaml", ownedTaskFlow(ownedTaskDecl))
	reviewAppMCPFixture(t, f.app.Dir)
	if err := reloadAppConfig(f.app); err != nil {
		t.Fatalf("reload with owns: %v", err)
	}
	rec = crudScopeRequest(t, f.mux, http.MethodPatch, "/api/tasks/1", f.user, map[string]any{"status": "y"})
	f.ownedBody(t, rec, "tasks.status")
}

func TestCommandOwnedFieldsMCPCanonicalUpdateAndRevertGuards(t *testing.T) {
	f := newOwnedFieldFixture(t, ownedTaskDecl)
	// The native connector update path shares ownedFieldViolation through
	// txUpdate; assert that seam directly with the connector generation view.
	view := snapshotAppMCPGeneration(f.app).view
	if v := ownedFieldViolation(view, "tasks", "title", "STATUS"); v == nil || v.Command != "complete_item" {
		t.Fatalf("generation view does not carry the owned set: %#v", v)
	}
	// Revert restores every column except owned ones.
	row := map[string]any{"title": "old", "status": "open", "completed_by": 1}
	skipped := stripOwnedFields(f.app, "tasks", row)
	if len(skipped) != 2 || row["title"] != "old" || len(row) != 1 {
		t.Fatalf("stripOwnedFields = %v, row = %v", skipped, row)
	}
}

func TestCommandOwnedFieldsWorkflowTransitionRoute(t *testing.T) {
	f := newOwnedFieldFixture(t, ownedTaskDecl)
	wf := &Workflow{Name: "task_flow", Table: "tasks", Field: "status", Initial: "open",
		Transitions: map[string]map[string]Transition{"open": {"done": {}}}}
	req := httptest.NewRequest(http.MethodPost, "/api/tasks/1/transition", strings.NewReader(`{"to":"done"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+f.user)
	req.SetPathValue("id", "1")
	rec := httptest.NewRecorder()
	handleTransition(rec, req, f.app, wf)
	f.ownedBody(t, rec, "tasks.status")
	if _, status, _ := f.task(t); status != "open" {
		t.Fatalf("a refused transition moved the row to %q", status)
	}
}

func TestCommandOwnedFieldsImportModeARefusesOwnedColumns(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	app.Flows = []Flow{{Name: "price_command", Trigger: FlowTrigger{Type: "command"},
		Command: &FlowCommand{Writes: []string{"products"}, Owns: []FlowCommandOwn{{Table: "products", Column: "qty"}}}}}
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	sess := seedAdminSession(t, app)

	body := `{"table":"products","format":"csv","bytes":100,"sha256":"` + strings.Repeat("a", 64) + `","columns":["sku","QTY"]}`
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, authedRequest("POST", "/api/_import", body, sess))
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), "field_owned_by_command") {
		t.Fatalf("declared owned column: %d %s", rec.Code, rec.Body.String())
	}
	cols, err := importableColumns(app.DB, "products", app)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range cols {
		if strings.EqualFold(c.Name, "qty") {
			t.Fatal("an owned column is importable, so a file header could still write it at load time")
		}
	}
	if _, _, err := newCSVSource(strings.NewReader("sku,qty\na,1\n"), cols, ""); err == nil {
		t.Fatal("the loader accepted a header naming an owned column")
	}
	// NDJSON ignores unknown keys, but an owned key must fail the load, in the
	// first object and mid-stream.
	check := func(keys []string) error {
		if v := ownedFieldViolation(app, "products", keys...); v != nil {
			return v
		}
		return nil
	}
	nd, _, err := newNDJSONSource(strings.NewReader(`{"sku":"a","qty":1}`+"\n"), cols)
	if err != nil {
		t.Fatal(err)
	}
	if err := nd.(*ndjsonSource).refuseKeys(check); err == nil {
		t.Fatal("NDJSON first object with an owned key was accepted")
	}
	nd, _, err = newNDJSONSource(strings.NewReader(`{"sku":"a"}`+"\n"+`{"sku":"b","qty":2}`+"\n"), cols)
	if err != nil {
		t.Fatal(err)
	}
	if err := nd.(*ndjsonSource).refuseKeys(check); err != nil {
		t.Fatal(err)
	}
	if _, err := nd.Next(); err != nil {
		t.Fatal(err)
	}
	if _, err := nd.Next(); err == nil || !strings.Contains(err.Error(), "owned by command") {
		t.Fatalf("mid-stream owned key: %v", err)
	}

	body = `{"table":"products","format":"csv","bytes":100,"sha256":"` + strings.Repeat("a", 64) + `","columns":["sku"]}`
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, authedRequest("POST", "/api/_import", body, sess))
	if rec.Code != http.StatusOK {
		t.Fatalf("import without the owned column: %d %s", rec.Code, rec.Body.String())
	}
}

func ownedParse(t *testing.T, owns string, columns map[string]map[string]string) (Flow, error) {
	t.Helper()
	source := strings.Replace(commandFixture, "  writes: [work_items]\n", "  writes: [work_items]\n"+owns, 1)
	return parseFlowCommandFileColumns("flows/complete_item.yaml", []byte(source), map[string]bool{"work_items": true, "other": true}, columns)
}

func TestCommandOwnsDeclarationValidation(t *testing.T) {
	columns := map[string]map[string]string{
		"work_items": {"id": "id", "status": "Status", "published_at": "published_at"},
		"other":      {"flag": "flag"},
	}
	flow, err := ownedParse(t, "  owns: [WORK_ITEMS.status, work_items.PUBLISHED_AT]\n", columns)
	if err != nil {
		t.Fatalf("valid owns: %v", err)
	}
	if got := flow.Command.Owns; len(got) != 2 || got[0] != (FlowCommandOwn{"work_items", "Status"}) || got[1] != (FlowCommandOwn{"work_items", "published_at"}) {
		t.Fatalf("owns not canonicalized to schema spelling: %#v", got)
	}
	for name, tc := range map[string]struct{ owns, want string }{
		"unknown table":       {"  owns: [ghosts.status]\n", "unknown table"},
		"table not in writes": {"  owns: [other.flag]\n", "not in this command's writes"},
		"unknown column":      {"  owns: [work_items.ghost]\n", "is not a column"},
		"duplicate":           {"  owns: [work_items.status, WORK_ITEMS.STATUS]\n", "duplicate"},
		"no dot":              {"  owns: [status]\n", "table.column"},
		"extra dot":           {"  owns: [work_items.status.x]\n", "table.column"},
		"not a list":          {"  owns: work_items.status\n", "list"},
		"empty list":          {"  owns: []\n", "list"},
		"non-string entry":    {"  owns: [1]\n", "table.column"},
	} {
		if _, err := ownedParse(t, tc.owns, columns); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err = %v, want it to contain %q", name, err, tc.want)
		}
	}
	// No column inventory means owns cannot be verified, so it is refused.
	if _, err := ownedParse(t, "  owns: [work_items.status]\n", nil); err == nil {
		t.Error("owns accepted without a column inventory")
	}
	// A command without owns still parses with the legacy entry point.
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(commandFixture), map[string]bool{"work_items": true}); err != nil {
		t.Fatal(err)
	}
}

// The write-time validator and `benmore check` share one dispatcher, so a bad
// owns declaration is reported by both with the same message.
func TestCommandOwnsWriteValidatorAndCheckAgree(t *testing.T) {
	f := newOwnedFieldFixture(t, ownedTaskDecl)
	bad := ownedTaskFlow("  owns: [tasks.no_such_column]\n")
	msg := ValidateOnWriteIn(f.app.Dir, "flows/complete_item.yaml", bad)
	if !strings.Contains(msg, "no_such_column") || !strings.Contains(msg, "is not a column") {
		t.Fatalf("write validator: %q", msg)
	}
	if got := ValidateOnWriteIn(f.app.Dir, "flows/complete_item.yaml", ownedTaskFlow(ownedTaskDecl)); got != "" {
		t.Fatalf("valid owns refused by the write validator: %q", got)
	}
	notWritten := ownedTaskFlow("  owns: [members.email]\n")
	if got := ValidateOnWriteIn(f.app.Dir, "flows/complete_item.yaml", notWritten); !strings.Contains(got, "not in this command's writes") {
		t.Fatalf("table outside writes: %q", got)
	}

	if err := os.WriteFile(filepath.Join(f.app.Dir, "flows", "complete_item.yaml"), []byte(bad), 0o644); err != nil {
		t.Fatal(err)
	}
	report := RunSourceCheck(f.app.Dir, "")
	found := false
	for _, finding := range report.Findings {
		if finding.Severity == "error" && finding.File == "flows/complete_item.yaml" && strings.Contains(finding.Message, "no_such_column") {
			found = true
		}
	}
	if !found {
		b, _ := json.Marshal(report)
		t.Fatalf("benmore check did not report the owns error: %s", b)
	}
}
