//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

// newGateApp returns an app with the framework tables the CRUD handlers need
// and the given schema, with app.Tables and app.JoinMap loaded from it.
func newGateApp(t *testing.T, schema ...string) *App {
	t.Helper()
	app, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	EnsureSessionsTable(app.DB)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatalf("EnsureUsersTable: %v", err)
	}
	EnsureAuditLogTable(app.DB)
	EnsureLocksTable(app.DB)
	EnsurePermissionsTable(app.DB)
	for _, q := range schema {
		mustExec(t, app.DB, q)
	}
	reloadGateSchema(t, app)
	return app
}

func reloadGateSchema(t *testing.T, app *App) {
	t.Helper()
	names, err := GetTableNames(app.DB)
	if err != nil {
		t.Fatal(err)
	}
	app.Tables = nil
	for _, n := range names {
		cols, err := GetTableColumns(app.DB, n)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: n, Columns: cols})
	}
	app.JoinMap = BuildJoinMap(app.DB)
}

func gateUser(t *testing.T, app *App, email string) (int64, string) {
	t.Helper()
	res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES (?, ?, 'user', 1)", email, email)
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}
	uid, _ := res.LastInsertId()
	return uid, CreateSession(app.DB, uid, email, "", time.Hour)
}

func gateCall(app *App, handler func(http.ResponseWriter, *http.Request, *App, string), table, method, path, ctype, body, sid string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "https://app.example.com"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", ctype)
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	handler(w, r, app, table)
	return w
}

func gateScalar(t *testing.T, app *App, q string, args ...any) string {
	t.Helper()
	var v any
	if err := app.DB.QueryRow(q, args...).Scan(&v); err != nil {
		t.Fatalf("%s: %v", q, err)
	}
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	if v == nil {
		return "<nil>"
	}
	b, _ := json.Marshal(v)
	return strings.Trim(string(b), `"`)
}

// A before-update `when:` guard reads the CURRENT row merged with the change.
// Batch update used to hand hooks only the submitted fields, so a guard on a
// column the batch didn't touch (status) saw NULL and never fired.
func TestBatchUpdateBeforeHookSeesMergedRow(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE invoices (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, status TEXT, note TEXT)")
	uid, sid := gateUser(t, app, "owner@example.com")
	mustExec(t, app.DB, "INSERT INTO invoices (id, user_id, status, note) VALUES (1, "+strconv.FormatInt(uid, 10)+", 'paid', 'orig')")
	app.Hooks = &HookConfig{BeforeUpdate: map[string][]Hook{
		"invoices": {{SQL: "SELECT 'paid invoices are frozen' AS error", When: "status = 'paid'"}},
	}}

	w := gateCall(app, handleBatchUpdate, "invoices", "PATCH", "/api/invoices/batch", "application/json", `{"ids":[1],"fields":{"note":"changed"}}`, sid)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "paid invoices are frozen") {
		t.Fatalf("guard on the merged row must refuse the batch: %d %s", w.Code, w.Body.String())
	}
	if got := gateScalar(t, app, "SELECT note FROM invoices WHERE id = 1"); got != "orig" {
		t.Fatalf("guarded batch update applied: note = %q", got)
	}
}

// validators.yaml cross-field rules apply to batch create (only `required`
// :validate rules used to run there) and to ingest.
func TestBatchCreateAndIngestApplyCrossFieldValidators(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE invoices (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, amount REAL, note TEXT)")
	_, sid := gateUser(t, app, "owner@example.com")
	app.Validators = &ValidatorConfig{Rules: map[string][]ValidatorRule{
		"invoices": {{Rule: "amount > 0", Error: "amount must be positive"}},
	}}

	w := gateCall(app, handleBatchCreate, "invoices", "POST", "/api/invoices/batch", "application/json", `[{"amount":5},{"amount":-3}]`, sid)
	if w.Code != http.StatusUnprocessableEntity || !strings.Contains(w.Body.String(), "amount must be positive") {
		t.Fatalf("batch create must apply validators.yaml: %d %s", w.Code, w.Body.String())
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM invoices"); n != "0" {
		t.Fatalf("a refused batch must roll back every item, have %s rows", n)
	}

	w = gateCall(app, handleStreamingIngest, "invoices", "POST", "/api/invoices/ingest", "application/x-ndjson", "{\"amount\":5}\n{\"amount\":-3}\n", sid)
	if w.Code != http.StatusOK {
		t.Fatalf("ingest: %d %s", w.Code, w.Body.String())
	}
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	if out["ingested"] != float64(1) || out["errors"] != float64(1) {
		t.Fatalf("ingest must skip the invalid row: %v", out)
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM invoices WHERE amount < 0"); n != "0" {
		t.Fatalf("an invalid row was ingested")
	}
}

// Batch create fires the same after-hooks as a single create and writes
// audit rows with the created values (it used to fire none and log nil).
func TestBatchCreateFiresAfterHooksAndAuditsValues(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE invoices (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, note TEXT)")
	EnsureJobsTable(app.DB)
	_, sid := gateUser(t, app, "owner@example.com")
	app.Hooks = &HookConfig{OnInsert: map[string][]Hook{
		"invoices": {{SQL: "SELECT 1"}},
	}}
	w := gateCall(app, handleBatchCreate, "invoices", "POST", "/api/invoices/batch", "application/json", `[{"note":"a"},{"note":"b"}]`, sid)
	if w.Code != http.StatusOK {
		t.Fatalf("batch create: %d %s", w.Code, w.Body.String())
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_jobs WHERE job_type = 'hook'"); n != "2" {
		t.Fatalf("after-insert hooks queued for batch items = %s, want 2", n)
	}
	if got := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_audit_log WHERE table_name = 'invoices' AND new_values LIKE '%\"note\":\"b\"%'"); got != "1" {
		t.Fatalf("batch create audit rows must carry the created values, matched %s", got)
	}
}

// A record lock held by someone else blocks batch update, batch delete and a
// single DELETE, as it already blocked PATCH.
func TestLocksBlockBatchAndDelete(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE docs (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT)")
	app.Access = &AccessConfig{rules: map[string]map[AccessOp]string{"docs": {"all": "everyone"}}}
	_, sidA := gateUser(t, app, "a@example.com")
	uidB, _ := gateUser(t, app, "b@example.com")
	mustExec(t, app.DB, "INSERT INTO docs (id, title) VALUES (1, 'orig')")
	if _, err := app.DB.Exec("INSERT INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at) VALUES ('docs', '1', ?, 'b@example.com', datetime('now', '+1 hour'))", uidB); err != nil {
		t.Fatal(err)
	}

	if w := gateCall(app, handleBatchUpdate, "docs", "PATCH", "/api/docs/batch", "application/json", `{"ids":[1],"fields":{"title":"x"}}`, sidA); w.Code != http.StatusConflict {
		t.Fatalf("batch update of a locked row: %d %s", w.Code, w.Body.String())
	}
	if w := gateCall(app, handleBatchDelete, "docs", "DELETE", "/api/docs/batch", "application/json", `{"ids":[1]}`, sidA); w.Code != http.StatusConflict {
		t.Fatalf("batch delete of a locked row: %d %s", w.Code, w.Body.String())
	}
	if w := gateCall(app, handleDelete, "docs", "DELETE", "/api/docs/1", "application/json", "", sidA); w.Code != http.StatusConflict {
		t.Fatalf("delete of a locked row: %d %s", w.Code, w.Body.String())
	}
	if got := gateScalar(t, app, "SELECT title FROM docs WHERE id = 1"); got != "orig" {
		t.Fatalf("locked row changed: %q", got)
	}
}

// Computed columns are derived by triggers; no create or batch path accepts
// a client value for them.
func TestComputedColumnNotWritableThroughBulkPaths(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE lines (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, qty INTEGER, total INTEGER)")
	_, sid := gateUser(t, app, "owner@example.com")
	app.Computed = &ComputedFieldConfig{Fields: map[string]map[string]*ComputedField{
		"lines": {"total": {Table: "lines", Column: "total", Expr: "qty * 10"}},
	}}

	gateCall(app, handleCreate, "lines", "POST", "/api/lines", "application/json", `{"qty":1,"total":999}`, sid)
	gateCall(app, handleBatchCreate, "lines", "POST", "/api/lines/batch", "application/json", `[{"qty":2,"total":999}]`, sid)
	gateCall(app, handleStreamingIngest, "lines", "POST", "/api/lines/ingest", "application/x-ndjson", "{\"qty\":3,\"total\":999}\n", sid)
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM lines"); n != "3" {
		t.Fatalf("expected the three creates to land, have %s", n)
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM lines WHERE total = 999"); n != "0" {
		t.Fatalf("a computed column took a client value on create")
	}
	w := gateCall(app, handleBatchUpdate, "lines", "PATCH", "/api/lines/batch", "application/json", `{"ids":[1],"fields":{"total":"999"}}`, sid)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("batch update naming only a computed column: %d %s", w.Code, w.Body.String())
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM lines WHERE total = 999"); n != "0" {
		t.Fatalf("a computed column took a client value on batch update")
	}
}

// A foreign key may only point at a parent the caller can read. Another
// owner's parent and a missing parent get the same refusal, on every write
// path, so the response is not an existence oracle.
func TestForeignKeyTargetMustBeReadable(t *testing.T) {
	app := newGateApp(t,
		"CREATE TABLE projects (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT)",
		"CREATE TABLE tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, project_id INTEGER REFERENCES projects(id), title TEXT)")
	uidA, _ := gateUser(t, app, "a@example.com")
	uidB, sidB := gateUser(t, app, "b@example.com")
	mustExec(t, app.DB, "INSERT INTO projects (id, user_id, name) VALUES (1, "+strconv.FormatInt(uidA, 10)+", 'A'), (2, "+strconv.FormatInt(uidB, 10)+", 'B')")
	mustExec(t, app.DB, "INSERT INTO tasks (id, user_id, project_id, title) VALUES (10, "+strconv.FormatInt(uidB, 10)+", 2, 'mine')")

	foreign := gateCall(app, handleCreate, "tasks", "POST", "/api/tasks", "application/json", `{"project_id":1,"title":"x"}`, sidB)
	missing := gateCall(app, handleCreate, "tasks", "POST", "/api/tasks", "application/json", `{"project_id":9999,"title":"x"}`, sidB)
	if foreign.Code != http.StatusUnprocessableEntity || missing.Code != foreign.Code || missing.Body.String() != foreign.Body.String() {
		t.Fatalf("foreign and missing parents must be refused identically: %d %s / %d %s", foreign.Code, foreign.Body.String(), missing.Code, missing.Body.String())
	}
	if w := gateCall(app, handleCreate, "tasks", "POST", "/api/tasks", "application/json", `{"project_id":2,"title":"ok"}`, sidB); w.Code != http.StatusOK {
		t.Fatalf("own parent must be accepted: %d %s", w.Code, w.Body.String())
	}
	if w := gateCall(app, handleBatchCreate, "tasks", "POST", "/api/tasks/batch", "application/json", `[{"project_id":1,"title":"x"}]`, sidB); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("batch create into another owner's parent: %d %s", w.Code, w.Body.String())
	}
	if w := gateCall(app, handleUpdate, "tasks", "PATCH", "/api/tasks/10", "application/json", `{"project_id":1}`, sidB); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("re-pointing to another owner's parent: %d %s", w.Code, w.Body.String())
	}
	if w := gateCall(app, handleBatchUpdate, "tasks", "PATCH", "/api/tasks/batch", "application/json", `{"ids":[10],"fields":{"project_id":"1"}}`, sidB); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("batch re-point to another owner's parent: %d %s", w.Code, w.Body.String())
	}
	r := httptest.NewRequest("POST", "https://app.example.com/api/_transaction", strings.NewReader(`{"operations":[{"table":"tasks","action":"insert","data":{"project_id":1,"title":"x"}}]}`))
	r.Header.Set("Authorization", "Bearer "+sidB)
	w := httptest.NewRecorder()
	handleTransaction(w, r, app)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("transaction insert into another owner's parent: %d %s", w.Code, w.Body.String())
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM tasks WHERE project_id = 1"); n != "0" {
		t.Fatalf("a task landed under another owner's project")
	}
	if got := gateScalar(t, app, "SELECT project_id FROM tasks WHERE id = 10"); got != "2" {
		t.Fatalf("re-point applied: project_id = %s", got)
	}
}

// An aggregate computed field's trigger rewrites the parent its FK names
// (`UPDATE parent ... WHERE id = NEW.fk`), even when the FK is undeclared in
// the schema. Pointing a row at another tenant's parent would rewrite that
// tenant's aggregate, so the trigger FK is gated like a declared one.
func TestAggregateTriggerFKCannotTargetAnotherOwner(t *testing.T) {
	app := newGateApp(t,
		"CREATE TABLE projects (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, note_count INTEGER DEFAULT 0)",
		"CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, project_ref INTEGER)")
	uidA, _ := gateUser(t, app, "a@example.com")
	_, sidB := gateUser(t, app, "b@example.com")
	mustExec(t, app.DB, "INSERT INTO projects (id, user_id, note_count) VALUES (1, "+strconv.FormatInt(uidA, 10)+", 0)")
	cfg := &ComputedFieldConfig{Fields: map[string]map[string]*ComputedField{
		"projects": {"note_count": {Table: "projects", Column: "note_count",
			SQL:      "SELECT COUNT(*) FROM notes WHERE project_ref = ?",
			Triggers: []ComputedTriggerDef{{Table: "notes", On: []string{"insert"}, FK: "project_ref"}}}},
	}}
	if err := installComputedTriggersChecked(app.DB, cfg); err != nil {
		t.Fatal(err)
	}
	app.Computed = cfg

	w := gateCall(app, handleCreate, "notes", "POST", "/api/notes", "application/json", `{"project_ref":1}`, sidB)
	if w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("note pointing at another owner's project: %d %s", w.Code, w.Body.String())
	}
	if got := gateScalar(t, app, "SELECT note_count FROM projects WHERE id = 1"); got != "0" {
		t.Fatalf("another owner's aggregate was rewritten: %s", got)
	}
	// The aggregate column itself is computed, so a client can't set it.
	gateCall(app, handleCreate, "projects", "POST", "/api/projects", "application/json", `{"note_count":42}`, sidB)
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM projects WHERE note_count = 42"); n != "0" {
		t.Fatalf("an aggregate column took a client value")
	}
}

// Raw constraint text (table, column, value) is not echoed in production.
func TestCreateConstraintErrorIsRedacted(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE handles (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, handle TEXT UNIQUE)")
	_, sidA := gateUser(t, app, "a@example.com")
	_, sidB := gateUser(t, app, "b@example.com")
	if w := gateCall(app, handleCreate, "handles", "POST", "/api/handles", "application/json", `{"handle":"taken"}`, sidA); w.Code != http.StatusOK {
		t.Fatalf("first create: %d %s", w.Code, w.Body.String())
	}
	for name, w := range map[string]*httptest.ResponseRecorder{
		"single": gateCall(app, handleCreate, "handles", "POST", "/api/handles", "application/json", `{"handle":"taken"}`, sidB),
		"batch":  gateCall(app, handleBatchCreate, "handles", "POST", "/api/handles/batch", "application/json", `[{"handle":"taken"}]`, sidB),
	} {
		if w.Code != http.StatusBadRequest || strings.Contains(w.Body.String(), "handles.handle") || strings.Contains(w.Body.String(), "UNIQUE") {
			t.Fatalf("%s: constraint detail leaked: %d %s", name, w.Code, w.Body.String())
		}
	}
}

// Protected-column matching ignores case: an owner column declared USER_ID
// is the owner column to the scoping SQL, so a client must not set it.
func TestProtectedFieldsAreCaseInsensitive(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE memos (id INTEGER PRIMARY KEY AUTOINCREMENT, USER_ID INTEGER, body TEXT)")
	uid, sid := gateUser(t, app, "owner@example.com")
	gateCall(app, handleCreate, "memos", "POST", "/api/memos", "application/json", `{"USER_ID":999,"body":"single"}`, sid)
	gateCall(app, handleBatchCreate, "memos", "POST", "/api/memos/batch", "application/json", `[{"USER_ID":999,"body":"batch"}]`, sid)
	gateCall(app, handleStreamingIngest, "memos", "POST", "/api/memos/ingest", "application/x-ndjson", "{\"USER_ID\":999,\"body\":\"ingest\"}\n", sid)
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM memos WHERE USER_ID = ?", uid); n != "3" {
		t.Fatalf("every create must own the row by the session, have %s owned rows", n)
	}
	gateCall(app, handleUpdate, "memos", "PATCH", "/api/memos/1", "application/json", `{"USER_ID":999}`, sid)
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM memos WHERE USER_ID = 999"); n != "0" {
		t.Fatalf("a client re-owned a row through a differently-cased owner column")
	}
}

// The audit row is written in the create's transaction: if it cannot be
// written, the row is not committed either.
func TestCreateAuditCommitsWithRow(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, body TEXT)")
	_, sid := gateUser(t, app, "owner@example.com")
	if w := gateCall(app, handleCreate, "notes", "POST", "/api/notes", "application/json", `{"body":"one"}`, sid); w.Code != http.StatusOK {
		t.Fatalf("create: %d %s", w.Code, w.Body.String())
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_audit_log WHERE table_name = 'notes' AND action = 'insert'"); n != "1" {
		t.Fatalf("audit rows = %s, want 1", n)
	}
	mustExec(t, app.DB, "DROP TABLE _benmore_audit_log")
	if w := gateCall(app, handleCreate, "notes", "POST", "/api/notes", "application/json", `{"body":"two"}`, sid); w.Code != http.StatusInternalServerError {
		t.Fatalf("create without an audit table: %d %s", w.Code, w.Body.String())
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM notes"); n != "1" {
		t.Fatalf("a create whose audit row failed was committed (%s rows)", n)
	}
	if w := gateCall(app, handleDelete, "notes", "DELETE", "/api/notes/1", "application/json", "", sid); w.Code != http.StatusInternalServerError {
		t.Fatalf("delete without an audit table: %d %s", w.Code, w.Body.String())
	}
	if n := gateScalar(t, app, "SELECT COUNT(*) FROM notes"); n != "1" {
		t.Fatalf("a delete whose audit row failed was committed")
	}
}

func TestUploadExtensionAllowlist(t *testing.T) {
	for ext, ok := range map[string]bool{"": true, "jpg": true, "mp4": true, "tar1": true, "ph-p": false, "p\"hp": false, "jpg ": false, "abcdefghijk": false, "JPG": false} {
		if got := safeUploadExt(ext); got != ok {
			t.Fatalf("safeUploadExt(%q) = %v, want %v", ext, got, ok)
		}
	}
	app, cleanup := newTestApp(t)
	defer cleanup()
	upload := func(name string) (string, error) {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		fw, _ := mw.CreateFormFile("file", name)
		fw.Write([]byte("plain text content"))
		mw.Close()
		r := httptest.NewRequest("POST", "/api/_upload", &body)
		r.Header.Set("Content-Type", mw.FormDataContentType())
		if err := r.ParseMultipartForm(uploadMemoryThreshold); err != nil {
			t.Fatal(err)
		}
		defer removeMultipartTemp(r)
		return HandleFileUpload(app, r, "file", "files", 0, nil)
	}
	if _, err := upload("notes.t%xt"); err == nil {
		t.Fatal("an extension outside [a-z0-9]{1,10} must be refused")
	}
	path, err := upload("Notes.TXT")
	if err != nil || !strings.HasSuffix(path, ".txt") {
		t.Fatalf("a normal extension must be stored lowercased: %q %v", path, err)
	}
}

func TestUploadSlotsBoundConcurrency(t *testing.T) {
	prev := uploadSlotWait
	uploadSlotWait = 50 * time.Millisecond
	defer func() { uploadSlotWait = prev }()
	var releases []func()
	for i := 0; i < maxConcurrentUploads; i++ {
		rel, ok := acquireUploadSlot(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil), "client-"+strconv.Itoa(i))
		if !ok {
			t.Fatalf("slot %d refused below the limit", i)
		}
		releases = append(releases, rel)
	}
	w := httptest.NewRecorder()
	if _, ok := acquireUploadSlot(w, httptest.NewRequest("POST", "/", nil), "client-extra"); ok || w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
		t.Fatalf("a saturated pool must answer 503 with Retry-After: ok=%v code=%d", ok, w.Code)
	}
	for _, rel := range releases {
		rel()
	}
	rel, ok := acquireUploadSlot(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil), "client-extra")
	if !ok {
		t.Fatal("released slots must be reusable")
	}
	rel()
}

// A burst larger than the slot pool queues: with the default wait, a request
// that arrives while every slot is busy gets one when an upload finishes a few
// seconds later instead of failing (apps upload several files at once with
// Promise.all, and bm.upload does not retry a 503).
func TestUploadBurstQueuesForAFreedSlot(t *testing.T) {
	var releases []func()
	for i := 0; i < maxConcurrentUploads; i++ {
		rel, ok := acquireUploadSlot(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil), "client-"+strconv.Itoa(i))
		if !ok {
			t.Fatalf("slot %d refused below the limit", i)
		}
		releases = append(releases, rel)
	}
	go func() {
		time.Sleep(2500 * time.Millisecond)
		releases[0]()
	}()
	w := httptest.NewRecorder()
	rel, ok := acquireUploadSlot(w, httptest.NewRequest("POST", "/", nil), "client-extra")
	if !ok {
		t.Fatalf("an upload queued behind a busy pool failed with %d instead of waiting for the freed slot", w.Code)
	}
	rel()
	for _, r := range releases[1:] {
		r()
	}
}

// With every upload slot busy, an anonymous request to an app that requires
// sign-in is refused as unauthenticated without queueing for a slot, so
// anonymous slow bodies cannot be what holds the slots.
func TestFilesUploadAuthenticatesBeforeTakingASlot(t *testing.T) {
	prev := uploadSlotWait
	uploadSlotWait = 50 * time.Millisecond
	defer func() { uploadSlotWait = prev }()
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureSessionsTable(app.DB)
	app.Design = &DesignConfig{Auth: map[string]string{"login": "/login"}}
	mux := http.NewServeMux()
	RegisterUploadRoute(mux, app)
	RegisterFileUploadRoute(mux, app)
	var releases []func()
	for i := 0; i < maxConcurrentUploads; i++ {
		rel, ok := acquireUploadSlot(httptest.NewRecorder(), httptest.NewRequest("POST", "/", nil), "client-"+strconv.Itoa(i))
		if !ok {
			t.Fatalf("slot %d refused below the limit", i)
		}
		releases = append(releases, rel)
	}
	defer func() {
		for _, rel := range releases {
			rel()
		}
	}()
	for _, path := range []string{"/api/_upload", "/api/_files"} {
		body, contentType := uploadTestBody(1 << 10)
		r := httptest.NewRequest(http.MethodPost, path, body)
		r.Header.Set("Content-Type", contentType)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s anonymous with all slots busy: %d %s, want 401", path, w.Code, w.Body.String())
		}
	}
}

// A write that times out waiting for the database lock is not a bad request:
// it answers 503 with Retry-After so clients retry, instead of the redacted
// 400 "the write was rejected" a constraint failure gets.
func TestDatabaseBusyWriteAnswers503(t *testing.T) {
	for name, err := range map[string]error{
		"busy":   sqlite3.Error{Code: sqlite3.ErrBusy},
		"locked": sqlite3.Error{Code: sqlite3.ErrLocked},
		"text":   errors.New("database is locked"),
	} {
		if status, _ := mutationErrorResponse(&App{}, "insert t", err); status != http.StatusServiceUnavailable {
			t.Errorf("%s: mutationErrorResponse status = %d, want 503", name, status)
		}
		w := httptest.NewRecorder()
		if !respondDatabaseBusy(w, err) || w.Code != http.StatusServiceUnavailable || w.Header().Get("Retry-After") == "" {
			t.Errorf("%s: respondDatabaseBusy = %d Retry-After=%q", name, w.Code, w.Header().Get("Retry-After"))
		}
	}
	unique := errors.New("UNIQUE constraint failed: users.email")
	if status, _ := mutationErrorResponse(&App{}, "insert t", unique); status != http.StatusBadRequest {
		t.Errorf("constraint failure status = %d, want 400", status)
	}
	if respondDatabaseBusy(httptest.NewRecorder(), unique) {
		t.Error("a constraint failure was answered as busy")
	}
}
