//go:build !cli

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func extractTextProblemsFor(t *testing.T, src string) []string {
	t.Helper()
	var file FlowFileGHA
	if err := decodeConfigYAML([]byte(src), &file); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return flowStepValueProblems(file)
}

func hasProblem(problems []string, part string) bool {
	for _, p := range problems {
		if strings.Contains(p, part) {
			return true
		}
	}
	return false
}

const extractTextStep = `run: extract_text
        with:
          source_path: "${{ steps.doc.outputs.first.file_url }}"
          record: { table: documents, id: "${{ steps.doc.outputs.first.id }}" }`

// A job or schedule transaction holds the app's write lock for the whole run,
// and the step can wait and extract for 20 minutes: refused at write time
// wherever it would run inside the transaction, allowed in on_error (which
// runs after the rollback) and in a flow without a transaction.
func TestExtractTextRefusedInTransactionalFlows(t *testing.T) {
	asyncTx := "on:\n  request: { method: POST, path: /x, auth: required, mode: async, transaction: true }\njobs:\n  j:\n    steps:\n"
	scheduleTx := "on:\n  schedule: { cron: \"*/5 * * * *\", transaction: true }\njobs:\n  j:\n    steps:\n"
	asyncPlain := "on:\n  request: { method: POST, path: /x, auth: required, mode: async }\njobs:\n  j:\n    steps:\n"
	cases := []struct {
		name, src string
		refused   bool
	}{
		{"top level async", asyncTx + "      - " + extractTextStep + "\n", true},
		{"top level schedule", scheduleTx + "      - " + extractTextStep + "\n", true},
		{"in parallel", asyncTx + "      - run: parallel\n        steps:\n          - " + strings.ReplaceAll(extractTextStep, "\n        ", "\n            ") + "\n", true},
		{"in if", asyncTx + "      - if: \"1 == 1\"\n        steps:\n          - " + strings.ReplaceAll(extractTextStep, "\n        ", "\n            ") + "\n", true},
		{"in on_error", asyncTx + "      - run: sql\n        query: SELECT 1\n        on_error:\n          - " + strings.ReplaceAll(extractTextStep, "\n        ", "\n            ") + "\n", false},
		{"no transaction", asyncPlain + "      - " + extractTextStep + "\n", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			problems := extractTextProblemsFor(t, tc.src)
			if got := hasProblem(problems, "can't run in a `transaction: true` flow"); got != tc.refused {
				t.Fatalf("refused=%v, want %v; problems=%q", got, tc.refused, problems)
			}
		})
	}
}

func TestExtractTextRefusesTransactionAtRunTime(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	ctx := &FlowContext{App: app, Tx: tx, Data: map[string]any{}, Params: map[string]string{}, backgroundRun: true}
	step := &FlowStep{Name: "text", Type: "extract_text", ExtractText: &FlowExtractText{SourcePath: "uploads/private/a.pdf"}, UploadRecord: &FlowUploadRecord{Table: "docs", ID: "1"}}
	if err := execStepExtractText(ctx, step); err == nil || !strings.Contains(err.Error(), "transaction: true") {
		t.Fatalf("extract_text ran inside a transaction: %v", err)
	}
}

// Without `record:` the uploader rule is only logged, so a schedule reading a
// user-editable file_url column extracted any user's private PDF. The step
// now always names the owning row, at write time and when it runs.
func TestExtractTextRequiresRecord(t *testing.T) {
	src := "on:\n  schedule: { cron: \"*/5 * * * *\" }\njobs:\n  j:\n    steps:\n      - run: extract_text\n        with: { source_path: \"${{ steps.doc.outputs.first.file_url }}\" }\n"
	if problems := extractTextProblemsFor(t, src); !hasProblem(problems, "needs `with.record") {
		t.Fatalf("a step without record: passed the write gate: %q", problems)
	}
	if problems := extractTextProblemsFor(t, strings.Replace(src, "file_url }}\" }", "file_url }}\", record: { table: docs, id: 1 } }", 1)); hasProblem(problems, "needs `with.record") {
		t.Fatalf("a step with record: was refused: %q", problems)
	}

	app, _, cleanup := signedURLApp(t)
	defer cleanup()
	if err := EnsureUploadOwnersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	// User 1 uploaded secret.pdf; user 2 stored its reference in a row of their own.
	mustExec(t, app.DB, `INSERT INTO _benmore_upload_owners (path, user_id) VALUES ('private/secret.pdf', 1)`)
	mustExec(t, app.DB, `INSERT INTO docs (id, user_id, file_url) VALUES (2, 2, '/uploads/private/secret.pdf')`)
	run := func(record *FlowUploadRecord) error {
		ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}, Writes: newFlowWriteLog(), backgroundRun: true}
		step := &FlowStep{Name: "text", Type: "extract_text", ExtractText: &FlowExtractText{SourcePath: "uploads/private/secret.pdf"}, UploadRecord: record}
		return execStepExtractText(ctx, step)
	}
	if err := run(nil); err == nil || !strings.Contains(err.Error(), "with.record") {
		t.Fatalf("a scheduled run without record: was not refused: %v", err)
	}
	if err := run(&FlowUploadRecord{Table: "docs", ID: "2"}); err == nil || !strings.Contains(err.Error(), "does not own the file") {
		t.Fatalf("another user's upload through a row of user 2 was not refused: %v", err)
	}
	// The uploader's own row passes the ownership check and reaches the
	// extractor (secret.pdf is not a PDF, so it stops there).
	if err := run(&FlowUploadRecord{Table: "docs", ID: "1"}); err == nil || !strings.Contains(err.Error(), "unsupported_file") {
		t.Fatalf("the uploader's own row did not reach the extractor: %v", err)
	}
}

const (
	extractTextCallerRefusal = "extract_text refused: the signed-in caller cannot read the `record:` row"
	// The test files do not exist, so a caller who passes every check stops
	// at the private read and no parser can start.
	extractTextReachedRead = "extract_text: unsupported_file"
)

// extractTextRequestRun runs the step on row 1 of table with a reference that
// arrived as request input, as in an async request flow.
func extractTextRequestRun(app *App, session *Session, table string) error {
	ctx := &FlowContext{
		App: app, Session: session, Writes: newFlowWriteLog(), backgroundRun: true,
		Data: map[string]any{"path": "uploads/private/held.pdf"}, Params: map[string]string{},
		RequestKeys: map[string]bool{"path": true},
	}
	step := &FlowStep{Name: "text", Type: "extract_text", ExtractText: &FlowExtractText{SourcePath: "{{path}}"}, UploadRecord: &FlowUploadRecord{Table: table, ID: "1"}}
	return execStepExtractText(ctx, step)
}

// A request-chosen reference needs a caller who could read the `record:` row
// through auto-CRUD. The step checked the per-row scope alone, which is empty
// on a table with no owner or tenant column: every signed-in caller passed on
// an admin-only, role-gated, permission-gated or `off` table, and a credential
// with no read scope on the table passed on its own rows.
func TestExtractTextCallerNeedsTableReadAccess(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE _benmore_permissions (resource_type TEXT, resource_id INTEGER, grant_type TEXT, grantee_id TEXT, permission TEXT, expires_at TEXT)`)
	app.Access = &AccessConfig{rolesDeclared: true, rules: map[string]map[AccessOp]string{
		"contracts": {OpRead: "admin"},
		"briefs":    {OpRead: "role:legal"},
		"ledgers":   {OpRead: "perm:ledgers.audit"},
		"vault":     {OpRead: "off"},
		"docs":      {OpRead: "self"},
		"notices":   {OpRead: "everyone"},
	}}
	for _, table := range []string{"contracts", "briefs", "ledgers", "vault"} {
		mustExec(t, app.DB, `CREATE TABLE `+table+` (id INTEGER PRIMARY KEY, file_url TEXT)`)
		mustExec(t, app.DB, `INSERT INTO `+table+` (id, file_url) VALUES (1, 'uploads/private/held.pdf')`)
		app.Tables = append(app.Tables, Table{Name: table, Columns: []Column{{Name: "id"}, {Name: "file_url"}}})
	}
	for _, table := range []string{"docs", "notices"} {
		mustExec(t, app.DB, `CREATE TABLE `+table+` (id INTEGER PRIMARY KEY, user_id INTEGER, file_url TEXT)`)
		mustExec(t, app.DB, `INSERT INTO `+table+` (id, user_id, file_url) VALUES (1, 2, 'uploads/private/held.pdf')`)
		app.Tables = append(app.Tables, Table{Name: table, Columns: []Column{{Name: "id"}, {Name: "user_id"}, {Name: "file_url"}}})
	}

	const refusal, reachedRead = extractTextCallerRefusal, extractTextReachedRead
	user := func(scopes string) *Session { return &Session{UserID: 2, Role: "user", Scopes: scopes} }
	cases := []struct {
		name, table string
		session     *Session
		want        string
	}{
		{"admin-only table, ordinary user", "contracts", user(""), refusal},
		{"admin-only table, admin", "contracts", &Session{UserID: 9, Role: "admin"}, reachedRead},
		{"role-gated table, ordinary user", "briefs", user(""), refusal},
		{"role-gated table, role holder", "briefs", &Session{UserID: 3, Role: "user", Roles: []string{"user", "legal"}}, reachedRead},
		{"perm-gated table, permission not held", "ledgers", user("ledgers:read"), refusal},
		{"perm-gated table, permission held", "ledgers", user("ledgers:read ledgers:audit"), reachedRead},
		{"read: off table, ordinary user", "vault", user(""), refusal},
		{"read: off table, admin", "vault", &Session{UserID: 9, Role: "admin"}, refusal},
		{"own row, unscoped sign-in", "docs", user(""), reachedRead},
		{"own row, credential scoped to this table", "docs", user("docs:read"), reachedRead},
		{"own row, credential scoped to another table", "docs", user("contracts:read"), refusal},
		{"another user's row", "docs", &Session{UserID: 7, Role: "user"}, refusal},
		{"no signed-in caller", "docs", nil, refusal},
		// The row scope still applies where the mode lets every signed-in
		// user read: stricter than a direct GET, as before.
		{"everyone-readable table with an owner column, owner", "notices", user(""), reachedRead},
		{"everyone-readable table with an owner column, another user", "notices", &Session{UserID: 7, Role: "user"}, refusal},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := extractTextRequestRun(app, tc.session, tc.table); err == nil || err.Error() != tc.want {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}

	// A reference no request chose (a schedule's own lookup) has no caller to
	// check: the row and the uploader rule decide, as before.
	ctx := &FlowContext{App: app, Writes: newFlowWriteLog(), backgroundRun: true, Data: map[string]any{}, Params: map[string]string{}}
	step := &FlowStep{Name: "text", Type: "extract_text", ExtractText: &FlowExtractText{SourcePath: "uploads/private/held.pdf"}, UploadRecord: &FlowUploadRecord{Table: "contracts", ID: "1"}}
	if err := execStepExtractText(ctx, step); err == nil || err.Error() != reachedRead {
		t.Fatalf("a scheduled run on an admin-only table: got %v, want %q", err, reachedRead)
	}
}

// On a tenant-keyed table the row scope is the tenant, so a role-gated table
// let every member of the tenant through. The role is the gate, and it never
// reaches another tenant's rows.
func TestExtractTextCallerNeedsTenantRole(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE _benmore_permissions (resource_type TEXT, resource_id INTEGER, grant_type TEXT, grantee_id TEXT, permission TEXT, expires_at TEXT)`)
	mustExec(t, app.DB, `CREATE TABLE cases (id INTEGER PRIMARY KEY, org_id TEXT, file_url TEXT)`)
	mustExec(t, app.DB, `INSERT INTO cases (id, org_id, file_url) VALUES (1, 'g1', 'uploads/private/held.pdf')`)
	app.Group = &GroupConfig{Table: "members", Key: "org_id", UserField: "email"}
	app.Access = &AccessConfig{rules: map[string]map[AccessOp]string{"cases": {OpRead: "role:manager"}}}
	app.Tables = []Table{{Name: "cases", Columns: []Column{{Name: "id"}, {Name: "org_id"}, {Name: "file_url"}}}}
	member := func(group string, roles ...string) *Session {
		return &Session{UserID: 2, Role: "user", GroupID: group, Roles: append([]string{"user"}, roles...)}
	}
	for _, tc := range []struct {
		name    string
		session *Session
		want    string
	}{
		{"member of the tenant without the role", member("g1"), extractTextCallerRefusal},
		{"manager of the tenant", member("g1", "manager"), extractTextReachedRead},
		{"manager of another tenant", member("g2", "manager"), extractTextCallerRefusal},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := extractTextRequestRun(app, tc.session, "cases"); err == nil || err.Error() != tc.want {
				t.Fatalf("got %v, want %q", err, tc.want)
			}
		})
	}
}

// A repeat of the same bytes is answered from the cache: no slot, no
// extractor, no budget.
func TestExtractTextRepeatIsServedFromCache(t *testing.T) {
	app, _, cleanup := signedURLApp(t)
	defer cleanup()
	content := []byte("%PDF-1.4 cached")
	if err := os.WriteFile(filepath.Join(app.Dir, "uploads", "private", "secret.pdf"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(content)
	sha := hex.EncodeToString(sum[:])
	key := extractTextCacheKey(app.Dir, sha, true)
	extractTextCachePut(key, extractTextResult{sha256: sha, parserVersion: "v", complete: true, pages: []string{"hello", "world"}}, time.Now())
	// Exhaust the caller's budget: a cache hit must not need it.
	budgetKey := extractTextBudgetKey(app.Dir, 1)
	extractTextBudgetSpend(budgetKey, time.Now(), extractTextUserBudget)
	ctx := &FlowContext{App: app, Session: &Session{UserID: 1}, Data: map[string]any{}, Params: map[string]string{}, Writes: newFlowWriteLog(), backgroundRun: true}
	step := &FlowStep{Name: "text", Type: "extract_text", ExtractText: &FlowExtractText{SourcePath: "uploads/private/secret.pdf"}, UploadRecord: &FlowUploadRecord{Table: "docs", ID: "1"}}
	if err := execStepExtractText(ctx, step); err != nil {
		t.Fatalf("cached extraction failed: %v", err)
	}
	out, _ := ctx.Data["text"].(map[string]any)
	pages, _ := out["pages"].([]map[string]any)
	if out["source_sha256"] != sha || out["page_count"] != 2 || len(pages) != 2 || pages[1]["text"] != "world" {
		t.Fatalf("unexpected cached output: %#v", out)
	}
	// A different OCR setting is a different result.
	off := false
	step.ExtractText.OCR = &off
	if err := execStepExtractText(ctx, step); err == nil || !strings.Contains(err.Error(), "limit_exceeded") {
		t.Fatalf("a miss with no budget left was not refused: %v", err)
	}
}

func TestExtractTextUserBudget(t *testing.T) {
	key := extractTextBudgetKey(t.TempDir(), 7)
	start := time.Now()
	if !extractTextBudgetAllows(key, start) {
		t.Fatal("a new user has no budget")
	}
	extractTextBudgetSpend(key, start, extractTextUserBudget-time.Second)
	if !extractTextBudgetAllows(key, start.Add(time.Minute)) {
		t.Fatal("budget ran out early")
	}
	extractTextBudgetSpend(key, start.Add(time.Minute), 2*time.Second)
	if extractTextBudgetAllows(key, start.Add(2*time.Minute)) {
		t.Fatal("spent budget still allows another extraction")
	}
	if !extractTextBudgetAllows(key, start.Add(extractTextBudgetWindow)) {
		t.Fatal("budget did not renew after the window")
	}
}

func TestExtractTextCacheBounds(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	big := strings.Repeat("x", extractTextCacheBytes/2)
	a, b, c := extractTextCacheKey(dir, "a", true), extractTextCacheKey(dir, "b", true), extractTextCacheKey(dir, "c", true)
	extractTextCachePut(a, extractTextResult{pages: []string{big}}, now)
	extractTextCachePut(b, extractTextResult{pages: []string{big}}, now)
	if _, ok := extractTextCacheGet(a, now); ok {
		t.Fatal("cache kept more than its byte limit")
	}
	if _, ok := extractTextCacheGet(b, now); !ok {
		t.Fatal("newest entry was evicted")
	}
	extractTextCachePut(c, extractTextResult{pages: []string{"small"}}, now)
	if _, ok := extractTextCacheGet(c, now.Add(extractTextCacheTTL+time.Second)); ok {
		t.Fatal("expired entry was served")
	}
}
