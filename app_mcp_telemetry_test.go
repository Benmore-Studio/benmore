//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestAppMCPWorkflowTrackingKeepsOriginalStateAndTerminalRules(t *testing.T) {
	cap := &appMCPCommandCapability{
		generation: &appMCPRuntimeGeneration{workflows: &WorkflowConfig{Workflows: map[string]*Workflow{"tasks": {
			Name: "tasks", Table: "tasks", Field: "status", States: []string{"open", "done"},
			Transitions: map[string]map[string]Transition{"open": {"done": {}}},
		}}}},
	}
	appMCPTrackWorkflowBeforeImage(cap, "tasks", map[string]any{"id": int64(1), "status": "open"})
	appMCPTrackWorkflowBeforeImage(cap, "tasks", map[string]any{"id": int64(1), "status": "done"})
	if len(cap.workflowTransitions) != 1 {
		t.Fatalf("tracked %d row images, want one", len(cap.workflowTransitions))
	}
	for _, row := range cap.workflowTransitions {
		if row.From != "open" || row.RowID != int64(1) {
			t.Fatalf("tracking lost original workflow state or id: %+v", row)
		}
	}
	workflow := cap.generation.workflows.Workflows["tasks"]
	if !appMCPWorkflowTerminal(workflow, "done") || appMCPWorkflowTerminal(workflow, "open") {
		t.Fatal("terminal states were not derived from outgoing transitions")
	}
	if appMCPWorkflowTerminal(workflow, "unexpected") {
		t.Fatal("undeclared workflow state was treated as terminal")
	}
	if !appMCPHasWorkflowTransition(cap, "tasks", []map[string]any{{"status": "done"}, {"status": "open"}}, []map[string]any{{"status": "done"}, {"status": "done"}}) {
		t.Fatal("later-row workflow transition was missed")
	}
	workflow.Timeouts = map[string]WorkflowTimeout{"done": {After: time.Minute, To: "open"}}
	if appMCPWorkflowTerminal(workflow, "done") {
		t.Fatal("a state with a timeout transition was treated as terminal")
	}
}

func TestAppMCPTelemetrySchemaRevisionHashesCapturedSchemaSources(t *testing.T) {
	manifest := &AppMCPManifest{ExecutionDigest: "execution", sourceHashes: map[string]string{
		"schema.sql": "schema-one", "migrations/001.sql": "migration-one", "hooks.yaml": "hook-one",
	}}
	first := appMCPTelemetrySchemaRevision(manifest, "execution")
	if len(first) != 64 {
		t.Fatalf("schema revision %q is not a full SHA256", first)
	}
	manifest.sourceHashes["hooks.yaml"] = "hook-two"
	if got := appMCPTelemetrySchemaRevision(manifest, "execution"); got != first {
		t.Fatal("non-schema source changed telemetry schema revision")
	}
	manifest.sourceHashes["schema.sql"] = "schema-two"
	if got := appMCPTelemetrySchemaRevision(manifest, "execution"); got == first {
		t.Fatal("captured schema change did not change telemetry schema revision")
	}
	if got := appMCPTelemetrySchemaRevision(manifest, "different-execution"); got != "" {
		t.Fatalf("revision used another source generation: %q", got)
	}
}

func TestAppMCPTelemetryAggregatesAndOmitsCallData(t *testing.T) {
	app, mux, admin, cleanup := adminPanelApp(t)
	defer cleanup()
	registerAppMCPTelemetryRoute(mux, app)

	for _, outcome := range appMCPTelemetryOutcomes {
		if err := appMCPRecordTelemetry(app, "status.read", strings.Repeat("a", 64), strings.Repeat("b", 64), "", outcome, 20*time.Millisecond); err != nil {
			t.Fatalf("record %s: %v", outcome, err)
		}
	}
	appMCPRecordAttemptTelemetry(app, "status.read", strings.Repeat("a", 64), strings.Repeat("b", 64), "", false)
	appMCPRecordAttemptTelemetry(app, "status.read", strings.Repeat("a", 64), strings.Repeat("b", 64), "", true)
	appMCPRecordQueuedEffects(app, "status.read", strings.Repeat("a", 64), strings.Repeat("b", 64), "", map[string]any{"effects": map[string]any{"items": []any{map[string]any{}, map[string]any{}}}})
	appMCPRecordEffectDelta(app, "status.read", strings.Repeat("a", 64), strings.Repeat("b", 64), "", "delivered", 1)
	input, token := "private-input-marker", "credential-token-marker"
	call := &sdk.CallToolParamsRaw{Name: "status.read", Arguments: json.RawMessage(`{"query":"private-input-marker","token":"credential-token-marker"}`), RequestState: token}
	result := &sdk.CallToolResult{StructuredContent: map[string]any{
		"data":    map[string]any{"text": input, "token": token},
		"effects": map[string]any{"items": []any{map[string]any{"status": "blocked", "payload": input}}},
	}}
	manifest := &AppMCPManifest{ContractDigest: strings.Repeat("a", 64), ExecutionDigest: strings.Repeat("b", 64), sourceHashes: map[string]string{}}
	appMCPRecordToolCall(app, call, manifest, time.Now().Add(-10*time.Millisecond), result, nil, "")

	var calls, applied, denied, conflict, unknown, failed, incomplete, attempts, retries int64
	var latency, pending, delivered, blocked, completions int64
	var schemaRevision string
	err := app.DB.QueryRow(`SELECT schema_revision, workflow_completions, calls, applied, denied, conflict, unknown, failed, incomplete, attempts, retries,
		latency_le_0_025, effects_pending, effects_delivered, effects_blocked
		FROM _benmore_mcp_telemetry WHERE tool_name=?`, "status.read").Scan(&schemaRevision, &completions, &calls, &applied, &denied, &conflict, &unknown, &failed, &incomplete, &attempts, &retries, &latency, &pending, &delivered, &blocked)
	if err != nil {
		t.Fatal(err)
	}
	if schemaRevision != "" || completions != 0 || calls != 7 || applied != 2 || denied != 1 || conflict != 1 || unknown != 1 || failed != 1 || incomplete != 1 || attempts != 2 || retries != 1 || latency != 7 || pending != 2 || delivered != 1 || blocked != 0 {
		t.Fatalf("unexpected counters: schema_revision=%q completions=%d calls=%d outcomes=%d/%d/%d/%d/%d/%d attempts=%d retries=%d latency=%d effects=%d/%d/%d", schemaRevision, completions, calls, applied, denied, conflict, unknown, failed, incomplete, attempts, retries, latency, pending, delivered, blocked)
	}
	rows, err := QueryRows(app.DB, "SELECT * FROM _benmore_mcp_telemetry")
	if err != nil {
		t.Fatal(err)
	}
	stored := ""
	for _, row := range rows {
		for _, value := range row {
			stored += " " + fmt.Sprint(value)
		}
	}
	if strings.Contains(stored, input) || strings.Contains(stored, token) {
		t.Fatalf("telemetry persisted call data: %s", stored)
	}
	if got := appMCPTelemetryOutcome(appMCPStatusTool, &sdk.CallToolResult{StructuredContent: map[string]any{"state": "unknown"}}, nil); got != "unknown" {
		t.Fatalf("unknown operation state recorded as %s", got)
	}
	if got := appMCPTelemetryOutcome(appMCPStatusTool, &sdk.CallToolResult{StructuredContent: map[string]any{"state": "conflict"}}, nil); got != "conflict" {
		t.Fatalf("conflict operation state recorded as %s", got)
	}
	if got := appMCPTelemetryOutcome("status.read", &sdk.CallToolResult{StructuredContent: map[string]any{"state": "unknown"}}, nil); got != "applied" {
		t.Fatalf("app output field was treated as connector state: %s", got)
	}
	if got := appMCPTelemetryOutcome("status.read", &sdk.CallToolResult{StructuredContent: map[string]any{"completeness": map[string]any{"state": "partial"}}}, nil); got != "incomplete" {
		t.Fatalf("partial result recorded as %s", got)
	}
	for _, tc := range []struct {
		err  error
		want string
	}{{nil, "delivered"}, {jobNotRetryable{errors.New(appMCPEffectBlockedPrefix + "revoked")}, "blocked"}, {jobNotRetryable{errors.New("unknown: delivery state")}, "unknown"}, {errors.New("delivery failed"), "failed"}} {
		if got := appMCPJobEffectOutcome(tc.err); got != tc.want {
			t.Fatalf("job effect outcome %q = %q, want %q", tc.err, got, tc.want)
		}
	}
	for i := 0; i < appMCPTelemetryRowLimit+1; i++ {
		if err := appMCPRecordTelemetry(app, fmt.Sprintf("tool.%03d", i), strings.Repeat("a", 64), strings.Repeat("b", 64), "", "applied", time.Millisecond); err != nil {
			t.Fatalf("record bounded row %d: %v", i, err)
		}
	}
	var retained int
	if err := app.DB.QueryRow("SELECT count(*) FROM _benmore_mcp_telemetry").Scan(&retained); err != nil || retained > appMCPTelemetryRowLimit {
		t.Fatalf("telemetry retained %d rows: %v", retained, err)
	}
	var newest, old int
	if err := app.DB.QueryRow("SELECT EXISTS(SELECT 1 FROM _benmore_mcp_telemetry WHERE tool_name='tool.256'), EXISTS(SELECT 1 FROM _benmore_mcp_telemetry WHERE tool_name='status.read')").Scan(&newest, &old); err != nil || newest != 1 || old != 0 {
		t.Fatalf("telemetry retention kept newest=%d oldest=%d: %v", newest, old, err)
	}

	if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/_mcp/telemetry", "", nil); rec.Code != http.StatusForbidden {
		t.Fatalf("anonymous telemetry status=%d", rec.Code)
	}
	if _, err := app.DB.Exec("INSERT INTO _benmore_users (username,email,role,verified) VALUES ('telemetry-member','telemetry-member@example.com','user',1)"); err != nil {
		t.Fatal(err)
	}
	var memberID int64
	if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email=?", "telemetry-member@example.com").Scan(&memberID); err != nil {
		t.Fatal(err)
	}
	member := CreateSession(app.DB, memberID, "telemetry-member@example.com", "", time.Hour)
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/_mcp/telemetry", member, nil); rec.Code != http.StatusForbidden {
		t.Fatalf("member telemetry status=%d", rec.Code)
	}
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/_mcp/telemetry", admin, nil); rec.Code != http.StatusOK {
		t.Fatalf("admin telemetry status=%d body=%s", rec.Code, rec.Body.String())
	} else {
		var response struct {
			Version int `json:"telemetry_version"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &response); err != nil || response.Version != appMCPTelemetryVersion {
			t.Fatalf("telemetry response version=%d err=%v body=%s", response.Version, err, rec.Body.String())
		}
	}
}

func TestAppMCPTelemetryMigratesLegacyAggregateRows(t *testing.T) {
	app, _, _, cleanup := adminPanelApp(t)
	defer cleanup()
	definitions := []string{"tool_name TEXT NOT NULL", "contract_digest TEXT NOT NULL", "execution_digest TEXT NOT NULL", "updated_at INTEGER NOT NULL DEFAULT 0"}
	for _, column := range appMCPTelemetryColumns() {
		if column != "workflow_completions" {
			definitions = append(definitions, column+" INTEGER NOT NULL DEFAULT 0")
		}
	}
	_, err := app.DB.Exec(`CREATE TABLE _benmore_mcp_telemetry (` + strings.Join(definitions, ",") + `, PRIMARY KEY(tool_name,contract_digest,execution_digest))`)
	if err != nil {
		t.Fatal(err)
	}
	_, err = app.DB.Exec(`INSERT INTO _benmore_mcp_telemetry(tool_name,contract_digest,execution_digest,calls) VALUES('legacy','c','e',1)`)
	if err != nil {
		t.Fatal(err)
	}
	if err := ensureAppMCPTelemetryTable(app.DB); err != nil {
		t.Fatal(err)
	}
	var revision string
	var completions, calls int64
	if err := app.DB.QueryRow(`SELECT schema_revision,workflow_completions,calls FROM _benmore_mcp_telemetry WHERE tool_name='legacy'`).Scan(&revision, &completions, &calls); err != nil || revision != "" || completions != 0 || calls != 1 {
		t.Fatalf("migrated telemetry revision=%q completions=%d calls=%d err=%v", revision, completions, calls, err)
	}
}

func TestAppMCPWorkflowCompletionTelemetryUsesConfirmedCommandPath(t *testing.T) {
	h, app := newWorkflowTelemetryHarness(t, hookTaskFlow, "")
	id := h.prepare()
	h.approveOK(id)
	if out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "" || out["outcome"] != "applied" {
		t.Fatalf("commit: code=%q result=%#v", code, out)
	}
	var schemaRevision string
	var completions int64
	if err := app.DB.QueryRow(`SELECT schema_revision,workflow_completions FROM _benmore_mcp_telemetry WHERE tool_name='complete_item'`).Scan(&schemaRevision, &completions); err != nil {
		t.Fatal(err)
	}
	if len(schemaRevision) != 64 || completions != 1 {
		t.Fatalf("committed workflow telemetry schema_revision=%q completions=%d", schemaRevision, completions)
	}
	if out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "" || out["outcome"] != "already_applied" {
		t.Fatalf("replay: code=%q result=%#v", code, out)
	}
	if err := app.DB.QueryRow(`SELECT workflow_completions FROM _benmore_mcp_telemetry WHERE tool_name='complete_item'`).Scan(&completions); err != nil || completions != 1 {
		t.Fatalf("replay changed workflow completion count=%d err=%v", completions, err)
	}
}

func TestAppMCPWorkflowCompletionTelemetryExcludesNonCompletion(t *testing.T) {
	t.Run("already terminal metadata update", func(t *testing.T) {
		flow := strings.ReplaceAll(hookTaskFlow, " AND status <> 'done'", "")
		if flow == hookTaskFlow {
			t.Fatal("fixture update statement changed")
		}
		h, app := newWorkflowTelemetryHarness(t, flow, "")
		if _, err := app.DB.Exec("UPDATE tasks SET status='done' WHERE id=1"); err != nil {
			t.Fatal(err)
		}
		commitWorkflowTelemetryCommand(t, h, false)
		assertWorkflowCompletions(t, app, 0)
	})
	t.Run("hook reverses terminal state", func(t *testing.T) {
		hook := "on_update:\n  tasks:\n    - sql: UPDATE tasks SET status='open' WHERE id={{id}}\n"
		h, app := newWorkflowTelemetryHarness(t, hookTaskFlow, hook)
		commitWorkflowTelemetryCommand(t, h, false)
		assertWorkflowCompletions(t, app, 0)
	})
	t.Run("rolled back command", func(t *testing.T) {
		flow := strings.Replace(hookTaskFlow, "expect_rows: '=1'", "expect_rows: '=2'", 1)
		if flow == hookTaskFlow {
			t.Fatal("could not add rollback assertion to activity insert")
		}
		h, app := newWorkflowTelemetryHarness(t, flow, "")
		id := h.prepare()
		h.approveOK(id)
		if out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code == "" || out != nil {
			t.Fatalf("commit with failing second mutation: code=%q result=%#v", code, out)
		}
		var status string
		if err := app.DB.QueryRow("SELECT status FROM tasks WHERE id=1").Scan(&status); err != nil || status != "open" {
			t.Fatalf("first mutation survived failed command: status=%q err=%v", status, err)
		}
		assertWorkflowCompletions(t, app, 0)
	})
	t.Run("stale dependency before apply", func(t *testing.T) {
		h, app := newWorkflowTelemetryHarness(t, hookTaskFlow, "")
		id := h.prepare()
		h.approveOK(id)
		if _, err := app.DB.Exec("UPDATE tasks SET title='changed after approval' WHERE id=1"); err != nil {
			t.Fatal(err)
		}
		if out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "conflict" || out != nil {
			t.Fatalf("commit after stale precondition: code=%q result=%#v", code, out)
		}
		assertWorkflowCompletions(t, app, 0)
	})
}

func newWorkflowTelemetryHarness(t *testing.T, flow, hooks string) (*exposureHarness, *App) {
	t.Helper()
	app, _, actorID := newCommandProviderTaskFixtureWithPolicies(t, flow, hooks)
	app.Workflows = &WorkflowConfig{Workflows: map[string]*Workflow{"tasks": {
		Name: "tasks", Table: "tasks", Field: "status", Initial: "open", States: []string{"open", "done"},
		Transitions: map[string]map[string]Transition{"open": {"done": {}}},
	}}}
	app.mu.Lock()
	app.mcpGeneration = nil
	app.mu.Unlock()
	ensureCommandAuditFixture(t, app)
	h := &exposureHarness{t: t, app: app, actorID: actorID}
	mux := http.NewServeMux()
	h.server = httptest.NewTLSServer(mux)
	t.Cleanup(h.server.Close)
	h.resource = h.server.URL + "/api/_mcp"
	registerAppMCPTransport(mux, app, h.resource)
	h.browser = &http.Client{Transport: h.server.Client().Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	var err error
	if h.pair, err = createAppMCPNativeGrantFor(context.Background(), app, actorID, "17", "client-b2", h.resource, "complete_item", time.Now()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	h.cookie = CreateSession(app.DB, actorID, "task-actor@example.com", "17", time.Hour)
	h.client = appMCPClient(t, h.server, h.pair.AccessToken, nil)
	return h, app
}

func commitWorkflowTelemetryCommand(t *testing.T, h *exposureHarness, replay bool) {
	t.Helper()
	id := h.prepare()
	h.approveOK(id)
	if out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "" || out["outcome"] != "applied" {
		t.Fatalf("commit: code=%q result=%#v", code, out)
	}
	if replay {
		if out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "" || out["outcome"] != "already_applied" {
			t.Fatalf("replay: code=%q result=%#v", code, out)
		}
	}
}

func assertWorkflowCompletions(t *testing.T, app *App, want int64) {
	t.Helper()
	var got int64
	err := app.DB.QueryRow(`SELECT workflow_completions FROM _benmore_mcp_telemetry WHERE tool_name='complete_item'`).Scan(&got)
	if err != nil || got != want {
		t.Fatalf("workflow completion count=%d want=%d err=%v", got, want, err)
	}
}
