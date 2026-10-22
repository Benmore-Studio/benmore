//go:build !cli && !windows

package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
)

type exposureHarness struct {
	t        *testing.T
	app      *App
	server   *httptest.Server
	resource string
	actorID  int64
	cookie   string
	pair     *appMCPTokenPair
	client   *sdk.ClientSession
	browser  *http.Client
}

func newExposureHarness(t *testing.T) *exposureHarness {
	t.Helper()
	return newExposureHarnessWithHooks(t, "")
}

func newExposureHarnessWithHooks(t *testing.T, hookSource string) *exposureHarness {
	t.Helper()
	return newExposureHarnessWithFlow(t, hookTaskFlow, hookSource)
}

func newExposureHarnessWithFlow(t *testing.T, flowSource, hookSource string) *exposureHarness {
	t.Helper()
	app, _, actorID := newCommandProviderTaskFixtureWithPolicies(t, flowSource, hookSource)
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
	return h
}

// call returns the structured result, or the connector error code.
func (h *exposureHarness) call(session *sdk.ClientSession, name string, args map[string]any) (map[string]any, string) {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		h.t.Fatalf("call %s: %v", name, err)
	}
	if result.IsError {
		code, _ := result.Meta["error_code"].(string)
		return nil, code
	}
	out, _ := result.StructuredContent.(map[string]any)
	return out, ""
}

func (h *exposureHarness) prepare() string { return h.prepareTask(1) }

func (h *exposureHarness) prepareTask(task int) string {
	h.t.Helper()
	out, code := h.call(h.client, "complete_item", map[string]any{"arguments": map[string]any{"id": task, "project_id": 7}})
	if code != "" {
		h.t.Fatalf("prepare failed: %s", code)
	}
	id, _ := out["operation_id"].(string)
	if !appMCPIsHex(id, 32) || out["review_url"] != h.resource[:len(h.resource)-len("/api/_mcp")]+appMCPOperationRoute+id {
		h.t.Fatalf("prepare result: %#v", out)
	}
	return id
}

func (h *exposureHarness) do(method, path string, cookie string, form url.Values, header map[string]string) (*http.Response, string) {
	h.t.Helper()
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	} else {
		body = strings.NewReader("")
	}
	req, err := http.NewRequest(method, h.server.URL+path, body)
	if err != nil {
		h.t.Fatal(err)
	}
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if cookie != "" {
		req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	resp, err := h.browser.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close()
	var sb strings.Builder
	buf := make([]byte, 4096)
	for {
		n, err := resp.Body.Read(buf)
		sb.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp, sb.String()
}

var exposureCSRF = regexp.MustCompile(`name="_csrf" value="([^"]+)"`)

func (h *exposureHarness) review(cookie, id string) (int, string, string) {
	resp, body := h.do("GET", appMCPOperationRoute+id, cookie, nil, nil)
	m := exposureCSRF.FindStringSubmatch(body)
	token := ""
	if m != nil {
		token = m[1]
	}
	return resp.StatusCode, body, token
}

func (h *exposureHarness) approve(cookie, id, csrf string, header map[string]string) int {
	resp, _ := h.do("POST", appMCPOperationRoute+id+"/approve", cookie, url.Values{"_csrf": {csrf}}, header)
	return resp.StatusCode
}

// approveOK runs the real browser path: GET the page, POST its own token.
func (h *exposureHarness) approveOK(id string) {
	h.t.Helper()
	status, body, token := h.review(h.cookie, id)
	if status != 200 || token == "" || !strings.Contains(body, "Exact change") {
		h.t.Fatalf("review page: %d %q", status, body)
	}
	if got := h.approve(h.cookie, id, token, nil); got != http.StatusSeeOther {
		h.t.Fatalf("approve status %d", got)
	}
}

func (h *exposureHarness) count(query string, args ...any) int {
	h.t.Helper()
	var n int
	if err := h.app.DB.QueryRow(query, args...).Scan(&n); err != nil {
		h.t.Fatal(err)
	}
	return n
}

func (h *exposureHarness) taskDone() bool {
	var status string
	if err := h.app.DB.QueryRow("SELECT status FROM tasks WHERE id=1").Scan(&status); err != nil {
		h.t.Fatal(err)
	}
	return status == "done"
}

func (h *exposureHarness) status(id string) map[string]any {
	h.t.Helper()
	out, code := h.call(h.client, appMCPStatusTool, map[string]any{"operation_id": id})
	if code != "" {
		h.t.Fatalf("status failed: %s", code)
	}
	return out
}

func setExposureClock(t *testing.T, at time.Time) {
	t.Helper()
	previous := appMCPClock
	appMCPClock = func() time.Time { return at }
	t.Cleanup(func() { appMCPClock = previous })
}

func TestAppMCPExposureWritesOffHidesEveryWriteSurface(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	listed, err := h.client.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range listed.Tools {
		names = append(names, tool.Name)
	}
	if !reflect.DeepEqual(names, []string{"_commit", "_status", "artifact.export", "complete_item"}) {
		t.Fatalf("live tools: %v", names)
	}
	if scopes := appMCPLiveScopes(h.app, h.app.MCP, snapshotAppMCPGeneration(h.app)); !strings.Contains(scopes, "tasks:write") {
		t.Fatalf("live scopes omit the command permission: %q", scopes)
	}
	if _, err := setAppMCPApprovedWrites(h.app.Dir, false); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(h.app)
	if got := appMCPLiveScopes(h.app, h.app.MCP, generation); got != appMCPSupportedScopes(h.app.MCP) || strings.Contains(got, "tasks:write") {
		t.Fatalf("writes-off scopes advertise a write permission: %q", got)
	}
	if len(appMCPLiveCommands(h.app, generation)) != 0 {
		t.Fatal("writes-off still lists command bindings")
	}
	// The grant's write scope no longer resolves: no tool is reachable.
	if _, err := h.client.ListTools(context.Background(), nil); err == nil {
		t.Fatal("tools stayed listed after writes were turned off")
	}
	// Both browser routes answer 404 even for a real operation and a real session.
	if status, _, _ := h.review(h.cookie, id); status != http.StatusNotFound {
		t.Fatalf("writes-off review status %d", status)
	}
	if got := h.approve(h.cookie, id, "x", nil); got != http.StatusNotFound {
		t.Fatalf("writes-off approve status %d", got)
	}
	// Re-enabling rotates the write epoch: the earlier operation never runs.
	if _, err := setAppMCPApprovedWrites(h.app.Dir, true); err != nil {
		t.Fatal(err)
	}
	h.client = appMCPClient(t, h.server, h.pair.AccessToken, nil)
	if state := h.status(id); state["state"] != "expired" || state["business"] != "not_committed" {
		t.Fatalf("operation survived an epoch rotation: %#v", state)
	}
	if got := h.approve(h.cookie, id, "x", nil); got == http.StatusSeeOther {
		t.Fatal("stale operation was approved")
	}
	if h.taskDone() {
		t.Fatal("business row changed")
	}
}

func TestAppMCPExposurePrepareApproveCommitReplay(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	if state := h.status(id); state["state"] != "prepared" || state["business"] != "not_committed" || state["receipt"] != nil {
		t.Fatalf("prepared status: %#v", state)
	}
	if h.taskDone() || h.count("SELECT count(*) FROM activities") != 0 {
		t.Fatal("prepare wrote business data")
	}
	// Commit without approval.
	if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "approval_required" {
		t.Fatalf("commit without approval: %q", code)
	}
	if h.taskDone() || h.count("SELECT count(*) FROM _benmore_mcp_command_approvals") != 0 {
		t.Fatal("unapproved commit changed state")
	}
	h.approveOK(id)
	if state := h.status(id); state["state"] != "approved" {
		t.Fatalf("approved status: %#v", state)
	}
	if h.count("SELECT count(*) FROM _benmore_audit_log WHERE action='mcp_command_approve' AND row_id=?", id) != 1 {
		t.Fatal("approve audit row missing")
	}
	first, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id})
	if code != "" || first["outcome"] != "applied" {
		t.Fatalf("commit: %q %#v", code, first)
	}
	receipt := first["receipt"].(map[string]any)
	result := receipt["result"].(map[string]any)
	if receipt["operation_id"] != id || result["status"] != "done" || result["actor_email"] != "task-actor@example.com" || !reflect.DeepEqual(receipt["effects"], map[string]any{"status": "none", "items": []any{}}) {
		t.Fatalf("receipt: %#v", receipt)
	}
	if !h.taskDone() || h.count("SELECT count(*) FROM activities WHERE task_id=1") != 1 {
		t.Fatal("business rows were not written exactly once")
	}
	if h.count("SELECT count(*) FROM _benmore_audit_log WHERE action='mcp_command_commit' AND row_id=?", id) != 1 {
		t.Fatal("commit audit row missing")
	}
	// The approval is consumed and the receipt is durable.
	status := h.status(id)
	if status["state"] != "succeeded" || status["business"] != "committed" || !reflect.DeepEqual(status["effects"], map[string]any{"status": "none", "items": []any{}}) || !reflect.DeepEqual(status["receipt"], receipt) {
		t.Fatalf("succeeded status: %#v", status)
	}
	// Replay: the same receipt, no second apply, no second audit row.
	again, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id})
	if code != "" || again["outcome"] != "already_applied" || !reflect.DeepEqual(again["receipt"], receipt) {
		t.Fatalf("replay: %q %#v", code, again)
	}
	if h.count("SELECT count(*) FROM activities WHERE task_id=1") != 1 || h.count("SELECT count(*) FROM _benmore_audit_log WHERE action='mcp_command_commit'") != 1 {
		t.Fatal("replay re-applied")
	}
	// Single use: a committed operation cannot be approved again.
	_, body, _ := h.review(h.cookie, id)
	if strings.Contains(body, "Approve this exact change") {
		t.Fatal("committed operation offers approval")
	}
	if got := h.approve(h.cookie, id, "x", nil); got == http.StatusSeeOther {
		t.Fatal("committed operation was approved")
	}
	// The whole union (operations, approvals, receipts) still authenticates.
	tx, err := h.app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	appID, key, err := appMCPReadyOperationStorage(context.Background(), tx, h.app)
	if err != nil {
		t.Fatal(err)
	}
	if _, approvals, err := appMCPValidateCommandStoreUnion(context.Background(), tx, appID, key); err != nil || len(approvals) != 1 || approvals[id].State != "consumed" {
		t.Fatalf("store union: %v %v", approvals, err)
	}
}

func TestAppMCPExposureApproveDenials(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	_, _, token := h.review(h.cookie, id)
	if token == "" {
		t.Fatal("no csrf token")
	}
	approvals := func() int { return h.count("SELECT count(*) FROM _benmore_mcp_command_approvals") }
	deny := func(name string, got int) {
		t.Helper()
		if got == http.StatusSeeOther || got == 200 || approvals() != 0 {
			t.Fatalf("%s: status %d approvals=%d", name, got, approvals())
		}
	}

	resp, _ := h.do("GET", appMCPOperationRoute+id+"/approve", h.cookie, nil, nil)
	deny("GET approve", resp.StatusCode)
	deny("Authorization header", h.approve(h.cookie, id, token, map[string]string{"Authorization": "Bearer " + h.pair.AccessToken}))
	deny("connector token only", h.approve("", id, token, map[string]string{"Authorization": "Bearer " + h.pair.AccessToken}))
	deny("no cookie", h.approve("", id, token, nil))
	deny("missing csrf", h.approve(h.cookie, id, "", nil))
	deny("unbound csrf", h.approve(h.cookie, id, generateCSRFToken(), nil))
	deny("csrf bound to another session", h.approve(h.cookie, id, authMintCSRFToken("some-other-session"), nil))
	deny("cross-site", h.approve(h.cookie, id, token, map[string]string{"Origin": "https://evil.example"}))

	// A different user of the same workspace.
	otherCookie := createCrudScopeSession(t, h.app, "other-user@example.com", "editor", "17", "")
	if _, err := h.app.DB.Exec("INSERT INTO members(org_id,email,user_id) SELECT '17',email,id FROM _benmore_users WHERE email='other-user@example.com'"); err != nil {
		t.Fatal(err)
	}
	_, _, otherToken := h.review(otherCookie, id)
	if otherToken != "" {
		t.Fatal("review page was shown to a different user")
	}
	deny("different user", h.approve(otherCookie, id, authMintCSRFToken(otherCookie), nil))
	deny("different user with initiator's token", h.approve(otherCookie, id, token, nil))

	// Delegated session shapes of the real initiator. The support session
	// names a real admin: it resolves only while its admin is one.
	if _, err := h.app.DB.Exec("INSERT INTO _benmore_users (id, username, email, password_hash, role, verified) VALUES (901, 'support-admin', 'support@example.com', 'x', 'admin', 1)"); err != nil {
		t.Fatal(err)
	}
	for name, update := range map[string]string{
		"scoped session":       "UPDATE _benmore_sessions SET scopes='tasks:write' WHERE id=?",
		"impersonated session": "UPDATE _benmore_sessions SET is_impersonation=1, impersonator_user_id=901, impersonator_email='support@example.com' WHERE id=?",
		"act-as session":       "UPDATE _benmore_sessions SET acting_as_group='29' WHERE id=?",
	} {
		delegated := CreateSession(h.app.DB, h.actorID, "task-actor@example.com", "17", time.Hour)
		if _, err := h.app.DB.Exec(update, sessionStorageKey(delegated)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if status, _, tok := h.review(delegated, id); status == 200 || tok != "" {
			t.Fatalf("%s: review page served", name)
		}
		deny(name, h.approve(delegated, id, authMintCSRFToken(delegated), nil))
	}

	// Unknown operation.
	deny("unknown operation", h.approve(h.cookie, strings.Repeat("a", 64), token, nil))

	// The real path still works exactly once.
	if got := h.approve(h.cookie, id, token, nil); got != http.StatusSeeOther {
		t.Fatalf("approve status %d", got)
	}
	if got := h.approve(h.cookie, id, token, nil); got == http.StatusSeeOther {
		t.Fatal("double approve accepted")
	}
	if approvals() != 1 || h.count("SELECT count(*) FROM _benmore_audit_log WHERE action='mcp_command_approve'") != 1 {
		t.Fatal("double approve left extra rows")
	}
}

// A preview value can carry characters chosen by the assistant (or by whoever
// wrote the row it reads). The review page must show them, not let them hide
// or reorder text, and must not leave part of a long value off screen.
func TestAppMCPExposureReviewShowsInvisibleCharacters(t *testing.T) {
	h := newExposureHarness(t)
	// RLO, zero-width space, NBSP, variation selector, Hangul filler, NEL.
	status := "open\u202eenod\u200b\u00a0x\ufe0f\u3164\u0085"
	if _, err := h.app.DB.Exec("UPDATE tasks SET status=? WHERE id=1", status); err != nil {
		t.Fatal(err)
	}
	id := h.prepare()
	resp, body := h.do("GET", appMCPOperationRoute+id, h.cookie, nil, nil)
	if resp.StatusCode != 200 || !strings.Contains(body, "Approve this exact change") {
		t.Fatalf("review page: %d %q", resp.StatusCode, body)
	}
	for _, r := range []rune{'\u202e', '\u200b', '\u00a0', '\ufe0f', '\u3164', '\u0085'} {
		if strings.ContainsRune(body, r) {
			t.Fatalf("review page renders %U raw: %q", r, body)
		}
	}
	if !strings.Contains(body, "open\\u202eenod\\u200b\\u00a0x\\ufe0f\\u3164\\u0085") {
		t.Fatalf("review page does not show the escaped value: %q", body)
	}
	// The escaped text is the same JSON value.
	text, err := appMCPReviewPreviewText(map[string]any{"status": status, "emoji": "\U0001F600\U000E0041"})
	if err != nil {
		t.Fatal(err)
	}
	var back map[string]any
	if err := json.Unmarshal([]byte(text), &back); err != nil || back["status"] != status || back["emoji"] != "\U0001F600\U000E0041" || !strings.Contains(text, "\\udb40\\udc41") {
		t.Fatalf("escaped preview does not round-trip: %q %v", text, err)
	}
	// Long values wrap: the page carries the wrapping style and its CSP admits
	// exactly that style block.
	style := regexp.MustCompile(`<style>([^<]*)</style>`).FindStringSubmatch(body)
	if style == nil || !strings.Contains(style[1], "white-space:pre-wrap") {
		t.Fatalf("review page has no wrapping style: %q", body)
	}
	sum := sha256.Sum256([]byte(style[1]))
	csp := resp.Header.Get("Content-Security-Policy")
	if !strings.Contains(csp, "style-src 'sha256-"+base64.StdEncoding.EncodeToString(sum[:])+"'") || !strings.Contains(csp, "default-src 'none'") ||
		!strings.Contains(csp, "frame-ancestors 'none'") || strings.Contains(csp, "unsafe-inline") || strings.Contains(csp, "script-src") {
		t.Fatalf("review page CSP: %q", csp)
	}
}

func TestAppMCPExposureExpiry(t *testing.T) {
	t.Run("unapproved operation expires", func(t *testing.T) {
		h := newExposureHarness(t)
		setExposureClock(t, time.Now().UTC().Add(-20*time.Minute))
		id := h.prepare() // created and expired 5 minutes ago
		setExposureClock(t, time.Now().UTC())
		if state := h.status(id); state["state"] != "expired" {
			t.Fatalf("status: %#v", state)
		}
		status, body, _ := h.review(h.cookie, id)
		if status != 200 || strings.Contains(body, "Approve this exact change") {
			t.Fatal("expired operation offers approval")
		}
		if got := h.approve(h.cookie, id, authMintCSRFToken(h.cookie), nil); got == http.StatusSeeOther || h.count("SELECT count(*) FROM _benmore_mcp_command_approvals") != 0 {
			t.Fatalf("expired operation approved: %d", got)
		}
	})
	t.Run("approved operation cannot commit after expiry", func(t *testing.T) {
		h := newExposureHarness(t)
		id := h.prepare()
		h.approveOK(id)
		setExposureClock(t, time.Now().UTC().Add(16*time.Minute))
		if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "expired_intent" {
			t.Fatalf("late commit: %q", code)
		}
		if state := h.status(id); state["state"] != "expired" {
			t.Fatalf("late status: %#v", state)
		}
		if h.taskDone() {
			t.Fatal("expired commit wrote")
		}
	})
}

const exposureNoGroupFlow = `command:
  version: 1
  prepared_schema:
    type: object
    additionalProperties: false
    required: [id, project_id]
    properties:
      id: {type: integer, minimum: 1, maximum: 9007199254740991}
      project_id: {type: integer, minimum: 1, maximum: 9007199254740991}
  preview_schema:
    type: object
    additionalProperties: false
    required: [status]
    properties:
      status: {type: string, minLength: 1, maxLength: 32}
  writes: [tasks]
  dependencies:
    - name: selected_task
      table: tasks
      query: SELECT id FROM tasks WHERE id = :id AND project_id = :project_id AND status <> 'done'
      params: {id: '${{ params.arguments.id }}', project_id: '${{ params.arguments.project_id }}'}
      max_rows: 1
jobs:
  prepare:
    steps:
      - id: selected_task
        run: sql
        with:
          query: SELECT id, status FROM tasks WHERE id = :id AND project_id = :project_id AND status <> 'done'
          params: {id: '${{ params.arguments.id }}', project_id: '${{ params.arguments.project_id }}'}
      - run: respond
        with:
          status: 200
          json:
            arguments: {id: '${{ steps.selected_task.outputs.first.id }}', project_id: '${{ params.arguments.project_id }}'}
            preview: {status: '${{ steps.selected_task.outputs.first.status }}'}
  apply:
    steps:
      - id: complete_task
        run: sql
        expect_rows: '>0'
        with:
          query: UPDATE tasks SET status = 'done', completed_by = :actor WHERE id = :id AND project_id = :project_id AND status <> 'done'
          params: {id: '${{ params.id }}', project_id: '${{ params.project_id }}', actor: '${{ user.id }}'}
      - run: respond
        with: {status: 200, json: {ok: true}}
  readback:
    steps:
      - id: completed_task
        run: sql
        with:
          query: SELECT t.id,t.status FROM tasks AS t WHERE t.id=:id AND t.project_id=:project_id
          params: {id: '${{ params.id }}', project_id: '${{ params.project_id }}'}
      - run: respond
        with:
          status: 200
          json:
            id: '${{ steps.completed_task.outputs.first.id }}'
            status: '${{ steps.completed_task.outputs.first.status }}'
`

// An app without groups has no workspace: its grants, sessions and operations
// carry an empty tenant. Its commands must still prepare, approve and commit.
func TestAppMCPExposureCommandOnAppWithoutGroups(t *testing.T) {
	epochFixture(t)
	t.Setenv("BENMORE_TEST_BOOT", "1")
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", `CREATE TABLE tasks (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL, completed_by INTEGER);
`)
	writeTestFile(t, dir, "app.yaml", `roles:
  editor: {scopes: [tasks:read, tasks:write]}
access:
  tasks: {all: everyone}
`)
	writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: provider-fixture-key-with-sufficient-length\n")
	writeTestFile(t, dir, "flows/complete_item.yaml", exposureNoGroupFlow)
	manifest := commandManifest()
	manifest.Tools[0].InputSchema.Properties["arguments"].Properties = map[string]*AppMCPSchema{
		"id":         {Type: "integer", Minimum: floatPointer(1), Maximum: floatPointer(float64(appMCPCommandSafeIntegerMax))},
		"project_id": {Type: "integer", Minimum: floatPointer(1), Maximum: floatPointer(float64(appMCPCommandSafeIntegerMax))},
	}
	manifest.Tools[0].InputSchema.Properties["arguments"].Required = []string{"id", "project_id"}
	manifest.Tools[0].OutputSchema = &AppMCPSchema{Type: "object", AdditionalProperties: commandBoolPtr(false), Required: []string{"id", "status"}, Properties: map[string]*AppMCPSchema{
		"id":     {Type: "integer", Minimum: floatPointer(1), Maximum: floatPointer(float64(appMCPCommandSafeIntegerMax))},
		"status": {Type: "string", MinLength: intPointer(1), MaxLength: intPointer(32)},
	}}
	manifest.Tools[0].Permissions = []string{"tasks:write"}
	manifest.Tools[0].Output.Include = []string{"id", "status"}
	manifest.Resources = []AppMCPResource{{Name: "command", URI: grantFixtureResource, MIMEType: "application/json", Component: "none"}}
	manifestBytes, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "mcp.yaml", string(manifestBytes))
	reviewAppMCPFixture(t, dir)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	app.DB.SetMaxOpenConns(1)
	t.Cleanup(app.Shutdown)
	ensureEmptyCommandWebhookFixture(t, app)
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	ensureCommandAuditFixture(t, app)
	cookie := createCrudScopeSession(t, app, "task-actor@example.com", "editor", "", "")
	actor := GetSessionFromDB(app.DB, cookie)
	if actor == nil || actor.GroupID != "" {
		t.Fatalf("groupless actor session: %#v", actor)
	}
	if _, err := app.DB.Exec(`INSERT INTO tasks(id,project_id,title,status) VALUES(1,7,'Task','open'),(2,7,'Other','open')`); err != nil {
		t.Fatal(err)
	}
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	h := &exposureHarness{t: t, app: app, actorID: actor.UserID, cookie: cookie}
	h.server = httptest.NewTLSServer(mux)
	t.Cleanup(h.server.Close)
	h.resource = h.server.URL + "/api/_mcp"
	registerAppMCPTransport(mux, app, h.resource)
	h.browser = &http.Client{Transport: h.server.Client().Transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	if h.pair, err = createAppMCPNativeGrantFor(context.Background(), app, actor.UserID, "", "client-b2", h.resource, "complete_item", time.Now()); err != nil {
		t.Fatalf("grant: %v", err)
	}
	h.client = appMCPClient(t, h.server, h.pair.AccessToken, nil)

	id := h.prepare()
	h.approveOK(id)
	out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id})
	if code != "" || out["outcome"] != "applied" {
		t.Fatalf("commit: %q %#v", code, out)
	}
	if state := h.status(id); state["state"] != "succeeded" || state["business"] != "committed" {
		t.Fatalf("status: %#v", state)
	}
	if h.count("SELECT count(*) FROM tasks WHERE id=1 AND status='done' AND completed_by=?", actor.UserID) != 1 {
		t.Fatal("groupless command did not apply")
	}
	// A session that carries a workspace is not the groupless preparer's.
	other := CreateSession(app.DB, actor.UserID, "task-actor@example.com", "5", time.Hour)
	second := h.prepareTask(2)
	if status, _, token := h.review(other, second); status == 200 || token != "" {
		t.Fatalf("a session with a workspace reviewed a groupless operation: %d", status)
	}
}

func TestAppMCPExposureOperationIsBoundToItsConnection(t *testing.T) {
	h := newExposureHarness(t)
	id := h.prepare()
	h.approveOK(id)
	second, err := createAppMCPNativeGrantFor(context.Background(), h.app, h.actorID, "17", "client-other", h.resource, "complete_item", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	other := appMCPClient(t, h.server, second.AccessToken, nil)
	if _, code := h.call(other, appMCPCommitTool, map[string]any{"operation_id": id}); code != "denied" {
		t.Fatalf("another grant committed: %q", code)
	}
	if _, code := h.call(other, appMCPStatusTool, map[string]any{"operation_id": id}); code != "denied" {
		t.Fatalf("another grant read status: %q", code)
	}
	if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": strings.Repeat("b", 64)}); code != "denied" {
		t.Fatalf("unknown operation: %q", code)
	}
	if h.taskDone() {
		t.Fatal("business row changed")
	}
}

func TestAppMCPExposureUnknownCommitReconcilesFromDurableRow(t *testing.T) {
	h := newExposureHarness(t)
	h.app.DB.SetMaxIdleConns(1)
	id := h.prepare()
	h.approveOK(id)
	// Reject the next outer COMMIT through the pooled (only) connection. That is
	// the claim's: no attempt becomes durable, so the retry below is a first attempt.
	// An unknown apply-phase COMMIT is covered in app_mcp_operation_attempts_test.go.
	conn, err := h.app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	hook := func(fail bool) {
		if err := conn.Raw(func(raw any) error {
			raw.(*sqlite3.SQLiteConn).RegisterCommitHook(func() int {
				if fail {
					return 1
				}
				return 0
			})
			return nil
		}); err != nil {
			t.Fatal(err)
		}
	}
	hook(true)
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "unknown_execution" {
		t.Fatalf("unknown commit: %q", code)
	}
	conn, err = h.app.DB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	hook(false)
	_ = conn.Close()
	// Durable truth: not committed, still approved; business rows untouched.
	if state := h.status(id); state["state"] != "approved" || state["business"] != "not_committed" || h.taskDone() {
		t.Fatalf("reconciled status: %#v done=%v", state, h.taskDone())
	}
	if out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "" || out["outcome"] != "applied" {
		t.Fatalf("retry: %q %#v", code, out)
	}
	if state := h.status(id); state["state"] != "succeeded" || h.count("SELECT count(*) FROM activities") != 1 {
		t.Fatalf("final status: %#v", state)
	}
}

func TestAppMCPExposureOutcomeMapping(t *testing.T) {
	boom := errors.New("boom")
	if err := appMCPFinishOutcome(appMCPCommandTxOutcome{State: appMCPCommandCommitConfirmed}, boom); err != nil {
		t.Fatalf("confirmed commit with cleanup error: %v", err)
	}
	var unknown *appMCPCommandOutcomeUnknownError
	if err := appMCPFinishOutcome(appMCPCommandTxOutcome{State: appMCPCommandCommitUnknown}, boom); !errors.As(err, &unknown) {
		t.Fatalf("unknown commit: %v", err)
	}
	if err := appMCPFinishOutcome(appMCPCommandTxOutcome{}, boom); err != boom {
		t.Fatalf("rolled back: %v", err)
	}
}
