//go:build !cli && !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func appMCPReadFlowFixture(t *testing.T, method string, transaction bool) (*App, int64, *appMCPTokenPair, *AppMCPTool) {
	t.Helper()
	app, uid, _ := appMCPGrantFixture(t)
	flow := fmt.Sprintf(`on:
  request:
    method: %s
    path: /api/mcp-note/:id
    auth: required
    role: editor
    permissions: [notes:read]
    transaction: %t
jobs:
  read_note:
    steps:
      - id: note
        query: SELECT id, user_id AS actor_id, CAST(:_group_id AS TEXT) AS tenant_id, title FROM notes WHERE id = :id AND user_id = :user_id
      - run: respond
        with:
          body: ${{ steps.note.outputs.rows[0] }}
`, method, transaction)
	manifest := `version: 1
connector: {id: fixture, name: Fixture, version: '1'}
contract_digest: ` + strings.Repeat("a", 64) + `
execution_digest: ` + strings.Repeat("b", 64) + `
tools:
  - name: read_note
    description: Read one authorized note
    handler: {kind: native, operation: flow.call, flow: read_note}
    input_schema:
      type: object
      additionalProperties: false
      required: [id]
      properties:
        id: {type: integer}
    output_schema:
      type: object
      additionalProperties: false
      required: [id, actor_id, tenant_id, title]
      properties:
        id: {type: integer}
        actor_id: {type: integer}
        tenant_id: {type: string}
        title: {type: string}
    permissions: [notes:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [id, actor_id, tenant_id, title]}
    component: none
resources: []
connections: []
`
	writeTestFile(t, app.Dir, "flows/read_note.yaml", flow)
	writeTestFile(t, app.Dir, "mcp.yaml", manifest)
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP, app.Flows, app.sourceFiles = config.mcp, config.flows, config.sourceFiles
	return app, uid, fixtureGrant(t, app, uid, time.Now()), &app.MCP.Tools[0]
}

func TestAppMCPReadFlowBindsCanonicalIdentityAndPreservesSQLID(t *testing.T) {
	const largeID int64 = 9007199254740993
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		for _, transaction := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/transaction=%t", method, transaction), func(t *testing.T) {
				app, uid, pair, tool := appMCPReadFlowFixture(t, method, transaction)
				app.DB.SetMaxOpenConns(1)
				auditExec(t, app.DB, "INSERT INTO notes(id,user_id,title) VALUES (?,?,?), (?,?,?)", largeID, uid, "owned", largeID+1, 999, "foreign-secret")
				args := map[string]any{"id": json.Number(fmt.Sprint(largeID))}
				result, err := runAppMCPReadFlow(context.Background(), app, pair.AccessToken, grantFixtureResource, tool, args)
				if err != nil {
					t.Fatalf("canonical flow read (%s): %v", nativeResultErrorCode(t, err), err)
				}
				encoded, err := json.Marshal(result.Data)
				if err != nil || !strings.Contains(string(encoded), `"id":9007199254740993`) || !strings.Contains(string(encoded), `"actor_id":`+fmt.Sprint(uid)) || !strings.Contains(string(encoded), `"tenant_id":"17"`) || strings.Contains(string(encoded), "foreign-secret") {
					t.Fatalf("untrusted identity or lossy projection: %s (%v)", encoded, err)
				}
				if result.Completeness.State != "indeterminate" || result.Completeness.Basis != "declared_output" {
					t.Fatalf("flow completeness overstated: %+v", result.Completeness)
				}
				if got, err := runAppMCPReadFlow(context.Background(), app, pair.AccessToken, grantFixtureResource, tool, map[string]any{"id": json.Number(fmt.Sprint(largeID + 1))}); got != nil || err == nil {
					t.Fatalf("foreign row returned: %+v %v", got, err)
				}
				if _, err := app.DB.Exec("INSERT INTO notes(user_id,title) VALUES (?, 'pool-restored')", uid); err != nil {
					t.Fatalf("read flow left pooled connection read-only or held: %v", err)
				}
			})
		}
	}
}

func TestAppMCPReadFlowPolicyRejectsEffectsEverywhere(t *testing.T) {
	for _, tc := range []struct {
		name  string
		steps []FlowStep
	}{
		{"api", []FlowStep{{Type: "api"}}},
		{"webhook", []FlowStep{{Type: "webhook"}}},
		{"enqueue", []FlowStep{{Type: "enqueue"}}},
		{"write", []FlowStep{{Type: "sql", SQL: "UPDATE notes SET title='x'"}}},
		{"nested", []FlowStep{{Type: "if", Steps: []FlowStep{{Type: "api"}}}}},
		{"else", []FlowStep{{Type: "if", ElseSteps: []FlowStep{{Type: "enqueue"}}}}},
		{"on_error", []FlowStep{{Type: "sql", SQL: "SELECT 1", OnError: []FlowStep{{Type: "webhook"}}}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			flow := &Flow{Trigger: FlowTrigger{Type: "http"}, Steps: tc.steps}
			if err := appMCPReadFlowPolicy(flow); err == nil {
				t.Fatal("effectful flow accepted")
			}
		})
	}
	if err := appMCPReadFlowPolicy(&Flow{Trigger: FlowTrigger{Type: "http"}, Async: true}); err == nil {
		t.Fatal("async flow accepted")
	}
}

func TestAppMCPReadFlowSQLiteAuthorizerAndPoolCleanup(t *testing.T) {
	app, uid, _, _ := appMCPReadFlowFixture(t, http.MethodGet, false)
	app.DB.SetMaxOpenConns(1)
	request := httptest.NewRequest(http.MethodGet, "/api/mcp-note/1", nil)
	ctx := &FlowContext{App: app, Request: request}
	closeConn, err := startAppMCPReadFlow(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, query := range []string{"DELETE FROM notes", "PRAGMA query_only=OFF", "ATTACH DATABASE ':memory:' AS bypass"} {
		if _, err := ctx.mcpReadConn.ExecContext(request.Context(), query); err == nil {
			t.Errorf("read-only connection accepted %q", query)
		}
	}
	closeConn()
	var count int
	if err := app.DB.QueryRow("SELECT count(*) FROM notes").Scan(&count); err != nil || count != 0 {
		t.Fatalf("blocked statements changed data: count=%d err=%v", count, err)
	}
	if _, err := app.DB.Exec("INSERT INTO notes(user_id,title) VALUES (?, 'writable-after-close')", uid); err != nil {
		t.Fatalf("connection state was not restored: %v", err)
	}
}

func TestAppMCPReadFlowRevocationRoleAndSourceDrift(t *testing.T) {
	app, _, pair, tool := appMCPReadFlowFixture(t, http.MethodGet, false)
	args := map[string]any{"id": json.Number("1")}
	app.Flows[0].Role = "admin"
	if result, err := runAppMCPReadFlow(context.Background(), app, pair.AccessToken, grantFixtureResource, tool, args); result != nil || err == nil {
		t.Fatalf("role mismatch authorized: %+v %v", result, err)
	}
	app.Flows[0].Role = "editor"
	if err := revokeAppMCPGrant(app, pair.GrantID); err != nil {
		t.Fatal(err)
	}
	if result, err := runAppMCPReadFlow(context.Background(), app, pair.AccessToken, grantFixtureResource, tool, args); result != nil || err == nil {
		t.Fatalf("revoked grant authorized: %+v %v", result, err)
	}
	writeTestFile(t, app.Dir, "flows/read_note.yaml", "# changed after review\n")
	if _, err := loadRuntimeConfig(app.Dir); err == nil {
		t.Fatal("source drift passed reviewed manifest loading")
	}
}

func TestAppMCPComputeArgsRejectImpreciseNumbers(t *testing.T) {
	for _, value := range []any{json.Number("9007199254740993"), int64(9007199254740993), []map[string]any{{"id": int64(9007199254740993)}}} {
		if got, err := appMCPComputeArgs(value); err == nil {
			t.Errorf("imprecise compute number accepted: %#v", got)
		}
	}
	for _, value := range []any{json.Number("9007199254740992"), json.Number("12.5"), int64(42)} {
		if _, err := appMCPComputeArgs(value); err != nil {
			t.Errorf("exact compute number rejected (%v): %v", value, err)
		}
	}
}

func TestAppMCPReadFlowAndComputeHonorCancellation(t *testing.T) {
	app, _, pair, tool := appMCPReadFlowFixture(t, http.MethodGet, false)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if result, err := runAppMCPReadFlow(ctx, app, pair.AccessToken, grantFixtureResource, tool, map[string]any{"id": json.Number("1")}); result != nil || err == nil {
		t.Fatalf("canceled SQL flow returned success: %+v %v", result, err)
	}
	if result, err := RunComputeContext(ctx, app, "unused", "unused", nil, time.Second); result != nil || err == nil {
		t.Fatalf("canceled compute returned success: %+v %v", result, err)
	}
}

// Route through a real loopback TLS proxy with the pinned public Host. This
// exercises the hosted-proxy exception without a separate runtime server.
type appMCPProxyFixtureTransport struct {
	base   http.RoundTripper
	target *url.URL
	token  string
}

func (p appMCPProxyFixtureTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Host = r.URL.Host
	r.URL.Scheme = p.target.Scheme
	r.URL.Host = p.target.Host
	r.Header.Set("Authorization", "Bearer "+p.token)
	return p.base.RoundTrip(r)
}
func TestAppMCPReadFlowSDKProxyAndFreshInventory(t *testing.T) {
	app, uid, pair, _ := appMCPReadFlowFixture(t, "GET", false)
	auditExec(t, app.DB, "INSERT INTO notes(id,user_id,title) VALUES (1,?,'owned')", uid)
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveAppMCP(w, r, app, grantFixtureResource) }))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	clientHTTP := server.Client()
	clientHTTP.Transport = appMCPProxyFixtureTransport{clientHTTP.Transport, target, pair.AccessToken}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := sdk.NewClient(&sdk.Implementation{Name: "flow-fixture", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: grantFixtureResource, HTTPClient: clientHTTP, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Close()
	listed, err := session.ListTools(ctx, nil)
	if err != nil || len(listed.Tools) != 1 || listed.CacheScope != "private" || listed.TTLMs != 0 {
		t.Fatalf("inventory: %+v %v", listed, err)
	}
	result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "read_note", Arguments: map[string]any{"id": 1}})
	if err != nil || result.IsError || result.StructuredContent == nil {
		t.Fatalf("flow tool: %+v %v", result, err)
	}
	text, ok := result.Content[0].(*sdk.TextContent)
	if !ok || !strings.Contains(text.Text, `"declared_output"`) {
		t.Fatalf("flow text: %+v", result.Content)
	}
	invalid, err := session.CallTool(ctx, &sdk.CallToolParams{Name: "read_note", Arguments: map[string]any{"id": "wrong"}})
	if err != nil || !invalid.IsError || invalid.StructuredContent != nil || invalid.Meta["error_code"] != "invalid_input" || !strings.Contains(invalid.Content[0].(*sdk.TextContent).Text, "invalid_input") {
		t.Fatalf("stable tool error: %+v %v", invalid, err)
	}
	app.Roles.Roles["user"] = RoleDef{Scopes: "notes:read"}
	auditExec(t, app.DB, "UPDATE _benmore_users SET role='user' WHERE id=?", uid)
	listed, err = session.ListTools(ctx, nil)
	if err != nil || len(listed.Tools) != 0 {
		t.Fatalf("cached forbidden inventory: %+v %v", listed, err)
	}
	if result, err = session.CallTool(ctx, &sdk.CallToolParams{Name: "read_note", Arguments: map[string]any{"id": 1}}); err == nil && (result == nil || !result.IsError) {
		t.Fatalf("forbidden cached tool: %+v %v", result, err)
	}
}
func TestAppMCPReadFlowErrorsDoNotLogPrivateRows(t *testing.T) {
	app, uid, pair, _ := appMCPReadFlowFixture(t, "GET", false)
	file := filepath.Join(app.Dir, "flows", "read_note.yaml")
	source, err := os.ReadFile(file)
	if err != nil {
		t.Fatal(err)
	}
	source = []byte(strings.Replace(string(source), "- id: note\n        query: SELECT id, user_id AS actor_id, CAST(:_group_id AS TEXT) AS tenant_id, title FROM notes WHERE id = :id AND user_id = :user_id", "- id: note\n        run: compute\n        module: throw-private\n        function: fail", 1))
	writeTestFile(t, app.Dir, "flows/read_note.yaml", string(source))
	writeTestFile(t, app.Dir, "static/throw-private.ts", `export function fail(){ throw new Error("PRIVATE-ROW-SECRET"); }`)
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP, app.Flows = config.mcp, config.flows
	// Mint a current token for the reviewed fixture.
	pair = fixtureGrant(t, app, uid, time.Now())
	var logs bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(previous)
	if result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "read_note", map[string]any{"id": 1}); result != nil || err == nil {
		t.Fatalf("throw returned rows: %+v %v", result, err)
	}
	if strings.Contains(logs.String(), "PRIVATE-ROW-SECRET") {
		t.Fatal("private exception payload entered canonical logs")
	}
}

func TestAppMCPReadFlowOnErrorResponseRemainsFailed(t *testing.T) {
	for _, transaction := range []bool{false, true} {
		t.Run(fmt.Sprint(transaction), func(t *testing.T) {
			app, uid, _, _ := appMCPReadFlowFixture(t, "GET", transaction)
			file := filepath.Join(app.Dir, "flows", "read_note.yaml")
			source, err := os.ReadFile(file)
			if err != nil {
				t.Fatal(err)
			}
			// The handler has a complete, otherwise valid result. A failed
			// connector read still must not release it as an authoritative read.
			handler := fmt.Sprintf(`    steps:
      - id: fails
        query: SELECT * FROM no_such_table
        on_error:
          - run: respond
            with:
              body: {id: 1, actor_id: %d, tenant_id: "17", title: fallback}
`, uid)
			writeTestFile(t, app.Dir, "flows/read_note.yaml", strings.Replace(string(source), "    steps:\n", handler, 1))
			reviewAppMCPFixture(t, app.Dir)
			config, err := loadRuntimeConfig(app.Dir)
			if err != nil {
				t.Fatal(err)
			}
			app.MCP, app.Flows, app.sourceFiles = config.mcp, config.flows, config.sourceFiles
			pair := fixtureGrant(t, app, uid, time.Now())
			result, err := runAppMCPNativeRead(context.Background(), app, pair.AccessToken, grantFixtureResource, "read_note", map[string]any{"id": 1})
			if result != nil || err == nil {
				t.Fatalf("failed connector released handler response: result=%+v err=%v", result, err)
			}
		})
	}
}

// A connector flow call is an in-process request with no client address, so a
// per-ip rate limit used to put every connected user in one shared bucket:
// one user's calls exhausted the flow for everyone else.
func TestAppMCPReadFlowIPRateLimitIsPerConnectedUser(t *testing.T) {
	app, uid, pair, tool := appMCPReadFlowFixture(t, http.MethodGet, false)
	for i := range app.Flows {
		if app.Flows[i].Name == tool.Handler.Flow {
			app.Flows[i].RateLimit = parseRateLimit("1/hour")
		}
	}
	sid := createCrudScopeSession(t, app, "second@example.com", "editor", "17", "")
	other := GetSessionFromDB(app.DB, sid).UserID
	auditExec(t, app.DB, "INSERT INTO members(org_id,email) VALUES ('17','second@example.com')")
	auditExec(t, app.DB, "INSERT INTO notes(id,user_id,title) VALUES (1,?,'first'),(2,?,'second')", uid, other)
	otherPair := fixtureGrant(t, app, other, time.Now())
	if _, err := runAppMCPReadFlow(context.Background(), app, pair.AccessToken, grantFixtureResource, tool, map[string]any{"id": json.Number("1")}); err != nil {
		t.Fatalf("first user's call: %v", err)
	}
	if _, err := runAppMCPReadFlow(context.Background(), app, otherPair.AccessToken, grantFixtureResource, tool, map[string]any{"id": json.Number("2")}); err != nil {
		t.Fatalf("second user throttled by the first user's calls: %v", err)
	}
	if _, err := runAppMCPReadFlow(context.Background(), app, pair.AccessToken, grantFixtureResource, tool, map[string]any{"id": json.Number("1")}); err == nil {
		t.Fatal("rate limit no longer applies to the same connected user")
	}
}

func TestAppMCPReadFlowRejectsParallel(t *testing.T) {
	flow := &Flow{Trigger: FlowTrigger{Type: "http"}, Steps: []FlowStep{{Type: "parallel", Steps: []FlowStep{{Type: "set"}}}}}
	if err := appMCPReadFlowPolicy(flow); err == nil {
		t.Fatal("parallel shared-context execution accepted")
	}
}
