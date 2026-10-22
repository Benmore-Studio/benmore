//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/jsonrpc"
	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
)

// This is declaration/capture and public-surface coverage only. It exercises
// the real read transport alongside an inert command declaration.
func TestAppMCPCommandSourceRemainsAbsentFromPairedPublicSurfaces(t *testing.T) {
	epochFixture(t)
	app, _ := auditApp(t)
	testKey, err := cryptoDeriveAppKey(strings.Repeat("42", 32))
	if err != nil {
		t.Fatal(err)
	}
	RegisterDBEncryptionKey(filepath.Join(app.Dir, "data.db"), testKey)
	if err := EnsureUserRolesTable(app.DB); err != nil {
		t.Fatal(err)
	}
	sid := createCrudScopeSession(t, app, "paired@example.com", "editor", "17", "")
	session := GetSessionFromDB(app.DB, sid)
	uid := session.UserID
	auditExec(t, app.DB, "INSERT INTO members(org_id,email) VALUES ('17',?)", "paired@example.com")
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{"editor": {Scopes: "notes:read"}, "admin": {Scopes: "notes:read"}}}
	app.Design = &DesignConfig{Auth: map[string]string{"enabled": "true"}}
	app.Paths = DiscoverAuthPaths(nil)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT);\nCREATE TABLE work_items (id INTEGER PRIMARY KEY, status TEXT);\n")
	auditExec(t, app.DB, "CREATE TABLE work_items (id INTEGER PRIMARY KEY, status TEXT)")
	auditExec(t, app.DB, "INSERT INTO notes(id,user_id,title) VALUES (1,?,'paired-owned')", uid)
	readFlow := `on:
  request:
    method: GET
    path: /api/mcp-note/:id
    auth: required
    role: editor
    permissions: [notes:read]
    transaction: false
jobs:
  read_note:
    steps:
      - id: note
        query: SELECT id, user_id AS actor_id, CAST(:_group_id AS TEXT) AS tenant_id, title FROM notes WHERE id = :id AND user_id = :user_id
      - run: respond
        with:
          body: ${{ steps.note.outputs.rows[0] }}
`
	commandFlow := `on: {request: {method: POST, path: /api/private-command, auth: required, transaction: true}}
` + commandFixtureForManifest
	commandFlow = strings.Replace(commandFlow, "prepared_schema: {type: object, additionalProperties: false, properties: {arguments: {type: object, additionalProperties: false, properties: {id: {type: string, maxLength: 64}}, required: [id]}}", "prepared_schema: {type: object, additionalProperties: false, properties: {arguments: {type: object, additionalProperties: false, properties: {id: {type: integer, minimum: 1, maximum: 9007199254740991}}, required: [id]}}", 1)
	commandFlow = strings.Replace(commandFlow, "prepare: {steps: [", "prepare: {steps: [{for_each: '${{ params.arguments.tasks }}', as: task, steps: [{run: set, with: {local_title: '${{ params.task }}'}}]}, {run: compute, with: {module: task/prepare, function: prepareTask, args: '${{ params.arguments.id }}'}}, ", 1)
	writeTestFile(t, app.Dir, "flows/read_note.yaml", readFlow)
	writeTestFile(t, app.Dir, "flows/complete_item.yaml", commandFlow)
	writeTestFile(t, app.Dir, "static/task/prepare.ts", "export function prepareTask() { return {}; }\n")
	readManifest, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	readManifest.Tools = []AppMCPTool{{Name: "read_note", Description: "Read one authorized note", Handler: AppMCPHandler{Kind: "native", Operation: "flow.call", Flow: "read_note"}, InputSchema: &AppMCPSchema{Type: "object", AdditionalProperties: &closed, Required: []string{"id"}, Properties: map[string]*AppMCPSchema{"id": {Type: "integer"}}}, OutputSchema: &AppMCPSchema{Type: "object", AdditionalProperties: &closed, Required: []string{"id", "actor_id", "tenant_id", "title"}, Properties: map[string]*AppMCPSchema{"id": {Type: "integer"}, "actor_id": {Type: "integer"}, "tenant_id": {Type: "string"}, "title": {Type: "string"}}}, Permissions: []string{"notes:read"}, Effect: "read", Approval: "none", Idempotency: "none", Reconciliation: "none", Output: AppMCPProjection{Include: []string{"id", "actor_id", "tenant_id", "title"}}, Component: "none"}}
	commandTool := commandManifest().Tools[0]
	args := commandTool.InputSchema.Properties["arguments"]
	args.Properties["tasks"] = &AppMCPSchema{Type: "array", Items: &AppMCPSchema{Type: "string", MaxLength: intPointer(128)}, MinItems: intPointer(1), MaxItems: intPointer(8)}
	args.Required = append(args.Required, "tasks")
	commandTool.Permissions = []string{"work_items:write"}
	readManifest.Tools = append(readManifest.Tools, commandTool)
	manifestBytes, err := yaml.Marshal(readManifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "mcp.yaml", string(manifestBytes))
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatalf("mixed source-backed declaration failed loading: %v", err)
	}
	app.MCP, app.Flows, app.sourceFiles = config.mcp, config.flows, config.sourceFiles
	if len(app.Flows) != 2 || app.Flows[0].Command == nil && app.Flows[1].Command == nil {
		t.Fatalf("mixed generation lost source declarations: %#v", app.Flows)
	}
	var command *Flow
	for i := range app.Flows {
		if app.Flows[i].Command != nil {
			command = &app.Flows[i]
		}
	}
	if command == nil || command.Command.PreparedSchema.Properties["arguments"].Properties["id"].Type != "integer" || app.MCP.Tools[1].InputSchema.Properties["arguments"].Properties["id"].Type != "string" || string(app.sourceFiles["static/task/prepare.ts"]) == "" {
		t.Fatal("captured task declaration lost distinct original/prepared schemas or compute source")
	}
	if appMCPReadTool(app, "complete_item") != nil || appMCPSupportedScopes(app.MCP) != "notes:read" {
		t.Fatal("command declaration entered ordinary SDK inventory or supported OAuth scopes")
	}
	if err := ensureAppMCPGrantTables(app.DB); err != nil {
		t.Fatal(err)
	}
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	pair := fixtureGrant(t, app, uid, time.Now())
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveAppMCP(w, r, app, grantFixtureResource) }))
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	httpClient := server.Client()
	httpClient.Transport = appMCPProxyFixtureTransport{httpClient.Transport, target, pair.AccessToken}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	client := sdk.NewClient(&sdk.Implementation{Name: "paired-command-surface", Version: "1"}, nil)
	sdkSession, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: grantFixtureResource, HTTPClient: httpClient, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = sdkSession.Close() })
	listed, err := sdkSession.ListTools(ctx, nil)
	if err != nil || len(listed.Tools) != 1 || listed.Tools[0].Name != "read_note" {
		t.Fatalf("actual SDK inventory did not preserve only B1 read: %+v %v", listed, err)
	}
	result, err := sdkSession.CallTool(ctx, &sdk.CallToolParams{Name: "read_note", Arguments: map[string]any{"id": 1}})
	if err != nil || result.IsError || result.StructuredContent == nil || !strings.Contains(result.Content[0].(*sdk.TextContent).Text, "paired-owned") {
		t.Fatalf("actual authorized B1 read failed: %+v %v", result, err)
	}
	var before int
	if err := app.DB.QueryRow("SELECT count(*) FROM work_items").Scan(&before); err != nil {
		t.Fatal(err)
	}
	refused, err := sdkSession.CallTool(ctx, &sdk.CallToolParams{Name: "complete_item", Arguments: map[string]any{"arguments": map[string]any{"id": "1", "tasks": []any{"ship"}}}})
	var rpcErr *jsonrpc.Error
	if refused != nil || !errors.As(err, &rpcErr) || rpcErr.Code != jsonrpc.CodeInvalidParams || rpcErr.Message != `unknown tool "complete_item"` {
		t.Fatalf("actual SDK command omission did not return exact JSON-RPC refusal: result=%+v error=%v", refused, err)
	}
	var after int
	if err := app.DB.QueryRow("SELECT count(*) FROM work_items").Scan(&after); err != nil || after != before {
		t.Fatalf("unknown command altered business state: before=%d after=%d err=%v", before, after, err)
	}

	mux := buildAppMux(app, false, appMCPOAuthHTTPOrigin)
	for _, path := range []string{"/.well-known/oauth-authorization-server", "/.well-known/oauth-protected-resource/api/_mcp"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, appMCPOAuthHTTPOrigin+path, nil))
		var metadata struct {
			Scopes []string `json:"scopes_supported"`
		}
		if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &metadata) != nil || len(metadata.Scopes) != 1 || metadata.Scopes[0] != "notes:read" {
			t.Fatalf("actual discovery widened command scope at %s: %d %s", path, rec.Code, rec.Body.String())
		}
	}
	appOAuthEnsureTables(app)
	auditExec(t, app.DB, "INSERT INTO _benmore_oauth_clients(client_id,name,redirect_uris,scopes) VALUES ('paired-client','Paired client',?,?)", `[`+`"`+mcpOAuthFixtureRedirect+`"`+`]`, "notes:read work_items:write")
	verifier := "paired-surface-verifier-012345678901234567890123456789"
	values := url.Values{"response_type": {"code"}, "client_id": {"paired-client"}, "redirect_uri": {mcpOAuthFixtureRedirect}, "state": {"paired-state"}, "code_challenge": {oauthPKCEChallenge(verifier)}, "code_challenge_method": {"S256"}, "resource": {grantFixtureResource}, "workspace": {"17"}}
	readConsent := cloneMCPOAuthValues(values)
	readConsent.Set("scope", "notes:read")
	readReq := httptest.NewRequest(http.MethodGet, appMCPOAuthHTTPOrigin+"/oauth/authorize?"+readConsent.Encode(), nil)
	readReq.AddCookie(sessionCookie(sid, false, time.Hour))
	readResp := httptest.NewRecorder()
	mux.ServeHTTP(readResp, readReq)
	if readResp.Code != http.StatusOK || !strings.Contains(readResp.Body.String(), "notes:read") {
		t.Fatalf("actual paired read consent failed: %d %s", readResp.Code, readResp.Body.String())
	}
	approval := appMCPOAuthHTTPHidden(t, readResp.Body.String())
	approval.Set("decision", "approve")
	approveReq := httptest.NewRequest(http.MethodPost, appMCPOAuthHTTPOrigin+"/oauth/authorize", strings.NewReader(approval.Encode()))
	approveReq.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	approveReq.Header.Set("Origin", appMCPOAuthHTTPOrigin)
	approveReq.AddCookie(sessionCookie(sid, false, time.Hour))
	approveResp := httptest.NewRecorder()
	mux.ServeHTTP(approveResp, approveReq)
	if approveResp.Code != http.StatusFound || !strings.Contains(approveResp.Header().Get("Location"), "code=") || !strings.Contains(approveResp.Header().Get("Location"), "state=paired-state") {
		t.Fatalf("actual paired read consent approval failed: %d %s", approveResp.Code, approveResp.Body.String())
	}
	writeConsent := cloneMCPOAuthValues(values)
	writeConsent.Set("scope", "work_items:write")
	writeReq := httptest.NewRequest(http.MethodGet, appMCPOAuthHTTPOrigin+"/oauth/authorize?"+writeConsent.Encode(), nil)
	writeReq.AddCookie(sessionCookie(sid, false, time.Hour))
	writeResp := httptest.NewRecorder()
	mux.ServeHTTP(writeResp, writeReq)
	if writeResp.Code != http.StatusBadRequest || strings.Contains(writeResp.Body.String(), "work_items:write") {
		t.Fatalf("actual command write-scope consent accepted: %d %s", writeResp.Code, writeResp.Body.String())
	}

	flowIndex := httptest.NewRecorder()
	indexReq := httptest.NewRequest(http.MethodGet, "https://fixture.example/_internal/flows.json", nil)
	indexReq.AddCookie(sessionCookie(sid, false, time.Hour))
	mux.ServeHTTP(flowIndex, indexReq)
	if flowIndex.Code != http.StatusOK || !strings.Contains(flowIndex.Body.String(), "readNote") || strings.Contains(flowIndex.Body.String(), "completeItem") || strings.Contains(flowIndex.Body.String(), "private-command") {
		t.Fatalf("actual flows.json exposed command or hid ordinary route: %d %s", flowIndex.Code, flowIndex.Body.String())
	}
	if _, pattern := mux.Handler(httptest.NewRequest(http.MethodPost, "/api/private-command", nil)); pattern == "POST /api/private-command" {
		t.Fatalf("ordinary mux registered command path %q", pattern)
	}
	ordinaryRoute := httptest.NewRecorder()
	mux.ServeHTTP(ordinaryRoute, httptest.NewRequest(http.MethodPost, "/api/private-command", strings.NewReader("{}")))
	if ordinaryRoute.Code != http.StatusNotFound {
		t.Fatalf("ordinary HTTP surface accepted command declaration: %d", ordinaryRoute.Code)
	}
	if err := executeFlowHTTP(app, command, httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/private-command", nil)); err == nil {
		t.Fatal("direct ordinary HTTP command execution accepted")
	}
	if err := executeFlowJob(app, command.Name, map[string]any{}); err == nil {
		t.Fatal("direct ordinary job command execution accepted")
	}
}
