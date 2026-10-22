//go:build !cli && !windows

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

type appMCPClientWireRequest struct {
	method string
	header http.Header
	body   []byte
	status int
}

type appMCPClientCapture struct {
	mu       sync.Mutex
	requests []appMCPClientWireRequest
}

type appMCPCaptureWriter struct {
	http.ResponseWriter
	status int
}

func (w *appMCPCaptureWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (c *appMCPClientCapture) handler(app *App, resource string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body = io.NopCloser(bytes.NewReader(body))
		cw := &appMCPCaptureWriter{ResponseWriter: w}
		serveAppMCP(cw, r, app, resource)
		if cw.status == 0 {
			cw.status = http.StatusOK
		}
		c.mu.Lock()
		c.requests = append(c.requests, appMCPClientWireRequest{method: r.Method, header: r.Header.Clone(), body: append([]byte(nil), body...), status: cw.status})
		c.mu.Unlock()
	})
}

func (c *appMCPClientCapture) snapshot() []appMCPClientWireRequest {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]appMCPClientWireRequest(nil), c.requests...)
}

func appMCPClient(t *testing.T, server *httptest.Server, token string, jar http.CookieJar) *sdk.ClientSession {
	t.Helper()
	// Keep bearer wrappers per SDK session so tenant credentials cannot nest.
	client := &http.Client{Transport: server.Client().Transport}
	if jar != nil {
		client.Jar = jar
	}
	if token != "" {
		client.Transport = appMCPBearerRoundTripper{base: client.Transport, token: token}
	}
	transport := &sdk.StreamableClientTransport{Endpoint: server.URL + "/api/_mcp", HTTPClient: client, DisableStandaloneSSE: true}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	session, err := sdk.NewClient(&sdk.Implementation{Name: "b1-acceptance", Version: "1"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		t.Fatalf("connect official MCP SDK: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return session
}

func appMCPClientCall(ctx context.Context, t *testing.T, session *sdk.ClientSession, name string) map[string]any {
	t.Helper()
	result, err := session.CallTool(ctx, &sdk.CallToolParams{Name: name, Arguments: map[string]any{}})
	if err != nil || result.IsError || result.StructuredContent == nil {
		t.Fatalf("call %s: result=%+v err=%v", name, result, err)
	}
	return result.StructuredContent.(map[string]any)
}

func appMCPClientIDs(t *testing.T, envelope map[string]any) []int {
	t.Helper()
	data, ok := envelope["data"].([]any)
	if !ok {
		t.Fatalf("result data has type %T: %#v", envelope["data"], envelope)
	}
	ids := make([]int, 0, len(data))
	for _, item := range data {
		row, ok := item.(map[string]any)
		if !ok {
			t.Fatalf("result row has type %T", item)
		}
		id, ok := row["id"].(float64)
		if !ok {
			t.Fatalf("result row id has type %T", row["id"])
		}
		ids = append(ids, int(id))
	}
	slices.Sort(ids)
	return ids
}

func assertAppMCPModernSDKWire(t *testing.T, captured []appMCPClientWireRequest, negotiated string) {
	t.Helper()
	if negotiated != "2026-07-28" {
		t.Fatalf("official SDK negotiated %q, want pinned modern version 2026-07-28", negotiated)
	}
	var discover, list, call int
	for _, request := range captured {
		if request.method != http.MethodPost || len(request.body) == 0 {
			continue
		}
		if got := request.header.Get("Mcp-Protocol-Version"); got != negotiated {
			t.Fatalf("SDK POST has protocol header %q, want %q", got, negotiated)
		}
		var message struct {
			Method string `json:"method"`
			Params struct {
				Meta map[string]any `json:"_meta"`
			} `json:"params"`
		}
		if err := json.Unmarshal(request.body, &message); err != nil {
			t.Fatalf("captured SDK POST body is not JSON: %v", err)
		}
		meta := message.Params.Meta
		if meta == nil || meta["io.modelcontextprotocol/protocolVersion"] != negotiated {
			t.Fatalf("SDK %s request omitted matching protocol _meta: %#v", message.Method, meta)
		}
		switch message.Method {
		case "server/discover":
			if _, ok := meta["io.modelcontextprotocol/clientInfo"].(map[string]any); !ok {
				t.Fatal("SDK discovery omitted clientInfo _meta")
			}
			if _, ok := meta["io.modelcontextprotocol/clientCapabilities"].(map[string]any); !ok {
				t.Fatal("SDK discovery omitted clientCapabilities _meta")
			}
			discover++
		case "tools/list":
			list++
		case "tools/call":
			call++
		}
	}
	if discover == 0 || list == 0 || call == 0 {
		t.Fatalf("captured SDK methods: server/discover=%d tools/list=%d tools/call=%d", discover, list, call)
	}
}

func TestAppMCPRealSDKTLSRevocationAndCookieOnlyDenial(t *testing.T) {
	app, _, uid := appMCPResultFixture(t, false)
	var resource string
	capture := &appMCPClientCapture{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { capture.handler(app, resource).ServeHTTP(w, r) }))
	t.Cleanup(server.Close)
	resource = server.URL + "/api/_mcp"
	pair, err := createAppMCPGrant(app, uid, "17", "sdk-revocation", resource, "notes:read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	session := appMCPClient(t, server, pair.AccessToken, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if got := session.InitializeResult().ProtocolVersion; got != "2026-07-28" {
		t.Fatalf("SDK negotiated protocol %q", got)
	}
	if listed, err := session.ListTools(ctx, nil); err != nil || len(listed.Tools) != 1 || listed.Tools[0].Name != "list_notes" {
		t.Fatalf("initial authorized SDK discovery: %+v %v", listed, err)
	}
	appMCPClientCall(ctx, t, session, "list_notes")
	assertAppMCPModernSDKWire(t, capture.snapshot(), session.InitializeResult().ProtocolVersion)
	if _, err := app.DB.Exec("UPDATE _benmore_mcp_grants SET revoked=1"); err != nil {
		t.Fatal(err)
	}
	if _, err := session.ListTools(ctx, nil); err == nil {
		t.Fatal("same SDK session retained discovery after its grant was revoked")
	}
	requests := capture.snapshot()
	if len(requests) == 0 {
		t.Fatal("revoked SDK request was not captured")
	}
	if requests[len(requests)-1].status != http.StatusUnauthorized {
		t.Fatalf("revoked SDK request status: %d", requests[len(requests)-1].status)
	}

	// An ordinary valid application session cookie is not an MCP bearer grant.
	sid := CreateSession(app.DB, uid, "delegate@example.com", "17", time.Hour)
	ordinaryRequest := httptest.NewRequest(http.MethodGet, "/", nil)
	ordinaryRequest.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	if sid == "" || getSession(app, ordinaryRequest) == nil {
		t.Fatal("ordinary application cookie fixture is not a valid session")
	}
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	cookieCapture := &appMCPClientCapture{}
	var cookieServer *httptest.Server
	cookieServer = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookieCapture.handler(app, cookieServer.URL+"/api/_mcp").ServeHTTP(w, r)
	}))
	defer cookieServer.Close()
	serverURL, _ := url.Parse(cookieServer.URL)
	jar.SetCookies(serverURL, []*http.Cookie{{Name: sessionCookieName, Value: sid, Path: "/", Secure: true, HttpOnly: true}})
	plain := cookieServer.Client()
	plain.Jar = jar
	transport := &sdk.StreamableClientTransport{Endpoint: cookieServer.URL + "/api/_mcp", HTTPClient: plain, DisableStandaloneSSE: true}
	_, err = sdk.NewClient(&sdk.Implementation{Name: "cookie-only", Version: "1"}, nil).Connect(ctx, transport, nil)
	if err == nil {
		t.Fatal("ordinary session cookie authenticated an MCP SDK client without bearer")
	}
	got := cookieCapture.snapshot()
	if len(got) == 0 || got[0].status != http.StatusUnauthorized || got[0].header.Get("Authorization") != "" || !strings.Contains(got[0].header.Get("Cookie"), sessionCookieName+"="+sid) {
		t.Fatalf("cookie-only request did not prove cookie-present/bearer-absent 401: %+v", got)
	}
}

func TestAppMCPRealSDKTLSScopesDiscoveryAndRowsToTenantGrant(t *testing.T) {
	app, uid, _ := appMCPGrantFixture(t)
	manifest := strings.Replace(appMCPManifestFixture(), "resources: []", `  - name: list_projects
    description: Read reviewed project IDs
    handler: {kind: native, operation: table.list, table: projects}
    input_schema: {type: object, additionalProperties: false}
    output_schema:
      type: object
      additionalProperties: false
      properties:
        id: {type: integer}
    permissions: [projects:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [id]}
    component: none
resources: []`, 1)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT, org_id TEXT);\nCREATE TABLE projects (id INTEGER PRIMARY KEY, org_id TEXT);\n")
	writeTestFile(t, app.Dir, "mcp.yaml", manifest)
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP = config.mcp
	if _, err := app.DB.Exec("ALTER TABLE notes ADD COLUMN org_id TEXT"); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec("CREATE TABLE projects (id INTEGER PRIMARY KEY, org_id TEXT)"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"notes", "projects"} {
		columns, err := GetTableColumns(app.DB, table)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for i := range app.Tables {
			if app.Tables[i].Name == table {
				app.Tables[i].Columns = columns
				found = true
			}
		}
		if !found {
			app.Tables = append(app.Tables, Table{Name: table, Columns: columns})
		}
	}
	app.Access.rules["notes"] = map[AccessOp]string{"read": "group"}
	app.Access.rules["projects"] = map[AccessOp]string{"read": "group"}
	app.Roles.Roles["project_reader"] = RoleDef{Scopes: "projects:read"}
	auditExec(t, app.DB, "INSERT INTO _benmore_user_roles(user_id,role,group_id) VALUES (?,'project_reader','29')", uid)
	auditExec(t, app.DB, "INSERT INTO notes(id,user_id,title,org_id) VALUES (1,?,'tenant 17','17'),(2,?,'tenant 29','29'),(3,?,'foreign tenant decoy','99')", uid, uid, uid)
	auditExec(t, app.DB, "INSERT INTO projects(id,org_id) VALUES (17,'17'),(29,'29'),(99,'99')")

	var resource string
	capture := &appMCPClientCapture{}
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { capture.handler(app, resource).ServeHTTP(w, r) }))
	t.Cleanup(server.Close)
	resource = server.URL + "/api/_mcp"
	pair17, err := createAppMCPGrant(app, uid, "17", "tenant-17-sdk", resource, "notes:read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	pair29, err := createAppMCPGrant(app, uid, "29", "tenant-29-sdk", resource, "notes:read projects:read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if pair17.AccessToken == pair29.AccessToken {
		t.Fatal("distinct tenant grants unexpectedly share a bearer token")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, tc := range []struct {
		name         string
		pair         *appMCPTokenPair
		wantTools    []string
		wantNotes    []int
		wantProjects []int
	}{
		{"tenant-17", pair17, []string{"list_notes"}, []int{1}, nil},
		{"tenant-29", pair29, []string{"list_notes", "list_projects"}, []int{2}, []int{29}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			start := len(capture.snapshot())
			session := appMCPClient(t, server, tc.pair.AccessToken, nil)
			listed, err := session.ListTools(ctx, nil)
			if err != nil {
				t.Fatal(err)
			}
			gotTools := make([]string, 0, len(listed.Tools))
			for _, tool := range listed.Tools {
				gotTools = append(gotTools, tool.Name)
			}
			slices.Sort(gotTools)
			if !reflect.DeepEqual(gotTools, tc.wantTools) {
				t.Fatalf("tenant discovery: got %v want %v", gotTools, tc.wantTools)
			}
			if got := appMCPClientIDs(t, appMCPClientCall(ctx, t, session, "list_notes")); !reflect.DeepEqual(got, tc.wantNotes) {
				t.Fatalf("tenant note rows: got %v want %v", got, tc.wantNotes)
			}
			if tc.wantProjects != nil {
				if got := appMCPClientIDs(t, appMCPClientCall(ctx, t, session, "list_projects")); !reflect.DeepEqual(got, tc.wantProjects) {
					t.Fatalf("tenant project rows: got %v want %v", got, tc.wantProjects)
				}
			}
			requests := capture.snapshot()[start:]
			for _, request := range requests {
				if got := request.header.Get("Authorization"); got != "Bearer "+tc.pair.AccessToken {
					t.Fatalf("%s SDK request used a different grant identity", tc.name)
				}
			}
			assertAppMCPModernSDKWire(t, requests, session.InitializeResult().ProtocolVersion)
		})
	}
}
