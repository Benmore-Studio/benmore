//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
)

const resourceWidgetSource = `import { App } from "@modelcontextprotocol/ext-apps";
import { label } from "./card_lib";
const app = new App({ name: "card", version: "1" });
document.body.dataset.marker = "CARD_MARKER_7f3a:" + label;
app.ontoolresult = (result) => { document.getElementById("root")!.textContent = JSON.stringify(result.structuredContent); };
void app.connect();
`

// appMCPResourceFixture is a read tool bound to the reviewed card component.
func appMCPResourceFixture(t *testing.T, widget string) *App {
	t.Helper()
	app, _, _ := appMCPGrantFixture(t)
	writeTestFile(t, app.Dir, "static/widgets/card.tsx", widget)
	writeTestFile(t, app.Dir, "static/widgets/card_lib.ts", "export const label = 'one';\n")
	appMCPResourceReload(t, app)
	return app
}

func appMCPResourceReload(t *testing.T, app *App) {
	t.Helper()
	source := strings.Replace(componentManifest(componentResourceFixture), "table.list", "table.read", 1)
	source = strings.Replace(source, "input_schema: {type: object, additionalProperties: false}", "input_schema: {type: object, additionalProperties: false, required: [id], properties: {id: {type: integer}}}", 1)
	source = strings.Replace(source, "output_schema:\n      type: object", "output_schema:\n      type: object\n      required: [id]", 1)
	writeTestFile(t, app.Dir, "mcp.yaml", source)
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP, app.sourceFiles = config.mcp, config.sourceFiles
}

type resourceSession struct {
	*sdk.ClientSession
	ctx    context.Context
	origin string
}

func appMCPResourceConnect(t *testing.T, app *App, email string) resourceSession {
	t.Helper()
	var resource string
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { serveAppMCP(w, r, app, resource) }))
	t.Cleanup(server.Close)
	resource = server.URL + "/api/_mcp"
	sid := createCrudScopeSession(t, app, email, "editor", "17", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	auditExec(t, app.DB, "INSERT INTO members(org_id,email) VALUES ('17',?)", email)
	auditExec(t, app.DB, "INSERT OR IGNORE INTO notes(id,user_id,title) VALUES (1,?,'ROW_SECRET_91')", uid)
	pair, err := createAppMCPGrant(app, uid, "17", "client-fixture", resource, "notes:read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	httpClient := server.Client()
	httpClient.Transport = appMCPBearerRoundTripper{base: httpClient.Transport, token: pair.AccessToken}
	client := sdk.NewClient(&sdk.Implementation{Name: "fixture-client", Version: "1"}, nil)
	session, err := client.Connect(ctx, &sdk.StreamableClientTransport{Endpoint: resource, HTTPClient: httpClient, DisableStandaloneSSE: true}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return resourceSession{ClientSession: session, ctx: ctx, origin: server.URL}
}

func readWidget(t *testing.T, s resourceSession) (*sdk.Resource, string) {
	t.Helper()
	listed, err := s.ListResources(s.ctx, nil)
	if err != nil || len(listed.Resources) != 1 {
		t.Fatalf("resources/list: %+v %v", listed, err)
	}
	read, err := s.ReadResource(s.ctx, &sdk.ReadResourceParams{URI: listed.Resources[0].URI})
	if err != nil || len(read.Contents) != 1 {
		t.Fatalf("resources/read: %+v %v", read, err)
	}
	return listed.Resources[0], read.Contents[0].Text
}

func TestAppMCPResourcesServeReviewedComponent(t *testing.T) {
	app := appMCPResourceFixture(t, resourceWidgetSource)
	s := appMCPResourceConnect(t, app, "first@example.com")
	if s.InitializeResult().Capabilities.Resources == nil {
		t.Fatal("a manifest with components must advertise resources")
	}
	resource, page := readWidget(t, s)
	_, bundleSHA := mcpAppsBundle()
	if !strings.HasPrefix(resource.URI, "ui://notes/card@") || resource.MIMEType != "text/html;profile=mcp-app" {
		t.Fatalf("resource: %+v", resource)
	}
	for _, want := range []string{bundleSHA, "CARD_MARKER_7f3a", `"one"`, "Content-Security-Policy", "default-src 'none'", "connect-src 'none'", "script-src 'sha256-", `"tools":["list_notes"]`, "benmore: tool is not permitted"} {
		if !strings.Contains(page, want) {
			t.Errorf("page lacks %q", want)
		}
	}
	for _, banned := range []string{"sourceMappingURL", "localStorage", "sessionStorage", "first@example.com", "ROW_SECRET_91"} {
		if strings.Contains(page, banned) {
			t.Errorf("page must not contain %q", banned)
		}
	}
	// The URI hash is the closure hash the page itself reports.
	if !strings.Contains(page, `content="sha256-`+strings.SplitN(resource.URI, "@", 2)[1]+`"`) {
		t.Error("URI is not the closure hash")
	}

	tools, err := s.ListTools(s.ctx, nil)
	if err != nil || len(tools.Tools) != 1 {
		t.Fatalf("tools: %+v %v", tools, err)
	}
	ui, _ := tools.Tools[0].Meta["ui"].(map[string]any)
	if ui["resourceUri"] != resource.URI || tools.Tools[0].Meta["ui/resourceUri"] != resource.URI {
		t.Fatalf("tool _meta does not carry the URI: %v", tools.Tools[0].Meta)
	}
	if visibility, _ := json.Marshal(ui["visibility"]); string(visibility) != `["model","app"]` {
		t.Fatalf("visibility: %s", visibility)
	}

	// The text fallback and a token-free deep link stay on the ordinary call.
	result, err := s.CallTool(s.ctx, &sdk.CallToolParams{Name: "list_notes", Arguments: map[string]any{"id": 1}})
	if err != nil || result.IsError || len(result.Content) != 1 {
		t.Fatalf("call: %+v %v", result, err)
	}
	if text, ok := result.Content[0].(*sdk.TextContent); !ok || !strings.Contains(text.Text, `"id":1`) {
		t.Fatalf("text fallback: %+v", result.Content)
	}
	if result.Meta["deep_link"] != s.origin+"/notes/1" {
		t.Fatalf("deep link: %v", result.Meta)
	}
	if _, err := s.ReadResource(s.ctx, &sdk.ReadResourceParams{URI: "ui://notes/card@" + strings.Repeat("0", 64)}); err == nil {
		t.Fatal("a URI of another closure was served")
	}
}

func TestAppMCPResourcesAbsentWithoutComponents(t *testing.T) {
	app, _, _ := appMCPResultFixture(t, true)
	s := appMCPResourceConnect(t, app, "first@example.com")
	if s.InitializeResult().Capabilities.Resources != nil {
		t.Fatalf("resources advertised without components: %+v", s.InitializeResult().Capabilities)
	}
	if listed, err := s.ListResources(s.ctx, nil); err == nil && len(listed.Resources) != 0 {
		t.Fatalf("resources/list answered without components: %+v", listed)
	}
	tools, err := s.ListTools(s.ctx, nil)
	if err != nil || len(tools.Tools) != 1 || tools.Tools[0].Meta != nil {
		t.Fatalf("a plain tool gained _meta: %+v %v", tools, err)
	}
}

func TestAppMCPResourcesAreIdenticalForEveryCaller(t *testing.T) {
	app := appMCPResourceFixture(t, resourceWidgetSource)
	one, two := appMCPResourceConnect(t, app, "first@example.com"), appMCPResourceConnect(t, app, "second@example.com")
	first, firstPage := readWidget(t, one)
	second, secondPage := readWidget(t, two)
	if first.URI != second.URI || firstPage != secondPage {
		t.Fatal("two callers received different resources")
	}
}

func TestAppMCPBrokenComponentIsNotPublishedAndToolStillWorks(t *testing.T) {
	app := appMCPResourceFixture(t, "export const broken = (;\n")
	s := appMCPResourceConnect(t, app, "first@example.com")
	listed, err := s.ListResources(s.ctx, nil)
	if err != nil || len(listed.Resources) != 0 {
		t.Fatalf("a broken component was published: %+v %v", listed, err)
	}
	tools, err := s.ListTools(s.ctx, nil)
	if err != nil || len(tools.Tools) != 1 {
		t.Fatalf("tools: %+v %v", tools, err)
	}
	if ui, _ := tools.Tools[0].Meta["ui"].(map[string]any); ui["resourceUri"] != nil {
		t.Fatalf("an unpublished component is linked: %v", tools.Tools[0].Meta)
	}
	result, err := s.CallTool(s.ctx, &sdk.CallToolParams{Name: "list_notes", Arguments: map[string]any{"id": 1}})
	if err != nil || result.IsError || len(result.Content) != 1 || result.Meta["deep_link"] != s.origin+"/notes/1" {
		t.Fatalf("text fallback or deep link lost: %+v %v", result, err)
	}
}

func TestAppMCPResourceClosureChangeGivesNewHash(t *testing.T) {
	app := appMCPResourceFixture(t, resourceWidgetSource)
	uri := func() string {
		t.Helper()
		widgets := appMCPGenerationWidgets(context.Background(), snapshotAppMCPGeneration(app))
		widget := widgets["ui://notes/card"]
		if widget == nil {
			t.Fatal("component not published")
		}
		return widget.URI
	}
	before := uri()
	appMCPResourceReload(t, app) // same sources: the same immutable resource
	if again := uri(); again != before {
		t.Fatalf("unchanged closure changed URI: %s != %s", again, before)
	}
	writeTestFile(t, app.Dir, "static/widgets/card_lib.ts", "export const label = 'two';\n") // an imported file, not the entrypoint
	appMCPResourceReload(t, app)
	if after := uri(); after == before {
		t.Fatal("an imported file changed but the resource hash did not")
	}
}

func TestAppMCPResourcesFollowToolGrantRules(t *testing.T) {
	app := appMCPResourceFixture(t, resourceWidgetSource)
	s := appMCPResourceConnect(t, app, "first@example.com")
	resource, _ := readWidget(t, s)
	// The caller loses access to the table behind the only bound tool.
	app.Access.rules["notes"] = map[AccessOp]string{OpRead: "admin"}
	listed, err := s.ListResources(s.ctx, nil)
	if err != nil || len(listed.Resources) != 0 {
		t.Fatalf("an unauthorized caller listed resources: %+v %v", listed, err)
	}
	if _, err := s.ReadResource(s.ctx, &sdk.ReadResourceParams{URI: resource.URI}); err == nil {
		t.Fatal("an unauthorized caller read a resource")
	}
	// A revoked grant gets nothing, and a missing token is a 401.
	auditExec(t, app.DB, "UPDATE _benmore_mcp_grants SET revoked=1")
	if _, err := s.ListResources(s.ctx, nil); err == nil {
		t.Fatal("a revoked grant listed resources")
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest("POST", grantFixtureResource, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"resources/list"}`))
	r.Header.Set("Content-Type", "application/json")
	serveAppMCP(w, r, app, grantFixtureResource)
	if w.Code != 401 {
		t.Fatalf("anonymous resources/list: %d", w.Code)
	}
}

func TestAppMCPResourceDiscoveryIsPrivate(t *testing.T) {
	app := appMCPResourceFixture(t, resourceWidgetSource)
	uid := GetSessionFromDB(app.DB, createCrudScopeSession(t, app, "raw@example.com", "editor", "17", "")).UserID
	auditExec(t, app.DB, "INSERT INTO members(org_id,email) VALUES ('17','raw@example.com')")
	pair := fixtureGrant(t, app, uid, time.Now())
	modern := "2026-07-28"
	call := func(method string, params map[string]any) string {
		params["_meta"] = map[string]any{"io.modelcontextprotocol/protocolVersion": modern, "io.modelcontextprotocol/clientInfo": map[string]any{"name": "fixture", "version": "1"}, "io.modelcontextprotocol/clientCapabilities": map[string]any{}}
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": params})
		r := httptest.NewRequest("POST", grantFixtureResource, strings.NewReader(string(body)))
		r.Header.Set("Mcp-Method", method)
		if uri, ok := params["uri"].(string); ok {
			r.Header.Set("Mcp-Name", uri)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Accept", "application/json, text/event-stream")
		r.Header.Set("Mcp-Protocol-Version", modern)
		r.Header.Set("Authorization", "Bearer "+pair.AccessToken)
		w := httptest.NewRecorder()
		serveAppMCP(w, r, app, grantFixtureResource)
		if w.Code != 200 {
			t.Fatalf("%s: %d %s", method, w.Code, w.Body.String())
		}
		return w.Body.String()
	}
	listed := call("resources/list", map[string]any{})
	if !strings.Contains(listed, `"cacheScope":"private"`) || strings.Contains(listed, `"cacheScope":"public"`) {
		t.Fatalf("resources/list is cacheable: %s", listed)
	}
	var envelope struct {
		Result struct {
			Resources []struct {
				URI string `json:"uri"`
			} `json:"resources"`
		} `json:"result"`
	}
	if json.Unmarshal([]byte(listed), &envelope) != nil || len(envelope.Result.Resources) != 1 {
		t.Fatalf("list: %s", listed)
	}
	if read := call("resources/read", map[string]any{"uri": envelope.Result.Resources[0].URI}); !strings.Contains(read, `"cacheScope":"private"`) || strings.Contains(read, `"cacheScope":"public"`) {
		t.Fatalf("resources/read is cacheable by a shared cache: %.300s", read)
	}
}

func TestCompileWidgetBundleContainmentAndShape(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "secret.json", `{"key":"outside-secret-value"}`)
	writeTestFile(t, dir, "static/ok.ts", "import { App } from '@modelcontextprotocol/ext-apps';\nexport const app = new App({name:'x',version:'1'});\ndocument.title = 'a';\n")
	writeTestFile(t, dir, "static/term.ts", "document.title = 'a</script><!--b';\n")
	writeTestFile(t, dir, "static/escape.ts", "import secret from '../secret.json';\ndocument.title = JSON.stringify(secret);\n")
	writeTestFile(t, dir, "static/external.ts", "import 'bm';\n")
	writeTestFile(t, dir, "static/css.ts", "import './x.css';\n")
	writeTestFile(t, dir, "static/x.css", "body{}")
	static := filepath.Join(dir, "static")
	body, inputs, err := compileWidgetBundle(filepath.Join(static, "ok.ts"), static)
	if err != nil || len(inputs) != 1 || filepath.Base(inputs[0]) != "ok.ts" {
		t.Fatalf("ok bundle: %v %v", inputs, err)
	}
	if strings.Contains(string(body), "sourceMappingURL") || strings.Contains(strings.ToLower(string(body)), "</script") {
		t.Fatal("bundle carries a source map or a script terminator")
	}
	for _, name := range []string{"escape.ts", "external.ts", "css.ts", "term.ts"} {
		body, _, err := compileWidgetBundle(filepath.Join(static, name), static)
		if err == nil || strings.Contains(err.Error(), "outside-secret-value") || strings.Contains(string(body), "outside-secret-value") {
			t.Errorf("%s: err=%v", name, err)
		}
	}
	if _, _, err := compileWidgetBundle(filepath.Join(static, "escape.ts"), static); err == nil || !strings.Contains(err.Error(), "widget build failed") {
		t.Fatalf("an import outside static/ was not refused: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, "secret.json")); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPDeepLinkUsesDeclaredFieldsOnly(t *testing.T) {
	manifest := mustParseManifest(t, componentManifest(strings.Replace(componentResourceFixture, "deep_link: /notes/{id}", "deep_link: /notes/{id}?title={title}", 1)))
	tool := &manifest.Tools[0]
	for name, tc := range map[string]struct {
		data any
		want string
	}{
		"integer and escaped string": {map[string]any{"id": 7, "title": "a b/c&d"}, "https://app.example/notes/7?title=a+b%2Fc%26d"},
		"wrong type":                 {map[string]any{"id": "7", "title": "x"}, ""},
		"missing field":              {map[string]any{"id": 7}, ""},
		"undeclared extra is unused": {map[string]any{"id": 7, "title": "x", "token": "secret"}, "https://app.example/notes/7?title=x"},
		"list data":                  {[]any{map[string]any{"id": 7}}, ""},
	} {
		if got := appMCPDeepLink(manifest, tool, tc.data, "https://app.example"); got != tc.want {
			t.Errorf("%s: %q want %q", name, got, tc.want)
		}
	}
	plain := mustParseManifest(t, componentManifest(strings.Replace(componentResourceFixture, "deep_link: /notes/{id}", "deep_link: /notes/{id}/{title}", 1)))
	if got := appMCPDeepLink(plain, &plain.Tools[0], map[string]any{"id": 1, "title": ".."}, "https://app.example"); got != "" {
		t.Errorf("dot segment value: %q", got)
	}
}

// The widget build reads captured files outside static/ too (a root
// tsconfig.json's extends target, package.json files on the resolver path),
// so a change to one must not be answered from the cache with the old build.
func TestAppMCPWidgetCacheCoversConfigurationOutsideStatic(t *testing.T) {
	app := appMCPResourceFixture(t, `import { App } from "@modelcontextprotocol/ext-apps";
import { label } from "@pick";
new App({ name: "card", version: "1" });
document.body.dataset.marker = label;
`)
	writeTestFile(t, app.Dir, "static/widgets/a.ts", "export const label = 'PICKED_' + 'ALPHA';\n")
	writeTestFile(t, app.Dir, "static/widgets/b.ts", "export const label = 'PICKED_' + 'BRAVO';\n")
	writeTestFile(t, app.Dir, "tsconfig.json", `{"extends": "./config/tsconfig.base.json"}`)
	page := func(target string) string {
		t.Helper()
		writeTestFile(t, app.Dir, "config/tsconfig.base.json", `{"compilerOptions":{"paths":{"@pick":["../static/widgets/`+target+`"]}}}`)
		appMCPResourceReload(t, app)
		widget := appMCPGenerationWidgets(context.Background(), snapshotAppMCPGeneration(app))["ui://notes/card"]
		if widget == nil {
			t.Fatal("component not published")
		}
		return widget.HTML
	}
	if first := page("a.ts"); !strings.Contains(first, "PICKED_ALPHA") {
		t.Fatalf("first build lacks its alias target: %.200s", first)
	}
	if second := page("b.ts"); !strings.Contains(second, "PICKED_BRAVO") || strings.Contains(second, "PICKED_ALPHA") {
		t.Fatal("a changed tsconfig extends target outside static/ was answered with the cached build")
	}
}

// esbuild leaves http(s):// imports external on its own; a component page is
// one self-contained module, so a remote import (static or dynamic) refuses
// the build instead of publishing code the closure hash does not cover.
func TestCompileWidgetBundleRefusesRemoteImports(t *testing.T) {
	dir := t.TempDir()
	static := filepath.Join(dir, "static")
	for name, source := range map[string]string{
		"static.ts":   "import 'https://cdn.example/x.js';\ndocument.title = 'a';\n",
		"named.ts":    "import { y } from 'http://cdn.example/y.js';\ndocument.title = y;\n",
		"dynamic.ts":  "void import('https://cdn.example/z.js');\n",
		"reexport.ts": "export * from 'https://cdn.example/w.js';\n",
	} {
		writeTestFile(t, dir, "static/"+name, source)
		if body, _, err := compileWidgetBundle(filepath.Join(static, name), static); err == nil {
			t.Errorf("%s: a remote import was published: %s", name, body)
		}
	}
}

// With components declared, a widget may call (through the host) only tools a
// component permits or binds. MCP Apps hosts treat a tool without
// _meta.ui.visibility as ["model","app"], so the built-in tools (command
// prepare, _commit, artifact.export) must say "model" explicitly; _status,
// which a widget may poll, keeps "app".
func TestAppMCPBuiltInToolsAreHiddenFromWidgets(t *testing.T) {
	app, _, actorID := newUnenrolledCommandProviderTaskFixtureWithManifest(t, hookTaskFlow, "", func(m *AppMCPManifest, dir string) {
		writeTestFile(t, dir, "static/widgets/status.tsx", "import { App } from \"@modelcontextprotocol/ext-apps\";\nvoid new App({ name: \"status\", version: \"1\" }).connect();\n")
		m.Resources = append(m.Resources, AppMCPResource{Name: "status_card", URI: "ui://tasks/status", MIMEType: "text/html", Component: "status",
			Entrypoint: "static/widgets/status.tsx", SchemaVersion: 1, DataSchema: &AppMCPSchema{Type: "object", AdditionalProperties: commandBoolPtr(false)}})
	})
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
	server := httptest.NewTLSServer(mux)
	t.Cleanup(server.Close)
	resource := server.URL + "/api/_mcp"
	registerAppMCPTransport(mux, app, resource)
	pair, err := createAppMCPNativeGrantFor(context.Background(), app, actorID, "17", "client-widget", resource, "complete_item", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client := appMCPClient(t, server, pair.AccessToken, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	listed, err := client.ListTools(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{"complete_item": `["model"]`, appMCPCommitTool: `["model"]`, mcpArtifactExportTool: `["model"]`, appMCPStatusTool: `["model","app"]`}
	for _, tool := range listed.Tools {
		ui, _ := tool.Meta["ui"].(map[string]any)
		got, _ := json.Marshal(ui["visibility"])
		if expected, ok := want[tool.Name]; ok {
			delete(want, tool.Name)
			if string(got) != expected {
				t.Errorf("%s visibility = %s, want %s", tool.Name, got, expected)
			}
		} else if ui["visibility"] == nil {
			t.Errorf("%s carries no visibility while components are declared", tool.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("tools missing from the inventory: %v", want)
	}
}
