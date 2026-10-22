//go:build !cli

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const externalRuntimeOpenAPI = `openapi: 3.0.3
info: {title: Items, version: '1'}
paths:
  /items/{id}:
    get:
      operationId: getItem
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
        - {name: q, in: query, required: false, schema: {type: string}}
        - {name: X-Trace, in: header, required: false, schema: {type: string}}
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: {type: object, additionalProperties: false, required: [name], properties: {name: {type: string}, internal: {type: string}, profile: {type: object, additionalProperties: false, properties: {name: {type: string}, internal: {type: string}}}, members: {type: array, items: {type: object, additionalProperties: false, properties: {name: {type: string}, internal: {type: string}}}}}}
  /search:
    post:
      operationId: searchItems
      requestBody:
        required: true
        content:
          application/json:
            schema: {type: object, additionalProperties: false, required: [term], properties: {term: {type: string}}}
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: {type: object, additionalProperties: false, required: [name], properties: {name: {type: string}, internal: {type: string}}}
  /items/{id}/remove:
    delete:
      operationId: removeItem
      parameters:
        - {name: id, in: path, required: true, schema: {type: integer}}
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: {type: object, additionalProperties: false, required: [name], properties: {name: {type: string}}}
`

const externalRuntimeManifest = `version: 1
connector: {id: fixture, name: Fixture, version: '1'}
contract_digest: ` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `
execution_digest: ` + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + `
connections:
  - name: items
    base_url: https://example.com/v1
    auth: {kind: bearer, env: ITEMS_API_KEY}
    openapi: openapi/items.yaml
  - name: keyed
    base_url: https://example.com
    auth: {kind: header, env: KEYED_API_KEY, header: X-Api-Key}
    openapi: openapi/items.yaml
tools:
  - name: get_item
    description: Read one item
    handler: {kind: external, connection: items, operation_id: getItem}
    input_schema:
      type: object
      additionalProperties: false
      required: [path]
      properties:
        path:
          type: object
          additionalProperties: false
          required: [id]
          properties:
            id: {type: integer}
        query:
          type: object
          additionalProperties: false
          properties:
            q: {type: string}
            debug: {type: string}
        header:
          type: object
          additionalProperties: false
          properties:
            X-Trace: {type: string}
            X-Other: {type: string}
    output_schema: {type: object, additionalProperties: false, required: [name], properties: {name: {type: string}, profile: {type: object, additionalProperties: false, properties: {name: {type: string}}}, members: {type: array, items: {type: object, additionalProperties: false, properties: {name: {type: string}}}}}}
    permissions: [rates:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [name, profile, members]}
    component: none
  - name: search_items
    description: Search items
    handler: {kind: external, connection: keyed, operation_id: searchItems}
    input_schema:
      type: object
      additionalProperties: false
      required: [body]
      properties:
        body:
          type: object
          additionalProperties: false
          required: [term]
          properties:
            term: {type: string}
    output_schema: {type: object, additionalProperties: false, required: [name], properties: {name: {type: string}}}
    permissions: [rates:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [name]}
    component: none
resources: []
`

type externalUpstream struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
	handler  http.HandlerFunc
	server   *httptest.Server
}

func (u *externalUpstream) hits() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.requests)
}
func (u *externalUpstream) last() *http.Request {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.requests[len(u.requests)-1]
}

// newExternalUpstream starts a local TLS server and points the outbound
// transport at it for the test only: every address dials the server and the
// certificate is trusted for example.com. The SSRF guard itself is untouched
// (TestAppMCPExternalDialRefusesPrivateAddress runs the real transport).
func newExternalUpstream(t *testing.T, handler http.HandlerFunc) *externalUpstream {
	t.Helper()
	u := &externalUpstream{handler: handler}
	u.server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		u.mu.Lock()
		u.requests = append(u.requests, r)
		body, _ := io.ReadAll(r.Body)
		u.bodies = append(u.bodies, string(body))
		u.mu.Unlock()
		u.handler(w, r)
	}))
	t.Cleanup(u.server.Close)
	pool := x509.NewCertPool()
	pool.AddCert(u.server.Certificate())
	previous := appMCPExternalTransport
	appMCPExternalTransport = func() *http.Transport {
		return &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, network, u.server.Listener.Addr().String())
			},
			TLSClientConfig:   &tls.Config{RootCAs: pool, ServerName: "example.com"},
			DisableKeepAlives: true,
		}
	}
	t.Cleanup(func() { appMCPExternalTransport = previous })
	return u
}

func externalJSONOK(body string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}
}

type externalFixture struct {
	app   *App
	uid   int64
	token string
}

func newExternalFixture(t *testing.T) *externalFixture {
	t.Helper()
	app, uid, _ := appMCPGrantFixture(t)
	writeTestFile(t, app.Dir, "openapi/items.yaml", externalRuntimeOpenAPI)
	writeTestFile(t, app.Dir, "mcp.yaml", externalRuntimeManifest)
	reviewAppMCPFixture(t, app.Dir)
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{"editor": {Scopes: "notes:read rates:read"}, "admin": {Scopes: "notes:read rates:read"}}}
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	app.MCP, app.Flows, app.sourceFiles = config.mcp, config.flows, config.sourceFiles
	pair, err := createAppMCPGrant(app, uid, "17", "client-fixture", grantFixtureResource, "rates:read", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return &externalFixture{app: app, uid: uid, token: pair.AccessToken}
}

func (f *externalFixture) call(t *testing.T, tool string, input map[string]any) (*appMCPReadResult, error) {
	t.Helper()
	return runAppMCPExternalRead(context.Background(), f.app, snapshotAppMCPGeneration(f.app), f.token, grantFixtureResource, tool, input)
}

func (f *externalFixture) connection(name string) *AppMCPConnection {
	for i := range f.app.MCP.Connections {
		if f.app.MCP.Connections[i].Name == name {
			return &f.app.MCP.Connections[i]
		}
	}
	return nil
}

func (f *externalFixture) setCredential(t *testing.T, connection, secret string) {
	t.Helper()
	if err := setAppMCPConnectionCredential(context.Background(), f.app, f.uid, f.connection(connection), secret); err != nil {
		t.Fatal(err)
	}
}

func externalErrorCode(t *testing.T, err error) string {
	t.Helper()
	failure, ok := err.(*appMCPResultError)
	if !ok {
		t.Fatalf("expected a connector result error, got %v", err)
	}
	return failure.Code
}

const externalSecret = "sk-live-never-echo-0123456789"

func TestAppMCPExternalReadHappyPath(t *testing.T) {
	f := newExternalFixture(t)
	f.setCredential(t, "items", externalSecret)
	upstream := newExternalUpstream(t, externalJSONOK(`{"name":"widget","internal":"not projected"}`))

	result, err := f.call(t, "get_item", map[string]any{
		"path": map[string]any{"id": json.Number("7")}, "query": map[string]any{"q": "a b"}, "header": map[string]any{"X-Trace": "t-1"},
	})
	if err != nil {
		t.Fatalf("external read: %v", err)
	}
	encoded, _ := json.Marshal(result)
	text := string(encoded)
	if !strings.Contains(text, `"name":"widget"`) || strings.Contains(text, "not projected") || strings.Contains(text, "source_revisions") || !strings.Contains(text, `"external_source"`) || strings.Contains(text, externalSecret) {
		t.Fatalf("unexpected envelope: %s", text)
	}
	request := upstream.last()
	if request.Method != "GET" || request.URL.Path != "/v1/items/7" || request.URL.Query().Get("q") != "a b" || request.Header.Get("X-Trace") != "t-1" || request.Header.Get("Authorization") != "Bearer "+externalSecret {
		t.Fatalf("unexpected upstream request: %s %s %v", request.Method, request.URL, request.Header)
	}
	for _, forbidden := range []string{"Cookie", "X-Forwarded-For", "Origin"} {
		if request.Header.Get(forbidden) != "" {
			t.Fatalf("%s reached the provider", forbidden)
		}
	}
}

func TestAppMCPExternalReadRecursivelyProjectsOutput(t *testing.T) {
	f := newExternalFixture(t)
	f.setCredential(t, "items", externalSecret)
	upstream := newExternalUpstream(t, externalJSONOK(`{"name":"widget","profile":{"name":"Ada","internal":"private","api_key":"secret"},"members":[{"name":"Grace","internal":"private","api_key":"secret"}]}`))

	generation := snapshotAppMCPGeneration(f.app)
	operation := generation.manifest.external["get_item"]
	operation.Output.Properties["profile"].AdditionalProperties = nil
	operation.Output.Properties["members"].Items.AdditionalProperties = nil
	result, err := runAppMCPExternalRead(context.Background(), f.app, generation, f.token, grantFixtureResource, "get_item", map[string]any{"path": map[string]any{"id": json.Number("7")}})
	if err != nil {
		t.Fatalf("external read (%s), hits=%d: %v", externalErrorCode(t, err), upstream.hits(), err)
	}
	encoded, _ := json.Marshal(result)
	text := string(encoded)
	if !strings.Contains(text, `"profile":{"name":"Ada"}`) || !strings.Contains(text, `"members":[{"name":"Grace"}]`) || strings.Contains(text, "api_key") || strings.Contains(text, "private") {
		t.Fatalf("unexpected projected result: %s", text)
	}
}

func TestAppMCPExternalBodyAndHeaderKeyAuth(t *testing.T) {
	f := newExternalFixture(t)
	f.setCredential(t, "keyed", externalSecret)
	upstream := newExternalUpstream(t, externalJSONOK(`{"name":"found"}`))
	if _, err := f.call(t, "search_items", map[string]any{"body": map[string]any{"term": "gizmo"}}); err != nil {
		t.Fatal(err)
	}
	request := upstream.last()
	if request.Method != "POST" || request.URL.Path != "/search" || request.Header.Get("X-Api-Key") != externalSecret || request.Header.Get("Authorization") != "" || request.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("unexpected upstream request: %s %s %v", request.Method, request.URL, request.Header)
	}
	if got := upstream.bodies[0]; got != `{"term":"gizmo"}` {
		t.Fatalf("body = %q", got)
	}
}

func TestAppMCPExternalDropsUndeclaredParameters(t *testing.T) {
	f := newExternalFixture(t)
	f.setCredential(t, "items", externalSecret)
	upstream := newExternalUpstream(t, externalJSONOK(`{"name":"widget"}`))
	// The tool schema admits debug and X-Other; the pinned operation declares neither.
	if _, err := f.call(t, "get_item", map[string]any{
		"path": map[string]any{"id": json.Number("7")}, "query": map[string]any{"q": "x", "debug": "1"}, "header": map[string]any{"X-Trace": "t", "X-Other": "leak"},
	}); err != nil {
		t.Fatal(err)
	}
	request := upstream.last()
	if request.URL.Query().Has("debug") || request.Header.Get("X-Other") != "" || request.URL.Query().Get("q") != "x" {
		t.Fatalf("undeclared parameters reached the provider: %s %v", request.URL, request.Header)
	}
}

func TestAppMCPExternalRefusesHeaderInjection(t *testing.T) {
	f := newExternalFixture(t)
	f.setCredential(t, "items", externalSecret)
	upstream := newExternalUpstream(t, externalJSONOK(`{"name":"widget"}`))
	for _, value := range []string{"a\r\nX-Evil: 1", "a\nb", "a\x00b"} {
		_, err := f.call(t, "get_item", map[string]any{"path": map[string]any{"id": json.Number("7")}, "header": map[string]any{"X-Trace": value}})
		if err == nil || externalErrorCode(t, err) != "invalid_input" {
			t.Fatalf("header value %q: %v", value, err)
		}
	}
	if upstream.hits() != 0 {
		t.Fatal("a refused request reached the provider")
	}
}

func TestAppMCPExternalRefusesRedirects(t *testing.T) {
	f := newExternalFixture(t)
	f.setCredential(t, "items", externalSecret)
	upstream := newExternalUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "https://other.example/v1/items/7", http.StatusFound)
	})
	_, err := f.call(t, "get_item", map[string]any{"path": map[string]any{"id": json.Number("7")}})
	if err == nil || externalErrorCode(t, err) != "unavailable_provider" {
		t.Fatalf("redirect not refused: %v", err)
	}
	if upstream.hits() != 1 {
		t.Fatalf("redirect was followed: %d hits", upstream.hits())
	}
}

func TestAppMCPExternalWriteToolIsRefusedWithClearError(t *testing.T) {
	source := strings.Replace(strings.Replace(externalRuntimeManifest, "effect: read", "effect: write", 1), "approval: none", "approval: first_party", 1)
	if _, err := parseAppMCPManifest([]byte(source)); err == nil || !strings.Contains(err.Error(), "external write tools are not enabled") {
		t.Fatalf("external write tool: %v", err)
	}
}

func TestAppMCPExternalReadToolCannotBindMutatingOperation(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "openapi/items.yaml", externalRuntimeOpenAPI)
	source := strings.Replace(externalRuntimeManifest, "operation_id: getItem", "operation_id: removeItem", 1)
	manifest, err := parseAppMCPManifest([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAppMCPDeclaredSources(dir, manifest); err == nil || !strings.Contains(err.Error(), "GET or POST") {
		t.Fatalf("a read tool bound a DELETE operation: %v", err)
	}
}

// The real transport dials through publicOnlyDialer: a provider that resolves to
// a loopback address is refused at connect time and never contacted.
func TestAppMCPExternalDialRefusesPrivateAddress(t *testing.T) {
	hits := 0
	server := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits++ }))
	defer server.Close()
	header := http.Header{"Accept": {"application/json"}}
	_, _, _, err := appMCPExternalDo(context.Background(), "GET", server.URL+"/v1/items/1", header, nil)
	if err == nil || externalErrorCode(t, err) != "unavailable_provider" || hits != 0 {
		t.Fatalf("private address reached: err=%v hits=%d", err, hits)
	}
}

func TestAppMCPExternalOversizedResponseIsIncomplete(t *testing.T) {
	f := newExternalFixture(t)
	f.setCredential(t, "items", externalSecret)
	newExternalUpstream(t, externalJSONOK(`{"name":"`+strings.Repeat("x", appMCPResultLimit+1)+`"}`))
	_, err := f.call(t, "get_item", map[string]any{"path": map[string]any{"id": json.Number("7")}})
	if err == nil || externalErrorCode(t, err) != "incomplete_result" {
		t.Fatalf("oversized response: %v", err)
	}
}

func TestAppMCPExternalResponseMustMatchDeclaredSchema(t *testing.T) {
	f := newExternalFixture(t)
	f.setCredential(t, "items", externalSecret)
	for name, body := range map[string]string{"wrong type": `{"name":3}`, "missing required": `{"internal":"x"}`, "not an object": `["x"]`, "trailing": `{"name":"a"} {"name":"b"}`} {
		newExternalUpstream(t, externalJSONOK(body))
		if _, err := f.call(t, "get_item", map[string]any{"path": map[string]any{"id": json.Number("7")}}); err == nil || externalErrorCode(t, err) != "incomplete_result" {
			t.Fatalf("%s: %v", name, err)
		}
	}
}

func TestAppMCPExternalMissingCredentialIsClearAndNothingIsSent(t *testing.T) {
	f := newExternalFixture(t)
	upstream := newExternalUpstream(t, externalJSONOK(`{"name":"widget"}`))
	_, err := f.call(t, "get_item", map[string]any{"path": map[string]any{"id": json.Number("7")}})
	if err == nil || externalErrorCode(t, err) != "denied" || !strings.Contains(err.Error(), `connection "items"`) || !strings.Contains(err.Error(), "/api/_mcp/connections/items/credential") {
		t.Fatalf("missing credential error: %v", err)
	}
	if upstream.hits() != 0 {
		t.Fatal("an unauthenticated request reached the provider")
	}
}

func TestAppMCPExternalProviderRejectionNeverEchoesCredential(t *testing.T) {
	f := newExternalFixture(t)
	f.setCredential(t, "items", externalSecret)
	newExternalUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "bad key "+r.Header.Get("Authorization"), http.StatusUnauthorized)
	})
	_, err := f.call(t, "get_item", map[string]any{"path": map[string]any{"id": json.Number("7")}})
	if err == nil || externalErrorCode(t, err) != "denied" || strings.Contains(err.Error(), externalSecret) {
		t.Fatalf("provider rejection: %v", err)
	}
	failure := appMCPSDKFailure(err)
	encoded, _ := json.Marshal(failure)
	if strings.Contains(string(encoded), externalSecret) {
		t.Fatal("credential echoed in the tool failure")
	}
}

func TestAppMCPExternalCredentialsAreSealedAndBound(t *testing.T) {
	f := newExternalFixture(t)
	f.setCredential(t, "items", externalSecret)
	var stored string
	if err := f.app.DB.QueryRow(`SELECT secret_ciphertext FROM _benmore_mcp_connection_credentials WHERE user_id=? AND connection='items'`, f.uid).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(stored, encPrefixV2) || strings.Contains(stored, externalSecret) {
		t.Fatalf("credential not sealed: %q", stored)
	}
	// The ciphertext authenticates only for its own user and connection.
	auditExec(t, f.app.DB, `INSERT INTO _benmore_users(id,username,email,password_hash) VALUES(900,'other','other@example.com','h')`)
	auditExec(t, f.app.DB, `UPDATE _benmore_mcp_connection_credentials SET user_id=900 WHERE user_id=?`, f.uid)
	if _, err := loadAppMCPConnectionSecret(context.Background(), f.app, 900, f.connection("items")); err == nil {
		t.Fatal("a credential moved to another user still opens")
	}
	auditExec(t, f.app.DB, `UPDATE _benmore_mcp_connection_credentials SET user_id=?, connection='keyed' WHERE user_id=900`, f.uid)
	if _, err := loadAppMCPConnectionSecret(context.Background(), f.app, f.uid, f.connection("keyed")); err == nil {
		t.Fatal("a credential moved to another connection still opens")
	}
	auditExec(t, f.app.DB, `UPDATE _benmore_mcp_connection_credentials SET connection='items'`)
	if got, err := loadAppMCPConnectionSecret(context.Background(), f.app, f.uid, f.connection("items")); err != nil || got != externalSecret {
		t.Fatalf("credential does not open in its own context: %q %v", got, err)
	}
}

func TestAppMCPExternalCredentialRoute(t *testing.T) {
	f := newExternalFixture(t)
	mux := http.NewServeMux()
	registerAppMCPConnectionRoutes(mux, f.app, grantFixtureResource)
	cookie := CreateSession(f.app.DB, f.uid, "delegate@example.com", "17", time.Hour)
	send := func(method, name, body string, configure func(*http.Request)) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, "https://fixture.example/api/_mcp/connections/"+name+"/credential", strings.NewReader(body))
		request.Header.Set("Content-Type", "application/json")
		configure(request)
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)
		return recorder
	}
	withSession := func(r *http.Request) { r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie}) }
	withCSRF := func(r *http.Request) { withSession(r); r.Header.Set("X-CSRF-Token", authMintCSRFToken("")) }
	put := `{"secret":"` + externalSecret + `"}`

	if got := send("PUT", "items", put, withSession); got.Code != 403 {
		t.Fatalf("missing CSRF accepted: %d", got.Code)
	}
	if got := send("PUT", "items", put, func(r *http.Request) { withCSRF(r); r.Header.Set("Authorization", "Bearer "+f.token) }); got.Code != 403 {
		t.Fatalf("connector bearer accepted: %d", got.Code)
	}
	if got := send("PUT", "items", put, func(r *http.Request) { r.Header.Set("X-CSRF-Token", authMintCSRFToken("")) }); got.Code != 403 {
		t.Fatalf("anonymous caller accepted: %d", got.Code)
	}
	if got := send("PUT", "nope", put, withCSRF); got.Code != 404 {
		t.Fatalf("unknown connection: %d", got.Code)
	}
	for _, bad := range []string{`{"secret":""}`, `{"secret":"a\r\nb"}`, `{"secret":"` + strings.Repeat("x", appMCPConnectionSecretLimit+1) + `"}`, `{"secret":"x"} {}`, `not json`} {
		if got := send("PUT", "items", bad, withCSRF); got.Code != 400 {
			t.Fatalf("bad secret %q accepted: %d", bad[:min(len(bad), 20)], got.Code)
		}
	}
	if got := send("PUT", "items", put, withCSRF); got.Code != 204 || got.Body.Len() != 0 {
		t.Fatalf("set: %d %q", got.Code, got.Body.String())
	}
	status := send("GET", "items", "", withSession)
	if status.Code != 200 || strings.TrimSpace(status.Body.String()) != `{"configured":true}` || strings.Contains(status.Body.String(), externalSecret) {
		t.Fatalf("status: %d %s", status.Code, status.Body.String())
	}
	if got, err := loadAppMCPConnectionSecret(context.Background(), f.app, f.uid, f.connection("items")); err != nil || got != externalSecret {
		t.Fatalf("stored credential: %q %v", got, err)
	}
	var audited string
	if err := f.app.DB.QueryRow(`SELECT COALESCE(old_values,'')||COALESCE(new_values,'') FROM _benmore_audit_log WHERE action='mcp_connection_credential_set'`).Scan(&audited); err != nil || strings.Contains(audited, externalSecret) {
		t.Fatalf("audit row missing or leaking: %q %v", audited, err)
	}
	if got := send("DELETE", "items", "", withCSRF); got.Code != 204 {
		t.Fatalf("clear: %d", got.Code)
	}
	if got := send("GET", "items", "", withSession); strings.TrimSpace(got.Body.String()) != `{"configured":false}` {
		t.Fatalf("status after clear: %s", got.Body.String())
	}
}

func TestAppMCPExternalRotationReseals(t *testing.T) {
	f := newExternalFixture(t)
	oldGlobal, oldEphemeral, oldBlind := appEncryptionKey, appEncryptionKeyEphemeral, appBlindIndexKey.Load()
	t.Cleanup(func() {
		appEncryptionKey, appEncryptionKeyEphemeral = oldGlobal, oldEphemeral
		appBlindIndexKey.Store(oldBlind)
	})
	f.setCredential(t, "items", externalSecret)
	if n, err := RotateEncryptionKey(f.app, "", true); err != nil || n != 1 {
		t.Fatalf("dry run = %d %v, want the credential planned", n, err)
	}
	newSource := strings.Repeat("c", 64)
	if n, err := RotateEncryptionKey(f.app, newSource, false); err != nil || n != 1 {
		t.Fatalf("rotation = %d %v", n, err)
	}
	if got, err := loadAppMCPConnectionSecret(context.Background(), f.app, f.uid, f.connection("items")); err != nil || got != externalSecret {
		t.Fatalf("credential after rotation: %q %v", got, err)
	}
	newKey, _ := cryptoDeriveAppKey(newSource)
	var stored string
	_ = f.app.DB.QueryRow(`SELECT secret_ciphertext FROM _benmore_mcp_connection_credentials`).Scan(&stored)
	if _, err := openAppMCPConnectionSecret(newKey, f.uid, "items", appMCPConnectionHostHash(f.connection("items").BaseURL), stored); err != nil {
		t.Fatalf("not sealed under the new key: %v", err)
	}
}

func TestAppMCPExternalRestoreCarriesLiveCredentials(t *testing.T) {
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	db := credentialFixtureDB(t, livePath)
	mcpGrantFixture(t, db)
	credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash, verified, created_at) VALUES
		(1, 'alice', 'alice@x.test', '$2a$12$a', 1, '2026-01-01 10:00:00'),
		(2, 'bob',   'bob@x.test',   '$2a$12$b', 1, '2026-01-02 10:00:00')`)
	credExec(t, db, `INSERT INTO _benmore_mcp_connection_credentials (user_id, connection, upstream_host, secret_ciphertext, updated_at) VALUES
		(1, 'items', 'h', 'enc:snapshot-alice', 1), (2, 'items', 'h', 'enc:snapshot-bob', 1)`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	// After the snapshot: bob cleared his credential, alice rotated hers.
	credExec(t, db, `DELETE FROM _benmore_mcp_connection_credentials WHERE user_id = 2`)
	credExec(t, db, `UPDATE _benmore_mcp_connection_credentials SET secret_ciphertext = 'enc:live-alice' WHERE user_id = 1`)
	db.Close()
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatal(err)
	}
	got := openRO(t, livePath)
	defer got.Close()
	if credString(t, got, `SELECT secret_ciphertext FROM _benmore_mcp_connection_credentials WHERE user_id = 1`) != "enc:live-alice" {
		t.Fatal("the live credential was not carried forward")
	}
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_mcp_connection_credentials WHERE user_id = 2`); n != 0 {
		t.Fatal("a credential cleared since the snapshot came back")
	}
}

func TestAppMCPExternalRestoreDropsCredentialsWithoutLiveState(t *testing.T) {
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")
	dir := t.TempDir()
	livePath := filepath.Join(dir, "data.db")
	// A live database without connector tables knows of no credential.
	live := credentialFixtureDB(t, livePath)
	credExec(t, live, `INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (1, 'alice', 'alice@x.test', '$2a$12$a')`)
	db := credentialFixtureDB(t, filepath.Join(dir, "source.db"))
	mcpGrantFixture(t, db)
	credExec(t, db, `INSERT INTO _benmore_users (id, username, email, password_hash) VALUES (1, 'alice', 'alice@x.test', '$2a$12$a')`)
	credExec(t, db, `INSERT INTO _benmore_mcp_connection_credentials (user_id, connection, upstream_host, secret_ciphertext, updated_at) VALUES (1, 'items', 'h', 'enc:snapshot-alice', 1)`)
	snapshot := filepath.Join(dir, "snapshot.db")
	snapshotTo(t, db, snapshot)
	db.Close()
	live.Close()
	if err := restoreDatabase(dir, snapshot); err != nil {
		t.Fatal(err)
	}
	got := openRO(t, livePath)
	defer got.Close()
	if n := credCount(t, got, `SELECT count(*) FROM _benmore_mcp_connection_credentials`); n != 0 {
		t.Fatalf("%d snapshot credentials survived with no live state", n)
	}
}

// Repointing a connection to another host makes the stored credentials unusable:
// the host is bound into the ciphertext and the row, so users must re-enter them.
func TestAppMCPExternalCredentialIsBoundToUpstreamHost(t *testing.T) {
	f := newExternalFixture(t)
	f.setCredential(t, "items", externalSecret)
	upstream := newExternalUpstream(t, externalJSONOK(`{"name":"widget"}`))
	moved := *f.connection("items")
	moved.BaseURL = "https://other.example.net/v1"
	if _, err := loadAppMCPConnectionSecret(context.Background(), f.app, f.uid, &moved); err != errAppMCPConnectionHost {
		t.Fatalf("a credential opened for another host: %v", err)
	}
	if ok, err := hasAppMCPConnectionCredential(context.Background(), f.app, f.uid, &moved); err != nil || ok {
		t.Fatalf("a credential stored for another host reads as configured: %v %v", ok, err)
	}
	// A path-only change keeps the host and the credential.
	same := *f.connection("items")
	same.BaseURL = "https://example.com/v2"
	if got, err := loadAppMCPConnectionSecret(context.Background(), f.app, f.uid, &same); err != nil || got != externalSecret {
		t.Fatalf("same-host credential: %q %v", got, err)
	}
	// Editing the stored host column to match is not enough: the ciphertext binds the old host.
	auditExec(t, f.app.DB, `UPDATE _benmore_mcp_connection_credentials SET upstream_host=?`, appMCPConnectionHostHash(moved.BaseURL))
	if _, err := loadAppMCPConnectionSecret(context.Background(), f.app, f.uid, &moved); err == nil || err == errAppMCPConnectionHost {
		t.Fatalf("a rewritten host column unlocked the credential: %v", err)
	}
	// Through the tool: a credential stored for another host refuses with a re-enter message and sends nothing.
	auditExec(t, f.app.DB, `UPDATE _benmore_mcp_connection_credentials SET upstream_host=?`, appMCPConnectionHostHash(moved.BaseURL))
	_, err := f.call(t, "get_item", map[string]any{"path": map[string]any{"id": json.Number("7")}})
	if err == nil || externalErrorCode(t, err) != "denied" || !strings.Contains(err.Error(), "different upstream host") || upstream.hits() != 0 {
		t.Fatalf("repointed connection: %v hits=%d", err, upstream.hits())
	}
}

func TestAppMCPExternalRefusesSeparatorsInPathValues(t *testing.T) {
	no := false
	text := &AppMCPSchema{Type: "object", AdditionalProperties: &no, Required: []string{"id"}, Properties: map[string]*AppMCPSchema{"id": {Type: "string"}}}
	op := &appMCPExternalOperation{Method: "GET", Path: "/items/{id}", Input: &AppMCPSchema{Type: "object", AdditionalProperties: &no, Required: []string{"path"}, Properties: map[string]*AppMCPSchema{"path": text}}}
	base, _ := url.Parse("https://example.com/v1")
	connection := &AppMCPConnection{Name: "items", BaseURL: "https://example.com/v1", Auth: AppMCPConnectionAuth{Kind: "bearer"}}
	for _, value := range []string{"a/b", `a\b`, "a%2Fb", "%2e%2e", "..", ".", ""} {
		if _, _, _, err := buildAppMCPExternalRequest(base, connection, op, map[string]any{"path": map[string]any{"id": value}}, externalSecret); err == nil || externalErrorCode(t, err) != "invalid_input" {
			t.Fatalf("path value %q: %v", value, err)
		}
	}
	rawURL, _, _, err := buildAppMCPExternalRequest(base, connection, op, map[string]any{"path": map[string]any{"id": "a b"}}, externalSecret)
	if err != nil || rawURL != "https://example.com/v1/items/a%20b" {
		t.Fatalf("plain value: %q %v", rawURL, err)
	}
}

func TestAppMCPExternalRotationLogsDroppedCredentials(t *testing.T) {
	f := newExternalFixture(t)
	oldGlobal, oldEphemeral, oldBlind := appEncryptionKey, appEncryptionKeyEphemeral, appBlindIndexKey.Load()
	t.Cleanup(func() {
		appEncryptionKey, appEncryptionKeyEphemeral = oldGlobal, oldEphemeral
		appBlindIndexKey.Store(oldBlind)
	})
	f.setCredential(t, "items", externalSecret)
	auditExec(t, f.app.DB, `INSERT INTO _benmore_users(id,username,email,password_hash) VALUES(901,'broken','broken@example.com','h')`)
	auditExec(t, f.app.DB, `INSERT INTO _benmore_mcp_connection_credentials(user_id,connection,upstream_host,secret_ciphertext,updated_at) VALUES(901,'items','h','enc:v2:00:00',1)`)
	var logged strings.Builder
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	if _, err := RotateEncryptionKey(f.app, strings.Repeat("d", 64), false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(logged.String(), "ERROR encryption-rotate: deleted 1 connection credential(s)") {
		t.Fatalf("dropped credentials were not logged: %s", logged.String())
	}
	if n := credCount(t, f.app.DB, `SELECT count(*) FROM _benmore_mcp_connection_credentials`); n != 1 {
		t.Fatalf("%d credential rows after rotation, want only the valid one", n)
	}
}

// A reviewed OpenAPI read operation may not map tool input to a
// method-override header: the upstream would run another method than the
// GET or POST the review approved.
func TestAppMCPExternalRefusesMethodOverrideHeaderParameters(t *testing.T) {
	m := &AppMCPManifest{}
	object := &AppMCPSchema{Type: "object"}
	for _, name := range []string{"X-HTTP-Method-Override", "x-http-method", "X-Method-Override"} {
		c := appMCPOpenAPICandidate{Method: "GET", Path: "/items", OutputSchema: object, InputSchema: &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{
			"header": {Type: "object", Properties: map[string]*AppMCPSchema{name: {Type: "string"}}},
		}}}
		if _, err := newAppMCPExternalOperation(m, "crm", c); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Errorf("%s: header parameter accepted (err=%v)", name, err)
		}
	}
	c := appMCPOpenAPICandidate{Method: "GET", Path: "/items", OutputSchema: object, InputSchema: &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{
		"header": {Type: "object", Properties: map[string]*AppMCPSchema{"X-Request-Id": {Type: "string"}}},
	}}}
	if _, err := newAppMCPExternalOperation(m, "crm", c); err != nil {
		t.Fatalf("ordinary header parameter refused: %v", err)
	}
}
