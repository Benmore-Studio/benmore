//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// publicIPBaseURL is a literal public address: isPrivateURL resolves hostnames
// and fails closed offline, so tests that need a "public" answer use a literal.
const publicIPBaseURL = "https://93.184.216.34/v1"

func TestAppMCPFlowInputContract(t *testing.T) {
	flow := &Flow{Name: "lookup", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/lookup/:id", Inputs: map[string]FlowInput{
		"q":     {Type: "text", Required: true},
		"limit": {Type: "number"},
		"kind":  {Type: "enum", Values: []string{"a", "b"}},
		"flag":  {Type: "bool"},
	}}}
	closed := false
	schema := func(required []string, props map[string]*AppMCPSchema) AppMCPTool {
		return AppMCPTool{Name: "lookup", InputSchema: &AppMCPSchema{Type: "object", AdditionalProperties: &closed, Required: required, Properties: props}}
	}
	good := map[string]*AppMCPSchema{"id": {Type: "integer"}, "q": {Type: "string"}, "limit": {Type: "integer"}, "kind": {Type: "string", Enum: []any{"a"}}, "flag": {Type: "boolean"}}
	if err := validateAppMCPFlowInputContract(schema([]string{"id", "q"}, good), flow); err != nil {
		t.Fatalf("matching contract refused: %v", err)
	}
	with := func(name string, property *AppMCPSchema) map[string]*AppMCPSchema {
		out := map[string]*AppMCPSchema{}
		for k, v := range good {
			out[k] = v
		}
		if property == nil {
			delete(out, name)
		} else {
			out[name] = property
		}
		return out
	}
	for name, tc := range map[string]struct {
		required []string
		props    map[string]*AppMCPSchema
		want     string
	}{
		"property the flow does not accept": {[]string{"id", "q"}, with("extra", &AppMCPSchema{Type: "string"}), "not accepted by flow"},
		"required flow input omitted":       {[]string{"id"}, good, `omits required flow input "q"`},
		"required flow input absent":        {[]string{"id"}, with("q", nil), `omits required flow input "q"`},
		"path parameter omitted":            {[]string{"q"}, good, `omits flow path parameter "id"`},
		"string vs number":                  {[]string{"id", "q"}, with("limit", &AppMCPSchema{Type: "string"}), "incompatible"},
		"number vs text":                    {[]string{"id", "q"}, with("q", &AppMCPSchema{Type: "number"}), "incompatible"},
		"boolean vs bool":                   {[]string{"id", "q"}, with("flag", &AppMCPSchema{Type: "string"}), "incompatible"},
		"enum wider than flow":              {[]string{"id", "q"}, with("kind", &AppMCPSchema{Type: "string", Enum: []any{"a", "z"}}), "enum value the flow rejects"},
		"identity key advertised":           {[]string{"id", "q"}, with("user_id", &AppMCPSchema{Type: "integer"}), "server-owned identity key"},
		"object path parameter":             {[]string{"id", "q"}, with("id", &AppMCPSchema{Type: "object", AdditionalProperties: &closed}), "incompatible"},
	} {
		err := validateAppMCPFlowInputContract(schema(tc.required, tc.props), flow)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: err=%v want %q", name, err, tc.want)
		}
	}
}

// The check runs from `benmore mcp check` and the checked loader alike.
func TestAppMCPFlowInputContractIsEnforcedByCheckAndLoad(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	source := strings.Replace(appMCPManifestFixture(), "handler: {kind: native, operation: table.list, table: notes}", "handler: {kind: native, operation: flow.call, flow: read_notes}", 1)
	source = strings.Replace(source, "input_schema: {type: object, additionalProperties: false}", "input_schema: {type: object, additionalProperties: false, required: [query], properties: {query: {type: string}, undeclared: {type: string}}}", 1)
	writeTestFile(t, dir, "mcp.yaml", source)
	writeTestFile(t, dir, "flows/read_notes.yaml", "on:\n  request: {method: GET, path: /api/read-notes, permissions: [notes:read], inputs: {query: {type: text, required: true}}}\njobs:\n  read:\n    steps:\n      - query: SELECT 1\n")
	reviewAppMCPFixture(t, dir)
	var out strings.Builder
	if err := runAppMCPCLI([]string{"check", dir}, &out); err == nil || !strings.Contains(err.Error(), `"undeclared" is not accepted by flow`) {
		t.Fatalf("mcp check accepted an undeclared input: %v", err)
	}
	if _, err := loadRuntimeConfig(dir); err == nil || !strings.Contains(err.Error(), "not accepted by flow") {
		t.Fatalf("manifest load accepted an undeclared input: %v", err)
	}
	fixed := strings.Replace(source, ", undeclared: {type: string}", "", 1)
	writeTestFile(t, dir, "mcp.yaml", fixed)
	reviewAppMCPFixture(t, dir)
	if err := runAppMCPCLI([]string{"check", dir}, &out); err != nil {
		t.Fatalf("matching flow contract refused: %v", err)
	}
}

func TestAppMCPOutputProjectionMustExistInOutputSchema(t *testing.T) {
	source := strings.Replace(appMCPManifestFixture(), "include: [id]", "include: [id, ghost]", 1)
	if _, err := parseAppMCPManifest([]byte(source)); err == nil || !strings.Contains(err.Error(), "absent from its output schema") {
		t.Fatalf("projection of an undeclared output field accepted: %v", err)
	}
}

const componentResourceFixture = `resources:
  - name: notes_card
    uri: ui://notes/card
    mime_type: text/html
    component: card
    entrypoint: static/widgets/card.tsx
    tools: [list_notes]
    schema_version: 1
    data_schema: {type: object, additionalProperties: false, required: [id], properties: {id: {type: integer}, title: {type: string}}}
    deep_link: /notes/{id}
`

func componentManifest(resource string) string {
	source := strings.Replace(appMCPManifestFixture(), "resources: []\n", resource, 1)
	return strings.Replace(source, "component: none", "component: ui://notes/card", 1)
}

func TestAppMCPComponentDeclarationIsStrict(t *testing.T) {
	manifest, err := parseAppMCPManifest([]byte(componentManifest(componentResourceFixture)))
	if err != nil || manifest.Resources[0].Entrypoint != "static/widgets/card.tsx" || manifest.Resources[0].SchemaVersion != 1 {
		t.Fatalf("valid component declaration: %+v %v", manifest, err)
	}
	// The bare four-field resource keeps working.
	bare := "resources:\n  - {name: bare, uri: ui://notes/card, mime_type: text/html, component: card}\n"
	if _, err := parseAppMCPManifest([]byte(componentManifest(bare))); err != nil {
		t.Fatalf("bare resource refused: %v", err)
	}
	for name, mutate := range map[string]func(string) string{
		"unknown key": func(s string) string {
			return strings.Replace(s, "schema_version: 1", "schema_version: 1\n    serve: true", 1)
		},
		"undeclared tool":      func(s string) string { return strings.Replace(s, "tools: [list_notes]", "tools: [ghost]", 1) },
		"entrypoint outside":   func(s string) string { return strings.Replace(s, "static/widgets/card.tsx", "widgets/card.tsx", 1) },
		"entrypoint traversal": func(s string) string { return strings.Replace(s, "static/widgets/card.tsx", "static/../env.yaml", 1) },
		"entrypoint not code": func(s string) string {
			return strings.Replace(s, "static/widgets/card.tsx", "static/widgets/data.db", 1)
		},
		"missing schema": func(s string) string { return strings.Replace(s, "schema_version: 1\n", "", 1) },
		"scheme deep link": func(s string) string {
			return strings.Replace(s, "deep_link: /notes/{id}", "deep_link: https://notes.example/{id}", 1)
		},
		"scheme-relative host": func(s string) string {
			return strings.Replace(s, "deep_link: /notes/{id}", "deep_link: //evil.example/{id}", 1)
		},
		"relative deep link": func(s string) string { return strings.Replace(s, "deep_link: /notes/{id}", "deep_link: notes/{id}", 1) },
		"token in link": func(s string) string {
			return strings.Replace(s, "deep_link: /notes/{id}", "deep_link: /notes/{id}?token=abc", 1)
		},
		"code in link": func(s string) string {
			return strings.Replace(s, "deep_link: /notes/{id}", "deep_link: /notes/{id}?Code=1", 1)
		},
		"secret in link": func(s string) string {
			return strings.Replace(s, "deep_link: /notes/{id}", "deep_link: /notes/{id}/secret", 1)
		},
		"undeclared field": func(s string) string {
			return strings.Replace(s, "deep_link: /notes/{id}", "deep_link: /notes/{owner}", 1)
		},
		"unbalanced field": func(s string) string { return strings.Replace(s, "deep_link: /notes/{id}", "deep_link: /notes/{id", 1) },
		"dot segments": func(s string) string {
			return strings.Replace(s, "deep_link: /notes/{id}", "deep_link: /notes/../{id}", 1)
		},
	} {
		if _, err := parseAppMCPManifest([]byte(componentManifest(mutate(componentResourceFixture)))); err == nil {
			t.Errorf("%s: invalid component declaration accepted", name)
		}
	}
}

func TestAppMCPComponentEntrypointMustExist(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "mcp.yaml", componentManifest(componentResourceFixture))
	reviewAppMCPFixture(t, dir)
	if _, err := loadRuntimeConfig(dir); err == nil || !strings.Contains(err.Error(), "entrypoint") {
		t.Fatalf("missing entrypoint file loaded: %v", err)
	}
	var out strings.Builder
	if err := runAppMCPCLI([]string{"check", dir}, &out); err == nil || !strings.Contains(err.Error(), "entrypoint") {
		t.Fatalf("mcp check accepted a missing entrypoint: %v", err)
	}
	writeTestFile(t, dir, "static/widgets/card.tsx", "export const Card = () => null\n")
	reviewAppMCPFixture(t, dir)
	if _, err := loadRuntimeConfig(dir); err != nil {
		t.Fatalf("declared component refused: %v", err)
	}
	if err := validateAppMCPBindings(dir, mustParseManifest(t, componentManifest(componentResourceFixture)), nil); err != nil {
		t.Fatalf("write-time path refused a present entrypoint: %v", err)
	}
}

func mustParseManifest(t *testing.T, source string) *AppMCPManifest {
	t.Helper()
	manifest, err := parseAppMCPManifest([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

// New declarations enter the contract digest, so editing one invalidates every
// pending intent; manifests that do not use them keep their reviewed digest.
func TestAppMCPNewDeclarationsEnterContractDigest(t *testing.T) {
	dir := t.TempDir()
	digest := func(manifest *AppMCPManifest) string {
		contract, _, err := appMCPDigests(dir, manifest)
		if err != nil {
			t.Fatal(err)
		}
		return contract
	}
	plain := mustParseManifest(t, appMCPManifestFixture())
	raw, _ := json.Marshal(plain)
	for _, key := range []string{"Entrypoint", "SchemaVersion", "DeepLink", "DataSchema", "OperationID", `"Connection"`} {
		if strings.Contains(string(raw), key) {
			t.Fatalf("unused declaration field %s changed the reviewed contract encoding: %s", key, raw)
		}
	}
	base := digest(mustParseManifest(t, componentManifest(componentResourceFixture)))
	for name, edit := range map[string]func(string) string{
		"entrypoint":     func(s string) string { return strings.Replace(s, "card.tsx", "other.tsx", 1) },
		"tools":          func(s string) string { return strings.Replace(s, "tools: [list_notes]", "tools: []", 1) },
		"schema_version": func(s string) string { return strings.Replace(s, "schema_version: 1", "schema_version: 2", 1) },
		"data_schema":    func(s string) string { return strings.Replace(s, "title: {type: string}", "title: {type: integer}", 1) },
		"deep_link":      func(s string) string { return strings.Replace(s, "/notes/{id}", "/n/{id}", 1) },
	} {
		if got := digest(mustParseManifest(t, componentManifest(edit(componentResourceFixture)))); got == base {
			t.Errorf("%s edit did not change the contract digest", name)
		}
	}
}

const externalManifestFixture = `version: 1
connector: {id: fixture, name: Fixture, version: '1'}
contract_digest: ` + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" + `
execution_digest: ` + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" + `
connections:
  - name: rates
    base_url: ` + publicIPBaseURL + `
    auth: {kind: bearer, env: RATES_API_KEY}
    openapi: openapi/rates.yaml
tools:
  - name: lookup_rate
    description: Look up one rate
    handler: {kind: external, connection: rates, operation_id: getRate}
    input_schema: {type: object, additionalProperties: false}
    output_schema: {type: object, additionalProperties: false, required: [rate], properties: {rate: {type: number}}}
    permissions: [rates:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [rate]}
    component: none
resources: []
`

const ratesOpenAPI = `openapi: 3.0.3
info: {title: Rates, version: '1'}
paths:
  /rate:
    get:
      operationId: getRate
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema: {type: object, additionalProperties: false, required: [rate], properties: {rate: {type: number}}}
`

// The gate is open in this runtime; a runtime that closes it still refuses
// every external declaration through the gated parser.
func TestAppMCPExternalDeclarationsAreRefusedWhileGateIsClosed(t *testing.T) {
	if _, err := parseAppMCPManifestGated([]byte(externalManifestFixture), false); err == nil || !strings.Contains(err.Error(), "external connections are not enabled in this runtime") {
		t.Fatalf("external manifest loaded while the gate is closed: %v", err)
	}
	connectionsOnly := strings.Replace(externalManifestFixture, "handler: {kind: external, connection: rates, operation_id: getRate}", "handler: {kind: native, operation: table.list, table: notes}", 1)
	connectionsOnly = strings.Replace(connectionsOnly, "rates:read", "notes:read", 1)
	if _, err := parseAppMCPManifestGated([]byte(connectionsOnly), false); err == nil || !strings.Contains(err.Error(), "not enabled") {
		t.Fatalf("connection declarations loaded while the gate is closed: %v", err)
	}
}

func TestAppMCPExternalGrammarIsValidated(t *testing.T) {
	manifest, err := parseAppMCPManifestGated([]byte(externalManifestFixture), true)
	if err != nil || len(manifest.Connections) != 1 || manifest.Tools[0].Handler.OperationID != "getRate" {
		t.Fatalf("valid external grammar: %+v %v", manifest, err)
	}
	for name, mutate := range map[string]func(string) string{
		"http base": func(s string) string {
			return strings.Replace(s, "https://93.184.216.34/v1", "http://93.184.216.34/v1", 1)
		},
		"userinfo": func(s string) string {
			return strings.Replace(s, "https://93.184.216.34/v1", "https://user:pw@93.184.216.34/v1", 1)
		},
		"query credential": func(s string) string {
			return strings.Replace(s, "https://93.184.216.34/v1", "https://93.184.216.34/v1?api_key=abc", 1)
		},
		"loopback base": func(s string) string {
			return strings.Replace(s, "https://93.184.216.34/v1", "https://127.0.0.1/v1", 1)
		},
		"private base": func(s string) string { return strings.Replace(s, "https://93.184.216.34/v1", "https://10.0.0.5/v1", 1) },
		"localhost base": func(s string) string {
			return strings.Replace(s, "https://93.184.216.34/v1", "https://localhost/v1", 1)
		},
		"inline credential":  func(s string) string { return strings.Replace(s, "env: RATES_API_KEY", "env: sk_live_abcdef", 1) },
		"unknown auth kind":  func(s string) string { return strings.Replace(s, "kind: bearer", "kind: basic", 1) },
		"none with env":      func(s string) string { return strings.Replace(s, "kind: bearer", "kind: none", 1) },
		"header kind no hdr": func(s string) string { return strings.Replace(s, "kind: bearer", "kind: header", 1) },
		"openapi traversal":  func(s string) string { return strings.Replace(s, "openapi/rates.yaml", "../rates.yaml", 1) },
		"openapi absolute":   func(s string) string { return strings.Replace(s, "openapi/rates.yaml", "/etc/rates.yaml", 1) },
		"openapi not spec":   func(s string) string { return strings.Replace(s, "openapi/rates.yaml", "openapi/rates.txt", 1) },
		"unknown key":        func(s string) string { return strings.Replace(s, "auth: {", "token: abc\n    auth: {", 1) },
		"undeclared conn":    func(s string) string { return strings.Replace(s, "connection: rates", "connection: other", 1) },
		"missing operation":  func(s string) string { return strings.Replace(s, ", operation_id: getRate", "", 1) },
		"external with flow": func(s string) string {
			return strings.Replace(s, "operation_id: getRate", "operation_id: getRate, flow: x", 1)
		},
		"fields on native": func(s string) string { return strings.Replace(s, "kind: external", "kind: native", 1) },
		"external write tool": func(s string) string {
			return strings.Replace(strings.Replace(s, "effect: read", "effect: write", 1), "approval: none", "approval: first_party", 1)
		},
	} {
		if _, err := parseAppMCPManifestGated([]byte(mutate(externalManifestFixture)), true); err == nil {
			t.Errorf("%s: invalid external declaration accepted", name)
		}
	}
	duplicate := strings.Replace(externalManifestFixture, "tools:\n", "  - name: rates\n    base_url: "+publicIPBaseURL+"\n    auth: {kind: none}\n    openapi: openapi/rates.yaml\ntools:\n", 1)
	if _, err := parseAppMCPManifestGated([]byte(duplicate), true); err == nil {
		t.Error("duplicate connection accepted")
	}
}

func TestAppMCPExternalOperationMustExistInPinnedOpenAPI(t *testing.T) {
	dir := t.TempDir()
	manifest, err := parseAppMCPManifestGated([]byte(externalManifestFixture), true)
	if err != nil {
		t.Fatal(err)
	}
	if err := validateAppMCPDeclaredSources(dir, manifest); err == nil {
		t.Fatal("missing pinned OpenAPI file accepted")
	}
	writeTestFile(t, dir, "openapi/rates.yaml", ratesOpenAPI)
	if err := validateAppMCPDeclaredSources(dir, manifest); err != nil {
		t.Fatalf("pinned operation refused: %v", err)
	}
	manifest.Tools[0].Handler.OperationID = "deleteRate"
	if err := validateAppMCPDeclaredSources(dir, manifest); err == nil || !strings.Contains(err.Error(), "absent from the pinned OpenAPI document") {
		t.Fatalf("operation absent from the pinned document accepted: %v", err)
	}
}

func TestAppMCPExternalDeclarationsEnterDigests(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "openapi/rates.yaml", ratesOpenAPI)
	digests := func(source string) (string, string) {
		contract, execution, err := appMCPDigests(dir, mustParseExternal(t, source))
		if err != nil {
			t.Fatal(err)
		}
		return contract, execution
	}
	baseContract, baseExecution := digests(externalManifestFixture)
	for name, edit := range map[string]func(string) string{
		"base_url":     func(s string) string { return strings.Replace(s, "/v1", "/v2", 1) },
		"auth env":     func(s string) string { return strings.Replace(s, "RATES_API_KEY", "OTHER_KEY", 1) },
		"openapi":      func(s string) string { return strings.Replace(s, "openapi/rates.yaml", "openapi/rates.yml", 1) },
		"operation_id": func(s string) string { return strings.Replace(s, "operation_id: getRate", "operation_id: getOther", 1) },
	} {
		if contract, _ := digests(edit(externalManifestFixture)); contract == baseContract {
			t.Errorf("%s edit did not change the contract digest", name)
		}
	}
	writeTestFile(t, dir, "openapi/rates.yaml", ratesOpenAPI+"# edited\n")
	if _, execution := digests(externalManifestFixture); execution == baseExecution {
		t.Error("editing the pinned OpenAPI file did not change the execution digest")
	}
}

func mustParseExternal(t *testing.T, source string) *AppMCPManifest {
	t.Helper()
	manifest, err := parseAppMCPManifestGated([]byte(source), true)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

// F03.8: connector dispatch is a private in-process call, never cookie CSRF,
// and an ambient cookie cannot be combined with a connector bearer to reach it.
func TestAppMCPConnectorDispatchIsNeverCookieCSRFAndCannotBeForged(t *testing.T) {
	app, uid, pair, tool := appMCPReadFlowFixture(t, http.MethodPost, false)
	auditExec(t, app.DB, "INSERT INTO notes(id,user_id,title) VALUES (1,?,'private-title')", uid)

	// Private dispatch of a POST flow needs no cookie and no CSRF token.
	result, err := runAppMCPReadFlow(context.Background(), app, pair.AccessToken, grantFixtureResource, tool, map[string]any{"id": json.Number("1")})
	if err != nil || result == nil || !strings.Contains(string(mustMarshalContract(t, result.Data)), "private-title") {
		t.Fatalf("private dispatch needed ambient CSRF state: %v", err)
	}

	mux := http.NewServeMux()
	RegisterFlows(mux, app, app.Flows)
	cookie := CreateSession(app.DB, uid, "delegate@example.com", "17", time.Hour)
	serve := func(configure func(*http.Request)) *httptest.ResponseRecorder {
		request := httptest.NewRequest(http.MethodPost, "/api/mcp-note/1", strings.NewReader("{}"))
		request.Header.Set("Content-Type", "application/json")
		configure(request)
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)
		return recorder
	}
	withCookie := func(r *http.Request) { r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie}) }
	// Ordinary cookie request without a CSRF token is refused, so the gate is live.
	if got := serve(withCookie); got.Code != http.StatusForbidden || !strings.Contains(got.Body.String(), "CSRF") {
		t.Fatalf("cookie request without CSRF: %d %q", got.Code, got.Body.String())
	}
	// A connector bearer beside the ambient cookie does not turn it into a bearer request.
	got := serve(func(r *http.Request) {
		withCookie(r)
		r.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	})
	if got.Code != http.StatusForbidden || strings.Contains(got.Body.String(), "private-title") {
		t.Fatalf("cookie plus connector bearer crossed into dispatch: %d %q", got.Code, got.Body.String())
	}
	// The connector bearer alone is not a flow credential on the public route.
	got = serve(func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+pair.AccessToken) })
	if got.Code == http.StatusOK || strings.Contains(got.Body.String(), "private-title") {
		t.Fatalf("connector bearer authenticated the public flow route: %d %q", got.Code, got.Body.String())
	}
	// Private identity lives only in an unexported context value: no header or
	// cookie combination yields it.
	forged := httptest.NewRequest(http.MethodPost, "/api/mcp-note/1", nil)
	withCookie(forged)
	forged.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	if _, private := appMCPFlowPrivateSession(app, forged); private {
		t.Fatal("an HTTP request was recognized as private connector dispatch")
	}
}

func mustMarshalContract(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
