//go:build !cli && !windows

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const appMCPOpenAPIJSONFixture = `{
  "openapi":"3.1.1",
  "info":{"title":"Fixture","version":"1"},
  "paths":{"/items/{id}":{
    "parameters":[{"name":"id","in":"path","required":true,"schema":{"type":"integer","enum":[9007199254740993]}}],
    "get":{"operationId":"readItem","parameters":[{"name":"q","in":"query","required":false,"schema":{"type":"string"}}],
      "requestBody":{"required":true,"content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"properties":{"name":{"type":"string"}},"required":["name"]}}}},
      "responses":{"200":{"description":"ok","content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"properties":{"ok":{"type":"boolean"}},"required":["ok"]}}}}}}
  }}
}`

const appMCPOpenAPIYAMLFixture = `openapi: 3.0.4
info: {title: Fixture, version: '1'}
paths:
  /items/{id}:
    parameters:
      - name: id
        in: path
        required: true
        schema: {type: integer}
    get:
      operationId: readItem
      parameters:
        - name: q
          in: query
          schema: {type: string}
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              properties: {name: {type: string}}
              required: [name]
      responses:
        '200':
          description: ok
          content:
            application/json:
              schema:
                type: object
                additionalProperties: false
                properties: {ok: {type: boolean}}
                required: [ok]
`

func appMCPOpenAPIGenerate(t *testing.T, dir, source, data string) (*appMCPOpenAPICandidates, []byte, error) {
	t.Helper()
	writeTestFile(t, dir, source, data)
	output := filepath.Join(dir, "candidate.json")
	var response strings.Builder
	err := runAppMCPCLI([]string{"generate", dir, "--openapi", filepath.Join(dir, source), "--out", output}, &response)
	if err != nil {
		return nil, nil, err
	}
	encoded, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var candidates appMCPOpenAPICandidates
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&candidates); err != nil {
		t.Fatalf("decode candidates: %v", err)
	}
	return &candidates, encoded, nil
}

func TestAppMCPOpenAPIGeneratesDisabledYAMLAndJSONCandidates(t *testing.T) {
	for _, tc := range []struct {
		name, source, document, version string
	}{
		{"yaml-3.0", "openapi.yaml", appMCPOpenAPIYAMLFixture, "3.0.4"},
		{"json-3.1", "openapi.json", appMCPOpenAPIJSONFixture, "3.1.1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			candidates, encoded, err := appMCPOpenAPIGenerate(t, dir, tc.source, tc.document)
			if err != nil {
				t.Fatal(err)
			}
			if candidates.Enabled || candidates.OpenAPI != tc.version || len(candidates.Operations) != 1 {
				t.Fatalf("candidate header: %+v", candidates)
			}
			operation := candidates.Operations[0]
			if operation.Enabled || operation.State != "unresolved" || operation.OperationID != "readItem" || operation.Method != "GET" || operation.Path != "/items/{id}" || len(operation.ReviewRequired) == 0 {
				t.Fatalf("candidate policy or operation: %+v", operation)
			}
			if _, err := parseAppMCPManifest(encoded); err == nil {
				t.Fatal("candidate JSON was accepted as a strict live manifest")
			}
			input := operation.InputSchema
			if input.Type != "object" || input.AdditionalProperties == nil || *input.AdditionalProperties || len(input.Required) != 2 || input.Required[0] != "path" || input.Required[1] != "body" {
				t.Fatalf("input envelope: %+v", input)
			}
			if input.Properties["path"].Properties["id"].Type != "integer" || input.Properties["query"].Properties["q"].Type != "string" || input.Properties["body"].Properties["name"].Type != "string" {
				t.Fatalf("parameter/body schemas: %+v", input)
			}
			if operation.OutputSchema.Type != "object" || operation.OutputSchema.Properties["ok"].Type != "boolean" {
				t.Fatalf("success schema: %+v", operation.OutputSchema)
			}
			if tc.name == "json-3.1" && operation.InputSchema.Properties["path"].Properties["id"].Enum[0] != json.Number("9007199254740993") {
				t.Fatalf("large integer enum lost precision: %#v", operation.InputSchema.Properties["path"].Properties["id"].Enum)
			}
		})
	}
}

func TestAppMCPOpenAPIResolvesLocalRefsAndHashesReadBytes(t *testing.T) {
	dir := t.TempDir()
	document := strings.Replace(appMCPOpenAPIJSONFixture, `"schema":{"type":"object","additionalProperties":false,"properties":{"name":{"type":"string"}},"required":["name"]}`, `"schema":{"$ref":"./body.json"}`, 1)
	writeTestFile(t, dir, "openapi.json", document)
	body := `{"type":"object","additionalProperties":false,"properties":{"name":{"type":"string"}},"required":["name"]}`
	writeTestFile(t, dir, "body.json", body)
	output := filepath.Join(dir, "candidate.json")
	if err := runAppMCPCLI([]string{"generate", dir, "--openapi", filepath.Join(dir, "openapi.json"), "--out", output}, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	var candidates appMCPOpenAPICandidates
	encoded, err := os.ReadFile(output)
	if err != nil || json.Unmarshal(encoded, &candidates) != nil {
		t.Fatalf("read candidate: %v", err)
	}
	want := map[string][]byte{"openapi.json": []byte(document), "body.json": []byte(body)}
	if len(candidates.Sources) != len(want) {
		t.Fatalf("source inventory: %+v", candidates.Sources)
	}
	for _, source := range candidates.Sources {
		data, ok := want[source.Path]
		if !ok {
			t.Fatalf("unexpected source: %+v", source)
		}
		sum := sha256.Sum256(data)
		if source.SHA256 != hex.EncodeToString(sum[:]) || source.Size != int64(len(data)) {
			t.Errorf("wrong source digest/size for %s: %+v", source.Path, source)
		}
	}
}

// A reference may only name reviewed app source. Before, an example $ref into
// secrets.yaml (or env.yaml, uploads/, .benmore/ ...) copied those bytes into
// the candidate output a developer reviews and commits.
func TestAppMCPOpenAPIRefusesUnreviewedSourceFiles(t *testing.T) {
	const secret = "sk_live_must_not_be_copied"
	withExample := func(target string) string {
		return strings.Replace(appMCPOpenAPIJSONFixture, `"required":["ok"]}}`, `"required":["ok"]},"examples":{"leak":{"$ref":"./`+target+`#/leak"}}}`, 1)
	}
	for _, target := range []string{"secrets.yaml", "env.yaml", ".env.production.yaml", "uploads/private/u.json", ".benmore/state.json", "openapi/node_modules/x.json", "mcp.yaml"} {
		t.Run(target, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, target, "leak: "+secret+"\n")
			_, _, err := appMCPOpenAPIGenerate(t, dir, "openapi.json", withExample(target))
			if err == nil || !strings.Contains(err.Error(), "reviewed app source") {
				t.Fatalf("reference to %s accepted: %v", target, err)
			}
			if data, readErr := os.ReadFile(filepath.Join(dir, "candidate.json")); readErr == nil && strings.Contains(string(data), secret) {
				t.Fatalf("%s bytes reached the candidate", target)
			}
		})
	}
	for _, target := range []string{"examples/leak.yaml", "static/leak.yaml"} {
		dir := t.TempDir()
		writeTestFile(t, dir, target, "leak: reviewed-example\n")
		if _, encoded, err := appMCPOpenAPIGenerate(t, dir, "openapi.json", withExample(target)); err != nil || !strings.Contains(string(encoded), "reviewed-example") {
			t.Fatalf("reviewed reference %s: %v", target, err)
		}
	}
	dir := t.TempDir()
	writeTestFile(t, dir, "uploads/openapi.json", appMCPOpenAPIJSONFixture)
	if err := runAppMCPCLI([]string{"generate", dir, "--openapi", filepath.Join(dir, "uploads/openapi.json"), "--out", filepath.Join(dir, "candidate.json")}, &strings.Builder{}); err == nil {
		t.Fatal("accepted a pinned document under uploads/")
	}
}

func TestAppMCPOpenAPIRejectsUnsupportedDocuments(t *testing.T) {
	recursive := strings.Replace(appMCPOpenAPIJSONFixture, `"schema":{"type":"object","additionalProperties":false,"properties":{"name":{"type":"string"}},"required":["name"]}`, `"schema":{"$ref":"#/components/schemas/Loop"}`, 1)
	recursive = strings.Replace(recursive, `"paths":`, `"components":{"schemas":{"Loop":{"$ref":"#/components/schemas/Loop"}}},"paths":`, 1)
	duplicateOperation := appMCPOpenAPIJSONFixture
	duplicateOperation = strings.Replace(duplicateOperation, `  }}
}`, `  },"/other":{"get":{"operationId":"readItem","responses":{"200":{"content":{"application/json":{"schema":{"type":"object","additionalProperties":false}}}}}}}}
}`, 1)
	cases := []struct {
		name, source, document string
	}{
		{"remote-ref", "openapi.json", strings.Replace(appMCPOpenAPIJSONFixture, `"type":"string"}},"required":["name"]}`, `"$ref":"https://example.invalid/schema.json"}},"required":["name"]}`, 1)},
		{"missing-ref", "openapi.json", strings.Replace(appMCPOpenAPIJSONFixture, `"type":"string"}},"required":["name"]}`, `"$ref":"./missing.json#/schema"}},"required":["name"]}`, 1)},
		{"recursive-ref", "openapi.json", recursive},
		{"ref-sibling", "openapi.json", strings.Replace(appMCPOpenAPIJSONFixture, `"type":"string"}},"required":["name"]}`, `"$ref":"./body.json","type":"string"}},"required":["name"]}`, 1)},
		{"one-of", "openapi.json", strings.Replace(appMCPOpenAPIJSONFixture, `"type":"string"}},"required":["name"]}`, `"oneOf":[{"type":"string"}]}},"required":["name"]}`, 1)},
		{"schema-additional-properties", "openapi.json", strings.Replace(appMCPOpenAPIJSONFixture, `"additionalProperties":false,"properties":{"name"`, `"additionalProperties":true,"properties":{"name"`, 1)},
		{"schema-null-keyword", "openapi.json", strings.Replace(appMCPOpenAPIJSONFixture, `"type":"string"}},"required":["name"]}`, `"type":"string","minLength":null}},"required":["name"]}`, 1)},
		{"inexact-nested-minimum", "openapi.json", strings.Replace(appMCPOpenAPIJSONFixture, `"type":"string"}},"required":["name"]}`, `"type":"number","minimum":0.10000000000000001}},"required":["name"]}`, 1)},
		{"bad-version", "openapi.json", strings.Replace(appMCPOpenAPIJSONFixture, "3.1.1", "3.2.0", 1)},
		{"duplicate-operation-id", "openapi.json", duplicateOperation},
		{"typed-required", "openapi.json", strings.Replace(appMCPOpenAPIJSONFixture, `"required":true,"schema":{"type":"integer","enum":[9007199254740993]}`, `"required":"true","schema":{"type":"integer","enum":[9007199254740993]}`, 1)},
		{"missing-json-success", "openapi.json", strings.Replace(appMCPOpenAPIJSONFixture, `,"content":{"application/json":{"schema":{"type":"object","additionalProperties":false,"properties":{"ok":{"type":"boolean"}},"required":["ok"]}}}`, "", 1)},
		{"duplicate-yaml-key", "openapi.yaml", strings.Replace(appMCPOpenAPIYAMLFixture, "openapi: 3.0.4", "openapi: 3.0.4\nopenapi: 3.0.4", 1)},
		{"yaml-alias", "openapi.yaml", strings.Replace(appMCPOpenAPIYAMLFixture, "info: {title: Fixture, version: '1'}", "info: &info {title: Fixture, version: '1'}\nx-info: *info", 1)},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			if _, _, err := appMCPOpenAPIGenerate(t, dir, tc.source, tc.document); err == nil {
				t.Fatal("unsupported OpenAPI document generated candidates")
			}
		})
	}
}

func TestAppMCPOpenAPIRejectsEscapingAndUnsafeOutputs(t *testing.T) {
	t.Run("parent-reference", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, dir, "openapi.json", strings.Replace(appMCPOpenAPIJSONFixture, `"type":"string"}},"required":["name"]}`, `"$ref":"../outside.json#/schema"}},"required":["name"]}`, 1))
		writeTestFile(t, filepath.Dir(dir), "outside.json", `{"schema":{"type":"string"}}`)
		err := runAppMCPCLI([]string{"generate", dir, "--openapi", filepath.Join(dir, "openapi.json"), "--out", filepath.Join(dir, "candidate.json")}, &strings.Builder{})
		if err == nil {
			t.Fatal("accepted parent reference")
		}
	})
	t.Run("outside-openapi", func(t *testing.T) {
		parent := t.TempDir()
		dir := filepath.Join(parent, "app")
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		outside := filepath.Join(parent, "outside.json")
		if err := os.WriteFile(outside, []byte(appMCPOpenAPIJSONFixture), 0600); err != nil {
			t.Fatal(err)
		}
		if err := runAppMCPCLI([]string{"generate", dir, "--openapi", outside, "--out", filepath.Join(dir, "candidate.json")}, &strings.Builder{}); err == nil {
			t.Fatal("accepted OpenAPI file outside app root")
		}
	})
	for _, name := range []string{"mcp.yaml", "MCP.YAML"} {
		t.Run("live-output-"+name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "openapi.json", appMCPOpenAPIJSONFixture)
			if err := runAppMCPCLI([]string{"generate", dir, "--openapi", filepath.Join(dir, "openapi.json"), "--out", filepath.Join(dir, name)}, &strings.Builder{}); err == nil {
				t.Fatalf("accepted live manifest output %q", name)
			}
		})
	}
	t.Run("existing-output-and-symlink-target", func(t *testing.T) {
		dir := t.TempDir()
		writeTestFile(t, dir, "openapi.json", appMCPOpenAPIJSONFixture)
		output := filepath.Join(dir, "candidate.json")
		writeTestFile(t, dir, "candidate.json", "sentinel")
		if err := runAppMCPCLI([]string{"generate", dir, "--openapi", filepath.Join(dir, "openapi.json"), "--out", output}, &strings.Builder{}); err == nil {
			t.Fatal("overwrote existing output")
		}
		got, _ := os.ReadFile(output)
		if string(got) != "sentinel" {
			t.Fatalf("existing output changed: %q", got)
		}
		if err := os.Remove(output); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, dir, "target", "target sentinel")
		if err := os.Symlink("target", output); err != nil {
			t.Fatal(err)
		}
		if err := runAppMCPCLI([]string{"generate", dir, "--openapi", filepath.Join(dir, "openapi.json"), "--out", output}, &strings.Builder{}); err == nil {
			t.Fatal("replaced symlink output")
		}
		got, _ = os.ReadFile(filepath.Join(dir, "target"))
		if string(got) != "target sentinel" {
			t.Fatalf("symlink target changed: %q", got)
		}
	})
}

func TestAppMCPOpenAPIRejectsDeepReferenceChain(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i < 33; i++ {
		name := fmt.Sprintf("ref%02d.json", i)
		content := fmt.Sprintf(`{"$ref":"./ref%02d.json"}`, i+1)
		if i == 32 {
			content = `{"type":"string"}`
		}
		writeTestFile(t, dir, name, content)
	}
	document := strings.Replace(appMCPOpenAPIJSONFixture, `"schema":{"type":"object","additionalProperties":false,"properties":{"name":{"type":"string"}},"required":["name"]}`, `"schema":{"$ref":"./ref00.json"}`, 1)
	if _, _, err := appMCPOpenAPIGenerate(t, dir, "openapi.json", document); err == nil {
		t.Fatal("accepted reference chain beyond depth limit")
	}
}

func TestAppMCPOpenAPIGenerateFlagsAndReadOnlyCommands(t *testing.T) {
	for _, args := range [][]string{
		{"generate", "app"},
		{"generate", "app", "--openapi", "x"},
		{"generate", "app", "--out", "x"},
		{"generate", "app", "--openapi", "x", "--out", "y", "extra"},
	} {
		if err := runAppMCPCLI(args, &strings.Builder{}); err == nil {
			t.Errorf("accepted invalid args %q", args)
		}
	}
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	writeTestFile(t, dir, "openapi.json", appMCPOpenAPIJSONFixture)
	reviewAppMCPFixture(t, dir)
	before := appMCPCLIFileSnapshot(t, dir)
	output := filepath.Join(t.TempDir(), "candidate.json")
	if err := runAppMCPCLI([]string{"generate", dir, "--openapi", filepath.Join(dir, "openapi.json"), "--out", output}, &strings.Builder{}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{{"inspect", dir, "--json"}, {"check", dir}} {
		if _, _, err := appMCPCLIReport(t, args...); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	after := appMCPCLIFileSnapshot(t, dir)
	delete(after, "candidate.json")
	if !appMCPCLIFilesEqual(before, after) {
		t.Fatalf("generate/inspect/check changed app state beyond explicit output\nbefore: %#v\nafter: %#v", before, after)
	}
	if _, err := os.Stat(output); err != nil {
		t.Fatalf("explicit candidate output missing: %v", err)
	}
}

func TestAppMCPOpenAPIReferenceBudgetsAndPathContract(t *testing.T) {
	reader := &appMCPOpenAPIReader{}
	_, err := reader.resolve(strings.Repeat("x", yamlMaxBytes+1), "", map[string]bool{}, 0, "literal")
	if err == nil {
		t.Fatal("expanded reference strings exceeded budget")
	}
	reader = &appMCPOpenAPIReader{nodes: 99999}
	_, err = reader.resolve(map[string]any{"nested": "value"}, "", map[string]bool{}, 0, "literal")
	if err == nil {
		t.Fatal("expanded reference nodes exceeded budget")
	}
	for _, route := range []string{"/items/{missing}", "/items/", "/items/{id", "/items/{id}?query=x"} {
		dir := t.TempDir()
		document := strings.Replace(appMCPOpenAPIJSONFixture, "/items/{id}", route, 1)
		if _, _, err := appMCPOpenAPIGenerate(t, dir, "openapi.json", document); err == nil {
			t.Errorf("accepted mismatched path contract %q", route)
		}
	}
}

// The OpenAPI budgets bound a whole manifest, not each connection: repeating a
// connection used to hand every copy a fresh 64-file/64 MiB budget, so parse
// work grew with the connection count in the process that validates the
// manifest (the hosted write gate and archive deploy included).
func TestAppMCPOpenAPIBudgetCoversWholeManifest(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "openapi/shared.yaml", appMCPOpenAPIYAMLFixture)
	distinct, shared := &AppMCPManifest{}, &AppMCPManifest{}
	for i := 0; i < 65; i++ {
		file := fmt.Sprintf("openapi/c%02d.yaml", i)
		writeTestFile(t, dir, file, appMCPOpenAPIYAMLFixture)
		connection := AppMCPConnection{Name: fmt.Sprintf("c%02d", i), BaseURL: "https://example.com", Auth: AppMCPConnectionAuth{Kind: "none"}, OpenAPI: file}
		distinct.Connections = append(distinct.Connections, connection)
		connection.OpenAPI = "openapi/shared.yaml"
		shared.Connections = append(shared.Connections, connection)
	}
	if err := validateAppMCPDeclaredSources(dir, distinct); err == nil || !strings.Contains(err.Error(), "file limit") {
		t.Fatalf("65 pinned files across connections each got a fresh budget: %v", err)
	}
	if err := validateAppMCPDeclaredSources(dir, shared); err != nil {
		t.Fatalf("connections sharing one pinned document: %v", err)
	}
}

func TestAppMCPOpenAPICandidateWithinSourceNeedsReview(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	writeTestFile(t, dir, "openapi.json", appMCPOpenAPIJSONFixture)
	reviewAppMCPFixture(t, dir)
	before := appMCPCLIFileSnapshot(t, dir)
	if err := generateAppMCPCandidates(dir, filepath.Join(dir, "openapi.json"), filepath.Join(dir, "candidate.json")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := appMCPCLIReport(t, "check", dir); err == nil {
		t.Fatal("new reviewed source was accepted without digest review")
	}
	after := appMCPCLIFileSnapshot(t, dir)
	delete(after, "candidate.json")
	if !appMCPCLIFilesEqual(before, after) {
		t.Fatal("candidate generation mutated original app source")
	}
}

func TestAppMCPOpenAPIRejectsReviewedSchemaWeakening(t *testing.T) {
	replaceSchema := func(schema string) string {
		return strings.Replace(appMCPOpenAPIJSONFixture, `"schema":{"type":"string"}`, `"schema":`+schema, 1)
	}
	for _, document := range []string{
		replaceSchema(`{"type":"string","maxLength":1,"maxlength":1000}`),
		replaceSchema(`{"type":"string","enum":[]}`),
		replaceSchema(`{"type":"array","items":{"type":"string","enum":[]}}`),
		replaceSchema(`{"type":"object","additionalProperties":false,"properties":{"item":{"type":"string","maxLength":1,"MAXLENGTH":1000}}}`),
		strings.Replace(appMCPOpenAPIJSONFixture, `"responses":{"200":`, `"responses":{"2XX":{"content":{"application/json":{"schema":{"type":"integer"}}}},"200":`, 1),
	} {
		dir := t.TempDir()
		if _, _, err := appMCPOpenAPIGenerate(t, dir, "openapi.json", document); err == nil {
			t.Fatalf("schema weakening accepted: %s", document)
		}
		if _, err := os.Stat(filepath.Join(dir, "candidate.json")); !os.IsNotExist(err) {
			t.Fatal("rejected schema created an output")
		}
	}
}

func TestAppMCPOpenAPIRefLiteralAndPropertyNamesStayLiteral(t *testing.T) {
	dir := t.TempDir()
	schema := `{"type":"object","additionalProperties":false,"properties":{"$ref":{"type":"string"},"$id":{"type":"string"}},"enum":[{"$ref":"#/components/examples/Allowed/value"}]}`
	document := strings.Replace(appMCPOpenAPIJSONFixture, `"schema":{"type":"string"}`, `"schema":`+schema, 1)
	document = strings.Replace(document, `"get":{"operationId":`, `"get":{"x-literal":{"$ref":"https://example.invalid/not-fetched"},"operationId":`, 1)
	candidates, _, err := appMCPOpenAPIGenerate(t, dir, "openapi.json", document)
	if err != nil {
		t.Fatal(err)
	}
	result := candidates.Operations[0].InputSchema.Properties["query"].Properties["q"]
	literal := map[string]any{"$ref": "#/components/examples/Allowed/value"}
	if !appMCPJSONValueEqual(result.Enum[0], literal, 0) || result.Properties["$ref"] == nil || result.Properties["$id"] == nil {
		t.Fatalf("literal reference/property names changed: %+v", result)
	}
	if err := validateAppMCPSchemaValue(result, literal); err != nil {
		t.Fatal(err)
	}
	if len(candidates.Sources) != 1 {
		t.Fatal("literal reference was loaded as a source")
	}
}

func TestAppMCPOpenAPIRefCannotSkipAncestorBase(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "child.json", `{"type":"string"}`)
	document := strings.Replace(appMCPOpenAPIJSONFixture, `"schema":{"type":"string"}`, `"schema":{"$ref":"#/components/schemas/Outer/properties/value"}`, 1)
	document = strings.Replace(document, `"paths":`, `"components":{"schemas":{"Outer":{"$id":"https://example.invalid/remote/","type":"object","properties":{"value":{"$ref":"child.json"}}}}},"paths":`, 1)
	if _, _, err := appMCPOpenAPIGenerate(t, dir, "openapi.json", document); err == nil || !strings.Contains(err.Error(), "ancestor base") {
		t.Fatalf("ancestor base was not rejected: %v", err)
	}
}

func TestAppMCPOpenAPIExampleReferencePreservesLiteralValue(t *testing.T) {
	dir := t.TempDir()
	document := strings.Replace(appMCPOpenAPIJSONFixture, `"info":`, `"components":{"examples":{"literal":{"value":{"$ref":"https://example.invalid/do-not-load","$id":"literal-data"}}}},"info":`, 1)
	document = strings.Replace(document, `"content":{"application/json":{"schema":`, `"content":{"application/json":{"examples":{"literal":{"$ref":"#/components/examples/literal"}},"schema":`, 1)
	candidates, _, err := appMCPOpenAPIGenerate(t, dir, "openapi.json", document)
	if err != nil {
		t.Fatal(err)
	}
	operation := candidates.Operations[0].Contract["operation"].(map[string]any)
	media := operation["requestBody"].(map[string]any)["content"].(map[string]any)["application/json"].(map[string]any)
	example := media["examples"].(map[string]any)["literal"].(map[string]any)["value"]
	if !appMCPJSONValueEqual(example, map[string]any{"$ref": "https://example.invalid/do-not-load", "$id": "literal-data"}, 0) {
		t.Fatalf("literal example changed: %#v", example)
	}
}

func TestAppMCPOpenAPIRefThroughLiteralExampleDoesNotInheritBase(t *testing.T) {
	dir := t.TempDir()
	document := strings.Replace(appMCPOpenAPIJSONFixture, `"schema":{"type":"string"}`, `"schema":{"$ref":"#/components/examples/E/value/schema"}`, 1)
	document = strings.Replace(document, `"paths":`, `"components":{"examples":{"E":{"value":{"$id":"literal-data","schema":{"type":"string"}}}}},"paths":`, 1)
	if _, _, err := appMCPOpenAPIGenerate(t, dir, "openapi.json", document); err != nil {
		t.Fatalf("literal Example value established schema base: %v", err)
	}
}

func TestAppMCPOpenAPIResponseHeaderAndLinkReferencesBoundSources(t *testing.T) {
	for _, kind := range []string{"headers", "links"} {
		for _, reference := range []string{"missing.json", "https://example.invalid/missing.json"} {
			dir := t.TempDir()
			document := strings.Replace(appMCPOpenAPIJSONFixture, `"responses":{"200":{"description":`, `"responses":{"200":{"`+kind+`":{"fixture":{"$ref":"`+reference+`"}},"description":`, 1)
			if _, _, err := appMCPOpenAPIGenerate(t, dir, "openapi.json", document); err == nil {
				t.Fatalf("unresolved %s ref accepted: %s", kind, reference)
			}
		}
	}
	dir := t.TempDir()
	header := `{"description":"Trace","schema":{"type":"string"}}`
	link := `{"operationId":"readItem","parameters":{"id":"$response.body#/id"}}`
	writeTestFile(t, dir, "header.json", header)
	writeTestFile(t, dir, "link.json", link)
	document := strings.Replace(appMCPOpenAPIJSONFixture, `"responses":{"200":{"description":`, `"responses":{"200":{"headers":{"X-Trace":{"$ref":"header.json"}},"links":{"next":{"$ref":"link.json"}},"description":`, 1)
	candidates, _, err := appMCPOpenAPIGenerate(t, dir, "openapi.json", document)
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates.Sources) != 3 {
		t.Fatalf("response source closure not pinned: %+v", candidates.Sources)
	}
}

func TestAppMCPOpenAPIHeaderContentReferencesBoundAndScoped(t *testing.T) {
	for _, reference := range []string{"missing.json", "https://example.invalid/missing.json"} {
		dir := t.TempDir()
		document := strings.Replace(appMCPOpenAPIJSONFixture, `"responses":{"200":{"description":`, `"responses":{"200":{"headers":{"Trace":{"content":{"application/json":{"schema":{"$ref":"`+reference+`"}}}}},"description":`, 1)
		if _, _, err := appMCPOpenAPIGenerate(t, dir, "openapi.json", document); err == nil {
			t.Fatalf("Header content ref accepted: %s", reference)
		}
	}
	dir := t.TempDir()
	writeTestFile(t, dir, "child.json", `{"type":"string"}`)
	document := strings.Replace(appMCPOpenAPIJSONFixture, `"schema":{"type":"string"}`, `"schema":{"$ref":"#/components/headers/Trace/content/application~1json/schema/properties/value"}`, 1)
	document = strings.Replace(document, `"paths":`, `"components":{"headers":{"Trace":{"content":{"application/json":{"schema":{"$id":"https://example.invalid/base/","type":"object","properties":{"value":{"$ref":"child.json"}}}}}}}},"paths":`, 1)
	if _, _, err := appMCPOpenAPIGenerate(t, dir, "openapi.json", document); err == nil || !strings.Contains(err.Error(), "ancestor base") {
		t.Fatalf("Header content schema base bypass: %v", err)
	}
}

func TestAppMCPOpenAPIAcceptsAnnotationsAndOptionalNullable(t *testing.T) {
	body := `"schema":{"type":"object","title":"Body","additionalProperties":false,"properties":{"name":{"type":"string","format":"email","title":"Name","example":"a@b.c"},"nick":{"type":["string","null"],"deprecated":true},"age":{"type":"integer","nullable":true}},"required":["name"]}`
	document := strings.Replace(appMCPOpenAPIJSONFixture, `"schema":{"type":"object","additionalProperties":false,"properties":{"name":{"type":"string"}},"required":["name"]}`, body, 1)
	candidates, _, err := appMCPOpenAPIGenerate(t, t.TempDir(), "openapi.json", document)
	if err != nil {
		t.Fatal(err)
	}
	// The candidate's source contract echoes the spec verbatim; only the generated schema is checked.
	schema, _ := json.Marshal(candidates.Operations[0].InputSchema)
	if strings.Contains(string(schema), `"format"`) || strings.Contains(string(schema), "a@b.c") {
		t.Fatalf("annotations leaked into generated schema: %s", schema)
	}
	got := candidates.Operations[0].InputSchema.Properties["body"]
	if got.Properties["nick"].Type != "string" || got.Properties["age"].Type != "integer" || len(got.Required) != 1 || got.Required[0] != "name" {
		t.Fatalf("nullable properties must be plain optional types: %+v", got)
	}
}

func TestAppMCPOpenAPIRefusesRequiredNullableProperty(t *testing.T) {
	document := strings.Replace(appMCPOpenAPIJSONFixture, `"properties":{"name":{"type":"string"}},"required":["name"]}}}},`, `"properties":{"name":{"type":["string","null"]}},"required":["name"]}}}},`, 1)
	if document == appMCPOpenAPIJSONFixture {
		t.Fatal("fixture replacement did not apply")
	}
	if _, _, err := appMCPOpenAPIGenerate(t, t.TempDir(), "openapi.json", document); err == nil || !strings.Contains(err.Error(), `"name"`) {
		t.Fatalf("required nullable property must be refused by name, got %v", err)
	}
}

// Review of #408: an output schema is validated strictly, so a nullable
// response property must be refused rather than turned into a non-null type
// that would reject the upstream's real null replies.
func TestAppMCPOpenAPIRefusesNullableResponseProperty(t *testing.T) {
	old := `"properties":{"ok":{"type":"boolean"}},"required":["ok"`
	document := strings.Replace(appMCPOpenAPIJSONFixture, old, `"properties":{"ok":{"type":"boolean"},"nick":{"type":["string","null"]}},"required":["ok"`, 1)
	if document == appMCPOpenAPIJSONFixture {
		t.Fatal("fixture replacement did not apply")
	}
	if _, _, err := appMCPOpenAPIGenerate(t, t.TempDir(), "openapi.json", document); err == nil || !strings.Contains(err.Error(), `"nick"`) {
		t.Fatalf("nullable response property must be refused by name, got %v", err)
	}
}
