//go:build !cli

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func appMCPManifestFixture() string {
	return `version: 1
connector: {id: fixture, name: Fixture, version: '1'}
contract_digest: ` + strings.Repeat("a", 64) + `
execution_digest: ` + strings.Repeat("b", 64) + `
tools:
  - name: list_notes
    description: Read reviewed note fields
    handler: {kind: native, operation: table.list, table: notes}
    input_schema: {type: object, additionalProperties: false}
    output_schema:
      type: object
      additionalProperties: false
      properties:
        id: {type: integer}
    permissions: [notes:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [id]}
    component: none
resources: []
connections: []
`
}
func TestAppMCPManifestStrictContract(t *testing.T) {
	valid := appMCPManifestFixture()
	if m, err := parseAppMCPManifest([]byte(valid)); err != nil || len(m.Tools) != 1 {
		t.Fatalf("valid manifest: %+v %v", m, err)
	}
	// Property names may coincide with schema keywords without becoming keywords.
	namedProperties := strings.Replace(valid, "properties:\n        id: {type: integer}", "properties:\n        id: {type: integer}\n        type: {type: string}\n        minLength: {type: string}", 1)
	if _, err := parseAppMCPManifest([]byte(namedProperties)); err != nil {
		t.Fatalf("keyword-named properties rejected: %v", err)
	}
	badNamedProperties := strings.Replace(namedProperties, "minLength: {type: string}", "enum: {type: string, minLength: 1.5, maximum: null}", 1)
	if _, err := parseAppMCPManifest([]byte(badNamedProperties)); err == nil {
		t.Fatal("keyword-named property bypassed integer/null checks")
	}
	for _, source := range []string{
		"", "null", valid + "version: 1\n", valid + "unknown: true\n", valid + "---\nversion: 1\n",
		strings.Replace(valid, "effect: read", "effect: write", 1),
		strings.Replace(valid, "notes:read", "*:read", 1),
		strings.Replace(valid, "component: none", "component: missing", 1),
		strings.Replace(valid, "additionalProperties: false", "additionalProperties: true", 1),
		strings.Replace(valid, "type: integer", "type: integer, $ref: 'https://invalid/schema'", 1),
		strings.Replace(valid, "table: notes", "table: notes, unexpected: true", 1),
		strings.Replace(valid, "type: integer", "type: number, minimum: .nan", 1),
		strings.Replace(valid, "type: integer", "type: string, minLength: 1.5", 1),
		strings.Replace(valid, "type: integer", "type: string, properties: null, minimum: null", 1),
		strings.Replace(valid, "type: integer", "type: number, enum: [.nan]", 1),
		strings.Replace(valid, "type: integer", "type: string, enum: [{1: value}]", 1),
		strings.Replace(valid, "include: [id]", "include: ['*']", 1),
		strings.Replace(valid, "connections: []", "connections: [unreviewed]", 1),
	} {
		if _, err := parseAppMCPManifest([]byte(source)); err == nil {
			t.Fatalf("invalid manifest accepted: %s", source)
		}
	}
}
func appMCPUpdateManifestFixture() string {
	return `version: 1
connector: {id: fixture, name: Fixture, version: '1'}
contract_digest: ` + strings.Repeat("a", 64) + `
execution_digest: ` + strings.Repeat("b", 64) + `
tools:
  - name: notes_update_title
    description: Update one note title.
    handler: {kind: native, operation: table.update, table: notes}
    input_schema:
      type: object
      additionalProperties: false
      required: [id, data]
      properties:
        id: {type: integer, minimum: 1, maximum: 9007199254740991}
        data:
          type: object
          additionalProperties: false
          required: [title]
          properties:
            title: {type: string, minLength: 1, maxLength: 200}
    output_schema:
      type: object
      additionalProperties: false
      required: [id, title]
      properties:
        id: {type: integer, minimum: 1, maximum: 9007199254740991}
        title: {type: string, minLength: 1, maxLength: 200}
    permissions: [notes:write]
    effect: write
    approval: first_party
    idempotency: operation
    reconciliation: authoritative_readback
    output: {include: [id, title]}
    component: none
resources: []
connections: []
`
}

func TestAppMCPPrivateWriteDeclarationIsTypedAndNotPublic(t *testing.T) {
	manifest, err := parseAppMCPManifest([]byte(appMCPUpdateManifestFixture()))
	if err != nil || manifest == nil || len(manifest.Tools) != 1 {
		t.Fatalf("typed private update declaration: %+v %v", manifest, err)
	}
	tool := appMCPUpdateTool(manifest, "notes_update_title")
	if tool == nil || validateAppMCPUpdateDeclaration(*tool) != nil || appMCPSupportedScopes(manifest) != "_none_:read" || appMCPDeclaredScopes(manifest) != "notes:write" {
		t.Fatalf("write declaration crossed the public scope boundary: %+v public=%q declared=%q", tool, appMCPSupportedScopes(manifest), appMCPDeclaredScopes(manifest))
	}
	for _, source := range []string{
		strings.Replace(appMCPUpdateManifestFixture(), "approval: first_party", "approval: none", 1),
		strings.Replace(appMCPUpdateManifestFixture(), "permissions: [notes:write]", "permissions: [other:write]", 1),
		strings.Replace(appMCPUpdateManifestFixture(), "required: [id, data]", "required: [id]", 1),
		strings.Replace(appMCPUpdateManifestFixture(), "include: [id, title]", "include: [id]", 1),
	} {
		if _, err := parseAppMCPManifest([]byte(source)); err == nil {
			t.Fatalf("invalid typed update declaration accepted: %s", source)
		}
	}
	optionalSource := strings.Replace(appMCPUpdateManifestFixture(), "required: [title]", "required: []", 1)
	optionalManifest, err := parseAppMCPManifest([]byte(optionalSource))
	if err != nil || optionalManifest == nil {
		t.Fatalf("optional writable fields should be valid: %v", err)
	}
	optionalTool := appMCPUpdateTool(optionalManifest, "notes_update_title")
	if _, _, err := validateAppMCPUpdateInput(optionalTool, map[string]any{"id": json.Number("1"), "data": map[string]any{}}); err == nil {
		t.Fatal("empty update data should be denied")
	}
	if _, _, err := validateAppMCPUpdateInput(optionalTool, map[string]any{"id": json.Number("1"), "data": map[string]any{"title": "subset"}}); err != nil {
		t.Fatalf("nonempty optional subset should be accepted: %v", err)
	}
}

func TestAppMCPManifestCheckedRuntimeAndWrite(t *testing.T) {
	dir := t.TempDir()
	if c, err := loadRuntimeConfig(dir); err != nil || c.mcp != nil {
		t.Fatalf("absence must disable: %+v %v", c, err)
	}
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewed := reviewAppMCPFixture(t, dir)
	if c, err := loadRuntimeConfig(dir); err != nil || c.mcp == nil {
		t.Fatalf("checked load: %+v %v", c, err)
	}
	if msg := ValidateOnWriteIn(dir, "mcp.yaml", reviewed); msg != "" {
		t.Fatalf("write gate: %s", msg)
	}
	invalid := strings.Replace(appMCPManifestFixture(), "table: notes", "table: missing", 1)
	writeTestFile(t, dir, "mcp.yaml", invalid)
	if _, err := loadRuntimeConfig(dir); err == nil {
		t.Fatal("unresolved reference accepted")
	}
	if msg := ValidateOnWriteIn(dir, "mcp.yaml", invalid); msg == "" {
		t.Fatal("write accepted unresolved reference")
	}
	if _, err := loadApp(dir); err == nil {
		t.Fatal("invalid startup accepted")
	}
	if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
		t.Fatalf("invalid manifest reached DB initialization: %v", err)
	}
	found := false
	for _, file := range walkAppFiles(dir) {
		if file.relPath == "mcp.yaml" {
			found = true
		}
	}
	if !found {
		t.Fatal("check omitted manifest")
	}
}

func TestAppMCPManifestRejectsCommentedAndReservedTables(t *testing.T) {
	for _, tc := range []struct{ table, source string }{{"notes", "-- CREATE TABLE notes (id INTEGER);"}, {"notes", "/* CREATE TABLE notes (id INTEGER); */"}, {"_benmore_users", "CREATE TABLE _benmore_users (id INTEGER);"}} {
		dir := t.TempDir()
		writeTestFile(t, dir, "schema.sql", tc.source)
		source := strings.ReplaceAll(appMCPManifestFixture(), "notes", tc.table)
		writeTestFile(t, dir, "mcp.yaml", source)
		reviewAppMCPFixture(t, dir)
		if _, err := loadRuntimeConfig(dir); err == nil {
			t.Fatalf("invalid table binding accepted: %s", tc.source)
		}
	}
}

// Table tools refuse a projected column the hidden-column rule hides; a flow
// tool returns whatever its SQL selects under the declared names, so the same
// name rule refuses secret-shaped output fields when the manifest loads.
func TestAppMCPManifestFlowOutputRefusesHiddenColumnNames(t *testing.T) {
	flowTool := func(field string) string {
		valid := appMCPManifestFixture()
		valid = strings.Replace(valid, "handler: {kind: native, operation: table.list, table: notes}", "handler: {kind: native, operation: flow.call, flow: list_notes}", 1)
		valid = strings.Replace(valid, "        id: {type: integer}", "        id: {type: integer}\n        "+field+": {type: string}", 1)
		return strings.Replace(valid, "include: [id]", "include: [id, "+field+"]", 1)
	}
	if _, err := parseAppMCPManifest([]byte(flowTool("title"))); err != nil {
		t.Fatalf("ordinary flow output field refused: %v", err)
	}
	if _, err := parseAppMCPManifest([]byte(flowTool("public_token"))); err != nil {
		t.Fatalf("public_ field refused, though the hidden-column rule shows it: %v", err)
	}
	for _, field := range []string{"api_token", "password_hash", "stripe_secret", "api_key", "token", "mfa_secret", "email_blind"} {
		if _, err := parseAppMCPManifest([]byte(flowTool(field))); err == nil || !strings.Contains(err.Error(), "secret-shaped") {
			t.Errorf("flow tool output %q: err = %v, want secret-shaped refusal", field, err)
		}
	}
	// Table tools keep their call-time check against the table's real columns.
	table := strings.Replace(appMCPManifestFixture(), "        id: {type: integer}", "        id: {type: integer}\n        api_token: {type: string}", 1)
	if _, err := parseAppMCPManifest([]byte(strings.Replace(table, "include: [id]", "include: [id, api_token]", 1))); err != nil {
		t.Fatalf("table tool manifest load changed: %v", err)
	}
}
