//go:build !cli

package main

import (
	"net/http"
	"reflect"
	"strings"
	"testing"
)

func TestReloadPublishesStagedMCPAuthoritySnapshot(t *testing.T) {
	// A staged encrypted policy needs the same durable key as its running DB,
	// registered SQL encryption functions, and real target columns.
	app := reloadStorageApp(t)
	mustExec(t, app.DB, "CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, email TEXT)")
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE private_docs (\n id INTEGER PRIMARY KEY,\n org_id TEXT,\n title TEXT,\n secret TEXT\n);\nCREATE TABLE contacts (\n id INTEGER PRIMARY KEY,\n email TEXT\n);\n")
	appYAML := `theme: ocean
seo: {url: "https://reviewed.example"}
groups: {table: members, key: org_id, user_field: email}
scopes:
  private_docs: {public_read_when: "title = 'public'"}
access:
  private_docs: {read: group}
roles:
  editor: {scopes: [private_docs:read]}
encrypted:
  contacts:
    - {column: email, roles: [admin]}
`
	encryptedYAML := `tables:
  private_docs: {fields: [secret], unmask_roles: [editor], blind_index: [secret]}
`
	mustExec(t, app.DB, "INSERT INTO members(org_id,email) VALUES ('17','delegate@example.com'),('29','delegate@example.com')")
	session := createCrudScopeSession(t, app, "delegate@example.com", "editor", "17", "")
	writeTestFile(t, app.Dir, "app.yaml", appYAML)
	writeTestFile(t, app.Dir, "encrypted.yaml", encryptedYAML)
	writeTestFile(t, app.Dir, "mcp.yaml", strings.ReplaceAll(appMCPManifestFixture(), "notes", "private_docs"))
	reviewAppMCPFixture(t, app.Dir)
	staged, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}

	if staged.mcp == nil {
		t.Fatal("mutation regression did not stage reviewed MCP authority")
	}

	writeTestFile(t, app.Dir, "app.yaml", `theme: slate
seo: {url: "https://conflict.example"}
groups: {table: members, key: wrong_org_id, user_field: username}
scopes: {private_docs: {public_read_when: "title = 'conflict'"}}
access: {private_docs: {read: admin}}
roles: {editor: {scopes: [other:read]}}
`)
	writeTestFile(t, app.Dir, "encrypted.yaml", "tables: {private_docs: {fields: [other_secret]}}\n")
	if err := reloadAppConfigStaged(app, staged, map[string]string{"ENCRYPTION_KEY": strings.Repeat("ab", 32)}); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(app.Group, staged.group) || !reflect.DeepEqual(app.Scopes, staged.scopes) ||
		!reflect.DeepEqual(app.Access, staged.access) || !reflect.DeepEqual(app.Roles, staged.roles) ||
		!reflect.DeepEqual(app.Encrypted, staged.encrypted) || !reflect.DeepEqual(app.Design, staged.design) {
		t.Fatal("reload did not publish the staged authority snapshot")
	}
	if reflect.DeepEqual(app.Group, LoadGroupConfig(app.Dir)) || reflect.DeepEqual(app.Scopes, LoadScopes(app.Dir)) ||
		reflect.DeepEqual(app.Access, LoadAccess(app.Dir)) || reflect.DeepEqual(app.Roles, LoadRolesConfig(app.Dir)) ||
		reflect.DeepEqual(app.Encrypted, LoadEncryptedFieldsConfig(app.Dir)) || reflect.DeepEqual(app.Design, LoadAppConfigYAML(app.Dir)) {
		t.Fatal("published authority still matches conflicting disk configuration")
	}

	writeTestFile(t, app.Dir, "app.yaml", appYAML)
	writeTestFile(t, app.Dir, "encrypted.yaml", encryptedYAML)
	if err := validateAppMCPDigests(app.Dir, app.MCP); err != nil {
		t.Fatalf("restored reviewed source: %v", err)
	}

	mustExec(t, app.DB, "INSERT INTO private_docs(org_id,title) VALUES ('17','private-17'),('29','private-29'),('29','public')")
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	recorder := crudScopeRequest(t, mux, http.MethodGet, "/api/private_docs", session, nil)
	body := recorder.Body.String()
	if recorder.Code != http.StatusOK || !strings.Contains(body, "private-17") || !strings.Contains(body, "public") || strings.Contains(body, "private-29") {
		t.Fatalf("canonical HTTP read ignored staged access, scope, or tenant policy: %d %s", recorder.Code, body)
	}
}

func TestAppMCPRuntimeUsesCapturedAuthorityAndKeepsMissingOptionalsNil(t *testing.T) {
	dir := t.TempDir()
	appYAML := `theme: captured
groups: {table: members, key: org_id, user_field: email}
scopes: {notes: {public_read_when: "title = 'public'"}}
access: {notes: {read: group}}
roles: {viewer: {scopes: [notes:read]}}
encrypted:
  inline:
    - {column: value, roles: [viewer]}
`
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);\n")
	writeTestFile(t, dir, "app.yaml", appYAML)
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, dir)
	c, err := loadRuntimeConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if c.mcp == nil || c.hooks != nil || c.workflows != nil || c.cron != nil || c.backup != nil || len(c.flows) != 0 {
		t.Fatalf("manifest load changed missing optional-file semantics: %+v", c)
	}

	captured := map[string][]byte{"app.yaml": nil, "encrypted.yaml": nil}
	contract, execution, sources, err := appMCPSourceDigests(dir, c.mcp, captured)
	if err != nil {
		t.Fatal(err)
	}
	if string(captured["app.yaml"]) != appYAML || captured["encrypted.yaml"] != nil {
		t.Fatal("expected exact reviewed app.yaml bytes and an absent encrypted.yaml")
	}
	if contract != c.mcp.ContractDigest || execution != c.mcp.ExecutionDigest || sources["app.yaml"] != c.mcp.sourceHashes["app.yaml"] {
		t.Fatal("captured authority bytes differ from the approved MCP source snapshot")
	}
	raw, _, err := parseAppConfigDocument(captured["app.yaml"])
	if err != nil {
		t.Fatal(err)
	}
	access, err := parseAccessConfig(captured["app.yaml"])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(c.group, parseGroupConfig(captured["app.yaml"])) ||
		!reflect.DeepEqual(c.scopes, parseScopes(captured["app.yaml"])) ||
		!reflect.DeepEqual(c.access, access) ||
		!reflect.DeepEqual(c.roles, parseRolesConfig(captured["app.yaml"])) ||
		!reflect.DeepEqual(c.encrypted, parseEncryptedFieldsConfig(captured["encrypted.yaml"], captured["app.yaml"])) ||
		!reflect.DeepEqual(c.design, designFromAppYAML(raw)) {
		t.Fatal("runtime authority differs from the captured reviewed bytes")
	}
}

func TestAppMCPAuthorityCaptureRejectsCaseAliases(t *testing.T) {
	for _, name := range []string{"App.yaml", "Encrypted.yaml", "Schema.prisma", "Schema.sql", "Migrations", "Hooks.yaml", "Workflows.yaml", "Cron.yaml", "Mcp.yaml", "Flows.yaml", "Flows"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			manifest, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, dir, name, "roles: {editor: '*'}")
			if _, _, err := appMCPDigests(dir, manifest); err == nil {
				t.Fatal("ambiguous authority filename accepted")
			}
		})
	}
}
