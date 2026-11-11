//go:build !cli && !windows

package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"go.yaml.in/yaml/v3"
)

// A file handler's membership_constraints and upload_tenant need the app's
// groups configuration and schema. The two validators that check that had no
// production caller, so review, mcp check and the write gate accepted such a
// tool on an app with no `groups:` at all. The strict loaders now refuse it; a
// served load keeps the connector and reports the tool, which fails closed.

func fileRequirementTool(name, handlerExtra string) string {
	return `  - name: ` + name + `
    description: Read a referenced private file.
    handler: {kind: file, operation: ingest, table: documents, file_column: file_url` + handlerExtra + `}
    input_schema:
      type: object
      additionalProperties: false
      required: [file_ref, record_id]
      properties:
        file_ref: {type: string}
        record_id: {type: string}
    output_schema:
      type: object
      additionalProperties: false
      required: [complete]
      properties:
        complete: {type: boolean}
    permissions: [files:read, documents:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [complete]}
    component: none
`
}

// fileRequirementApp writes an app whose manifest holds the given file tools
// and seals it the way a review made before these checks existed did.
func fileRequirementApp(t *testing.T, appYAML, schema string, tools ...string) (dir, manifest string) {
	t.Helper()
	dir = t.TempDir()
	writeTestFile(t, dir, "app.yaml", appYAML)
	writeTestFile(t, dir, "schema.sql", schema)
	writeTestFile(t, dir, "mcp.yaml", `version: 1
connector: {id: fixture, name: Fixture, version: '1'}
contract_digest: `+strings.Repeat("a", 64)+`
execution_digest: `+strings.Repeat("b", 64)+`
tools:
`+strings.Join(tools, "")+`resources: []
connections: []
`)
	return dir, reviewAppMCPFixture(t, dir)
}

const (
	fileRequirementNoGroups   = "site_name: Fixture\n"
	fileRequirementGroups     = "site_name: Fixture\ngroups: {table: members, key: org_id, user_field: email}\n"
	fileRequirementSchema     = "CREATE TABLE documents (id INTEGER PRIMARY KEY, file_url TEXT, user_id INTEGER);\n"
	fileRequirementFullSchema = "CREATE TABLE documents (id INTEGER PRIMARY KEY, file_url TEXT, user_id INTEGER, org_id TEXT);\nCREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, email TEXT, kind TEXT, status TEXT);\n"
	fileRequirementMembership = `mcp.yaml: tool "member_file" membership_constraints require configured groups.table, groups.key, and groups.user_field`
	fileRequirementTenant     = `mcp.yaml: tool "tenant_file" upload_tenant requires current, a file_column, and configured groups.table/key/user_field`
)

func TestAppMCPReviewRefusesFileHandlerWithUnmetGroupRequirement(t *testing.T) {
	member := fileRequirementTool("member_file", ", membership_constraints: {kind: human, status: active}")
	tenant := fileRequirementTool("tenant_file", ", upload_tenant: current")
	plain := fileRequirementTool("plain_file", "")
	for _, tc := range []struct {
		name, app, schema string
		tools             []string
		want              string // "" = accepted
		served            []string
	}{
		{name: "membership_constraints without groups", app: fileRequirementNoGroups, schema: fileRequirementSchema, tools: []string{plain, member},
			want: fileRequirementMembership, served: []string{fileRequirementMembership}},
		{name: "upload_tenant without groups", app: fileRequirementNoGroups, schema: fileRequirementSchema, tools: []string{tenant, plain},
			want: fileRequirementTenant, served: []string{fileRequirementTenant}},
		{name: "both, each tool reported", app: fileRequirementNoGroups, schema: fileRequirementSchema, tools: []string{member, plain, tenant},
			want: fileRequirementMembership, served: []string{fileRequirementMembership, fileRequirementTenant}},
		{name: "groups configured but the membership table lacks the constrained column", app: fileRequirementGroups,
			schema: "CREATE TABLE documents (id INTEGER PRIMARY KEY, file_url TEXT, org_id TEXT);\nCREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, email TEXT);\n", tools: []string{member},
			want:   `mcp.yaml: tool "member_file" membership constraint "kind" is not a canonical readable groups column`,
			served: []string{`mcp.yaml: tool "member_file" membership constraint "kind" is not a canonical readable groups column`}},
		{name: "groups configured but the source table lacks the tenant key", app: fileRequirementGroups,
			schema: "CREATE TABLE documents (id INTEGER PRIMARY KEY, file_url TEXT);\nCREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT, email TEXT);\n", tools: []string{tenant},
			want:   `mcp.yaml: tool "tenant_file" upload_tenant requires the configured tenant key on its source row and canonical groups table`,
			served: []string{`mcp.yaml: tool "tenant_file" upload_tenant requires the configured tenant key on its source row and canonical groups table`}},
		{name: "requirements met", app: fileRequirementGroups, schema: fileRequirementFullSchema, tools: []string{member, tenant, plain}},
		{name: "no requirement declared", app: fileRequirementNoGroups, schema: fileRequirementSchema, tools: []string{plain}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, manifest := fileRequirementApp(t, tc.app, tc.schema, tc.tools...)
			verdict := func(gate string, err error) {
				t.Helper()
				switch {
				case tc.want == "" && err != nil:
					t.Errorf("%s refused a manifest whose requirements are met: %v", gate, err)
				case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
					t.Errorf("%s: %v, want %q", gate, err, tc.want)
				}
			}
			_, err := loadRuntimeConfig(dir)
			verdict("strict load", err)
			verdict("mcp check", runAppMCPCLI([]string{"check", dir}, io.Discard))
			verdict("mcp inspect", runAppMCPCLI([]string{"inspect", dir, "--json"}, io.Discard))
			issue := ValidateOnWriteIn(dir, "mcp.yaml", manifest)
			if tc.want == "" && issue != "" || tc.want != "" && !strings.Contains(issue, tc.want) {
				t.Errorf("write gate: %q, want %q", issue, tc.want)
			}
			_, err = reviewAppMCPSource(dir)
			verdict("mcp review", err)
			if after, _ := os.ReadFile(filepath.Join(dir, "mcp.yaml")); tc.want != "" && string(after) != manifest {
				t.Error("a refused review rewrote mcp.yaml")
			}
			writeTestFile(t, dir, "mcp.yaml", manifest)

			// What an app already running this manifest does at its next load:
			// the connector is neither refused nor withheld, and each affected
			// tool is named.
			served, err := loadServedRuntimeConfig(dir)
			if err != nil || served.mcp == nil || served.mcpWithheld != "" {
				t.Fatalf("served load: mcp=%v withheld=%q err=%v", served != nil && served.mcp != nil, served.mcpWithheld, err)
			}
			if len(served.mcp.Tools) != len(tc.tools) {
				t.Fatalf("served load kept %d of %d tools", len(served.mcp.Tools), len(tc.tools))
			}
			if strings.Join(served.mcpToolProblems, "\n") != strings.Join(tc.served, "\n") {
				t.Errorf("served load reported %q, want %q", served.mcpToolProblems, tc.served)
			}
			for _, problem := range served.mcpToolProblems {
				if notice := appMCPToolProblemsNotice(problem); !strings.Contains(notice, problem) || !strings.Contains(notice, "the connector stays on and this tool refuses every call") {
					t.Errorf("load notice: %q", notice)
				}
			}
		})
	}
}

// The sources a strict load checks are the captured ones: an encrypted
// membership column declared in encrypted.yaml or in app.yaml is refused.
func TestAppMCPReviewRefusesEncryptedMembershipConstraintFromEitherSource(t *testing.T) {
	member := fileRequirementTool("member_file", ", membership_constraints: {kind: human}")
	const want = `mcp.yaml: tool "member_file" membership constraint "kind" cannot use an encrypted column`
	for name, sources := range map[string]map[string]string{
		"encrypted.yaml": {"app.yaml": fileRequirementGroups, "encrypted.yaml": "tables:\n  members:\n    fields: [kind]\n"},
		"app.yaml":       {"app.yaml": fileRequirementGroups + "encrypted:\n  members:\n    - {column: kind}\n"},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			for file, content := range sources {
				writeTestFile(t, dir, file, content)
			}
			writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("ab", 32)+"\n")
			writeTestFile(t, dir, "schema.sql", fileRequirementFullSchema)
			writeTestFile(t, dir, "mcp.yaml", "version: 1\nconnector: {id: fixture, name: Fixture, version: '1'}\ncontract_digest: "+strings.Repeat("a", 64)+"\nexecution_digest: "+strings.Repeat("b", 64)+"\ntools:\n"+member+"resources: []\nconnections: []\n")
			reviewAppMCPFixture(t, dir)
			if _, err := loadRuntimeConfig(dir); err == nil || !strings.Contains(err.Error(), want) {
				t.Fatalf("strict load: %v, want %q", err, want)
			}
		})
	}
}

// What such a tool does when it is called: it has always failed closed. Each
// variant is sealed and loaded the way a deployed app loads it. The same row
// and file are readable through the tool while it declares neither
// requirement, and denied while it declares one the app cannot meet; the
// served load keeps the connector either way and names the tool.
func TestAppMCPFileToolWithUnmetGroupRequirementFailsClosed(t *testing.T) {
	app, _ := appMCPFileColumnFixture(t)
	app.DB.SetMaxOpenConns(1)
	app.Group = nil // the app has no groups: in app.yaml
	if _, err := os.Stat(filepath.Join(app.Dir, "app.yaml")); !os.IsNotExist(err) {
		t.Fatalf("fixture must have no app.yaml (so no groups), stat err=%v", err)
	}
	var uid int64
	if err := app.DB.QueryRow(`SELECT user_id FROM notes WHERE id=1`).Scan(&uid); err != nil {
		t.Fatal(err)
	}
	current := "current"
	for _, tc := range []struct {
		name    string
		mutate  func(*AppMCPHandler)
		problem string
	}{
		{"no requirement", func(*AppMCPHandler) {}, ""},
		{"membership_constraints", func(h *AppMCPHandler) { h.MembershipConstraints = map[string]any{"kind": "human"} },
			`mcp.yaml: tool "ingest_file" membership_constraints require configured groups.table, groups.key, and groups.user_field`},
		{"upload_tenant", func(h *AppMCPHandler) { h.UploadTenant = &current },
			`mcp.yaml: tool "ingest_file" upload_tenant requires current, a file_column, and configured groups.table/key/user_field`},
		{"no requirement again", func(*AppMCPHandler) {}, ""},
	} {
		source, err := os.ReadFile(filepath.Join(app.Dir, "mcp.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		manifest, err := parseAppMCPManifest(source)
		if err != nil {
			t.Fatal(err)
		}
		tool := appMCPFileTool(manifest, "ingest_file")
		if tool == nil || tool.Handler.FileColumn != "file_path" {
			t.Fatal("fixture lost its exact file column binding")
		}
		tool.Handler.MembershipConstraints, tool.Handler.UploadTenant = nil, nil
		tc.mutate(&tool.Handler)
		encoded, err := yaml.Marshal(manifest)
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, app.Dir, "mcp.yaml", string(encoded))
		reviewAppMCPFixture(t, app.Dir)

		config, err := loadServedRuntimeConfig(app.Dir)
		if err != nil || config.mcp == nil || config.mcpWithheld != "" {
			t.Fatalf("%s: served load refused or withheld the connector: %v", tc.name, err)
		}
		if got := strings.Join(config.mcpToolProblems, "\n"); got != tc.problem {
			t.Fatalf("%s: served load reported %q, want %q", tc.name, got, tc.problem)
		}
		if _, err := loadRuntimeConfig(app.Dir); (err != nil) != (tc.problem != "") || err != nil && !strings.Contains(err.Error(), tc.problem) {
			t.Fatalf("%s: strict load: %v", tc.name, err)
		}
		app.MCP = config.mcp
		pair, err := createAppMCPGrant(app, uid, "", "client-fixture", grantFixtureResource, "files:read notes:read", time.Now())
		if err != nil {
			t.Fatalf("%s: group-less grant: %v", tc.name, err)
		}
		_, err = runAppMCPFileTool(context.Background(), app, snapshotAppMCPGeneration(app), pair.AccessToken, grantFixtureResource, "ingest_file", map[string]any{"file_ref": "uploads/private/source.csv", "record_id": "1"})
		var failure *appMCPResultError
		switch {
		case tc.problem == "" && err != nil:
			t.Fatalf("%s: a file tool with no group requirement did not read on an app without groups: %v", tc.name, err)
		case tc.problem != "" && (!errors.As(err, &failure) || failure.Code != "denied"):
			t.Fatalf("%s: %v, want denied", tc.name, err)
		}
	}
}
