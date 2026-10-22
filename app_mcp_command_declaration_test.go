//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestAppMCPCommandLoadAppCapturesSourceAndLeavesRoutesInert(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE work_items (id INTEGER PRIMARY KEY, title TEXT);\n")
	writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: provider-fixture-key-with-sufficient-length\n")
	source := `on: {request: {method: POST, path: /api/private-command, auth: required, transaction: true}}
` + commandFixtureForManifest
	writeTestFile(t, dir, "flows/complete_item.yaml", source)
	manifest, err := yaml.Marshal(commandManifest())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "mcp.yaml", string(manifest))
	reviewAppMCPFixture(t, dir)

	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("source-backed loadApp rejected command declaration: %v", err)
	}
	t.Cleanup(app.Shutdown)
	if len(app.Flows) != 1 || app.Flows[0].Command == nil || app.Flows[0].Source != "flows/complete_item.yaml" || app.Flows[0].sourceHash != hashBytesSHA256([]byte(source)) {
		t.Fatalf("loaded flow lost captured declaration identity: %+v", app.Flows)
	}
	if string(app.sourceFiles["flows/complete_item.yaml"]) != source {
		t.Fatal("app source capture differs from reviewed command bytes")
	}
	if appMCPReadTool(app, "complete_item") != nil || appMCPSupportedScopes(app.MCP) != "_none_:read" {
		t.Fatal("private command entered B1 public tool or scope surface")
	}

	mux := http.NewServeMux()
	RegisterFlows(mux, app, app.Flows)
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/api/private-command", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("private command declaration became an ordinary/public HTTP route: %d %s", recorder.Code, recorder.Body.String())
	}
	if err := executeFlowHTTP(app, &app.Flows[0], httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/api/private-command", nil)); err == nil {
		t.Fatal("direct ordinary HTTP execution accepted command declaration")
	}
	if err := executeFlowJob(app, "complete_item", map[string]any{}); err == nil {
		t.Fatal("direct ordinary job execution accepted command declaration")
	}
}

func TestAppMCPCommandGenerationDeepCopiesDeclaration(t *testing.T) {
	max := 50
	previewMax := 30
	original := &FlowCommand{
		Version:        1,
		PreparedSchema: &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{"nested": {Type: "object", Properties: map[string]*AppMCPSchema{"value": {Type: "string", MaxLength: &max}}}}},
		Writes:         []string{"work_items"},
		Dependencies:   []FlowCommandDependency{{Name: "item", Table: "work_items", Query: "SELECT id FROM work_items", Params: map[string]FlowCommandParamRef{"id": {Kind: "intent_path", Path: "item.id"}}, MaxRows: 2}},
		PreviewSchema:  &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{"preview": {Type: "string", MaxLength: &previewMax}}},
		Prepare:        FlowCommandPhase{Steps: []FlowStep{{Type: "if", Steps: []FlowStep{{Type: "set", Set: map[string]string{"local": "old"}}}}}},
		Apply: FlowCommandPhase{Steps: []FlowStep{
			{Type: "compute", Compute: &FlowCompute{Module: "task", Function: "apply", Args: map[string]any{"nested": map[string]any{"v": "old"}}}},
			{Type: "if", SQLParams: map[string]string{"id": "old"}, CommandSQLParams: map[string]FlowCommandParamRef{"id": {Kind: "phase_path", Path: "stored.id"}}, Steps: []FlowStep{{Type: "sql", SQLParams: map[string]string{"id": "old"}, CommandSQLParams: map[string]FlowCommandParamRef{"id": {Kind: "phase_path", Path: "stored.id"}}}}, ElseSteps: []FlowStep{{Type: "respond", Respond: &FlowRespond{JSON: map[string]any{"status": "old"}, JSONArray: []any{"old"}}}}},
		}},
		Readback: FlowCommandPhase{Steps: []FlowStep{{Type: "respond", Respond: &FlowRespond{JSON: map[string]any{"result": "old"}, JSONArray: []any{"old"}}}}},
		Request:  &FlowCommandRequest{Method: "POST", Path: "/api/private-command", AuthRequired: true, Transaction: true, RateLimit: &FlowRateLimit{Rate: 5, Scope: "user"}},
	}
	flow := Flow{Name: "complete_item", Source: "flows/complete_item.yaml", sourceHash: "fixed-source-hash", Trigger: FlowTrigger{Type: "command"}, Command: original}
	generation := newAppMCPRuntimeGeneration(&App{}, nil, nil, nil, nil, nil, nil, nil, nil, nil, []Flow{flow}, nil, nil, nil, nil, nil, nil, nil, nil)
	captured := generation.flows[0].Command
	original.PreparedSchema.Properties["nested"].Properties["value"].MaxLength = nil
	original.PreviewSchema.Properties["preview"].MaxLength = nil
	original.Writes[0] = "other"
	original.Dependencies[0].Params["id"] = FlowCommandParamRef{Kind: "actor_id"}
	original.Apply.Steps[0].Compute.Args.(map[string]any)["nested"].(map[string]any)["v"] = "changed"
	original.Apply.Steps[1].SQLParams["id"] = "changed"
	original.Apply.Steps[1].CommandSQLParams["id"] = FlowCommandParamRef{Kind: "actor_id"}
	original.Apply.Steps[1].Steps[0].SQLParams["id"] = "changed"
	original.Apply.Steps[1].Steps[0].CommandSQLParams["id"] = FlowCommandParamRef{Kind: "selected_tenant"}
	original.Apply.Steps[1].ElseSteps[0].Respond.JSON["status"] = "changed"
	original.Apply.Steps[1].ElseSteps[0].Respond.JSONArray[0] = "changed"
	original.Prepare.Steps[0].Steps[0].Set["local"] = "changed"
	original.Readback.Steps[0].Respond.JSONArray[0] = "changed"
	original.Request.RateLimit.Rate = 99
	if captured.PreparedSchema.Properties["nested"].Properties["value"].MaxLength == nil || *captured.PreparedSchema.Properties["nested"].Properties["value"].MaxLength != 50 {
		t.Fatal("nested schema aliased the source")
	}
	if captured.PreviewSchema.Properties["preview"].MaxLength == nil || *captured.PreviewSchema.Properties["preview"].MaxLength != 30 {
		t.Fatal("preview schema aliased the source")
	}
	if captured.Writes[0] != "work_items" || captured.Dependencies[0].Params["id"].Kind != "intent_path" {
		t.Fatal("inventory or selector map aliased the source")
	}
	if captured.Apply.Steps[0].Compute.Args.(map[string]any)["nested"].(map[string]any)["v"] != "old" || captured.Request.RateLimit.Rate != 5 {
		t.Fatal("phase args or route metadata aliased the source")
	}
	if captured.Apply.Steps[1].SQLParams["id"] != "old" || captured.Apply.Steps[1].CommandSQLParams["id"].Kind != "phase_path" || captured.Apply.Steps[1].CommandSQLParams["id"].Path != "stored.id" || captured.Apply.Steps[1].Steps[0].CommandSQLParams["id"].Kind != "phase_path" || captured.Apply.Steps[1].Steps[0].CommandSQLParams["id"].Path != "stored.id" || captured.Apply.Steps[1].Steps[0].SQLParams["id"] != "old" || captured.Apply.Steps[1].ElseSteps[0].Respond.JSON["status"] != "old" || captured.Apply.Steps[1].ElseSteps[0].Respond.JSONArray[0] != "old" {
		t.Fatal("nested phase lists, typed refs, or response maps/arrays aliased the source")
	}
	if original.Apply.Steps[1].CommandSQLParams["id"].Kind != "actor_id" || original.Apply.Steps[1].Steps[0].CommandSQLParams["id"].Kind != "selected_tenant" || captured.Apply.Steps[1].CommandSQLParams["id"].Path != "stored.id" || captured.Apply.Steps[1].Steps[0].CommandSQLParams["id"].Path != "stored.id" {
		t.Fatal("source and captured typed-reference maps are not independent")
	}
	if captured.Prepare.Steps[0].Steps[0].Set["local"] != "old" || captured.Readback.Steps[0].Respond.JSONArray[0] != "old" {
		t.Fatal("prepare or readback nested phase data aliased the source")
	}
	if generation.flows[0].Source != "flows/complete_item.yaml" || generation.flows[0].sourceHash != "fixed-source-hash" {
		t.Fatal("captured flow source identity changed")
	}
}

func TestAppMCPCommandBindingIsPrivateAndUnique(t *testing.T) {
	command, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(commandFixtureForManifest), map[string]bool{"work_items": true})
	if err != nil {
		t.Fatal(err)
	}
	manifest := commandManifest()
	if err := validateAppMCPBindingsForTables(manifest, []Flow{command}, map[string]bool{"work_items": true}, nil); err != nil {
		t.Fatalf("valid command binding rejected: %v", err)
	}
	if err := validateAppMCPBindingsForTables(manifest, []Flow{command, command}, map[string]bool{"work_items": true}, nil); err == nil {
		t.Fatal("duplicate command binding accepted")
	}
	flowCall := *manifest
	flowCall.Tools = append([]AppMCPTool(nil), manifest.Tools...)
	flowCall.Tools[0].Handler.Kind = "native"
	flowCall.Tools[0].Handler.Operation = "flow.call"
	if err := validateAppMCPBindingsForTables(&flowCall, []Flow{command}, map[string]bool{"work_items": true}, nil); err == nil {
		t.Fatal("B1 flow.call must not bind a command")
	}
	unbound := command
	unbound.Name = "other_command"
	if err := validateAppMCPBindingsForTables(manifest, []Flow{command, unbound}, map[string]bool{"work_items": true}, nil); err == nil {
		t.Fatal("unbound command alongside a valid binding must be rejected")
	}
}

func TestAppMCPCommandPhaseReferencesUseTheirOwnSchema(t *testing.T) {
	input := &AppMCPSchema{Type: "object", Required: []string{"intent"}, Properties: map[string]*AppMCPSchema{"intent": {Type: "object", Required: []string{"lookup"}, Properties: map[string]*AppMCPSchema{"lookup": {Type: "string"}}}}}
	prepared := &AppMCPSchema{Type: "object", Required: []string{"stored"}, Properties: map[string]*AppMCPSchema{"stored": {Type: "object", Required: []string{"id"}, Properties: map[string]*AppMCPSchema{"id": {Type: "integer"}}}}}
	step := func(kind, path string) []FlowStep {
		return []FlowStep{{Type: "sql", SQLParams: map[string]string{"id": "lossy-normalized-value"}, CommandSQLParams: map[string]FlowCommandParamRef{"id": {Kind: kind, Path: path}}}}
	}
	command := &FlowCommand{PreparedSchema: prepared, Writes: []string{"work_items"}, Prepare: FlowCommandPhase{Steps: step("phase_path", "intent.lookup")}, Apply: FlowCommandPhase{Steps: step("phase_path", "stored.id")}, Readback: FlowCommandPhase{Steps: []FlowStep{{Type: "sql", SQLParams: map[string]string{"actor": "flattened", "tenant": "flattened"}, CommandSQLParams: map[string]FlowCommandParamRef{"actor": {Kind: "actor_id"}, "tenant": {Kind: "selected_tenant"}}}}}}
	tool := commandManifest().Tools[0]
	tool.InputSchema = input
	if err := validateAppMCPCommandDescriptor(tool, command, nil, map[string]bool{"work_items": true}, nil); err != nil {
		t.Fatalf("distinct input/prepared refs or raw actor references rejected: %v", err)
	}
	command.Prepare.Steps = step("phase_path", "stored.id")
	if err := validateAppMCPCommandDescriptor(tool, command, nil, map[string]bool{"work_items": true}, nil); err == nil {
		t.Fatal("prepare reference resolved against prepared arguments")
	}
	command.Prepare.Steps = step("phase_path", "intent.lookup")
	command.Apply.Steps = step("phase_path", "intent.lookup")
	if err := validateAppMCPCommandDescriptor(tool, command, nil, map[string]bool{"work_items": true}, nil); err == nil {
		t.Fatal("apply reference resolved against original intent")
	}
}

func TestAppMCPCommandAllowsLeastPrivilegeMixedReadWriteScopes(t *testing.T) {
	command, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(commandFixtureForManifest), map[string]bool{"work_items": true})
	if err != nil {
		t.Fatal(err)
	}
	manifest := commandManifest()
	manifest.Tools[0].Permissions = []string{"projects:read", "work_items:write"}
	if err := validateAppMCPBindingsForTables(manifest, []Flow{command}, map[string]bool{"work_items": true, "projects": true}, nil); err != nil {
		t.Fatalf("mixed least-privilege scopes rejected: %v", err)
	}
	manifest.Tools[0].Permissions = []string{"projects:read"}
	if err := validateAppMCPBindingsForTables(manifest, []Flow{command}, map[string]bool{"work_items": true, "projects": true}, nil); err == nil {
		t.Fatal("command without a declared write scope accepted")
	}
	for _, permissions := range [][]string{{"work_items"}, {"work_items:"}, {"work_items:execute"}, {"projects:write"}} {
		manifest.Tools[0].Permissions = permissions
		if err := validateAppMCPBindingsForTables(manifest, []Flow{command}, map[string]bool{"work_items": true, "projects": true}, nil); err == nil {
			t.Fatalf("missing, unsupported, or unrelated write permission accepted: %v", permissions)
		}
	}
	for _, permissions := range [][]string{{"work_items:write", "work_items:write"}, {"work_items:write", "*:read"}} {
		if err := validateFlowPermissions(permissions); err == nil {
			t.Fatalf("duplicate or wildcard permissions accepted: %v", permissions)
		}
	}
	manifest.Tools[0].Permissions = []string{"missing:read", "work_items:write"}
	if err := validateAppMCPBindingsForTables(manifest, []Flow{command}, map[string]bool{"work_items": true}, nil); err == nil {
		t.Fatal("unknown read resource accepted")
	}
}

func TestAppMCPCommandNamesRejectAuthorityAliases(t *testing.T) {
	for _, name := range []string{"user", "user.id", "user_group_id", "params", "steps", "operation", "internal", "_private"} {
		if commandLocalName(name) {
			t.Fatalf("unsafe local name %q accepted", name)
		}
	}
	if !commandLocalName("lookup_result") {
		t.Fatal("ordinary local name rejected")
	}
	manifest := commandManifest()
	manifest.Tools[0].InputSchema.Properties["user_group_id"] = &AppMCPSchema{Type: "string"}
	if err := validateAppMCPCommandDescriptor(manifest.Tools[0], &FlowCommand{PreparedSchema: &AppMCPSchema{Type: "object"}, Writes: []string{"work_items"}}, nil, map[string]bool{"work_items": true}, nil); err == nil {
		t.Fatal("flattened identity alias in manifest input accepted")
	}
}

func TestAppMCPCommandSchemaNameGuardReachesNestedArrayItems(t *testing.T) {
	valid := &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{
		"groups": {Type: "array", MaxItems: intPointer(4), Items: &AppMCPSchema{Type: "array", MaxItems: intPointer(4), Items: &AppMCPSchema{Type: "object", Properties: map[string]*AppMCPSchema{"label": {Type: "string"}}}}},
	}}
	if err := validateCommandSchemaNames(valid); err != nil {
		t.Fatalf("bounded nested array input rejected: %v", err)
	}
	bad := cloneAppMCPSchema(valid)
	bad.Properties["groups"].Items.Items.Properties["user_group_id"] = &AppMCPSchema{Type: "string"}
	if err := validateCommandSchemaNames(bad); err == nil {
		t.Fatal("reserved identity alias in nested array object accepted")
	}
}

func TestAppMCPCommandLoadRejectsUnboundCommandWithoutManifest(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE work_items (id INTEGER PRIMARY KEY, title TEXT);\n")
	writeTestFile(t, dir, "flows/complete_item.yaml", commandFixture)
	if _, err := loadRuntimeConfig(dir); err == nil {
		t.Fatal("command without mcp.yaml binding accepted")
	}
	ordinary := "on: {request: {method: POST, path: /api/ordinary, auth: required}}\njobs:\n  first: {steps: [{run: respond, with: {status: 200, body: ok}}]}\n  second: {steps: [{run: respond, with: {status: 200, body: ok}}]}\n"
	writeTestFile(t, dir, "flows/complete_item.yaml", ordinary)
	if _, err := loadRuntimeConfig(dir); err != nil {
		t.Fatalf("ordinary no-manifest two-job flow rejected: %v", err)
	}
}

func TestAppMCPCommandTaskAndRoadmapSourcesCaptureBoundedLoopsAndCompute(t *testing.T) {
	for _, shape := range []struct {
		field, alias, module, function string
	}{{"tasks", "task", "task/prepare", "prepareTask"}, {"milestones", "milestone", "roadmap/prepare", "prepareMilestone"}} {
		t.Run(shape.field, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "schema.sql", "CREATE TABLE work_items (id INTEGER PRIMARY KEY, owner_id INTEGER, org_id TEXT, status TEXT);\n")
			writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: provider-fixture-key-with-sufficient-length\n")
			source := replaceCommandTextOnce(t, commandFixtureForManifest,
				"properties: {id: {type: string, maxLength: 64}}",
				"properties: {id: {type: integer, minimum: 1, maximum: 9007199254740991}}")
			jobsAt := strings.Index(source, "jobs:\n")
			if jobsAt < 0 || strings.Count(source, "jobs:\n") != 1 {
				t.Fatal("command fixture jobs boundary missing or ambiguous")
			}
			source = source[:jobsAt] +
				"jobs:\n" +
				"  prepare:\n    steps:\n" +
				"      - for_each: '${{ params.arguments." + shape.field + " }}'\n        as: " + shape.alias + "\n        steps:\n          - run: set\n            with: {local_title: '${{ params." + shape.alias + " }}'}\n" +
				"      - run: compute\n        with: {module: " + shape.module + ", function: " + shape.function + ", args: '${{ params.arguments.id }}'}\n" +
				"      - id: item\n        run: sql\n        with:\n          query: SELECT id FROM work_items WHERE id = :id AND owner_id = :actor AND org_id = :tenant\n          params: {id: '${{ params.arguments.id }}', actor: '${{ user.id }}', tenant: '${{ user.group_id }}'}\n" +
				"      - run: respond\n        with: {status: 200, json: {arguments: '${{ params }}', preview: '${{ steps.item.outputs }}'}}\n" +
				"  apply:\n    steps:\n      - run: sql\n        expect_rows: '>0'\n        with:\n          query: UPDATE work_items SET status = 'done' WHERE id = :id AND owner_id = :actor AND org_id = :tenant\n          params: {id: '${{ params.arguments.id }}', actor: '${{ user.id }}', tenant: '${{ user.group_id }}'}\n      - run: respond\n        with: {status: 200, json: {ok: true}}\n" +
				"  readback:\n    steps:\n      - id: item\n        run: sql\n        with:\n          query: SELECT id FROM work_items WHERE id = :id AND owner_id = :actor AND org_id = :tenant\n          params: {id: '${{ params.arguments.id }}', actor: '${{ user.id }}', tenant: '${{ user.group_id }}'}\n      - run: respond\n        with: {status: 200, json: {ok: true}}\n"

			if source == commandFixtureForManifest || !strings.Contains(source, shape.module) {
				t.Fatal("source fixture did not install the intended task or milestone phases")
			}
			flowSource := "on: {request: {method: POST, path: /api/private-command, auth: required, transaction: true}}\n" + source
			writeTestFile(t, dir, "flows/complete_item.yaml", flowSource)
			manifest := commandManifest()
			inputArgs := manifest.Tools[0].InputSchema.Properties["arguments"]
			inputArgs.Properties[shape.field] = &AppMCPSchema{Type: "array", Items: &AppMCPSchema{Type: "string", MaxLength: intPointer(128)}, MinItems: intPointer(1), MaxItems: intPointer(32)}
			inputArgs.Required = append(inputArgs.Required, shape.field)
			manifestBytes, err := yaml.Marshal(manifest)
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, dir, "mcp.yaml", string(manifestBytes))
			writeTestFile(t, dir, "static/"+shape.module+".ts", "export function "+shape.function+"() { return {}; }\n")
			reviewAppMCPFixture(t, dir)
			app, err := loadApp(dir)
			if err != nil {
				t.Fatalf("source-backed %s command load failed: %v", shape.field, err)
			}
			t.Cleanup(app.Shutdown)
			generation := snapshotAppMCPGeneration(app)
			var captured *Flow
			for i := range generation.flows {
				if generation.flows[i].Name == "complete_item" {
					captured = &generation.flows[i]
				}
			}
			if captured == nil || captured.Command == nil || generation.manifest.Tools[0].InputSchema.Properties["arguments"].Properties["id"].Type != "string" || captured.Command.PreparedSchema.Properties["arguments"].Properties["id"].Type != "integer" {
				t.Fatal("source-loaded generation lost distinct original and prepared argument schemas")
			}
			if string(generation.sourceFiles["static/"+shape.module+".ts"]) == "" || len(captured.Command.Prepare.ComputeModules) != 1 || captured.Command.Prepare.ComputeModules[0] != shape.module {
				t.Fatal("source-loaded generation lost its compute module")
			}
			inputItems := generation.manifest.Tools[0].InputSchema.Properties["arguments"].Properties[shape.field]
			if inputItems.MaxItems == nil || *inputItems.MaxItems != 32 || len(captured.Command.Prepare.Steps) < 4 || captured.Command.Prepare.Steps[0].Type != "for_each" || captured.Command.Prepare.Steps[0].ForAs != shape.alias {
				t.Fatal("source-loaded generation lost bounded task or milestone loop metadata")
			}
			for phaseName, phase := range map[string]FlowCommandPhase{"prepare": captured.Command.Prepare, "apply": captured.Command.Apply, "readback": captured.Command.Readback} {
				var sqlStep *FlowStep
				for i := range phase.Steps {
					if phase.Steps[i].Type == "sql" {
						sqlStep = &phase.Steps[i]
						break
					}
				}
				if sqlStep == nil || len(sqlStep.CommandSQLParams) != 3 || sqlStep.CommandSQLParams["id"].Kind != "phase_path" || sqlStep.CommandSQLParams["id"].Path != "arguments.id" || sqlStep.CommandSQLParams["actor"].Kind != "actor_id" || sqlStep.CommandSQLParams["tenant"].Kind != "selected_tenant" {
					t.Fatalf("source-loaded %s typed SQL bindings were lost: %+v", phaseName, sqlStep)
				}
			}
		})
	}
}

func intPointer(v int) *int { return &v }

const commandFixtureForManifest = `command:
  version: 1
  prepared_schema: {type: object, additionalProperties: false, properties: {arguments: {type: object, additionalProperties: false, properties: {id: {type: string, maxLength: 64}}, required: [id]}}, required: [arguments]}
  preview_schema: {type: object, additionalProperties: false, properties: {preview: {type: string, maxLength: 128}}, required: [preview]}
  writes: [work_items]
  dependencies: [{name: item, table: work_items, query: "SELECT id FROM work_items WHERE id = :id", params: {id: "${{ params.arguments.id }}"}, max_rows: 10}]
jobs:
  prepare: {steps: [{run: respond, with: {status: 200, json: {arguments: "${{ params }}", preview: {preview: ready}}}}]}
  apply: {steps: [{run: respond, with: {status: 200, json: {ok: true}}}]}
  readback: {steps: [{run: respond, with: {status: 200, json: {ok: true}}}]}
`

func commandManifest() *AppMCPManifest {
	closed := false
	max := 64
	input := &AppMCPSchema{Type: "object", AdditionalProperties: &closed, Properties: map[string]*AppMCPSchema{"arguments": {Type: "object", AdditionalProperties: &closed, Properties: map[string]*AppMCPSchema{"id": {Type: "string", MaxLength: &max}}, Required: []string{"id"}}}, Required: []string{"arguments"}}
	output := &AppMCPSchema{Type: "object", AdditionalProperties: &closed, Properties: map[string]*AppMCPSchema{"ok": {Type: "boolean"}}, Required: []string{"ok"}}
	return &AppMCPManifest{Version: 1, Connector: AppMCPIdentity{ID: "fixture-app", Name: "Fixture App", Version: "1"}, ContractDigest: stringsOfZero(64), ExecutionDigest: stringsOfZero(64), sourceHashes: map[string]string{}, Tools: []AppMCPTool{{Name: "complete_item", Description: "Complete one item", Handler: AppMCPHandler{Kind: "flow", Operation: "command", Flow: "complete_item"}, InputSchema: input, OutputSchema: output, Permissions: []string{"work_items:write"}, Effect: "write", Approval: "first_party", Idempotency: "operation", Reconciliation: "authoritative_readback", Output: AppMCPProjection{Include: []string{"ok"}}, Component: "none"}}}
}
func stringsOfZero(n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += "0"
	}
	return out
}
