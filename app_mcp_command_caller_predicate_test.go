//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// An approved command is not checked against its table's access rule, so a
// command whose SQL matches rows with no binding from the actor lets every
// holder of its permission change every such row. Review, check and inspect
// say so as a warning; nothing is refused.

const (
	callerFixtureDependency = "      query: SELECT id FROM work_items WHERE id = :id\n      params: {id: '${{ params.arguments.id }}'}\n"
	callerFixturePrepare    = "          query: SELECT id FROM work_items WHERE id = :id\n          params: {id: '${{ params.arguments.id }}'}\n      - run: respond\n        with:\n          status: 200\n          json: {arguments:"
	callerFixtureApply      = "          query: UPDATE work_items SET status = 'done' WHERE id = :id\n          params: {id: '${{ params.arguments.id }}'}\n"
)

// callerFixtureWith swaps one block of commandFixture (flows_command_test.go):
// a command that updates one work item by an id the caller supplies.
func callerFixtureWith(t *testing.T, old, replacement string) string {
	t.Helper()
	if strings.Count(commandFixture, old) < 1 {
		t.Fatalf("commandFixture no longer holds %q", old)
	}
	return strings.Replace(commandFixture, old, replacement, 1)
}

func callerFixtureApplySQL(t *testing.T, query, params string) string {
	return callerFixtureWith(t, callerFixtureApply, "          query: \""+query+"\"\n          params: "+params+"\n")
}

func callerPredicateWrites(t *testing.T, source string, hooks *HookConfig, workflows *WorkflowConfig) []commandUnboundWrite {
	t.Helper()
	flow, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(source), map[string]bool{"work_items": true, "audit_notes": true})
	if err != nil {
		t.Fatalf("fixture does not compile: %v\n%s", err, source)
	}
	return appMCPCommandCallerUnboundWrites(flow, hooks, workflows)
}

func TestCommandCallerPredicateWarnsOnlyWithoutACallerBinding(t *testing.T) {
	idOnly := "{id: '${{ params.arguments.id }}'}"
	cases := []struct {
		name, source string
		want         []commandUnboundWrite
	}{
		{"unbound update", commandFixture, []commandUnboundWrite{{"update", "work_items"}}},
		{"unbound delete", callerFixtureApplySQL(t, "DELETE FROM work_items WHERE id = :id", idOnly), []commandUnboundWrite{{"delete", "work_items"}}},
		{"unbound insert from a table", callerFixtureApplySQL(t, "INSERT INTO work_items (id, status) SELECT id || '-copy', status FROM work_items WHERE id = :id", idOnly), []commandUnboundWrite{{"insert", "work_items"}}},
		{"bound by user id", callerFixtureApplySQL(t, "UPDATE work_items SET status = 'done' WHERE id = :id AND user_id = :actor", "{id: '${{ params.arguments.id }}', actor: '${{ user.id }}'}"), nil},
		{"bound by tenant", callerFixtureApplySQL(t, "UPDATE work_items SET status = 'done' WHERE id = :id AND org_id = :tenant", "{id: '${{ params.arguments.id }}', tenant: '${{ user.group_id }}'}"), nil},
		{"bound by email", callerFixtureApplySQL(t, "DELETE FROM work_items WHERE id = :id AND owner_email = :email", "{id: '${{ params.arguments.id }}', email: '${{ user.email }}'}"), nil},
		{"bound by role", callerFixtureApplySQL(t, "UPDATE work_items SET status = 'done' WHERE id = :id AND :role = 'manager'", "{id: '${{ params.arguments.id }}', role: '${{ user.role }}'}"), nil},
		{"bound in prepare", callerFixtureWith(t, callerFixturePrepare,
			"          query: SELECT id FROM work_items WHERE id = :id AND user_id = :actor\n          params: {id: '${{ params.arguments.id }}', actor: '${{ user.id }}'}\n      - run: respond\n        with:\n          status: 200\n          json: {arguments:"), nil},
		{"bound by a dependency", callerFixtureWith(t, callerFixtureDependency,
			"      query: SELECT id FROM work_items WHERE id = :id AND org_id = :tenant\n      params: {id: '${{ params.arguments.id }}', tenant: '${{ user.group_id }}'}\n"), nil},
		{"read-only apply", callerFixtureApplySQL(t, "SELECT id FROM work_items WHERE id = :id", idOnly), nil},
		{"plain insert", callerFixtureApplySQL(t, "INSERT INTO work_items (id, status) VALUES (:id, 'new')", idOnly), nil},
		{"insert unless it exists", callerFixtureApplySQL(t, "INSERT INTO work_items (id, status) SELECT :id, 'new' WHERE NOT EXISTS (SELECT 1 FROM work_items WHERE id = :id)", idOnly), nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := callerPredicateWrites(t, tc.source, nil, nil)
			if len(got) != len(tc.want) || len(got) == 1 && got[0] != tc.want[0] {
				t.Fatalf("unbound writes = %v, want %v", got, tc.want)
			}
		})
	}
}

// A write inside an if branch is found, and a binding inside one counts.
func TestCommandCallerPredicateReadsNestedSteps(t *testing.T) {
	nested := func(params, where string) string {
		return callerFixtureWith(t, "      - run: sql\n        expect_rows: \">0\"\n        with:\n"+callerFixtureApply,
			"      - id: found\n        run: sql\n        with:\n          query: SELECT count(*) AS n FROM work_items WHERE id = :id\n          params: {id: '${{ params.arguments.id }}'}\n"+
				"      - if: ${{ steps.found.outputs.first.n }} == 1\n        steps:\n          - run: sql\n            with:\n              query: DELETE FROM work_items WHERE id = :id"+where+"\n              params: "+params+"\n")
	}
	if got := callerPredicateWrites(t, nested("{id: '${{ params.arguments.id }}'}", ""), nil, nil); len(got) != 1 || got[0] != (commandUnboundWrite{"delete", "work_items"}) {
		t.Fatalf("a nested unbound delete was not found: %v", got)
	}
	if got := callerPredicateWrites(t, nested("{id: '${{ params.arguments.id }}', actor: '${{ user.id }}'}", " AND user_id = :actor"), nil, nil); len(got) != 0 {
		t.Fatalf("a nested actor binding was not counted: %v", got)
	}
}

// Before-hooks and workflow guards run inside the command with the actor, so
// one that reads the caller may be the predicate.
func TestCommandCallerPredicateLeavesHookAndWorkflowGuardedWritesAlone(t *testing.T) {
	warns := func(hooks *HookConfig, workflows *WorkflowConfig) bool {
		return len(callerPredicateWrites(t, commandFixture, hooks, workflows)) == 1
	}
	callerHook := []Hook{{SQL: "SELECT 'not yours' AS error WHERE (SELECT user_id FROM work_items WHERE id = '{{id}}') <> {{user_id}}"}}
	if warns(&HookConfig{BeforeUpdate: map[string][]Hook{"work_items": callerHook}}, nil) {
		t.Fatal("a before_update hook that reads the caller did not lift the warning")
	}
	if warns(&HookConfig{BeforeUpdate: map[string][]Hook{"work_items": {{SQL: "SELECT 'closed' AS error", When: "old_user_id != user_id"}}}}, nil) {
		t.Fatal("a before_update when: that reads the caller did not lift the warning")
	}
	if !warns(&HookConfig{BeforeUpdate: map[string][]Hook{"work_items": {{SQL: "SELECT 'too long' AS error", When: "length(status) > 20"}}}}, nil) {
		t.Fatal("a before_update hook that never reads the caller lifted the warning")
	}
	if !warns(&HookConfig{BeforeDelete: map[string][]Hook{"work_items": callerHook}, BeforeUpdate: map[string][]Hook{"audit_notes": callerHook}}, nil) {
		t.Fatal("a hook of another action or table lifted the warning")
	}

	workflow := func(transitions map[string]map[string]Transition, field string) *WorkflowConfig {
		return &WorkflowConfig{Workflows: map[string]*Workflow{"items": {Name: "items", Table: "work_items", Field: field, Transitions: transitions}}}
	}
	guarded := map[string]map[string]Transition{"open": {"done": {Role: "manager"}}, "done": {"open": {When: "old_user_id = user_id"}}}
	if warns(nil, workflow(guarded, "status")) {
		t.Fatal("a state change whose every transition is guarded still warned")
	}
	if !warns(nil, workflow(map[string]map[string]Transition{"open": {"done": {Role: "manager"}}, "done": {"open": {}}}, "status")) {
		t.Fatal("a workflow with one open transition lifted the warning")
	}
	if !warns(nil, workflow(guarded, "stage")) {
		t.Fatal("a workflow on a column the statement never names lifted the warning")
	}
}

func TestCommandCallerPredicateWarningSaysWhatToAdd(t *testing.T) {
	flow, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(commandFixture), map[string]bool{"work_items": true})
	if err != nil {
		t.Fatal(err)
	}
	flow.Source = "flows/complete_item.yaml"
	got := appMCPCommandCallerPredicateWarning(flow, nil, nil)
	for _, want := range []string{
		`flows/complete_item.yaml: command "complete_item" has no predicate tied to the caller`,
		"UPDATE work_items", "${{ user.id }}", "${{ user.group_id }}", "`access:` rule",
		"AND user_id = :actor", "advice only", "benmore docs connector.caller_predicate",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("warning lacks %q:\n%s", want, got)
		}
	}
	bound := callerFixtureApplySQL(t, "UPDATE work_items SET status = 'done' WHERE id = :id AND user_id = :actor", "{id: '${{ params.arguments.id }}', actor: '${{ user.id }}'}")
	flow, err = parseFlowCommandFile("flows/complete_item.yaml", []byte(bound), map[string]bool{"work_items": true})
	if err != nil {
		t.Fatal(err)
	}
	if got := appMCPCommandCallerPredicateWarning(flow, nil, nil); got != "" {
		t.Fatalf("a bound command warned: %s", got)
	}
}

func callerPredicateWarnings(warnings []string) (found []string) {
	for _, warning := range warnings {
		if strings.Contains(warning, "has no predicate tied to the caller") {
			found = append(found, warning)
		}
	}
	return found
}

func callerPredicateFindings(report CheckReport) (found []CheckFinding) {
	for _, finding := range report.Findings {
		if strings.Contains(finding.Message, "has no predicate tied to the caller") {
			found = append(found, finding)
		}
	}
	return found
}

// The same advice reaches every surface, and it is only advice: review binds
// the source with the digests it would have written anyway, the write gate
// accepts the file, and the check reports a warning with the rule's address.
func TestCommandCallerPredicateIsAdviceOnEveryReviewSurface(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "schema.sql", "CREATE TABLE members(id INTEGER PRIMARY KEY, org_id TEXT, email TEXT);\nCREATE TABLE work_items(id TEXT PRIMARY KEY, status TEXT, user_id INTEGER, org_id TEXT);\n")
	writeTestFile(t, root, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\n")
	writeTestFile(t, root, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("ab", 32)+"\n")
	// The manifest fixture's command (app_mcp_command_declaration_test.go),
	// with an apply that updates the row the caller names.
	const noApply = "  apply: {steps: [{run: respond, with: {status: 200, json: {ok: true}}}]}\n"
	applyWith := func(query, params string) string {
		if !strings.Contains(commandFixtureForManifest, noApply) {
			t.Fatal("commandFixtureForManifest no longer holds the apply line this test replaces")
		}
		return "on: {request: {method: POST, path: /api/private-command, auth: required, transaction: true}}\n" +
			strings.Replace(commandFixtureForManifest, noApply, "  apply:\n    steps:\n      - run: sql\n        with:\n          query: "+query+"\n          params: "+params+"\n      - run: respond\n        with: {status: 200, json: {ok: true}}\n", 1)
	}
	unbound := applyWith("UPDATE work_items SET status = 'done' WHERE id = :id", "{id: '${{ params.arguments.id }}'}")
	writeTestFile(t, root, "flows/complete_item.yaml", unbound)
	manifest, err := yaml.Marshal(commandManifest())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, root, "mcp.yaml", string(manifest))

	if refusal := ValidateOnWriteIn(root, "flows/complete_item.yaml", unbound); refusal != "" {
		t.Fatalf("the write gate refused an unbound command: %s", refusal)
	}
	reviewed, err := reviewAppMCPSource(root)
	if err != nil {
		t.Fatalf("review refused an unbound command: %v", err)
	}
	if got := callerPredicateWarnings(reviewed.Warnings); len(got) != 1 || !strings.Contains(got[0], "flows/complete_item.yaml") || !strings.Contains(got[0], "UPDATE work_items") {
		t.Fatalf("mcp review warnings = %v", reviewed.Warnings)
	}
	// The digests review wrote are the ones the source alone determines.
	written, err := os.ReadFile(filepath.Join(root, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	bound, err := parseAppMCPManifest(written)
	if err != nil {
		t.Fatal(err)
	}
	contract, execution, err := appMCPDigests(root, bound)
	if err != nil || contract != reviewed.ContractDigest || execution != reviewed.ExecutionDigest || bound.ContractDigest != contract || bound.ExecutionDigest != execution {
		t.Fatalf("the warning moved a digest: %v %q %q", err, contract, execution)
	}
	checked, err := inspectAppMCPSource(root)
	if err != nil || !checked.SourceValid || len(callerPredicateWarnings(checked.Warnings)) != 1 {
		t.Fatalf("mcp check after review: %v %+v", err, checked)
	}

	for _, writtenPath := range []string{"", "flows/complete_item.yaml", "mcp.yaml", "schema.sql"} {
		report := RunSourceCheck(root, writtenPath)
		got := callerPredicateFindings(report)
		if len(got) != 1 || got[0].Severity != "warning" || got[0].Source != "mcp_connector" || got[0].File != "flows/complete_item.yaml" || got[0].Docs != appMCPCommandCallerPredicateDocs {
			t.Fatalf("check after writing %q: %+v", writtenPath, report.Findings)
		}
		if report.Errors != 0 {
			t.Fatalf("check after writing %q counts an error: %+v", writtenPath, report.Findings)
		}
	}
	// A write of another file reports that file's warnings only.
	for _, writtenPath := range []string{"static/app.tsx", "hooks.yaml"} {
		if got := callerPredicateFindings(RunSourceCheck(root, writtenPath)); len(got) != 0 {
			t.Fatalf("a write of %q reported the command's warning: %+v", writtenPath, got)
		}
	}

	// A before-hook that reads the caller is a predicate the SQL does not show.
	writeTestFile(t, root, "hooks.yaml", "before_update:\n  work_items:\n    - sql: \"SELECT 'not yours' AS error\"\n      when: \"old_user_id != user_id\"\n")
	if got := callerPredicateFindings(RunSourceCheck(root, "")); len(got) != 0 {
		t.Fatalf("a caller-reading before_update hook still warned: %+v", got)
	}
	if err := os.Remove(filepath.Join(root, "hooks.yaml")); err != nil {
		t.Fatal(err)
	}

	// Bound from the actor: nothing to say on any surface.
	fixed := applyWith("UPDATE work_items SET status = 'done' WHERE id = :id AND user_id = :actor", "{id: '${{ params.arguments.id }}', actor: '${{ user.id }}'}")
	writeTestFile(t, root, "flows/complete_item.yaml", fixed)
	reviewed, err = reviewAppMCPSource(root)
	if err != nil || len(reviewed.Warnings) != 0 {
		t.Fatalf("a bound command: %v %v", err, reviewed)
	}
	if got := callerPredicateFindings(RunSourceCheck(root, "")); len(got) != 0 {
		t.Fatalf("a bound command still has a check finding: %+v", got)
	}
}
