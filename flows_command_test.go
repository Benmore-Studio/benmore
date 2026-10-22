//go:build !cli

package main

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

const commandFixture = `command:
  version: 1
  prepared_schema:
    type: object
    additionalProperties: false
    properties:
      arguments:
        type: object
        additionalProperties: false
        properties:
          id: {type: string, maxLength: 64}
        required: [id]
    required: [arguments]
  preview_schema:
    type: object
    additionalProperties: false
    properties:
      preview: {type: string, maxLength: 128}
    required: [preview]
  writes: [work_items]
  dependencies:
    - name: item
      table: work_items
      query: SELECT id FROM work_items WHERE id = :id
      params: {id: '${{ params.arguments.id }}'}
      max_rows: 256
jobs:
  prepare:
    steps:
      - id: item
        run: sql
        with:
          query: SELECT id FROM work_items WHERE id = :id
          params: {id: '${{ params.arguments.id }}'}
      - run: respond
        with:
          status: 200
          json: {arguments: '${{ params }}', preview: '${{ steps.item.outputs }}'}
  apply:
    steps:
      - run: sql
        expect_rows: ">0"
        with:
          query: UPDATE work_items SET status = 'done' WHERE id = :id
          params: {id: '${{ params.arguments.id }}'}
      - run: respond
        with: {status: 200, json: {ok: true}}
  readback:
    steps:
      - id: item
        run: sql
        with:
          query: SELECT id FROM work_items WHERE id = :id
          params: {id: '${{ params.arguments.id }}'}
      - run: respond
        with: {status: 200, json: {items: '${{ steps.item.outputs }}'}}
`

func TestFlowCommandCompilerBuildsInertNamedDescriptor(t *testing.T) {
	flow, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(commandFixture), map[string]bool{"work_items": true})
	if err != nil {
		t.Fatal(err)
	}
	if flow.Name != "complete_item" || flow.Trigger.Type != "command" || flow.Command == nil || len(flow.Steps) != 0 {
		t.Fatalf("unexpected command flow: %#v", flow)
	}
	if flow.Command.Version != 1 || len(flow.Command.Dependencies) != 1 || flow.Command.Dependencies[0].Params["id"].Kind != "intent_path" || flow.Command.Dependencies[0].Params["id"].Path != "arguments.id" {
		t.Fatalf("dependency was not compiled to a typed selector: %#v", flow.Command.Dependencies)
	}
	if len(flow.Command.Apply.WriteTables) != 1 || flow.Command.Apply.WriteTables[0] != "work_items" {
		t.Fatalf("write inventory missing: %#v", flow.Command.Apply.WriteTables)
	}
}

func TestFlowCommandCompilerRejectsUnsafeOrAmbiguousSource(t *testing.T) {
	cases := map[string]string{
		"unknown step field":         replaceCommandFixture("      - run: respond\n        with: {status: 200, json: {ok: true}}", "      - run: respond\n        body: nope\n        with: {status: 200, json: {ok: true}}"),
		"out of inventory write":     replaceCommandFixture("UPDATE work_items SET status", "UPDATE users SET status"),
		"multi statement selector":   replaceCommandFixture("      query: SELECT id FROM work_items WHERE id = :id\n      params:", "      query: SELECT id FROM work_items WHERE id = :id; DELETE FROM work_items\n      params:"),
		"interpolated selector":      replaceCommandFixture("      query: SELECT id FROM work_items WHERE id = :id\n      params:", "      query: SELECT id FROM work_items WHERE id = '${{ params.arguments.id }}'\n      params:"),
		"too many rows":              replaceCommandFixture("max_rows: 256", "max_rows: 257"),
		"duplicate key":              replaceCommandFixture("version: 1", "version: 1\n  version: 1"),
		"null nested scalar":         replaceCommandFixture("max_rows: 256", "max_rows: null"),
		"unknown dependency key":     replaceCommandFixture("      max_rows: 256", "      max_rows: 256\n      unexpected: true"),
		"null dependency table":      replaceCommandFixture("      table: work_items", "      table: null"),
		"unknown legacy root field":  replaceCommandFixture("command:\n", "action: update\ncommand:\n"),
		"null command version":       replaceCommandFixture("version: 1", "version: null"),
		"unsupported schema keyword": replaceCommandFixture("type: string, maxLength: 64", "type: string, maxLength: 64, pattern: '.*'"),
		"null schema value":          replaceCommandFixture("type: string, maxLength: 64", "type: null, maxLength: 64"),
		"unknown nested schema key":  replaceCommandFixture("id: {type: string, maxLength: 64}", "id: {type: string, maxLength: 64, unexpected: true}"),
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(source), map[string]bool{"work_items": true}); err == nil {
				t.Fatal("expected command source rejection")
			}
		})
	}
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(strings.Replace(commandFixture, "version: 1", "version: &version 1", 1)), map[string]bool{"work_items": true}); err == nil {
		t.Fatal("YAML anchors must be rejected")
	}
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(commandFixture+"\n---\nother: document\n"), map[string]bool{"work_items": true}); err == nil {
		t.Fatal("multiple YAML documents must be rejected")
	}
	requestSource := "on: {request: {method: POST, path: /api/private-command, auth: required, transaction: true}}\n" + commandFixture
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(requestSource), map[string]bool{"work_items": true}); err != nil {
		t.Fatalf("valid command request baseline rejected: %v", err)
	}
	for _, mutation := range []struct{ old, replacement string }{
		{"transaction: true}}", "transaction: true, unexpected: true}}"},
		{"method: POST", "method: null"},
	} {
		mutated := replaceCommandTextOnce(t, requestSource, mutation.old, mutation.replacement)
		if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(mutated), map[string]bool{"work_items": true}); err == nil {
			t.Fatalf("request presence mutation %q accepted", mutation.replacement)
		}
	}
}

func TestFlowCommandCompilerSelectorBoundsAndTypedRefs(t *testing.T) {
	for _, tc := range []struct {
		ref  string
		kind string
	}{
		{"${{ user.id }}", "actor_id"},
		{"${{ user.group_id }}", "selected_tenant"},
	} {
		source := strings.Replace(commandFixture, "${{ params.arguments.id }}", tc.ref, 1)
		flow, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(source), map[string]bool{"work_items": true})
		if err != nil || flow.Command.Dependencies[0].Params["id"].Kind != tc.kind {
			t.Fatalf("typed selector %q: %#v %v", tc.ref, flow.Command, err)
		}
	}
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(strings.Replace(commandFixture, "${{ params.arguments.id }}", "${{ env.ID }}", 1)), map[string]bool{"work_items": true}); err == nil {
		t.Fatal("unsupported selector reference accepted")
	}
	for _, max := range []string{"1", "256"} {
		source := strings.Replace(commandFixture, "max_rows: 256", "max_rows: "+max, 1)
		if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(source), map[string]bool{"work_items": true}); err != nil {
			t.Fatalf("valid selector max_rows=%s rejected: %v", max, err)
		}
	}
	withDependencies := func(count int) string {
		dependencies := "  dependencies:\n"
		for i := 0; i < count; i++ {
			name := "item"
			if i > 0 {
				name = fmt.Sprintf("dep%d", i)
			}
			dependencies += "    - name: " + name + "\n      table: work_items\n      query: SELECT id FROM work_items WHERE id = :id\n      params: {id: '${{ params.arguments.id }}'}\n      max_rows: 256\n"
		}
		base := strings.Index(commandFixture, "  dependencies:\n")
		relativeEnd := strings.Index(commandFixture[base:], "jobs:\n")
		if relativeEnd < 0 {
			panic("command fixture jobs boundary missing")
		}
		end := base + relativeEnd
		return commandFixture[:base] + dependencies + commandFixture[end:]
	}
	source := withDependencies(64)
	flow, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(source), map[string]bool{"work_items": true})
	if err != nil || len(flow.Command.Dependencies) != 64 {
		t.Fatalf("64 bounded selectors or aggregate max_rows>1024 rejected: %v", err)
	}
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(withDependencies(65)), map[string]bool{"work_items": true}); err == nil {
		t.Fatal("65 selectors accepted")
	}
}

func TestFlowCommandSQLInventoryIsCompleteOrRejects(t *testing.T) {
	workItems := map[string]bool{"work_items": true, "audit_log": true}
	cteQuery := "WITH chosen AS (SELECT id FROM work_items) SELECT id FROM chosen WHERE id = :id"
	cteInventory, err := commandSQLTableInventory(cteQuery)
	if err != nil || fmt.Sprint(cteInventory) != "[work_items]" {
		t.Fatalf("CTE physical inventory: %#v %v", cteInventory, err)
	}
	cteSource := replaceCommandPhaseSQL(t, commandFixture, "prepare", cteQuery)
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(cteSource), workItems); err != nil {
		t.Fatalf("bounded CTE rejected: %v", err)
	}
	caseQueryText := "SELECT CASE WHEN id = :id THEN id ELSE id END AS id FROM work_items WHERE id = :id"
	caseInventory, err := commandSQLTableInventory(caseQueryText)
	if err != nil || fmt.Sprint(caseInventory) != "[work_items]" {
		t.Fatalf("CASE physical inventory: %#v %v", caseInventory, err)
	}
	caseQuery := replaceCommandPhaseSQL(t, commandFixture, "prepare", caseQueryText)
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(caseQuery), workItems); err != nil {
		t.Fatalf("CASE selector rejected: %v", err)
	}
	subqueryText := "SELECT id FROM (SELECT id FROM work_items) AS chosen WHERE id = :id"
	subqueryInventory, err := commandSQLTableInventory(subqueryText)
	if err != nil || fmt.Sprint(subqueryInventory) != "[work_items]" {
		t.Fatalf("subquery physical inventory: %#v %v", subqueryInventory, err)
	}
	subquery := replaceCommandPhaseSQL(t, commandFixture, "prepare", subqueryText)
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(subquery), workItems); err != nil {
		t.Fatalf("bounded subquery rejected: %v", err)
	}

	joinText := "SELECT w.id FROM work_items AS w JOIN audit_log AS a ON a.item_id = w.id WHERE w.id = :id"
	joinInventory, err := commandSQLTableInventory(joinText)
	if err != nil || fmt.Sprint(joinInventory) != "[audit_log work_items]" {
		t.Fatalf("JOIN physical inventory: %#v %v", joinInventory, err)
	}
	join := replaceCommandPhaseSQL(t, commandFixture, "prepare", joinText)
	join = strings.Replace(join, "      max_rows: 256\njobs:", "      max_rows: 256\n    - name: audit\n      table: audit_log\n      query: SELECT id FROM audit_log WHERE id = :id\n      params: {id: '${{ params.arguments.id }}'}\n      max_rows: 10\njobs:", 1)
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(join), workItems); err != nil {
		t.Fatalf("declared explicit join rejected: %v", err)
	}

	for name, query := range map[string]string{
		"undeclared join":         "SELECT w.id FROM work_items w JOIN secret_rows s ON s.id = w.id WHERE w.id = :id",
		"undeclared comma source": "SELECT id FROM work_items, secret_rows WHERE id = :id",
		"reserved comma source":   "SELECT id FROM work_items, _benmore_secrets WHERE id = :id",
		"attached schema":         "SELECT id FROM attached.work_items WHERE id = :id",
		"temp schema":             "SELECT id FROM temp.work_items WHERE id = :id",
	} {
		t.Run(name, func(t *testing.T) {
			source := replaceCommandPhaseSQL(t, commandFixture, "prepare", query)
			if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(source), workItems); err == nil {
				t.Fatal("unsafe relation source admitted")
			}
		})
	}
	for name, query := range map[string]string{
		"IN subquery inside grouped predicate": `SELECT id FROM work_items WHERE (id IN (SELECT id FROM secret_rows)) AND id=:id`,
		"scalar function subquery":             `SELECT COALESCE((SELECT id FROM secret_rows LIMIT 1), id) FROM work_items WHERE id=:id`,
	} {
		t.Run(name, func(t *testing.T) {
			inventory, err := commandSQLTableInventory(query)
			if err != nil || fmt.Sprint(inventory) != "[secret_rows work_items]" {
				t.Fatalf("nested expression read was incomplete: %#v %v", inventory, err)
			}
			source := replaceCommandPhaseSQL(t, commandFixture, "prepare", query)
			if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(source), workItems); err == nil {
				t.Fatal("validly bound declaration with an undeclared expression read was admitted")
			}
		})
	}
	for name, query := range map[string]string{
		"ordinary scalar grouped expression": "SELECT COALESCE((id + 1), id) FROM work_items WHERE id=:id",
		"ordinary parenthesized expression":  "SELECT (id + 1) FROM work_items WHERE id=:id",
	} {
		t.Run(name, func(t *testing.T) {
			inventory, err := commandSQLTableInventory(query)
			if err != nil || fmt.Sprint(inventory) != "[work_items]" {
				t.Fatalf("ordinary expression control: %#v %v", inventory, err)
			}
			source := replaceCommandPhaseSQL(t, commandFixture, "prepare", query)
			if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(source), workItems); err != nil {
				t.Fatalf("ordinary expression declaration rejected: %v", err)
			}
		})
	}
	for name, query := range map[string]string{
		"IN table RHS":                      `SELECT id FROM work_items WHERE id IN secret_rows AND id=:id`,
		"NOT IN table RHS":                  `SELECT id FROM work_items WHERE id NOT IN secret_rows AND id=:id`,
		"main-qualified IN RHS":             `SELECT id FROM work_items WHERE id IN main.secret_rows AND id=:id`,
		"reserved IN RHS":                   `SELECT id FROM work_items WHERE id IN _benmore_secrets AND id=:id`,
		"quoted business IN RHS":            `SELECT id FROM work_items WHERE id IN 'secret_rows' AND id=:id`,
		"quoted reserved IN RHS":            `SELECT id FROM work_items WHERE id IN '_benmore_secrets' AND id=:id`,
		"quoted business NOT IN RHS":        `SELECT id FROM work_items WHERE id NOT IN 'secret_rows' AND id=:id`,
		"quoted reserved nested NOT IN RHS": `SELECT id FROM work_items WHERE (id NOT IN '_benmore_secrets') AND id=:id`,
		"missing IN RHS":                    `SELECT id FROM work_items WHERE id IN AND id=:id`,
	} {
		t.Run(name, func(t *testing.T) {
			source := replaceCommandPhaseSQL(t, commandFixture, "prepare", query)
			if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(source), workItems); err == nil {
				t.Fatal("validly bound declaration with an unclassified table-form IN source was admitted")
			}
			if inventory, err := commandSQLTableInventory(query); err == nil {
				t.Fatalf("table-form IN source returned a partial inventory: %#v", inventory)
			}
		})
	}
	inList := `SELECT id FROM work_items WHERE id IN (1, 2, 3) AND id=:id`
	inListInventory, err := commandSQLTableInventory(inList)
	if err != nil || fmt.Sprint(inListInventory) != "[work_items]" {
		t.Fatalf("parenthesized IN-list inventory: %#v %v", inListInventory, err)
	}
	inListSource := replaceCommandPhaseSQL(t, commandFixture, "prepare", inList)
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(inListSource), workItems); err != nil {
		t.Fatalf("supported literal IN list declaration rejected: %v", err)
	}
	for name, query := range map[string]string{
		"qualified cte shadow":      `WITH secret_rows AS (SELECT id FROM work_items) SELECT w.id FROM work_items w JOIN main.secret_rows s ON s.id=w.id WHERE w.id=:id`,
		"comma after nested join":   `SELECT w.id FROM work_items w JOIN (SELECT id FROM work_items) q ON q.id=w.id, secret_rows s WHERE w.id=:id`,
		"grouped physical relation": `SELECT id FROM work_items WHERE id IN (SELECT id FROM (secret_rows)) AND id=:id`,
		"nested cte scope shadow":   `SELECT id FROM work_items WHERE id IN (WITH secret_rows AS (SELECT id FROM work_items) SELECT id FROM secret_rows) AND id=:id UNION SELECT id FROM secret_rows WHERE id=:id`,
	} {
		t.Run(name, func(t *testing.T) {
			source := replaceCommandPhaseSQL(t, commandFixture, "prepare", query)
			if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(source), workItems); err == nil {
				t.Fatal("validly bound declaration with unsafe or incomplete relation shape was admitted")
			}
			inventory, err := commandSQLTableInventory(query)
			if name == "qualified cte shadow" && (err != nil || !commandStringIn(inventory, "secret_rows")) {
				t.Fatalf("main-qualified physical table hidden by CTE: %#v %v", inventory, err)
			}
			if err == nil && !commandStringIn(inventory, "secret_rows") {
				t.Fatalf("accepted shape omitted physical secret_rows: %#v", inventory)
			}
		})
	}
	quoted := replaceCommandPhaseSQL(t, commandFixture, "prepare", `SELECT id FROM "MAIN"."WORK_ITEMS" WHERE id = :id`)
	quotedInventory, err := commandSQLTableInventory(`SELECT id FROM "MAIN"."WORK_ITEMS" WHERE id = :id`)
	if err != nil || fmt.Sprint(quotedInventory) != "[WORK_ITEMS]" {
		t.Fatalf("quoted physical inventory: %#v %v", quotedInventory, err)
	}
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(quoted), workItems); err != nil {
		t.Fatalf("quoted case-varied main relation rejected: %v", err)
	}
}

func TestFlowCommandPreservesRawActorAndTenantPhaseBindings(t *testing.T) {
	source := commandFixture
	section := func(text, start, end, from, to string) string {
		begin := strings.Index(text, start)
		if begin < 0 {
			panic("phase fixture section missing")
		}
		finish := len(text)
		if end != "" {
			finish = strings.Index(text[begin+len(start):], end)
			if finish < 0 {
				panic("phase fixture section missing")
			}
			finish += begin + len(start)
		}
		changed := strings.Replace(text[begin:finish], from, to, 1)
		if changed == text[begin:finish] {
			panic("phase reference fixture target missing")
		}
		return text[:begin] + changed + text[finish:]
	}
	source = section(source, "  prepare:\n", "  apply:\n", "${{ params.arguments.id }}", "${{ user.group_id }}")
	source = section(source, "  apply:\n", "  readback:\n", "${{ params.arguments.id }}", "${{ user.id }}")
	source = section(source, "  readback:\n", "", "${{ params.arguments.id }}", "${{ user.group_id }}")
	flow, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(source), map[string]bool{"work_items": true})
	if err != nil {
		t.Fatalf("raw actor/tenant phase references rejected: %v", err)
	}
	if flow.Command.Prepare.Steps[0].CommandSQLParams["id"].Kind != "selected_tenant" || flow.Command.Apply.Steps[0].CommandSQLParams["id"].Kind != "actor_id" || flow.Command.Readback.Steps[0].CommandSQLParams["id"].Kind != "selected_tenant" {
		t.Fatalf("phase references lost trusted identity kinds: prepare=%+v apply=%+v readback=%+v", flow.Command.Prepare.Steps[0].CommandSQLParams, flow.Command.Apply.Steps[0].CommandSQLParams, flow.Command.Readback.Steps[0].CommandSQLParams)
	}
}

func TestFlowCommandSQLBindingsRejectEveryOtherPlaceholderFamily(t *testing.T) {
	for _, q := range []string{"SELECT id FROM work_items WHERE id = ?", "SELECT id FROM work_items WHERE id = @id", "SELECT id FROM work_items WHERE id = $id", "SELECT id FROM work_items WHERE id = :"} {
		if err := validateCommandSQLBindings(q, map[string]string{}, true); err == nil {
			t.Fatalf("unsupported or unmatched placeholder accepted: %s", q)
		}
	}
	if err := validateCommandSQLBindings("SELECT id FROM work_items WHERE id = :id", map[string]string{}, true); err == nil {
		t.Fatal("missing named binding accepted")
	}
	if err := validateCommandSQLBindings("SELECT id FROM work_items", map[string]string{"id": "${{ params.id }}"}, true); err == nil {
		t.Fatal("unused named binding accepted")
	}
	for _, q := range []string{"SELECT '${{ params.id }}' FROM work_items", "SELECT id FROM work_items WHERE id = ?", "SELECT id FROM work_items WHERE id = @id", "SELECT id FROM work_items WHERE id = $id"} {
		if err := validateCommandSQLBindings(q, map[string]string{}, true); err == nil {
			t.Fatalf("nonliteral or unsupported binding SQL accepted: %s", q)
		}
	}
}

// A block comment that runs to the end of a command statement would swallow the
// RETURNING * the hook probe appends: the hooked write would derive no rows and
// skip its hooks, validators and workflow guards. Every closed comment form,
// and a trailing line comment (the newline before RETURNING ends it), is fine.
func TestFlowCommandSQLRejectsUnterminatedBlockComment(t *testing.T) {
	writes := []string{"work_items"}
	for _, q := range []string{
		"UPDATE work_items SET status = 'done' WHERE id = :id /* note",
		"UPDATE work_items SET status = 'done' WHERE id = :id /*/",
		"UPDATE work_items SET status = 'done' WHERE id = :id /**/ /*",
		"UPDATE work_items SET status = 'done' /* a */ WHERE id = :id /* b *",
	} {
		if err := validateCommandSQLText(q); err == nil {
			t.Errorf("unterminated block comment accepted: %q", q)
		}
		if err := validateCommandRuntimeSQLText(q, "apply", writes); err == nil {
			t.Errorf("runtime admitted unterminated block comment: %q", q)
		}
	}
	for _, q := range []string{
		"UPDATE work_items SET status = 'done' WHERE id = :id /* note */",
		"UPDATE work_items SET status = 'done' WHERE id = :id /**/",
		"UPDATE work_items SET status = 'done' WHERE id = :id /***/",
		"UPDATE work_items SET status = '/*' WHERE id = :id",
		"UPDATE work_items SET status = 'done' WHERE id = :id -- note",
	} {
		if err := validateCommandSQLText(q); err != nil {
			t.Errorf("closed comment refused: %q: %v", q, err)
		}
	}
}

func TestFlowCommandTrustedActorEmailIsApplySQLOnly(t *testing.T) {
	query := "UPDATE work_items SET status='done', title=:email WHERE id=:id"
	params := map[string]string{"id": "${{ params.arguments.id }}", "email": "${{ user.email }}"}
	if _, err := validateCommandSQLAdmission(query, params, "apply", []string{"work_items"}, map[string]bool{"work_items": true}); err != nil {
		t.Fatalf("exact trusted actor email apply binding rejected: %v", err)
	}
	for _, phase := range []string{"prepare", "readback"} {
		if _, err := validateCommandSQLAdmission("SELECT id FROM work_items WHERE title=:email", map[string]string{"email": "${{ user.email }}"}, phase, []string{"work_items"}, map[string]bool{"work_items": true}); err == nil {
			t.Fatalf("actor email binding accepted in %s SQL", phase)
		}
	}
	if _, err := validateCommandSQLAdmission("UPDATE work_items SET title=:email WHERE id=:id", map[string]string{"id": "${{ params.arguments.id }}", "email": "prefix ${{ user.email }}"}, "apply", []string{"work_items"}, map[string]bool{"work_items": true}); err == nil {
		t.Fatal("composed actor email SQL binding accepted")
	}
	if _, err := compileCommandSQLRef("${{ user.email }}", nil, nil); err == nil {
		t.Fatal("actor email was admitted as a selector binding")
	}
	if err := validateCommandActorEmailPlacement([]FlowStepGHA{{Run: "set", With: map[string]any{"saved": "${{ user.email }}"}}}, "apply"); err == nil {
		t.Fatal("actor email was admitted in a generic set value")
	}
	if err := validateCommandActorEmailPlacement([]FlowStepGHA{{Run: "compute", With: map[string]any{"args": map[string]any{"email": "${{ user.email }}"}}}}, "apply"); err == nil {
		t.Fatal("actor email was admitted in compute arguments")
	}
	step := &FlowStep{SQL: query,
		SQLParams:        map[string]string{"id": "${{ params.arguments.id }}", "email": "${{ user.email }}"},
		CommandSQLParams: map[string]FlowCommandParamRef{"id": {Kind: "phase_path", Path: "arguments.id"}, "email": {Kind: "actor_email"}},
	}
	if err := validateCommandRuntimeSQLBindings(step, "apply"); err != nil {
		t.Fatalf("runtime rejected exact compiled actor email binding: %v", err)
	}
	for _, mutate := range []struct {
		phase string
		path  string
	}{{"prepare", ""}, {"apply", "email"}, {"readback", ""}} {
		bad := *step
		bad.CommandSQLParams = map[string]FlowCommandParamRef{"id": {Kind: "phase_path", Path: "arguments.id"}, "email": {Kind: "actor_email", Path: mutate.path}}
		if err := validateCommandRuntimeSQLBindings(&bad, mutate.phase); err == nil {
			t.Fatalf("tampered actor email binding accepted for phase=%s path=%q", mutate.phase, mutate.path)
		}
	}
}

func TestFlowCommandEveryPhaseUsesLiteralAndNamedBindAdmission(t *testing.T) {
	for _, phase := range []string{"prepare", "apply", "readback"} {
		validSource := commandFixture
		validQuery := "SELECT id FROM work_items WHERE id = :id"
		if phase == "apply" {
			validQuery = "UPDATE work_items SET status = 'done' WHERE id = :id"
		}
		if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(validSource), map[string]bool{"work_items": true}); err != nil {
			t.Fatalf("valid literal :id phase baseline rejected for %s: %v", phase, err)
		}
		for _, invalidQuery := range []string{"SELECT '${{ params.id }}' FROM work_items", "SELECT id FROM work_items WHERE id = ?", "SELECT id FROM work_items WHERE id = @id", "SELECT id FROM work_items WHERE id = $id"} {
			t.Run(phase+"/"+invalidQuery, func(t *testing.T) {
				badQuery := invalidQuery
				if phase == "apply" {
					switch {
					case strings.Contains(badQuery, "'${{"):
						badQuery = "UPDATE work_items SET status = 'done' WHERE id = '${{ params.id }}'"
					case strings.Contains(badQuery, " = ?"):
						badQuery = "UPDATE work_items SET status = 'done' WHERE id = ?"
					case strings.Contains(badQuery, " = @"):
						badQuery = "UPDATE work_items SET status = 'done' WHERE id = @id"
					default:
						badQuery = "UPDATE work_items SET status = 'done' WHERE id = $id"
					}
				}
				at := strings.Index(validSource, "  "+phase+":\n")
				if at < 0 {
					t.Fatal("phase missing from valid declaration")
				}
				queryAt := strings.Index(validSource[at:], validQuery)
				if queryAt < 0 {
					t.Fatal("phase query missing from valid declaration")
				}
				source := validSource[:at+queryAt] + strings.Replace(validSource[at+queryAt:], validQuery, badQuery, 1)
				var node yaml.Node
				if err := yaml.Unmarshal([]byte(source), &node); err != nil {
					t.Fatal(err)
				}
				root, err := commandMap(node.Content[0])
				if err != nil {
					t.Fatal(err)
				}
				jobs, err := commandMap(root["jobs"])
				if err != nil {
					t.Fatal(err)
				}
				phaseMap, err := commandMap(jobs[phase])
				if err != nil || phaseMap["steps"].Kind != yaml.SequenceNode || len(phaseMap["steps"].Content) == 0 || phaseMap["steps"].Content[0].Kind != yaml.MappingNode {
					t.Fatalf("expected a valid one-step mapping before SQL admission: %v", err)
				}
				err = validateCommandStepNode(phaseMap["steps"].Content[0], phase, 0, []string{"work_items"}, map[string]bool{"work_items": true})
				if err == nil || strings.Contains(err.Error(), "expected mapping") {
					t.Fatalf("nonliteral or unsupported SQL binding admitted or wrong node tested: %v", err)
				}
			})
		}
	}
}

func TestFlowCommandNamedBindMustBeAdjacent(t *testing.T) {
	params := map[string]string{"id": "${{ params.id }}"}
	if err := validateCommandSQLBindings("SELECT id FROM work_items WHERE id = :id", params, true); err != nil {
		t.Fatalf("adjacent named bind rejected: %v", err)
	}
	for _, query := range []string{
		"SELECT id FROM work_items WHERE id = : id",
		"SELECT id FROM work_items WHERE id = :\tid",
		"SELECT id FROM work_items WHERE id = :/* gap */id",
	} {
		if err := validateCommandSQLBindings(query, params, true); err == nil {
			t.Fatalf("separated named bind accepted: %q", query)
		}
	}
}

func TestFlowCommandYAMLTraversalBound(t *testing.T) {
	for _, tc := range []struct {
		depth     int
		wantError string
	}{{30, "unknown command file key"}, {40, "nesting limit"}} {
		t.Run(fmt.Sprint(tc.depth), func(t *testing.T) {
			deep := "deep:\n"
			// Count the mapping under deep itself as level one; extra
			// entries add one child mapping apiece.
			for i := 0; i < tc.depth-1; i++ {
				deep += strings.Repeat("  ", i+1) + "level:\n"
			}
			deep += strings.Repeat("  ", tc.depth) + "leaf: value\n"
			source := strings.Replace(commandFixture, "jobs:\n", deep+"jobs:\n", 1)
			result := make(chan error, 1)
			go func() {
				_, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(source), map[string]bool{"work_items": true})
				result <- err
			}()
			select {
			case err := <-result:
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("depth %d parse error = %v, want %q", tc.depth, err, tc.wantError)
				}
			case <-time.After(5 * time.Second):
				t.Fatalf("depth %d mapping traversal did not complete within the bound", tc.depth)
			}
		})
	}
}

func TestValidateOnWriteInCompilesCommandAtTrueAppRelativePath(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE work_items (id INTEGER PRIMARY KEY, status TEXT);\n")
	writeTestFile(t, dir, "flows/complete_item.yaml", commandFixture)
	if msg := ValidateOnWriteIn(dir, "flows/complete_item.yaml", commandFixture); msg != "" {
		t.Fatalf("valid command write rejected: %s", msg)
	}
	if msg := ValidateOnWriteIn(dir, filepath.Join(dir, "flows", "complete_item.yaml"), commandFixture); msg != "" {
		t.Fatalf("valid absolute app-local command write rejected: %s", msg)
	}

	badInventory := strings.ReplaceAll(commandFixture, "work_items", "missing_items")
	if msg := ValidateOnWriteIn(dir, "flows/complete_item.yaml", badInventory); msg == "" {
		t.Fatal("command writing outside the app schema inventory accepted")
	}
	for _, path := range []string{
		"flows.yaml",
		"flows/nested/complete_item.yaml",
		"nested/flows/complete_item.yaml",
		"flows/complete_item.yml",
		filepath.Join(dir+"-outside", "flows", "complete_item.yaml"),
	} {
		if msg := ValidateOnWriteIn(dir, path, commandFixture); msg == "" {
			t.Errorf("command at unsupported path %q accepted", path)
		}
	}
	if msg := ValidateOnWriteIn("", "flows/complete_item.yaml", commandFixture); msg == "" {
		t.Fatal("command write without appDir accepted")
	}
	ordinaryFlow := "on: {request: {method: POST, path: /api/ordinary, auth: required}}\njobs:\n  first: {steps: [{run: respond, with: {status: 200, body: ok}}]}\n  second: {steps: [{run: respond, with: {status: 200, body: ok}}]}\n"
	if msg := ValidateOnWriteIn(dir, "flows/ordinary.yaml", ordinaryFlow); msg != "" {
		t.Fatalf("ordinary flow write changed by command dispatch: %s", msg)
	}
	if msg := ValidateOnWriteIn("", "settings.yaml", "command: echo hello\n"); msg != "" {
		t.Fatalf("unrelated YAML root key was routed into the command compiler: %s", msg)
	}
}

func TestFlowCommandAuthoredStepBudgetIsCommandWide(t *testing.T) {
	build := func(perPhase int) string {
		phase := func(name, response string) string {
			var steps strings.Builder
			for i := 1; i < perPhase; i++ {
				steps.WriteString("      - run: set\n        with: {local_value: literal}\n")
			}
			steps.WriteString("      - run: respond\n        with: " + response + "\n")
			return "  " + name + ":\n    steps:\n" + steps.String()
		}
		return "command:\n  version: 1\n  prepared_schema: {type: object, additionalProperties: false}\n  preview_schema: {type: object, additionalProperties: false}\n  writes: [work_items]\n  dependencies: [{name: item, table: work_items, query: 'SELECT id FROM work_items', params: {}, max_rows: 1}]\njobs:\n" +
			phase("prepare", "{status: 200, json: {arguments: {}, preview: ''}}") +
			phase("apply", "{status: 200, json: {ok: true}}") +
			phase("readback", "{status: 200, json: {ok: true}}")
	}
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(build(85)), map[string]bool{"work_items": true}); err != nil {
		t.Fatalf("255 total authored steps rejected: %v", err)
	}
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(build(86)), map[string]bool{"work_items": true}); err == nil {
		t.Fatal("258 authored steps across phases accepted")
	}
}

func TestFlowCommandLoaderCapturesExactSourceAndRejectsRootPlacement(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "flows"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flows", "complete_item.yaml"), []byte(commandFixture), 0600); err != nil {
		t.Fatal(err)
	}
	// The compiler's table set comes from captured schema bytes in production;
	// direct source capture is exercised here with an explicit file map.
	captured := map[string][]byte{"flows/complete_item.yaml": []byte(commandFixture), "schema.sql": []byte("CREATE TABLE work_items (id TEXT PRIMARY KEY, status TEXT);")}
	flows, err := loadFlowsCheckedFromSources(dir, true, captured)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 || flows[0].sourceHash != hashBytesSHA256([]byte(commandFixture)) || flows[0].Source != "flows/complete_item.yaml" || flows[0].Trigger.Type != "command" {
		t.Fatalf("source identity lost: %#v", flows)
	}
	if _, err := loadFlowsCheckedFromSources(dir, true, map[string][]byte{"flows.yaml": []byte(commandFixture), "schema.sql": []byte("CREATE TABLE work_items (id TEXT PRIMARY KEY, status TEXT);")}); err == nil {
		t.Fatal("root flows.yaml must reject command presence")
	}
	if _, err := loadFlowsCheckedFromSources(dir, false, map[string][]byte{"flows.yaml": []byte("command: null\n"), "schema.sql": []byte("CREATE TABLE work_items (id TEXT PRIMARY KEY, status TEXT);")}); err == nil {
		t.Fatal("legacy opt-out silently discarded root command presence")
	}
	changed := strings.Replace(commandFixture, "maxLength: 128", "maxLength: 127", 1)
	reloaded, err := loadFlowsCheckedFromSources(dir, true, map[string][]byte{"flows/complete_item.yaml": []byte(changed), "schema.sql": []byte("CREATE TABLE work_items (id TEXT PRIMARY KEY, status TEXT);")})
	if err != nil || len(reloaded) != 1 || reloaded[0].sourceHash == flows[0].sourceHash || reloaded[0].Command == flows[0].Command {
		t.Fatalf("changed source reload reused prior captured descriptor: err=%v", err)
	}
	ordinary := []byte("on: {request: {method: POST, path: /api/ordinary, auth: required}}\njobs:\n  first: {steps: [{run: respond, with: {status: 200, body: ok}}]}\n  second: {steps: [{run: respond, with: {status: 200, body: ok}}]}\n")
	flows, err = loadFlowsCheckedFromSources(dir, true, map[string][]byte{"flows/ordinary.yaml": ordinary, "schema.sql": []byte("CREATE TABLE work_items (id TEXT PRIMARY KEY, status TEXT);")})
	if err != nil || len(flows) != 2 || flows[0].Command != nil || len(flows[0].Steps) == 0 {
		t.Fatalf("ordinary multi-job flow parsing changed: %v %#v", err, flows)
	}
}

func TestGHAParserRefusesCommandPresenceBeforeJobExpansion(t *testing.T) {
	if flows, err := parseGHAFlowFile("flows/complete_item.yaml", []byte(commandFixture)); err == nil || len(flows) != 0 {
		t.Fatalf("command declaration expanded as ordinary jobs: err=%v flows=%#v", err, flows)
	}
	invalid := []byte("command: null\non: {request: {method: POST, path: /api/ordinary, auth: required}}\njobs:\n  one: {steps: [{run: respond, with: {status: 200, body: ok}}]}\n  two: {steps: [{run: respond, with: {status: 200, body: ok}}]}\n")
	if flows, err := parseGHAFlowFile("flows/invalid_command.yaml", invalid); err == nil || len(flows) != 0 {
		t.Fatalf("null command presence was ignored: err=%v flows=%#v", err, flows)
	}
}

func replaceCommandFixture(old, replacement string) string {
	if old == "" || strings.Count(commandFixture, old) != 1 {
		panic("command fixture replacement target missing or ambiguous")
	}
	updated := strings.Replace(commandFixture, old, replacement, 1)
	if updated == commandFixture {
		panic("command fixture replacement made no change")
	}
	return updated
}

func replaceCommandTextOnce(t *testing.T, source, old, replacement string) string {
	t.Helper()
	if old == "" || strings.Count(source, old) != 1 {
		t.Fatalf("fixture target missing or ambiguous: %q", old)
	}
	changed := strings.Replace(source, old, replacement, 1)
	if changed == source {
		t.Fatalf("fixture replacement made no change: %q", old)
	}
	return changed
}

func replaceCommandPhaseSQL(t *testing.T, source, phase, query string) string {
	t.Helper()
	start := strings.Index(source, "  "+phase+":\n")
	if start < 0 {
		t.Fatalf("command fixture phase %q missing", phase)
	}
	end := len(source)
	for _, next := range []string{"prepare", "apply", "readback"} {
		if next == phase {
			continue
		}
		if at := strings.Index(source[start+len("  "+phase+":\n"):], "  "+next+":\n"); at >= 0 && start+len("  "+phase+":\n")+at < end {
			end = start + len("  "+phase+":\n") + at
		}
	}
	section := source[start:end]
	const old = "query: SELECT id FROM work_items WHERE id = :id"
	if strings.Count(section, old) != 1 {
		t.Fatalf("command fixture phase %q SQL target missing or ambiguous", phase)
	}
	updated := strings.Replace(section, old, "query: "+query, 1)
	return source[:start] + updated + source[end:]
}

func replaceCommandPhaseTextOnce(t *testing.T, source, phase, old, replacement string) string {
	t.Helper()
	start := strings.Index(source, "  "+phase+":\n")
	if start < 0 {
		t.Fatalf("command fixture phase %q missing", phase)
	}
	end := len(source)
	for _, next := range []string{"prepare", "apply", "readback"} {
		if next != phase {
			if at := strings.Index(source[start+len("  "+phase+":\n"):], "  "+next+":\n"); at >= 0 && start+len("  "+phase+":\n")+at < end {
				end = start + len("  "+phase+":\n") + at
			}
		}
	}
	section := source[start:end]
	if strings.Count(section, old) != 1 {
		t.Fatalf("phase %q target missing or ambiguous: %q", phase, old)
	}
	return source[:start] + strings.Replace(section, old, replacement, 1) + source[end:]
}

func insertCommandPrepareSteps(t *testing.T, source, steps string) string {
	t.Helper()
	const marker = "      - run: respond\n        with:\n          status: 200\n          json: {arguments: '${{ params }}', preview: '${{ steps.item.outputs }}'}"
	if strings.Count(source, marker) != 1 {
		t.Fatal("prepare terminal fixture target missing")
	}
	return strings.Replace(source, marker, steps+marker, 1)
}

func TestFlowCommandLoopSourcesAndUnnamedBindingsPreserveSourceOrder(t *testing.T) {
	source := strings.Replace(commandFixture,
		"          id: {type: string, maxLength: 64}\n        required: [id]",
		"          id: {type: string, maxLength: 64}\n          items: {type: array, maxItems: 2, items: {type: object, additionalProperties: false, properties: {id: {type: string, maxLength: 64}}, required: [id]}}\n          other_items: {type: array, maxItems: 2, items: {type: object, additionalProperties: false, properties: {id: {type: string, maxLength: 64}}, required: [id]}}\n        required: [id, items, other_items]", 1)
	const before = "      - run: respond\n        with:\n          status: 200\n          json: {arguments: '${{ params }}', preview: '${{ steps.item.outputs }}'}"
	const loops = "      - for_each: params.arguments.items\n        as: row\n        steps:\n          - run: sql\n            with: {query: SELECT id FROM work_items WHERE id=:id, params: {id: '${{ row.id }}'}}\n      - for_each: '${{ params.arguments.other_items }}'\n        as: row\n        steps:\n          - run: sql\n            with: {query: SELECT id FROM work_items WHERE id=:id, params: {id: '${{ row.id }}'}}\n" + before
	if strings.Count(source, before) != 1 {
		t.Fatal("prepare terminal fixture target missing")
	}
	source = strings.Replace(source, before, loops, 1)
	flow, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(source), map[string]bool{"work_items": true})
	if err != nil {
		t.Fatalf("bounded sequential loops rejected: %v", err)
	}
	steps := flow.Command.Prepare.Steps
	if len(steps) != 4 || steps[1].Type != "for_each" || steps[2].Type != "for_each" {
		t.Fatalf("unexpected source structure: %#v", steps)
	}
	if steps[1].ForEach != "params.arguments.items" || steps[2].ForEach != "${{ params.arguments.other_items }}" || steps[1].ForAs != "row" || steps[2].ForAs != "row" {
		t.Fatalf("loop source order lost: %#v %#v", steps[1], steps[2])
	}
	for _, loop := range steps[1:3] {
		if len(loop.Steps) != 1 || loop.Steps[0].Name != "" || loop.Steps[0].SQLParams["id"] != "${{ row.id }}" || loop.Steps[0].CommandSQLParams["id"] != (FlowCommandParamRef{Kind: "loop_path", Path: "row.id"}) {
			t.Fatalf("unnamed SQL binding source was lost: %#v", loop)
		}
	}
	for _, loopSource := range []string{"params.arguments.items", "${{ params.arguments.items }}", "${{ params.arguments.items }} WHERE"} {
		if _, ok := commandLoopParameterPath(loopSource); ok != !strings.Contains(loopSource, "WHERE") {
			t.Fatalf("loop source admission mismatch for %q", loopSource)
		}
	}
}

func TestFlowCommandWholeOutputAndLexicalFieldAdmission(t *testing.T) {
	flow, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(commandFixture), map[string]bool{"work_items": true})
	if err != nil {
		t.Fatal(err)
	}
	exec := &appMCPCommandExecution{capability: &appMCPCommandCapability{}, results: map[string]any{"item": []map[string]any{{"id": "one"}}}}
	got, ok := exec.lookup("steps.item.outputs")
	if !ok || got == nil {
		t.Fatalf("whole captured SQL output did not resolve: %#v %v", got, ok)
	}
	if len(flow.Command.Prepare.Steps) != 2 || flow.Command.Prepare.Steps[1].Respond.JSON["preview"] != "${{ steps.item.outputs }}" {
		t.Fatal("terminal source did not preserve whole output")
	}
	if flow.Command.Readback.Steps[1].Respond.JSON["items"] != "${{ steps.item.outputs }}" {
		t.Fatal("nested readback source did not preserve whole output")
	}
	nonObject := replaceCommandPhaseTextOnce(t, commandFixture, "readback", "{items: '${{ steps.item.outputs }}'}", "'${{ steps.item.outputs }}'")
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(nonObject), map[string]bool{"work_items": true}); err == nil {
		t.Fatal("non-object terminal result was admitted")
	}
	computeSource := strings.Replace(commandFixture, "      - run: respond\n        with:\n          status: 200\n          json: {arguments: '${{ params }}', preview: '${{ steps.item.outputs }}'}", "      - id: projection\n        run: compute\n        with: {module: reports, function: identity, args: '${{ steps.item.outputs }}'}\n      - run: respond\n        with:\n          status: 200\n          json: {arguments: '${{ params }}', preview: '${{ steps.item.outputs }}'}", 1)
	computed, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(computeSource), map[string]bool{"work_items": true})
	if err != nil {
		t.Fatalf("whole SQL output rejected as compute input: %v", err)
	}
	if computed.Command.Prepare.Steps[1].Compute.Args != "${{ steps.item.outputs }}" {
		t.Fatal("compute source did not preserve whole SQL output")
	}

	bad := strings.Replace(commandFixture, "      - run: respond\n        with:\n          status: 200", "      - if: '${{ steps.future.outputs.first.id }} == x'\n        steps:\n          - run: set\n            with: {seen: done}\n      - run: respond\n        with:\n          status: 200", 1)
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(bad), map[string]bool{"work_items": true}); err == nil {
		t.Fatal("forward reference in condition was admitted")
	}
	branchOnly := insertCommandPrepareSteps(t, commandFixture, "      - if: '${{ params.arguments.id }} == x'\n        steps:\n          - id: branch_item\n            run: sql\n            with: {query: SELECT id FROM work_items WHERE id=:id, params: {id: '${{ params.arguments.id }}'}}\n      - run: sql\n        with: {query: SELECT id FROM work_items WHERE id=:id, params: {id: '${{ steps.branch_item.outputs.first.id }}'}}\n")
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(branchOnly), map[string]bool{"work_items": true}); err == nil {
		t.Fatal("branch-only output escaped its branch scope")
	}
	boundedLoopSource := strings.Replace(commandFixture,
		"          id: {type: string, maxLength: 64}\n        required: [id]",
		"          id: {type: string, maxLength: 64}\n          items: {type: array, maxItems: 2, items: {type: object, additionalProperties: false, properties: {id: {type: string, maxLength: 64}}, required: [id]}}\n        required: [id]", 1)
	if boundedLoopSource == commandFixture {
		t.Fatal("bounded lexical-loop baseline did not match the prepared schema")
	}
	loopEscape := insertCommandPrepareSteps(t, boundedLoopSource, "      - for_each: params.arguments.items\n        as: row\n        steps:\n          - run: set\n            with: {saved: '${{ row.id }}'}\n      - run: set\n        with: {escaped: '${{ row.id }}'}\n")
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(loopEscape), map[string]bool{"work_items": true}); err == nil {
		t.Fatal("loop local escaped its iteration")
	}
	innerEscape := insertCommandPrepareSteps(t, boundedLoopSource, "      - for_each: params.arguments.items\n        as: outer\n        steps:\n          - for_each: params.arguments.items\n            as: inner\n            steps:\n              - run: set\n                with: {saved: '${{ inner.id }}'}\n          - run: set\n            with: {escaped: '${{ inner.id }}'}\n")
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(innerEscape), map[string]bool{"work_items": true}); err == nil {
		t.Fatal("nested iteration local escaped its child frame")
	}
	crossPhase := replaceCommandPhaseTextOnce(t, commandFixture, "apply", "'${{ params.arguments.id }}'", "'${{ steps.item.outputs.first.id }}'")
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(crossPhase), map[string]bool{"work_items": true}); err == nil {
		t.Fatal("prepare producer was admitted as an apply-phase output")
	}
	scalarSet := insertCommandPrepareSteps(t, commandFixture, "      - run: set\n        with: {selected: '${{ steps.item.outputs.first.id }}'}\n")
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(scalarSet), map[string]bool{"work_items": true}); err != nil {
		t.Fatalf("dominating scalar SQL output rejected by set: %v", err)
	}
	wholeSet := insertCommandPrepareSteps(t, commandFixture, "      - run: set\n        with: {selected: '${{ steps.item.outputs }}'}\n")
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(wholeSet), map[string]bool{"work_items": true}); err == nil {
		t.Fatal("whole collection SQL output admitted into scalar set")
	}
}

func TestFlowCommandBoundedScannerDecryptsBeforeSQLiteAffinity(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec("CREATE TABLE scan_values (encrypted_int INTEGER, encrypted_real REAL, plain_int INTEGER, nullable_int INTEGER)"); err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{0x31}, 32)
	intCipher, err := fieldEncryptWithKey(key, "42")
	if err != nil {
		t.Fatal(err)
	}
	realCipher, err := fieldEncryptWithKey(key, "12.5")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO scan_values VALUES (?, ?, 7, NULL)", intCipher, realCipher); err != nil {
		t.Fatal(err)
	}
	rows, err := db.Query("SELECT encrypted_int, encrypted_real, plain_int, nullable_int FROM scan_values")
	if err != nil {
		t.Fatal(err)
	}
	result, err := scanCommandRowsBounded(rows, key, 4)
	if err != nil {
		t.Fatal(err)
	}
	if len(result) != 1 {
		t.Fatalf("unexpected row count: %d", len(result))
	}
	if value, ok := result[0]["encrypted_int"].(int64); !ok || value != 42 {
		t.Fatalf("encrypted INTEGER lost native type: %#v (%T)", result[0]["encrypted_int"], result[0]["encrypted_int"])
	}
	if value, ok := result[0]["encrypted_real"].(float64); !ok || value != 12.5 {
		t.Fatalf("encrypted REAL lost native type: %#v (%T)", result[0]["encrypted_real"], result[0]["encrypted_real"])
	}
	if value, ok := result[0]["plain_int"].(int64); !ok || value != 7 {
		t.Fatalf("plain INTEGER control changed: %#v", result[0]["plain_int"])
	}
	if value := result[0]["nullable_int"]; value != nil {
		t.Fatalf("NULL control changed: %#v", value)
	}
}
