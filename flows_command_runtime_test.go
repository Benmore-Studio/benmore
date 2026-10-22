//go:build !cli

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"testing"

	"github.com/mattn/go-sqlite3"
)

func TestPrimeFullTextIndexesRestoresPriorAuthorizerPolicy(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE VIRTUAL TABLE tasks_fts USING fts5(name)`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	priorPriming := map[string]bool{"prior_fts": true}
	guard := &appMCPCommandExecution{verifiedFTSPriming: priorPriming}
	cap := &appMCPCommandCapability{ctx: context.Background(), tx: tx, guard: guard}
	for _, indexes := range []map[string]bool{{"tasks_fts": true}, {"missing_fts": true}} {
		err := cap.primeFullTextIndexes(indexes)
		if indexes["tasks_fts"] && err != nil {
			t.Fatalf("prime exact existing FTS index: %v", err)
		}
		if indexes["missing_fts"] && err == nil {
			t.Fatal("priming a missing captured FTS index unexpectedly succeeded")
		}
		if guard.internal || guard.verifiedFTSPriming["prior_fts"] != true || guard.verifiedFTSPriming["tasks_fts"] {
			t.Fatalf("prior authorizer state was not restored after priming %v: internal=%t priming=%v", indexes, guard.internal, guard.verifiedFTSPriming)
		}
	}
}

func TestCommandFTSStorageIsOnlyWritableThroughCapturedTableTriggers(t *testing.T) {
	source, err := appMCPCommandFullTextTriggerWrites(&appMCPRuntimeGeneration{
		sourceFiles: map[string][]byte{"schema.prisma": []byte(`model Task {
  id Int @id
  name String
  @@fulltext([name])
  @@map("tasks")
}`)},
	}, []string{"tasks"})
	wantFTSStorage := []string{"tasks_fts", "tasks_fts_config", "tasks_fts_data", "tasks_fts_docsize", "tasks_fts_idx"}
	if err != nil || len(source) != len(wantFTSStorage) {
		t.Fatalf("derive exact captured full-text trigger target: %v (%v)", source, err)
	}
	for _, table := range wantFTSStorage {
		if !source[table] {
			t.Errorf("captured FTS storage closure omitted %q: %v", table, source)
		}
	}
	for _, statement := range []string{
		"INSERT INTO tasks_fts(rowid,name) VALUES(1,'x')",
		"UPDATE tasks_fts SET name='x' WHERE rowid=1",
		"DELETE FROM tasks_fts WHERE rowid=1",
		"DELETE FROM tasks_fts_data WHERE id=1",
	} {
		if err := validateCommandRuntimeSQLText(statement, "apply", []string{"tasks"}); err == nil {
			t.Errorf("authored command SQL was allowed to target FTS storage: %q", statement)
		}
	}
	cap := &appMCPCommandCapability{
		generation: &appMCPRuntimeGeneration{sourceFiles: map[string][]byte{"schema.prisma": []byte(`model Task {
  id Int @id
  name String
  @@fulltext([name])
  @@map("tasks")
}`)}},
		command: &FlowCommand{Writes: []string{"tasks", "tasks_fts_data"}},
	}
	for _, query := range []string{
		`UPDATE tasks SET description=(SELECT name FROM tasks_fts_data LIMIT 1) WHERE id=1`,
		`UPDATE tasks_fts_data SET id=1`,
		`UPDATE "tasks_fts_data" SET id=1`,
		`UPDATE main.tasks_fts_data SET id=1`,
	} {
		if err := cap.validateSQLPhase(query, "apply", []string{"tasks", "tasks_fts_data"}); err == nil {
			t.Errorf("authored command SQL was allowed to reference captured FTS storage: %q", query)
		}
	}
	policy := appMCPCommandAuthorizerPolicy{metadataOp: appMCPCommandMetadataHookWrite, hookWrites: commandTableSet([]string{"tasks"})}
	for _, table := range []string{"tasks_fts", "tasks_fts_data", "tasks_fts_idx", "tasks_fts_docsize", "tasks_fts_config"} {
		if got := authorizeCommandHook(policy, sqlite3.SQLITE_INSERT, table, "main", "main"); got != sqlite3.SQLITE_DENY {
			t.Errorf("direct hook write to FTS storage %q authorization = %d, want DENY", table, got)
		}
	}
	guard := &appMCPCommandExecution{phase: "apply", verifiedFTSWrites: source}
	for _, table := range append(wantFTSStorage, "tasks_fts_unexpected") {
		got := guard.authorize(sqlite3.SQLITE_READ, table, "", "main")
		want := sqlite3.SQLITE_DENY
		if source[table] {
			want = sqlite3.SQLITE_OK
		}
		if got != want {
			t.Errorf("apply read authorization for %q = %d, want %d", table, got, want)
		}
	}
	for _, table := range append(wantFTSStorage, "tasks_fts_unexpected") {
		got := guard.authorize(sqlite3.SQLITE_DELETE, table, "", "main")
		want := sqlite3.SQLITE_DENY
		if source[table] {
			want = sqlite3.SQLITE_OK
		}
		if got != want {
			t.Errorf("apply write authorization for %q = %d, want %d", table, got, want)
		}
	}
}

func TestAppMCPCommandWholeSQLOutputLookupUsesJSONArray(t *testing.T) {
	first := map[string]any{
		"id":       json.Number("9007199254740991"),
		"literal":  "${{ params.secret }}",
		"nullable": nil,
	}
	second := map[string]any{
		"id":       int64(2),
		"literal":  "{{ user.id }}",
		"nullable": nil,
	}
	rows := []map[string]any{first, second}
	exec := &appMCPCommandExecution{
		capability: &appMCPCommandCapability{},
		results:    map[string]any{"sql_rows": rows},
	}

	value, ok := exec.lookup("steps.sql_rows.outputs")
	outputs, typed := value.([]any)
	if !ok || !typed || outputs == nil || len(outputs) != 2 {
		t.Fatalf("whole SQL output was not exposed as a two-element JSON array: %#v, ok=%t", value, ok)
	}
	firstOutput, ok := outputs[0].(map[string]any)
	if !ok || firstOutput["id"] != json.Number("9007199254740991") || firstOutput["nullable"] != nil || firstOutput["literal"] != "${{ params.secret }}" {
		t.Fatalf("whole SQL output changed its typed first row or interpreted literal text: %#v", outputs[0])
	}
	secondOutput, ok := outputs[1].(map[string]any)
	if !ok || secondOutput["id"] != int64(2) || secondOutput["nullable"] != nil || secondOutput["literal"] != "{{ user.id }}" {
		t.Fatalf("whole SQL output changed its typed second row or interpreted literal text: %#v", outputs[1])
	}
	firstOutput["alias_check"] = true
	if first["alias_check"] != true {
		t.Fatal("whole SQL output did not retain the original typed row maps")
	}

	empty := &appMCPCommandExecution{
		capability: &appMCPCommandCapability{},
		results:    map[string]any{"sql_rows": []map[string]any{}},
	}
	emptyValue, ok := empty.lookup("steps.sql_rows.outputs")
	emptyOutputs, typed := emptyValue.([]any)
	if !ok || !typed || emptyOutputs == nil || len(emptyOutputs) != 0 {
		t.Fatalf("zero-row SQL output was not an empty JSON array: %#v, ok=%t", emptyValue, ok)
	}

	one := &appMCPCommandExecution{
		capability: &appMCPCommandCapability{},
		results:    map[string]any{"sql_rows": []map[string]any{first}},
	}
	firstValue, ok := one.lookup("steps.sql_rows.outputs.first.id")
	if !ok || firstValue != json.Number("9007199254740991") {
		t.Fatalf("first-row lookup changed its existing typed result: %#v, ok=%t", firstValue, ok)
	}
	if _, ok := exec.lookup("steps.sql_rows.outputs.first.id"); ok {
		t.Fatal("first-row lookup unexpectedly admitted a multi-row result")
	}

	phaseOutput := []any{"already-json"}
	other := &appMCPCommandExecution{
		capability: &appMCPCommandCapability{},
		results:    map[string]any{"compute": phaseOutput},
	}
	got, ok := other.lookup("steps.compute.outputs")
	gotPhaseOutput, typed := got.([]any)
	if !ok || !typed || len(gotPhaseOutput) != 1 || gotPhaseOutput[0] != "already-json" {
		t.Fatalf("existing JSON phase output changed type or value: %#v, ok=%t", got, ok)
	}
}

func TestAppMCPCommandWholeSQLOutputRespondValidatesRowsBeforeEncoding(t *testing.T) {
	validRows := []map[string]any{
		{"id": json.Number("9007199254740991"), "literal": "${{ params.secret }}", "nullable": nil},
		{"id": int64(2), "literal": "{{ user.id }}", "nullable": nil},
	}
	exec, ctx, step := wholeSQLRowsRespondFixture(validRows)
	if err := exec.respond(ctx, step); err != nil {
		t.Fatalf("valid bounded whole-SQL response was rejected: %v", err)
	}
	rows, ok := exec.result["rows"].([]any)
	if !ok || len(rows) != 2 {
		t.Fatalf("response did not retain its bounded JSON row array: %#v", exec.result["rows"])
	}
	row, ok := rows[0].(map[string]any)
	if !ok || row["id"] != json.Number("9007199254740991") || row["nullable"] != nil || row["literal"] != "${{ params.secret }}" {
		t.Fatalf("response changed exact numeric/null/template-looking SQL values: %#v", rows[0])
	}

	tests := []struct {
		name string
		rows []map[string]any
	}{
		{
			name: "closed row rejects additional property",
			rows: []map[string]any{
				{"id": json.Number("1"), "literal": "ok", "nullable": nil, "unexpected": true},
				validRows[1],
			},
		},
		{
			name: "closed row rejects wrong property type",
			rows: []map[string]any{
				{"id": "1", "literal": "ok", "nullable": nil},
				validRows[1],
			},
		},
		{name: "array rejects too few rows", rows: validRows[:1]},
		{name: "array rejects too many rows", rows: append(append([]map[string]any(nil), validRows...), validRows[0])},
		{
			name: "invalid UTF-8 remains invalid through response validation",
			rows: []map[string]any{
				{"id": json.Number("1"), "literal": string([]byte{0xff}), "nullable": nil},
				validRows[1],
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			exec, ctx, step := wholeSQLRowsRespondFixture(test.rows)
			if err := exec.respond(ctx, step); err == nil {
				t.Fatal("invalid whole-SQL response unexpectedly passed its closed schema")
			}
			if exec.responses != 0 || ctx.Stopped {
				t.Fatalf("invalid whole-SQL response changed response state: responses=%d stopped=%t", exec.responses, ctx.Stopped)
			}
		})
	}
}

func wholeSQLRowsRespondFixture(rows []map[string]any) (*appMCPCommandExecution, *FlowContext, *FlowStep) {
	closed := false
	rowSchema := &AppMCPSchema{
		Type:                 "object",
		AdditionalProperties: &closed,
		Required:             []string{"id", "literal", "nullable"},
		Properties: map[string]*AppMCPSchema{
			"id":       {Type: "integer"},
			"literal":  {Type: "string", MaxLength: intPointer(128)},
			"nullable": {Type: "null"},
		},
	}
	responseSchema := &AppMCPSchema{
		Type:                 "object",
		AdditionalProperties: &closed,
		Required:             []string{"rows"},
		Properties: map[string]*AppMCPSchema{
			"rows": {Type: "array", MinItems: intPointer(2), MaxItems: intPointer(2), Items: rowSchema},
		},
	}
	exec := &appMCPCommandExecution{
		capability:     &appMCPCommandCapability{},
		results:        map[string]any{"sql_rows": rows},
		responseSchema: responseSchema,
	}
	ctx := &FlowContext{command: exec}
	step := &FlowStep{Respond: &FlowRespond{Status: 200, JSON: map[string]any{"rows": "${{ steps.sql_rows.outputs }}"}}}
	return exec, ctx, step
}
