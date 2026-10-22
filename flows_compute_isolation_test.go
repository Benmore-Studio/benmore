//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// A compute module receives copies of the values its args name. Writing to
// them must not change an earlier step's output or a request field: those
// values were already checked (taint, `if:`) and later steps trust what they
// hold. Before, the request value written into the untainted sql output
// reached sql_dynamic as raw SQL text.
func TestComputeCannotRewriteEarlierStepOutputs(t *testing.T) {
	app := writeComputeFixture(t, "mut.ts", `
		export function merge(a: any): any {
			a.base[0].v = a.patch;
			a.req.tag = "rewritten";
			return a.base;
		}
	`)
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(app.Dir, "data.db"), app.Dir))
	if err != nil {
		t.Fatal(err)
	}
	app.DB = db
	defer app.Shutdown()
	mustExec(t, app.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`)
	mustExec(t, app.DB, `INSERT INTO notes (body) VALUES ('a')`)

	flow := taintTestFlow(
		FlowStep{Name: "cfg", Type: "sql", SQL: "SELECT 'body' AS v"},
		FlowStep{Name: "c", Type: "compute", Compute: &FlowCompute{Module: "mut", Function: "merge", Args: map[string]any{
			"base":  "${{ steps.cfg.outputs.rows }}",
			"patch": "${{ q }}",
			"req":   "${{ obj }}",
		}}},
		// cfg is an untainted lookup: sql_dynamic may read it, so it must
		// still hold what the SQL step returned.
		FlowStep{Name: "dyn", Type: "sql_dynamic", SQL: "SELECT {{cfg.v}} AS x FROM notes"},
		FlowStep{Type: "respond", Respond: &FlowRespond{Status: 200, JSON: map[string]any{
			"v":    "{{cfg.v}}",
			"rows": "{{cfg.1.v | default:'none'}}",
			"c0":   "{{c.0.v}}",
			"tag":  "{{obj.tag}}",
		}}},
	)
	req := httptest.NewRequest("POST", "/api/t", strings.NewReader(`{"q":"zzz' OR '1'='1","obj":{"tag":"orig"}}`))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()
	if err := executeFlowHTTP(app, &flow, rec, req); err != nil {
		t.Fatalf("flow: %v (body %s)", err, rec.Body.String())
	}
	var got struct {
		V, Rows, C0, Tag any
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatalf("response %s: %v", rec.Body.String(), err)
	}
	if got.V != "body" || got.Rows != "none" {
		t.Fatalf("compute rewrote the sql step's output: %s", rec.Body.String())
	}
	if got.Tag != "orig" {
		t.Fatalf("compute rewrote a request field: %s", rec.Body.String())
	}
	// The module's own result is its edited copy.
	if got.C0 != "zzz' OR '1'='1" {
		t.Fatalf("compute result = %s", rec.Body.String())
	}
}

// Containers of other types (typed maps and slices) are copied too, keeping
// their types.
func TestCloneComputeArgCopiesTypedContainers(t *testing.T) {
	strMap := map[string]string{"a": "1"}
	nested := map[string]any{"m": strMap, "s": [][]string{{"x"}}, "rows": []map[string]any{{"k": "v"}}}
	got := cloneComputeArg(nested).(map[string]any)
	got["m"].(map[string]string)["a"] = "2"
	got["s"].([][]string)[0][0] = "y"
	got["rows"].([]map[string]any)[0]["k"] = "w"
	if strMap["a"] != "1" || nested["s"].([][]string)[0][0] != "x" || nested["rows"].([]map[string]any)[0]["k"] != "v" {
		t.Fatalf("clone shares storage with its source: %v", nested)
	}
}
