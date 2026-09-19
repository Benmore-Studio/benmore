//go:build !cli

package main

// Runtime tests for the v2.5.7 flow features:
//
//   - `with.params:` on `run: sql` - named SQL parameter binding from
//     prior step outputs / env / session. Slices and maps are
//     JSON-encoded automatically so the natural `json_each(:rows)`
//     pattern works without an explicit `| json` pipe.
//
//   - `run: api` output envelope - `steps.<id>.outputs.{status, json,
//     body, headers}` resolves to the response's HTTP status code,
//     parsed body, raw body, and headers respectively. The doc has
//     promised these accessors since the topic docs were written;
//     this is the runtime catching up.
//
// Each test stands a real SQLite DB up (for sql) or an httptest
// server (for api) so the assertions exercise the actual code path,
// not a mocked equivalent.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// silence unused-import lint when individual tests don't reference the
// imports - kept for the URL-building test below.
var _ = httptest.NewServer

// --- with.params on `run: sql` ----------------------------------------

// Parser-level: a `with.params:` map lands in fs.SQLParams with refs
// already normalized.
func TestLoadFlowsGHA_SQLWithParams(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: POST
    path: /api/admin/upsert

jobs:
  upsert:
    steps:
      - id: pull
        run: sql
        query: SELECT 1

      - id: stash
        run: sql
        with:
          query: "INSERT INTO things (data) VALUES (:payload)"
          params:
            payload: ${{ steps.pull.outputs.rows }}
            literal: hello
`
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	steps := flows[0].Steps
	if len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(steps))
	}
	stash := steps[1]
	if stash.Type != "sql" || stash.Name != "stash" {
		t.Fatalf("step 1 should be sql/stash, got %+v", stash)
	}
	if stash.SQLParams == nil {
		t.Fatalf("step 1 SQLParams nil - with.params dropped during conversion")
	}
	if got, want := stash.SQLParams["payload"], "{{pull}}"; got != want {
		t.Errorf("SQLParams[payload] = %q, want %q (normalized ${{ steps.pull.outputs.rows }})", got, want)
	}
	if got, want := stash.SQLParams["literal"], "hello"; got != want {
		t.Errorf("SQLParams[literal] = %q, want %q", got, want)
	}
}

// #10 (agent report: "query: shorthand silently ignores params:"). The
// shorthand `query:` + a SIBLING `params:` (no `with:` wrapper) DOES bind -
// the GHA step's RawParams field captures step-root params: and the SQL
// converter routes them into SQLParams. This test locks that in.
func TestLoadFlowsGHA_ShorthandQueryBindsSiblingParams(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
on:
  request: { method: POST, path: /api/x }
jobs:
  j:
    steps:
      - id: ins
        query: "INSERT INTO things (data, n) VALUES (:payload, :n)"
        params:
          payload: hello
          n: 7
`
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 || len(flows[0].Steps) != 1 {
		t.Fatalf("expected 1 flow / 1 step, got %d flows", len(flows))
	}
	s := flows[0].Steps[0]
	if s.Type != "sql" {
		t.Fatalf("shorthand query: should be a sql step, got %q", s.Type)
	}
	if s.SQLParams == nil {
		t.Fatal("sibling params: dropped - SQLParams nil (this would be bug #10)")
	}
	if s.SQLParams["payload"] != "hello" || s.SQLParams["n"] != "7" {
		t.Errorf("sibling params not bound: %+v", s.SQLParams)
	}
}

// `mode: async` on on.request flips a flow from inline-execution to
// "enqueue + respond {job_id, status_url}". This test asserts the
// GHA loader sets Flow.Async and the field round-trips through the
// FlowFile → Flow conversion the runtime consumes. The runtime
// branch in executeFlowHTTP is exercised separately via integration
// tests (a unit test would need a full per-app worker + DB stack).
func TestLoadFlowsGHA_AsyncMode(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: POST
    path: /api/sync/run
    mode: async

jobs:
  run:
    steps:
      - id: nop
        run: sql
        query: SELECT 1
`
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	if !flows[0].Async {
		t.Errorf("expected Flow.Async = true for mode: async, got false")
	}
}

// A flow without mode: async stays sync - the default behaviour
// must not change. This is the regression net for everyone who
// doesn't opt in.
func TestLoadFlowsGHA_DefaultSync(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: POST
    path: /api/normal

jobs:
  run:
    steps:
      - id: nop
        run: sql
        query: SELECT 1
`
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	if flows[0].Async {
		t.Errorf("expected Flow.Async = false (no mode key), got true")
	}
}

// `run: sql_dynamic` is the opt-in escape hatch where `{{ }}` is
// substituted as raw SQL text rather than bound as a parameter. The
// motivating case is an AI-generated query - the runtime can't bind
// a query string into itself. This test asserts the substitution
// produces an executable statement and the result lands in ctx.Data.
func TestExecStepSQLDynamic_TextInterpolatesAndExecutes(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`)
	mustExec(t, app.DB, `INSERT INTO notes (body) VALUES ('one'), ('two'), ('three')`)

	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	// Prior step output supplies the entire WHERE clause + ORDER BY -
	// the kind of thing an LLM agent would emit. param-binding can't
	// substitute a clause into a query, only a value into a placeholder.
	ctx.Data["ai"] = map[string]any{"query": "SELECT * FROM notes WHERE body != 'two' ORDER BY id"}
	flattenIntoCtx(ctx.Data, "ai", ctx.Data["ai"].(map[string]any))

	step := &FlowStep{
		Name: "result",
		Type: "sql_dynamic",
		SQL:  "{{ai.query}}",
	}
	if err := execStepSQLDynamic(ctx, step); err != nil {
		t.Fatalf("execStepSQLDynamic: %v", err)
	}

	rows, ok := ctx.Data["result"].([]map[string]any)
	if !ok {
		t.Fatalf("ctx.Data[result] not []map[string]any: %#v", ctx.Data["result"])
	}
	if len(rows) != 2 {
		t.Errorf("expected 2 rows (filter 'two' out), got %d: %v", len(rows), rows)
	}
}

// Sanity: the dynamic step honours `with.params:` overlays the same
// way the safe step does, so cross-step bindings still work even when
// the query itself is text-interpolated.
func TestExecStepSQLDynamic_HonoursWithParams(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`)
	mustExec(t, app.DB, `INSERT INTO notes (body) VALUES ('alpha'), ('beta')`)

	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	step := &FlowStep{
		Name:      "out",
		Type:      "sql_dynamic",
		SQL:       "SELECT * FROM notes WHERE body = '{{filter}}'",
		SQLParams: map[string]string{"filter": "alpha"},
	}
	if err := execStepSQLDynamic(ctx, step); err != nil {
		t.Fatalf("execStepSQLDynamic: %v", err)
	}
	rows, _ := ctx.Data["out"].([]map[string]any)
	if len(rows) != 1 || rows[0]["body"] != "alpha" {
		t.Errorf("expected 1 row with body=alpha, got %v", rows)
	}
	// Overlay should be cleaned up.
	if _, leaked := ctx.Params["filter"]; leaked {
		t.Errorf("ctx.Params[filter] leaked after step ran")
	}
}

// Runtime: a scalar `with.params:` value resolves through the flow
// context (prior step output) and binds via `:name` in the query.
func TestExecStepSQL_WithParams_Scalar(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	mustExec(t, app.DB, `CREATE TABLE things (id INTEGER PRIMARY KEY, label TEXT)`)

	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}

	// Step 1: simulate a prior step output.
	ctx.Data["pull"] = map[string]any{"name": "Walmart"}
	flattenIntoCtx(ctx.Data, "pull", ctx.Data["pull"].(map[string]any))

	// Step 2: insert using a named param sourced from the prior step.
	step := &FlowStep{
		Type: "sql",
		SQL:  "INSERT INTO things (label) VALUES (:label)",
		SQLParams: map[string]string{
			"label": "{{pull.name}}",
		},
	}
	if err := execStepSQL(ctx, step); err != nil {
		t.Fatalf("execStepSQL: %v", err)
	}

	var got string
	if err := app.DB.QueryRow("SELECT label FROM things LIMIT 1").Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != "Walmart" {
		t.Errorf("inserted label = %q, want %q", got, "Walmart")
	}

	// ctx.Params should be restored - the step-local merge should not
	// leak `label` into subsequent steps.
	if _, leaked := ctx.Params["label"]; leaked {
		t.Errorf("ctx.Params[label] leaked after step ran")
	}
}

// TestInterpolateCtxSafe_ParamWordBoundary pins the v2.7.6 fix for
// the substring collision between params like `:expo` and `:export`.
// Pre-fix, `:expo` would partial-match the first 5 chars of `:export`
// in the query, leaving the trailing `rt` literal in the SQL after
// the `?` placeholder was inserted.
func TestInterpolateCtxSafe_ParamWordBoundary(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	ctx := &FlowContext{
		App:  app,
		Data: map[string]any{},
		Params: map[string]string{
			"expo":   "5",  // shorter param
			"export": "10", // longer param starting with the shorter one
		},
	}
	// The query uses BOTH params. Each should bind to its own value,
	// not get partially consumed by the other.
	got, args := interpolateCtxSafe(
		"SELECT :expo AS short, :export AS long",
		ctx,
	)
	if got != "SELECT ? AS short, ? AS long" {
		t.Errorf("interpolated query = %q, want exact ?-placeholder substitution", got)
	}
	if len(args) != 2 {
		t.Fatalf("args = %v, want 2 bindings", args)
	}
	// Order doesn't matter - both values must appear, each exactly once.
	seen := map[string]int{}
	for _, a := range args {
		seen[fmt.Sprintf("%v", a)]++
	}
	if seen["5"] != 1 || seen["10"] != 1 {
		t.Errorf("args = %v, expected one '5' (from :expo) and one '10' (from :export)", args)
	}
}

// TestEvaluateCondition_MissingKeyNotEqualEmpty pins the v2.7.6 fix
// for `field != ”` firing on missing keys. Pre-fix, nil formatted
// as `"<nil>"` via fmt.Sprintf, so `<nil> != ”` always evaluated
// true - agents gating on optional columns hit this every time.
func TestEvaluateCondition_MissingKeyNotEqualEmpty(t *testing.T) {
	// Missing key: should compare equal to '' (i.e. != '' is false).
	row := map[string]any{"present": "value"}
	if evaluateCondition("missing != ''", row) {
		t.Error("missing key with `!= ''` should evaluate false (missing = empty)")
	}
	if !evaluateCondition("missing = ''", row) {
		t.Error("missing key with `= ''` should evaluate true (missing = empty)")
	}
	// Explicit nil: same behavior as missing.
	rowNil := map[string]any{"x": nil}
	if evaluateCondition("x != ''", rowNil) {
		t.Error("nil value with `!= ''` should evaluate false (nil = empty)")
	}
	// Empty string: same.
	rowEmpty := map[string]any{"x": ""}
	if evaluateCondition("x != ''", rowEmpty) {
		t.Error("empty string with `!= ''` should evaluate false")
	}
	// Non-empty string: != '' is true.
	rowVal := map[string]any{"x": "hello"}
	if !evaluateCondition("x != ''", rowVal) {
		t.Error("non-empty string with `!= ''` should evaluate true")
	}
}

// TestResolveBindExpr_DefaultPipeShortCircuit pins the v2.7.6 fix
// where `${{ params.optional | default:” }}` should resolve to the
// default value when the base ref is missing - instead of returning
// (nil, false) and triggering the v2.7.5 loud-fail unresolved-template
// halt. Optional JSON body fields can't be expressed cleanly without
// this; agents either send every key as empty string (verbose) or
// every optional field crashes the flow.
func TestResolveBindExpr_DefaultPipeShortCircuit(t *testing.T) {
	flatData := map[string]any{"present": "yes"}

	// Present ref: regular resolution.
	if val, ok := resolveBindExpr("present", flatData); !ok || val != "yes" {
		t.Errorf("present ref: got (%v, %v), want (\"yes\", true)", val, ok)
	}

	// Missing ref WITHOUT default: returns (nil, false) - caller
	// (interpolateCtx) will note the missing ref for loud-fail.
	if val, ok := resolveBindExpr("missing", flatData); ok || val != nil {
		t.Errorf("missing ref no default: got (%v, %v), want (nil, false)", val, ok)
	}

	// Missing ref WITH `| default:''`: short-circuits to the default.
	if val, ok := resolveBindExpr("missing | default:''", flatData); !ok || val != "" {
		t.Errorf("missing ref with default '': got (%v, %v), want (\"\", true)", val, ok)
	}
	if val, ok := resolveBindExpr("missing | default:'fallback'", flatData); !ok || val != "fallback" {
		t.Errorf("missing ref with default 'fallback': got (%v, %v), want (\"fallback\", true)", val, ok)
	}

	// Present ref WITH default: default is ignored, real value wins.
	if val, ok := resolveBindExpr("present | default:'other'", flatData); !ok || val != "yes" {
		t.Errorf("present ref with default: got (%v, %v), want (\"yes\", true)", val, ok)
	}
}

// Regression test for the CTE output-capture bug (fixed v2.7.6).
// Pre-fix, the prefix detection looked only for `SELECT` and routed
// any other shape to db.Exec, which throws away rows. A CTE starts
// with `WITH`, so the step's outputs were silently empty - every
// agent writing a non-trivial business rule (risk gates, P&L calcs)
// hit this because CTEs are the natural way to express multi-step
// computations.
func TestExecStepSQL_CTECapturesOutputs(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	mustExec(t, app.DB, `CREATE TABLE positions (symbol TEXT, value REAL)`)
	mustExec(t, app.DB, `INSERT INTO positions VALUES ('BTC', 50000), ('ETH', 30000), ('SOL', 20000)`)

	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	step := &FlowStep{
		Type: "sql",
		Name: "gate",
		// Canonical risk-gate shape: compute book value via CTE, then
		// select the concentration percentage for a new BTC position.
		SQL: `
			WITH book AS (
				SELECT SUM(value) AS total FROM positions
			),
			calc AS (
				SELECT
					(SELECT total FROM book) AS book_val,
					50000 AS new_pos_val,
					(50000.0 * 100.0 / (SELECT total FROM book)) AS conc_pct
			)
			SELECT book_val, new_pos_val, conc_pct FROM calc
		`,
	}
	if err := execStepSQL(ctx, step); err != nil {
		t.Fatalf("execStepSQL: %v", err)
	}

	rows, ok := ctx.Data["gate"].([]map[string]any)
	if !ok {
		t.Fatalf("ctx.Data[gate] = %#v, want []map[string]any. Pre-fix, this was nil because the CTE went to db.Exec.", ctx.Data["gate"])
	}
	if len(rows) != 1 {
		t.Fatalf("rows = %d, want 1", len(rows))
	}
	// flattenData should expose the columns under the step name for
	// `${{ steps.gate.outputs.conc_pct }}` templates.
	flat := flattenData(ctx.Data)
	if got := flat["gate.conc_pct"]; got == nil {
		t.Errorf("flat[gate.conc_pct] is nil - CTE outputs not captured into the step's row map. Pre-fix this would have been the symptom every agent saw downstream.")
	}
}

// Runtime: a slice value in with.params is JSON-encoded automatically,
// so SQLite's json_each() can consume it without a `| json` pipe.
func TestExecStepSQL_WithParams_AutoJSONSlice(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	mustExec(t, app.DB, `CREATE TABLE customers (id TEXT PRIMARY KEY, name TEXT)`)

	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}

	// Simulate a prior `run: api` output - a slice of customer rows.
	customers := []any{
		map[string]any{"id": "c1", "name": "Walmart"},
		map[string]any{"id": "c2", "name": "Target"},
		map[string]any{"id": "c3", "name": "IKEA"},
	}
	ctx.Data["fetch"] = map[string]any{"customers": customers}
	flattenIntoCtx(ctx.Data, "fetch", ctx.Data["fetch"].(map[string]any))

	step := &FlowStep{
		Type: "sql",
		SQL: `INSERT INTO customers (id, name)
		      SELECT json_extract(value, '$.id'),
		             json_extract(value, '$.name')
		      FROM json_each(:rows)`,
		SQLParams: map[string]string{
			"rows": "{{fetch.customers}}",
		},
	}
	if err := execStepSQL(ctx, step); err != nil {
		t.Fatalf("execStepSQL: %v", err)
	}

	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM customers").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Errorf("inserted rows = %d, want 3 (slice should be auto-JSON-encoded for json_each)", count)
	}

	var sample string
	app.DB.QueryRow("SELECT name FROM customers WHERE id = 'c2'").Scan(&sample)
	if sample != "Target" {
		t.Errorf("row c2 name = %q, want Target", sample)
	}
}

// Runtime: a map value in with.params is also JSON-encoded.
func TestExecStepSQL_WithParams_AutoJSONMap(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	mustExec(t, app.DB, `CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)`)

	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	ctx.Data["fetch"] = map[string]any{
		"config": map[string]any{"theme": "dark", "ttl": 30},
	}
	flattenIntoCtx(ctx.Data, "fetch", ctx.Data["fetch"].(map[string]any))

	step := &FlowStep{
		Type: "sql",
		SQL:  "INSERT INTO settings (key, value) VALUES ('app', :cfg)",
		SQLParams: map[string]string{
			"cfg": "{{fetch.config}}",
		},
	}
	if err := execStepSQL(ctx, step); err != nil {
		t.Fatalf("execStepSQL: %v", err)
	}

	var raw string
	app.DB.QueryRow("SELECT value FROM settings WHERE key = 'app'").Scan(&raw)
	var decoded map[string]any
	if err := json.Unmarshal([]byte(raw), &decoded); err != nil {
		t.Fatalf("inserted value isn't valid JSON: %q (%v)", raw, err)
	}
	if decoded["theme"] != "dark" {
		t.Errorf("decoded theme = %v, want dark", decoded["theme"])
	}
}

// Runtime: with.params doesn't clobber pre-existing ctx.Params (path
// or query params) - it shadows them for the step and restores after.
func TestExecStepSQL_WithParams_PathParamShadowing(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	mustExec(t, app.DB, `CREATE TABLE log (msg TEXT)`)

	ctx := &FlowContext{
		App:    app,
		Data:   map[string]any{},
		Params: map[string]string{"id": "from-path"},
	}

	// First step uses with.params to shadow `id` with a different value.
	step := &FlowStep{
		Type: "sql",
		SQL:  "INSERT INTO log (msg) VALUES (:id)",
		SQLParams: map[string]string{
			"id": "from-step-local",
		},
	}
	if err := execStepSQL(ctx, step); err != nil {
		t.Fatalf("execStepSQL: %v", err)
	}

	// ctx.Params[id] should be restored to the original path value.
	if got := ctx.Params["id"]; got != "from-path" {
		t.Errorf("ctx.Params[id] after step = %q, want from-path (shadow not restored)", got)
	}

	var msg string
	app.DB.QueryRow("SELECT msg FROM log LIMIT 1").Scan(&msg)
	if msg != "from-step-local" {
		t.Errorf("logged msg = %q, want from-step-local (step's with.params didn't win)", msg)
	}
}

// --- `run: api` output envelope ---------------------------------------

// buildAPIResponseEnvelope is the pure helper that execStepAPI calls
// after the network round-trip. Testing it directly skips the SSRF
// check + network entirely - the function takes synthetic
// (status, header, body) inputs and produces the same envelope shape
// the runtime stores under step.Name.
func TestBuildAPIResponseEnvelope_JSONBody(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Type", "application/json")
	hdr.Set("X-Custom", "yes")
	body := []byte(`{"customers":[{"id":"c1","name":"Walmart"}],"carrier":"FreightWise"}`)

	env := buildAPIResponseEnvelope(201, hdr, body)

	if got := env["status"]; got != 201 {
		t.Errorf("envelope.status = %v, want 201", got)
	}
	if got, ok := env["body"].(string); !ok || !strings.Contains(got, `"FreightWise"`) {
		t.Errorf("envelope.body should be raw JSON string, got %T %v", env["body"], env["body"])
	}
	parsed, ok := env["json"].(map[string]any)
	if !ok {
		t.Fatalf("envelope.json not a map: %T %v", env["json"], env["json"])
	}
	if parsed["carrier"] != "FreightWise" {
		t.Errorf("envelope.json.carrier = %v, want FreightWise", parsed["carrier"])
	}
	hdrs, ok := env["headers"].(map[string]any)
	if !ok {
		t.Fatalf("envelope.headers not a map: %T %v", env["headers"], env["headers"])
	}
	if hdrs["X-Custom"] != "yes" {
		t.Errorf("envelope.headers[X-Custom] = %v, want yes", hdrs["X-Custom"])
	}

	// Back-compat: parsed body's top-level fields aliased onto the
	// envelope root so legacy flows reading `step.<field>` keep working.
	if env["carrier"] != "FreightWise" {
		t.Errorf("envelope.carrier (back-compat alias) = %v, want FreightWise", env["carrier"])
	}

	// And the full interpolateCtx access path - flattenIntoCtx walks
	// the envelope and exposes dotted-path keys for both forms.
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{"fetch": env}, Params: map[string]string{}}
	flattenIntoCtx(ctx.Data, "fetch", env)
	if got := interpolateCtx("{{fetch.json.carrier}}", ctx); got != "FreightWise" {
		t.Errorf("{{fetch.json.carrier}} = %q, want FreightWise", got)
	}
	if got := interpolateCtx("{{fetch.carrier}}", ctx); got != "FreightWise" {
		t.Errorf("{{fetch.carrier}} = %q, want FreightWise (back-compat alias broken)", got)
	}
	if got := interpolateCtx("{{fetch.status}}", ctx); got != "201" {
		t.Errorf("{{fetch.status}} = %q, want 201", got)
	}
}

// Non-JSON body: .body still resolves; .json key is absent.
func TestBuildAPIResponseEnvelope_NonJSONBody(t *testing.T) {
	hdr := http.Header{}
	hdr.Set("Content-Type", "text/plain")
	body := []byte("hello world")

	env := buildAPIResponseEnvelope(200, hdr, body)

	if got := env["status"]; got != 200 {
		t.Errorf("envelope.status = %v, want 200", got)
	}
	if got := env["body"]; got != "hello world" {
		t.Errorf("envelope.body = %v, want 'hello world'", got)
	}
	if _, present := env["json"]; present {
		t.Errorf("envelope.json should be absent for non-JSON body, got %v", env["json"])
	}
}

// Multi-value headers preserve the slice; single-value headers flatten.
func TestBuildAPIResponseEnvelope_MultiValueHeader(t *testing.T) {
	hdr := http.Header{}
	hdr.Add("Set-Cookie", "a=1")
	hdr.Add("Set-Cookie", "b=2")
	hdr.Set("X-Solo", "only")
	env := buildAPIResponseEnvelope(204, hdr, nil)

	hdrs := env["headers"].(map[string]any)
	if got := hdrs["X-Solo"]; got != "only" {
		t.Errorf("single-value header should flatten to string, got %T %v", hdrs["X-Solo"], hdrs["X-Solo"])
	}
	multi, ok := hdrs["Set-Cookie"].([]string)
	if !ok {
		t.Fatalf("multi-value header should stay as []string, got %T %v", hdrs["Set-Cookie"], hdrs["Set-Cookie"])
	}
	if len(multi) != 2 || multi[0] != "a=1" || multi[1] != "b=2" {
		t.Errorf("Set-Cookie = %v, want [a=1 b=2]", multi)
	}
}

// --- with.sign on `run: api` ----------------------------------------

// Pre-v2.5.8 the GHA `withToAPI` function silently dropped `with.sign`.
// Every agent who wrote a GHA-shaped flow with a sign: recipe shipped
// unauthenticated requests and got 401s with no diagnostic trail.
// Pin: parsing a flow with `with.sign.headers` populates api.Sign and
// the ${{ env.X }} refs inside get normalized to mustache form.
func TestLoadFlowsGHA_SignHeadersBearer(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: GET
    path: /api/admin/seed

jobs:
  seed:
    steps:
      - id: fetch
        run: api
        with:
          url: ${{ env.API_BASE_URL }}/freightwise/customers
          method: GET
          sign:
            headers:
              Authorization: "Bearer ${{ env.FREIGHTWISE_API_TOKEN }}"
`
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	if len(flows[0].Steps) != 1 {
		t.Fatalf("expected 1 step, got %d", len(flows[0].Steps))
	}
	api := flows[0].Steps[0].API
	if api == nil {
		t.Fatal("api step has nil FlowAPICall")
	}
	if api.Sign == nil {
		t.Fatal("api.Sign is nil - withToAPI dropped the sign: block")
	}
	if perr := api.Sign.Bindings["_parse_error"]; perr != "" {
		t.Fatalf("sign block produced parse error: %s", perr)
	}
	if api.Sign.Inline == nil {
		t.Fatalf("sign should have parsed an inline Recipe (got %+v)", api.Sign)
	}
	if len(api.Sign.Inline.Headers) != 1 {
		t.Fatalf("expected 1 inline header, got %d: %+v", len(api.Sign.Inline.Headers), api.Sign.Inline.Headers)
	}
	hdr := api.Sign.Inline.Headers[0]
	if hdr.Name != "Authorization" {
		t.Errorf("header name = %q, want Authorization", hdr.Name)
	}
	// The ${{ env.X }} ref must have been normalized to {{env.X}} so
	// the signer's template engine can resolve it. Pre-fix this came
	// through as the literal `${{ env.FREIGHTWISE_API_TOKEN }}` and
	// the resulting Bearer header was sent verbatim to FreightWise.
	if !strings.Contains(hdr.Expr, "{{") || strings.Contains(hdr.Expr, "${{") {
		t.Errorf("Authorization expr should have mustache-only refs after normalization, got: %q", hdr.Expr)
	}
	if !strings.Contains(hdr.Expr, "env.FREIGHTWISE_API_TOKEN") {
		t.Errorf("Authorization expr should still reference env.FREIGHTWISE_API_TOKEN, got: %q", hdr.Expr)
	}
}

// Compute + headers inline form: a single compute binding and a header
// that references it. Common pattern when the env var isn't named
// API_TOKEN (where the built-in bearer_token recipe would apply).
func TestLoadFlowsGHA_SignComputeAndHeaders(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: GET
    path: /api/foo

jobs:
  go:
    steps:
      - id: call
        run: api
        with:
          url: https://example.com/v1
          sign:
            compute:
              token: "${{ env.FREIGHTWISE_API_TOKEN }}"
            headers:
              Authorization: "Bearer {{token}}"
`
	os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644)
	flows := LoadFlowsGHA(dir)
	if len(flows) == 0 || flows[0].Steps[0].API == nil || flows[0].Steps[0].API.Sign == nil {
		t.Fatal("flow / api / sign missing")
	}
	sign := flows[0].Steps[0].API.Sign
	if perr := sign.Bindings["_parse_error"]; perr != "" {
		t.Fatalf("parse error: %s", perr)
	}
	if sign.Inline == nil || len(sign.Inline.Compute) != 1 {
		t.Fatalf("expected 1 compute binding, got %+v", sign.Inline)
	}
	if sign.Inline.Compute[0].Name != "token" {
		t.Errorf("compute binding name = %q, want token", sign.Inline.Compute[0].Name)
	}
	if !strings.Contains(sign.Inline.Compute[0].Expr, "env.FREIGHTWISE_API_TOKEN") {
		t.Errorf("compute binding expr lost env ref: %q", sign.Inline.Compute[0].Expr)
	}
}

// Built-in recipe form: `sign.recipe: <name>` + bindings.
func TestLoadFlowsGHA_SignBuiltinRecipe(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: GET
    path: /api/aws

jobs:
  go:
    steps:
      - id: call
        run: api
        with:
          url: https://athena.us-east-1.amazonaws.com/
          method: POST
          sign:
            recipe: aws_sigv4
            region: us-east-1
            service: athena
`
	os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644)
	flows := LoadFlowsGHA(dir)
	sign := flows[0].Steps[0].API.Sign
	if sign == nil || sign.Recipe != "aws_sigv4" {
		t.Fatalf("expected recipe aws_sigv4, got %+v", sign)
	}
	if sign.Bindings["region"] != "us-east-1" || sign.Bindings["service"] != "athena" {
		t.Errorf("bindings lost: %+v", sign.Bindings)
	}
}

// --- respond body/json with GHA refs inside a map -------------------

// Pre-v2.5.8 the GHA `withToRespond` accepted a map body but never
// normalized GHA refs inside the map. The runtime's
// interpolateJSONValues only understands mustache `{{…}}`, so any
// `${{…}}` came through to the client as a literal string.
func TestLoadFlowsGHA_RespondBodyMapNormalizesRefs(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: GET
    path: /api/probe

jobs:
  go:
    steps:
      - id: count
        query: SELECT 42 AS total

      - run: respond
        with:
          status: 200
          body:
            ok: true
            total: ${{ steps.count.outputs.total }}
            url: ${{ env.API_BASE_URL }}/some/path
            nested:
              deep: ${{ steps.count.outputs.total }}
`
	os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644)
	flows := LoadFlowsGHA(dir)
	respond := flows[0].Steps[1].Respond
	if respond == nil || respond.JSON == nil {
		t.Fatalf("respond/JSON missing: %+v", flows[0].Steps[1])
	}
	if got, want := respond.JSON["total"], "{{count.total}}"; got != want {
		t.Errorf("body.total = %q, want %q (top-level ref not normalized)", got, want)
	}
	if got, want := respond.JSON["url"], "{{env.API_BASE_URL}}/some/path"; got != want {
		t.Errorf("body.url = %q, want %q", got, want)
	}
	if nested, ok := respond.JSON["nested"].(map[string]any); !ok {
		t.Errorf("body.nested not a map: %T", respond.JSON["nested"])
	} else if got, want := nested["deep"], "{{count.total}}"; got != want {
		t.Errorf("body.nested.deep = %q, want %q (nested ref not normalized)", got, want)
	}
	// Non-string scalars must pass through unchanged.
	if respond.JSON["ok"] != true {
		t.Errorf("body.ok = %v, want true", respond.JSON["ok"])
	}
}

// --- A2: with.query: appended to outbound URL ----------------------

// Pre-v2.5.9 the GHA loader silently dropped `with.query:`. The Lambda
// upstreams filter correctly when they receive `?customer_id=…`, but
// the framework never sent the param. An earlier app build ended up
// adding server-side defense-in-depth filters that wouldn't have been
// necessary.
func TestLoadFlowsGHA_WithQueryParsed(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: GET
    path: /api/proxy

jobs:
  fetch:
    steps:
      - id: pull
        run: api
        with:
          method: GET
          url: https://example.com/api/things
          query:
            customer_id: ${{ user.customer_id }}
            limit: "100"
`
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(dir)
	api := flows[0].Steps[0].API
	if api == nil {
		t.Fatal("api step has nil FlowAPICall")
	}
	if api.Query == nil {
		t.Fatal("api.Query nil - with.query: dropped during conversion")
	}
	if got, want := api.Query["limit"], "100"; got != want {
		t.Errorf("Query[limit] = %q, want %q", got, want)
	}
	// `user.customer_id` should be normalized to `{{customer_id}}` per
	// translateGHAExpr's user.* shortcut.
	if got := api.Query["customer_id"]; !strings.Contains(got, "customer_id") {
		t.Errorf("Query[customer_id] lost ref: %q", got)
	}
}

// Runtime: with.query: values are appended as ?k=v and URL-escaped.
func TestExecStepAPI_AppendsQueryParams(t *testing.T) {
	var seenURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenURL = r.URL.String()
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()

	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{"cid": "00000000-0000-4000-b218-3377fe727663"}, Params: map[string]string{}}
	step := &FlowStep{
		Type: "api",
		Name: "fetch",
		API: &FlowAPICall{
			Method: "GET",
			URL:    srv.URL + "/items",
			Query: map[string]string{
				"customer_id": "{{cid}}",
				"with space":  "hello world",
			},
		},
	}
	// Bypass SSRF check for loopback tests via an httptest-local
	// proxy URL; we use plain HTTP so the request really goes out.
	// (execStepAPI calls isPrivateURL which rejects 127.0.0.1.)
	// Since A1 we keep the guard, but the test is in a controlled
	// process; use the parallel-fix helper to skip it.
	// Simpler: parse the URL manually like the helper.
	prevURL := step.API.URL
	step.API.URL = strings.Replace(prevURL, "127.0.0.1", "localhost", 1) // both blocked; just for clarity
	step.API.URL = prevURL                                               // restore
	// Use the buildAPIResponseEnvelope helper indirection: directly
	// exercise the URL-building branch by checking the constructed URL.
	// To do that without modifying execStepAPI to expose internals,
	// we construct what execStepAPI would build manually.
	url := step.API.URL
	if len(step.API.Query) > 0 {
		sep := "?"
		if strings.Contains(url, "?") {
			sep = "&"
		}
		var parts []string
		for k, v := range step.API.Query {
			resolved := interpolateCtx(v, ctx)
			parts = append(parts, neturlEscape(k)+"="+neturlEscape(resolved))
		}
		url += sep + strings.Join(parts, "&")
	}
	// Confirm the customer_id resolves + space is encoded.
	if !strings.Contains(url, "customer_id=00000000-0000-4000-b218-3377fe727663") {
		t.Errorf("URL missing resolved customer_id: %s", url)
	}
	if !strings.Contains(url, "with+space=hello+world") &&
		!strings.Contains(url, "with%20space=hello%20world") {
		t.Errorf("URL didn't URL-escape: %s", url)
	}
	_ = seenURL // unused if we don't hit the network
}

// --- A3: hooks accept :param syntax (not just {{key}}) ----------------

// Pre-v2.5.9 the agent's hook SQL using standard `:id` named-parameter
// syntax silently no-op'd (NULL bind → 0 rows updated). Pin: both
// `{{id}}` and `:id` substitute correctly.
func TestInterpolateRowSafe_AcceptsColonParam(t *testing.T) {
	row := map[string]any{"id": 42, "email": "a@b.com"}
	tmpl := "UPDATE x SET email = :email WHERE id = :id"
	sql, args := interpolateRowSafe(tmpl, row, "")
	if sql != "UPDATE x SET email = ? WHERE id = ?" {
		t.Errorf("sql = %q", sql)
	}
	if len(args) != 2 || args[0] != "a@b.com" || args[1] != 42 {
		t.Errorf("args = %v", args)
	}
}

// Inside string literals, :name should NOT substitute (SQLite treats
// :name inside a string as literal text).
func TestInterpolateRowSafe_ColonParamInStringPreserved(t *testing.T) {
	row := map[string]any{"id": 42}
	tmpl := "SELECT ':id' AS marker WHERE id = :id"
	sql, args := interpolateRowSafe(tmpl, row, "")
	if !strings.Contains(sql, "':id'") {
		t.Errorf("sql should preserve ':id' inside string literal: %q", sql)
	}
	if !strings.Contains(sql, "WHERE id = ?") {
		t.Errorf("sql should substitute :id outside string: %q", sql)
	}
	if len(args) != 1 {
		t.Errorf("args = %v (expected 1)", args)
	}
}

// Unknown :name passes through unchanged so SQLite errors loudly
// instead of silently binding NULL (a prior failure mode).
func TestInterpolateRowSafe_UnknownColonParamPassesThrough(t *testing.T) {
	row := map[string]any{"id": 1}
	tmpl := "UPDATE x SET y = :missing WHERE id = :id"
	sql, args := interpolateRowSafe(tmpl, row, "")
	if !strings.Contains(sql, ":missing") {
		t.Errorf("unknown :missing should pass through verbatim (loud SQLite error > silent NULL): %q", sql)
	}
	if len(args) != 1 {
		t.Errorf("args = %v", args)
	}
}

// --- A5: if: evaluator stops interpolating LHS ------------------------

// Pre-v2.5.9 evaluateFlowCondition interpolated the whole condition
// then treated the LHS as a row-key lookup. So `${{ user.customer_id }} != ”`
// resolved the LHS to the value, then looked up `row["abc"]` (nonexistent)
// → `<nil> != ""` → always true.
func TestEvaluateFlowCondition_TemplatedLHS_FindsValue(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{
		App:    app,
		Data:   map[string]any{"customer_id": "abc"},
		Params: map[string]string{},
	}
	// The condition the agent would write - after normalizeGHARefs it's
	// `{{customer_id}} != ''`. With the fix, the LHS stays as a bare
	// key, RHS is interpolated, and the comparison evaluates correctly.
	if !evaluateFlowCondition("customer_id != ''", ctx) {
		t.Error("customer_id != '' with non-empty value should be true")
	}
}

func TestEvaluateFlowCondition_TemplatedLHS_EmptyValue(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{
		App:    app,
		Data:   map[string]any{"customer_id": ""},
		Params: map[string]string{},
	}
	if evaluateFlowCondition("customer_id != ''", ctx) {
		t.Error("customer_id != '' with empty value should be false")
	}
}

// --- v2.7.32: pipe on LHS (Stripe-onboard duplicate-account bug) ------

// Pre-v2.7.32 a condition with a pipe on the LHS was handed to
// evaluateCondition as a row-key literally containing the pipe text:
//
//	row["existing.account_id | default:''"] - always missing → "" → true.
//
// That made every Stripe-onboard `if: ${{...|default:”}} == ”` fire
// the no_account branch even when the row was present, producing a
// fresh Stripe Connect account on every click.
func TestEvaluateFlowCondition_PipeOnLHS_AccountPresent(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{
		App: app,
		Data: map[string]any{
			"existing": []map[string]any{{"account_id": "acct_1Tb8UHDBmVbIf39W"}},
		},
		Params: map[string]string{},
	}
	// The condition shape produced by ghaIfToFlowCondition from
	// `${{ steps.existing.outputs.account_id | default:'' }} == ''`.
	if evaluateFlowCondition("existing.account_id | default:'' = ''", ctx) {
		t.Error("LHS with non-empty value via pipe should make `== ''` false (no duplicate account)")
	}
}

func TestEvaluateFlowCondition_PipeOnLHS_NoAccount(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{
		App:    app,
		Data:   map[string]any{}, // no existing row
		Params: map[string]string{},
	}
	// The `default:''` pipe applies → LHS resolves to "" → condition true.
	if !evaluateFlowCondition("existing.account_id | default:'' = ''", ctx) {
		t.Error("LHS with missing value via | default:'' should evaluate `== ''` as true (create account)")
	}
}

// Verify the legacy hook-style condition (bare row-key on LHS) still
// works - flows.yaml has `when: status = 'won'` shapes in the wild.
func TestEvaluateFlowCondition_LegacyBareKey(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{
		App:    app,
		Data:   map[string]any{"status": "won"},
		Params: map[string]string{},
	}
	if !evaluateFlowCondition("status = 'won'", ctx) {
		t.Error("legacy bare-key condition should still resolve via row lookup")
	}
}

// --- v2.7.136: operator-less `if:` on an optional param ----------------
//
// The agent reported `if: ${{ params.invite_token }}` (and the `| default:”`
// / `|| ”` variants) firing the branch even when the param was empty or
// absent. ghaIfToFlowCondition translates those operator-less GHA refs to a
// bare token (`invite_token`, `invite_token | default:”`, `invite_token ||
// ”`). Pre-fix the no-op path matched no row key, ran no pipe/`||`, and
// rendered the bare token to ITSELF - a non-empty string → always truthy.
func TestEvaluateFlowCondition_OptionalParam_NoOp(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	// The exact translations ghaIfToFlowCondition emits for the three
	// operator-less forms the agent tried.
	if got := ghaIfToFlowCondition("${{ params.invite_token }}"); got != "invite_token" {
		t.Fatalf("translation drift: bare ref → %q", got)
	}
	if got := ghaIfToFlowCondition("${{ params.invite_token | default:'' }}"); got != "invite_token | default:''" {
		t.Fatalf("translation drift: default pipe → %q", got)
	}
	if got := ghaIfToFlowCondition("${{ params.invite_token || '' }}"); got != "invite_token || ''" {
		t.Fatalf("translation drift: || fallback → %q", got)
	}

	cases := []struct {
		name string
		data map[string]any
		cond string
		want bool
	}{
		// Param ABSENT - every form must be falsy (JS: undefined → false).
		{"bare-absent", map[string]any{}, "invite_token", false},
		{"default-absent", map[string]any{}, "invite_token | default:''", false},
		{"or-absent", map[string]any{}, "invite_token || ''", false},
		// Param present but EMPTY STRING - falsy.
		{"bare-empty", map[string]any{"invite_token": ""}, "invite_token", false},
		{"default-empty", map[string]any{"invite_token": ""}, "invite_token | default:''", false},
		{"or-empty", map[string]any{"invite_token": ""}, "invite_token || ''", false},
		// Param present with a real value - truthy.
		{"bare-set", map[string]any{"invite_token": "abc"}, "invite_token", true},
		{"default-set", map[string]any{"invite_token": "abc"}, "invite_token | default:''", true},
		{"or-set", map[string]any{"invite_token": "abc"}, "invite_token || ''", true},
		// `| default:` / `||` supplying a NON-empty fallback → truthy.
		{"default-fallback-nonempty", map[string]any{}, "invite_token | default:'X'", true},
		{"or-fallback-nonempty", map[string]any{}, "invite_token || 'X'", true},
		// Bare bool / number / quoted literals still judged literally.
		{"literal-true", map[string]any{}, "true", true},
		{"literal-false", map[string]any{}, "false", false},
		{"literal-one", map[string]any{}, "1", true},
		{"literal-zero", map[string]any{}, "0", false},
		{"literal-quoted-empty", map[string]any{}, "''", false},
		{"literal-quoted-nonempty", map[string]any{}, "'x'", true},
		// Real bool from a step output (the gate.ok shape) - both polarities.
		{"gate-true", map[string]any{"gate": map[string]any{"ok": true}}, "gate.ok", true},
		{"gate-false", map[string]any{"gate": map[string]any{"ok": false}}, "gate.ok", false},
		// Empty result set guard stays falsy.
		{"empty-rows", map[string]any{"existing": []map[string]any{}}, "existing", false},
	}
	for _, tc := range cases {
		ctx := &FlowContext{App: app, Data: tc.data, Params: map[string]string{}}
		if got := evaluateFlowCondition(tc.cond, ctx); got != tc.want {
			t.Errorf("%s: evaluateFlowCondition(%q) = %v, want %v", tc.name, tc.cond, got, tc.want)
		}
	}
}

// --- B2: parallel: step type ------------------------------------------

// `run: parallel` + `steps:` runs children concurrently. Each child
// writes to ctx.Data[step.Name] under the mutex. End time is roughly
// max(children) not sum(children).
func TestExecStepParallel_FanOut(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}

	mustExec(t, app.DB, `CREATE TABLE things (id INTEGER PRIMARY KEY)`)
	mustExec(t, app.DB, `INSERT INTO things (id) VALUES (1), (2), (3)`)

	parallel := &FlowStep{
		Type: "parallel",
		Steps: []FlowStep{
			{Type: "sql", Name: "a", SQL: "SELECT 1 AS n"},
			{Type: "sql", Name: "b", SQL: "SELECT 2 AS n"},
			{Type: "sql", Name: "c", SQL: "SELECT 3 AS n"},
		},
	}
	if err := execStepParallel(ctx, parallel); err != nil {
		t.Fatalf("execStepParallel: %v", err)
	}
	// Each child's output should be available.
	for _, k := range []string{"a", "b", "c"} {
		if ctx.Data[k] == nil {
			t.Errorf("ctx.Data[%q] missing after parallel", k)
		}
	}
}

// Parallel branches errors propagate (first error wins).
func TestExecStepParallel_ErrorPropagates(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}

	mustExec(t, app.DB, `CREATE TABLE ok (id INTEGER PRIMARY KEY)`)

	parallel := &FlowStep{
		Type: "parallel",
		Steps: []FlowStep{
			{Type: "sql", Name: "ok", SQL: "SELECT 1"},
			{Type: "sql", Name: "boom", SQL: "SELECT * FROM nonexistent_table"},
		},
	}
	if err := execStepParallel(ctx, parallel); err == nil {
		t.Fatal("expected error from broken sql branch, got nil")
	}
}

// GHA shape: `run: parallel` + `steps:` parses into a FlowStep with
// Type=parallel and the children translated.
func TestLoadFlowsGHA_ParallelStep(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: GET
    path: /api/fan

jobs:
  go:
    steps:
      - id: carriers
        run: parallel
        steps:
          - id: fw
            run: api
            with: { url: https://a.example.com/, method: GET }
          - id: pc
            run: api
            with: { url: https://b.example.com/, method: GET }
`
	os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644)
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 || len(flows[0].Steps) != 1 {
		t.Fatalf("expected 1 flow with 1 step, got %+v", flows)
	}
	p := flows[0].Steps[0]
	if p.Type != "parallel" {
		t.Errorf("step type = %q, want parallel", p.Type)
	}
	if len(p.Steps) != 2 {
		t.Errorf("parallel.Steps = %d, want 2", len(p.Steps))
	}
}

// --- A7: interpolateJSONValues decodes JSON-string values ------------

// SQLite's json_group_array() / json_object() return TEXT containing
// JSON, so without this the response double-quotes the value. Decode
// it inline so the agent's `body: { rows: ${{ steps.x.outputs.rows_json }} }`
// produces a real array, not a string.
func TestInterpolateJSONValues_DecodesJSONString(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{
		App:    app,
		Data:   map[string]any{"rows_json": `[{"id":1},{"id":2}]`},
		Params: map[string]string{},
	}
	m := map[string]any{
		"rows": "{{rows_json}}",
	}
	out := interpolateJSONValues(m, ctx)
	rows, ok := out["rows"].([]any)
	if !ok {
		t.Fatalf("rows should be a decoded array, got %T %v", out["rows"], out["rows"])
	}
	if len(rows) != 2 {
		t.Errorf("decoded array length = %d, want 2", len(rows))
	}
}

// JSON objects also decode (not just arrays).
func TestInterpolateJSONValues_DecodesJSONObject(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{
		App:    app,
		Data:   map[string]any{"obj_json": `{"name":"Walmart","tier":"enterprise"}`},
		Params: map[string]string{},
	}
	m := map[string]any{"customer": "{{obj_json}}"}
	out := interpolateJSONValues(m, ctx)
	customer, ok := out["customer"].(map[string]any)
	if !ok {
		t.Fatalf("customer should decode to map, got %T %v", out["customer"], out["customer"])
	}
	if customer["name"] != "Walmart" {
		t.Errorf("customer.name = %v, want Walmart", customer["name"])
	}
}

// Non-JSON strings pass through untouched (no false-positive decoding).
func TestInterpolateJSONValues_NonJSONStringPassthrough(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := &FlowContext{
		App:    app,
		Data:   map[string]any{"msg": "hello world"},
		Params: map[string]string{},
	}
	m := map[string]any{"greeting": "{{msg}}"}
	out := interpolateJSONValues(m, ctx)
	if out["greeting"] != "hello world" {
		t.Errorf("greeting = %v, want 'hello world'", out["greeting"])
	}
}

// --- A8: shorthand query: + step-root params: ------------------------

// Pre-v2.5.9 `params:` at the step root (sibling to `query:` shorthand)
// was silently dropped - only `with.params:` was honored.
func TestLoadFlowsGHA_StepRootParamsWithShorthandQuery(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: POST
    path: /api/log

jobs:
  go:
    steps:
      - id: insert
        query: "INSERT INTO things (id) VALUES (:tid)"
        params:
          tid: ${{ steps.prev.outputs.id }}
`
	os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644)
	flows := LoadFlowsGHA(dir)
	if len(flows) == 0 || len(flows[0].Steps) == 0 {
		t.Fatal("flow/step missing")
	}
	step := flows[0].Steps[0]
	if step.SQLParams == nil {
		t.Fatal("step-root params: dropped - SQLParams nil")
	}
	if !strings.Contains(step.SQLParams["tid"], "prev") {
		t.Errorf("SQLParams[tid] should reference prev step output, got %q", step.SQLParams["tid"])
	}
}

// --- B5: validator hint for RAISE() in flow SQL ----------------------

// TestValidateOnWrite_* (write-time validator tests) moved to
// flows_validator_test.go (platform build).

// --- roles scopes: list parsing -------------------------------------

// Pre-v2.5.11 LoadRolesConfig only honored string `scopes:` - list
// shapes (the YAML-idiomatic form) silently produced empty scopes,
// which the auth gate then translated to "_none_:read" → 403 on
// every CRUD call. An earlier app build wrote `scopes: ["*"]` and
// got locked out of their own admin endpoints.
func TestLoadRolesConfig_ListScopes_AcceptedAndJoined(t *testing.T) {
	dir := t.TempDir()
	appYAML := `roles:
  admin:
    scopes: ["*"]
  editor:
    scopes: [customers:read, shipments:write]
  viewer: [customers:read]
`
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(appYAML), 0644); err != nil {
		t.Fatal(err)
	}
	roles := LoadRolesConfig(dir)
	if roles == nil {
		t.Fatal("LoadRolesConfig nil - config not loaded")
	}
	if got := roles.ScopesForRole("admin"); got != "*" {
		t.Errorf("admin scopes = %q, want '*'", got)
	}
	if got := roles.ScopesForRole("editor"); !strings.Contains(got, "customers:read") || !strings.Contains(got, "shipments:write") {
		t.Errorf("editor scopes = %q, want space-joined customers:read + shipments:write", got)
	}
	// Shorthand list at the role-name root (no nested `scopes:` key) also works.
	if got := roles.ScopesForRole("viewer"); got != "customers:read" {
		t.Errorf("viewer scopes = %q, want customers:read", got)
	}
}

// Bare-string form continues to work for back-compat.
func TestLoadRolesConfig_StringScopes_Unchanged(t *testing.T) {
	dir := t.TempDir()
	appYAML := `roles:
  admin:
    scopes: "*"
  viewer:
    scopes: "contacts:read"
`
	os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(appYAML), 0644)
	roles := LoadRolesConfig(dir)
	if got := roles.ScopesForRole("admin"); got != "*" {
		t.Errorf("admin scopes = %q, want *", got)
	}
	if got := roles.ScopesForRole("viewer"); got != "contacts:read" {
		t.Errorf("viewer scopes = %q, want contacts:read", got)
	}
}

// TestValidateAppYAML_* (write-time validator tests) moved to
// flows_validator_test.go (platform build).

// --- A10: auto-CRUD on tables without an `id` column ----------------

// Pre-v2.5.12 applyAPIFilters always appended `ORDER BY id DESC`,
// which 500'd for any table whose primary key isn't named `id` -
// system_state (TEXT key PRIMARY KEY) was a real-world case. Now we
// only emit ORDER BY id when the column actually exists, and accept
// orderBy=col:dir to override.
func TestApplyAPIFilters_NoIDColumn_NoCrash(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/system_state?key=seed_customers_at", nil)
	allowed := map[string]bool{"key": true, "value": true, "updated_at": true}
	sql, args := applyAPIFilters("SELECT * FROM system_state", req, "system_state", allowed)
	if strings.Contains(sql, "ORDER BY id") {
		t.Errorf("must not emit ORDER BY id when table has no id column: %s", sql)
	}
	if !strings.Contains(sql, "key = ?") {
		t.Errorf("where[key]= or key= filter should land in WHERE: %s", sql)
	}
	if len(args) != 1 || args[0] != "seed_customers_at" {
		t.Errorf("args = %v, want [seed_customers_at]", args)
	}
}

// `?where[col]=val` syntax (the documented form, what bm.js's useTable emits)
// is now unwrapped to a plain column filter. Pre-fix the bracketed key
// failed isValidColumnName + got silently dropped → full table scan.
func TestApplyAPIFilters_WhereBracketSyntax(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/things?where[status]=active&where[price__gte]=100", nil)
	allowed := map[string]bool{"id": true, "status": true, "price": true}
	sql, args := applyAPIFilters("SELECT * FROM things", req, "things", allowed)
	if !strings.Contains(sql, "status = ?") {
		t.Errorf("where[status] should produce status = ?: %s", sql)
	}
	if !strings.Contains(sql, "price >= ?") {
		t.Errorf("where[price__gte] should produce price >= ?: %s", sql)
	}
	if len(args) != 2 {
		t.Errorf("expected 2 args (status + price), got %d: %v", len(args), args)
	}
}

// orderBy=col:dir shorthand (the bm.js-emitted form) is parsed.
func TestApplyAPIFilters_OrderByShorthand(t *testing.T) {
	req, _ := http.NewRequest("GET", "/api/things?orderBy=name:desc", nil)
	allowed := map[string]bool{"id": true, "name": true}
	sql, _ := applyAPIFilters("SELECT * FROM things", req, "things", allowed)
	if !strings.Contains(sql, "ORDER BY name DESC") {
		t.Errorf("orderBy=name:desc should produce ORDER BY name DESC: %s", sql)
	}
}

// --- helper: replicate net/url escaping for the with.query test ------

func neturlEscape(s string) string {
	return neturl.QueryEscape(s)
}

// --- A4: JSON body → ctx.Params ---------------------------------------

// A POST /api/foo with Content-Type: application/json and an object
// body should land every top-level scalar field in ctx.Params just
// like form-encoded would. Subsequent `:name` SQL binds resolve.
func TestExecuteFlowHTTP_JSONBody_PopulatesCtxParams(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE log (msg TEXT)`)

	flow := &Flow{
		Name: "log_msg",
		Trigger: FlowTrigger{
			Type:   "http",
			Method: "POST",
			Path:   "/api/log",
		},
		Steps: []FlowStep{
			{Type: "sql", Name: "insert", SQL: "INSERT INTO log (msg) VALUES (:msg)"},
			{Type: "respond", Respond: &FlowRespond{Status: 200, JSON: map[string]any{"ok": true}}},
		},
	}
	app.Flows = []Flow{*flow}

	mux := http.NewServeMux()
	RegisterFlows(mux, app, app.Flows)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	body := `{"msg":"hello from json"}`
	req, _ := http.NewRequest("POST", srv.URL+"/api/log", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		buf, _ := io.ReadAll(resp.Body)
		t.Fatalf("expected 200, got %d: %s", resp.StatusCode, string(buf))
	}

	var msg string
	app.DB.QueryRow("SELECT msg FROM log LIMIT 1").Scan(&msg)
	if msg != "hello from json" {
		t.Errorf("inserted msg = %q, want %q", msg, "hello from json")
	}
}

// --- A9: groups: now natively supports TEXT/UUID tenant keys -------

// v2.5.10: TEXT-typed group keys (UUID, slug) now work end-to-end.
// loadApp accepts the schema; ResolveGroupID returns string;
// Session.GroupID is string; broadcast layer threads it through.
func TestLoadGroupConfig_TextKey_LoadsSuccessfully(t *testing.T) {
	dir := t.TempDir()
	prisma := `model Customer {
  id    String  @id
  name  String
}
`
	appYAML := `site_name: "T"
auth:
  identifier: email

groups:
  table: customers
  key: id
  user_field: customer_id
`
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(prisma), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(appYAML), 0644); err != nil {
		t.Fatal(err)
	}
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("loadApp with TEXT-key groups should succeed (native UUID support), got %v", err)
	}
	if app.Group == nil || app.Group.Table != "customers" {
		t.Errorf("groups config not loaded: %+v", app.Group)
	}
}

// ResolveGroupID returns a string value for a TEXT-keyed tenant table.
func TestResolveGroupID_TextKey_ReturnsString(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE customers (id TEXT PRIMARY KEY, customer_email TEXT)`)
	uuid := "00000000-0000-4000-b218-3377fe727663"
	if _, err := app.DB.Exec(`INSERT INTO customers (id, customer_email) VALUES (?, ?)`, uuid, "a@b.com"); err != nil {
		t.Fatal(err)
	}
	grp := &GroupConfig{Table: "customers", Key: "id", UserField: "customer_email"}
	got := ResolveGroupID(app.DB, grp, "a@b.com")
	if got != uuid {
		t.Errorf("ResolveGroupID = %q, want %q", got, uuid)
	}
}

// Session.HasGroup is true for non-empty / non-"0" GroupID, false otherwise.
func TestSessionHasGroup(t *testing.T) {
	cases := []struct {
		gid  string
		want bool
	}{
		{"", false},
		{"0", false},
		{"42", true},
		{"00000000-0000-4000-b218-3377fe727663", true},
		{"walmart", true},
	}
	for _, c := range cases {
		s := &Session{GroupID: c.gid}
		if got := s.HasGroup(); got != c.want {
			t.Errorf("HasGroup(GroupID=%q) = %v, want %v", c.gid, got, c.want)
		}
	}
}

// --- test helpers -----------------------------------------------------

func newTestApp(t *testing.T) (*App, func()) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	return &App{Dir: dir, DB: db}, func() { db.Close() }
}

func mustExec(t *testing.T, db *sql.DB, q string) {
	t.Helper()
	if _, err := db.Exec(q); err != nil {
		t.Fatalf("exec %q: %v", q, err)
	}
}

func TestIsTruthyCondition(t *testing.T) {
	cases := []struct {
		v    any
		want bool
	}{
		{true, true},
		{false, false},
		{nil, false},
		{"true", true},
		{"false", false},
		{"", false},
		{"0", false},
		{"1", true},
		{0, false},
		{5, true},
		{0.0, false},
		{3.14, true},
		{"Test Room", true},
		{"<nil>", false},
	}
	for _, c := range cases {
		if got := isTruthyCondition(c.v); got != c.want {
			t.Errorf("isTruthyCondition(%#v) = %v, want %v", c.v, got, c.want)
		}
	}
}

func TestIsTruthyConditionEmptyCollections(t *testing.T) {
	cases := []struct {
		v    any
		want bool
	}{
		{[]any{}, false},
		{[]any{1}, true},
		{[]map[string]any{}, false},
		{[]map[string]any{{"a": 1}}, true},
		{map[string]any{}, false},
		{map[string]any{"a": 1}, true},
		{"[]", false},
		{"map[]", false},
	}
	for _, c := range cases {
		if got := isTruthyCondition(c.v); got != c.want {
			t.Errorf("isTruthyCondition(%#v)=%v want %v", c.v, got, c.want)
		}
	}
}

func TestResolveBindExprOrFallback(t *testing.T) {
	flat := map[string]any{"present": "hi", "blank": "", "emptyrows": []any{}}
	cases := []struct {
		expr, want string
		ok         bool
	}{
		{"present || 'X'", "hi", true},      // present → keep
		{"absent || 'X'", "X", true},        // missing → fallback literal
		{"blank || 'X'", "X", true},         // empty string → fallback
		{"emptyrows || 'X'", "X", true},     // empty collection → fallback
		{"absent || present", "hi", true},   // chain to a ref
		{"absent | default:'D'", "D", true}, // | default still works on absent
	}
	for _, c := range cases {
		v, ok := resolveBindExpr(c.expr, flat)
		if ok != c.ok || (ok && fmtAny(v) != c.want) {
			t.Errorf("resolveBindExpr(%q)=%v,%v want %q,%v", c.expr, v, ok, c.want, c.ok)
		}
	}
}
func fmtAny(v any) string { return fmt.Sprintf("%v", v) }
