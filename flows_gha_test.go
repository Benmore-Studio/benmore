//go:build !cli

package main

// Tests for the GHA-shaped flows parser. Two layers:
//
//   - normalizeGHARefs: every `${{ ... }}` translation in the doc gets
//     a row-by-row golden test.
//   - End-to-end: a representative flows.yaml in GHA shape parses
//     into the runtime's []Flow shape with the right trigger, the
//     right step types, and refs already normalized.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNormalizeGHARefs(t *testing.T) {
	cases := map[string]string{
		// steps.X.outputs.Y → X.Y
		`${{ steps.access.outputs.user_id }}`: `{{access.user_id}}`,
		`hi ${{ steps.foo.outputs.bar }}!`:    `hi {{foo.bar}}!`,
		// env passthrough
		`${{env.STRIPE_SECRET}}`: `{{env.STRIPE_SECRET}}`,
		// user.* shorthand. Pre-v2.7.5 we special-cased id/email/role
		// into flat keys (`user_email`, `user_id`, `user_role`) and
		// stripped the prefix on all other fields. The runtime's
		// session map only populated id/email/role, so every other
		// reference silently emitted literal `{{plan}}` text. Now the
		// executor exposes the entire _benmore_users row at
		// ctx.Data["user"] and flattenData provides `user.<col>` paths
		// for every field — so `user.email` / `user.id` / `user.role`
		// keep working, AND so do `user.plan` / `user.first_name` /
		// `user.<anything>`. We pass the expression through unchanged
		// so the runtime's dotted-path lookup handles them uniformly.
		`${{ user.email }}`:    `{{user.email}}`,
		`${{ user.id }}`:       `{{user.id}}`,
		`${{ user.role }}`:     `{{user.role}}`,
		`${{ user.first_name }}`: `{{user.first_name}}`,
		`${{ user.plan }}`:     `{{user.plan}}`,
		// org_id / group_id is still a flat session key because the
		// session row carries it (not the user row), so the legacy
		// alias stays.
		`${{ user.org_id }}`:   `{{user_group_id}}`,
		`${{ user.group_id }}`: `{{user_group_id}}`,
		// params
		`${{ params.id }}`: `{{id}}`,
		// Whitespace tolerance.
		`${{   env.X   }}`: `{{env.X}}`,
		// Multiple refs in one string.
		`Hi ${{ user.email }}, you owe ${{ steps.bill.outputs.amount }}`: `Hi {{user.email}}, you owe {{bill.amount}}`,
		// No refs → unchanged.
		`plain string`: `plain string`,
	}
	for in, want := range cases {
		if got := normalizeGHARefs(in); got != want {
			t.Errorf("normalizeGHARefs(%q)\n  got:  %q\n  want: %q", in, got, want)
		}
	}
}

// TestGhaIfToFlowCondition pins the per-step `if:` modifier translation.
// Earlier app builds both hit cases where the
// translator emitted forms the legacy evaluator couldn't handle:
//
//  1. `${{ X }} = 1` (single equals — SQL/agent intuition) silently fell
//     through the no-op path and left {{...}} braces on the lhs.
//  2. `${{ X }} == 1` wrapped the literal `1` as `{{1}}`, then v2.7.5's
//     loud-fail-on-unresolved-template logic flagged `{{1}}` as a
//     missing ref and halted the flow.
//  3. `${{ X }}` (truthy form, no operator) emitted `{{X}}` instead of
//     a bare key, so the evaluator's `row[lhs]` lookup missed.
//
// All three now produce evaluator-compatible output.
func TestGhaIfToFlowCondition(t *testing.T) {
	cases := map[string]string{
		// `==` with a literal rhs — must NOT wrap the literal.
		`${{ steps.gate.outputs.is_rejected }} == 1`: `gate.is_rejected = 1`,
		// `=` (single equals) — accepted as a synonym for ==.
		`${{ steps.gate.outputs.is_rejected }} = 1`: `gate.is_rejected = 1`,
		// `!=` with a literal rhs.
		`${{ user.role }} != 'admin'`: `user.role != 'admin'`,
		// `>=` numeric.
		`${{ steps.calc.outputs.conc_pct }} >= 20`: `calc.conc_pct >= 20`,
		// Both sides GHA refs — rhs wrapped so the runtime interpolates
		// it against ctx.Data before the evaluator compares.
		`${{ steps.a.outputs.x }} == ${{ steps.b.outputs.y }}`: `a.x = {{b.y}}`,
		// Truthy form (no operator) — emit bare key, not braced.
		`${{ steps.gate.outputs.is_rejected }}`: `gate.is_rejected`,
		// `${{ ... }}` wrapper stripping.
		`${{ user.id }} > 0`: `user.id > 0`,
	}
	for in, want := range cases {
		if got := ghaIfToFlowCondition(in); got != want {
			t.Errorf("ghaIfToFlowCondition(%q)\n  got:  %q\n  want: %q", in, got, want)
		}
	}
}

func TestLoadFlowsGHA_HappyPath(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: POST
    path: /api/notes/:id/save
    auth: required
    role: editor

jobs:
  save:
    steps:
      - id: access
        run: sql
        query: SELECT user_id FROM notes WHERE id = :id

      - if: ${{ steps.access.outputs.user_id != user.id }}
        run: respond
        with:
          status: 403
          body:
            error: forbidden

      - run: sql
        query: UPDATE notes SET title = :title WHERE id = :id

      - run: webhook
        with:
          url: ${{ env.SLACK }}
          body: Note ${{ steps.access.outputs.user_id }} saved
`
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	f := flows[0]
	if f.Name != "save" {
		t.Errorf("flow name = %q, want save", f.Name)
	}
	if f.Trigger.Method != "POST" || f.Trigger.Path != "/api/notes/:id/save" {
		t.Errorf("trigger: %+v", f.Trigger)
	}
	if f.Auth != "required" || f.Role != "editor" {
		t.Errorf("auth/role: %+v", f)
	}
	if len(f.Steps) != 4 {
		t.Fatalf("expected 4 steps, got %d: %+v", len(f.Steps), f.Steps)
	}
	if f.Steps[0].Type != "sql" || f.Steps[0].Name != "access" {
		t.Errorf("step 0: %+v", f.Steps[0])
	}
	// Step 1 is an `if` wrapper around the respond step.
	if f.Steps[1].Type != "if" {
		t.Errorf("step 1 should be 'if', got %q (full: %+v)", f.Steps[1].Type, f.Steps[1])
	}
	// The if's condition should have normalized refs (no ${{ }}).
	if strings.Contains(f.Steps[1].Condition, "${{") {
		t.Errorf("if condition still has GHA refs: %q", f.Steps[1].Condition)
	}
	if !strings.Contains(f.Steps[1].Condition, "access.user_id") {
		t.Errorf("if condition should reference access.user_id: %q", f.Steps[1].Condition)
	}
	// The webhook URL should have normalized env ref.
	if f.Steps[3].Type != "webhook" {
		t.Errorf("step 3 should be webhook: %+v", f.Steps[3])
	}
	if !strings.Contains(f.Steps[3].Webhook, "{{env.SLACK}}") {
		t.Errorf("webhook url not normalized: %q", f.Steps[3].Webhook)
	}
}

func TestLoadFlowsGHA_ShorthandQuery(t *testing.T) {
	// `query:` alone is shorthand for `run: sql; with: { query: ... }`.
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: GET
    path: /api/notes/:id

jobs:
  fetch:
    steps:
      - id: note
        query: SELECT * FROM notes WHERE id = :id

      - run: respond
        with:
          body: ${{ steps.note.outputs.title }}
`
	os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644)
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 || len(flows[0].Steps) != 2 {
		t.Fatalf("expected 1 flow with 2 steps, got: %+v", flows)
	}
	if flows[0].Steps[0].Type != "sql" {
		t.Errorf("shorthand query should produce sql step: %+v", flows[0].Steps[0])
	}
}

func TestLoadFlowsGHA_BodyAsJSON(t *testing.T) {
	// respond's `with.body` can be a map → JSON response.
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: POST
    path: /api/forbidden

jobs:
  block:
    steps:
      - run: respond
        with:
          status: 403
          body:
            error: forbidden
            code: AUTH_REQUIRED
`
	os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644)
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 || flows[0].Steps[0].Respond == nil {
		t.Fatalf("respond step missing: %+v", flows)
	}
	if flows[0].Steps[0].Respond.Status != 403 {
		t.Errorf("respond status: %d", flows[0].Steps[0].Respond.Status)
	}
	if flows[0].Steps[0].Respond.JSON["error"] != "forbidden" {
		t.Errorf("respond JSON body: %+v", flows[0].Steps[0].Respond.JSON)
	}
}

func TestLoadFlowsGHA_ScheduleTrigger(t *testing.T) {
	// `on: schedule: cron: ...` produces a cron-typed FlowTrigger.
	dir := t.TempDir()
	yamlBody := `
on:
  schedule:
    cron: "*/5 * * * *"

jobs:
  cleanup:
    steps:
      - run: sql
        query: DELETE FROM logs WHERE created_at < datetime('now', '-30 days')
`
	os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644)
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 {
		t.Fatalf("expected 1 cron flow, got %d", len(flows))
	}
	if flows[0].Trigger.Type != "cron" {
		t.Errorf("trigger type = %q, want cron", flows[0].Trigger.Type)
	}
	if flows[0].Trigger.Cron != "*/5 * * * *" {
		t.Errorf("cron expression = %q", flows[0].Trigger.Cron)
	}
}

func TestLoadFlowsGHA_EventTrigger(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
on:
  event:
    table: notes
    op: insert

jobs:
  notify:
    steps:
      - run: webhook
        with:
          url: ${{ env.SLACK }}
          body: New note from ${{ user.email }}
`
	os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644)
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 || flows[0].Trigger.Type != "on_insert" {
		t.Fatalf("expected on_insert trigger, got %+v", flows)
	}
	if flows[0].Trigger.Table != "notes" {
		t.Errorf("event table = %q", flows[0].Trigger.Table)
	}
}

func TestLoadFlowsGHA_ForEach(t *testing.T) {
	// for_each iterates over a previous step's rows; `as:` names the
	// loop variable.
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: POST
    path: /api/notify-all

jobs:
  blast:
    steps:
      - id: users
        query: SELECT id, email FROM _benmore_users WHERE verified = 1

      - for_each: ${{ steps.users.outputs }}
        as: user
        steps:
          - run: email
            with:
              to: ${{ user.email }}
              subject: Hello
              template: ping
`
	os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644)
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	// Last step (after the SQL lookup) should be a for_each.
	last := flows[0].Steps[len(flows[0].Steps)-1]
	if last.Type != "for_each" {
		t.Fatalf("expected for_each step, got %q", last.Type)
	}
	if last.ForAs != "user" {
		t.Errorf("for_each as = %q", last.ForAs)
	}
	if len(last.Steps) != 1 || last.Steps[0].Type != "email" {
		t.Errorf("for_each body should have one email step: %+v", last.Steps)
	}
}

func TestLoadFlowsGHA_OnError(t *testing.T) {
	dir := t.TempDir()
	yamlBody := `
on:
  request:
    method: POST
    path: /api/risky

jobs:
  do:
    steps:
      - run: api
        with:
          method: POST
          url: https://example.com/might-fail
        on_error:
          - run: respond
            with:
              status: 503
              body:
                error: upstream unavailable
`
	os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644)
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 || len(flows[0].Steps) != 1 {
		t.Fatalf("expected 1 step, got %+v", flows)
	}
	if len(flows[0].Steps[0].OnError) != 1 || flows[0].Steps[0].OnError[0].Type != "respond" {
		t.Errorf("on_error block missing: %+v", flows[0].Steps[0])
	}
}

func TestLoadFlowsGHA_GracefulMiss(t *testing.T) {
	// A flows.yaml in the legacy shape should NOT be parsed by the GHA
	// loader — return nil so the legacy loader gets a turn.
	dir := t.TempDir()
	yamlBody := `
old_flow:
  trigger: POST /api/old
  steps:
    - sql: SELECT 1
`
	os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(yamlBody), 0644)
	flows := LoadFlowsGHA(dir)
	if flows != nil {
		t.Errorf("legacy-shape flows.yaml should miss GHA loader, got: %+v", flows)
	}
}

// TestFlowRunTypesMatch guards the parser↔validator single-source contract.
// Every `run:` type the parser handles (flowRunTypes) must pass the
// write-time validator. This is the regression test for the v2.7.67
// `compute` drift, where compute ran but validateFlowsYAML rejected it as
// an unknown step type because the validator kept its own stale list.
// TestFlowRunTypesMatch (validator/parser agreement) moved to
// flows_validator_test.go (platform build).

// TestResolveComputeArgsNative locks in that `run: compute` args resolve to
// NATIVE values across every ref shape — earlier debugging where
// whole-object/array refs (.first, .rows, rows[0]) came back null because the
// compute resolver wasn't normalizing refs like the rest of the framework.
func TestResolveComputeArgsNative(t *testing.T) {
	ctx := &FlowContext{Data: map[string]any{
		"forecast": []map[string]any{{"ppa_rate_per_mwh": 75.0}},
		"costs":    []map[string]any{{"amount": 50000.0}, {"amount": 25000.0}},
	}}
	args := map[string]any{
		"first": "${{ steps.forecast.outputs.first }}",
		"row0":  "${{ steps.forecast.outputs.rows[0] }}",
		"ppa":   "${{ steps.forecast.outputs.rows[0].ppa_rate_per_mwh }}",
		"costs": "${{ steps.costs.outputs.rows }}",
		"def":   "${{ steps.nope.outputs.rows | default:'none' }}",
	}
	got, ok := resolveComputeArgsValue(args, ctx).(map[string]any)
	if !ok {
		t.Fatal("args did not resolve to a map")
	}
	if fr, ok := got["first"].(map[string]any); !ok || fr["ppa_rate_per_mwh"] != 75.0 {
		t.Errorf(".first not a native row map: %#v", got["first"])
	}
	if fr, ok := got["row0"].(map[string]any); !ok || fr["ppa_rate_per_mwh"] != 75.0 {
		t.Errorf("rows[0] not a native row map: %#v", got["row0"])
	}
	if got["ppa"] != 75.0 {
		t.Errorf("scalar leaf: got %#v", got["ppa"])
	}
	if arr, ok := got["costs"].([]map[string]any); !ok || len(arr) != 2 {
		t.Errorf("rows array not native (%d): %#v", len(arr), got["costs"])
	}
	if got["def"] != "none" {
		t.Errorf("default pipe: got %#v", got["def"])
	}
}

// v2.7.139: `.outputs.first[.col]` is sugar for row 0. Pre-fix it had no
// handler and silently resolved to nothing on SELECT (only `.rows[0]` worked),
// which bound NULLs / halted template_unresolved despite the docs promising it.
func TestTranslateGHAExpr_FirstAlias(t *testing.T) {
	cases := map[string]string{
		"steps.q.outputs.first.group_id": "q.0.group_id", // the bug: now resolves to row 0
		"steps.q.outputs.first":          "q.0",           // bare .first → row 0
		"steps.q.outputs.rows[0].id":     "q.0.id",        // the workaround still works
		"steps.q.outputs.firstname":      "q.firstname",   // word-boundary: real column, NOT mangled
		"steps.q.outputs.email":          "q.email",       // generic single-row sugar unaffected
		"steps.q.outputs.rows":           "q",             // result set unaffected
		"params.invite_token":            "invite_token",  // unrelated branch unaffected
	}
	for in, want := range cases {
		if got := translateGHAExpr(in); got != want {
			t.Errorf("translateGHAExpr(%q) = %q, want %q", in, got, want)
		}
	}
}
