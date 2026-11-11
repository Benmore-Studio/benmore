//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func valueExprRespond(t *testing.T, app *App, body, request string) map[string]any {
	t.Helper()
	flow := `on:
  request:
    method: POST
    path: /api/expr
jobs:
  main:
    steps:
      - id: c
        query: "SELECT COUNT(*), 2 AS two"
      - run: respond
        with:
          status: 200
          body: ` + body + "\n"
	rr := runProbeGHAFlow(t, app, flow, request)
	if rr.Code != http.StatusOK {
		t.Fatalf("respond %s with %s: %d %s", body, request, rr.Code, rr.Body.String())
	}
	var got map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("respond body: %v %s", err, rr.Body.String())
	}
	return got
}

// `${{ params.id && 'yes' || 'no' }}` in a value rendered "no" when id was 7:
// the value resolver knew only refs, pipes and the `||` fallback, so
// `params.id && 'yes'` was an unknown ref and the fallback won without a
// warning. Value expressions now take the `if:` grammar with the same
// JavaScript semantics.
func TestFlowValueExpressionsUseTheConditionGrammar(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	body := `{ label: "${{ params.id && 'yes' || 'no' }}", big: "${{ params.n > 3 }}", text: "n>3: ${{ params.n > 3 }}", not: "${{ !params.id }}", pick: "${{ params.id && steps.c.outputs.two }}" }`
	cases := []struct {
		request string
		want    map[string]any
	}{
		{`{"id":7,"n":10}`, map[string]any{"label": "yes", "big": true, "text": "n>3: true", "not": false, "pick": float64(2)}},
		{`{"n":2}`, map[string]any{"label": "no", "big": false, "text": "n>3: false", "not": true, "pick": nil}},
		// Truthiness is `if:`'s: "0" and "" are falsy.
		{`{"id":"0","n":"9"}`, map[string]any{"label": "no", "big": true, "text": "n>3: true", "not": true, "pick": "0"}},
	}
	for _, c := range cases {
		got := valueExprRespond(t, app, body, c.request)
		for k, want := range c.want {
			if got[k] != want {
				t.Errorf("%s: %s = %#v, want %#v (body %v)", c.request, k, got[k], want, got)
			}
		}
	}
}

// The same expression gives the same answer as a value and as an `if:`.
func TestFlowValueExpressionMatchesIfCondition(t *testing.T) {
	ctx := &FlowContext{Data: map[string]any{"id": "7", "empty": "", "zero": "0", "n": 10, "role": "admin"}, Params: map[string]string{}}
	for _, expr := range []string{
		"params.id && 'yes' || 'no'",
		"params.empty && 'yes' || 'no'",
		"params.zero || params.id",
		"params.n >= 10 && params.role == 'admin'",
		"!(params.n < 5) && params.missing == ''",
		"params.missing && 'x'",
		"params.role != 'admin' || params.n > 100",
	} {
		value, ok := resolveBindExpr(expr, flatDataForCtx(ctx))
		if !ok {
			t.Fatalf("%s did not resolve", expr)
		}
		cond := evaluateFlowCondition(ghaIfToFlowCondition("${{ "+expr+" }}"), ctx)
		if isTruthyCondition(value) != cond {
			t.Errorf("%s: value %#v (truthy %v) but if: %v", expr, value, isTruthyCondition(value), cond)
		}
	}
}

// Templates without operators resolve exactly as before: refs, pipes, the
// `||` fallback (a bare fallback word is text), and a column whose name has
// parentheses.
func TestFlowValueTemplatesWithoutOperatorsAreUnchanged(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	got := valueExprRespond(t, app, `{ fb: "${{ params.x || 'fallback' }}", word: "${{ params.x || none }}", def: "${{ params.x | default:'d' }}", count: "${{ steps.c.outputs.COUNT(*) }}", eq: "${{ params.x | default:'a=b' }}" }`, `{}`)
	want := map[string]any{"fb": "fallback", "word": "none", "def": "d", "count": float64(1), "eq": "a=b"}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %#v, want %#v (%v)", k, got[k], v, got)
		}
	}
	for _, expr := range []string{"x", "x | default:'a'", "x || 'y'", "x || hello!", "x | default:a=b", "steps.c.outputs.COUNT(*)", "'a && b' ", "x | default:'<b>'"} {
		if flowValueExprUsesOperators(expr) {
			t.Errorf("%q must keep the ref resolver", expr)
		}
	}
	for _, expr := range []string{"a && b", "a == 'x'", "!a", "a || !b", "a != b", "n > 3", "(a) && b"} {
		if !flowValueExprUsesOperators(expr) {
			t.Errorf("%q must use the expression grammar", expr)
		}
	}
}

// A request value is only ever an operand: operators, quotes and templates
// inside it are text (security.md 2b).
func TestFlowValueExpressionRequestValuesStayOperands(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "SECRET_TOKEN", "s3cr3t")
	got := valueExprRespond(t, app, `{ eq: "${{ params.a == params.b }}", echo: "${{ params.a && params.a || 'none' }}", tmpl: "${{ params.t && params.t || 'none' }}" }`,
		`{"a":"x' || '1","b":"y","t":"{{env.SECRET_TOKEN}}"}`)
	if got["eq"] != false || got["echo"] != "x' || '1" || got["tmpl"] != "{{env.SECRET_TOKEN}}" {
		t.Fatalf("a request value changed the expression: %v", got)
	}
}

// A value expression binds into SQL as one parameter.
func TestFlowValueExpressionBindsIntoSQL(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE marks (v TEXT)`)
	flow := `on:
  request:
    method: POST
    path: /api/mark
jobs:
  main:
    steps:
      - run: sql
        with:
          query: "INSERT INTO marks (v) VALUES (${{ params.id && 'yes' || 'no' }})"
      - run: respond
        with: { status: 200, body: { ok: true } }
`
	for _, req := range []string{`{"id":7}`, `{}`} {
		if rr := runProbeGHAFlow(t, app, flow, req); rr.Code != http.StatusOK {
			t.Fatalf("%s: %d %s", req, rr.Code, rr.Body.String())
		}
	}
	rows, err := app.DB.Query(`SELECT v FROM marks ORDER BY rowid`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var v string
		rows.Scan(&v)
		got = append(got, v)
	}
	if strings.Join(got, ",") != "yes,no" {
		t.Fatalf("bound values = %v", got)
	}
}

// Every analysis that asks which data a template reads sees the refs behind
// `&&`, `!` and comparisons: the sql_dynamic request guard, the env-only
// shortcut of URLs and email HTML, and pre-encoded URL values.
func TestFlowValueExpressionRefsReachTaintAnalysis(t *testing.T) {
	refs := flowExprRefPaths("ok.v && params.evil || 'x'")
	if !slices.Contains(refs, "evil") || !slices.Contains(refs, "ok.v") {
		t.Fatalf("refs of an expression = %v", refs)
	}
	if refs := flowExprRefPaths("ok.v && (params.evil"); !slices.Contains(refs, "evil") {
		t.Fatalf("an expression that doesn't parse must still report its words: %v", refs)
	}
	if flowExprIsEnvOnly("env.A && params.evil || env.B") {
		t.Fatal("an expression that can pick a request value is not env-only")
	}
	if !flowExprIsEnvOnly("env.A || 'x'") {
		t.Fatal("an env fallback stays env-only")
	}
	if flowExprEndsInURLEncode("params.a && params.b | urlencode") {
		t.Fatal("an expression is not a pre-encoded value")
	}
}

// sql_dynamic refuses request input behind `&&` as it does a bare ref. The
// loader already refuses such a file (validateSQLDynamicSafety); the runtime
// guard is the second line, checked here on a flow built directly.
func TestFlowValueExpressionSQLDynamicGuardSeesRequestInput(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT)`)
	flow := &Flow{Name: "dyn", Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/dyn"},
		Steps: []FlowStep{
			{Name: "ok", Type: "sql", SQL: "SELECT 1 AS v"},
			{Name: "dyn", Type: "sql_dynamic", SQL: "SELECT * FROM notes WHERE {{ok.v && params.evil || '1=1'}}"},
			{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "ok"}},
		}}
	r := httptest.NewRequest(http.MethodPost, "/api/dyn", strings.NewReader(`{"evil":"1=1 OR 1"}`))
	r.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	journal := captureLog(t, func() { executeFlowHTTP(app, flow, rr, r) })
	if rr.Code == http.StatusOK || !strings.Contains(journal, "request-sourced value") {
		t.Fatalf("sql_dynamic ran request input behind &&: %d %s\n%s", rr.Code, rr.Body.String(), journal)
	}
}

// An expression that doesn't parse resolves to nothing: the step fails with
// template_unresolved instead of rendering a guess, and the write gate and
// `benmore check` refuse it first.
func TestFlowValueExpressionThatDoesNotParse(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	flow := `on:
  request:
    method: POST
    path: /api/bad
jobs:
  main:
    steps:
      - run: respond
        with:
          status: 200
          body: { label: "${{ params.id && }}" }
`
	var rr *httptest.ResponseRecorder
	captureLog(t, func() { rr = runProbeGHAFlow(t, app, flow, `{"id":1}`) })
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), "template_unresolved") {
		t.Fatalf("an unparseable value expression must fail loud: %d %s", rr.Code, rr.Body.String())
	}

	msg := validateFlowsYAML(flow)
	if !strings.Contains(msg, "doesn't parse as an expression") || !strings.Contains(msg, "params.id &&") || !strings.Contains(msg, "value_expressions") {
		t.Fatalf("write gate did not refuse the value expression: %q", msg)
	}
	for _, ok := range []string{
		strings.Replace(flow, "${{ params.id && }}", "${{ params.id && 'yes' || 'no' }}", 1),
		strings.Replace(flow, "${{ params.id && }}", "${{ params.id || 'a && b' }}", 1),
		strings.Replace(flow, "${{ params.id && }}", "${{ params.n >= 2 && !params.off }}", 1),
	} {
		if msg := validateFlowsYAML(ok); msg != "" {
			t.Fatalf("write gate refused a valid value expression: %q\n%s", msg, ok)
		}
	}
	nested := `on:
  request:
    method: POST
    path: /api/bad
jobs:
  main:
    steps:
      - if: ${{ params.go }}
        steps:
          - run: sql
            with:
              query: "SELECT ${{ params.a == }} AS x"
      - run: respond
        with: { status: 200, body: { ok: true } }
`
	if msg := validateFlowsYAML(nested); !strings.Contains(msg, "doesn't parse as an expression") {
		t.Fatalf("a nested step's value expression was not checked: %q", msg)
	}
}

// An api URL expression that can pick a request value is not an env-only
// value, so it is never written as is: request input behind `&&` cannot
// choose the host of a call that carries credentials. Author-chosen hosts
// (env values picked by a comparison) still work.
func TestFlowValueExpressionCannotPutRequestInputInACredentialedHost(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "USE_CUSTOM", "1")
	SetAppEnv(app.Dir, "DEFAULT_HOST", "api.example.com")
	SetAppEnv(app.Dir, "EU_HOST", "eu.api.example.com")
	ctx := outboundURLCtx(map[string]any{"host": "evil.example", "region": "eu"}, "host", "region")
	ctx.App = app
	call := &FlowAPICall{URL: "https://{{env.USE_CUSTOM && host || env.DEFAULT_HOST}}/v1", Auth: "Bearer {{env.KEY}}"}
	if got, err := buildAPIRequestURL(ctx, call, nil); err == nil || !strings.Contains(err.Error(), "may not choose the scheme or host") {
		t.Fatalf("request input chose a credentialed host through an expression: %q, %v", got, err)
	}
	call = &FlowAPICall{URL: "https://{{env.USE_CUSTOM == '1' && env.EU_HOST || env.DEFAULT_HOST}}/v1", Auth: "Bearer {{env.KEY}}"}
	if got, err := buildAPIRequestURL(ctx, call, nil); err != nil || got != "https://eu.api.example.com/v1" {
		t.Fatalf("an env-only host expression = %q, %v", got, err)
	}
}

// In an email's inline html: an env-only value is written as is; an
// expression that can pick a request value is escaped like any other value.
func TestFlowValueExpressionInEmailHTMLIsEscaped(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "SHOW_NOTE", "1")
	SetAppEnv(app.Dir, "FOOTER_HTML", "<b>footer</b>")
	ctx := outboundURLCtx(map[string]any{"note": "<script>alert(1)</script>"}, "note")
	ctx.App = app
	got := interpolateCtxHTML("<p>{{ env.SHOW_NOTE && note || env.FOOTER_HTML }}</p>", ctx)
	if strings.Contains(got, "<script>") || !strings.Contains(got, "&lt;script&gt;") {
		t.Fatalf("a request value behind && was written as HTML: %s", got)
	}
}

// The write gate's sql_dynamic check reads every ref of an expression, as the
// runtime guard does: request input behind `&&` is refused when the file is
// written, not only when the flow runs.
func TestSQLDynamicWriteGateReadsRefsInsideExpressions(t *testing.T) {
	flow := func(expr string) string {
		return `on:
  request:
    method: POST
    path: /api/dyn
jobs:
  main:
    steps:
      - id: ok
        query: "SELECT 1 AS v"
      - run: sql_dynamic
        with:
          query: "SELECT * FROM notes ORDER BY ${{ ` + expr + ` }}"
      - run: respond
        with: { status: 200, body: { ok: true } }
`
	}
	if msg := validateFlowsYAML(flow("steps.ok.outputs.v && params.sort || 'id'")); !strings.Contains(msg, "sql_dynamic") || !strings.Contains(msg, "params.sort") {
		t.Fatalf("request input behind && passed the sql_dynamic write gate: %q", msg)
	}
	if msg := validateFlowsYAML(flow("steps.ok.outputs.v == 1 && 'id' || 'created_at'")); msg != "" {
		t.Fatalf("an expression over step outputs and literals was refused: %q", msg)
	}
}

// A `||` inside a quoted pipe argument is text. The parser keeps it in the
// ref, so taint analysis sees no ref behind it; the runtime must not resolve
// one there either, or sql_dynamic could inline request text the taint check
// never saw.
func TestQuotedOrInPipeArgReadsNoRef(t *testing.T) {
	flat := map[string]any{"blank": "", "evil": "x' OR 1=1 --", "name": "Ada"}
	expr := `blank | trim:"||evil||" || !1`
	if flowTemplateRefsKey("SELECT '{{"+expr+"}}'", "evil") {
		t.Fatalf("taint now reports evil for %s; the test no longer covers the gap", expr)
	}
	if v, _ := resolveBindExpr(expr, flat); v == "x' OR 1=1 --" {
		t.Fatalf("%s read evil at runtime although taint analysis does not report it", expr)
	}
	// The same quoting without operators: the pipe argument stays literal.
	if v, ok := resolveBindExpr(`missing | default:"a||evil"`, flat); !ok || v != "a||evil" {
		t.Fatalf(`default:"a||evil" = %#v, %v`, v, ok)
	}
	// An unquoted || still falls back.
	if v, ok := resolveBindExpr(`blank || name`, flat); !ok || v != "Ada" {
		t.Fatalf("blank || name = %#v, %v", v, ok)
	}
	for in, want := range map[string]int{`a || b`: 2, `'||' || b`: 5, `"x||y"`: -1, `'unterminated || b`: -1, `a | trim:"|" || b`: 13} {
		if got := indexOutsideQuotes(in, "||"); got != want {
			t.Errorf("indexOutsideQuotes(%q) = %d, want %d", in, got, want)
		}
	}
}

// An inline html body that is exactly one reference is written as the
// document the app built. When that reference is text the caller sent, it is
// escaped instead: a public form could otherwise mail arbitrary markup from
// the app's domain.
func TestEmailHTMLSoleRequestValueIsEscaped(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	ctx := outboundURLCtx(map[string]any{"message": `<a href="https://evil.example">Reset your password</a>`}, "message")
	ctx.App = app
	if got := interpolateCtxHTML("{{ message }}", ctx); strings.Contains(got, "<a ") {
		t.Fatalf("a sole request value was written as HTML: %s", got)
	}
	built := outboundURLCtx(map[string]any{"doc": "<p>built by a step</p>"})
	built.App = app
	if got := interpolateCtxHTML("{{ doc }}", built); got != "<p>built by a step</p>" {
		t.Fatalf("a sole computed value = %q, want the document as is", got)
	}
}
