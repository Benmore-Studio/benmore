//go:build !cli

package main

import (
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestValidateFlowInputValuesJSONAndForm(t *testing.T) {
	min, max := 1.0, 5.0
	inputs := map[string]FlowInput{
		"name":    {Type: "text", Required: true},
		"email":   {Type: "email", Required: true},
		"date":    {Type: "date"},
		"role":    {Type: "enum", Values: []string{"member", "admin"}},
		"score":   {Type: "number", Min: &min, Max: &max},
		"enabled": {Type: "bool"},
	}

	tests := []struct {
		name   string
		values map[string]any
		want   string
	}{
		{
			name:   "raw JSON values",
			values: mustFlowInputJSON(t, `{"name":"Ada","email":"ada@example.org","date":"2024-02-29","role":"member","score":3.5,"enabled":true}`),
		},
		{
			name: "HTTP form strings",
			values: map[string]any{
				"name": "Ada", "email": "ada@example.org", "date": "2024-02-29",
				"role": "member", "score": "4.25", "enabled": "false",
			},
		},
		{name: "structured text rejected", values: mustFlowInputJSON(t, `{"name":{"x":1},"email":"ada@example.org"}`), want: "name"},
		{name: "invalid email rejected", values: map[string]any{"name": "Ada", "email": "not-an-email"}, want: "email"},
		{name: "invalid date rejected", values: map[string]any{"name": "Ada", "email": "ada@example.org", "date": "2023-02-29"}, want: "date"},
		{name: "enum nonmember rejected", values: map[string]any{"name": "Ada", "email": "ada@example.org", "role": "owner"}, want: "role"},
		{name: "structured number rejected", values: mustFlowInputJSON(t, `{"name":"Ada","email":"ada@example.org","score":[2]}`), want: "score"},
		{name: "number outside range rejected", values: map[string]any{"name": "Ada", "email": "ada@example.org", "score": "6"}, want: "score"},
		{name: "nonfinite number rejected", values: map[string]any{"name": "Ada", "email": "ada@example.org", "score": math.Inf(1)}, want: "score"},
		{name: "invalid form boolean rejected", values: map[string]any{"name": "Ada", "email": "ada@example.org", "enabled": "yes"}, want: "enabled"},
		{name: "numeric form boolean rejected", values: map[string]any{"name": "Ada", "email": "ada@example.org", "enabled": "1"}, want: "enabled"},
		{name: "numeric JSON boolean rejected", values: mustFlowInputJSON(t, `{"name":"Ada","email":"ada@example.org","enabled":1}`), want: "enabled"},
		{name: "required null rejected", values: mustFlowInputJSON(t, `{"name":null,"email":"ada@example.org"}`), want: "name"},
		{name: "required empty rejected", values: map[string]any{"name": "", "email": "ada@example.org"}, want: "name"},
		{name: "required missing rejected", values: map[string]any{"email": "ada@example.org"}, want: "name"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateFlowInputValues(inputs, tt.values)
			if tt.want == "" {
				if err != nil {
					t.Fatalf("unexpected validation error: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("error = %v, want field %q", err, tt.want)
			}
			for _, value := range tt.values {
				if s, ok := value.(string); ok && s != "" && strings.Contains(err.Error(), s) {
					t.Fatalf("error exposed input value %q: %v", s, err)
				}
			}
		})
	}
}

func mustFlowInputJSON(t *testing.T, raw string) map[string]any {
	t.Helper()
	var values map[string]any
	if err := json.Unmarshal([]byte(raw), &values); err != nil {
		t.Fatal(err)
	}
	return values
}

func TestFlowInputValidationPrecedesCanonicalSteps(t *testing.T) {
	app, _ := auditApp(t)
	mustExec(t, app.DB, "CREATE TABLE input_effects (value TEXT)")
	writeTestFile(t, app.Dir, "flows/validated.yaml", `on:
  request:
    method: POST
    path: /api/validated
    inputs:
      amount: {type: number, required: true, min: 1, max: 5}
      enabled: {type: bool}
jobs:
  apply:
    steps:
      - query: INSERT INTO input_effects VALUES (:amount)
      - run: respond
        with: {status: 200, body: {ok: true}}
`)
	flows, err := loadFlowsChecked(app.Dir, true)
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, flows)
	allowed := 0
	for _, tc := range []struct {
		body, contentType string
		status            int
	}{
		{`{"amount":3,"enabled":true}`, "application/json", 200},
		{`{"amount":6}`, "application/json", 422},
		{`{"amount":null}`, "application/json", 422},
		{`{"amount":3,"enabled":1}`, "application/json", 422},
		{`{"amount":[3]}`, "application/json", 422},
		{`{`, "application/json", 400},
		{`null`, "application/json", 400},
		{`[]`, "application/json", 400},
		{`amount=2&enabled=false`, "application/x-www-form-urlencoded", 200},
		{`amount=2&enabled=yes`, "application/x-www-form-urlencoded", 422},
	} {
		r := httptest.NewRequest("POST", "/api/validated", strings.NewReader(tc.body))
		r.Header.Set("Content-Type", tc.contentType)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("body %s: got %d %s want %d", tc.body, w.Code, w.Body.String(), tc.status)
		}
		if tc.status == 200 {
			allowed++
		}
		var count int
		if err := app.DB.QueryRow("SELECT count(*) FROM input_effects").Scan(&count); err != nil || count != allowed {
			t.Fatalf("invalid request executed steps: count=%d allowed=%d err=%v", count, allowed, err)
		}
	}
}

func TestFlowInputValidationPrecedesAsyncEnqueue(t *testing.T) {
	app, _ := auditApp(t)
	EnsureJobsTable(app.DB)
	flow := &Flow{Name: "async-input", Async: true, Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/async-input", Inputs: map[string]FlowInput{"amount": {Type: "number", Required: true}}}}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, []Flow{*flow})
	for _, body := range []string{`{"amount":{}}`, `{}`, `{"amount":null}`} {
		r := httptest.NewRequest("POST", "/api/async-input", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != 422 {
			t.Fatalf("invalid async input: got %d %s", w.Code, w.Body.String())
		}
	}
	var count int
	if err := app.DB.QueryRow("SELECT count(*) FROM _benmore_jobs").Scan(&count); err != nil || count != 0 {
		t.Fatalf("invalid inputs enqueued jobs: count=%d err=%v", count, err)
	}
}

func TestFlowInputValidationPreservesShadowedInputs(t *testing.T) {
	app, _ := auditApp(t)
	for _, required := range []bool{false, true} {
		flow := &Flow{Name: "shadowed", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/shadowed", Inputs: map[string]FlowInput{"amount": {Type: "number", Required: required}}}, Steps: []FlowStep{{Name: "amount", Type: "respond"}}}
		for _, tc := range []struct {
			value string
			valid bool
		}{{"3", true}, {"no", false}} {
			w := httptest.NewRecorder()
			executeFlowHTTP(app, flow, w, httptest.NewRequest("GET", "/api/shadowed?amount="+tc.value, nil))
			if (w.Code == 422) == tc.valid {
				t.Fatalf("shadowed required=%v value=%s status=%d", required, tc.value, w.Code)
			}
		}
	}
}

func TestFlowInputValidationRejectsMaskedBody(t *testing.T) {
	app, _ := auditApp(t)
	max := 5.0
	flow := &Flow{Name: "masked", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/masked", Inputs: map[string]FlowInput{"amount": {Type: "number", Max: &max}}}}
	r := httptest.NewRequest("POST", "/api/masked?amount=3", strings.NewReader(`{"amount":100}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	executeFlowHTTP(app, flow, w, r)
	if w.Code != 422 {
		t.Fatalf("masked body accepted: %d %s", w.Code, w.Body.String())
	}
}

// An optional input the caller leaves out (or sends as null) takes its
// declared `default:` everywhere a sent value would land: `${{ params.x }}`,
// `:x` in SQL and with.params. Defaults were documented but never bound, so a
// quote request without `hours` failed with template_unresolved (500).
func TestFlowInputDefaultsAreBound(t *testing.T) {
	app, _ := auditApp(t)
	const source = `on:
  request:
    method: POST
    path: /api/quote
    inputs:
      service_id: {type: number, required: true}
      hours: {type: number, default: 1}
      rush: {type: bool, default: false}
      tier: {type: enum, values: [standard, rush], default: standard}
jobs:
  main:
    steps:
      - id: q
        run: sql
        with:
          query: "SELECT :hours * 100 AS cents, CASE WHEN :rush_flag THEN 1 ELSE 0 END AS rush_sql, :tier AS tier_sql"
          params:
            rush_flag: '${{ params.rush }}'
      - run: respond
        with:
          json:
            hours: '${{ params.hours }}'
            rush: '${{ params.rush }}'
            tier: '${{ params.tier }}'
            cents: '${{ steps.q.outputs.cents }}'
            rush_sql: '${{ steps.q.outputs.rush_sql }}'
            tier_sql: '${{ steps.q.outputs.tier_sql }}'
`
	if msg := ValidateOnWrite("flows/quote.yaml", source); msg != "" {
		t.Fatalf("write gate refused the flow: %s", msg)
	}
	flows, err := parseGHAFlowFile("flows/quote.yaml", []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, flows)
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/api/quote", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	for _, tc := range []struct {
		body string
		want map[string]any
	}{
		{`{"service_id":7}`, map[string]any{"hours": 1.0, "rush": false, "tier": "standard", "cents": 100.0, "rush_sql": 0.0, "tier_sql": "standard"}},
		{`{"service_id":7,"hours":null,"rush":null}`, map[string]any{"hours": 1.0, "rush": false, "tier": "standard", "cents": 100.0, "rush_sql": 0.0, "tier_sql": "standard"}},
		{`{"service_id":7,"hours":3,"rush":true,"tier":"rush"}`, map[string]any{"hours": 3.0, "rush": true, "tier": "rush", "cents": 300.0, "rush_sql": 1.0, "tier_sql": "rush"}},
	} {
		w := post(tc.body)
		if w.Code != http.StatusOK {
			t.Fatalf("%s: status=%d body=%s", tc.body, w.Code, w.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("%s: %v (%s)", tc.body, err, w.Body.String())
		}
		for k, v := range tc.want {
			if got[k] != v {
				t.Errorf("%s: %s=%#v, want %#v (body %s)", tc.body, k, got[k], v, w.Body.String())
			}
		}
	}
	// A default never stands in for a required input.
	if w := post(`{"hours":2}`); w.Code != http.StatusUnprocessableEntity {
		t.Fatalf("missing required input: status=%d body=%s", w.Code, w.Body.String())
	}
}

// An async flow's job carries the defaults, as it carries sent values.
func TestFlowInputDefaultsReachAsyncJob(t *testing.T) {
	app, _ := auditApp(t)
	EnsureJobsTable(app.DB)
	flow := Flow{Name: "async-defaults", Async: true, Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/async-defaults", Inputs: map[string]FlowInput{"hours": {Type: "number", Default: 2}}}}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, []Flow{flow})
	r := httptest.NewRequest(http.MethodPost, "/api/async-defaults", strings.NewReader(`{}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusAccepted && w.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
	}
	var payload string
	if err := app.DB.QueryRow("SELECT payload FROM _benmore_jobs ORDER BY id DESC LIMIT 1").Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		t.Fatalf("payload %q: %v", payload, err)
	}
	if data["hours"] != 2.0 {
		t.Fatalf("job payload hours=%#v, want the default 2 (payload %s)", data["hours"], payload)
	}
}

// The write gate refuses a default a caller could not have sent, since it is
// bound in place of one.
func TestFlowInputDefaultMustMatchType(t *testing.T) {
	for _, tc := range []struct {
		input string
		ok    bool
	}{
		{"hours: {type: number, default: 1}", true},
		{"hours: {type: number, default: 2.5, min: 1, max: 5}", true},
		{"hours: {type: number, default: lots}", false},
		{"hours: {type: number, default: 9, max: 5}", false},
		{"tier: {type: enum, values: [standard, rush], default: express}", false},
		{"rush: {type: bool, default: yes please}", false},
		{"rush: {type: bool, default: false}", true},
		{"day: {type: date, default: '2026-01-31'}", true},
		{"day: {type: date, default: tomorrow}", false},
		{"note: {type: text, default: 5}", false},
	} {
		source := "on:\n  request:\n    method: POST\n    path: /api/defaults\n    inputs:\n      " + tc.input + "\njobs:\n  main:\n    steps:\n      - run: respond\n        with: {json: {ok: true}}\n"
		msg := ValidateOnWrite("flows/defaults.yaml", source)
		if (msg == "") != tc.ok {
			t.Errorf("%s: write gate=%q, want ok=%v", tc.input, msg, tc.ok)
		}
		if !tc.ok && !strings.Contains(msg, "default") {
			t.Errorf("%s: refusal does not name the default: %q", tc.input, msg)
		}
	}
}
