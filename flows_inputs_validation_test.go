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
