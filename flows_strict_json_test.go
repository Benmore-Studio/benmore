//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestStrictJSONFlowRejectsAmbiguousAndInvalidRequestsBeforeSteps(t *testing.T) {
	app, _ := auditApp(t)
	mustExec(t, app.DB, `CREATE TABLE strict_effects (value TEXT NOT NULL)`)
	strictSource := `on:
  request:
    method: POST
    path: /api/strict-json
    strict_json: true
    transaction: true
jobs:
  apply:
    steps:
      - run: sql
        with:
          query: INSERT INTO strict_effects(value) VALUES (:value)
      - run: respond
        with: {status: 200, json: {ok: true}}
`
	ordinarySource := strings.Replace(strictSource, "/api/strict-json", "/api/ordinary-json", 1)
	ordinarySource = strings.Replace(ordinarySource, "    strict_json: true\n", "", 1)
	strict, err := parseGHAFlowFile("flows/strict-json.yaml", []byte(strictSource))
	if err != nil || len(strict) != 1 || !strict[0].Trigger.StrictJSON {
		t.Fatalf("strict flow parse = %#v, %v", strict, err)
	}
	ordinary, err := parseGHAFlowFile("flows/ordinary-json.yaml", []byte(ordinarySource))
	if err != nil || len(ordinary) != 1 || ordinary[0].Trigger.StrictJSON {
		t.Fatalf("ordinary flow parse = %#v, %v", ordinary, err)
	}
	falseSource := strings.Replace(strictSource, "strict_json: true", "strict_json: false", 1)
	falseFlag, err := parseGHAFlowFile("flows/strict-json-off.yaml", []byte(falseSource))
	if err != nil || len(falseFlag) != 1 || falseFlag[0].Trigger.StrictJSON {
		t.Fatalf("explicit false flow parse = %#v, %v", falseFlag, err)
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, append(strict, ordinary...))

	cases := []struct {
		name, body, contentType string
	}{
		{"duplicate top-level key", `{"value":"first","value":"second"}`, "application/json"},
		{"duplicate nested key", `{"value":"ok","nested":{"x":1,"x":2}}`, "application/json"},
		{"malformed", `{`, "application/json"},
		{"trailing value", `{"value":"ok"} {}`, "application/json"},
		{"array", `[]`, "application/json"},
		{"null", `null`, "application/json"},
		{"invalid UTF-8", string([]byte{'{', '"', 'v', 'a', 'l', 'u', 'e', '"', ':', '"', 0xff, '"', '}'}), "application/json"},
		{"missing media type", `{"value":"ok"}`, ""},
		{"wrong media type", `value=ok`, "application/x-www-form-urlencoded"},
		{"oversized", `{"value":"` + strings.Repeat("x", flowStrictJSONMaxBytes) + `"}`, "application/json"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			before := strictJSONEffectCount(t, app)
			r := httptest.NewRequest(http.MethodPost, "/api/strict-json", strings.NewReader(tc.body))
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, r)
			if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "Invalid JSON request") {
				t.Fatalf("status/body = %d %q, want safe 400", w.Code, w.Body.String())
			}
			if strings.Contains(w.Body.String(), tc.body) || strictJSONEffectCount(t, app) != before {
				t.Fatal("invalid request was echoed or executed a flow step")
			}
		})
	}
	beforeDirect := strictJSONEffectCount(t, app)
	directRequest := httptest.NewRequest(http.MethodPost, "/api/strict-json", strings.NewReader(`{"value":"first","value":"second"}`))
	directRequest.Header.Set("Content-Type", "application/json")
	directResponse := httptest.NewRecorder()
	if err := executeFlowHTTPAsWithAPIClient(app, &strict[0], directResponse, directRequest, nil, nil); err == nil || directResponse.Code != http.StatusBadRequest || strictJSONEffectCount(t, app) != beforeDirect {
		t.Fatalf("strict rejection must return an error after writing a safe 400; status=%d err=%v", directResponse.Code, err)
	}
	valid := httptest.NewRequest(http.MethodPost, "/api/strict-json", strings.NewReader(`{"value":"accepted","nested":{"x":1}}`))
	valid.Header.Set("Content-Type", "application/json; charset=utf-8")
	validResponse := httptest.NewRecorder()
	mux.ServeHTTP(validResponse, valid)
	if validResponse.Code != http.StatusOK || strictJSONEffectCount(t, app) != 1 {
		t.Fatalf("valid strict request = %d %s; writes=%d", validResponse.Code, validResponse.Body.String(), strictJSONEffectCount(t, app))
	}
	ordinaryReq := httptest.NewRequest(http.MethodPost, "/api/ordinary-json", strings.NewReader(`{"value":"first","value":"last"}`))
	ordinaryReq.Header.Set("Content-Type", "application/json")
	ordinaryResponse := httptest.NewRecorder()
	mux.ServeHTTP(ordinaryResponse, ordinaryReq)
	var got string
	if err := app.DB.QueryRow(`SELECT value FROM strict_effects ORDER BY rowid DESC LIMIT 1`).Scan(&got); err != nil || ordinaryResponse.Code != http.StatusOK || got != "last" {
		t.Fatalf("ordinary flow behavior changed: status=%d value=%q err=%v", ordinaryResponse.Code, got, err)
	}
}

func TestStrictJSONFlagMustBeAValidYAMLBoolean(t *testing.T) {
	for _, raw := range []string{`null`, `"true"`, `1`, `yes`, `{}`} {
		source := fmt.Sprintf("on:\n  request:\n    method: POST\n    path: /api/flag\n    strict_json: %s\njobs:\n  apply:\n    steps:\n      - run: respond\n        with: {status: 200, json: {ok: true}}\n", raw)
		if _, err := parseGHAFlowFile("flows/flag.yaml", []byte(source)); err == nil {
			t.Errorf("runtime loader accepted strict_json: %s", raw)
		}
		if msg := validateFlowsYAML(source); msg == "" {
			t.Errorf("write gate accepted strict_json: %s", raw)
		}
	}
}

func strictJSONEffectCount(t *testing.T, app *App) int {
	t.Helper()
	var count int
	if err := app.DB.QueryRow(`SELECT count(*) FROM strict_effects`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
