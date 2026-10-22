//go:build !cli

package main

import (
	"encoding/json"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
)

func runHeaderParseFlow(t *testing.T, headers map[string][]string, body string, transaction bool) (*httptest.ResponseRecorder, *App) {
	t.Helper()
	app, done := newTestApp(t)
	t.Cleanup(done)
	steps := []FlowStep{
		{Name: "request_headers", Type: "parse", Parse: "headers"},
	}
	if transaction {
		if _, err := app.DB.Exec(`CREATE TABLE header_parse_writes (value TEXT NOT NULL)`); err != nil {
			t.Fatal(err)
		}
		steps = append(steps, FlowStep{Type: "sql", SQL: `INSERT INTO header_parse_writes(value) VALUES ('committed')`, ExpectRows: "=1"})
	}
	steps = append(steps, FlowStep{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "{{request_headers}}"}})
	flow := Flow{Name: "parse_headers", Transaction: transaction, Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/parse-headers"}, Steps: steps}
	req := httptest.NewRequest("POST", "/api/parse-headers", strings.NewReader(body))
	for key, values := range headers {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}
	rr := httptest.NewRecorder()
	if err := executeFlowHTTP(app, &flow, rr, req); err != nil {
		t.Fatalf("execute flow: %v", err)
	}
	return rr, app
}

func TestParseRequestHeadersPreservesValuesAndIgnoresBodySpoofs(t *testing.T) {
	tests := []struct {
		name    string
		headers map[string][]string
		body    string
		want    []string
	}{
		{name: "missing", want: nil},
		{name: "single", headers: map[string][]string{"Idempotency-Key": {"header-key"}}, want: []string{"header-key"}},
		{name: "repeated", headers: map[string][]string{"Idempotency-Key": {"first", "second"}}, want: []string{"first", "second"}},
		{name: "body spoof", body: `{"Idempotency-Key":"body-key"}`, want: nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rr, _ := runHeaderParseFlow(t, tc.headers, tc.body, false)
			if rr.Code != 200 {
				t.Fatalf("status = %d, body = %s", rr.Code, rr.Body.String())
			}
			var got map[string][]string
			if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
				t.Fatalf("decode response: %v (%s)", err, rr.Body.String())
			}
			if !reflect.DeepEqual(got["Idempotency-Key"], tc.want) {
				t.Fatalf("Idempotency-Key values = %#v, want %#v", got["Idempotency-Key"], tc.want)
			}
		})
	}
}

func TestParseRequestHeadersKeepsTransactionalResponseAfterCommit(t *testing.T) {
	rr, app := runHeaderParseFlow(t, map[string][]string{"Idempotency-Key": {"tx-key"}}, "", true)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"Idempotency-Key":["tx-key"]`) {
		t.Fatalf("transactional response = %d %s", rr.Code, rr.Body.String())
	}
	var count int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM header_parse_writes WHERE value='committed'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("transaction write count = %d, err = %v", count, err)
	}
}
