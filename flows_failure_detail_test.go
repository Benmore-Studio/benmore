//go:build !cli

package main

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

// flowFailureAnswer reads a failed flow's answer: one JSON object, the
// flow_no_response diagnostic, whose "message" is the server-error text. It
// was a text line followed by the JSON, which res.json() could not parse
// (Round 2 B15).
func flowFailureAnswer(t *testing.T, rr *httptest.ResponseRecorder) (string, map[string]any) {
	t.Helper()
	if ct := rr.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("failed flow answer Content-Type = %q, want JSON: %q", ct, rr.Body.String())
	}
	var diag map[string]any
	if err := json.Unmarshal(rr.Body.Bytes(), &diag); err != nil {
		t.Fatalf("failed flow answer is not one JSON object: %v %q", err, rr.Body.String())
	}
	line, _ := diag["message"].(string)
	return line, diag
}

// A failing `run: sql` step answered 500 flow_no_response naming the step but
// not why it failed. Every caller now gets a fixed reason (never SQLite's
// text); the step's own error and hint are in the answer only in dev mode and
// for a signed-in app admin, and always in the request log and the journal
// (FLOW ERROR lines) under the answer's request id.
func TestFailedFlowStepNamesASafeReasonAndShowsTheErrorWherePolicyAllows(t *testing.T) {
	for _, mode := range []string{"anonymous", "member", "admin", "dev"} {
		t.Run(mode, func(t *testing.T) {
			f := newServerErrorFixture(t, mode == "dev")
			adminID, adminSID := gateUser(t, f.app, "admin@example.com")
			mustExec(t, f.app.DB, "UPDATE _benmore_users SET role = 'admin' WHERE id = "+strconv.FormatInt(adminID, 10))
			flow := &Flow{Name: "add-note", Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/add-note"},
				Steps: []FlowStep{
					{Name: "insert_note", Type: "sql", SQL: `INSERT INTO missing_notes (body) VALUES ('x')`},
					{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "ok"}},
				}}
			f.handler = func(w http.ResponseWriter, r *http.Request) { executeFlowHTTP(f.app, flow, w, r) }
			r := httptest.NewRequest(http.MethodPost, "https://app.example.com/api/add-note", strings.NewReader(`{}`))
			r.Header.Set("Content-Type", "application/json")
			switch mode {
			case "member":
				r.Header.Set("Authorization", "Bearer "+f.sid)
			case "admin":
				r.Header.Set("Authorization", "Bearer "+adminSID)
			}
			w := httptest.NewRecorder()
			journal := captureLog(t, func() { f.logged.ServeHTTP(w, r) })

			id := w.Header().Get(requestIDHeader)
			if w.Code != http.StatusInternalServerError || !requestIDPattern.MatchString(id) {
				t.Fatalf("status %d id %q: %s", w.Code, id, w.Body.String())
			}
			line, diag := flowFailureAnswer(t, w)
			if diag["error"] != "flow_no_response" || diag["failed_step"] != "insert_note" || diag["failed_type"] != "sql" || diag["request_id"] != id {
				t.Fatalf("diagnostic lost its fields: %v", diag)
			}
			if diag["reason"] != "the statement names a table that does not exist" {
				t.Fatalf("reason = %v", diag["reason"])
			}
			detail := mode == "admin" || mode == "dev"
			stepErr, _ := diag["step_error"].(string)
			if detail {
				if !strings.Contains(stepErr, "no such table: missing_notes") || !strings.Contains(line, "no such table: missing_notes") {
					t.Fatalf("%s must see the step's error: line %q step_error %q", mode, line, stepErr)
				}
				if hint, _ := diag["hint"].(string); !strings.Contains(hint, "insert_note") {
					t.Fatalf("%s must see the step hint: %v", mode, diag["hint"])
				}
			} else {
				if strings.Contains(w.Body.String(), "missing_notes") || strings.Contains(w.Body.String(), "no such") {
					t.Fatalf("%s caller got the database's text: %s", mode, w.Body.String())
				}
				if line != "Internal error (request id: "+id+")" || diag["step_error"] != nil || diag["hint"] != nil {
					t.Fatalf("%s answer changed shape: line %q diag %v", mode, line, diag)
				}
				if hint, _ := diag["error_detail"].(string); !strings.Contains(hint, "request_id") {
					t.Fatalf("%s answer does not say where the error is: %v", mode, diag["error_detail"])
				}
			}
			// The journal has the full error on one FLOW ERROR line with the
			// request id, as `benmore tail --grep <id>` finds it.
			found := false
			for _, l := range strings.Split(journal, "\n") {
				if strings.Contains(l, "FLOW ERROR [add-note]") && strings.Contains(l, "no such table: missing_notes") && strings.Contains(l, "(request "+id+")") {
					found = true
				}
			}
			if !found {
				t.Fatalf("journal has no FLOW ERROR line with the error and request id:\n%s", journal)
			}
			rows := f.rows()
			if len(rows) != 1 || rows[0].requestID != id || !strings.Contains(rows[0].errDetail, "no such table: missing_notes") {
				t.Fatalf("request log row: %+v", rows)
			}
		})
	}
}

// The reason is a fixed phrase per kind of failure and never quotes the
// error: no table, column, value or upstream text reaches it.
func TestFlowFailureReasonNeverQuotesTheError(t *testing.T) {
	cases := []struct {
		stepType, err, want string
	}{
		{"sql", "sql: no such table: secret_ledger", "the statement names a table that does not exist"},
		{"sql", "sql: no such column: ssn", "the statement names a column that does not exist"},
		{"sql", `sql: near "SELEC": syntax error`, "the statement has a syntax error"},
		{"sql", "sql: UNIQUE constraint failed: users.email", "a record with the same unique value already exists"},
		{"sql", "sql: NOT NULL constraint failed: notes.body", "a required value is missing"},
		{"sql", "sql: FOREIGN KEY constraint failed", "a referenced record does not exist"},
		{"sql", "sql: CHECK constraint failed: amount > 0", "a value is not allowed"},
		{"sql", `sql: expect_rows assertion failed on step "x": 0 row(s) affected, expected >0`, "the statement returned or changed a different number of rows than expect_rows allows"},
		{"sql_dynamic", "sql_dynamic: database is locked", "the database was busy"},
		{"sql", "sql: trigger raised: alice@example.com is banned", "the statement failed"},
		{"api", "api: GET https://api.example.com/v1?key=abc returned 500: {\"detail\":\"x\"}", "the upstream service answered with an error status"},
		{"api", "api: dial tcp: connection refused", "the outbound call failed"},
		{"compute", "compute: TypeError: cannot read property 'ssn' of undefined", "the compute module failed"},
		{"email", "email: 550 mailbox unavailable", "the email could not be sent"},
		{"sql", "unresolved template reference(s) in step \"x\": steps.y.outputs.z - ...", "a ${{ }} reference in the step had no value when it ran"},
		{"", "commit: database is locked", "the database was busy"},
		{"transcribe", "transcribe: whisper exited 1", "the transcribe step failed"},
	}
	for _, c := range cases {
		got := flowFailureReason(c.stepType, errors.New(c.err))
		if got != c.want {
			t.Errorf("flowFailureReason(%q, %q) = %q, want %q", c.stepType, c.err, got, c.want)
		}
		for _, word := range []string{"secret_ledger", "ssn", "users.email", "alice", "abc", "550", "whisper"} {
			if strings.Contains(c.err, word) && strings.Contains(got, word) {
				t.Errorf("reason %q quotes %q from the error", got, word)
			}
		}
	}
}
