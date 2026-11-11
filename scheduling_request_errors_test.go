//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// POST /api/_scheduled answered every body it could not decode with
// "run_at (RFC3339) required", and row_id was a string field, so the natural
// `"row_id": 1` failed with that message although run_at was valid (round
// 2026-11-05 logic finding 8). A number row_id is accepted and stored as
// text; other decode problems are reported as what they are.
func TestScheduledTaskRequestErrorsNameTheField(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "sched@example.com", "user", "", "")

	w := auditPost(mux, sid, "/api/_scheduled", "", `{"kind":"reminder","title":"n","table":"notes","row_id":1,"run_at":"30s"}`, true)
	if w.Code != 200 {
		t.Fatalf("numeric row_id refused: %d %s", w.Code, w.Body.String())
	}
	var stored string
	if err := app.DB.QueryRow("SELECT row_id FROM _benmore_scheduled_tasks").Scan(&stored); err != nil || stored != "1" {
		t.Fatalf("stored row_id = %q, %v; want \"1\"", stored, err)
	}
	r := httptest.NewRequest("GET", "/api/_scheduled?table=notes&row_id=1", nil)
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	lw := httptest.NewRecorder()
	mux.ServeHTTP(lw, r)
	var listed struct {
		Tasks []map[string]any `json:"tasks"`
	}
	if err := json.Unmarshal(lw.Body.Bytes(), &listed); err != nil || len(listed.Tasks) != 1 {
		t.Fatalf("listing by the numeric row_id: %d %s", lw.Code, lw.Body.String())
	}
	if w := auditPost(mux, sid, "/api/_scheduled", "", `{"kind":"reminder","row_id":"abc-1","run_at":"30s"}`, true); w.Code != 200 {
		t.Fatalf("string row_id refused: %d %s", w.Code, w.Body.String())
	}

	for _, tc := range []struct {
		body, want string
	}{
		{`{"kind":"reminder","row_id":1.5,"run_at":"30s"}`, "row_id must be a string or an integer"},
		{`{"kind":"reminder","row_id":{"id":1},"run_at":"30s"}`, "row_id must be a string or an integer"},
		{`{"kind":"reminder","title":7,"run_at":"30s"}`, `"title" must be a string`},
		{`{"kind":"reminder","run_at":`, "request body must be a JSON object"},
		{`[1,2]`, "request body must be a JSON object"},
		{`{"kind":"reminder","title":"no time"}`, "run_at required"},
	} {
		w := auditPost(mux, sid, "/api/_scheduled", "", tc.body, true)
		var answer struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &answer)
		if w.Code != 400 || !strings.Contains(answer.Error, tc.want) {
			t.Errorf("%s: %d %s, want 400 naming %q", tc.body, w.Code, w.Body.String(), tc.want)
		}
		if tc.want != "run_at required" && strings.Contains(answer.Error, "run_at") {
			t.Errorf("%s blamed run_at: %s", tc.body, answer.Error)
		}
	}

	// Approvals decode row_id the same way.
	w = auditPost(mux, sid, "/api/_approvals", "", `{"table":"expense-label","row_id":7,"approver_email":"boss@example.com","title":"t"}`, true)
	if w.Code != 200 {
		t.Fatalf("approval with a numeric row_id: %d %s", w.Code, w.Body.String())
	}
	if err := app.DB.QueryRow("SELECT row_id FROM _benmore_approvals").Scan(&stored); err != nil || stored != "7" {
		t.Fatalf("approval row_id = %q, %v; want \"7\"", stored, err)
	}
	if w := auditPost(mux, sid, "/api/_approvals", "", `{"table":"expense-label","row_id":true}`, true); w.Code != 400 || !strings.Contains(w.Body.String(), "row_id must be a string or an integer") {
		t.Fatalf("approval with a boolean row_id: %d %s", w.Code, w.Body.String())
	}
}

// Scheduling a role-gated flow its creator never held said "task owner no
// longer has the flow's required role" at creation (finding 11c). Creation
// now says the caller does not hold the role; the fire-time reason stored on
// a blocked task keeps its wording.
func TestScheduledFlowCreationRefusalSaysWhy(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "plain@example.com", "user", "", "")
	app.Flows = []Flow{{Name: "approve", Auth: "required", Role: "manager", Trigger: FlowTrigger{Type: "http", Method: "POST"}, Steps: []FlowStep{{Type: "sql", SQL: "SELECT 1"}}}}

	w := auditPost(mux, sid, "/api/_scheduled", "", `{"kind":"flow","flow":"approve","run_at":"1h"}`, true)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "you do not hold the role this flow requires") || strings.Contains(w.Body.String(), "no longer") {
		t.Fatalf("role refusal at creation: %d %s", w.Code, w.Body.String())
	}
	w = auditPost(mux, sid, "/api/_scheduled", "", `{"kind":"flow","flow":"missing","run_at":"1h"}`, true)
	if w.Code != 403 || !strings.Contains(w.Body.String(), "no flow with this name exists") || strings.Contains(w.Body.String(), "no longer") {
		t.Fatalf("unknown flow at creation: %d %s", w.Code, w.Body.String())
	}
	if n := countRows(t, app, "_benmore_scheduled_tasks"); n != 0 {
		t.Fatalf("refused schedules stored %d tasks", n)
	}

	// At fire time the stored reason still says the grant went away.
	_, err := schedulableFlow(app, "approve", GetSessionFromDB(app.DB, sid))
	if err == nil || err.Error() != "task owner no longer has the flow's required role" {
		t.Fatalf("fire-time reason = %v", err)
	}
}
