//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// `run: notify` gives a flow (request, cron, async, data event) the in-app
// notification a hooks.yaml `notify:` creates. A flow's SQL writes never
// fire hooks.yaml or event flows, and there is no notification create API,
// so before this step a cron job had no supported way to notify a user.

const notifyRequestFlow = `on:
  request:
    method: POST
    path: /api/ping-user
    auth: required

jobs:
  ping:
    steps:
      - id: n
        run: notify
        with:
          user_id: ${{ params.to }}
          title: "Ping from ${{ user.email }}"
          body: "${{ params.message }}"
          link: /inbox
          type: success
      - run: respond
        with:
          status: 200
          json: { id: "${{ steps.n.outputs.id }}", to: "${{ steps.n.outputs.user_id }}" }
`

func notifyFlows(t *testing.T, path, text string) []Flow {
	t.Helper()
	if msg := ValidateOnWrite(path, text); msg != "" {
		t.Fatalf("%s fails the write gate: %s", path, msg)
	}
	flows, err := parseGHAFlowFile(path, []byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return flows
}

func notifyUserID(t *testing.T, app *App, sid string) int64 {
	t.Helper()
	s := GetSessionFromDB(app.DB, sid)
	if s == nil {
		t.Fatal("missing session")
	}
	return s.UserID
}

// notifyInbox is what GET /api/_notifications and /count answer the caller.
func notifyInbox(t *testing.T, app *App, sid string) (rows []map[string]any, unread, count int64) {
	t.Helper()
	mux := http.NewServeMux()
	RegisterNotificationRoutes(mux, app)
	get := func(path string, into any) {
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+sid)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, req)
		if rr.Code != http.StatusOK || json.Unmarshal(rr.Body.Bytes(), into) != nil {
			t.Fatalf("GET %s: %d %s", path, rr.Code, rr.Body.String())
		}
	}
	var list struct {
		Notifications []map[string]any `json:"notifications"`
		Unread        int64            `json:"unread"`
	}
	get("/api/_notifications", &list)
	var c struct {
		Unread int64 `json:"unread"`
	}
	get("/api/_notifications/count", &c)
	return list.Notifications, list.Unread, c.Unread
}

func postFlow(t *testing.T, app *App, flow *Flow, sid string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(flow.Trigger.Method, flow.Trigger.Path, strings.NewReader(string(raw)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sid)
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rr, req)
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	return rr.Code, out
}

const notifyEventSSE = `{"table":"_benmore_notifications","action":"insert"}`
const notifyEventWS = `{"type":"change","table":"_benmore_notifications","action":"insert"}`

// A request flow notifies another user: the notification is stored for the
// recipient only, counted, and announced live to the recipient's streams
// only. Request input fills title and body as values: text that looks like
// a template reference is stored as sent, never resolved again.
func TestFlowNotifyStepFromRequestFlow(t *testing.T) {
	app, _ := auditApp(t)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	carol := createCrudScopeSession(t, app, "carol@example.com", "user", "", "")
	bobID := notifyUserID(t, app, bob)
	SetAppEnv(app.Dir, "NOTIFY_PROBE", "env-secret-value")
	flows := notifyFlows(t, "flows/ping-user.yaml", notifyRequestFlow)

	aliceSub := subscribeFlowRealtime(t, app, alice)
	bobSub := subscribeFlowRealtime(t, app, bob)
	carolSub := subscribeFlowRealtime(t, app, carol)

	message := "see {{env.NOTIFY_PROBE}} and ${{ env.NOTIFY_PROBE }}"
	status, out := postFlow(t, app, &flows[0], alice, map[string]any{"to": bobID, "message": message})
	if status != http.StatusOK {
		t.Fatalf("flow status=%d body=%v", status, out)
	}
	if out["to"] != strconv.FormatInt(bobID, 10) && out["to"] != float64(bobID) {
		t.Errorf("outputs.user_id = %v, want %d", out["to"], bobID)
	}

	rows, unread, count := notifyInbox(t, app, bob)
	if len(rows) != 1 || unread != 1 || count != 1 {
		t.Fatalf("bob's inbox: rows=%v unread=%d count=%d, want one unread notification", rows, unread, count)
	}
	n := rows[0]
	if n["title"] != "Ping from alice@example.com" || n["body"] != message || n["type"] != "success" || n["link"] != "/inbox" {
		t.Fatalf("stored notification = %v", n)
	}
	if id, _ := n["id"].(float64); id <= 0 || out["id"] != strconv.FormatInt(int64(id), 10) && out["id"] != id {
		t.Errorf("outputs.id = %v, stored id = %v", out["id"], n["id"])
	}
	for name, sid := range map[string]string{"alice": alice, "carol": carol} {
		if rows, unread, _ := notifyInbox(t, app, sid); len(rows) != 0 || unread != 0 {
			t.Errorf("%s's inbox got %v", name, rows)
		}
	}

	sse, ws := bobSub.drain()
	if !reflect.DeepEqual(sse, []string{notifyEventSSE}) || !reflect.DeepEqual(ws, []string{notifyEventWS}) {
		t.Fatalf("recipient live events: sse=%q ws=%q", sse, ws)
	}
	for name, sub := range map[string]*flowRealtimeSubscriber{"alice (the caller)": aliceSub, "carol": carolSub} {
		if sse, ws := sub.drain(); len(sse)+len(ws) != 0 {
			t.Errorf("%s heard another user's notification: sse=%q ws=%q", name, sse, ws)
		}
	}
}

// A cron job runs a flow with no session and no request: it reads the owner
// from a row and notifies them. The scheduled flow is transactional, so the
// notification is announced after COMMIT, to the owner only.
func TestFlowNotifyStepFromCronFlow(t *testing.T) {
	app, _ := auditApp(t)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	bobID := notifyUserID(t, app, bob)
	auditExec(t, app.DB, "INSERT INTO notes (id, user_id, title) VALUES (7, ?, 'Invoice INV-7 is overdue')", bobID)
	app.Flows = notifyFlows(t, "flows/remind.yaml", `on:
  schedule:
    cron: "@hourly"
    transaction: true

jobs:
  remind:
    steps:
      - id: due
        run: sql
        with:
          query: "SELECT id, user_id, title FROM notes WHERE id = 7"
      - for_each: ${{ steps.due.outputs.rows }}
        as: note
        steps:
          - run: notify
            with:
              user_id: ${{ note.user_id }}
              title: "Reminder"
              body: "${{ note.title }}"
              link: "/notes/${{ note.id }}"
              type: warning
`)
	aliceSub := subscribeFlowRealtime(t, app, alice)
	bobSub := subscribeFlowRealtime(t, app, bob)

	if err := runCronJob(app, CronJob{ID: "remind", Schedule: "@hourly", Flow: "remind"}, nil); err != nil {
		t.Fatalf("cron run: %v", err)
	}
	rows, unread, count := notifyInbox(t, app, bob)
	if len(rows) != 1 || unread != 1 || count != 1 {
		t.Fatalf("owner's inbox: rows=%v unread=%d count=%d", rows, unread, count)
	}
	if n := rows[0]; n["title"] != "Reminder" || n["body"] != "Invoice INV-7 is overdue" || n["link"] != "/notes/7" || n["type"] != "warning" {
		t.Fatalf("stored notification = %v", n)
	}
	if sse, ws := bobSub.drain(); !reflect.DeepEqual(sse, []string{notifyEventSSE}) || !reflect.DeepEqual(ws, []string{notifyEventWS}) {
		t.Fatalf("owner live events: sse=%q ws=%q", sse, ws)
	}
	if sse, ws := aliceSub.drain(); len(sse)+len(ws) != 0 {
		t.Fatalf("another user heard the owner's notification: sse=%q ws=%q", sse, ws)
	}
	if rows, _, _ := notifyInbox(t, app, alice); len(rows) != 0 {
		t.Fatalf("alice's inbox got %v", rows)
	}
}

// In a transactional flow the notification is part of the transaction: a
// later failure rolls it back and nothing is announced.
func TestFlowNotifyStepRollsBackWithItsTransaction(t *testing.T) {
	app, _ := auditApp(t)
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	bobID := notifyUserID(t, app, bob)
	flows := notifyFlows(t, "flows/assign.yaml", `on:
  request:
    method: POST
    path: /api/assign
    auth: required
    transaction: true

jobs:
  assign:
    steps:
      - run: notify
        with:
          user_id: ${{ params.to }}
          title: "Assigned"
      - run: sql
        with:
          query: "INSERT INTO missing_table (x) VALUES (1)"
      - run: respond
        with:
          status: 200
          json: { ok: true }
`)
	bobSub := subscribeFlowRealtime(t, app, bob)
	if status, out := postFlow(t, app, &flows[0], bob, map[string]any{"to": bobID}); status == http.StatusOK {
		t.Fatalf("failing transactional flow answered 200: %v", out)
	}
	if rows, unread, _ := notifyInbox(t, app, bob); len(rows) != 0 || unread != 0 {
		t.Fatalf("a rolled-back notification was kept: %v", rows)
	}
	if sse, ws := bobSub.drain(); len(sse)+len(ws) != 0 {
		t.Fatalf("a rolled-back notification was announced: sse=%q ws=%q", sse, ws)
	}
}

// A recipient id that names no user fails the step: nothing is stored (no
// orphan row an account created later with that id would inherit), the flow
// answers its step failure, and an on_error handler can catch it.
func TestFlowNotifyStepMissingUserFailsTheStep(t *testing.T) {
	app, _ := auditApp(t)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	flows := notifyFlows(t, "flows/ping-user.yaml", notifyRequestFlow)
	status, out := postFlow(t, app, &flows[0], alice, map[string]any{"to": 999999, "message": "hi"})
	if status != http.StatusInternalServerError || out["failed_step"] != "n" || out["failed_type"] != "notify" {
		t.Fatalf("missing recipient: status=%d body=%v", status, out)
	}
	if reason, _ := out["reason"].(string); reason != "the notification could not be created" {
		t.Errorf("reason = %q", reason)
	}
	var stored int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_notifications").Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("missing recipient stored %d notifications (err %v)", stored, err)
	}
	for _, to := range []any{"bob", 0, -3, "1; DROP TABLE notes"} {
		if status, out := postFlow(t, app, &flows[0], alice, map[string]any{"to": to, "message": "hi"}); status != http.StatusInternalServerError || out["failed_type"] != "notify" {
			t.Errorf("user_id %v: status=%d body=%v", to, status, out)
		}
	}

	handled := notifyFlows(t, "flows/ping-handled.yaml", `on:
  request:
    method: POST
    path: /api/ping-handled
    auth: required

jobs:
  ping:
    steps:
      - run: notify
        with:
          user_id: ${{ params.to }}
          title: "Ping"
        on_error:
          - run: respond
            with:
              status: 404
              json: { error: "no such user" }
      - run: respond
        with:
          status: 200
          json: { ok: true }
`)
	if status, out := postFlow(t, app, &handled[0], alice, map[string]any{"to": 999999}); status != http.StatusNotFound || out["error"] != "no such user" {
		t.Fatalf("on_error handler: status=%d body=%v", status, out)
	}
}

// The write gate (and `benmore check`, and the loader, which share
// validateGHAFlowsContents) refuses a notify step that could never create a
// notification, and the step-key gate refuses a key the step does not read.
func TestFlowNotifyStepWriteGate(t *testing.T) {
	file := func(with string) string {
		return "on:\n  request:\n    method: POST\n    path: /api/n\n    auth: required\njobs:\n  n:\n    steps:\n      - id: n\n        run: notify\n        with:\n" + with +
			"      - run: respond\n        with:\n          status: 200\n          json: { ok: true }\n"
	}
	for _, tc := range []struct {
		name, with, want string
	}{
		{"no recipient", "          title: Hi\n", "requires `with.user_id`"},
		{"no title", "          user_id: 4\n", "requires `with.title`"},
		{"empty title", "          user_id: 4\n          title: \"  \"\n", "`with.title` is empty"},
		{"literal name", "          user_id: bob\n          title: Hi\n", "is not a user id"},
		{"zero id", "          user_id: 0\n          title: Hi\n", "is not a user id"},
		{"list recipient", "          user_id: [1, 2]\n          title: Hi\n", "`with.user_id` must be"},
		{"map body", "          user_id: 4\n          title: Hi\n          body: { a: 1 }\n", "`with.body` must be text"},
		{"unknown type", "          user_id: 4\n          title: Hi\n          type: urgent\n", "`with.type` \"urgent\""},
		{"unknown key", "          user_id: 4\n          title: Hi\n          recipient: 5\n", "`with.recipient`"},
		{"hook spelling", "          user_id: 4\n          notify_title: Hi\n", "`with.notify_title`"},
	} {
		if msg := ValidateOnWrite("flows/n.yaml", file(tc.with)); !strings.Contains(msg, tc.want) {
			t.Errorf("%s: write gate = %q, want it to contain %q", tc.name, msg, tc.want)
		}
	}
	for _, tc := range []struct{ name, with string }{
		{"integer literal", "          user_id: 4\n          title: Hi\n"},
		{"quoted integer", "          user_id: \"4\"\n          title: Hi\n"},
		{"templated", "          user_id: ${{ params.to }}\n          title: \"Hi ${{ params.name }}\"\n          body: \"${{ params.body }}\"\n          link: \"/x/${{ params.id }}\"\n"},
		{"templated type", "          user_id: 4\n          title: Hi\n          type: ${{ params.kind }}\n"},
		{"every type", "          user_id: 4\n          title: Hi\n          type: error\n"},
	} {
		if msg := ValidateOnWrite("flows/n.yaml", file(tc.with)); msg != "" {
			t.Errorf("%s: refused: %s", tc.name, msg)
		}
	}
	// Nested steps are checked too.
	nested := "on:\n  schedule:\n    cron: \"@hourly\"\njobs:\n  n:\n    steps:\n      - id: x\n        run: sql\n        with:\n          query: \"SELECT id, user_id FROM notes\"\n      - for_each: ${{ steps.x.outputs.rows }}\n        steps:\n          - run: notify\n            with:\n              user_id: ${{ item.user_id }}\n"
	if msg := ValidateOnWrite("flows/n.yaml", nested); !strings.Contains(msg, "requires `with.title`") {
		t.Errorf("nested notify without a title: %q", msg)
	}
}

// A notify step built from request input yields request input: its outputs
// stay tainted, so `sql_dynamic` still refuses `steps.n.outputs.user_id`
// when the recipient came from the request (security.md 2c).
func TestFlowNotifyStepOutputsKeepRequestTaint(t *testing.T) {
	for _, tc := range []struct {
		userID  string
		tainted bool
	}{
		{"{{to}}", true},
		{"{{owner.user_id}}", false},
	} {
		ctx := &FlowContext{Data: map[string]any{}, Params: map[string]string{}, RequestKeys: map[string]bool{"to": true}}
		step := &FlowStep{Name: "n", Type: "notify", Notify: &FlowNotify{UserID: tc.userID, Title: "Hi"}}
		ctx.taintStepOutputs(step)
		if got := ctx.taintedRef("{{n.user_id}}") != ""; got != tc.tainted {
			t.Errorf("user_id %s: outputs tainted = %v, want %v", tc.userID, got, tc.tainted)
		}
	}
}

// A data-event flow - the flow counterpart of a hooks.yaml `notify:` - can
// notify the row's owner; only the owner hears it.
func TestFlowNotifyStepFromDataEventFlow(t *testing.T) {
	app, _ := auditApp(t)
	alice := createCrudScopeSession(t, app, "alice@example.com", "user", "", "")
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	bobID := notifyUserID(t, app, bob)
	flows := notifyFlows(t, "flows/note-added.yaml", `on:
  event: {table: notes, op: insert}
jobs:
  tell:
    steps:
      - run: notify
        with:
          user_id: ${{ user_id }}
          title: "Note added"
          body: "${{ title }}"
`)
	aliceSub := subscribeFlowRealtime(t, app, alice)
	bobSub := subscribeFlowRealtime(t, app, bob)
	var failure error
	runFlowEventWith(app, flows[0], map[string]any{"id": int64(3), "user_id": bobID, "title": "groceries"}, func(ctx *FlowContext) { failure = ctx.Error })
	if failure != nil {
		t.Fatalf("event flow failed: %v", failure)
	}
	if rows, unread, _ := notifyInbox(t, app, bob); len(rows) != 1 || unread != 1 || rows[0]["body"] != "groceries" {
		t.Fatalf("owner's inbox = %v (unread %d)", rows, unread)
	}
	if sse, _ := bobSub.drain(); !reflect.DeepEqual(sse, []string{notifyEventSSE}) {
		t.Fatalf("owner's live events = %q", sse)
	}
	if sse, ws := aliceSub.drain(); len(sse)+len(ws) != 0 {
		t.Fatalf("alice heard bob's notification: %q %q", sse, ws)
	}
}
