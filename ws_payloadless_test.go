//go:build !cli

package main

import (
	"encoding/json"
	"net/http/httptest"
	"testing"
)

func wsPayloadOf(t *testing.T, member *wsClient) string {
	t.Helper()
	realtimeFlush()
	select {
	case raw := <-member.send:
		var frame struct {
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(raw, &frame); err != nil {
			t.Fatalf("frame %s: %v", raw, err)
		}
		return string(frame.Payload)
	default:
		t.Fatal("room member received nothing")
	}
	return ""
}

// A `ws:` step or hook with no payload used to send its whole context to
// every room member: request fields, the caller's user row, SQL rows, an
// enqueue step's status token (a capability for the job's status), and for
// a hook the written row, encrypted-field columns in plaintext. Room members are
// any signed-in user of the app or tenant who joins an undeclared room, so
// a payload-less message now carries only a minimal event: `{}` from a flow
// or cron step, `{"table":...}` from a hook. A declared payload is unchanged.
func TestPayloadlessWSSendsMinimalEvent(t *testing.T) {
	resetWSHub(t)
	app := secretTaintApp(t)
	EnsureJobsTable(app.DB)
	member := newWSTestClient(realtimeAppID(app.Dir), 7, "")
	registerWSClient(member)
	defer unregisterWSClient(member)
	wsJoinAs(member, "lobby")

	flow := Flow{Name: "notify", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/notify"}, Steps: []FlowStep{
		{Name: "row", Type: "sql", SQL: "SELECT 'internal-note' AS note"},
		{Name: "job", Type: "enqueue", Enqueue: &FlowEnqueue{Flow: "later"}},
		{Type: "ws", WS: &FlowWS{Room: "lobby"}},
		{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "ok"}},
	}}
	req := httptest.NewRequest("GET", "/api/notify?card=4242", nil)
	if err := executeFlowHTTP(app, &flow, httptest.NewRecorder(), req); err != nil {
		t.Fatal(err)
	}
	if got := wsPayloadOf(t, member); got != `{}` {
		t.Fatalf("flow ws step without payload sent %s; want {}", got)
	}

	steps := convertSteps([]FlowStepYAML{{Name: "row", SQL: "SELECT 'internal-note' AS note"}, {WS: &FlowWSYAML{Room: "lobby"}}})
	if err := runCronJob(app, CronJob{ID: "tick", Steps: steps}, nil); err != nil {
		t.Fatal(err)
	}
	if got := wsPayloadOf(t, member); got != `{}` {
		t.Fatalf("cron ws step without payload sent %s; want {}", got)
	}

	if err := roundTripHookJob(t, app, hookJobPayload(Hook{WS: &WSHook{Room: "lobby"}}, "notes", map[string]any{"id": 4, "body": "private text"})); err != nil {
		t.Fatal(err)
	}
	if got := wsPayloadOf(t, member); got != `{"table":"notes"}` {
		t.Fatalf("hook ws without payload sent %s; want {\"table\":\"notes\"}", got)
	}

	// A declared payload still sends what it names.
	flow.Steps[2].WS.Payload = `{"note":"{{row.note}}"}`
	if err := executeFlowHTTP(app, &flow, httptest.NewRecorder(), httptest.NewRequest("GET", "/api/notify", nil)); err != nil {
		t.Fatal(err)
	}
	if got := wsPayloadOf(t, member); got != `{"note":"internal-note"}` {
		t.Fatalf("declared payload sent %s", got)
	}
}
