//go:build !cli

package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// A `ws:` step with no payload sends only the minimal event `{}` to the
// room: never the flow context, so neither env-derived values (a set or api
// step reading {{env.X}}) nor request fields or step outputs. A declared
// payload reaches the room as before.
func TestWSStepDefaultPayloadOmitsEnvDerivedValues(t *testing.T) {
	resetWSHub(t)
	app := secretTaintApp(t)
	member := newWSTestClient(realtimeAppID(app.Dir), 7, "")
	registerWSClient(member)
	defer unregisterWSClient(member)
	wsJoinAs(member, "lobby")

	run := func(payload string) map[string]any {
		t.Helper()
		flow := Flow{Name: "notify", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/notify"}, Steps: []FlowStep{
			{Name: "cfg", Type: "set", Set: map[string]string{"key": "{{env.CLIENT_SECRET}}", "region": "us"}},
			{Name: "row", Type: "sql", SQL: "SELECT 'shipped' AS status"},
			{Type: "ws", WS: &FlowWS{Room: "lobby", Payload: payload}},
			{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "ok"}},
		}}
		if err := executeFlowHTTP(app, &flow, httptest.NewRecorder(), httptest.NewRequest("GET", "/api/notify?note=hello", nil)); err != nil {
			t.Fatal(err)
		}
		realtimeFlush()
		var frame struct {
			Payload map[string]any `json:"payload"`
		}
		select {
		case raw := <-member.send:
			if strings.Contains(string(raw), "s3cret-value") {
				t.Fatalf("room received an env-derived value: %s", raw)
			}
			if err := json.Unmarshal(raw, &frame); err != nil {
				t.Fatalf("frame %s: %v", raw, err)
			}
		default:
			t.Fatal("room member received nothing")
		}
		return frame.Payload
	}

	if got := run(""); len(got) != 0 {
		t.Fatalf("default payload = %v; want the empty event {}", got)
	}

	declared := run(`{"status":"{{row.status}}","note":"{{note}}"}`)
	if declared["status"] != "shipped" || declared["note"] != "hello" || len(declared) != 2 {
		t.Fatalf("declared payload changed: %v", declared)
	}
}
