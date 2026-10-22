//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"
)

// jsonTemplateReceiver points the strict outbound transport at a local
// server and returns the bodies it receives. The hook and step URLs are a
// public address literal, so they pass the SSRF guard.
func jsonTemplateReceiver(t *testing.T) (string, chan string) {
	t.Helper()
	got := make(chan string, 8)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
	}))
	t.Cleanup(srv.Close)
	saved := strictOutboundTransport
	strictOutboundTransport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}}
	t.Cleanup(func() { strictOutboundTransport = saved })
	return "http://93.184.216.34/hook", got
}

func decodeJSONObject(t *testing.T, where, body string) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal([]byte(body), &out); err != nil {
		t.Fatalf("%s: not a JSON object: %v\n%s", where, err, body)
	}
	return out
}

const jsonTemplateSpoof = `hi","from":"admin","x":"`

// A row value or request field written into a JSON template stays one value.
// Before the fix the value was spliced in verbatim, so a quote in it closed
// the string and added (or overrode) keys of the outbound body or of the
// message other room members receive; a legitimate quote or newline made the
// JSON invalid.
func TestHookJSONTemplatesEscapeRowValues(t *testing.T) {
	resetWSHub(t)
	app := hookDefaultBodyApp(t)
	hookURL, got := jsonTemplateReceiver(t)
	row := map[string]any{"id": 4, "name": jsonTemplateSpoof, "note": "line one\nsaid \"x\" \\ done", "tags": `["a","b"]`, "count": "1,\"admin\":true"}
	const template = `{"from":"system","name":"{{name}}","note":"{{note}}","id":{{id}},"tags":{{tags}},"count":{{count}}}`

	check := func(where, body string) {
		t.Helper()
		obj := decodeJSONObject(t, where, body)
		if obj["from"] != "system" || obj["name"] != jsonTemplateSpoof || obj["note"] != row["note"] {
			t.Fatalf("%s: string values not kept whole: %v", where, obj)
		}
		if obj["id"] != float64(4) {
			t.Fatalf("%s: numeric value changed: %v", where, obj["id"])
		}
		if tags, _ := obj["tags"].([]any); len(tags) != 2 {
			t.Fatalf("%s: a JSON value in a value position must stay JSON: %v", where, obj["tags"])
		}
		if obj["count"] != "1,\"admin\":true" || obj["admin"] != nil || len(obj) != 6 {
			t.Fatalf("%s: a value that is not one JSON value must not add keys: %v", where, obj)
		}
	}

	if err := roundTripHookJob(t, app, hookJobPayload(Hook{Webhook: hookURL, Body: template}, "integrations", row)); err != nil {
		t.Fatal(err)
	}
	select {
	case body := <-got:
		check("hook body", body)
	case <-time.After(5 * time.Second):
		t.Fatal("hook webhook not delivered")
	}

	member := newWSTestClient(realtimeAppID(app.Dir), 7, "")
	registerWSClient(member)
	defer unregisterWSClient(member)
	wsJoinAs(member, "feed")
	if err := roundTripHookJob(t, app, hookJobPayload(Hook{WS: &WSHook{Room: "feed", Payload: template}}, "integrations", row)); err != nil {
		t.Fatal(err)
	}
	realtimeFlush()
	select {
	case raw := <-member.send:
		var frame struct {
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(raw, &frame); err != nil {
			t.Fatal(err)
		}
		check("hook ws payload", string(frame.Payload))
	default:
		t.Fatal("room member received nothing")
	}

	// A template that is not a JSON document keeps verbatim substitution.
	if err := roundTripHookJob(t, app, hookJobPayload(Hook{Webhook: hookURL, Body: `name={{name}}`}, "integrations", row)); err != nil {
		t.Fatal(err)
	}
	if body := <-got; body != "name="+jsonTemplateSpoof {
		t.Fatalf("text body changed: %q", body)
	}
}

func TestFlowJSONTemplatesEscapeRequestValues(t *testing.T) {
	resetWSHub(t)
	app := secretTaintApp(t)
	hookURL, got := jsonTemplateReceiver(t)
	member := newWSTestClient(realtimeAppID(app.Dir), 7, "")
	registerWSClient(member)
	defer unregisterWSClient(member)
	wsJoinAs(member, "lobby")

	const template = `{"from":"system","msg":"{{msg}}","when":":day","rows":{{q.rows}},"n":{{n}},"ok":true}`
	flow := Flow{Name: "notify", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/notify/:day"}, Steps: []FlowStep{
		{Name: "q", Type: "sql", SQL: `SELECT json_array(1, 2) AS rows`},
		{Type: "webhook", Webhook: hookURL, WebhookBody: template},
		{Type: "ws", WS: &FlowWS{Room: "lobby", Payload: template}},
		{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "ok"}},
	}}
	q := url.Values{"msg": {jsonTemplateSpoof}, "n": {`2,"admin":true`}, "true": {`true,"admin":true`}}
	day := url.PathEscape(`mon","admin":"yes`)
	rec := httptest.NewRecorder()
	if err := executeFlowHTTP(app, &flow, rec, httptest.NewRequest("GET", "/api/notify/"+day+"?"+q.Encode(), nil)); err != nil {
		t.Fatal(err)
	}
	if rec.Code != 200 {
		t.Fatalf("flow status %d: %s", rec.Code, rec.Body)
	}
	check := func(where, body string) {
		t.Helper()
		obj := decodeJSONObject(t, where, body)
		if obj["from"] != "system" || obj["msg"] != jsonTemplateSpoof || obj["when"] != `mon","admin":"yes` || obj["ok"] != true {
			t.Fatalf("%s: values not kept whole: %v", where, obj)
		}
		if rows, _ := obj["rows"].([]any); len(rows) != 2 {
			t.Fatalf("%s: JSON text in a value position must stay JSON: %v", where, obj["rows"])
		}
		if obj["n"] != `2,"admin":true` || obj["admin"] != nil || len(obj) != 6 {
			t.Fatalf("%s: request input added keys: %v", where, obj)
		}
	}
	select {
	case body := <-got:
		check("run: webhook body", body)
	case <-time.After(5 * time.Second):
		t.Fatal("webhook not delivered")
	}
	realtimeFlush()
	select {
	case raw := <-member.send:
		var frame struct {
			Payload json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(raw, &frame); err != nil {
			t.Fatal(err)
		}
		check("ws payload", string(frame.Payload))
	default:
		t.Fatal("room member received nothing")
	}
}

// The renderer's slot rules, on the author's template alone.
func TestJSONTemplateShape(t *testing.T) {
	row := map[string]any{"s": `a"b`, "n": 5, "nil": nil, "j": `{"k":1}`, "t": "x y"}
	for _, c := range []struct{ template, want string }{
		{`{"a":"{{s}}"}`, `{"a":"a\"b"}`},
		{`["{{s}}",{{n}}]`, `["a\"b",5]`},
		{`{"a":{{nil}},"b":"{{nil}}"}`, `{"a":null,"b":"<nil>"}`},
		{`{"a":{{j}}}`, `{"a":{"k":1}}`},
		{`{"a":{{t}}}`, `{"a":"x y"}`},
		{`"{{s}}"`, `"a\"b"`},
		{`{"a":"{{missing}}"}`, `{"a":"{{missing}}"}`},
		// Not JSON documents: verbatim, as before.
		{`{{j}}`, `{"k":1}`},
		{`{"a":1 {{t}}}`, `{"a":1 x y}`},
		{`s={{s}}`, `s=a"b`},
	} {
		if got := interpolateRowJSONWithEnv(c.template, row, map[string]string{}, ""); got != c.want {
			t.Errorf("%s: got %s, want %s", c.template, got, c.want)
		}
	}
}
