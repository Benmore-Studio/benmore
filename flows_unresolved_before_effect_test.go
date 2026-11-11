//go:build !cli

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// A step that writes, sends or queues checks its references before it acts.
// The dispatcher checks them after the step has run, which is too late for an
// effect that cannot be taken back: a `run: sql` step stored the row with the
// text `{{params.b}}` in it, an email and a text message went out with the
// placeholder, a job was queued carrying it, and only then did the step fail.
// Each test here runs a flow whose step reads a value the request did not
// send and requires the same failure with nothing written, sent or queued.

const unresolvedProbeHead = "on:\n  request:\n    method: POST\n    path: /api/probe\njobs:\n  probe:\n    steps:\n"
const unresolvedProbeTail = "      - run: respond\n        with: { status: 200, json: { ok: true } }\n"
const unresolvedReason = "a ${{ }} reference in the step had no value when it ran"

// runUnresolvedProbe runs one flow file as an anonymous JSON POST and returns
// the answer and the body of every outbound request the flow made.
func runUnresolvedProbe(t *testing.T, app *App, steps, body string) (*httptest.ResponseRecorder, []string) {
	t.Helper()
	return runProbeSteps(t, app, steps+unresolvedProbeTail, body)
}

// runProbeSteps is runUnresolvedProbe for steps that answer themselves.
func runProbeSteps(t *testing.T, app *App, steps, body string) (*httptest.ResponseRecorder, []string) {
	t.Helper()
	flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "probe.yaml"), []byte(unresolvedProbeHead+steps))
	if err != nil || len(flows) != 1 {
		t.Fatalf("parse flow: %v (%d flows)\n%s", err, len(flows), steps)
	}
	var sent []string
	client := &http.Client{Transport: outboundRoundTrip(func(r *http.Request) (*http.Response, error) {
		b, _ := io.ReadAll(r.Body)
		sent = append(sent, string(b))
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: r}, nil
	})}
	r := httptest.NewRequest(http.MethodPost, "https://app.example.com/api/probe", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	executeFlowHTTPAsWithAPIClient(app, &flows[0], rr, r, nil, client)
	return rr, sent
}

// requireUnresolvedFailure checks the answer is the one a reference with no
// value has always produced: 500 with the fixed reason.
func requireUnresolvedFailure(t *testing.T, name string, rr *httptest.ResponseRecorder) {
	t.Helper()
	if rr.Code != http.StatusInternalServerError {
		t.Fatalf("%s: answered %d %s, want 500", name, rr.Code, rr.Body.String())
	}
	if got := decodeJSONAnswer(t, rr)["reason"]; got != unresolvedReason {
		t.Fatalf("%s: reason %v, want %q (%s)", name, got, unresolvedReason, rr.Body.String())
	}
}

func TestSQLStepWithAnUnresolvedReferenceRunsNoStatement(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, note TEXT)")
	count := func() string { return gateScalar(t, app, "SELECT COUNT(*) FROM items") }
	for _, c := range []struct{ name, steps, body string }{
		{"with.params", "      - run: sql\n        with:\n          query: \"INSERT INTO items (name, note) VALUES (:a, :b)\"\n          params:\n            a: \"${{ params.a }}\"\n            b: \"${{ params.b }}\"\n", `{"a":"A"}`},
		{"with.params, part of a value", "      - run: sql\n        with:\n          query: \"INSERT INTO items (name) VALUES (:nm)\"\n          params:\n            nm: \"${{ params.a }}-${{ params.b }}\"\n", `{"a":"A"}`},
		{"a quoted reference in the query", "      - run: sql\n        with:\n          query: \"INSERT INTO items (name, note) VALUES ('inline', '${{ params.b }}')\"\n", `{}`},
		{"a bare reference in the query", "      - run: sql\n        with:\n          query: \"INSERT INTO items (name, note) VALUES ('bare', ${{ params.b }})\"\n", `{}`},
		{"a retried step", "      - run: sql\n        retry: 3\n        retry_delay: 1ms\n        with:\n          query: \"INSERT INTO items (name, note) VALUES ('retry', :b)\"\n          params:\n            b: \"${{ params.b }}\"\n", `{}`},
	} {
		rr, _ := runUnresolvedProbe(t, app, c.steps, c.body)
		requireUnresolvedFailure(t, c.name, rr)
		if n := count(); n != "0" {
			t.Fatalf("%s: the statement ran: %s row(s) written, the stored note is %s", c.name, n, gateScalar(t, app, "SELECT COALESCE(note, name) FROM items LIMIT 1"))
		}
	}

	// A loop row that lacks a field stops the flow before that row's write;
	// the rows before it are written as they were.
	loop := "      - for_each: ${{ params.rows }}\n        as: r\n        steps:\n          - run: sql\n            with:\n              query: \"INSERT INTO items (name, note) VALUES (:n, :o)\"\n              params:\n                n: \"${{ r.name }}\"\n                o: \"${{ r.opt }}\"\n"
	rr, _ := runUnresolvedProbe(t, app, loop, `{"rows":[{"name":"r1","opt":"x"},{"name":"r2"}]}`)
	requireUnresolvedFailure(t, "a loop row without the field", rr)
	if names := gateScalar(t, app, "SELECT group_concat(name) FROM items"); names != "r1" {
		t.Fatalf("loop wrote %s, want only r1", names)
	}

	// Every reference has a value: the step runs as before.
	mustExec(t, app.DB, "DELETE FROM items")
	rr, _ = runUnresolvedProbe(t, app, "      - run: sql\n        with:\n          query: \"INSERT INTO items (name, note) VALUES (:a, '${{ params.b }}')\"\n          params:\n            a: \"${{ params.a }}\"\n", `{"a":"A","b":"B"}`)
	if rr.Code != http.StatusOK || gateScalar(t, app, "SELECT name || '-' || note FROM items") != "A-B" {
		t.Fatalf("a step whose references resolve answered %d %s", rr.Code, rr.Body.String())
	}
}

func TestEnqueueStepWithAnUnresolvedReferenceQueuesNoJob(t *testing.T) {
	app := newGateApp(t)
	EnsureJobsTable(app.DB)
	for name, with := range map[string]string{
		"a payload value": `{ flow: worker, with: { note: "${{ params.note }}" } }`,
		"the unique key":  `{ flow: worker, unique_key: "job:${{ params.note }}" }`,
	} {
		rr, _ := runUnresolvedProbe(t, app, "      - id: q\n        run: enqueue\n        with: "+with+"\n", `{}`)
		requireUnresolvedFailure(t, name, rr)
		if n := gateScalar(t, app, "SELECT COUNT(*) FROM _benmore_jobs"); n != "0" {
			t.Fatalf("%s: a job was queued: %s", name, gateScalar(t, app, "SELECT payload FROM _benmore_jobs LIMIT 1"))
		}
	}
	rr, _ := runUnresolvedProbe(t, app, "      - id: q\n        run: enqueue\n        with: { flow: worker, with: { note: \"${{ params.note }}\" } }\n", `{"note":"n1"}`)
	if rr.Code != http.StatusOK || gateScalar(t, app, "SELECT json_extract(payload, '$.note') FROM _benmore_jobs") != "n1" {
		t.Fatalf("an enqueue whose references resolve answered %d %s", rr.Code, rr.Body.String())
	}
}

func TestEmailStepWithAnUnresolvedReferenceSendsNothing(t *testing.T) {
	app := newGateApp(t)
	var sent []EmailOpts
	registerAppMailSender(app.Dir, func(opts EmailOpts) error {
		sent = append(sent, opts)
		return nil
	})
	t.Cleanup(func() { appMailSenders.Delete(filepath.Clean(app.Dir)) })
	step := func(with string) string { return "      - run: email\n        with: " + with + "\n" }
	for name, with := range map[string]string{
		"the text body": `{ to: "a@example.com", subject: "Hello", text: "Hi ${{ params.name }}" }`,
		"the html body": `{ to: "a@example.com", subject: "Hello", html: "<p>Hi ${{ params.name }}</p>" }`,
		"the subject":   `{ to: "a@example.com", subject: "Order ${{ params.order }}", text: "shipped" }`,
		"reply_to":      `{ to: "a@example.com", subject: "Hello", text: "hi", reply_to: "${{ params.reply }}" }`,
	} {
		rr, _ := runUnresolvedProbe(t, app, step(with), `{}`)
		requireUnresolvedFailure(t, name, rr)
		if len(sent) != 0 {
			t.Fatalf("%s: the message was sent before the step failed: subject %q text %q html %q", name, sent[0].Subject, sent[0].BodyText, sent[0].BodyHTML)
		}
	}
	// An optional List-Unsubscribe link that does not resolve only drops the
	// header, as before: the message is not lost with it.
	rr, _ := runUnresolvedProbe(t, app, step(`{ to: "a@example.com", subject: "Hello", text: "hi", unsubscribe_url: "${{ params.unsub }}" }`), `{}`)
	if rr.Code != http.StatusOK || len(sent) != 1 || sent[0].UnsubscribeURL != "" {
		t.Fatalf("an unresolved unsubscribe_url answered %d and sent %d message(s) %+v", rr.Code, len(sent), sent)
	}
	sent = nil
	rr, _ = runUnresolvedProbe(t, app, step(`{ to: "a@example.com", subject: "Hello", text: "Hi ${{ params.name }}" }`), `{"name":"Ada"}`)
	if rr.Code != http.StatusOK || len(sent) != 1 || sent[0].BodyText != "Hi Ada" {
		t.Fatalf("an email whose references resolve answered %d and sent %+v", rr.Code, sent)
	}
}

func TestSMSStepWithAnUnresolvedReferenceSendsNothing(t *testing.T) {
	app := newGateApp(t)
	var sent []string
	providerURL := testSMSWebhook(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var message struct {
			Body string `json:"body"`
		}
		_ = json.NewDecoder(r.Body).Decode(&message)
		sent = append(sent, message.Body)
		w.WriteHeader(http.StatusOK)
	}))
	SetAppEnv(app.Dir, "SMS_PROVIDER", "webhook")
	SetAppEnv(app.Dir, "SMS_WEBHOOK_URL", providerURL)
	step := func(to, body string) string {
		return "      - id: msg\n        run: sms\n        with: { to: " + to + ", body: " + body + " }\n"
	}
	for name, s := range map[string]string{
		"the body":      step(`"+15550100171"`, `"Hello ${{ params.missing }}"`),
		"the recipient": step(`"${{ params.nobody }}"`, `"hi"`),
	} {
		rr, _ := runUnresolvedProbe(t, app, s, `{}`)
		requireUnresolvedFailure(t, name, rr)
		if len(sent) != 0 {
			t.Fatalf("%s: a text went out before the step failed: %q", name, sent)
		}
	}
	rr, _ := runUnresolvedProbe(t, app, step(`"+15550100172"`, `"Hello ${{ params.name }}"`), `{"name":"Ada"}`)
	if rr.Code != http.StatusOK || len(sent) != 1 || sent[0] != "Hello Ada" {
		t.Fatalf("a text whose references resolve answered %d and sent %q", rr.Code, sent)
	}
}

// The legacy room message (`ws:` in a cron step or a legacy flow file).
func TestLegacyWSStepWithAnUnresolvedReferenceSendsNothing(t *testing.T) {
	resetWSHub(t)
	app := broadcastRoomApp(t)
	app.WSRooms = nil
	member := roomClient(app, realtimeAppID(app.Dir), 1, "", "lobby")
	registerWSClient(member)
	defer unregisterWSClient(member)
	ctx := &FlowContext{App: app, Data: map[string]any{"who": "Ada"}, Params: map[string]string{}}
	unresolved := &FlowStep{Type: "ws", WS: &FlowWS{Room: "lobby", Payload: `{"text":"hi {{nope.value}}"}`}}
	if err := executeStep(ctx, unresolved); err == nil || !strings.Contains(err.Error(), "unresolved template reference") {
		t.Fatalf("unresolved payload reference: err=%v", err)
	}
	if wsReceivedAny(member) {
		t.Fatal("room members received the message with the placeholder in it")
	}
	if err := executeStep(ctx, &FlowStep{Type: "ws", WS: &FlowWS{Room: "lobby", Payload: `{"text":"hi {{who}}"}`}}); err != nil || !wsReceivedAny(member) {
		t.Fatalf("a room message whose references resolve: err=%v", err)
	}
}

// These step types already checked before acting; the tests keep them there.
func TestStepsThatCheckedReferencesFirstStillDo(t *testing.T) {
	app := newGateApp(t, "CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)")
	EnsureNotificationsTable(app.DB)
	uid, _ := gateUser(t, app, "reader@example.com")
	for _, c := range []struct{ name, steps string }{
		{"notify", "      - run: notify\n        with: { user_id: \"" + valueText(uid) + "\", title: \"Hello ${{ params.name }}\" }\n"},
		{"sql_dynamic", "      - run: sql_dynamic\n        with:\n          query: \"INSERT INTO items (name) VALUES ('${{ steps.none.outputs.name }}')\"\n"},
		{"api", "      - run: api\n        with: { method: POST, url: \"https://example.com/hook\", json: { name: \"${{ params.name }}\" } }\n"},
		{"webhook", "      - run: webhook\n        with: { url: \"https://example.com/hook\", payload: { name: \"${{ params.name }}\" } }\n"},
	} {
		rr, outbound := runUnresolvedProbe(t, app, c.steps, `{}`)
		if rr.Code != http.StatusInternalServerError || len(outbound) != 0 {
			t.Fatalf("%s: answered %d and made %d outbound call(s): %s", c.name, rr.Code, len(outbound), rr.Body.String())
		}
	}
	if n := gateScalar(t, app, "SELECT (SELECT COUNT(*) FROM items) + (SELECT COUNT(*) FROM _benmore_notifications)"); n != "0" {
		t.Fatalf("a step that checks first wrote %s row(s)", n)
	}
}

// The hint an app admin reads names the cause, not the SQL engine or the mail
// provider's settings.
func TestUnresolvedReferenceHintSaysNothingHappened(t *testing.T) {
	err := unresolvedStepRefsError(&FlowStep{Name: "ins", Type: "sql"}, []string{"params.b"})
	for stepType, want := range map[string]string{
		"sql":     "the statement did not run and nothing was written",
		"email":   "nothing was sent",
		"sms":     "nothing was sent",
		"enqueue": "no job was queued",
	} {
		if hint := stepFailureHint("ins", stepType, err.Error()); !strings.Contains(hint, want) || !strings.Contains(hint, "default:''") {
			t.Errorf("%s hint does not say %q and how to give a fallback: %s", stepType, want, hint)
		}
	}
	if hint := stepFailureHint("ins", "sql", "sql: no such table: items"); strings.Contains(hint, "reference in the step had no value") {
		t.Errorf("another sql failure got the unresolved-reference hint: %s", hint)
	}
}
