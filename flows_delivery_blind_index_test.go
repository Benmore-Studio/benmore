//go:build !cli

package main

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The steps that send flow data out of the app (webhook, api, email, sms,
// broadcast, notify) leave out declared blind-index columns the way a
// response does. Each test hands the step whole rows of patients (ssn is
// blind-indexed) and reads what the receiver got.

const blindDeliveryHead = `on:
  request:
    method: POST
    path: /api/f
jobs:
  main:
    steps:
      - id: p
        run: sql
        with:
          query: "SELECT * FROM patients ORDER BY id"
`

// After the delivery step: the flow still reads and binds the blind value.
const blindDeliveryTail = `      - id: same
        run: sql
        with:
          query: "SELECT count(*) AS n FROM patients WHERE ssn_blind = :b"
          params:
            b: ${{ steps.p.outputs.first.ssn_blind }}
      - run: respond
        with:
          status: 200
          json:
            same: ${{ steps.same.outputs.first.n }}
`

// blindDeliveryApp is blindRespondApp with the framework tables the notify
// and enqueue steps write.
func blindDeliveryApp(t *testing.T) *App {
	t.Helper()
	app := blindRespondApp(t)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureNotificationsTable(app.DB)
	EnsureJobsTable(app.DB)
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email) VALUES (1, 'ada', 'ada@example.com')`)
	return app
}

// blindDeliveryRun runs head + steps + tail and returns the outbound requests
// the api and webhook steps made.
func blindDeliveryRun(t *testing.T, app *App, steps string) []stepValueSent {
	t.Helper()
	flow := parseExpectRowsFlow(t, app, blindDeliveryHead+steps+blindDeliveryTail)
	var sent []stepValueSent
	req := httptest.NewRequest(http.MethodPost, "/api/f", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	if err := executeFlowHTTPAsWithAPIClient(app, &flow, rr, req, nil, stepValueClient(&sent)); err != nil {
		t.Fatalf("flow error: %v", err)
	}
	// Both patients share an SSN: the step after the delivery bound the real
	// blind value, so the step outputs were not changed.
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"same":2`) {
		t.Fatalf("the flow after the delivery step: %d %s", rr.Code, rr.Body.String())
	}
	return sent
}

// blindDeliveryCheck fails when what was sent names or holds the blind index,
// or lost the other columns of the rows.
func blindDeliveryCheck(t *testing.T, what, sent, blind string) {
	t.Helper()
	if strings.Contains(sent, "ssn_blind") || strings.Contains(sent, blind) {
		t.Fatalf("%s carries the blind index: %s", what, sent)
	}
	if !strings.Contains(sent, "Ada") || !strings.Contains(sent, "111-22-3333") {
		t.Fatalf("%s lost the other columns: %s", what, sent)
	}
}

func TestFlowWebhookLeavesOutDeclaredBlindIndexColumns(t *testing.T) {
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	for name, step := range map[string]string{
		"payload": `      - run: webhook
        with:
          url: https://8.8.8.8/cb
          payload:
            rows: ${{ steps.p.outputs.rows }}
            nested:
              - patient: ${{ steps.p.outputs.first }}
            ssn_blind: ${{ steps.p.outputs.first.ssn_blind }}
`,
		"text body": `      - run: webhook
        with:
          url: https://8.8.8.8/cb
          body: '{"rows": ${{ steps.p.outputs.rows | json }}, "one": ${{ steps.p.outputs.first | json }}}'
`,
		"whole context": `      - run: webhook
        with:
          url: https://8.8.8.8/cb
`,
		"whole context in a loop": `      - id: named
        run: sql
        with:
          query: "SELECT id, ssn_blind FROM patients WHERE id = 1"
      - run: set
        with:
          ssn_blind: ${{ steps.p.outputs.first.ssn_blind }}
      - for_each: ${{ steps.named.outputs.rows }}
        as: row
        steps:
          - run: webhook
            with:
              url: https://8.8.8.8/cb
`,
	} {
		t.Run(name, func(t *testing.T) {
			sent := blindDeliveryRun(t, app, step)
			if len(sent) != 1 {
				t.Fatalf("sent %+v", sent)
			}
			blindDeliveryCheck(t, "webhook body", sent[0].body, blind)
			if !json.Valid([]byte(sent[0].body)) {
				t.Fatalf("webhook body is not JSON: %s", sent[0].body)
			}
		})
	}
}

func TestFlowAPILeavesOutDeclaredBlindIndexColumns(t *testing.T) {
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	for name, step := range map[string]string{
		"json object": `      - run: api
        with:
          url: https://8.8.8.8/in
          method: POST
          json:
            rows: ${{ steps.p.outputs.rows }}
            deep:
              - patient: ${{ steps.p.outputs.rows[1] }}
            first: ${{ steps.p.outputs.first }}
            ssn_blind: ${{ steps.p.outputs.first.ssn_blind }}
`,
		"json list": `      - run: api
        with:
          url: https://8.8.8.8/in
          method: POST
          json:
            - ${{ steps.p.outputs.rows }}
            - ${{ steps.p.outputs.first }}
`,
		"json reference": `      - run: api
        with:
          url: https://8.8.8.8/in
          method: POST
          json: ${{ steps.p.outputs.rows }}
`,
		"body reference": `      - run: api
        with:
          url: https://8.8.8.8/in
          method: POST
          body: ${{ steps.p.outputs }}
`,
		"text body": `      - run: api
        with:
          url: https://8.8.8.8/in
          method: POST
          body: '{"rows": ${{ steps.p.outputs.rows | json }}}'
`,
		"form": `      - run: api
        with:
          url: https://8.8.8.8/in
          method: POST
          form:
            row: ${{ steps.p.outputs.first | json }}
            ssn_blind: ${{ steps.p.outputs.first.ssn_blind }}
`,
		"query": `      - run: api
        with:
          url: https://8.8.8.8/in
          method: GET
          query:
            row: ${{ steps.p.outputs.first | json }}
            ssn_blind: ${{ steps.p.outputs.first.ssn_blind }}
`,
		"url": `      - run: api
        with:
          url: 'https://8.8.8.8/in?row=${{ steps.p.outputs.first | json }}'
          method: GET
`,
	} {
		t.Run(name, func(t *testing.T) {
			sent := blindDeliveryRun(t, app, step)
			if len(sent) != 1 {
				t.Fatalf("sent %+v", sent)
			}
			raw := sent[0].url + " " + sent[0].body
			decoded, err := neturl.QueryUnescape(raw)
			if err != nil {
				decoded = raw
			}
			blindDeliveryCheck(t, "api request", raw+" "+decoded, blind)
		})
	}
}

// A header and the stored response: the request header loses the key, and
// the upstream's answer is stored and judged as it arrived, a key named like
// a blind column included.
func TestFlowAPIBlindIndexHeaderAndStoredResponse(t *testing.T) {
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	flow := parseExpectRowsFlow(t, app, blindDeliveryHead+`      - id: call
        run: api
        with:
          url: https://8.8.8.8/in
          method: POST
          headers:
            X-Row: ${{ steps.p.outputs.first | json }}
          json:
            name: ${{ steps.p.outputs.first.name }}
          success_when: ${{ steps.call.outputs.json.match | json }} == '{"ssn_blind":"upstream"}'
      - run: respond
        with:
          status: 200
          json:
            token: ${{ steps.call.outputs.json.match.ssn_blind }}
`)
	var header string
	client := &http.Client{Transport: apiStatusRoundTripper(func(r *http.Request) (*http.Response, error) {
		header = r.Header.Get("X-Row")
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
			Body: io.NopCloser(strings.NewReader(`{"match":{"ssn_blind":"upstream"}}`)), Request: r}, nil
	})}
	req := httptest.NewRequest(http.MethodPost, "/api/f", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	if err := executeFlowHTTPAsWithAPIClient(app, &flow, rr, req, nil, client); err != nil {
		t.Fatalf("flow error: %v", err)
	}
	blindDeliveryCheck(t, "api header", header, blind)
	if rr.Code != 200 || !strings.Contains(rr.Body.String(), `"token":"upstream"`) {
		t.Fatalf("the stored response: %d %s", rr.Code, rr.Body.String())
	}
}

func TestFlowEmailLeavesOutDeclaredBlindIndexColumns(t *testing.T) {
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	if err := os.MkdirAll(filepath.Join(app.Dir, "emails"), 0o755); err != nil {
		t.Fatal(err)
	}
	template := "<ul>{{#p}}<li>{{name}} {{ssn}} [{{ssn_blind}}]</li>{{/p}}</ul><p>{{rows}}</p>"
	if err := os.WriteFile(filepath.Join(app.Dir, "emails", "roster.html"), []byte(template), 0o644); err != nil {
		t.Fatal(err)
	}
	flow := parseExpectRowsFlow(t, app, blindDeliveryHead+`      - run: email
        with:
          to: ops@example.com
          subject: 'Roster ${{ steps.p.outputs.first | json }}'
          html: '<pre>${{ steps.p.outputs.rows | json }}</pre>'
          text: 'rows ${{ steps.p.outputs.rows | json }}'
      - run: email
        with:
          to: ops@example.com
          subject: Roster
          template: roster
          data:
            rows: ${{ steps.p.outputs.rows | json }}
`)
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}, Writes: newFlowWriteLog()}
	executeSteps(ctx, flow.Steps[:1])
	if ctx.Error != nil {
		t.Fatal(ctx.Error)
	}
	inline, _, err := buildEmailOpts(ctx, &flow.Steps[1])
	if err != nil {
		t.Fatal(err)
	}
	blindDeliveryCheck(t, "email subject", inline.Subject, blind)
	blindDeliveryCheck(t, "email html", inline.BodyHTML, blind)
	blindDeliveryCheck(t, "email text", inline.BodyText, blind)
	templated, _, err := buildEmailOpts(ctx, &flow.Steps[2])
	if err != nil {
		t.Fatal(err)
	}
	blindDeliveryCheck(t, "email template", templated.BodyHTML, blind)
	if !strings.Contains(templated.BodyHTML, "<li>Bo 111-22-3333 []</li>") {
		t.Errorf("template rows: %s", templated.BodyHTML)
	}
	// The step outputs the messages were built from keep the value.
	if rows, _ := ctx.Data["p"].([]map[string]any); len(rows) != 2 || rows[0]["ssn_blind"] != blind {
		t.Errorf("the step's rows changed: %v", ctx.Data["p"])
	}
}

func TestFlowSMSLeavesOutDeclaredBlindIndexColumns(t *testing.T) {
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	got := make(chan string, 1)
	providerURL := testSMSWebhook(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		got <- string(raw)
		w.WriteHeader(200)
	}))
	SetAppEnv(app.Dir, "SMS_PROVIDER", "webhook")
	SetAppEnv(app.Dir, "SMS_WEBHOOK_URL", providerURL)
	blindDeliveryRun(t, app, `      - run: sms
        with:
          to: "+15550104477"
          body: 'Patient ${{ steps.p.outputs.first | json }}'
`)
	select {
	case body := <-got:
		blindDeliveryCheck(t, "sms", body, blind)
	default:
		t.Fatal("no sms was sent")
	}
}

func TestFlowBroadcastLeavesOutDeclaredBlindIndexColumns(t *testing.T) {
	resetWSHub(t)
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	member := roomClient(app, realtimeAppID(app.Dir), 1, "", "ward-1")
	registerWSClient(member)
	defer unregisterWSClient(member)
	blindDeliveryRun(t, app, `      - run: broadcast
        with:
          room: ward-1
          payload:
            rows: ${{ steps.p.outputs.rows }}
            note: 'first ${{ steps.p.outputs.first | json }}'
            ssn_blind: ${{ steps.p.outputs.first.ssn_blind }}
`)
	select {
	case frame := <-member.send:
		blindDeliveryCheck(t, "broadcast frame", string(frame), blind)
	default:
		t.Fatal("the room member received nothing")
	}
}

func TestFlowNotifyLeavesOutDeclaredBlindIndexColumns(t *testing.T) {
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	blindDeliveryRun(t, app, `      - run: notify
        with:
          user_id: 1
          title: 'Patient ${{ steps.p.outputs.first | json }}'
          body: 'rows ${{ steps.p.outputs.rows | json }}'
`)
	var title, body string
	if err := app.DB.QueryRow(`SELECT title, body FROM _benmore_notifications WHERE user_id = 1`).Scan(&title, &body); err != nil {
		t.Fatal(err)
	}
	blindDeliveryCheck(t, "notification title", title, blind)
	blindDeliveryCheck(t, "notification body", body, blind)
}

// `run: enqueue` stays inside the app: the job flow may need the value.
func TestFlowEnqueueKeepsBlindIndexColumns(t *testing.T) {
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	blindDeliveryRun(t, app, `      - run: enqueue
        with:
          flow: follow-up
          with:
            row: ${{ steps.p.outputs.first | json }}
            ssn_blind: ${{ steps.p.outputs.first.ssn_blind }}
`)
	var payload string
	if err := app.DB.QueryRow(`SELECT payload FROM _benmore_jobs WHERE flow_name = 'follow-up'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(payload), &got); err != nil {
		t.Fatalf("%v: %s", err, payload)
	}
	if got["ssn_blind"] != blind {
		t.Errorf("the job payload lost the blind value: %s", payload)
	}
	if row, _ := got["row"].(string); !strings.Contains(row, "ssn_blind") || !strings.Contains(row, blind) {
		t.Errorf("the queued row lost its blind column: %s", payload)
	}
}

// What the author chose is sent: a single value under another key, a blind
// value selected under another name, and a column that only ends in `_blind`.
// A key named like a declared blind column is not.
func TestFlowDeliveryBlindIndexAuthorChoices(t *testing.T) {
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	sent := blindDeliveryRun(t, app, `      - id: s
        run: sql
        with:
          query: "SELECT * FROM shades"
      - id: named
        run: sql
        with:
          query: "SELECT ssn_blind AS match_key, ssn_blind FROM patients WHERE id = 1"
      - run: webhook
        with:
          url: https://8.8.8.8/cb
          payload:
            shade: ${{ steps.s.outputs.first }}
            named: ${{ steps.named.outputs.first }}
            token: ${{ steps.named.outputs.first.ssn_blind }}
            ssn_blind: ${{ steps.named.outputs.first.ssn_blind }}
      - run: api
        with:
          url: https://8.8.8.8/in
          method: POST
          query:
            token: ${{ steps.named.outputs.first.ssn_blind }}
          form:
            token: ${{ steps.named.outputs.first.ssn_blind }}
`)
	if len(sent) != 2 {
		t.Fatalf("sent %+v", sent)
	}
	var got struct {
		Shade map[string]any `json:"shade"`
		Named map[string]any `json:"named"`
		Token string         `json:"token"`
		Blind *string        `json:"ssn_blind"`
	}
	if err := json.Unmarshal([]byte(sent[0].body), &got); err != nil {
		t.Fatalf("%v: %s", err, sent[0].body)
	}
	if got.Shade["color_blind"] != "deutan-safe" || got.Shade["label"] != "teal" {
		t.Errorf("an undeclared column ending in _blind was dropped: %v", got.Shade)
	}
	if got.Named["match_key"] != blind {
		t.Errorf("a blind value selected under another name was dropped: %v", got.Named)
	}
	if _, present := got.Named["ssn_blind"]; present {
		t.Errorf("the declared blind column stayed in the row: %v", got.Named)
	}
	if got.Token != blind {
		t.Errorf("a value referenced on its own under another key = %q, want the stored value", got.Token)
	}
	if got.Blind != nil {
		t.Errorf("the payload carries a key named like the declared blind column: %s", sent[0].body)
	}
	want := "token=" + neturl.QueryEscape(blind)
	if !strings.HasSuffix(sent[1].url, "?"+want) || sent[1].body != want {
		t.Errorf("api query/form under another key: url %s body %s, want %s", sent[1].url, sent[1].body, want)
	}
}

// An app with no blind index declared is untouched, whatever its keys are.
func TestFlowDeliveryWithoutBlindIndexUnchanged(t *testing.T) {
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"patients": {{Column: "ssn"}}}}
	sent := blindDeliveryRun(t, app, `      - run: webhook
        with:
          url: https://8.8.8.8/cb
          payload:
            rows: ${{ steps.p.outputs.rows }}
            ssn_blind: ${{ steps.p.outputs.first.ssn_blind }}
      - run: webhook
        with:
          url: https://8.8.8.8/cb
`)
	if len(sent) != 2 {
		t.Fatalf("sent %+v", sent)
	}
	for _, s := range sent {
		if !strings.Contains(s.body, `"ssn_blind":"`+blind+`"`) {
			t.Errorf("a column no blind index declares was dropped: %s", s.body)
		}
	}
}
