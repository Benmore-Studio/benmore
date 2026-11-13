//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	neturl "net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The senders the delivery steps left: a `ws:` step, `run: proxy`, a
// `redirect` target, a hooks.yaml delivery and a cron.yaml job's own steps.
// Each hands the sender whole rows of patients (ssn is blind-indexed) and
// reads what the receiver got.

// blindSenderReceiver points the strict outbound client at a local server
// and returns the bodies it received.
func blindSenderReceiver(t *testing.T) chan string {
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
	return got
}

func blindSenderReceived(t *testing.T, got chan string, what string) string {
	t.Helper()
	select {
	case body := <-got:
		return body
	case <-time.After(5 * time.Second):
		t.Fatalf("%s: nothing was received", what)
		return ""
	}
}

func blindSenderFrame(t *testing.T, member *wsClient, what string) string {
	t.Helper()
	select {
	case frame := <-member.send:
		return string(frame)
	default:
		t.Fatalf("%s: the room member received nothing", what)
		return ""
	}
}

// A cron.yaml job's own steps are the flow steps: its `webhook:` (with a
// body and with the whole context) and its `ws:` step leave the declared
// blind column out, and a later step of the job still binds it.
func TestCronInlineStepsLeaveOutDeclaredBlindIndexColumns(t *testing.T) {
	resetWSHub(t)
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	got := blindSenderReceiver(t)
	member := roomClient(app, realtimeAppID(app.Dir), 1, "", "ward-1")
	registerWSClient(member)
	defer unregisterWSClient(member)

	cron, err := parseCronYAML([]byte(`jobs:
  - id: roster
    schedule: "@hourly"
    run:
      - sql: "SELECT * FROM patients ORDER BY id"
        name: p
      - webhook: http://93.184.216.34/cb
        body: '{"rows": {{p | json}}}'
      - webhook: http://93.184.216.34/cb
      - ws:
          room: ward-1
          payload: '{"rows": {{p | json}}, "note": "first {{p.0.name}}"}'
      - sql: "INSERT INTO lookups (probe) SELECT 'cron:' || count(*) FROM patients WHERE ssn_blind = {{p.0.ssn_blind}}"
`))
	if err != nil {
		t.Fatal(err)
	}
	if err := runCronJob(app, cron.Jobs[0], nil); err != nil {
		t.Fatalf("cron job: %v", err)
	}
	blindDeliveryCheck(t, "cron webhook body", blindSenderReceived(t, got, "webhook with a body"), blind)
	blindDeliveryCheck(t, "cron webhook context", blindSenderReceived(t, got, "webhook with no body"), blind)
	frame := blindSenderFrame(t, member, "cron ws step")
	blindDeliveryCheck(t, "cron ws frame", frame, blind)
	if !json.Valid([]byte(frame)) {
		t.Fatalf("ws frame is not JSON: %s", frame)
	}
	// Both patients share an SSN: the step after the deliveries bound the
	// real blind value.
	var n int
	if err := app.DB.QueryRow(`SELECT count(*) FROM lookups WHERE probe = 'cron:2'`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("the job's later step did not bind the blind value: %d rows, %v", n, err)
	}
}

// A `ws:` step with no blind index declared sends what it always did.
func TestFlowWSStepWithoutBlindIndexUnchanged(t *testing.T) {
	resetWSHub(t)
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"patients": {{Column: "ssn"}}}}
	member := roomClient(app, realtimeAppID(app.Dir), 1, "", "ward-1")
	registerWSClient(member)
	defer unregisterWSClient(member)
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}, Writes: newFlowWriteLog()}
	executeSteps(ctx, []FlowStep{
		{Type: "sql", Name: "p", SQL: "SELECT * FROM patients ORDER BY id"},
		{Type: "ws", WS: &FlowWS{Room: "ward-1", Payload: `{"rows": {{p | json}}}`}},
	})
	if ctx.Error != nil {
		t.Fatal(ctx.Error)
	}
	if frame := blindSenderFrame(t, member, "ws step"); !strings.Contains(frame, `"ssn_blind":"`+blind+`"`) {
		t.Errorf("a column no blind index declares was dropped: %s", frame)
	}
}

// A proxy flow anonymous callers can run declares a rate limit.
var blindProxyHead = strings.Replace(blindDeliveryHead, "    path: /api/f\n", "    path: /api/f\n    rate_limit: 1000/min\n", 1)

// blindProxyRun runs sql + one proxy step and returns the request the
// upstream received.
func blindProxyRun(t *testing.T, app *App, with string) (sent stepValueSent, headers http.Header) {
	t.Helper()
	flow := parseExpectRowsFlow(t, app, blindProxyHead+`      - run: proxy
        with:
          content_types: [audio/mpeg]
`+with)
	calls := 0
	client := &http.Client{Transport: apiStatusRoundTripper(func(r *http.Request) (*http.Response, error) {
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
		}
		calls++
		sent, headers = stepValueSent{r.Method, r.URL.String(), r.Header.Get("Content-Type"), string(body)}, r.Header.Clone()
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"audio/mpeg"}},
			Body: io.NopCloser(strings.NewReader("ID3abc")), Request: r}, nil
	})}
	req := httptest.NewRequest(http.MethodPost, "/api/f", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	if err := executeFlowHTTPAsWithAPIClient(app, &flow, rr, req, nil, client); err != nil {
		t.Fatalf("flow error: %v", err)
	}
	if rr.Code != 200 || rr.Body.String() != "ID3abc" || calls != 1 {
		t.Fatalf("proxy answered %d %s after %d upstream calls", rr.Code, rr.Body.String(), calls)
	}
	return sent, headers
}

func TestFlowProxyLeavesOutDeclaredBlindIndexColumns(t *testing.T) {
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	for name, with := range map[string]string{
		"json object": `          url: https://8.8.8.8/in
          method: POST
          json:
            rows: ${{ steps.p.outputs.rows }}
            first: ${{ steps.p.outputs.first }}
            note: 'first ${{ steps.p.outputs.first | json }}'
            ssn_blind: ${{ steps.p.outputs.first.ssn_blind }}
`,
		"json reference": `          url: https://8.8.8.8/in
          method: POST
          json: ${{ steps.p.outputs.rows }}
`,
		"text body": `          url: https://8.8.8.8/in
          method: POST
          body: '{"rows": ${{ steps.p.outputs.rows | json }}}'
`,
		"url": `          url: 'https://8.8.8.8/in?row=${{ steps.p.outputs.first | json }}'
`,
	} {
		t.Run(name, func(t *testing.T) {
			sent, _ := blindProxyRun(t, app, with)
			raw := sent.url + " " + sent.body
			decoded, err := neturl.QueryUnescape(raw)
			if err != nil {
				decoded = raw
			}
			blindDeliveryCheck(t, "proxy request", raw+" "+decoded, blind)
		})
	}
	_, headers := blindProxyRun(t, app, `          url: https://8.8.8.8/in
          headers:
            X-Row: ${{ steps.p.outputs.first | json }}
            X-Token: ${{ steps.p.outputs.first.ssn_blind }}
`)
	blindDeliveryCheck(t, "proxy header", headers.Get("X-Row"), blind)
	// A single value the author sends under another name is sent.
	if token := headers.Get("X-Token"); token != blind {
		t.Errorf("a value referenced on its own under another header = %q, want the stored value", token)
	}
	// An app with no blind index declared is untouched.
	app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"patients": {{Column: "ssn"}}}}
	sent, _ := blindProxyRun(t, app, `          url: https://8.8.8.8/in
          method: POST
          json: ${{ steps.p.outputs.rows }}
`)
	if !strings.Contains(sent.body, `"ssn_blind":"`+blind+`"`) {
		t.Errorf("a column no blind index declares was dropped: %s", sent.body)
	}
}

// blindRedirectTarget runs sql + one redirect step and returns the Location.
func blindRedirectTarget(t *testing.T, app *App, to string) string {
	t.Helper()
	flow := parseExpectRowsFlow(t, app, blindDeliveryHead+`      - run: redirect
        with:
          to: `+to+"\n")
	req := httptest.NewRequest(http.MethodPost, "/api/f", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	if err := executeFlowHTTPAsWithAPIClient(app, &flow, rr, req, nil, nil); err != nil {
		t.Fatalf("flow error: %v", err)
	}
	if rr.Code != http.StatusSeeOther {
		t.Fatalf("redirect answered %d %s", rr.Code, rr.Body.String())
	}
	return rr.Header().Get("Location")
}

func TestFlowRedirectLeavesOutDeclaredBlindIndexColumns(t *testing.T) {
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	for name, tc := range map[string]struct{ to, want string }{
		"a query key named like the column": {
			`'/next?name=${{ steps.p.outputs.first.name }}&ssn_blind=${{ steps.p.outputs.first.ssn_blind }}&ssn=${{ steps.p.outputs.first.ssn }}'`,
			"/next?name=Ada&ssn=111-22-3333",
		},
		"the only query key": {
			`'/next/Ada/111-22-3333?SSN_Blind=${{ steps.p.outputs.first.ssn_blind }}#top'`,
			"/next/Ada/111-22-3333#top",
		},
		"the first of two": {
			`'/next?ssn_blind=${{ steps.p.outputs.first.ssn_blind }}&name=${{ steps.p.outputs.first.name }}&ssn=111-22-3333'`,
			"/next?name=Ada&ssn=111-22-3333",
		},
		"a row in the query": {
			`'/next?row=${{ steps.p.outputs.first | json | urlencode }}'`,
			"",
		},
	} {
		t.Run(name, func(t *testing.T) {
			target := blindRedirectTarget(t, app, tc.to)
			decoded, err := neturl.QueryUnescape(target)
			if err != nil {
				decoded = target
			}
			blindDeliveryCheck(t, "redirect target", target+" "+decoded, blind)
			if tc.want != "" && target != tc.want {
				t.Errorf("target = %s, want %s", target, tc.want)
			}
		})
	}
	// A single value under another key is the author's choice and is sent,
	// and every other part of the target is byte for byte what was written.
	target := blindRedirectTarget(t, app, `'/next?b=2&token=${{ steps.p.outputs.first.ssn_blind }}&a=1&a=%20x#ssn_blind=1'`)
	if want := "/next?b=2&token=" + blind + "&a=1&a=%20x#ssn_blind=1"; target != want {
		t.Errorf("target = %s, want %s", target, want)
	}
	// An app with no blind index declared is untouched.
	app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"patients": {{Column: "ssn"}}}}
	target = blindRedirectTarget(t, app, `'/next?ssn_blind=${{ steps.p.outputs.first.ssn_blind }}'`)
	if want := "/next?ssn_blind=" + blind; target != want {
		t.Errorf("no blind index declared: target = %s, want %s", target, want)
	}
}

// blindHookRow is the row an update event hands the hooks of patients: the
// row as stored (queryNativeRowsWith, as the write paths read it) with the
// old_ deltas.
func blindHookRow(t *testing.T, app *App, blind string) map[string]any {
	t.Helper()
	rows, err := queryNativeRowsWith(app.DB, app, "patients", "SELECT * FROM patients WHERE id = 1")
	if err != nil || len(rows) != 1 {
		t.Fatalf("event row: %v %v", rows, err)
	}
	row := rows[0]
	if row["ssn_blind"] != blind {
		t.Fatalf("the event row does not carry the blind column: %v", row)
	}
	row["old_ssn_blind"] = blind
	row["old_name"] = "Adah"
	return row
}

// A hooks.yaml delivery (webhook, email, sms, notify, ws) reads the event
// row without the declared blind column and its old_ delta, so a placeholder
// naming one is left as written, like any name the row does not have; hook
// SQL still binds it.
func TestHookDeliveriesLeaveOutDeclaredBlindIndexColumns(t *testing.T) {
	resetWSHub(t)
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	row := blindHookRow(t, app, blind)
	const refs = `{{name}} {{ssn}} was {{old_name}} [{{ssn_blind}}] [{{old_ssn_blind}}]`
	const rendered = `Ada 111-22-3333 was Adah [{{ssn_blind}}] [{{old_ssn_blind}}]`
	check := func(what, sent string) {
		t.Helper()
		if strings.Contains(sent, blind) {
			t.Fatalf("%s carries the blind index: %s", what, sent)
		}
		if !strings.Contains(sent, rendered) {
			t.Fatalf("%s = %s, want the other columns and the placeholders as written: %s", what, sent, rendered)
		}
	}

	got := blindSenderReceiver(t)
	if err := executeHookResult(app, Hook{Webhook: "http://93.184.216.34/hook", Body: `{"text": "` + refs + `", "ssn_blind": "{{ssn_blind}}"}`}, "patients", row); err != nil {
		t.Fatal(err)
	}
	check("hook webhook body", blindSenderReceived(t, got, "hook webhook body"))
	// The hook job as the worker runs it, with and without its table.
	for _, table := range []string{"patients", ""} {
		payload := hookJobPayload(Hook{Webhook: "http://93.184.216.34/hook"}, table, row)
		if table == "" {
			delete(payload["_hook"].(map[string]any), "table")
		}
		if err := roundTripHookJob(t, app, payload); err != nil {
			t.Fatal(err)
		}
		body := blindSenderReceived(t, got, "hook webhook default body")
		blindDeliveryCheck(t, "hook webhook default body (table "+table+")", body, blind)
		if !strings.Contains(body, `"old_name":"Adah"`) {
			t.Fatalf("hook webhook default body lost an ordinary old_ delta: %s", body)
		}
	}

	var mail []EmailOpts
	registerAppMailSender(app.Dir, func(opts EmailOpts) error {
		mail = append(mail, opts)
		return nil
	})
	t.Cleanup(func() { appMailSenders.Delete(filepath.Clean(app.Dir)) })
	if err := executeHookResult(app, Hook{Email: &EmailHook{To: "ops@example.com", Subject: refs, Body: "<p>" + refs + "</p>"}}, "patients", row); err != nil {
		t.Fatal(err)
	}
	if len(mail) != 1 {
		t.Fatalf("mail sent: %+v", mail)
	}
	check("hook email subject", mail[0].Subject)
	check("hook email body", mail[0].BodyHTML)

	sms := make(chan string, 1)
	providerURL := testSMSWebhook(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := io.ReadAll(r.Body)
		sms <- string(raw)
		w.WriteHeader(200)
	}))
	SetAppEnv(app.Dir, "SMS_PROVIDER", "webhook")
	SetAppEnv(app.Dir, "SMS_WEBHOOK_URL", providerURL)
	if err := executeHookResult(app, Hook{SMS: &SMSHook{To: "+15550104477", Body: refs}}, "patients", row); err != nil {
		t.Fatal(err)
	}
	check("hook sms", blindSenderReceived(t, sms, "hook sms"))

	if err := executeHookResult(app, Hook{Notify: &NotifyHook{UserID: "1", Title: refs, Body: refs, Link: "/p/{{id}}?k={{ssn_blind}}"}}, "patients", row); err != nil {
		t.Fatal(err)
	}
	var title, text, link string
	if err := app.DB.QueryRow(`SELECT title, body, link FROM _benmore_notifications WHERE user_id = 1`).Scan(&title, &text, &link); err != nil {
		t.Fatal(err)
	}
	check("hook notification title", title)
	check("hook notification body", text)
	if strings.Contains(link, blind) {
		t.Fatalf("hook notification link carries the blind index: %s", link)
	}

	member := roomClient(app, realtimeAppID(app.Dir), 1, "", "ward-1")
	registerWSClient(member)
	defer unregisterWSClient(member)
	if err := executeHookResult(app, Hook{WS: &WSHook{Room: "ward-1", Payload: `{"text": "` + refs + `"}`}}, "patients", row); err != nil {
		t.Fatal(err)
	}
	check("hook ws frame", blindSenderFrame(t, member, "hook ws"))

	// Hook SQL runs inside the app and binds the value as before; the row
	// the hook was handed is not changed.
	if err := executeHookResult(app, Hook{SQL: `INSERT INTO lookups (probe) VALUES ({{ssn_blind}})`}, "patients", row); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := app.DB.QueryRow(`SELECT count(*) FROM lookups WHERE probe = ?`, blind).Scan(&n); err != nil || n != 1 {
		t.Fatalf("hook SQL did not bind the blind value: %d rows, %v", n, err)
	}
	if row["ssn_blind"] != blind || row["old_ssn_blind"] != blind {
		t.Errorf("the delivery changed the hook's row: %v", row)
	}
}

// What a hook delivery keeps: a column that only ends in `_blind`, and every
// column of an app that declares no blind index.
func TestHookDeliveryBlindIndexAuthorChoices(t *testing.T) {
	resetWSHub(t)
	app := blindDeliveryApp(t)
	blind := blindRespondStored(t, app)
	member := roomClient(app, realtimeAppID(app.Dir), 1, "", "ward-1")
	registerWSClient(member)
	defer unregisterWSClient(member)

	shade := map[string]any{"id": 1, "label": "teal", "color_blind": "deutan-safe", "old_color_blind": "protan-safe"}
	if err := executeHookResult(app, Hook{WS: &WSHook{Room: "ward-1", Payload: `{"shade": "{{label}} {{color_blind}} {{old_color_blind}}"}`}}, "shades", shade); err != nil {
		t.Fatal(err)
	}
	if frame := blindSenderFrame(t, member, "hook ws"); !strings.Contains(frame, "teal deutan-safe protan-safe") {
		t.Errorf("an undeclared column ending in _blind was dropped: %s", frame)
	}

	row := blindHookRow(t, app, blind)
	app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"patients": {{Column: "ssn"}}}}
	if err := executeHookResult(app, Hook{WS: &WSHook{Room: "ward-1", Payload: `{"k": "{{ssn_blind}}"}`}}, "patients", row); err != nil {
		t.Fatal(err)
	}
	if frame := blindSenderFrame(t, member, "hook ws"); !strings.Contains(frame, blind) {
		t.Errorf("a column no blind index declares was dropped: %s", frame)
	}
}
