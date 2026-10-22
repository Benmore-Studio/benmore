//go:build !cli

package main

// Step values live apps write that the runtime used to drop, now honored:
// a webhook's `payload:` (and a `body:` written as a map or list), a
// templated or quoted respond `status:`, an api `body:` written as a map or
// list (and a `json:` list), respond `headers:` / `content_type:` through an
// allowlist, and an email's `unsubscribe_url`. Each test runs the authored
// YAML through the real loader, write gate and executor; outbound calls go
// through the per-run test client, so the private-address check still runs.

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
)

// stepValueSent is one outbound request a step made.
type stepValueSent struct {
	method, url, contentType, body string
}

// stepValueClient answers every request with 200 and records it.
func stepValueClient(sent *[]stepValueSent) *http.Client {
	var mu sync.Mutex
	return &http.Client{Transport: apiStatusRoundTripper(func(r *http.Request) (*http.Response, error) {
		var body []byte
		if r.Body != nil {
			body, _ = io.ReadAll(r.Body)
		}
		mu.Lock()
		*sent = append(*sent, stepValueSent{r.Method, r.URL.String(), r.Header.Get("Content-Type"), string(body)})
		mu.Unlock()
		return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"ok":true}`)), Request: r}, nil
	})}
}

// runStepValueFlow loads a flow file and runs it over HTTP (anonymous) with
// a query string. preset runs on the response headers first, standing in
// for middleware that writes before the flow (CORS).
func runStepValueFlow(t *testing.T, app *App, source, query string, preset func(http.Header)) (*httptest.ResponseRecorder, []stepValueSent, error) {
	t.Helper()
	flow := parseExpectRowsFlow(t, app, source)
	var sent []stepValueSent
	req := httptest.NewRequest(flow.Trigger.Method, flow.Trigger.Path+query, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	if preset != nil {
		preset(rr.Header())
	}
	err := executeFlowHTTPAsWithAPIClient(app, &flow, rr, req, nil, stepValueClient(&sent))
	return rr, sent, err
}

// responseValueFlow wraps fixtures that provide their own final response. Unlike
// expectRowsFlow, it must not append an unreachable fallback respond step.
func responseValueFlow(onRequest, steps string) string {
	return "on:\n  request:\n    method: POST\n    path: /api/probe\n" + onRequest +
		"jobs:\n  probe:\n    steps:\n" + steps
}

func jsonEqual(t *testing.T, got, want string) bool {
	t.Helper()
	var g, w any
	if err := json.Unmarshal([]byte(got), &g); err != nil {
		t.Errorf("not JSON: %q (%v)", got, err)
		return false
	}
	if err := json.Unmarshal([]byte(want), &w); err != nil {
		t.Fatalf("bad want %q: %v", want, err)
	}
	return reflect.DeepEqual(g, w)
}

// webhookPayloadStep is the notification apps' delivery callback, as live
// apps write it.
const webhookPayloadStep = `      - id: cb
        run: webhook
        with:
          url: ${{ params.callback_url }}
          payload:
            id: ${{ params.id }}
            channel: email
            to: ${{ params.to }}
            status: sent
            source: notify-hub
`

const webhookPayloadQuery = "?callback_url=https%3A%2F%2F8.8.8.8%2Fcb&id=7&to=a%40example.com"

// `with.payload` is the JSON body. It used to be dropped: with no body the
// step posted the whole flow context, which a non-admin caller naming the
// callback URL was refused.
func TestWebhookPayloadIsTheJSONBody(t *testing.T) {
	const want = `{"id":"7","channel":"email","to":"a@example.com","status":"sent","source":"notify-hub"}`
	source := stepKeyFlow(webhookPayloadStep)
	if msg := ValidateOnWrite("flows/probe.yaml", source); msg != "" {
		t.Fatalf("write gate refused the live shape: %s", msg)
	}
	app := secretTaintApp(t)
	rr, sent, err := runStepValueFlow(t, app, source, webhookPayloadQuery, nil)
	if err != nil || rr.Code != 200 {
		t.Fatalf("flow failed: %v (status %d)", err, rr.Code)
	}
	if len(sent) != 1 || sent[0].method != "POST" || sent[0].url != "https://8.8.8.8/cb" || sent[0].contentType != "application/json" {
		t.Fatalf("sent %+v, want one JSON POST to the callback", sent)
	}
	if !jsonEqual(t, sent[0].body, want) {
		t.Errorf("webhook body = %s, want %s", sent[0].body, want)
	}

	// An admin service account calling with a callback URL used to receive
	// the whole context; it now gets the payload it declared, nothing else.
	flow := parseExpectRowsFlow(t, app, source)
	var adminSent []stepValueSent
	ctx := &FlowContext{App: app, Session: &Session{UserID: 1, Role: "admin"},
		Data:        map[string]any{"callback_url": "https://8.8.8.8/cb", "id": "7", "to": "a@example.com", "internal_note": "not for the callback"},
		Params:      map[string]string{"callback_url": "https://8.8.8.8/cb", "id": "7", "to": "a@example.com"},
		RequestKeys: map[string]bool{"callback_url": true, "id": true, "to": true},
		apiClient:   stepValueClient(&adminSent)}
	if err := executeStep(ctx, &flow.Steps[0]); err != nil || len(adminSent) != 1 {
		t.Fatalf("admin call: err %v, sent %+v", err, adminSent)
	}
	if !jsonEqual(t, adminSent[0].body, want) {
		t.Errorf("admin webhook body = %s, want only the payload %s", adminSent[0].body, want)
	}

	// `body:` written as a map is the same body; a list payload is a JSON array.
	for name, c := range map[string]struct{ step, want string }{
		"body map":     {"      - run: webhook\n        with:\n          url: https://8.8.8.8/cb\n          body: { id: \"${{ params.id }}\", ok: true, tags: [a, b] }\n", `{"id":"7","ok":true,"tags":["a","b"]}`},
		"payload list": {"      - run: webhook\n        with:\n          url: https://8.8.8.8/cb\n          payload: [ { id: \"${{ params.id }}\" }, 2 ]\n", `[{"id":"7"},2]`},
	} {
		source := stepKeyFlow(c.step)
		if msg := ValidateOnWrite("flows/probe.yaml", source); msg != "" {
			t.Fatalf("%s: write gate: %s", name, msg)
		}
		_, sent, err := runStepValueFlow(t, app, source, webhookPayloadQuery, nil)
		if err != nil || len(sent) != 1 || !jsonEqual(t, sent[0].body, c.want) {
			t.Errorf("%s: err %v sent %+v, want body %s", name, err, sent, c.want)
		}
	}
}

// A payload value that does not resolve stops the step before anything is
// sent, and a payload carrying a secret may not go to a request-chosen host.
func TestWebhookPayloadRefusals(t *testing.T) {
	app := secretTaintApp(t)
	cases := map[string]struct{ steps, query, want string }{
		"unresolved value": {
			"      - run: webhook\n        with:\n          url: https://8.8.8.8/cb\n          payload: { id: \"${{ steps.nope.outputs.id }}\" }\n",
			"", "nothing was sent",
		},
		"env value to a request-chosen host": {
			"      - run: webhook\n        with:\n          url: ${{ params.callback_url }}\n          payload: { key: \"${{ env.CLIENT_SECRET }}\" }\n",
			webhookPayloadQuery, "may not choose the scheme or host",
		},
		"env-derived value to a request-chosen host": {
			"      - id: tok\n        query: \"SELECT :s AS token\"\n        params: { s: \"${{ env.CLIENT_SECRET }}\" }\n" +
				"      - run: webhook\n        with:\n          url: ${{ params.callback_url }}\n          payload: [ \"${{ steps.tok.outputs.first.token }}\" ]\n",
			webhookPayloadQuery, "may not choose the scheme or host",
		},
	}
	for name, c := range cases {
		rr, sent, err := runStepValueFlow(t, app, stepKeyFlow(c.steps), c.query, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: flow error = %v, want %q", name, err, c.want)
		}
		if len(sent) != 0 || rr.Code != 500 {
			t.Errorf("%s: status %d, sent %+v; want 500 and nothing sent", name, rr.Code, sent)
		}
	}
}

// A text `body:` is sent as it always was, and a fixed URL with no body
// still posts the context.
func TestWebhookTextBodyUnchanged(t *testing.T) {
	app := secretTaintApp(t)
	_, sent, err := runStepValueFlow(t, app, stepKeyFlow("      - run: webhook\n        with:\n          url: https://8.8.8.8/cb\n          body: '{\"id\": \"${{ params.id }}\", \"kind\": \"text\"}'\n"), "?id=7", nil)
	if err != nil || len(sent) != 1 || sent[0].body != `{"id": "7", "kind": "text"}` {
		t.Fatalf("text body: err %v sent %+v", err, sent)
	}
	_, sent, err = runStepValueFlow(t, app, stepKeyFlow("      - run: webhook\n        with: { url: \"https://8.8.8.8/cb\" }\n"), "?id=7", nil)
	if err != nil || len(sent) != 1 || !strings.Contains(sent[0].body, `"id":"7"`) {
		t.Fatalf("no body: err %v sent %+v, want the context", err, sent)
	}
}

// Two bodies, or a payload that is not a map or list, are refused when the
// file is written; a deployed file keeps sending its text body.
func TestWebhookPayloadWriteGate(t *testing.T) {
	both := stepKeyFlow("      - id: cb\n        run: webhook\n        with:\n          url: https://8.8.8.8/cb\n          body: '{\"text\": true}'\n          payload: { ok: true }\n")
	for source, want := range map[string]string{
		both: "step steps[0] (\"cb\"): `with.body` and `with.payload` are both set",
		stepKeyFlow("      - run: webhook\n        with: { url: \"https://8.8.8.8/cb\", payload: \"ok\" }\n"): "`with.payload` is the JSON body and must be a map or a list",
	} {
		if msg := ValidateOnWrite("flows/probe.yaml", source); !strings.Contains(msg, want) {
			t.Errorf("write gate said %q, want %q", msg, want)
		}
	}
	flows, logged, err := captureFlowLoad("flows/deployed.yaml", both)
	if err != nil || len(flows) != 1 {
		t.Fatalf("deployed file does not load: %v", err)
	}
	if !strings.Contains(logged, "WARNING: flows/deployed.yaml: flows.yaml: job \"probe\" step steps[0] (\"cb\"): `with.body` and `with.payload` are both set") {
		t.Errorf("loader log does not name the second body:\n%s", logged)
	}
	if step := flows[0].Steps[0]; step.WebhookBody != `{"text": true}` || step.WebhookJSON != nil {
		t.Errorf("deployed step loaded body %q json %v, want the text body only", step.WebhookBody, step.WebhookJSON)
	}
}

// A templated or quoted status is rendered; an integer 200-599 is the
// status, anything else fails the step. It used to be sent as 200.
func TestRespondStatusTemplateIsTheStatus(t *testing.T) {
	respond := func(status string) string {
		return "      - id: calc\n        query: \"SELECT :s AS status\"\n        params: { s: \"${{ params.s | default:'402' }}\" }\n" +
			"      - id: err\n        run: respond\n        with:\n          status: " + status + "\n          json: { error: payment_required }\n"
	}
	for name, c := range map[string]struct {
		status, query string
		code          int
	}{
		"template":                 {"${{ steps.calc.outputs.first.status }}", "", 402},
		"template from a set step": {"${{ calc.status }}", "", 402},
		"quoted number":            {`"404"`, "", 404},
		"integer":                  {"201", "", 201},
	} {
		steps := respond(c.status)
		if name == "template from a set step" {
			// mylogacy-api's shape: a step named calc whose output has status.
			steps = "      - id: calc\n        run: set\n        with: { status: \"402\" }\n" +
				"      - id: err\n        run: respond\n        with:\n          status: ${{ calc.status }}\n          json: { error: payment_required }\n"
		}
		source := responseValueFlow("", steps)
		if msg := ValidateOnWrite("flows/probe.yaml", source); msg != "" {
			t.Fatalf("%s: write gate: %s", name, msg)
		}
		app := expectRowsApp(t)
		rr, _, err := runStepValueFlow(t, app, source, c.query, nil)
		if err != nil || rr.Code != c.code || !strings.Contains(rr.Body.String(), `"error":"payment_required"`) {
			t.Errorf("%s: status %d body %s err %v, want %d", name, rr.Code, rr.Body.String(), err, c.code)
		}
	}

	// A status that renders to anything but an integer 200-599 fails loudly.
	// 1xx is informational in HTTP: Go would send it ahead of an implicit 200
	// and the router answers 101 with a 502, so a flow cannot choose one.
	for query, rendered := range map[string]string{"?s=abc": "abc", "?s=700": "700", "?s=99": "99", "?s=101": "101", "?s=199": "199", "?s=404.5": "404.5", "": ""} {
		steps := respond("${{ steps.calc.outputs.first.status }}")
		if query == "" {
			// A value that renders to nothing (a NULL column).
			steps = "      - id: calc\n        query: \"SELECT NULL AS status\"\n" +
				"      - run: respond\n        with: { status: \"${{ steps.calc.outputs.first.status }}\", json: { error: payment_required } }\n"
		}
		app := expectRowsApp(t)
		rr, _, err := runStepValueFlow(t, app, responseValueFlow("", steps), query, nil)
		want := `respond status rendered to "` + rendered + `", want 200-599`
		if err == nil || !strings.Contains(err.Error(), want) || rr.Code != 500 || strings.Contains(rr.Body.String(), "payment_required") {
			t.Errorf("%s: status %d body %s err %v, want a 500 and %q", query, rr.Code, rr.Body.String(), err, want)
		}
	}
	// A reference with no value answers template_unresolved.
	app := expectRowsApp(t)
	rr, _, _ := runStepValueFlow(t, app, responseValueFlow("", "      - run: respond\n        with: { status: \"${{ steps.nope.outputs.status }}\", json: { ok: true } }\n"), "", nil)
	if rr.Code != 500 || !strings.Contains(rr.Body.String(), "template_unresolved") {
		t.Errorf("unresolved status: %d %s", rr.Code, rr.Body.String())
	}
	// No status is 200, as before.
	rr, _, err := runStepValueFlow(t, app, responseValueFlow("", "      - run: respond\n        with: { json: { ok: true } }\n"), "", nil)
	if err != nil || rr.Code != 200 {
		t.Errorf("no status: %d %v", rr.Code, err)
	}

	// The write gate refuses a literal that is not a status.
	for status, want := range map[string]string{
		"ok":   "`with.status` is \"ok\", which is not an HTTP status",
		"101":  "`with.status` is \"101\"",
		"700":  "`with.status` is \"700\"",
		"true": "`with.status` is \"true\"",
	} {
		msg := ValidateOnWrite("flows/probe.yaml", responseValueFlow("", "      - run: respond\n        with: { status: "+status+", json: { ok: true } }\n"))
		if !strings.Contains(msg, want) {
			t.Errorf("status %s: write gate said %q, want %q", status, msg, want)
		}
	}
}

// `with.body` written as a map or list, and `with.json` written as a list,
// are sent as JSON. They used to send no body at all.
func TestAPIBodyMapIsSentAsJSON(t *testing.T) {
	app := secretTaintApp(t)
	for name, c := range map[string]struct{ with, wantBody, wantType string }{
		"body map (kixie)": {
			"body:\n            apikey: k-123\n            email: ${{ params.email }}\n            eventname: lead\n            tags: [a, b]\n",
			`{"apikey":"k-123","email":"a@example.com","eventname":"lead","tags":["a","b"]}`, "application/json",
		},
		"body list":  {"body: [ { email: \"${{ params.email }}\" } ]\n", `[{"email":"a@example.com"}]`, "application/json"},
		"json list":  {"json: [ \"${{ params.email }}\", 2 ]\n", `["a@example.com",2]`, "application/json"},
		"empty body": {"body: {}\n", `{}`, "application/json"},
		"declared content type": {
			"headers: { Content-Type: application/vnd.api+json }\n          body: { email: \"${{ params.email }}\" }\n",
			`{"email":"a@example.com"}`, "application/vnd.api+json",
		},
	} {
		source := stepKeyFlow("      - id: push\n        run: api\n        with:\n          method: POST\n          url: https://8.8.8.8/leads\n          " + c.with)
		if msg := ValidateOnWrite("flows/probe.yaml", source); msg != "" {
			t.Fatalf("%s: write gate: %s", name, msg)
		}
		_, sent, err := runStepValueFlow(t, app, source, "?email=a%40example.com", nil)
		if err != nil || len(sent) != 1 || sent[0].contentType != c.wantType || !jsonEqual(t, sent[0].body, c.wantBody) {
			t.Errorf("%s: err %v sent %+v, want %s %s", name, err, sent, c.wantType, c.wantBody)
		}
	}

	// A text body is sent as written, as before.
	_, sent, err := runStepValueFlow(t, app, stepKeyFlow("      - run: api\n        with: { method: POST, url: \"https://8.8.8.8/raw\", body: \"e=${{ params.email }}\" }\n"), "?email=x", nil)
	if err != nil || len(sent) != 1 || sent[0].body != "e=x" {
		t.Errorf("text body: err %v sent %+v", err, sent)
	}

	// A list body counts toward the secret checks: an env value in it may
	// not go to a request-chosen host.
	rr, sent, err := runStepValueFlow(t, app, stepKeyFlow("      - run: api\n        with: { method: POST, url: \"${{ params.target }}\", json: [ \"${{ env.CLIENT_SECRET }}\" ] }\n"), "?target=https%3A%2F%2F8.8.8.8%2Fx", nil)
	if err == nil || !strings.Contains(err.Error(), "may not choose the scheme or host") || len(sent) != 0 || rr.Code != 500 {
		t.Errorf("secret list body to a request-chosen host: err %v sent %+v", err, sent)
	}

	// A map body next to json or form is refused; a deployed file keeps
	// sending the json or form body.
	for other, want := range map[string]string{
		"json: { a: 1 }":     "`with.body` written as a map or list is a JSON body, and the step also sets `with.json`",
		"form: { a: \"1\" }": "`with.body` written as a map or list is a JSON body, and the step also sets `with.form`",
	} {
		source := stepKeyFlow("      - run: api\n        with:\n          method: POST\n          url: https://8.8.8.8/x\n          body: { b: 2 }\n          " + other + "\n")
		if msg := ValidateOnWrite("flows/probe.yaml", source); !strings.Contains(msg, want) {
			t.Errorf("write gate said %q, want %q", msg, want)
		}
		_, sent, err := runStepValueFlow(t, app, source, "", nil)
		if err != nil || len(sent) != 1 || strings.Contains(sent[0].body, `"b"`) {
			t.Errorf("deployed %s: err %v sent %+v, want the %s body", other, err, sent, other)
		}
	}
}

// The live respond shapes: a CSV download (headers and content_type), a
// cache directive, and a JSON content type on a JSON text body. Each was
// accepted and dropped: the CSV went out as application/json holding a JSON
// string, with no download name.
func TestRespondHeadersAndContentTypeAreSent(t *testing.T) {
	const csvStep = "      - id: csv\n        query: \"SELECT 'name,email' || char(10) || 'Ann,ann@example.com' AS text\"\n"
	cases := map[string]struct {
		steps                string
		wantType, wantBody   string
		wantHeaders          map[string]string
		wantJSONBody         bool
		presetVary, wantVary []string
	}{
		"csv export (headers)": {
			steps:    csvStep + "      - run: respond\n        with:\n          status: 200\n          headers:\n            Content-Type: \"text/csv; charset=utf-8\"\n            Content-Disposition: 'attachment; filename=\"waitlist.csv\"'\n          body: ${{ steps.csv.outputs.first.text }}\n",
			wantType: "text/csv; charset=utf-8", wantBody: "name,email\nAnn,ann@example.com",
			wantHeaders: map[string]string{"Content-Disposition": `attachment; filename="waitlist.csv"`},
		},
		"content_type key on a text template": {
			steps:    csvStep + "      - run: respond\n        with:\n          content_type: application/EDI-X12\n          body: \"ISA*00*${{ steps.csv.outputs.first.text }}~\"\n",
			wantType: "application/EDI-X12", wantBody: "ISA*00*name,email\nAnn,ann@example.com~",
		},
		"cache control on a json body": {
			steps:    "      - run: respond\n        with:\n          status: 200\n          headers: { Cache-Control: \"private, no-store\" }\n          json: { ok: true }\n",
			wantType: "application/json", wantBody: `{"ok":true}`, wantJSONBody: true,
			wantHeaders: map[string]string{"Cache-Control": "private, no-store"},
		},
		"json type on a json text value": {
			steps:    "      - id: rows\n        query: \"SELECT json_array(1, 2) AS doc\"\n      - run: respond\n        with:\n          headers: { content-type: application/json }\n          body: ${{ steps.rows.outputs.first.doc }}\n",
			wantType: "application/json", wantBody: "[1,2]",
		},
		"templated values, Vary added to the framework's": {
			steps:    "      - id: n\n        query: \"SELECT 3 AS n, 'report' AS name\"\n      - run: respond\n        with:\n          headers:\n            X-Total-Count: ${{ steps.n.outputs.first.n }}\n            Content-Disposition: 'inline; filename=\"${{ steps.n.outputs.first.name }}.txt\"'\n            Vary: Accept-Language\n            ETag: '\"v3\"'\n          body: \"three\"\n",
			wantType: "text/plain; charset=utf-8", wantBody: "three",
			wantHeaders: map[string]string{"X-Total-Count": "3", "Content-Disposition": `inline; filename="report.txt"`, "Etag": `"v3"`},
			presetVary:  []string{"Origin"}, wantVary: []string{"Origin", "Accept-Language"},
		},
	}
	for name, c := range cases {
		for _, transactional := range []bool{false, true} {
			onRequest := ""
			if transactional {
				onRequest = "    transaction: true\n"
			}
			source := responseValueFlow(onRequest, c.steps)
			if msg := ValidateOnWrite("flows/probe.yaml", source); msg != "" {
				t.Fatalf("%s: write gate: %s", name, msg)
			}
			app := expectRowsApp(t)
			rr, _, err := runStepValueFlow(t, app, source, "", func(h http.Header) {
				for _, v := range c.presetVary {
					h.Add("Vary", v)
				}
			})
			label := name
			if transactional {
				label += " (transaction)"
			}
			if err != nil || rr.Code != 200 || rr.Header().Get("Content-Type") != c.wantType {
				t.Errorf("%s: status %d type %q err %v", label, rr.Code, rr.Header().Get("Content-Type"), err)
				continue
			}
			if got := strings.TrimSpace(rr.Body.String()); c.wantJSONBody && !jsonEqual(t, got, c.wantBody) || !c.wantJSONBody && got != c.wantBody {
				t.Errorf("%s: body %q, want %q", label, rr.Body.String(), c.wantBody)
			}
			for header, want := range c.wantHeaders {
				if got := rr.Header().Get(header); got != want {
					t.Errorf("%s: %s = %q, want %q", label, header, got, want)
				}
			}
			if c.wantVary != nil && !slices.Equal(rr.Header().Values("Vary"), c.wantVary) {
				t.Errorf("%s: Vary = %v, want %v", label, rr.Header().Values("Vary"), c.wantVary)
			}
		}
	}
}

// A rendered value that could not be sent fails the step before anything
// is written: a line break (header injection), a broken download name, and
// a list body under a text content type.
func TestRespondHeaderValuesThatCannotBeSent(t *testing.T) {
	cases := map[string]struct{ steps, query, want string }{
		"line break in a value": {
			"      - run: respond\n        with:\n          headers: { X-Note: \"${{ params.note }}\" }\n          body: ok\n",
			"?note=a%0d%0aSet-Cookie:%20sid=1", "respond header X-Note holds a line break",
		},
		"quote in a download name": {
			"      - run: respond\n        with:\n          headers: { Content-Disposition: 'attachment; filename=\"${{ params.name }}\"' }\n          body: ok\n",
			"?name=a%22%3B%20filename%3Devil.exe", "respond header Content-Disposition must be `attachment` or `inline`",
		},
		"a list under a text type": {
			"      - id: rows\n        query: \"SELECT 1 AS id UNION ALL SELECT 2\"\n      - run: respond\n        with:\n          content_type: text/csv\n          body: ${{ steps.rows.outputs.rows }}\n",
			"", "which is not text",
		},
	}
	for name, c := range cases {
		app := expectRowsApp(t)
		rr, _, err := runStepValueFlow(t, app, responseValueFlow("", c.steps), c.query, nil)
		if err == nil || !strings.Contains(err.Error(), c.want) || rr.Code != 500 {
			t.Errorf("%s: status %d err %v, want 500 and %q", name, rr.Code, err, c.want)
		}
		for _, h := range []string{"X-Note", "Set-Cookie", "Content-Disposition"} {
			if rr.Header().Get(h) != "" {
				t.Errorf("%s: %s was sent: %q", name, h, rr.Header().Get(h))
			}
		}
	}
}

// Headers outside the allowlist are refused when the file is written; a
// deployed file loads, logs each one, and answers without it.
func TestRespondHeaderAllowlist(t *testing.T) {
	refused := map[string]string{
		"Set-Cookie":                  "a flow response may not set cookies",
		"Content-Security-Policy":     "the Content-Security-Policy is the framework's",
		"Access-Control-Allow-Origin": "CORS is configured for the whole app",
		"Location":                    "redirect with a `run: redirect` step",
		"Refresh":                     "redirect with a `run: redirect` step",
		"Strict-Transport-Security":   "HSTS is set by the platform",
		"Content-Length":              "the server writes the message framing itself",
		"Transfer-Encoding":           "the server writes the message framing itself",
		"Connection":                  "the server writes the message framing itself",
		"X-Frame-Options":             "the framework or the router sets or reads it",
		"X-Content-Type-Options":      "the framework or the router sets or reads it",
		"X-Request-Id":                "the framework or the router sets or reads it",
		"X-Real-IP":                   "the framework or the router sets or reads it",
		"X-Benmore-App":               "X-Benmore-* headers are the framework's",
		"X-Forwarded-For":             "X-Forwarded-* headers are the framework's",
		"X-Accel-Redirect":            "X-Accel-* headers are the framework's",
		"Referrer-Policy":             "is not a header a respond step may set",
		"Server":                      "is not a header a respond step may set",
	}
	var headers strings.Builder
	for name := range refused {
		headers.WriteString("            " + name + ": x\n")
	}
	headers.WriteString("            X-Report: yes\n")
	source := responseValueFlow("", "      - run: respond\n        with:\n          headers:\n"+headers.String()+"          body: ok\n")
	msg := ValidateOnWrite("flows/probe.yaml", source)
	for name, want := range refused {
		if !strings.Contains(msg, "`with.headers` \""+name+"\" "+want) && !strings.Contains(msg, "`with.headers` \""+name+"\" is refused: "+want) {
			t.Errorf("write gate does not refuse %s with %q:\n%s", name, want, msg)
		}
	}
	if strings.Contains(msg, "X-Report") {
		t.Errorf("write gate refused an allowed X- header:\n%s", msg)
	}

	flows, logged, err := captureFlowLoad("flows/deployed.yaml", source)
	if err != nil || len(flows) != 1 {
		t.Fatalf("deployed file does not load: %v", err)
	}
	for name := range refused {
		if !strings.Contains(logged, "WARNING: flows/deployed.yaml: flows.yaml: job \"probe\" step steps[0]: `with.headers` \""+name+"\"") {
			t.Errorf("loader log does not name %s", name)
		}
	}
	app := expectRowsApp(t)
	rr, _, err := runStepValueFlow(t, app, source, "", nil)
	if err != nil || rr.Code != 200 || rr.Header().Get("X-Report") != "yes" {
		t.Fatalf("deployed respond: %d %v %v", rr.Code, err, rr.Header())
	}
	for name := range refused {
		if got := rr.Header().Get(name); got == "x" {
			t.Errorf("refused header %s was sent", name)
		}
	}
}

// The other value rules: Content-Type and Cache-Control are literal, a
// shared-cache directive is refused where only signed-in callers reach the
// flow, the content type is written once, and a map body keeps a JSON type.
func TestRespondHeaderValueRules(t *testing.T) {
	respond := func(with string) string {
		return responseValueFlow("", "      - run: respond\n        with:\n"+with)
	}
	signedIn := func(with string) string {
		return responseValueFlow("    auth: required\n", "      - run: respond\n        with:\n"+with)
	}
	cases := map[string]struct{ source, want string }{
		"templated content type": {respond("          content_type: \"${{ params.type }}\"\n          body: ok\n"), "`with.content_type` must be literal text, not a template"},
		"templated Content-Type": {respond("          headers: { Content-Type: \"${{ params.type }}\" }\n          body: ok\n"), "`with.headers` \"Content-Type\" must be literal text, not a template"},
		"not a media type":       {respond("          content_type: csv\n          body: ok\n"), "`with.content_type` is not a media type"},
		"event stream":           {respond("          content_type: text/event-stream\n          body: ok\n"), "the router holds event streams open"},
		"templated Cache-Control": {respond("          headers: { Cache-Control: \"max-age=${{ params.ttl }}\" }\n          body: ok\n"),
			"`with.headers` \"Cache-Control\" must be literal text"},
		"public cache, signed in": {signedIn("          headers: { Cache-Control: \"public, max-age=3600\" }\n          body: ok\n"), "lets a shared cache (a CDN or proxy) store the response"},
		"s-maxage, signed in":     {signedIn("          headers: { Cache-Control: \"private, s-maxage=60\" }\n          body: ok\n"), "lets a shared cache"},
		"content type twice":      {respond("          content_type: text/csv\n          headers: { Content-Type: text/plain }\n          body: ok\n"), "and `with.content_type` both set the content type"},
		"map body, text type":     {respond("          content_type: text/csv\n          json: { a: 1 }\n"), "the content type is \"text/csv\", but `with.json` is a map or list"},
		"bad disposition":         {respond("          headers: { Content-Disposition: \"attachment; filename=a.csv\" }\n          body: ok\n"), "must be `attachment` or `inline`"},
		"headers not a map":       {respond("          headers: [ X-A ]\n          body: ok\n"), "`with.headers` must be a map"},
		"list header value":       {respond("          headers: { X-A: [1, 2] }\n          body: ok\n"), "must have one text value"},
		"same header twice":       {respond("          headers: { X-A: \"1\", x-a: \"2\" }\n          body: ok\n"), "names the same header as"},
	}
	for name, c := range cases {
		if msg := ValidateOnWrite("flows/probe.yaml", c.source); !strings.Contains(msg, c.want) {
			t.Errorf("%s: write gate said %q, want %q", name, msg, c.want)
		}
	}
	// A public flow may let shared caches store its answer.
	if msg := ValidateOnWrite("flows/probe.yaml", respond("          headers: { Cache-Control: \"public, max-age=60\" }\n          body: ok\n")); msg != "" {
		t.Errorf("public cache on a public flow refused: %s", msg)
	}

	// Deployed files: the refused value is dropped and the response is what
	// it was before.
	app := expectRowsApp(t)
	rr, _, err := runStepValueFlow(t, app, respond("          content_type: \"${{ params.type }}\"\n          body: plain words\n"), "?type=text%2Fhtml", nil)
	if err != nil || rr.Header().Get("Content-Type") != "text/plain; charset=utf-8" {
		t.Errorf("templated content type was used: %v %q", err, rr.Header().Get("Content-Type"))
	}
	rr, _, err = runStepValueFlow(t, app, respond("          content_type: text/csv\n          json: { a: 1 }\n"), "", nil)
	if err != nil || rr.Header().Get("Content-Type") != "application/json" {
		t.Errorf("map body with a text type: %v %q, want application/json", err, rr.Header().Get("Content-Type"))
	}
	flow := parseExpectRowsFlow(t, app, signedIn("          headers: { Cache-Control: \"public, max-age=3600\", X-Kept: yes }\n          body: ok\n"))
	if got := flow.Steps[0].Respond.Headers; len(got) != 1 || got[0].Name != "X-Kept" {
		t.Errorf("signed-in flow kept headers %+v, want the public Cache-Control dropped", got)
	}
}

// A respond step without headers or a content type answers as before.
func TestRespondWithoutHeadersUnchanged(t *testing.T) {
	for name, c := range map[string]struct{ with, wantType, wantBody string }{
		"text template":   {"body: \"${{ params.q }} not found\"", "text/plain; charset=utf-8", "<b> not found"},
		"map body":        {"json: { ok: true }", "application/json", "{\"ok\":true}\n"},
		"bare ref string": {"body: \"${{ params.q }}\"", "application/json", "\"\\u003cb\\u003e\"\n"},
	} {
		app := expectRowsApp(t)
		rr, _, err := runStepValueFlow(t, app, responseValueFlow("", "      - run: respond\n        with: { status: 202, "+c.with+" }\n"), "?q=%3Cb%3E", nil)
		if err != nil || rr.Code != 202 || rr.Header().Get("Content-Type") != c.wantType || rr.Body.String() != c.wantBody {
			t.Errorf("%s: %d %q %q err %v", name, rr.Code, rr.Header().Get("Content-Type"), rr.Body.String(), err)
		}
	}
}

// `with.unsubscribe_url` becomes the List-Unsubscribe target. It used to be
// accepted and never read. The one-click POST header is not asked for.
func TestEmailUnsubscribeURLIsSent(t *testing.T) {
	sends := fakeEmailGateway(t)
	email := func(unsubscribe string) string {
		return stepKeyFlow("      - run: email\n        with:\n          to: ${{ params.to }}\n          subject: Weekly digest\n          text: hello\n          unsubscribe_url: " + unsubscribe + "\n")
	}
	for name, c := range map[string]struct{ unsubscribe, want string }{
		"template":              {"\"https://app.example.com/api/email-unsubscribe?e=${{ params.to | urlencode }}\"", "https://app.example.com/api/email-unsubscribe?e=a%40example.com"},
		"literal":               {"https://www.example.com/unsubscribe", "https://www.example.com/unsubscribe"},
		"caller-supplied":       {"\"${{ params.unsubscribe_url | default:'' }}\"", ""},
		"caller-supplied, set ": {"\"${{ params.u | default:'' }}\"", "https://hub.example.com/u/9"},
	} {
		source := email(c.unsubscribe)
		if msg := ValidateOnWrite("flows/probe.yaml", source); msg != "" {
			t.Fatalf("%s: write gate: %s", name, msg)
		}
		before := len(sends())
		app := expectRowsApp(t)
		rr, _, err := runStepValueFlow(t, app, source, "?to=a%40example.com&u=https%3A%2F%2Fhub.example.com%2Fu%2F9", nil)
		got := sends()
		if err != nil || rr.Code != 200 || len(got) != before+1 {
			t.Fatalf("%s: status %d err %v, %d sends", name, rr.Code, err, len(got)-before)
		}
		req := got[len(got)-1]
		if u, _ := req["unsubscribe_url"].(string); u != c.want {
			t.Errorf("%s: unsubscribe_url = %q, want %q", name, u, c.want)
		}
		if _, oneClick := req["unsubscribe_one_click"]; oneClick {
			t.Errorf("%s: the send asked for the one-click POST header", name)
		}
	}

	// The header is optional and the message is not: a URL that is not a
	// plain https URL, or a reference with no value, drops only the header.
	for query, unsubscribe := range map[string]string{
		"?to=a%40example.com&u=http%3A%2F%2Fhub.example.com%2Fu":                                        "\"${{ params.u }}\"",
		"?to=a%40example.com&u=mailto%3Ax%40example.com":                                                "\"${{ params.u }}\"",
		"?to=a%40example.com&u=https%3A%2F%2Fa.example.com%2Fu%3E%2C%20%3Cmailto%3Ax%40evil.example%3E": "\"${{ params.u }}\"",
		"?to=a%40example.com": "\"${{ params.missing_url }}\"",
	} {
		before := len(sends())
		app := expectRowsApp(t)
		rr, _, err := runStepValueFlow(t, app, email(unsubscribe), query, nil)
		got := sends()
		if err != nil || rr.Code != 200 || len(got) != before+1 {
			t.Errorf("%s: status %d err %v, sends %d; want the message sent", query, rr.Code, err, len(got)-before)
			continue
		}
		if u, _ := got[len(got)-1]["unsubscribe_url"].(string); u != "" {
			t.Errorf("%s: unsubscribe_url = %q, want no header", query, u)
		}
	}

	// The write gate refuses a URL that is written out and is not https.
	for value, want := range map[string]string{
		"http://www.example.com/unsubscribe":          "`with.unsubscribe_url` must be an https:// URL",
		"mailto:unsubscribe@example.com":              "`with.unsubscribe_url` must be an https:// URL",
		"\"http://example.com/u?e=${{ params.to }}\"": "`with.unsubscribe_url` must be an https:// URL",
	} {
		if msg := ValidateOnWrite("flows/probe.yaml", email(value)); !strings.Contains(msg, want) {
			t.Errorf("%s: write gate said %q, want %q", value, msg, want)
		}
	}
}
