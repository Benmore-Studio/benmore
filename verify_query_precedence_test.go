//go:build !cli

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The documented inbound example (api(at:"webhooks") inbound_example): a
// replayed, correctly signed Stripe event with ?id=&type= in the URL used to
// store the query's values, because the query string was bound first and a
// JSON body key yielded to it. The signed body must win.
func TestVerifiedFlowQueryCannotOverrideSignedBody(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "STRIPE_WEBHOOK_SECRET", "whsec_query_test")
	mustExec(t, app.DB, `CREATE TABLE stripe_events (source TEXT, event_id TEXT UNIQUE, type TEXT)`)
	flow := Flow{
		Name:    "stripe_simple",
		Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/webhooks/stripe-simple"},
		Verify:  "stripe",
		Secret:  "{{env.STRIPE_WEBHOOK_SECRET}}",
		Steps: []FlowStep{
			{Type: "sql", SQL: "INSERT OR IGNORE INTO stripe_events (source, event_id, type) VALUES ('stripe-simple', :id, :type)"},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"received": true}}},
		},
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, []Flow{flow})

	body := []byte(`{"id":"evt_real_X","type":"invoice.paid"}`)
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	signature := "t=" + ts + ",v1=" + hmacHex(t, "whsec_query_test", append([]byte(ts+"."), body...))
	send := func(target string) int {
		r := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Stripe-Signature", signature)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, r)
		return rr.Code
	}
	for _, target := range []string{
		"/api/webhooks/stripe-simple",
		"/api/webhooks/stripe-simple",
		"/api/webhooks/stripe-simple?id=evt_forged_X&type=charge.refunded",
	} {
		if code := send(target); code != http.StatusOK {
			t.Fatalf("%s: status %d, want 200", target, code)
		}
	}
	rows, err := app.DB.Query(`SELECT event_id, type FROM stripe_events ORDER BY event_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var id, typ string
		if err := rows.Scan(&id, &typ); err != nil {
			t.Fatal(err)
		}
		got = append(got, id+"/"+typ)
	}
	if strings.Join(got, ",") != "evt_real_X/invoice.paid" {
		t.Fatalf("stored events = %v, want only the signed evt_real_X/invoice.paid (the query string must not replace signed fields)", got)
	}
}

// No verifier signs the URL query, so a verified flow binds nothing from it:
// not a name the signed body leaves unset, and not through a `run: parse`
// of a form body (r.Form merges the query in). The route's own path
// parameters still bind.
func TestVerifiedFlowBindsNothingFromQuery(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "PARTNER_SECRET", "partner-secret")
	mustExec(t, app.DB, `CREATE TABLE partner_events (account TEXT, event_id TEXT, kind TEXT, note TEXT, form_note TEXT)`)
	verify := &FlowVerify{Recipe: "hmac_sha256_body", Header: "X-Partner-Signature", Secret: "{{env.PARTNER_SECRET}}"}
	jsonFlow := Flow{
		Name:         "partner_json",
		Trigger:      FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/partner/:account/json"},
		VerifyConfig: verify,
		Steps: []FlowStep{
			{
				Type:      "sql",
				SQL:       "INSERT INTO partner_events (account, event_id, kind, note) VALUES (:account, :id, :kind, :note)",
				SQLParams: map[string]string{"note": normalizeGHARefs("${{ params.note | default:'unset' }}")},
			},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"ok": true}}},
		},
	}
	formFlow := Flow{
		Name:         "partner_form",
		Trigger:      FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/partner/:account/form"},
		VerifyConfig: verify,
		Steps: []FlowStep{
			{Name: "payload", Type: "parse", Parse: "body"},
			{
				Type: "sql",
				SQL:  "INSERT INTO partner_events (account, event_id, kind, note, form_note) VALUES (:account, :id, :kind, :note, :form_note)",
				SQLParams: map[string]string{
					"note":      normalizeGHARefs("${{ params.note | default:'unset' }}"),
					"form_note": normalizeGHARefs("${{ payload.note | default:'unset' }}"),
				},
			},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"ok": true}}},
		},
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, []Flow{jsonFlow, formFlow})
	send := func(target, contentType string, body []byte) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		r.Header.Set("X-Partner-Signature", hmacHex(t, "partner-secret", body))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, r)
		return rr
	}
	if rr := send("/api/partner/acct-1/json?note=forged&account=acct-2", "application/json", []byte(`{"id":"evt_1","kind":"created"}`)); rr.Code != http.StatusOK {
		t.Fatalf("json: status %d body %s, want 200", rr.Code, rr.Body.String())
	}
	if rr := send("/api/partner/acct-1/form?note=forged", "application/x-www-form-urlencoded", []byte("id=evt_2&kind=created")); rr.Code != http.StatusOK {
		t.Fatalf("form: status %d body %s, want 200", rr.Code, rr.Body.String())
	}
	rows, err := app.DB.Query(`SELECT account, event_id, COALESCE(note, '<null>'), COALESCE(form_note, '<null>') FROM partner_events ORDER BY event_id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var account, id, note, formNote string
		if err := rows.Scan(&account, &id, &note, &formNote); err != nil {
			t.Fatal(err)
		}
		got = append(got, account+"/"+id+"/"+note+"/"+formNote)
	}
	want := "acct-1/evt_1/unset/<null>,acct-1/evt_2/unset/unset"
	if strings.Join(got, ",") != want {
		t.Fatalf("stored rows = %v, want %s (the path parameter binds; no query value reaches :note or the parsed form)", got, want)
	}
}

// strict_json promises one unambiguous object; on an unverified strict
// route a query field naming a body key is a second value for it and is
// refused before any step, while a query field the body does not set is
// still bound. A verified strict route binds no query field at all.
func TestStrictJSONRefusesQueryDuplicatingBodyKey(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "PARTNER_SECRET", "partner-secret")
	mustExec(t, app.DB, `CREATE TABLE partner_events (event_id TEXT, kind TEXT, note TEXT)`)
	steps := []FlowStep{
		{
			Type:      "sql",
			SQL:       "INSERT INTO partner_events (event_id, kind, note) VALUES (:id, :kind, :note)",
			SQLParams: map[string]string{"note": normalizeGHARefs("${{ params.note | default:'unset' }}")},
		},
		{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"ok": true}}},
	}
	verified := Flow{
		Name:         "partner_verified",
		Trigger:      FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/partner/verified", StrictJSON: true},
		VerifyConfig: &FlowVerify{Recipe: "hmac_sha256_body", Header: "X-Partner-Signature", Secret: "{{env.PARTNER_SECRET}}"},
		Steps:        steps,
	}
	plain := Flow{
		Name:    "partner_plain",
		Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/partner/plain", StrictJSON: true},
		Steps:   steps,
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, []Flow{verified, plain})

	body := []byte(`{"id":"evt_1","kind":"created"}`)
	send := func(target string) int {
		r := httptest.NewRequest(http.MethodPost, target, bytes.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Partner-Signature", hmacHex(t, "partner-secret", body))
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, r)
		return rr.Code
	}
	if code := send("/api/partner/plain?kind=deleted&note=q"); code != http.StatusBadRequest {
		t.Fatalf("unverified strict route with a query key duplicating a body key: status %d, want 400", code)
	}
	if code := send("/api/partner/plain?note=" + url.QueryEscape("from query")); code != http.StatusOK {
		t.Fatalf("unverified strict route with a query key the body does not set: status %d, want 200", code)
	}
	if code := send("/api/partner/verified?kind=deleted&note=" + url.QueryEscape("from query")); code != http.StatusOK {
		t.Fatalf("verified strict route with a query string: status %d, want 200 (the query is ignored)", code)
	}
	var refused, kept, verifiedQuery int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM partner_events WHERE kind <> 'created'`).Scan(&refused); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM partner_events WHERE kind = 'created' AND note = 'from query'`).Scan(&kept); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM partner_events WHERE kind = 'created' AND note = 'unset'`).Scan(&verifiedQuery); err != nil {
		t.Fatal(err)
	}
	if refused != 0 || kept != 1 || verifiedQuery != 1 {
		t.Fatalf("rows with a replaced kind = %d (want 0), unverified rows with the query-only note = %d (want 1), verified rows without it = %d (want 1)", refused, kept, verifiedQuery)
	}
}

// hmac_sha256_path_bearer signs one path segment. A query or form field of
// the same name used to replace it in the flow's values, so a caller holding
// handle-a's token could act on handle-b.
func TestPathBearerSignedSegmentCannotBeReplaced(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "PROCORE_WEBHOOK_MASTER_SECRET", "master-secret")
	mustExec(t, app.DB, `CREATE TABLE webhook_log (handle TEXT)`)
	flow := Flow{
		Name:    "procore_webhook",
		Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/procore-webhook/:handle"},
		VerifyConfig: &FlowVerify{
			Recipe: "hmac_sha256_path_bearer", Secret: "{{env.PROCORE_WEBHOOK_MASTER_SECRET}}",
			Prefix: "Bearer ", PathParam: "handle", Context: "procore-webhook:",
		},
		Steps: []FlowStep{
			{Type: "sql", SQL: "INSERT INTO webhook_log (handle) VALUES (:handle)"},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"handle": "{{handle}}"}}},
		},
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, []Flow{flow})
	tokenA := hmacHex(t, "master-secret", []byte("procore-webhook:handle-a"))
	send := func(target, form string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form))
		if form != "" {
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
		r.Header.Set("Authorization", "Bearer "+tokenA)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, r)
		return rr
	}
	for _, c := range []struct{ target, form string }{
		{"/api/procore-webhook/handle-a?handle=handle-b", ""},
		{"/api/procore-webhook/handle-a", "handle=handle-b"},
	} {
		rr := send(c.target, c.form)
		if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), `"handle-a"`) {
			t.Fatalf("%s form=%q: status %d body %s, want the signed handle-a", c.target, c.form, rr.Code, rr.Body.String())
		}
	}
	var other int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM webhook_log WHERE handle <> 'handle-a'`).Scan(&other); err != nil || other != 0 {
		t.Fatalf("rows for a handle the token was not derived for = %d err=%v, want 0", other, err)
	}
}

// Unverified, non-strict flows keep their documented precedence: a query
// value still outranks a JSON body key of the same name.
func TestUnverifiedFlowQueryPrecedenceUnchanged(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	flow := Flow{
		Name:    "echo",
		Trigger: FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/echo"},
		Steps: []FlowStep{
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"kind": "{{kind}}"}}},
		},
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, []Flow{flow})
	r := httptest.NewRequest(http.MethodPost, "/api/echo?kind=from-query", strings.NewReader(`{"kind":"from-body"}`))
	r.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	mux.ServeHTTP(rr, r)
	if rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "from-query") {
		t.Fatalf("status %d body %s, want the query value", rr.Code, rr.Body.String())
	}
}
