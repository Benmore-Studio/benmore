//go:build !cli

package main

import (
	"bytes"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// benmoreReceiver serves a `verify: benmore` flow that records each
// delivery it accepts, and points the strict outbound transport at it, so a
// subscription delivery to http://<public literal>/api/hooks/notes reaches it.
func benmoreReceiver(t *testing.T, secret string) (*App, *receiverLog) {
	t.Helper()
	receiver, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	SetAppEnv(receiver.Dir, "PARTNER_HOOK_SECRET", secret)
	t.Cleanup(func() { SetAppEnv(receiver.Dir, "PARTNER_HOOK_SECRET", "") })
	mustExec(t, receiver.DB, `CREATE TABLE inbound (event TEXT, tbl TEXT)`)
	source := "on:\n  request:\n    method: POST\n    path: /api/hooks/notes\n    verify: benmore\n    secret: \"${{ env.PARTNER_HOOK_SECRET }}\"\n" +
		"jobs:\n  receive:\n    steps:\n" +
		"      - id: record\n        query: \"INSERT INTO inbound (event, tbl) VALUES (:event, :table)\"\n" +
		"      - run: respond\n        with: { status: 200, json: { received: true } }\n"
	if msg := ValidateOnWrite("flows/notes_hook.yaml", source); msg != "" {
		t.Fatalf("write gate refused the receiver flow: %s", msg)
	}
	flows, err := parseGHAFlowFile("flows/notes_hook.yaml", []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, receiver, flows)
	log := &receiverLog{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		mux.ServeHTTP(rec, r)
		log.add(rec.status)
	}))
	t.Cleanup(srv.Close)
	saved := strictOutboundTransport
	strictOutboundTransport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}}
	t.Cleanup(func() { strictOutboundTransport = saved })
	return receiver, log
}

type receiverLog struct {
	mu       sync.Mutex
	statuses []int
}

func (l *receiverLog) add(status int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.statuses = append(l.statuses, status)
}

func (l *receiverLog) last() int {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.statuses) == 0 {
		return 0
	}
	return l.statuses[len(l.statuses)-1]
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

// A Benmore app can verify a delivery from another Benmore app's webhook
// subscription with `verify: benmore`. No built-in verifier read the
// platform's own signature (X-Webhook-Signature: t=<ts>,v1=<hex>): `verify:
// stripe` reads only Stripe-Signature, the header form wants a bare body
// HMAC, and hmac_timestamp_dot_body a bare signature, so all of them
// answered 401 (round 2026-11-04). The delivery here is the real one
// (executeWebhookSubscriptionJob signs it).
func TestVerifyBenmoreAcceptsSubscriptionDeliveries(t *testing.T) {
	resetCircuitsForTest(t)
	const secret = "partner-subscription-signing-secret"
	receiver, received := benmoreReceiver(t, secret)

	sender, done := newTestApp(t)
	defer done()
	EnsureUsersTable(sender.DB)
	EnsureSessionsTable(sender.DB)
	EnsureWebhooksTable(sender.DB)
	EnsureJobsTable(sender.DB)
	_, _, adminID := loginTestUser(sender, "owner@example.com", "admin")
	sender.Tables = []Table{{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER"}, {Name: "title", Type: "TEXT"}}}}
	if _, err := sender.DB.Exec("INSERT INTO _benmore_webhooks (user_id, url, secret, tables, events) VALUES (?, 'http://93.184.216.34/api/hooks/notes', ?, 'notes', '')", adminID, secret); err != nil {
		t.Fatal(err)
	}
	_ = enqueueWebhookSubscriptionsTx(sender.DB, sender, "insert", "notes", map[string]any{"id": 7, "title": "signed and delivered"}, nil)
	if err := executeWebhookSubscriptionJob(webhookTestJobPayload(t, sender), sender); err != nil {
		t.Fatalf("delivery to a verify: benmore receiver failed: %v (receiver answered %d)", err, received.last())
	}
	var event, table string
	if err := receiver.DB.QueryRow(`SELECT event, tbl FROM inbound`).Scan(&event, &table); err != nil {
		t.Fatalf("the receiver kept no row: %v", err)
	}
	if event != "insert" || table != "notes" || received.last() != http.StatusOK {
		t.Fatalf("received row = %q %q, status %d", event, table, received.last())
	}

	// The legacy v0 signature that a sender may add for a migration window
	// does not stop the v1 check from passing.
	SetAppEnv(sender.Dir, "BENMORE_WEBHOOK_LEGACY_V0", "1")
	t.Cleanup(func() { SetAppEnv(sender.Dir, "BENMORE_WEBHOOK_LEGACY_V0", "") })
	_ = enqueueWebhookSubscriptionsTx(sender.DB, sender, "insert", "notes", map[string]any{"id": 8, "title": "with v0"}, nil)
	if err := executeWebhookSubscriptionJob(webhookTestJobPayload(t, sender), sender); err != nil {
		t.Fatalf("delivery with the legacy v0 signature failed: %v", err)
	}

	// A subscription signing with another secret is refused, and nothing is kept.
	mustExec(t, sender.DB, "UPDATE _benmore_webhooks SET secret = 'some-other-secret'")
	_ = enqueueWebhookSubscriptionsTx(sender.DB, sender, "insert", "notes", map[string]any{"id": 9, "title": "wrong key"}, nil)
	if err := executeWebhookSubscriptionJob(webhookTestJobPayload(t, sender), sender); err == nil || received.last() != http.StatusUnauthorized {
		t.Fatalf("a delivery signed with another secret: err=%v receiver=%d, want refused with 401", err, received.last())
	}
	var rows int
	if err := receiver.DB.QueryRow(`SELECT COUNT(*) FROM inbound`).Scan(&rows); err != nil || rows != 2 {
		t.Fatalf("receiver rows = %d err=%v, want the 2 genuine deliveries", rows, err)
	}
}

// `verify: benmore` checks what webhooks.go signs and nothing weaker: the
// v1 HMAC over "<t>.<body>", within the 5-minute window `verify: stripe`
// uses. A changed body, a stale or future timestamp, a body-only (v0)
// signature, Stripe's header or a bare body HMAC are refused.
func TestVerifyBenmoreRefusesWhatTheSenderDidNotSign(t *testing.T) {
	const secret = "partner-subscription-signing-secret"
	dir := t.TempDir()
	SetAppEnv(dir, "PARTNER_HOOK_SECRET", secret)
	t.Cleanup(func() { SetAppEnv(dir, "PARTNER_HOOK_SECRET", "") })
	flow := &Flow{Name: "hook", Verify: "benmore", Secret: "${{ env.PARTNER_HOOK_SECRET }}"}
	body := []byte(`{"event":"insert","table":"notes","data":{"id":1}}`)
	check := func(body []byte, headers map[string]string) bool {
		r := httptest.NewRequest(http.MethodPost, "/api/hook", bytes.NewReader(body))
		for k, v := range headers {
			r.Header.Set(k, v)
		}
		return verifyWebhookSignature(flow, r, dir)
	}
	at := func(when time.Time, legacyV0 bool) map[string]string {
		ts := strconv.FormatInt(when.Unix(), 10)
		return map[string]string{
			"X-Webhook-Signature": webhookSubscriptionSignature(secret, ts, body, legacyV0),
			"X-Webhook-Timestamp": ts,
		}
	}
	now := time.Now()
	if !check(body, at(now, false)) || !check(body, at(now, true)) {
		t.Fatal("a current delivery signature was refused")
	}
	if !check(body, at(now.Add(-4*time.Minute), false)) {
		t.Fatal("a delivery inside the 5-minute window was refused")
	}
	ts := strconv.FormatInt(now.Unix(), 10)
	v0Only := "t=" + ts + ",v0=" + hmacHex(t, secret, body)
	refused := map[string]struct {
		body    []byte
		headers map[string]string
	}{
		"changed body":         {[]byte(`{"event":"delete","table":"notes","data":{"id":1}}`), at(now, false)},
		"6 minutes old":        {body, at(now.Add(-6*time.Minute), false)},
		"6 minutes ahead":      {body, at(now.Add(6*time.Minute), false)},
		"body-only v0":         {body, map[string]string{"X-Webhook-Signature": v0Only}},
		"no signature":         {body, map[string]string{"X-Webhook-Timestamp": ts}},
		"in Stripe-Signature":  {body, map[string]string{"Stripe-Signature": at(now, false)["X-Webhook-Signature"]}},
		"bare body HMAC":       {body, map[string]string{"X-Webhook-Signature": hmacHex(t, secret, body)}},
		"signed with ts only":  {body, map[string]string{"X-Webhook-Signature": "t=" + ts}},
		"another secret's sig": {body, map[string]string{"X-Webhook-Signature": webhookSubscriptionSignature("another-secret", ts, body, false)}},
	}
	for name, c := range refused {
		if check(c.body, c.headers) {
			t.Errorf("%s: accepted", name)
		}
	}
	if !strings.Contains(webhookSubscriptionSignature(secret, ts, body, false), "v1=") {
		t.Fatal("the subscription signature lost its v1 entry")
	}
}
