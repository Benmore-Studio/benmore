//go:build !cli

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func hookDefaultBodyApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db, Tables: []Table{{Name: "integrations", Columns: []Column{
		{Name: "id", Type: "INTEGER"}, {Name: "name", Type: "TEXT"}, {Name: "api_key", Type: "TEXT"},
	}}}}
	t.Cleanup(app.Shutdown)
	return app
}

// roundTripHookJob runs a hook the way the worker does: through the stored
// JSON payload.
func roundTripHookJob(t *testing.T, app *App, payload map[string]any) error {
	t.Helper()
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]any
	if err := json.Unmarshal(raw, &data); err != nil {
		t.Fatal(err)
	}
	return executeHookJob(app, data)
}

var hookDefaultBodyRow = map[string]any{"id": 4, "name": "crm", "api_key": "live-credential", "old_api_key": "previous-credential"}

// A hook `webhook:` with no `body:` posts the event row. Like a webhook
// subscription delivery it carries only the columns an API read would, never
// a hidden credential column or its old_ delta.
func TestHookWebhookDefaultBodyStripsHiddenColumns(t *testing.T) {
	app := hookDefaultBodyApp(t)
	got := make(chan string, 4)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got <- string(b)
	}))
	defer srv.Close()
	// The hook URL is a public address literal (it passes the SSRF guard);
	// the strict transport is pointed at the local receiver for this test.
	saved := strictOutboundTransport
	strictOutboundTransport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}}
	defer func() { strictOutboundTransport = saved }()
	const hookURL = "http://93.184.216.34/hook"

	check := func(name string, payload map[string]any) {
		t.Helper()
		if err := roundTripHookJob(t, app, payload); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		select {
		case body := <-got:
			if strings.Contains(body, "credential") || !strings.Contains(body, `"name":"crm"`) {
				t.Fatalf("%s: webhook body = %s; want name kept and api_key/old_api_key stripped", name, body)
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s: webhook not delivered", name)
		}
	}
	check("queued with its table", hookJobPayload(Hook{Webhook: hookURL}, "integrations", hookDefaultBodyRow))
	// A job queued before the table was recorded strips by column name.
	legacy := hookJobPayload(Hook{Webhook: hookURL}, "", hookDefaultBodyRow)
	delete(legacy["_hook"].(map[string]any), "table")
	check("queued without a table", legacy)

	// An explicit body still renders any column the author names.
	if err := roundTripHookJob(t, app, hookJobPayload(Hook{Webhook: hookURL, Body: `{"k":"{{api_key}}"}`}, "integrations", hookDefaultBodyRow)); err != nil {
		t.Fatal(err)
	}
	if body := <-got; body != `{"k":"live-credential"}` {
		t.Fatalf("explicit body = %s", body)
	}
}

// A hook `ws:` with no payload sends only the table that changed: room
// members are clients, so no column of the row (hidden or not) is sent
// unless the payload names it.
func TestHookWSDefaultPayloadStripsHiddenColumns(t *testing.T) {
	resetWSHub(t)
	app := hookDefaultBodyApp(t)
	member := newWSTestClient(realtimeAppID(app.Dir), 7, "")
	registerWSClient(member)
	defer unregisterWSClient(member)
	wsJoinAs(member, "integration-4")

	if err := roundTripHookJob(t, app, hookJobPayload(Hook{WS: &WSHook{Room: "integration-{{id}}"}}, "integrations", hookDefaultBodyRow)); err != nil {
		t.Fatal(err)
	}
	realtimeFlush()
	select {
	case raw := <-member.send:
		if strings.Contains(string(raw), "credential") || !strings.Contains(string(raw), `"payload":{"table":"integrations"}`) {
			t.Fatalf("ws payload = %s; want only the table", raw)
		}
	default:
		t.Fatal("room member received nothing")
	}
}
