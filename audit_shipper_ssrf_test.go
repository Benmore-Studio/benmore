//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// The destination is validated once at startup, but every tick re-resolves it
// and may be redirected. Delivery itself must refuse a loopback address unless
// the operator opted into private destinations with ALLOW_HTTP=1.
func TestAuditShipperDeliveryRefusesLoopbackUnlessOptedIn(t *testing.T) {
	db, err := sql.Open("sqlite3", filepath.Join(t.TempDir(), "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	EnsureAuditLogTable(db)
	ensureAuditShipperCursor(db)
	mustExec(t, db, `INSERT INTO _benmore_audit_log (action, table_name, row_id) VALUES ('create', 'notes', '1')`)

	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		posts.Add(1)
	}))
	defer srv.Close()
	secret := "0123456789abcdef0123456789abcdef"

	t.Setenv("BENMORE_AUDIT_WEBHOOK_ALLOW_HTTP", "")
	shipOnce(db, srv.URL, secret, "", 100, "test")
	if n := posts.Load(); n != 0 {
		t.Fatalf("audit shipper delivered %d batch(es) to a loopback address without the private opt-in", n)
	}

	// A platform-managed tenant sets its own env: the override never opens
	// the host's loopback to it.
	t.Setenv("BENMORE_AUDIT_WEBHOOK_ALLOW_HTTP", "1")
	t.Setenv("BENMORE_BIND_LOOPBACK", "1")
	shipOnce(db, srv.URL, secret, "", 100, "test")
	if n := posts.Load(); n != 0 {
		t.Fatalf("hosted tenant delivered %d batch(es) to loopback via ALLOW_HTTP", n)
	}
	if reason := validateAuditWebhookURL(srv.URL); reason == "" {
		t.Fatal("hosted tenant: a loopback audit destination must be refused at startup")
	}

	t.Setenv("BENMORE_BIND_LOOPBACK", "")
	shipOnce(db, srv.URL, secret, "", 100, "test")
	if n := posts.Load(); n != 1 {
		t.Fatalf("with ALLOW_HTTP=1 the shipper made %d deliveries, want 1", n)
	}
}
