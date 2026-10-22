//go:build !cli

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newBillingEventTestApp(t *testing.T) (*App, *BillingConfig, func(body string)) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db}
	t.Cleanup(app.Shutdown)
	const secret = "whsec_billing_order_test"
	SetAppEnv(app.Dir, "STRIPE_WEBHOOK_SECRET", secret)
	cfg := &BillingConfig{Provider: "stripe", WebhookSecretEnv: "STRIPE_WEBHOOK_SECRET"}
	ensureBillingTablesReal(app)
	send := func(body string) {
		t.Helper()
		ts := strconv.FormatInt(time.Now().Unix(), 10)
		mac := hmac.New(sha256.New, []byte(secret))
		mac.Write([]byte(ts + "." + body))
		req := httptest.NewRequest(http.MethodPost, "/api/_billing/webhook", strings.NewReader(body))
		req.Header.Set("Stripe-Signature", "t="+ts+",v1="+hex.EncodeToString(mac.Sum(nil)))
		rec := httptest.NewRecorder()
		handleStripeWebhook(rec, req, app, cfg)
		if rec.Code != http.StatusOK {
			t.Fatalf("webhook status %d: %s", rec.Code, rec.Body.String())
		}
	}
	return app, cfg, send
}

func subscriptionEvent(id, typ string, created int64, status string) string {
	return fmt.Sprintf(`{"id":%q,"type":%q,"created":%d,"data":{"object":{"id":"sub_order","customer":"cus_order","status":%q,"cancel_at_period_end":false}}}`,
		id, typ, created, status)
}

func subscriptionStatus(t *testing.T, app *App) string {
	t.Helper()
	var status string
	if err := app.DB.QueryRow(`SELECT status FROM _benmore_subscriptions WHERE stripe_subscription_id = 'sub_order'`).Scan(&status); err != nil {
		t.Fatalf("read subscription: %v", err)
	}
	return status
}

// Stripe delivers events at least once and in no particular order. A late
// customer.subscription.updated (still active) arriving after the
// customer.subscription.deleted that ended the subscription must not
// reactivate it.
func TestBillingLateUpdateDoesNotReactivateCanceledSubscription(t *testing.T) {
	app, _, send := newBillingEventTestApp(t)
	base := time.Now().Unix() - 600

	send(subscriptionEvent("evt_created", "customer.subscription.created", base, "active"))
	send(subscriptionEvent("evt_deleted", "customer.subscription.deleted", base+120, "canceled"))
	if got := subscriptionStatus(t, app); got != "canceled" {
		t.Fatalf("status after delete = %q, want canceled", got)
	}
	// The update Stripe sent before the cancellation arrives last.
	send(subscriptionEvent("evt_updated_late", "customer.subscription.updated", base+60, "active"))
	if got := subscriptionStatus(t, app); got != "canceled" {
		t.Fatalf("a late, older update reactivated a canceled subscription: status = %q", got)
	}
	// Same-second ordering: a canceled subscription is terminal at Stripe.
	send(subscriptionEvent("evt_updated_same_second", "customer.subscription.updated", base+120, "active"))
	if got := subscriptionStatus(t, app); got != "canceled" {
		t.Fatalf("an update from the cancellation's second reactivated it: status = %q", got)
	}
}

// A redelivered event is applied once: replaying an old event id must not
// overwrite what newer events set.
func TestBillingReplayedEventIsNotReapplied(t *testing.T) {
	app, _, send := newBillingEventTestApp(t)
	base := time.Now().Unix() - 600

	send(subscriptionEvent("evt_a", "customer.subscription.updated", base, "past_due"))
	// The row was later changed outside this event stream (for example by a
	// newer event without an ordering problem); a replay of evt_a must be a
	// no-op even though its created time equals the stored one.
	if _, err := app.DB.Exec(`UPDATE _benmore_subscriptions SET status = 'active' WHERE stripe_subscription_id = 'sub_order'`); err != nil {
		t.Fatal(err)
	}
	send(subscriptionEvent("evt_a", "customer.subscription.updated", base, "past_due"))
	if got := subscriptionStatus(t, app); got != "active" {
		t.Fatalf("replayed event re-applied: status = %q, want active", got)
	}
	var n int
	app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_billing_events WHERE id = 'evt_a'`).Scan(&n)
	if n != 1 {
		t.Fatalf("processed event rows for evt_a = %d, want 1", n)
	}
}

// Newer events still apply in order, and an existing row without an event
// time (written by an older runtime) accepts the first event.
func TestBillingEventsApplyInOrderAndUpgradeLegacyRows(t *testing.T) {
	app, _, send := newBillingEventTestApp(t)
	if _, err := app.DB.Exec(`INSERT INTO _benmore_subscriptions (user_id, stripe_customer_id, stripe_subscription_id, status, plan) VALUES (7, 'cus_order', 'sub_order', 'active', '')`); err != nil {
		t.Fatal(err)
	}
	base := time.Now().Unix() - 600
	send(subscriptionEvent("evt_1", "customer.subscription.updated", base, "past_due"))
	if got := subscriptionStatus(t, app); got != "past_due" {
		t.Fatalf("legacy row did not accept its first event: %q", got)
	}
	send(subscriptionEvent("evt_2", "customer.subscription.updated", base+30, "active"))
	if got := subscriptionStatus(t, app); got != "active" {
		t.Fatalf("newer event not applied: %q", got)
	}
	var uid int64
	app.DB.QueryRow(`SELECT user_id FROM _benmore_subscriptions WHERE stripe_subscription_id = 'sub_order'`).Scan(&uid)
	if uid != 7 {
		t.Fatalf("user link lost: user_id = %d", uid)
	}
}

// A paid invoice must not fall back to open when its earlier
// invoice.finalized event is delivered after invoice.payment_succeeded.
func TestBillingLateInvoiceEventDoesNotRegressPaidInvoice(t *testing.T) {
	app, _, send := newBillingEventTestApp(t)
	base := time.Now().Unix() - 600
	inv := func(id, typ string, created int64, status string) string {
		return fmt.Sprintf(`{"id":%q,"type":%q,"created":%d,"data":{"object":{"id":"in_order","customer":"cus_order","subscription":"sub_order","status":%q,"amount_paid":500,"currency":"usd"}}}`,
			id, typ, created, status)
	}
	send(inv("evt_paid", "invoice.payment_succeeded", base+60, "paid"))
	send(inv("evt_finalized", "invoice.finalized", base, "open"))
	var status string
	var paidAt sql.NullString
	app.DB.QueryRow(`SELECT status, paid_at FROM _benmore_invoices WHERE stripe_invoice_id = 'in_order'`).Scan(&status, &paidAt)
	if status != "paid" || !paidAt.Valid {
		t.Fatalf("late finalized event regressed the invoice: status=%q paid_at=%v", status, paidAt)
	}
}

// The ordering column and the processed-event table are added to databases
// created before them, and adding them twice is harmless.
func TestBillingTablesUpgradeIdempotently(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db}
	t.Cleanup(app.Shutdown)
	mustExec(t, db, `CREATE TABLE _benmore_subscriptions (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, stripe_customer_id TEXT, stripe_subscription_id TEXT UNIQUE, status TEXT, plan TEXT, current_period_end DATETIME, cancel_at_period_end INTEGER DEFAULT 0, metadata TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	mustExec(t, db, `INSERT INTO _benmore_subscriptions (user_id, stripe_subscription_id, status) VALUES (1, 'sub_legacy', 'active')`)
	ensureBillingTablesReal(app)
	ensureBillingTablesReal(app)
	var created int64
	if err := db.QueryRow(`SELECT stripe_event_created FROM _benmore_subscriptions WHERE stripe_subscription_id = 'sub_legacy'`).Scan(&created); err != nil || created != 0 {
		t.Fatalf("legacy row stripe_event_created = %d, %v", created, err)
	}
	for _, table := range []string{"_benmore_invoices", "_benmore_billing_events"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil || n != 1 {
			t.Fatalf("table %s missing", table)
		}
	}
}
