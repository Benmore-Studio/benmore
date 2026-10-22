//go:build !cli

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
	"time"
)

// A checkout without a subscription must never link one user to another
// user's Stripe customer. Before the fix, one-time checkouts shared the
// empty-string subscription key, so the second buyer inherited the first
// buyer's row.
func TestBillingOneTimeCheckoutsDoNotShareSubscriptionRow(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	const secret = "whsec_billing_collision_test"
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
	checkout := func(userID, customer, subscription string) string {
		sub := "null"
		if subscription != "" {
			sub = strconv.Quote(subscription)
		}
		return fmt.Sprintf(`{"type":"checkout.session.completed","data":{"object":{"customer":%q,"subscription":%s,"metadata":{"user_id":%q}}}}`,
			customer, sub, userID)
	}

	send(checkout("1", "cus_first", ""))
	send(checkout("2", "cus_second", ""))

	var leaked int
	app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_subscriptions WHERE user_id = 2 AND stripe_customer_id = 'cus_first'`).Scan(&leaked)
	if leaked != 0 {
		t.Fatalf("user 2 was linked to user 1's Stripe customer")
	}

	// Subscription checkouts still link the subscription to its user.
	send(checkout("3", "cus_third", "sub_third"))
	var uid int64
	if err := app.DB.QueryRow(`SELECT user_id FROM _benmore_subscriptions WHERE stripe_subscription_id = 'sub_third'`).Scan(&uid); err != nil || uid != 3 {
		t.Fatalf("subscription checkout: user_id = %d, err = %v; want 3", uid, err)
	}
}
