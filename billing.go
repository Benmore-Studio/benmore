//go:build !cli

package main

// Stripe billing. The opinionated convenience layer over the existing
// webhook + flow primitives: when an app declares `billing:` in
// app.yaml, the framework auto-creates two tables and registers a
// signature-verified webhook endpoint that syncs subscription state
// without any per-app glue code.
//
// app.yaml:
//   billing:
//     provider: stripe
//     webhook_secret_env: STRIPE_WEBHOOK_SECRET    # name of env var
//     publishable_key_env: STRIPE_PUBLISHABLE_KEY  # for client SDK
//
// Tables auto-created:
//   _benmore_subscriptions  — one row per Stripe Subscription, scoped
//                             by user_id when the customer's metadata
//                             carries `user_id`.
//   _benmore_invoices       — one row per Stripe Invoice.
//
// Endpoints:
//   POST /api/_billing/webhook   — signature-verified, syncs state
//   GET  /api/_billing/me        — returns current user's subscription
//   POST /api/_billing/portal    — redirects to Stripe Customer Portal
//
// React side: bm.useSubscription() returns the current user's plan
// + status; bm.api('POST', '_billing/portal') gets a redirect URL
// the client can window.location to.
//
// Test/dev: when no Stripe keys are configured, the endpoints respond
// with 503 + a helpful message. Apps without `billing:` skip
// registration entirely.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// BillingConfig is parsed from app.yaml's `billing:` block.
type BillingConfig struct {
	Provider          string
	WebhookSecretEnv  string
	PublishableKeyEnv string
	APIKeyEnv         string // STRIPE_SECRET_KEY for portal sessions
}

// loadBillingConfig pulls from app.Design's raw map. We use the SEO
// map as a generic "settings the user wrote in app.yaml" home rather
// than adding another typed sub-struct that needs YAML wiring.
func loadBillingConfig(app *App) *BillingConfig {
	if app == nil || app.Design == nil {
		return nil
	}
	// Use the Auth map's prefix convention: "billing_provider" =>
	// provider, etc. Loose typing keeps the YAML loader unchanged.
	provider := app.Design.Auth["billing_provider"]
	if provider == "" {
		// Fallback: SEO map (the generic "extra config" bin).
		provider = app.Design.SEO["billing_provider"]
	}
	if provider == "" {
		return nil
	}
	return &BillingConfig{
		Provider:          provider,
		WebhookSecretEnv:  firstNonEmptyStr(app.Design.Auth["billing_webhook_secret_env"], app.Design.SEO["billing_webhook_secret_env"], "STRIPE_WEBHOOK_SECRET"),
		PublishableKeyEnv: firstNonEmptyStr(app.Design.Auth["billing_publishable_key_env"], app.Design.SEO["billing_publishable_key_env"], "STRIPE_PUBLISHABLE_KEY"),
		APIKeyEnv:         firstNonEmptyStr(app.Design.Auth["billing_api_key_env"], app.Design.SEO["billing_api_key_env"], "STRIPE_SECRET_KEY"),
	}
}

// RegisterBillingRoutes wires the three endpoints + ensures the two
// tables. No-op when billing isn't configured.
func RegisterBillingRoutes(mux *http.ServeMux, app *App) {
	cfg := loadBillingConfig(app)
	if cfg == nil {
		return
	}
	ensureBillingTablesReal(app)
	log.Printf("  billing: stripe (webhook=POST /api/_billing/webhook, portal=POST /api/_billing/portal)")

	mux.HandleFunc("POST /api/_billing/webhook", func(w http.ResponseWriter, r *http.Request) {
		handleStripeWebhook(w, r, app, cfg)
	})
	mux.HandleFunc("GET /api/_billing/me", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpError(w, "authentication required", http.StatusUnauthorized)
			return
		}
		row := app.DB.QueryRow(`SELECT id, stripe_subscription_id, status, plan, current_period_end, cancel_at_period_end FROM _benmore_subscriptions WHERE user_id = ? ORDER BY id DESC LIMIT 1`, session.UserID)
		var sub struct {
			ID                 int64   `json:"id"`
			SubscriptionID     string  `json:"stripe_subscription_id"`
			Status             string  `json:"status"`
			Plan               string  `json:"plan"`
			CurrentPeriodEnd   *string `json:"current_period_end"`
			CancelAtPeriodEnd  bool    `json:"cancel_at_period_end"`
		}
		err := row.Scan(&sub.ID, &sub.SubscriptionID, &sub.Status, &sub.Plan, &sub.CurrentPeriodEnd, &sub.CancelAtPeriodEnd)
		w.Header().Set("Content-Type", "application/json")
		if err != nil {
			json.NewEncoder(w).Encode(map[string]any{"status": "none"})
			return
		}
		json.NewEncoder(w).Encode(sub)
	})
	mux.HandleFunc("POST /api/_billing/portal", func(w http.ResponseWriter, r *http.Request) {
		if !validateCSRF(r) && !isBearerAuth(r) {
			httpError(w, "CSRF validation failed", http.StatusForbidden)
			return
		}
		session := getSession(app, r)
		if session == nil {
			httpError(w, "authentication required", http.StatusUnauthorized)
			return
		}
		apiKey := GetEnv(app.Dir, cfg.APIKeyEnv)
		if apiKey == "" {
			httpError(w, "billing not fully configured: "+cfg.APIKeyEnv+" env var is missing", http.StatusServiceUnavailable)
			return
		}
		// Look up Stripe customer id for this user.
		var customerID string
		app.DB.QueryRow("SELECT stripe_customer_id FROM _benmore_subscriptions WHERE user_id = ? LIMIT 1", session.UserID).Scan(&customerID)
		if customerID == "" {
			httpError(w, "no Stripe customer found for this user — complete a checkout first", http.StatusNotFound)
			return
		}
		var body struct {
			ReturnURL string `json:"return_url"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if body.ReturnURL == "" {
			body.ReturnURL = "https://" + r.Host + "/"
		}
		url, err := createStripePortalSession(apiKey, customerID, body.ReturnURL)
		if err != nil {
			httpError(w, "portal session failed: "+err.Error(), http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"url": url})
	})
}

// ensureBillingTables wires the two tables idempotently. The schema
// lives in a constant block so it's easy to scan when reasoning
// about subscription state.
func init() {
	billingTableSchema = `
CREATE TABLE IF NOT EXISTS _benmore_subscriptions (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER,
	stripe_customer_id TEXT,
	stripe_subscription_id TEXT UNIQUE,
	status TEXT,
	plan TEXT,
	current_period_end DATETIME,
	cancel_at_period_end INTEGER DEFAULT 0,
	metadata TEXT,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
	updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_subs_user ON _benmore_subscriptions(user_id);
CREATE INDEX IF NOT EXISTS idx_subs_customer ON _benmore_subscriptions(stripe_customer_id);

CREATE TABLE IF NOT EXISTS _benmore_invoices (
	id INTEGER PRIMARY KEY AUTOINCREMENT,
	user_id INTEGER,
	stripe_customer_id TEXT,
	stripe_invoice_id TEXT UNIQUE,
	stripe_subscription_id TEXT,
	status TEXT,
	amount_cents INTEGER,
	currency TEXT,
	hosted_invoice_url TEXT,
	pdf_url TEXT,
	paid_at DATETIME,
	created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_inv_user ON _benmore_invoices(user_id);
`
}

var billingTableSchema string

func ensureBillingTablesReal(app *App) {
	for _, stmt := range strings.Split(billingTableSchema, ";") {
		s := strings.TrimSpace(stmt)
		if s == "" {
			continue
		}
		if _, err := app.DB.Exec(s); err != nil {
			log.Printf("billing: ensure table: %s — %s", s, err)
		}
	}
}

// handleStripeWebhook verifies the Stripe-Signature header (HMAC-SHA256
// over the timestamp + raw body, with the webhook secret as key) and
// upserts subscription/invoice rows for the events we care about.
func handleStripeWebhook(w http.ResponseWriter, r *http.Request, app *App, cfg *BillingConfig) {
	secret := GetEnv(app.Dir, cfg.WebhookSecretEnv)
	if secret == "" {
		httpError(w, "billing webhook not configured: "+cfg.WebhookSecretEnv+" env var is missing", http.StatusServiceUnavailable)
		return
	}

	payload, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		httpError(w, "read body: "+err.Error(), http.StatusBadRequest)
		return
	}
	sig := r.Header.Get("Stripe-Signature")
	if !verifyStripeSignatureBytes(payload, sig, secret) {
		httpError(w, "invalid signature", http.StatusForbidden)
		return
	}

	var evt struct {
		Type string                 `json:"type"`
		Data struct {
			Object map[string]any `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &evt); err != nil {
		httpError(w, "parse event: "+err.Error(), http.StatusBadRequest)
		return
	}

	ensureBillingTablesReal(app)

	switch evt.Type {
	case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted":
		upsertSubscription(app, evt.Data.Object)
	case "invoice.payment_succeeded", "invoice.payment_failed", "invoice.finalized":
		upsertInvoice(app, evt.Data.Object)
	case "checkout.session.completed":
		// On first checkout the customer was just created; pull the
		// customer.metadata.user_id we set during checkout init.
		obj := evt.Data.Object
		customerID, _ := obj["customer"].(string)
		subscriptionID, _ := obj["subscription"].(string)
		metadata, _ := obj["metadata"].(map[string]any)
		userIDStr, _ := metadata["user_id"].(string)
		if userIDStr != "" && customerID != "" {
			uid, _ := strconv.ParseInt(userIDStr, 10, 64)
			app.DB.Exec(`INSERT INTO _benmore_subscriptions (user_id, stripe_customer_id, stripe_subscription_id, status, plan)
VALUES (?, ?, ?, ?, ?) ON CONFLICT(stripe_subscription_id) DO UPDATE SET user_id = excluded.user_id`,
				uid, customerID, subscriptionID, "active", "")
		}
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

func upsertSubscription(app *App, obj map[string]any) {
	id, _ := obj["id"].(string)
	customerID, _ := obj["customer"].(string)
	status, _ := obj["status"].(string)
	cancel, _ := obj["cancel_at_period_end"].(bool)
	plan := ""
	if items, ok := obj["items"].(map[string]any); ok {
		if dataArr, ok := items["data"].([]any); ok && len(dataArr) > 0 {
			if first, ok := dataArr[0].(map[string]any); ok {
				if price, ok := first["price"].(map[string]any); ok {
					if nick, ok := price["nickname"].(string); ok && nick != "" {
						plan = nick
					} else if pid, ok := price["id"].(string); ok {
						plan = pid
					}
				}
			}
		}
	}
	var periodEnd *time.Time
	if ts, ok := obj["current_period_end"].(float64); ok {
		t := time.Unix(int64(ts), 0).UTC()
		periodEnd = &t
	}
	cancelInt := 0
	if cancel {
		cancelInt = 1
	}
	app.DB.Exec(`INSERT INTO _benmore_subscriptions (stripe_customer_id, stripe_subscription_id, status, plan, current_period_end, cancel_at_period_end)
VALUES (?, ?, ?, ?, ?, ?)
ON CONFLICT(stripe_subscription_id) DO UPDATE SET
	status = excluded.status,
	plan = excluded.plan,
	current_period_end = excluded.current_period_end,
	cancel_at_period_end = excluded.cancel_at_period_end,
	updated_at = CURRENT_TIMESTAMP`,
		customerID, id, status, plan, periodEnd, cancelInt)
}

func upsertInvoice(app *App, obj map[string]any) {
	id, _ := obj["id"].(string)
	customerID, _ := obj["customer"].(string)
	subID, _ := obj["subscription"].(string)
	status, _ := obj["status"].(string)
	currency, _ := obj["currency"].(string)
	hostedURL, _ := obj["hosted_invoice_url"].(string)
	pdfURL, _ := obj["invoice_pdf"].(string)
	amount, _ := obj["amount_paid"].(float64)
	var paidAt *time.Time
	if status == "paid" {
		t := time.Now().UTC()
		paidAt = &t
	}
	app.DB.Exec(`INSERT INTO _benmore_invoices (stripe_customer_id, stripe_invoice_id, stripe_subscription_id, status, amount_cents, currency, hosted_invoice_url, pdf_url, paid_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(stripe_invoice_id) DO UPDATE SET
	status = excluded.status, amount_cents = excluded.amount_cents,
	hosted_invoice_url = excluded.hosted_invoice_url, pdf_url = excluded.pdf_url,
	paid_at = excluded.paid_at`,
		customerID, id, subID, status, int64(amount), currency, hostedURL, pdfURL, paidAt)
}

// verifyStripeSignatureBytes implements Stripe's webhook signature
// scheme against an already-read payload. The framework's existing
// verifyStripeSignature(header, secret, *http.Request) lives in
// flows.go and re-reads the request body internally; here we already
// have the bytes (LimitReader cap), so we accept them directly.
func verifyStripeSignatureBytes(payload []byte, sigHeader, secret string) bool {
	if sigHeader == "" {
		return false
	}
	var ts string
	var sigs []string
	for _, part := range strings.Split(sigHeader, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			ts = kv[1]
		case "v1":
			sigs = append(sigs, kv[1])
		}
	}
	if ts == "" || len(sigs) == 0 {
		return false
	}
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	if time.Since(time.Unix(tsInt, 0)) > 5*time.Minute {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(payload)
	expected := hex.EncodeToString(mac.Sum(nil))
	for _, s := range sigs {
		if hmac.Equal([]byte(s), []byte(expected)) {
			return true
		}
	}
	return false
}

// createStripePortalSession asks Stripe to mint a one-time portal
// URL we can redirect the user to. Customer must already exist (i.e.
// the user has gone through a checkout before).
func createStripePortalSession(apiKey, customerID, returnURL string) (string, error) {
	body := strings.NewReader("customer=" + customerID + "&return_url=" + returnURL)
	req, _ := http.NewRequest("POST", "https://api.stripe.com/v1/billing_portal/sessions", body)
	req.Header.Set("Authorization", "Bearer "+apiKey)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		buf, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("stripe %d: %s", resp.StatusCode, string(buf))
	}
	var out struct {
		URL string `json:"url"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", err
	}
	return out.URL, nil
}
