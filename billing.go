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
//   _benmore_subscriptions  - one row per Stripe Subscription, scoped
//                             by user_id when the customer's metadata
//                             carries `user_id`.
//   _benmore_invoices       - one row per Stripe Invoice.
//
// Endpoints:
//   POST /api/_billing/webhook   - signature-verified, syncs state
//   GET  /api/_billing/me        - returns current user's subscription
//   POST /api/_billing/portal    - redirects to Stripe Customer Portal
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
	"net/url"
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
func RegisterBillingRoutes(mux appRouteRegistrar, app *App) {
	if loadBillingConfig(app) == nil {
		return
	}
	ensureBillingTablesReal(app)
	registerBillingRoutes(mux, app)
}

func registerBillingRoutes(mux appRouteRegistrar, app *App) {
	cfg := loadBillingConfig(app)
	if cfg == nil {
		return
	}
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
			ID                int64   `json:"id"`
			SubscriptionID    string  `json:"stripe_subscription_id"`
			Status            string  `json:"status"`
			Plan              string  `json:"plan"`
			CurrentPeriodEnd  *string `json:"current_period_end"`
			CancelAtPeriodEnd bool    `json:"cancel_at_period_end"`
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
			httpError(w, "no Stripe customer found for this user - complete a checkout first", http.StatusNotFound)
			return
		}
		var body struct {
			ReturnURL string `json:"return_url"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		returnURL, ok := billingPortalReturnURL(app, r, body.ReturnURL)
		if !ok {
			httpError(w, "return_url must be a path or a URL on this app's own origin", http.StatusBadRequest)
			return
		}
		url, err := createStripePortalSession(apiKey, customerID, returnURL)
		if err != nil {
			// Stripe's error body names the account (dashboard log URLs, a
			// masked key); it goes to the log, not to the app's end user.
			serverErrorStatus(w, r, app, http.StatusBadGateway, "billing portal", err, "portal session failed")
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"url": url})
	})
}

// billingPortalReturnURL vets where the Stripe portal sends the customer
// back. Empty means the request's own origin; a path ("/account") is made
// absolute on it; an absolute http(s) URL must be on the request's host or
// the app's configured public origin (seo.url, BENMORE_PUBLIC_URL or
// CORS_ORIGIN). Anything else - another site, a scheme-relative "//host",
// credentials in the authority, a backslash a browser reads as "/" - is
// refused, so app code that forwards a query parameter can't be turned into
// an open redirect.
func billingPortalReturnURL(app *App, r *http.Request, raw string) (string, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "https://" + r.Host + "/", true
	}
	if strings.ContainsAny(raw, "\\") || strings.ContainsFunc(raw, func(c rune) bool { return c < 0x20 || c == 0x7f }) {
		return "", false
	}
	if strings.HasPrefix(raw, "/") && !strings.HasPrefix(raw, "//") {
		return "https://" + r.Host + raw, true
	}
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Host == "" || u.Opaque != "" {
		return "", false
	}
	if scheme := strings.ToLower(u.Scheme); scheme != "https" && scheme != "http" {
		return "", false
	}
	allowed := []string{r.Host}
	if app != nil && app.Design != nil {
		allowed = append(allowed, app.Design.SEO["url"])
	}
	allowed = append(allowed, uploadsCanonicalOrigin(app))
	want := billingHostKey(u.Host)
	for _, origin := range allowed {
		host := origin
		if strings.Contains(origin, "://") {
			o, err := url.Parse(origin)
			if err != nil {
				continue
			}
			host = o.Host
		}
		if host != "" && billingHostKey(host) == want {
			return raw, true
		}
	}
	return "", false
}

// billingHostKey lowercases a host[:port] and drops a default port and a
// trailing dot, so "App.Example:443" and "app.example" compare equal.
func billingHostKey(host string) string {
	host = strings.ToLower(host)
	host = strings.TrimSuffix(strings.TrimSuffix(host, ":443"), ":80")
	return strings.TrimSuffix(host, ".")
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

CREATE TABLE IF NOT EXISTS _benmore_billing_events (
	id TEXT PRIMARY KEY,
	type TEXT NOT NULL DEFAULT '',
	received_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
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
			log.Printf("billing: ensure table: %s - %s", s, err)
		}
	}
	// Stripe delivers events at least once and in no guaranteed order:
	// stripe_event_created is the `created` time of the newest event applied
	// to the row, so an older event never overwrites newer state. Rows from
	// before the column start at 0 and accept the next event.
	for _, table := range []string{"_benmore_subscriptions", "_benmore_invoices"} {
		if billingColumnExists(app, table, "stripe_event_created") {
			continue
		}
		if _, err := app.DB.Exec(`ALTER TABLE ` + table + ` ADD COLUMN stripe_event_created INTEGER NOT NULL DEFAULT 0`); err != nil && !billingColumnExists(app, table, "stripe_event_created") {
			log.Printf("billing: add %s.stripe_event_created: %s", table, err)
		}
	}
}

func billingColumnExists(app *App, table, column string) bool {
	rows, err := app.DB.Query(`SELECT name FROM pragma_table_info(?)`, table)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil && name == column {
			return true
		}
	}
	return false
}

// billingEventSeen reports whether the event id was already handled.
func billingEventSeen(app *App, id string) bool {
	if id == "" {
		return false
	}
	var n int
	app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_billing_events WHERE id = ?`, id).Scan(&n)
	return n > 0
}

// recordBillingEvent remembers a handled event id. Stripe retries a delivery
// for up to three days, so ids older than that window are pruned.
func recordBillingEvent(app *App, id, typ string) {
	if id == "" {
		return
	}
	if _, err := app.DB.Exec(`INSERT OR IGNORE INTO _benmore_billing_events (id, type) VALUES (?, ?)`, id, typ); err != nil {
		log.Printf("billing: record event %s: %v", id, err)
	}
	app.DB.Exec(`DELETE FROM _benmore_billing_events WHERE received_at < datetime('now', '-35 days')`)
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
		ID      string `json:"id"`
		Created int64  `json:"created"`
		Type    string `json:"type"`
		Data    struct {
			Object map[string]any `json:"object"`
		} `json:"data"`
	}
	if err := json.Unmarshal(payload, &evt); err != nil {
		httpError(w, "parse event: "+err.Error(), http.StatusBadRequest)
		return
	}

	ensureBillingTablesReal(app)

	// A redelivered event was already applied.
	if billingEventSeen(app, evt.ID) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true}`))
		return
	}

	switch evt.Type {
	case "customer.subscription.created", "customer.subscription.updated", "customer.subscription.deleted":
		upsertSubscription(app, evt.Data.Object, evt.Created)
	case "invoice.payment_succeeded", "invoice.payment_failed", "invoice.finalized":
		upsertInvoice(app, evt.Data.Object, evt.Created)
	case "checkout.session.completed":
		// On first checkout the customer was just created; pull the
		// customer.metadata.user_id we set during checkout init.
		obj := evt.Data.Object
		customerID, _ := obj["customer"].(string)
		subscriptionID, _ := obj["subscription"].(string)
		metadata, _ := obj["metadata"].(map[string]any)
		userIDStr, _ := metadata["user_id"].(string)
		// Only subscription checkouts belong in _benmore_subscriptions. A
		// one-time payment has no subscription id; stored as '' it collided
		// on the UNIQUE key, and the upsert handed the previous buyer's row
		// (and Stripe customer, which the portal endpoint then opens) to
		// whoever checked out next.
		if userIDStr != "" && customerID != "" && subscriptionID != "" {
			uid, _ := strconv.ParseInt(userIDStr, 10, 64)
			app.DB.Exec(`INSERT INTO _benmore_subscriptions (user_id, stripe_customer_id, stripe_subscription_id, status, plan)
VALUES (?, ?, ?, ?, ?) ON CONFLICT(stripe_subscription_id) DO UPDATE SET user_id = excluded.user_id`,
				uid, customerID, subscriptionID, "active", "")
		}
	}
	recordBillingEvent(app, evt.ID, evt.Type)
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(`{"ok":true}`))
}

// upsertSubscription applies a subscription event unless the row already holds
// a newer one (eventCreated older than stripe_event_created) or the
// subscription has ended: Stripe never reactivates a canceled or
// incomplete_expired subscription, so an update from the same second as the
// cancellation can't revive it either.
func upsertSubscription(app *App, obj map[string]any, eventCreated int64) {
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
	app.DB.Exec(`INSERT INTO _benmore_subscriptions (stripe_customer_id, stripe_subscription_id, status, plan, current_period_end, cancel_at_period_end, stripe_event_created)
VALUES (?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(stripe_subscription_id) DO UPDATE SET
	status = excluded.status,
	plan = excluded.plan,
	current_period_end = excluded.current_period_end,
	cancel_at_period_end = excluded.cancel_at_period_end,
	stripe_event_created = excluded.stripe_event_created,
	updated_at = CURRENT_TIMESTAMP
WHERE excluded.stripe_event_created >= _benmore_subscriptions.stripe_event_created
  AND COALESCE(_benmore_subscriptions.status, '') NOT IN ('canceled', 'incomplete_expired')`,
		customerID, id, status, plan, periodEnd, cancelInt, eventCreated)
}

// upsertInvoice applies an invoice event unless the row already holds a newer
// one, so a late invoice.finalized can't turn a paid invoice back to open.
func upsertInvoice(app *App, obj map[string]any, eventCreated int64) {
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
	app.DB.Exec(`INSERT INTO _benmore_invoices (stripe_customer_id, stripe_invoice_id, stripe_subscription_id, status, amount_cents, currency, hosted_invoice_url, pdf_url, paid_at, stripe_event_created)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(stripe_invoice_id) DO UPDATE SET
	status = excluded.status, amount_cents = excluded.amount_cents,
	hosted_invoice_url = excluded.hosted_invoice_url, pdf_url = excluded.pdf_url,
	paid_at = excluded.paid_at, stripe_event_created = excluded.stripe_event_created
WHERE excluded.stripe_event_created >= _benmore_invoices.stripe_event_created`,
		customerID, id, subID, status, int64(amount), currency, hostedURL, pdfURL, paidAt, eventCreated)
}

// verifyStripeSignatureBytes implements Stripe's webhook signature
// scheme against an already-read payload. The framework's existing
// verifyStripeSignature(header, secret, *http.Request) lives in
// flows_verify.go and re-reads the request body internally; here we already
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
	// Encode both fields: return_url comes from the caller, and raw
	// concatenation let a value like "...&customer=cus_other" add its own
	// form fields to the request, including a second customer.
	body := strings.NewReader(url.Values{"customer": {customerID}, "return_url": {returnURL}}.Encode())
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
