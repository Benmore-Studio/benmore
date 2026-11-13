//go:build !cli

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// EnsureWebhooksTable creates the webhook subscriptions table.
func EnsureWebhooksTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_webhooks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		url TEXT NOT NULL,
		secret TEXT NOT NULL,
		tables TEXT NOT NULL DEFAULT '',
		events TEXT NOT NULL DEFAULT '',
		active INTEGER NOT NULL DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	db.Exec("CREATE INDEX IF NOT EXISTS idx_webhooks_user ON _benmore_webhooks(user_id)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_webhooks_active ON _benmore_webhooks(active)")
}

// webhookHintMinLen is the shortest secret that gets a last-4 hint: four
// characters of a short secret are most of it.
const webhookHintMinLen = 16

// webhookSecretHint is how the subscription list shows a signing secret:
// masked, with its last four characters when it is long enough for those to
// identify it without giving it away.
func webhookSecretHint(secret string) string {
	if len(secret) < webhookHintMinLen {
		return "****"
	}
	return "****" + secret[len(secret)-4:]
}

// webhookStatusKeyUnreadable marks a subscription whose stored signing
// secret this app's key cannot open (GET /api/_webhooks `status`).
const webhookStatusKeyUnreadable = "secret_unreadable"

// webhookUnreadableKeyFix tells an admin what an unreadable signing secret
// means and how to recover. The secret itself is gone: nothing can re-derive it.
const webhookUnreadableKeyFix = "this subscription's signing secret was sealed under an encryption key the app no longer has (a key generated for a process that has since restarted, before the app saved one, or an ENCRYPTION_KEY changed without the rotation workflow), so every delivery fails. Delete it (DELETE /api/_webhooks/{id}) and create it again with the secret your receiver verifies."

// webhookNoDurableKeyMessage answers a subscription create that cannot seal
// the secret under a key that survives a restart (durableSealKey).
const webhookNoDurableKeyMessage = "webhook subscription secrets are sealed under the app's ENCRYPTION_KEY, and this app has none that survives a restart: its generated key could not be saved to env.yaml. Set ENCRYPTION_KEY and restart the app (hosted, as the app owner: `benmore env <app> set ENCRYPTION_KEY=<64 hex characters> --env <dev|prod>` then `benmore restart <app> --env <dev|prod>`; self-hosted: env.yaml or the process environment), then create the subscription again."

// openWebhookSubscriptionSecret returns the signing secret a subscription row
// stores. A plaintext (pre-encryption) value is returned as is; a sealed one
// this database's key cannot open is an error, never an empty secret.
func openWebhookSubscriptionSecret(app *App, stored string) (string, error) {
	return fieldDecryptForDB(app.DB, stored)
}

// webhookUnreadableWarned remembers the databases whose unreadable
// subscription secrets were already reported (routes re-register on reload).
var webhookUnreadableWarned sync.Map // *sql.DB → true

// warnUnreadableWebhookSecrets logs, once per database per process, how many
// active subscriptions have a signing secret this app's key cannot open.
func warnUnreadableWebhookSecrets(app *App) {
	rows, err := queryMetadataRows(app.DB, "SELECT id, secret FROM _benmore_webhooks WHERE active = 1")
	if err != nil {
		return
	}
	var unreadable []string
	for _, row := range rows {
		if _, err := openWebhookSubscriptionSecret(app, valueText(row["secret"])); err != nil {
			unreadable = append(unreadable, "#"+valueText(row["id"]))
		}
	}
	if len(unreadable) == 0 {
		return
	}
	if _, warned := webhookUnreadableWarned.LoadOrStore(app.DB, true); !warned {
		log.Printf("WEBHOOKS: WARN %d active subscription(s) (%s) have a signing secret this app cannot decrypt; their deliveries fail. GET /api/_webhooks marks them %s: %s", len(unreadable), strings.Join(unreadable, ", "), webhookStatusKeyUnreadable, webhookUnreadableKeyFix)
	}
}

// RegisterWebhookRoutes sets up webhook subscription API endpoints.
func RegisterWebhookRoutes(mux appRouteRegistrar, app *App) {
	EnsureWebhooksTable(app.DB)
	warnUnreadableWebhookSecrets(app)
	registerWebhookRoutes(mux, app)
}

func registerWebhookRoutes(mux appRouteRegistrar, app *App) {
	// POST /api/_webhooks - register a new webhook
	mux.HandleFunc("POST /api/_webhooks", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}

		// CSRF check (skip for Bearer auth)
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}

		// A subscription receives every matching row change in the app,
		// across all users and tenants, so creating one is an admin
		// capability (a stepped-in/act-as admin does not qualify).
		if !session.IsAdminBypass() || !session.IsAdminConsole() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "webhook subscriptions receive every row change in the app; only app admins can create them"})
			return
		}

		// Rate limit: max 10 webhooks per user
		var count int
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_webhooks WHERE user_id = ?", session.UserID).Scan(&count)
		if count >= 10 {
			httpJSON(w, http.StatusTooManyRequests, map[string]any{"error": "maximum 10 webhooks per user"})
			return
		}

		// Parse request body
		var req struct {
			URL    string `json:"url"`
			Secret string `json:"secret"`
			Tables string `json:"tables"`
			Events string `json:"events"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			// Fall back to form values
			req.URL = r.FormValue("url")
			req.Secret = r.FormValue("secret")
			req.Tables = r.FormValue("tables")
			req.Events = r.FormValue("events")
		}

		// Validate required fields
		if req.URL == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "url is required"})
			return
		}
		if req.Secret == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "secret is required"})
			return
		}

		// URL scheme validation: only http:// and https:// allowed
		parsed, err := url.Parse(req.URL)
		if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "url must use http:// or https:// scheme"})
			return
		}

		// SSRF protection: reject private/internal URLs
		if isPrivateURL(req.URL) {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "url must not point to a private or internal address"})
			return
		}

		// Validate events if provided
		if req.Events != "" {
			validEvents := map[string]bool{"insert": true, "update": true, "delete": true}
			for _, ev := range strings.Split(req.Events, ",") {
				ev = strings.TrimSpace(ev)
				if ev != "" && !validEvents[ev] {
					httpJSON(w, http.StatusBadRequest, map[string]any{"error": fmt.Sprintf("invalid event: %s (must be insert, update, or delete)", ev)})
					return
				}
			}
		}

		// M-6: encrypt the subscriber secret at rest (parity with OAuth
		// tokens). The secret is HMAC key material - storing it cleartext on
		// disk is a direct compromise path if the DB file leaks. Every
		// delivery decrypts it, so it is sealed only under a key that
		// survives a restart: an app without a configured ENCRYPTION_KEY
		// saves its generated key to env.yaml first, and when it can't the
		// subscription is refused rather than sealed under a key the next
		// restart loses (fieldEncryptForDB → durableSealKey).
		encSecret, encErr := fieldEncryptForDB(app.DB, req.Secret)
		if encErr != nil {
			if errors.Is(encErr, errNoDurableEncryptionKey) {
				serverErrorJSONBody(w, r, app, http.StatusServiceUnavailable, "_webhooks", fmt.Errorf("encrypt secret: %w", encErr), withRefusalDocs(map[string]any{
					"error": webhookNoDurableKeyMessage,
					"code":  "encryption_key_not_durable",
				}, "encryption_key_not_durable"))
				return
			}
			serverErrorJSON(w, r, app, "_webhooks", fmt.Errorf("encrypt secret: %w", encErr), "failed to create webhook")
			return
		}

		result, err := app.DB.Exec(
			"INSERT INTO _benmore_webhooks (user_id, url, secret, tables, events) VALUES (?, ?, ?, ?, ?)",
			session.UserID, req.URL, encSecret, req.Tables, req.Events,
		)
		if err != nil {
			serverErrorJSON(w, r, app, "_webhooks", err, "failed to create webhook")
			return
		}

		id, _ := result.LastInsertId()
		httpJSON(w, http.StatusCreated, map[string]any{
			"id":     id,
			"status": "created",
		})
	})

	// GET /api/_webhooks - list webhooks (own only, admin sees all)
	mux.HandleFunc("GET /api/_webhooks", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}

		var rows []map[string]any
		var err error
		if session.IsAdminConsole() {
			rows, err = queryMetadataRows(app.DB, "SELECT id, user_id, url, secret, tables, events, active, created_at FROM _benmore_webhooks ORDER BY created_at DESC")
		} else {
			rows, err = queryMetadataRows(app.DB, "SELECT id, user_id, url, secret, tables, events, active, created_at FROM _benmore_webhooks WHERE user_id = ? ORDER BY created_at DESC", session.UserID)
		}
		if err != nil {
			serverErrorJSON(w, r, app, "_webhooks", err, "failed to list webhooks")
			return
		}

		// Mask secrets: show only last 4 chars. Decrypt first (M-6) so the
		// last-4 hint reflects the real secret, not ciphertext bytes.
		// fieldDecrypt passes through values that were stored cleartext
		// (no encPrefix), so pre-encryption rows keep working. A secret the
		// app's key cannot open is reported, not shown as an ordinary `****`:
		// every delivery of that subscription fails until it is re-created.
		for _, row := range rows {
			row["status"] = "active"
			if valueText(row["active"]) != "1" {
				row["status"] = "inactive"
			}
			stored, ok := row["secret"].(string)
			if !ok {
				continue
			}
			secret, err := openWebhookSubscriptionSecret(app, stored)
			if err != nil {
				row["secret"] = "****"
				row["status"] = webhookStatusKeyUnreadable
				row["fix"] = webhookUnreadableKeyFix
				continue
			}
			row["secret"] = webhookSecretHint(secret)
		}

		httpJSON(w, http.StatusOK, map[string]any{"webhooks": rows})
	})

	// DELETE /api/_webhooks/{id} - unregister webhook (own only, admin can delete any)
	mux.HandleFunc("DELETE /api/_webhooks/{id}", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}

		// CSRF check (skip for Bearer auth)
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}

		id := r.PathValue("id")

		var result sql.Result
		var err error
		if session.IsAdminConsole() {
			result, err = app.DB.Exec("DELETE FROM _benmore_webhooks WHERE id = ?", id)
		} else {
			result, err = app.DB.Exec("DELETE FROM _benmore_webhooks WHERE id = ? AND user_id = ?", id, session.UserID)
		}
		if err != nil {
			serverErrorJSON(w, r, app, "_webhooks", err, "failed to delete webhook")
			return
		}
		affected, _ := result.RowsAffected()
		if affected == 0 {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "webhook not found"})
			return
		}

		httpJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
	})
}

// enqueueWebhookSubscriptionsTx stores matching deliveries with the mutation,
// so a committed update cannot lose its webhook intent on a process crash.
// row is the stored row before injectSessionContext (webhookDataRow).
func enqueueWebhookSubscriptionsTx(tx mutationTx, app *App, event, table string, row map[string]any, session *Session) error {
	if strings.HasPrefix(table, "_benmore_") {
		return nil
	}
	rows, err := queryMetadataRows(tx, "SELECT id, user_id, url, tables, events FROM main._benmore_webhooks WHERE active = 1")
	if isNoSuchTable(err) {
		return nil // no subscription table, no subscriptions
	}
	if err != nil {
		return fmt.Errorf("read webhook subscriptions: %w", err)
	}
	payloadRow := webhookDataRow(app, table, row, session)
	adminCache := map[string]bool{}
	for _, wh := range rows {
		ownerKey := valueText(wh["user_id"])
		allowed, seen := adminCache[ownerKey]
		if !seen {
			var checkErr error
			allowed, checkErr = webhookOwnerIsActiveAdminChecked(tx, wh["user_id"])
			if checkErr != nil {
				return fmt.Errorf("check webhook subscription owner: %w", checkErr)
			}
			adminCache[ownerKey] = allowed
		}
		if !allowed || !webhookSubscriptionMatches(wh, table, event) {
			continue
		}
		// No signing secret in the job: admins can read job payloads
		// (GET /api/_jobs/{id}); delivery reads it from the subscription row.
		payload := map[string]any{"_webhook_subscription": map[string]any{
			"webhook_id": valueText(wh["id"]), "url": valueText(wh["url"]),
			"event": event, "table": table,
		}, "_row": payloadRow}
		if session != nil {
			meta := payload["_webhook_subscription"].(map[string]any)
			meta["user_email"], meta["user_id"] = session.Email, session.UserID
		}
		if err := sealJobPayloadRow(tx, app, table, payload); err != nil {
			return fmt.Errorf("enqueue webhook subscription: %w", err)
		}
		if err := enqueueMutationJob(tx, "webhook", table, event, "webhook_subscription", "webhook_subscription", payload); err != nil {
			return fmt.Errorf("enqueue webhook subscription: %w", err)
		}
	}
	return nil
}

// webhookDataRow is a subscription delivery's `data` for a row change. stored
// is the row as the table holds it (with old_<col> copies on update), taken
// before injectSessionContext. A receiver reads `data` as the changed row, so
// a session-context name that is a column of the table keeps the row's own
// value: an admin editing alice's ticket is delivered with alice's user_id,
// not the admin's next to old_user_id = alice. Names that are not columns
// carry the caller's session context, as they always have, except the
// internal authorization flags (sessionInternalContextKeys), which never
// leave the app. The actor is on the envelope (triggered_by,
// triggered_by_user_id). Hook SQL, when:, templates and event flows keep
// reading the actor under these names.
func webhookDataRow(app *App, table string, stored map[string]any, session *Session) map[string]any {
	data := copyRow(stored)
	injectSessionContext(data, session)
	for _, key := range sessionContextKeys {
		own, present := stored[key]
		switch {
		case present:
			data[key] = own
		case hasColumn(app, table, key) || sessionInternalContextKey(key):
			// A column this event didn't carry (a create that left it to
			// its default): not the actor's value under the row's name.
			delete(data, key)
		}
	}
	return webhookPayloadRow(app, table, data)
}

// webhookPayloadRow is the row a subscription delivery carries. A delivery is
// a response leaving the app: it has the columns an API read would
// (apiHiddenColumn), not `*_secret`/`*_token` values or their old_* deltas.
func webhookPayloadRow(app *App, table string, row map[string]any) map[string]any {
	payloadRow := make(map[string]any, len(row))
	for k, v := range row {
		if !hiddenEventKey(app, table, k) {
			payloadRow[k] = v
		}
	}
	return payloadRow
}

func webhookSubscriptionMatches(wh map[string]any, table, event string) bool {
	for key, wanted := range map[string]string{"tables": table, "events": event} {
		value := valueText(wh[key])
		if value == "" || value == "<nil>" {
			continue
		}
		matched := false
		for _, candidate := range strings.Split(value, ",") {
			if strings.TrimSpace(candidate) == wanted {
				matched = true
				break
			}
		}
		if !matched {
			return false
		}
	}
	return true
}

// executeWebhookSubscriptionJob delivers a webhook subscription payload.
// Called from the job worker in jobs.go.
func executeWebhookSubscriptionJob(data map[string]any, app *App) error {
	whData, ok := data["_webhook_subscription"].(map[string]any)
	if !ok {
		return fmt.Errorf("missing _webhook_subscription in payload")
	}
	// Re-check the subscription at delivery, including every retry: one
	// deleted or deactivated after this job was queued, pointed elsewhere,
	// or whose owner is no longer an active admin gets nothing. The check
	// at enqueue alone left queued and backing-off deliveries (and crash
	// requeues) sending rows to an endpoint the admin had just removed.
	var (
		subURL, subSecret string
		subActive         int
		subOwner          int64
	)
	webhookID := valueText(whData["webhook_id"])
	// A delivery that is dropped sent nothing. An ordinary job still completes
	// (the subscriber asked for nothing more); a connector-command effect fails,
	// so its status never reads delivered.
	_, commandEffect := data[appMCPEffectKey]
	dropped := func(reason string) error {
		if commandEffect {
			return jobNotRetryable{errors.New("dropped: " + reason)}
		}
		return nil
	}
	lookupErr := app.DB.QueryRow("SELECT url, secret, active, user_id FROM _benmore_webhooks WHERE id = ?", webhookID).
		Scan(&subURL, &subSecret, &subActive, &subOwner)
	switch {
	case lookupErr == sql.ErrNoRows:
		log.Printf("WEBHOOK SUBSCRIPTION #%s removed before delivery; dropped", webhookID)
		return dropped("subscription removed")
	case lookupErr != nil:
		return fmt.Errorf("webhook subscription lookup: %w", lookupErr)
	case subActive != 1:
		log.Printf("WEBHOOK SUBSCRIPTION #%s inactive; delivery dropped", webhookID)
		return dropped("subscription inactive")
	case !webhookOwnerIsActiveAdmin(app, subOwner):
		log.Printf("WEBHOOK SUBSCRIPTION #%s owner is no longer an active admin; delivery dropped", webhookID)
		return dropped("subscription owner is no longer an active admin")
	case valueText(whData["url"]) != subURL:
		log.Printf("WEBHOOK SUBSCRIPTION #%s URL changed after the delivery was queued; dropped", webhookID)
		return dropped("subscription URL changed")
	}
	whURL := subURL
	// M-6: the secret is stored encrypted in the webhooks table; decrypt it
	// here at the only point it's actually needed (HMAC signing).
	// fieldDecrypt is a pass-through for cleartext (pre-encryption) values.
	// A secret the app's key cannot open stays unreadable on every retry, so
	// the delivery fails once with the reason instead of retrying.
	secret, decryptErr := openWebhookSubscriptionSecret(app, subSecret)
	if decryptErr != nil {
		log.Printf("WEBHOOK SUBSCRIPTION #%s: signing secret unreadable; delivery failed without retry: %s", webhookID, webhookUnreadableKeyFix)
		return jobNotRetryable{fmt.Errorf("webhook subscription #%s %s: %s", webhookID, webhookStatusKeyUnreadable, webhookUnreadableKeyFix)}
	}
	event := valueText(whData["event"])
	table := valueText(whData["table"])

	// SSRF protection: re-validate at delivery time (URL could have been modified)
	if isPrivateURL(whURL) {
		log.Printf("SECURITY: blocked webhook subscription delivery to private host: %s", webhookHostForLog(whURL))
		return jobNotRetryable{errors.New(appMCPEffectBlockedPrefix + "private webhook destination")}
	}

	// Circuit breaker: skip if endpoint is known-dead. Nothing is sent, so
	// the delivery waits for the cooldown without spending an attempt: an
	// outage longer than the retry backoff used to fail every queued
	// delivery without one request reaching the endpoint.
	host := circuitKey(app, whURL)
	if err := CheckCircuit(host); err != nil {
		var open *circuitOpenError
		if errors.As(err, &open) {
			return jobDeferred{error: fmt.Errorf("circuit open: %s", err), until: open.retryAt}
		}
		return fmt.Errorf("circuit open: %s", err)
	}

	// The row as it was queued, with sealed encrypted.yaml values opened.
	rowData, err := openJobPayloadRow(app, data, table)
	if err != nil {
		return err
	}
	if rowData == nil {
		rowData = make(map[string]any)
	}

	bodyBytes, err := json.Marshal(webhookSubscriptionBody(whData, event, table, rowData, time.Now()))
	if err != nil {
		return fmt.Errorf("failed to marshal webhook body: %s", err)
	}

	ts := fmt.Sprintf("%d", time.Now().Unix())
	// Legacy body-only v0 signature has NO timestamp binding, so a receiver
	// that honors it is replayable indefinitely. It is now OFF by default
	// (round-2): operators mid-migration can re-enable it for one transition
	// window via BENMORE_WEBHOOK_LEGACY_V0=1. New receivers should verify v1
	// (t.body) only.
	emitV0 := strings.EqualFold(strings.TrimSpace(GetEnv(app.Dir, "BENMORE_WEBHOOK_LEGACY_V0")), "1") ||
		strings.EqualFold(strings.TrimSpace(GetEnv(app.Dir, "BENMORE_WEBHOOK_LEGACY_V0")), "true")

	// Send the webhook
	req, err := http.NewRequest("POST", whURL, strings.NewReader(string(bodyBytes)))
	if err != nil {
		RecordFailure(host)
		return jobNotRetryable{errors.New("webhook request could not be built")}
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Webhook-Signature", webhookSubscriptionSignature(secret, ts, bodyBytes, emitV0))
	req.Header.Set("X-Webhook-Timestamp", ts)
	req.Header.Set("X-Webhook-Event", event)
	req.Header.Set("X-Webhook-Table", table)

	client := safeHTTPClientStrict(10 * time.Second)
	status, err := postWebhook(client, req)
	if err != nil {
		RecordFailure(host)
		return webhookDeliveryError(err, commandEffect)
	}

	RecordSuccess(host)
	log.Printf("WEBHOOK SUBSCRIPTION [%s/%s] %s -> %d", event, table, webhookHostForLog(whURL), status)
	return nil
}

// webhookSubscriptionSignature is a delivery's X-Webhook-Signature value:
// `t=<ts>,v1=<hex(HMAC-SHA256(secret, ts + "." + body))>`, the envelope
// shape Stripe uses. The timestamp is signed and sent outside the body so a
// receiver can refuse a replay (`verify: benmore` allows 5 minutes either
// way, flows_verify.go). The v1 prefix leaves room to rotate the scheme;
// legacyV0 adds the old body-only signature as v0 for a receiver still
// migrating off it (it binds no timestamp, so it is replayable).
func webhookSubscriptionSignature(secret, ts string, body []byte, legacyV0 bool) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(body)
	v1 := hex.EncodeToString(mac.Sum(nil))
	if !legacyV0 {
		return fmt.Sprintf("t=%s,v1=%s", ts, v1)
	}
	legacy := hmac.New(sha256.New, []byte(secret))
	legacy.Write(body)
	return fmt.Sprintf("t=%s,v0=%s,v1=%s", ts, hex.EncodeToString(legacy.Sum(nil)), v1)
}

// webhookSubscriptionBody is the signed delivery envelope. `data` is the row
// (webhookDataRow); who made the change is the envelope's: triggered_by (the
// actor's email) and triggered_by_user_id, from the session that queued the
// delivery. A sessionless change carries neither.
func webhookSubscriptionBody(whData map[string]any, event, table string, rowData map[string]any, now time.Time) map[string]any {
	body := map[string]any{
		"event":     event,
		"table":     table,
		"data":      rowData,
		"timestamp": now.UTC().Format(time.RFC3339),
	}
	if userEmail, ok := whData["user_email"]; ok {
		body["triggered_by"] = userEmail
	}
	if userID, ok := whData["user_id"]; ok {
		body["triggered_by_user_id"] = userID
	}
	return body
}

// webhookOwnerIsActiveAdmin mirrors Session.IsAdmin for a stored subscriber:
// the primary role column or an unexpired global admin grant, on an account
// that is not deactivated.
func webhookOwnerIsActiveAdmin(app *App, userID any) bool {
	allowed, _ := webhookOwnerIsActiveAdminChecked(app.DB, userID)
	return allowed
}

func webhookOwnerIsActiveAdminChecked(db rowQuerier, userID any) (bool, error) {
	uid := toInt64(userID)
	if uid <= 0 {
		return false, nil
	}
	var role string
	var deactivated sql.NullString
	if err := db.QueryRow("SELECT COALESCE(role,''), deactivated_at FROM main._benmore_users WHERE id = ?", uid).Scan(&role, &deactivated); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, err
	}
	if accountDeactivated(deactivated) {
		return false, nil
	}
	if role == "admin" {
		return true, nil
	}
	return userHasGlobalAdminGrantWithSchema(db, uid, "main")
}
