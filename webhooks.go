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

// RegisterWebhookRoutes sets up webhook subscription API endpoints.
func RegisterWebhookRoutes(mux appRouteRegistrar, app *App) {
	EnsureWebhooksTable(app.DB)
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
		// tokens, which already use fieldEncrypt). The secret is HMAC key
		// material - storing it cleartext on disk is a direct compromise
		// path if the DB file leaks. fieldEncrypt is a no-op when no
		// ENCRYPTION_KEY is configured, so this stays backward-compatible.
		encSecret, encErr := fieldEncryptForDB(app.DB, req.Secret)
		if encErr != nil {
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
		// (no encPrefix), so pre-encryption rows keep working.
		for _, row := range rows {
			if secret, ok := row["secret"].(string); ok {
				secret, _ = fieldDecryptForDB(app.DB, secret)
				row["secret"] = webhookSecretHint(secret)
			}
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

// FireWebhookSubscriptions checks for matching webhook subscriptions and enqueues delivery jobs.
// Called from the CRUD mutation handlers after hooks and flows fire on each CRUD mutation.
func FireWebhookSubscriptions(app *App, event string, table string, row map[string]any, session *Session) {
	// Don't fire webhooks for internal framework tables
	if strings.HasPrefix(table, "_benmore_") {
		return
	}

	// Query active webhooks that match this table and event
	rows, err := queryMetadataRows(app.DB,
		"SELECT id, user_id, url, tables, events FROM _benmore_webhooks WHERE active = 1",
	)
	if err != nil || len(rows) == 0 {
		return
	}
	payloadRow := webhookPayloadRow(app, table, row)

	// Deliver only for subscribers who are STILL active global admins: a
	// subscription created before this check existed, or by a user since
	// demoted or deactivated, must stop receiving other users' data.
	adminCache := map[string]bool{}
	for _, wh := range rows {
		ownerKey := fmt.Sprintf("%v", wh["user_id"])
		allowed, seen := adminCache[ownerKey]
		if !seen {
			allowed = webhookOwnerIsActiveAdmin(app, wh["user_id"])
			adminCache[ownerKey] = allowed
		}
		if !allowed {
			continue
		}
		whID := fmt.Sprintf("%v", wh["id"])
		whURL := fmt.Sprintf("%v", wh["url"])
		whTables := fmt.Sprintf("%v", wh["tables"])
		whEvents := fmt.Sprintf("%v", wh["events"])

		// Filter by table if specified
		if whTables != "" && whTables != "<nil>" {
			matched := false
			for _, t := range strings.Split(whTables, ",") {
				if strings.TrimSpace(t) == table {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// Filter by event if specified
		if whEvents != "" && whEvents != "<nil>" {
			matched := false
			for _, ev := range strings.Split(whEvents, ",") {
				if strings.TrimSpace(ev) == event {
					matched = true
					break
				}
			}
			if !matched {
				continue
			}
		}

		// Enqueue webhook delivery as a job (async, never blocks the CRUD response)
		EnqueueWebhookSubscriptionJob(app, whID, whURL, event, table, payloadRow, session)
	}
}

// enqueueWebhookSubscriptionsTx stores matching deliveries with the mutation,
// so a committed update cannot lose its webhook intent on a process crash.
func enqueueWebhookSubscriptionsTx(tx mutationTx, app *App, event, table string, row map[string]any, session *Session) error {
	if strings.HasPrefix(table, "_benmore_") {
		return nil
	}
	rows, err := queryMetadataRows(tx, "SELECT id, user_id, url, tables, events FROM main._benmore_webhooks WHERE active = 1")
	if err != nil {
		return fmt.Errorf("read webhook subscriptions: %w", err)
	}
	payloadRow := webhookPayloadRow(app, table, row)
	adminCache := map[string]bool{}
	for _, wh := range rows {
		ownerKey := fmt.Sprint(wh["user_id"])
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
		// No signing secret in the job (see EnqueueWebhookSubscriptionJob):
		// delivery reads it from the subscription row.
		payload := map[string]any{"_webhook_subscription": map[string]any{
			"webhook_id": fmt.Sprint(wh["id"]), "url": fmt.Sprint(wh["url"]),
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
		value := fmt.Sprint(wh[key])
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

// EnqueueWebhookSubscriptionJob adds a webhook subscription delivery to the job queue.
// The signing secret is not copied into the job: admins can read job payloads
// (GET /api/_jobs/{id}), while the subscription list shows only its last four
// characters. Delivery reads it from the subscription row. The row's
// encrypted.yaml values are sealed (sealJobPayloadRow); a delivery whose row
// can't be sealed is not queued.
func EnqueueWebhookSubscriptionJob(app *App, webhookID, webhookURL, event, table string, row map[string]any, session *Session) {
	payload := map[string]any{
		"_webhook_subscription": map[string]any{
			"webhook_id": webhookID,
			"url":        webhookURL,
			"event":      event,
			"table":      table,
		},
		"_row": row,
	}
	if session != nil {
		payload["_webhook_subscription"].(map[string]any)["user_email"] = session.Email
		payload["_webhook_subscription"].(map[string]any)["user_id"] = session.UserID
	}
	if err := sealJobPayloadRow(app.DB, app, table, payload); err != nil {
		log.Printf("WEBHOOK SUBSCRIPTION #%s not queued: %s", webhookID, err)
		return
	}

	data, _ := json.Marshal(payload)
	app.DB.Exec(
		"INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at) VALUES ('webhook_subscription', 'webhook_subscription', ?, datetime('now'))",
		string(data),
	)
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
	webhookID := fmt.Sprintf("%v", whData["webhook_id"])
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
	case fmt.Sprintf("%v", whData["url"]) != subURL:
		log.Printf("WEBHOOK SUBSCRIPTION #%s URL changed after the delivery was queued; dropped", webhookID)
		return dropped("subscription URL changed")
	}
	whURL := subURL
	// M-6: the secret is stored encrypted in the webhooks table; decrypt it
	// here at the only point it's actually needed (HMAC signing).
	// fieldDecrypt is a pass-through for cleartext (pre-encryption) values.
	secret, decryptErr := fieldDecryptForDB(app.DB, subSecret)
	if decryptErr != nil {
		return fmt.Errorf("webhook secret decryption failed")
	}
	event := fmt.Sprintf("%v", whData["event"])
	table := fmt.Sprintf("%v", whData["table"])

	// SSRF protection: re-validate at delivery time (URL could have been modified)
	if isPrivateURL(whURL) {
		log.Printf("SECURITY: blocked webhook subscription delivery to private host: %s", webhookHostForLog(whURL))
		return jobNotRetryable{errors.New(appMCPEffectBlockedPrefix + "private webhook destination")}
	}

	// Circuit breaker: skip if endpoint is known-dead
	host := circuitKey(app, whURL)
	if err := CheckCircuit(host); err != nil {
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

	// Build the payload
	body := map[string]any{
		"event":     event,
		"table":     table,
		"data":      rowData,
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}
	if userEmail, ok := whData["user_email"]; ok {
		body["triggered_by"] = userEmail
	}

	bodyBytes, err := json.Marshal(body)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook body: %s", err)
	}

	// Compute HMAC-SHA256 signature over `<timestamp>.<body>` - same
	// envelope shape Stripe uses. The timestamp is the same value we put
	// in the body but receivers need it OUTSIDE the body for replay
	// protection (they reject deliveries where |now - ts| > 5min). The
	// v1 prefix gives us room to rotate signature schemes later without
	// breaking existing receivers; v0 is reserved for the previous
	// body-only signature so legacy receivers can detect it explicitly.
	ts := fmt.Sprintf("%d", time.Now().Unix())
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(bodyBytes)
	v1Sig := hex.EncodeToString(mac.Sum(nil))

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
	// Stripe-style combined header so receivers can pick the version they
	// trust without parsing two separate signature headers.
	sigHeader := fmt.Sprintf("t=%s,v1=%s", ts, v1Sig)
	if emitV0 {
		macLegacy := hmac.New(sha256.New, []byte(secret))
		macLegacy.Write(bodyBytes)
		sigHeader = fmt.Sprintf("t=%s,v0=%s,v1=%s", ts, hex.EncodeToString(macLegacy.Sum(nil)), v1Sig)
	}
	req.Header.Set("X-Webhook-Signature", sigHeader)
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
	if deactivated.Valid && deactivated.String != "" {
		return false, nil
	}
	if role == "admin" {
		return true, nil
	}
	return userHasGlobalAdminGrantWithSchema(db, uid, "main")
}
