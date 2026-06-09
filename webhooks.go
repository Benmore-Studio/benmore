//go:build !cli

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
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

// RegisterWebhookRoutes sets up webhook subscription API endpoints.
func RegisterWebhookRoutes(mux *http.ServeMux, app *App) {
	EnsureWebhooksTable(app.DB)

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

		result, err := app.DB.Exec(
			"INSERT INTO _benmore_webhooks (user_id, url, secret, tables, events) VALUES (?, ?, ?, ?, ?)",
			session.UserID, req.URL, req.Secret, req.Tables, req.Events,
		)
		if err != nil {
			log.Printf("WEBHOOK ERROR: failed to create webhook: %s", err)
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to create webhook"})
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
		if session.IsAdmin() {
			rows, err = QueryRows(app.DB, "SELECT id, user_id, url, secret, tables, events, active, created_at FROM _benmore_webhooks ORDER BY created_at DESC")
		} else {
			rows, err = QueryRows(app.DB, "SELECT id, user_id, url, secret, tables, events, active, created_at FROM _benmore_webhooks WHERE user_id = ? ORDER BY created_at DESC", session.UserID)
		}
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to list webhooks"})
			return
		}

		// Mask secrets: show only last 4 chars
		for _, row := range rows {
			if secret, ok := row["secret"].(string); ok && len(secret) > 4 {
				row["secret"] = "****" + secret[len(secret)-4:]
			} else if ok {
				row["secret"] = "****"
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
		if session.IsAdmin() {
			result, err = app.DB.Exec("DELETE FROM _benmore_webhooks WHERE id = ?", id)
		} else {
			result, err = app.DB.Exec("DELETE FROM _benmore_webhooks WHERE id = ? AND user_id = ?", id, session.UserID)
		}
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to delete webhook"})
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
// Called from crud.go after hooks and flows fire on each CRUD mutation.
func FireWebhookSubscriptions(app *App, event string, table string, row map[string]any, session *Session) {
	// Don't fire webhooks for internal framework tables
	if strings.HasPrefix(table, "_benmore_") {
		return
	}

	// Query active webhooks that match this table and event
	rows, err := QueryRows(app.DB,
		"SELECT id, user_id, url, secret, tables, events FROM _benmore_webhooks WHERE active = 1",
	)
	if err != nil || len(rows) == 0 {
		return
	}

	for _, wh := range rows {
		whID := fmt.Sprintf("%v", wh["id"])
		whURL := fmt.Sprintf("%v", wh["url"])
		whSecret := fmt.Sprintf("%v", wh["secret"])
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
		EnqueueWebhookSubscriptionJob(app.DB, whID, whURL, whSecret, event, table, row, session)
	}
}

// EnqueueWebhookSubscriptionJob adds a webhook subscription delivery to the job queue.
func EnqueueWebhookSubscriptionJob(db *sql.DB, webhookID, webhookURL, secret, event, table string, row map[string]any, session *Session) {
	payload := map[string]any{
		"_webhook_subscription": map[string]any{
			"webhook_id": webhookID,
			"url":        webhookURL,
			"secret":     secret,
			"event":      event,
			"table":      table,
		},
		"_row": row,
	}
	if session != nil {
		payload["_webhook_subscription"].(map[string]any)["user_email"] = session.Email
		payload["_webhook_subscription"].(map[string]any)["user_id"] = session.UserID
	}

	data, _ := json.Marshal(payload)
	db.Exec(
		"INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at) VALUES ('webhook_subscription', 'webhook_subscription', ?, datetime('now'))",
		string(data),
	)
}

// executeWebhookSubscriptionJob delivers a webhook subscription payload.
// Called from the job worker in jobs.go.
func executeWebhookSubscriptionJob(data map[string]any, appDir string) error {
	whData, ok := data["_webhook_subscription"].(map[string]any)
	if !ok {
		return fmt.Errorf("missing _webhook_subscription in payload")
	}
	rowData, _ := data["_row"].(map[string]any)
	if rowData == nil {
		rowData = make(map[string]any)
	}

	whURL := fmt.Sprintf("%v", whData["url"])
	secret := fmt.Sprintf("%v", whData["secret"])
	event := fmt.Sprintf("%v", whData["event"])
	table := fmt.Sprintf("%v", whData["table"])

	// SSRF protection: re-validate at delivery time (URL could have been modified)
	if isPrivateURL(whURL) {
		log.Printf("SECURITY: blocked webhook subscription delivery to private URL: %s", whURL)
		return fmt.Errorf("blocked private URL: %s", whURL)
	}

	// Circuit breaker: skip if endpoint is known-dead
	host := extractHost(whURL)
	if err := CheckCircuit(host); err != nil {
		return fmt.Errorf("circuit open: %s", err)
	}

	// Build the payload
	body := map[string]any{
		"event": event,
		"table": table,
		"data":  rowData,
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

	// Legacy body-only signature retained as v0 so receivers that
	// hard-coded HMAC(secret, body) keep working through one
	// transition cycle. Drop v0 emission once known integrations
	// are confirmed migrated.
	macLegacy := hmac.New(sha256.New, []byte(secret))
	macLegacy.Write(bodyBytes)
	v0Sig := hex.EncodeToString(macLegacy.Sum(nil))

	// Send the webhook
	req, err := http.NewRequest("POST", whURL, strings.NewReader(string(bodyBytes)))
	if err != nil {
		RecordFailure(host)
		return fmt.Errorf("failed to create request: %s", err)
	}
	req.Header.Set("Content-Type", "application/json")
	// Stripe-style combined header so receivers can pick the version they
	// trust without parsing two separate signature headers.
	req.Header.Set("X-Webhook-Signature", fmt.Sprintf("t=%s,v0=%s,v1=%s", ts, v0Sig, v1Sig))
	req.Header.Set("X-Webhook-Timestamp", ts)
	req.Header.Set("X-Webhook-Event", event)
	req.Header.Set("X-Webhook-Table", table)

	client := safeHTTPClientStrict(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		RecordFailure(host)
		return fmt.Errorf("webhook delivery failed: %s", err)
	}
	resp.Body.Close()

	if resp.StatusCode >= 500 {
		RecordFailure(host)
		return fmt.Errorf("webhook returned %d", resp.StatusCode)
	}

	RecordSuccess(host)
	log.Printf("WEBHOOK SUBSCRIPTION [%s/%s] %s -> %d", event, table, whURL, resp.StatusCode)
	return nil
}
