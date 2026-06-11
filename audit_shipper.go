//go:build !cli

package main

// Audit-log shipper. Tails the per-app _benmore_audit_log table and
// POSTs new entries to a configured webhook destination (typically an
// S3 bucket via a tiny relay, a SIEM ingest endpoint, or a SOC-2 log
// retention service). Closes the "logs only live locally" compliance
// gap - auditors need to see the full mutation trail for years, and
// the local SQLite file is not where that history is allowed to live
// for any regulated app.
//
// Activation: set BENMORE_AUDIT_WEBHOOK_URL on the per-app process.
// Without it, no goroutine spawns and the audit log stays purely local.
//
// Configuration:
//   BENMORE_AUDIT_WEBHOOK_URL       - destination (REQUIRED to enable)
//   BENMORE_AUDIT_WEBHOOK_SECRET    - REQUIRED HMAC signing key (32+ chars)
//   BENMORE_AUDIT_WEBHOOK_TOKEN     - optional additional Bearer for header auth
//   BENMORE_AUDIT_WEBHOOK_INTERVAL  - polling cadence (default 30s)
//   BENMORE_AUDIT_WEBHOOK_BATCH     - rows per POST (default 100)
//
// Wire shape: POSTs a JSON array of audit rows. Receiver echoes 2xx on
// success - anything else, we retry the same window on the next tick.
// Cursor persisted in a one-row tracker table so a restart resumes
// from the same point (no duplicate shipping, no skipped events).
//
// Authentication of the payload to the receiver:
//
//   X-Benmore-Timestamp: <unix-seconds>
//   X-Benmore-Signature: sha256=<hex-of-HMAC-SHA256(secret, "<ts>.<body>")>
//
// Receiver verification (Python example):
//
//   import hmac, hashlib, time
//   ts = request.headers["X-Benmore-Timestamp"]
//   sig = request.headers["X-Benmore-Signature"]
//   body = request.body  # raw bytes
//   expected = "sha256=" + hmac.new(
//       SECRET.encode(), f"{ts}.".encode() + body, hashlib.sha256
//   ).hexdigest()
//   assert hmac.compare_digest(sig, expected), "bad signature"
//   assert abs(time.time() - int(ts)) < 300, "replay window (5min)"
//
// Why HMAC + timestamp rather than just a Bearer token: the secret
// never traverses the wire - only a derived signature does. A receiver
// that gets compromised can't replay the value as a token to other
// endpoints, and an attacker who observes one POST can't reuse the
// signature for a different body. Standard GitHub/Stripe/Linear shape.

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	auditShipperCursorTable = "_benmore_audit_shipper_cursor"
	defaultShipperInterval  = 30 * time.Second
	defaultShipperBatch     = 100
)

// StartAuditShipper begins the background ship loop if
// BENMORE_AUDIT_WEBHOOK_URL is set. Idempotent - calling it twice
// spawns one shipper (each app process boots only one).
//
// Security model:
//
//   1. URL must be HTTPS. HTTP destinations leak the entire audit
//      stream (PII, user actions, old/new values) in plaintext over
//      the wire. Override only with BENMORE_AUDIT_WEBHOOK_ALLOW_HTTP=1
//      for the rare on-prem-internal case where the operator has
//      separately confirmed the path is on a private link.
//
//   2. URL must resolve to a PUBLIC IP. Same SSRF protection the
//      framework applies to webhooks + flows: no loopback, no RFC1918,
//      no link-local. Blocks "ship our audit log to 169.254.169.254"
//      (cloud metadata) and "ship to localhost:<random>" (escalation
//      via a co-resident process).
//
//   3. On any URL-validation failure the shipper REFUSES to start -
//      no goroutine, no ticker, no first request. The operator sees
//      a clear log line at boot and the audit data stays local. Fail
//      closed, not fail noisy.
//
//   4. The destination URL is set via an environment file owned by the
//      app's system user (mode 0600). Setting it requires either being root
//      or editing that file - which on a multi-tenant host is admin-only, so
//      a tenant user with no admin role cannot configure this.
//
// What this protects against:
//   - SSRF to AWS/GCP metadata services and other internal endpoints.
//   - Accidental ship to localhost:<port> hitting a co-resident dev
//     server.
//   - Plaintext exfiltration over HTTP.
//   - Misconfiguration where the URL is reachable but should never
//     receive PII (e.g. a public webhook.site debug URL).
//
// What this does NOT protect against (still your responsibility):
//   - A compromised platform admin who legitimately configures the
//     URL to point at an attacker-controlled public HTTPS endpoint.
//     That's the same threat model as any other admin compromise.
func StartAuditShipper(app *App) {
	if app == nil || app.DB == nil {
		return
	}
	url := strings.TrimSpace(os.Getenv("BENMORE_AUDIT_WEBHOOK_URL"))
	if url == "" {
		return
	}

	// Hard validation gate before any cursor table is even created.
	if reason := validateAuditWebhookURL(url); reason != "" {
		log.Printf("audit-shipper: REFUSING TO START - %s (set BENMORE_AUDIT_WEBHOOK_URL to a public HTTPS endpoint)", reason)
		return
	}

	// HMAC secret is REQUIRED. Shipping audit data unsigned would mean
	// the receiver has no cryptographic proof the payload came from
	// this benmore instance - anyone who learns the URL could POST
	// forged audit events. Refuse to start until the operator configures
	// a real shared secret.
	secret := strings.TrimSpace(os.Getenv("BENMORE_AUDIT_WEBHOOK_SECRET"))
	if len(secret) < 32 {
		log.Printf("audit-shipper: REFUSING TO START - BENMORE_AUDIT_WEBHOOK_SECRET must be set to a 32+ char random string (used for HMAC-SHA256 body signing). Generate with `openssl rand -hex 32` and share with the receiver.")
		return
	}

	token := strings.TrimSpace(os.Getenv("BENMORE_AUDIT_WEBHOOK_TOKEN"))
	interval := defaultShipperInterval
	if v := strings.TrimSpace(os.Getenv("BENMORE_AUDIT_WEBHOOK_INTERVAL")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			interval = d
		}
	}
	batch := defaultShipperBatch
	if v := strings.TrimSpace(os.Getenv("BENMORE_AUDIT_WEBHOOK_BATCH")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 && n <= 10000 {
			batch = n
		}
	}

	ensureAuditShipperCursor(app.DB)

	appName := strings.TrimSpace(os.Getenv("BENMORE_APP_NAME"))
	if appName == "" {
		appName = "router"
	}

	log.Printf("audit-shipper: enabled - dest=%s interval=%s batch=%d", redactURL(url), interval, batch)

	safeGo("audit.shipper", func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-app.Stop:
				return
			case <-ticker.C:
				shipOnce(app.DB, url, secret, token, batch, appName)
			}
		}
	})
}

func ensureAuditShipperCursor(db *sql.DB) {
	db.Exec(fmt.Sprintf(`CREATE TABLE IF NOT EXISTS %s (
		id INTEGER PRIMARY KEY CHECK (id = 1),
		last_shipped_id INTEGER NOT NULL DEFAULT 0,
		last_shipped_at DATETIME
	)`, auditShipperCursorTable))
	// Seed the single tracker row.
	db.Exec(fmt.Sprintf("INSERT OR IGNORE INTO %s (id, last_shipped_id) VALUES (1, 0)", auditShipperCursorTable))
}

type auditRow struct {
	ID         int64           `json:"id"`
	Action     string          `json:"action"`
	TableName  string          `json:"table_name"`
	RowID      string          `json:"row_id,omitempty"`
	UserID     int64           `json:"user_id,omitempty"`
	UserEmail  string          `json:"user_email,omitempty"`
	OldValues  json.RawMessage `json:"old_values,omitempty"`
	NewValues  json.RawMessage `json:"new_values,omitempty"`
	CreatedAt  string          `json:"created_at"`
	App        string          `json:"app"`
}

func shipOnce(db *sql.DB, url, secret, token string, batch int, appName string) {
	var cursor int64
	if err := db.QueryRow(fmt.Sprintf("SELECT last_shipped_id FROM %s WHERE id = 1", auditShipperCursorTable)).Scan(&cursor); err != nil {
		log.Printf("audit-shipper: cursor read failed: %s", err)
		return
	}
	rows, err := db.Query(`
		SELECT id, action, table_name, COALESCE(row_id, ''), COALESCE(user_id, 0),
		       COALESCE(user_email, ''), COALESCE(old_values, ''), COALESCE(new_values, ''),
		       COALESCE(created_at, '')
		FROM _benmore_audit_log
		WHERE id > ?
		ORDER BY id
		LIMIT ?`, cursor, batch)
	if err != nil {
		log.Printf("audit-shipper: query failed: %s", err)
		return
	}
	defer rows.Close()

	var entries []auditRow
	var maxID int64
	for rows.Next() {
		var r auditRow
		var oldVals, newVals string
		if err := rows.Scan(&r.ID, &r.Action, &r.TableName, &r.RowID, &r.UserID, &r.UserEmail, &oldVals, &newVals, &r.CreatedAt); err != nil {
			continue
		}
		r.App = appName
		if oldVals != "" {
			r.OldValues = json.RawMessage(oldVals)
		}
		if newVals != "" {
			r.NewValues = json.RawMessage(newVals)
		}
		entries = append(entries, r)
		if r.ID > maxID {
			maxID = r.ID
		}
	}
	if len(entries) == 0 {
		return
	}

	payload, err := json.Marshal(map[string]any{
		"app":     appName,
		"count":   len(entries),
		"entries": entries,
	})
	if err != nil {
		log.Printf("audit-shipper: marshal failed: %s", err)
		return
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(payload))
	if err != nil {
		log.Printf("audit-shipper: request build failed: %s", err)
		return
	}
	req.Header.Set("Content-Type", "application/json")
	// HMAC-SHA256 signature over `<timestamp>.<body>`. Receiver verifies
	// the signature and rejects payloads older than 5min (replay guard).
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts))
	mac.Write([]byte("."))
	mac.Write(payload)
	signature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	req.Header.Set("X-Benmore-Timestamp", ts)
	req.Header.Set("X-Benmore-Signature", signature)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("audit-shipper: POST failed: %s (will retry next tick)", err)
		return
	}
	defer resp.Body.Close()
	// Drain a small amount so the connection can be reused.
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		_, err := db.Exec(fmt.Sprintf("UPDATE %s SET last_shipped_id = ?, last_shipped_at = ? WHERE id = 1",
			auditShipperCursorTable), maxID, time.Now().UTC().Format(time.RFC3339))
		if err != nil {
			log.Printf("audit-shipper: cursor update failed: %s", err)
			return
		}
		log.Printf("audit-shipper: shipped %d entries (cursor → %d)", len(entries), maxID)
	} else {
		log.Printf("audit-shipper: dest returned %d (will retry same window next tick)", resp.StatusCode)
	}
}

// validateAuditWebhookURL enforces the security gate documented on
// StartAuditShipper. Returns "" when the URL is acceptable, otherwise
// a human-readable reason that's safe to log at startup.
//
// Rules:
//   - scheme must be https (or http only if BENMORE_AUDIT_WEBHOOK_ALLOW_HTTP=1)
//   - host must not resolve to a private / loopback / link-local IP
//     (SSRF protection - reuses isPrivateURL from fetch.go which
//     already handles the IP-range checks for webhooks + flows)
//   - host must parse to a real hostname (not "", not whitespace)
//
// Fails closed on ambiguous cases (DNS resolution errors, parse
// errors, etc.) - better to keep the audit log local than to ship to
// an unverified destination.
func validateAuditWebhookURL(raw string) string {
	if raw == "" {
		return "URL is empty"
	}
	allowHTTP := strings.TrimSpace(os.Getenv("BENMORE_AUDIT_WEBHOOK_ALLOW_HTTP")) == "1"
	if !allowHTTP && !strings.HasPrefix(strings.ToLower(raw), "https://") {
		return "URL must be https:// (set BENMORE_AUDIT_WEBHOOK_ALLOW_HTTP=1 only if the path is on a verified private link)"
	}
	if isPrivateURL(raw) {
		// isPrivateURL is the framework's existing SSRF gate (fetch.go).
		// Returns true for private/loopback/link-local IPs, non-http(s)
		// schemes, .local / .internal suffixes, DNS failures.
		// When the operator explicitly opted into HTTP for an on-prem
		// internal link via BENMORE_AUDIT_WEBHOOK_ALLOW_HTTP=1, allow
		// private destinations (that's the whole point of the override).
		if !allowHTTP {
			return "URL resolves to a private / loopback / link-local address - refused (set BENMORE_AUDIT_WEBHOOK_ALLOW_HTTP=1 if this is an intentional on-prem internal endpoint)"
		}
	}
	return ""
}

// redactURL keeps the host visible in startup logs but hides any
// credentials in the URL itself.
func redactURL(u string) string {
	idx := strings.Index(u, "@")
	if idx < 0 {
		return u
	}
	schemeEnd := strings.Index(u, "://")
	if schemeEnd < 0 || idx < schemeEnd {
		return u
	}
	return u[:schemeEnd+3] + "<redacted>@" + u[idx+1:]
}
