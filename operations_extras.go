//go:build !cli

package main

// Three small endpoints every "real" SaaS needs:
//
//   /api/_my-data          DSAR: dump every row owned by the authed
//                          user. GDPR Article 15 / CCPA equivalent.
//                          One round-trip, no per-app glue.
//   /_status               public-facing status page rendered from
//                          _benmore_request_log: uptime, recent error
//                          rate, last response time bucket.
//   /api/_errors           POST endpoint bm.js submits uncaught
//                          errors to. Inserted into _benmore_client_errors;
//                          forwarded to Sentry/Slack when those envs
//                          are set on the app.
//
// All three are unconditional registrations — apps don't opt in
// because every app benefits from these and the cost is trivial.

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// ===== DSAR =====
// RegisterDSARRoute mounts GET /api/_my-data. Requires an authed
// session; returns a JSON blob with all user-scoped rows across every
// table that has a `user_id` column. Audit log rows where actor =
// current user are also included. Designed to satisfy Right of
// Access requests without writing per-app glue.
func RegisterDSARRoute(mux *http.ServeMux, app *App) {
	mux.HandleFunc("GET /api/_my-data", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpError(w, "authentication required", http.StatusUnauthorized)
			return
		}
		out := map[string]any{
			"exported_at": time.Now().UTC().Format(time.RFC3339),
			"user_id":     session.UserID,
			"email":       session.Email,
			"tables":      map[string]any{},
		}
		tables := out["tables"].(map[string]any)
		for _, t := range app.Tables {
			hasUserID := false
			for _, c := range t.Columns {
				if c.Name == "user_id" {
					hasUserID = true
					break
				}
			}
			if !hasUserID {
				continue
			}
			rows, err := app.DB.Query("SELECT * FROM "+sanitizeIdent(t.Name)+" WHERE user_id = ?", session.UserID)
			if err != nil {
				continue
			}
			records, _ := scanRowsToMaps(rows)
			rows.Close()
			tables[t.Name] = records
		}
		// Profile from _benmore_users.
		if rows, err := app.DB.Query("SELECT * FROM _benmore_users WHERE id = ?", session.UserID); err == nil {
			recs, _ := scanRowsToMaps(rows)
			rows.Close()
			if len(recs) > 0 {
				// Redact secrets even on DSAR (the user can already see
				// their own data, but secrets aren't personal data — and
				// a developer column like `payment_token` shouldn't ride
				// out in a JSON export the user could share unsafely).
				for col := range recs[0] {
					if isSensitiveUserColumn(col) {
						delete(recs[0], col)
					}
				}
				out["profile"] = recs[0]
			}
		}
		// Audit log entries for the user.
		if rows, err := app.DB.Query("SELECT id, table_name, row_id, action, before_data, after_data, created_at FROM _benmore_audit_log WHERE user_id = ? ORDER BY id DESC LIMIT 1000", session.UserID); err == nil {
			recs, _ := scanRowsToMaps(rows)
			rows.Close()
			out["audit_log"] = recs
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="my-data-%d-%s.json"`,
			session.UserID, time.Now().UTC().Format("20060102")))
		json.NewEncoder(w).Encode(out)
	})
}

// scanRowsToMaps converts a *sql.Rows iterator into []map[string]any.
// Used by DSAR + status helpers; not exported because callers should
// use the typed CRUD layer for everything else.
func scanRowsToMaps(rows interface {
	Columns() ([]string, error)
	Next() bool
	Scan(dest ...any) error
}) ([]map[string]any, error) {
	cols, err := rows.Columns()
	if err != nil {
		return nil, err
	}
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		row := map[string]any{}
		for i, c := range cols {
			v := vals[i]
			if b, ok := v.([]byte); ok {
				v = string(b)
			}
			row[c] = v
		}
		out = append(out, row)
	}
	return out, nil
}

// sanitizeIdent guards against injection into the FROM clause.
// Allow [A-Za-z0-9_] only; reject anything else.
func sanitizeIdent(s string) string {
	var b strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' {
			b.WriteRune(c)
		}
	}
	return b.String()
}

// ===== Status page =====
// GET /_status renders a minimal HTML page (no auth) with uptime
// summary + error rate. Pulls from _benmore_request_log; cheap query
// because the table is indexed on created_at.
func RegisterStatusRoute(mux *http.ServeMux, app *App) {
	mux.HandleFunc("GET /_status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "public, max-age=30")

		now := time.Now()
		stats := statusSnapshot(app, now)

		var sb strings.Builder
		sb.WriteString(`<!doctype html><html><head><meta charset="utf-8"><title>Status</title>`)
		sb.WriteString(`<style>body{font-family:system-ui,-apple-system,sans-serif;max-width:680px;margin:60px auto;padding:0 24px;background:#0a0a0a;color:#e4e4e7}h1{font-size:24px;margin:0 0 4px;letter-spacing:-0.02em}.sub{color:#71717a;margin:0 0 32px;font-size:13px}.card{background:#111;border:1px solid #27272a;border-radius:10px;padding:18px 20px;margin-bottom:12px;display:flex;align-items:center;gap:14px}.dot{width:10px;height:10px;border-radius:50%}.ok{background:#22c55e}.warn{background:#f59e0b}.bad{background:#ef4444}.name{flex:1;font-weight:600;font-size:14px}.val{color:#a1a1aa;font-size:13px;font-family:ui-monospace,monospace}</style></head><body>`)
		fmt.Fprintf(&sb, `<h1>%s — Status</h1>`, html.EscapeString(stats.SiteName))
		sb.WriteString(`<p class="sub">Live data from the last 24 hours · Updated `)
		sb.WriteString(now.UTC().Format(time.RFC3339))
		sb.WriteString(`</p>`)
		writeStatusRow(&sb, "Service availability", stats.Up, fmt.Sprintf("%d / %d requests succeeded", stats.OkCount, stats.TotalCount))
		writeStatusRow(&sb, "Error rate (24h)", stats.ErrorOK, fmt.Sprintf("%.2f%%", stats.ErrorRate*100))
		writeStatusRow(&sb, "Median response time", stats.LatencyOK, fmt.Sprintf("%d ms", stats.MedianMS))
		writeStatusRow(&sb, "P95 response time", stats.LatencyOK, fmt.Sprintf("%d ms", stats.P95MS))
		sb.WriteString(`</body></html>`)
		w.Write([]byte(sb.String()))
	})
}

type statusStats struct {
	SiteName   string
	OkCount    int64
	TotalCount int64
	ErrorRate  float64
	MedianMS   int64
	P95MS      int64
	Up         bool
	ErrorOK    bool
	LatencyOK  bool
}

func statusSnapshot(app *App, now time.Time) statusStats {
	s := statusStats{Up: true, ErrorOK: true, LatencyOK: true}
	if app != nil && app.Design != nil && app.Design.SEO != nil {
		s.SiteName = app.Design.SEO["site_name"]
	}
	if s.SiteName == "" {
		s.SiteName = "App"
	}
	since := now.Add(-24 * time.Hour).UTC().Format("2006-01-02 15:04:05")
	app.DB.QueryRow(`SELECT COUNT(*), SUM(CASE WHEN status < 400 THEN 1 ELSE 0 END) FROM _benmore_request_log WHERE created_at >= ?`, since).Scan(&s.TotalCount, &s.OkCount)
	if s.TotalCount > 0 {
		s.ErrorRate = float64(s.TotalCount-s.OkCount) / float64(s.TotalCount)
	}
	if s.ErrorRate > 0.05 {
		s.ErrorOK = false
		s.Up = false
	}
	// Median + P95 via NTILE — approximate but good enough for status page.
	var durations []int64
	if rows, err := app.DB.Query(`SELECT duration_ms FROM _benmore_request_log WHERE created_at >= ? ORDER BY duration_ms`, since); err == nil {
		for rows.Next() {
			var d int64
			rows.Scan(&d)
			durations = append(durations, d)
		}
		rows.Close()
	}
	if n := len(durations); n > 0 {
		s.MedianMS = durations[n/2]
		s.P95MS = durations[(n*95)/100]
		if s.P95MS > 2000 {
			s.LatencyOK = false
		}
	}
	return s
}

func writeStatusRow(sb *strings.Builder, name string, ok bool, val string) {
	dotClass := "ok"
	if !ok {
		dotClass = "bad"
	}
	fmt.Fprintf(sb, `<div class="card"><span class="dot %s"></span><span class="name">%s</span><span class="val">%s</span></div>`,
		dotClass, html.EscapeString(name), html.EscapeString(val))
}

// ===== Client-side error capture =====
// bm.js POSTs uncaught errors to /api/_errors. We insert into
// _benmore_client_errors (auto-created) and forward to Sentry/Slack
// when those envs are configured on the app.
func RegisterErrorCaptureRoute(mux *http.ServeMux, app *App) {
	app.DB.Exec(`CREATE TABLE IF NOT EXISTS _benmore_client_errors (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		kind TEXT, message TEXT, stack TEXT, source TEXT,
		line INTEGER, col INTEGER, status INTEGER, url TEXT,
		ua TEXT, user_id INTEGER, ip TEXT,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	app.DB.Exec(`CREATE INDEX IF NOT EXISTS idx_client_err_created ON _benmore_client_errors(created_at)`)

	mux.HandleFunc("POST /api/_errors", func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Kind, Message, Stack, Source, URL string
			Line, Col, Status                 int
		}
		dec := json.NewDecoder(io.LimitReader(r.Body, 64<<10))
		dec.Decode(&body)
		if body.Message == "" {
			w.WriteHeader(204)
			return
		}
		userID := int64(0)
		if s := getSession(app, r); s != nil {
			userID = s.UserID
		}
		ip := clientIP(r)
		ua := r.UserAgent()
		if len(ua) > 240 {
			ua = ua[:240]
		}
		app.DB.Exec(`INSERT INTO _benmore_client_errors (kind, message, stack, source, line, col, status, url, ua, user_id, ip)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			body.Kind, body.Message, body.Stack, body.Source, body.Line, body.Col, body.Status, body.URL, ua, userID, ip)
		// Best-effort external forwarding.
		go forwardErrorExternals(app, body, ip)
		w.WriteHeader(204)
	})
}

// forwardErrorExternals fans the error out to Sentry and/or Slack
// when the relevant env vars are configured. Both are HTTP POSTs;
// failures swallowed (don't let an external outage block more
// important work).
func forwardErrorExternals(app *App, body struct {
	Kind, Message, Stack, Source, URL string
	Line, Col, Status                 int
}, ip string) {
	if dsn := GetEnv(app.Dir, "SENTRY_DSN"); dsn != "" {
		sendToSentry(dsn, body)
	}
	if hook := GetEnv(app.Dir, "ERROR_SLACK_WEBHOOK"); hook != "" {
		sendErrorToSlack(hook, app, body, ip)
	}
}

// sendToSentry uses Sentry's standard envelope endpoint. The DSN is
// parsed inline so we don't need the official SDK. Throws away the
// response — Sentry's reliability is on them.
func sendToSentry(dsn string, body struct {
	Kind, Message, Stack, Source, URL string
	Line, Col, Status                 int
}) {
	// DSN shape: https://<public>@<host>/<project>
	u := strings.TrimPrefix(strings.TrimPrefix(dsn, "https://"), "http://")
	at := strings.Index(u, "@")
	slash := strings.LastIndex(u, "/")
	if at < 0 || slash < 0 || slash < at {
		return
	}
	publicKey := u[:at]
	host := u[at+1 : slash]
	project := u[slash+1:]
	endpoint := "https://" + host + "/api/" + project + "/store/"
	if isPrivateURL(endpoint) {
		return
	}
	payload := map[string]any{
		"event_id": fmt.Sprintf("%032x", time.Now().UnixNano()),
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"platform":  "javascript",
		"level":     "error",
		"message":   body.Message,
		"exception": map[string]any{
			"values": []any{map[string]any{
				"type":  body.Kind,
				"value": body.Message,
			}},
		},
		"request": map[string]any{"url": body.URL},
	}
	data, _ := json.Marshal(payload)
	req, _ := http.NewRequest("POST", endpoint, strings.NewReader(string(data)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Sentry-Auth", fmt.Sprintf("Sentry sentry_version=7, sentry_key=%s, sentry_client=benmore/1", publicKey))
	client := safeHTTPClient(5 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("sentry: %s", err)
		return
	}
	resp.Body.Close()
}

func sendErrorToSlack(webhook string, app *App, body struct {
	Kind, Message, Stack, Source, URL string
	Line, Col, Status                 int
}, ip string) {
	if isPrivateURL(webhook) {
		return
	}
	subdomain := ""
	if app != nil {
		subdomain = app.AppID
	}
	text := fmt.Sprintf("*[%s] %s error*\n```%s```\nat %s:%d:%d\nIP %s",
		subdomain, body.Kind, body.Message, body.Source, body.Line, body.Col, ip)
	payload, _ := json.Marshal(map[string]any{"text": text})
	resp, err := http.Post(webhook, "application/json", strings.NewReader(string(payload)))
	if err == nil {
		resp.Body.Close()
	}
}
