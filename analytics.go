//go:build !cli

package main

// Per-app analytics - privacy-preserving, first-party, Plausible-level.
//
// Every app automatically gets analytics. A lightweight JS beacon (~600
// bytes) fires on each page load, sending path, referrer, screen size,
// and visitor cookie to POST /api/_analytics. The framework stores
// events in _benmore_analytics (per-app SQLite) and tracks visitors
// via a _bm_vid first-party cookie (1-year, HttpOnly, SameSite=Lax).
//
// Sessions: 30-minute inactivity window. Same visitor cookie within
// 30 minutes = same session. After 30 minutes of no activity, the
// next pageview starts a new session.
//
// Privacy:
//   - First-party only - no cross-site tracking, no third-party data sharing
//   - IP addresses are never stored - only used for country detection at write time
//   - Data lives in the app's own SQLite DB, never leaves the server
//   - Cookie consent: apps should disclose analytics cookies in their privacy policy
//   - Can be disabled via features.analytics: false in app.yaml
//
// Ring buffer: auto-prune to last 50,000 events per app.

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
)

const analyticsEventCap = 50000

// analyticsPruneEvery is how many recorded pageviews pass between prunes.
const analyticsPruneEvery = 500

// analyticsVisitorCap bounds _benmore_visitors. Every new visitor adds a row
// and the beacon is public, so without a bound any caller can grow the
// table one request at a time until the app's database is full. The least
// recently seen visitors go first. A variable so tests can lower it.
var analyticsVisitorCap = 100000

// EnsureAnalyticsTables creates the per-app analytics tables.
func EnsureAnalyticsTables(db *sql.DB) {
	if db == nil {
		return
	}
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_analytics (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		visitor_id TEXT NOT NULL,
		session_id TEXT NOT NULL,
		path TEXT NOT NULL,
		referrer TEXT DEFAULT '',
		referrer_domain TEXT DEFAULT '',
		utm_source TEXT DEFAULT '',
		utm_medium TEXT DEFAULT '',
		utm_campaign TEXT DEFAULT '',
		screen_w INTEGER DEFAULT 0,
		screen_h INTEGER DEFAULT 0,
		device_type TEXT DEFAULT 'desktop',
		browser TEXT DEFAULT '',
		os TEXT DEFAULT '',
		country TEXT DEFAULT '',
		duration_ms INTEGER DEFAULT 0,
		is_bounce INTEGER DEFAULT 1,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_analytics_time ON _benmore_analytics(created_at DESC)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_analytics_visitor ON _benmore_analytics(visitor_id)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_analytics_session ON _benmore_analytics(session_id)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_analytics_path ON _benmore_analytics(path)`)

	// Entry/exit page tracking per session
	db.Exec(`ALTER TABLE _benmore_analytics ADD COLUMN is_entry INTEGER DEFAULT 0`)
	db.Exec(`ALTER TABLE _benmore_analytics ADD COLUMN is_exit INTEGER DEFAULT 0`)

	// Funnels - user-defined conversion paths
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_funnels (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL,
		steps TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)

	// Visitor table - maps cookie IDs to first/last seen + user_id backfill
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_visitors (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		visitor_id TEXT UNIQUE NOT NULL,
		user_id INTEGER DEFAULT 0,
		first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
		session_count INTEGER DEFAULT 1,
		pageview_count INTEGER DEFAULT 0
	)`)
	// pruneAnalyticsVisitors removes the least recently seen visitors.
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_visitors_last_seen ON _benmore_visitors(last_seen, pageview_count)`)
}

// pruneAnalyticsVisitors keeps at most keep rows of _benmore_visitors,
// dropping the least recently seen first (and, among those seen in the same
// second, the ones with the fewest pageviews).
func pruneAnalyticsVisitors(db *sql.DB, keep int) {
	_, _ = db.Exec(`DELETE FROM _benmore_visitors WHERE id IN (
		SELECT id FROM _benmore_visitors ORDER BY last_seen ASC, pageview_count ASC, id ASC
		LIMIT MAX((SELECT COUNT(*) FROM _benmore_visitors) - ?, 0))`, keep)
}

// analyticsVisitorIDOK reports whether v has the shape generateVisitorID
// mints (16 lowercase hex digits). The cookie comes back from the browser, so
// anything else is a value somebody chose: it is replaced, never stored.
func analyticsVisitorIDOK(v string) bool {
	if len(v) != 16 {
		return false
	}
	for i := 0; i < len(v); i++ {
		if c := v[i]; !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}

// analyticsCountry keeps a two-letter country code and drops everything else
// (Cloudflare's XX/T1 placeholders, or whatever a direct caller put in the
// header).
func analyticsCountry(v string) string {
	if len(v) != 2 || v == "XX" || v == "T1" {
		return ""
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 'A' || v[i] > 'Z' {
			return ""
		}
	}
	return v
}

// RegisterAnalyticsRoutes adds the beacon endpoint.
func RegisterAnalyticsRoutes(mux appRouteRegistrar, app *App) {
	if app == nil || app.DB == nil || !app.FeatureEnabled("analytics") {
		return
	}
	EnsureAnalyticsTables(app.DB)
	registerAnalyticsRoutes(mux, app)
}

func registerAnalyticsRoutes(mux appRouteRegistrar, app *App) {
	if app == nil || app.DB == nil || !app.FeatureEnabled("analytics") {
		return
	}
	var insertCount atomic.Int64

	mux.HandleFunc("POST /api/_analytics", func(w http.ResponseWriter, r *http.Request) {
		// Consent gate: do not set the _bm_vid cookie or write a row
		// to the analytics tables when the visitor has not explicitly
		// opted in via the cookie banner. Beacon still returns 204 so
		// the client JS doesn't retry - we silently skip on the
		// server side instead.
		if !cookieConsentGiven(r) {
			w.WriteHeader(204)
			return
		}

		// Parse beacon payload
		var ev struct {
			Path     string `json:"p"`
			Referrer string `json:"r"`
			ScreenW  int    `json:"sw"`
			ScreenH  int    `json:"sh"`
			Duration int    `json:"d"`
			Final    int    `json:"fin"` // 1 = unload beacon (update duration); 0 = initial visit (insert row)
			UTMSrc   string `json:"us"`
			UTMMed   string `json:"um"`
			UTMCamp  string `json:"uc"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 2048)).Decode(&ev); err != nil {
			w.WriteHeader(204)
			return
		}

		// Get or create visitor cookie
		vid := ""
		if cookie, err := r.Cookie("_bm_vid"); err == nil && analyticsVisitorIDOK(cookie.Value) {
			vid = cookie.Value
		}
		if vid == "" {
			vid = generateVisitorID()
			// protoOf for proxy-correct Secure flag - see #18.
			http.SetCookie(w, &http.Cookie{
				Name:     "_bm_vid",
				Value:    vid,
				Path:     "/",
				MaxAge:   365 * 24 * 3600, // 1 year
				HttpOnly: true,
				Secure:   protoOf(r) == "https",
				SameSite: http.SameSiteLaxMode,
			})
		}

		// Final beacon: update the duration of the most recent matching row
		// and bail. Does NOT insert a new row (that would double-count the
		// pageview). Does NOT bump visitor pageview_count or re-run
		// entry/exit logic - that was already done by the initial beacon.
		if ev.Final == 1 {
			path := ev.Path
			if path == "" {
				path = "/"
			}
			if len(path) > 500 {
				path = path[:500]
			}
			_, err := app.DB.ExecContext(r.Context(),
				`UPDATE _benmore_analytics SET duration_ms = ?
				 WHERE id = (SELECT MAX(id) FROM _benmore_analytics
				             WHERE session_id = (SELECT session_id FROM _benmore_analytics
				                 WHERE visitor_id = ? AND created_at > datetime('now', '-30 minutes')
				                 ORDER BY id DESC LIMIT 1)
				             AND path = ? AND duration_ms = 0)`,
				ev.Duration, vid, path,
			)
			if err != nil {
				serverErrorStatus(w, r, app, http.StatusServiceUnavailable, "_analytics", err, "analytics storage unavailable")
				return
			}
			w.WriteHeader(204)
			return
		}

		// Parse referrer domain
		refDomain := ""
		if ev.Referrer != "" {
			if u, err := url.Parse(ev.Referrer); err == nil {
				refDomain = u.Hostname()
				// Strip self-referrals (same host as the request)
				reqHost := r.Host
				if idx := strings.Index(reqHost, ":"); idx >= 0 {
					reqHost = reqHost[:idx]
				}
				if refDomain == reqHost {
					refDomain = ""
					ev.Referrer = ""
				}
			}
		}

		// Device type from screen width
		deviceType := "desktop"
		if ev.ScreenW > 0 && ev.ScreenW <= 768 {
			deviceType = "mobile"
		} else if ev.ScreenW > 768 && ev.ScreenW <= 1024 {
			deviceType = "tablet"
		}

		// Browser + OS from UA
		ua := r.UserAgent()
		browser := parseBrowser(ua)
		os := parseOS(ua)

		// Country from Cloudflare header - free, accurate, zero latency.
		// CF adds this on every proxied request. Falls back to empty.
		// XX = unknown, T1 = Tor.
		country := analyticsCountry(r.Header.Get("CF-IPCountry"))

		// Sanitize path
		path := ev.Path
		if path == "" {
			path = "/"
		}
		if len(path) > 500 {
			path = path[:500]
		}

		// Resolve auth before holding a database transaction: session lookup can
		// need another connection, including when the pool has a single slot.
		var userID int64
		if sess := getSession(app, r); sess != nil {
			userID = sess.UserID
		}
		err := func() error {
			tx, err := app.DB.BeginTx(r.Context(), nil)
			if err != nil {
				return err
			}
			defer tx.Rollback()
			// Acquire the writer before reading session state, including on DBs
			// opened without _txlock=immediate. Concurrent first visits must use
			// one session; visitor counters and event rows commit together.
			if _, err := tx.Exec(`INSERT INTO _benmore_visitors (visitor_id, user_id, last_seen, session_count, pageview_count)
				VALUES (?, ?, datetime('now'), 0, 1)
				ON CONFLICT(visitor_id) DO UPDATE SET last_seen = datetime('now'),
				pageview_count = pageview_count + 1,
				user_id = CASE WHEN user_id = 0 THEN excluded.user_id ELSE user_id END`, vid, userID); err != nil {
				return err
			}
			sid, newSession, err := resolveAnalyticsSession(tx, vid)
			if err != nil {
				return err
			}
			if newSession {
				if _, err := tx.Exec("UPDATE _benmore_visitors SET session_count = session_count + 1 WHERE visitor_id = ?", vid); err != nil {
					return err
				}
			}
			// Insert event.
			result, err := tx.Exec(
				`INSERT INTO _benmore_analytics (visitor_id, session_id, path, referrer, referrer_domain, utm_source, utm_medium, utm_campaign, screen_w, screen_h, device_type, browser, os, country, duration_ms) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
				vid, sid, path, ev.Referrer, refDomain, ev.UTMSrc, ev.UTMMed, ev.UTMCamp,
				ev.ScreenW, ev.ScreenH, deviceType, browser, os, country, ev.Duration,
			)
			if err != nil {
				return err
			}
			id, err := result.LastInsertId()
			if err != nil {
				return err
			}
			if _, err := tx.Exec("UPDATE _benmore_analytics SET is_entry = ?, is_exit = 1 WHERE id = ?", newSession, id); err != nil {
				return err
			}
			if _, err := tx.Exec("UPDATE _benmore_analytics SET is_bounce = 0, is_exit = 0 WHERE session_id = ? AND id != ?", sid, id); err != nil {
				return err
			}
			return tx.Commit()
		}()
		if err != nil {
			serverErrorStatus(w, r, app, http.StatusServiceUnavailable, "_analytics", err, "analytics storage unavailable")
			return
		}

		// Lazy prune: a range delete below the boundary id (request_log.go
		// pruneRingTable), not the old NOT IN over a 50,000-row subquery.
		if insertCount.Add(1)%analyticsPruneEvery == 0 {
			pruneRingTable(app.DB, "_benmore_analytics", analyticsEventCap)
			pruneAnalyticsVisitors(app.DB, analyticsVisitorCap)
		}

		w.WriteHeader(204)
	})

	// GET /api/_analytics/summary - aggregated stats for the dashboard
	mux.HandleFunc("GET /api/_analytics/summary", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdminConsole() {
			http.Error(w, "admin required", 403)
			return
		}
		// Only the parsed integer reaches the SQL text.
		days := min(queryInt(r, "days", 7), 365)
		since := fmt.Sprintf("datetime('now', '-%d days')", days)

		summary := map[string]any{}

		// Total pageviews
		var pageviews int64
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_analytics WHERE created_at >= " + since).Scan(&pageviews)
		summary["pageviews"] = pageviews

		// Unique visitors
		var uniques int64
		app.DB.QueryRow("SELECT COUNT(DISTINCT visitor_id) FROM _benmore_analytics WHERE created_at >= " + since).Scan(&uniques)
		summary["unique_visitors"] = uniques

		// Sessions
		var sessions int64
		app.DB.QueryRow("SELECT COUNT(DISTINCT session_id) FROM _benmore_analytics WHERE created_at >= " + since).Scan(&sessions)
		summary["sessions"] = sessions

		// Bounce rate
		var bounced int64
		app.DB.QueryRow("SELECT COUNT(DISTINCT session_id) FROM _benmore_analytics WHERE is_bounce = 1 AND created_at >= " + since).Scan(&bounced)
		if sessions > 0 {
			summary["bounce_rate"] = float64(bounced) / float64(sessions) * 100
		} else {
			summary["bounce_rate"] = 0
		}

		// Avg session duration (approx - max duration in each session)
		var avgDur float64
		app.DB.QueryRow("SELECT COALESCE(AVG(d),0) FROM (SELECT session_id, MAX(duration_ms) as d FROM _benmore_analytics WHERE created_at >= " + since + " GROUP BY session_id)").Scan(&avgDur)
		summary["avg_duration_ms"] = avgDur

		// Breakdowns. QueryRows returns the rows read before a failure (a
		// timed-out statement) along with the error, so a failed breakdown
		// fails the summary instead of showing as a shorter list.
		var readErr error
		breakdown := func(key, query string) {
			rows, err := queryMetadataRows(app.DB, query)
			if err != nil && readErr == nil {
				readErr = err
			}
			summary[key] = rows
		}

		// Top pages
		breakdown("top_pages", "SELECT path, COUNT(*) as views, COUNT(DISTINCT visitor_id) as uniques FROM _benmore_analytics WHERE created_at >= "+since+" GROUP BY path ORDER BY views DESC LIMIT 10")

		// Top referrers
		breakdown("top_referrers", "SELECT referrer_domain, COUNT(*) as views FROM _benmore_analytics WHERE referrer_domain != '' AND created_at >= "+since+" GROUP BY referrer_domain ORDER BY views DESC LIMIT 10")

		// Device breakdown
		breakdown("devices", "SELECT device_type, COUNT(*) as views FROM _benmore_analytics WHERE created_at >= "+since+" GROUP BY device_type ORDER BY views DESC")

		// Browser breakdown
		breakdown("browsers", "SELECT browser, COUNT(*) as views FROM _benmore_analytics WHERE browser != '' AND created_at >= "+since+" GROUP BY browser ORDER BY views DESC LIMIT 8")

		// Daily pageviews (for sparkline)
		breakdown("daily", "SELECT DATE(created_at) as day, COUNT(*) as views, COUNT(DISTINCT visitor_id) as uniques FROM _benmore_analytics WHERE created_at >= "+since+" GROUP BY day ORDER BY day")
		if readErr != nil {
			serverErrorStatus(w, r, app, http.StatusServiceUnavailable, "_analytics summary", readErr, "analytics query failed")
			return
		}

		// New vs returning visitors
		var newV, retV int64
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_visitors WHERE session_count = 1 AND last_seen >= " + since).Scan(&newV)
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_visitors WHERE session_count > 1 AND last_seen >= " + since).Scan(&retV)
		summary["new_visitors"] = newV
		summary["returning_visitors"] = retV

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(summary)
	})

	// POST /api/_analytics/funnel - create a funnel definition
	mux.HandleFunc("POST /api/_analytics/funnel", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdminConsole() {
			http.Error(w, "admin required", 403)
			return
		}
		if !requireCSRF(w, r) {
			return
		}
		var req struct {
			Name  string   `json:"name"`
			Steps []string `json:"steps"` // ["/", "/pricing", "/signup"]
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" || len(req.Steps) < 2 {
			http.Error(w, "name and at least 2 steps required", 400)
			return
		}
		stepsJSON, _ := json.Marshal(req.Steps)
		result, err := app.DB.Exec("INSERT INTO _benmore_funnels (name, steps) VALUES (?, ?)", req.Name, string(stepsJSON))
		if err != nil {
			serverError(w, r, app, "_analytics funnel", err, "insert failed")
			return
		}
		id, _ := result.LastInsertId()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true, "id": id})
	})

	// GET /api/_analytics/funnels - list + evaluate all funnels
	mux.HandleFunc("GET /api/_analytics/funnels", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdminConsole() {
			http.Error(w, "admin required", 403)
			return
		}
		// Only the parsed integer reaches the SQL text.
		days := min(queryInt(r, "days", 30), 365)
		since := fmt.Sprintf("datetime('now', '-%d days')", days)

		rows, err := app.DB.Query("SELECT id, name, steps FROM _benmore_funnels ORDER BY id")
		if err != nil {
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode([]any{})
			return
		}
		defer rows.Close()

		var funnels []map[string]any
		for rows.Next() {
			var id int64
			var name, stepsJSON string
			rows.Scan(&id, &name, &stepsJSON)
			var steps []string
			json.Unmarshal([]byte(stepsJSON), &steps)

			// Evaluate funnel - count visitors who reached each step
			stepResults := evaluateFunnel(app.DB, steps, since)

			funnels = append(funnels, map[string]any{
				"id":    id,
				"name":  name,
				"steps": stepResults,
			})
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(funnels)
	})

	// DELETE /api/_analytics/funnel?id=X
	mux.HandleFunc("DELETE /api/_analytics/funnel", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdminConsole() {
			http.Error(w, "admin required", 403)
			return
		}
		if !requireCSRF(w, r) {
			return
		}
		id := r.URL.Query().Get("id")
		app.DB.Exec("DELETE FROM _benmore_funnels WHERE id = ?", id)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]any{"ok": true})
	})

	log.Printf("  analytics: beacon at /api/_analytics, summary at /api/_analytics/summary, funnels at /api/_analytics/funnels")
}

// evaluateFunnel calculates conversion through a sequence of pages.
// For each step, counts how many unique visitors who started at step 1
// also visited the subsequent steps (in any order, within the same session).
func evaluateFunnel(db *sql.DB, steps []string, since string) []map[string]any {
	if len(steps) == 0 {
		return nil
	}

	results := make([]map[string]any, len(steps))

	// Get all sessions that hit step 1
	step1Sessions := map[string]bool{}
	rows, err := db.Query(
		"SELECT DISTINCT session_id FROM _benmore_analytics WHERE path = ? AND created_at >= "+since,
		steps[0],
	)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var sid string
			rows.Scan(&sid)
			step1Sessions[sid] = true
		}
	}

	totalStart := len(step1Sessions)
	results[0] = map[string]any{
		"path":       steps[0],
		"visitors":   totalStart,
		"conversion": 100.0,
		"dropoff":    0.0,
	}

	// For each subsequent step, check how many of the step-1 sessions also hit it
	prevCount := totalStart
	for i := 1; i < len(steps); i++ {
		count := 0
		for sid := range step1Sessions {
			var exists int
			db.QueryRow(
				"SELECT 1 FROM _benmore_analytics WHERE session_id = ? AND path = ? LIMIT 1",
				sid, steps[i],
			).Scan(&exists)
			if exists == 1 {
				count++
			}
		}

		convPct := 0.0
		dropPct := 0.0
		if totalStart > 0 {
			convPct = float64(count) / float64(totalStart) * 100
		}
		if prevCount > 0 {
			dropPct = float64(prevCount-count) / float64(prevCount) * 100
		}

		results[i] = map[string]any{
			"path":       steps[i],
			"visitors":   count,
			"conversion": convPct,
			"dropoff":    dropPct,
		}
		prevCount = count
	}

	return results
}

// resolveAnalyticsSession runs after acquiring the transaction's writer lock.
// Sessions expire after 30 minutes of inactivity; this read has no side effects.
func resolveAnalyticsSession(tx *sql.Tx, visitorID string) (string, bool, error) {
	var lastSID string
	err := tx.QueryRow(
		"SELECT session_id FROM _benmore_analytics WHERE visitor_id = ? AND created_at > datetime('now', '-30 minutes') ORDER BY id DESC LIMIT 1",
		visitorID,
	).Scan(&lastSID)
	if err != nil && err != sql.ErrNoRows {
		return "", false, err
	}

	if lastSID != "" {
		return lastSID, false, nil
	}

	return generateVisitorID(), true, nil
}

func generateVisitorID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Basic UA parsing - good enough for analytics categories, not trying
// to be comprehensive. Returns the browser family name.
func parseBrowser(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "edg/"):
		return "Edge"
	case strings.Contains(ua, "opr/") || strings.Contains(ua, "opera"):
		return "Opera"
	case strings.Contains(ua, "chrome") && !strings.Contains(ua, "edg/"):
		return "Chrome"
	case strings.Contains(ua, "safari") && !strings.Contains(ua, "chrome"):
		return "Safari"
	case strings.Contains(ua, "firefox"):
		return "Firefox"
	case strings.Contains(ua, "bot") || strings.Contains(ua, "crawl") || strings.Contains(ua, "spider"):
		return "Bot"
	}
	return "Other"
}

func parseOS(ua string) string {
	ua = strings.ToLower(ua)
	switch {
	case strings.Contains(ua, "iphone") || strings.Contains(ua, "ipad"):
		return "iOS"
	case strings.Contains(ua, "android"):
		return "Android"
	case strings.Contains(ua, "mac os"):
		return "macOS"
	case strings.Contains(ua, "windows"):
		return "Windows"
	case strings.Contains(ua, "linux"):
		return "Linux"
	case strings.Contains(ua, "bot") || strings.Contains(ua, "crawl"):
		return "Bot"
	}
	return "Other"
}

// AnalyticsBeaconJS returns the lightweight JS beacon that fires on
// every page load. Embedded by layout.go into every page when
// analytics is enabled. ~600 bytes minified.
func AnalyticsBeaconJS() string {
	// Two beacons per pageview:
	//   1. on load - records the visit (d=0, fin=0). Server INSERTs a row.
	//   2. on beforeunload - records the dwell time (d=dur, fin=1).
	//      Server UPDATEs the existing row's duration; does NOT insert.
	// Without the `fin` flag, both beacons used to insert separate rows
	// and a single visit was counted twice.
	return `<script>
(function(){
var d=document,w=window,n=navigator;
var p=location.pathname,r=d.referrer||'';
var u=new URLSearchParams(location.search);
var vid='';
try{var c=d.cookie.match(/_bm_vid=([^;]+)/);if(c)vid=c[1];}catch(e){}
var t0=Date.now();
function send(dur,fin){
var b={p:p,r:r,sw:screen.width,sh:screen.height,d:dur||0,fin:fin?1:0,us:u.get('utm_source')||'',um:u.get('utm_medium')||'',uc:u.get('utm_campaign')||''};
if(n.sendBeacon){n.sendBeacon('/api/_analytics',JSON.stringify(b));}
else{var x=new XMLHttpRequest();x.open('POST','/api/_analytics',true);x.setRequestHeader('Content-Type','application/json');x.send(JSON.stringify(b));}
}
send(0,0);
w.addEventListener('beforeunload',function(){send(Date.now()-t0,1);});
})();
</script>`
}

// AnalyticsCookieNotice returns a small, dismissible cookie notice
// for apps that have analytics enabled. Injected once per visitor
// (tracks dismissal via localStorage).
// AnalyticsCookieNotice renders the consent banner shown until a visitor
// makes a choice. Two buttons - Accept and Decline - both persist the
// choice as the `bm_cookie_consent` cookie (NOT localStorage) so the
// server-side analytics handler can read it on subsequent requests and
// skip the visitor cookie + DB write when the visitor declined.
//
// The previous "OK"-only implementation was non-compliant: there was no
// way to refuse, and the analytics cookie was set regardless of whether
// the visitor saw or interacted with the banner. GDPR / ePrivacy /
// CCPA all require a clear decline path and require that non-essential
// cookies aren't set until consent is given.
//
// The cookie has a 1-year MaxAge so the banner doesn't re-appear on
// every visit. `SameSite=Lax` and `Secure` (over HTTPS) lock it down
// to first-party use. We deliberately don't use localStorage for the
// consent record - only a cookie can be read server-side, and the
// server is the gate that actually prevents tracking when declined.
//
// Intentionally NO link to a privacy policy. The data controller for
// a customer app's tracking is the customer (the framework is the
// processor - visitor data lands in the app's own data.db, never
// leaves the app's own database), so a "Learn more" link rooted at
// `/privacy` would either 404 (when the customer hasn't written one)
// or send visitors to whatever boilerplate the customer pasted in,
// which may not accurately describe the framework's tracking. The
// safer default is no link - customers who want a real disclosure
// can add /privacy themselves and reference it from their own
// footer. The security scan's GDPR check (security_scan.go) flags
// missing /privacy as a warning so this gets surfaced.
func AnalyticsCookieNotice(app *App) string {
	text, link := analyticsNoticeCopy(app)
	return `<div id="bm-cookie" role="region" aria-label="Cookie consent" style="display:none;position:fixed;bottom:16px;left:16px;z-index:99990;max-width:380px;padding:14px 16px;border-radius:10px;background:#18181b;border:1px solid #27272a;box-shadow:0 8px 24px rgba(0,0,0,0.3);font-family:system-ui,sans-serif;font-size:12px;color:#a1a1aa;line-height:1.5;">
  <div style="margin-bottom:10px;">` + text + link + `</div>
  <div style="display:flex;gap:8px;">
    <button id="bm-cookie-accept" type="button" style="padding:6px 14px;border-radius:6px;border:1px solid #52525b;background:#27272a;color:#e4e4e7;font-size:11px;font-weight:600;cursor:pointer;font-family:inherit;">Accept</button>
    <button id="bm-cookie-decline" type="button" style="padding:6px 14px;border-radius:6px;border:1px solid #3f3f46;background:transparent;color:#a1a1aa;font-size:11px;font-weight:500;cursor:pointer;font-family:inherit;">Decline</button>
  </div>
</div>
<script>
(function(){
  // The choice lives in the bm_cookie_consent cookie ("accepted" or
  // "declined"). Page scripts read it with window.bmCookieConsent() and
  // hear changes as a bm:cookie-consent event on document (detail is the
  // choice), so a third-party script can wait for "accepted".
  // window.bmCookieSettings() shows the banner again to change the choice.
  function read(){
    var c = document.cookie.split('; ').find(function(c){ return c.startsWith('bm_cookie_consent='); });
    return c ? c.slice('bm_cookie_consent='.length) : '';
  }
  function show(on){ var el = document.getElementById('bm-cookie'); if (el) el.style.display = on ? 'block' : 'none'; }
  function setConsent(v){
    // 1 year, SameSite=Lax. Secure flag set automatically when served over https.
    var maxAge = 365*24*3600;
    var secure = location.protocol === 'https:' ? '; Secure' : '';
    document.cookie = 'bm_cookie_consent=' + v + '; Max-Age=' + maxAge + '; Path=/; SameSite=Lax' + secure;
    show(false);
    try { document.dispatchEvent(new CustomEvent('bm:cookie-consent', { detail: v })); } catch(e) {}
  }
  window.bmCookieConsent = read;
  window.bmCookieSettings = function(){ show(true); };
  // Migrate old localStorage-based "OK" click → cookie consent. The
  // previous banner stored consent in localStorage.bm_cookie_ok, which
  // the server can't read (so visitors who already clicked OK before
  // this change would see the new banner reappear). Carry the old
  // click forward as an explicit accept + clean up the stale key.
  // Automated browsers (navigator.webdriver: Playwright, Puppeteer, CDP)
  // get no banner: it covered the page in agents' own checks. Their consent
  // stays unset, which already means no analytics; bmCookieSettings() still
  // shows it on demand.
  if (!read() && !navigator.webdriver) {
    try {
      if (localStorage.getItem('bm_cookie_ok') === '1') {
        setConsent('accepted');
        localStorage.removeItem('bm_cookie_ok');
      } else {
        show(true);
      }
    } catch(e) { show(true); /* localStorage may be blocked */ }
  }
  var accept = document.getElementById('bm-cookie-accept');
  var decline = document.getElementById('bm-cookie-decline');
  if (accept) accept.onclick = function(){ setConsent('accepted'); };
  if (decline) decline.onclick = function(){ setConsent('declined'); };
})();
</script>`
}

// analyticsDefaultNotice is what the banner says unless the app sets
// seo.cookie_notice. It describes only the framework's own analytics: a
// visitor cookie and page-view events, recorded after Accept. It does not
// promise anonymity (a signed-in visitor's account id is recorded) or the
// absence of trackers an app adds itself.
const analyticsDefaultNotice = "We use a cookie to measure how this site is used. Nothing is recorded unless you accept."

// analyticsNoticeCopy returns the banner's escaped text and optional privacy
// link from app.yaml seo.cookie_notice and seo.privacy_url. An app that adds
// its own trackers (analytics, ads) must name them in cookie_notice. The link
// accepts a same-origin path or an https URL only.
func analyticsNoticeCopy(app *App) (text, link string) {
	text = html.EscapeString(analyticsDefaultNotice)
	if app == nil || app.Design == nil {
		return text, ""
	}
	if custom := strings.TrimSpace(app.Design.SEO["cookie_notice"]); custom != "" {
		text = html.EscapeString(custom)
	}
	if u := strings.TrimSpace(app.Design.SEO["privacy_url"]); analyticsNoticeLinkOK(u) {
		link = ` <a href="` + html.EscapeString(u) + `" style="color:inherit;text-decoration:underline;">Privacy policy</a>`
	}
	return text, link
}

func analyticsNoticeLinkOK(u string) bool {
	if strings.HasPrefix(u, "/") && !strings.HasPrefix(u, "//") && !strings.ContainsAny(u, "\\ \t\n") {
		return true
	}
	parsed, err := url.Parse(u)
	return err == nil && parsed.Scheme == "https" && parsed.Host != ""
}

// cookieConsentGiven returns true when the visitor has explicitly
// accepted analytics cookies via the banner. Used by the analytics
// beacon handler to decide whether to set the visitor cookie and
// persist a tracking row. Absence of the cookie (first-time visitor
// who hasn't clicked yet) counts as NOT given - track nothing until
// explicit opt-in.
func cookieConsentGiven(r *http.Request) bool {
	c, err := r.Cookie("bm_cookie_consent")
	if err != nil {
		return false
	}
	return c.Value == "accepted"
}
