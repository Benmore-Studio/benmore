//go:build !cli

package main

import (
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// ===== Demo Mode =====
// When features.feedback (demo mode) is enabled:
// 1. The entire app is password-gated with a simple password (DEMO_PASSWORD env var)
// 2. Anyone who passes the gate can leave feedback via a floating widget
// 3. Feedback appears in the admin panel with comments + status tracking
// 4. Brute-force protection: 3 failed attempts → 15 min lockout per IP

// EnsureFeedbackTables creates the feedback tables.
func EnsureFeedbackTables(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_feedback (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		visitor_name TEXT,
		visitor_email TEXT,
		page_url TEXT NOT NULL,
		body TEXT NOT NULL,
		element_selector TEXT,
		screenshot TEXT,
		status TEXT NOT NULL DEFAULT 'open',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_feedback_comments (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		feedback_id INTEGER NOT NULL REFERENCES _benmore_feedback(id),
		user_id INTEGER,
		user_email TEXT,
		body TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
}

// --- Brute-force protection ---
type demoAttemptTracker struct {
	mu       sync.Mutex
	attempts map[string][]time.Time // IP → timestamps of failed attempts
}

var demoTracker = &demoAttemptTracker{attempts: make(map[string][]time.Time)}

func (t *demoAttemptTracker) isLocked(ip string) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	attempts := t.attempts[ip]
	// Clean old attempts (older than 15 min)
	cutoff := time.Now().Add(-15 * time.Minute)
	var recent []time.Time
	for _, a := range attempts {
		if a.After(cutoff) {
			recent = append(recent, a)
		}
	}
	t.attempts[ip] = recent
	return len(recent) >= 3
}

func (t *demoAttemptTracker) recordFail(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.attempts[ip] = append(t.attempts[ip], time.Now())
}

func (t *demoAttemptTracker) clearAttempts(ip string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.attempts, ip)
}

// demoSessionToken generates a deterministic token from the password so all
// valid sessions share the same token (no storage needed).
func demoSessionToken(password string) string {
	h := sha256.Sum256([]byte("benmore-demo:" + password))
	return hex.EncodeToString(h[:16])
}

// DemoGateMiddleware wraps the entire mux to require a demo password.
func DemoGateMiddleware(password string, next http.Handler) http.Handler {
	token := demoSessionToken(password)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Allow static assets, internal routes, API routes, and the gate itself
		if strings.HasPrefix(r.URL.Path, "/static/") ||
			strings.HasPrefix(r.URL.Path, "/_internal/") ||
			strings.HasPrefix(r.URL.Path, "/api/") ||
			strings.HasPrefix(r.URL.Path, "/auth/") ||
			r.URL.Path == "/favicon.ico" ||
			r.URL.Path == "/robots.txt" ||
			r.URL.Path == "/sw.js" ||
			r.URL.Path == "/_demo/login" {
			next.ServeHTTP(w, r)
			return
		}

		// Check for valid demo session cookie
		cookie, err := r.Cookie("demo_session")
		if err == nil && cookie.Value == token {
			next.ServeHTTP(w, r)
			return
		}

		// Show the demo gate page
		serveDemoGate(w, r, "")
	})
}

// RegisterDemoLoginRoute wires POST /_demo/login - the endpoint the
// gate page posts to. Split out of RegisterDemoRoutes (v2.7.164) so
// the visitor-password gate works WITHOUT features.testing: the gate
// middleware excludes /_demo/login from gating, so this route must
// exist whenever the middleware is armed or the login form 404s and
// the app bricks for every visitor.
func RegisterDemoLoginRoute(mux *http.ServeMux, app *App, password string) {
	token := demoSessionToken(password)
	mux.HandleFunc("POST /_demo/login", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		// Use RemoteAddr for rate limiting - don't trust X-Forwarded-For (spoofable)
		ip, _, _ := net.SplitHostPort(r.RemoteAddr)
		if ip == "" {
			ip = r.RemoteAddr
		}

		if demoTracker.isLocked(ip) {
			serveDemoGate(w, r, "Too many attempts. Please try again in 15 minutes.")
			return
		}

		pw := r.FormValue("password")
		// Constant-time comparison to prevent timing attacks
		if !hmac.Equal([]byte(pw), []byte(password)) {
			demoTracker.recordFail(ip)
			remaining := 3 - len(demoTracker.attempts[ip])
			if remaining < 0 {
				remaining = 0
			}
			msg := "Incorrect password."
			if remaining == 0 {
				msg = "Too many attempts. Please try again in 15 minutes."
			}
			serveDemoGate(w, r, msg)
			return
		}

		demoTracker.clearAttempts(ip)
		// protoOf for proxy-correct Secure flag - see #18.
		http.SetCookie(w, &http.Cookie{
			Name:     "demo_session",
			Value:    token,
			Path:     "/",
			MaxAge:   86400 * 7, // 7 days
			HttpOnly: true,
			Secure:   protoOf(r) == "https",
			SameSite: http.SameSiteLaxMode,
		})
		http.Redirect(w, r, "/", http.StatusSeeOther)
	})
}

// RegisterDemoRoutes sets up the demo login + feedback API.
func RegisterDemoRoutes(mux *http.ServeMux, app *App, password string) {
	EnsureFeedbackTables(app.DB)
	token := demoSessionToken(password)

	RegisterDemoLoginRoute(mux, app, password)

	// Webhook config
	webhookURL := GetAppEnv(app.Dir, "TESTING_WEBHOOK_URL")
	webhookToken := GetAppEnv(app.Dir, "TESTING_WEBHOOK_TOKEN")

	// POST /api/_feedback - submit feedback (anyone with demo session)
	mux.HandleFunc("POST /api/_feedback", func(w http.ResponseWriter, r *http.Request) {
		// Verify demo session
		cookie, err := r.Cookie("demo_session")
		if err != nil || cookie.Value != token {
			// Also allow authenticated users
			session := getSession(app, r)
			if session == nil {
				httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "access denied"})
				return
			}
		}

		var body struct {
			Name            string `json:"name"`
			Email           string `json:"email"`
			PageURL         string `json:"page_url"`
			Body            string `json:"body"`
			ElementSelector string `json:"element_selector"`
			Screenshot      string `json:"screenshot"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Body) == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "feedback body is required"})
			return
		}
		if len(body.Screenshot) > 2*1024*1024 {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "screenshot too large (2MB max)"})
			return
		}

		result, err := app.DB.Exec(
			`INSERT INTO _benmore_feedback (visitor_name, visitor_email, page_url, body, element_selector, screenshot)
			 VALUES (?, ?, ?, ?, ?, ?)`,
			strings.TrimSpace(body.Name), strings.TrimSpace(body.Email),
			body.PageURL, strings.TrimSpace(body.Body),
			body.ElementSelector, body.Screenshot)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to save"})
			return
		}
		id, _ := result.LastInsertId()

		// Fire webhook if configured
		if webhookURL != "" {
			go func() {
				payload := map[string]any{
					"id":               id,
					"app_id":           app.AppID,
					"external_id":      app.ExternalID,
					"visitor_name":     strings.TrimSpace(body.Name),
					"visitor_email":    strings.TrimSpace(body.Email),
					"page_url":         body.PageURL,
					"body":             strings.TrimSpace(body.Body),
					"element_selector": body.ElementSelector,
					"screenshot":       body.Screenshot,
					"app_url":          r.Host,
					"timestamp":        time.Now().UTC().Format(time.RFC3339),
				}
				if isPrivateURL(webhookURL) {
					return
				}
				jsonData, _ := json.Marshal(payload)
				req, err := http.NewRequest("POST", webhookURL, strings.NewReader(string(jsonData)))
				if err != nil {
					return
				}
				req.Header.Set("Content-Type", "application/json")
				if webhookToken != "" {
					req.Header.Set("Authorization", "Bearer "+webhookToken)
				}
				client := safeHTTPClient(10 * time.Second)
				client.Do(req)
			}()
		}

		httpJSON(w, http.StatusOK, map[string]any{"id": id, "status": "submitted"})
	})

	// GET /api/_feedback - list feedback (admin only)
	mux.HandleFunc("GET /api/_feedback", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}
		rows, _ := QueryRows(app.DB, `SELECT id, visitor_name, visitor_email, page_url, body, element_selector, status, created_at
			FROM _benmore_feedback ORDER BY created_at DESC`)
		httpJSON(w, http.StatusOK, rows)
	})

	// GET /api/_feedback/{id} - single feedback with comments
	mux.HandleFunc("GET /api/_feedback/{id}", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}
		id := r.PathValue("id")
		rows, _ := QueryRows(app.DB, "SELECT * FROM _benmore_feedback WHERE id = ?", id)
		if len(rows) == 0 {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		comments, _ := QueryRows(app.DB, "SELECT * FROM _benmore_feedback_comments WHERE feedback_id = ? ORDER BY created_at", id)
		result := rows[0]
		result["comments"] = comments
		httpJSON(w, http.StatusOK, result)
	})

	// PATCH /api/_feedback/{id} - update status (admin)
	mux.HandleFunc("PATCH /api/_feedback/{id}", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF"})
			return
		}
		var body struct {
			Status string `json:"status"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		allowed := map[string]bool{"open": true, "in_progress": true, "resolved": true, "wont_fix": true}
		if !allowed[body.Status] {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid status"})
			return
		}
		app.DB.Exec("UPDATE _benmore_feedback SET status = ? WHERE id = ?", body.Status, r.PathValue("id"))
		httpJSON(w, http.StatusOK, map[string]any{"status": body.Status})
	})

	// POST /api/_feedback/{id}/comment - add comment (admin)
	mux.HandleFunc("POST /api/_feedback/{id}/comment", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF"})
			return
		}
		var body struct {
			Body string `json:"body"`
		}
		json.NewDecoder(r.Body).Decode(&body)
		if strings.TrimSpace(body.Body) == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "body required"})
			return
		}
		app.DB.Exec("INSERT INTO _benmore_feedback_comments (feedback_id, user_id, user_email, body) VALUES (?, ?, ?, ?)",
			r.PathValue("id"), session.UserID, session.Email, strings.TrimSpace(body.Body))
		httpJSON(w, http.StatusOK, map[string]any{"status": "commented"})
	})

	if webhookURL != "" {
		log.Printf("  testing: webhook → %s", webhookURL)
	}

	// Test data reset (admin only, testing mode only)
	mux.HandleFunc("POST /api/_testing/reset", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF"})
			return
		}
		// Get all app tables (not _benmore_ tables)
		tables, _ := GetTableNames(app.DB)
		for _, t := range tables {
			if !strings.HasPrefix(t, "_benmore_") {
				app.DB.Exec(fmt.Sprintf("DELETE FROM %s", t))
			}
		}
		// Re-run seeds
		seedPath := app.Dir + "/seeds.sql"
		seedData, err := readFileFromDir(app.Dir, "seeds.sql")
		if err != nil {
			httpJSON(w, http.StatusOK, map[string]any{"status": "cleared", "seeds": false, "note": "no seeds.sql found"})
			return
		}
		_ = seedPath
		statements := strings.Split(string(seedData), ";")
		for _, stmt := range statements {
			stmt = strings.TrimSpace(stmt)
			if stmt != "" {
				app.DB.Exec(stmt)
			}
		}
		httpJSON(w, http.StatusOK, map[string]any{"status": "reset", "seeds": true, "tables_cleared": len(tables)})
	})

	log.Printf("  testing mode: password-gated, feedback widget, test reset")
}

// RegisterFeedbackAPI registers the feedback read/write endpoints without
// requiring a demo password. Called whenever features.testing is enabled
// so the widget can submit feedback with a regular authenticated session
// and MCP tools can read from the table.
func RegisterFeedbackAPI(mux *http.ServeMux, app *App) {
	webhookURL := GetAppEnv(app.Dir, "TESTING_WEBHOOK_URL")
	webhookToken := GetAppEnv(app.Dir, "TESTING_WEBHOOK_TOKEN")

	// POST /api/_feedback - submit. Open to anonymous visitors so people
	// previewing a draft (e.g., on /login) can leave feedback without an
	// account. Authenticated users get their email auto-attached.
	mux.HandleFunc("POST /api/_feedback", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)

		var body struct {
			Name            string `json:"name"`
			Email           string `json:"email"`
			PageURL         string `json:"page_url"`
			Body            string `json:"body"`
			ElementSelector string `json:"element_selector"`
			Screenshot      string `json:"screenshot"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Body) == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "feedback body is required"})
			return
		}
		if session != nil {
			if body.Name == "" {
				body.Name = session.Email
			}
			if body.Email == "" {
				body.Email = session.Email
			}
		} else {
			if body.Name == "" {
				body.Name = "Anonymous"
			}
		}

		result, err := app.DB.Exec(
			`INSERT INTO _benmore_feedback (visitor_name, visitor_email, page_url, body, element_selector, screenshot) VALUES (?, ?, ?, ?, ?, ?)`,
			strings.TrimSpace(body.Name), strings.TrimSpace(body.Email),
			body.PageURL, strings.TrimSpace(body.Body),
			body.ElementSelector, body.Screenshot)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to save"})
			return
		}
		id, _ := result.LastInsertId()

		if webhookURL != "" && !isPrivateURL(webhookURL) {
			go func() {
				payload, _ := json.Marshal(map[string]any{"id": id, "body": body.Body, "page_url": body.PageURL, "email": body.Email})
				req, _ := http.NewRequest("POST", webhookURL, strings.NewReader(string(payload)))
				if req != nil {
					req.Header.Set("Content-Type", "application/json")
					if webhookToken != "" {
						req.Header.Set("Authorization", "Bearer "+webhookToken)
					}
					(safeHTTPClient(10 * time.Second)).Do(req)
				}
			}()
		}
		httpJSON(w, http.StatusOK, map[string]any{"id": id, "status": "submitted"})
	})

	// GET /api/_feedback - list (any authenticated user on drafts).
	// Anonymous callers get an empty list (not 401) so the injected widget
	// on /login doesn't spam red errors in the console.
	mux.HandleFunc("GET /api/_feedback", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusOK, []any{})
			return
		}
		rows, _ := QueryRows(app.DB, `SELECT id, visitor_name, visitor_email, page_url, body, element_selector, status, created_at FROM _benmore_feedback ORDER BY created_at DESC`)
		httpJSON(w, http.StatusOK, rows)
	})

	// GET /api/_feedback/{id}
	mux.HandleFunc("GET /api/_feedback/{id}", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "login required"})
			return
		}
		rows, _ := QueryRows(app.DB, "SELECT * FROM _benmore_feedback WHERE id = ?", r.PathValue("id"))
		if len(rows) == 0 {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
			return
		}
		comments, _ := QueryRows(app.DB, "SELECT * FROM _benmore_feedback_comments WHERE feedback_id = ? ORDER BY created_at", r.PathValue("id"))
		result := rows[0]
		result["comments"] = comments
		httpJSON(w, http.StatusOK, result)
	})

	log.Printf("  feedback: API registered at /api/_feedback")
}

func serveDemoGate(w http.ResponseWriter, r *http.Request, errMsg string) {
	errorHTML := ""
	if errMsg != "" {
		errorHTML = fmt.Sprintf(`<div style="background:#fef2f2;border:1px solid #fecaca;padding:10px 14px;font-size:13px;color:#dc2626;margin-bottom:16px;border-radius:8px;">%s</div>`, html.EscapeString(errMsg))
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprintf(w, `<!DOCTYPE html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Demo Access</title>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:system-ui,-apple-system,sans-serif;background:#f8fafc;display:flex;align-items:center;justify-content:center;min-height:100vh;padding:24px}</style>
</head><body>
<div style="background:#fff;border:1px solid #e2e8f0;border-radius:16px;padding:40px;max-width:380px;width:100%%;box-shadow:0 4px 24px rgba(0,0,0,0.06);">
  <div style="text-align:center;margin-bottom:24px;">
    <div style="width:48px;height:48px;border-radius:12px;background:#f1f5f9;display:inline-flex;align-items:center;justify-content:center;margin-bottom:16px;">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
    </div>
    <h1 style="font-size:20px;font-weight:600;color:#1e293b;margin-bottom:4px;">Demo Access</h1>
    <p style="font-size:14px;color:#64748b;">Enter the password to preview this application.</p>
  </div>
  %s
  <form method="POST" action="/_demo/login">
    <input type="password" name="password" placeholder="Demo password" autofocus required
      style="width:100%%;height:44px;padding:0 14px;border:1px solid #e2e8f0;border-radius:8px;font-size:14px;color:#1e293b;outline:none;margin-bottom:16px;"
      onfocus="this.style.borderColor='#7c3aed';this.style.boxShadow='0 0 0 3px rgba(124,58,237,0.1)'"
      onblur="this.style.borderColor='#e2e8f0';this.style.boxShadow='none'">
    <button type="submit" style="width:100%%;height:44px;background:#1e293b;color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:500;cursor:pointer;">
      Enter Demo
    </button>
  </form>
</div>
</body></html>`, errorHTML)
}

// FeedbackWidgetHTML returns the floating feedback widget HTML/JS.
// In demo mode, shows for everyone (no auth check needed - gate handles access).
// TestingBannerHTML returns a collapsible session info bar for QA testers.
// TestingBannerHTML returns the auto-injected amber preview banner shown
// at the top of every page when testing mode is active. Drafts auto-enable
// testing (App.FeatureEnabled) so this is the unified banner for both:
//
//   - Public draft preview - anonymous visitor on a draft-preview URL,
//     no session, sees just the "Draft Preview" branding + Built with Benmore link
//   - Logged-in tester/admin - sees the same banner plus their email and role
//     pinned inline so they know who they're authenticated as
//   - Demo-password-gated demo on a prod app - same banner, gate is enforced
//     separately by DemoGateMiddleware
//
// Not dismissable on drafts because dismissing would defeat the point -
// the banner is the entire emotional difference between draft and prod.
// TestingBannerHTML used to inject a fixed top banner that stole 32px
// of viewport height - a constant source of clipped 100vh layouts. The
// banner has been replaced by a popover on the Built-with-Benmore
// badge (see BuiltWithBadgeHTML), which carries the same metadata
// without disturbing the page geometry. Function kept as a no-op so
// existing callers in WrapLayoutWithPage / injectRawPageEssentials
// don't break.
func TestingBannerHTML(session *Session, app *App) string { return "" }

// testingBannerHTMLLegacy retains the original implementation -
// unused at runtime but preserved here so the wire format is easy to
// reference if we ever bring a different banner back. Marked unused
// with _ assignment in callers, or remove if Go vet complains.
func testingBannerHTMLLegacy(session *Session, app *App) string {
	siteName := ""
	if app != nil && app.Design != nil && app.Design.SEO != nil {
		siteName = app.Design.SEO["site_name"]
	}
	if siteName == "" {
		siteName = "this app"
	}

	// Build the optional session pill (right side of the banner)
	sessionPill := ""
	if session != nil {
		role := session.Role
		appRole := resolveAppRole(app, session)
		if appRole != "" && appRole != role {
			role = role + " / " + appRole
		}
		sessionPill = fmt.Sprintf(`<span class="bm-tb-session" style="display:flex;align-items:center;gap:6px;padding:2px 8px;border-radius:9999px;background:rgba(120,53,15,0.12);border:1px solid rgba(120,53,15,0.18);font-size:10.5px;font-weight:600;white-space:nowrap;">%s · %s</span>`, escapeHTMLAttr(session.Email), escapeHTMLAttr(role))
	}

	label := "Testing Mode"

	return fmt.Sprintf(`<!-- Preview Banner (auto-injected by Benmore) -->
<style>
/* The banner is fixed at top:0 with a 32px height. Add matching
   body padding-top AND expose the height as a CSS variable so apps
   that compute their own viewport (height: 100vh dashboards, full-
   screen flex layouts, etc.) can subtract it without hard-coding.
   Use it like: height: calc(100vh - var(--bm-chrome-top, 0px));
   Variable is unset when the banner is off, so the fallback 0px
   keeps non-banner pages working unchanged. */
:root{--bm-chrome-top:32px}
body{padding-top:32px}
#bm-test-banner{position:fixed;top:0;left:0;right:0;z-index:99999;background:linear-gradient(90deg,#fbbf24 0%%,#f59e0b 50%%,#fbbf24 100%%);background-size:200%% 100%%;animation:bm-tb-shimmer 10s linear infinite;border-bottom:1px solid #d97706;padding:0 16px;font-family:system-ui,-apple-system,sans-serif;font-size:12px;color:#78350f;display:flex;align-items:center;justify-content:space-between;height:32px;box-shadow:0 1px 4px rgba(0,0,0,0.08);}
#bm-test-banner .bm-tb-left{display:flex;align-items:center;gap:10px;min-width:0;flex:1;}
#bm-test-banner .bm-tb-right{display:flex;align-items:center;gap:10px;flex-shrink:0;}
#bm-test-banner .bm-tb-pulse{width:8px;height:8px;border-radius:50%%;background:#78350f;box-shadow:0 0 0 0 rgba(120,53,15,0.6);animation:bm-tb-pulse 2s ease-in-out infinite;flex-shrink:0;}
#bm-test-banner strong{font-weight:700;letter-spacing:0.03em;text-transform:uppercase;font-size:10.5px;}
#bm-test-banner .bm-tb-msg{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}
#bm-test-banner a, #bm-test-banner button.bm-tb-link{color:#78350f;text-decoration:underline;text-decoration-thickness:1px;text-underline-offset:2px;font-weight:600;white-space:nowrap;background:none;border:none;cursor:pointer;font-size:12px;font-family:inherit;padding:0;}
#bm-test-banner a:hover, #bm-test-banner button.bm-tb-link:hover{color:#451a03;}
@keyframes bm-tb-shimmer{0%%{background-position:200%% 0}100%%{background-position:-200%% 0}}
@keyframes bm-tb-pulse{0%%,100%%{box-shadow:0 0 0 0 rgba(120,53,15,0.6)}50%%{box-shadow:0 0 0 6px rgba(120,53,15,0)}}
@media(max-width:680px){#bm-test-banner .bm-tb-extended{display:none}#bm-test-banner .bm-tb-session{display:none}}
@media(max-width:480px){#bm-test-banner .bm-tb-bwb{display:none}}

/* Testing Guide popover */
#bm-tg-overlay{position:fixed;inset:0;z-index:99999;background:rgba(0,0,0,0.6);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);display:none;align-items:center;justify-content:center;padding:24px;font-family:system-ui,-apple-system,sans-serif;}
#bm-tg-overlay.show{display:flex;}
#bm-tg-card{background:#0a0a0a;border:1px solid #2a2a2a;border-radius:16px;max-width:560px;width:100%%;max-height:85vh;overflow-y:auto;color:#e4e4e7;box-shadow:0 20px 80px rgba(0,0,0,0.6);}
#bm-tg-head{padding:24px 28px 16px;display:flex;align-items:flex-start;justify-content:space-between;gap:12px;}
#bm-tg-head h3{font-size:18px;font-weight:600;letter-spacing:-0.02em;margin:0 0 4px;color:#fff;}
#bm-tg-head p{font-size:13px;color:#888;margin:0;}
#bm-tg-close{background:none;border:none;color:#666;font-size:22px;line-height:1;cursor:pointer;padding:0 4px;flex-shrink:0;}
#bm-tg-close:hover{color:#fff;}
#bm-tg-body{padding:0 28px 24px;}
.bm-tg-section{margin-bottom:18px;}
.bm-tg-label{font-size:10.5px;font-weight:600;color:#a78bfa;text-transform:uppercase;letter-spacing:0.06em;margin-bottom:6px;}
.bm-tg-text{font-size:13px;line-height:1.6;color:#ccc;}
.bm-tg-list{margin:6px 0 0;padding-left:18px;font-size:13px;line-height:1.7;color:#aaa;}
.bm-tg-list li{margin-bottom:4px;}
.bm-tg-list code{font-family:ui-monospace,monospace;font-size:11.5px;color:#a78bfa;background:rgba(167,139,250,0.08);padding:1px 6px;border-radius:4px;border:1px solid rgba(167,139,250,0.16);}
.bm-tg-keys{display:flex;flex-direction:column;gap:8px;margin-top:6px;}
.bm-tg-key{display:flex;align-items:flex-start;gap:12px;padding:9px 12px;background:rgba(255,255,255,0.02);border:1px solid rgba(255,255,255,0.06);border-radius:8px;}
.bm-tg-key kbd{display:inline-flex;align-items:center;justify-content:center;min-width:28px;height:24px;padding:0 7px;background:linear-gradient(180deg,#1a1a1a,#0a0a0a);border:1px solid #2a2a2a;border-bottom-color:#3a3a3a;border-radius:5px;font-family:ui-monospace,monospace;font-size:11px;font-weight:600;color:#a78bfa;box-shadow:inset 0 -1px 0 rgba(0,0,0,0.4);flex-shrink:0;}
.bm-tg-key-desc{font-size:12.5px;color:#aaa;line-height:1.5;}
.bm-tg-key-desc strong{color:#e4e4e7;}
#bm-tg-foot{padding:16px 28px;border-top:1px solid #1a1a1a;display:flex;align-items:center;justify-content:space-between;}
#bm-tg-foot .bm-tg-meta{font-size:11px;color:#666;}
#bm-tg-foot button{background:linear-gradient(180deg,#fff,#ccc);color:#000;border:none;padding:8px 18px;border-radius:8px;font-size:12px;font-weight:600;cursor:pointer;font-family:inherit;}
</style>
<div id="bm-test-banner">
  <div class="bm-tb-left">
    <span class="bm-tb-pulse"></span>
    <strong>%s</strong>
    <span class="bm-tb-msg bm-tb-extended">%s · Limited functionality · Not for production use</span>
  </div>
  <div class="bm-tb-right">
    %s
    <button type="button" class="bm-tb-link" onclick="bmTgShow()">Testing guide</button>
    <a class="bm-tb-bwb" href="https://benmore.ai" target="_blank" rel="noopener">Built with Benmore</a>
  </div>
</div>
<div id="bm-tg-overlay" onclick="if(event.target.id==='bm-tg-overlay')bmTgHide()">
  <div id="bm-tg-card">
    <div id="bm-tg-head">
      <div>
        <h3>You're testing %s</h3>
        <p>This is a draft preview, not a production app. Here's what you can do.</p>
      </div>
      <button id="bm-tg-close" onclick="bmTgHide()">&times;</button>
    </div>
    <div id="bm-tg-body">
      <div class="bm-tg-section">
        <div class="bm-tg-label">What this is</div>
        <p class="bm-tg-text">A live preview of an app being built. Anyone with the link can view it. The amber bar at the top is permanent - drafts can never be promoted to production accidentally.</p>
      </div>
      <div class="bm-tg-section">
        <div class="bm-tg-label">What works</div>
        <ul class="bm-tg-list">
          <li>Sign up, log in, and use every feature like a real app</li>
          <li>Create, edit, and delete data - your test data lives in the draft database</li>
          <li>Share the URL with anyone - they can poke at it without an account</li>
        </ul>
      </div>
      <div class="bm-tg-section">
        <div class="bm-tg-label">What's limited</div>
        <ul class="bm-tg-list">
          <li><strong>No real email or webhooks.</strong> Outbound sends are captured to a dashboard inbox, not delivered.</li>
          <li><strong>No background jobs.</strong> Cron tasks are disabled on drafts.</li>
          <li><strong>Rate limited.</strong> 60 requests per minute per IP - enough to test, not enough to load-test.</li>
          <li><strong>Storage capped.</strong> 50 MB per draft branch.</li>
        </ul>
      </div>
      <div class="bm-tg-section">
        <div class="bm-tg-label">How to give feedback</div>
        <p class="bm-tg-text">Click the purple <strong>Feedback</strong> tab on the right edge of any page, or use the keyboard shortcuts below. You can leave a comment, attach a screenshot, and pin it to the exact element you're talking about. The app's owner sees your feedback in their dashboard.</p>
      </div>
      <div class="bm-tg-section">
        <div class="bm-tg-label">Keyboard shortcuts</div>
        <div class="bm-tg-keys">
          <div class="bm-tg-key"><kbd>F</kbd><div class="bm-tg-key-desc"><strong>Feedback</strong> - open a comment input anywhere on the page</div></div>
          <div class="bm-tg-key"><kbd>E</kbd><div class="bm-tg-key-desc"><strong>Element selector</strong> - pin a comment to a specific element by clicking it</div></div>
          <div class="bm-tg-key"><kbd>S</kbd><div class="bm-tg-key-desc"><strong>Screenshot</strong> - capture the current page and attach it to a comment</div></div>
          <div class="bm-tg-key"><kbd>Esc</kbd><div class="bm-tg-key-desc">Close any open feedback input or this guide</div></div>
        </div>
        <p class="bm-tg-text" style="font-size:11px;color:#666;margin-top:8px;">Shortcuts work on every page - just type the letter while not focused on an input field.</p>
      </div>
      <div class="bm-tg-section">
        <div class="bm-tg-label">Found a bug?</div>
        <p class="bm-tg-text">Hit <kbd style="background:#1a1a1a;border:1px solid #2a2a2a;padding:1px 6px;border-radius:4px;font-family:ui-monospace,monospace;font-size:11px;color:#a78bfa;">S</kbd> to grab a screenshot, then describe what you expected vs what happened. The team will see the URL, the screenshot, and the element you were on automatically.</p>
      </div>
    </div>
    <div id="bm-tg-foot">
      <span class="bm-tg-meta">Powered by <a href="https://benmore.ai" target="_blank" rel="noopener" style="color:#a78bfa;text-decoration:none;">Benmore</a></span>
      <button onclick="bmTgHide()">Got it</button>
    </div>
  </div>
</div>
<script>
document.body.style.paddingTop='32px';
function bmTgShow(){var o=document.getElementById('bm-tg-overlay');if(o)o.classList.add('show');}
function bmTgHide(){var o=document.getElementById('bm-tg-overlay');if(o)o.classList.remove('show');}
document.addEventListener('keydown',function(e){if(e.key==='Escape')bmTgHide();});
</script>
`, label, escapeHTMLAttr(siteName), sessionPill, escapeHTMLAttr(siteName))
}

// BuiltWithBadgeHTML returns the sticky bottom-right "Built with Benmore"
// attribution badge. It renders ONLY for the hosted platform's free tier
// (OwnerPlan == "free"); self-hosted apps (no platform plan) and paid plans
// render nothing. Build time, when tracked, is sourced from app.BuildSeconds.
func BuiltWithBadgeHTML(app *App) string {
	if app == nil {
		return ""
	}
	if app.Dir != "" && filepath.Base(app.Dir) == "_platform" {
		return ""
	}
	// Free-tier-only attribution (paid plans + self-hosted render nothing).
	if app.OwnerPlan != "free" {
		return ""
	}
	subRef := ""
	if app.Dir != "" {
		subRef = filepath.Base(app.Dir)
	}
	return BuiltWithBenmorePill(subRef)
}

// BuiltWithBenmorePill is the standardized "Built with Benmore" attribution
// chip used IDENTICALLY by deployed apps and edges: a fixed bottom-right rounded
// pill with the Benmore logo that links STRAIGHT to benmore.ai - no popover, no
// "experimental" interstitial. ref tags the inbound link (app subdomain, or "edge").
func BuiltWithBenmorePill(ref string) string {
	return fmt.Sprintf(`<a href="https://benmore.ai/?ref=%s" target="_blank" rel="noopener" aria-label="Built with Benmore" style="position:fixed;bottom:16px;right:16px;z-index:99996;display:inline-flex;align-items:center;gap:8px;padding:6px 14px 6px 6px;border-radius:9999px;background:#fff;border:1px solid #e4e4e7;box-shadow:0 2px 8px rgba(0,0,0,0.10);text-decoration:none;color:#18181b;font-family:system-ui,-apple-system,sans-serif;font-size:12px;font-weight:500;line-height:1;white-space:nowrap;"><img src="%s" alt="" width="20" height="20" style="display:block;width:20px;height:20px;max-width:none;min-width:0;margin:0;padding:0;border:0;border-radius:5px;flex-shrink:0;"/><span style="color:#52525b;font:500 12px/1 system-ui,-apple-system,sans-serif;">Built with Benmore</span></a>`, ref, benmoreLogoDataURI)
}
// buildInfoSection renders the "Currently on" + "Testing mode"
// metadata blocks for the badge popover. When testing mode is off,
// returns just the site identity row; when on, adds a "Testing
// Mode" tag + role indicator that the floating banner used to show.
func buildInfoSection(app *App, siteName string, testing bool) string {
	parts := []string{}
	parts = append(parts, fmt.Sprintf(
		`<div class="bm-ip-section"><p class="bm-ip-h">App</p><div class="bm-ip-kv"><span class="bm-ip-k">Site</span><span class="bm-ip-v">%s</span></div></div>`,
		escapeHTMLAttr(siteName)))
	if testing {
		// Hotkeys live in feedback_ui.go's widget script - keep this
		// list in sync. Rendered as a stacked block so the keys stay
		// readable in the narrow popover (label/value would wrap
		// awkwardly with three rows).
		parts = append(parts, `<div class="bm-ip-section">`+
			`<p class="bm-ip-h">Testing mode</p>`+
			`<p style="margin:0 0 6px;font-size:12px;">Feedback widget is on. Use these from anywhere on the page:</p>`+
			`<div style="display:grid;grid-template-columns:auto 1fr;gap:4px 10px;font-size:12px;">`+
			`<kbd style="font-family:ui-monospace,monospace;background:rgba(0,0,0,0.06);padding:1px 6px;border-radius:4px;font-size:11px;text-align:center;">F</kbd><span>Leave a written note</span>`+
			`<kbd style="font-family:ui-monospace,monospace;background:rgba(0,0,0,0.06);padding:1px 6px;border-radius:4px;font-size:11px;text-align:center;">E</kbd><span>Pick an element to comment on</span>`+
			`<kbd style="font-family:ui-monospace,monospace;background:rgba(0,0,0,0.06);padding:1px 6px;border-radius:4px;font-size:11px;text-align:center;">S</kbd><span>Capture a screenshot</span>`+
			`</div></div>`)
	}
	return strings.Join(parts, "\n")
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

// escapeHTMLAttr escapes a string for safe inclusion in an HTML attribute
// or text node. Used by the banner to prevent injection from app metadata.
func escapeHTMLAttr(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, `"`, "&quot;")
	s = strings.ReplaceAll(s, "'", "&#39;")
	return s
}

func FeedbackWidgetHTML() string {
	return `<!-- bm-feedback-widget -->
<div id="bm-fb-root">
<!-- Draggable, minimizable feedback FAB (testing mode). Position + minimized
     state persist in localStorage; re-applied on every re-inject. -->
<div id="bm-feedback-btn" title="Feedback - drag to move" style="position:fixed;right:18px;bottom:18px;z-index:99990;font-family:system-ui,-apple-system,sans-serif;touch-action:none;user-select:none;-webkit-user-select:none;">
  <div id="bm-fb-fab" style="position:relative;display:flex;align-items:center;justify-content:center;width:44px;height:44px;border-radius:50%;background:#7c3aed;box-shadow:0 4px 14px rgba(124,58,237,0.4);cursor:grab;transition:width 0.12s,height 0.12s,background 0.15s;" onmouseover="this.style.background='#6d28d9'" onmouseout="this.style.background='#7c3aed'">
    <svg id="bm-fb-flag" viewBox="0 0 24 24" fill="none" stroke="#ffffff" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="width:20px;height:20px;pointer-events:none;"><path d="M4 15s1-1 4-1 5 2 8 2 4-1 4-1V3s-1 1-4 1-5-2-8-2-4 1-4 1z"/><line x1="4" y1="22" x2="4" y2="15"/></svg>
    <div id="bm-fb-badge" style="display:none;position:absolute;top:-2px;right:-2px;width:10px;height:10px;border-radius:50%;background:#22c55e;border:2px solid #ffffff;"></div>
  </div>
  <button id="bm-fb-min" title="Minimize" style="position:absolute;top:-7px;left:-7px;width:18px;height:18px;border-radius:50%;background:#ffffff;border:1px solid #e2e8f0;box-shadow:0 1px 4px rgba(0,0,0,0.18);cursor:pointer;display:flex;align-items:center;justify-content:center;padding:0;">
    <svg viewBox="0 0 24 24" fill="none" stroke="#64748b" stroke-width="3" stroke-linecap="round" style="width:10px;height:10px;pointer-events:none;"><line x1="5" y1="12" x2="19" y2="12"/></svg>
  </button>
</div>

<!-- Sidebar overlay -->
<div id="bm-feedback-overlay" style="display:none;position:fixed;top:0;left:0;width:100vw;height:100vh;background:rgba(0,0,0,0.15);z-index:99991;" onclick="bmfbCloseSidebar()"></div>

<!-- Sidebar panel (read-only history) -->
<div id="bm-feedback-panel" style="display:none;position:fixed;top:0;right:0;z-index:99992;width:380px;max-width:100vw;height:100vh;background:#ffffff;border-left:1px solid #e2e8f0;box-shadow:-8px 0 30px rgba(0,0,0,0.1);font-family:system-ui,-apple-system,sans-serif;overflow-y:auto;transform:translateX(100%);transition:transform 0.25s ease;">
  <div style="position:sticky;top:0;z-index:1;background:#ffffff;padding:16px 20px;border-bottom:1px solid #e2e8f0;display:flex;align-items:center;justify-content:space-between;">
    <div>
      <div style="font-size:16px;font-weight:700;color:#1e293b;">Feedback</div>
      <div style="font-size:11px;color:#64748b;margin-top:2px;">Page: <span id="bm-fb-page" style="color:#1e293b;font-weight:500;"></span></div>
    </div>
    <button onclick="bmfbCloseSidebar()" style="background:none;border:none;cursor:pointer;color:#64748b;font-size:22px;line-height:1;padding:4px;">&times;</button>
  </div>
  <div style="padding:14px 20px;background:#faf5ff;border-bottom:1px solid #e9d5ff;">
    <div style="font-size:12px;color:#6b21a8;line-height:1.55;margin-bottom:10px;"><strong>This app is in testing mode.</strong> Leave feedback any of these ways - click one or use the shortcut key:</div>
    <div style="display:flex;flex-direction:column;gap:6px;">
      <button onclick="bmfbFeedback()" class="bm-fb-action" style="display:flex;align-items:center;gap:10px;width:100%;text-align:left;background:#ffffff;border:1px solid #e9d5ff;border-radius:8px;padding:9px 11px;cursor:pointer;font-family:inherit;font-size:13px;color:#1e293b;transition:background 0.12s,border-color 0.12s;" onmouseover="this.style.background='#f5f3ff';this.style.borderColor='#c4b5fd'" onmouseout="this.style.background='#ffffff';this.style.borderColor='#e9d5ff'">
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#7c3aed" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><path d="M21 15a2 2 0 0 1-2 2H7l-4 4V5a2 2 0 0 1 2-2h14a2 2 0 0 1 2 2z"/></svg>
        <span style="flex:1;">Leave a general comment</span>
        <span style="background:#f1f5f9;border:1px solid #e2e8f0;border-radius:4px;padding:1px 7px;font-size:10px;font-weight:700;color:#475569;">F</span>
      </button>
      <button onclick="bmfbElement()" class="bm-fb-action" style="display:flex;align-items:center;gap:10px;width:100%;text-align:left;background:#ffffff;border:1px solid #e9d5ff;border-radius:8px;padding:9px 11px;cursor:pointer;font-family:inherit;font-size:13px;color:#1e293b;transition:background 0.12s,border-color 0.12s;" onmouseover="this.style.background='#f5f3ff';this.style.borderColor='#c4b5fd'" onmouseout="this.style.background='#ffffff';this.style.borderColor='#e9d5ff'">
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#7c3aed" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><path d="M3 3l7.07 16.97 2.51-7.39 7.39-2.51L3 3z"/><path d="M13 13l6 6"/></svg>
        <span style="flex:1;">Point at an element &amp; comment</span>
        <span style="background:#f1f5f9;border:1px solid #e2e8f0;border-radius:4px;padding:1px 7px;font-size:10px;font-weight:700;color:#475569;">E</span>
      </button>
      <button onclick="bmfbScreenshot()" class="bm-fb-action" style="display:flex;align-items:center;gap:10px;width:100%;text-align:left;background:#ffffff;border:1px solid #e9d5ff;border-radius:8px;padding:9px 11px;cursor:pointer;font-family:inherit;font-size:13px;color:#1e293b;transition:background 0.12s,border-color 0.12s;" onmouseover="this.style.background='#f5f3ff';this.style.borderColor='#c4b5fd'" onmouseout="this.style.background='#ffffff';this.style.borderColor='#e9d5ff'">
        <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="#7c3aed" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" style="flex-shrink:0;"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
        <span style="flex:1;">Attach a screenshot</span>
        <span style="background:#f1f5f9;border:1px solid #e2e8f0;border-radius:4px;padding:1px 7px;font-size:10px;font-weight:700;color:#475569;">S</span>
      </button>
    </div>
  </div>
  <div style="padding:16px 20px;">
    <div style="font-size:12px;font-weight:600;color:#64748b;text-transform:uppercase;letter-spacing:0.05em;margin-bottom:12px;">History</div>
    <div id="bm-fb-list" style="display:flex;flex-direction:column;gap:10px;">
      <div style="text-align:center;padding:20px 0;font-size:12px;color:#94a3b8;">Loading...</div>
    </div>
  </div>
</div>

<!-- Floating textarea card (for F and E hotkeys) -->
<div id="bm-fb-input-card" style="display:none;position:fixed;bottom:80px;left:50%;transform:translateX(-50%);z-index:99993;width:400px;max-width:calc(100vw - 32px);background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.12);font-family:system-ui,-apple-system,sans-serif;padding:16px;">
  <div id="bm-fb-input-label" style="font-size:12px;font-weight:600;color:#64748b;margin-bottom:8px;text-transform:uppercase;letter-spacing:0.05em;"></div>
  <div id="bm-fb-input-element-info" style="display:none;font-size:11px;color:#7c3aed;margin-bottom:8px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;"></div>
  <textarea id="bm-fb-input-textarea" placeholder="Type your feedback..." style="width:100%;height:80px;padding:10px 12px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;font-family:inherit;resize:none;color:#1e293b;background:#ffffff;outline:none;box-sizing:border-box;" onfocus="this.style.borderColor='#7c3aed';this.style.boxShadow='0 0 0 2px rgba(124,58,237,0.1)'" onblur="this.style.borderColor='#e2e8f0';this.style.boxShadow='none'"></textarea>
  <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:10px;">
    <button onclick="bmfbCancelInput()" style="padding:6px 14px;font-size:12px;font-weight:500;background:#ffffff;color:#64748b;border:1px solid #e2e8f0;border-radius:6px;cursor:pointer;font-family:inherit;">Cancel</button>
    <button onclick="bmfbSubmitInput()" style="padding:6px 14px;font-size:12px;font-weight:600;background:#7c3aed;color:#ffffff;border:none;border-radius:6px;cursor:pointer;font-family:inherit;transition:background 0.15s;" onmouseover="this.style.background='#6d28d9'" onmouseout="this.style.background='#7c3aed'">Send</button>
  </div>
</div>

<!-- Screenshot input card (for S hotkey) -->
<div id="bm-fb-screenshot-card" style="display:none;position:fixed;bottom:80px;left:50%;transform:translateX(-50%);z-index:99993;width:400px;max-width:calc(100vw - 32px);background:#ffffff;border:1px solid #e2e8f0;border-radius:12px;box-shadow:0 8px 32px rgba(0,0,0,0.12);font-family:system-ui,-apple-system,sans-serif;padding:16px;">
  <div style="font-size:12px;font-weight:600;color:#64748b;margin-bottom:8px;text-transform:uppercase;letter-spacing:0.05em;">Screenshot Feedback</div>
  <div id="bm-fb-ss-drop" style="border:2px dashed #e2e8f0;border-radius:8px;padding:20px;text-align:center;font-size:12px;color:#94a3b8;cursor:pointer;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:8px;background:#ffffff;margin-bottom:10px;" onclick="document.getElementById('bm-fb-ss-file').click()">
    <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="#94a3b8" stroke-width="2"><rect x="3" y="3" width="18" height="18" rx="2"/><circle cx="8.5" cy="8.5" r="1.5"/><polyline points="21 15 16 10 5 21"/></svg>
    <span id="bm-fb-ss-label">Click to choose, paste, or drop an image</span>
  </div>
  <img id="bm-fb-ss-preview" style="display:none;max-width:100%;max-height:120px;border-radius:6px;margin-bottom:10px;border:1px solid #e2e8f0;">
  <input type="file" id="bm-fb-ss-file" accept="image/*" style="display:none">
  <textarea id="bm-fb-ss-textarea" placeholder="Add a comment about this screenshot..." style="width:100%;height:60px;padding:10px 12px;border:1px solid #e2e8f0;border-radius:8px;font-size:13px;font-family:inherit;resize:none;color:#1e293b;background:#ffffff;outline:none;box-sizing:border-box;" onfocus="this.style.borderColor='#7c3aed';this.style.boxShadow='0 0 0 2px rgba(124,58,237,0.1)'" onblur="this.style.borderColor='#e2e8f0';this.style.boxShadow='none'"></textarea>
  <div style="display:flex;justify-content:flex-end;gap:8px;margin-top:10px;">
    <button onclick="bmfbCancelScreenshot()" style="padding:6px 14px;font-size:12px;font-weight:500;background:#ffffff;color:#64748b;border:1px solid #e2e8f0;border-radius:6px;cursor:pointer;font-family:inherit;">Cancel</button>
    <button onclick="bmfbSubmitScreenshot()" id="bm-fb-ss-submit" style="padding:6px 14px;font-size:12px;font-weight:600;background:#7c3aed;color:#ffffff;border:none;border-radius:6px;cursor:pointer;font-family:inherit;opacity:0.5;transition:background 0.15s;" disabled>Send</button>
  </div>
</div>

<!-- Toast notification -->
<div id="bm-fb-toast" style="display:none;position:fixed;bottom:24px;right:24px;z-index:99999;background:#1e293b;color:#ffffff;font-size:13px;font-weight:500;padding:10px 20px;border-radius:999px;box-shadow:0 4px 16px rgba(0,0,0,0.15);font-family:system-ui,-apple-system,sans-serif;transition:opacity 0.3s;"></div>

<!-- Element highlight overlay (crosshair mode) -->
<style>#bm-fb-highlight{position:fixed;z-index:99995;pointer-events:none;border:2px solid #7c3aed;background:rgba(124,58,237,0.08);transition:all 0.1s;}</style>
<div id="bm-fb-highlight" style="display:none;"></div>
</div><!-- /bm-fb-root -->

<script>
(function(){
  // Self-healing widget: TSX-stack apps frequently do
  // document.body.innerHTML = ... on render/navigation, which wipes the
  // injected widget (and its <style>) out of the DOM while this script's
  // closures and document-level listeners survive - producing the
  // "button flashes then vanishes; E enters select-mode but nothing
  // highlights" symptom. So: capture the markup once, look every element
  // up FRESH on use (no cached detached refs), and re-inject the markup
  // whenever <body> is rebuilt (MutationObserver below).
  var TPL='';
  function $(id){return document.getElementById(id);}
  var selecting=false;
  var currentMode=null; // 'feedback','element','screenshot'
  var pendingSelector='';
  var pendingScreenshot='';

  // --- Utility ---
  function escH(s){if(!s)return '';var d=document.createElement('div');d.textContent=s;return d.innerHTML;}

  function isEditing(){
    var ae=document.activeElement;
    if(!ae)return false;
    var tag=ae.tagName;
    if(tag==='INPUT'||tag==='TEXTAREA'||tag==='SELECT')return true;
    if(ae.isContentEditable)return true;
    return false;
  }

  function showToast(msg){
    var t=$('bm-fb-toast');
    if(!t)return;
    t.textContent=msg;t.style.display='block';t.style.opacity='1';
    setTimeout(function(){t.style.opacity='0';setTimeout(function(){t.style.display='none';},300);},2000);
  }

  function showBadge(){
    var b=$('bm-fb-badge');
    if(b)b.style.display='block';
  }

  // --- Load history ---
  function loadFeedbackList(){
    var listEl=$('bm-fb-list');
    if(!listEl)return;
    fetch('/api/_feedback',{credentials:'same-origin'}).then(function(r){
      if(!r.ok){listEl.innerHTML='<div style="text-align:center;padding:16px 0;font-size:12px;color:#94a3b8;">Could not load feedback.</div>';return Promise.reject();}
      return r.json();
    }).then(function(items){
      if(!items||items.length===0){
        listEl.innerHTML='<div style="text-align:center;padding:20px 0;font-size:12px;color:#94a3b8;">No feedback yet for this page.</div>';
        return;
      }
      var currentPage=window.location.pathname;
      var filtered=items.filter(function(fb){return fb.page_url===currentPage;});
      if(filtered.length===0){
        listEl.innerHTML='<div style="text-align:center;padding:20px 0;font-size:12px;color:#94a3b8;">No feedback yet for this page.</div>';
        return;
      }
      var html='';
      filtered.forEach(function(fb){
        var body=fb.body||'';
        if(body.length>160)body=body.substring(0,160)+'...';
        var created=fb.created_at||'';
        html+='<div style="background:#f8fafc;border:1px solid #e2e8f0;border-radius:8px;padding:12px;">';
        html+='<div style="font-size:12px;color:#1e293b;line-height:1.5;margin-bottom:8px;">'+escH(body)+'</div>';
        if(fb.element_selector){
          html+='<div style="font-size:10px;color:#7c3aed;margin-bottom:6px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">';
          html+='<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="#7c3aed" stroke-width="2" style="vertical-align:middle;margin-right:3px;"><path d="M3 3l7.07 16.97 2.51-7.39 7.39-2.51L3 3z"/></svg>';
          html+=escH(fb.element_selector)+'</div>';
        }
        if(fb.screenshot){
          html+='<img src="'+escH(fb.screenshot)+'" style="max-width:100%;max-height:80px;border-radius:4px;margin-bottom:6px;border:1px solid #e2e8f0;">';
        }
        html+='<div style="font-size:10px;color:#94a3b8;">'+escH(created)+'</div>';
        html+='</div>';
      });
      listEl.innerHTML=html;
    }).catch(function(){});
  }

  // --- Sidebar ---
  window.bmfbOpenSidebar=function(){
    ensure();
    var panel=$('bm-feedback-panel'),overlay=$('bm-feedback-overlay');
    if(!panel||!overlay)return;
    panel.style.display='block';
    overlay.style.display='block';
    $('bm-fb-page').textContent=window.location.pathname;
    $('bm-feedback-btn').style.display='none';
    requestAnimationFrame(function(){panel.style.transform='translateX(0)';});
    loadFeedbackList();
  };
  window.bmfbCloseSidebar=function(){
    var panel=$('bm-feedback-panel'),overlay=$('bm-feedback-overlay');
    if(panel)panel.style.transform='translateX(100%)';
    if(overlay)overlay.style.display='none';
    setTimeout(function(){if(panel)panel.style.display='none';},250);
    var btn=$('bm-feedback-btn');if(btn)btn.style.display='block';
  };

  // --- Drawer action buttons → close the drawer, then start the mode.
  //     (Element mode needs the drawer gone so the page is hoverable.) ---
  window.bmfbFeedback=function(){bmfbCloseSidebar();setTimeout(openFeedbackInput,260);};
  window.bmfbElement=function(){bmfbCloseSidebar();setTimeout(startElementMode,260);};
  window.bmfbScreenshot=function(){bmfbCloseSidebar();setTimeout(openScreenshotInput,260);};

  // --- Draggable + minimizable FAB ---
  var FB_POS='bm:fb:pos', FB_MIN='bm:fb:min';
  function clampX(x){var w=$('bm-feedback-btn');var bw=w?w.offsetWidth:44;return Math.max(4,Math.min(x,window.innerWidth-bw-4));}
  function clampY(y){var w=$('bm-feedback-btn');var bh=w?w.offsetHeight:44;return Math.max(4,Math.min(y,window.innerHeight-bh-4));}
  function isMin(){try{return localStorage.getItem(FB_MIN)==='1';}catch(_){return false;}}
  function setMinimized(min,save){
    if(save){try{localStorage.setItem(FB_MIN,min?'1':'0');}catch(_){}}
    var fab=$('bm-fb-fab'),icon=$('bm-fb-flag'),mn=$('bm-fb-min');
    if(!fab)return;
    if(min){
      fab.style.width='16px';fab.style.height='16px';fab.style.boxShadow='0 2px 6px rgba(124,58,237,0.55)';
      if(icon)icon.style.display='none';
      if(mn)mn.style.display='none';
      fab.title='Feedback (minimized - click to expand, drag to move)';
    } else {
      fab.style.width='44px';fab.style.height='44px';fab.style.boxShadow='0 4px 14px rgba(124,58,237,0.4)';
      if(icon)icon.style.display='block';
      if(mn)mn.style.display='flex';
      fab.title='Feedback (drag to move)';
    }
  }
  // Apply saved position + minimized state to the (possibly re-injected) node.
  function applyFabState(){
    var wrap=$('bm-feedback-btn');
    if(wrap){
      try{var p=JSON.parse(localStorage.getItem(FB_POS)||'null');
        if(p&&typeof p.left==='number'){wrap.style.left=clampX(p.left)+'px';wrap.style.top=clampY(p.top)+'px';wrap.style.right='auto';wrap.style.bottom='auto';}
      }catch(_){}
    }
    setMinimized(isMin(),false);
  }
  // Bind drag once per fresh fab node.
  function setupDrag(){
    var wrap=$('bm-feedback-btn'),fab=$('bm-fb-fab'),mn=$('bm-fb-min');
    if(!wrap||!fab)return;
    if(!fab._bmdrag){
      fab._bmdrag=1;
      var sx,sy,ox,oy,moved,dragging;
      fab.addEventListener('pointerdown',function(e){
        if(e.button!==undefined&&e.button!==0)return;
        dragging=true;moved=false;
        var r=wrap.getBoundingClientRect();ox=r.left;oy=r.top;sx=e.clientX;sy=e.clientY;
        wrap.style.left=ox+'px';wrap.style.top=oy+'px';wrap.style.right='auto';wrap.style.bottom='auto';
        try{fab.setPointerCapture(e.pointerId);}catch(_){}
        fab.style.cursor='grabbing';
      });
      fab.addEventListener('pointermove',function(e){
        if(!dragging)return;
        var dx=e.clientX-sx,dy=e.clientY-sy;
        if(Math.abs(dx)>4||Math.abs(dy)>4)moved=true;
        wrap.style.left=clampX(ox+dx)+'px';wrap.style.top=clampY(oy+dy)+'px';
      });
      fab.addEventListener('pointerup',function(e){
        if(!dragging)return;dragging=false;fab.style.cursor='grab';
        try{fab.releasePointerCapture(e.pointerId);}catch(_){}
        if(moved){
          var r=wrap.getBoundingClientRect();
          try{localStorage.setItem(FB_POS,JSON.stringify({left:r.left,top:r.top}));}catch(_){}
        } else if(isMin()){
          setMinimized(false,true);
        } else {
          bmfbOpenSidebar();
        }
      });
    }
    if(mn&&!mn._bmw){mn._bmw=1;
      mn.addEventListener('pointerdown',function(e){e.stopPropagation();});
      mn.addEventListener('click',function(e){e.stopPropagation();setMinimized(true,true);});
    }
  }

  // --- General feedback (F key) ---
  function openFeedbackInput(){
    ensure();closeAllCards();
    currentMode='feedback';
    pendingSelector='';
    var label=$('bm-fb-input-label');if(label)label.textContent='General Feedback';
    var ei=$('bm-fb-input-element-info');if(ei)ei.style.display='none';
    var card=$('bm-fb-input-card');if(card)card.style.display='block';
    var ta=$('bm-fb-input-textarea');
    if(ta){ta.value='';ta.placeholder='Type your feedback...';setTimeout(function(){ta.focus();},50);}
  }

  // --- Element feedback (E key) ---
  function startElementMode(){
    ensure();closeAllCards();
    currentMode='element';
    selecting=true;
    document.addEventListener('mousemove',onHover);
    document.addEventListener('click',onElementClick,true);
    document.body.style.cursor='crosshair';
  }
  function onHover(e){
    var t=e.target;
    if(t.id&&t.id.indexOf('bm-fb')===0)return;
    if(t.id&&t.id.indexOf('bm-feedback')===0)return;
    var h=$('bm-fb-highlight');if(!h)return;
    var r=t.getBoundingClientRect();
    h.style.display='block';h.style.top=r.top+'px';h.style.left=r.left+'px';h.style.width=r.width+'px';h.style.height=r.height+'px';
  }
  function onElementClick(e){
    if(!selecting)return;
    e.preventDefault();e.stopPropagation();
    pendingSelector=cssPath(e.target);
    stopSelecting();
    // Show input card with element info
    var label=$('bm-fb-input-label');if(label)label.textContent='Element Feedback';
    var info=$('bm-fb-input-element-info');
    if(info){info.textContent='Element: '+pendingSelector;info.style.display='block';}
    var card=$('bm-fb-input-card');if(card)card.style.display='block';
    var ta=$('bm-fb-input-textarea');
    if(ta){ta.value='';ta.placeholder='Comment about this element...';setTimeout(function(){ta.focus();},50);}
  }
  function stopSelecting(){
    selecting=false;
    document.removeEventListener('mousemove',onHover);
    document.removeEventListener('click',onElementClick,true);
    var h=$('bm-fb-highlight');if(h)h.style.display='none';
    document.body.style.cursor='';
  }
  function cssPath(el){
    if(el.id)return '#'+el.id;
    var p=[];var c=el;
    while(c&&c!==document.body){var t=c.tagName.toLowerCase();
      if(c.className&&typeof c.className==='string'){var cls=c.className.trim().split(/\s+/)[0];if(cls&&!cls.startsWith('bm-'))t+='.'+cls;}
      p.unshift(t);c=c.parentElement;}
    return p.join(' > ');
  }

  // --- Screenshot feedback (S key) ---
  function openScreenshotInput(){
    ensure();closeAllCards();
    currentMode='screenshot';
    pendingScreenshot='';
    var card=$('bm-fb-screenshot-card');if(card)card.style.display='block';
    var ta=$('bm-fb-ss-textarea');if(ta)ta.value='';
    var lbl=$('bm-fb-ss-label');if(lbl)lbl.textContent='Click to choose, paste, or drop an image';
    var pv=$('bm-fb-ss-preview');if(pv)pv.style.display='none';
    var dz=$('bm-fb-ss-drop');if(dz)dz.style.display='flex';
    var submitBtn=$('bm-fb-ss-submit');
    if(submitBtn){submitBtn.disabled=true;submitBtn.style.opacity='0.5';}
  }

  // Screenshot file/drop handlers - (re)bound per fresh node in wire().
  function readSSImg(blob){
    var r=new FileReader();r.onload=function(e){
      pendingScreenshot=e.target.result;
      var pv=$('bm-fb-ss-preview');if(pv){pv.src=pendingScreenshot;pv.style.display='block';}
      var dz=$('bm-fb-ss-drop');if(dz)dz.style.display='none';
      var submitBtn=$('bm-fb-ss-submit');
      if(submitBtn){submitBtn.disabled=false;submitBtn.style.opacity='1';}
    };r.readAsDataURL(blob);
  }

  // Global paste - only active while the screenshot card is open. Bound
  // once on document (survives body rebuilds); looks the card up fresh.
  document.addEventListener('paste',function(e){
    var card=$('bm-fb-screenshot-card');
    if(!card||card.style.display!=='block')return;
    var items=e.clipboardData&&e.clipboardData.items;if(!items)return;
    for(var i=0;i<items.length;i++){if(items[i].type.indexOf('image')>=0){readSSImg(items[i].getAsFile());break;}}
  });

  // --- Close helpers ---
  function closeAllCards(){
    var ic=$('bm-fb-input-card');if(ic)ic.style.display='none';
    var sc=$('bm-fb-screenshot-card');if(sc)sc.style.display='none';
    if(selecting)stopSelecting();
    currentMode=null;
  }
  window.bmfbCancelInput=function(){closeAllCards();};
  window.bmfbCancelScreenshot=function(){closeAllCards();};

  // --- Submit: general/element feedback ---
  window.bmfbSubmitInput=function(){
    var body=document.getElementById('bm-fb-input-textarea').value.trim();
    if(!body)return;
    var payload={
      page_url:window.location.pathname,
      body:body,
      element_selector:pendingSelector||'',
      screenshot:''
    };
    postFeedback(payload);
  };

  // --- Submit: screenshot feedback ---
  window.bmfbSubmitScreenshot=function(){
    if(!pendingScreenshot)return;
    var body=document.getElementById('bm-fb-ss-textarea').value.trim();
    if(!body)body='(screenshot)';
    var payload={
      page_url:window.location.pathname,
      body:body,
      element_selector:'',
      screenshot:pendingScreenshot
    };
    postFeedback(payload);
  };

  // --- POST feedback ---
  function postFeedback(payload){
    fetch('/api/_feedback',{method:'POST',credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify(payload)
    }).then(function(r){return r.json().then(function(d){return{ok:r.ok,data:d}})})
    .then(function(res){
      if(!res.ok)return;
      closeAllCards();
      showToast('Feedback saved');
      showBadge();
    }).catch(function(){});
  }

  // --- Hotkey listener (bound once on document; survives body rebuilds) ---
  document.addEventListener('keydown',function(e){
    if(isEditing())return;
    if(e.ctrlKey||e.metaKey||e.altKey)return;
    var key=e.key;
    if(key==='f'||key==='F'){
      if(currentMode==='feedback')return;
      e.preventDefault();
      openFeedbackInput();
    } else if(key==='e'||key==='E'){
      if(currentMode==='element'||selecting)return;
      e.preventDefault();
      startElementMode();
    } else if(key==='s'||key==='S'){
      if(currentMode==='screenshot')return;
      e.preventDefault();
      openScreenshotInput();
    } else if(key==='Escape'){
      if(currentMode){closeAllCards();e.preventDefault();}
    }
  });

  // --- (Re)bind node-specific listeners. Idempotent per node (_bmw flag)
  //     so it's safe to call on every ensure(); fresh re-injected nodes
  //     get wired, already-wired nodes are skipped. ---
  function wire(){
    var f=$('bm-fb-ss-file');
    if(f&&!f._bmw){f._bmw=1;f.addEventListener('change',function(){if(this.files&&this.files[0])readSSImg(this.files[0]);});}
    var d=$('bm-fb-ss-drop');
    if(d&&!d._bmw){d._bmw=1;
      d.addEventListener('dragover',function(e){e.preventDefault();this.style.borderColor='#7c3aed';this.style.background='#faf5ff';});
      d.addEventListener('dragleave',function(){this.style.borderColor='#e2e8f0';this.style.background='#ffffff';});
      d.addEventListener('drop',function(e){e.preventDefault();this.style.borderColor='#e2e8f0';this.style.background='#ffffff';if(e.dataTransfer.files&&e.dataTransfer.files[0])readSSImg(e.dataTransfer.files[0]);});
    }
    var ta=$('bm-fb-input-textarea');
    if(ta&&!ta._bmw){ta._bmw=1;ta.addEventListener('keydown',function(e){if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();bmfbSubmitInput();}});}
    setupDrag();
    applyFabState();
  }

  // --- Re-inject the widget markup if the app wiped it from <body>. ---
  function ensure(){
    if(!$('bm-feedback-btn')&&TPL){document.body.insertAdjacentHTML('beforeend',TPL);}
    wire();
  }

  // Capture the server-injected markup as the re-injection template, then
  // wire up. This inline classic script runs during parse, before the
  // deferred app module - so #bm-fb-root is present here.
  var root=$('bm-fb-root');
  if(root)TPL=root.outerHTML;
  ensure();

  // Self-heal: many TSX apps do document.body.innerHTML = ... on render,
  // removing the widget. Re-inject whenever <body>'s children change and
  // the widget is gone. Our own insertAdjacentHTML re-fires the observer
  // once, finds the button present, and no-ops - no loop.
  if(window.MutationObserver){
    var mo=new MutationObserver(function(){if(!$('bm-feedback-btn'))ensure();});
    try{mo.observe(document.body,{childList:true});}catch(_){}
  }
})();
</script>`
}

// ServeFeedbackAdmin renders the feedback admin page within the admin panel.
func ServeFeedbackAdmin(w http.ResponseWriter, r *http.Request, app *App) {
	session := getSession(app, r)
	if session == nil || !session.IsAdmin() {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}

	rows, _ := QueryRows(app.DB, `SELECT id, visitor_name, visitor_email, page_url, body, element_selector, status, created_at
		FROM _benmore_feedback ORDER BY created_at DESC LIMIT 100`)

	var openCount, resolvedCount int64
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_feedback WHERE status = 'open'").Scan(&openCount)
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_feedback WHERE status = 'resolved'").Scan(&resolvedCount)

	var sb strings.Builder

	sb.WriteString(fmt.Sprintf(`<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:24px;">
		<div style="background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:8px;padding:20px;">
			<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:hsl(var(--muted-foreground));">Total</div>
			<div style="font-size:2rem;font-weight:700;color:hsl(var(--foreground));margin-top:4px;">%d</div>
		</div>
		<div style="background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:8px;padding:20px;">
			<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:#d97706;">Open</div>
			<div style="font-size:2rem;font-weight:700;color:#d97706;margin-top:4px;">%d</div>
		</div>
		<div style="background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:8px;padding:20px;">
			<div style="font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:0.06em;color:#059669;">Resolved</div>
			<div style="font-size:2rem;font-weight:700;color:#059669;margin-top:4px;">%d</div>
		</div>
	</div>`, len(rows), openCount, resolvedCount))

	sb.WriteString(`<div style="background:hsl(var(--card));border:1px solid hsl(var(--border));border-radius:8px;overflow:hidden;">
		<table style="width:100%%;border-collapse:collapse;font-size:13px;">
		<thead><tr style="border-bottom:1px solid hsl(var(--border));">
			<th style="text-align:left;padding:10px 16px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;">Status</th>
			<th style="text-align:left;padding:10px 16px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;">From</th>
			<th style="text-align:left;padding:10px 16px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;">Page</th>
			<th style="text-align:left;padding:10px 16px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;">Feedback</th>
			<th style="text-align:right;padding:10px 16px;font-weight:600;color:hsl(var(--muted-foreground));font-size:11px;text-transform:uppercase;">When</th>
		</tr></thead><tbody>`)

	for _, row := range rows {
		status := fmt.Sprintf("%v", row["status"])
		name := fmt.Sprintf("%v", row["visitor_name"])
		email := fmt.Sprintf("%v", row["visitor_email"])
		if name == "<nil>" || name == "" {
			name = email
		}
		if name == "<nil>" || name == "" {
			name = "Anonymous"
		}
		page := fmt.Sprintf("%v", row["page_url"])
		body := fmt.Sprintf("%v", row["body"])
		created := fmt.Sprintf("%v", row["created_at"])
		id := fmt.Sprintf("%v", row["id"])

		if len(body) > 80 {
			body = body[:80] + "..."
		}

		statusColor := "#d97706"
		statusBg := "#fef3c7"
		switch status {
		case "resolved":
			statusColor = "#059669"
			statusBg = "#d1fae5"
		case "in_progress":
			statusColor = "#2563eb"
			statusBg = "#dbeafe"
		case "wont_fix":
			statusColor = "#64748b"
			statusBg = "#f1f5f9"
		}

		sb.WriteString(fmt.Sprintf(`<tr style="border-bottom:1px solid hsl(var(--border)/0.5);cursor:pointer;" onclick="showFeedbackDetail(%s)">
			<td style="padding:8px 16px;"><span style="font-size:11px;font-weight:600;color:%s;background:%s;padding:3px 10px;border-radius:4px;">%s</span></td>
			<td style="padding:8px 16px;color:hsl(var(--foreground));">%s</td>
			<td style="padding:8px 16px;color:hsl(var(--muted-foreground));font-size:12px;">%s</td>
			<td style="padding:8px 16px;color:hsl(var(--foreground));max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;">%s</td>
			<td style="padding:8px 16px;text-align:right;color:hsl(var(--muted-foreground));font-size:12px;white-space:nowrap;">%s</td>
		</tr>`, id, statusColor, statusBg, html.EscapeString(status),
			html.EscapeString(name), html.EscapeString(page), html.EscapeString(body), html.EscapeString(created)))
	}

	if len(rows) == 0 {
		sb.WriteString(`<tr><td colspan="5" style="padding:32px;text-align:center;color:hsl(var(--muted-foreground));">No feedback yet. Enable demo mode and share the password with reviewers.</td></tr>`)
	}

	sb.WriteString(`</tbody></table></div>`)

	// Detail modal
	sb.WriteString(`<dialog id="fb-detail-modal" style="border:1px solid hsl(var(--border));border-radius:12px;background:hsl(var(--card));color:hsl(var(--foreground));box-shadow:0 20px 60px rgba(0,0,0,0.3);max-width:600px;width:100%%;padding:0;position:fixed;top:50%%;left:50%%;transform:translate(-50%%,-50%%);margin:0;">
		<div id="fb-detail-content" style="padding:24px;"></div>
	</dialog>
	<script>
	function showFeedbackDetail(id){
		fetch('/api/_feedback/'+id,{credentials:'same-origin'}).then(function(r){return r.json()}).then(function(fb){
			var el=document.getElementById('fb-detail-content');
			var so='<option value="open"'+(fb.status==='open'?' selected':'')+'>Open</option><option value="in_progress"'+(fb.status==='in_progress'?' selected':'')+'>In Progress</option><option value="resolved"'+(fb.status==='resolved'?' selected':'')+'>Resolved</option><option value="wont_fix"'+(fb.status==='wont_fix'?' selected':'')+'>Won\'t Fix</option>';
			var from=(fb.visitor_name||fb.visitor_email||'Anonymous');
			var h='<div style="display:flex;justify-content:space-between;align-items:start;margin-bottom:16px;"><div><div style="font-size:16px;font-weight:600;">Feedback #'+fb.id+'</div><div style="font-size:12px;color:hsl(var(--muted-foreground));margin-top:2px;">'+from+(fb.visitor_email?' &middot; '+fb.visitor_email:'')+' on '+fb.page_url+'</div></div><button onclick="this.closest(\'dialog\').close()" style="background:none;border:none;cursor:pointer;font-size:20px;color:hsl(var(--muted-foreground));">&times;</button></div>';
			h+='<div style="background:hsl(var(--background));border:1px solid hsl(var(--border));border-radius:8px;padding:16px;margin-bottom:16px;font-size:14px;line-height:1.6;white-space:pre-wrap;">'+fb.body+'</div>';
			if(fb.element_selector)h+='<div style="font-size:12px;color:hsl(var(--muted-foreground));margin-bottom:12px;">Element: <code style="background:hsl(var(--muted));padding:2px 6px;border-radius:4px;">'+fb.element_selector+'</code></div>';
			if(fb.screenshot)h+='<img src="'+fb.screenshot+'" style="max-width:100%%;border:1px solid hsl(var(--border));border-radius:8px;margin-bottom:16px;">';
			h+='<div style="display:flex;gap:8px;align-items:center;margin-bottom:20px;"><label style="font-size:12px;font-weight:500;">Status:</label><select onchange="updateFbStatus('+fb.id+',this.value)" style="height:32px;padding:0 8px;border:1px solid hsl(var(--border));border-radius:6px;background:hsl(var(--background));color:hsl(var(--foreground));font-size:12px;">'+so+'</select></div>';
			h+='<div style="border-top:1px solid hsl(var(--border));padding-top:16px;"><div style="font-size:12px;font-weight:600;margin-bottom:12px;">Comments</div>';
			(fb.comments||[]).forEach(function(c){h+='<div style="background:hsl(var(--background));border:1px solid hsl(var(--border));border-radius:8px;padding:12px;margin-bottom:8px;"><div style="font-size:11px;color:hsl(var(--muted-foreground));margin-bottom:4px;">'+c.user_email+' &middot; '+c.created_at+'</div><div style="font-size:13px;">'+c.body+'</div></div>';});
			h+='<div style="display:flex;gap:8px;margin-top:12px;"><input id="fb-ci" type="text" placeholder="Add a comment..." style="flex:1;height:36px;padding:0 12px;border:1px solid hsl(var(--border));border-radius:6px;background:hsl(var(--background));color:hsl(var(--foreground));font-size:13px;"><button onclick="addFbComment('+fb.id+')" style="padding:0 16px;height:36px;font-size:12px;background:hsl(var(--primary));color:hsl(var(--primary-foreground));border:none;border-radius:6px;cursor:pointer;font-weight:500;">Send</button></div></div>';
			el.innerHTML=h;document.getElementById('fb-detail-modal').showModal();
		});
	}
	function updateFbStatus(id,s){fetch('/api/_feedback/'+id,{method:'PATCH',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({status:s})});}
	function addFbComment(id){var i=document.getElementById('fb-ci');var b=i.value.trim();if(!b)return;fetch('/api/_feedback/'+id+'/comment',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({body:b})}).then(function(){showFeedbackDetail(id);i.value='';});}
	</script>`)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	fmt.Fprint(w, adminShell(sb.String(), "Feedback", "_feedback", app, session))
}
