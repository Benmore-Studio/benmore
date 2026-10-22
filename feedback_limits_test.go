//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func anonFeedbackPost(mux *http.ServeMux, ip string, fields map[string]string) *httptest.ResponseRecorder {
	payload, _ := json.Marshal(fields)
	r := httptest.NewRequest(http.MethodPost, "/api/_feedback", strings.NewReader(string(payload)))
	r.Host = "app.example.test"
	r.RemoteAddr = ip + ":40000"
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// An anonymous POST /api/_feedback stored every field at whatever length the
// request carried (only the screenshot was capped), so one request could add
// megabytes of text to the app's database. The comment is now refused past
// its limit and the widget-filled fields are cut to theirs.
func TestFeedbackSubmissionFieldsAreBounded(t *testing.T) {
	app, _ := feedbackCSRFFixture(t)
	mux := http.NewServeMux()
	RegisterFeedbackAPI(mux, app)

	if w := anonFeedbackPost(mux, "203.0.113.5", map[string]string{"body": strings.Repeat("x", feedbackMaxBodyBytes+1)}); w.Code != http.StatusBadRequest {
		t.Fatalf("oversized comment: status %d, want 400 (%s)", w.Code, w.Body.String())
	}
	if w := anonFeedbackPost(mux, "203.0.113.5", map[string]string{"body": "x", "page_url": strings.Repeat("u", 4<<20)}); w.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request: status %d, want 413 (%s)", w.Code, w.Body.String())
	}
	long := strings.Repeat("é", 4000)
	w := anonFeedbackPost(mux, "203.0.113.5", map[string]string{
		"body": "button overlaps", "name": long, "email": long, "page_url": long, "origin_host": long, "element_selector": long,
	})
	if w.Code != http.StatusOK {
		t.Fatalf("status %d (%s)", w.Code, w.Body.String())
	}
	var rows, name, email, page, host, selector int
	if err := app.DB.QueryRow(`SELECT COUNT(*), MAX(length(CAST(visitor_name AS BLOB))), MAX(length(CAST(visitor_email AS BLOB))),
		MAX(length(CAST(page_url AS BLOB))), MAX(length(CAST(origin_host AS BLOB))), MAX(length(CAST(element_selector AS BLOB)))
		FROM _benmore_feedback`).Scan(&rows, &name, &email, &page, &host, &selector); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("stored %d rows, want only the accepted one", rows)
	}
	for _, c := range []struct {
		field    string
		got, max int
	}{
		{"visitor_name", name, feedbackMaxNameBytes}, {"visitor_email", email, feedbackMaxEmailBytes},
		{"page_url", page, feedbackMaxURLBytes}, {"origin_host", host, feedbackMaxHostBytes},
		{"element_selector", selector, feedbackMaxSelectorBytes},
	} {
		if c.got > c.max || c.got < c.max-1 {
			t.Errorf("%s stored %d bytes, want it cut to %d on a rune boundary", c.field, c.got, c.max)
		}
	}
}

// Nothing limited how often a visitor with no account posted feedback. One
// address now gets feedbackAnonRate posts per window; another address and a
// signed-in tester are not held back by it.
func TestFeedbackAnonymousSubmitsAreLimitedPerAddress(t *testing.T) {
	app, sid := feedbackCSRFFixture(t)
	mux := http.NewServeMux()
	RegisterFeedbackAPI(mux, app)

	for i := 0; i < feedbackAnonRate; i++ {
		if w := anonFeedbackPost(mux, "203.0.113.7", map[string]string{"body": "note"}); w.Code != http.StatusOK {
			t.Fatalf("post %d: status %d (%s)", i+1, w.Code, w.Body.String())
		}
	}
	w := anonFeedbackPost(mux, "203.0.113.7", map[string]string{"body": "note"})
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("post past the limit: status %d, Retry-After %q; want 429 with Retry-After", w.Code, w.Header().Get("Retry-After"))
	}
	if w := anonFeedbackPost(mux, "203.0.113.8", map[string]string{"body": "note"}); w.Code != http.StatusOK {
		t.Fatalf("another address: status %d (%s)", w.Code, w.Body.String())
	}
	if w := (feedbackPost{bearer: sid}).send(mux); w.Code != http.StatusOK {
		t.Fatalf("signed-in tester from any address: status %d (%s)", w.Code, w.Body.String())
	}
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_feedback").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != feedbackAnonRate+2 {
		t.Fatalf("stored %d rows, want %d", n, feedbackAnonRate+2)
	}
}

// _benmore_feedback was never bounded, so posts spread over many addresses
// could fill the app's database to its storage ceiling. Open items are now
// capped; rows the owner has handled do not count, and resolving some reopens
// the inbox.
func TestFeedbackOpenItemsAreCapped(t *testing.T) {
	defer func(n int64) { feedbackMaxOpenRows = n }(feedbackMaxOpenRows)
	feedbackMaxOpenRows = 3

	app, _ := feedbackCSRFFixture(t)
	if _, err := app.DB.Exec(`INSERT INTO _benmore_feedback (page_url, body, status) VALUES ('/', 'old', 'resolved'), ('/', 'older', 'wont_fix')`); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterFeedbackAPI(mux, app)
	for i := 0; i < 3; i++ {
		if w := anonFeedbackPost(mux, fmt.Sprintf("203.0.113.%d", 20+i), map[string]string{"body": "note"}); w.Code != http.StatusOK {
			t.Fatalf("post %d: status %d (%s); handled rows must not count", i+1, w.Code, w.Body.String())
		}
	}
	if w := anonFeedbackPost(mux, "203.0.113.30", map[string]string{"body": "note"}); w.Code != http.StatusTooManyRequests {
		t.Fatalf("post past the open-item cap: status %d, want 429 (%s)", w.Code, w.Body.String())
	}
	var open int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_feedback WHERE status = 'open'").Scan(&open); err != nil {
		t.Fatal(err)
	}
	if open != 3 {
		t.Fatalf("%d open rows stored, want 3", open)
	}

	// The owner resolves the backlog; a fresh process (totals read again)
	// accepts feedback once more.
	if _, err := app.DB.Exec("UPDATE _benmore_feedback SET status = 'resolved'"); err != nil {
		t.Fatal(err)
	}
	mux = http.NewServeMux()
	RegisterFeedbackAPI(mux, app)
	if w := anonFeedbackPost(mux, "203.0.113.31", map[string]string{"body": "note"}); w.Code != http.StatusOK {
		t.Fatalf("after resolving: status %d (%s)", w.Code, w.Body.String())
	}
}

// Screenshots are the bulk of a feedback row. Past the shared budget a
// submission is kept without its screenshot and says so.
func TestFeedbackScreenshotsShareABudget(t *testing.T) {
	defer func(n int64) { feedbackScreenshotBudget = n }(feedbackScreenshotBudget)
	feedbackScreenshotBudget = 2500

	app, _ := feedbackCSRFFixture(t)
	mux := http.NewServeMux()
	RegisterFeedbackAPI(mux, app)
	shot := "data:image/png;base64," + strings.Repeat("A", 978)
	for i := 0; i < 2; i++ {
		w := anonFeedbackPost(mux, "203.0.113.40", map[string]string{"body": "see", "screenshot": shot})
		if w.Code != http.StatusOK || strings.Contains(w.Body.String(), "not stored") {
			t.Fatalf("post %d within the budget: %d %s", i+1, w.Code, w.Body.String())
		}
	}
	w := anonFeedbackPost(mux, "203.0.113.40", map[string]string{"body": "see", "screenshot": shot})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "not stored") {
		t.Fatalf("post past the budget: %d %s; want it kept and told the screenshot was not stored", w.Code, w.Body.String())
	}
	var rows, withShot, bytes int64
	if err := app.DB.QueryRow(`SELECT COUNT(*), SUM(screenshot <> ''), SUM(length(screenshot)) FROM _benmore_feedback`).Scan(&rows, &withShot, &bytes); err != nil {
		t.Fatal(err)
	}
	if rows != 3 || withShot != 2 || bytes > feedbackScreenshotBudget {
		t.Fatalf("rows=%d with screenshot=%d bytes=%d; want 3 rows, 2 screenshots, within %d bytes", rows, withShot, bytes, feedbackScreenshotBudget)
	}
}

// The demo-gated submit path shares the same bounds.
func TestFeedbackDemoSubmitSharesTheBounds(t *testing.T) {
	app, _ := feedbackCSRFFixture(t)
	mux := http.NewServeMux()
	registerDemoRoutes(mux, app, "visitor-pass")
	payload, _ := json.Marshal(map[string]string{"body": strings.Repeat("x", feedbackMaxBodyBytes+1)})
	r := httptest.NewRequest(http.MethodPost, "/api/_feedback", strings.NewReader(string(payload)))
	r.Host = "app.example.test"
	r.Header.Set("Origin", "http://app.example.test")
	r.AddCookie(&http.Cookie{Name: "demo_session", Value: demoSessionToken("visitor-pass")})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("oversized comment on the demo path: status %d, want 400 (%s)", w.Code, w.Body.String())
	}
}

// A refused submission used to close nothing and say nothing; the widget now
// shows the server's reason.
func TestFeedbackWidgetShowsARefusal(t *testing.T) {
	for _, testingMode := range []bool{true, false} {
		if !strings.Contains(FeedbackWidgetHTML(testingMode), "Feedback was not saved") {
			t.Fatalf("widget (testing=%v) drops a refused submission silently", testingMode)
		}
	}
}
