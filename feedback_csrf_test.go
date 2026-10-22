//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// feedbackCSRFFixture is an app with the feedback tables and one signed-in
// user, opened the way production opens its database.
func feedbackCSRFFixture(t *testing.T) (*App, string) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureFeedbackTables(db)
	res, err := db.Exec("INSERT INTO _benmore_users (username, email, role, verified) VALUES ('tester', 'tester@example.com', 'user', 1)")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := res.LastInsertId()
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{})}
	t.Cleanup(app.Shutdown)
	return app, CreateSession(db, uid, "tester@example.com", "", time.Hour)
}

type feedbackPost struct {
	origin, secFetch, cookie, bearer, csrf, demo string
}

type feedbackCase struct {
	name string
	post feedbackPost
	want int
}

func (p feedbackPost) send(mux *http.ServeMux) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/_feedback", strings.NewReader(`{"body":"button overlaps","page_url":"/"}`))
	r.Host = "app.example.test"
	r.Header.Set("Content-Type", "application/json")
	if p.origin != "" {
		r.Header.Set("Origin", p.origin)
	}
	if p.secFetch != "" {
		r.Header.Set("Sec-Fetch-Site", p.secFetch)
	}
	if p.cookie != "" {
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: p.cookie})
	}
	if p.demo != "" {
		r.AddCookie(&http.Cookie{Name: "demo_session", Value: p.demo})
	}
	if p.bearer != "" {
		r.Header.Set("Authorization", "Bearer "+p.bearer)
	}
	if p.csrf != "" {
		r.Header.Set("X-CSRF-Token", p.csrf)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// POST /api/_feedback had no CSRF or origin check: a page on another site
// (or a sibling subdomain, which counts as same-site for SameSite=Lax
// cookies) could submit feedback through a visitor's browser, under the
// visitor's session or demo cookie. Cross-site and same-site browser posts
// are now refused; a signed-in browser must present the CSRF token the
// injected widget sends; anonymous same-origin and non-browser posts keep
// working.
func TestFeedbackSubmitRefusesCrossSiteAndUntokenedSessionPosts(t *testing.T) {
	const self = "http://app.example.test"
	for _, mode := range []string{"session", "demo"} {
		t.Run(mode, func(t *testing.T) {
			app, sid := feedbackCSRFFixture(t)
			mux := http.NewServeMux()
			demo := ""
			if mode == "session" {
				RegisterFeedbackAPI(mux, app)
			} else {
				registerDemoRoutes(mux, app, "visitor-pass")
				demo = demoSessionToken("visitor-pass")
			}
			cases := []feedbackCase{
				{"cross-site origin", feedbackPost{origin: "https://attacker.example", demo: demo}, http.StatusForbidden},
				{"sibling subdomain without Origin", feedbackPost{secFetch: "same-site", demo: demo}, http.StatusForbidden},
				{"cross-site with session cookie", feedbackPost{origin: "https://attacker.example", cookie: sid}, http.StatusForbidden},
				{"same-origin session without token", feedbackPost{origin: self, cookie: sid}, http.StatusForbidden},
				{"same-origin session with token", feedbackPost{origin: self, cookie: sid, csrf: authMintCSRFToken(sid)}, http.StatusOK},
				{"bearer session token", feedbackPost{bearer: sid}, http.StatusOK},
			}
			if mode == "session" {
				cases = append(cases,
					feedbackCase{"anonymous same-origin", feedbackPost{origin: self, secFetch: "same-origin"}, http.StatusOK},
					feedbackCase{"anonymous non-browser", feedbackPost{}, http.StatusOK})
			} else {
				cases = append(cases, feedbackCase{"demo visitor same-origin", feedbackPost{origin: self, demo: demo}, http.StatusOK})
			}
			for _, c := range cases {
				if w := c.post.send(mux); w.Code != c.want {
					t.Errorf("%s: status %d, want %d (%s)", c.name, w.Code, c.want, w.Body.String())
				}
			}
			var n int
			if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_feedback").Scan(&n); err != nil {
				t.Fatal(err)
			}
			want := 0
			for _, c := range cases {
				if c.want == http.StatusOK {
					want++
				}
			}
			if n != want {
				t.Errorf("stored %d feedback rows, want %d (one per accepted post)", n, want)
			}
		})
	}
}

// The framework-injected widget is the main submitter; it must send the
// page's CSRF token or a signed-in tester's feedback would be refused.
func TestFeedbackWidgetSendsCSRFToken(t *testing.T) {
	for _, testing_ := range []bool{true, false} {
		html := FeedbackWidgetHTML(testing_)
		if !strings.Contains(html, `'X-CSRF-Token'`) || !strings.Contains(html, `meta[name="csrf-token"]`) {
			t.Fatalf("widget posts feedback without the page CSRF token")
		}
		if !strings.Contains(html, `/api/_csrf`) {
			t.Fatalf("widget has no fresh-token retry for a page open past the token lifetime")
		}
	}
}
