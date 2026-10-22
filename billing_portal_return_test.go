//go:build !cli

package main

import (
	"database/sql"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func billingPortalFixture(t *testing.T, seo map[string]string) (*http.ServeMux, string, *captureRoundTripper) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir, DB: db, SessionDuration: time.Hour}
	t.Cleanup(app.Shutdown)
	app.Design = &DesignConfig{Auth: map[string]string{"billing_provider": "stripe"}, SEO: seo}
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	app.Paths = DiscoverAuthPaths(nil)
	SetAppEnv(app.Dir, "STRIPE_SECRET_KEY", "sk_test_portal_fixture")
	_, sid, uid := loginTestUser(app, "portal@example.com", "user")
	ensureBillingTablesReal(app)
	if _, err := app.DB.Exec(`INSERT INTO _benmore_subscriptions (user_id, stripe_customer_id, stripe_subscription_id, status) VALUES (?, 'cus_portal', 'sub_portal', 'active')`, uid); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	registerBillingRoutes(mux, app)
	capture := &captureRoundTripper{}
	old := http.DefaultTransport
	http.DefaultTransport = capture
	t.Cleanup(func() { http.DefaultTransport = old })
	return mux, sid, capture
}

func postPortal(mux *http.ServeMux, sid, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/api/_billing/portal", strings.NewReader(body))
	r.Host = "app.example"
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// The Stripe portal sends the customer back to return_url when they leave,
// so a caller-chosen URL on another site made /api/_billing/portal an open
// redirect: an app passing a value from its own query string sent its users
// to whatever site a link named.
func TestBillingPortalRefusesForeignReturnURL(t *testing.T) {
	mux, sid, capture := billingPortalFixture(t, nil)
	for _, bad := range []string{
		"https://evil.example/phish",
		"//evil.example/phish",
		"https://app.example@evil.example/",
		"https://app.example.evil.example/",
		"javascript:alert(1)",
		"/\\evil.example",
		"https:/\\evil.example",
		"ftp://app.example/",
	} {
		capture.body = ""
		w := postPortal(mux, sid, `{"return_url":`+jsonQuote(bad)+`}`)
		if w.Code != http.StatusBadRequest || capture.body != "" {
			t.Fatalf("return_url %q: status %d, stripe called=%v (%s)", bad, w.Code, capture.body != "", w.Body.String())
		}
	}
}

// Same-origin URLs, paths and the default keep working.
func TestBillingPortalAcceptsOwnOriginReturnURL(t *testing.T) {
	mux, sid, capture := billingPortalFixture(t, map[string]string{"url": "https://www.app-brand.example"})
	for raw, want := range map[string]string{
		"":                                     "https://app.example/",
		"https://app.example/account?tab=1":    "https://app.example/account?tab=1",
		"HTTPS://APP.EXAMPLE/account":          "HTTPS://APP.EXAMPLE/account",
		"/settings/billing":                    "https://app.example/settings/billing",
		"https://www.app-brand.example/thanks": "https://www.app-brand.example/thanks",
	} {
		capture.body = ""
		body := `{}`
		if raw != "" {
			body = `{"return_url":` + jsonQuote(raw) + `}`
		}
		w := postPortal(mux, sid, body)
		if w.Code != http.StatusOK {
			t.Fatalf("return_url %q: status %d (%s)", raw, w.Code, w.Body.String())
		}
		form, _ := url.ParseQuery(capture.body)
		if got := form.Get("return_url"); got != want {
			t.Fatalf("return_url %q sent to Stripe as %q, want %q", raw, got, want)
		}
	}
}

func jsonQuote(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch r {
		case '"':
			b.WriteString(`\"`)
		case '\\':
			b.WriteString(`\\`)
		default:
			b.WriteRune(r)
		}
	}
	b.WriteByte('"')
	return b.String()
}

type stripeErrorTransport struct{}

func (stripeErrorTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return &http.Response{StatusCode: 401, Header: http.Header{"Content-Type": {"application/json"}},
		Body:    io.NopCloser(strings.NewReader(`{"error":{"message":"Invalid API Key provided: sk_live_********abcd","request_log_url":"https://dashboard.stripe.com/logs/req_x"}}`)),
		Request: r}, nil
}

// Stripe's error body (a masked secret key, the account's dashboard log URL)
// was relayed to the app's end user in the 502; it is logged instead.
func TestBillingPortalDoesNotRelayStripeErrorBody(t *testing.T) {
	mux, sid, _ := billingPortalFixture(t, nil)
	http.DefaultTransport = stripeErrorTransport{}
	w := postPortal(mux, sid, `{}`)
	if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "sk_live") || strings.Contains(w.Body.String(), "dashboard.stripe.com") {
		t.Fatalf("portal failure relayed Stripe's error body: %d %s", w.Code, w.Body.String())
	}
}
