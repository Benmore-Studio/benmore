//go:build !cli && !windows

package main

import (
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// Behavioural half of referrer_policy_post_form_guard_test.go (incident
// 2026-10-14, benmore-go#464: the connector review pages sent
// Referrer-Policy: no-referrer, a real browser posted the approve form with
// `Origin: null`, and no person could approve a connector change on any app,
// while every Go test passed because net/http never derives an Origin from a
// referrer policy). These tests are the browser: each framework page that
// carries a secret in its URL and posts a same-origin form is requested, the
// form is POSTed back with the Origin a browser computes from THAT PAGE'S
// Referrer-Policy header, and the post must not be refused for its origin.

// browserFormPostOrigin is the Origin a browser puts on a same-origin form POST
// from a page served with the given Referrer-Policy header (Fetch, "append a
// request Origin header"; measured with Chrome 154: no-referrer gives
// `Origin: null`, every other policy gives the page's own origin). The header
// may be a fallback list; the last policy the browser recognises wins.
func browserFormPostOrigin(pageOrigin, policyHeader string) string {
	policy := "" // the default policy never nulls a same-origin POST
	known := map[string]bool{"no-referrer": true, "no-referrer-when-downgrade": true, "same-origin": true, "origin": true,
		"strict-origin": true, "origin-when-cross-origin": true, "strict-origin-when-cross-origin": true, "unsafe-url": true}
	for _, p := range strings.Split(policyHeader, ",") {
		if p = strings.ToLower(strings.TrimSpace(p)); known[p] {
			policy = p
		}
	}
	if policy == "no-referrer" {
		return "null"
	}
	return pageOrigin
}

var postFormActionRe = regexp.MustCompile(`(?is)<form\b[^>]*\bmethod\s*=\s*["']?post["']?[^>]*\baction\s*=\s*"([^"]*)"|<form\b[^>]*\baction\s*=\s*"([^"]*)"[^>]*\bmethod\s*=\s*["']?post`)

// postFormAction returns the first post form's action, unescaped.
func postFormAction(t *testing.T, body string) string {
	t.Helper()
	m := postFormActionRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("page renders no post form: %.300s", body)
	}
	return html.UnescapeString(m[1] + m[2])
}

// browserVariants: Chrome, Firefox 90+ and Safari 16.4+ send Sec-Fetch-Site
// and the gate (security.md 5b) accepts `Origin: null` with it; a browser
// without Fetch Metadata does not, and there `Origin: null` is refused. A page
// must work for both, which is why the second variant exists: it is the one
// that fails when a page falls back to no-referrer.
var browserVariants = map[string]bool{"with Sec-Fetch-Site": true, "without Fetch Metadata": false}

func browserHeaders(origin, policy string, fetchMetadata bool) map[string]string {
	h := map[string]string{"Origin": browserFormPostOrigin(origin, policy)}
	if fetchMetadata {
		h["Sec-Fetch-Site"] = "same-origin"
	}
	return h
}

func TestBrowserFormPostOriginFollowsTheReferrerPolicy(t *testing.T) {
	for policy, want := range map[string]string{
		"no-referrer": "null", "No-Referrer": "null", "same-origin": "https://a.example", "": "https://a.example",
		"strict-origin-when-cross-origin": "https://a.example", "unsafe-url": "https://a.example",
		"no-referrer, same-origin": "https://a.example", "same-origin, no-referrer": "null", "bogus": "https://a.example",
	} {
		if got := browserFormPostOrigin("https://a.example", policy); got != want {
			t.Errorf("policy %q: Origin %q, want %q", policy, got, want)
		}
	}
}

// The MCP review page (operation id in the path) and batch page (grant id in
// the query), reusing the exposure harness.
func TestReferrerPolicyBrowserPostsAreNotRefusedForOrigin_MCPReview(t *testing.T) {
	for name, fetchMetadata := range browserVariants {
		t.Run(name, func(t *testing.T) {
			h := newExposureHarness(t)
			id := h.prepare()
			resp, body := h.do("GET", appMCPOperationRoute+id, h.cookie, nil, nil)
			form := appMCPOAuthHTTPHidden(t, body)
			if form.Get("_csrf") == "" {
				t.Fatalf("review page carries no token: %d", resp.StatusCode)
			}
			headers := browserHeaders(h.server.URL, resp.Header.Get("Referrer-Policy"), fetchMetadata)
			post, _ := h.do("POST", postFormAction(t, body), h.cookie, form, headers)
			if post.StatusCode != http.StatusSeeOther || h.count("SELECT count(*) FROM _benmore_mcp_command_approvals") != 1 {
				t.Fatalf("review page (Referrer-Policy %q) posted %v was refused: status %d; use Referrer-Policy: same-origin (security.md 5b)",
					resp.Header.Get("Referrer-Policy"), headers, post.StatusCode)
			}
		})
	}
}

func TestReferrerPolicyBrowserPostsAreNotRefusedForOrigin_MCPBatch(t *testing.T) {
	for name, fetchMetadata := range browserVariants {
		t.Run(name, func(t *testing.T) {
			h := newExposureHarness(t)
			id := h.prepare()
			resp, body := h.do("GET", appMCPBatchRoute+"?grant="+h.pair.GrantID, h.cookie, nil, nil)
			form := appMCPOAuthHTTPHidden(t, body)
			form.Set("op", id) // the ticked box
			if form.Get("_csrf") == "" {
				t.Fatalf("batch page carries no token: %d", resp.StatusCode)
			}
			headers := browserHeaders(h.server.URL, resp.Header.Get("Referrer-Policy"), fetchMetadata)
			post, _ := h.do("POST", postFormAction(t, body), h.cookie, form, headers)
			if post.StatusCode != http.StatusSeeOther {
				t.Fatalf("batch page (Referrer-Policy %q) posted %v was refused: status %d; use Referrer-Policy: same-origin (security.md 5b)",
					resp.Header.Get("Referrer-Policy"), headers, post.StatusCode)
			}
		})
	}
}

// The connector OAuth consent page (client, redirect and consent nonce in the URL).
func TestReferrerPolicyBrowserPostsAreNotRefusedForOrigin_ConnectorConsent(t *testing.T) {
	for name, fetchMetadata := range browserVariants {
		t.Run(name, func(t *testing.T) {
			f := newAppMCPOAuthHTTPFixture(t)
			values := cloneMCPOAuthValues(f.values)
			values.Set("workspace", "17")
			page := f.request(t, http.MethodGet, "/oauth/authorize?"+values.Encode(), nil, "", "")
			if page.Code != http.StatusOK {
				t.Fatalf("consent page: %d %.300s", page.Code, page.Body.String())
			}
			form := appMCPOAuthHTTPHidden(t, page.Body.String())
			form.Set("decision", "approve") // the clicked button
			headers := browserHeaders(appMCPOAuthHTTPOrigin, page.Header().Get("Referrer-Policy"), fetchMetadata)
			w := browserPost(f.mux, appMCPOAuthHTTPOrigin+postFormAction(t, page.Body.String()), form, headers, f.sid)
			if w.Code != http.StatusFound || !strings.Contains(w.Header().Get("Location"), "code=") {
				t.Fatalf("consent page (Referrer-Policy %q) posted %v was refused: status %d; use Referrer-Policy: same-origin (security.md 5b)",
					page.Header().Get("Referrer-Policy"), headers, w.Code)
			}
		})
	}
}

// The email-change confirmation page (token in the URL), one of the three
// framework confirmation pages that already got this wrong once (5b).
func TestReferrerPolicyBrowserPostsAreNotRefusedForOrigin_EmailChangeConfirm(t *testing.T) {
	for name, fetchMetadata := range browserVariants {
		t.Run(name, func(t *testing.T) {
			app, mux, uid, _ := newEmailChangeTestApp(t)
			ensureEmailChangesTable(app.DB)
			if _, err := app.DB.Exec("INSERT INTO _benmore_email_changes (user_id, new_email, token_hash, expires_at) VALUES (?, 'next@example.com', ?, ?)",
				uid, hashResetToken("change"), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
				t.Fatal(err)
			}
			const origin = "https://app.example"
			page := httptest.NewRecorder()
			mux.ServeHTTP(page, httptest.NewRequest(http.MethodGet, origin+"/settings/confirm-email?token=change", nil))
			form := appMCPOAuthHTTPHidden(t, page.Body.String())
			form.Set("password", "Correct-Horse-1")
			headers := browserHeaders(origin, page.Header().Get("Referrer-Policy"), fetchMetadata)
			browserPost(mux, origin+postFormAction(t, page.Body.String()), form, headers, "")
			if got := currentEmail(t, app, uid); got != "next@example.com" {
				t.Fatalf("email-change page (Referrer-Policy %q) posted %v was refused: email is still %q; use Referrer-Policy: same-origin (security.md 5b)",
					page.Header().Get("Referrer-Policy"), headers, got)
			}
		})
	}
}

// browserPost serves one form POST the way a browser sends it.
func browserPost(h http.Handler, target string, form url.Values, headers map[string]string, sid string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	if sid != "" {
		r.AddCookie(sessionCookie(sid, false, time.Hour))
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
