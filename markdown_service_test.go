package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func markdownTestServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	registerMarkdownRoutes(mux)
	return httptest.NewServer(mux)
}

// resetMarkdownRateLimiters swaps mdSingleLimiter/mdBatchLimiter for fresh
// instances (see newMarkdownLimiters in markdown_service.go). Any test that
// intentionally drives one of these limiters to its cap must call this -
// directly, or via t.Cleanup(resetMarkdownRateLimiters) - so the budget it
// consumed doesn't leak into every other test in this binary that hits
// these endpoints. All markdownTestServer-backed tests share 127.0.0.1 as
// their source IP, so without a reset a rate-limit test running earlier
// could cause spurious 429s in an unrelated test running later.
func resetMarkdownRateLimiters() {
	mdSingleLimiter, mdBatchLimiter = newMarkdownLimiters()
}

func TestMarkdownEndpointRendersRichAndSafe(t *testing.T) {
	srv := markdownTestServer(t)
	defer srv.Close()

	body, _ := json.Marshal(markdownReq{Text: "# Title\n\n| A | B |\n|---|---|\n| 1 | 2 |\n\n```go\nx := 1\n```\n\n<script>alert(1)</script>"})
	resp, err := http.Post(srv.URL+"/_internal/markdown", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	out := string(raw)
	for _, want := range []string{"<h1", "<table", "chroma"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output: %q", want, out)
		}
	}
	for _, bad := range []string{"<script", "alert(1)"} {
		if strings.Contains(out, bad) {
			t.Errorf("XSS leak %q in output: %q", bad, out)
		}
	}
}

func TestMarkdownBatchAligned(t *testing.T) {
	srv := markdownTestServer(t)
	defer srv.Close()

	payload := `{"items":[{"text":"# One"},{"text":"**two**","inline":true}]}`
	resp, err := http.Post(srv.URL+"/_internal/markdown/batch", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got struct {
		HTML []string `json:"html"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.HTML) != 2 {
		t.Fatalf("want 2 results, got %d", len(got.HTML))
	}
	if !strings.Contains(got.HTML[0], "<h1") {
		t.Errorf("item 0 not rendered: %q", got.HTML[0])
	}
	if strings.Contains(got.HTML[1], "<p>") { // inline mode strips wrapping <p>
		t.Errorf("item 1 should be inline (no <p>): %q", got.HTML[1])
	}
}

func TestMarkdownAssetRoutesETag(t *testing.T) {
	srv := markdownTestServer(t)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/_internal/markdown.css")
	if err != nil {
		t.Fatal(err)
	}
	etag := resp.Header.Get("ETag")
	resp.Body.Close()
	if etag == "" {
		t.Fatal("no ETag on markdown.css")
	}
	// Conditional request should 304.
	req, _ := http.NewRequest("GET", srv.URL+"/_internal/markdown.css", nil)
	req.Header.Set("If-None-Match", etag)
	resp2, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusNotModified {
		t.Errorf("conditional GET = %d, want 304", resp2.StatusCode)
	}
}

func TestMarkdownPipeEmitsRawHTML(t *testing.T) {
	// The markdown pipe returns sanitized HTML that RenderMustache must emit
	// raw (not HTML-escaped).
	out := RenderMustache("{{ body | markdown }}", map[string]any{"body": "# Hi\n\nsome **text**"})
	if !strings.Contains(out, "<h1") {
		t.Errorf("markdown pipe did not emit raw HTML: %q", out)
	}
	if strings.Contains(out, "&lt;h1") {
		t.Errorf("markdown pipe output was HTML-escaped: %q", out)
	}
	// Inline variant strips the wrapping <p>.
	inline := RenderMustache("{{ msg | markdown_inline }}", map[string]any{"msg": "hello **world**"})
	if strings.Contains(inline, "<p>") {
		t.Errorf("markdown_inline should not wrap in <p>: %q", inline)
	}
}

func TestNonMarkdownPipeStillEscapes(t *testing.T) {
	// The raw-emit branch must be scoped to the markdown pipes only; every
	// other pipe must keep HTML-escaping its output.
	out := RenderMustache("{{ x | upper }}", map[string]any{"x": "<script>hi"})
	if !strings.Contains(out, "&lt;") || strings.Contains(out, "<script") {
		t.Errorf("non-markdown pipe should still escape HTML: %q", out)
	}
}

func TestMarkdownEndpointStripsRawIframe(t *testing.T) {
	srv := markdownTestServer(t)
	defer srv.Close()
	// Raw HTML in Markdown source passes goldmark (WithUnsafe) → the sanitizer
	// must strip an attacker iframe pointed at a non-allowlisted host.
	body, _ := json.Marshal(markdownReq{Text: `<iframe src="https://evil.example/phish"></iframe>` + "\n\n<iframe srcdoc=\"<script>alert(1)</script>\"></iframe>"})
	resp, err := http.Post(srv.URL+"/_internal/markdown", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := string(raw)
	for _, bad := range []string{"evil.example", "srcdoc", "<script"} {
		if strings.Contains(out, bad) {
			t.Errorf("sanitizer let %q through: %q", bad, out)
		}
	}
}

func TestMarkdownEndpointBlocksSVGDataURIImage(t *testing.T) {
	srv := markdownTestServer(t)
	defer srv.Close()

	body, _ := json.Marshal(markdownReq{Text: `![x](data:image/svg+xml;base64,PHN2ZyBvbmxvYWQ9YWxlcnQoMSk+PC9zdmc+)`})
	resp, err := http.Post(srv.URL+"/_internal/markdown", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	out := string(raw)
	for _, bad := range []string{"data:image/svg+xml", "onload", "alert(1)"} {
		if strings.Contains(out, bad) {
			t.Errorf("svg data URI leak %q in output: %q", bad, out)
		}
	}
}

func TestMarkdownCacheHitReturnsSame(t *testing.T) {
	a := renderMarkdownSafe("# same", false)
	b := renderMarkdownSafe("# same", false)
	if a != b || !strings.Contains(a, "<h1") {
		t.Errorf("cache mismatch: %q vs %q", a, b)
	}
}

// TestMarkdownBatchRejectsOversizedRequest locks Task 24's fix: the batch
// response is {"html":[...]} aligned by index with the request's items, so
// silently truncating past 500 (the old behavior) desynced that alignment
// with no signal to the caller. Over the cap must now be a 400, not a
// quietly-shorter response.
func TestMarkdownBatchRejectsOversizedRequest(t *testing.T) {
	srv := markdownTestServer(t)
	defer srv.Close()

	items := make([]markdownReq, markdownBatchMaxItems+1)
	for i := range items {
		items[i] = markdownReq{Text: "x"}
	}
	payload, err := json.Marshal(map[string]any{"items": items})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(srv.URL+"/_internal/markdown/batch", "application/json", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusBadRequest)
	}

	// A request at exactly the cap must still succeed and return an aligned
	// response - only OVER the cap is rejected.
	items = items[:markdownBatchMaxItems]
	payload, err = json.Marshal(map[string]any{"items": items})
	if err != nil {
		t.Fatal(err)
	}
	resp2, err := http.Post(srv.URL+"/_internal/markdown/batch", "application/json", strings.NewReader(string(payload)))
	if err != nil {
		t.Fatal(err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("at-cap request: status = %d, want 200", resp2.StatusCode)
	}
	var got struct {
		HTML []string `json:"html"`
	}
	if err := json.NewDecoder(resp2.Body).Decode(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.HTML) != markdownBatchMaxItems {
		t.Fatalf("at-cap request: want %d results, got %d", markdownBatchMaxItems, len(got.HTML))
	}
}

// TestMarkdownCacheByteBudgetEnforced locks the byte-cap fix for the render
// cache: a single entry too large for the whole budget must never be
// cached (it can only ever displace everything else to make room for
// itself), and once several smaller entries collectively exceed the
// budget, the oldest must be evicted to keep the cache within it.
func TestMarkdownCacheByteBudgetEnforced(t *testing.T) {
	c := newMarkdownCache(1024) // tiny budget, deterministic + fast

	big := strings.Repeat("a", 2048) // bigger than the whole budget
	c.put("big", big)
	if _, ok := c.get("big"); ok {
		t.Fatal("an entry larger than the total budget must never be cached")
	}
	if c.curBytes != 0 {
		t.Fatalf("rejecting an oversized entry must not touch curBytes, got %d", c.curBytes)
	}

	// Several entries that individually fit but collectively exceed the
	// 1024-byte budget (10 * ~200+key bytes).
	val := strings.Repeat("b", 200)
	for i := 0; i < 10; i++ {
		c.put(fmt.Sprintf("k%d", i), val)
	}
	if c.curBytes > c.maxBytes {
		t.Errorf("cache exceeded its byte budget: %d > %d", c.curBytes, c.maxBytes)
	}
	if _, ok := c.get("k0"); ok {
		t.Error("oldest entry should have been evicted once the byte budget was exceeded")
	}
	if _, ok := c.get("k9"); !ok {
		t.Error("most recently inserted entry should still be cached")
	}
}

// TestMarkdownSkipsCacheForLargeInput locks the "skip caching inputs above
// ~32 KiB" half of the fix: large-but-under-the-512KiB-request-cap inputs
// still render, they just never occupy a cache slot (otherwise a flood of
// distinct near-cap payloads dominates the byte budget almost immediately).
func TestMarkdownSkipsCacheForLargeInput(t *testing.T) {
	big := "# " + strings.Repeat("a", markdownCacheableBytes+1024)
	key := markdownCacheKey(big, false)

	out := renderMarkdownSafe(big, false)
	if !strings.Contains(out, "<h1") {
		t.Fatalf("expected large input to still render, got: %q", out[:min(len(out), 80)])
	}
	if _, ok := mdCache.get(key); ok {
		t.Error("input above markdownCacheableBytes must not be cached")
	}
}

// TestMarkdownEndpointsRateLimited proves the DoS this task closes: POSTs
// to /_internal/markdown and /_internal/markdown/batch are subject to an
// explicit rate limit (Task 3), unlike the surrounding /_internal/ GET
// static assets which stay exempt (see
// TestMarkdownPOSTRateLimitedWhileStaticGETExempt below for the exemption
// side). Drives the ordinary markdownTestServer (real network conn, real
// RemoteAddr) rather than calling the handlers directly - safe now that
// resetMarkdownRateLimiters resets mdSingleLimiter/mdBatchLimiter to a
// fresh instance afterward, so this test's budget consumption can't leak
// into any other test in this file that also hits these endpoints.
func TestMarkdownEndpointsRateLimited(t *testing.T) {
	t.Cleanup(resetMarkdownRateLimiters)

	srv := markdownTestServer(t)
	defer srv.Close()

	hitSingle := func() int {
		body, _ := json.Marshal(markdownReq{Text: "hi"})
		resp, err := http.Post(srv.URL+"/_internal/markdown", "application/json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}
	hitBatch := func() int {
		payload := `{"items":[{"text":"hi"}]}`
		resp, err := http.Post(srv.URL+"/_internal/markdown/batch", "application/json", strings.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		return resp.StatusCode
	}

	t.Run("single", func(t *testing.T) {
		sawLimited := false
		for i := 0; i < mdMarkdownRateLimit+10; i++ {
			code := hitSingle()
			if code == http.StatusTooManyRequests {
				sawLimited = true
				break
			}
			if code != http.StatusOK {
				t.Fatalf("request %d: unexpected status %d", i+1, code)
			}
		}
		if !sawLimited {
			t.Fatal("POST /_internal/markdown was never rate-limited - the DoS exemption is still open")
		}
	})

	t.Run("batch", func(t *testing.T) {
		sawLimited := false
		for i := 0; i < mdMarkdownBatchRateLimit+10; i++ {
			code := hitBatch()
			if code == http.StatusTooManyRequests {
				sawLimited = true
				break
			}
			if code != http.StatusOK {
				t.Fatalf("request %d: unexpected status %d", i+1, code)
			}
		}
		if !sawLimited {
			t.Fatal("POST /_internal/markdown/batch was never rate-limited - the DoS exemption is still open")
		}
	})
}

// TestMarkdownPOSTRateLimitedWhileStaticGETExempt drives the actual
// production middleware stack (RateLimitMiddleware wrapping the mux, same
// as host.go/router.go/server.go wrap every app's routes) to prove two
// things at once, end to end:
//  1. GET requests to genuine static assets under /_internal/ (here,
//     markdown.css) remain exempt from the global rate limiter - the fix
//     for Task 3 must NOT regress the "I keep hitting the rate limit just
//     clicking around" behavior isStaticPath exists to prevent.
//  2. POST /_internal/markdown is nonetheless rate-limited - not by the
//     outer global limiter (which still exempts the whole /_internal/
//     prefix, unchanged), but by the endpoint's own explicit limiter added
//     in markdown_service.go. The outer limiter is given a tiny budget
//     specifically so a regression that let static GETs start counting
//     against it (or that relied on the outer limiter for the POST fix)
//     would show up immediately.
func TestMarkdownPOSTRateLimitedWhileStaticGETExempt(t *testing.T) {
	t.Cleanup(resetMarkdownRateLimiters)

	mux := http.NewServeMux()
	registerMarkdownRoutes(mux)
	outer := NewRateLimiter(3, time.Minute)
	h := RateLimitMiddleware(outer, mux)

	ip := "198.51.100.30:5555"

	getStatic := func() int {
		req := httptest.NewRequest("GET", "/_internal/markdown.css", nil)
		req.RemoteAddr = ip
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	postMarkdown := func() int {
		body, _ := json.Marshal(markdownReq{Text: "hi"})
		req := httptest.NewRequest("POST", "/_internal/markdown", strings.NewReader(string(body)))
		req.RemoteAddr = ip
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	// Far more GETs than the outer budget (3): none should ever 429.
	for i := 0; i < 20; i++ {
		if code := getStatic(); code == http.StatusTooManyRequests {
			t.Fatalf("GET /_internal/markdown.css was rate-limited (429) on request %d - static assets must stay exempt", i+1)
		}
	}

	// POSTs share the /_internal/ prefix so the OUTER limiter still exempts
	// them too (unchanged) - the endpoint's own limiter must still catch it.
	sawLimited := false
	for i := 0; i < mdMarkdownRateLimit+10; i++ {
		if postMarkdown() == http.StatusTooManyRequests {
			sawLimited = true
			break
		}
	}
	if !sawLimited {
		t.Fatal("POST /_internal/markdown was never rate-limited through the real middleware stack - the DoS exemption is still open")
	}
}
