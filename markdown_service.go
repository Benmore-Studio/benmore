package main

import (
	"container/list"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/benmore-studio/benmark"
)

// markdown_service.go wires the benmark renderer (github.com/benmore-studio/benmark)
// into the framework as the server-side Markdown engine. The client SDK
// (bm.markdown) and the gotmpl `markdown` pipe both render through here, so
// there is ONE renderer across every surface instead of the old client-only
// regex subset.

const (
	// markdownMaxBytes caps a single render input. Large enough for long docs,
	// small enough that the endpoint can't be used to burn CPU on huge payloads.
	markdownMaxBytes = 512 << 10 // 512 KiB

	// markdownCacheableBytes: only inputs at or below this size participate in
	// the render cache. Larger (up to markdownMaxBytes) inputs still render,
	// they just never get memoized - without this, a flood of distinct
	// near-512KiB payloads could each land a cache entry and dominate the
	// byte budget below almost immediately.
	markdownCacheableBytes = 32 << 10 // 32 KiB

	// markdownCacheMaxBytes bounds the render cache by total bytes held
	// (key+value), not entry count. The old count cap (4096 entries) let
	// each entry hold up to ~512 KiB of input plus a larger rendered-HTML
	// value, so ~4096 unthrottled distinct POSTs could pin multi-GiB of
	// heap for the process lifetime. A byte budget bounds worst-case memory
	// regardless of how large individual entries are.
	markdownCacheMaxBytes = 64 << 20 // 64 MiB

	// mdMarkdownRateLimit / mdMarkdownBatchRateLimit: see mdSingleLimiter /
	// mdBatchLimiter below for why these exist.
	mdMarkdownRateLimit      = 40 // requests/minute/IP for POST /_internal/markdown
	mdMarkdownBatchRateLimit = 20 // requests/minute/IP for POST /_internal/markdown/batch (heavier: up to 500 items/call)
)

var (
	// Two reusable renderers (benmark.Renderer is concurrency-safe): full
	// document mode, and the inline "chat" subset that strips the wrapping
	// <p> and hard-wraps newlines.
	mdDocRenderer    = benmark.New()
	mdInlineRenderer = benmark.New(benmark.WithInline(true))

	mdCache = newMarkdownCache(markdownCacheMaxBytes)

	mdCSS     = benmark.CSS()
	mdHydrate = benmark.HydrateJS()
	mdCSSETag = weakETag([]byte(mdCSS))
	mdHydETag = weakETag([]byte(mdHydrate))

	// mdSingleLimiter / mdBatchLimiter: POST /_internal/markdown[/batch] is
	// unauthenticated by design (the client SDK renders Markdown before
	// login) and lives under /_internal/, which RateLimitMiddleware exempts
	// entirely via isStaticPath - a path-only, method-agnostic check meant
	// for GET static assets that was silently also exempting these POSTs
	// from the global rate limiter. Rather than teach isStaticPath about
	// HTTP methods (it also gates request-log skip-logging, a much
	// lower-stakes call shared by both GET and POST paths), these two
	// handlers carry their own explicit, self-contained rate limit - the
	// "explicit carve-out" option. GET /_internal/markdown.css and
	// /_internal/markdown-hydrate.js are untouched and remain exempt, as do
	// all other genuine static GET assets under /_internal/.
	//
	// Built via newMarkdownLimiters() rather than inline NewRateLimiter
	// calls so they're swappable/resettable: every other limiter in the
	// repo is either constructed per call site or passed in as a parameter
	// (cf. RateLimitMiddleware(rl, next) in ratelimit.go). These were the
	// one process-lifetime singleton with no reset/injection point, which
	// forced rate-limit tests to bypass the HTTP server and fabricate
	// RemoteAddrs just to dodge the shared, never-reset budget. See
	// resetMarkdownRateLimiters in markdown_service_test.go.
	mdSingleLimiter, mdBatchLimiter = newMarkdownLimiters()
)

// newMarkdownLimiters constructs the pair of rate limiters backing
// POST /_internal/markdown[/batch], at the same rate/window as production
// (mdMarkdownRateLimit / mdMarkdownBatchRateLimit per minute). Factored out
// of the var block above so both the package-level vars and
// resetMarkdownRateLimiters (test helper) build them identically.
func newMarkdownLimiters() (single, batch *RateLimiter) {
	return NewRateLimiter(mdMarkdownRateLimit, time.Minute), NewRateLimiter(mdMarkdownBatchRateLimit, time.Minute)
}

// renderMarkdownSafe renders text to sanitized HTML, memoized. On any render
// error it falls back to HTML-escaped plaintext so the caller never receives
// unsanitized markup and the XSS-safe guarantee is preserved.
func renderMarkdownSafe(text string, inline bool) string {
	if text == "" {
		return ""
	}
	key := markdownCacheKey(text, inline)
	if out, ok := mdCache.get(key); ok {
		return out
	}
	r := mdDocRenderer
	if inline {
		r = mdInlineRenderer
	}
	out, err := r.RenderString(text)
	if err != nil {
		out = html.EscapeString(text)
	}
	if len(text) <= markdownCacheableBytes {
		mdCache.put(key, out)
	}
	return out
}

func markdownCacheKey(text string, inline bool) string {
	h := sha256.New()
	if inline {
		h.Write([]byte{1})
	} else {
		h.Write([]byte{0})
	}
	h.Write([]byte(text))
	return hex.EncodeToString(h.Sum(nil))
}

// registerMarkdownRoutes adds the Markdown render endpoints + static assets to
// a mux. Called from RegisterLibRoutes (shared by app + edge origins).
func registerMarkdownRoutes(mux *http.ServeMux) {
	mux.HandleFunc("POST /_internal/markdown", handleMarkdownRender)
	mux.HandleFunc("POST /_internal/markdown/batch", handleMarkdownBatch)

	mux.HandleFunc("GET /_internal/markdown.css", func(w http.ResponseWriter, r *http.Request) {
		serveMarkdownAsset(w, r, "text/css; charset=utf-8", mdCSS, mdCSSETag)
	})
	mux.HandleFunc("GET /_internal/markdown-hydrate.js", func(w http.ResponseWriter, r *http.Request) {
		serveMarkdownAsset(w, r, "application/javascript; charset=utf-8", mdHydrate, mdHydETag)
	})
}

type markdownReq struct {
	Text   string `json:"text"`
	Inline bool   `json:"inline"`
}

// handleMarkdownRender renders one Markdown string to sanitized HTML.
// Body: {"text": "...", "inline": false}. Response: text/html.
func handleMarkdownRender(w http.ResponseWriter, r *http.Request) {
	if markdownRateLimited(w, r, mdSingleLimiter, "single") {
		return
	}
	var req markdownReq
	if err := decodeMarkdownBody(w, r, &req); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	io.WriteString(w, renderMarkdownSafe(req.Text, req.Inline))
}

// markdownBatchMaxItems bounds a single batch call. The response is
// {"html":[...]} aligned by index with the request's items, so silently
// dropping the tail (the old behavior) would desync that alignment for
// any caller trusting `items[i]` <-> `html[i]` - a caller sending 600
// chat messages would get back 500 rendered strings with NO indication
// which 100 were dropped. Reject the whole request instead so the
// response-length-equals-request-length invariant always holds.
const markdownBatchMaxItems = 500

// handleMarkdownBatch renders many strings in one round-trip so a message list
// renders without N requests. Body: {"items":[{"text","inline"},...]}.
// Response: {"html":["...",...]} aligned by index. Rejects with 400 if
// more than markdownBatchMaxItems are sent - see its doc comment.
func handleMarkdownBatch(w http.ResponseWriter, r *http.Request) {
	if markdownRateLimited(w, r, mdBatchLimiter, "batch") {
		return
	}
	var body struct {
		Items []markdownReq `json:"items"`
	}
	if err := decodeMarkdownBody(w, r, &body); err != nil {
		http.Error(w, "invalid request", http.StatusBadRequest)
		return
	}
	if len(body.Items) > markdownBatchMaxItems {
		http.Error(w, fmt.Sprintf("too many items: got %d, max %d", len(body.Items), markdownBatchMaxItems), http.StatusBadRequest)
		return
	}
	out := make([]string, len(body.Items))
	for i, it := range body.Items {
		out[i] = renderMarkdownSafe(it.Text, it.Inline)
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	_ = json.NewEncoder(w).Encode(map[string][]string{"html": out})
}

// markdownRateLimited enforces the given limiter, keyed by source IP (same
// approach as RateLimitMiddleware in ratelimit.go: RemoteAddr's host only,
// never the raw ip:port pair, since the ephemeral port differs every TCP
// connection). Writes a 429 + Retry-After and returns true when the caller
// is over budget; the handler must return immediately in that case.
func markdownRateLimited(w http.ResponseWriter, r *http.Request, rl *RateLimiter, scope string) bool {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	if rl.Allow("md:" + scope + ":" + host) {
		return false
	}
	w.Header().Set("Retry-After", "60")
	http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
	return true
}

func decodeMarkdownBody(w http.ResponseWriter, r *http.Request, dst any) error {
	r.Body = http.MaxBytesReader(w, r.Body, markdownMaxBytes)
	return json.NewDecoder(r.Body).Decode(dst)
}

// serveMarkdownAsset serves framework-own CSS/JS with ETag revalidation. Like
// bm.js, this is framework code that changes on deploy, so it must revalidate
// rather than sit in a 24h CDN cache and go stale.
func serveMarkdownAsset(w http.ResponseWriter, r *http.Request, contentType, body, etag string) {
	w.Header().Set("Content-Type", contentType)
	w.Header().Set("ETag", etag)
	w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
	w.Header().Set("CDN-Cache-Control", "no-store")
	if match := r.Header.Get("If-None-Match"); match == etag || match == "W/"+etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	io.WriteString(w, body)
}

func weakETag(b []byte) string {
	sum := sha256.Sum256(b)
	return `"` + hex.EncodeToString(sum[:8]) + `"`
}

// ---- byte-bounded LRU cache of rendered HTML ----
//
// Bounded by total bytes held (key+value across all entries), not entry
// count. An entry-count cap (the old behavior: 4096 entries) says nothing
// about how large each entry is - each held up to markdownCacheableBytes of
// input plus a potentially much larger rendered-HTML value, so a flood of
// distinct near-cap-size inputs could pin multi-GiB of heap for the
// process lifetime regardless of the 4096 ceiling. A byte budget bounds
// worst-case memory directly.

type markdownCache struct {
	mu       sync.Mutex
	maxBytes int64
	curBytes int64
	ll       *list.List
	items    map[string]*list.Element
}

type mdEntry struct{ key, val string }

// entrySize accounts for both key and value bytes - the key is a fixed
// 64-byte hex string (see markdownCacheKey) so this is dominated by the
// rendered HTML value.
func markdownEntrySize(key, val string) int64 {
	return int64(len(key) + len(val))
}

func newMarkdownCache(maxBytes int64) *markdownCache {
	return &markdownCache{maxBytes: maxBytes, ll: list.New(), items: make(map[string]*list.Element)}
}

func (c *markdownCache) get(key string) (string, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.items[key]; ok {
		c.ll.MoveToFront(el)
		return el.Value.(*mdEntry).val, true
	}
	return "", false
}

// put inserts/updates an entry and evicts from the back (oldest) until the
// cache is back under its byte budget. A single entry that can never fit
// under the budget on its own is skipped outright rather than accepted and
// immediately evicting every other entry to make room for it.
func (c *markdownCache) put(key, val string) {
	c.mu.Lock()
	defer c.mu.Unlock()

	size := markdownEntrySize(key, val)
	if size > c.maxBytes {
		return
	}

	if el, ok := c.items[key]; ok {
		old := el.Value.(*mdEntry)
		c.curBytes += size - markdownEntrySize(old.key, old.val)
		old.val = val
		c.ll.MoveToFront(el)
	} else {
		c.items[key] = c.ll.PushFront(&mdEntry{key: key, val: val})
		c.curBytes += size
	}

	for c.curBytes > c.maxBytes {
		oldest := c.ll.Back()
		if oldest == nil {
			break
		}
		c.ll.Remove(oldest)
		e := oldest.Value.(*mdEntry)
		delete(c.items, e.key)
		c.curBytes -= markdownEntrySize(e.key, e.val)
	}
}
