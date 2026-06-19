//go:build !cli

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// fetchTemplateStore holds inner templates for async fetch, keyed by hash.
var fetchTemplateStore = struct {
	sync.RWMutex
	templates map[string]string
}{templates: make(map[string]string)}

// RegisterFetchRoutes adds the internal async fetch endpoint.
func RegisterFetchRoutes(mux *http.ServeMux, app *App) {
	mux.HandleFunc("GET /_internal/fetch", func(w http.ResponseWriter, r *http.Request) {
		// Auth/CSRF gate. This endpoint makes outbound requests on the
		// server's behalf, so it must not be drivable cross-site. A valid
		// CSRF token (same-origin proof) OR a bearer-authenticated caller
		// is required; otherwise an attacker page could trigger fetches
		// using the victim's ambient session. Fail closed.
		if !validateCSRF(r) && !isBearerAuth(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}

		fetchURL := r.URL.Query().Get("url")
		as := r.URL.Query().Get("as")
		templateHash := r.URL.Query().Get("t")
		headersParam := r.URL.Query().Get("headers")
		cacheParam := r.URL.Query().Get("cache")

		if fetchURL == "" {
			http.Error(w, "Missing url", http.StatusBadRequest)
			return
		}

		// Resolve relative URLs against the app's CONFIGURED canonical
		// origin, never r.Host. r.Host is attacker-influenceable (Host
		// header / forwarding) so resolving against it let a relative URL
		// be redirected at an internal endpoint while we replayed the
		// victim's cookies - a confused-deputy SSRF. The canonical origin
		// is operator-set and trusted.
		canonicalOrigin := uploadsCanonicalOrigin(app)
		// trustedLocal is true only when the destination is the configured
		// canonical origin. Cookies are forwarded ONLY to trustedLocal
		// destinations - never to an r.Host-derived or remote host.
		trustedLocal := false
		if strings.HasPrefix(fetchURL, "/") {
			if canonicalOrigin == "" {
				// No configured origin → we cannot prove the relative URL
				// resolves to a trusted host. Fail closed rather than fall
				// back to r.Host.
				http.Error(w, "Relative fetch URLs require a configured BENMORE_PUBLIC_URL", http.StatusBadGateway)
				return
			}
			fetchURL = strings.TrimRight(canonicalOrigin, "/") + fetchURL
			trustedLocal = true
		}

		// Always run the SSRF check - including for canonical-origin-derived
		// URLs. The canonical origin itself could be misconfigured to a
		// private host, and a relative path can still target a private
		// internal route, so this gate must never be skipped.
		if isPrivateURL(fetchURL) {
			http.Error(w, "Blocked", http.StatusForbidden)
			return
		}

		// Check cache
		cacheDuration := parseDuration(cacheParam)
		cacheKey := fetchURL
		if cacheDuration > 0 {
			fetchCache.RLock()
			entry, ok := fetchCache.entries[cacheKey]
			fetchCache.RUnlock()
			if ok && time.Now().Before(entry.expiresAt) {
				renderFetchResponse(w, entry.data, as, templateHash)
				return
			}
		}

		// Make the HTTP request (2s timeout - fast fail is better than blocking)
		client := safeHTTPClientStrict(2 * time.Second)
		req, err := http.NewRequest("GET", fetchURL, nil)
		if err != nil {
			http.Error(w, "Request error", http.StatusBadGateway)
			return
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "Benmore/1.0")

		// Forward cookies ONLY to the configured canonical origin. We must
		// never forward the caller's cookies to a host derived from r.Host
		// or to a remote/absolute destination - that is exactly the
		// confused-deputy replay this fix closes. Match the parsed
		// destination host against the canonical origin host; equality is
		// the sole condition under which cookies are trusted to leave.
		if !trustedLocal && canonicalOrigin != "" {
			if parsed, parseErr := url.Parse(fetchURL); parseErr == nil {
				if co, coErr := url.Parse(canonicalOrigin); coErr == nil &&
					parsed.Host != "" && parsed.Host == co.Host {
					trustedLocal = true
				}
			}
		}
		if trustedLocal {
			for _, cookie := range r.Cookies() {
				req.AddCookie(cookie)
			}
		}

		if headersParam != "" {
			headersParam = InterpolateEnv(headersParam, app.Dir)
			for _, h := range strings.Split(headersParam, ",") {
				parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
				if len(parts) == 2 {
					req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
				}
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("FETCH ASYNC error: %s → %s", fetchURL, err)
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<div style="color:var(--text-muted);font-size:0.8rem;padding:0.5rem;">Failed to load data</div>`))
			return
		}
		defer resp.Body.Close()

		body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		if resp.StatusCode >= 400 {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<div style="color:var(--text-muted);font-size:0.8rem;padding:0.5rem;">Data unavailable</div>`))
			return
		}

		var data any
		if err := json.Unmarshal(body, &data); err != nil {
			data = string(body)
		}

		// Cache
		if cacheDuration > 0 {
			fetchCache.Lock()
			fetchCache.entries[cacheKey] = &cacheEntry{data: data, expiresAt: time.Now().Add(cacheDuration)}
			fetchCache.Unlock()
		}

		renderFetchResponse(w, data, as, templateHash)
	})
}

// uploadsCanonicalOrigin returns the app's operator-configured public
// origin (scheme://host[:port]) used to resolve relative /_internal/fetch
// URLs and to decide whether cookies may be forwarded. Prefers
// BENMORE_PUBLIC_URL, falling back to the existing CORS_ORIGIN convention.
// Returns "" when unset - callers MUST fail closed rather than fall back to
// the attacker-influenceable r.Host. Only the scheme+host are kept.
func uploadsCanonicalOrigin(app *App) string {
	if app == nil {
		return ""
	}
	raw := GetEnv(app.Dir, "BENMORE_PUBLIC_URL")
	if raw == "" {
		raw = GetEnv(app.Dir, "CORS_ORIGIN")
	}
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	// CORS_ORIGIN may be a comma-separated list or "*"; take the first
	// concrete origin and ignore wildcards (a wildcard is not a resolvable
	// host we can safely forward cookies to).
	if i := strings.IndexByte(raw, ','); i >= 0 {
		raw = strings.TrimSpace(raw[:i])
	}
	if raw == "" || raw == "*" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

func renderFetchResponse(w http.ResponseWriter, data any, as, templateHash string) {
	// Get the inner template
	fetchTemplateStore.RLock()
	inner, ok := fetchTemplateStore.templates[templateHash]
	fetchTemplateStore.RUnlock()

	if !ok || inner == "" {
		// No template - return raw JSON
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(data)
		return
	}

	// Build context and render mustache
	ctx := make(map[string]any)
	if as != "" {
		// Convert []any to []map[string]any for mustache section rendering
		switch d := data.(type) {
		case []any:
			var rows []map[string]any
			for _, item := range d {
				if m, ok := item.(map[string]any); ok {
					rows = append(rows, m)
				}
			}
			ctx[as] = rows
		case map[string]any:
			ctx[as] = d
			for k, v := range d {
				ctx[as+"."+k] = v
				if nested, ok := v.(map[string]any); ok {
					for nk, nv := range nested {
						ctx[as+"."+k+"."+nk] = nv
					}
				}
			}
		default:
			ctx[as] = data
		}
	}

	rendered := RenderMustache(inner, ctx)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write([]byte(rendered))
}

// ExpandFetchTagsAsync replaces <fetch> tags with a loading skeleton + HTMX lazy load.
// The page renders instantly. Data loads async and swaps in when ready.
func ExpandFetchTagsAsync(content string, app *App, ctx *RenderContext) string {
	return fetchTagRe.ReplaceAllStringFunc(content, func(match string) string {
		m := fetchTagRe.FindStringSubmatch(match)
		if m == nil {
			return match
		}

		attrs := parseAttrs(m[1])
		inner := m[2]

		rawURL := attrs["url"]
		as := attrs["as"]
		cache := attrs["cache"]
		headers := attrs["headers"]
		loading := attrs["loading"]

		if rawURL == "" {
			return renderFetchError(app, "fetch: url attribute required")
		}

		// Resolve mustache vars in URL (for URLs inside loops)
		rawURL = RenderMustache(rawURL, ctx.Data)
		if headers != "" {
			headers = RenderMustache(headers, ctx.Data)
		}
		rawURL = InterpolateEnv(rawURL, app.Dir)
		if headers != "" {
			headers = InterpolateEnv(headers, app.Dir)
		}

		// Store the inner template for the async endpoint to use
		templateHash := fmt.Sprintf("%x", sha256.Sum256([]byte(inner)))[:12]
		fetchTemplateStore.Lock()
		fetchTemplateStore.templates[templateHash] = inner
		fetchTemplateStore.Unlock()

		// Build the internal fetch URL
		params := url.Values{
			"url": {rawURL},
			"as":  {as},
			"t":   {templateHash},
		}
		if cache != "" {
			params.Set("cache", cache)
		}
		if headers != "" {
			params.Set("headers", headers)
		}
		internalURL := "/_internal/fetch?" + params.Encode()

		// Determine loading state
		if loading == "" {
			loading = "skeleton"
		}

		var placeholder string
		switch loading {
		case "none":
			placeholder = ""
		case "spinner":
			placeholder = `<div style="display:flex;justify-content:center;padding:2rem;"><div style="width:24px;height:24px;border:2px solid var(--border);border-top-color:var(--primary);border-radius:50%;animation:spin 0.6s linear infinite;"></div></div><style>@keyframes spin{to{transform:rotate(360deg)}}</style>`
		default: // "skeleton"
			placeholder = `<div style="padding:0.5rem 0;"><div style="height:2rem;background:var(--surface-hov);border-radius:var(--radius-sm);animation:pulse 1.5s ease-in-out infinite;margin-bottom:0.5rem;width:60%;"></div><div style="height:1.5rem;background:var(--surface-hov);border-radius:var(--radius-sm);animation:pulse 1.5s ease-in-out infinite;width:40%;"></div></div><style>@keyframes pulse{0%,100%{opacity:1}50%{opacity:0.4}}</style>`
		}

		// Return a div that HTMX will load async on page render.
		// delay:50ms prevents blocking initial page paint.
		// hx-indicator keeps the skeleton visible during load.
		return fmt.Sprintf(`<div hx-get="%s" hx-trigger="load delay:50ms" hx-swap="innerHTML">%s</div>`,
			internalURL, placeholder)
	})
}
