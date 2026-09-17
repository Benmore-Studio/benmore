//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// RegisterFetchRoutes accepts only descriptors emitted by the server's renderer.
func RegisterFetchRoutes(mux *http.ServeMux, app *App) {
	registerFetchRoutes(mux, app, fetchHTTPClient(2*time.Second))
}

func registerFetchRoutes(mux *http.ServeMux, app *App, client *http.Client) {
	mux.HandleFunc("GET /_internal/fetch", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		session := getSession(app, r)
		if isBearerAuth(r) && session == nil || !isBearerAuth(r) && !validateCSRF(r) {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		desc, err := openFetchDescriptor(app, r.URL.Query().Get("d"), session)
		if err != nil {
			// An already-open page may contain the previous release's raw URL,
			// or an expired descriptor. HTMX processes this header before its
			// error response handling, obtaining fresh server-authored markup.
			if r.Header.Get("HX-Request") == "true" {
				w.Header().Set("HX-Refresh", "true")
			}
			http.Error(w, "Invalid fetch descriptor", http.StatusForbidden)
			return
		}
		fetchURL, trustedLocal, err := resolveFetchURL(app, desc.URL)
		if err != nil {
			http.Error(w, "Blocked fetch URL", http.StatusForbidden)
			return
		}
		cacheDuration := parseDuration(desc.Cache)
		if session != nil || desc.Headers != "" || r.Header.Get("Cookie") != "" || r.Header.Get("Authorization") != "" {
			cacheDuration = 0
		}
		cacheKey := fetchCacheKey(app, fetchURL)
		if cacheDuration > 0 {
			fetchCache.RLock()
			entry, ok := fetchCache.entries[cacheKey]
			fetchCache.RUnlock()
			if ok && time.Now().Before(entry.expiresAt) {
				renderFetchResponse(w, entry.data, desc.As, desc.Inner)
				return
			}
		}
		req, err := http.NewRequestWithContext(r.Context(), "GET", fetchURL, nil)
		if err != nil {
			http.Error(w, "Request error", http.StatusBadGateway)
			return
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "Benmore/1.0")
		if trustedLocal {
			for _, cookie := range r.Cookies() {
				req.AddCookie(cookie)
			}
		}
		setFetchHeaders(req, desc.Headers)
		resp, err := client.Do(req)
		if err != nil {
			http.Error(w, "Failed to load data", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
		if err != nil || len(body) > 1<<20 || resp.StatusCode >= 400 {
			http.Error(w, "Data unavailable", http.StatusBadGateway)
			return
		}
		var data any
		if json.Unmarshal(body, &data) != nil {
			data = string(body)
		}
		if cacheDuration > 0 && cacheableFetchResponse(resp) {
			fetchCache.Lock()
			fetchCache.entries[cacheKey] = &cacheEntry{data: data, expiresAt: time.Now().Add(cacheDuration)}
			fetchCache.Unlock()
		}
		renderFetchResponse(w, data, desc.As, desc.Inner)
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

func renderFetchResponse(w http.ResponseWriter, data any, as, inner string) {
	if inner == "" {
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

		if _, _, err := resolveFetchURL(app, rawURL); err != nil {
			return renderFetchError(app, err.Error())
		}
		session := ctx.User
		if ctx.Request != nil {
			session = getSession(app, ctx.Request)
		}
		token, err := sealFetchDescriptor(app, fetchDescriptor{URL: rawURL, Headers: headers, As: as, Inner: inner, Cache: cache, Audience: sessionSecurityFingerprint(session), Expires: time.Now().Add(fetchDescriptorTTL).Unix()})
		if err != nil {
			return renderFetchError(app, "fetch: descriptor unavailable")
		}
		internalURL := "/_internal/fetch?d=" + url.QueryEscape(token)

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
