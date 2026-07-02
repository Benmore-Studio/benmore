//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"
)

var fetchTagRe = regexp.MustCompile(`(?s)<fetch\s+([^>]*)>(.*?)</fetch>`)

// FetchCache caches external API responses in memory with TTL.
var fetchCache = struct {
	sync.RWMutex
	entries map[string]*cacheEntry
}{entries: make(map[string]*cacheEntry)}

type cacheEntry struct {
	data      any
	expiresAt time.Time
}

// ExpandFetchTags processes <fetch url="..." as="data" cache="1h"> tags.
func ExpandFetchTags(content string, app *App, ctx *RenderContext) string {
	return fetchTagRe.ReplaceAllStringFunc(content, func(match string) string {
		m := fetchTagRe.FindStringSubmatch(match)
		if m == nil {
			return match
		}

		attrs := parseAttrs(m[1])
		inner := m[2]

		rawURL := attrs["url"]
		as := attrs["as"]
		cacheDuration := parseDuration(attrs["cache"])
		headers := attrs["headers"]

		if rawURL == "" {
			return renderFetchError(app, "fetch: url attribute required")
		}

		// Interpolate mustache vars from context data (for URLs inside query loops)
		rawURL = RenderMustache(rawURL, ctx.Data)
		if headers != "" {
			headers = RenderMustache(headers, ctx.Data)
		}

		// Interpolate env vars in URL and headers
		rawURL = InterpolateEnv(rawURL, app.Dir)
		if headers != "" {
			headers = InterpolateEnv(headers, app.Dir)
		}

		// SSRF protection: block private IPs
		if isPrivateURL(rawURL) {
			return renderFetchError(app, "fetch: cannot request private/internal URLs")
		}

		// Check cache
		cacheKey := rawURL
		if cacheDuration > 0 {
			fetchCache.RLock()
			entry, ok := fetchCache.entries[cacheKey]
			fetchCache.RUnlock()
			if ok && time.Now().Before(entry.expiresAt) {
				if as != "" {
					ctx.Data[as] = entry.data
				}
				return renderFetchInner(inner, entry.data, as, ctx)
			}
		}

		// Make HTTP request (3s timeout to prevent page hangs)
		client := safeHTTPClientStrict(3 * time.Second)
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			return renderFetchError(app, fmt.Sprintf("fetch: %s", err))
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "Benmore/1.0")

		// Parse custom headers: "Authorization: Bearer xxx, X-Api-Key: yyy"
		if headers != "" {
			for _, h := range strings.Split(headers, ",") {
				parts := strings.SplitN(strings.TrimSpace(h), ":", 2)
				if len(parts) == 2 {
					req.Header.Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
				}
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("FETCH timeout/error: %s → %s", rawURL, err)
			// On timeout, render inner with empty data instead of blocking the page
			if inner != "" && as != "" {
				return RenderMustache(inner, ctx.Data)
			}
			return renderFetchError(app, fmt.Sprintf("fetch %s: %s", rawURL, err))
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
		if err != nil {
			return renderFetchError(app, fmt.Sprintf("fetch read: %s", err))
		}

		if resp.StatusCode >= 400 {
			log.Printf("FETCH error: %s → HTTP %d", rawURL, resp.StatusCode)
			return renderFetchError(app, fmt.Sprintf("fetch %s: HTTP %d", rawURL, resp.StatusCode))
		}

		// Parse JSON response
		var data any
		if err := json.Unmarshal(body, &data); err != nil {
			// Not JSON - treat as string
			data = string(body)
		}

		// Cache the response
		if cacheDuration > 0 {
			fetchCache.Lock()
			fetchCache.entries[cacheKey] = &cacheEntry{data: data, expiresAt: time.Now().Add(cacheDuration)}
			fetchCache.Unlock()
		}

		// Store in context
		if as != "" {
			ctx.Data[as] = data
		}

		return renderFetchInner(inner, data, as, ctx)
	})
}

func renderFetchInner(inner string, data any, as string, ctx *RenderContext) string {
	if inner == "" || as == "" {
		return ""
	}

	// Make data available under the "as" name
	merged := make(map[string]any)
	for k, v := range ctx.Data {
		merged[k] = v
	}

	switch d := data.(type) {
	case map[string]any:
		merged[as] = d
		// Also flatten top-level keys for easier access
		for k, v := range d {
			merged[as+"."+k] = v
		}
	case []any:
		// Convert to []map[string]any if possible
		var rows []map[string]any
		for _, item := range d {
			if m, ok := item.(map[string]any); ok {
				rows = append(rows, m)
			}
		}
		if len(rows) > 0 {
			merged[as] = rows
		} else {
			merged[as] = d
		}
	default:
		merged[as] = d
	}

	return RenderMustache(inner, merged)
}

func renderFetchError(app *App, msg string) string {
	if app != nil && !app.DevMode {
		log.Printf("FETCH ERROR: %s", msg)
		return `<div class="benmore-error">Failed to load external data.</div>`
	}
	return fmt.Sprintf(`<div class="benmore-error">%s</div>`, html.EscapeString(msg))
}

// isPrivateURL checks if a URL points to a private/internal IP (SSRF protection).
// Fails CLOSED on any ambiguity (parse error, DNS lookup failure, unknown scheme):
// the caller must be able to assume that "false" means we proved the URL is public.
func isPrivateURL(rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil {
		return true // block on parse error
	}

	// Only HTTP(S) is safe to fan out to. Block file://, gopher://, ftp://,
	// dict://, ldap://, etc. - they have curl/Go-quirk SSRF histories.
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return true
	}

	host := u.Hostname()

	// Block obvious internal hostnames
	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "0.0.0.0" || host == "::1" {
		return true
	}
	if strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return true
	}

	// Resolve and check IP ranges.
	ips, err := net.LookupIP(host)
	if err != nil {
		return true // fail CLOSED - can't prove the URL is public
	}
	if len(ips) == 0 {
		return true
	}

	for _, ip := range ips {
		if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return true
		}
		if ip.IsMulticast() || ip.IsUnspecified() {
			return true
		}
		if isExtraReservedIP(ip) {
			return true
		}
	}

	return false
}

// safeHTTPClient builds an http.Client that re-runs isPrivateURL on
// every redirect target. Without this, an attacker who controls a
// public URL can return 302 → http://127.0.0.1:6379 and bypass our
// up-front SSRF gate. Callers that hand-roll an http.Client lose this
// protection - when adding a new outbound surface, use this helper.
func safeHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return http.ErrUseLastResponse
			}
			if isPrivateURL(req.URL.String()) {
				return fmt.Errorf("redirect to private URL blocked: %s", req.URL.Host)
			}
			return nil
		},
	}
}

// safeHTTPClientStrict is safeHTTPClient PLUS a DialContext.Control that
// validates the ACTUAL resolved IP at connect time - closing the
// DNS-rebinding TOCTOU on attacker-controlled outbound URLs (flow `run: api`,
// `<fetch>`, webhook delivery). isPrivateURL resolves the host once up front,
// but the real dial re-resolves independently, so a hostile DNS can answer
// public for the check and private (e.g. 169.254.169.254 IMDS) for the
// connection. Checking the post-resolution dial address defeats that at the
// Go layer, for every caller - including the router, which is NOT under the
// per-app systemd IPAddressDeny. Defense-in-depth on top of the OS egress
// firewall.
//
// NOT used by the signer token-exchange (safeHTTPClient): those URLs are
// developer-authored and legitimately target internal/on-prem OAuth servers
// on RFC1918 - see doRecipeBeforeRequest.
func safeHTTPClientStrict(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Control: func(network, address string, c syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return fmt.Errorf("dial: bad address %q", address)
			}
			ip := net.ParseIP(host)
			if ip == nil {
				return fmt.Errorf("dial: unresolved address %q", host)
			}
			if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
				ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
				isExtraReservedIP(ip) {
				return fmt.Errorf("dial to private/reserved IP blocked: %s", ip)
			}
			return nil
		},
	}
	c := safeHTTPClient(timeout)
	c.Transport = &http.Transport{
		DialContext:           dialer.DialContext,
		TLSHandshakeTimeout:   timeout,
		ResponseHeaderTimeout: timeout,
		Proxy:                 http.ProxyFromEnvironment,
	}
	return c
}

// isExtraReservedIP covers ranges that Go's stdlib doesn't flag as
// Private/Loopback/LinkLocal but which still must not be reachable from
// our outbound HTTP. CGN (100.64/10) and benchmark (198.18/15) commonly
// route to internal infrastructure on cloud providers; IANA's "future
// use" 240/4 should never be live.
func isExtraReservedIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		// 100.64.0.0/10 - Carrier-Grade NAT (RFC 6598)
		if v4[0] == 100 && (v4[1]&0xC0) == 64 {
			return true
		}
		// 198.18.0.0/15 - benchmark testing (RFC 2544)
		if v4[0] == 198 && (v4[1] == 18 || v4[1] == 19) {
			return true
		}
		// 240.0.0.0/4 - reserved for future use (RFC 1112)
		if v4[0] >= 240 {
			return true
		}
	}
	return false
}

func parseDuration(s string) time.Duration {
	if s == "" {
		return 0
	}
	s = strings.TrimSpace(s)

	// Support: "1h", "30m", "5m", "1d"
	if strings.HasSuffix(s, "d") {
		s = strings.TrimSuffix(s, "d")
		var n int
		fmt.Sscanf(s, "%d", &n)
		return time.Duration(n) * 24 * time.Hour
	}

	d, err := time.ParseDuration(s)
	if err != nil {
		return 0
	}
	return d
}
