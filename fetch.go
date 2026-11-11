//go:build !cli

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
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
	size      int
}

// The cache key includes request-derived URL text (a `{{query.q}}` in the
// fetch URL), so visitors can mint entries of up to 1 MiB each, and expired
// entries were never removed. Bound both the entry count and the retained
// bytes; over budget, expired entries go first, then those closest to expiry.
const (
	fetchCacheMaxEntries = 512
	fetchCacheMaxBytes   = 32 << 20
)

func fetchCacheStore(key string, data any, size int, ttl time.Duration) {
	if size > fetchCacheMaxBytes/4 {
		return
	}
	fetchCache.Lock()
	defer fetchCache.Unlock()
	now := time.Now()
	delete(fetchCache.entries, key)
	total := size
	for k, e := range fetchCache.entries {
		if now.After(e.expiresAt) {
			delete(fetchCache.entries, k)
			continue
		}
		total += e.size
	}
	for len(fetchCache.entries) >= fetchCacheMaxEntries || total > fetchCacheMaxBytes {
		var soonestKey string
		var soonest time.Time
		for k, e := range fetchCache.entries {
			if soonestKey == "" || e.expiresAt.Before(soonest) {
				soonestKey, soonest = k, e.expiresAt
			}
		}
		if soonestKey == "" {
			break
		}
		total -= fetchCache.entries[soonestKey].size
		delete(fetchCache.entries, soonestKey)
	}
	fetchCache.entries[key] = &cacheEntry{data: data, expiresAt: now.Add(ttl), size: size}
}

// ExpandFetchTags processes <fetch url="..." as="data" cache="1h"> tags.
func ExpandFetchTags(content string, app *App, ctx *RenderContext) string {
	return expandFetchTagsWithClient(content, app, ctx, fetchHTTPClient(3*time.Second))
}

func expandFetchTagsWithClient(content string, app *App, ctx *RenderContext, client *http.Client) string {
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

		// No env pass here: RenderTemplate already resolved the author's
		// {{env.X}} before any data was rendered, and running it now would
		// expand an env placeholder inside a rendered row value.

		// SSRF protection: block private IPs
		var err error
		rawURL, _, err = resolveFetchURL(app, rawURL)
		if err != nil {
			return renderFetchError(app, err.Error())
		}
		if headers != "" || ctx.User != nil || ctx.Request != nil && (ctx.Request.Header.Get("Cookie") != "" || ctx.Request.Header.Get("Authorization") != "") {
			cacheDuration = 0
		}

		// Check cache
		cacheKey := fetchCacheKey(app, rawURL)
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
		req, err := http.NewRequest("GET", rawURL, nil)
		if err != nil {
			return renderFetchError(app, fmt.Sprintf("fetch: %s", err))
		}
		req.Header.Set("Accept", "application/json")
		req.Header.Set("User-Agent", "Benmore/1.0")

		setFetchHeaders(req, headers)

		resp, err := client.Do(req)
		if err != nil {
			log.Printf("FETCH request failed")
			// On timeout, render inner with empty data instead of blocking the page
			if inner != "" && as != "" {
				return RenderMustache(inner, ctx.Data)
			}
			return renderFetchError(app, "fetch request failed")
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20)) // 1MB max
		if err != nil {
			return renderFetchError(app, fmt.Sprintf("fetch read: %s", err))
		}

		if resp.StatusCode >= 400 {
			log.Printf("FETCH error: HTTP %d", resp.StatusCode)
			return renderFetchError(app, fmt.Sprintf("fetch: HTTP %d", resp.StatusCode))
		}

		// Parse JSON response
		var data any
		if err := json.Unmarshal(body, &data); err != nil {
			// Not JSON - treat as string
			data = string(body)
		}

		// Cache only public responses without caller credentials.
		if cacheDuration > 0 && cacheableFetchResponse(resp) {
			fetchCacheStore(cacheKey, data, len(body), cacheDuration)
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
	return outboundURLCheck(rawURL) != nil
}

// isPrivateURLContext is isPrivateURL bounded by ctx (the DNS lookup stops
// when ctx ends), for delivery paths that hold a deadline.
func isPrivateURLContext(ctx context.Context, rawURL string) bool {
	return outboundURLCheckContext(ctx, rawURL) != nil
}

// The two reasons outboundURLCheck refuses a URL. Both mean "not proved
// public"; they differ only in what a message may tell the author.
var (
	errOutboundPrivate    = errors.New("the URL is not http(s), or names a private, loopback or reserved address")
	errOutboundUnresolved = errors.New("the host could not be resolved")
)

// outboundLookupIP resolves a host for outboundURLCheck; tests replace it to
// answer without DNS.
var outboundLookupIP = func(ctx context.Context, host string) ([]net.IP, error) {
	return net.DefaultResolver.LookupIP(ctx, "ip", host)
}

// outboundURLCheck is isPrivateURL with the reason: nil only when the URL is
// http(s) and every address its host resolves to is public;
// errOutboundUnresolved when the host has no address to judge (the lookup
// failed or found none); errOutboundPrivate for everything else. A host that
// is an address literal in any spelling a resolver reads (literalOutboundIP:
// `127.1`, `0x7f000001`, an IPv6 address with a zone) is judged without DNS,
// so a private one is reported as private.
func outboundURLCheck(rawURL string) error {
	return outboundURLCheckContext(context.Background(), rawURL)
}

// outboundURLCheckContext is outboundURLCheck with the DNS lookup bounded
// by ctx.
func outboundURLCheckContext(ctx context.Context, rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return errOutboundPrivate // block on parse error
	}

	// Only HTTP(S) is safe to fan out to. Block file://, gopher://, ftp://,
	// dict://, ldap://, etc. - they have curl/Go-quirk SSRF histories.
	scheme := strings.ToLower(u.Scheme)
	if scheme != "http" && scheme != "https" {
		return errOutboundPrivate
	}

	host := u.Hostname()

	// Block obvious internal hostnames
	if host == "" || host == "localhost" || host == "127.0.0.1" || host == "0.0.0.0" || host == "::1" {
		return errOutboundPrivate
	}
	if strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
		return errOutboundPrivate
	}
	if ip := literalOutboundIP(host); ip != nil && blockedOutboundIP(ip) {
		return errOutboundPrivate
	}

	// Resolve and check IP ranges.
	ips, err := outboundLookupIP(ctx, host)
	if err != nil || len(ips) == 0 {
		return errOutboundUnresolved // fail CLOSED - can't prove the URL is public
	}

	for _, ip := range ips {
		if blockedOutboundIP(ip) {
			return errOutboundPrivate
		}
	}

	return nil
}

// literalOutboundIP returns the address a host names when it is an address
// literal: an IPv4 or IPv6 address (an IPv6 zone such as `fe80::1%eth0` is
// dropped), or a numeric IPv4 form inet_aton(3) reads (parseInetAtonIPv4).
// nil for a host name. Write-time checks use it to judge a literal host
// without DNS as the resolver and the dial-time check would.
func literalOutboundIP(host string) net.IP {
	host = strings.TrimSuffix(host, ".")
	if addr, err := netip.ParseAddr(host); err == nil {
		return net.IP(addr.WithZone("").AsSlice())
	}
	return parseInetAtonIPv4(host)
}

// parseInetAtonIPv4 reads host the way inet_aton(3) (and glibc's resolver,
// curl and browsers' URL parsers) reads a numeric IPv4 host: one to four
// dot-separated parts, each decimal, octal (a leading 0) or hex (0x), the
// last part filling the remaining bytes. `127.1`, `0x7f000001`,
// `2130706433` and `0177.0.0.1` are all 127.0.0.1. A trailing dot is
// allowed. nil when host is not such a literal.
func parseInetAtonIPv4(host string) net.IP {
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return nil
	}
	parts := strings.Split(host, ".")
	if len(parts) > 4 {
		return nil
	}
	values := make([]uint64, len(parts))
	for i, part := range parts {
		base, digits := 10, part
		switch {
		case len(part) >= 2 && (part[:2] == "0x" || part[:2] == "0X"):
			base, digits = 16, part[2:]
		case len(part) >= 2 && part[0] == '0':
			base, digits = 8, part[1:]
		}
		if digits == "" || strings.ContainsAny(digits, "+-_") {
			return nil
		}
		v, err := strconv.ParseUint(digits, base, 32)
		if err != nil {
			return nil
		}
		values[i] = v
	}
	last := len(values) - 1
	for _, v := range values[:last] {
		if v > 0xff {
			return nil
		}
	}
	if values[last] >= 1<<(8*(4-last)) {
		return nil
	}
	n := values[last]
	for i, v := range values[:last] {
		n |= v << (8 * (3 - i))
	}
	return net.IPv4(byte(n>>24), byte(n>>16), byte(n>>8), byte(n))
}

// blockedOutboundIP is the one address policy for server-side outbound HTTP,
// shared by the isPrivateURL name check and the dial-time guard in
// safeHTTPClientStrict so the two cannot drift apart.
func blockedOutboundIP(ip net.IP) bool {
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() ||
		ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() ||
		isExtraReservedIP(ip)
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
			if isPrivateURLContext(req.Context(), req.URL.String()) {
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
// Every strict client shares one Transport (strictOutboundTransport), so
// keep-alive connections are reused and idle ones close after
// IdleConnTimeout. A Transport per call left every idle connection (one fd
// and two goroutines) open until the remote closed it, and reused none.
//
// A redirect that leaves the original origin keeps only a few harmless
// headers (strictRedirectPolicy): net/http drops Authorization and Cookie on
// its own, but not an author's X-Api-Key or a signer's headers.
func safeHTTPClientStrict(timeout time.Duration) *http.Client {
	c := safeHTTPClient(timeout)
	base := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if err := base(req, via); err != nil {
			return err
		}
		return strictRedirectPolicy(req, via)
	}
	c.Transport = strictOutboundTransport
	return c
}

// strictOutboundTransport is the one Transport behind safeHTTPClientStrict.
// Proxy is nil on purpose: through an environment proxy the dial-time check
// would see the proxy's address instead of the target's and approve every
// target. Per-request limits come from http.Client.Timeout and the request
// context; the transport's own limits are fixed.
var strictOutboundTransport = &http.Transport{
	Proxy: nil,
	DialContext: (&net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		Control:   strictOutboundDialControl,
	}).DialContext,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: time.Second,
	IdleConnTimeout:       60 * time.Second,
	MaxIdleConns:          256,
	MaxIdleConnsPerHost:   8,
}

// strictOutboundDialControl refuses a connection whose resolved address is
// private, loopback or reserved.
func strictOutboundDialControl(network, address string, c syscall.RawConn) error {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("dial: bad address %q", address)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return fmt.Errorf("dial: unresolved address %q", host)
	}
	if blockedOutboundIP(ip) {
		return fmt.Errorf("dial to private/reserved IP blocked: %s", ip)
	}
	return nil
}

// strictRedirectHeaders are the request headers a cross-origin redirect
// keeps. Everything else - an author's api headers, signer output
// (X-Api-Key, signatures, AWS sigv4 headers), Referer (which can carry a
// query-string key) - stays with the origin it was written for.
var strictRedirectHeaders = map[string]bool{
	"Accept":          true,
	"Accept-Language": true,
	"User-Agent":      true,
}

// strictRedirectPolicy runs after net/http has copied the original
// request's headers onto the redirect. On the original origin nothing
// changes. On another origin a body-carrying redirect (307/308 of a POST)
// is refused, because the body may hold credentials too, and the headers
// are cut down to strictRedirectHeaders.
func strictRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) == 0 || sameRedirectOrigin(via[0].URL, req.URL) {
		return nil
	}
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return fmt.Errorf("cross-origin redirect of a %s request blocked", req.Method)
	}
	for k := range req.Header {
		if !strictRedirectHeaders[http.CanonicalHeaderKey(k)] {
			delete(req.Header, k)
		}
	}
	return nil
}

// sameRedirectOrigin reports whether next stays on from's origin. An upgrade
// from http to https on the same host with default ports counts as the same
// origin (the headers already crossed the wire in clear).
func sameRedirectOrigin(from, next *url.URL) bool {
	if from == nil || next == nil || !strings.EqualFold(from.Hostname(), next.Hostname()) {
		return false
	}
	if strings.EqualFold(from.Scheme, next.Scheme) {
		return redirectPort(from) == redirectPort(next)
	}
	return strings.EqualFold(from.Scheme, "http") && strings.EqualFold(next.Scheme, "https") &&
		redirectPort(from) == "80" && redirectPort(next) == "443"
}

func redirectPort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "https":
		return "443"
	case "http":
		return "80"
	}
	return ""
}

// isExtraReservedIP covers ranges that Go's stdlib doesn't flag as
// Private/Loopback/LinkLocal but which still must not be reachable from
// our outbound HTTP. CGN (100.64/10) and benchmark (198.18/15) commonly
// route to internal infrastructure on cloud providers; IANA's "future
// use" 240/4 should never be live. 0.0.0.0/8 and IPv6 site-local fec0::/10
// address "this host/network" or internal sites, never a public server.
func isExtraReservedIP(ip net.IP) bool {
	if v4 := ip.To4(); v4 != nil {
		// 0.0.0.0/8 - "this network" (RFC 1122); stdlib flags only 0.0.0.0
		if v4[0] == 0 {
			return true
		}
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
		return false
	}
	// NAT64 (RFC 6052 well-known prefix 64:ff9b::/96): where the network
	// provides NAT64, the gateway forwards to the embedded IPv4 address, so
	// 64:ff9b::a9fe:a9fe reaches 169.254.169.254. Judge the embedded address.
	// The local-use prefix 64:ff9b:1::/48 (RFC 8215) is operator-assigned and
	// treated as private outright.
	if ip16 := ip.To16(); ip16 != nil {
		// fec0::/10 - deprecated IPv6 site-local (RFC 3879), still routed internally
		if ip16[0] == 0xfe && ip16[1]&0xc0 == 0xc0 {
			return true
		}
		if bytes.Equal(ip16[:12], nat64WellKnownPrefix) {
			return blockedOutboundIP(net.IP(ip16[12:16]))
		}
		if bytes.Equal(ip16[:6], nat64LocalUsePrefix) {
			return true
		}
	}
	return false
}

var (
	nat64WellKnownPrefix = []byte{0, 0x64, 0xff, 0x9b, 0, 0, 0, 0, 0, 0, 0, 0}
	nat64LocalUsePrefix  = []byte{0, 0x64, 0xff, 0x9b, 0, 1}
)

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
