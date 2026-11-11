package main

// OAuth dynamic client registration limits (RFC 7591).
//
// POST /oauth/register is unauthenticated by design: an MCP client registers
// itself before anyone signs in. Every call stores a client row, so nothing
// but the app-wide request limiter bounded how fast one client could fill a
// database with them: up to 64 KiB a call on a connector app and 1 MiB with
// no field limits on the legacy app endpoint and the platform's own server.
//
//   - Per client address (an IPv6 client by its /64, clientRateBucket):
//     oauthRegisterRate registrations per oauthRegisterWindow, per
//     authorization server (one app, or the platform).
//   - Every registration path takes the connector endpoint's field limits:
//     a 64 KiB body, a client_name of at most 256 bytes of valid UTF-8, at
//     most 16 redirect URIs of at most 8192 bytes each, and a scope of at
//     most oauthRegisterMaxScope bytes.
//
// Registered clients are not swept: a client row is referenced by codes,
// grants and tokens in several tables, so "never used" has no single test.

import (
	"net/http"
	"time"
	"unicode/utf8"
)

const (
	oauthRegisterRate           = 20
	oauthRegisterWindow         = time.Hour
	oauthRegisterMaxBody        = 64 << 10
	oauthRegisterMaxName        = 256
	oauthRegisterMaxRedirects   = 16
	oauthRegisterMaxRedirectLen = 8192
	oauthRegisterMaxScope       = 4096
)

var oauthRegisterLimiter = NewRateLimiter(oauthRegisterRate, oauthRegisterWindow)

// oauthRegisterAllowed spends one registration from the client's budget at
// one authorization server (server names it: an app directory, or the
// platform). On refusal it has answered 429 with Retry-After.
func oauthRegisterAllowed(w http.ResponseWriter, r *http.Request, server string) bool {
	ok, retry, _ := oauthRegisterLimiter.Check("oauth-register:" + server + ":" + clientRateBucket(clientIP(r)))
	if ok {
		return true
	}
	setRetryAfter(w, retry)
	w.Header().Set("Cache-Control", "no-store")
	httpJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too_many_requests", "error_description": "too many client registrations; try again later"})
	return false
}

// oauthRegisterMetadataOK applies the field limits above. A missing name or
// redirect list fails too; each path keeps its own redirect URI rule.
func oauthRegisterMetadataOK(name string, redirects []string, scope string) bool {
	if name == "" || len(name) > oauthRegisterMaxName || !utf8.ValidString(name) ||
		len(redirects) == 0 || len(redirects) > oauthRegisterMaxRedirects || len(scope) > oauthRegisterMaxScope {
		return false
	}
	for _, redirect := range redirects {
		if len(redirect) > oauthRegisterMaxRedirectLen {
			return false
		}
	}
	return true
}
