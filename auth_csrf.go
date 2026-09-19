//go:build !cli

package main

// CSRF token generation, validation, and browser-origin checks.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const csrfTokenName = "_csrf"

// generateCSRFToken creates a CSRF token derived from HMAC(secret, random_nonce + timestamp).
// No storage needed - validation recomputes the HMAC.
//
// This is the session-LESS variant kept for backward compatibility:
// pre-authentication pages (login / signup), the auto-injected <meta>
// tag rendered before a session exists, and every existing caller that
// has no *http.Request in scope still mint an unbound token here. Such
// tokens validate for any request (see authCSRFSign with sid="").
func generateCSRFToken() string {
	return authMintCSRFToken("")
}

// authMintCSRFToken mints a CSRF token, optionally bound to a session id.
// H-11: when sid != "" the session id is folded into the HMAC input (but
// NOT into the visible payload, so the wire format stays the legacy
// 3-part "nonce|ts|sig" and every existing parser/length check keeps
// working). A session-bound token only validates for requests carrying
// that same session (validateCSRF re-derives with the live session id),
// so a token minted for one user can no longer be replayed by another -
// the /api/_csrf endpoint is unauthenticated, so without binding one
// fetched token authenticated every user's mutations.
func authMintCSRFToken(sid string) string {
	return authMintCSRFTokenWithSecret(sid, serverSecret)
}

func authMintCSRFTokenWithSecret(sid, secret string) string {
	nonce := generateToken(16)
	ts := fmt.Sprintf("%d", time.Now().Unix())
	payload := nonce + "|" + ts
	sig := authCSRFSignWithSecret(payload, sid, secret)
	return payload + "|" + sig
}

// authCSRFSign computes the HMAC over the token payload, binding it to a
// session id when provided. sid=="" reproduces the legacy unbound MAC so
// session-less tokens (and tokens minted before a session existed) stay
// valid - that's the back-compat path validateCSRF falls back to.
func authCSRFSign(payload, sid string) string {
	return authCSRFSignWithSecret(payload, sid, serverSecret)
}

func authCSRFSignWithSecret(payload, sid, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	if sid != "" {
		// Domain-separate the session component so a "|"-bearing payload
		// can't be confused with the binding boundary.
		mac.Write([]byte("\x00sid\x00"))
		mac.Write([]byte(sid))
	}
	return hex.EncodeToString(mac.Sum(nil))
}

// authRawSessionID returns the raw session id the request is authenticating
// with (cookie first, then a non-prefixed Bearer session token), or "" when
// the request carries no session. Used to bind/validate CSRF tokens against
// the originating session. Persistent API tokens (bmr_ prefix) are exempt -
// those callers go through the isBearerAuth CSRF exemption anyway.
func authRawSessionID(r *http.Request) string {
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		return c.Value
	}
	if auth := r.Header.Get("Authorization"); strings.HasPrefix(auth, "Bearer ") {
		tok := strings.TrimPrefix(auth, "Bearer ")
		if !isPersistentAPIToken(tok) {
			return tok
		}
	}
	return ""
}

// isBearerAuth returns true if the request is authenticated by a Bearer
// token ONLY. Bearer-authenticated requests don't need CSRF protection
// since there's no cookie to ride on cross-site.
//
// A request that carries a session cookie does NOT qualify even when an
// Authorization header is also present (M1, 2026-06-11 audit): getSession
// prefers the cookie, so such a request is cookie-authenticated - and the
// old prefix-only check meant any attacker who could coax the browser into
// adding `Authorization: Bearer junk` (e.g. via fetch on an app with a
// CORS allowlist) skipped CSRF while still riding the victim's cookie.
// CLI / MCP / SDK clients never hold the session cookie, so they keep the
// exemption. The rare client that holds a stale cookie alongside a valid
// Bearer token must clear the cookie (or pass CSRF) - failing closed is
// the right default for an auth gate.
func isBearerAuth(r *http.Request) bool {
	if !strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ") {
		return false
	}
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		return false
	}
	return true
}

// isSameOriginRequest returns true if the request's Origin header is
// absent OR matches r.Host. Used to gate cookie-credentialed long-lived
// channels (WebSocket / SSE) - browsers DO send Origin on those, but
// don't preflight, so without a server-side check an attacker page can
// open a WS/EventSource to our origin, the browser attaches our session
// cookie, and the attacker tab receives whatever we broadcast.
//
// Same-origin requests in the wild either omit Origin or send the
// page's origin. Cross-origin browser requests always send Origin set
// to the *attacker* page. Bearer-auth (CLI / native) sends no Origin
// and no cookies, so the no-Origin path stays open for those clients.
func isSameOriginRequest(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	// Compare host (incl. port) against the request's Host header.
	return strings.EqualFold(u.Host, r.Host)
}

// requireCSRF gates a mutation handler that accepts session-cookie auth.
// Bearer-authenticated requests (CLI / MCP / SDK) are exempt - there's no
// cookie to ride on for cross-origin abuse. Returns true when the handler
// should proceed; on false the caller must return immediately (response
// has already been written).
func requireCSRF(w http.ResponseWriter, r *http.Request) bool {
	if isBearerAuth(r) {
		return true
	}
	if validateCSRF(r) {
		return true
	}
	// Log enough to debug the two common causes without leaking the
	// token: header-presence, length, and the request shape. A page
	// served before BENMORE_SERVER_SECRET was set will fail here
	// because its HMAC was signed with a since-replaced ephemeral
	// secret - that case looks like "header present, valid length".
	hdr := r.Header.Get("X-CSRF-Token")
	formHas := r.FormValue(csrfTokenName) != ""
	log.Printf("requireCSRF: REJECT method=%s path=%s header_present=%t header_len=%d form_present=%t referer=%q",
		r.Method, r.URL.Path, hdr != "", len(hdr), formHas, r.Header.Get("Referer"))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusForbidden)
	w.Write([]byte(`{"error":"invalid csrf token"}`))
	return false
}

// validateCSRF verifies a CSRF token's HMAC and checks it's not expired (24h).
func validateCSRF(r *http.Request) bool {
	reason, ok := validateCSRFReason(r)
	if !ok {
		log.Printf("validateCSRF: REJECT path=%s reason=%s ua=%q", r.URL.Path, reason, r.UserAgent())
	}
	return ok
}

// validateCSRFReason is the implementation; surfaces WHY the token was
// rejected so operators can debug stale-token-after-redeploy issues
// (the most common false-positive on this code path).
func validateCSRFReason(r *http.Request) (string, bool) {
	token := r.FormValue(csrfTokenName)
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	if token == "" {
		return "missing", false
	}

	parts := strings.SplitN(token, "|", 3)
	if len(parts) != 3 {
		return "malformed", false
	}

	nonce, tsStr, providedSig := parts[0], parts[1], parts[2]

	// CSRF origin gate (round-2 #2). The session cookie is SameSite=Lax so a
	// cross-site POST/fetch won't even carry it; this is the second layer and
	// is what actually stops a forged request - the HMAC token below is
	// defense-in-depth. A cross-site request must NOT be able to reach the HMAC
	// check (which would otherwise accept a session-less/unbound token lifted
	// from /api/_csrf or the page meta tag).
	//   - Origin present -> must match our Host.
	//   - Origin absent  -> consult Sec-Fetch-Site (sent by all modern
	//     browsers): reject cross-site / same-site. Earlier this treated a
	//     missing Origin as same-origin, which let a no-Origin cross-site POST
	//     through. A request with neither header (old/native client) still
	//     falls through to the token, preserving legitimate non-browser callers.
	if origin := r.Header.Get("Origin"); origin != "" {
		if u, err := url.Parse(origin); err != nil || !strings.EqualFold(u.Host, r.Host) {
			return "origin_mismatch", false
		}
	} else if sfs := r.Header.Get("Sec-Fetch-Site"); sfs == "cross-site" || sfs == "same-site" {
		return "sec_fetch_" + sfs, false
	}

	// Verify HMAC. H-11: prefer the session-bound MAC (token tied to the
	// request's originating session id) and fall back to the legacy
	// unbound MAC so tokens minted before a session existed (login/signup
	// pages, the pre-auth <meta> tag, and every session-less caller) keep
	// validating. A token bound to session A therefore can NOT be replayed
	// on session B - B's id won't reproduce A's signature, and the unbound
	// fallback won't match a bound signature either.
	payload := nonce + "|" + tsStr
	sid := authRawSessionID(r)
	boundSig := authCSRFSign(payload, sid)
	unboundSig := authCSRFSign(payload, "")
	if !hmac.Equal([]byte(providedSig), []byte(boundSig)) &&
		!hmac.Equal([]byte(providedSig), []byte(unboundSig)) {
		return "hmac_mismatch", false
	}

	// Check expiry (24 hours)
	var ts int64
	if _, err := fmt.Sscanf(tsStr, "%d", &ts); err != nil || ts == 0 {
		return "ts_unparseable", false
	}
	age := time.Now().Unix() - ts
	if age > 86400 {
		return fmt.Sprintf("expired_age=%ds", age), false
	}

	return "", true
}

// InjectCSRF adds a hidden CSRF field to all forms in HTML content.
func InjectCSRF(content string) string {
	token := generateCSRFToken()
	csrfField := fmt.Sprintf(`<input type="hidden" name="%s" value="%s">`, csrfTokenName, token)

	result := strings.Builder{}
	i := 0
	lower := strings.ToLower(content)
	for {
		idx := strings.Index(lower[i:], "<form")
		if idx < 0 {
			result.WriteString(content[i:])
			break
		}
		pos := i + idx
		closeIdx := strings.Index(content[pos:], ">")
		if closeIdx < 0 {
			result.WriteString(content[i:])
			break
		}
		endOfTag := pos + closeIdx + 1
		result.WriteString(content[i:endOfTag])
		result.WriteString(csrfField)
		i = endOfTag
	}
	return result.String()
}
