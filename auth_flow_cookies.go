//go:build !cli

package main

// Short-lived cookies that carry a half-finished sign-in: the OAuth state,
// PKCE verifier and nonce, the OTP and MFA steps, and the MFA-setup token.
//
// They follow the session cookie's naming rule (auth_sessions.go). Over HTTPS
// the name carries the __Host- prefix, so a browser keeps the cookie only
// host-only, Secure and on Path=/: a sibling subdomain (another tenant on the
// same parent domain) cannot plant its own value with a Domain attribute. An
// attacker knows the state and verifier of an OAuth flow it started, and holds
// valid signed OTP / MFA / setup cookies for an account it owns, so a planted
// cookie would let it finish the victim's sign-in as the attacker.

import "net/http"

// Base names of the flow cookies.
const (
	flowCookieOAuthState = "_oauth_state"
	flowCookieOAuthPKCE  = "_oauth_pkce"
	flowCookieOAuthNonce = "_oauth_nonce"
	flowCookieOTP        = "_benmore_otp_uid"
	flowCookieMFA        = "_benmore_mfa_uid"
	flowCookieMFACLI     = "_benmore_mfa_cli"
	flowCookieMFASetup   = "_benmore_mfa_setup"
)

// flowCookieName is the cookie name for a Secure flag.
func flowCookieName(base string, secure bool) string {
	if secure {
		return "__Host-" + base
	}
	return base
}

// setFlowCookie writes a flow cookie: HttpOnly, SameSite=Lax, Path=/, no
// Domain (a __Host- cookie may carry none).
func setFlowCookie(w http.ResponseWriter, base, value string, secure bool, maxAge int) {
	http.SetCookie(w, &http.Cookie{
		Name: flowCookieName(base, secure), Value: value,
		Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode, MaxAge: maxAge,
	})
}

// requestFlowCookie returns the flow cookie a request carries. The unprefixed
// name counts only on a plain-HTTP request: over HTTPS it is exactly what a
// sibling subdomain could plant.
func requestFlowCookie(r *http.Request, base string) (*http.Cookie, error) {
	if c, err := r.Cookie("__Host-" + base); err == nil && c.Value != "" {
		return c, nil
	}
	if protoOf(r) != "https" {
		return r.Cookie(base)
	}
	return nil, http.ErrNoCookie
}

// clearFlowCookie expires a flow cookie under both names. The prefixed name is
// expired with Secure and Path=/, which browsers require of a __Host- cookie.
func clearFlowCookie(w http.ResponseWriter, base string) {
	http.SetCookie(w, &http.Cookie{Name: "__Host-" + base, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: base, Value: "", Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}
