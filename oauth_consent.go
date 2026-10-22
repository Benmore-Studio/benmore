//go:build !cli

package main

// Shared OAuth consent step for both authorization servers: the platform's
// (MCP clients connecting to a benmore.ai account, oauth_provider.go) and
// every app's own (app_oauth.go). Dynamic client registration is open on
// both, so an authorization code must never be issued by a GET: any website
// could otherwise send a signed-in user to /oauth/authorize and receive a
// token for their account. GET renders this consent page; only a same-origin
// POST carrying a consent token bound to the signed-in subject and the exact
// request issues a code.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"
)

// oauthAuthorizeParams is the validated /oauth/authorize request, carried
// unchanged from the consent page (GET) to the approval (POST).
type oauthAuthorizeParams struct {
	ClientID, RedirectURI, State, Scope, CodeChallenge, CodeChallengeMethod, Resource string
	clientName, clientScopes                                                          string
}

// oauthConsentKey derives a purpose-specific key so a consent token can never
// verify as any other brokerSign token (OAuth broker state, GitHub or Stripe
// state) signed with the same server secret.
func oauthConsentKey() string {
	mac := hmac.New(sha256.New, []byte(serverSecret))
	mac.Write([]byte("benmore-oauth-consent-v1"))
	return hex.EncodeToString(mac.Sum(nil))
}

// oauthConsentDigest binds a consent token to the exact request it approves.
func oauthConsentDigest(email string, p oauthAuthorizeParams) string {
	h := sha256.New()
	for _, f := range []string{email, p.ClientID, p.RedirectURI, p.State, p.Scope, p.CodeChallenge, p.CodeChallengeMethod, p.Resource} {
		h.Write([]byte(f))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

const oauthConsentTTL = 10 * time.Minute

func mintOAuthConsent(email string, p oauthAuthorizeParams, now time.Time) string {
	payload, _ := json.Marshal(map[string]any{"p": "oauth-consent", "d": oauthConsentDigest(email, p), "exp": now.Add(oauthConsentTTL).Unix()})
	return brokerSign(payload, oauthConsentKey())
}

func verifyOAuthConsent(token, email string, p oauthAuthorizeParams, now time.Time) bool {
	raw, ok := brokerVerify(token, oauthConsentKey())
	if !ok {
		return false
	}
	var c struct {
		P   string `json:"p"`
		D   string `json:"d"`
		Exp int64  `json:"exp"`
	}
	if json.Unmarshal(raw, &c) != nil || c.P != "oauth-consent" || now.Unix() > c.Exp {
		return false
	}
	return hmac.Equal([]byte(c.D), []byte(oauthConsentDigest(email, p)))
}

// sameOriginPost rejects cross-site form posts. Browsers send Sec-Fetch-Site
// on every POST; fall back to Origin for older ones.
func sameOriginPost(r *http.Request) bool {
	switch r.Header.Get("Sec-Fetch-Site") {
	case "same-origin":
		return true
	case "":
	default:
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return false
	}
	u, err := url.Parse(origin)
	return err == nil && strings.EqualFold(u.Host, r.Host)
}

// oauthCSPSourceRe bounds what a redirect URI may contribute to the consent
// page's CSP: a scheme and an optional host[:port], nothing that could end the
// directive or add another source.
var oauthCSPSourceRe = regexp.MustCompile(`^[a-z][a-z0-9+.-]*:(//[a-z0-9.\-]+(:[0-9]{1,5})?|//\[[0-9a-f:.]+\](:[0-9]{1,5})?)?$`)

// oauthConsentFormAction is the consent page's form-action. Browsers apply
// form-action to the redirects that follow a submission, so the POST's 302 to
// the client's redirect_uri (code or access_denied) must be allowed too, or
// the browser silently blocks it and Approve appears to do nothing. The URI
// was already validated against the registered client.
func oauthConsentFormAction(redirectURI string) string {
	u, err := url.Parse(redirectURI)
	if err != nil || u.Scheme == "" {
		return "'self'"
	}
	src := strings.ToLower(u.Scheme) + ":"
	if u.Host != "" {
		src += "//" + strings.ToLower(u.Host)
	}
	if !oauthCSPSourceRe.MatchString(src) {
		return "'self'"
	}
	return "'self' " + src
}

// writeOAuthConsentPage renders the consent screen. It is frame-proof and
// posts back to /oauth/authorize with the request parameters in fields. The
// email sits between email_off markers: Cloudflare's email obfuscation would
// otherwise show "[email protected]" and rely on a decoder script this CSP
// blocks.
//
// extra is pre-escaped HTML placed inside the form above the buttons (the
// connector's auto-approve checkbox); callers without one pass "".
func writeOAuthConsentPage(w http.ResponseWriter, clientName, accountLabel, subject, redirectHost, scopeText string, fields map[string]string, extra string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action "+oauthConsentFormAction(fields["redirect_uri"])+"; frame-ancestors 'none'; base-uri 'none'")
	esc := html.EscapeString
	hidden := ""
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		hidden += `<input type="hidden" name="` + esc(k) + `" value="` + esc(fields[k]) + `">`
	}
	fmt.Fprintf(w, `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Authorize access</title>
<style>body{font-family:system-ui,sans-serif;background:#0a0a0a;color:#e4e4e7;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0;padding:16px}main{max-width:440px;width:100%%;background:#18181b;border:1px solid #27272a;border-radius:12px;padding:28px}h1{font-size:18px;margin:0 0 12px}p{line-height:1.5;color:#a1a1aa;margin:0 0 12px}strong{color:#fafafa}.host{font-family:ui-monospace,monospace;background:#27272a;padding:2px 6px;border-radius:4px;color:#fbbf24}.row{display:flex;gap:10px;margin-top:20px}button{flex:1;padding:10px;border-radius:8px;border:1px solid #3f3f46;font-weight:600;cursor:pointer;font-size:14px}.ok{background:#fafafa;color:#0a0a0a}.no{background:transparent;color:#e4e4e7}</style></head>
<body><main><h1>Allow <strong>%s</strong> to access your %s account?</h1>
<p>Signed in as <!--email_off--><strong>%s</strong><!--/email_off-->.</p>
<p>Approving sends an access key to <span class="host">%s</span>. It grants %s for up to 30 days, until you revoke it.</p>
<p>Only approve if you started this connection yourself from a tool you trust.</p>
<form method="post" action="/oauth/authorize">%s%s<div class="row"><button class="no" name="decision" value="deny">Deny</button><button class="ok" name="decision" value="approve">Approve</button></div></form></main></body></html>`,
		esc(clientName), esc(accountLabel), esc(subject), esc(redirectHost), esc(scopeText), hidden, extra)
}
