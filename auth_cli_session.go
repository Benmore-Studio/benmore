//go:build !cli

package main

import (
	"html"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// cliStateRe is the shape of the login nonce the CLI generates (hex today;
// a wider alphabet is tolerated). Anything else is refused so the value can
// be reflected into redirects and cookies without escaping concerns.
var cliStateRe = regexp.MustCompile(`^[A-Za-z0-9_-]{16,128}$`)

// cliStatePOSTPrefix marks a login state from a CLI whose loopback callback
// accepts the token as a POSTed form. The platform then hands the token over
// in the body of an auto-submitting form instead of the callback URL's query,
// which the browser keeps in its history. The marker rides in the state
// because the state already travels, unchanged, through every sign-in path
// (the confirmation form, OAuth state, the MFA step); CLI builds from before
// this send a plain hex state and keep getting the redirect they understand.
const cliStatePOSTPrefix = "p_"

func cliStateAcceptsPOST(state string) bool {
	return strings.HasPrefix(state, cliStatePOSTPrefix)
}

// parseCLIPortState splits the "PORT" or "PORT~STATE" value the CLI login
// carries through OAuth state cookies and the MFA step. A missing state
// parses (ok, state "") so callers can tell "absent" from "malformed", but
// nothing mints a CLI token without one: the nonce is what ties the token to
// the login the person started (cliLoginCallbackHandler checks it), and
// without it a cross-site link could rotate the account's CLI token and hand
// the new one to any localhost port.
func parseCLIPortState(v string) (port, state string, ok bool) {
	port = v
	for i := 0; i < len(v); i++ {
		if v[i] == '~' {
			port, state = v[:i], v[i+1:]
			if !cliStateRe.MatchString(state) {
				return "", "", false
			}
			break
		}
	}
	return port, state, true
}

// validCLIPort reports a decimal TCP port, so the value is safe to reflect
// into the loopback callback URL (no host or path injection).
func validCLIPort(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n < 65536 && strconv.Itoa(n) == port
}

// cliLoginApp reports whether app is the platform dashboard, the only app
// whose sign-in proves a platform account and so the only one that may
// issue a platform CLI token. Mirrors the buildAppMux gate on
// /auth/cli-session: any other app's _benmore_users are app-local accounts
// (anyone can sign up there as anyone@example.com), and in single-process
// `benmore host` the platform database is reachable from every app.
func cliLoginApp(app *App) bool {
	return app != nil && app.Dir != "" && filepath.Base(app.Dir) == "_platform"
}

// oauthCLIPortAllowed reports whether a sign-in through provider name on app
// may finish a CLI login. Only the dashboard's built-in providers qualify:
// those verify the address themselves (oauthEmailVerified), whereas an
// app.yaml provider is whatever endpoint the app author configured, and its
// `trust_email` or `email_verified` claim is the author's word, not proof.
func oauthCLIPortAllowed(app *App, name string) bool {
	if !cliLoginApp(app) {
		return false
	}
	_, builtIn := oauthProviders[name]
	return builtIn
}

// cliSessionHandler serves /auth/cli-session on the platform dashboard app
// (_platform only; see buildAppMux). It turns an existing direct browser
// sign-in into a platform CLI token so "Continue as <you>" on /cli-auth needs
// no second Google/password round-trip.
//
// Minting replaces the account's current CLI token and sends the new one to
// a loopback port, so it is a state change that must be the person's own
// deliberate act: GET only renders a confirmation page, and the token is
// minted on that page's same-origin POST carrying a session-bound CSRF token.
// A cross-site link or a page on a sibling tenant subdomain (same-site, so
// the Lax session cookie rides along) can no longer rotate the token. The
// CLI's login nonce (state) is required on both legs.
func cliSessionHandler(app *App) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			r.Body = http.MaxBytesReader(w, r.Body, 16<<10)
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid request", http.StatusBadRequest)
				return
			}
		}
		var port, state string
		if r.Method == http.MethodPost {
			port, state = r.PostForm.Get("port"), r.PostForm.Get("state")
		} else {
			port, state = r.URL.Query().Get("port"), r.URL.Query().Get("state")
		}
		// Validate both up front so they are safe to reflect into the
		// fallback redirect and the confirmation page.
		if !validCLIPort(port) {
			http.Error(w, "invalid port", http.StatusBadRequest)
			return
		}
		if !cliStateRe.MatchString(state) {
			http.Error(w, "This sign-in link is missing its login check. Run `benmore login` again (update the CLI if this keeps happening).", http.StatusBadRequest)
			return
		}
		formQuery := "port=" + port + "&state=" + url.QueryEscape(state)
		sess := getSession(app, r)
		if sess == nil || sess.Email == "" {
			if r.Method == http.MethodPost {
				http.Error(w, "sign in first", http.StatusUnauthorized)
				return
			}
			// No active session - send them to the sign-in form (port preserved).
			http.Redirect(w, r, "/cli-auth?"+formQuery, http.StatusSeeOther)
			return
		}
		// The CLI token is a full-access credential for every app the
		// account reaches, and minting it rotates the one the owner holds.
		// Only the person's own full sign-in may do that: API tokens,
		// scoped sessions, support impersonation and act-as are delegated
		// access and must not widen themselves into it.
		if !directLoginSession(app, sess) {
			http.Error(w, "Sign in to the dashboard directly (not through an API token, a scoped session, impersonation or act-as) to connect the CLI.", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodPost {
			writeCLISessionConfirmPage(w, sess.Email, port, state, authMintCSRFToken(authRawSessionID(r)))
			return
		}
		if !sameOriginPost(r) || !validateCSRF(r) {
			http.Error(w, "CLI authorization not confirmed - run `benmore login` again.", http.StatusForbidden)
			return
		}
		if oauthMintCLIToken(w, r, app, sess.Email, port+"~"+state) {
			return // token minted + redirected to the localhost callback
		}
		// Framework build / mint unavailable - fall back to the form.
		http.Redirect(w, r, "/cli-auth?"+formQuery, http.StatusSeeOther)
	}
}

// writeCLISessionConfirmPage renders the frame-proof "Connect the CLI as
// <you>" confirmation. Its form is the only way to reach the mint.
func writeCLISessionConfirmPage(w http.ResponseWriter, email, port, state, csrf string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; form-action 'self' http://127.0.0.1:*; frame-ancestors 'none'; base-uri 'none'")
	esc := html.EscapeString
	_, _ = w.Write([]byte(`<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Connect the CLI</title>
<style>body{font:15px/1.5 system-ui,-apple-system,sans-serif;max-width:420px;margin:12vh auto;padding:0 16px;color:#18181b;background:#fff}
@media(prefers-color-scheme:dark){body{color:#e4e4e7;background:#09090b}}
button{width:100%;height:44px;border:0;border-radius:999px;background:#18181b;color:#fff;font:inherit;font-weight:500;cursor:pointer;margin-top:12px}
@media(prefers-color-scheme:dark){button{background:#e4e4e7;color:#09090b}}
p.small{font-size:13px;opacity:.7}</style></head><body>
<h1 style="font-size:22px;font-weight:500">Connect the Benmore CLI</h1>
<p>Sign the <code>benmore</code> command line on this computer in as <strong>` + esc(email) + `</strong>?</p>
<p class="small">This replaces any CLI token this account already has, so other machines or CI using it will need to sign in again. Only continue if you just ran <code>benmore login</code>.</p>
<form method="POST" action="/auth/cli-session">
<input type="hidden" name="port" value="` + esc(port) + `">
<input type="hidden" name="state" value="` + esc(state) + `">
<input type="hidden" name="_csrf" value="` + esc(csrf) + `">
<button type="submit">Connect the CLI</button>
</form></body></html>`))
}
