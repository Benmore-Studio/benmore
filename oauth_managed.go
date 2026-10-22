//go:build !cli

package main

// Managed-mode social login - APP side. The platform OAuth broker
// (platform_oauth_broker.go, router process) owns the shared provider
// credentials; this file is what runs inside each app process:
//
//   - /auth/<provider> redirects to the broker when the app has no BYO
//     client credentials but the platform serves that provider
//     (BENMORE_OAUTH_BROKER_URL + BENMORE_OAUTH_BROKER_PROVIDERS env,
//     injected by the router's env-file writer).
//   - /auth/managed/callback verifies the broker's handoff assertion
//     (HMAC with THIS app's own server secret, 60s expiry, single-use
//     jti, audience = this app) and then runs the exact same
//     find-or-create + session path BYO OAuth uses.
//
// Self-hosted / framework builds: the env vars are absent, so nothing
// here activates.

import (
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// brokerSign/brokerVerify: compact HMAC-signed payload encoding shared
// by the broker (router) and the app-side verifier.
func brokerSign(payload []byte, secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	return base64.RawURLEncoding.EncodeToString(payload) + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func brokerVerify(token, secret string) ([]byte, bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return nil, false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return nil, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return nil, false
	}
	return payload, true
}

// managedAssertion is the broker → app handoff payload.
type managedAssertion struct {
	Email    string `json:"email"`
	Name     string `json:"name,omitempty"`
	Provider string `json:"provider"`
	Aud      string `json:"aud"` // instance subdomain
	Iat      int64  `json:"iat"`
	Exp      int64  `json:"exp"`
	JTI      string `json:"jti"`
	// N is the hash of the nonce the initiating browser holds in its cookie.
	// Present only when the start request carried one (new app + new router);
	// it binds the assertion to that browser (login-CSRF defence).
	N string `json:"n,omitempty"`
}

// The nonce cookie ties a managed sign-in to the browser that started it.
// Over HTTPS it carries the __Host- prefix (host-only, Secure, Path=/), like
// the session cookie, so a sibling subdomain can't plant one.
const (
	managedNonceCookie    = "__Host-benmore_oauth_nonce"
	devManagedNonceCookie = "benmore_oauth_nonce"
	managedNonceTTL       = 10 * time.Minute // matches the broker's state lifetime
)

func managedNonceCookieName(secure bool) string {
	if secure {
		return managedNonceCookie
	}
	return devManagedNonceCookie
}

// managedNonceHash is the value sent through the broker; the cookie nonce
// itself never appears in a URL.
func managedNonceHash(nonce string) string {
	sum := sha256.Sum256([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// validManagedNonceHash accepts exactly a base64url SHA-256 (43 chars).
func validManagedNonceHash(n string) bool {
	if len(n) != 43 {
		return false
	}
	b, err := base64.RawURLEncoding.DecodeString(n)
	return err == nil && len(b) == sha256.Size
}

// managedRequireNonce is the operator rollout flag. Off by default so apps
// and routers on different binaries interoperate during a fleet rollout; turn
// it on only after every app and the router run a nonce-aware binary.
func managedRequireNonce() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("BENMORE_OAUTH_REQUIRE_NONCE"))) {
	case "1", "true", "yes", "on":
		return true
	}
	return false
}

// readManagedNonceCookie mirrors requestSessionCookie: the unprefixed name
// counts only on plain HTTP.
func readManagedNonceCookie(r *http.Request) string {
	if c, err := r.Cookie(managedNonceCookie); err == nil && c.Value != "" {
		return c.Value
	}
	if protoOf(r) != "https" {
		if c, err := r.Cookie(devManagedNonceCookie); err == nil {
			return c.Value
		}
	}
	return ""
}

// The cookie holds up to managedNonceMax pending nonces, oldest first, joined
// by "." (a nonce is hex, so it never contains one). A second sign-in started
// in another tab appends instead of overwriting, so the first tab's callback
// still finds its nonce.
const (
	managedNonceMax = 3
	managedNonceSep = "."
)

// managedNonceList splits a cookie value into its held nonces.
func managedNonceList(cookie string) []string {
	var out []string
	for _, n := range strings.Split(cookie, managedNonceSep) {
		if n != "" {
			out = append(out, n)
		}
	}
	return out
}

// managedNonceAppend adds a fresh nonce and keeps the newest managedNonceMax.
func managedNonceAppend(cookie, nonce string) string {
	list := append(managedNonceList(cookie), nonce)
	if len(list) > managedNonceMax {
		list = list[len(list)-managedNonceMax:]
	}
	return strings.Join(list, managedNonceSep)
}

// managedNonceMatch returns the index of the held nonce whose hash equals
// want, or -1. Every held nonce is compared, in constant time, so timing
// reveals neither which slot matched nor how many are held.
func managedNonceMatch(list []string, want string) int {
	found := -1
	for i, n := range list {
		if subtle.ConstantTimeCompare([]byte(managedNonceHash(n)), []byte(want)) == 1 {
			found = i
		}
	}
	return found
}

func setManagedNonceCookie(w http.ResponseWriter, secure bool, value string) {
	http.SetCookie(w, &http.Cookie{
		Name: managedNonceCookieName(secure), Value: value, Path: "/",
		MaxAge: int(managedNonceTTL.Seconds()), HttpOnly: true, Secure: secure, SameSite: http.SameSiteLaxMode,
	})
}

func clearManagedNonceCookies(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{Name: managedNonceCookie, Path: "/", MaxAge: -1, HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode})
	http.SetCookie(w, &http.Cookie{Name: devManagedNonceCookie, Path: "/", MaxAge: -1, HttpOnly: true, SameSite: http.SameSiteLaxMode})
}

// managedBrokerURL/managedBrokerProviders read the router-injected env.
func managedBrokerURL() string {
	return strings.TrimRight(strings.TrimSpace(os.Getenv("BENMORE_OAUTH_BROKER_URL")), "/")
}

func managedBrokerProviders() []string {
	raw := strings.TrimSpace(os.Getenv("BENMORE_OAUTH_BROKER_PROVIDERS"))
	if raw == "" {
		return nil
	}
	var out []string
	for _, p := range strings.Split(raw, ",") {
		if p = strings.TrimSpace(strings.ToLower(p)); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// seenManagedJTI enforces single-use handoff tokens. Entries live only
// as long as the 60s assertion window needs.
var seenManagedJTI = struct {
	mu sync.Mutex
	m  map[string]int64
}{m: map[string]int64{}}

func managedJTIFresh(jti string, exp int64) bool {
	now := time.Now().Unix()
	seenManagedJTI.mu.Lock()
	defer seenManagedJTI.mu.Unlock()
	for k, e := range seenManagedJTI.m {
		if e < now {
			delete(seenManagedJTI.m, k)
		}
	}
	if _, dup := seenManagedJTI.m[jti]; dup {
		return false
	}
	seenManagedJTI.m[jti] = exp
	return true
}

// registerManagedOAuthRoutes wires the broker-backed login routes for
// every platform-served provider the app hasn't configured its own
// credentials for. Returns the provider names it registered (for the
// login-page button list). Called from RegisterOAuthRoutes.
func registerManagedOAuthRoutes(mux appRouteRegistrar, app *App, byoConfigured map[string]bool) []string {
	broker := managedBrokerURL()
	if broker == "" {
		return nil
	}
	appName := strings.TrimSpace(os.Getenv("BENMORE_APP_NAME"))
	if appName == "" {
		return nil
	}
	var registered []string
	for _, name := range managedBrokerProviders() {
		if byoConfigured[name] {
			continue // BYO credentials always win
		}
		n := name
		mux.HandleFunc(fmt.Sprintf("GET /auth/%s", n), func(w http.ResponseWriter, r *http.Request) {
			nonce := generateToken(16)
			secure := protoOf(r) == "https"
			setManagedNonceCookie(w, secure, managedNonceAppend(readManagedNonceCookie(r), nonce))
			q := url.Values{
				"provider":    {n},
				"app":         {appName},
				"return_host": {r.Host},
				"n":           {managedNonceHash(nonce)},
			}
			http.Redirect(w, r, broker+"/platform/oauth/start?"+q.Encode(), http.StatusFound)
		})
		registered = append(registered, n)
		log.Printf("  oauth: %s (/auth/%s, managed by the platform)", n, n)
	}
	if len(registered) == 0 {
		return nil
	}

	mux.HandleFunc("GET /auth/managed/callback", func(w http.ResponseWriter, r *http.Request) {
		payload, ok := brokerVerify(r.URL.Query().Get("token"), serverSecret)
		if !ok {
			http.Error(w, "invalid sign-in token", http.StatusBadRequest)
			return
		}
		var a managedAssertion
		if err := json.Unmarshal(payload, &a); err != nil {
			http.Error(w, "invalid sign-in token", http.StatusBadRequest)
			return
		}
		now := time.Now().Unix()
		if a.Aud != appName || now > a.Exp || a.Iat > now+30 || a.Email == "" {
			http.Error(w, "sign-in token expired - try again", http.StatusBadRequest)
			return
		}
		// Login-CSRF gate: an assertion carrying n is honoured only in the
		// browser holding the matching start cookie. A legacy assertion
		// (no n: old app start or old router) passes unless the operator
		// flag is on. Checked before the jti is consumed so a foreign
		// browser can't burn the initiator's assertion.
		held := managedNonceList(readManagedNonceCookie(r))
		if a.N != "" {
			idx := managedNonceMatch(held, a.N)
			if idx < 0 {
				http.Error(w, "sign-in was not started in this browser - try again", http.StatusBadRequest)
				return
			}
			// Consume only the matching nonce; other tabs keep theirs.
			rest := append(append([]string{}, held[:idx]...), held[idx+1:]...)
			if len(rest) > 0 {
				setManagedNonceCookie(w, protoOf(r) == "https", strings.Join(rest, managedNonceSep))
			} else {
				clearManagedNonceCookies(w)
			}
		} else if managedRequireNonce() {
			http.Error(w, "sign-in token is not bound to this browser - try again", http.StatusBadRequest)
			return
		}
		if !managedJTIFresh(a.JTI, a.Exp) {
			http.Error(w, "sign-in token already used - try again", http.StatusBadRequest)
			return
		}
		// Same gates as BYO OAuth: one plain mailbox, then the
		// domain/allowlist policy. (The broker already refused
		// provider-unverified emails.)
		a.Email = strings.TrimSpace(a.Email)
		if !validAuthEmail(a.Email) {
			log.Printf("managed OAuth login rejected: the provider returned a value that is not a single plain email address")
			authRedirect(w, r, app.Paths.Login, "Your sign-in provider returned an email address this app can't use. Sign in another way.")
			return
		}
		if ok, reason := emailAllowedForApp(app, a.Email); !ok {
			log.Printf("managed OAuth login rejected for %s: %s", logAddressRef(a.Email), reason)
			authRedirect(w, r, app.Paths.Login, reason)
			return
		}
		userID, err := oauthFindOrCreateUser(app, a.Email, a.Name, true) // the broker admits provider-verified emails only
		if err != nil {
			serverError(w, r, app, "managed oauth", fmt.Errorf("user creation failed: %w", err), "authentication failed")
			return
		}
		syncPlatformUserFromOAuth(app, a.Email)

		if oauthMFAGate(w, r, app, userID, a.Email, "") {
			return
		}
		groupID := ResolveGroupID(app.DB, app.Group, a.Email)
		sessionID := createSignInSession(app.DB, userID, a.Email, groupID, app.SessionDuration)
		http.SetCookie(w, sessionCookie(sessionID, app.DevMode, app.SessionDuration))

		redirectTo := "/"
		if app.Design != nil {
			if rd := app.Design.Auth["redirect"]; rd != "" {
				redirectTo = rd
			}
		}
		http.Redirect(w, r, redirectTo, http.StatusSeeOther)
	})
	return registered
}
