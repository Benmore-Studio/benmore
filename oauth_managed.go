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
func registerManagedOAuthRoutes(mux *http.ServeMux, app *App, byoConfigured map[string]bool) []string {
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
			q := url.Values{
				"provider":    {n},
				"app":         {appName},
				"return_host": {r.Host},
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
		if !managedJTIFresh(a.JTI, a.Exp) {
			http.Error(w, "sign-in token already used - try again", http.StatusBadRequest)
			return
		}
		// Same gates as BYO OAuth: domain/allowlist policy. (The broker
		// already refused provider-unverified emails.)
		if ok, reason := emailAllowedForApp(app, a.Email); !ok {
			log.Printf("managed OAuth login rejected for %s: %s", a.Email, reason)
			authRedirect(w, r, app.Paths.Login, reason)
			return
		}
		userID, err := oauthFindOrCreateUser(app, a.Email, a.Name)
		if err != nil {
			log.Printf("managed OAuth user creation failed: %s", err)
			http.Error(w, "authentication failed", http.StatusInternalServerError)
			return
		}
		syncPlatformUserFromOAuth(app, a.Email)

		groupID := ResolveGroupID(app.DB, app.Group, a.Email)
		sessionID := CreateSession(app.DB, userID, a.Email, groupID, app.SessionDuration)
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
