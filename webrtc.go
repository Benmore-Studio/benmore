//go:build !cli

package main

// WebRTC ICE-server provisioning. Agents writing peer-to-peer apps
// (livestream, voice rooms, screen-share) need an ICE configuration
// that actually connects across the public internet - STUN alone
// fails for symmetric NATs (which most carrier-grade cellular and
// some home routers run). TURN servers relay media when STUN's
// hole-punching can't establish a direct path.
//
// This file ships ONE endpoint: GET /api/_webrtc/ice - returns the
// list the agent passes verbatim into `new RTCPeerConnection({iceServers: ...})`.
// The SDK wraps it as `bm.webrtc.iceServers()`. Default response is
// STUN-only (Google's public servers); when env vars are set the
// framework adds TURN credentials.
//
// Two TURN providers supported:
//
//   1. Cloudflare Calls (free) - env: TURN_PROVIDER=cloudflare,
//      TURN_CF_APP_ID=…, TURN_CF_APP_TOKEN=…
//      Server mints short-lived (1h) creds via Cloudflare's API on
//      each request. Cached in-process for 50min so we don't slam
//      Cloudflare's mint endpoint. The TOKEN never reaches the
//      client - only the time-limited per-session creds do.
//
//   2. Static (self-hosted coturn or any TURN provider) - env:
//      TURN_URL=turn:turn.example.com:3478, TURN_USERNAME=…,
//      TURN_CREDENTIAL=…
//      Returned as-is. Simple, but the credential lives client-side
//      indefinitely - only use for trusted networks.
//
// Credential resolution order (first match wins):
//
//   a. Per-app env (TURN_PROVIDER / TURN_* in the app's env). Use this
//      when an app needs its own credential isolation. The Cloudflare app
//      id and token are taken as a pair from one scope
//      (cloudflareCredentialPair): an app sets both or neither.
//
//   b. Host-wide env (BENMORE_PLATFORM_TURN_*), set once on the host (e.g.
//      via a systemd EnvironmentFile or the process environment). Every app
//      served by that host then gets TURN automatically with no per-app
//      config - provision one Cloudflare Calls (or other) app, set the env
//      vars once, and the whole deployment has working TURN.
//
// The point: no app code should need to think about TURN for the common
// case. Call `bm.webrtc.iceServers()` and you get a working list - same
// shape, same code, whether the host provisioned TURN or not.
//
// Both branches return the same shape:
//   {"iceServers":[{"urls":["stun:..."]}, {"urls":["turn:..."], "username":"…", "credential":"…"}]}

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// turnCache holds a per-app TURN credential bundle. We cache per app
// because credentials are per app (CF APP_ID + APP_TOKEN are app-level
// secrets, and static TURN_URL is app-level config).
type turnCacheEntry struct {
	iceServers []iceServer
	expires    time.Time
}

var (
	turnCacheMu sync.Mutex
	turnCache   = map[string]*turnCacheEntry{} // key: scope|app.Dir|principal
	// turnMintLimiter bounds provider mint calls per app; a caller past it
	// gets STUN only rather than a shared credential.
	turnMintLimiter = NewRateLimiter(120, time.Minute)
)

const turnCacheMaxEntries = 10000

// iceServer mirrors the WebRTC RTCIceServer dictionary shape.
type iceServer struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

// defaultSTUN is the public STUN list always included. Google's STUN
// servers have ~100% uptime and are the de-facto standard for hobby
// WebRTC apps. For high-traffic production apps the operator should
// supplement with their own STUN.
func defaultSTUN() iceServer {
	return iceServer{
		URLs: []string{
			"stun:stun.l.google.com:19302",
			"stun:stun1.l.google.com:19302",
		},
	}
}

// RegisterWebRTCRoute wires GET /api/_webrtc/ice into the app's mux.
// TURN credentials relay arbitrary traffic on the provider's (often the
// platform's) account, so they go only to signed-in callers - or to anyone
// when the app opts into anonymous realtime with features.ws_anonymous, the
// same flag that admits anonymous room and broadcast viewers. Other callers
// get the STUN-only list, so the endpoint always answers with a usable
// shape. Credentials are minted per app and caller, never shared.
func RegisterWebRTCRoute(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("GET /api/_webrtc/ice", func(w http.ResponseWriter, r *http.Request) {
		ice := []iceServer{defaultSTUN()}
		if principal := turnPrincipal(app, r); principal != "" {
			ice = buildICEServers(app, principal)
		}
		w.Header().Set("Content-Type", "application/json")
		// Cache headers: a thin no-cache so browsers always check
		// freshness (creds expire within an hour). The server-side
		// cache already amortises the Cloudflare-mint cost.
		w.Header().Set("Cache-Control", "private, no-cache, must-revalidate")
		json.NewEncoder(w).Encode(map[string]any{
			"iceServers": ice,
		})
	})
}

// buildICEServers assembles the ICE list for one request. Returns
// STUN by default; layers TURN on top when env vars present (per-app
// first, platform-wide fallback). Agents never need to know which
// path supplied the credentials - the SDK surface is identical.
func buildICEServers(app *App, principal string) []iceServer {
	ice := []iceServer{defaultSTUN()}

	provider, scope := resolveTURNProvider(app)
	switch provider {
	case "cloudflare", "cf", "cf_calls":
		if servers := cloudflareTURNCreds(app, scope, principal); len(servers) > 0 {
			ice = append(ice, servers...)
		}
	case "static":
		if turnURL := resolveTURNVar(app, "TURN_URL"); turnURL != "" {
			ice = append(ice, iceServer{
				URLs:       []string{turnURL},
				Username:   resolveTURNVar(app, "TURN_USERNAME"),
				Credential: resolveTURNVar(app, "TURN_CREDENTIAL"),
			})
		}
	case "":
		// No TURN configured anywhere - STUN-only response. Agents on
		// cooperative networks (same LAN, no symmetric NAT) still work;
		// the operator can flip TURN on without any app code changes.
	default:
		log.Printf("webrtc: unknown TURN_PROVIDER=%q (use 'cloudflare' or 'static')", provider)
	}
	return ice
}

// resolveTURNProvider returns the TURN provider name and which scope
// supplied it ("app" / "platform" / "" for unset). The scope is later
// used as a cache key so per-app overrides don't collide with platform-
// shared creds.
func resolveTURNProvider(app *App) (provider, scope string) {
	if v := strings.ToLower(strings.TrimSpace(getAppEnv(app, "TURN_PROVIDER"))); v != "" {
		return v, "app:" + app.Dir
	}
	if v := strings.ToLower(strings.TrimSpace(os.Getenv("BENMORE_PLATFORM_TURN_PROVIDER"))); v != "" {
		return v, "platform"
	}
	// Convenience default: if BENMORE_PLATFORM_TURN_CF_APP_ID is set
	// without an explicit PROVIDER, assume cloudflare. Removes one
	// env var the operator would otherwise have to remember.
	if os.Getenv("BENMORE_PLATFORM_TURN_CF_APP_ID") != "" {
		return "cloudflare", "platform"
	}
	return "", ""
}

// resolveTURNVar reads a TURN_* env, preferring per-app storage over
// platform-wide. Platform vars are prefixed BENMORE_PLATFORM_<KEY>.
func resolveTURNVar(app *App, key string) string {
	if v := strings.TrimSpace(getAppEnv(app, key)); v != "" {
		return v
	}
	if v := strings.TrimSpace(os.Getenv("BENMORE_PLATFORM_" + key)); v != "" {
		return v
	}
	return ""
}

// cloudflareCredentialPair returns a Cloudflare app id and token from ONE
// scope: the app's own pair when it sets both, otherwise the platform's
// BENMORE_PLATFORM_* pair. A tenant-set id never pairs with the platform
// token, which would send the platform's credential to a Cloudflare path the
// tenant chose. The id is placed in the request path, so it must be hex (as
// Cloudflare's app and key ids are); a pair whose id isn't is unusable.
func cloudflareCredentialPair(app *App, idKey, tokenKey string) (id, token string, ok bool) {
	id, token = strings.TrimSpace(getAppEnv(app, idKey)), strings.TrimSpace(getAppEnv(app, tokenKey))
	if id == "" || token == "" {
		id = strings.TrimSpace(os.Getenv("BENMORE_PLATFORM_" + idKey))
		token = strings.TrimSpace(os.Getenv("BENMORE_PLATFORM_" + tokenKey))
	}
	if id == "" || token == "" || !cloudflareIDValid(id) {
		return "", "", false
	}
	return id, token, true
}

func cloudflareIDValid(id string) bool {
	if len(id) == 0 || len(id) > 128 {
		return false
	}
	for i := 0; i < len(id); i++ {
		c := id[i]
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F') {
			return false
		}
	}
	return true
}

// cloudflareTURNCreds mints - or returns a cached - Cloudflare Calls
// TURN credential bundle. CF's API:
//
//	POST https://rtc.live.cloudflare.com/v1/turn/keys/{APP_ID}/credentials/generate
//	Authorization: Bearer {APP_TOKEN}
//	{"ttl": 86400}
//
//	→ {"iceServers":{"urls":[...], "username":"…", "credential":"…"}}
//
// We request a 1h TTL and cache for 50min so renewal happens before
// the credential expires under any client. `scope` differentiates
// per-app overrides ("app:<dir>") from platform-shared creds
// ("platform") - same APP_ID + APP_TOKEN can mint per-session creds
// for every app in the deployment safely.
func cloudflareTURNCreds(app *App, scope, principal string) []iceServer {
	// One credential per app and caller: a platform-scoped credential used
	// to be shared by every app on the host and every caller of each.
	cacheKey := scope + "|" + app.Dir + "|" + principal

	turnCacheMu.Lock()
	if entry, ok := turnCache[cacheKey]; ok && time.Now().Before(entry.expires) {
		turnCacheMu.Unlock()
		return entry.iceServers
	}
	turnCacheMu.Unlock()
	if !turnMintLimiter.Allow(app.Dir) {
		log.Printf("webrtc: TURN mint rate limit reached for %s - serving STUN only", app.Dir)
		return nil
	}

	appID, token, ok := cloudflareCredentialPair(app, "TURN_CF_APP_ID", "TURN_CF_APP_TOKEN")
	if !ok {
		log.Printf("webrtc: cloudflare TURN configured but no usable TURN_CF_APP_ID / TURN_CF_APP_TOKEN pair (scope=%s) - falling back to STUN-only", scope)
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	body := strings.NewReader(`{"ttl":3600}`)
	url := fmt.Sprintf("https://rtc.live.cloudflare.com/v1/turn/keys/%s/credentials/generate", appID)
	req, err := http.NewRequestWithContext(ctx, "POST", url, body)
	if err != nil {
		log.Printf("webrtc: cloudflare turn req build: %v", err)
		return nil
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		log.Printf("webrtc: cloudflare turn fetch: %v", err)
		return nil
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))

	if resp.StatusCode >= 300 {
		log.Printf("webrtc: cloudflare turn %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
		return nil
	}

	// CF returns: { "iceServers": { "urls": [...], "username": "...", "credential": "..." } }
	// - note the single object, not an array. We normalize to our array shape.
	var parsed struct {
		IceServers struct {
			URLs       []string `json:"urls"`
			Username   string   `json:"username"`
			Credential string   `json:"credential"`
		} `json:"iceServers"`
	}
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		log.Printf("webrtc: cloudflare turn parse: %v (body=%q)", err, string(respBody))
		return nil
	}
	if len(parsed.IceServers.URLs) == 0 {
		log.Printf("webrtc: cloudflare turn returned no URLs (body=%q)", string(respBody))
		return nil
	}

	servers := []iceServer{{
		URLs:       parsed.IceServers.URLs,
		Username:   parsed.IceServers.Username,
		Credential: parsed.IceServers.Credential,
	}}

	turnCacheMu.Lock()
	if len(turnCache) >= turnCacheMaxEntries {
		now := time.Now()
		for k, e := range turnCache {
			if !now.Before(e.expires) {
				delete(turnCache, k)
			}
		}
	}
	if len(turnCache) < turnCacheMaxEntries {
		turnCache[cacheKey] = &turnCacheEntry{
			iceServers: servers,
			expires:    time.Now().Add(50 * time.Minute),
		}
	}
	turnCacheMu.Unlock()
	return servers
}

// turnPrincipal names who a TURN credential is for: the signed-in user, or
// the client address when the app admits anonymous realtime (an IPv6 client
// by its /64, so rotating through its addresses can't mint a credential per
// address and spend the app's turnMintLimiter budget). "" means the caller
// gets STUN only.
func turnPrincipal(app *App, r *http.Request) string {
	if sess := getSession(app, r); sess != nil && sess.UserID > 0 {
		return fmt.Sprintf("user:%d", sess.UserID)
	}
	if broadcastAllowAnon(app) {
		return "ip:" + clientRateBucket(clientIP(r))
	}
	return ""
}

// getAppEnv reads an env var via the per-app store (set via
// env vars on the app). Wraps the package-level
// GetAppEnv with a nil-app guard for safety.
func getAppEnv(app *App, key string) string {
	if app == nil {
		return ""
	}
	return GetAppEnv(app.Dir, key)
}
