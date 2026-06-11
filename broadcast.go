//go:build !cli

package main

// bm.broadcast - server-proxied SFU integration via Cloudflare Realtime.
//
// Why an SFU at all: peer-mesh WebRTC requires the publisher to upload
// N copies of their media (one per viewer). At ~5 viewers a typical
// home uplink saturates and the stream falls apart. An SFU (Selective
// Forwarding Unit) routes a single publisher upload to N viewers
// through its own infra - the publisher uploads once, no matter how
// many people watch.
//
// Why proxy and not WHIP/WHEP-direct: Cloudflare Realtime auth uses
// a long-lived APP_TOKEN that MUST stay server-side. If we minted a
// short-lived bearer for the client to talk to CF directly it would
// work, but the SDK gets simpler when the server is the only thing
// that knows the CF endpoint exists. Network cost is one extra hop on
// the SDP offer/answer (~5KB each); media flows browser↔CF directly
// once ICE is established, so the proxy doesn't relay video at all.
//
// API surface:
//
//   POST /api/_broadcast/publish     { slug, sdp }   → { sdp, sessionId }
//   POST /api/_broadcast/subscribe   { slug, sdp }   → { sdp, sessionId }
//   POST /api/_broadcast/stop        { slug }        → { ok }
//   GET  /api/_broadcast/stats/{slug}                → { live, viewers, started_at }
//
// All require auth by default; broadcasts respect the same scope
// model as auto-CRUD (publishers must be authed, subscribers depend
// on features.ws_anonymous).
//
// Slug uniqueness: enforced at INSERT - one active publisher per slug.
// Re-publishing the same slug fails with 409.
//
// Cleanup: `_benmore_broadcasts.last_seen_at` is updated on subscribe;
// rows older than 5 minutes without a subscribe / stop are GC'd on
// next publish attempt to that slug, so a publisher who crashed
// without calling stop doesn't permanently block their slug.

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"
)

// EnsureBroadcastTable creates the slug → publisher-session map.
// Idempotent - safe to call on every app load.
func EnsureBroadcastTable(db *sql.DB) {
	if db == nil {
		return
	}
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_broadcasts (
		slug TEXT PRIMARY KEY,
		publisher_session_id TEXT NOT NULL,
		publisher_user_id INTEGER,
		viewer_count INTEGER DEFAULT 0,
		created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
		last_seen_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
	)`)
}

// RegisterBroadcastRoutes wires the four bm.broadcast endpoints.
// Caller has already loaded app.DB; this routine ensures the
// _benmore_broadcasts table exists and attaches handlers.
func RegisterBroadcastRoutes(mux *http.ServeMux, app *App) {
	EnsureBroadcastTable(app.DB)

	mux.HandleFunc("POST /api/_broadcast/publish", func(w http.ResponseWriter, r *http.Request) {
		broadcastPublish(w, r, app)
	})
	mux.HandleFunc("POST /api/_broadcast/subscribe", func(w http.ResponseWriter, r *http.Request) {
		broadcastSubscribe(w, r, app)
	})
	mux.HandleFunc("POST /api/_broadcast/stop", func(w http.ResponseWriter, r *http.Request) {
		broadcastStop(w, r, app)
	})
	mux.HandleFunc("GET /api/_broadcast/stats/{slug}", func(w http.ResponseWriter, r *http.Request) {
		broadcastStats(w, r, app)
	})
}

// sfuConfig resolves Cloudflare Realtime SFU credentials, preferring
// per-app overrides (SFU_CF_APP_ID / SFU_CF_APP_TOKEN) over platform-
// shared (BENMORE_PLATFORM_SFU_CF_APP_ID / BENMORE_PLATFORM_SFU_CF_APP_TOKEN).
// Returns ok=false when no creds are configured anywhere - handlers
// then 503 with a clear message so the SDK can fall back to peer-mesh.
type sfuConfig struct {
	appID    string
	appToken string
	ok       bool
}

func resolveSFUConfig(app *App) sfuConfig {
	get := func(key string) string {
		return strings.TrimSpace(resolveTURNVar(app, key)) // re-uses the per-app→platform precedence ladder
	}
	cfg := sfuConfig{
		appID:    get("SFU_CF_APP_ID"),
		appToken: get("SFU_CF_APP_TOKEN"),
	}
	cfg.ok = cfg.appID != "" && cfg.appToken != ""
	return cfg
}

// broadcastPublish - server proxy for the WebRTC publish flow.
//
//   1. Validate session (publisher MUST be authed).
//   2. Validate slug shape; check no live publisher already on this slug
//      (with TTL GC for stale rows).
//   3. Create a CF Realtime SFU session.
//   4. Forward the client's SDP offer with the session's local tracks.
//   5. Store slug → sessionId, return CF's answer to the client.
//
// On any CF API failure we return a 502 with the upstream error so
// the agent sees what went wrong (vs. a 200 with broken SDP that
// would silently fail at setRemoteDescription).
func broadcastPublish(w http.ResponseWriter, r *http.Request, app *App) {
	mergeJSONBodyIntoForm(r) // accept JSON bodies via the same shim as auth
	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid csrf"})
		return
	}
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "must be signed in to publish"})
		return
	}

	cfg := resolveSFUConfig(app)
	if !cfg.ok {
		httpJSON(w, http.StatusServiceUnavailable, map[string]any{
			"error":  "SFU not configured",
			"reason": "Set BENMORE_PLATFORM_SFU_CF_APP_ID + BENMORE_PLATFORM_SFU_CF_APP_TOKEN (or the per-app SFU_CF_* vars) to enable broadcast.",
		})
		return
	}

	slug := strings.TrimSpace(r.FormValue("slug"))
	sdpOffer := r.FormValue("sdp")
	if !isValidBroadcastSlug(slug) || sdpOffer == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "slug + sdp required"})
		return
	}

	// GC stale publishers - rows older than 5min with no recent activity
	// indicate a publisher that crashed without calling stop.
	app.DB.Exec("DELETE FROM _benmore_broadcasts WHERE last_seen_at < datetime('now', '-5 minutes')")

	// One live publisher per slug - second concurrent claim returns 409.
	var existing string
	err := app.DB.QueryRow("SELECT publisher_session_id FROM _benmore_broadcasts WHERE slug = ?", slug).Scan(&existing)
	if err == nil && existing != "" {
		httpJSON(w, http.StatusConflict, map[string]any{"error": "slug already live", "publisher_session_id": existing})
		return
	}

	// Step 1 - create CF session.
	sessionID, err := cfCreateSession(cfg)
	if err != nil {
		log.Printf("broadcast: cf session create failed: %v", err)
		httpJSON(w, http.StatusBadGateway, map[string]any{"error": "upstream SFU unavailable"})
		return
	}

	// Step 2 - push the publisher's offer through. CF infers the track
	// metadata from the SDP itself (every m-line becomes a track keyed
	// by its mid). Track names default to the mid in the SDP, which the
	// subscribers will request by stable-naming convention "0", "1", …
	answer, err := cfPublishTracks(cfg, sessionID, sdpOffer)
	if err != nil {
		log.Printf("broadcast: cf publish failed: %v", err)
		httpJSON(w, http.StatusBadGateway, map[string]any{"error": "SFU rejected offer", "detail": err.Error()})
		return
	}

	// Persist the slug → sessionId mapping for subscribers.
	_, err = app.DB.Exec(`INSERT INTO _benmore_broadcasts
		(slug, publisher_session_id, publisher_user_id) VALUES (?, ?, ?)`,
		slug, sessionID, session.UserID)
	if err != nil {
		log.Printf("broadcast: db insert failed: %v", err)
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "db error"})
		return
	}

	httpJSON(w, http.StatusOK, map[string]any{
		"sdp":        answer,
		"session_id": sessionID,
		"slug":       slug,
	})
}

// broadcastSubscribe - server proxy for the WebRTC subscribe flow.
// Mirrors publish but creates a NEW CF session that "pulls" tracks
// from the publisher's session (CF SFU's primary use case).
func broadcastSubscribe(w http.ResponseWriter, r *http.Request, app *App) {
	mergeJSONBodyIntoForm(r)
	// Anon viewers OK when features.ws_anonymous is set; otherwise auth
	// required. Same model bm.room follows.
	if !broadcastAllowAnon(app) {
		if session := getSession(app, r); session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "auth required (set features.ws_anonymous: true to allow anon viewers)"})
			return
		}
	}

	cfg := resolveSFUConfig(app)
	if !cfg.ok {
		httpJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "SFU not configured"})
		return
	}

	slug := strings.TrimSpace(r.FormValue("slug"))
	sdpOffer := r.FormValue("sdp")
	if !isValidBroadcastSlug(slug) || sdpOffer == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "slug + sdp required"})
		return
	}

	var publisherSessionID string
	err := app.DB.QueryRow("SELECT publisher_session_id FROM _benmore_broadcasts WHERE slug = ?", slug).Scan(&publisherSessionID)
	if err != nil || publisherSessionID == "" {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "no live broadcast for slug"})
		return
	}

	// Step 1 - create subscriber session.
	subSessionID, err := cfCreateSession(cfg)
	if err != nil {
		log.Printf("broadcast: cf session create (sub) failed: %v", err)
		httpJSON(w, http.StatusBadGateway, map[string]any{"error": "upstream SFU unavailable"})
		return
	}

	// Step 2 - request to pull tracks from the publisher.
	answer, err := cfPullTracks(cfg, subSessionID, publisherSessionID, sdpOffer)
	if err != nil {
		log.Printf("broadcast: cf pull failed: %v", err)
		httpJSON(w, http.StatusBadGateway, map[string]any{"error": "SFU rejected pull", "detail": err.Error()})
		return
	}

	// Bump viewer counter + freshness timestamp.
	app.DB.Exec(`UPDATE _benmore_broadcasts SET
		viewer_count = viewer_count + 1,
		last_seen_at = CURRENT_TIMESTAMP WHERE slug = ?`, slug)

	httpJSON(w, http.StatusOK, map[string]any{
		"sdp":        answer,
		"session_id": subSessionID,
		"slug":       slug,
	})
}

// broadcastStop - tear down the publisher record. CF's session GC
// reclaims the upstream resources separately when no client is
// connected.
func broadcastStop(w http.ResponseWriter, r *http.Request, app *App) {
	mergeJSONBodyIntoForm(r)
	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid csrf"})
		return
	}
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "auth required"})
		return
	}
	slug := strings.TrimSpace(r.FormValue("slug"))
	if !isValidBroadcastSlug(slug) {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "slug required"})
		return
	}
	// Owner-or-admin only - a viewer can't kill a publisher's stream.
	var ownerID int64
	app.DB.QueryRow("SELECT COALESCE(publisher_user_id, 0) FROM _benmore_broadcasts WHERE slug = ?", slug).Scan(&ownerID)
	if ownerID != 0 && ownerID != session.UserID && !session.IsAdmin() {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "not the publisher"})
		return
	}
	app.DB.Exec("DELETE FROM _benmore_broadcasts WHERE slug = ?", slug)
	httpJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func broadcastStats(w http.ResponseWriter, r *http.Request, app *App) {
	slug := strings.TrimSpace(r.PathValue("slug"))
	if !isValidBroadcastSlug(slug) {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "slug required"})
		return
	}
	var viewers int
	var createdAt string
	err := app.DB.QueryRow("SELECT viewer_count, created_at FROM _benmore_broadcasts WHERE slug = ?", slug).Scan(&viewers, &createdAt)
	if err != nil {
		httpJSON(w, http.StatusOK, map[string]any{"live": false, "viewers": 0})
		return
	}
	httpJSON(w, http.StatusOK, map[string]any{
		"live":       true,
		"viewers":    viewers,
		"started_at": createdAt,
	})
}

// broadcastAllowAnon mirrors the ws_anonymous policy - same opt-in
// flag that lets anon viewers participate in bm.room.
func broadcastAllowAnon(app *App) bool {
	if app == nil || app.Design == nil || app.Design.Features == nil {
		return false
	}
	return app.Design.Features.WSAnonymous != nil && *app.Design.Features.WSAnonymous
}

// isValidBroadcastSlug - same charset rules as scopedRoomID so slugs
// can double as room names without escaping. Bounded length keeps the
// audit trail readable in logs.
func isValidBroadcastSlug(s string) bool {
	if s == "" || len(s) > 128 {
		return false
	}
	for i := 0; i < len(s); i++ {
		b := s[i]
		ok := (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') ||
			b == '_' || b == '-' || b == '.' || b == ':'
		if !ok {
			return false
		}
	}
	return true
}

// ============================================================
// Cloudflare Realtime SFU API client
// ============================================================
//
// CF's REST API (current as of 2026):
//
//   POST https://rtc.live.cloudflare.com/v1/apps/{APP_ID}/sessions/new
//     Authorization: Bearer {APP_TOKEN}
//     → { "sessionId": "abc..." }
//
//   POST .../sessions/{SID}/tracks/new
//     {
//       "sessionDescription": { "type": "offer", "sdp": "v=0..." },
//       "tracks": [{ "location": "local",  "mid": "0", "trackName": "..." }, ...]
//     }
//     → { "sessionDescription": { "type": "answer", "sdp": "..." } }
//
//   For subscribers - "pull" tracks from another session:
//     "tracks": [{ "location": "remote", "trackName": "...", "sessionId": "PUB_SID" }]
//
// We use the SDP-passthrough mode: just give CF the client's offer
// verbatim, ask for "all tracks" by inferring them from the m-lines.
// This is the simplest path that handles 1 video + 1 audio track,
// which is the canonical livestream shape.

const cfRealtimeAPIBase = "https://rtc.live.cloudflare.com/v1"

type cfSessionResp struct {
	SessionID string `json:"sessionId"`
}

type cfSDPDesc struct {
	Type string `json:"type"`
	SDP  string `json:"sdp"`
}

type cfTracksReq struct {
	SessionDescription cfSDPDesc `json:"sessionDescription"`
	Tracks             []cfTrack `json:"tracks"`
}

type cfTrack struct {
	Location  string `json:"location"`           // "local" (publish) | "remote" (pull)
	Mid       string `json:"mid,omitempty"`      // local: SDP m-line index
	TrackName string `json:"trackName"`
	SessionID string `json:"sessionId,omitempty"` // remote: source publisher's session
}

type cfTracksResp struct {
	SessionDescription cfSDPDesc `json:"sessionDescription"`
	Tracks             []cfTrack `json:"tracks,omitempty"`
}

func cfCreateSession(cfg sfuConfig) (string, error) {
	body, err := cfPost(cfg, fmt.Sprintf("/apps/%s/sessions/new", cfg.appID), nil)
	if err != nil {
		return "", err
	}
	var resp cfSessionResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("session parse: %w (body=%q)", err, string(body))
	}
	if resp.SessionID == "" {
		return "", fmt.Errorf("empty sessionId (body=%q)", string(body))
	}
	return resp.SessionID, nil
}

// cfPublishTracks ships the publisher's offer to CF. We let CF infer
// tracks from the SDP by passing one "local" track per m-line found.
// CF returns an answer SDP; we relay it verbatim to the client.
func cfPublishTracks(cfg sfuConfig, sessionID, sdpOffer string) (string, error) {
	mids := extractMids(sdpOffer)
	tracks := make([]cfTrack, 0, len(mids))
	for _, mid := range mids {
		tracks = append(tracks, cfTrack{
			Location:  "local",
			Mid:       mid,
			TrackName: "track-" + mid,
		})
	}
	req := cfTracksReq{
		SessionDescription: cfSDPDesc{Type: "offer", SDP: sdpOffer},
		Tracks:             tracks,
	}
	body, err := cfPost(cfg, fmt.Sprintf("/apps/%s/sessions/%s/tracks/new", cfg.appID, sessionID), req)
	if err != nil {
		return "", err
	}
	var resp cfTracksResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("tracks parse: %w (body=%q)", err, string(body))
	}
	return resp.SessionDescription.SDP, nil
}

// cfPullTracks asks CF to forward the publisher's tracks into the
// subscriber's session. The subscriber's SDP offer tells CF what
// directions / codecs it can accept; we list the publisher's tracks
// as "remote" sources to be plumbed in.
func cfPullTracks(cfg sfuConfig, subSessionID, pubSessionID, sdpOffer string) (string, error) {
	mids := extractMids(sdpOffer)
	tracks := make([]cfTrack, 0, len(mids))
	for _, mid := range mids {
		tracks = append(tracks, cfTrack{
			Location:  "remote",
			TrackName: "track-" + mid,
			SessionID: pubSessionID,
		})
	}
	req := cfTracksReq{
		SessionDescription: cfSDPDesc{Type: "offer", SDP: sdpOffer},
		Tracks:             tracks,
	}
	body, err := cfPost(cfg, fmt.Sprintf("/apps/%s/sessions/%s/tracks/new", cfg.appID, subSessionID), req)
	if err != nil {
		return "", err
	}
	var resp cfTracksResp
	if err := json.Unmarshal(body, &resp); err != nil {
		return "", fmt.Errorf("pull parse: %w (body=%q)", err, string(body))
	}
	return resp.SessionDescription.SDP, nil
}

// cfPost - small bearer-auth POST helper. 5s timeout; small body cap.
func cfPost(cfg sfuConfig, path string, body any) ([]byte, error) {
	url := cfRealtimeAPIBase + path
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("marshal: %w", err)
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest("POST", url, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("req build: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.appToken)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("do: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<17)) // 128KB cap; SDPs can run 5-30KB
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(respBody)))
	}
	return respBody, nil
}

// extractMids parses SDP m-line MIDs (the integer IDs after "a=mid:").
// Falls back to per-m-line index when MIDs are absent. CF requires
// a track entry per direction we want to plumb, so missing this
// causes the SFU to ignore one side of the call.
func extractMids(sdp string) []string {
	var mids []string
	idx := 0
	for _, line := range strings.Split(sdp, "\n") {
		line = strings.TrimRight(line, "\r")
		if strings.HasPrefix(line, "m=") {
			// New m-line. If no MID is set on this section, fall back to index.
			mids = append(mids, fmt.Sprintf("%d", idx))
			idx++
		}
		if strings.HasPrefix(line, "a=mid:") && len(mids) > 0 {
			mids[len(mids)-1] = strings.TrimSpace(strings.TrimPrefix(line, "a=mid:"))
		}
	}
	return mids
}
