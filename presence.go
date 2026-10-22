//go:build !cli

package main

// Presence - framework primitive for "who's live in this thing right now."
// Replaces the hand-rolled patterns multiple apps wrote independently:
//
//   1. Client `pagehide` + sendBeacon to mark "I've left"
//   2. 20-second heartbeat PATCH so the server knows the user is alive
//   3. Server-side cron that deletes participants whose last heartbeat
//      was more than N seconds ago (browser crashed, tab killed, etc.)
//
// Same three layers, same code, every time. This module bakes them in
// so apps can call `bm.presence('huddle:42')` and get a working presence
// pipeline including SSE invalidation on join/leave.
//
// Wire format:
//
//   POST /api/_presence/heartbeat
//       body: { slug, action: 'join' | 'heartbeat' | 'leave' }
//       returns: { ok, members: number, expires_in_s: number }
//
//   GET  /api/_presence?slug=...
//       returns: { slug, members: [{ user_id, joined_at, last_seen }], count }
//
// SSE: every join/leave/sweep-expiry fires `{table:"_benmore_presence",
// action:"insert"|"delete"}` to signed-in streams (a join or leave only
// within the caller's tenant in an app with groups:) so clients re-fetch.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Heartbeat staleness window. Clients send a heartbeat every 20s; the
// server treats anything older than 90s as departed. The sweep loop
// runs every 60s.
// presenceTable is the framework table behind bm.presence; its realtime
// events drive bm.presence(slug).onChange.
const presenceTable = "_benmore_presence"

const (
	presenceExpiryWindow = 90 * time.Second
	presenceSweepEvery   = 60 * time.Second
	presenceHeartbeatS   = 20 // advisory; surfaced in response so SDK doesn't hardcode it
)

// EnsurePresenceTable creates the framework's per-app presence table.
// Idempotent. Called once at app boot.
func EnsurePresenceTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_presence (
		slug TEXT NOT NULL,
		user_id INTEGER NOT NULL,
		joined_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		last_seen_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
		PRIMARY KEY (slug, user_id)
	)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_benmore_presence_last_seen ON _benmore_presence(last_seen_at)`)
}

// RegisterPresenceRoutes mounts /api/_presence + /api/_presence/heartbeat.
// Auth required - anonymous presence makes no sense for our use cases
// (huddles, live rooms, stream watchers); if anon presence is ever a
// real ask, we can add features.presence_anonymous.
func RegisterPresenceRoutes(mux appRouteRegistrar, app *App) {
	mux.HandleFunc("POST /api/_presence/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		// The body is read before the CSRF check because it can carry the
		// token: bm.presence leaves with navigator.sendBeacon on pagehide,
		// and a beacon cannot set X-CSRF-Token, so the SDK sends the token as
		// `_csrf` in the JSON payload. It is validated like a header token.
		var body struct {
			Slug   string `json:"slug"`
			Action string `json:"action"`
			CSRF   string `json:"_csrf"`
		}
		decodeErr := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&body)
		if !isBearerAuth(r) && !(body.CSRF != "" && validateCSRFToken(r, body.CSRF)) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		if decodeErr != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
			return
		}
		slug := strings.TrimSpace(body.Slug)
		if slug == "" || len(slug) > 200 || !presenceSlugUsable(slug) {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "slug required (1-200 chars, no NUL)"})
			return
		}
		action := strings.ToLower(strings.TrimSpace(body.Action))
		if action == "" {
			action = "heartbeat"
		}
		// A slug is a room name: declared ws_rooms rules decide who may be
		// present in it, as they do for bm.room and bm.broadcast. Leaving
		// stays open so a member removed mid-session can still clear its row.
		if action != "leave" && !roomMembershipAllowed(app, session, session.UserID, slug) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "not a member of this room"})
			return
		}
		// Tenant-namespaced storage key (cross-tenant presence isolation).
		key := presenceKey(app, session, slug)
		switch action {
		case "join":
			// INSERT … ON CONFLICT bumps last_seen if already present.
			_, err := app.DB.Exec(
				`INSERT INTO _benmore_presence (slug, user_id, joined_at, last_seen_at)
				 VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
				 ON CONFLICT(slug, user_id) DO UPDATE SET last_seen_at = CURRENT_TIMESTAMP`,
				key, session.UserID,
			)
			if err != nil {
				serverErrorJSON(w, r, app, "presence", err, "db error")
				return
			}
			BroadcastScopedDirect(app, presenceTable, "insert", presenceTenant(app, session), 0)
		case "heartbeat":
			_, err := app.DB.Exec(
				`UPDATE _benmore_presence SET last_seen_at = CURRENT_TIMESTAMP WHERE slug = ? AND user_id = ?`,
				key, session.UserID,
			)
			if err != nil {
				serverErrorJSON(w, r, app, "presence", err, "db error")
				return
			}
		case "leave":
			_, err := app.DB.Exec(`DELETE FROM _benmore_presence WHERE slug = ? AND user_id = ?`, key, session.UserID)
			if err != nil {
				serverErrorJSON(w, r, app, "presence", err, "db error")
				return
			}
			BroadcastScopedDirect(app, presenceTable, "delete", presenceTenant(app, session), 0)
		default:
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "action must be join | heartbeat | leave"})
			return
		}
		count := presenceMemberCount(app.DB, key)
		httpJSON(w, http.StatusOK, map[string]any{
			"ok":           true,
			"members":      count,
			"expires_in_s": int(presenceExpiryWindow.Seconds()),
			"heartbeat_s":  presenceHeartbeatS,
		})
	})

	mux.HandleFunc("GET /api/_presence", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		slug := strings.TrimSpace(r.URL.Query().Get("slug"))
		if slug == "" || !presenceSlugUsable(slug) {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "slug query param required (no NUL)"})
			return
		}
		if !roomMembershipAllowed(app, session, session.UserID, slug) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "not a member of this room"})
			return
		}
		members := presenceMembers(app.DB, presenceKey(app, session, slug))
		httpJSON(w, http.StatusOK, map[string]any{
			"slug":    slug,
			"count":   len(members),
			"members": members,
		})
	})
}

// presenceKey namespaces a slug by the caller's effective tenant (act-as
// aware, as every other tenant surface) so a user in one group can't read or
// write another group's presence (the table has no tenant column, and slugs
// like "huddle:42" are guessable across tenants). The NUL separator can't
// appear in a validated slug (presenceSlugUsable). No-op for
// non-multi-tenant apps.
func presenceKey(app *App, session *Session, slug string) string {
	if app.Group != nil && app.Group.Key != "" && session != nil && session.EffectiveGroupID() != "" {
		return session.EffectiveGroupID() + "\x00" + slug
	}
	return slug
}

// presenceTenant is the tenant a presence change is announced in: the
// caller's effective tenant in an app with groups:, else none.
func presenceTenant(app *App, session *Session) string {
	if app.Group != nil && app.Group.Key != "" && session.EffectiveHasGroup() {
		return session.EffectiveGroupID()
	}
	return ""
}

// presenceSlugUsable refuses a slug holding NUL, presenceKey's tenant
// separator: a caller without a tenant is keyed by the bare slug, so
// "<group>\x00<slug>" would read and write that group's presence list.
func presenceSlugUsable(slug string) bool {
	return !strings.ContainsRune(slug, 0)
}

// presenceMemberCount returns the live count for a slug, honoring the
// expiry window so a sweep race doesn't surface stale rows.
func presenceMemberCount(db *sql.DB, slug string) int {
	var n int
	db.QueryRow(
		`SELECT COUNT(*) FROM _benmore_presence
		 WHERE slug = ? AND last_seen_at > datetime('now', ?)`,
		slug, fmt.Sprintf("-%d seconds", int(presenceExpiryWindow.Seconds())),
	).Scan(&n)
	return n
}

// presenceMembers lists the live participants for a slug.
func presenceMembers(db *sql.DB, slug string) []map[string]any {
	rows, err := db.Query(
		`SELECT user_id, joined_at, last_seen_at FROM _benmore_presence
		 WHERE slug = ? AND last_seen_at > datetime('now', ?)
		 ORDER BY joined_at ASC`,
		slug, fmt.Sprintf("-%d seconds", int(presenceExpiryWindow.Seconds())),
	)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var uid int64
		var joined, lastSeen string
		if err := rows.Scan(&uid, &joined, &lastSeen); err != nil {
			continue
		}
		out = append(out, map[string]any{
			"user_id":      uid,
			"joined_at":    joined,
			"last_seen_at": lastSeen,
		})
	}
	if out == nil {
		out = []map[string]any{}
	}
	return out
}

// StartPresenceSweeper runs the cron-equivalent goroutine that DELETEs
// expired presence rows. Fires BroadcastUnscoped on every sweep that
// removed at least one row so connected clients re-fetch and stop
// showing ghost participants.
//
// Stops when app.Stop closes (matches the cron + jobs worker pattern).
func StartPresenceSweeper(app *App) {
	stop := app.workerStopGeneration()
	safeGo("presence.sweep", func() {
		ticker := time.NewTicker(presenceSweepEvery)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				res, err := app.DB.Exec(
					`DELETE FROM _benmore_presence WHERE last_seen_at <= datetime('now', ?)`,
					fmt.Sprintf("-%d seconds", int(presenceExpiryWindow.Seconds())),
				)
				if err != nil {
					continue
				}
				if n, _ := res.RowsAffected(); n > 0 {
					BroadcastUnscoped(app, presenceTable, "delete")
				}
			}
		}
	})
}
