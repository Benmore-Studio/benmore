//go:build !cli

package main

// Presence — framework primitive for "who's live in this thing right now."
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
// action:"insert"|"update"|"delete"}` so clients re-fetch the list.

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
// Auth required — anonymous presence makes no sense for our use cases
// (huddles, live rooms, stream watchers); if anon presence is ever a
// real ask, we can add features.presence_anonymous.
func RegisterPresenceRoutes(mux *http.ServeMux, app *App) {
	mux.HandleFunc("POST /api/_presence/heartbeat", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		var body struct {
			Slug   string `json:"slug"`
			Action string `json:"action"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
			return
		}
		slug := strings.TrimSpace(body.Slug)
		if slug == "" || len(slug) > 200 {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "slug required (1-200 chars)"})
			return
		}
		action := strings.ToLower(strings.TrimSpace(body.Action))
		if action == "" {
			action = "heartbeat"
		}
		switch action {
		case "join":
			// INSERT … ON CONFLICT bumps last_seen if already present.
			_, err := app.DB.Exec(
				`INSERT INTO _benmore_presence (slug, user_id, joined_at, last_seen_at)
				 VALUES (?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
				 ON CONFLICT(slug, user_id) DO UPDATE SET last_seen_at = CURRENT_TIMESTAMP`,
				slug, session.UserID,
			)
			if err != nil {
				httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "db error: " + err.Error()})
				return
			}
			BroadcastUnscoped(app, "_benmore_presence", "insert")
		case "heartbeat":
			_, err := app.DB.Exec(
				`UPDATE _benmore_presence SET last_seen_at = CURRENT_TIMESTAMP WHERE slug = ? AND user_id = ?`,
				slug, session.UserID,
			)
			if err != nil {
				httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "db error: " + err.Error()})
				return
			}
		case "leave":
			_, err := app.DB.Exec(`DELETE FROM _benmore_presence WHERE slug = ? AND user_id = ?`, slug, session.UserID)
			if err != nil {
				httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "db error: " + err.Error()})
				return
			}
			BroadcastUnscoped(app, "_benmore_presence", "delete")
		default:
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "action must be join | heartbeat | leave"})
			return
		}
		count := presenceMemberCount(app.DB, slug)
		httpJSON(w, http.StatusOK, map[string]any{
			"ok":             true,
			"members":        count,
			"expires_in_s":   int(presenceExpiryWindow.Seconds()),
			"heartbeat_s":    presenceHeartbeatS,
		})
	})

	mux.HandleFunc("GET /api/_presence", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		slug := strings.TrimSpace(r.URL.Query().Get("slug"))
		if slug == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "slug query param required"})
			return
		}
		members := presenceMembers(app.DB, slug)
		httpJSON(w, http.StatusOK, map[string]any{
			"slug":    slug,
			"count":   len(members),
			"members": members,
		})
	})
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
	safeGo("presence.sweep", func() {
		ticker := time.NewTicker(presenceSweepEvery)
		defer ticker.Stop()
		for {
			select {
			case <-app.Stop:
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
					BroadcastUnscoped(app, "_benmore_presence", "delete")
				}
			}
		}
	})
}
