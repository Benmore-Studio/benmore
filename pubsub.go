//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"sync"
	"time"
)

// Horizontal scaling support via SQLite-based pub/sub.
//
// Single instance (default): Broadcast calls SSE hub directly - zero overhead.
// Multi-instance (BENMORE_CLUSTER=true): Broadcast writes to _benmore_events table,
// a background poller reads new events and distributes to local SSE hub.
// This ensures all instances behind a load balancer stay in sync.

// IsClusterMode returns true when BENMORE_CLUSTER=true is set.
func IsClusterMode() bool {
	return os.Getenv("BENMORE_CLUSTER") == "true"
}

// EnsureEventsTable creates the pub/sub events table for cluster mode.
func EnsureEventsTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_events (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		table_name TEXT NOT NULL,
		action TEXT NOT NULL,
		group_id INTEGER DEFAULT 0,
		user_id INTEGER DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_benmore_events_created ON _benmore_events(created_at)`)
}

// PublishEvent inserts a change event into the shared events table.
func PublishEvent(db *sql.DB, table, action string, groupID string, userID int64) {
	_, err := db.Exec(
		`INSERT INTO _benmore_events (table_name, action, group_id, user_id) VALUES (?, ?, ?, ?)`,
		table, action, groupID, userID,
	)
	if err != nil {
		log.Printf("PUBSUB ERROR: failed to publish event: %s", err)
	}
}

// eventPoller tracks the last-seen event ID and polls for new events.
type eventPoller struct {
	db      *sql.DB
	lastID  int64
	stopCh  chan struct{}
	appStop chan struct{} // H-14: tied to app.Stop so a hot reload tears the poller down
	once    sync.Once
}

// StartEventPoller launches a background goroutine that polls _benmore_events
// for new entries and pushes them into the local SSE hub.
//
// H-14: the returned *eventPoller is discarded by the caller (server.go), so
// nothing ever closes ep.stopCh. Pre-fix that meant every hot reload spawned a
// fresh pair of poller goroutines that lived forever (goroutine + DB-handle
// leak) and a panic in one crashed the whole process (raw `go`). We now (a)
// bind the goroutines' lifecycle to app.Stop in addition to ep.stopCh, so a
// reload/shutdown reaps them even though the handle is dropped, and (b) launch
// them via safeGo so a panic is recovered + logged instead of fatal.
func StartEventPoller(app *App) *eventPoller {
	ep := &eventPoller{
		db:      app.DB,
		stopCh:  make(chan struct{}),
		appStop: app.Stop,
	}

	// Initialize lastID to current max so we don't replay old events on startup
	var maxID sql.NullInt64
	app.DB.QueryRow("SELECT MAX(id) FROM _benmore_events").Scan(&maxID)
	if maxID.Valid {
		ep.lastID = maxID.Int64
	}

	safeGo("pubsub.poller", ep.run)
	safeGo("pubsub.cleanup", ep.cleanup)

	log.Printf("  pubsub: event poller started (cluster mode)")
	return ep
}

func (ep *eventPoller) run() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ep.stopCh:
			return
		case <-ep.appStop:
			return
		case <-ticker.C:
			ep.poll()
		}
	}
}

func (ep *eventPoller) poll() {
	rows, err := ep.db.Query(
		`SELECT id, table_name, action, group_id, user_id FROM _benmore_events WHERE id > ? ORDER BY id`,
		ep.lastID,
	)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id int64
		var table, action string
		var groupID string
		var userID int64
		if err := rows.Scan(&id, &table, &action, &groupID, &userID); err != nil {
			continue
		}
		// Distribute to local SSE + WS hubs - BroadcastChangeScoped handles both
		BroadcastChangeScoped(table, action, groupID, userID)
		ep.lastID = id
	}
}

// cleanup removes events older than 5 minutes every 60 seconds.
func (ep *eventPoller) cleanup() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ep.stopCh:
			return
		case <-ep.appStop:
			return
		case <-ticker.C:
			cutoff := time.Now().Add(-5 * time.Minute).UTC().Format("2006-01-02 15:04:05")
			ep.db.Exec("DELETE FROM _benmore_events WHERE created_at < ?", cutoff)
		}
	}
}

// Stop shuts down the event poller.
func (ep *eventPoller) Stop() {
	ep.once.Do(func() { close(ep.stopCh) })
}

// Broadcast is the unified entry point for change notifications.
// It handles cache invalidation, metering, and SSE distribution.
//
// Single instance: directly calls the local SSE hub (fast, no DB write).
// Cluster mode: writes to _benmore_events table; the poller on each instance
// picks up the event and distributes to its local SSE hub.
//
// Scope resolution (v2.7.29): if the declarative access config marks
// this table's read mode as `anon` or `everyone`, the broadcast is
// unscoped - every subscriber gets the full {table, action} event with
// row details. Pre-2.7.29, owner-scoped tables (those with user_id)
// always sent a generic "refresh" hint to non-owners, even when the
// developer had explicitly declared the rows public via access.read=anon.
// That broke live-chat / public-feed patterns where every viewer needs
// to see the actual insert. Authoring a row in a private table still
// scopes to owner+admins as before.
func Broadcast(app *App, table, action string, session *Session) {
	var groupID string
	var userID int64
	if session != nil {
		groupID = session.GroupID
		userID = session.UserID
		// Meter the mutation
		scope := meterScope(session)
		Increment(scope, "row_"+action+"s")
	}

	// If the table is publicly readable per access: config, the row
	// is already public - there's no privacy reason to hide it from
	// any subscriber. Treat as unscoped so every connected client gets
	// the full event with row data, matching what they'd see by
	// re-fetching anyway.
	if app != nil && app.Access != nil {
		hasUID := hasColumn(app, table, "user_id")
		hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
		readMode := app.Access.ModeFor(table, "read", hasUID, hasGroupKey)
		if readMode == "anon" || readMode == "everyone" {
			groupID = ""
			userID = 0
		}
	}

	// Cache invalidation is always local - each instance manages its own cache
	InvalidateQueryCacheForTable(table)

	if IsClusterMode() {
		// Cluster mode: write to shared events table; pollers distribute
		PublishEvent(app.DB, table, action, groupID, userID)
	} else {
		// Single instance: direct SSE + WS broadcast (no DB overhead)
		broadcastToSSE(table, action, groupID, userID)
		BroadcastWSChange(table, action, groupID, userID)
	}
}

// BroadcastUnscoped is for broadcasts without a session (system events, cascades).
// Same single/cluster mode logic as Broadcast.
func BroadcastUnscoped(app *App, table, action string) {
	InvalidateQueryCacheForTable(table)

	if IsClusterMode() {
		PublishEvent(app.DB, table, action, "", 0)
	} else {
		broadcastToSSE(table, action, "", 0)
		BroadcastWSChange(table, action, "", 0)
	}
}

// BroadcastScopedDirect is for broadcasts where groupID/userID are known
// but no session is available (e.g., notifications, workflow timeouts).
func BroadcastScopedDirect(app *App, table, action string, groupID string, userID int64) {
	InvalidateQueryCacheForTable(table)

	if IsClusterMode() {
		PublishEvent(app.DB, table, action, groupID, userID)
	} else {
		broadcastToSSE(table, action, groupID, userID)
		BroadcastWSChange(table, action, groupID, userID)
	}
}

// broadcastToSSE pushes a change event directly to the local SSE hub.
// This is the fast path for single-instance mode and the delivery path
// for the cluster-mode poller.
func broadcastToSSE(table, action string, groupID string, userID int64) {
	msg := fmt.Sprintf(`{"table":"%s","action":"%s"}`, table, action)
	genericMsg := `{"table":"","action":"refresh"}`

	sseHub.mu.RLock()
	defer sseHub.mu.RUnlock()
	for client := range sseHub.clients {
		// Server-side scope filtering.
		// Three cases:
		//   1. group-scoped event (groupID is set + not "0"): only
		//      clients in the same group see anything. Admins bypass.
		//   2. owner-scoped event (groupID empty, userID > 0):
		//      the owner sees the full event; other non-admin
		//      clients see a generic refresh (so they know SOMETHING
		//      changed and can re-fetch a scoped list, without
		//      learning which row).
		//   3. unscoped event (groupID empty, userID 0): everyone
		//      sees the full event - used for system-wide cascades
		//      like analytics, config changes, public table updates.
		//
		// Pre-v2.7.5 the owner-scoped check was buggy: the operator-
		// precedence rules in Go meant `groupID == ""` short-
		// circuited the OR, so EVERY non-group event landed in the
		// generic-refresh branch - even for the owner. Effect:
		// owners never got detailed events for their own mutations.
		// Parens added below + explicit "unscoped means broadcast"
		// branch.
		if groupID != "" && groupID != "0" && !client.isAdmin && client.groupID != groupID {
			continue // case 1: wrong group, skip
		}
		ownerScoped := (groupID == "" || groupID == "0") && userID > 0
		if ownerScoped && !client.isAdmin && client.userID != userID {
			// case 2: non-owner gets the generic refresh
			select {
			case client.ch <- genericMsg:
			default:
			}
			continue
		}
		// case 3 (or owner / admin in case 1/2): full event
		select {
		case client.ch <- msg:
		default:
			// Drop if client is slow
		}
	}
}
