//go:build !cli

package main

import (
	"database/sql"
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
	// The legacy group_id column has INTEGER affinity. Bind opaque tenant IDs
	// as bytes so SQLite cannot coerce "001" to 1 or "1e2" to 100. Pollers scan
	// both these bytes and existing integer rows into strings unchanged.
	_, err := db.Exec(
		`INSERT INTO _benmore_events (table_name, action, group_id, user_id) VALUES (?, ?, ?, ?)`,
		table, action, []byte(groupID), userID,
	)
	if err != nil {
		log.Printf("PUBSUB ERROR: failed to publish event: %s", err)
	}
}

// eventPoller tracks the last-seen event ID and polls for new events.
type eventPoller struct {
	db      *sql.DB
	app     *App
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
		app:     app,
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
		BroadcastChangeScoped(ep.app, table, action, groupID, userID)
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
		groupID = session.EffectiveGroupID()
		userID = session.UserID
		// Meter the mutation
		scope := meterScope(session)
		Increment(app, scope, "row_"+action+"s")
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
		// Single instance: hand the event to this app's dispatcher; the
		// writer's request does not pay for the fan-out (realtime_dispatch.go).
		dispatchRealtimeChange(app, realtimeChange{table: table, action: action, groupID: groupID, userID: userID})
	}
}

// BroadcastUnscoped is for broadcasts without a session (system events,
// cascades). The caller names no tenant or owner, so delivery derives the
// audience from the table's read access mode (realtimeAudienceFor): a
// publicly readable table reaches every reader, while a tenant, owner or
// membership-scoped table reaches admins in full and other readers only as
// the generic refresh, which names no table. Same single/cluster mode logic
// as Broadcast.
func BroadcastUnscoped(app *App, table, action string) {
	InvalidateQueryCacheForTable(table)

	if IsClusterMode() {
		PublishEvent(app.DB, table, action, "", 0)
	} else {
		dispatchRealtimeChange(app, realtimeChange{table: table, action: action})
	}
}

// BroadcastScopedDirect is for broadcasts where groupID/userID are known
// but no session is available (e.g., notifications, workflow timeouts).
func BroadcastScopedDirect(app *App, table, action string, groupID string, userID int64) {
	InvalidateQueryCacheForTable(table)

	if IsClusterMode() {
		PublishEvent(app.DB, table, action, groupID, userID)
	} else {
		dispatchRealtimeChange(app, realtimeChange{table: table, action: action, groupID: groupID, userID: userID})
	}
}
