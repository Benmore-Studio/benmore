//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Realtime change fan-out runs off the request path.
//
// A CRUD mutation used to deliver its {table, action} event to every SSE and
// WebSocket client inline, under the hub lock, revalidating each client's
// session against the database first: two or more queries per connected
// client per write, paid by the writer's request. Now:
//
//   - the writer enqueues the event on its app's dispatcher (one goroutine per
//     app, a bounded FIFO queue) and returns; query-cache invalidation stays
//     synchronous so read-your-writes holds;
//   - the dispatcher snapshots the hub under its read lock and releases it
//     before any authorization, so no I/O or DB work happens under the lock;
//   - cheap filters run first (app, tenant, owner, subscription) and only the
//     clients that survive them consult their principal, whose credential
//     check is cached for realtimePrincipalTTL;
//   - one goroutine per app delivers events in enqueue order, so every
//     connection sees that app's events in order.
//
// The dispatcher stops with app.Stop (a hot reload or shutdown), first
// delivering what was already queued. An app with no Stop channel (synthetic
// in-process apps) or one already stopped is delivered inline.
const realtimeDispatchQueueSize = 4096

// realtimeChange is one {table, action} event and the scope it was raised in.
type realtimeChange struct {
	table, action, groupID string
	userID                 int64
}

type realtimeDispatchItem struct {
	change  realtimeChange
	barrier chan struct{} // non-nil: a flush marker, closed when reached
}

type realtimeDispatcher struct {
	app    *App
	stop   <-chan struct{}
	queue  chan realtimeDispatchItem
	closed bool // guarded by realtimeDispatchers.mu
}

var realtimeDispatchers = struct {
	mu sync.Mutex
	m  map[*App]*realtimeDispatcher
}{m: map[*App]*realtimeDispatcher{}}

var (
	realtimeDispatchDropped atomic.Int64
	realtimeDropLogMu       sync.Mutex
	realtimeDropLogAt       time.Time
)

// dispatchRealtimeChange queues a change for delivery to the app's SSE and
// WebSocket clients without blocking the caller.
func dispatchRealtimeChange(app *App, change realtimeChange) {
	if app == nil {
		return
	}
	realtimeDispatchers.mu.Lock()
	d := realtimeDispatchers.m[app]
	if d == nil || d.closed {
		d = startRealtimeDispatcher(app)
		if d == nil {
			realtimeDispatchers.mu.Unlock()
			deliverRealtimeChange(app, change)
			return
		}
		realtimeDispatchers.m[app] = d
	}
	select {
	case d.queue <- realtimeDispatchItem{change: change}:
		realtimeDispatchers.mu.Unlock()
	default:
		realtimeDispatchers.mu.Unlock()
		realtimeDispatchDrop(app, change)
	}
}

// startRealtimeDispatcher starts a dispatcher bound to the app's current Stop
// generation, or returns nil when there is none to bind to. Called with
// realtimeDispatchers.mu held.
func startRealtimeDispatcher(app *App) *realtimeDispatcher {
	// TryRLock: a caller that already holds app.mu (or a reload waiting for
	// it) must never deadlock a broadcast; it is delivered inline instead.
	if !app.mu.TryRLock() {
		return nil
	}
	stop := app.Stop
	app.mu.RUnlock()
	if stop == nil {
		return nil
	}
	select {
	case <-stop:
		return nil
	default:
	}
	d := &realtimeDispatcher{app: app, stop: stop, queue: make(chan realtimeDispatchItem, realtimeDispatchQueueSize)}
	safeGo("realtime.dispatch", d.run)
	return d
}

func (d *realtimeDispatcher) run() {
	for {
		select {
		case item := <-d.queue:
			d.handle(item)
		case <-d.stop:
			// No enqueue can reach this queue once closed is set under the
			// registry lock, so the drain below sees every queued item.
			realtimeDispatchers.mu.Lock()
			d.closed = true
			if realtimeDispatchers.m[d.app] == d {
				delete(realtimeDispatchers.m, d.app)
			}
			realtimeDispatchers.mu.Unlock()
			for {
				select {
				case item := <-d.queue:
					d.handle(item)
				default:
					return
				}
			}
		}
	}
}

func (d *realtimeDispatcher) handle(item realtimeDispatchItem) {
	if item.barrier != nil {
		close(item.barrier)
		return
	}
	deliverRealtimeChange(d.app, item.change)
}

// realtimeFlush waits until every event queued so far has been delivered.
// Tests use it; production code never needs to.
func realtimeFlush() {
	realtimeDispatchers.mu.Lock()
	var waits []chan struct{}
	for _, d := range realtimeDispatchers.m {
		if d.closed {
			continue
		}
		b := make(chan struct{})
		// A blocking send would hold the registry lock while the queue is
		// full; skip such a dispatcher's barrier only if it cannot be queued.
		select {
		case d.queue <- realtimeDispatchItem{barrier: b}:
			waits = append(waits, b)
		default:
		}
	}
	realtimeDispatchers.mu.Unlock()
	for _, b := range waits {
		<-b
	}
}

func realtimeDispatchDrop(app *App, change realtimeChange) {
	n := realtimeDispatchDropped.Add(1)
	realtimeDropLogMu.Lock()
	defer realtimeDropLogMu.Unlock()
	if time.Since(realtimeDropLogAt) < 10*time.Second {
		return
	}
	realtimeDropLogAt = time.Now()
	name := ""
	if app != nil {
		name = filepath.Base(app.Dir)
	}
	log.Printf("  realtime: dispatch queue full for app %q; dropped %s/%s (%d dropped since start)", name, change.table, change.action, n)
}

// realtimeAudience is who may receive one change event in full.
type realtimeAudience struct {
	// tenant, when set, limits the event to that tenant's clients (and
	// admins); other clients receive nothing.
	tenant string
	// ownerOnly sends the full event only to owner (and admins); every other
	// reader of the table receives the generic refresh, which names no table.
	ownerOnly bool
	owner     int64
}

// realtimeAudienceFor derives an event's audience from the scope it was raised
// in and the table's read access mode, so every entry point - a session's
// Broadcast, BroadcastScopedDirect, BroadcastUnscoped and cluster events -
// applies the same row policy rowScopeClause applies to reads:
//
//   - anon/everyone tables: the scope as given (Broadcast already unscopes them);
//   - member-of, owner_or_role and explicitly declared self: the actor sees the
//     event, other readers get the generic refresh, even inside one tenant,
//     since membership, role tiers and ownership can't be resolved per client
//     without the row;
//   - group-keyed tables: the raising tenant; with no tenant, admins and the
//     actor only (others get the generic refresh);
//   - owner (user_id) tables: the owner; with no owner, admins only.
//
// A table with no row-level scope keeps the scope as given.
func realtimeAudienceFor(app *App, table, groupID string, userID int64) realtimeAudience {
	a := realtimeAudience{tenant: groupID, owner: userID}
	if groupID == "0" {
		a.tenant = ""
	}
	a.ownerOnly = a.tenant == "" && userID > 0
	if app == nil || table == "" {
		return a
	}
	hasUID := hasColumn(app, table, "user_id")
	grouped := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	mode := app.Access.ModeFor(table, OpRead, hasUID, grouped)
	if mode == "anon" || mode == "everyone" {
		return a
	}
	rowScoped := false
	switch {
	case strings.HasPrefix(mode, "member-of:"), strings.HasPrefix(mode, "owner_or_role:"), explicitSelfFor(app, table, OpRead):
		rowScoped = true
	case grouped:
		rowScoped = a.tenant == ""
	case hasUID:
		rowScoped = true
	}
	if rowScoped {
		a.ownerOnly = true
		if a.owner <= 0 {
			a.owner = realtimeNoOwner
		}
	}
	return a
}

// classify reports whether a client receives nothing (skip) or the full event
// (full; otherwise the generic refresh).
func (a realtimeAudience) classify(isAdmin bool, groupID string, userID int64) (skip, full bool) {
	if a.tenant != "" && !isAdmin && groupID != a.tenant {
		return true, false
	}
	return false, !a.ownerOnly || isAdmin || userID == a.owner
}

const realtimeSSEGenericRefresh = `{"table":"","action":"refresh"}`

var realtimeWSGenericRefresh, _ = json.Marshal(wsServerMsg{Type: "change", Action: "refresh"})

// deliverRealtimeChange fans one change out to this process's SSE and
// WebSocket clients of app. It never holds a hub lock while authorizing.
func deliverRealtimeChange(app *App, change realtimeChange) {
	if change.table == "" {
		deliverRealtimeRefresh(app)
		return
	}
	audience := realtimeAudienceFor(app, change.table, change.groupID, change.userID)

	sseMsg := fmt.Sprintf(`{"table":"%s","action":"%s"}`, change.table, change.action)
	sseHub.mu.RLock()
	sseTargets := make([]*sseClient, 0, len(sseHub.clients))
	for c := range sseHub.clients {
		if realtimeSameApp(app, c.principal.app) {
			sseTargets = append(sseTargets, c)
		}
	}
	sseHub.mu.RUnlock()
	for _, c := range sseTargets {
		skip, full := audience.classify(c.isAdmin, c.groupID, c.userID)
		if skip || !c.principal.canRead(change.table, change.userID) {
			continue
		}
		msg := realtimeSSEGenericRefresh
		if full {
			msg = sseMsg
		}
		select {
		case c.ch <- msg:
		default: // drop if the client is slow
		}
	}

	wsMsg, _ := json.Marshal(wsServerMsg{Type: "change", Table: change.table, Action: change.action})
	wsHub.mu.RLock()
	wsTargets := make([]*wsClient, 0, len(wsHub.clients))
	for c := range wsHub.clients {
		if realtimeSameApp(app, c.principal.app) {
			wsTargets = append(wsTargets, c)
		}
	}
	wsHub.mu.RUnlock()
	for _, c := range wsTargets {
		skip, full := audience.classify(c.isAdmin, c.groupID, c.userID)
		if skip || (full && !wsClientSubscribed(c, change.table)) ||
			!c.principal.canRead(change.table, change.userID) {
			continue
		}
		msg := realtimeWSGenericRefresh
		if full {
			msg = wsMsg
		}
		select {
		case c.send <- msg:
		default:
		}
	}
}

// deliverRealtimeRefresh sends the generic refresh to every live stream of
// app. A table-less change (an opaque SQL write, an import, a reset) names no
// table or row, so it is the generic refresh itself: no table read gate
// applies (canRead("") matched no table, so it reached no one), only a
// current credential.
func deliverRealtimeRefresh(app *App) {
	sseHub.mu.RLock()
	sseTargets := make([]*sseClient, 0, len(sseHub.clients))
	for c := range sseHub.clients {
		if realtimeSameApp(app, c.principal.app) {
			sseTargets = append(sseTargets, c)
		}
	}
	sseHub.mu.RUnlock()
	for _, c := range sseTargets {
		if _, valid := c.principal.current(); !valid {
			continue
		}
		select {
		case c.ch <- realtimeSSEGenericRefresh:
		default:
		}
	}
	wsHub.mu.RLock()
	wsTargets := make([]*wsClient, 0, len(wsHub.clients))
	for c := range wsHub.clients {
		if realtimeSameApp(app, c.principal.app) {
			wsTargets = append(wsTargets, c)
		}
	}
	wsHub.mu.RUnlock()
	for _, c := range wsTargets {
		if _, valid := c.principal.current(); !valid {
			continue
		}
		select {
		case c.send <- realtimeWSGenericRefresh:
		default:
		}
	}
}
