//go:build !cli

package main

// Realtime side of flows: table events for flow SQL writes, and the
// `run: broadcast` step that sends a server message to a WebSocket room.
//
// Table events. Auto-CRUD announces every mutation through Broadcast; a flow's
// `run: sql` / `run: sql_dynamic` writes used to announce nothing, so a
// bm.live() view of a table written only by flows never refreshed. Each SQL
// step now records the (table, action) pairs its statements wrote, and the
// run's entry point calls announceFlowWrites once the writes are durable:
//
//   - a write made inside the flow's transaction is announced only after that
//     transaction commits; rollback or a failed commit announces nothing;
//   - a write made without a transaction (a non-transactional flow, or an
//     on_error handler, which runs outside the transaction) is durable when
//     its statement returns, so it is announced even if a later step fails.
//
// Delivery is unchanged Broadcast: the event is {table, action} with no row
// data, and every SSE/WebSocket subscriber is checked per event
// (realtimePrincipal.canRead: live session, re-validated at most every
// realtimePrincipalTTL, table read access, token scope; then tenant/owner
// scoping from the flow's session and the table's access mode,
// realtimeAudienceFor). A run with no session
// (cron, webhook, data-event, async job, anonymous) is scoped by
// sessionlessWriteScope instead: to the tenant or owner its trusted trigger
// data names, otherwise to admins (tenant tables) or a generic refresh (owner
// tables), so one tenant's writes never name a table to another tenant.
//
// A cron job has no trigger tenant, so its writes to a tenant table used to
// reach admins only and every member's live view went stale. A write in a run
// with no request at all (cron, and jobs and events that carry no request
// field) that RETURNs the table's tenant column is announced to each tenant
// its rows name (flowReturnedTenants): `UPDATE bookings SET stale = 1 WHERE
// ... RETURNING studio_id`. Those values are the written rows' own, never
// request input. A write that returns no tenant still reaches admins only.

import (
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
)

// flowWriteLog records the distinct (table, action) pairs a flow run wrote,
// split by whether the write happened inside the run's transaction.
type flowWriteLog struct {
	mu    sync.Mutex
	order []flowWriteEntry
	seen  map[flowWriteEntry]bool
	// tenants holds, per entry, the tenants the rows of its RETURNING writes
	// named (flowReturnedTenants); untenanted marks an entry with at least one
	// write whose rows' tenants are unknown.
	tenants    map[flowWriteEntry]map[string]bool
	untenanted map[flowWriteEntry]bool
	// committed runs once the run's transaction commits (announceFlowWrites);
	// a rollback drops it.
	committed []func()
	// reads are read-audit events of the run's transactional SQL, written
	// once the transaction has ended, committed or not (flushFlowTxReadAudit).
	reads []readAuditEntry
}

func (l *flowWriteLog) addReads(entries []readAuditEntry) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.reads = append(l.reads, entries...)
}

func (l *flowWriteLog) takeReads() []readAuditEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	reads := l.reads
	l.reads = nil
	return reads
}

// onCommit queues fn for after the run's transaction commits.
func (l *flowWriteLog) onCommit(fn func()) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.committed = append(l.committed, fn)
}

// takeCommitted returns the queued post-commit functions when committed, and
// empties the queue either way.
func (l *flowWriteLog) takeCommitted(committed bool) []func() {
	l.mu.Lock()
	defer l.mu.Unlock()
	fns := l.committed
	l.committed = nil
	if !committed {
		return nil
	}
	return fns
}

type flowWriteEntry struct {
	table, action string
	inTx          bool
}

func newFlowWriteLog() *flowWriteLog {
	return &flowWriteLog{seen: map[flowWriteEntry]bool{}}
}

// add records writes. tenants is the tenant set the statement's returned
// rows named (only for a single-table write); nil means unknown.
func (l *flowWriteLog) add(writes []sqlWrite, inTx bool, tenants []string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, w := range writes {
		e := flowWriteEntry{table: w.Table, action: w.Action, inTx: inTx}
		if !l.seen[e] {
			l.seen[e] = true
			l.order = append(l.order, e)
		}
		if tenants == nil {
			l.markUntenanted(e)
			continue
		}
		if l.tenants == nil {
			l.tenants = map[flowWriteEntry]map[string]bool{}
		}
		set := l.tenants[e]
		if set == nil {
			set = map[string]bool{}
			l.tenants[e] = set
		}
		for _, g := range tenants {
			if len(set) >= flowReturnedTenantCap && !set[g] {
				// Past the cap the remaining tenants are not named; admins
				// still hear about the write.
				if !l.untenanted[e] {
					log.Printf("flows: a write to %s returned more than %d tenants; the others get no live refresh for it", w.Table, flowReturnedTenantCap)
				}
				l.markUntenanted(e)
				break
			}
			set[g] = true
		}
	}
}

func (l *flowWriteLog) markUntenanted(e flowWriteEntry) {
	if l.untenanted == nil {
		l.untenanted = map[flowWriteEntry]bool{}
	}
	l.untenanted[e] = true
}

// flowReturnedTenantCap bounds the per-tenant events one run sends for one
// table and action.
const flowReturnedTenantCap = 256

// flowDurableWrite is one durable (table, action) and the tenants to tell.
type flowDurableWrite struct {
	sqlWrite
	tenants    map[string]bool
	untenanted bool
}

// take returns the durable writes (all non-transactional ones, plus the
// transactional ones when committed) and empties the log, so a second call
// announces nothing.
func (l *flowWriteLog) take(committed bool) []flowDurableWrite {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []flowDurableWrite
	for _, e := range l.order {
		if !e.inTx || committed {
			out = append(out, flowDurableWrite{sqlWrite: sqlWrite{Table: e.table, Action: e.action}, tenants: l.tenants[e], untenanted: l.untenanted[e]})
		}
	}
	l.order, l.seen = nil, map[flowWriteEntry]bool{}
	l.tenants, l.untenanted = nil, nil
	return out
}

// recordFlowSQLWrites notes the tables an executed flow SQL statement wrote.
// query is the text that ran; affected is the driver's RowsAffected, or -1
// when unknown. A single statement that changed no rows is not a write.
func recordFlowSQLWrites(ctx *FlowContext, query string, affected int64) {
	recordFlowSQLWriteRows(ctx, query, affected, nil)
}

// recordFlowSQLWriteRows is recordFlowSQLWrites for a statement that returned
// rows (a write with RETURNING), whose rows may name their tenants.
func recordFlowSQLWriteRows(ctx *FlowContext, query string, affected int64, rows []map[string]any) {
	if ctx == nil || ctx.Writes == nil || !sqlMayWrite(query) {
		return
	}
	writes, statements := sqlWriteTargets(query)
	if len(writes) == 0 || (statements == 1 && affected == 0) {
		return
	}
	var tenants []string
	if statements == 1 && len(writes) == 1 {
		tenants = flowReturnedTenants(ctx, writes[0].Table, rows)
	}
	ctx.Writes.add(writes, ctx.Tx != nil, tenants)
}

// flowReturnedTenants returns the tenants named by the rows a single-table
// write RETURNed, or nil when they can't be used: the run has a session (its
// own tenant scopes the event) or any request input at all - an HTTP
// request, or request fields carried by a job or event - so no returned
// value can be a caller's choice; the app or table is not tenant-keyed; or a
// row lacks the tenant column. Rows with an empty or 0 tenant name none.
func flowReturnedTenants(ctx *FlowContext, table string, rows []map[string]any) []string {
	if ctx == nil || ctx.App == nil || ctx.Session != nil || ctx.Request != nil || len(rows) == 0 {
		return nil
	}
	ctx.DataMu.Lock()
	requestInput := len(ctx.RequestKeys) > 0
	ctx.DataMu.Unlock()
	app := ctx.App
	if requestInput || app.Group == nil || app.Group.Key == "" {
		return nil
	}
	name, ok := flowAnnounceableTables(app)[strings.ToLower(table)]
	if !ok || !hasColumn(app, name, app.Group.Key) {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, row := range rows {
		found := false
		for col, v := range row {
			if !strings.EqualFold(col, app.Group.Key) {
				continue
			}
			found = true
			if v == nil {
				break
			}
			if g := valueText(v); g != "" && g != "0" && !seen[g] {
				seen[g] = true
				out = append(out, g)
			}
			break
		}
		if !found {
			return nil
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// sqlMayWrite is a cheap prefilter so read-only steps skip tokenizing.
func sqlMayWrite(query string) bool {
	upper := strings.ToUpper(query)
	return strings.Contains(upper, "INSERT") || strings.Contains(upper, "UPDATE") ||
		strings.Contains(upper, "DELETE") || strings.Contains(upper, "REPLACE")
}

// announceFlowWrites broadcasts one table event per distinct (table, action)
// the run durably wrote. committed reports whether the run's transaction (if
// it had one) committed. Only app schema tables are announced - never
// _benmore_*, sqlite_* or full-text shadow tables. It first writes the run's
// deferred read-audit events, whether or not the transaction committed.
func announceFlowWrites(ctx *FlowContext, committed bool) {
	if ctx == nil || ctx.App == nil || ctx.Writes == nil {
		return
	}
	flushFlowTxReadAudit(ctx)
	for _, fn := range ctx.Writes.takeCommitted(committed) {
		fn()
	}
	writes := ctx.Writes.take(committed)
	if len(writes) == 0 {
		return
	}
	tables := flowAnnounceableTables(ctx.App)
	// One announcement per (table, action), merging a table's transactional
	// and non-transactional writes and the tenants their rows returned.
	var order []sqlWrite
	merged := map[sqlWrite]*flowDurableWrite{}
	for _, w := range writes {
		name, ok := tables[strings.ToLower(w.Table)]
		if !ok {
			continue
		}
		key := sqlWrite{Table: name, Action: w.Action}
		m := merged[key]
		if m == nil {
			m = &flowDurableWrite{sqlWrite: key, tenants: map[string]bool{}}
			merged[key] = m
			order = append(order, key)
		}
		for g := range w.tenants {
			m.tenants[g] = true
		}
		m.untenanted = m.untenanted || w.untenanted
	}
	for _, key := range order {
		name, action := key.Table, key.Action
		if ctx.Session != nil {
			Broadcast(ctx.App, name, action, ctx.Session)
			continue
		}
		groupID, userID, public := sessionlessWriteScope(ctx, name)
		if public {
			BroadcastUnscoped(ctx.App, name, action)
			continue
		}
		if m := merged[key]; groupID == realtimeNoTenant && len(m.tenants) > 0 {
			// The written rows' own tenants (flowReturnedTenants).
			for _, g := range slices.Sorted(maps.Keys(m.tenants)) {
				BroadcastScopedDirect(ctx.App, name, action, g, 0)
			}
			if !m.untenanted {
				continue
			}
		}
		BroadcastScopedDirect(ctx.App, name, action, groupID, userID)
	}
}

// Scope values that match no subscriber: a tenant event for no tenant reaches
// only admins; an owner event for no owner gives every other reader the
// generic refresh (realtimeAudience.classify, realtime_dispatch.go).
const (
	realtimeNoTenant       = "__benmore_no_tenant__"
	realtimeNoOwner  int64 = 1<<63 - 1
)

// sessionlessWriteScope picks the audience for a table event from a run with
// no session. Publicly readable tables stay unscoped, as Broadcast treats
// them. Otherwise the tenant (group-keyed tables in a grouped app) or owner
// (user_id tables) comes only from trusted trigger data - the runtime's
// _group_id / user_id identity keys an async job keeps from its caller, or a
// data event's row - never from request input (ctx.RequestKeys).
func sessionlessWriteScope(ctx *FlowContext, table string) (groupID string, userID int64, public bool) {
	app := ctx.App
	trusted := func(key string) string {
		ctx.DataMu.Lock()
		defer ctx.DataMu.Unlock()
		if ctx.RequestKeys[key] {
			return ""
		}
		switch v := ctx.Data[key].(type) {
		case string:
			return v
		case nil:
			return ""
		default:
			return valueText(v)
		}
	}
	tenant := ""
	if app.Group != nil && app.Group.Key != "" {
		for _, key := range []string{"_group_id", app.Group.Key} {
			if g := trusted(key); g != "" && g != "0" {
				tenant = g
				break
			}
		}
	}
	return triggeredWriteScope(app, table, tenant, trusted("user_id"))
}

// triggeredWriteScope is the audience of a write to table made without a
// session, from the tenant and owner its trusted trigger data names (a flow's
// trigger, or the row of the CRUD write that queued a hook job). A publicly
// readable table is unscoped; a tenant-keyed table reaches that tenant, else
// only admins; an owner-keyed table reaches its owner in full and other
// readers as the generic refresh. Any other table is unscoped, and its read
// mode decides the rest (realtimeAudienceFor).
func triggeredWriteScope(app *App, table, tenant, owner string) (groupID string, userID int64, public bool) {
	hasUID := hasColumn(app, table, "user_id")
	grouped := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	if app.Access != nil {
		if mode := app.Access.ModeFor(table, "read", hasUID, grouped); mode == "anon" || mode == "everyone" {
			return "", 0, true
		}
	}
	if grouped {
		if tenant != "" && tenant != "0" {
			return tenant, 0, false
		}
		return realtimeNoTenant, 0, false
	}
	if hasUID {
		if id, err := strconv.ParseInt(owner, 10, 64); err == nil && id > 0 {
			return "", id, false
		}
		return "", realtimeNoOwner, false
	}
	return "", 0, true
}

// flowAnnounceableTables maps lower-cased names to the schema spelling of every
// app table a flow write may announce.
func flowAnnounceableTables(app *App) map[string]string {
	app.mu.RLock()
	tables := app.Tables
	app.mu.RUnlock()
	byLower := make(map[string]string, len(tables))
	for _, t := range tables {
		byLower[strings.ToLower(t.Name)] = t.Name
	}
	out := make(map[string]string, len(tables))
	for lower, name := range byLower {
		if strings.HasPrefix(lower, "_benmore_") || strings.HasPrefix(lower, "sqlite_") || ftsShadowOf(lower, byLower) {
			continue
		}
		out[lower] = name
	}
	return out
}

// ftsShadowOf reports whether name is the FTS5 index (or one of its shadow
// tables) of another app table.
func ftsShadowOf(name string, tables map[string]string) bool {
	for _, suffix := range []string{"_fts", "_fts_data", "_fts_idx", "_fts_docsize", "_fts_config", "_fts_content"} {
		if parent := strings.TrimSuffix(name, suffix); parent != name && parent != "" {
			if _, ok := tables[parent]; ok {
				return true
			}
		}
	}
	return false
}

// flowBroadcastMaxPayload caps a `run: broadcast` payload at the size of the
// largest message a client may send (wsMaxMessageSize).
const flowBroadcastMaxPayload = wsMaxMessageSize

// execStepBroadcast sends {type:"message", room, from:"server", payload} to
// every current member of the room in this app (this tenant, in grouped apps).
// Outputs: steps.<id>.outputs.room and .recipients (connections it was queued
// for; 0 is not an error - nobody may be in the room).
func execStepBroadcast(ctx *FlowContext, step *FlowStep) error {
	b := step.Broadcast
	if b == nil || strings.TrimSpace(b.Room) == "" {
		return fmt.Errorf("broadcast step requires `with.room`")
	}
	if !b.HasPayload {
		return fmt.Errorf("broadcast step requires `with.payload`")
	}
	room := strings.TrimSpace(interpolateCtx(b.Room, ctx))
	payload := resolveJSONValue(b.Payload, ctx)
	// An unresolved ref must not reach room members: return before sending
	// and let the dispatcher report the refs (executeStep, flows_steps.go).
	ctx.DataMu.Lock()
	unresolved := len(ctx.MissingRefs) > 0
	ctx.DataMu.Unlock()
	if unresolved {
		return nil
	}
	if !validWSRoomName(room) {
		return fmt.Errorf("broadcast: room %q is not a valid room name (1-%d characters of a-z A-Z 0-9 _ - . :)", room, wsRoomNameMax)
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("broadcast: payload is not JSON-encodable: %w", err)
	}
	if len(raw) > flowBroadcastMaxPayload {
		return fmt.Errorf("broadcast: payload is %d bytes, over the %d-byte limit - send an id and let members fetch the rest", len(raw), flowBroadcastMaxPayload)
	}
	groupID := ""
	if ctx.Session != nil {
		groupID = ctx.Session.EffectiveGroupID()
	}
	n, err := BroadcastWSToRoomFromServer(ctx.App, groupID, room, raw)
	if err != nil {
		return fmt.Errorf("broadcast: %w", err)
	}
	log.Printf("flows: broadcast step=%q room=%q recipients=%d bytes=%d", step.Name, room, n, len(raw))
	ctx.setStepOutput(step.Name, map[string]any{"room": room, "recipients": n})
	return nil
}
