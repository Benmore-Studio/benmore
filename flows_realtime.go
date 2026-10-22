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

import (
	"encoding/json"
	"fmt"
	"log"
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
	// committed runs once the run's transaction commits (announceFlowWrites);
	// a rollback drops it.
	committed []func()
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

func (l *flowWriteLog) add(writes []sqlWrite, inTx bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, w := range writes {
		e := flowWriteEntry{table: w.Table, action: w.Action, inTx: inTx}
		if !l.seen[e] {
			l.seen[e] = true
			l.order = append(l.order, e)
		}
	}
}

// take returns the durable writes (all non-transactional ones, plus the
// transactional ones when committed) and empties the log, so a second call
// announces nothing.
func (l *flowWriteLog) take(committed bool) []sqlWrite {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []sqlWrite
	for _, e := range l.order {
		if !e.inTx || committed {
			out = append(out, sqlWrite{Table: e.table, Action: e.action})
		}
	}
	l.order, l.seen = nil, map[flowWriteEntry]bool{}
	return out
}

// recordFlowSQLWrites notes the tables an executed flow SQL statement wrote.
// query is the text that ran; affected is the driver's RowsAffected, or -1
// when unknown. A single statement that changed no rows is not a write.
func recordFlowSQLWrites(ctx *FlowContext, query string, affected int64) {
	if ctx == nil || ctx.Writes == nil || !sqlMayWrite(query) {
		return
	}
	writes, statements := sqlWriteTargets(query)
	if len(writes) == 0 || (statements == 1 && affected == 0) {
		return
	}
	ctx.Writes.add(writes, ctx.Tx != nil)
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
// _benmore_*, sqlite_* or full-text shadow tables.
func announceFlowWrites(ctx *FlowContext, committed bool) {
	if ctx == nil || ctx.App == nil || ctx.Writes == nil {
		return
	}
	for _, fn := range ctx.Writes.takeCommitted(committed) {
		fn()
	}
	writes := ctx.Writes.take(committed)
	if len(writes) == 0 {
		return
	}
	tables := flowAnnounceableTables(ctx.App)
	sent := map[sqlWrite]bool{}
	for _, w := range writes {
		name, ok := tables[strings.ToLower(w.Table)]
		if !ok {
			continue
		}
		key := sqlWrite{Table: name, Action: w.Action}
		if sent[key] {
			continue
		}
		sent[key] = true
		if ctx.Session != nil {
			Broadcast(ctx.App, name, w.Action, ctx.Session)
			continue
		}
		if groupID, userID, public := sessionlessWriteScope(ctx, name); public {
			BroadcastUnscoped(ctx.App, name, w.Action)
		} else {
			BroadcastScopedDirect(ctx.App, name, w.Action, groupID, userID)
		}
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
	hasUID := hasColumn(app, table, "user_id")
	grouped := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	if app.Access != nil {
		if mode := app.Access.ModeFor(table, "read", hasUID, grouped); mode == "anon" || mode == "everyone" {
			return "", 0, true
		}
	}
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
			return fmt.Sprint(v)
		}
	}
	if grouped {
		for _, key := range []string{"_group_id", app.Group.Key} {
			if g := trusted(key); g != "" && g != "0" {
				return g, 0, false
			}
		}
		return realtimeNoTenant, 0, false
	}
	if hasUID {
		if id, err := strconv.ParseInt(trusted("user_id"), 10, 64); err == nil && id > 0 {
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
