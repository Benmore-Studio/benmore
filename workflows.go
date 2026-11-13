//go:build !cli

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"maps"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"
)

// RegisterWorkflows sets up transition API endpoints and starts timeout checkers.
func RegisterWorkflows(mux appRouteRegistrar, app *App) {
	registerWorkflows(mux, app)
	for _, wf := range app.workflowConfig().Workflows {
		if len(wf.Timeouts) > 0 {
			startWorkflowTimeoutChecker(app, wf)
			log.Printf("  workflow-timeout: %s (%d states with timeouts)", wf.Name, len(wf.Timeouts))
		}
	}
}

// workflowSameTableError refuses a second workflow on a table. The transition
// routes are the table's (POST /api/<table>/{id}/transition takes only `to`,
// GET .../transitions answers one `current`), and the SDK types, the
// <transitions> tag and the generated tests are keyed by table, so a table
// has one state machine. Two used to parse clean and then panic ServeMux in
// registerWorkflows (the same pattern twice): the app died at the next reload
// and at every start. Tables compare as SQLite compares them, so `Orders` and
// `orders` are one table.
func workflowSameTableError(raw map[string]WorkflowYAML) error {
	first := map[string]string{} // folded table → the first workflow naming it
	for _, name := range sortedWhenKeys(raw) {
		table := strings.TrimSpace(raw[name].Table)
		if table == "" {
			continue
		}
		key := sqliteIdentifierFold(table)
		other, taken := first[key]
		if !taken {
			first[key] = name
			continue
		}
		kept := strings.TrimSpace(raw[other].Table)
		return fmt.Errorf("workflows.yaml: workflows %q and %q both name table %q, and the framework supports one workflow per table: "+
			"POST /api/%s/{id}/transition and GET /api/%s/{id}/transitions are the table's routes and move one state column. "+
			"Keep one workflow on %q and move the other state machine to its own table (for example a row that points at this one), "+
			"which gets its own transition routes. See api({at:'workflows'}) → one_per_table.",
			other, name, kept, kept, kept, kept)
	}
	return nil
}

func registerWorkflows(mux appRouteRegistrar, app *App) {
	for _, wf := range app.workflowConfig().Workflows {
		w := wf // capture

		// The schema's spelling, plus the one workflows.yaml used when it
		// differed (ServeMux is case-sensitive; a deployed client keeps working).
		for _, table := range slices.Compact([]string{w.Table, w.ConfiguredTable}) {
			if table == "" {
				continue
			}
			// POST /api/{table}/{id}/transition - execute a state transition
			mux.HandleFunc(fmt.Sprintf("POST /api/%s/{id}/transition", table), func(wr http.ResponseWriter, r *http.Request) {
				handleTransition(wr, r, app, w)
			})

			// GET /api/{table}/{id}/transitions - list valid transitions for current user
			mux.HandleFunc(fmt.Sprintf("GET /api/%s/{id}/transitions", table), func(wr http.ResponseWriter, r *http.Request) {
				handleAvailableTransitions(wr, r, app, w)
			})
		}

		log.Printf("  workflow: %s.%s (%d states, %s → ...)", w.Table, w.Field, len(w.States), w.Initial)
	}
}

// handleTransition executes a state machine transition.
func handleTransition(w http.ResponseWriter, r *http.Request, app *App, wf *Workflow) {
	// 1. Require auth
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	// 2. The table-level gates, decided by the predicate the available-moves
	// list answers from (workflowTransitionDenialFor), so the list never
	// offers a move this route refuses.
	denial := workflowTransitionDenialFor(app, wf, session)
	if denial == transitionScopeDenied {
		httpJSON(w, http.StatusForbidden, scopeDeniedBody(checkScope(session, wf.Table, "write")))
		return
	}
	// A transition is an update of the state column, so it obeys the
	// table's declarative update mode (admin/off/role:…) exactly like
	// PATCH does; row scope alone let any user move rows on tables whose
	// implicit mode is admin. EnforceCRUDAccess writes that rule's answer.
	if !EnforceCRUDAccess(w, r, app, wf.Table, OpUpdate, 0) {
		return
	}
	if denial == transitionAccessDenied {
		writeUnmatchedAPINotFound(w)
		return
	}

	// 3. Validate CSRF (skip Bearer)
	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	// A command-owned state column moves only through its command.
	if denial == transitionOwnedDenied {
		writeOwnedFieldRefusal(w, ownedFieldViolation(app, wf.Table, wf.Field))
		return
	}

	// 3. Extract ID
	id := r.PathValue("id")
	if id == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "missing id"})
		return
	}
	if !rowIDCanonical(app, wf.Table, id) {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}

	// Record lock - a transition is an update, so another user's edit lock
	// refuses it exactly as it refuses PATCH (crud_update.go): only on a row
	// the caller may edit, so a lock never confirms an invisible row exists.
	if locked, lockedBy := CheckLock(app.DB, wf.Table, id, session.UserID); locked && canAccessRowScoped(app, wf.Table, id, session, "edit") {
		httpJSON(w, http.StatusConflict, lockErrorResponse(app.DevMode, lockedBy))
		return
	}

	// 4. Parse body
	var body struct {
		To      string `json:"to"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.To == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "'to' field required"})
		return
	}

	// 5. Fetch current row (with scoping). A transition is a write, so the
	// row is read under the "edit" scope.
	readSQL, readArgs := workflowRowQuery(app, wf, session, id, "edit")

	rows, err := queryNativeRowsWith(app.DB, app, wf.Table, readSQL, readArgs...)
	if err != nil || len(rows) == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	row := rows[0]

	// 6. Get current state (stateVal is the stored value, kept for the
	// conditional UPDATE below; hooks later receive and may annotate row)
	stateVal := row[wf.Field]
	currentState := valueText(stateVal)

	// 7. Validate transition exists
	targets, exists := wf.Transitions[currentState]
	if !exists {
		httpJSON(w, http.StatusConflict, map[string]any{
			"error": "no transitions from current state",
			"from":  currentState,
		})
		return
	}

	transition, validTarget := targets[body.To]
	if !validTarget {
		// Build list of valid targets for the error response
		var valid []string
		for to := range targets {
			valid = append(valid, to)
		}
		httpJSON(w, http.StatusConflict, map[string]any{
			"error": "invalid transition",
			"from":  currentState,
			"to":    body.To,
			"valid": valid,
		})
		return
	}

	// 8. Check role
	if transition.Role != "" && !hasWorkflowRole(app, session, wf.Table, transition.Role) {
		httpJSON(w, http.StatusForbidden, withRefusalDocs(map[string]any{
			"error":   "forbidden",
			"message": workflowRoleRequired(transition.Role),
		}, refusalWorkflowRole))
		return
	}

	// 11. Execute UPDATE
	updateSQL := "UPDATE " + quoteIdent(wf.Table) + " SET " + quoteIdent(wf.Field) + " = ?"
	updateArgs := []any{body.To}

	if hasColumn(app, wf.Table, "updated_at") {
		updateSQL += ", updated_at = ?"
		updateArgs = append(updateArgs, nil)
	}
	// Condition the write on the state the transition was validated against
	// (a racing transition from the same state must not also apply) and on
	// the same row scope the read used. An encrypted state column stores
	// ciphertext, which can't be compared with the decrypted value read above.
	updateSQL += " WHERE id = ?"
	updateArgs = append(updateArgs, id)
	if encryptedDefFor(app, wf.Table, wf.Field) == nil {
		updateSQL += " AND " + quoteColumn(wf.Table, wf.Field) + " = ?"
		updateArgs = append(updateArgs, stateVal)
	}
	if hasColumn(app, wf.Table, "deleted_at") {
		updateSQL += " AND deleted_at IS NULL"
	}
	if pred, pargs, bypass := rowScopeClause(app, wf.Table, session, "edit"); !bypass && pred != "" {
		updateSQL += " AND " + pred
		updateArgs = append(updateArgs, pargs...)
	}

	// Keep the scoped state recheck, before-hook SQL, mutation, SQL after-hooks
	// and durable delivery intents in one transaction, as canonical updates do.
	// Workflow states remain protected from generic PATCH; only this already
	// authorized transition path supplies the conditional state UPDATE above.
	tx, err := app.DB.BeginTx(r.Context(), nil)
	if err != nil {
		serverErrorJSON(w, r, app, wf.Table+" transition", err, "transaction start failed")
		return
	}
	defer tx.Rollback()
	freshRows, err := queryNativeRowsWith(tx, app, wf.Table, readSQL, readArgs...)
	if err != nil || len(freshRows) != 1 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	row = freshRows[0]
	if valueText(row[wf.Field]) != currentState {
		httpJSON(w, http.StatusConflict, map[string]any{"error": "state changed", "from": currentState})
		return
	}
	// The condition is judged over the row before the change, with the
	// caller's session keys and old_<column> (transitionEventRow).
	if transition.When != "" && !whenHolds(tx, app, wf.Table, transition.When, transitionEventRow(row, row, session)) {
		httpJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "condition not met", "when": transition.When})
		return
	}
	// Preserve workflow hook semantics: predicates and placeholders see the
	// stored row merged with the requested state, plus the previous values
	// and session context.
	target := copyRow(row)
	target[wf.Field] = body.To
	beforeRow := transitionEventRow(target, row, session)
	markSubmittedFields(beforeRow, []string{wf.Field})
	if err := fireBeforeHooksWith(tx, app, "update", wf.Table, beforeRow); err != nil {
		httpJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}

	// Transitions share the canonical monotonic version clock. Whole-second
	// timestamps let an older PATCH token survive a rapid state cycle and
	// can regress a version written by a server whose clock was ahead.
	if hasColumn(app, wf.Table, "updated_at") {
		next, _, timestampErr := prepareUpdateTimestamp(tx, wf.Table, id, "")
		if timestampErr != nil {
			serverErrorJSON(w, r, app, wf.Table+" transition", timestampErr, "could not prepare transition version")
			return
		}
		updateArgs[1] = next
	}

	result, err := execVersioned(tx, wf.Table, id, session, updateSQL, updateArgs...)
	if err != nil {
		serverErrorJSON(w, r, app, wf.Table+" transition", err, "transition failed")
		return
	}
	affected, err := result.RowsAffected()
	if err != nil {
		serverErrorJSON(w, r, app, wf.Table+" transition", err, "transition result unavailable")
		return
	}
	if affected == 0 {
		httpJSON(w, http.StatusConflict, map[string]any{
			"error": "state changed",
			"from":  currentState,
			"hint":  "the record changed while this transition ran; re-read it and retry",
		})
		return
	}

	updatedRow, refreshTables, err := transitionEffectsTx(tx, app, wf, id, row, currentState, body.To, session)
	if err != nil {
		serverErrorJSON(w, r, app, wf.Table+" transition", err, "transition side effect failed")
		return
	}
	if err := tx.Commit(); err != nil {
		serverErrorJSON(w, r, app, wf.Table+" transition", err, "transition commit failed")
		return
	}

	// External event handlers and live notifications only observe a commit.
	FireFlowsForEvent(app, "on_update", wf.Table, updatedRow)
	Broadcast(app, wf.Table, "update", session)
	broadcastHookRefreshes(app, session, refreshTables, []transactionResult{{Table: wf.Table, Action: "update"}})

	// 17. Response
	httpJSON(w, http.StatusOK, map[string]any{
		"status": "transitioned",
		"from":   currentState,
		"to":     body.To,
		"id":     id,
	})
}

// handleAvailableTransitions returns valid next states for the current user.
func handleAvailableTransitions(w http.ResponseWriter, r *http.Request, app *App, wf *Workflow) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}
	// It reads the row's state, so a scoped credential needs read scope
	// on the table, as a GET /api/<table>/{id} would.
	if err := checkScope(session, wf.Table, "read"); err != nil {
		httpJSON(w, http.StatusForbidden, scopeDeniedBody(err))
		return
	}

	if !EnforceCRUDAccess(w, r, app, wf.Table, OpRead, 0) {
		return
	}

	id := r.PathValue("id")
	if id == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "missing id"})
		return
	}
	if !rowIDCanonical(app, wf.Table, id) {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}

	// Fetch row (with scoping)
	readSQL, readArgs := workflowRowQuery(app, wf, session, id, "view")

	rows, err := queryNativeRowsWith(app.DB, app, wf.Table, readSQL, readArgs...)
	if err != nil || len(rows) == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}

	transitions := []map[string]string{}
	for _, move := range availableWorkflowMoves(app, wf, session, rows[0]) {
		entry := map[string]string{"to": move.To}
		if move.Role != "" {
			entry["role"] = move.Role
		}
		transitions = append(transitions, entry)
	}

	httpJSON(w, http.StatusOK, map[string]any{
		"current":     valueText(rows[0][wf.Field]),
		"transitions": transitions,
	})
}

// workflowMove is one transition a caller may make from a row's current state.
type workflowMove struct {
	To   string
	Role string // the transition's role list, "" when it has none
}

// workflowTransitionDenial is the table-level reason POST
// /api/<table>/{id}/transition refuses a caller before it looks at the row.
type workflowTransitionDenial int

const (
	transitionAdmitted     workflowTransitionDenial = iota
	transitionScopeDenied                           // the credential or role has no write scope on the table
	transitionAccessDenied                          // the table's update rule refuses the caller
	transitionOwnedDenied                           // the state column is command-owned
)

// workflowTransitionDenialFor decides the table-level gates of a transition
// for session, in the order the route answers them: write scope, the table's
// update rule (a transition is an update of the state column), then a
// command-owned state column. The transition route refuses on what it returns
// and the available-moves list offers nothing unless it admits the caller, so
// the two cannot drift.
func workflowTransitionDenialFor(app *App, wf *Workflow, session *Session) workflowTransitionDenial {
	if session == nil {
		return transitionAccessDenied
	}
	if checkScope(session, wf.Table, "write") != nil {
		return transitionScopeDenied
	}
	hasUID := hasColumn(app, wf.Table, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, wf.Table, app.Group.Key)
	if mode := app.Access.ModeFor(wf.Table, OpUpdate, hasUID, hasGroupKey); mode == "off" || !tableModeAllowed(app, wf.Table, OpUpdate, mode, session, 0) {
		return transitionAccessDenied
	}
	if ownedFieldViolation(app, wf.Table, wf.Field) != nil {
		return transitionOwnedDenied
	}
	return transitionAdmitted
}

// workflowRowQuery is the SELECT a workflow route reads row id with: live
// rows only, inside session's row scope for aclAction ("edit" for the row a
// transition moves, "view" for the state the moves list reports).
func workflowRowQuery(app *App, wf *Workflow, session *Session, id, aclAction string) (string, []any) {
	query := "SELECT * FROM " + quoteIdent(wf.Table) + " WHERE id = ?"
	args := []any{id}
	if hasColumn(app, wf.Table, "deleted_at") {
		query += " AND deleted_at IS NULL"
	}
	// Canonical rowScopeClause (act-as aware + ACL).
	if pred, pargs, bypass := rowScopeClause(app, wf.Table, session, aclAction); !bypass && pred != "" {
		query += " AND " + pred
		args = append(args, pargs...)
	}
	return query, args
}

// availableWorkflowMoves lists, sorted by target, the transitions session may
// make from the state row is in: the ones POST .../transition would accept
// from this caller for this row. The caller passes the route's table-level
// gates (workflowTransitionDenialFor: write scope, the update rule, no
// command-owned state column, for which the route answers 403
// field_owned_by_command), the row is inside the caller's edit scope (read
// with the route's own query, workflowRowQuery), the caller holds the
// transition's `role:` and its `when:` holds, judged over the row
// handleTransition judges it over (transitionEventRow). A condition that
// cannot be evaluated is not met, as on the transition route. GET
// /api/<table>/{id}/transitions and the SSR <transitions> tag both answer
// from here; row is the full row as the caller may read it.
func availableWorkflowMoves(app *App, wf *Workflow, session *Session, row map[string]any) []workflowMove {
	targets := wf.Transitions[valueText(row[wf.Field])]
	if len(targets) == 0 || workflowTransitionDenialFor(app, wf, session) != transitionAdmitted {
		return nil
	}
	// The row the route would move. Where the edit scope is the view scope
	// the caller's row is that row already.
	id := valueText(row["id"])
	viewSQL, viewArgs := workflowRowQuery(app, wf, session, id, "view")
	if editSQL, editArgs := workflowRowQuery(app, wf, session, id, "edit"); editSQL != viewSQL || !slices.Equal(argTexts(editArgs), argTexts(viewArgs)) {
		editable, err := queryNativeRowsWith(app.DB, app, wf.Table, editSQL, editArgs...)
		if err != nil || len(editable) != 1 {
			return nil
		}
		row = editable[0]
		targets = wf.Transitions[valueText(row[wf.Field])]
	}
	var eventRow map[string]any
	var moves []workflowMove
	for _, to := range slices.Sorted(maps.Keys(targets)) {
		t := targets[to]
		if t.Role != "" && !hasWorkflowRole(app, session, wf.Table, t.Role) {
			continue
		}
		if t.When != "" {
			if eventRow == nil {
				eventRow = transitionEventRow(row, row, session)
			}
			if !whenHolds(app.DB, app, wf.Table, t.When, eventRow) {
				continue
			}
		}
		move := workflowMove{To: to}
		if t.Role != "" {
			move.Role = canonicalWorkflowRole(t.Role)
		}
		moves = append(moves, move)
	}
	return moves
}

// argTexts spells each query argument with its type, for comparing two
// argument lists.
func argTexts(args []any) []string {
	out := make([]string, len(args))
	for i, a := range args {
		out[i] = fmt.Sprintf("%T:%v", a, a)
	}
	return out
}

// rowWithOldValues returns row with old_<column> added for every column of
// before, the row as it was stored before the change.
func rowWithOldValues(row, before map[string]any) map[string]any {
	out := make(map[string]any, len(row)+len(before)+len(sessionContextKeys)+1)
	maps.Copy(out, row)
	for k, v := range before {
		out["old_"+k] = v
	}
	return out
}

// transitionEventRow is the row a transition is judged over and its hooks
// read, the shape an update's event row has: row's columns, old_<column> for
// every column of before (the row as stored before the state moves) and the
// caller's session keys. The session keys replace same-named columns, as in
// every hooks.yaml hook, so on a table with a user_id column `user_id` is who
// makes the transition and `old_user_id` the row's own. One builder for the
// transition's `when:` (row and before are both the stored row: the state
// column still holds the current state), the before_update hooks (row holds
// the target state), on_transition and on_update hooks (row is the row read
// back), the available-moves list and the approved-command path, so a guard
// such as `old_user_id != user_id` means the same everywhere. It used to be
// the plain stored row for `when:` (user_id the row's own, every old_<column>
// NULL), which made that guard always true: a requester approved their own
// request. actor nil is a timeout, which has no caller: the row keeps its own
// user_id and the other caller keys are unset.
func transitionEventRow(row, before map[string]any, actor *Session) map[string]any {
	out := rowWithOldValues(row, before)
	injectSessionContext(out, actor)
	return out
}

// hasWorkflowRole reports whether session may make a transition whose `role:`
// is requiredRole: one role or an any-of list ("owner,manager"), matched like
// an access `role:` mode. A listed role passes for a platform admin, through
// the _benmore_users.role hierarchy (hasRole), as the caller's membership role
// in the effective tenant (resolveAppRole), or through a role grant counted as
// the access mode counts it (workflowRoleFromGrant). `admin` on a table the
// tenant does not bound is the global admin only, never the membership role
// (workflowMembershipRoleAllowed). A `role:` that names no role admits only a
// platform admin.
func hasWorkflowRole(app *App, session *Session, table, requiredRole string) bool {
	if requiredRole == "" {
		return true
	}
	if session.IsAdmin() {
		return true
	}
	roles := workflowRoleNames(requiredRole)
	if len(roles) == 0 {
		return false
	}
	// App-level role from the group membership table, then the platform
	// role hierarchy, for each listed role.
	if workflowMembershipRoleAllowed(app, table, roles, resolveAppRole(app, session)) {
		return true
	}
	for _, role := range roles {
		if hasRole(session.Role, role) {
			return true
		}
	}
	return workflowRoleFromGrant(app, table, session, roles, app.DB.QueryRow)
}

// workflowRoleFromGrant reports whether session holds one of roles through its
// role grants (_benmore_user_roles), counted the way a `role:` access mode on
// table counts them (tableModeAllowed): a grant scoped to the caller's tenant
// only on a table the tenant key bounds, otherwise only a global one. queryRow
// reads the global grant on the caller's connection (a command's transaction).
func workflowRoleFromGrant(app *App, table string, session *Session, roles []string, queryRow func(query string, args ...any) *sql.Row) bool {
	if app == nil || session == nil || len(roles) == 0 || !HasAnyRole(session, roles) {
		return false
	}
	if workflowTenantBound(app, table) {
		return true
	}
	tier, args, ok := globalRoleTier(session, roles)
	if !ok {
		return false
	}
	if tier == "1=1" {
		return true
	}
	var held bool
	return queryRow("SELECT "+tier, args...).Scan(&held) == nil && held
}

// copyRow creates a shallow copy of a row map for safe concurrent access.
func copyRow(row map[string]any) map[string]any {
	cp := make(map[string]any, len(row))
	for k, v := range row {
		cp[k] = v
	}
	return cp
}

// GetWorkflowForTable returns the workflow definition for a table, if any.
func GetWorkflowForTable(app *App, table string) *Workflow {
	config := app.workflowConfig()
	if config == nil {
		return nil
	}
	for _, wf := range config.Workflows {
		if identIs(wf.Table, table) {
			return wf
		}
	}
	return nil
}

// ===== Timeout Checker =====

// workflowTimeoutInterval is how often a workflow's timeouts are checked.
var workflowTimeoutInterval = 60 * time.Second

// startWorkflowTimeoutChecker runs checkWorkflowTimeouts until the current
// stop generation closes. RegisterWorkflows runs on every hot reload, so a
// checker that never stopped (the old `for { Sleep }` loop) left one more
// checker per push, each still applying the workflow it was started with:
// a removed timeout kept firing and every row that timed out ran its
// on_transition hooks once per checker. Tracked through startWorker, so
// Shutdown waits for a sweep in progress before closing the database.
func startWorkflowTimeoutChecker(app *App, wf *Workflow) <-chan struct{} {
	return app.startWorker("workflows.timeoutChecker:"+wf.Name, func(stop <-chan struct{}) {
		ticker := time.NewTicker(workflowTimeoutInterval)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				func() {
					defer func() {
						if r := recover(); r != nil {
							log.Printf("WORKFLOW TIMEOUT PANIC [%s]: %v", wf.Name, r)
						}
					}()
					checkWorkflowTimeouts(app, wf)
				}()
			}
		}
	})
}

func checkWorkflowTimeouts(app *App, wf *Workflow) {
	checkWorkflowTimeoutsAt(app, wf, time.Now())
}

// checkWorkflowTimeoutsAt is one sweep of wf. now is the clock the per-row
// failure waits run on; whether a row is past its deadline is the database's
// own `datetime('now')`.
func checkWorkflowTimeoutsAt(app *App, wf *Workflow, now time.Time) {
	for state, timeout := range wf.Timeouts {
		if timeout.After <= 0 {
			continue
		}
		sweepWorkflowTimeoutState(app, wf, state, timeout, now)
	}
	workflowTimeoutBackoff.prune(now)
	workflowTimeoutResume.prune(now)
}

// sweepWorkflowTimeoutState times out the due rows of one state, oldest first.
// It reads them a page at a time, keyset on (updated_at, id), passes over the
// rows still waiting out a failed attempt, and stops when workflowTimeoutBatch
// rows were tried, workflowTimeoutScanLimit rows were read, or the rows ran
// out. A sweep stopped by either bound leaves its position, and the next one
// continues from there, so no number of failing rows keeps a later row from
// being reached. The select this replaces was `ORDER BY updated_at LIMIT 500`
// with the wait checked inside the loop: once a state held 500 rows whose
// timeout kept failing, every sweep read those 500, skipped them all, and no
// newer row of the state timed out again.
func sweepWorkflowTimeoutState(app *App, wf *Workflow, state string, timeout WorkflowTimeout, now time.Time) {
	seconds := int(timeout.After.Seconds())
	// `+updated_at` is the stored value as it is (the driver converts a
	// DATETIME column, not an expression), so the next page compares against
	// exactly what this page was ordered by.
	query := fmt.Sprintf(
		"SELECT id, +updated_at AS sweep_position FROM %s WHERE %s = ? AND updated_at < datetime('now', '-%d seconds')",
		quoteIdent(wf.Table), quoteColumn(wf.Table, wf.Field), seconds,
	)
	if hasColumn(app, wf.Table, "deleted_at") {
		query += " AND deleted_at IS NULL"
	}

	posKey := workflowTimeoutStateKey{dir: app.Dir, workflow: wf.Name, state: state}
	pos, resumed := workflowTimeoutResume.get(posKey)
	tried, read := 0, 0
	failed, firstFailedID, firstErr := 0, "", error(nil)
	defer func() {
		// One line per sweep and state, not one per failing row: rows that
		// keep failing are retried on their own waits indefinitely, and a
		// line each was up to workflowTimeoutBatch lines a minute for good.
		if failed > 0 {
			log.Printf("WORKFLOW TIMEOUT ERROR [%s] state=%s: %d row(s) could not time out (first id=%s: %s); each is retried on its own doubling wait", wf.Name, state, failed, firstFailedID, firstErr)
		}
	}()
	for tried < workflowTimeoutBatch && read < workflowTimeoutScanLimit {
		page, args := query, []any{state}
		if resumed {
			page += " AND (updated_at, id) > (?, ?)"
			args = append(args, pos.updatedAt, pos.id)
		}
		// The first page is one batch, which is all a sweep needs unless rows
		// waiting out a failure fill it; then the rest of the scan budget is
		// read in one more query. Without an index on (state, updated_at, id)
		// each page is a full scan of the table, so twenty pages a sweep cost
		// twenty scans a minute per state.
		limit := workflowTimeoutBatch
		if read > 0 {
			limit = workflowTimeoutScanLimit - read
		}
		page += fmt.Sprintf(" ORDER BY updated_at, id LIMIT %d", limit)
		rows, err := queryNativeRowsWith(app.DB, app, wf.Table, page, args...)
		if err != nil {
			log.Printf("WORKFLOW TIMEOUT ERROR [%s]: %s", wf.Name, err)
			// Whatever failed, the next sweep starts from the oldest row
			// instead of repeating a page that may be what failed.
			workflowTimeoutResume.clear(posKey)
			return
		}

		seen := 0
		for seen < len(rows) && tried < workflowTimeoutBatch {
			row := rows[seen]
			seen++
			read++
			pos, resumed = workflowTimeoutPosition{updatedAt: row["sweep_position"], id: row["id"], at: now}, true
			id := valueText(row["id"])
			key := workflowTimeoutKey{dir: app.Dir, workflow: wf.Name, id: id}
			if workflowTimeoutBackoff.skip(key, now) {
				continue
			}
			// Each timed-out row is its own write transaction (with its hook
			// jobs, audit row and webhook jobs), so the tries are what is
			// capped: a backlog drains over several sweeps instead of holding
			// the checker for one unbounded pass.
			tried++
			if _, err := applyWorkflowTimeoutDue(app, wf, id, state, timeout.To, seconds); err != nil {
				workflowTimeoutBackoff.fail(key, now)
				if failed == 0 {
					firstFailedID, firstErr = id, err
				}
				failed++
				continue
			}
			workflowTimeoutBackoff.clear(key)
		}
		if seen == len(rows) && len(rows) < limit {
			// The rows ran out: the next sweep starts from the oldest again.
			workflowTimeoutResume.clear(posKey)
			return
		}
	}
	if resumed {
		workflowTimeoutResume.set(posKey, pos)
	}
}

// workflowTimeoutBatch caps the rows one sweep tries to time out per state.
const workflowTimeoutBatch = 500

// workflowTimeoutScanLimit caps the rows one sweep reads per state while it
// looks for workflowTimeoutBatch rows to try: 20 pages. Rows waiting out a
// failed attempt are read and passed over, so this is what a large backlog of
// them costs each sweep; the rest is read by the sweeps that follow.
const workflowTimeoutScanLimit = 20 * workflowTimeoutBatch

// workflowTimeoutResume holds, per app, workflow and state, where a sweep that
// stopped at a bound left off: the (updated_at, id) of the last row it read.
// In memory only, like the failure waits: after a restart the first sweep
// starts from the oldest row.
type workflowTimeoutStateKey struct{ dir, workflow, state string }

type workflowTimeoutPosition struct {
	updatedAt, id any
	at            time.Time
}

type workflowTimeoutResumeMap struct {
	mu sync.Mutex
	m  map[workflowTimeoutStateKey]workflowTimeoutPosition
}

var workflowTimeoutResume = &workflowTimeoutResumeMap{m: map[workflowTimeoutStateKey]workflowTimeoutPosition{}}

func (r *workflowTimeoutResumeMap) get(k workflowTimeoutStateKey) (workflowTimeoutPosition, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	pos, ok := r.m[k]
	return pos, ok
}

func (r *workflowTimeoutResumeMap) set(k workflowTimeoutStateKey, pos workflowTimeoutPosition) {
	r.mu.Lock()
	r.m[k] = pos
	r.mu.Unlock()
}

func (r *workflowTimeoutResumeMap) clear(k workflowTimeoutStateKey) {
	r.mu.Lock()
	delete(r.m, k)
	r.mu.Unlock()
}

// prune drops positions no sweep has moved for a while (the workflow, its
// timeout or the app is gone), so the map stays bounded.
func (r *workflowTimeoutResumeMap) prune(now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, pos := range r.m {
		if now.Sub(pos.at) > 2*workflowTimeoutMaxBackoff {
			delete(r.m, k)
		}
	}
}

// A timeout whose transaction fails (a hook that cannot run on that row, say)
// would otherwise be retried every sweep forever, one failing write
// transaction and error line per row per minute. Each failure doubles the
// wait before the row is tried again, up to an hour.
type workflowTimeoutKey struct{ dir, workflow, id string }

type workflowTimeoutRetry struct {
	failures int
	next     time.Time
}

type workflowTimeoutBackoffMap struct {
	mu sync.Mutex
	m  map[workflowTimeoutKey]workflowTimeoutRetry
}

var workflowTimeoutBackoff = &workflowTimeoutBackoffMap{m: map[workflowTimeoutKey]workflowTimeoutRetry{}}

const workflowTimeoutMaxBackoff = time.Hour

// workflowTimeoutBackoffMax bounds the failure waits remembered per process.
const workflowTimeoutBackoffMax = 50_000

func (b *workflowTimeoutBackoffMap) skip(k workflowTimeoutKey, now time.Time) bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, ok := b.m[k]
	return ok && now.Before(r.next)
}

func (b *workflowTimeoutBackoffMap) fail(k workflowTimeoutKey, now time.Time) time.Duration {
	b.mu.Lock()
	defer b.mu.Unlock()
	r, known := b.m[k]
	if !known && len(b.m) >= workflowTimeoutBackoffMax {
		// Full: drop one entry (map order is arbitrary). That row is tried
		// again sooner than its wait, which the per-sweep batch bounds; an
		// entry for every row that ever failed was unbounded memory on a
		// large table whose timeout keeps failing.
		for victim := range b.m {
			delete(b.m, victim)
			break
		}
	}
	r.failures++
	wait := workflowTimeoutMaxBackoff
	if r.failures < 7 { // 1m, 2m, 4m ... 32m, then the cap
		wait = time.Minute << (r.failures - 1)
	}
	r.next = now.Add(wait)
	b.m[k] = r
	return wait
}

func (b *workflowTimeoutBackoffMap) clear(k workflowTimeoutKey) {
	b.mu.Lock()
	delete(b.m, k)
	b.mu.Unlock()
}

// prune drops entries for rows that have not been seen failing for a while
// (deleted, moved by a user, or fixed), so the map stays bounded.
func (b *workflowTimeoutBackoffMap) prune(now time.Time) {
	b.mu.Lock()
	defer b.mu.Unlock()
	for k, r := range b.m {
		if now.Sub(r.next) > 2*workflowTimeoutMaxBackoff {
			delete(b.m, k)
		}
	}
}

// broadcastWorkflowTimeout announces a timeout transition to the row's own
// audience, the way a sessionless flow write is scoped (sessionlessWriteScope):
// the row's tenant on a group-keyed table, its owner on a user_id table, and
// everyone only when the table is publicly readable. An unscoped broadcast
// told every tenant's readers when another tenant's rows timed out.
func broadcastWorkflowTimeout(app *App, table string, rows []map[string]any) {
	data := map[string]any{}
	if len(rows) > 0 {
		data = rows[0]
	}
	groupID, userID, public := sessionlessWriteScope(&FlowContext{App: app, Data: data}, table)
	if public {
		BroadcastUnscoped(app, table, "update")
		return
	}
	BroadcastScopedDirect(app, table, "update", groupID, userID)
}

// transitionEffectsTx is the in-transaction tail shared by a user transition
// and a timeout, so both emit what an update emits: it reads the row back in
// its new state, runs the on_transition hooks and the table's after-update
// hooks, queues webhook subscriptions and writes the audit row, all in tx
// (delivery is the job worker's, after commit). oldRow is the row as it was
// before the state moved. actor is the caller; nil is a timeout, which has no
// caller (hook context keys stay the row's own, the audit row names the system
// and carries `_trigger: timeout`). It returns the new row (with old_<column>
// deltas and, for a caller, session context) and the tables hooks wrote to.
func transitionEffectsTx(tx mutationTx, app *App, wf *Workflow, id string, oldRow map[string]any, from, to string, actor *Session) (map[string]any, []string, error) {
	// A missing/failed read cannot report a successful transition with
	// fabricated hook data.
	updatedRows, err := queryNativeRowsWith(tx, app, wf.Table, "SELECT * FROM "+quoteIdent(wf.Table)+" WHERE id = ?", id)
	if err != nil || len(updatedRows) != 1 {
		if err == nil {
			err = fmt.Errorf("transitioned row read back %d rows", len(updatedRows))
		}
		return nil, nil, fmt.Errorf("could not read transitioned row: %w", err)
	}
	stored := rowWithOldValues(updatedRows[0], oldRow) // what a subscription delivers (webhookDataRow)
	updatedRow := transitionEventRow(updatedRows[0], oldRow, actor)

	// A timeout has no caller to run hook SQL as: its hooks are queued as jobs
	// in this transaction instead, so a hook needing a session value, or whose
	// `when:` fails, cannot roll the state change back.
	deferred := actor == nil
	refreshTables, err := fireHookListTxMode(tx, app, "transition", wf.Table, updatedRow, wf.OnTransition[to], deferred)
	if err == nil {
		var afterRefresh []string
		afterRefresh, err = fireHookListTxMode(tx, app, "update", wf.Table, updatedRow, afterHooksFor(app, "update", wf.Table), deferred)
		refreshTables = append(refreshTables, afterRefresh...)
	}
	if err == nil {
		err = enqueueWebhookSubscriptionsTx(tx, app, "update", wf.Table, stored, actor)
	}
	if err == nil {
		auditActor, auditNew := actor, map[string]any{wf.Field: to}
		if actor == nil {
			auditActor = &Session{ID: "system:timeout", Email: "system@localhost", Role: "system"}
			auditNew["_trigger"] = "timeout"
		}
		err = LogAuditTx(tx, app, "transition", wf.Table, id, auditActor, map[string]any{wf.Field: from}, auditNew)
	}
	return updatedRow, refreshTables, err
}

// applyWorkflowTimeout moves one timed-out row to its timeout state in one
// transaction. The UPDATE is conditioned on the row still being in the
// timed-out state: a user transition (or another process's checker, in
// cluster mode) may have moved it since the SELECT. Only the caller whose
// UPDATE applied (applied=true) has the transition's effects: they commit with
// the state (transitionEffectsTx), so a crash cannot leave a moved row with
// no audit row or hook job, and a timeout fires the table's on_update hooks,
// webhook subscriptions and flows as any update does.
func applyWorkflowTimeout(app *App, wf *Workflow, id, fromState, toState string) (bool, error) {
	return applyWorkflowTimeoutDue(app, wf, id, fromState, toState, 0)
}

// applyWorkflowTimeoutDue is applyWorkflowTimeout that also re-checks the
// deadline (dueSeconds > 0) inside the transaction: a row edited after the
// sweep selected it has a fresh updated_at and is no longer timed out.
func applyWorkflowTimeoutDue(app *App, wf *Workflow, id, fromState, toState string, dueSeconds int) (bool, error) {
	tx, err := app.DB.BeginTx(withWriteTxLabel(context.Background(), "workflow timeout:"+wf.Name), nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	where := " WHERE id = ? AND " + quoteColumn(wf.Table, wf.Field) + " = ?"
	if hasColumn(app, wf.Table, "deleted_at") {
		where += " AND deleted_at IS NULL"
	}
	if dueSeconds > 0 {
		where += fmt.Sprintf(" AND updated_at < datetime('now', '-%d seconds')", dueSeconds)
	}
	oldRows, err := queryNativeRowsWith(tx, app, wf.Table, "SELECT * FROM "+quoteIdent(wf.Table)+where, id, fromState)
	if err != nil {
		return false, err
	}
	if len(oldRows) != 1 {
		return false, nil
	}
	updateSQL := "UPDATE " + quoteIdent(wf.Table) + " SET " + quoteIdent(wf.Field) + " = ?"
	updateArgs := []any{toState}
	if hasColumn(app, wf.Table, "updated_at") {
		next, _, err := prepareUpdateTimestamp(tx, wf.Table, id, "")
		if err != nil {
			return false, err
		}
		updateSQL += ", updated_at = ?"
		updateArgs = append(updateArgs, next)
	}
	updateSQL += where
	updateArgs = append(updateArgs, id, fromState)
	res, err := tx.Exec(updateSQL, updateArgs...)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return false, err
	}
	if n != 1 {
		return false, nil
	}
	updatedRow, refreshTables, err := transitionEffectsTx(tx, app, wf, id, oldRows[0], fromState, toState, nil)
	if err != nil {
		return false, err
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}

	// External handlers and live notifications only observe a commit.
	FireFlowsForEvent(app, "on_update", wf.Table, updatedRow)
	broadcastWorkflowTimeout(app, wf.Table, []map[string]any{updatedRow})
	broadcastHookRefreshes(app, nil, refreshTables, []transactionResult{{Table: wf.Table, Action: "update"}})
	log.Printf("WORKFLOW TIMEOUT [%s] %s id=%s: %s → %s", wf.Name, wf.Table, id, fromState, toState)
	return true, nil
}

// ===== Helpers =====

func httpJSON(w http.ResponseWriter, status int, data any) {
	if status >= http.StatusBadRequest {
		addCacheControlDirective(w.Header(), "no-store") // keeps a stricter "private, no-store"
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

// injectSessionContext adds user context fields to a row for hook interpolation.
// Defined in hooks.go - this is a forward declaration comment for reference.
// func injectSessionContext(row map[string]any, session *Session)

// isBearerAuth checks if the request uses Bearer token authentication.
// Defined in auth_csrf.go.

// validateCSRF checks the CSRF token on the request.
// Defined in auth_csrf.go.

// workflowCreateStateRefused reports whether a create's value for col is
// dropped because col is a workflow's state column. A new row may start only
// in the workflow's declared `initial` state; any other value (or any value
// when no `initial` is declared) is dropped so the column default applies.
// Updates are blocked outright (workflowProtectedFields); without this a
// caller could create a row directly in a role-guarded state. Every create
// path (single, batch, ingest, transaction) uses it. A nil value is a JSON
// null the caller sent and is dropped too.
func workflowCreateStateRefused(app *App, table, col string, value any) bool {
	config := app.workflowConfig()
	if config == nil {
		return false
	}
	for _, wf := range config.Workflows {
		if identIs(wf.Table, table) && identIs(wf.Field, col) {
			// An explicit null is not a state either: a nullable column would
			// store NULL, a row no transition leaves.
			return value == nil || wf.Initial == "" || valueText(value) != wf.Initial
		}
	}
	return false
}

// workflowCreateInitial returns the state a new row of table starts in when
// col is a workflow's state column and the workflow declares `initial`. A
// create writes it whatever the caller sent or left out, so the row never
// depends on the column default (a nullable column stored NULL, a NOT NULL one
// an empty string: a state no transition leaves).
func workflowCreateInitial(app *App, table, col string) (string, bool) {
	config := app.workflowConfig()
	if config == nil {
		return "", false
	}
	for _, wf := range config.Workflows {
		if wf != nil && wf.Initial != "" && identIs(wf.Table, table) && identIs(wf.Field, col) {
			return wf.Initial, true
		}
	}
	return "", false
}

// withWorkflowInitial returns data with every workflow state column of table
// set to its initial state (data itself is not modified).
func withWorkflowInitial(app *App, table string, data map[string]any) map[string]any {
	config := app.workflowConfig()
	if config == nil {
		return data
	}
	var out map[string]any
	for _, wf := range config.Workflows {
		if wf == nil || wf.Initial == "" || !identIs(wf.Table, table) {
			continue
		}
		if out == nil {
			out = make(map[string]any, len(data)+1)
			maps.Copy(out, data)
		}
		for k := range out {
			if identIs(k, wf.Field) {
				delete(out, k)
			}
		}
		out[wf.Field] = wf.Initial
	}
	if out == nil {
		return data
	}
	return out
}

// workflowInitialColumns returns the workflow state columns of table, sorted,
// that an INSERT the framework builds itself has to write, each with the
// `initial` state a new row starts in. It is withWorkflowInitial for the
// inserts that take no row from a request: bulk import Mode A, the founding
// membership of /api/_groups/create and the member-of auto-join. Without it
// those rows took the column default: NULL (a state no transition leaves), a
// NOT NULL failure, or a default that is not `initial`.
//
// As in handleCreate and txInsertWithPlan, a column the create set protects
// (owner, tenant key, in-tenant role field, computed) is left alone. So is one
// the INSERT already names (written) or the table does not have (hasCol): a
// workflow naming a missing column must not break the insert.
func workflowInitialColumns(app *App, table string, hasCol func(string) bool, written []string) ([]string, []any) {
	state := withWorkflowInitial(app, table, nil)
	if len(state) == 0 {
		return nil, nil
	}
	protected := protectedCreateFields(app, table)
	var cols []string
	var values []any
	for _, col := range slices.Sorted(maps.Keys(state)) {
		named := slices.ContainsFunc(written, func(w string) bool { return identIs(w, col) })
		if named || protected.has(col) || !hasCol(col) {
			continue
		}
		cols = append(cols, col)
		values = append(values, state[col])
	}
	return cols, values
}

// canonicalizeWorkflowColumns rewrites each workflow's table and state column
// to the schema's spelling. SQLite folds identifier case, so a workflows.yaml
// `field: Status` over column `status` ran its SQL but missed every exact
// comparison (create refusal, route and row lookups), letting a caller create
// a row directly in a role-guarded state. A name the schema does not have is
// left as written; the write gate and `benmore check` refuse it.
func canonicalizeWorkflowColumns(cfg *WorkflowConfig, tables []Table) {
	if cfg == nil {
		return
	}
	for _, wf := range cfg.Workflows {
		if wf == nil {
			continue
		}
		for _, t := range tables {
			if !identIs(t.Name, wf.Table) {
				continue
			}
			if wf.Table != t.Name {
				wf.ConfiguredTable = wf.Table
			}
			wf.Table = t.Name
			for _, c := range t.Columns {
				if identIs(c.Name, wf.Field) {
					wf.Field = c.Name
				}
			}
		}
	}
}

// canonicalizeWorkflowTableNames is canonicalizeWorkflowColumns for callers
// that know only the served table names (connector route validation and
// review): the transition route is registered under the workflow's table, so
// it must be spelled as the runtime will spell it.
func canonicalizeWorkflowTableNames(cfg *WorkflowConfig, names []string) {
	if cfg == nil {
		return
	}
	for _, wf := range cfg.Workflows {
		if wf == nil {
			continue
		}
		for _, n := range names {
			if identIs(n, wf.Table) {
				if wf.Table != n {
					// As canonicalizeWorkflowColumns: the runtime keeps the
					// configured spelling's routes registered too.
					wf.ConfiguredTable = wf.Table
				}
				wf.Table = n
				break
			}
		}
	}
}

func workflowProtectedFields(app *App, table string) []string {
	config := app.workflowConfig()
	if config == nil {
		return nil
	}
	var fields []string
	for _, wf := range config.Workflows {
		if identIs(wf.Table, table) {
			fields = append(fields, wf.Field)
		}
	}
	return fields
}
