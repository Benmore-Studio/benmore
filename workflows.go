//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"
)

// RegisterWorkflows sets up transition API endpoints and starts timeout checkers.
func RegisterWorkflows(mux appRouteRegistrar, app *App) {
	registerWorkflows(mux, app)
	for _, wf := range app.Workflows.Workflows {
		if len(wf.Timeouts) > 0 {
			startWorkflowTimeoutChecker(app, wf)
			log.Printf("  workflow-timeout: %s (%d states with timeouts)", wf.Name, len(wf.Timeouts))
		}
	}
}

func registerWorkflows(mux appRouteRegistrar, app *App) {
	for _, wf := range app.Workflows.Workflows {
		w := wf // capture

		// POST /api/{table}/{id}/transition - execute a state transition
		mux.HandleFunc(fmt.Sprintf("POST /api/%s/{id}/transition", w.Table), func(wr http.ResponseWriter, r *http.Request) {
			handleTransition(wr, r, app, w)
		})

		// GET /api/{table}/{id}/transitions - list valid transitions for current user
		mux.HandleFunc(fmt.Sprintf("GET /api/%s/{id}/transitions", w.Table), func(wr http.ResponseWriter, r *http.Request) {
			handleAvailableTransitions(wr, r, app, w)
		})

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

	// 2. Scope enforcement
	if err := checkScope(session, wf.Table, "write"); err != nil {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}
	// A transition is an update of the state column, so it obeys the
	// table's declarative update mode (admin/off/role:…) exactly like
	// PATCH does; row scope alone let any user move rows on tables whose
	// implicit mode is admin.
	if !EnforceCRUDAccess(w, r, app, wf.Table, OpUpdate, 0) {
		return
	}

	// 3. Validate CSRF (skip Bearer)
	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	// A command-owned state column moves only through its command.
	if v := ownedFieldViolation(app, wf.Table, wf.Field); v != nil {
		writeOwnedFieldRefusal(w, v)
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

	// 5. Fetch current row (with scoping)
	readSQL := "SELECT * FROM " + quoteIdent(wf.Table) + " WHERE id = ?"
	readArgs := []any{id}

	// Soft delete filter
	if hasColumn(app, wf.Table, "deleted_at") {
		readSQL += " AND deleted_at IS NULL"
	}

	// Scoping - canonical rowScopeClause (act-as aware + ACL). A transition
	// is a write, so authorize against "edit".
	if pred, pargs, bypass := rowScopeClause(app, wf.Table, session, "edit"); !bypass && pred != "" {
		readSQL += " AND " + pred
		readArgs = append(readArgs, pargs...)
	}

	rows, err := queryNativeRowsWith(app.DB, app, wf.Table, readSQL, readArgs...)
	if err != nil || len(rows) == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	row := rows[0]

	// 6. Get current state (stateVal is the stored value, kept for the
	// conditional UPDATE below; hooks later receive and may annotate row)
	stateVal := row[wf.Field]
	currentState := fmt.Sprintf("%v", stateVal)

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
	if transition.Role != "" && !hasWorkflowRole(app, session, transition.Role) {
		httpJSON(w, http.StatusForbidden, map[string]any{
			"error":   "forbidden",
			"message": fmt.Sprintf("role '%s' required for this transition", transition.Role),
		})
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
	if fmt.Sprint(row[wf.Field]) != currentState {
		httpJSON(w, http.StatusConflict, map[string]any{"error": "state changed", "from": currentState})
		return
	}
	if transition.When != "" && !whenHolds(tx, app, wf.Table, transition.When, row) {
		httpJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": "condition not met", "when": transition.When})
		return
	}
	// Preserve workflow hook semantics: predicates and placeholders see the
	// stored row merged with the requested state, plus session context.
	beforeRow := copyRow(row)
	beforeRow[wf.Field] = body.To
	markSubmittedFields(beforeRow, []string{wf.Field})
	injectSessionContext(beforeRow, session)
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

	result, err := tx.Exec(updateSQL, updateArgs...)
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

	// Read through the transaction. A missing/failed read cannot report a
	// successful transition with fabricated hook data.
	updatedRows, err := queryNativeRowsWith(tx, app, wf.Table, "SELECT * FROM "+quoteIdent(wf.Table)+" WHERE id = ?", id)
	if err != nil || len(updatedRows) != 1 {
		if err == nil {
			err = fmt.Errorf("transitioned row read back %d rows", len(updatedRows))
		}
		serverErrorJSON(w, r, app, wf.Table+" transition", err, "could not read transitioned row")
		return
	}
	updatedRow := updatedRows[0]

	// Inject old_* fields for hook context
	for k, v := range row {
		updatedRow["old_"+k] = v
	}
	injectSessionContext(updatedRow, session)

	refreshTables, err := fireHookListTx(tx, app, "transition", wf.Table, updatedRow, wf.OnTransition[body.To])
	if err == nil {
		var afterRefresh []string
		afterRefresh, err = fireAfterHooksTx(tx, app, "update", wf.Table, updatedRow)
		refreshTables = append(refreshTables, afterRefresh...)
	}
	if err == nil {
		err = enqueueWebhookSubscriptionsTx(tx, app, "update", wf.Table, updatedRow, session)
	}
	if err == nil {
		err = LogAuditTx(tx, app, "transition", wf.Table, id, session,
			map[string]any{wf.Field: currentState}, map[string]any{wf.Field: body.To})
	}
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
	broadcastHookRefreshes(app, refreshTables, []transactionResult{{Table: wf.Table, Action: "update"}})

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
		httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
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
	readSQL := "SELECT * FROM " + quoteIdent(wf.Table) + " WHERE id = ?"
	readArgs := []any{id}
	if hasColumn(app, wf.Table, "deleted_at") {
		readSQL += " AND deleted_at IS NULL"
	}
	if pred, pargs, bypass := rowScopeClause(app, wf.Table, session, "view"); !bypass && pred != "" {
		readSQL += " AND " + pred
		readArgs = append(readArgs, pargs...)
	}

	rows, err := queryNativeRowsWith(app.DB, app, wf.Table, readSQL, readArgs...)
	if err != nil || len(rows) == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}

	currentState := fmt.Sprintf("%v", rows[0][wf.Field])
	targets := wf.Transitions[currentState]

	var transitions []map[string]string
	for to, t := range targets {
		// Only show transitions the user has the role for
		if t.Role == "" || hasWorkflowRole(app, session, t.Role) {
			entry := map[string]string{"to": to}
			if t.Role != "" {
				entry["role"] = t.Role
			}
			transitions = append(transitions, entry)
		}
	}

	if transitions == nil {
		transitions = []map[string]string{}
	}

	httpJSON(w, http.StatusOK, map[string]any{
		"current":     currentState,
		"transitions": transitions,
	})
}

// hasWorkflowRole checks if the user can perform a transition requiring the given role.
func hasWorkflowRole(app *App, session *Session, requiredRole string) bool {
	if requiredRole == "" {
		return true
	}
	if session.IsAdmin() {
		return true
	}
	// Check app-level role from group membership table
	appRole := resolveAppRole(app, session)
	if appRole == requiredRole {
		return true
	}
	// Fall back to platform role hierarchy
	return hasRole(session.Role, requiredRole)
}

// fireTransitionHooks fires on_transition hooks for the target state.
func fireTransitionHooks(app *App, wf *Workflow, targetState string, row map[string]any) {
	hooks := wf.OnTransition[targetState]
	for _, hook := range hooks {
		if hook.When != "" && !whenHolds(app.DB, app, wf.Table, hook.When, row) {
			continue
		}
		r := copyRow(row)
		EnqueueHookJob(app, hook, wf.Table, r)
	}
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
	if app.Workflows == nil {
		return nil
	}
	for _, wf := range app.Workflows.Workflows {
		if wf.Table == table {
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
	for state, timeout := range wf.Timeouts {
		if timeout.After <= 0 {
			continue
		}

		seconds := int(timeout.After.Seconds())
		query := fmt.Sprintf(
			"SELECT id FROM %s WHERE %s = ? AND updated_at < datetime('now', '-%d seconds')",
			quoteIdent(wf.Table), quoteColumn(wf.Table, wf.Field), seconds,
		)
		if hasColumn(app, wf.Table, "deleted_at") {
			query += " AND deleted_at IS NULL"
		}

		rows, err := queryNativeRowsWith(app.DB, app, wf.Table, query, state)
		if err != nil {
			log.Printf("WORKFLOW TIMEOUT ERROR [%s]: %s", wf.Name, err)
			continue
		}

		for _, row := range rows {
			id := fmt.Sprintf("%v", row["id"])

			// Fetch full row for hooks. A failed read leaves the timeout to
			// the next sweep rather than applying it without its hooks.
			fullRows, err := queryNativeRowsWith(app.DB, app, wf.Table, "SELECT * FROM "+quoteIdent(wf.Table)+" WHERE id = ?", id)
			if err != nil {
				log.Printf("WORKFLOW TIMEOUT ERROR [%s] id=%s: read row: %s", wf.Name, id, err)
				continue
			}

			applied, err := applyWorkflowTimeout(app, wf, id, state, timeout.To)
			if err != nil {
				log.Printf("WORKFLOW TIMEOUT ERROR [%s] id=%s: %s", wf.Name, id, err)
				continue
			}
			if !applied {
				continue
			}

			// Fire on_transition hooks
			if len(fullRows) > 0 {
				hookRow := fullRows[0]
				hookRow["old_"+wf.Field] = state
				hookRow[wf.Field] = timeout.To
				fireTransitionHooks(app, wf, timeout.To, hookRow)
			}

			// Audit log - system session for automated timeout transitions
			systemSession := &Session{ID: "system:timeout", Email: "system@localhost", Role: "system"}
			LogAudit(app, "transition", wf.Table, id, systemSession,
				map[string]any{wf.Field: state},
				map[string]any{wf.Field: timeout.To, "_trigger": "timeout"},
			)

			log.Printf("WORKFLOW TIMEOUT [%s] %s id=%s: %s → %s", wf.Name, wf.Table, id, state, timeout.To)

			broadcastWorkflowTimeout(app, wf.Table, fullRows)
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

// applyWorkflowTimeout moves one timed-out row to its timeout state. The
// UPDATE is conditioned on the row still being in the timed-out state: a user
// transition (or another process's checker, in cluster mode) may have moved it
// since the SELECT. Only the caller whose UPDATE applied (applied=true) may
// fire the transition's hooks and audit it.
func applyWorkflowTimeout(app *App, wf *Workflow, id, fromState, toState string) (bool, error) {
	tx, err := app.DB.Begin()
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	where := " WHERE id = ? AND " + quoteColumn(wf.Table, wf.Field) + " = ?"
	if hasColumn(app, wf.Table, "deleted_at") {
		where += " AND deleted_at IS NULL"
	}
	var matches int
	if err := tx.QueryRow("SELECT COUNT(*) FROM "+quoteIdent(wf.Table)+where, id, fromState).Scan(&matches); err != nil {
		return false, err
	}
	if matches != 1 {
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
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return n == 1, nil
}

// ===== Helpers =====

func httpJSON(w http.ResponseWriter, status int, data any) {
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
// path (single, batch, ingest, transaction) uses it.
func workflowCreateStateRefused(app *App, table, col string, value any) bool {
	if app == nil || app.Workflows == nil || value == nil {
		return false
	}
	for _, wf := range app.Workflows.Workflows {
		if wf.Table == table && wf.Field == col {
			return wf.Initial == "" || fmt.Sprintf("%v", value) != wf.Initial
		}
	}
	return false
}

func workflowProtectedFields(app *App, table string) []string {
	if app.Workflows == nil {
		return nil
	}
	var fields []string
	for _, wf := range app.Workflows.Workflows {
		if wf.Table == table {
			fields = append(fields, wf.Field)
		}
	}
	return fields
}
