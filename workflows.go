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
func RegisterWorkflows(mux *http.ServeMux, app *App) {
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

		// Start timeout checker if any timeouts are configured
		if len(w.Timeouts) > 0 {
			startWorkflowTimeoutChecker(app, w)
			log.Printf("  workflow-timeout: %s (%d states with timeouts)", w.Name, len(w.Timeouts))
		}
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

	// 3. Validate CSRF (skip Bearer)
	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	// 3. Extract ID
	id := r.PathValue("id")
	if id == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "missing id"})
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
	readSQL := fmt.Sprintf("SELECT * FROM %s WHERE id = ?", wf.Table)
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

	rows, err := QueryRows(app.DB, readSQL, readArgs...)
	if err != nil || len(rows) == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}
	row := rows[0]

	// 6. Get current state
	currentState := fmt.Sprintf("%v", row[wf.Field])

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

	// 9. Check 'when' condition
	if transition.When != "" && !evaluateCondition(transition.When, row) {
		httpJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"error": "condition not met",
			"when":  transition.When,
		})
		return
	}

	// 10. Fire before-hooks (can abort)
	injectSessionContext(row, session)
	if err := FireBeforeHooks(app, "update", wf.Table, row); err != nil {
		httpJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": err.Error()})
		return
	}

	// 11. Execute UPDATE
	updateSQL := fmt.Sprintf("UPDATE %s SET %s = ?", wf.Table, wf.Field)
	updateArgs := []any{body.To}

	if hasColumn(app, wf.Table, "updated_at") {
		updateSQL += ", updated_at = datetime('now')"
	}
	updateSQL += " WHERE id = ?"
	updateArgs = append(updateArgs, id)

	result, err := app.DB.Exec(updateSQL, updateArgs...)
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "transition failed"})
		return
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "not found"})
		return
	}

	// 12. Fetch updated row for hooks
	updatedRows, _ := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id = ?", wf.Table), id)
	var updatedRow map[string]any
	if len(updatedRows) > 0 {
		updatedRow = updatedRows[0]
	} else {
		updatedRow = row
	}

	// Inject old_* fields for hook context
	for k, v := range row {
		updatedRow["old_"+k] = v
	}
	injectSessionContext(updatedRow, session)

	// 13. Fire on_transition hooks
	fireTransitionHooks(app, wf, body.To, updatedRow)

	// 14. Fire standard update hooks + flow events
	FireHooks(app, "update", wf.Table, updatedRow)
	FireFlowsForEvent(app, "on_update", wf.Table, updatedRow)

	// 15. SSE broadcast
	Broadcast(app, wf.Table, "update", session)

	// 16. Audit log
	LogAudit(app, "transition", wf.Table, id, session,
		map[string]any{wf.Field: currentState},
		map[string]any{wf.Field: body.To},
	)

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

	id := r.PathValue("id")
	if id == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "missing id"})
		return
	}

	// Fetch row (with scoping)
	readSQL := fmt.Sprintf("SELECT * FROM %s WHERE id = ?", wf.Table)
	readArgs := []any{id}
	if hasColumn(app, wf.Table, "deleted_at") {
		readSQL += " AND deleted_at IS NULL"
	}
	if pred, pargs, bypass := rowScopeClause(app, wf.Table, session, "view"); !bypass && pred != "" {
		readSQL += " AND " + pred
		readArgs = append(readArgs, pargs...)
	}

	rows, err := QueryRows(app.DB, readSQL, readArgs...)
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
		if hook.When != "" && !evaluateCondition(hook.When, row) {
			continue
		}
		r := copyRow(row)
		EnqueueHookJob(app.DB, hook, r)
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

func startWorkflowTimeoutChecker(app *App, wf *Workflow) {
	safeGo("workflows.timeoutChecker", func() {
		defer func() {
			if r := recover(); r != nil {
				log.Printf("WORKFLOW TIMEOUT PANIC [%s]: %v", wf.Name, r)
			}
		}()

		for {
			time.Sleep(60 * time.Second)
			checkWorkflowTimeouts(app, wf)
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
			wf.Table, wf.Field, seconds,
		)
		if hasColumn(app, wf.Table, "deleted_at") {
			query += " AND deleted_at IS NULL"
		}

		rows, err := QueryRows(app.DB, query, state)
		if err != nil {
			log.Printf("WORKFLOW TIMEOUT ERROR [%s]: %s", wf.Name, err)
			continue
		}

		for _, row := range rows {
			id := fmt.Sprintf("%v", row["id"])

			// Fetch full row for hooks
			fullRows, _ := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id = ?", wf.Table), id)

			// Execute transition
			updateSQL := fmt.Sprintf("UPDATE %s SET %s = ?", wf.Table, wf.Field)
			updateArgs := []any{timeout.To}
			if hasColumn(app, wf.Table, "updated_at") {
				updateSQL += ", updated_at = datetime('now')"
			}
			updateSQL += " WHERE id = ?"
			updateArgs = append(updateArgs, id)

			if _, err := app.DB.Exec(updateSQL, updateArgs...); err != nil {
				log.Printf("WORKFLOW TIMEOUT ERROR [%s] id=%s: %s", wf.Name, id, err)
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

			BroadcastUnscoped(app, wf.Table, "update")
		}
	}
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
// Defined in auth.go.

// validateCSRF checks the CSRF token on the request.
// Defined in auth.go.

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
