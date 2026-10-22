//go:build !cli

package main

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
)

var errRestoreLocked = errors.New("restore target is locked")

// Restoration makes existing relationships visible again. Check every stored
// reference against today's read gate and live-row scope before reviving it.
func restoreForeignKeyTargetDenial(tx mutationQuerier, app *App, table string, actor *Session, row map[string]any) error {
	for column, fk := range foreignKeyRefs(app, table) {
		value := row[column]
		if value == nil || strings.HasPrefix(sqliteIdentifierFold(fk.Table), "_benmore_") {
			continue
		}
		if !SessionCanAccessTable(app, fk.Table, OpRead, actor) || (actor != nil && checkScope(actor, fk.Table, "read") != nil) {
			return &fkTargetError{column: column}
		}
		parentColumn := fk.Column
		if parentColumn == "" {
			parentColumn = "id"
		}
		if !safeIdent(fk.Table) || !safeIdent(parentColumn) {
			return &fkTargetError{column: column}
		}
		query := fmt.Sprintf("SELECT 1 FROM main.%s WHERE %s = ?", quoteIdent(fk.Table), quoteIdent(parentColumn))
		args := []any{value}
		if hasColumn(app, fk.Table, "deleted_at") {
			query += " AND deleted_at IS NULL"
		}
		if pred, pargs, bypass := rowScopeClause(app, fk.Table, actor, "view"); !bypass && pred != "" {
			query += " AND " + pred
			args = append(args, pargs...)
		}
		var one int
		if err := tx.QueryRow(query+" LIMIT 1", args...).Scan(&one); err != nil {
			return &fkTargetError{column: column}
		}
	}
	return nil
}

// Restore is an explicit update action. Its only input is the row ID: a body
// can never turn this into a PATCH that bypasses protected-field checks.
func handleRestore(w http.ResponseWriter, r *http.Request, app *App, table string) {
	if !EnforceCRUDAccess(w, r, app, table, OpUpdate, 0) || !EnforceCRUDAccess(w, r, app, table, OpRead, 0) {
		return
	}
	id := r.PathValue("id")
	if !rowIDCanonical(app, table, id) {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": errUpdateTarget.Error()})
		return
	}
	if !isBearerAuth(r) && !validateCSRF(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}
	actor := getSession(app, r)
	if actor != nil {
		for _, action := range []string{"read", "write"} {
			if err := checkScope(actor, table, action); err != nil {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
				return
			}
		}
	}
	if !hasColumn(app, table, "deleted_at") {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "Table does not support soft-delete restoration (no deleted_at column)"})
		return
	}
	tx, err := app.DB.BeginTx(r.Context(), nil)
	if err != nil {
		serverErrorJSON(w, r, app, table+" restore", err, "Transaction start failed")
		return
	}
	defer tx.Rollback()
	before, after, refreshTables, err := applyCanonicalUpdateTxContextMode(r.Context(), tx, app, actor, table, id, nil, "", false, true)
	if err != nil {
		if respondOwnedField(w, err) || respondStorageFull(w, app, err) || respondDatabaseBusy(w, err) {
			return
		}
		var denied *memberOfUpdateError
		if errors.As(err, &denied) {
			writeMemberOfDenial(w, r, denied.denial)
			return
		}
		if errors.Is(err, errRestoreLocked) {
			httpJSON(w, http.StatusConflict, lockErrorResponse(false, ""))
			return
		}
		var requestErr *updateRequestError
		if errors.As(err, &requestErr) {
			writeUpdateRequestError(w, r, app, table+" restore", requestErr)
		} else {
			serverErrorJSON(w, r, app, table+" restore", err, "Restore failed")
		}
		return
	}
	if err := tx.Commit(); err != nil {
		if !respondStorageFull(w, app, err) && !respondDatabaseBusy(w, err) {
			serverErrorJSON(w, r, app, table+" restore", err, "Commit failed")
		}
		return
	}

	eventRow := copyRow(after)
	for key, value := range before {
		eventRow["old_"+key] = value
	}
	injectSessionContext(eventRow, actor)
	FireFlowsForEvent(app, "on_update", table, eventRow)
	Broadcast(app, table, "update", actor)
	broadcastHookRefreshes(app, refreshTables, []transactionResult{{Table: table, Action: "update"}})
	appendHXTrigger(w, "benmore:changed")
	sanitizeResponseRows(app, table, []map[string]any{after}, actor)
	httpJSON(w, http.StatusOK, after)
}

// Existing app-authored HTTP or private-command routes keep their behavior.
// Any intersecting path conservatively owns this table's restore action; route
// probing uses ServeMux itself so literals, :params and catchalls agree with
// actual registration. This runs only while constructing the route table.
func restoreRouteOwnedByFlow(app *App, table string) bool {
	app.mu.RLock()
	flows := app.Flows
	app.mu.RUnlock()
	targetPath := "/api/" + table + "/{id}/restore"
	for _, flow := range flows {
		method, path := flow.Trigger.Method, flow.Trigger.Path
		if flow.Command != nil && flow.Command.Request != nil {
			method, path = flow.Command.Request.Method, flow.Command.Request.Path
		} else if flow.Command != nil || flow.Trigger.Type != "http" {
			continue
		}
		if method != http.MethodPost {
			continue
		}
		parts := strings.Split(path, "/")
		for i, part := range parts {
			if strings.HasPrefix(part, ":") {
				parts[i] = "{" + strings.TrimPrefix(part, ":") + "}"
			}
		}
		if restoreRouteIntersects(strings.Join(parts, "/"), targetPath) {
			return true
		}
	}
	return false
}

func restoreRouteIntersects(path, targetPath string) (intersects bool) {
	defer func() { _ = recover() }() // Invalid authored routes are rejected by their own validator.
	custom, target := http.NewServeMux(), http.NewServeMux()
	custom.HandleFunc("POST "+path, http.NotFound)
	target.HandleFunc("POST "+targetPath, http.NotFound)
	for _, probe := range []string{appMCPRouteProbe(path, targetPath), appMCPRouteProbe(targetPath, path), appMCPRouteProbe(targetPath, targetPath)} {
		escaped, err := appMCPProbeURL(probe)
		if err != nil {
			continue
		}
		req, err := http.NewRequest(http.MethodPost, escaped, nil)
		if err != nil {
			continue
		}
		_, a := custom.Handler(req)
		_, b := target.Handler(req)
		if a != "" && b != "" {
			return true
		}
	}
	return false
}
