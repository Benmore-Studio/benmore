//go:build !cli

package main

// Batch record creation, updates, and deletion.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

func handleBatchCreate(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Same coarse access gate as the single-row create (M5, 2026-06-11
	// audit): before this, `access: write: admin` / `all: off` tables
	// were writable through /batch.
	if !EnforceCRUDAccess(w, r, app, table, OpWrite, 0) {
		return
	}
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	var items []map[string]any
	if err := json.NewDecoder(r.Body).Decode(&items); err != nil {
		httpError(w, "Expected JSON array", http.StatusBadRequest)
		return
	}
	if len(items) == 0 {
		httpError(w, "Empty array", http.StatusBadRequest)
		return
	}

	cols, err := GetTableColumns(app.DB, table)
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}

	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "write"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}
	protected := map[string]bool{
		"user_id": true, "created_at": true, "updated_at": true,
		"password_hash": true, "role": true,
		"password_change_required": true,
	}
	if app.Group != nil && app.Group.Key != "" {
		protected[app.Group.Key] = true
	}
	// H-10: protect the configurable in-tenant RoleField (e.g. member_role)
	// on the membership table so a member cannot self-elevate via CRUD.
	if app.Group != nil && app.Group.RoleField != "" && app.Group.Table != "" && table == app.Group.Table {
		protected[app.Group.RoleField] = true
	}

	// Wrap entire batch in a transaction
	tx, err := app.DB.Begin()
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}

	// Extract validation rules once for the table
	validationRules := ExtractValidationRules(app, table)

	isUUID := app.IsUUIDTable(table)
	var ids []any
	for _, item := range items {
		// member-of: every batch item must land in a parent the caller is
		// a member of - same gate as single-row create (M5). All-or-
		// nothing: one bad item rolls the whole batch back.
		if d := memberOfCreateDenial(app, table, session, func(col string) string {
			if v, ok := item[col]; ok && v != nil {
				return fmt.Sprintf("%v", v)
			}
			return ""
		}); d != nil {
			tx.Rollback()
			writeMemberOfDenial(w, r, d)
			return
		}

		var fields []string
		var placeholders []string
		var values []any

		for _, col := range cols {
			if col.PK {
				continue
			}
			if col.Name == "user_id" {
				if session != nil {
					fields = append(fields, col.Name)
					placeholders = append(placeholders, "?")
					values = append(values, session.UserID)
				}
				continue
			}
			if app.Group != nil && col.Name == app.Group.Key && session != nil && session.EffectiveHasGroup() {
				fields = append(fields, col.Name)
				placeholders = append(placeholders, "?")
				values = append(values, session.EffectiveGroupID())
				continue
			}
			if protected[col.Name] {
				continue
			}

			if val, ok := item[col.Name]; ok && val != nil {
				fields = append(fields, col.Name)
				placeholders = append(placeholders, "?")
				values = append(values, fmt.Sprintf("%v", val))
			}
		}

		if len(fields) == 0 {
			continue
		}

		// Validate fields against rules
		if len(validationRules) > 0 {
			for field, rule := range validationRules {
				if val, ok := item[field]; ok {
					valStr := fmt.Sprintf("%v", val)
					for _, r := range strings.Split(rule, ",") {
						r = strings.TrimSpace(r)
						if r == "required" && valStr == "" {
							tx.Rollback()
							httpJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": fmt.Sprintf("Field '%s' is required", field)})
							return
						}
					}
				} else if strings.Contains(rule, "required") {
					tx.Rollback()
					httpJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": fmt.Sprintf("Field '%s' is required", field)})
					return
				}
			}
		}

		// Build before-hook row and fire before-hooks
		beforeRow := make(map[string]any)
		for i, f := range fields {
			beforeRow[f] = values[i]
		}
		injectSessionContext(beforeRow, session)
		if err := FireBeforeHooks(app, "insert", table, beforeRow); err != nil {
			tx.Rollback()
			httpError(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}

		sqlStr := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
			table, strings.Join(fields, ", "), strings.Join(placeholders, ", "))
		result, err := tx.Exec(sqlStr, values...)
		if err != nil {
			tx.Rollback()
			httpError(w, fmt.Sprintf("Batch insert failed: %s", err.Error()), http.StatusBadRequest)
			return
		}

		var id any
		if isUUID {
			var uuidID string
			err := tx.QueryRow(fmt.Sprintf("SELECT id FROM %s WHERE rowid = last_insert_rowid()", table)).Scan(&uuidID)
			if err != nil {
				tx.Rollback()
				httpError(w, "Batch insert failed: could not retrieve UUID", http.StatusInternalServerError)
				return
			}
			id = uuidID
		} else {
			intID, _ := result.LastInsertId()
			id = intID
		}
		ids = append(ids, id)

		// Collect row data for post-commit hooks
		row := make(map[string]any)
		for i, f := range fields {
			row[f] = values[i]
		}
		row["id"] = id
		injectSessionContext(row, session)
	}

	if err := tx.Commit(); err != nil {
		httpError(w, "Commit failed", http.StatusInternalServerError)
		return
	}

	// Fire hooks and audit AFTER commit - hooks write to DB and would deadlock inside the tx
	for _, id := range ids {
		LogAudit(app, "create", table, fmt.Sprintf("%v", id), session, nil, nil)
	}

	Broadcast(app, table, "insert", session)
	appendHXTrigger(w, "benmore:changed")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"ids": ids, "count": len(ids), "status": "created"})
}

func handleBatchUpdate(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Same coarse access gate as the single-row update (M5).
	if !EnforceCRUDAccess(w, r, app, table, OpUpdate, 0) {
		return
	}
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "write"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}

	var body struct {
		IDs    []any             `json:"ids"`
		Fields map[string]string `json:"fields"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, "Expected JSON with ids and fields", http.StatusBadRequest)
		return
	}
	if len(body.IDs) == 0 || len(body.Fields) == 0 {
		httpError(w, "ids and fields required", http.StatusBadRequest)
		return
	}

	// member-of: a batch update that re-points the join column must
	// verify membership in the NEW parent - same gate as single-row
	// update (M5). The per-row WHERE below only proves membership in
	// each row's CURRENT parent.
	if d := memberOfRepointDenial(app, table, session, func(col string) string { return body.Fields[col] }); d != nil {
		writeMemberOfDenial(w, r, d)
		return
	}

	// Build allowlist
	cols, _ := GetTableColumns(app.DB, table)
	validCols := make(map[string]bool)
	for _, c := range cols {
		validCols[c.Name] = true
	}
	protected := map[string]bool{
		"id": true, "user_id": true, "created_at": true,
		"updated_at": true, "password_hash": true, "role": true, "_csrf": true,
		"password_change_required": true,
	}
	if app.Group != nil && app.Group.Key != "" {
		protected[app.Group.Key] = true
	}
	// H-10: same self-escalation guard as the single-row update path - the
	// configurable in-tenant RoleField must be protected on the membership
	// table so a batch update can't elevate a member's role.
	// invariant: a member must never self-set their in-tenant role via CRUD.
	if app.Group != nil && app.Group.RoleField != "" && app.Group.Table != "" && table == app.Group.Table {
		protected[app.Group.RoleField] = true
	}
	for _, f := range workflowProtectedFields(app, table) {
		protected[f] = true
	}

	var sets []string
	var values []any
	for k, v := range body.Fields {
		if protected[k] || !validCols[k] {
			continue
		}
		sets = append(sets, fmt.Sprintf("%s = ?", k))
		values = append(values, v)
	}
	if len(sets) == 0 {
		httpError(w, "No valid fields", http.StatusBadRequest)
		return
	}

	placeholders := make([]string, len(body.IDs))
	for i, id := range body.IDs {
		placeholders[i] = "?"
		values = append(values, id)
	}

	// Fire before-hooks per row - fetch existing rows first
	idPlaceholders := make([]string, len(body.IDs))
	idArgs := make([]any, len(body.IDs))
	for i, id := range body.IDs {
		idPlaceholders[i] = "?"
		idArgs[i] = id
	}
	oldRows, _ := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id IN (%s)", table, strings.Join(idPlaceholders, ",")), idArgs...)
	oldRowIndex := make(map[string]map[string]any)
	for _, row := range oldRows {
		if id, ok := row["id"]; ok {
			oldRowIndex[fmt.Sprintf("%v", id)] = row
		}
	}

	for _, id := range body.IDs {
		beforeRow := make(map[string]any)
		beforeRow["id"] = id
		for k, v := range body.Fields {
			beforeRow[k] = v
		}
		injectSessionContext(beforeRow, session)
		if err := FireBeforeHooks(app, "update", table, beforeRow); err != nil {
			httpError(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}

	sqlStr := fmt.Sprintf("UPDATE %s SET %s WHERE id IN (%s)",
		table, strings.Join(sets, ", "), strings.Join(placeholders, ","))

	// SECURITY: enforce org/owner scoping + ACL on batch update
	if pred, pargs, bypass := rowScopeClause(app, table, session, "edit"); !bypass && pred != "" {
		sqlStr += " AND " + pred
		values = append(values, pargs...)
	}

	result, err := app.DB.Exec(sqlStr, values...)
	if err != nil {
		httpError(w, fmt.Sprintf("Batch update failed: %s", err.Error()), http.StatusBadRequest)
		return
	}
	affected, _ := result.RowsAffected()

	// Fire after-hooks and audit per row
	updatedRows, _ := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id IN (%s)", table, strings.Join(idPlaceholders, ",")), idArgs...)
	for _, row := range updatedRows {
		idStr := fmt.Sprintf("%v", row["id"])
		injectSessionContext(row, session)
		FireHooks(app, "update", table, row)
		FireFlowsForEvent(app, "on_update", table, row)
		FireWebhookSubscriptions(app, "update", table, row, session)
		LogAudit(app, "update", table, idStr, session, oldRowIndex[idStr], row)
	}

	Broadcast(app, table, "update", session)
	appendHXTrigger(w, "benmore:changed")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"updated": affected, "status": "updated"})
}

func handleBatchDelete(w http.ResponseWriter, r *http.Request, app *App, table string) {
	// Same coarse access gate as the single-row delete (M5).
	if !EnforceCRUDAccess(w, r, app, table, OpDelete, 0) {
		return
	}
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return
	}

	session := getSession(app, r)
	if session != nil {
		if err := checkScope(session, table, "delete"); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
			return
		}
	}

	var body struct {
		IDs []any `json:"ids"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpError(w, "Expected JSON with ids", http.StatusBadRequest)
		return
	}
	if len(body.IDs) == 0 {
		httpError(w, "ids required", http.StatusBadRequest)
		return
	}

	placeholders := make([]string, len(body.IDs))
	values := make([]any, len(body.IDs))
	for i, id := range body.IDs {
		placeholders[i] = "?"
		values[i] = id
	}

	// Fetch rows before delete (for before-hooks and audit)
	prefetchRows, _ := QueryRows(app.DB, fmt.Sprintf("SELECT * FROM %s WHERE id IN (%s)", table, strings.Join(placeholders, ",")), values...)

	// Fire before-hooks per row
	for _, row := range prefetchRows {
		injectSessionContext(row, session)
		if err := FireBeforeHooks(app, "delete", table, row); err != nil {
			httpError(w, err.Error(), http.StatusUnprocessableEntity)
			return
		}
	}

	// Soft delete if table has deleted_at, otherwise hard delete
	var sql string
	if hasColumn(app, table, "deleted_at") {
		sql = fmt.Sprintf("UPDATE %s SET deleted_at = datetime('now') WHERE id IN (%s) AND deleted_at IS NULL",
			table, strings.Join(placeholders, ","))
	} else {
		sql = fmt.Sprintf("DELETE FROM %s WHERE id IN (%s)",
			table, strings.Join(placeholders, ","))
	}

	// SECURITY: enforce org/owner scoping + ACL on batch delete
	if pred, pargs, bypass := rowScopeClause(app, table, session, "delete"); !bypass && pred != "" {
		sql += " AND " + pred
		values = append(values, pargs...)
	}

	result, err := app.DB.Exec(sql, values...)
	if err != nil {
		httpError(w, fmt.Sprintf("Batch delete failed: %s", err.Error()), http.StatusBadRequest)
		return
	}
	affected, _ := result.RowsAffected()

	// Cascade soft deletes for each deleted row
	if hasColumn(app, table, "deleted_at") {
		for _, row := range prefetchRows {
			if id, ok := row["id"]; ok {
				cascadeSoftDelete(app, table, fmt.Sprintf("%v", id))
			}
		}
	}

	// Fire after-hooks and audit per row
	for _, row := range prefetchRows {
		idStr := fmt.Sprintf("%v", row["id"])
		injectSessionContext(row, session)
		FireHooks(app, "delete", table, row)
		FireFlowsForEvent(app, "on_delete", table, row)
		FireWebhookSubscriptions(app, "delete", table, row, session)
		LogAudit(app, "delete", table, idStr, session, row, nil)
	}

	Broadcast(app, table, "delete", session)
	appendHXTrigger(w, "benmore:changed")

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{"deleted": affected, "status": "deleted"})
}
