//go:build !cli

package main

// Atomic CRUD transactions and the mutation path shared with record reverts.

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// transactionOp represents a single operation within an atomic transaction.
type transactionOp struct {
	Table  string         `json:"table"`
	Action string         `json:"action"` // "insert", "update", "delete"
	Data   map[string]any `json:"data"`   // field values for insert/update
	ID     any            `json:"id"`     // row ID for update/delete
	Ref    string         `json:"ref"`    // FK field to set from a prior operation's ID (e.g., "order_id")
	RefOp  int            `json:"ref_op"` // index of prior operation whose ID to use
}

// transactionResult is the result of one operation in the transaction.
type transactionResult struct {
	Table  string `json:"table"`
	Action string `json:"action"`
	ID     any    `json:"id"`
}

// handleTransaction executes multiple CRUD operations atomically in a single transaction.
// If any operation fails, the entire transaction rolls back.
//
// Request: POST /api/_transaction
// Body: {"operations": [{table, action, data, id?, ref?, ref_op?}, ...]}
//
// The "ref" field enables forward references: if operation 0 inserts an order and
// operation 1 inserts a line item, set ref="order_id" and ref_op=0 on operation 1
// to automatically set line_items.order_id = the ID from operation 0.
func handleTransaction(w http.ResponseWriter, r *http.Request, app *App) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	var body struct {
		Operations []transactionOp `json:"operations"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	executeCRUDTransaction(w, r, app, body.Operations)
}

// executeCRUDTransaction is the shared mutation pipeline for transactions and
// version reverts. It preserves typed SQL values and every CRUD security gate.
func executeCRUDTransaction(w http.ResponseWriter, r *http.Request, app *App, operations []transactionOp) {
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	if !isBearerAuth(r) && !validateCSRF(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	if len(operations) == 0 {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "no operations"})
		return
	}

	// Validate all tables exist and actions are valid
	validTables := make(map[string]bool)
	tables, _ := GetTableNames(app.DB)
	for _, t := range tables {
		validTables[t] = true
	}
	for i, op := range operations {
		if !validTables[op.Table] {
			httpJSON(w, http.StatusBadRequest, map[string]any{
				"error": fmt.Sprintf("operation %d: unknown table '%s'", i, op.Table),
			})
			return
		}
		if op.Action != "insert" && op.Action != "update" && op.Action != "delete" {
			httpJSON(w, http.StatusBadRequest, map[string]any{
				"error": fmt.Sprintf("operation %d: invalid action '%s' (must be insert, update, or delete)", i, op.Action),
			})
			return
		}
		if op.Ref != "" && (op.RefOp < 0 || op.RefOp >= i) {
			httpJSON(w, http.StatusBadRequest, map[string]any{
				"error": fmt.Sprintf("operation %d: ref_op must reference a prior operation (0-%d)", i, i-1),
			})
			return
		}
		// Scope check per operation
		scopeAction := "write"
		if op.Action == "delete" {
			scopeAction = "delete"
		}
		if err := checkScope(session, op.Table, scopeAction); err != nil {
			httpJSON(w, http.StatusForbidden, map[string]any{
				"error": fmt.Sprintf("operation %d: %s", i, err.Error()),
			})
			return
		}
		// Coarse access gate per operation (M5, 2026-06-11 audit) - the
		// same EnforceCRUDAccess every single-row handler runs. Before
		// this, `access: write: admin` / `all: off` tables were writable
		// through /api/_transaction.
		opAccess := OpWrite
		switch op.Action {
		case "update":
			opAccess = OpUpdate
		case "delete":
			opAccess = OpDelete
		}
		if !EnforceCRUDAccess(w, r, app, op.Table, opAccess, 0) {
			return
		}
		if op.Action != "insert" {
			if locked, by := CheckLock(app.DB, op.Table, fmt.Sprint(op.ID), session.UserID); locked {
				httpJSON(w, http.StatusConflict, lockErrorResponse(app.DevMode, by))
				return
			}
		}
	}

	// Begin transaction
	tx, err := app.DB.Begin()
	if err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "transaction start failed"})
		return
	}
	defer tx.Rollback()

	results := make([]transactionResult, len(operations))
	oldRows := make([]map[string]any, len(operations))
	newRows := make([]map[string]any, len(operations))

	for i, op := range operations {
		// Resolve forward reference
		if op.Ref != "" && i > 0 {
			refID := results[op.RefOp].ID
			if refID != nil {
				if op.Data == nil {
					op.Data = make(map[string]any)
				}
				op.Data[op.Ref] = refID
			}
		}

		memberOfVal := func(col string) string {
			if v, ok := op.Data[col]; ok && v != nil {
				return fmt.Sprint(v)
			}
			return ""
		}
		if op.Action != "insert" {
			action := "edit"
			if op.Action == "delete" {
				action = "delete"
			}
			oldRows[i], err = txAuthorizedRow(tx, app, op.Table, fmt.Sprint(op.ID), session, action)
			if err != nil {
				httpJSON(w, http.StatusBadRequest, map[string]any{"error": "not found or not authorized"})
				return
			}
		}

		switch op.Action {
		case "insert":
			if d := memberOfCreateDenialWith(tx, app, op.Table, session, memberOfVal); d != nil {
				writeMemberOfDenial(w, r, d)
				return
			}
			id, err := txInsert(tx, app, op.Table, op.Data, session)
			if err != nil {
				httpJSON(w, http.StatusBadRequest, map[string]any{
					"error": fmt.Sprintf("operation %d (insert %s): %s", i, op.Table, err),
				})
				return
			}
			results[i] = transactionResult{Table: op.Table, Action: "insert", ID: id}

		case "update":
			if d := memberOfRepointDenialWith(tx, app, op.Table, session, memberOfVal); d != nil {
				writeMemberOfDenial(w, r, d)
				return
			}
			rowID := fmt.Sprintf("%v", op.ID)
			if err := txUpdate(tx, app, op.Table, rowID, op.Data, session); err != nil {
				httpJSON(w, http.StatusBadRequest, map[string]any{
					"error": fmt.Sprintf("operation %d (update %s/%s): %s", i, op.Table, rowID, err),
				})
				return
			}
			results[i] = transactionResult{Table: op.Table, Action: "update", ID: op.ID}

		case "delete":
			rowID := fmt.Sprintf("%v", op.ID)
			if err := txDelete(tx, app, op.Table, rowID, session); err != nil {
				httpJSON(w, http.StatusBadRequest, map[string]any{
					"error": fmt.Sprintf("operation %d (delete %s/%s): %s", i, op.Table, rowID, err),
				})
				return
			}
			results[i] = transactionResult{Table: op.Table, Action: "delete", ID: op.ID}
		}
		if op.Action != "delete" {
			rows, readErr := queryRowsWith(tx, fmt.Sprintf("SELECT * FROM %s WHERE id = ?", op.Table), results[i].ID)
			if readErr != nil || len(rows) != 1 {
				httpJSON(w, 500, map[string]any{"error": "could not read mutated row"})
				return
			}
			newRows[i] = rows[0]
		}

	}

	// Commit
	if err := tx.Commit(); err != nil {
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "commit failed"})
		return
	}

	// Post-commit: fire hooks, audit, SSE for each operation
	for i, res := range results {
		row := newRows[i]
		if res.Action == "delete" {
			row = oldRows[i]
		}
		eventRow := make(map[string]any)
		for k, v := range row {
			eventRow[k] = v
		}
		if res.Action == "update" {
			for k, v := range oldRows[i] {
				eventRow["old_"+k] = v
			}
		}

		injectSessionContext(eventRow, session)
		FireHooks(app, res.Action, res.Table, eventRow)
		FireFlowsForEvent(app, "on_"+res.Action, res.Table, eventRow)
		FireWebhookSubscriptions(app, res.Action, res.Table, eventRow, session)
		LogAudit(app, res.Action, res.Table, fmt.Sprint(res.ID), session, oldRows[i], newRows[i])
		Broadcast(app, res.Table, res.Action, session)
	}
	appendHXTrigger(w, "benmore:changed")

	httpJSON(w, http.StatusOK, map[string]any{
		"status":  "committed",
		"count":   len(results),
		"results": results,
	})
}

// txInsert performs a single INSERT within a transaction.
// Enforces protected fields and auto-injects user_id/org_id.
// Returns the new row's ID (int64 for INTEGER PK, string for UUID PK).
func txInsert(tx *sql.Tx, app *App, table string, data map[string]any, session *Session) (any, error) {
	cols, err := tableColumnsWith(tx, table)
	if err != nil {
		return nil, err
	}

	protected := map[string]bool{
		"id": true, "user_id": true, "created_at": true, "updated_at": true,
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
	for _, f := range workflowProtectedFields(app, table) {
		protected[f] = true
	}

	validCols := make(map[string]bool)
	for _, c := range cols {
		validCols[c.Name] = true
	}

	var fields []string
	var placeholders []string
	var values []any

	// Auto-inject user_id
	if session != nil && validCols["user_id"] {
		fields = append(fields, "user_id")
		placeholders = append(placeholders, "?")
		values = append(values, session.UserID)
	}
	// Auto-inject org key - EFFECTIVE group so a stepped-in admin's created
	// rows land in the acted-as tenant, not the admin's (usually empty) native group.
	if app.Group != nil && app.Group.Key != "" && session != nil && session.EffectiveHasGroup() && validCols[app.Group.Key] {
		fields = append(fields, app.Group.Key)
		placeholders = append(placeholders, "?")
		values = append(values, session.EffectiveGroupID())
	}

	for k, v := range data {
		if protected[k] || !validCols[k] {
			continue
		}
		fields = append(fields, k)
		placeholders = append(placeholders, "?")
		values = append(values, v)
	}

	if len(fields) == 0 {
		return nil, fmt.Errorf("no valid fields")
	}

	before := make(map[string]any)
	for i, f := range fields {
		before[f] = values[i]
	}
	if err := validateTxMutation(tx, app, "insert", table, before, session); err != nil {
		return nil, err
	}

	sqlStr := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		table, strings.Join(fields, ", "), strings.Join(placeholders, ", "))

	var id any
	if err := tx.QueryRow(sqlStr+" RETURNING id", values...).Scan(&id); err != nil {
		return nil, err
	}
	if rule := memberOfFor(app, table, OpRead); rule != nil && session != nil && rule.localJoinCol(app, table) == "id" {
		if err := memberOfAutoJoinWith(tx, app, rule, id, session); err != nil {
			return nil, fmt.Errorf("founder membership: %w", err)
		}
	}
	return id, nil
}

// txUpdate performs a single UPDATE within a transaction.
// Enforces protected fields and scoping.
func txUpdate(tx *sql.Tx, app *App, table string, id string, data map[string]any, session *Session) error {
	cols, err := tableColumnsWith(tx, table)
	if err != nil {
		return err
	}

	protected := map[string]bool{
		"id": true, "user_id": true, "created_at": true,
		"updated_at": true, "password_hash": true, "role": true,
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
	for _, f := range workflowProtectedFields(app, table) {
		protected[f] = true
	}

	validCols := make(map[string]bool)
	for _, c := range cols {
		validCols[c.Name] = true
	}

	var sets []string
	var values []any
	for k, v := range data {
		if protected[k] || !validCols[k] {
			continue
		}
		sets = append(sets, fmt.Sprintf("%s = ?", k))
		values = append(values, v)
	}
	if len(sets) == 0 {
		return fmt.Errorf("no valid fields")
	}

	before, err := txAuthorizedRow(tx, app, table, id, session, "edit")
	if err != nil {
		return err
	}
	for k, v := range data {
		if !protected[k] && validCols[k] {
			before[k] = v
		}
	}
	if err := validateTxMutation(tx, app, "update", table, before, session); err != nil {
		return err
	}

	// Auto-set updated_at
	if validCols["updated_at"] {
		sets = append(sets, "updated_at = datetime('now')")
	}

	sqlStr := fmt.Sprintf("UPDATE %s SET %s WHERE id = ?", table, strings.Join(sets, ", "))
	values = append(values, id)

	// Scoping (owner/org OR explicit ACL)
	if pred, pargs, bypass := rowScopeClause(app, table, session, "edit"); !bypass && pred != "" {
		sqlStr += " AND " + pred
		values = append(values, pargs...)
	}

	result, err := tx.Exec(sqlStr, values...)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("not found or not authorized")
	}
	return nil
}

// txDelete performs a single DELETE (or soft delete) within a transaction.
// Enforces scoping.
func txDelete(tx *sql.Tx, app *App, table string, id string, session *Session) error {
	before, err := txAuthorizedRow(tx, app, table, id, session, "delete")
	if err != nil {
		return err
	}
	if err := validateTxMutation(tx, app, "delete", table, before, session); err != nil {
		return err
	}

	var sqlStr string
	var values []any

	if hasColumn(app, table, "deleted_at") {
		sqlStr = fmt.Sprintf("UPDATE %s SET deleted_at = datetime('now') WHERE id = ? AND deleted_at IS NULL", table)
	} else {
		sqlStr = fmt.Sprintf("DELETE FROM %s WHERE id = ?", table)
	}
	values = append(values, id)

	// Scoping (owner/org OR explicit ACL)
	if pred, pargs, bypass := rowScopeClause(app, table, session, "delete"); !bypass && pred != "" {
		sqlStr += " AND " + pred
		values = append(values, pargs...)
	}

	result, err := tx.Exec(sqlStr, values...)
	if err != nil {
		return err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return fmt.Errorf("not found or not authorized")
	}
	return nil
}

// The transaction path shares validators and hook evaluation with ordinary CRUD,
// using the transaction connection so policies see earlier operations atomically.
func validateTxMutation(tx *sql.Tx, app *App, event, table string, row map[string]any, session *Session) error {
	injectSessionContext(row, session)
	if event != "delete" {
		r := &http.Request{Form: make(url.Values)}
		for k, v := range row {
			r.Form.Set(k, jsonToFormValue(v))
		}
		if errs := ValidateFields(r, ExtractValidationRules(app, table)); len(errs) > 0 {
			return fmt.Errorf("field validation failed: %v", errs)
		}
		if err := ValidateCrossField(app.Validators, table, row); err != nil {
			return err
		}
	}
	return fireBeforeHooksWith(tx, app, event, table, row)
}

func txAuthorizedRow(tx *sql.Tx, app *App, table, id string, session *Session, action string) (map[string]any, error) {
	q := fmt.Sprintf("SELECT * FROM %s WHERE id = ?", table)
	args := []any{id}
	if hasColumn(app, table, "deleted_at") {
		q += " AND deleted_at IS NULL"
	}
	if pred, pargs, bypass := rowScopeClause(app, table, session, action); !bypass && pred != "" {
		q += " AND " + pred
		args = append(args, pargs...)
	}
	rows, err := queryRowsWith(tx, q, args...)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, fmt.Errorf("not found or not authorized")
	}
	return rows[0], nil
}
