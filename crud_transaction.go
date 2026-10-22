//go:build !cli

package main

// Atomic CRUD transactions and the mutation path shared with record reverts.

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/mattn/go-sqlite3"
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
	decoder := json.NewDecoder(r.Body)
	decoder.UseNumber()
	if err := decoder.Decode(&body); err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON"})
		return
	}
	for i := range body.Operations {
		body.Operations[i].ID = canonicalJSONNumberID(body.Operations[i].ID)
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
			// Only a row in the caller's scope answers 409; any other is
			// the scoped write's 404, never a confirmation it exists.
			lockScope := "edit"
			if op.Action == "delete" {
				lockScope = "delete"
			}
			if locked, by := CheckLock(app.DB, op.Table, fmt.Sprint(op.ID), session.UserID); locked && canAccessRowScoped(app, op.Table, fmt.Sprint(op.ID), session, lockScope) {
				httpJSON(w, http.StatusConflict, lockErrorResponse(app.DevMode, by))
				return
			}
		}
	}

	// Begin transaction
	tx, err := app.DB.Begin()
	if err != nil {
		serverErrorJSON(w, r, app, "_transaction", err, "transaction start failed")
		return
	}
	defer tx.Rollback()

	results := make([]transactionResult, len(operations))
	oldRows := make([]map[string]any, len(operations))
	newRows := make([]map[string]any, len(operations))
	var hookRefreshTables []string

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
				if respondOwnedField(w, err) || respondStorageFull(w, app, err) {
					return
				}
				status, msg := mutationErrorResponse(app, "transaction insert "+op.Table, err)
				httpJSON(w, status, map[string]any{
					"error": fmt.Sprintf("operation %d (insert %s): %s", i, op.Table, msg),
				})
				return
			}
			results[i] = transactionResult{Table: op.Table, Action: "insert", ID: id}

		case "update":
			rowID := fmt.Sprintf("%v", op.ID)
			expected := ""
			if op.Data != nil {
				if v, ok := op.Data["_expected_updated_at"]; ok && v != nil {
					expected = fmt.Sprint(v)
				}
				delete(op.Data, "_expected_updated_at")
			}
			before, after, refreshTables, updateErr := applyCanonicalUpdateTx(tx, app, session, op.Table, rowID, op.Data, expected)
			if updateErr != nil {
				if respondOwnedField(w, updateErr) {
					return
				}
				var denied *memberOfUpdateError
				if errors.As(updateErr, &denied) {
					writeMemberOfDenial(w, r, denied.denial)
					return
				}
				if errors.Is(updateErr, errUpdateConflict) {
					httpJSON(w, http.StatusConflict, map[string]any{"error": "conflict", "message": "Record was modified by another user"})
					return
				}
				if respondStorageFull(w, app, updateErr) {
					return
				}
				var requestErr *updateRequestError
				if errors.As(updateErr, &requestErr) {
					writeUpdateRequestError(w, r, app, "_transaction update "+op.Table, requestErr)
					return
				}
				if respondDatabaseBusy(w, updateErr) {
					return
				}
				httpJSON(w, http.StatusBadRequest, map[string]any{
					"error": fmt.Sprintf("operation %d (update %s/%s): %s", i, op.Table, rowID, publicConstraintMessage(app, "transaction update "+op.Table, updateErr)),
				})
				return
			}
			results[i] = transactionResult{Table: op.Table, Action: "update", ID: op.ID}
			oldRows[i], newRows[i] = before, after
			hookRefreshTables = append(hookRefreshTables, refreshTables...)

		case "delete":
			rowID := fmt.Sprintf("%v", op.ID)
			if err := txDelete(tx, app, op.Table, rowID, session); err != nil {
				if respondStorageFull(w, app, err) {
					return
				}
				status, msg := http.StatusBadRequest, errUpdateTarget.Error()
				if !errors.Is(err, errUpdateTarget) {
					_, msg = mutationErrorResponse(app, "transaction delete "+op.Table, err)
				}
				if _, denied := err.(*membershipManageError); denied {
					status = http.StatusForbidden
				}
				httpJSON(w, status, map[string]any{
					"error": fmt.Sprintf("operation %d (delete %s/%s): %s", i, op.Table, rowID, msg),
				})
				return
			}
			results[i] = transactionResult{Table: op.Table, Action: "delete", ID: op.ID}
		}
		if op.Action != "delete" && op.Action != "update" {
			rows, readErr := queryNativeRowsWith(tx, app, op.Table, "SELECT * FROM "+quoteIdent(op.Table)+" WHERE id = ?", results[i].ID)
			if readErr != nil || len(rows) != 1 {
				if readErr == nil {
					readErr = fmt.Errorf("mutated row %v read back %d rows", results[i].ID, len(rows))
				}
				serverErrorJSON(w, r, app, "_transaction "+op.Action+" "+op.Table, readErr, "could not read mutated row")
				return
			}
			newRows[i] = rows[0]
		}
		// Insert and delete audit rows commit (or roll back) with the
		// mutation; the update pipeline writes its own inside the same tx.
		if op.Action != "update" {
			if err := LogAuditTx(tx, app, op.Action, op.Table, fmt.Sprint(results[i].ID), session, oldRows[i], newRows[i]); err != nil {
				if respondStorageFull(w, app, err) {
					return
				}
				serverErrorJSON(w, r, app, "_transaction "+op.Action+" "+op.Table, err, "audit write failed")
				return
			}
		}

	}

	// Commit
	if err := tx.Commit(); err != nil {
		if respondStorageFull(w, app, err) {
			return
		}
		serverErrorJSON(w, r, app, "_transaction", err, "commit failed")
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
		if res.Action != "update" {
			FireHooks(app, res.Action, res.Table, eventRow)
			FireWebhookSubscriptions(app, res.Action, res.Table, eventRow, session)
		}
		FireFlowsForEvent(app, "on_"+res.Action, res.Table, eventRow)
		Broadcast(app, res.Table, res.Action, session)
	}
	broadcastHookRefreshes(app, hookRefreshTables, results)
	appendHXTrigger(w, "benmore:changed")

	httpJSON(w, http.StatusOK, map[string]any{
		"status":  "committed",
		"count":   len(results),
		"results": results,
	})
}

func broadcastHookRefreshes(app *App, tables []string, results []transactionResult) {
	mutated := make(map[string]bool, len(results))
	for _, result := range results {
		mutated[result.Table] = true
	}
	seen := make(map[string]bool, len(tables))
	for _, table := range tables {
		if table == "" || mutated[table] || seen[table] {
			continue
		}
		seen[table] = true
		BroadcastUnscoped(app, table, "refresh")
	}
}

// insertPlan caches the per-table metadata a create needs, so a bulk path
// (batch, ingest) pays for the column list and the :validate rule scan once,
// not once per row.
type insertPlan struct {
	schemaCols   map[string]Column
	cols         []Column
	validCols    map[string]bool
	protected    protectedFields
	rules        map[string]string
	uuidDefaults []string
}

func newInsertPlan(q mutationQuerier, app *App, table string) (*insertPlan, error) {
	cols, err := tableColumnsWith(q, table)
	if err != nil {
		return nil, err
	}
	rules, err := ExtractValidationRulesWith(app, table, q)
	if err != nil {
		return nil, err
	}
	plan := &insertPlan{schemaCols: prismaWriteColumns(app, table), cols: cols, validCols: make(map[string]bool, len(cols)), protected: protectedCreateFields(app, table), rules: rules}
	plan.uuidDefaults = prismaUUIDDefaultColumns(plan.schemaCols, cols)
	plan.protected.add("id")
	for _, c := range cols {
		plan.validCols[c.Name] = true
	}
	return plan, nil
}

// txInsert performs a single INSERT within a transaction.
// Enforces protected fields and auto-injects user_id/org_id.
// Returns the new row's ID (int64 for INTEGER PK, string for UUID PK).
func txInsert(tx *sql.Tx, app *App, table string, data map[string]any, session *Session) (any, error) {
	plan, err := newInsertPlan(tx, app, table)
	if err != nil {
		return nil, err
	}
	return txInsertWithPlan(tx, app, table, data, session, plan)
}

// txInsertWithPlan is the one create pipeline the transaction, batch and
// ingest paths share: protected and computed columns are dropped, the owner
// and tenant come from the session, submitted foreign keys must point at rows
// the caller can read, and validators plus before-hooks run on the
// transaction's connection. Validation refusals come back as
// *mutationValidationError, foreign-key refusals as *fkTargetError, and a
// create that names no writable column as errNoValidFields.
func txInsertWithPlan(tx *sql.Tx, app *App, table string, data map[string]any, session *Session, plan *insertPlan) (any, error) {
	if v := ownedFieldViolation(app, table, mapKeys(data)...); v != nil {
		return nil, v
	}
	if err := membershipCreateDenial(tx, app, table, session); err != nil {
		return nil, err
	}
	validCols := plan.validCols

	allowed := func(name string) bool {
		return validCols[name] && !plan.protected.has(name) && !workflowCreateStateRefused(app, table, name, data[name])
	}
	if err := requirePrismaCreateFields(plan.schemaCols, data, allowed); err != nil {
		return nil, &mutationValidationError{err: err}
	}
	var normalizeErr error
	data, normalizeErr = normalizePrismaFields(plan.schemaCols, data, allowed)
	if normalizeErr != nil {
		return nil, &mutationValidationError{err: normalizeErr}
	}

	var fields []string
	var placeholders []string
	var values []any

	// Auto-inject the owner and tenant columns under their declared names: a
	// column declared USER_ID is still the owner column to the scoping SQL.
	for _, c := range plan.cols {
		if identIs(c.Name, "user_id") && session != nil {
			fields = append(fields, c.Name)
			placeholders = append(placeholders, "?")
			values = append(values, session.UserID)
		}
		// EFFECTIVE group so a stepped-in admin's created rows land in the
		// acted-as tenant, not the admin's (usually empty) native group.
		if app.Group != nil && identIs(c.Name, app.Group.Key) && session != nil && session.EffectiveHasGroup() {
			fields = append(fields, c.Name)
			placeholders = append(placeholders, "?")
			values = append(values, session.EffectiveGroupID())
		}
	}

	var submitted []string // columns written from the operation, for {{_submitted}}
	submittedValues := make(map[string]any)
	for k, v := range data {
		// A workflow's state column takes only its initial state on insert.
		if plan.protected.has(k) || !validCols[k] || workflowCreateStateRefused(app, table, k, v) {
			continue
		}
		fields = append(fields, k)
		placeholders = append(placeholders, "?")
		values = append(values, v)
		submitted = append(submitted, k)
		submittedValues[k] = v
	}

	if len(fields) == 0 {
		return nil, errNoValidFields
	}
	if err := foreignKeyTargetDenial(tx, app, table, session, submittedValues); err != nil {
		return nil, err
	}

	if err := materializeUUIDDefaults(tx, plan.uuidDefaults, &fields, &values); err != nil {
		return nil, err
	}
	if err := materializeValidatorDefaults(tx, app.validatorConfig(), table, plan.cols, &fields, &values); err != nil {
		return nil, err
	}
	for len(placeholders) < len(fields) {
		placeholders = append(placeholders, "?")
	}

	before := make(map[string]any)
	for i, f := range fields {
		before[f] = values[i]
	}
	markSubmittedFields(before, submitted)
	if err := validateTxMutationRules(tx, app, "insert", table, before, session, plan.rules); err != nil {
		var metadataErr *validationMetadataError
		if errors.As(err, &metadataErr) {
			return nil, err
		}
		return nil, &mutationValidationError{err: err}
	}

	var sealErr error
	fields, values, sealErr = sealNativeCiphertextLiterals(tx, app, table, fields, values)
	if sealErr != nil {
		return nil, sealErr
	}
	for len(placeholders) < len(fields) {
		placeholders = append(placeholders, "?")
	}

	sqlStr := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		quoteIdent(table), strings.Join(quoteIdents(fields), ", "), strings.Join(placeholders, ", "))

	var id any
	if err := tx.QueryRow(sqlStr+" RETURNING id", values...).Scan(&id); err != nil {
		return nil, err
	}
	if rule := memberOfFor(app, table, OpRead); rule != nil && session != nil && memberOfAutoJoins(app, table, rule) {
		if err := memberOfAutoJoinWith(tx, app, rule, id, session); err != nil {
			return nil, fmt.Errorf("founder membership: %w", err)
		}
	}
	return id, nil
}

// txUpdate performs a single UPDATE within a transaction.
// Enforces protected fields and scoping.
var errUpdateConflict = errors.New("record was modified by another user")
var errUpdateTarget = errors.New("not found or not authorized")

type updateRequestError struct {
	status  int
	message string
	cause   error
	// noopEcho: everything submitted was an unchanged command-owned echo, so a
	// single-row PATCH answers 200 with nothing written.
	noopEcho bool
}

func (e *updateRequestError) Error() string { return e.message }
func (e *updateRequestError) Unwrap() error { return e.cause }

// writeUpdateRequestError answers an update pipeline refusal: a 4xx with its
// message, as it is meant for the caller; an internal failure (5xx) through
// serverErrorJSON, which keeps the cause server-side.
func writeUpdateRequestError(w http.ResponseWriter, r *http.Request, app *App, where string, e *updateRequestError) {
	if e.status >= http.StatusInternalServerError {
		cause := e.cause
		if cause == nil {
			cause = errors.New(e.message)
		}
		serverErrorJSONBody(w, r, app, e.status, where, cause, map[string]any{"error": e.message})
		return
	}
	httpJSON(w, e.status, map[string]any{"error": e.message})
}

func updateInternalError(err error) error {
	return &updateRequestError{status: http.StatusInternalServerError, message: "Update failed", cause: err}
}

type memberOfUpdateError struct{ denial *memberOfDenial }

func (e *memberOfUpdateError) Error() string { return "not found or not authorized" }

// protectedUpdateFields returns the columns no update may write. Keys are the
// case-folded names plus every declared column name that folds to one of
// them, so both protected[name] and protectedFields.has(name) refuse a column
// declared USER_ID as surely as user_id.
func protectedUpdateFields(app *App, table string) map[string]bool {
	protected := protectedCreateFields(app, table)
	protected.add("id", "deleted_at")
	protected.add(workflowProtectedFields(app, table)...)
	// With groups.role_field, a membership row's identity column carries the
	// in-tenant role: re-pointing it hands that role to whoever the new value
	// names, so it is as protected as the role column (H-10). A new row may
	// still name any identity; its role column is never client-written.
	if g := app.Group; g != nil && g.RoleField != "" && g.Table != "" && identIs(table, g.Table) {
		protected.add(g.UserField)
	}
	for _, t := range app.Tables {
		if !identIs(t.Name, table) {
			continue
		}
		for _, c := range t.Columns {
			if protected.has(c.Name) {
				protected[c.Name] = true
			}
		}
	}
	return protected
}

// applyCanonicalUpdateTx is the shared one-row update pipeline. The caller owns
// transaction lifetime and all response/commit behavior. MCP grant adapters
// must reauthorize in this same tx and refuse tables with event-flow effects
// until those effects have durable recovery intents.
func applyCanonicalUpdateTx(tx *sql.Tx, app *App, actor *Session, table, id string, values map[string]any, expectedUpdatedAt string) (map[string]any, map[string]any, []string, error) {
	return applyCanonicalUpdateTxContext(context.Background(), tx, app, actor, table, id, values, expectedUpdatedAt)
}

func applyCanonicalUpdateTxContext(ctx context.Context, tx *sql.Tx, app *App, actor *Session, table, id string, values map[string]any, expectedUpdatedAt string) (map[string]any, map[string]any, []string, error) {
	return applyCanonicalUpdateTxContextMode(ctx, tx, app, actor, table, id, values, expectedUpdatedAt, false, false)
}

func applyCanonicalUpdateTxContextPrivate(ctx context.Context, tx *sql.Tx, app *App, actor *Session, table, id string, values map[string]any, expectedUpdatedAt string) (map[string]any, map[string]any, []string, error) {
	return applyCanonicalUpdateTxContextMode(ctx, tx, app, actor, table, id, values, expectedUpdatedAt, true, false)
}

func applyCanonicalUpdateTxContextMode(ctx context.Context, tx *sql.Tx, app *App, actor *Session, table, id string, values map[string]any, expectedUpdatedAt string, private, restore bool) (map[string]any, map[string]any, []string, error) {
	if ctx == nil {
		return nil, nil, nil, errors.New("missing canonical update context")
	}
	q := appMCPContextTx{tx: tx, ctx: ctx, private: private}
	if restore {
		// This is the only server-authored write allowed to clear deleted_at.
		// Never forward a caller's arbitrary fields through restore mode.
		values = map[string]any{"deleted_at": nil}
		if !SessionCanAccessTable(app, table, OpUpdate, actor) || !SessionCanAccessTable(app, table, OpRead, actor) {
			return nil, nil, nil, &updateRequestError{status: http.StatusNotFound, message: errUpdateTarget.Error(), cause: errUpdateTarget}
		}
	}
	if actor != nil {
		if err := checkScope(actor, table, "write"); err != nil {
			return nil, nil, nil, &updateRequestError{status: http.StatusForbidden, message: err.Error(), cause: err}
		}
		if restore {
			if err := checkScope(actor, table, "read"); err != nil {
				return nil, nil, nil, &updateRequestError{status: http.StatusForbidden, message: err.Error(), cause: err}
			}
		}
	}
	before, err := txAuthorizedRowMode(q, app, table, id, actor, "edit", restore)
	if err != nil {
		if errors.Is(err, errUpdateTarget) {
			return nil, nil, nil, &updateRequestError{status: http.StatusNotFound, message: errUpdateTarget.Error(), cause: err}
		}
		return nil, nil, nil, &updateRequestError{status: http.StatusInternalServerError, message: "could not read target row", cause: err}
	}
	if restore {
		// Returning a Row requires read authority before changing its state.
		if _, err := txAuthorizedRowMode(q, app, table, id, actor, "view", true); err != nil {
			if errors.Is(err, errUpdateTarget) {
				return nil, nil, nil, &updateRequestError{status: http.StatusNotFound, message: errUpdateTarget.Error(), cause: err}
			}
			return nil, nil, nil, updateInternalError(err)
		}
		var uid int64
		if actor != nil {
			uid = actor.UserID
		}
		locked, err := canonicalRecordLocked(ctx, tx, table, id, uid)
		if err != nil {
			return nil, nil, nil, updateInternalError(err)
		}
		if locked {
			return nil, nil, nil, errRestoreLocked
		}
	}
	if d := memberOfRepointDenialWith(q, app, table, actor, func(col string) string {
		if v, ok := values[col]; ok && v != nil {
			return fmt.Sprint(v)
		}
		return ""
	}); d != nil {
		return nil, nil, nil, &memberOfUpdateError{denial: d}
	}
	if err := txUpdateMode(q, app, table, id, values, actor, expectedUpdatedAt, restore); err != nil {
		return nil, nil, nil, err
	}
	mainTable := "main." + quoteIdent(table)
	eventRows, err := queryNativeRowsWith(q, app, table, fmt.Sprintf("SELECT * FROM %s WHERE id = ?", mainTable), id)
	if err != nil || len(eventRows) != 1 {
		return nil, nil, nil, &updateRequestError{status: http.StatusInternalServerError, message: "could not read mutated row", cause: err}
	}
	eventRow := make(map[string]any, len(eventRows[0])+len(before))
	for k, v := range eventRows[0] {
		eventRow[k] = v
	}
	for k, v := range before {
		eventRow["old_"+k] = v
	}
	injectSessionContext(eventRow, actor)
	refreshTables, err := fireAfterHooksTx(q, app, "update", table, eventRow)
	if err != nil {
		return nil, nil, nil, &updateRequestError{status: http.StatusInternalServerError, message: "update side effect failed", cause: err}
	}
	afterRows, err := queryNativeRowsWith(q, app, table, fmt.Sprintf("SELECT * FROM %s WHERE id = ?", mainTable), id)
	if err != nil || len(afterRows) != 1 {
		return nil, nil, nil, &updateRequestError{status: http.StatusInternalServerError, message: "could not read mutated row after hooks", cause: err}
	}
	after := afterRows[0]
	after, err = txAuthorizedRow(q, app, table, id, actor, "view")
	if err != nil {
		return nil, nil, nil, &updateRequestError{status: http.StatusForbidden, message: "updated row is not readable", cause: err}
	}
	afterEvent := make(map[string]any, len(after)+len(before))
	for k, v := range after {
		afterEvent[k] = v
	}
	for k, v := range before {
		afterEvent["old_"+k] = v
	}
	injectSessionContext(afterEvent, actor)
	if err := enqueueWebhookSubscriptionsTx(q, app, "update", table, afterEvent, actor); err != nil {
		return nil, nil, nil, &updateRequestError{status: http.StatusInternalServerError, message: "update side effect failed", cause: err}
	}
	if err := LogAuditTx(q, app, "update", table, id, actor, before, after); err != nil {
		return nil, nil, nil, &updateRequestError{status: http.StatusInternalServerError, message: "audit write failed", cause: err}
	}
	return before, after, refreshTables, nil
}

func txUpdate(tx mutationTx, app *App, table string, id string, data map[string]any, session *Session, expectedUpdatedAt string) error {
	return txUpdateMode(tx, app, table, id, data, session, expectedUpdatedAt, false)
}

func txUpdateMode(tx mutationTx, app *App, table string, id string, data map[string]any, session *Session, expectedUpdatedAt string, restore bool) error {
	if restore {
		data = map[string]any{"deleted_at": nil}
	}
	submittedCount := len(data)
	data, ownedErr := ownedUpdateDrop(tx, app, session, table, id, data)
	if ownedErr != nil {
		return ownedErr
	}
	echoed := submittedCount - len(data)
	cols, err := mainTableColumnsWith(tx, table)
	if err != nil {
		return updateInternalError(err)
	}

	protected := protectedFields(protectedUpdateFields(app, table))
	if restore {
		if !hasColumnInList(cols, "deleted_at") {
			return &updateRequestError{status: http.StatusNotFound, message: errUpdateTarget.Error(), cause: errUpdateTarget}
		}
		delete(protected, "deleted_at")
		for _, c := range cols {
			if identIs(c.Name, "deleted_at") {
				data = map[string]any{c.Name: nil}
				break
			}
		}
	}

	validCols := make(map[string]bool)
	for _, c := range cols {
		validCols[c.Name] = true
	}

	before, err := txAuthorizedRowMode(tx, app, table, id, session, "edit", restore)
	if err != nil {
		if errors.Is(err, errUpdateTarget) {
			return &updateRequestError{status: http.StatusNotFound, message: errUpdateTarget.Error(), cause: err}
		}
		return updateInternalError(err)
	}
	data, err = normalizePrismaFields(prismaWriteColumns(app, table), data, func(name string) bool { return validCols[name] && !protected.has(name) })
	if err != nil {
		return &updateRequestError{status: http.StatusUnprocessableEntity, message: err.Error(), cause: err}
	}

	var sets []string
	var writeFields []string
	var values []any
	for k, v := range data {
		if protected.has(k) || !validCols[k] {
			continue
		}
		sets = append(sets, quoteIdent(k)+" = ?")
		writeFields = append(writeFields, k)
		values = append(values, v)
	}
	if len(sets) == 0 {
		return &updateRequestError{status: http.StatusBadRequest, message: "No fields to update", noopEcho: echoed > 0}
	}

	var submitted []string
	changed := make(map[string]any)
	for k, v := range data {
		if !protected.has(k) && validCols[k] {
			if current, ok := before[k]; !ok || current == nil || fmt.Sprint(current) != fmt.Sprint(v) {
				changed[k] = v
			}
			before[k] = v
			submitted = append(submitted, k)
		}
	}
	if err := membershipUpdateDenial(tx, app, table, session, before, changed); err != nil {
		return &updateRequestError{status: http.StatusForbidden, message: err.Error(), cause: err}
	}
	if err := membershipActivationDenial(app, table, session, before, changed); err != nil {
		return err
	}
	// Re-pointing a foreign key needs read access to the new parent, as on
	// create; otherwise the update could attach the row (and any aggregate
	// computed field) to another tenant's record. An unchanged value is not
	// re-checked, so a form that echoes every field still saves.
	parents := changed
	if restore {
		// Reviving a row also revives its relationships. A formerly readable
		// parent may have been deleted or moved outside this caller's scope.
		parents = before
	}
	if err := foreignKeyTargetDenial(tx, app, table, session, parents); err != nil {
		return &updateRequestError{status: http.StatusUnprocessableEntity, message: err.Error(), cause: err}
	}
	if restore {
		if err := restoreForeignKeyTargetDenial(tx, app, table, session, before); err != nil {
			return &updateRequestError{status: http.StatusUnprocessableEntity, message: err.Error(), cause: err}
		}
	}
	// The row here is the current row merged with the change, so the
	// submitted-field list comes from the change alone.
	markSubmittedFields(before, submitted)
	if err := validateTxMutation(tx, app, "update", table, before, session); err != nil {
		var metadataErr *validationMetadataError
		if errors.As(err, &metadataErr) {
			return updateInternalError(err)
		}
		return &updateRequestError{status: http.StatusUnprocessableEntity, message: err.Error(), cause: err}
	}

	writeFields, values, err = sealNativeCiphertextLiterals(tx, app, table, writeFields, values)
	if err != nil {
		return updateInternalError(err)
	}
	sets = sets[:0]
	for _, field := range writeFields {
		sets = append(sets, quoteIdent(field)+" = ?")
	}

	// Compare the API timestamp to the stored instant, then advance its version.
	// Keep the exact stored representation in the SQL predicate so the final
	// write remains a compare-and-swap rather than a rounded time comparison.
	var storedUpdatedAt string
	if validCols["updated_at"] {
		next, stored, err := prepareUpdateTimestamp(tx, table, id, expectedUpdatedAt)
		if err != nil {
			return err
		}
		sets = append(sets, "updated_at = ?")
		values = append(values, next)
		storedUpdatedAt = stored
	}

	sqlStr := fmt.Sprintf("UPDATE main.%s SET %s WHERE id = ?", quoteIdent(table), strings.Join(sets, ", "))
	values = append(values, id)
	if restore {
		sqlStr += " AND deleted_at IS NOT NULL"
	} else if validCols["deleted_at"] {
		sqlStr += " AND deleted_at IS NULL"
	}
	if expectedUpdatedAt != "" && validCols["updated_at"] {
		sqlStr += " AND CAST(updated_at AS TEXT) = ?"
		values = append(values, storedUpdatedAt)
	}

	// Scoping (owner/org OR explicit ACL)
	if pred, pargs, bypass := rowScopeClause(app, table, session, "edit"); !bypass && pred != "" {
		sqlStr += " AND " + pred
		values = append(values, pargs...)
	}

	result, err := tx.Exec(sqlStr, values...)
	if err != nil {
		// An UPDATE rejected by a database constraint is a caller refusal,
		// just as on create. Classify the driver code at this mutation
		// boundary; internal faults may contain constraint-looking text.
		var sqliteErr sqlite3.Error
		if errors.As(err, &sqliteErr) && sqliteErr.Code == sqlite3.ErrConstraint {
			return &updateRequestError{status: http.StatusBadRequest, message: publicConstraintMessage(app, "update "+table, err), cause: err}
		}
		return updateInternalError(err)
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		if expectedUpdatedAt != "" && validCols["updated_at"] {
			return errUpdateConflict
		}
		return &updateRequestError{status: http.StatusNotFound, message: errUpdateTarget.Error(), cause: errUpdateTarget}
	}
	return nil
}

// membershipActivationDenial refuses a generic CRUD change to groups.active_field
// on the groups membership table unless the caller acts inside the row's own
// tenant (effective group equal to the row's group key) or is an admin who
// bypasses row scope. A deactivated member has no tenant any more, yet still
// reaches the row as its owner (user_id) or through a share, and must not be
// able to switch their own membership back on. row is the target row (its
// group key is never client-written); changed holds the submitted columns
// whose value differs.
func membershipActivationDenial(app *App, table string, session *Session, row, changed map[string]any) error {
	g := app.Group
	if g == nil || g.Key == "" || g.Table == "" || !identIs(table, g.Table) || session.IsAdminBypass() {
		return nil
	}
	touched := false
	field := g.ActiveField
	for col, value := range changed {
		if identIs(col, g.ActiveField) || (identIs(col, "deleted_at") && value == nil) {
			touched = true
			field = col
			break
		}
	}
	if !touched {
		return nil
	}
	if session != nil && session.EffectiveHasGroup() {
		for col, v := range row {
			if identIs(col, g.Key) && v != nil && fmt.Sprint(v) == session.EffectiveGroupID() {
				return nil
			}
		}
	}
	return &updateRequestError{status: http.StatusForbidden, message: fmt.Sprintf("%s.%s can only be changed by a member of the row's tenant", table, field)}
}

// txDelete performs a single DELETE (or soft delete) within a transaction.
// Enforces scoping.
func txDelete(tx *sql.Tx, app *App, table string, id string, session *Session) error {
	_, err := txDeleteRow(tx, app, table, id, session)
	return err
}

// txDeleteRow is txDelete returning the deleted row (as read before the
// delete, without session context keys). A missing or out-of-scope row is
// errUpdateTarget and a before-hook refusal is *mutationValidationError.
func txDeleteRow(tx *sql.Tx, app *App, table string, id string, session *Session) (map[string]any, error) {
	row, err := txAuthorizedRow(tx, app, table, id, session, "delete")
	if err != nil {
		return nil, err
	}
	if err := membershipDeleteDenial(tx, app, table, session, row); err != nil {
		return nil, err
	}
	before := make(map[string]any, len(row))
	for k, v := range row {
		before[k] = v
	}
	if err := validateTxMutation(tx, app, "delete", table, before, session); err != nil {
		return nil, &mutationValidationError{err: err}
	}

	var sqlStr string
	var values []any

	if hasColumn(app, table, "deleted_at") {
		sqlStr = "UPDATE " + quoteIdent(table) + " SET deleted_at = datetime('now') WHERE id = ? AND deleted_at IS NULL"
	} else {
		sqlStr = "DELETE FROM " + quoteIdent(table) + " WHERE id = ?"
	}
	values = append(values, id)

	// Scoping (owner/org OR explicit ACL)
	if pred, pargs, bypass := rowScopeClause(app, table, session, "delete"); !bypass && pred != "" {
		sqlStr += " AND " + pred
		values = append(values, pargs...)
	}

	result, err := tx.Exec(sqlStr, values...)
	if err != nil {
		return nil, err
	}
	affected, _ := result.RowsAffected()
	if affected == 0 {
		return nil, errUpdateTarget
	}
	if !hasColumn(app, table, "deleted_at") {
		if err := purgeRowKeyedState(tx, table, id); err != nil {
			return nil, err
		}
	}
	return row, nil
}

// purgeRowKeyedState removes the record shares and locks keyed to a row that
// was just hard-deleted, in the delete's own transaction. They are keyed by
// (table, row id) only, and a plain INTEGER PRIMARY KEY hands a deleted top
// id to the next insert: without this, someone else's new row inherited the
// old row's grants. A soft-deleted row keeps its id, so it keeps them.
func purgeRowKeyedState(tx mutationTx, table, id string) error {
	for _, ledger := range []struct {
		name  string
		query string
	}{
		{"_benmore_permissions", "DELETE FROM main._benmore_permissions WHERE resource_type = ? AND resource_id = ?"},
		{"_benmore_locks", "DELETE FROM main._benmore_locks WHERE table_name = ? AND row_id = ?"},
	} {
		// Either ledger may not exist in an app that never used the feature.
		// Check that explicitly: an existing ledger's failed DELETE (including
		// a trigger failure) must roll back the row deletion, not leave state
		// that a newly inserted row could inherit when SQLite reuses its id.
		var exists bool
		if err := tx.QueryRow(`SELECT EXISTS (SELECT 1 FROM main.sqlite_schema WHERE name = ? COLLATE NOCASE AND type IN ('table', 'view'))`, ledger.name).Scan(&exists); err != nil {
			return fmt.Errorf("check row state ledger %s: %w", ledger.name, err)
		}
		if !exists {
			continue
		}
		if _, err := tx.Exec(ledger.query, table, id); err != nil {
			return fmt.Errorf("delete row state from %s: %w", ledger.name, err)
		}
	}
	return nil
}

// The transaction path shares validators and hook evaluation with ordinary CRUD,
// using the transaction connection so policies see earlier operations atomically.
func validateTxMutation(tx mutationTx, app *App, event, table string, row map[string]any, session *Session) error {
	var rules map[string]string
	if event != "delete" {
		var err error
		rules, err = ExtractValidationRulesWith(app, table, tx)
		if err != nil {
			return err
		}
	}
	return validateTxMutationRules(tx, app, event, table, row, session, rules)
}

// validateTxMutationRules is validateTxMutation with the :validate rules
// already extracted (bulk paths extract them once per request).
func validateTxMutationRules(tx mutationTx, app *App, event, table string, row map[string]any, session *Session, rules map[string]string) error {
	injectSessionContext(row, session)
	if event != "delete" {
		r := &http.Request{Form: make(url.Values)}
		for k, v := range row {
			r.Form.Set(k, jsonToFormValue(v))
		}
		if errs := ValidateFields(r, rules); len(errs) > 0 {
			return fmt.Errorf("field validation failed: %v", errs)
		}
		if err := ValidateCrossField(app.validatorConfig(), table, row); err != nil {
			return err
		}
	}
	if event == "update" {
		// Hook SQL sees what the request sent, not the stored row it was
		// merged into (submittedHookRow).
		return fireBeforeHooksRows(tx, app, event, table, row, submittedHookRow(row, session))
	}
	return fireBeforeHooksWith(tx, app, event, table, row)
}

func txAuthorizedRow(tx mutationQuerier, app *App, table, id string, session *Session, action string) (map[string]any, error) {
	return txAuthorizedRowMode(tx, app, table, id, session, action, false)
}

// deleted selects only soft-deleted rows for the explicit restore action;
// ordinary callers can still see only live rows.
func txAuthorizedRowMode(tx mutationQuerier, app *App, table, id string, session *Session, action string, deleted bool) (map[string]any, error) {
	if !rowIDCanonical(app, table, id) {
		return nil, errUpdateTarget
	}
	q := fmt.Sprintf("SELECT * FROM main.%s WHERE id = ?", quoteIdent(table))
	args := []any{id}
	cols, err := mainTableColumnsWith(tx, table)
	if err != nil {
		return nil, err
	}
	if deleted {
		if !hasColumnInList(cols, "deleted_at") {
			return nil, errUpdateTarget
		}
		q += " AND deleted_at IS NOT NULL"
	} else if hasColumnInList(cols, "deleted_at") {
		q += " AND deleted_at IS NULL"
	}
	if pred, pargs, bypass := rowScopeClause(app, table, session, action); !bypass && pred != "" {
		q += " AND " + pred
		args = append(args, pargs...)
	}
	rows, err := queryNativeRowsWith(tx, app, table, q, args...)
	if err != nil {
		return nil, err
	}
	if len(rows) != 1 {
		return nil, errUpdateTarget
	}
	return rows[0], nil
}
