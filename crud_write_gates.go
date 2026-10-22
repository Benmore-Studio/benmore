//go:build !cli

package main

// Write gates shared by every auto-CRUD create and update path (single row,
// batch, ingest, /api/_transaction): the mass-assignment protected set,
// foreign-key target visibility, and the redaction of database constraint
// errors. Keeping them in one place is what stops the bulk paths drifting
// from the single-row path again.

import (
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
)

// protectedFields is a set of column names a client may never write.
// Membership is case-insensitive, like SQLite identifiers: a column declared
// USER_ID is the same column as user_id to the scoping predicates, so it must
// be the same column to the mass-assignment guard too.
type protectedFields map[string]bool

func newProtectedFields(names ...string) protectedFields {
	p := protectedFields{}
	p.add(names...)
	return p
}

func (p protectedFields) add(names ...string) {
	for _, n := range names {
		if n != "" {
			p[sqliteIdentifierFold(n)] = true
		}
	}
}

func (p protectedFields) has(name string) bool {
	return p[sqliteIdentifierFold(name)]
}

// identIs reports whether a column name is the given framework column,
// ignoring ASCII case.
func identIs(name, want string) bool {
	return want != "" && sqliteIdentifierFold(name) == sqliteIdentifierFold(want)
}

// protectedCreateFields is the mass-assignment set for a create on table:
// framework identity columns, the tenant key, the in-tenant role field on the
// membership table, and the columns triggers derive: computed columns and
// blind-index siblings (`<col>_blind`, the HMAC of an encrypted column).
func protectedCreateFields(app *App, table string) protectedFields {
	p := newProtectedFields("user_id", "created_at", "updated_at", "password_hash", "role", "password_change_required")
	if identIs(table, "_benmore_users") {
		p.add(mfaSetupNonceColumn)
	}
	if app == nil {
		return p
	}
	if app.Group != nil && app.Group.Key != "" {
		p.add(app.Group.Key)
	}
	// H-10: protect the configurable in-tenant RoleField (e.g. member_role)
	// on the membership table so a member cannot self-elevate via CRUD.
	if app.Group != nil && app.Group.RoleField != "" && app.Group.Table != "" && identIs(table, app.Group.Table) {
		p.add(app.Group.RoleField)
	}
	p.add(computedColumns(app, table)...)
	p.add(blindIndexSiblingColumns(app, table)...)
	return p
}

// blindIndexSiblingColumns returns table's `<col>_blind` columns. The
// blind-index triggers write them from the encrypted column; a value a client
// supplied would survive a create that omits the base column and any update
// of the sibling alone, detaching the row from equality search.
func blindIndexSiblingColumns(app *App, table string) []string {
	if app == nil || app.Encrypted == nil {
		return nil
	}
	var cols []string
	for t, defs := range app.Encrypted.Fields {
		if !identIs(t, table) {
			continue
		}
		for _, d := range defs {
			if d.BlindIndex && d.Column != "" {
				cols = append(cols, d.Column+blindColSuffix)
			}
		}
	}
	return cols
}

// fkTargetError refuses a write whose foreign key names a parent row the
// caller cannot read. The message is identical whether the parent is missing
// or belongs to someone else, so the refusal is not an existence oracle.
type fkTargetError struct{ column string }

func (e *fkTargetError) Error() string {
	return fmt.Sprintf("%s references a record that does not exist or is not accessible", e.column)
}

// foreignKeyRefs returns table's foreign-key columns: the schema's declared
// FKs (app.JoinMap) plus the FK columns aggregate computed fields use to pick
// the parent row they rewrite.
func foreignKeyRefs(app *App, table string) map[string]ForeignKey {
	refs := map[string]ForeignKey{}
	if app == nil {
		return refs
	}
	for t, fks := range app.joinMapSnapshot() {
		if sqliteIdentifierFold(t) != sqliteIdentifierFold(table) {
			continue
		}
		for col, fk := range fks {
			refs[col] = fk
		}
	}
	for col, fk := range computedAggregateRefs(app, table) {
		if _, declared := refs[col]; !declared {
			refs[col] = fk
		}
	}
	return refs
}

// foreignKeyTargetDenial checks every submitted foreign-key value against the
// caller's READ scope on the parent table, using the transaction's connection
// so parents created earlier in the same transaction count. Only values the
// client submitted are checked: user_id and the tenant key are filled from the
// session. Returns nil when the write may proceed.
//
// The parent is visible when rows of its table are not scoped per row (no
// owner/tenant/membership columns, or an anon/everyone read mode) or when
// the row matches the same predicate the list endpoint applies. Platform
// admins (not stepped into a tenant) are not restricted.
func foreignKeyTargetDenial(q mutationQuerier, app *App, table string, session *Session, submitted map[string]any) error {
	if app == nil || len(submitted) == 0 || session.IsAdminBypass() {
		return nil
	}
	refs := foreignKeyRefs(app, table)
	if len(refs) == 0 {
		return nil
	}
	for col, v := range submitted {
		if v == nil {
			continue
		}
		val := strings.TrimSpace(fmt.Sprint(v))
		if val == "" {
			continue
		}
		var fk ForeignKey
		found := false
		for refCol, ref := range refs {
			if identIs(col, refCol) {
				fk, found = ref, true
				break
			}
		}
		if !found || strings.HasPrefix(sqliteIdentifierFold(fk.Table), "_benmore_") {
			continue
		}
		parentCol := fk.Column
		if parentCol == "" {
			parentCol = "id"
		}
		if !safeIdent(fk.Table) || !safeIdent(parentCol) {
			return &fkTargetError{column: col}
		}
		pred, args, restricted := fkParentScope(app, fk.Table, session)
		if !restricted {
			continue
		}
		query := fmt.Sprintf("SELECT 1 FROM main.%s WHERE %s = ?", quoteIdent(fk.Table), quoteIdent(parentCol))
		qargs := []any{val}
		if pred != "" {
			query += " AND " + pred
			qargs = append(qargs, args...)
		}
		var one int
		if err := q.QueryRow(query+" LIMIT 1", qargs...).Scan(&one); err != nil {
			return &fkTargetError{column: col}
		}
	}
	return nil
}

// fkParentScope returns the read predicate a caller's FK value must satisfy
// on parent. restricted=false means the parent table has no per-row read
// scoping for this caller, so any existing row may be referenced (the schema's
// own FK constraint still checks existence).
func fkParentScope(app *App, parent string, session *Session) (string, []any, bool) {
	hasUID := hasColumn(app, parent, "user_id")
	hasGroupKey := app.Group != nil && app.Group.Key != "" && hasColumn(app, parent, app.Group.Key)
	mode := app.Access.ModeFor(parent, OpRead, hasUID, hasGroupKey)
	if app.Access.ReadAllowsBroaderRows(mode) {
		return "", nil, false
	}
	scoped := hasUID || hasGroupKey || memberOfFor(app, parent, OpRead) != nil
	if !scoped {
		return "", nil, false
	}
	publicReadWhen := ""
	if sc, ok := app.Scopes[parent]; ok {
		publicReadWhen = sc.PublicReadWhen
	}
	if session == nil {
		// An anonymous writer can read only the public slice of a scoped table.
		if publicReadWhen != "" {
			return "(" + publicReadWhen + ")", nil, true
		}
		return "0", nil, true
	}
	pred, args := queryScopeFilter(app, parent, session)
	if pred == "" {
		// Scoped table but no usable identity to scope by: only an explicit
		// public slice is readable.
		return "0", nil, true
	}
	return pred, args, true
}

// writeFKTargetDenial renders a foreign-key refusal.
func writeFKTargetDenial(w http.ResponseWriter, err error) bool {
	var fkErr *fkTargetError
	if !errors.As(err, &fkErr) {
		return false
	}
	httpJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": fkErr.Error()})
	return true
}

// publicConstraintMessage turns a database error from a write into text safe
// to return to the client. The raw SQLite message names constraints, columns
// and sometimes values; a UNIQUE or FOREIGN KEY failure echoed verbatim lets a
// caller probe for other tenants' ids and unique values. Dev mode keeps the
// raw text for debugging; production logs it server-side instead.
func publicConstraintMessage(app *App, context string, err error) string {
	if err == nil {
		return ""
	}
	if app != nil && app.DevMode {
		return err.Error()
	}
	log.Printf("write rejected (%s): %v", context, err)
	msg := err.Error()
	switch {
	case strings.Contains(msg, "UNIQUE constraint failed"), strings.Contains(msg, "PRIMARY KEY"):
		return "a record with the same unique value already exists"
	case strings.Contains(msg, "FOREIGN KEY constraint failed"):
		return "a referenced record does not exist or is not accessible"
	case strings.Contains(msg, "NOT NULL constraint failed"):
		return "a required field is missing"
	case strings.Contains(msg, "CHECK constraint failed"):
		return "a field value is not allowed"
	default:
		return "the write was rejected"
	}
}

// mutationValidationError marks an error from validators or before-hooks:
// author-written text that is meant for the client (422), unlike a database
// error, which is redacted.
type mutationValidationError struct{ err error }

func (e *mutationValidationError) Error() string { return e.err.Error() }
func (e *mutationValidationError) Unwrap() error { return e.err }

// errNoValidFields: a create named no writable column (and none was filled in
// from the session).
var errNoValidFields = errors.New("no valid fields")

// mutationErrorResponse maps an error from the shared create/delete pipeline
// onto a status and client-safe message. Command-owned and storage-full
// errors have their own responders, which callers run first.
func mutationErrorResponse(app *App, context string, err error) (int, string) {
	var fkErr *fkTargetError
	var validationErr *mutationValidationError
	var membershipErr *membershipManageError
	switch {
	case errors.As(err, &membershipErr):
		return http.StatusForbidden, membershipErr.Error()
	case errors.As(err, &fkErr):
		return http.StatusUnprocessableEntity, fkErr.Error()
	case errors.As(err, &validationErr):
		return http.StatusUnprocessableEntity, validationErr.Error()
	case errors.Is(err, errNoValidFields):
		return http.StatusBadRequest, errNoValidFields.Error()
	case isDatabaseBusyError(err):
		return http.StatusServiceUnavailable, "the database is busy, retry shortly"
	}
	return http.StatusBadRequest, publicConstraintMessage(app, context, err)
}
