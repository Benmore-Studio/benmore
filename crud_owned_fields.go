//go:build !cli

package main

// Command-owned fields at the generic CRUD boundary.
//
// A command flow declares `command.owns: [table.column, ...]` for lifecycle,
// provenance or publication columns that should not be set through generic
// auto-CRUD (create, update, singleton upsert, batch, ingest, transaction,
// group bootstrap, revert, bulk import Mode A, the native MCP table update).
// Those routes refuse any request that names such a column, for every caller
// including admins: ownership is a write path, not a permission. An UPDATE that
// echoes the column's current stored value is a no-op and is allowed (a full-row
// form post) when the caller can read that column; a changed value, an unreadable
// column, any value on create, batch update, the workflow transition route and
// the native MCP table update (strict, no echo) are refused.
//
// Ownership constrains generic CRUD ONLY. It does not make the declaring command
// the sole writer: other commands, ordinary flows (`run: sql`), hooks, cron,
// operator SQL (`sql write:true`, seed/reset) and Mode B SQL restore can still
// write the column, and there is no cross-command check. The declaring command's
// apply keeps its independent scope, role and validation checks.

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
)

// ownedFieldError is returned by every generic write path that meets a
// command-owned column.
type ownedFieldError struct{ Field, Command string }

func (e *ownedFieldError) Error() string {
	return fmt.Sprintf("field %s is owned by command %s", e.Field, e.Command)
}

// commandOwnedColumns returns the folded column name -> owning command for a
// table, read from the app's current flows (published under app.mu together with
// the rest of the runtime generation, so a reload that removes a command lifts
// the restriction with it). The first command in load order wins a shared column.
func commandOwnedColumns(app *App, table string) map[string]string {
	app.mu.RLock()
	flows := app.Flows
	app.mu.RUnlock()
	var owned map[string]string
	fold := sqliteIdentifierFold(table)
	for _, flow := range flows {
		if flow.Command == nil {
			continue
		}
		for _, o := range flow.Command.Owns {
			if sqliteIdentifierFold(o.Table) != fold {
				continue
			}
			if owned == nil {
				owned = map[string]string{}
			}
			if _, taken := owned[sqliteIdentifierFold(o.Column)]; !taken {
				owned[sqliteIdentifierFold(o.Column)] = flow.Name
			}
		}
	}
	return owned
}

// ownedFieldChecker resolves the table's owned set once (for per-item loops);
// the returned func reports the first owned column among keys (sorted, so the
// answer is deterministic), or nil. With no owned columns it is a cheap no-op.
func ownedFieldChecker(app *App, table string) func(keys ...string) *ownedFieldError {
	owned := commandOwnedColumns(app, table)
	if len(owned) == 0 {
		return func(...string) *ownedFieldError { return nil }
	}
	return func(keys ...string) *ownedFieldError {
		sort.Strings(keys)
		for _, k := range keys {
			if cmd, ok := owned[sqliteIdentifierFold(k)]; ok {
				return &ownedFieldError{Field: table + "." + k, Command: cmd}
			}
		}
		return nil
	}
}

func ownedFieldViolation(app *App, table string, keys ...string) *ownedFieldError {
	return ownedFieldChecker(app, table)(keys...)
}

// ownedEchoReadable reports whether session may READ column k of this row, which
// is the precondition for letting an echo of its stored value through: the
// 403-vs-200 answer of the comparison would otherwise be an equality oracle on a
// value the caller cannot read. Hidden, encrypted/masked, scope-unreadable or
// read-denied columns, and rows the caller cannot view, are strict violations.
func ownedEchoReadable(q mutationQuerier, app *App, session *Session, table, id, k string) bool {
	if apiHiddenColumn(app, table, k) || !SessionCanAccessTable(app, table, OpRead, session) {
		return false
	}
	if app.Encrypted != nil {
		for _, def := range app.Encrypted.Fields[table] {
			if sqliteIdentifierFold(def.Column) == sqliteIdentifierFold(k) {
				return false
			}
		}
	}
	_, err := txAuthorizedRow(q, app, table, id, session, "view")
	return err == nil
}

// ownedUpdateDrop applies the UPDATE rule to data for row id: an owned column
// whose value equals the stored one is dropped from the write (a full-row echo is
// a no-op) when the caller can read that column; any other owned column is a
// violation. The comparison is done by SQLite in the caller's transaction, so
// column affinity coerces the value exactly as the write would. Echoing NULL as
// "" is a change and is refused. A failing comparison query is an internal error,
// never an ownership refusal.
func ownedUpdateDrop(q mutationQuerier, app *App, session *Session, table, id string, data map[string]any) (map[string]any, error) {
	check := ownedFieldChecker(app, table)
	if check(mapKeys(data)...) == nil {
		return data, nil
	}
	kept := make(map[string]any, len(data))
	for k, v := range data {
		if check(k) == nil {
			kept[k] = v
			continue
		}
		if !ownedEchoReadable(q, app, session, table, id, k) {
			return nil, check(k)
		}
		var same bool
		stmt := fmt.Sprintf("SELECT EXISTS(SELECT 1 FROM main.%s WHERE id = ? AND %s IS ?)", quoteIdent(table), quoteColumn(table, k))
		if err := q.QueryRow(stmt, id, v).Scan(&same); err != nil {
			return nil, updateInternalError(err)
		}
		if !same {
			return nil, check(k)
		}
	}
	return kept, nil
}

func mapKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}

// writeOwnedFieldRefusal answers 403 with the documented JSON error.
func writeOwnedFieldRefusal(w http.ResponseWriter, v *ownedFieldError) {
	httpJSON(w, http.StatusForbidden, map[string]any{
		"error":   "field_owned_by_command",
		"field":   v.Field,
		"command": v.Command,
		"message": "this field can only be changed by its command",
	})
}

// respondOwnedField writes the refusal when err carries one.
func respondOwnedField(w http.ResponseWriter, err error) bool {
	var v *ownedFieldError
	if errors.As(err, &v) {
		writeOwnedFieldRefusal(w, v)
		return true
	}
	return false
}

// stripOwnedFields removes command-owned columns from a values map (used by
// version revert, which restores every other column) and returns what it removed.
func stripOwnedFields(app *App, table string, values map[string]any) []string {
	owned := commandOwnedColumns(app, table)
	var stripped []string
	for k := range values {
		if _, ok := owned[sqliteIdentifierFold(k)]; ok {
			delete(values, k)
			stripped = append(stripped, k)
		}
	}
	sort.Strings(stripped)
	return stripped
}
