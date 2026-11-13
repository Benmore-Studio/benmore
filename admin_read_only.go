//go:build !cli

package main

import (
	"net/http"
	"strings"
)

// Framework tables the admin panel shows but never writes.
//
// The panel's write routes (POST /_admin/api/<table>/create|update|delete) run
// the generic CRUD handlers on whatever table the URL names. Generic CRUD is
// the writer of app tables. A framework table has a writer of its own (the
// role API, the permissions API, the job queue, the migration runner, ...)
// that checks what a generic write skips, so the panel writes none of them:
//
//   - record permissions: a hand-made grant skips the share checks;
//   - jobs and scheduled tasks: a hand-made row queues any flow with a payload
//     and actor of the writer's choice;
//   - the audit tables: a hand-made row says someone changed or read a record
//     they never touched (inserts pass the append-only triggers of a
//     compliance: hipaa app, which stop only changes to existing rows);
//   - the credential tables: sessions, tokens, passkeys, reset and sign-in
//     grants and the connector's stores are minted and revoked by the sign-in
//     code, with hashing, expiry, audit rows and revocation of what depends on
//     them. A row written by hand skips all of it;
//   - the role grants: a hand-written grant skips the role API's checks (a
//     declared role, the last admin, and no admin demoting another);
//   - the migrations ledger, webhooks, approvals, locks, custom fields,
//     devices, usage, upload owners and the rest: state the framework keeps
//     consistent with something else.
//
// The rule is the name, not a list: every table whose name starts with
// _benmore_ is read-only here, so a table a later release adds is covered the
// day it exists. The one exception is _benmore_users, which the panel manages
// under the guards of crud_write_gates.go, user_identifier_update.go and
// last_admin_guard.go.
//
// A table the engine owns carries no prefix either: a virtual table and its
// shadow tables (adminEngineOwnedTable).
//
// One framework table carries no prefix: <table>_history, the stored versions
// of a table app.yaml versions. Its writers are the table's history triggers
// and the retention sweep. A row written by hand there is a version that
// never existed (or one that is gone), which the versions API then lists and
// a revert restores; the route's update and delete go by id, and every
// version of a row carries the row's id, so one request rewrote or removed a
// row's whole history. adminPanelReadOnlyKind adds it to the name rule.

const (
	adminReadOnlyAudit      = "audit"
	adminReadOnlyCredential = "credential"
	adminReadOnlyGrants     = "grants"
	adminReadOnlyFramework  = "framework"
	adminReadOnlyHistory    = "history"
	adminReadOnlyIndex      = "index"
)

// frameworkTablePrefix starts the name of every table the framework owns.
const frameworkTablePrefix = "_benmore_"

// adminPanelWritableFrameworkTable is the only framework table the admin
// panel writes.
const adminPanelWritableFrameworkTable = "_benmore_users"

// adminReadOnlyKind reports why the admin panel does not write table: "" for
// a table it does (an app table, or _benmore_users). Names compare as SQLite
// compares them, so a URL naming _BENMORE_AUDIT_LOG is the same table.
//
// The kinds before the last one only choose the message and its docs
// pointer: every name in those registries carries the prefix, so the prefix
// rule alone already makes them read-only (TestAdminReadOnlyKindIsDerivedFromTheName).
func adminReadOnlyKind(table string) string {
	for _, name := range auditAppendOnlyTables {
		if identIs(table, name) {
			return adminReadOnlyAudit
		}
	}
	for _, spec := range restoreGrantTables {
		if identIs(table, spec.name) {
			return adminReadOnlyCredential
		}
	}
	// Role grants: the role API (rbac.go) is their writer, with the declared-
	// role, last-admin and other-admin checks a generic write skips.
	if identIs(table, "_benmore_user_roles") {
		return adminReadOnlyGrants
	}
	for _, name := range restoreMCPTables {
		if identIs(table, name) {
			return adminReadOnlyCredential
		}
	}
	if strings.HasPrefix(sqliteIdentifierFold(table), frameworkTablePrefix) && !identIs(table, adminPanelWritableFrameworkTable) {
		return adminReadOnlyFramework
	}
	return ""
}

// versionHistorySuffix ends the name of a versioned table's history table
// (reconcileVersionedTable creates <table>_history).
const versionHistorySuffix = "_history"

// adminPanelReadOnlyKind reports why the admin panel does not write table:
// the name rule (adminReadOnlyKind), then version history, then the engine's
// own tables (adminEngineOwnedTable). "" for a table it writes.
func adminPanelReadOnlyKind(app *App, table string) string {
	if kind := adminReadOnlyKind(table); kind != "" {
		return kind
	}
	if adminVersionHistoryTable(app, table) {
		return adminReadOnlyHistory
	}
	if adminEngineOwnedTable(app, table) {
		return adminReadOnlyIndex
	}
	return ""
}

// adminEngineOwnedTable reports whether table is a virtual table or a shadow
// table of one: a full-text index (<table>_fts) and the tables SQLite keeps
// its records in (_data, _idx, _docsize, _config, _content). Their writer is
// the engine, as the indexed table's rows change. Two of an FTS5 index's
// shadow tables have an id column, so the panel's generic create, update and
// delete went through on them: the index's own records were replaced, and
// every later insert into the indexed table failed.
//
// The engine says which tables these are (PRAGMA table_list: type virtual or
// shadow), never the name: an app may own a table named notes_fts_data. A
// table list that cannot be read leaves the table read-only.
func adminEngineOwnedTable(app *App, table string) bool {
	if app == nil || app.DB == nil {
		return true
	}
	// The type is compared in the statement: no row means the engine does
	// not own the table (or there is none of that name).
	var owned int
	err := app.DB.QueryRow(`SELECT COUNT(*) FROM pragma_table_list WHERE schema = 'main' AND name = ? COLLATE NOCASE AND type IN ('virtual', 'shadow')`, table).Scan(&owned)
	return err != nil || owned > 0
}

// adminVersionHistoryTable reports whether table holds stored versions. The
// suffix alone decides nothing: an app may own a table named visit_history.
// A history table is one of
//
//   - <source>_history for a source table app.yaml versions now (the name
//     the installer gives it, compared as SQLite compares names);
//   - history kept from a table no longer versioned: the shape the auto-CRUD
//     inventory already keeps out of /api/<table> (isVersionHistoryDefinition,
//     the suffix and all five version metadata columns). Its versions come
//     back into use when the table is versioned again.
//
// A read that fails leaves the table read-only.
func adminVersionHistoryTable(app *App, table string) bool {
	if config := app.versionedConfig(); config != nil {
		for _, source := range config.Tables {
			if identIs(table, source+versionHistorySuffix) {
				return true
			}
		}
	}
	if !strings.HasSuffix(sqliteIdentifierFold(table), versionHistorySuffix) {
		return false
	}
	definitions, err := readCRUDTableDefinitions(app.DB)
	if err != nil {
		return true
	}
	for _, definition := range definitions {
		if identIs(definition.name, table) {
			return isVersionHistoryDefinition(definition)
		}
	}
	return false
}

// adminReadOnlyMessage is the refusal (and the note on the table's page).
func adminReadOnlyMessage(table, kind string) string {
	if kind == adminReadOnlyAudit {
		return table + " is an audit table: the admin panel shows it and never writes it. The framework writes its rows as the events happen; none can be added, edited or deleted here."
	}
	if kind == adminReadOnlyFramework {
		return table + " is a framework table: the admin panel shows it and never writes it. Its rows are written by the framework and by the endpoint of the feature that owns it; none can be added, edited or deleted here."
	}
	if kind == adminReadOnlyHistory {
		return table + " is a version history table: the admin panel shows it and never writes it. Its rows are the earlier states of a versioned table's rows, recorded as they are replaced; none can be added, edited or deleted here. Read them with GET /api/<table>/<id>/versions and restore one with POST /api/<table>/<id>/revert/<version>."
	}
	if kind == adminReadOnlyIndex {
		return table + " is a search index table: the admin panel shows it and never writes it. SQLite keeps its rows as the rows of the indexed table change; none can be added, edited or deleted here."
	}
	if kind == adminReadOnlyGrants {
		return table + " holds role grants: the admin panel shows it and never writes it. Grant, extend and revoke roles with POST, PATCH and DELETE /api/_auth/users/<id>/roles/<role>, and change the primary role on the user's page."
	}
	return table + " holds sign-in credentials: the admin panel shows it and never writes it. Sessions, tokens, passkeys and reset grants are created and revoked through the sign-in and account endpoints."
}

// The framework tables the panel reads outside their own pages: the
// dashboard's tiles and lists, the page header, the search index and the
// Feedback page. Each of those reads is skipped while admin.yaml hides its
// table (AdminConfig.IsTableHidden), like the table's own pages.
const (
	adminUsersTable    = "_benmore_users"
	adminSessionsTable = "_benmore_sessions"
	adminUsageTable    = "_benmore_usage"
	adminAuditTable    = "_benmore_audit_log"
	adminFeedbackTable = "_benmore_feedback"
)

// adminTableHidden reports whether the panel leaves table out: admin.yaml
// hides it (IsTableHidden, names compared as SQLite compares them), or it
// holds the stored versions of a table admin.yaml hides (<table>_history,
// which shows that table's earlier rows). Every panel page and write route
// that takes its table from the URL asks this.
func adminTableHidden(app *App, table string) bool {
	hidden := app.adminConfig()
	if hidden.IsTableHidden(table) {
		return true
	}
	folded := sqliteIdentifierFold(table)
	if !strings.HasSuffix(folded, versionHistorySuffix) || !hidden.IsTableHidden(strings.TrimSuffix(folded, versionHistorySuffix)) {
		return false
	}
	return adminVersionHistoryTable(app, table)
}

// adminHiddenRowsClause is the condition that leaves the rows about a hidden
// table out of a framework table's panel pages, with its arguments, or ""
// when there is nothing to leave out. The framework's own tables keep rows
// about an app table and name it in a `table_name` column: the audit log (the
// old and new values of every change), the read audit, locks, custom fields,
// imports. The condition applies to a table whose name carries the framework
// prefix and which has that column; an app table's own column of that name
// is the app's data.
func adminHiddenRowsClause(app *App, table string, cols []Column) (string, []any) {
	if !strings.HasPrefix(sqliteIdentifierFold(table), frameworkTablePrefix) {
		return "", nil
	}
	names := app.adminConfig().HiddenTables()
	if len(names) == 0 {
		return "", nil
	}
	for _, col := range cols {
		if identIs(col.Name, "table_name") {
			// NOCASE folds the letters SQLite folds in a table name.
			args := make([]any, len(names))
			for i, name := range names {
				args[i] = name
			}
			column := quoteColumn(table, col.Name)
			return "(" + column + " IS NULL OR " + column + " COLLATE NOCASE NOT IN (?" + strings.Repeat(", ?", len(names)-1) + "))", args
		}
	}
	return "", nil
}

// adminRefuseTableWrite answers a panel write the panel does not make and
// reports whether it did: a table admin.yaml hides gets the not-found
// answer its pages get, and a read-only table the 403 that names its writer.
func adminRefuseTableWrite(w http.ResponseWriter, r *http.Request, app *App, table string) bool {
	if adminTableHidden(app, table) {
		notFoundHandler(app)(w, r)
		return true
	}
	kind := adminPanelReadOnlyKind(app, table)
	if kind == "" {
		return false
	}
	httpJSON(w, http.StatusForbidden, withRefusalDocs(map[string]any{
		"error":   "admin_table_read_only",
		"table":   table,
		"message": adminReadOnlyMessage(table, kind),
	}, "admin_table_read_only"))
	return true
}
