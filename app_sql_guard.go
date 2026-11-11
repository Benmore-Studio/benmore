//go:build !cli

package main

// App-authored SQL may not change the framework's own schema objects.
//
// Flow `run: sql` / `sql_dynamic` steps (request, cron, event and async
// flows, the /_admin tool runner), hooks.yaml `sql:` (before-hooks, after-hooks
// in the write's transaction, queued hook jobs, workflow effects) and page
// <query> tags run text an app editor wrote on the app's ordinary connections.
// A flow could therefore `DROP TRIGGER _benmore_audit_log_no_update` and
// rewrite an audit row of a `compliance: hipaa` app in its next step, and the
// trigger stayed gone for every writer until the next reload.
//
// Such a statement now runs inside a scope the engine enforces. The call site
// passes the text through appSQL, which puts a marker comment in front of it;
// the driver wrapper (benmoreConn) removes the marker and, for exactly that
// driver call, makes the connection's authorizer apply appSQLScope.authorize
// to every action SQLite compiles. The decision is made from the authorizer's
// action code and its table/trigger/index arguments, so quoting, a `main.`
// prefix, comments, a CTE or text built by sql_dynamic cannot hide the object.
// The marker is in-band because hook SQL reaches the driver through several
// wrappers that take no context; app text cannot remove a prefix the
// framework adds, and a text that starts with the marker itself only gets the
// scope.
//
// Refused inside the scope:
//   - CREATE / DROP of a table, view, index, trigger or virtual table whose
//     name starts with _benmore_, in main or temp (a TEMP table of that name
//     would shadow the real one on its pooled connection);
//   - CREATE / DROP of an index or trigger ON a _benmore_ table, whatever the
//     object is called, and ALTER TABLE of one;
//   - ALTER TABLE ... RENAME TO a _benmore_ name (the one case the authorizer
//     is not told about; read off the shared lexer before the statement runs);
//   - setting PRAGMA writable_schema, which would let plain DML edit
//     sqlite_master;
//   - for a `compliance: hipaa` app, UPDATE and DELETE on the audit tables
//     and an INSERT that replaces (REPLACE INTO, INSERT OR REPLACE; lexer,
//     as for RENAME TO), so append-only does not depend on the triggers being
//     there.
//
// Still allowed: reading and writing ROWS of framework tables (INSERT into
// the audit tables included), DDL on the app's own tables, and DROP TABLE of
// an app table that carries framework triggers (versioning, encryption,
// computed fields): SQLite reports the triggers that go with the table like a
// DROP TRIGGER statement, so the scope counts the table's framework triggers
// before the call and admits exactly that many after its DROP_TABLE. SQLite
// itself refuses DDL on sqlite_* objects once writable_schema cannot be set.
//
// Not in the scope: approved connector commands, hook `when:`, aggregates and
// connector reads run under their own stricter authorizers; seeds.sql runs
// under the reset authorizer; `sql(write:true)` and SQL imports take DML only.
// User migration files have a scope of their own, authorizeMigration
// (migration_framework_guard.go).

import (
	"context"
	"database/sql/driver"
	"fmt"
	"log"
	"maps"
	"slices"
	"strings"
	"sync"

	sqlite3 "github.com/mattn/go-sqlite3"
)

const (
	appSQLMark            = "/*benmore:app-sql*/"
	appSQLMarkHIPAA       = "/*benmore:app-sql:hipaa*/"
	appMigrationMark      = "/*benmore:app-migration*/"
	appMigrationMarkHIPAA = "/*benmore:app-migration:hipaa*/"
)

// appSQL marks query as app-authored for the driver call that runs it. Mark
// the text at the Exec/Query call, after every check that reads it.
func appSQL(app *App, query string) string {
	if app.hipaa() {
		return appSQLMarkHIPAA + query
	}
	return appSQLMark + query
}

// appMigrationSQL marks one statement of a user migration file
// (migration_framework_guard.go) for the driver call that runs it.
func appMigrationSQL(hipaa bool, stmt string) string {
	if hipaa {
		return appMigrationMarkHIPAA + stmt
	}
	return appMigrationMark + stmt
}

// cutAppSQLMark removes the marker and returns the scope it asks for.
func cutAppSQLMark(query string) (string, *appSQLScope) {
	if rest, ok := strings.CutPrefix(query, appMigrationMarkHIPAA); ok {
		return rest, &appSQLScope{migration: true, hipaa: true}
	}
	if rest, ok := strings.CutPrefix(query, appMigrationMark); ok {
		return rest, &appSQLScope{migration: true}
	}
	if rest, ok := strings.CutPrefix(query, appSQLMarkHIPAA); ok {
		return rest, &appSQLScope{hipaa: true}
	}
	if rest, ok := strings.CutPrefix(query, appSQLMark); ok {
		return rest, &appSQLScope{}
	}
	return query, nil
}

// appSQLScope is the policy for one driver call (or one page query).
type appSQLScope struct {
	hipaa bool
	// migration: the statement comes from a user migration file, which takes
	// the narrower rules of authorizeMigration.
	migration bool
	// refused is the first refusal, in words for the app's builder.
	refused string
	// SQLite reports the triggers that go with a dropped table as DROP_TRIGGER
	// actions after its DROP_TABLE. frameworkTriggers counts, per table of
	// main, the framework-named triggers it had when the call began (nil when
	// the text holds no DROP); dropping is the table of the last DROP_TABLE and
	// implicit how many of its framework triggers are still to be reported.
	// Every one beyond that count is a DROP TRIGGER statement.
	frameworkTriggers map[string]int
	dropping          string
	implicit          int
}

// appSQLRefusedError replaces SQLite's "not authorized".
type appSQLRefusedError struct{ reason string }

func (e *appSQLRefusedError) Error() string { return e.reason }

func frameworkObjectName(name string) bool {
	return strings.HasPrefix(sqliteIdentifierFold(name), "_benmore_")
}

func auditAppendOnlyTable(name string) bool {
	folded := sqliteIdentifierFold(name)
	for _, table := range auditAppendOnlyTables {
		if folded == table {
			return true
		}
	}
	return false
}

func (s *appSQLScope) refuse(format string, args ...any) int {
	if s.refused == "" {
		s.refused = fmt.Sprintf(format, args...)
	}
	return sqlite3.SQLITE_DENY
}

const appSQLFrameworkObjectRule = "Flow, hook and page SQL reads and writes rows, and may create, change or drop the app's own tables, indexes, triggers and views; those of the framework (_benmore_*) are not the app's to change"

func (s *appSQLScope) refuseObject(verb, kind, name string) int {
	return s.refuse("app SQL may not %s the framework %s %s. %s.", verb, kind, name, appSQLFrameworkObjectRule)
}

// authorize is the scope's answer to one authorizer action.
func (s *appSQLScope) authorize(action int, arg1, arg2, database string) int {
	if s.migration {
		return s.authorizeMigration(action, arg1, arg2)
	}
	switch action {
	case sqlite3.SQLITE_CREATE_TABLE, sqlite3.SQLITE_CREATE_TEMP_TABLE, sqlite3.SQLITE_CREATE_VTABLE:
		if frameworkObjectName(arg1) {
			return s.refuseObject("create", "table", arg1)
		}
	case sqlite3.SQLITE_CREATE_VIEW, sqlite3.SQLITE_CREATE_TEMP_VIEW:
		if frameworkObjectName(arg1) {
			return s.refuseObject("create", "view", arg1)
		}
	case sqlite3.SQLITE_DROP_TABLE, sqlite3.SQLITE_DROP_TEMP_TABLE, sqlite3.SQLITE_DROP_VTABLE,
		sqlite3.SQLITE_DROP_VIEW, sqlite3.SQLITE_DROP_TEMP_VIEW:
		if frameworkObjectName(arg1) {
			kind := "table"
			if action == sqlite3.SQLITE_DROP_VIEW || action == sqlite3.SQLITE_DROP_TEMP_VIEW {
				kind = "view"
			}
			return s.refuseObject("drop", kind, arg1)
		}
		s.dropping, s.implicit = "", 0
		if strings.EqualFold(database, "main") {
			s.dropping = sqliteIdentifierFold(arg1)
			s.implicit = s.frameworkTriggers[s.dropping]
		}
	case sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_CREATE_TEMP_INDEX, sqlite3.SQLITE_DROP_INDEX, sqlite3.SQLITE_DROP_TEMP_INDEX:
		verb := "create"
		if action == sqlite3.SQLITE_DROP_INDEX || action == sqlite3.SQLITE_DROP_TEMP_INDEX {
			verb = "drop"
		}
		if frameworkObjectName(arg2) {
			return s.refuse("app SQL may not %s an index on the framework table %s. %s.", verb, arg2, appSQLFrameworkObjectRule)
		}
		if frameworkObjectName(arg1) {
			return s.refuseObject(verb, "index", arg1)
		}
	case sqlite3.SQLITE_CREATE_TRIGGER, sqlite3.SQLITE_CREATE_TEMP_TRIGGER:
		if frameworkObjectName(arg2) {
			return s.refuse("app SQL may not create a trigger on the framework table %s. %s.", arg2, appSQLFrameworkObjectRule)
		}
		if frameworkObjectName(arg1) {
			return s.refuseObject("create", "trigger", arg1)
		}
	case sqlite3.SQLITE_DROP_TRIGGER, sqlite3.SQLITE_DROP_TEMP_TRIGGER:
		if frameworkObjectName(arg2) {
			return s.refuse("app SQL may not drop the trigger %s on the framework table %s. %s.", arg1, arg2, appSQLFrameworkObjectRule)
		}
		if frameworkObjectName(arg1) {
			// A trigger that goes with its own table's DROP TABLE.
			if action != sqlite3.SQLITE_DROP_TRIGGER || s.implicit == 0 || s.dropping != sqliteIdentifierFold(arg2) {
				return s.refuseObject("drop", "trigger", arg1)
			}
			s.implicit--
		}
	case sqlite3.SQLITE_ALTER_TABLE:
		if frameworkObjectName(arg2) {
			return s.refuseObject("alter", "table", arg2)
		}
	case sqlite3.SQLITE_PRAGMA:
		if strings.EqualFold(arg1, "writable_schema") && arg2 != "" {
			return s.refuse("app SQL may not set PRAGMA writable_schema: the database schema is changed with CREATE, ALTER and DROP statements only.")
		}
	case sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE:
		if s.hipaa && auditAppendOnlyTable(arg1) {
			return s.refuse("%s is append-only under compliance: hipaa: app SQL may add rows to it and never update or delete them.", sqliteIdentifierFold(arg1))
		}
	}
	return sqlite3.SQLITE_OK
}

// authorizeMigration is the scope of one statement of a user migration file.
// A migration is the app's schema tool, so it keeps what migrations do to
// framework tables today: add a column or an index to one, put a trigger of
// the app's own name on one, write its rows, and drop a framework trigger
// from one of the APP's tables (the load installs those again from config).
// It cannot do what would take a framework control away: set writable_schema
// (the reviewer's migration deleted the six append-only triggers from
// sqlite_master and then rewrote an audit row), create a trigger under a
// framework name, drop a framework trigger from a framework table, or put a
// TEMP table or view of a framework name on the pooled connection. For a
// hipaa app it cannot change the audit tables or their rows at all, whether
// or not the triggers are there.
func (s *appSQLScope) authorizeMigration(action int, arg1, arg2 string) int {
	audit := func(name string) bool { return s.hipaa && auditAppendOnlyTable(name) }
	appendOnly := func(table, what string) int {
		return s.refuse("%s is append-only under compliance: hipaa: a migration may not %s.%s", sqliteIdentifierFold(table), what, s.docs())
	}
	switch action {
	case sqlite3.SQLITE_PRAGMA:
		if strings.EqualFold(arg1, "writable_schema") && arg2 != "" {
			return s.refuse("a migration may not set PRAGMA writable_schema: the database schema is changed with CREATE, ALTER and DROP statements only.%s", s.docs())
		}
	case sqlite3.SQLITE_CREATE_TEMP_TABLE, sqlite3.SQLITE_CREATE_TEMP_VIEW:
		if frameworkObjectName(arg1) {
			return s.refuse("a migration may not create the temporary table or view %s: it would stand in for the framework's own %s on the connection.%s", arg1, arg1, s.docs())
		}
	case sqlite3.SQLITE_CREATE_TRIGGER, sqlite3.SQLITE_CREATE_TEMP_TRIGGER:
		if audit(arg2) {
			return appendOnly(arg2, "add a trigger to it")
		}
		if frameworkObjectName(arg1) {
			return s.refuse("a migration may not create the trigger %s: names that start with _benmore_ are the framework's own triggers. Give the trigger a name of the app.%s", arg1, s.docs())
		}
	case sqlite3.SQLITE_DROP_TRIGGER, sqlite3.SQLITE_DROP_TEMP_TRIGGER:
		if audit(arg2) {
			return appendOnly(arg2, "drop a trigger of it")
		}
		if frameworkObjectName(arg1) && frameworkObjectName(arg2) {
			return s.refuse("a migration may not drop the framework trigger %s on the framework table %s.%s", arg1, arg2, s.docs())
		}
	case sqlite3.SQLITE_CREATE_INDEX, sqlite3.SQLITE_CREATE_TEMP_INDEX, sqlite3.SQLITE_DROP_INDEX, sqlite3.SQLITE_DROP_TEMP_INDEX:
		if audit(arg2) {
			return appendOnly(arg2, "add or drop an index on it")
		}
	case sqlite3.SQLITE_ALTER_TABLE:
		if audit(arg2) {
			return appendOnly(arg2, "alter it")
		}
	case sqlite3.SQLITE_DROP_TABLE:
		if audit(arg1) {
			return appendOnly(arg1, "drop it")
		}
	case sqlite3.SQLITE_UPDATE, sqlite3.SQLITE_DELETE:
		if audit(arg1) {
			return appendOnly(arg1, "update or delete its rows")
		}
	}
	return sqlite3.SQLITE_OK
}

// begin is the check made before the statement is compiled, for what the
// authorizer is not told: the new name of ALTER TABLE ... RENAME TO, and for a
// hipaa app that an INSERT replaces the row it conflicts with (REPLACE INTO,
// INSERT OR REPLACE) and what the body of a CREATE TRIGGER will do when it
// fires, in a statement the framework runs outside any scope. Neither may
// depend on the audit tables' own triggers being there.
func (s *appSQLScope) begin(query string) error {
	rename := !s.migration && containsFold(query, "rename")
	replace := s.hipaa && containsFold(query, "replace")
	trigger := s.hipaa && containsFold(query, "trigger")
	if !rename && !replace && !trigger {
		return nil
	}
	toks := sqlTokenize(query)
	if table := sqlTriggerBodyAuditWrite(toks); trigger && table != "" {
		s.refuse("%s is append-only under compliance: hipaa: %s may not create a trigger that updates, deletes or replaces its rows.%s", table, s.who(), s.docs())
		return s.end(sqlite3.ErrAuth)
	}
	for _, stmt := range sqlTokenStatements(toks) {
		if name := sqlRenameTarget(stmt); rename && frameworkObjectName(name) {
			s.refuseObject("rename a table to", "name", name)
			return s.end(sqlite3.ErrAuth)
		}
		if table := sqlReplaceTarget(stmt); replace && auditAppendOnlyTable(table) {
			if s.migration {
				s.refuse("%s is append-only under compliance: hipaa: a migration may not replace its rows.%s", sqliteIdentifierFold(table), s.docs())
			} else {
				s.refuse("%s is append-only under compliance: hipaa: app SQL may add rows to it and never replace them.", sqliteIdentifierFold(table))
			}
			return s.end(sqlite3.ErrAuth)
		}
	}
	return nil
}

// who names the author of the statement in a refusal.
func (s *appSQLScope) who() string {
	if s.migration {
		return "a migration"
	}
	return "app SQL"
}

// docs is the address a migration refusal ends with: a push shows it to the
// builder as the dry run's error.
func (s *appSQLScope) docs() string {
	if s.migration {
		return ` See api(at:"schema.framework_tables").`
	}
	return ""
}

// end turns the driver's error for a refused statement into the refusal.
func (s *appSQLScope) end(err error) error {
	if err == nil || s.refused == "" {
		return err
	}
	log.Printf("SECURITY: refused app SQL: %s", s.refused)
	return &appSQLRefusedError{reason: s.refused}
}

func containsFold(s, lowerSub string) bool {
	return strings.Contains(strings.ToLower(s), lowerSub)
}

// sqlDDLWord reports token i of a statement as the bare keyword word.
func sqlDDLWord(toks []sqlToken, i int, word string) bool {
	return i >= 0 && i < len(toks) && toks[i].kind == sqlTokWord && strings.EqualFold(toks[i].text, word)
}

// sqlObjectName reads `[schema .] name` at token i and returns the name and
// the index after it; "" when no name is there.
func sqlObjectName(toks []sqlToken, i int) (string, int) {
	if i >= len(toks) || toks[i].kind == sqlTokPunct {
		return "", i
	}
	if i+2 < len(toks) && toks[i+1].kind == sqlTokPunct && toks[i+1].text == "." && toks[i+2].kind != sqlTokPunct {
		return toks[i+2].text, i + 3
	}
	return toks[i].text, i + 1
}

// sqlRenameTarget is the new table name of one `ALTER TABLE t RENAME TO name`
// statement, "" for any other statement (RENAME COLUMN included).
func sqlRenameTarget(toks []sqlToken) string {
	if !sqlDDLWord(toks, 0, "ALTER") || !sqlDDLWord(toks, 1, "TABLE") {
		return ""
	}
	_, i := sqlObjectName(toks, 2)
	if !sqlDDLWord(toks, i, "RENAME") || !sqlDDLWord(toks, i+1, "TO") {
		return ""
	}
	name, _ := sqlObjectName(toks, i+2)
	return name
}

// sqlReplaceTarget is the table of one `REPLACE INTO t` or `INSERT OR REPLACE
// INTO t` statement (a WITH prefix included), "" for any other statement.
func sqlReplaceTarget(toks []sqlToken) string {
	i := sqlStatementVerbIndex(toks)
	switch {
	case sqlDDLWord(toks, i, "REPLACE") && sqlDDLWord(toks, i+1, "INTO"):
		i += 2
	case sqlDDLWord(toks, i, "INSERT") && sqlDDLWord(toks, i+1, "OR") && sqlDDLWord(toks, i+2, "REPLACE") && sqlDDLWord(toks, i+3, "INTO"):
		i += 4
	default:
		return ""
	}
	name, _ := sqlObjectName(toks, i)
	return name
}

// sqlTriggerBodyAuditWrite names the audit table a CREATE TRIGGER statement in
// toks would update, delete from or replace rows of when it fires, "" when
// there is none. A trigger's body is compiled when the trigger fires, by
// whichever statement fires it, so the authorizer of the statement that
// creates it is told nothing about the body. A plain INSERT is not a rewrite.
func sqlTriggerBodyAuditWrite(toks []sqlToken) string {
	name := func(i int) string {
		table, _ := sqlObjectName(toks, i)
		if auditAppendOnlyTable(table) {
			return sqliteIdentifierFold(table)
		}
		return ""
	}
	for i := 0; i < len(toks); i++ {
		if !sqlDDLWord(toks, i, "TRIGGER") {
			continue
		}
		// The body runs from BEGIN to its END; a CASE inside has an END too.
		for i++; i < len(toks) && !sqlDDLWord(toks, i, "BEGIN"); i++ {
		}
		depth, insert := 1, ""
		for i++; i < len(toks) && depth > 0; i++ {
			switch {
			case sqlDDLWord(toks, i, "CASE"):
				depth++
			case sqlDDLWord(toks, i, "END"):
				depth--
			}
			var table string
			switch {
			case toks[i].kind == sqlTokPunct && toks[i].text == ";":
				insert = ""
			case sqlDDLWord(toks, i, "UPDATE") && sqlDDLWord(toks, i-1, "DO"):
				table = insert // INSERT INTO <audit> ... ON CONFLICT DO UPDATE
			case sqlDDLWord(toks, i, "UPDATE") && sqlDDLWord(toks, i+1, "OR"):
				table = name(i + 3)
			case sqlDDLWord(toks, i, "UPDATE"):
				table = name(i + 1)
			case sqlDDLWord(toks, i, "DELETE") && sqlDDLWord(toks, i+1, "FROM"):
				table = name(i + 2)
			case sqlDDLWord(toks, i, "REPLACE") && sqlDDLWord(toks, i+1, "INTO"):
				table = name(i + 2)
			case sqlDDLWord(toks, i, "INSERT") && sqlDDLWord(toks, i+1, "OR") && sqlDDLWord(toks, i+2, "REPLACE") && sqlDDLWord(toks, i+3, "INTO"):
				table = name(i + 4)
			case sqlDDLWord(toks, i, "INSERT") && sqlDDLWord(toks, i+1, "OR") && sqlDDLWord(toks, i+3, "INTO"):
				insert = name(i + 4)
			case sqlDDLWord(toks, i, "INSERT") && sqlDDLWord(toks, i+1, "INTO"):
				insert = name(i + 2)
			}
			if table != "" {
				return table
			}
		}
	}
	return ""
}

// sqlFrameworkDDLTarget names the framework object a CREATE, DROP or ALTER
// statement in authored SQL text would change, "" when there is none. It is
// the write-time advice (appSQLFrameworkDDLProblem); the control is the
// authorizer scope above, which also sees names this text does not spell out.
func sqlFrameworkDDLTarget(query string) string {
	for _, toks := range sqlTokenStatements(sqlTokenize(query)) {
		if !sqlDDLWord(toks, 0, "CREATE") && !sqlDDLWord(toks, 0, "DROP") && !sqlDDLWord(toks, 0, "ALTER") {
			continue
		}
		if name := sqlRenameTarget(toks); frameworkObjectName(name) {
			return name
		}
		i := 1
		for sqlDDLWord(toks, i, "TEMP") || sqlDDLWord(toks, i, "TEMPORARY") || sqlDDLWord(toks, i, "UNIQUE") || sqlDDLWord(toks, i, "VIRTUAL") {
			i++
		}
		kind := ""
		for _, k := range []string{"TABLE", "INDEX", "TRIGGER", "VIEW"} {
			if sqlDDLWord(toks, i, k) {
				kind = k
			}
		}
		if kind == "" {
			continue
		}
		i++
		if sqlDDLWord(toks, i, "IF") {
			for i++; sqlDDLWord(toks, i, "NOT") || sqlDDLWord(toks, i, "EXISTS"); i++ {
			}
		}
		name, next := sqlObjectName(toks, i)
		if frameworkObjectName(name) {
			return name
		}
		if !sqlDDLWord(toks, 0, "CREATE") || (kind != "INDEX" && kind != "TRIGGER") {
			continue
		}
		// CREATE INDEX name ON table (...) / CREATE TRIGGER name ... ON table:
		// the first ON outside parentheses names the table.
		for depth := 0; next < len(toks); next++ {
			if t := toks[next]; t.kind == sqlTokPunct && t.text == "(" {
				depth++
			} else if t.kind == sqlTokPunct && t.text == ")" {
				depth--
			} else if depth == 0 && sqlDDLWord(toks, next, "ON") {
				if table, _ := sqlObjectName(toks, next+1); frameworkObjectName(table) {
					return table
				}
				break
			}
		}
	}
	return ""
}

// appSQLFrameworkDDLProblem is the write gate's and `benmore check`'s refusal
// of flow or hook SQL that is DDL on a framework object. The runtime refuses
// the statement whenever it runs; this says so when the file is written.
func appSQLFrameworkDDLProblem(query string) string {
	name := sqlFrameworkDDLTarget(query)
	if name == "" {
		return ""
	}
	return fmt.Sprintf("the SQL creates, drops or alters %s, a framework object, and the runtime refuses that statement when it runs. %s. To add rows to the audit log use INSERT INTO _benmore_audit_log; api(at:\"audit.append_only\").", name, appSQLFrameworkObjectRule)
}

// hooksFrameworkDDLViolation is appSQLFrameworkDDLProblem for every `sql:` of
// a hooks.yaml.
func hooksFrameworkDDLViolation(content string) string {
	var file HooksYAML
	if decodeConfigYAML([]byte(content), &file) != nil {
		return ""
	}
	sections := []struct {
		name  string
		hooks map[string][]HookEntryYAML
	}{
		{"before_insert", file.BeforeInsert}, {"before_update", file.BeforeUpdate}, {"before_delete", file.BeforeDelete},
		{"on_insert", file.OnInsert}, {"on_update", file.OnUpdate}, {"on_delete", file.OnDelete},
	}
	for _, section := range sections {
		for _, table := range slices.Sorted(maps.Keys(section.hooks)) {
			for i, entry := range section.hooks[table] {
				if problem := appSQLFrameworkDDLProblem(entry.SQL); problem != "" {
					return fmt.Sprintf("hooks.yaml: %s.%s[%d]: %s", section.name, table, i, problem)
				}
			}
		}
	}
	return ""
}

// ---- the connection's default authorizer ----

// benmoreConnsByDriverConn finds the wrapper of a driver connection, so
// restoreConnAuthorizer can put back that connection's own default.
var benmoreConnsByDriverConn sync.Map // *sqlite3.SQLiteConn -> *benmoreConn

// installDefaultAuthorizer makes c.authorize the connection's authorizer:
// the app SQL scope while a marked statement is compiled, then the storage
// ceiling when the database has one. It stays registered for the connection's
// life, so a marked statement registers nothing.
func (c *benmoreConn) installDefaultAuthorizer(ceiling bool) {
	c.ceiling.Store(ceiling)
	c.SQLiteConn.RegisterAuthorizer(c.authorize)
}

func (c *benmoreConn) authorize(action int, arg1, arg2, database string) int {
	if s := c.appSQL; s != nil {
		if s.authorize(action, arg1, arg2, database) == sqlite3.SQLITE_DENY {
			return sqlite3.SQLITE_DENY
		}
	}
	if c.ceiling.Load() {
		return authorizeStorageCeiling(action, arg1, arg2, database)
	}
	return sqlite3.SQLITE_OK
}

// beginAppSQL opens the scope a marked statement asks for and returns the
// text to run. Caller holds c.gate; the scope ends with endAppSQL before the
// gate is released.
func (c *benmoreConn) beginAppSQL(query string) (string, *appSQLScope, error) {
	query, scope := cutAppSQLMark(query)
	if scope == nil {
		return query, nil, nil
	}
	if err := scope.begin(query); err != nil {
		return query, nil, err
	}
	if containsFold(query, "drop") {
		scope.frameworkTriggers = c.frameworkTriggerCounts()
	}
	c.appSQL = scope
	return query, scope, nil
}

// frameworkTriggerCounts is appSQLScope.frameworkTriggers for this
// connection's database as the connection sees it now, uncommitted schema
// changes included. nil when it cannot be read: a table that carries
// framework triggers is then not dropped by app SQL.
func (c *benmoreConn) frameworkTriggerCounts() map[string]int {
	rows, err := c.SQLiteConn.QueryContext(context.Background(), `SELECT lower(tbl_name), COUNT(*) FROM main.sqlite_master WHERE type = 'trigger' AND substr(lower(name), 1, 9) = '_benmore_' GROUP BY 1`, nil)
	if err != nil {
		return nil
	}
	defer rows.Close()
	counts := map[string]int{}
	dest := make([]driver.Value, 2)
	for rows.Next(dest) == nil {
		table, _ := dest[0].(string)
		if b, ok := dest[0].([]byte); ok {
			table = string(b)
		}
		n, _ := dest[1].(int64)
		counts[table] = int(n)
	}
	return counts
}

// appSQLDenies applies the scope of the statement being compiled for a caller
// that has put its own authorizer on this connection and still runs marked
// statements (the migration dry run).
func (c *benmoreConn) appSQLDenies(action int, arg1, arg2, database string) bool {
	return c.appSQL != nil && c.appSQL.authorize(action, arg1, arg2, database) == sqlite3.SQLITE_DENY
}

func (c *benmoreConn) endAppSQL(scope *appSQLScope, err error) error {
	if scope == nil {
		return err
	}
	c.appSQL = nil
	return scope.end(err)
}
