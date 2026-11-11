//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"log"
	"strings"
	"time"
)

// Append-only audit tables under `compliance: hipaa`.
//
// BEFORE UPDATE / BEFORE DELETE triggers on the two framework audit tables
// abort every change, and a BEFORE INSERT trigger refuses an insert that names
// an existing id (REPLACE), so an editor's SQL, a bulk import or a bug cannot
// rewrite history. The triggers are re-checked against their exact text at
// every start and reload, and a user migration or seeds.sql may not name an
// audit table once they exist (refuseAuditTableStatement). The framework's own maintenance (retention sweep, account
// erasure scrubbing, legacy session-id rekeying, the test runner's cleanup) is
// the one privileged path: withAuditMutable drops the triggers, runs the
// change and recreates them inside the caller's transaction. DDL is
// transactional in SQLite and a writer holds the database exclusively, so no
// other connection ever sees the triggers missing and a rollback restores
// them. A statement that can reach a connection without this wrapper (authored
// flow SQL) is not stopped by it: the guarantee is against editor SQL and
// accident, not against code that ships in the app.

var auditAppendOnlyTables = []string{"_benmore_audit_log", "_benmore_read_audit"}

// auditAppendOnlyKinds are the triggers on each table. "overwrite" stops
// `INSERT OR REPLACE` / `REPLACE INTO` naming an existing id: a REPLACE
// deletes the old row through conflict resolution, which fires no DELETE
// trigger (recursive triggers are off), but every BEFORE INSERT trigger runs
// before conflict resolution.
var auditAppendOnlyKinds = []string{"update", "delete", "overwrite"}

// auditExecer is a *sql.DB or *sql.Tx.
type auditExecer interface {
	Exec(string, ...any) (sql.Result, error)
	QueryRow(string, ...any) *sql.Row
}

func auditTriggerName(table, kind string) string {
	return table + "_no_" + kind
}

// auditTriggerSQL is the exact CREATE TRIGGER statement for one trigger.
// SQLite stores it verbatim in sqlite_master.sql (there is no IF NOT EXISTS
// to strip), so the stored text identifies a trigger that was replaced under
// the same name.
func auditTriggerSQL(table, kind string) string {
	name, t := quoteIdent(auditTriggerName(table, kind)), quoteIdent(table)
	abort := fmt.Sprintf(`BEGIN SELECT RAISE(ABORT, '%s is append-only'); END`, table)
	switch kind {
	case "update":
		return fmt.Sprintf(`CREATE TRIGGER %s BEFORE UPDATE ON %s %s`, name, t, abort)
	case "delete":
		return fmt.Sprintf(`CREATE TRIGGER %s BEFORE DELETE ON %s %s`, name, t, abort)
	default: // overwrite
		return fmt.Sprintf(`CREATE TRIGGER %s BEFORE INSERT ON %s WHEN EXISTS (SELECT 1 FROM %s WHERE id = NEW.id) %s`, name, t, t, abort)
	}
}

func auditTriggerNames() []string {
	names := make([]string, 0, len(auditAppendOnlyTables)*len(auditAppendOnlyKinds))
	for _, table := range auditAppendOnlyTables {
		for _, kind := range auditAppendOnlyKinds {
			names = append(names, auditTriggerName(table, kind))
		}
	}
	return names
}

// installAuditAppendOnly makes the triggers on every audit table that exists
// exactly the framework's: a missing one is created, one whose stored text
// differs (a migration that dropped it and created a no-op under the same
// name) is replaced, and any other trigger on an audit table (a BEFORE INSERT
// ... RAISE(IGNORE) would silently drop new audit rows) is dropped. It runs at
// every start and reload of a hipaa app and inside withAuditMutable.
func installAuditAppendOnly(x auditExecer) error {
	for _, table := range auditAppendOnlyTables {
		var n int
		if err := x.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?`, table).Scan(&n); err != nil {
			return err
		}
		if n == 0 {
			continue
		}
		expected := map[string]string{}
		for _, kind := range auditAppendOnlyKinds {
			expected[auditTriggerName(table, kind)] = auditTriggerSQL(table, kind)
		}
		stored, err := auditTableTriggers(x, table)
		if err != nil {
			return err
		}
		for name, text := range stored {
			if want, ours := expected[name]; ours && text == want {
				delete(expected, name)
				continue
			}
			if _, ours := expected[name]; ours {
				log.Printf("SECURITY: audit trigger %s was changed; restoring it", name)
			} else {
				log.Printf("SECURITY: dropping trigger %s on append-only table %s", name, table)
			}
			if _, err := x.Exec(`DROP TRIGGER IF EXISTS ` + quoteIdent(name)); err != nil {
				return err
			}
		}
		for _, kind := range auditAppendOnlyKinds {
			if _, missing := expected[auditTriggerName(table, kind)]; !missing {
				continue
			}
			if _, err := x.Exec(auditTriggerSQL(table, kind)); err != nil {
				return err
			}
		}
	}
	return nil
}

// auditTableTriggers maps the name of every trigger on table to its stored SQL.
func auditTableTriggers(x auditExecer, table string) (map[string]string, error) {
	// QueryRow is all auditExecer offers; group_concat keeps it one row.
	// The unit separator cannot appear in an identifier this table carries
	// triggers under without quoting, and a name holding it is simply dropped.
	var packed sql.NullString
	if err := x.QueryRow(`SELECT group_concat(name || char(31) || COALESCE(sql, ''), char(30)) FROM sqlite_master WHERE type='trigger' AND tbl_name=?`, table).Scan(&packed); err != nil {
		return nil, err
	}
	out := map[string]string{}
	if !packed.Valid || packed.String == "" {
		return out, nil
	}
	for _, rec := range strings.Split(packed.String, "\x1e") {
		name, text, _ := strings.Cut(rec, "\x1f")
		out[name] = text
	}
	return out, nil
}

// auditAppendOnlyActive reports whether the append-only triggers are
// installed in this database (the app is, or was, compliance: hipaa).
func auditAppendOnlyActive(x auditExecer) (bool, error) {
	names := auditTriggerNames()
	marks := strings.TrimSuffix(strings.Repeat("?,", len(names)), ",")
	args := make([]any, len(names))
	for i, n := range names {
		args[i] = n
	}
	var n int
	if err := x.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name IN (`+marks+`)`, args...).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// refuseAuditTableStatement refuses an app-authored statement (a user
// migration, seeds.sql) that names an audit table in a database whose audit
// tables are append-only: DDL there could drop or shadow the triggers, add one
// that discards new rows, or forge history.
func refuseAuditTableStatement(x auditExecer, stmt string) error {
	if !mentionsAuditTable(stmt) {
		return nil
	}
	active, err := auditAppendOnlyActive(x)
	if err != nil {
		return err
	}
	if active {
		return fmt.Errorf("the audit tables are append-only under compliance: hipaa; app SQL may not name _benmore_audit_log or _benmore_read_audit")
	}
	return nil
}

// ensureAuditAppendOnly installs the triggers for a `compliance: hipaa` app,
// retrying once (a busy database). A failure is returned: the served build
// refuses to start or reload without them (buildAppMuxChecked), since a hipaa
// app must not run with audit history that can be rewritten. It only logged,
// and the app kept serving unprotected.
func ensureAuditAppendOnly(app *App) error {
	if !app.hipaa() {
		return nil
	}
	err := installAuditAppendOnly(app.DB)
	if err != nil {
		time.Sleep(200 * time.Millisecond)
		err = installAuditAppendOnly(app.DB)
	}
	if err != nil {
		log.Printf("SECURITY: audit append-only triggers could not be installed: %v", err)
		return fmt.Errorf("compliance: hipaa: the append-only audit triggers could not be installed, so the app does not start without them: %w", err)
	}
	return nil
}

// withAuditMutable runs fn, which changes or deletes audit rows through x,
// with the append-only triggers lifted. x must be a transaction: the triggers
// are restored before fn's error is returned, and a rollback undoes both.
// An app without the triggers just runs fn.
func withAuditMutable(x auditExecer, fn func() error) error {
	active, err := auditAppendOnlyActive(x)
	if err != nil {
		return err
	}
	if !active {
		return fn()
	}
	for _, name := range auditTriggerNames() {
		if _, err := x.Exec(`DROP TRIGGER IF EXISTS ` + quoteIdent(name)); err != nil {
			return err
		}
	}
	err = fn()
	if rerr := installAuditAppendOnly(x); err == nil {
		err = rerr
	}
	return err
}

// execAuditMutable runs one maintenance statement in its own transaction with
// the triggers lifted.
func execAuditMutable(db *sql.DB, query string, args ...any) (sql.Result, error) {
	tx, err := db.Begin()
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var res sql.Result
	if err := withAuditMutable(tx, func() (e error) { res, e = tx.Exec(query, args...); return }); err != nil {
		return nil, err
	}
	return res, tx.Commit()
}

// mentionsAuditTable reports whether a statement names an audit table
// (substring on purpose, like the load_extension check).
func mentionsAuditTable(stmt string) bool {
	s := strings.ToLower(stmt)
	return strings.Contains(s, "_benmore_audit") || strings.Contains(s, "_benmore_read_audit")
}
