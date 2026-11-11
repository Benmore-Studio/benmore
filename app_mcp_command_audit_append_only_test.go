//go:build !cli && !windows

package main

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

// installAppendOnlyAuditFixture puts the append-only triggers of a
// `compliance: hipaa` app on both audit tables, exactly as a load does.
func installAppendOnlyAuditFixture(t *testing.T, app *App) {
	t.Helper()
	EnsureAuditLogTable(app.DB)
	EnsureReadAuditTable(app.DB)
	if err := installAuditAppendOnly(app.DB); err != nil {
		t.Fatalf("install append-only audit triggers: %v", err)
	}
	for _, table := range auditAppendOnlyTables {
		stored, err := auditTableTriggers(app.DB, table)
		if err != nil || len(stored) != len(auditAppendOnlyKinds) {
			t.Fatalf("append-only triggers on %s: %d (%v)", table, len(stored), err)
		}
		for _, kind := range auditAppendOnlyKinds {
			if stored[auditTriggerName(table, kind)] != auditTriggerSQL(table, kind) {
				t.Fatalf("fixture trigger %s is not the generated one", auditTriggerName(table, kind))
			}
		}
	}
}

// An approved command writes an audit row at prepare, approve and commit. On
// an app whose audit tables are append-only, each of those inserts runs the
// overwrite guard, which looks the new row's id up in the audit table.
func TestAppMCPCommandAuditsThroughAppendOnlyTriggers(t *testing.T) {
	h := newExposureHarness(t)
	installAppendOnlyAuditFixture(t, h.app)
	id := h.prepare()
	h.approveOK(id)
	out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id})
	if code != "" || out["outcome"] != "applied" {
		t.Fatalf("commit with append-only audit tables: %q %#v", code, out)
	}
	if !h.taskDone() {
		t.Fatal("the command's business write did not happen")
	}
	for _, action := range []string{"mcp_command_prepare", "mcp_command_approve", "mcp_command_commit"} {
		if n := h.count("SELECT count(*) FROM _benmore_audit_log WHERE action=? AND row_id=?", action, id); n != 1 {
			t.Errorf("%s audit rows for this operation: %d, want 1", action, n)
		}
	}
	// The triggers were not weakened to get there.
	for _, table := range auditAppendOnlyTables {
		stored, err := auditTableTriggers(h.app.DB, table)
		if err != nil {
			t.Fatal(err)
		}
		for _, kind := range auditAppendOnlyKinds {
			if stored[auditTriggerName(table, kind)] != auditTriggerSQL(table, kind) {
				t.Errorf("trigger %s changed during the command", auditTriggerName(table, kind))
			}
		}
	}
	if _, err := h.app.DB.Exec(`UPDATE _benmore_audit_log SET action='rewritten' WHERE row_id=?`, id); err == nil || !strings.Contains(err.Error(), "append-only") {
		t.Errorf("the audit rows a command wrote can be rewritten: %v", err)
	}
}

// The audit scope of a command connection admits one insert and the reads the
// append-only triggers make for it. It can never change or remove an audit
// row, read one, or touch the read-audit table, with or without the triggers.
func TestAppMCPCommandAuditScopeCannotRewriteAuditRows(t *testing.T) {
	for _, appendOnly := range []bool{false, true} {
		name := map[bool]string{false: "ordinary app", true: "append-only audit tables"}[appendOnly]
		t.Run(name, func(t *testing.T) {
			app, sessionID, _ := newCommandProviderTaskFixture(t)
			ensureCommandAuditFixture(t, app)
			EnsureReadAuditTable(app.DB)
			if _, err := app.DB.Exec(`INSERT INTO _benmore_audit_log(action, table_name, row_id, user_id, user_email) VALUES('seed','tasks','1',1,'seed@example.com')`); err != nil {
				t.Fatal(err)
			}
			if appendOnly {
				installAppendOnlyAuditFixture(t, app)
			}
			err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
				app: app, generation: snapshotAppMCPGeneration(app), toolName: "complete_item",
				origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
			}, func(cap *appMCPCommandCapability) (bool, error) {
				if err := appMCPAudit(cap, "mcp_command_probe", strings.Repeat("ab", 16), map[string]any{"probe": true}); err != nil {
					t.Errorf("the scope's own audit insert failed: %v", err)
				}
				statements := []string{
					`UPDATE main._benmore_audit_log SET action='rewritten'`,
					`UPDATE main._benmore_audit_log SET action='rewritten' WHERE id=1`,
					`DELETE FROM main._benmore_audit_log`,
					`DELETE FROM main._benmore_audit_log WHERE id=1`,
					`SELECT action FROM main._benmore_audit_log WHERE id=1`,
					`SELECT user_email FROM main._benmore_audit_log`,
					`INSERT INTO main._benmore_read_audit(table_name, query_type, user_id, user_email) VALUES('tasks','list',1,'seed@example.com')`,
					`SELECT id FROM main._benmore_read_audit`,
				}
				if appendOnly {
					// The overwrite guard is what stops a REPLACE of an existing
					// row, and a guard that exists cannot be dropped here.
					statements = append(statements,
						`INSERT OR REPLACE INTO main._benmore_audit_log(id, action, table_name, row_id, user_id, user_email) VALUES(1,'replaced','tasks','1',1,'seed@example.com')`,
						`DROP TRIGGER _benmore_audit_log_no_update`,
						`DROP TRIGGER _benmore_audit_log_no_overwrite`)
				}
				for _, statement := range statements {
					scopeErr := cap.withNativeMetadata(appMCPCommandMetadataAudit, func() error {
						rows, err := cap.tx.QueryContext(cap.ctx, statement)
						if err != nil {
							return err
						}
						defer rows.Close()
						for rows.Next() {
						}
						return rows.Err()
					})
					if scopeErr == nil {
						t.Errorf("audit scope ran %q", statement)
					}
				}
				return false, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			var action string
			if err := app.DB.QueryRow(`SELECT action FROM _benmore_audit_log WHERE id=1`).Scan(&action); err != nil || action != "seed" {
				t.Fatalf("the seeded audit row changed: %q %v", action, err)
			}
		})
	}
}

// auditAppendOnlyTriggerRead is the set of reads a guarded connection admits
// with an audit insert. Prove it against the triggers the framework generates:
// compile an insert into each audit table under an authorizer that records
// every read, and require exactly the admitted columns of that table.
func TestAuditAppendOnlyTriggerReadsMatchTheGeneratedTriggers(t *testing.T) {
	app, _, _ := newCommandProviderTaskFixture(t)
	installAppendOnlyAuditFixture(t, app)
	inserts := map[string]string{
		"_benmore_audit_log":  `INSERT INTO main._benmore_audit_log(action, table_name, row_id, user_id, user_email) VALUES('a','t','1',1,'e')`,
		"_benmore_read_audit": `INSERT INTO main._benmore_read_audit(table_name, query_type, user_id, user_email) VALUES('t','list',1,'e')`,
	}
	for _, table := range auditAppendOnlyTables {
		conn, err := app.DB.Conn(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		err = conn.Raw(func(raw any) error {
			sqliteConn, ok := sqliteConnOf(raw)
			if !ok {
				t.Fatal("not a SQLite connection")
			}
			sqliteConn.RegisterAuthorizer(func(action int, arg1, arg2, _ string) int {
				if action == sqlite3.SQLITE_READ {
					seen[strings.ToLower(arg1)+"."+strings.ToLower(arg2)] = true
				}
				return sqlite3.SQLITE_OK
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		stmt, err := conn.PrepareContext(context.Background(), inserts[table])
		if err == nil {
			stmt.Close()
		}
		_ = conn.Raw(func(raw any) error {
			if sqliteConn, ok := sqliteConnOf(raw); ok {
				restoreConnAuthorizer(sqliteConn)
			}
			return nil
		})
		conn.Close()
		if err != nil {
			t.Fatalf("compile insert into %s: %v", table, err)
		}
		var reads []string
		for read := range seen {
			// An AUTOINCREMENT insert reads its sequence row; that is the
			// insert itself, not a trigger.
			if strings.HasPrefix(read, "sqlite_sequence.") {
				continue
			}
			reads = append(reads, read)
			name, column, _ := strings.Cut(read, ".")
			if !auditAppendOnlyTriggerRead(name, column) {
				t.Errorf("the generated triggers on %s read %s, which auditAppendOnlyTriggerRead does not admit", table, read)
			}
		}
		sort.Strings(reads)
		// The guard's `SELECT 1` is reported as a columnless read of the table.
		if len(reads) != 2 || reads[0] != table+"." || reads[1] != table+".id" {
			t.Errorf("reads of an insert into %s through its triggers = %v, want the table and its id only", table, reads)
		}
	}
	for _, refused := range [][2]string{{"_benmore_audit_log", "details"}, {"_benmore_audit_log", "user_email"}, {"_benmore_users", "id"}, {"tasks", "id"}, {"_benmore_users", ""}} {
		if auditAppendOnlyTriggerRead(refused[0], refused[1]) {
			t.Errorf("auditAppendOnlyTriggerRead admits %s.%s", refused[0], refused[1])
		}
	}
	// The revoke scope writes its own audit row; it already reads framework
	// tables outside the connector's, so the guard's lookup passes there too.
	if authorizeCommandRevoke(sqlite3.SQLITE_READ, "_benmore_audit_log", "id", "main") != sqlite3.SQLITE_OK || authorizeCommandRevoke(sqlite3.SQLITE_READ, "_benmore_audit_log", "", "main") != sqlite3.SQLITE_OK {
		t.Error("the revoke scope refuses the overwrite guard's read")
	}
	// The command audit scope takes only the audit log's part of that set.
	ok := func(code int) bool { return code == sqlite3.SQLITE_OK }
	if !ok(authorizeCommandNativeMetadata(appMCPCommandMetadataAudit, sqlite3.SQLITE_READ, "_benmore_audit_log", "id", "main")) {
		t.Error("the audit scope refuses the overwrite guard's read")
	}
	for name, code := range map[string]int{
		"another audit column":       authorizeCommandNativeMetadata(appMCPCommandMetadataAudit, sqlite3.SQLITE_READ, "_benmore_audit_log", "details", "main"),
		"the read-audit table":       authorizeCommandNativeMetadata(appMCPCommandMetadataAudit, sqlite3.SQLITE_READ, "_benmore_read_audit", "id", "main"),
		"the audit id in temp":       authorizeCommandNativeMetadata(appMCPCommandMetadataAudit, sqlite3.SQLITE_READ, "_benmore_audit_log", "id", "temp"),
		"the audit id, other scope":  authorizeCommandNativeMetadata(appMCPCommandMetadataReceipt, sqlite3.SQLITE_READ, "_benmore_audit_log", "id", "main"),
		"the audit id, read scope":   authorizeCommandNativeMetadata(appMCPCommandMetadataRead, sqlite3.SQLITE_READ, "_benmore_audit_log", "id", "main"),
		"update an audit row":        authorizeCommandNativeMetadata(appMCPCommandMetadataAudit, sqlite3.SQLITE_UPDATE, "_benmore_audit_log", "action", "main"),
		"delete an audit row":        authorizeCommandNativeMetadata(appMCPCommandMetadataAudit, sqlite3.SQLITE_DELETE, "_benmore_audit_log", "", "main"),
		"insert a read-audit row":    authorizeCommandNativeMetadata(appMCPCommandMetadataAudit, sqlite3.SQLITE_INSERT, "_benmore_read_audit", "", "main"),
		"drop an append-only guard":  authorizeCommandNativeMetadata(appMCPCommandMetadataAudit, sqlite3.SQLITE_DROP_TRIGGER, "_benmore_audit_log_no_update", "_benmore_audit_log", "main"),
		"insert audit, other scope":  authorizeCommandNativeMetadata(appMCPCommandMetadataReceipt, sqlite3.SQLITE_INSERT, "_benmore_audit_log", "", "main"),
		"update audit, revoke scope": authorizeCommandRevoke(sqlite3.SQLITE_UPDATE, "_benmore_audit_log", "action", "main"),
		"delete audit, revoke scope": authorizeCommandRevoke(sqlite3.SQLITE_DELETE, "_benmore_audit_log", "", "main"),
	} {
		if ok(code) {
			t.Errorf("command scope allowed: %s", name)
		}
	}
}

// The native update tool writes its audit row through the generic CRUD update
// on the write coordinator's connection, with the same triggers in the way.
func TestAppMCPNativeUpdateAuditsThroughAppendOnlyTriggers(t *testing.T) {
	f := newCanonicalUpdateFixture(t, "", "", "")
	installAppendOnlyAuditFixture(t, f.app)
	before := hookCount(t, f.app, `SELECT count(*) FROM _benmore_audit_log WHERE table_name='notes' AND row_id='1'`)
	projected, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("after"), f.now)
	if err != nil || projected["title"] != "after" {
		t.Fatalf("native update with append-only audit tables: %v %v", projected, err)
	}
	if after := hookCount(t, f.app, `SELECT count(*) FROM _benmore_audit_log WHERE table_name='notes' AND row_id='1'`); after != before+1 {
		t.Fatalf("native update audit rows: %d before, %d after, want one more", before, after)
	}
}
