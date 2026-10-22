//go:build !cli

package main

import (
	"database/sql"
	"math"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func initRevisionStorage(t *testing.T, db *sql.DB, tables ...string) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := initializeAppMCPRevisionStorage(tx, tables); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func verifyRevisionStorage(t *testing.T, db *sql.DB, tables ...string) error {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	return verifyAppMCPRevisionStorage(tx, tables)
}

func appMCPRevisionRow(t *testing.T, db *sql.DB, table, keyType, rowKey string) (incarnation string, revision int64, deleted int) {
	t.Helper()
	err := db.QueryRow(`SELECT incarnation,revision,deleted FROM main._benmore_mcp_row_revisions WHERE table_name=? AND key_type=? AND row_key=?`, table, keyType, rowKey).Scan(&incarnation, &revision, &deleted)
	if err != nil {
		t.Fatal(err)
	}
	return incarnation, revision, deleted
}

func seedRevisionNote(t *testing.T, db *sql.DB) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO notes(id,title) VALUES(1,'before')`); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPRevisionTriggersTrackKeysAndRetainTombstones(t *testing.T) {
	db := newAppMCPReadConnectionTestDB(t)
	if _, err := db.Exec(`CREATE TABLE typed_keys (id BLOB NOT NULL PRIMARY KEY, value TEXT NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	const huge int64 = 9007199254740993
	if _, err := db.Exec(`INSERT INTO notes(id,title) VALUES(?, 'seeded')`, huge); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO typed_keys(id,value) VALUES(1,'integer'),('1','text'),('old','old')`); err != nil {
		t.Fatal(err)
	}
	initRevisionStorage(t, db, "notes", "typed_keys")
	if err := verifyRevisionStorage(t, db, "notes", "typed_keys"); err != nil {
		t.Fatal(err)
	}
	incarnation, revision, deleted := appMCPRevisionRow(t, db, "notes", "integer", "9007199254740993")
	if incarnation == "" || revision != 1 || deleted != 0 {
		t.Fatalf("backfilled large integer key = %q/%d/%d", incarnation, revision, deleted)
	}
	textInc, textRevision, textDeleted := appMCPRevisionRow(t, db, "typed_keys", "text", "1")
	intInc, intRevision, intDeleted := appMCPRevisionRow(t, db, "typed_keys", "integer", "1")
	if textInc == "" || intInc != textInc || textRevision != 1 || intRevision != 1 || textDeleted != 0 || intDeleted != 0 {
		t.Fatalf("typed integer/text keys collapsed: integer=%q/%d/%d text=%q/%d/%d", intInc, intRevision, intDeleted, textInc, textRevision, textDeleted)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO typed_keys(id,value) VALUES(X'01','unsupported')`); err == nil {
		t.Fatal("INSERT OR IGNORE committed a BLOB key after the revision trigger rejected it")
	}
	if _, err := db.Exec(`UPDATE OR IGNORE typed_keys SET id=X'02' WHERE id='old'`); err == nil {
		t.Fatal("UPDATE OR IGNORE committed an unsupported key type after the revision trigger rejected it")
	}
	var oldValue string
	if err := db.QueryRow(`SELECT value FROM typed_keys WHERE id='old'`).Scan(&oldValue); err != nil || oldValue != "old" {
		t.Fatalf("ignored unsupported-key write changed original row: value=%q err=%v", oldValue, err)
	}

	// Equal-value and same-second writes remain distinct mutations.
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(`UPDATE notes SET title='seeded' WHERE id=?`, huge); err != nil {
			t.Fatal(err)
		}
	}
	_, revision, deleted = appMCPRevisionRow(t, db, "notes", "integer", "9007199254740993")
	if revision != 3 || deleted != 0 {
		t.Fatalf("equal-value updates revision/deleted=%d/%d", revision, deleted)
	}
	rollback, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer rollback.Rollback()
	if _, err := rollback.Exec(`UPDATE notes SET title='rolled back' WHERE id=?`, huge); err != nil {
		rollback.Rollback()
		t.Fatal(err)
	}
	if err := rollback.Rollback(); err != nil {
		t.Fatal(err)
	}
	_, revision, deleted = appMCPRevisionRow(t, db, "notes", "integer", "9007199254740993")
	if revision != 3 || deleted != 0 {
		t.Fatalf("rolled-back SQL changed revision/deleted=%d/%d", revision, deleted)
	}
	app := &App{DB: db, Hooks: &HookConfig{OnUpdate: map[string][]Hook{
		"notes": {{SQL: `UPDATE notes SET title='after-hook' WHERE id={{id}}`}},
	}}}
	afterHookTx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer afterHookTx.Rollback()
	if _, err := afterHookTx.Exec(`UPDATE notes SET title='before-hook' WHERE id=?`, huge); err != nil {
		afterHookTx.Rollback()
		t.Fatal(err)
	}
	if _, err := fireAfterHooksTx(afterHookTx, app, "update", "notes", map[string]any{"id": huge}); err != nil {
		afterHookTx.Rollback()
		t.Fatal(err)
	}
	if err := afterHookTx.Commit(); err != nil {
		t.Fatal(err)
	}
	var title string
	if err := db.QueryRow(`SELECT title FROM notes WHERE id=?`, huge).Scan(&title); err != nil || title != "after-hook" {
		t.Fatalf("SQL after-hook state=%q err=%v", title, err)
	}
	_, revision, deleted = appMCPRevisionRow(t, db, "notes", "integer", "9007199254740993")
	if revision != 5 || deleted != 0 {
		t.Fatalf("SQL after-hook revision/deleted=%d/%d want 5/0", revision, deleted)
	}
	flowTx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer flowTx.Rollback()
	flowCtx := &FlowContext{App: &App{DB: db}, Tx: flowTx, Data: map[string]any{}, Params: map[string]string{}}
	if err := execStepSQL(flowCtx, &FlowStep{Type: "sql", SQL: `INSERT INTO notes(id,title) VALUES(42,'flow writer')`}); err != nil {
		flowTx.Rollback()
		t.Fatal(err)
	}
	if err := flowTx.Commit(); err != nil {
		t.Fatal(err)
	}
	_, flowRevision, flowDeleted := appMCPRevisionRow(t, db, "notes", "integer", "42")
	if flowRevision != 1 || flowDeleted != 0 {
		t.Fatalf("transactional flow SQL insert revision/deleted=%d/%d", flowRevision, flowDeleted)
	}

	if _, err := db.Exec(`UPDATE typed_keys SET id='new' WHERE id='old'`); err != nil {
		t.Fatal(err)
	}
	_, oldRevision, oldDeleted := appMCPRevisionRow(t, db, "typed_keys", "text", "old")
	_, newRevision, newDeleted := appMCPRevisionRow(t, db, "typed_keys", "text", "new")
	if oldRevision != 2 || oldDeleted != 1 || newRevision != 1 || newDeleted != 0 {
		t.Fatalf("PK move old/new = %d/%d and %d/%d", oldRevision, oldDeleted, newRevision, newDeleted)
	}
	if _, err := db.Exec(`DELETE FROM typed_keys WHERE id='new'`); err != nil {
		t.Fatal(err)
	}
	_, newRevision, newDeleted = appMCPRevisionRow(t, db, "typed_keys", "text", "new")
	if newRevision != 2 || newDeleted != 1 {
		t.Fatalf("deleted key tombstone = %d/%d", newRevision, newDeleted)
	}
	if _, err := db.Exec(`INSERT INTO typed_keys(id,value) VALUES('new','recreated')`); err != nil {
		t.Fatal(err)
	}
	_, newRevision, newDeleted = appMCPRevisionRow(t, db, "typed_keys", "text", "new")
	if newRevision != 3 || newDeleted != 0 {
		t.Fatalf("recreated key reset its tombstone: %d/%d", newRevision, newDeleted)
	}

	// With no alternate UNIQUE constraint, REPLACE of the same primary key is
	// one new version; the separate integer/text identities stay independent.
	if _, err := db.Exec(`INSERT OR REPLACE INTO typed_keys(id,value) VALUES('1','replaced')`); err != nil {
		t.Fatal(err)
	}
	_, textRevision, _ = appMCPRevisionRow(t, db, "typed_keys", "text", "1")
	_, intRevision, _ = appMCPRevisionRow(t, db, "typed_keys", "integer", "1")
	if textRevision != 2 || intRevision != 1 {
		t.Fatalf("REPLACE revision text/integer=%d/%d", textRevision, intRevision)
	}
	if _, err := db.Exec(`INSERT INTO typed_keys(id,value) VALUES('1','upserted') ON CONFLICT(id) DO UPDATE SET value=excluded.value`); err != nil {
		t.Fatal(err)
	}
	_, textRevision, _ = appMCPRevisionRow(t, db, "typed_keys", "text", "1")
	if textRevision != 3 {
		t.Fatalf("UPSERT update revision=%d want 3", textRevision)
	}
	if err := verifyRevisionStorage(t, db, "notes", "typed_keys"); err != nil {
		t.Fatalf("repeat verification failed after mutations: %v", err)
	}
	reinstall, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer reinstall.Rollback()
	if err := initializeAppMCPRevisionStorage(reinstall, []string{"notes", "typed_keys"}); err == nil {
		reinstall.Rollback()
		t.Fatal("explicit initializer adopted an existing ledger")
	}
	if err := reinstall.Rollback(); err != nil {
		t.Fatal(err)
	}
	_, revision, _ = appMCPRevisionRow(t, db, "notes", "integer", "9007199254740993")
	if revision != 5 {
		t.Fatalf("initializer reset existing revision: got %d want 5", revision)
	}
}

func TestAppMCPRevisionTracksComputedAndCascadedSQLMutations(t *testing.T) {
	db := newAppMCPReadConnectionTestDB(t)
	if _, err := db.Exec(`
CREATE TABLE tasks (id INTEGER PRIMARY KEY, state TEXT, computed_state TEXT);
CREATE TABLE task_items (id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL REFERENCES tasks(id) ON DELETE CASCADE);
CREATE TRIGGER app_compute_task_state AFTER UPDATE OF state ON tasks FOR EACH ROW BEGIN
 UPDATE tasks SET computed_state=NEW.state WHERE id=NEW.id;
END;
INSERT INTO tasks VALUES(1,'open','open');
INSERT INTO tasks VALUES(2,'queued','queued');
INSERT INTO task_items VALUES(1,1);`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`PRAGMA foreign_keys=ON`); err != nil {
		t.Fatal(err)
	}
	initRevisionStorage(t, db, "tasks", "task_items")
	if _, err := db.Exec(`UPDATE tasks SET state='done' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	var computed string
	if err := db.QueryRow(`SELECT computed_state FROM tasks WHERE id=1`).Scan(&computed); err != nil || computed != "done" {
		t.Fatalf("computed SQL side effect=%q err=%v", computed, err)
	}
	_, taskRevision, taskDeleted := appMCPRevisionRow(t, db, "tasks", "integer", "1")
	if taskRevision != 3 || taskDeleted != 0 {
		t.Fatalf("computed source mutation revision/deleted=%d/%d", taskRevision, taskDeleted)
	}
	if _, err := db.Exec(`UPDATE tasks SET computed_state='direct' WHERE id=2`); err != nil {
		t.Fatal(err)
	}
	_, directRevision, directDeleted := appMCPRevisionRow(t, db, "tasks", "integer", "2")
	if directRevision != 2 || directDeleted != 0 {
		t.Fatalf("direct computed-field mutation revision/deleted=%d/%d", directRevision, directDeleted)
	}
	if _, err := db.Exec(`DELETE FROM tasks WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	_, taskRevision, taskDeleted = appMCPRevisionRow(t, db, "tasks", "integer", "1")
	_, childRevision, childDeleted := appMCPRevisionRow(t, db, "task_items", "integer", "1")
	if taskRevision != 4 || taskDeleted != 1 || childRevision != 2 || childDeleted != 1 {
		t.Fatalf("cascade tombstones parent=%d/%d child=%d/%d", taskRevision, taskDeleted, childRevision, childDeleted)
	}
}

func TestAppMCPRevisionTracksCanonicalPatchAndTransactionHandlers(t *testing.T) {
	app, sid, _ := canonicalUpdateFixture(t)
	initRevisionStorage(t, app.DB, "notes")
	_, revision, deleted := appMCPRevisionRow(t, app.DB, "notes", "integer", "1")
	if revision != 1 || deleted != 0 {
		t.Fatalf("canonical fixture backfill revision/deleted=%d/%d", revision, deleted)
	}
	w := canonicalPatch(app, sid, "notes", "1", "application/json", `{"title":"PATCH revision"}`)
	if w.Code != http.StatusOK || canonicalTitle(t, app) != "PATCH revision" {
		t.Fatalf("canonical PATCH: status=%d body=%s title=%q", w.Code, w.Body.String(), canonicalTitle(t, app))
	}
	_, revision, deleted = appMCPRevisionRow(t, app.DB, "notes", "integer", "1")
	if revision != 2 || deleted != 0 {
		t.Fatalf("canonical PATCH revision/deleted=%d/%d", revision, deleted)
	}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	w = auditPost(mux, sid, "/api/_transaction", "", `{"operations":[{"table":"notes","action":"update","id":1,"data":{"title":"atomic revision"}}]}`, false)
	if w.Code != http.StatusOK || canonicalTitle(t, app) != "atomic revision" {
		t.Fatalf("canonical atomic update: status=%d body=%s title=%q", w.Code, w.Body.String(), canonicalTitle(t, app))
	}
	_, revision, deleted = appMCPRevisionRow(t, app.DB, "notes", "integer", "1")
	if revision != 3 || deleted != 0 {
		t.Fatalf("canonical atomic update revision/deleted=%d/%d", revision, deleted)
	}
}

func TestAppMCPRevisionInstallerRefusesUnsupportedTables(t *testing.T) {
	for _, tc := range []struct {
		name, ddl, table string
	}{
		{"composite key", `CREATE TABLE candidate (id INTEGER NOT NULL, other INTEGER NOT NULL, PRIMARY KEY(id,other))`, "candidate"},
		{"nullable text key", `CREATE TABLE candidate (id TEXT PRIMARY KEY)`, "candidate"},
		{"view", `CREATE VIEW candidate AS SELECT 1 AS id`, "candidate"},
		{"virtual table", `CREATE VIRTUAL TABLE candidate USING fts5(id)`, "candidate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newAppMCPReadConnectionTestDB(t)
			if _, err := db.Exec(tc.ddl); err != nil {
				t.Fatal(err)
			}
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			defer tx.Rollback()
			err = initializeAppMCPRevisionStorage(tx, []string{tc.table})
			_ = tx.Rollback()
			if err == nil {
				t.Fatal("unsupported table was accepted")
			}
		})
	}
}

func TestAppMCPRevisionInstallIsAtomicAndTempDecoysCannotCaptureIt(t *testing.T) {
	db := newAppMCPReadConnectionTestDB(t)
	if _, err := db.Exec(`INSERT INTO main.notes(id,title) VALUES(1,'before')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TEMP TABLE _benmore_mcp_row_revisions (table_name TEXT); CREATE TEMP TABLE notes (id INTEGER PRIMARY KEY, title TEXT)`); err != nil {
		t.Fatal(err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := initializeAppMCPRevisionStorage(tx, []string{"notes"}); err != nil {
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM main.sqlite_schema WHERE name IN (?,?)`, appMCPRevisionTablesName, appMCPRowRevisionsName).Scan(&count); err != nil || count != 0 {
		t.Fatalf("rolled-back installation left main sidecars=%d err=%v", count, err)
	}
	initRevisionStorage(t, db, "notes")
	if _, err := db.Exec(`UPDATE main.notes SET title='after' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	_, revision, _ := appMCPRevisionRow(t, db, "notes", "integer", "1")
	if revision != 2 {
		t.Fatalf("main table trigger missed write under TEMP shadow: revision=%d", revision)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM temp._benmore_mcp_row_revisions`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("revision write reached TEMP decoy: count=%d err=%v", count, err)
	}
}

func TestAppMCPRevisionVerificationRejectsTamperingAndBootstrapRotatesIncarnation(t *testing.T) {
	t.Run("missing trigger", func(t *testing.T) {
		db := newAppMCPReadConnectionTestDB(t)
		initRevisionStorage(t, db, "notes")
		trigger := appMCPRevisionTriggerSQL("notes")[0].name
		if _, err := db.Exec("DROP TRIGGER main." + quoteIdent(trigger)); err != nil {
			t.Fatal(err)
		}
		if err := verifyRevisionStorage(t, db, "notes"); err == nil {
			t.Fatal("missing trigger passed preflight")
		}
	})
	t.Run("tampered trigger requires explicit incarnation rotation", func(t *testing.T) {
		db := newAppMCPReadConnectionTestDB(t)
		seedRevisionNote(t, db)
		initRevisionStorage(t, db, "notes")
		oldIncarnation, _, _ := appMCPRevisionRow(t, db, "notes", "integer", "1")
		trigger := appMCPRevisionTriggerSQL("notes")[0].name
		if _, err := db.Exec("DROP TRIGGER main." + quoteIdent(trigger)); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("CREATE TRIGGER main." + quoteIdent(trigger) + ` AFTER INSERT ON notes BEGIN SELECT 1; END`); err != nil {
			t.Fatal(err)
		}
		if err := verifyRevisionStorage(t, db, "notes"); err == nil {
			t.Fatal("tampered trigger passed preflight")
		}
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		defer tx.Rollback()
		if err := repairAppMCPRevisionStorage(tx, []string{"notes"}); err != nil {
			tx.Rollback()
			t.Fatal(err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		newIncarnation, revision, _ := appMCPRevisionRow(t, db, "notes", "integer", "1")
		if newIncarnation == oldIncarnation || revision != 1 {
			t.Fatalf("repair incarnation/revision old=%q new=%q/%d", oldIncarnation, newIncarnation, revision)
		}
		if err := verifyRevisionStorage(t, db, "notes"); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("sidecar schema", func(t *testing.T) {
		db := newAppMCPReadConnectionTestDB(t)
		initRevisionStorage(t, db, "notes")
		if _, err := db.Exec(`ALTER TABLE main._benmore_mcp_row_revisions ADD COLUMN changed TEXT`); err != nil {
			t.Fatal(err)
		}
		if err := verifyRevisionStorage(t, db, "notes"); err == nil {
			t.Fatal("tampered sidecar schema passed preflight")
		}
	})
	t.Run("table recreation", func(t *testing.T) {
		db := newAppMCPReadConnectionTestDB(t)
		initRevisionStorage(t, db, "notes")
		if _, err := db.Exec(`DROP TABLE main.notes; CREATE TABLE main.notes (id INTEGER PRIMARY KEY, title TEXT)`); err != nil {
			t.Fatal(err)
		}
		if err := verifyRevisionStorage(t, db, "notes"); err == nil {
			t.Fatal("recreated business table passed preflight without its triggers")
		}
	})
	t.Run("missing all metadata requires explicit bootstrap and rotates incarnation", func(t *testing.T) {
		db := newAppMCPReadConnectionTestDB(t)
		seedRevisionNote(t, db)
		initRevisionStorage(t, db, "notes")
		oldIncarnation, oldRevision, _ := appMCPRevisionRow(t, db, "notes", "integer", "1")
		rows, err := db.Query(`SELECT name FROM main.sqlite_schema WHERE type='trigger' AND substr(name,1,17)='_benmore_mcp_rev_'`)
		if err != nil {
			t.Fatal(err)
		}
		var triggerNames []string
		for rows.Next() {
			var name string
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				t.Fatal(err)
			}
			triggerNames = append(triggerNames, name)
		}
		if err := rows.Close(); err != nil {
			t.Fatal(err)
		}
		for _, name := range triggerNames {
			if _, err := db.Exec("DROP TRIGGER main." + quoteIdent(name)); err != nil {
				t.Fatal(err)
			}
		}
		if _, err := db.Exec(`DROP TABLE main._benmore_mcp_row_revisions; DROP TABLE main._benmore_mcp_revision_tables`); err != nil {
			t.Fatal(err)
		}
		if err := verifyRevisionStorage(t, db, "notes"); err == nil {
			t.Fatal("missing metadata passed verification")
		}
		// Dropping the table sidecars also drops their triggers. This explicit
		// bootstrap intentionally creates a new incarnation; no prior token can
		// compare equal across it.
		initRevisionStorage(t, db, "notes")
		newIncarnation, newRevision, _ := appMCPRevisionRow(t, db, "notes", "integer", "1")
		if newIncarnation == oldIncarnation || oldRevision != 1 || newRevision != 1 {
			t.Fatalf("bootstrap incarnation/revision old=%q/%d new=%q/%d", oldIncarnation, oldRevision, newIncarnation, newRevision)
		}
	})
}

func TestAppMCPRevisionOverflowAndTwoConnectionsDoNotLoseBusinessWrites(t *testing.T) {
	db := newAppMCPReadConnectionTestDB(t)
	seedRevisionNote(t, db)
	initRevisionStorage(t, db, "notes")
	incarnation, _, _ := appMCPRevisionRow(t, db, "notes", "integer", "1")
	if _, err := db.Exec(`UPDATE main._benmore_mcp_row_revisions SET revision=? WHERE table_name='notes' AND incarnation=? AND key_type='integer' AND row_key='1'`, int64(math.MaxInt64), incarnation); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE OR IGNORE main.notes SET title='overflow' WHERE id=1`); err == nil {
		t.Fatal("UPDATE OR IGNORE committed a business row after revision overflow")
	}
	var title string
	if err := db.QueryRow(`SELECT title FROM main.notes WHERE id=1`).Scan(&title); err != nil || title == "overflow" {
		t.Fatalf("overflow business write escaped rollback: title=%q err=%v", title, err)
	}
	if _, err := db.Exec(`DELETE FROM main.notes WHERE id=1`); err == nil {
		t.Fatal("delete committed after revision overflow")
	}
	if err := db.QueryRow(`SELECT title FROM main.notes WHERE id=1`).Scan(&title); err != nil || title == "overflow" {
		t.Fatalf("overflow delete changed business row: title=%q err=%v", title, err)
	}
	if _, err := db.Exec(`INSERT INTO main._benmore_mcp_row_revisions(table_name,incarnation,key_type,row_key,revision,deleted) VALUES('notes',?,'integer','2',?,1)`, incarnation, int64(math.MaxInt64)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO main.notes(id,title) VALUES(2,'resurrect overflow')`); err == nil {
		t.Fatal("INSERT OR IGNORE committed a row after tombstone revision overflow")
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM main.notes WHERE id=2`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("overflow resurrection inserted business row: count=%d err=%v", count, err)
	}

	path := filepath.Join(t.TempDir(), "two-connection.db")
	first, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=0")
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	second, err := sql.Open("sqlite3", path+"?_journal_mode=WAL&_busy_timeout=0")
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	for _, handle := range []*sql.DB{first, second} {
		handle.SetMaxOpenConns(1)
	}
	if _, err := first.Exec(`CREATE TABLE tasks (id INTEGER PRIMARY KEY, state TEXT); INSERT INTO tasks VALUES(1,'open')`); err != nil {
		t.Fatal(err)
	}
	initRevisionStorage(t, first, "tasks")
	tx, err := first.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`UPDATE tasks SET state='first' WHERE id=1`); err != nil {
		tx.Rollback()
		t.Fatal(err)
	}
	if _, err := second.Exec(`UPDATE tasks SET state='second' WHERE id=1`); err == nil || !strings.Contains(strings.ToLower(err.Error()), "locked") {
		tx.Rollback()
		t.Fatalf("second writer did not observe SQLite write conflict: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, err := second.Exec(`UPDATE tasks SET state='second' WHERE id=1`); err != nil {
		t.Fatal(err)
	}
	_, revision, _ := appMCPRevisionRow(t, first, "tasks", "integer", "1")
	if revision != 3 {
		t.Fatalf("serialized writers lost revision increment: got %d want 3", revision)
	}
}

func TestAppMCPRevisionVerificationRejectsLedgerCorruption(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*testing.T, *sql.DB)
	}{
		{
			name: "missing live ledger row",
			mutate: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`DELETE FROM main._benmore_mcp_row_revisions WHERE table_name='notes' AND key_type='integer' AND row_key='1'`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "active orphan",
			mutate: func(t *testing.T, db *sql.DB) {
				var incarnation string
				if err := db.QueryRow(`SELECT incarnation FROM main._benmore_mcp_revision_tables WHERE table_name='notes'`).Scan(&incarnation); err != nil {
					t.Fatal(err)
				}
				if _, err := db.Exec(`INSERT INTO main._benmore_mcp_row_revisions(table_name,incarnation,key_type,row_key,revision,deleted) VALUES('notes',?,'integer','999',1,0)`, incarnation); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "malformed incarnation",
			mutate: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`UPDATE main._benmore_mcp_revision_tables SET incarnation='not-an-incarnation' WHERE table_name='notes'`); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			name: "stale incarnation",
			mutate: func(t *testing.T, db *sql.DB) {
				if _, err := db.Exec(`UPDATE main._benmore_mcp_revision_tables SET incarnation='00000000000000000000000000000000' WHERE table_name='notes'`); err != nil {
					t.Fatal(err)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newAppMCPReadConnectionTestDB(t)
			seedRevisionNote(t, db)
			initRevisionStorage(t, db, "notes")
			tc.mutate(t, db)
			if err := verifyRevisionStorage(t, db, "notes"); err == nil {
				t.Fatal("corrupt revision ledger passed verification")
			}
		})
	}
}
