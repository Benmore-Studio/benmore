//go:build !cli && !windows

package main

import (
	"context"
	"database/sql"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// revisionLedgerRows returns the ledger rows (revision, deleted) recorded for
// one integer key of table in its current incarnation.
func revisionLedgerRows(t *testing.T, db *sql.DB, table string, id int64) [][2]int64 {
	t.Helper()
	rows, err := db.Query(`SELECT revision,deleted FROM main._benmore_mcp_row_revisions WHERE table_name=? AND incarnation=(SELECT incarnation FROM main._benmore_mcp_revision_tables WHERE table_name=?) AND key_type='integer' AND row_key=?`, table, table, strconv.FormatInt(id, 10))
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out [][2]int64
	for rows.Next() {
		var revision, deleted int64
		if err := rows.Scan(&revision, &deleted); err != nil {
			t.Fatal(err)
		}
		out = append(out, [2]int64{revision, deleted})
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

// assertOneLiveLedgerRow checks the revision ledger holds exactly one live row
// for the key, as the insert trigger writes it.
func assertOneLiveLedgerRow(t *testing.T, db *sql.DB, table string, id int64) int64 {
	t.Helper()
	rows := revisionLedgerRows(t, db, table, id)
	if len(rows) != 1 || rows[0][1] != 0 || rows[0][0] < 1 {
		t.Fatalf("%s/%d revision ledger rows = %v, want one live row", table, id, rows)
	}
	return rows[0][0]
}

// The encrypted-field and computed-field triggers on an enrolled table are
// dropped and created again by every load. They used to become newer than the
// revision triggers, so they fired first: their same-row UPDATE ran the
// revision update trigger before the insert trigger had written the ledger
// row, and every insert into the table failed with "revision ledger row
// missing" until the connector was disabled and enabled again.
func TestAppMCPRevisionTriggersFireFirstAfterEncryptedAndComputedReloads(t *testing.T) {
	t.Setenv("BENMORE_CLUSTER", "false")
	f := newCanonicalUpdateFixture(t, "", "", "")
	session := GetSessionFromDB(f.app.DB, f.sid)
	if session == nil {
		t.Fatal("fixture session is missing")
	}
	insertNote := func(title, secret string) int64 {
		t.Helper()
		result, err := f.app.DB.Exec("INSERT INTO main.notes(user_id,title,secret) VALUES(?,?,?)", session.UserID, title, secret)
		if err != nil {
			t.Fatalf("insert %q into the enrolled table: %v", title, err)
		}
		id, err := result.LastInsertId()
		if err != nil {
			t.Fatal(err)
		}
		return id
	}
	assertStored := func(id int64, title, secret string) {
		t.Helper()
		var storedSecret, normalized string
		if err := f.app.DB.QueryRow("SELECT secret,normalized FROM main.notes WHERE id=?", id).Scan(&storedSecret, &normalized); err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(storedSecret, "enc:") || strings.Contains(storedSecret, secret) {
			t.Fatalf("notes/%d secret was not encrypted: %q", id, storedSecret)
		}
		if normalized != strings.ToLower(title) {
			t.Fatalf("notes/%d computed normalized = %q, want %q", id, normalized, strings.ToLower(title))
		}
		assertOneLiveLedgerRow(t, f.app.DB, "notes", id)
	}

	before := insertNote("Before Reload", "first-secret")
	assertStored(before, "Before Reload", "first-secret")

	for i := 0; i < 2; i++ {
		if err := reloadAppConfig(f.app); err != nil {
			t.Fatalf("reload %d: %v", i+1, err)
		}
	}
	var encryptionTriggers int
	if err := f.app.DB.QueryRow("SELECT count(*) FROM main.sqlite_schema WHERE type='trigger' AND name LIKE '_benmore_enc_notes_secret_%'").Scan(&encryptionTriggers); err != nil || encryptionTriggers != 2 {
		t.Fatalf("reload did not keep the encryption triggers: %d (%v)", encryptionTriggers, err)
	}

	afterReload := insertNote("After Reload", "second-secret")
	assertStored(afterReload, "After Reload", "second-secret")

	mux := buildAppMux(f.app, true, "http://localhost")
	created := crudScopeRequest(t, mux, http.MethodPost, "/api/notes", f.sid, map[string]any{"title": "Through CRUD", "secret": "crud-secret"})
	if created.Code != http.StatusOK && created.Code != http.StatusCreated {
		t.Fatalf("auto-CRUD insert into the enrolled table after reload: %d %s", created.Code, created.Body.String())
	}
	var createdRow map[string]any
	mustDecodeBody(t, created, &createdRow)
	crudID, ok := createdRow["id"].(float64)
	if !ok || crudID < 1 {
		t.Fatalf("auto-CRUD create returned no id: %s", created.Body.String())
	}
	assertStored(int64(crudID), "Through CRUD", "crud-secret")
	revisionBefore := assertOneLiveLedgerRow(t, f.app.DB, "notes", int64(crudID))
	updated := crudScopeRequest(t, mux, http.MethodPatch, "/api/notes/"+strconv.FormatInt(int64(crudID), 10), f.sid, map[string]any{"title": "Updated Through CRUD", "secret": "crud-secret-2"})
	if updated.Code != http.StatusOK {
		t.Fatalf("auto-CRUD update of the enrolled table after reload: %d %s", updated.Code, updated.Body.String())
	}
	assertStored(int64(crudID), "Updated Through CRUD", "crud-secret-2")
	if revisionAfter := assertOneLiveLedgerRow(t, f.app.DB, "notes", int64(crudID)); revisionAfter <= revisionBefore {
		t.Fatalf("update did not advance the row revision: %d -> %d", revisionBefore, revisionAfter)
	}
	if _, err := verifyTestRevisionEnrollment(t, f.app, snapshotAppMCPGeneration(f.app)); err != nil {
		t.Fatalf("revision enrollment does not verify after reloads: %v", err)
	}
}

// A restart runs the same load steps as a reload against the stored database.
func TestAppMCPRevisionTriggersFireFirstAfterRestart(t *testing.T) {
	t.Setenv("BENMORE_CLUSTER", "false")
	f := newCanonicalUpdateFixture(t, "", "", "")
	session := GetSessionFromDB(f.app.DB, f.sid)
	if session == nil {
		t.Fatal("fixture session is missing")
	}
	dir := f.app.Dir
	f.app.Shutdown()
	restarted, err := loadApp(dir)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	t.Cleanup(restarted.Shutdown)
	result, err := restarted.DB.Exec("INSERT INTO main.notes(user_id,title,secret) VALUES(?,?,?)", session.UserID, "After Restart", "restart-secret")
	if err != nil {
		t.Fatalf("insert into the enrolled table after restart: %v", err)
	}
	id, _ := result.LastInsertId()
	assertOneLiveLedgerRow(t, restarted.DB, "notes", id)
}

// commandRewrittenActivitiesFixture is the task command app with the table the
// command inserts into (activities) holding an encrypted column, a same-row
// computed column, or both.
func commandRewrittenActivitiesFixture(t *testing.T, encrypted, computed bool) (*App, string) {
	t.Helper()
	app, sessionID, _ := newUnenrolledCommandProviderTaskFixtureWithManifest(t, commandTaskFlowFixture, "", func(_ *AppMCPManifest, dir string) {
		schema, err := os.ReadFile(filepath.Join(dir, "schema.sql"))
		if err != nil {
			t.Fatal(err)
		}
		withLabel := strings.Replace(string(schema), "event TEXT NOT NULL);", "event TEXT NOT NULL, event_label TEXT);", 1)
		if withLabel == string(schema) {
			t.Fatal("task fixture schema changed shape")
		}
		writeTestFile(t, dir, "schema.sql", withLabel)
		if encrypted {
			writeTestFile(t, dir, "encrypted.yaml", "tables:\n  activities:\n    fields:\n      - event\n")
		}
		if computed {
			writeTestFile(t, dir, "computed.yaml", "fields:\n  - table: activities\n    column: event_label\n    expr: upper(actor_email)\n")
		}
	})
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
		t.Fatalf("enable writes: %v", err)
	}
	return app, sessionID
}

func runCompleteItemCommand(t *testing.T, app *App, sessionID string) (map[string]any, error) {
	t.Helper()
	var readback map[string]any
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: snapshotAppMCPGeneration(app), toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		prepared, err := cap.prepare(map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
		if err != nil {
			return false, err
		}
		_, result, err := cap.apply(prepared)
		if err != nil {
			return false, err
		}
		readback = result
		return true, nil
	})
	return readback, err
}

func TestAppMCPCommandInsertsIntoRewrittenTableAfterReload(t *testing.T) {
	for _, tc := range []struct {
		name                string
		encrypted, computed bool
	}{
		{"encrypted", true, false},
		{"computed", false, true},
		{"encrypted_and_computed", true, true},
	} {
		encrypted, computed := tc.encrypted, tc.computed
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("BENMORE_CLUSTER", "false")
			app, sessionID := commandRewrittenActivitiesFixture(t, encrypted, computed)
			if err := reloadAppConfig(app); err != nil {
				t.Fatalf("reload: %v", err)
			}
			// A hot reload turns approved writes off; the owner turns them back on.
			if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, snapshotAppMCPGeneration(app)); err != nil {
				t.Fatalf("enable writes after reload: %v", err)
			}
			readback, err := runCompleteItemCommand(t, app, sessionID)
			if err != nil {
				t.Fatalf("command inserting into the enrolled table after reload: %v", err)
			}
			if readback["status"] != "done" || readback["actor_email"] != "task-actor@example.com" {
				t.Fatalf("command readback = %v", readback)
			}
			var activityID int64
			var event string
			var label sql.NullString
			if err := app.DB.QueryRow("SELECT id,event,event_label FROM main.activities WHERE task_id=1").Scan(&activityID, &event, &label); err != nil {
				t.Fatal(err)
			}
			if strings.HasPrefix(event, "enc:") != encrypted {
				t.Fatalf("activities.event = %q (encrypted field: %v)", event, encrypted)
			}
			if computed && label.String != "TASK-ACTOR@EXAMPLE.COM" {
				t.Fatalf("computed activities.event_label = %q", label.String)
			}
			assertOneLiveLedgerRow(t, app.DB, "activities", activityID)
			assertOneLiveLedgerRow(t, app.DB, "tasks", 1)
		})
	}
}

// SQLite runs a table's triggers for one event newest first, both on the
// connection that created them and on one that reads the schema afresh
// (sqlite_schema rowid order). The revision trigger order check and the load
// steps that put the revision triggers first rely on exactly this.
func TestSQLiteRunsNewestTriggerFirst(t *testing.T) {
	path := filepath.Join(t.TempDir(), "order.db")
	open := func() *sql.DB {
		t.Helper()
		db, err := sql.Open("sqlite3_benmore", path)
		if err != nil {
			t.Fatal(err)
		}
		db.SetMaxOpenConns(1)
		t.Cleanup(func() { _ = db.Close() })
		return db
	}
	exec := func(db *sql.DB, query string) {
		t.Helper()
		if _, err := db.Exec(query); err != nil {
			t.Fatal(err)
		}
	}
	trigger := func(name string) string {
		return "CREATE TRIGGER " + name + " AFTER INSERT ON t BEGIN INSERT INTO fired(name) VALUES('" + name + "'); END"
	}
	firing := func(db *sql.DB) string {
		t.Helper()
		exec(db, "DELETE FROM fired")
		exec(db, "INSERT INTO t DEFAULT VALUES")
		var order string
		if err := db.QueryRow("SELECT group_concat(name, ',') FROM (SELECT name FROM fired ORDER BY seq)").Scan(&order); err != nil {
			t.Fatal(err)
		}
		return order
	}
	creator := open()
	exec(creator, "CREATE TABLE t(id INTEGER PRIMARY KEY); CREATE TABLE fired(seq INTEGER PRIMARY KEY, name TEXT)")
	exec(creator, trigger("made_first"))
	exec(creator, trigger("made_second"))
	if got := firing(creator); got != "made_second,made_first" {
		t.Fatalf("creating connection fired %q", got)
	}
	if got := firing(open()); got != "made_second,made_first" {
		t.Fatalf("fresh connection fired %q", got)
	}
	exec(creator, "DROP TRIGGER made_first")
	exec(creator, trigger("made_first"))
	if got := firing(creator); got != "made_first,made_second" {
		t.Fatalf("creating connection fired %q after recreating made_first", got)
	}
	if got := firing(open()); got != "made_first,made_second" {
		t.Fatalf("fresh connection fired %q after recreating made_first", got)
	}
}

func revisionTriggerTextAndLedger(t *testing.T, db *sql.DB) string {
	t.Helper()
	var parts []string
	for _, query := range []string{
		`SELECT name,sql FROM main.sqlite_schema WHERE type='trigger' ORDER BY name`,
		`SELECT table_name,incarnation,schema_digest FROM main._benmore_mcp_revision_tables ORDER BY table_name`,
		`SELECT table_name,incarnation,key_type,row_key,revision,deleted FROM main._benmore_mcp_row_revisions ORDER BY table_name,key_type,row_key`,
	} {
		parts = append(parts, appMCPRevisionUniqueRows(t, db, query)...)
	}
	return strings.Join(parts, "\n")
}

func reseatRevisionTriggersForTest(t *testing.T, db *sql.DB) {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := reseatAppMCPRevisionTriggers(tx); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPRevisionReseatPutsRevisionTriggersFirstWithoutChangingThem(t *testing.T) {
	for _, tc := range []struct{ table, ddl string }{
		{"notes", `CREATE TABLE notes(id INTEGER PRIMARY KEY, title TEXT, shadow TEXT)`},
		// An alternate UNIQUE key installs the unique-reconciling trigger set.
		{"unique_rows", `CREATE TABLE unique_rows(id INTEGER PRIMARY KEY, title TEXT UNIQUE, shadow TEXT)`},
	} {
		t.Run(tc.table, func(t *testing.T) {
			db, err := sql.Open("sqlite3_benmore", filepath.Join(t.TempDir(), "app.db"))
			if err != nil {
				t.Fatal(err)
			}
			db.SetMaxOpenConns(1)
			t.Cleanup(func() { _ = db.Close() })
			if _, err := db.Exec(tc.ddl + `; INSERT INTO ` + tc.table + `(id,title) VALUES(1,'seed')`); err != nil {
				t.Fatal(err)
			}
			initRevisionStorage(t, db, tc.table)
			var reconciling int
			if err := db.QueryRow(`SELECT count(*) FROM main.sqlite_schema WHERE type='trigger' AND substr(name,1,17)='_benmore_mcp_rev_' AND sql LIKE '%victim%'`).Scan(&reconciling); err != nil || (reconciling > 0) != (tc.table == "unique_rows") {
				t.Fatalf("%s unique-reconciling revision triggers = %d (%v)", tc.table, reconciling, err)
			}
			// A trigger made after enrollment that rewrites the inserted row,
			// as the encrypted-field and computed-field triggers do.
			if _, err := db.Exec(`CREATE TRIGGER rewrite_inserted AFTER INSERT ON ` + tc.table + ` BEGIN UPDATE ` + tc.table + ` SET shadow=upper(NEW.title) WHERE rowid=NEW.rowid; END`); err != nil {
				t.Fatal(err)
			}
			tx, err := db.Begin()
			if err != nil {
				t.Fatal(err)
			}
			problem, err := appMCPRevisionTriggerOrderProblem(tx, []string{tc.table})
			_ = tx.Rollback()
			if err != nil || problem != tc.table {
				t.Fatalf("order problem = %q (%v), want %q", problem, err, tc.table)
			}
			if err := verifyRevisionStorage(t, db, tc.table); err == nil || !strings.Contains(err.Error(), "no longer fire before") {
				t.Fatalf("verification accepted revision triggers that no longer fire first: %v", err)
			}
			if _, err := db.Exec(`INSERT INTO ` + tc.table + `(id,title) VALUES(2,'refused')`); err == nil || !strings.Contains(err.Error(), "revision ledger row missing") {
				t.Fatalf("insert with the rewriting trigger first: %v", err)
			}
			before := revisionTriggerTextAndLedger(t, db)

			reseatRevisionTriggersForTest(t, db)
			if after := revisionTriggerTextAndLedger(t, db); after != before {
				t.Fatalf("reseat changed revision trigger text or the ledger:\nbefore %s\nafter  %s", before, after)
			}
			if err := verifyRevisionStorage(t, db, tc.table); err != nil {
				t.Fatalf("verification after reseat: %v", err)
			}
			if _, err := db.Exec(`INSERT INTO ` + tc.table + `(id,title) VALUES(3,'accepted')`); err != nil {
				t.Fatalf("insert after reseat: %v", err)
			}
			var shadow string
			if err := db.QueryRow(`SELECT shadow FROM ` + tc.table + ` WHERE id=3`).Scan(&shadow); err != nil || shadow != "ACCEPTED" {
				t.Fatalf("rewriting trigger did not run: %q (%v)", shadow, err)
			}
			assertOneLiveLedgerRow(t, db, tc.table, 3)
			if rows := revisionLedgerRows(t, db, tc.table, 2); len(rows) != 0 {
				t.Fatalf("refused insert left ledger rows: %v", rows)
			}
			// Already first: a second reseat changes nothing, not even order.
			var rowids string
			if err := db.QueryRow(`SELECT group_concat(name||':'||rowid) FROM (SELECT name,rowid FROM main.sqlite_schema WHERE type='trigger' ORDER BY rowid)`).Scan(&rowids); err != nil {
				t.Fatal(err)
			}
			reseatRevisionTriggersForTest(t, db)
			var again string
			if err := db.QueryRow(`SELECT group_concat(name||':'||rowid) FROM (SELECT name,rowid FROM main.sqlite_schema WHERE type='trigger' ORDER BY rowid)`).Scan(&again); err != nil || again != rowids {
				t.Fatalf("second reseat moved triggers: %q -> %q (%v)", rowids, again, err)
			}
		})
	}
}

// A revision trigger whose text was changed is not recreated: only an
// explicit repair replaces it, and verification keeps refusing it.
func TestAppMCPRevisionReseatLeavesChangedRevisionTriggersAlone(t *testing.T) {
	db := newAppMCPReadConnectionTestDB(t)
	initRevisionStorage(t, db, "notes")
	deleteTrigger := appMCPRevisionTriggerSQL("notes")[3]
	if _, err := db.Exec(`DROP TRIGGER main.` + quoteIdent(deleteTrigger.name) + `; CREATE TRIGGER main.` + quoteIdent(deleteTrigger.name) + ` AFTER DELETE ON notes BEGIN SELECT 1; END`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER rewrite_inserted AFTER INSERT ON notes BEGIN UPDATE notes SET title=upper(NEW.title) WHERE rowid=NEW.rowid; END`); err != nil {
		t.Fatal(err)
	}
	before := revisionTriggerTextAndLedger(t, db)
	var rowids string
	if err := db.QueryRow(`SELECT group_concat(name||':'||rowid) FROM (SELECT name,rowid FROM main.sqlite_schema WHERE type='trigger' ORDER BY rowid)`).Scan(&rowids); err != nil {
		t.Fatal(err)
	}
	reseatRevisionTriggersForTest(t, db)
	var after string
	if err := db.QueryRow(`SELECT group_concat(name||':'||rowid) FROM (SELECT name,rowid FROM main.sqlite_schema WHERE type='trigger' ORDER BY rowid)`).Scan(&after); err != nil || after != rowids {
		t.Fatalf("reseat recreated a changed revision trigger set: %q -> %q (%v)", rowids, after, err)
	}
	if got := revisionTriggerTextAndLedger(t, db); got != before {
		t.Fatal("reseat changed a tampered revision trigger set")
	}
	if err := verifyRevisionStorage(t, db, "notes"); err == nil || !strings.Contains(err.Error(), "explicit repair") {
		t.Fatalf("tampered revision trigger passed verification: %v", err)
	}
}

// If a trigger is ever created after the revision triggers outside the load
// steps, the connector refuses the enrollment and status says so instead of
// "active"; enable --writes puts the triggers first without re-enrolling.
func TestAppMCPRevisionStatusReportsTriggerOrderAndEnableWritesRepairsIt(t *testing.T) {
	t.Setenv("BENMORE_CLUSTER", "false")
	f := newCanonicalUpdateFixture(t, "", "", "")
	session := GetSessionFromDB(f.app.DB, f.sid)
	if session == nil {
		t.Fatal("fixture session is missing")
	}
	ctx := context.Background()
	if st := appMCPConnectorStatusFor(ctx, f.app); st.Enrollment != "active" {
		t.Fatalf("fixture enrollment status = %q (%s)", st.Enrollment, st.Problem)
	}
	const name = "_benmore_enc_notes_secret_insert"
	var stored string
	if err := f.app.DB.QueryRow(`SELECT sql FROM main.sqlite_schema WHERE type='trigger' AND name=?`, name).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec(`DROP TRIGGER main.` + quoteIdent(name)); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec(stored); err != nil {
		t.Fatal(err)
	}
	if _, err := f.app.DB.Exec("INSERT INTO main.notes(user_id,title,secret) VALUES(?,?,?)", session.UserID, "Out Of Order", "s"); err == nil || !strings.Contains(err.Error(), "revision ledger row missing") {
		t.Fatalf("insert with the encryption trigger first: %v", err)
	}
	if _, err := verifyTestRevisionEnrollment(t, f.app, snapshotAppMCPGeneration(f.app)); err == nil || !strings.Contains(err.Error(), "no longer fire before") {
		t.Fatalf("enrollment verified with revision triggers out of order: %v", err)
	}
	st := appMCPConnectorStatusFor(ctx, f.app)
	if st.Enrollment != "out_of_order" || !strings.Contains(st.Problem, "enable --writes") {
		t.Fatalf("status with revision triggers out of order = %q (%q)", st.Enrollment, st.Problem)
	}
	orderFindings := func() []CheckFinding {
		var out []CheckFinding
		for _, finding := range checkLiveLayersWithDB(f.app.Dir, f.app.DB, func(string) string { return "" }) {
			if strings.Contains(finding.Message, "revision ledger row missing") {
				out = append(out, finding)
			}
		}
		return out
	}
	if findings := orderFindings(); len(findings) != 1 || findings[0].Severity != "error" || !strings.Contains(findings[0].Message, `"notes"`) {
		t.Fatalf("live check with revision triggers out of order = %+v", findings)
	}
	record := readTestRevisionEnrollment(t, f.app.Dir)
	ledger := revisionTriggerTextAndLedger(t, f.app.DB)

	if err := appMCPEnrollAndEnableWrites(ctx, f.app, snapshotAppMCPGeneration(f.app)); err != nil {
		t.Fatalf("enable --writes: %v", err)
	}
	if st := appMCPConnectorStatusFor(ctx, f.app); st.Enrollment != "active" {
		t.Fatalf("status after enable --writes = %q (%s)", st.Enrollment, st.Problem)
	}
	if findings := orderFindings(); len(findings) != 0 {
		t.Fatalf("live check after enable --writes = %+v", findings)
	}
	after := readTestRevisionEnrollment(t, f.app.Dir)
	if after.EnrollmentID != record.EnrollmentID || !sameRevisionEnrollmentTables(after.Tables, record.Tables) {
		t.Fatal("enable --writes re-enrolled instead of reordering the revision triggers")
	}
	if got := revisionTriggerTextAndLedger(t, f.app.DB); got != ledger {
		t.Fatal("reordering changed revision trigger text or the ledger")
	}
	result, err := f.app.DB.Exec("INSERT INTO main.notes(user_id,title,secret) VALUES(?,?,?)", session.UserID, "Back In Order", "s")
	if err != nil {
		t.Fatalf("insert after enable --writes: %v", err)
	}
	id, _ := result.LastInsertId()
	assertOneLiveLedgerRow(t, f.app.DB, "notes", id)
}
