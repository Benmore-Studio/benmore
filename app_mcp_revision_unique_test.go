//go:build !cli && !windows

package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func appMCPRevisionUniqueRows(t *testing.T, db *sql.DB, query string) []string {
	t.Helper()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var result []string
	for rows.Next() {
		values := make([]sql.NullString, len(columns))
		dest := make([]any, len(values))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			t.Fatal(err)
		}
		result = append(result, fmt.Sprint(values))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func appMCPRevisionUniqueRoadmapSnapshot(t *testing.T, db *sql.DB) []string {
	var snapshot []string
	for _, query := range []string{
		`SELECT 'stage',CAST(id AS TEXT),COALESCE(start_date,'<null>'),COALESCE(due_date,'<null>') FROM main.roadmap_stages ORDER BY id`,
		`SELECT 'slot',CAST(id AS TEXT),CAST(project_id AS TEXT),org_id,COALESCE(start_date,'<null>'),COALESCE(due_date,'<null>') FROM main.roadmap_slots ORDER BY id`,
		`SELECT 'edge',CAST(id AS TEXT),CAST(project_id AS TEXT),org_id,CAST(predecessor_slot_id AS TEXT),CAST(successor_slot_id AS TEXT),CAST(lag_days AS TEXT) FROM main.roadmap_edges ORDER BY id`,
		`SELECT 'revision',table_name,incarnation,key_type,row_key,CAST(revision AS TEXT),CAST(deleted AS TEXT) FROM main._benmore_mcp_row_revisions WHERE table_name IN ('roadmap_stages','roadmap_slots','roadmap_edges') ORDER BY table_name,key_type,row_key`,
	} {
		snapshot = append(snapshot, appMCPRevisionUniqueRows(t, db, query)...)
	}
	return snapshot
}

func TestAppMCPRevisionLegacyTriggerBodiesMatchPredecessor(t *testing.T) {
	want := map[string]string{
		"_benmore_mcp_rev_ab5aa97074c454a0_insert":      "47278d4cdf2c32d37e6c357c9898ad71c45ff86b8df5bc426e39fa22b2efad4d",
		"_benmore_mcp_rev_ab5aa97074c454a0_update_same": "4a43287e80cf5ae3b58fb4862c5f937179a6344fde429d11518f0c874e4fd63a",
		"_benmore_mcp_rev_ab5aa97074c454a0_update_move": "28c72e4586a9356031e4b35c72d331e1abf9fd9a654d975d3e4f14a1a0b2a8f9",
		"_benmore_mcp_rev_ab5aa97074c454a0_delete":      "52f77d13ccd35bf1fd83e67d2046a1a647a14c69467eb61e571b1e6b94687a7f",
	}
	triggers := appMCPRevisionTriggerSQL("notes")
	if len(triggers) != len(want) {
		t.Fatalf("legacy trigger count=%d want=%d", len(triggers), len(want))
	}
	for _, trigger := range triggers {
		digest := sha256.Sum256([]byte(trigger.sql))
		if got := hex.EncodeToString(digest[:]); got != want[trigger.name] {
			t.Fatalf("predecessor trigger %s changed: %s", trigger.name, got)
		}
	}
	db := newAppMCPReadConnectionTestDB(t)
	initRevisionStorage(t, db, "notes")
	if err := verifyRevisionStorage(t, db, "notes"); err != nil {
		t.Fatalf("legacy enrollment failed native verification: %v", err)
	}
}

func TestAppMCPRevisionUniqueReplaceTracksEveryVictim(t *testing.T) {
	for _, recursive := range []int{0, 1} {
		t.Run(fmt.Sprintf("recursive_triggers_%d", recursive), func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "revisions.db")
			setupDB, err := sql.Open("sqlite3_benmore", path)
			if err != nil {
				t.Fatal(err)
			}
			defer setupDB.Close()
			setupDB.SetMaxOpenConns(1)
			if _, err := setupDB.Exec(`CREATE TABLE unique_rows (id INTEGER PRIMARY KEY, email TEXT, group_id INTEGER, code TEXT); CREATE UNIQUE INDEX unique_email_group ON unique_rows(email,group_id); CREATE UNIQUE INDEX unique_code ON unique_rows(code); INSERT INTO unique_rows VALUES (1,'first',10,'one'),(2,'second',20,'two'),(3,'survivor',30,'three'),(6,'unrelated',60,'unrelated')`); err != nil {
				t.Fatal(err)
			}
			initRevisionStorage(t, setupDB, "unique_rows")

			writerDB, err := sql.Open("sqlite3_benmore", path)
			if err != nil {
				t.Fatal(err)
			}
			defer writerDB.Close()
			writerDB.SetMaxOpenConns(1)
			writer, err := writerDB.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer writer.Close()
			if _, err := writer.ExecContext(context.Background(), fmt.Sprintf(`PRAGMA recursive_triggers=%d`, recursive)); err != nil {
				t.Fatal(err)
			}
			var actualRecursive int
			if err := writer.QueryRowContext(context.Background(), `PRAGMA recursive_triggers`).Scan(&actualRecursive); err != nil || actualRecursive != recursive {
				t.Fatalf("ordinary writer recursive_triggers=%d err=%v", actualRecursive, err)
			}
			if _, err := writer.ExecContext(context.Background(), `INSERT OR REPLACE INTO main.unique_rows VALUES (4,'first',10,'two'),(5,'survivor',30,'three')`); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"1", "2", "3"} {
				_, revision, deleted := appMCPRevisionRow(t, setupDB, "unique_rows", "integer", key)
				if revision != 2 || deleted != 1 {
					t.Fatalf("replaced victim %s revision/deleted=%d/%d", key, revision, deleted)
				}
			}
			var physicallyReplaced int
			if err := setupDB.QueryRow(`SELECT count(*) FROM main.unique_rows WHERE id IN (1,2,3)`).Scan(&physicallyReplaced); err != nil || physicallyReplaced != 0 {
				t.Fatalf("physical victims remain=%d err=%v", physicallyReplaced, err)
			}
			_, revision, deleted := appMCPRevisionRow(t, setupDB, "unique_rows", "integer", "6")
			if revision != 1 || deleted != 0 {
				t.Fatalf("unrelated survivor revision/deleted=%d/%d", revision, deleted)
			}
			var physicalRows int
			if err := setupDB.QueryRow(`SELECT count(*) FROM main.unique_rows WHERE (id=4 AND email='first' AND group_id=10) OR (id=5 AND email='survivor' AND group_id=30)`).Scan(&physicalRows); err != nil || physicalRows != 2 {
				t.Fatalf("multirow incoming business rows=%d err=%v", physicalRows, err)
			}
			if err := setupDB.QueryRow(`SELECT count(*) FROM main.unique_rows WHERE id=6 AND email='unrelated' AND group_id=60 AND code='unrelated'`).Scan(&physicalRows); err != nil || physicalRows != 1 {
				t.Fatalf("unrelated survivor business row=%d err=%v", physicalRows, err)
			}
			for _, key := range []string{"4", "5"} {
				_, revision, deleted := appMCPRevisionRow(t, setupDB, "unique_rows", "integer", key)
				if revision != 1 || deleted != 0 {
					t.Fatalf("incoming row %s revision/deleted=%d/%d", key, revision, deleted)
				}
			}
			if _, err := writer.ExecContext(context.Background(), `INSERT INTO main.unique_rows VALUES (1,'restored',11,'restored'),(7,'same-edit',70,'code7'),(8,'same-target',80,'code8'),(9,'move-source',90,'code9'),(10,'move-target',100,'code10')`); err != nil {
				t.Fatal(err)
			}
			_, reincarnatedRevision, reincarnatedDeleted := appMCPRevisionRow(t, setupDB, "unique_rows", "integer", "1")
			if reincarnatedRevision != 3 || reincarnatedDeleted != 0 {
				t.Fatalf("tombstoned key reinsertion=%d/%d", reincarnatedRevision, reincarnatedDeleted)
			}
			var restoredTitle string
			if err := setupDB.QueryRow(`SELECT email FROM main.unique_rows WHERE id=1`).Scan(&restoredTitle); err != nil || restoredTitle != "restored" {
				t.Fatalf("reincarnated physical row=%q err=%v", restoredTitle, err)
			}
			if _, err := writer.ExecContext(context.Background(), `UPDATE OR REPLACE main.unique_rows SET email='same-target',group_id=80 WHERE id=7`); err != nil {
				t.Fatal(err)
			}
			_, sameVictimRevision, sameVictimDeleted := appMCPRevisionRow(t, setupDB, "unique_rows", "integer", "8")
			_, sameRowRevision, sameRowDeleted := appMCPRevisionRow(t, setupDB, "unique_rows", "integer", "7")
			if sameVictimRevision != 2 || sameVictimDeleted != 1 || sameRowRevision != 2 || sameRowDeleted != 0 {
				t.Fatalf("same-key update victim/new=%d/%d %d/%d", sameVictimRevision, sameVictimDeleted, sameRowRevision, sameRowDeleted)
			}
			var sameBusinessRows int
			if err := setupDB.QueryRow(`SELECT count(*) FROM main.unique_rows WHERE id=8`).Scan(&sameBusinessRows); err != nil || sameBusinessRows != 0 {
				t.Fatalf("same-key UPDATE victim physical rows=%d err=%v", sameBusinessRows, err)
			}
			if err := setupDB.QueryRow(`SELECT count(*) FROM main.unique_rows WHERE id=7 AND email='same-target' AND group_id=80`).Scan(&sameBusinessRows); err != nil || sameBusinessRows != 1 {
				t.Fatalf("same-key UPDATE physical row=%d err=%v", sameBusinessRows, err)
			}
			if recursive == 1 {
				const failingMovedUpdate = `UPDATE OR REPLACE main.unique_rows SET id=11,email='move-target',group_id=100 WHERE id=9`
				baselinePath := filepath.Join(t.TempDir(), "native-replace-baseline.db")
				baselineDB, err := sql.Open("sqlite3_benmore", baselinePath)
				if err != nil {
					t.Fatal(err)
				}
				defer baselineDB.Close()
				baselineDB.SetMaxOpenConns(1)
				baselineDB.SetMaxIdleConns(1)
				if _, err := baselineDB.Exec(`PRAGMA recursive_triggers=1`); err != nil {
					t.Fatal(err)
				}
				var baselineRecursive int
				if err := baselineDB.QueryRow(`PRAGMA recursive_triggers`).Scan(&baselineRecursive); err != nil || baselineRecursive != 1 {
					t.Fatalf("baseline recursive_triggers=%d err=%v", baselineRecursive, err)
				}
				if _, err := baselineDB.Exec(`CREATE TABLE unique_rows (id INTEGER PRIMARY KEY, email TEXT, group_id INTEGER, code TEXT); CREATE UNIQUE INDEX unique_email_group ON unique_rows(email,group_id); CREATE UNIQUE INDEX unique_code ON unique_rows(code); CREATE TRIGGER native_delete_control AFTER DELETE ON unique_rows BEGIN SELECT 1; END; INSERT INTO unique_rows VALUES (1,'restored',11,'restored'),(4,'first',10,'two'),(5,'survivor',30,'three'),(6,'unrelated',60,'unrelated'),(7,'same-target',80,'code7'),(9,'move-source',90,'code9'),(10,'move-target',100,'code10')`); err != nil {
					t.Fatal(err)
				}
				baselineBefore := appMCPRevisionUniqueRows(t, baselineDB, `SELECT CAST(id AS TEXT),email,CAST(group_id AS TEXT),code FROM main.unique_rows ORDER BY id`)
				if _, err := baselineDB.Exec(failingMovedUpdate); err == nil || !strings.Contains(err.Error(), "UNIQUE constraint failed: unique_rows.code") {
					t.Fatalf("native trigger-control moved UPDATE error=%v", err)
				}
				baselineAfter := appMCPRevisionUniqueRows(t, baselineDB, `SELECT CAST(id AS TEXT),email,CAST(group_id AS TEXT),code FROM main.unique_rows ORDER BY id`)
				if fmt.Sprint(baselineAfter) != fmt.Sprint(baselineBefore) {
					t.Fatalf("native trigger-control refusal changed business rows before=%v after=%v", baselineBefore, baselineAfter)
				}

				businessBefore := appMCPRevisionUniqueRows(t, setupDB, `SELECT CAST(id AS TEXT),email,CAST(group_id AS TEXT),code FROM main.unique_rows ORDER BY id`)
				ledgerBefore := appMCPRevisionUniqueRows(t, setupDB, `SELECT incarnation,key_type,row_key,CAST(revision AS TEXT),CAST(deleted AS TEXT) FROM main._benmore_mcp_row_revisions WHERE table_name='unique_rows' ORDER BY key_type,row_key`)
				if _, err := writer.ExecContext(context.Background(), failingMovedUpdate); err == nil || !strings.Contains(err.Error(), "UNIQUE constraint failed: unique_rows.code") {
					t.Fatalf("enrolled recursive1 moved UPDATE error=%v", err)
				}
				businessAfter := appMCPRevisionUniqueRows(t, setupDB, `SELECT CAST(id AS TEXT),email,CAST(group_id AS TEXT),code FROM main.unique_rows ORDER BY id`)
				ledgerAfter := appMCPRevisionUniqueRows(t, setupDB, `SELECT incarnation,key_type,row_key,CAST(revision AS TEXT),CAST(deleted AS TEXT) FROM main._benmore_mcp_row_revisions WHERE table_name='unique_rows' ORDER BY key_type,row_key`)
				if fmt.Sprint(businessAfter) != fmt.Sprint(businessBefore) || fmt.Sprint(ledgerAfter) != fmt.Sprint(ledgerBefore) {
					t.Fatalf("enrolled recursive1 refusal changed state business=%v -> %v ledger=%v -> %v", businessBefore, businessAfter, ledgerBefore, ledgerAfter)
				}
			}
			if _, err := writer.ExecContext(context.Background(), `UPDATE OR REPLACE main.unique_rows SET id=11,email='move-target',group_id=100,code='moved-code11' WHERE id=9`); err != nil {
				t.Fatal(err)
			}
			_, movedVictimRevision, movedVictimDeleted := appMCPRevisionRow(t, setupDB, "unique_rows", "integer", "10")
			_, movedOldRevision, movedOldDeleted := appMCPRevisionRow(t, setupDB, "unique_rows", "integer", "9")
			_, movedNewRevision, movedNewDeleted := appMCPRevisionRow(t, setupDB, "unique_rows", "integer", "11")
			if movedVictimRevision != 2 || movedVictimDeleted != 1 || movedOldRevision != 2 || movedOldDeleted != 1 || movedNewRevision != 1 || movedNewDeleted != 0 {
				t.Fatalf("moved-key update victim/old/new=%d/%d %d/%d %d/%d", movedVictimRevision, movedVictimDeleted, movedOldRevision, movedOldDeleted, movedNewRevision, movedNewDeleted)
			}
			if err := setupDB.QueryRow(`SELECT count(*) FROM main.unique_rows WHERE id IN (9,10)`).Scan(&sameBusinessRows); err != nil || sameBusinessRows != 0 {
				t.Fatalf("moved-key UPDATE victims remain=%d err=%v", sameBusinessRows, err)
			}
			if err := setupDB.QueryRow(`SELECT count(*) FROM main.unique_rows WHERE id=11 AND email='move-target' AND group_id=100 AND code='moved-code11'`).Scan(&sameBusinessRows); err != nil || sameBusinessRows != 1 {
				t.Fatalf("moved-key UPDATE incoming row=%d err=%v", sameBusinessRows, err)
			}
			if _, err := writer.ExecContext(context.Background(), `INSERT OR REPLACE INTO main.unique_rows VALUES (7,'same-pk-replaced',70,'new-code7')`); err != nil {
				t.Fatal(err)
			}
			_, samePKRevision, samePKDeleted := appMCPRevisionRow(t, setupDB, "unique_rows", "integer", "7")
			if samePKRevision != int64(3+recursive) || samePKDeleted != 0 {
				t.Fatalf("same-PK REPLACE with recursive_triggers=%d: %d/%d", recursive, samePKRevision, samePKDeleted)
			}
			if err := verifyRevisionStorage(t, setupDB, "unique_rows"); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestAppMCPRevisionUniqueUpdateReplaceAndConflictControls(t *testing.T) {
	db := newAppMCPReadConnectionTestDB(t)
	if _, err := db.Exec(`PRAGMA recursive_triggers=0; CREATE TABLE unique_rows (id INTEGER PRIMARY KEY, email TEXT, group_id INTEGER, code TEXT); CREATE UNIQUE INDEX unique_email_group ON unique_rows(email,group_id); CREATE UNIQUE INDEX unique_code ON unique_rows(code); INSERT INTO unique_rows VALUES (4,'editor',40,'edit-code'),(5,'target',50,'target-code'),(6,'plain',60,'plain-code')`); err != nil {
		t.Fatal(err)
	}
	var recursive int
	if err := db.QueryRow(`PRAGMA recursive_triggers`).Scan(&recursive); err != nil || recursive != 0 {
		t.Fatalf("fixture recursive_triggers=%d err=%v", recursive, err)
	}
	initRevisionStorage(t, db, "unique_rows")
	if _, err := db.Exec(`UPDATE OR REPLACE main.unique_rows SET email='target',group_id=50 WHERE id=4`); err != nil {
		t.Fatal(err)
	}
	_, r5, d5 := appMCPRevisionRow(t, db, "unique_rows", "integer", "5")
	_, r4, d4 := appMCPRevisionRow(t, db, "unique_rows", "integer", "4")
	if r5 != 2 || d5 != 1 || r4 != 2 || d4 != 0 {
		t.Fatalf("UPDATE OR REPLACE victim/editor=%d/%d %d/%d", r5, d5, r4, d4)
	}
	if _, err := db.Exec(`INSERT INTO main.unique_rows VALUES (10,'move-source',100,'move-code'),(11,'move-target',110,'target2')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE OR REPLACE main.unique_rows SET id=12,email='move-target',group_id=110 WHERE id=10`); err != nil {
		t.Fatal(err)
	}
	_, movedVictimRevision, movedVictimDeleted := appMCPRevisionRow(t, db, "unique_rows", "integer", "11")
	_, movedRowRevision, movedRowDeleted := appMCPRevisionRow(t, db, "unique_rows", "integer", "12")
	if movedVictimRevision != 2 || movedVictimDeleted != 1 || movedRowRevision != 1 || movedRowDeleted != 0 {
		t.Fatalf("moved-key UPDATE OR REPLACE victim/new=%d/%d %d/%d", movedVictimRevision, movedVictimDeleted, movedRowRevision, movedRowDeleted)
	}

	_, before6r, before6d := appMCPRevisionRow(t, db, "unique_rows", "integer", "6")
	if _, err := db.Exec(`INSERT INTO main.unique_rows VALUES (7,'other',70,'other-code') ON CONFLICT(email,group_id) DO UPDATE SET code=excluded.code`); err != nil {
		t.Fatal(err)
	}
	_, after6r, after6d := appMCPRevisionRow(t, db, "unique_rows", "integer", "6")
	if after6r != before6r || after6d != before6d {
		t.Fatalf("DO UPDATE changed unrelated row 6: %d/%d", after6r, after6d)
	}
	if _, err := db.Exec(`INSERT INTO main.unique_rows VALUES (8,'other',70,'updated-code') ON CONFLICT(email,group_id) DO UPDATE SET code=excluded.code`); err != nil {
		t.Fatal(err)
	}
	_, row7r, row7d := appMCPRevisionRow(t, db, "unique_rows", "integer", "7")
	if row7r != 2 || row7d != 0 {
		t.Fatalf("same-key UPSERT did not preserve/increment identity: %d/%d", row7r, row7d)
	}
	var absent8 int
	if err := db.QueryRow(`SELECT count(*) FROM main.unique_rows WHERE id=8`).Scan(&absent8); err != nil || absent8 != 0 {
		t.Fatalf("DO UPDATE inserted conflicting row id8=%d err=%v", absent8, err)
	}
	if _, err := db.Exec(`INSERT INTO main.unique_rows VALUES (8,'other',70,'ignored') ON CONFLICT(email,group_id) DO NOTHING`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT OR IGNORE INTO main.unique_rows VALUES (9,'target',50,'ignored')`); err != nil {
		t.Fatal(err)
	}
	_, after4r, after4d := appMCPRevisionRow(t, db, "unique_rows", "integer", "4")
	if after4r != 2 || after4d != 0 {
		t.Fatalf("DO NOTHING/IGNORE changed row 4: %d/%d", after4r, after4d)
	}
	if _, err := db.Exec(`INSERT OR REPLACE INTO main.unique_rows VALUES (7,'upserted',71,'other-code')`); err != nil {
		t.Fatal(err)
	}
	_, row7r, row7d = appMCPRevisionRow(t, db, "unique_rows", "integer", "7")
	if row7r != 3 || row7d != 0 {
		t.Fatalf("same-primary-key REPLACE row 7=%d/%d", row7r, row7d)
	}
	if err := verifyRevisionStorage(t, db, "unique_rows"); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPRevisionUniqueRollbackAndReopen(t *testing.T) {
	path := filepath.Join(t.TempDir(), "revision.db")
	db, err := sql.Open("sqlite3_benmore", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if _, err := db.Exec(`CREATE TABLE unique_rows(id INTEGER PRIMARY KEY, email TEXT UNIQUE, value TEXT); INSERT INTO unique_rows VALUES(1,'victim','original')`); err != nil {
		t.Fatal(err)
	}
	initRevisionStorage(t, db, "unique_rows")
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT OR REPLACE INTO unique_rows VALUES(2,'victim','rolled back')`); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT OR REPLACE INTO unique_rows VALUES(3,'victim','committed')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	db, err = sql.Open("sqlite3_benmore", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := verifyRevisionStorage(t, db, "unique_rows"); err != nil {
		t.Fatal(err)
	}
	_, victimRevision, victimDeleted := appMCPRevisionRow(t, db, "unique_rows", "integer", "1")
	_, currentRevision, currentDeleted := appMCPRevisionRow(t, db, "unique_rows", "integer", "3")
	var rolledBackCount int
	if err := db.QueryRow(`SELECT count(*) FROM main._benmore_mcp_row_revisions WHERE table_name='unique_rows' AND row_key='2'`).Scan(&rolledBackCount); err != nil {
		t.Fatal(err)
	}
	if victimRevision != 2 || victimDeleted != 1 || rolledBackCount != 0 || currentRevision != 1 || currentDeleted != 0 {
		t.Fatalf("rollback/reopen ledger victim=%d/%d rolledBackRows=%d current=%d/%d", victimRevision, victimDeleted, rolledBackCount, currentRevision, currentDeleted)
	}
}

func TestAppMCPRevisionUniqueOverflowAbortsWholeReplace(t *testing.T) {
	db := newAppMCPReadConnectionTestDB(t)
	if _, err := db.Exec(`CREATE TABLE unique_rows (id INTEGER PRIMARY KEY, email TEXT UNIQUE, value TEXT); INSERT INTO unique_rows VALUES(1,'victim','before')`); err != nil {
		t.Fatal(err)
	}
	initRevisionStorage(t, db, "unique_rows")
	if _, err := db.Exec(`UPDATE main._benmore_mcp_row_revisions SET revision=9223372036854775807 WHERE table_name='unique_rows' AND row_key='1' AND deleted=0`); err != nil {
		t.Fatal(err)
	}
	ledgerBefore := appMCPRevisionUniqueRows(t, db, `SELECT incarnation,key_type,row_key,CAST(revision AS TEXT),CAST(deleted AS TEXT) FROM main._benmore_mcp_row_revisions WHERE table_name='unique_rows' ORDER BY key_type,row_key`)
	if _, err := db.Exec(`INSERT OR REPLACE INTO main.unique_rows VALUES(20,'fresh','first'),(2,'victim','after')`); err == nil || !strings.Contains(err.Error(), "revision overflow") {
		t.Fatalf("max victim did not abort: %v", err)
	}
	ledgerAfter := appMCPRevisionUniqueRows(t, db, `SELECT incarnation,key_type,row_key,CAST(revision AS TEXT),CAST(deleted AS TEXT) FROM main._benmore_mcp_row_revisions WHERE table_name='unique_rows' ORDER BY key_type,row_key`)
	if fmt.Sprint(ledgerAfter) != fmt.Sprint(ledgerBefore) {
		t.Fatalf("overflow changed complete ledger before=%v after=%v", ledgerBefore, ledgerAfter)
	}
	var id int
	var value string
	if err := db.QueryRow(`SELECT id,value FROM main.unique_rows WHERE email='victim'`).Scan(&id, &value); err != nil || id != 1 || value != "before" {
		t.Fatalf("failed replace changed business row id=%d value=%q err=%v", id, value, err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM main.unique_rows WHERE id IN (2,20)`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("failed statement kept incoming rows count=%d err=%v", count, err)
	}
	_, revision, deleted := appMCPRevisionRow(t, db, "unique_rows", "integer", "1")
	if revision != int64(9223372036854775807) || deleted != 0 {
		t.Fatalf("failed replace changed victim ledger=%d/%d", revision, deleted)
	}
}

func TestAppMCPRevisionUniqueMainLookupAndRepair(t *testing.T) {
	db := newAppMCPReadConnectionTestDB(t)
	if _, err := db.Exec(`INSERT INTO main.notes VALUES(1,'same'); CREATE TEMP TABLE notes (id INTEGER PRIMARY KEY, title TEXT)`); err != nil {
		t.Fatal(err)
	}
	initRevisionStorage(t, db, "notes")
	_, _, legacy := appMCPRevisionRow(t, db, "notes", "integer", "1")
	if legacy != 0 {
		t.Fatalf("legacy backfill deleted=%d", legacy)
	}
	if err := verifyRevisionStorage(t, db, "notes"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`DROP TABLE temp.notes; CREATE UNIQUE INDEX main.notes_title_unique ON notes(title); CREATE TRIGGER main.notes_other AFTER UPDATE ON notes BEGIN SELECT 1; END`); err != nil {
		t.Fatal(err)
	}
	if err := verifyRevisionStorage(t, db, "notes"); err == nil {
		t.Fatal("new alternate UNIQUE index passed old enrollment")
	}
	oldInc, _, _ := appMCPRevisionRow(t, db, "notes", "integer", "1")
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := repairAppMCPRevisionStorage(tx, []string{"notes"}); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	newInc, rev, deleted := appMCPRevisionRow(t, db, "notes", "integer", "1")
	if oldInc == newInc || rev != 1 || deleted != 0 {
		t.Fatalf("repair did not rotate cleanly: old=%q new=%q %d/%d", oldInc, newInc, rev, deleted)
	}
	if err := verifyRevisionStorage(t, db, "notes"); err != nil {
		t.Fatal(err)
	}
	var title string
	if err := db.QueryRow(`SELECT title FROM main.notes WHERE id=1`).Scan(&title); err != nil || title != "same" {
		t.Fatalf("repair changed business row=%q err=%v", title, err)
	}
	var other int
	if err := db.QueryRow(`SELECT COUNT(*) FROM main.sqlite_schema WHERE type='trigger' AND name='notes_other'`).Scan(&other); err != nil || other != 1 {
		t.Fatalf("repair removed unrelated trigger count=%d err=%v", other, err)
	}
	if _, err := db.Exec(`CREATE TEMP TABLE notes (id INTEGER PRIMARY KEY, title TEXT); INSERT OR REPLACE INTO main.notes VALUES(2,'same')`); err != nil {
		t.Fatal(err)
	}
	_, rev, deleted = appMCPRevisionRow(t, db, "notes", "integer", "1")
	if rev != 2 || deleted != 1 {
		t.Fatalf("main-qualified sweep missed victim under TEMP shadow: %d/%d", rev, deleted)
	}
}

func TestAppMCPRevisionUniqueEnhancedTriggerTamperRequiresRepair(t *testing.T) {
	db := newAppMCPReadConnectionTestDB(t)
	if _, err := db.Exec(`CREATE TABLE unique_rows(id INTEGER PRIMARY KEY,email TEXT UNIQUE); INSERT INTO unique_rows VALUES(1,'old')`); err != nil {
		t.Fatal(err)
	}
	initRevisionStorage(t, db, "unique_rows")
	oldIncarnation, _, _ := appMCPRevisionRow(t, db, "unique_rows", "integer", "1")
	trigger := appMCPRevisionTriggerSQLWithUniqueReconciliation("unique_rows")[0]
	if _, err := db.Exec(`DROP TRIGGER main.` + quoteIdent(trigger.name)); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TRIGGER main.` + quoteIdent(trigger.name) + ` AFTER INSERT ON unique_rows BEGIN SELECT 1; END`); err != nil {
		t.Fatal(err)
	}
	if err := verifyRevisionStorage(t, db, "unique_rows"); err == nil {
		t.Fatal("tampered enhanced trigger passed verification")
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if err := repairAppMCPRevisionStorage(tx, []string{"unique_rows"}); err != nil {
		_ = tx.Rollback()
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	newIncarnation, revision, deleted := appMCPRevisionRow(t, db, "unique_rows", "integer", "1")
	if newIncarnation == oldIncarnation || revision != 1 || deleted != 0 {
		t.Fatalf("enhanced-trigger repair identity/revision=%q -> %q %d/%d", oldIncarnation, newIncarnation, revision, deleted)
	}
	if err := verifyRevisionStorage(t, db, "unique_rows"); err != nil {
		t.Fatalf("repaired enhanced trigger failed verification: %v", err)
	}
	if _, err := db.Exec(`INSERT OR REPLACE INTO unique_rows VALUES(2,'old')`); err != nil {
		t.Fatal(err)
	}
	_, revision, deleted = appMCPRevisionRow(t, db, "unique_rows", "integer", "1")
	if revision != 2 || deleted != 1 {
		t.Fatalf("repaired enhanced trigger failed to reconcile: %d/%d", revision, deleted)
	}
}

func TestAppMCPRevisionUniqueIndexAdmissionAndE1ConflictShape(t *testing.T) {
	for _, tc := range []struct{ name, ddl string }{
		{"expression", `CREATE TABLE candidate(id INTEGER PRIMARY KEY, value TEXT); CREATE UNIQUE INDEX uq_expr ON candidate(lower(value))`},
		{"partial", `CREATE TABLE candidate(id INTEGER PRIMARY KEY, value TEXT); CREATE UNIQUE INDEX uq_partial ON candidate(value) WHERE value IS NOT NULL`},
		{"collation", `CREATE TABLE candidate(id INTEGER PRIMARY KEY, value TEXT); CREATE UNIQUE INDEX uq_nocase ON candidate(value COLLATE NOCASE)`},
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
			err = initializeAppMCPRevisionStorage(tx, []string{"candidate"})
			_ = tx.Rollback()
			if err == nil {
				t.Fatal("unsupported unique index accepted")
			}
		})
	}
	db := newAppMCPReadConnectionTestDB(t)
	if _, err := db.Exec(`CREATE TABLE document_slots (id INTEGER PRIMARY KEY, group_id INTEGER NOT NULL, project_id INTEGER NOT NULL);
CREATE TABLE document_slot_dependencies (
 id INTEGER PRIMARY KEY AUTOINCREMENT,
 group_id INTEGER NOT NULL,
 project_id INTEGER NOT NULL,
 predecessor_slot_id INTEGER NOT NULL,
 successor_slot_id INTEGER NOT NULL,
 lag_days INTEGER NOT NULL DEFAULT 0,
 user_id INTEGER NOT NULL,
 created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
 FOREIGN KEY(predecessor_slot_id) REFERENCES document_slots(id) ON DELETE CASCADE,
 FOREIGN KEY(successor_slot_id) REFERENCES document_slots(id) ON DELETE CASCADE
);
CREATE UNIQUE INDEX document_slot_dependencies_group_id_predecessor_slot_id_successor_slot_id_key ON document_slot_dependencies(group_id,predecessor_slot_id,successor_slot_id);
CREATE INDEX document_slot_dependencies_project_id_predecessor_slot_id_idx ON document_slot_dependencies(project_id,predecessor_slot_id);
CREATE INDEX document_slot_dependencies_project_id_successor_slot_id_idx ON document_slot_dependencies(project_id,successor_slot_id);
INSERT INTO document_slots VALUES(3,7,9),(4,7,9);
INSERT INTO document_slot_dependencies(id,group_id,project_id,predecessor_slot_id,successor_slot_id,lag_days,user_id) VALUES(41,7,9,3,4,1,101),(42,8,9,3,4,9,102)`); err != nil {
		t.Fatal(err)
	}
	initRevisionStorage(t, db, "document_slot_dependencies")
	_, group8RevisionBefore, group8DeletedBefore := appMCPRevisionRow(t, db, "document_slot_dependencies", "integer", "42")
	var upsertID, upsertPredecessor, upsertSuccessor, upsertLag int
	if err := db.QueryRow(`INSERT INTO document_slot_dependencies
 (group_id,project_id,predecessor_slot_id,successor_slot_id,lag_days,user_id,created_at)
 VALUES(7,9,3,4,7,999,CURRENT_TIMESTAMP)
 ON CONFLICT(group_id,predecessor_slot_id,successor_slot_id)
 DO UPDATE SET lag_days=excluded.lag_days
 RETURNING id,predecessor_slot_id,successor_slot_id,lag_days`).Scan(&upsertID, &upsertPredecessor, &upsertSuccessor, &upsertLag); err != nil {
		t.Fatal(err)
	}
	if upsertID != 41 || upsertPredecessor != 3 || upsertSuccessor != 4 || upsertLag != 7 {
		t.Fatalf("source-shaped E1 UPSERT readback id=%d endpoints=%d/%d lag=%d", upsertID, upsertPredecessor, upsertSuccessor, upsertLag)
	}
	var group7ID, group7Lag, group7User int
	if err := db.QueryRow(`SELECT id,lag_days,user_id FROM document_slot_dependencies WHERE group_id=7 AND project_id=9 AND predecessor_slot_id=3 AND successor_slot_id=4`).Scan(&group7ID, &group7Lag, &group7User); err != nil {
		t.Fatal(err)
	}
	var group8ID, group8Lag, group8User int
	if err := db.QueryRow(`SELECT id,lag_days,user_id FROM document_slot_dependencies WHERE group_id=8 AND project_id=9 AND predecessor_slot_id=3 AND successor_slot_id=4`).Scan(&group8ID, &group8Lag, &group8User); err != nil {
		t.Fatal(err)
	}
	_, group8RevisionAfter, group8DeletedAfter := appMCPRevisionRow(t, db, "document_slot_dependencies", "integer", "42")
	_, group7Revision, group7Deleted := appMCPRevisionRow(t, db, "document_slot_dependencies", "integer", "41")
	if group8ID != 42 || group8Lag != 9 || group8User != 102 || group8RevisionAfter != group8RevisionBefore || group8DeletedAfter != group8DeletedBefore {
		t.Fatalf("other group changed: id=%d lag=%d user=%d revision=%d/%d", group8ID, group8Lag, group8User, group8RevisionAfter, group8DeletedAfter)
	}
	if group7ID != 41 || group7Lag != 7 || group7User != 101 || group7Revision != 2 || group7Deleted != 0 {
		t.Fatalf("E1 conflict update did not preserve/increment source row identity: id=%d lag=%d user=%d revision=%d/%d", group7ID, group7Lag, group7User, group7Revision, group7Deleted)
	}
	if err := verifyRevisionStorage(t, db, "document_slot_dependencies"); err != nil {
		t.Fatal(err)
	}

	typedDB := newAppMCPReadConnectionTestDB(t)
	if _, err := typedDB.Exec(`CREATE TABLE typed_unique(id BLOB NOT NULL PRIMARY KEY, group_id INTEGER NOT NULL, code TEXT NOT NULL, UNIQUE(group_id,code)); INSERT INTO typed_unique VALUES(1,7,'same'),('1',8,'other')`); err != nil {
		t.Fatal(err)
	}
	initRevisionStorage(t, typedDB, "typed_unique")
	if _, err := typedDB.Exec(`INSERT OR REPLACE INTO typed_unique VALUES(2,7,'same')`); err != nil {
		t.Fatal(err)
	}
	_, integerRevision, integerDeleted := appMCPRevisionRow(t, typedDB, "typed_unique", "integer", "1")
	_, textRevision, textDeleted := appMCPRevisionRow(t, typedDB, "typed_unique", "text", "1")
	if integerRevision != 2 || integerDeleted != 1 || textRevision != 1 || textDeleted != 0 {
		t.Fatalf("typed conflict collapsed integer/text identities: integer=%d/%d text=%d/%d", integerRevision, integerDeleted, textRevision, textDeleted)
	}
	if err := verifyRevisionStorage(t, typedDB, "typed_unique"); err != nil {
		t.Fatal(err)
	}

	nullDB := newAppMCPReadConnectionTestDB(t)
	if _, err := nullDB.Exec(`CREATE TABLE nullable_unique(id INTEGER PRIMARY KEY, group_id INTEGER, code TEXT, UNIQUE(group_id,code)); INSERT INTO nullable_unique VALUES(1,7,NULL),(2,7,NULL)`); err != nil {
		t.Fatal(err)
	}
	initRevisionStorage(t, nullDB, "nullable_unique")
	if _, err := nullDB.Exec(`INSERT INTO nullable_unique VALUES(3,7,NULL)`); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"1", "2"} {
		_, revision, deleted := appMCPRevisionRow(t, nullDB, "nullable_unique", "integer", key)
		if revision != 1 || deleted != 0 {
			t.Fatalf("NULL composite uniqueness incorrectly reconciled key %s: %d/%d", key, revision, deleted)
		}
	}
	if err := verifyRevisionStorage(t, nullDB, "nullable_unique"); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPRevisionUniqueReplaceStalesPreparedRoadmapDependency(t *testing.T) {
	app, sessionID, _ := newCommandProviderRoadmapFixture(t)
	if _, err := app.DB.Exec(`INSERT INTO roadmap_edges(id,project_id,org_id,predecessor_slot_id,successor_slot_id,lag_days) VALUES(1,9,'17',1,2,1)`); err != nil {
		t.Fatal(err)
	}
	generation := snapshotAppMCPGeneration(app)
	var prepared *appMCPCommandPrepared
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "update_roadmap", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		var err error
		prepared, err = cap.prepare(commandRoadmapIntent())
		return false, err
	})
	if err != nil || prepared == nil {
		t.Fatalf("capture prepared roadmap dependency: %v", err)
	}
	writerDB, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(app.Dir, "data.db"), app.Dir))
	if err != nil {
		t.Fatal(err)
	}
	defer writerDB.Close()
	writerDB.SetMaxOpenConns(1)
	writer, err := writerDB.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.ExecContext(context.Background(), `PRAGMA recursive_triggers=0`); err != nil {
		t.Fatal(err)
	}
	var recursive int
	if err := writer.QueryRowContext(context.Background(), `PRAGMA recursive_triggers`).Scan(&recursive); err != nil || recursive != 0 {
		t.Fatalf("independent writer recursive_triggers=%d err=%v", recursive, err)
	}
	if _, err := writer.ExecContext(context.Background(), `INSERT OR REPLACE INTO roadmap_edges(id,project_id,org_id,predecessor_slot_id,successor_slot_id,lag_days) VALUES(99,9,'17',1,2,99)`); err != nil {
		t.Fatal(err)
	}
	_, victimRevision, victimDeleted := appMCPRevisionRow(t, app.DB, "roadmap_edges", "integer", "1")
	if victimRevision != 2 || victimDeleted != 1 {
		t.Fatalf("independent conflict did not tombstone captured edge: %d/%d", victimRevision, victimDeleted)
	}
	stateAfterExternalWrite := appMCPRevisionUniqueRoadmapSnapshot(t, app.DB)
	err = appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "update_roadmap", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		_, _, err := cap.apply(prepared)
		return false, err
	})
	if err == nil || !strings.Contains(err.Error(), "dependency") {
		t.Fatalf("prepared command accepted changed dependency: %v", err)
	}
	stateAfterStaleApply := appMCPRevisionUniqueRoadmapSnapshot(t, app.DB)
	if fmt.Sprint(stateAfterStaleApply) != fmt.Sprint(stateAfterExternalWrite) {
		t.Fatalf("stale apply changed state after legitimate external write\nbefore=%v\nafter=%v", stateAfterExternalWrite, stateAfterStaleApply)
	}
}

func BenchmarkAppMCPRevisionUniqueVictimReconciliation(b *testing.B) {
	for _, batch := range []int{1, 16} {
		b.Run(fmt.Sprintf("rows_512_batch_%d", batch), func(b *testing.B) {
			path := filepath.Join(b.TempDir(), "revision.db")
			db, err := sql.Open("sqlite3_benmore", path)
			if err != nil {
				b.Fatal(err)
			}
			defer db.Close()
			db.SetMaxOpenConns(1)
			if _, err := db.Exec(`CREATE TABLE unique_rows(id INTEGER PRIMARY KEY, group_id INTEGER NOT NULL, code TEXT NOT NULL, UNIQUE(group_id,code))`); err != nil {
				b.Fatal(err)
			}
			for start := 0; start < 512; start += 64 {
				var query strings.Builder
				query.WriteString(`INSERT INTO unique_rows(id,group_id,code) VALUES`)
				args := make([]any, 0, 64*3)
				for i := start; i < start+64; i++ {
					if i != start {
						query.WriteByte(',')
					}
					query.WriteString(`(?,?,?)`)
					args = append(args, i+1, i, fmt.Sprintf("code-%d", i))
				}
				if _, err := db.Exec(query.String(), args...); err != nil {
					b.Fatal(err)
				}
			}
			tx, err := db.Begin()
			if err != nil {
				b.Fatal(err)
			}
			if err := initializeAppMCPRevisionStorage(tx, []string{"unique_rows"}); err != nil {
				_ = tx.Rollback()
				b.Fatal(err)
			}
			if err := tx.Commit(); err != nil {
				b.Fatal(err)
			}
			makeBatch := func(firstID int) (string, []any) {
				var query strings.Builder
				query.WriteString(`INSERT OR REPLACE INTO unique_rows(id,group_id,code) VALUES`)
				args := make([]any, 0, batch*3)
				for i := 0; i < batch; i++ {
					if i > 0 {
						query.WriteByte(',')
					}
					query.WriteString(`(?,?,?)`)
					args = append(args, firstID+i, i, fmt.Sprintf("code-%d", i))
				}
				return query.String(), args
			}
			statementA, argsA := makeBatch(10000)
			statementB, argsB := makeBatch(20000)
			// Untimed setup proves this exact alternate-key conflict removes the
			// original physical row and records its tombstone without growing the table.
			if _, err := db.Exec(statementA, argsA...); err != nil {
				b.Fatal(err)
			}
			for i := 0; i < batch; i++ {
				_, victimRevision, victimDeleted := appMCPRevisionRowB(b, db, "unique_rows", "integer", fmt.Sprint(i+1))
				_, incomingRevision, incomingDeleted := appMCPRevisionRowB(b, db, "unique_rows", "integer", fmt.Sprint(10000+i))
				if victimRevision != 2 || victimDeleted != 1 || incomingRevision != 1 || incomingDeleted != 0 {
					b.Fatalf("timing victim/incoming row %d=%d/%d %d/%d", i, victimRevision, victimDeleted, incomingRevision, incomingDeleted)
				}
				var physicalCount int
				if err := db.QueryRow(`SELECT count(*) FROM main.unique_rows WHERE id=?`, i+1).Scan(&physicalCount); err != nil || physicalCount != 0 {
					b.Fatalf("timing original physical victim %d count=%d err=%v", i+1, physicalCount, err)
				}
				if err := db.QueryRow(`SELECT count(*) FROM main.unique_rows WHERE id=? AND group_id=? AND code=?`, 10000+i, i, fmt.Sprintf("code-%d", i)).Scan(&physicalCount); err != nil || physicalCount != 1 {
					b.Fatalf("timing incoming physical row %d count=%d err=%v", 10000+i, physicalCount, err)
				}
			}
			var liveRows int
			if err := db.QueryRow(`SELECT count(*) FROM unique_rows`).Scan(&liveRows); err != nil || liveRows != 512 {
				b.Fatalf("timing fixture live rows=%d err=%v", liveRows, err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				statement, args := statementA, argsA
				if i%2 == 0 {
					statement, args = statementB, argsB
				}
				if _, err := db.Exec(statement, args...); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func appMCPRevisionRowB(b *testing.B, db *sql.DB, table, keyType, rowKey string) (string, int64, int) {
	b.Helper()
	var incarnation string
	var revision int64
	var deleted int
	if err := db.QueryRow(`SELECT incarnation,revision,deleted FROM main._benmore_mcp_row_revisions WHERE table_name=? AND key_type=? AND row_key=?`, table, keyType, rowKey).Scan(&incarnation, &revision, &deleted); err != nil {
		b.Fatal(err)
	}
	return incarnation, revision, deleted
}

func TestAppMCPRevisionUniqueRepairRetainsOwnerBindingAndStalesPreparedCommand(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixture(t)
	generation := snapshotAppMCPGeneration(app)
	origin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}
	preparedBefore, err := prepareCommandTask(t, app, origin)
	if err != nil || preparedBefore == nil {
		t.Fatalf("initial prepared positive failed: %v", err)
	}
	before := readTestRevisionEnrollment(t, app.Dir)
	if _, err := app.DB.Exec(`CREATE UNIQUE INDEX tasks_title_unique ON tasks(title)`); err != nil {
		t.Fatal(err)
	}
	if _, err := verifyTestRevisionEnrollment(t, app, generation); err == nil {
		t.Fatal("changed alternate-UNIQUE schema passed the current enrollment")
	}
	if _, err := repairAppMCPRevisionEnrollment(context.Background(), app, generation); err != nil {
		t.Fatalf("explicit owner-held enrollment repair: %v", err)
	}
	after := readTestRevisionEnrollment(t, app.Dir)
	if after.State != "active" || after.OwnerEpoch != before.OwnerEpoch || after.EnrollmentID == before.EnrollmentID {
		t.Fatalf("repair lost owner binding or failed to rotate enrollment: before=%+v after=%+v", before, after)
	}
	owner, err := currentAppMCPEpoch(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if owner.Epoch != before.OwnerEpoch || owner.ApprovedWrites == nil || *owner.ApprovedWrites {
		t.Fatalf("repair changed owner identity or left writes enabled: %+v", owner)
	}
	if _, err := verifyTestRevisionEnrollment(t, app, generation); err != nil {
		t.Fatalf("repaired owner-bound enrollment did not verify: %v", err)
	}
	var title string
	if err := app.DB.QueryRow(`SELECT title FROM tasks WHERE id=1`).Scan(&title); err != nil || title != "Source-backed task" {
		t.Fatalf("repair changed business task=%q err=%v", title, err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
		t.Fatalf("fresh native owner-controlled write enable failed: %v", err)
	}
	preparedFresh, err := prepareCommandTask(t, app, origin)
	if err != nil || preparedFresh == nil {
		t.Fatalf("fresh prepared positive after repair failed: %v", err)
	}
	if _, err := applyCommandTask(t, app, origin, preparedBefore); err == nil {
		t.Fatal("old prepared command survived enrollment repair")
	}
	assertCommandTaskUnchanged(t, app)
	if _, err := applyCommandTask(t, app, origin, preparedFresh); err != nil {
		t.Fatalf("fresh prepared command failed after stale-object refusal: %v", err)
	}
	var status string
	if err := app.DB.QueryRow(`SELECT status FROM tasks WHERE id=1`).Scan(&status); err != nil || status != "done" {
		t.Fatalf("fresh command did not apply after repair: status=%q err=%v", status, err)
	}
}
