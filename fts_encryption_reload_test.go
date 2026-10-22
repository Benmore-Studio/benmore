//go:build !cli

package main

import (
	"path/filepath"
	"strings"
	"testing"
)

// The first check creates FTS after encryption. A later check/reload recreates
// encryption triggers but reuses FTS, reversing SQLite's insert trigger order.
// An encryption-only nested UPDATE must not delete an unindexed FTS row.
func TestFTSEncryptedWritesAfterLifecycleTransition(t *testing.T) {
	for _, mode := range []string{"startup", "reload", "check", "legacy-reload"} {
		t.Run(mode, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, dir, "app.yaml", "auth:\n  signup: false\nversioned: [expenses]\n")
			writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("ab", 32)+"\n")
			writeTestFile(t, dir, "encrypted.yaml", "tables:\n  expenses:\n    fields: [finance_note]\n    blind_index: [finance_note]\n")
			writeTestFile(t, dir, "schema.prisma", `model Expense {
 id Int @id @default(autoincrement())
 title String?
 body String? @default("")
 financeNote String @default("") @map("finance_note")
 updatedAt DateTime @updatedAt @map("updated_at")
 @@map("expenses")
 @@fulltext([title, body])
}
`)
			first, err := loadAppWithOptions(dir, appLoadOptions{checkOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			defer func() { dbCryptoRegistry.Delete(canonicalDBPath(filepath.Join(dir, "data.db"))) }()
			app := first
			defer func() {
				if app != nil {
					app.Shutdown()
				}
			}()
			if mode == "legacy-reload" {
				mustExec(t, app.DB, `INSERT INTO expenses(id,title,body,finance_note) VALUES(2,'legacy searchable','old body','previous private')`)
				// The old unconditional trigger must be upgraded, and that repair
				// must rebuild postings lost before reconciliation.
				mustExec(t, app.DB, `DROP TRIGGER expenses_fts_au`)
				mustExec(t, app.DB, `CREATE TRIGGER expenses_fts_au AFTER UPDATE ON expenses BEGIN INSERT INTO expenses_fts(expenses_fts, rowid, title, body) VALUES('delete', old.id, old.title, old.body); INSERT INTO expenses_fts(rowid, title, body) VALUES (new.id, new.title, new.body); END`)
				mustExec(t, app.DB, `INSERT INTO expenses_fts(expenses_fts,rowid,title,body) VALUES('delete',2,'legacy searchable','old body')`)
			}
			for transition := 0; transition < 2; transition++ {
				switch mode {
				case "startup":
					app.Shutdown()
					app, err = loadAppWithOptions(dir, appLoadOptions{startup: true})
				case "reload", "legacy-reload":
					err = reloadAppConfig(app)
				case "check":
					checked, checkErr := loadAppWithOptions(dir, appLoadOptions{checkOnly: true})
					err = checkErr
					if checked != nil {
						checked.Shutdown()
					}
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			if _, err := app.DB.Exec(`INSERT INTO expenses(id,title,body,finance_note) VALUES(1,'alpha title','bravo body','private canary')`); err != nil {
				t.Fatalf("first encrypted insert after %s: %v", mode, err)
			}
			assertFTS := func(query string, want int) {
				t.Helper()
				var got int
				err := app.DB.QueryRow(`SELECT count(*) FROM expenses_fts WHERE expenses_fts MATCH ?`, escapeFTS5Query(query)).Scan(&got)
				if err != nil || got != want {
					t.Fatalf("FTS %q: got %d, want %d, err %v", query, got, want, err)
				}
			}
			assertStorage := func(value string) {
				t.Helper()
				var count int
				err := app.DB.QueryRow(`SELECT count(*) FROM expenses WHERE id=1 AND benmore_ciphertext_matches(finance_note,'expenses','finance_note') AND finance_note_blind=benmore_blind_index(?)`, value).Scan(&count)
				if err != nil || count != 1 {
					t.Fatalf("encrypted/blind storage: count=%d err=%v", count, err)
				}
			}
			assertStorage("private canary")
			assertFTS("alpha", 1)
			assertFTS("bravo", 1)
			assertFTS("private", 0)
			if mode == "legacy-reload" {
				assertFTS("legacy", 1)
				mustExec(t, app.DB, `DELETE FROM expenses WHERE id=2`)
				assertFTS("legacy", 0)
			}
			for _, statement := range []string{
				`UPDATE expenses SET finance_note='replacement secret' WHERE id=1`,
				`UPDATE expenses SET title='charlie title',body='delta body',finance_note='replacement secret' WHERE id=1`,
				`UPDATE expenses SET title=title,body=body WHERE id=1`,
			} {
				if _, err := app.DB.Exec(statement); err != nil {
					t.Fatal(err)
				}
			}
			assertStorage("replacement secret")
			assertFTS("alpha", 0)
			assertFTS("bravo", 0)
			assertFTS("charlie", 1)
			assertFTS("delta", 1)
			mustExec(t, app.DB, `UPDATE expenses SET title=NULL,body=NULL WHERE id=1`)
			assertFTS("charlie", 0)
			assertFTS("delta", 0)
			mustExec(t, app.DB, `UPDATE expenses SET title='echo title',body='foxtrot body' WHERE id=1`)
			assertFTS("echo", 1)
			assertFTS("foxtrot", 1)
			mustExec(t, app.DB, `UPDATE expenses SET rowid=9 WHERE id=1`)
			var indexedID int
			if err := app.DB.QueryRow(`SELECT rowid FROM expenses_fts WHERE expenses_fts MATCH 'echo'`).Scan(&indexedID); err != nil || indexedID != 9 {
				t.Fatalf("rowid alias update: id=%d err=%v", indexedID, err)
			}
			if _, err := app.DB.Exec(`INSERT INTO expenses_fts(expenses_fts,rank) VALUES('integrity-check',1)`); err != nil {
				t.Fatal(err)
			}
			if _, err := app.DB.Exec(`DELETE FROM expenses WHERE id=9`); err != nil {
				t.Fatal(err)
			}
			assertFTS("echo", 0)
			assertFTS("foxtrot", 0)
			var rows int
			if err := app.DB.QueryRow(`SELECT count(*) FROM expenses`).Scan(&rows); err != nil || rows != 0 {
				t.Fatalf("persisted rows=%d err=%v", rows, err)
			}
		})
	}
}
