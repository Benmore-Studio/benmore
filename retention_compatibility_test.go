//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func TestRetentionKeepsUnknownTimestampsAndUnconfiguredTables(t *testing.T) {
	db := migrationSafetyDB(t)
	EnsureAuditLogTable(db)
	mustExec(t, db, `CREATE TABLE archived_events (id INTEGER PRIMARY KEY, created_at TEXT, deleted_at TEXT)`)
	mustExec(t, db, `CREATE TABLE unconfigured (id INTEGER PRIMARY KEY, created_at TEXT)`)
	mustExec(t, db, `INSERT INTO unconfigured VALUES (1, '2000-01-01 00:00:00')`)
	mustExec(t, db, `INSERT INTO archived_events VALUES
		(1, NULL, NULL),
		(2, 'not-a-date', NULL),
		(3, '2026-10-19T00:00:00Z', 'invalid'),
		(4, NULL, '2026-10-17 23:59:59'),
		(5, '2026-10-18 00:00:00', NULL),
		(6, '2026-10-17T23:59:59Z', NULL)`)
	now := time.Date(2026, 10, 20, 0, 0, 0, 0, time.UTC)
	policy := []RetentionPolicy{{Table: "archived_events", Column: "created_at", TTL: 48 * time.Hour}}
	for sweep := 0; sweep < 2; sweep++ {
		enforceRetentionAt(db, policy, now)
		for id := 1; id <= 6; id++ {
			var n int
			if err := db.QueryRow(`SELECT count(*) FROM archived_events WHERE id=?`, id).Scan(&n); err != nil {
				t.Fatal(err)
			}
			want := 1
			if id == 4 || id == 6 {
				want = 0
			}
			if n != want {
				t.Fatalf("sweep %d row %d: retained=%d want=%d", sweep, id, n, want)
			}
		}
	}
	var n int
	if err := db.QueryRow(`SELECT count(*) FROM unconfigured`).Scan(&n); err != nil || n != 1 {
		t.Fatalf("unconfigured table changed: count=%d err=%v", n, err)
	}
}

// A table without a rowid (a hand-written migration) cannot be deleted in
// batches by rowid; it is still swept, in the one statement it always was.
func TestRetentionSweepsWithoutRowidTables(t *testing.T) {
	db := migrationSafetyDB(t)
	EnsureAuditLogTable(db)
	mustExec(t, db, `CREATE TABLE codes (code TEXT PRIMARY KEY, created_at TEXT) WITHOUT ROWID`)
	mustExec(t, db, `INSERT INTO codes VALUES ('old', '2000-01-01 00:00:00'), ('new', '2999-01-01 00:00:00')`)
	enforceRetentionAt(db, []RetentionPolicy{{Table: "codes", Column: "created_at", TTL: time.Hour}}, time.Now())
	var left string
	if err := db.QueryRow(`SELECT group_concat(code) FROM codes`).Scan(&left); err != nil || left != "new" {
		t.Fatalf("rows left: %q (%v), want only the unexpired one", left, err)
	}
}

// BenchmarkRetentionTimestampSelection measures the cost of the corrected
// predicate against an ordinary timestamp index, not end-to-end deletion time.
// Both predicates select the same rows in this control fixture; mixed-format
// correctness is separately covered by TestRetentionComparesInstantsAcrossTimestampFormats.
func BenchmarkRetentionTimestampSelection(b *testing.B) {
	for _, size := range []int{10000, 100000} {
		b.Run(fmt.Sprintf("rows=%d", size), func(b *testing.B) {
			db, err := sql.Open("sqlite3", filepath.Join(b.TempDir(), "data.db"))
			if err != nil {
				b.Fatal(err)
			}
			b.Cleanup(func() {
				if err := db.Close(); err != nil {
					b.Error(err)
				}
			})
			for _, q := range []string{
				`CREATE TABLE events (id INTEGER PRIMARY KEY, created_at TEXT)`,
				`CREATE INDEX events_timestamp ON events(created_at)`,
			} {
				if _, err := db.Exec(q); err != nil {
					b.Fatal(err)
				}
			}
			if _, err := db.Exec(`WITH RECURSIVE rows(id) AS (SELECT 1 UNION ALL SELECT id+1 FROM rows WHERE id < ?)
				INSERT INTO events SELECT id, CASE WHEN id % 2 = 0 THEN '2026-10-17T00:00:00Z' ELSE '2026-10-19T00:00:00Z' END FROM rows`, size); err != nil {
				b.Fatal(err)
			}
			for _, tc := range []struct{ name, predicate string }{
				{"text-index-control", `created_at < ?`},
				{"instant-predicate", `julianday(events.created_at) < julianday(?)`},
			} {
				b.Run(tc.name, func(b *testing.B) {
					b.ReportAllocs()
					for b.Loop() {
						var n int
						if err := db.QueryRow(`SELECT count(*) FROM events WHERE `+tc.predicate, "2026-10-18T00:00:00Z").Scan(&n); err != nil {
							b.Fatal(err)
						}
						if n != size/2 {
							b.Fatalf("selected=%d want=%d", n, size/2)
						}
					}
				})
			}
		})
	}
}
