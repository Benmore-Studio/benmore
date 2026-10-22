//go:build !cli

package main

import (
	"fmt"
	"testing"
	"time"
)

func TestRetentionComparesInstantsAcrossTimestampFormats(t *testing.T) {
	db := migrationSafetyDB(t)
	EnsureAuditLogTable(db)
	mustExec(t, db, `CREATE TABLE events(id INTEGER PRIMARY KEY, created_at DATETIME, deleted_at DATETIME)`)
	now := time.Date(2026, 10, 12, 6, 0, 0, 0, time.UTC)
	cases := []struct {
		stamp   string
		expired bool
	}{
		{"2026-10-10 05:59:59", true}, {"2026-10-10 23:59:59", false},
		{"2026-10-10T05:59:59Z", true}, {"2026-10-10T06:00:00Z", false},
		{"2026-10-10T08:30:00+03:00", true}, {"2026-10-10T03:30:00-03:00", false},
		{"2026-10-10T06:00:00.500Z", false}, {"2026-10-10T05:59:59.500Z", true},
		{"not-a-date", false},
	}
	for _, softDelete := range []bool{false, true} {
		t.Run(fmt.Sprintf("soft-delete=%v", softDelete), func(t *testing.T) {
			mustExec(t, db, `DELETE FROM events`)
			for i, c := range cases {
				created, deleted := any(c.stamp), any(nil)
				if softDelete {
					created = "2026-10-12T06:00:00Z"
					deleted = c.stamp
				}
				if _, err := db.Exec(`INSERT INTO events VALUES(?,?,?)`, i, created, deleted); err != nil {
					t.Fatal(err)
				}
			}
			enforceRetentionAt(db, []RetentionPolicy{{Table: "events", TTL: 48 * time.Hour, Column: "created_at"}}, now)
			for i, c := range cases {
				var n int
				if err := db.QueryRow(`SELECT COUNT(*) FROM events WHERE id=?`, i).Scan(&n); err != nil {
					t.Fatal(err)
				}
				if (n == 0) != c.expired {
					t.Errorf("timestamp=%q deleted=%v want=%v", c.stamp, n == 0, c.expired)
				}
			}
		})
	}
}
