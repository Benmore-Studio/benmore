//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

func TestVersionHistoryClockMaterializesStartOnceAndChainsBackwardClock(t *testing.T) {
	base := time.Date(2026, 10, 16, 12, 0, 0, 123456789, time.UTC)
	calls := 0
	name := fmt.Sprintf("sqlite3_benmore_versionclock_%d", time.Now().UnixNano())
	sql.Register(name, &sqlite3.SQLiteDriver{ConnectHook: func(conn *sqlite3.SQLiteConn) error {
		return registerVersionHistoryClock(conn, func() time.Time {
			instant := base.Add(-time.Duration(calls) * time.Second)
			calls++
			return instant
		})
	}})
	db, err := sql.Open(name, filepath.Join(t.TempDir(), "clock.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	mustExec(t, db, `CREATE TABLE clock_records(id INTEGER PRIMARY KEY, title TEXT)`)
	if err := InstallVersioningTriggers(db, &VersionedConfig{Tables: []string{"clock_records"}}); err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, `INSERT INTO clock_records(id,title) VALUES(1,'first')`)
	mustExec(t, db, `UPDATE clock_records SET title='second' WHERE id=1`)
	if calls != 2 {
		t.Fatalf("first timestamp-less history must capture start once and end once, got %d clock reads", calls)
	}
	mustExec(t, db, `UPDATE clock_records SET title='third' WHERE id=1`)
	mustExec(t, db, `DELETE FROM clock_records WHERE id=1`)
	if calls != 4 {
		t.Fatalf("later writes must reuse retained start and sample only end, got %d clock reads", calls)
	}
	rows, err := db.Query(`SELECT CAST(_valid_from AS TEXT),CAST(_valid_to AS TEXT),title,_change_type FROM clock_records_history ORDER BY _version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	index := 0
	for rows.Next() {
		var rawStart, rawEnd, title, change string
		if err := rows.Scan(&rawStart, &rawEnd, &title, &change); err != nil {
			t.Fatal(err)
		}
		start, startOK := parseUpdateTimestamp(rawStart)
		end, endOK := parseUpdateTimestamp(rawEnd)
		if !startOK || !endOK || !start.Equal(base.Add(time.Duration(index)*time.Nanosecond)) || !end.Equal(base.Add(time.Duration(index+1)*time.Nanosecond)) {
			t.Fatalf("backward clock lost contiguous nanosecond boundary at version %d: %q -> %q", index+1, rawStart, rawEnd)
		}
		wantTitle := []string{"first", "second", "third"}
		wantChange := []string{"update", "update", "delete"}
		if index >= len(wantTitle) || title != wantTitle[index] || change != wantChange[index] {
			t.Fatalf("unexpected snapshot version %d: title=%q change=%q", index+1, title, change)
		}
		index++
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if index != 3 {
		t.Fatalf("got %d history snapshots, want 3", index)
	}
}
