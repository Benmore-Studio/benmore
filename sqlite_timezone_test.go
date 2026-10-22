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

func openTodayTestDB(t *testing.T, now time.Time) *sql.DB {
	t.Helper()
	name := fmt.Sprintf("sqlite3_benmore_today_%d", time.Now().UnixNano())
	sql.Register(name, &sqlite3.SQLiteDriver{ConnectHook: func(conn *sqlite3.SQLiteConn) error {
		return registerBenmoreToday(conn, func() time.Time { return now })
	}})
	db, err := sql.Open(name, filepath.Join(t.TempDir(), "today.db"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func todayAt(t *testing.T, db *sql.DB, zone string) (string, error) {
	t.Helper()
	var date string
	err := db.QueryRow("SELECT benmore_today(?)", zone).Scan(&date)
	return date, err
}

func TestBenmoreTodayRegisteredOnFrameworkSQLiteDriver(t *testing.T) {
	db, err := sql.Open("sqlite3_benmore", filepath.Join(t.TempDir(), "today.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	location, err := time.LoadLocation("America/New_York")
	if err != nil {
		t.Fatal(err)
	}
	want := time.Now().In(location).Format("2006-01-02")
	got, err := todayAt(t, db, "America/New_York")
	if err != nil {
		t.Fatalf("benmore_today not registered on framework driver: %v", err)
	}
	if got != want {
		t.Fatalf("benmore_today(New_York) = %s, want %s", got, want)
	}
}

func TestBenmoreTodayUsesIANAZoneAcrossUTCAndDSTBoundaries(t *testing.T) {
	tests := []struct {
		name, instant, want string
	}{
		{"UTC midnight is still prior New York day", "2026-10-15T03:59:00Z", "2026-10-14"},
		{"New York local midnight", "2026-10-15T04:00:00Z", "2026-10-15"},
		{"spring DST local midnight before", "2026-03-08T04:59:00Z", "2026-03-07"},
		{"spring DST local midnight after", "2026-03-08T05:00:00Z", "2026-03-08"},
		{"spring DST day after before local midnight", "2026-03-09T03:59:00Z", "2026-03-08"},
		{"spring DST day after local midnight", "2026-03-09T04:00:00Z", "2026-03-09"},
		{"fall DST local midnight before", "2026-11-01T03:59:00Z", "2026-10-31"},
		{"fall DST local midnight after", "2026-11-01T04:00:00Z", "2026-11-01"},
		{"fall DST day after before local midnight", "2026-11-02T04:59:00Z", "2026-11-01"},
		{"fall DST day after local midnight", "2026-11-02T05:00:00Z", "2026-11-02"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			instant, err := time.Parse(time.RFC3339, tc.instant)
			if err != nil {
				t.Fatal(err)
			}
			db := openTodayTestDB(t, instant)
			got, err := todayAt(t, db, "America/New_York")
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Fatalf("benmore_today at %s = %s, want %s", tc.instant, got, tc.want)
			}
		})
	}
}

func TestBenmoreTodayRejectsMissingAndInvalidZones(t *testing.T) {
	db := openTodayTestDB(t, time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC))
	for _, zone := range []string{"", "   ", "Local", "Mars/Olympus_Mons"} {
		t.Run(fmt.Sprintf("%q", zone), func(t *testing.T) {
			if _, err := todayAt(t, db, zone); err == nil {
				t.Fatalf("benmore_today(%q) unexpectedly succeeded", zone)
			}
		})
	}
}

func TestBenmoreTodayRejectsNullZone(t *testing.T) {
	db := openTodayTestDB(t, time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC))
	var date string
	if err := db.QueryRow("SELECT benmore_today(NULL)").Scan(&date); err == nil {
		t.Fatal("benmore_today(NULL) unexpectedly succeeded")
	}
}
