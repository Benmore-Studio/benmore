//go:build !cli

package main

import (
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestBootTimingLargeDatabase measures served-app boots on a large synthetic
// database. It is opt-in (it writes BENMORE_BOOT_BENCH_MB megabytes):
//
//	BENMORE_BOOT_BENCH_MB=300 go test -tags sqlite_fts5 -run TestBootTimingLargeDatabase -v .
//
// It uses only loadAppWithOptions and App.Shutdown, so the same file measures
// an older tree. A restart after a clean shutdown should not read the file:
// no quick_check, no pre-migrate snapshot, no integrity_check.
func TestBootTimingLargeDatabase(t *testing.T) {
	mb, _ := strconv.Atoi(os.Getenv("BENMORE_BOOT_BENCH_MB"))
	if mb <= 0 {
		t.Skip("set BENMORE_BOOT_BENCH_MB to measure boots on a large synthetic database")
	}
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "bigapp")
	writeTestFile(t, dir, "app.yaml", "site_name: bigapp\n")
	writeTestFile(t, dir, "schema.prisma", "model Event {\n  id Int @id @default(autoincrement())\n  kind String\n  body String\n  @@index([kind])\n}\n")
	boot := func() time.Duration {
		t.Helper()
		start := time.Now()
		app, err := loadAppWithOptions(dir, appLoadOptions{startup: true})
		if err != nil {
			t.Fatal(err)
		}
		elapsed := time.Since(start)
		app.Shutdown()
		return elapsed
	}
	boot() // creates the schema

	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Repeat("x", 1000)
	kinds := []string{"view", "click", "signup", "purchase", "refund"}
	for size := int64(0); size < int64(mb)<<20; {
		tx, err := db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		stmt, err := tx.Prepare("INSERT INTO events (kind, body) VALUES (?, ?)")
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 20000; i++ {
			if _, err := stmt.Exec(kinds[i%len(kinds)], body+strconv.Itoa(i)); err != nil {
				t.Fatal(err)
			}
		}
		stmt.Close()
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec("PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(dir, "data.db"))
		if err != nil {
			t.Fatal(err)
		}
		size = info.Size()
	}
	db.Close()
	info, _ := os.Stat(filepath.Join(dir, "data.db"))
	t.Logf("database: %.0f MB", float64(info.Size())/(1<<20))

	backupBytes := func() (n int, total int64) {
		entries, _ := os.ReadDir(filepath.Join(dir, ".benmore", "backups"))
		for _, e := range entries {
			if i, err := e.Info(); err == nil && strings.HasSuffix(e.Name(), ".db") {
				n++
				total += i.Size()
			}
		}
		return n, total
	}
	// The fill was written by another process: the first boot cannot prove a
	// clean shutdown, as after a crash or the first boot of a new runtime.
	for i, label := range []string{"boot after outside writes", "clean restart 1", "clean restart 2", "clean restart 3"} {
		d := boot()
		n, total := backupBytes()
		t.Logf("%d %-26s %8s   pre-migrate snapshots on disk: %d (%.0f MB)", i, label, d.Round(time.Millisecond), n, float64(total)/(1<<20))
	}
}
