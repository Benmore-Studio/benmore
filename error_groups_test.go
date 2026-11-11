//go:build !cli

package main

import (
	"database/sql"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func errorGroupsFixture(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db")+"?_busy_timeout=5000")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if err := ensureErrorGroups(db); err != nil {
		t.Fatal(err)
	}
	return &App{Dir: dir, DB: db, Stop: make(chan struct{})}
}

func TestErrorGroupsPersistThrottleAndReopen(t *testing.T) {
	app := errorGroupsFixture(t)
	now := time.Date(2026, 10, 27, 12, 0, 0, 0, time.UTC)
	ev := errorEvent{Source: "server", Kind: "server", Level: "error", Type: "query", Message: "missing row 123", Route: "/api/items/:id", RequestID: "abc12345", UserID: 42}
	for i := 0; i < 100; i++ {
		forward, since, err := recordGroupAt(app, ev, now)
		if err != nil {
			t.Fatal(err)
		}
		if forward != (i == 0) {
			t.Fatalf("occurrence %d forwarded=%v", i, forward)
		}
		if i == 0 && since != 0 {
			t.Fatalf("first report has prior occurrences: %d", since)
		}
	}
	var count, unforwarded int
	var key string
	if err := app.DB.QueryRow("SELECT group_key,count,unforwarded FROM _benmore_error_groups").Scan(&key, &count, &unforwarded); err != nil {
		t.Fatal(err)
	}
	if count != 100 || unforwarded != 99 {
		t.Fatalf("count=%d unforwarded=%d", count, unforwarded)
	}
	if _, err := app.DB.Exec("UPDATE _benmore_error_groups SET resolved_at=CURRENT_TIMESTAMP WHERE group_key=?", key); err != nil {
		t.Fatal(err)
	}
	// A new app/reporter generation shares only the database, not throttle memory.
	reloaded := &App{Dir: app.Dir, DB: app.DB, Stop: make(chan struct{})}
	forward, since, err := recordGroupAt(reloaded, ev, now.Add(5*time.Minute+time.Second))
	if err != nil || !forward || since != 99 {
		t.Fatalf("after reload: forward=%v since=%d err=%v", forward, since, err)
	}
	var resolved sql.NullString
	if err := app.DB.QueryRow("SELECT count,unforwarded,resolved_at FROM _benmore_error_groups WHERE group_key=?", key).Scan(&count, &unforwarded, &resolved); err != nil {
		t.Fatal(err)
	}
	if count != 101 || unforwarded != 0 || resolved.Valid {
		t.Fatalf("reopened count=%d unforwarded=%d resolved=%v", count, unforwarded, resolved)
	}
}

func TestErrorGroupsConcurrentAppInstances(t *testing.T) {
	app := errorGroupsFixture(t)
	other := &App{Dir: app.Dir, DB: app.DB}
	now := time.Now()
	ev := errorEvent{Source: "server", Kind: "server", Level: "error", Type: "query", Message: "same failure"}
	var forwarded atomic.Int64
	var wg sync.WaitGroup
	for i := 0; i < 40; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			target := app
			if i%2 == 0 {
				target = other
			}
			forward, _, err := recordGroupAt(target, ev, now)
			if err != nil {
				t.Error(err)
				return
			}
			if forward {
				forwarded.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if forwarded.Load() != 1 {
		t.Fatalf("concurrent forwards: %d", forwarded.Load())
	}
	var count int
	if err := app.DB.QueryRow("SELECT count FROM _benmore_error_groups").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 40 {
		t.Fatalf("lost occurrences: %d", count)
	}
}

func TestErrorMessageNormalization(t *testing.T) {
	a := normalizeErrorMessage(`row 123 owner alice@example.com token deadbeef id 123e4567-e89b-12d3-a456-426614174000 value "first"`)
	b := normalizeErrorMessage(`row 456 owner bob@example.net token cafefeed id 223e4567-e89b-12d3-a456-426614174001 value "second"`)
	if a != b {
		t.Fatalf("same issue did not normalize:\n%s\n%s", a, b)
	}
	if normalizeErrorMessage("read failed") == normalizeErrorMessage("write failed") {
		t.Fatal("different errors collapsed")
	}
}
