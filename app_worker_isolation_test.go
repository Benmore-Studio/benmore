//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

// Exercise public app routes, so a process-global buffer cannot pass by using
// a test-only logging path. Both apps deliberately use user ID 1.
func TestAppAuditAndUsageStayWithOriginatingApp(t *testing.T) {
	fixture := func(email string) (*App, *http.ServeMux, string) {
		app, _ := newTestApp(t)
		app.Stop = make(chan struct{})
		app.Paths = DiscoverAuthPaths(nil)
		t.Cleanup(app.Shutdown)
		app.Design = &DesignConfig{Auth: map[string]string{"read_audit": "*"}}
		app.Tables = []Table{{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true}, {Name: "title", Type: "TEXT"}}}}
		mustExec(t, app.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT)`)
		mustExec(t, app.DB, `INSERT INTO notes VALUES (1, 'fixture')`)
		token := createCrudScopeSession(t, app, email, "admin", "", "")
		return app, buildAppMux(app, true, "https://fixture.example.com"), token
	}
	appA, muxA, tokenA := fixture("owner-a@example.com")
	appB, muxB, tokenB := fixture("owner-b@example.com")
	if w := crudScopeRequest(t, muxA, "GET", "/api/notes/1", tokenA, nil); w.Code != 200 {
		t.Fatalf("read fixture: %d %s", w.Code, w.Body)
	}
	for _, tc := range []struct {
		app   *App
		mux   *http.ServeMux
		token string
		want  int
	}{{appA, muxA, tokenA, 1}, {appB, muxB, tokenB, 0}} {
		w := crudScopeRequest(t, tc.mux, "GET", "/api/_audit/reads", tc.token, nil)
		var entries []map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &entries); err != nil || w.Code != 200 || len(entries) != tc.want {
			t.Errorf("read audit crossed app boundary: want=%d status=%d body=%s err=%v", tc.want, w.Code, w.Body, err)
		}
		w = crudScopeRequest(t, tc.mux, "GET", "/api/_usage", tc.token, nil)
		if w.Code != 200 {
			t.Fatalf("usage response: %d %s", w.Code, w.Body)
		}
		var count int
		if err := tc.app.DB.QueryRow(`SELECT COALESCE(SUM(count),0) FROM _benmore_usage WHERE metric='api_requests'`).Scan(&count); err != nil || count != tc.want {
			t.Errorf("usage crossed app boundary: count=%d want=%d err=%v", count, tc.want, err)
		}
	}
}

func TestAppShutdownDrainsTrackedWorkBeforeClosingDatabase(t *testing.T) {
	app, _ := newTestApp(t)
	mustExec(t, app.DB, `CREATE TABLE final_write (value INTEGER)`)
	started, release := make(chan struct{}), make(chan struct{})
	written := make(chan error, 1)
	app.startWorker("fixture.final-write", func(stop <-chan struct{}) {
		close(started)
		<-stop
		<-release
		_, err := app.DB.Exec(`INSERT INTO final_write VALUES (1)`)
		written <- err
	})
	<-started
	done := make(chan struct{})
	go func() { app.Shutdown(); close(done) }()
	<-app.Stop
	if err := app.DB.Ping(); err != nil {
		close(release)
		t.Fatalf("database closed before tracked work drained: %v", err)
	}
	close(release)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not wait/finish")
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	app.Shutdown() // idempotent
	<-app.startWorker("fixture.after-shutdown", func(<-chan struct{}) { t.Error("started work after shutdown") })
}

func TestAppBufferReloadAndShutdownPreservePendingEntries(t *testing.T) {
	app, _ := newTestApp(t)
	InitReadAudit(app, false)
	InitMetering(app)
	session := &Session{UserID: 1, Email: "fixture@example.com"}
	LogReadAccess(app, "notes", "1", "read", session)
	Increment(app, "user:1", "reads")
	// Simulate the worker generation transition used by hotReloadApp. The
	// old flush workers must retain their own stop channel and pending buffer.
	app.mu.Lock()
	close(app.Stop)
	app.Stop = make(chan struct{})
	app.mu.Unlock()
	InitReadAudit(app, true)
	InitMetering(app)
	LogReadAccess(app, "notes", "2", "read", session)
	Increment(app, "user:1", "reads")
	app.Shutdown()
	db, err := OpenDB(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var entries, count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM _benmore_read_audit`).Scan(&entries); err != nil || entries != 2 {
		t.Fatalf("audit entries lost across reload/shutdown: %d %v", entries, err)
	}
	if err := db.QueryRow(`SELECT SUM(count) FROM _benmore_usage`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("usage lost across reload/shutdown: %d %v", count, err)
	}
}

func TestScheduledBackupStopsWithApp(t *testing.T) {
	app, _ := newTestApp(t)
	StartBackupWorker(app, &BackupConfig{Interval: time.Hour, Keep: 2})
	done := make(chan struct{})
	go func() { app.Shutdown(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("scheduled backup worker ignored shutdown")
	}
	if err := app.DB.Ping(); err == nil || !strings.Contains(err.Error(), "closed") {
		t.Fatalf("database not closed after worker exit: %v", err)
	}
}
