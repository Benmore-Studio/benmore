//go:build !cli

package main

import (
	"fmt"
	"testing"
	"time"
)

func newStopGenerationImportApp(t *testing.T) *App {
	t.Helper()
	app, cleanup := newImportTestApp(t)
	EnsureAuditLogTable(app.DB)
	app.Stop = make(chan struct{})
	t.Cleanup(func() {
		app.mu.Lock()
		select {
		case <-app.Stop:
		default:
			close(app.Stop)
		}
		app.mu.Unlock()
		deadline := time.Now().Add(5 * time.Second)
		for importRunning(app) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if importRunning(app) {
			t.Error("import worker did not finish before DB cleanup")
		}
		cleanup()
	})
	return app
}

func TestImportLaunchSynchronizesStopPublication(t *testing.T) {
	app := newStopGenerationImportApp(t)
	old := app.Stop
	content := "sku,qty\nA,1\nB,2\n"
	id := "stoplock01"
	sess := &importSession{ID: id, TableName: "products", Format: "csv", BytesTotal: int64(len(content)), SHA256: stageString(t, app, id, content)}
	insertSession(t, app, sess)
	entered, returned := make(chan struct{}), make(chan error, 1)
	app.mu.Lock()
	go func() {
		close(entered)
		returned <- startImport(app, sess)
	}()
	<-entered
	var early bool
	select {
	case err := <-returned:
		early = true
		if err != nil {
			t.Errorf("startImport: %v", err)
		}
		t.Error("import launch bypassed locked stop publication")
	case <-time.After(25 * time.Millisecond):
	}
	close(old)
	fresh := make(chan struct{})
	app.Stop = fresh
	app.mu.Unlock()
	if !early {
		select {
		case err := <-returned:
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("import launch did not resume after publication unlocked")
		}
	}
	defer func() {
		close(fresh)
		deadline := time.Now().Add(5 * time.Second)
		for importRunning(app) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if importRunning(app) {
			t.Error("import worker did not finish before DB cleanup")
		}
	}()
	if sess.stop != fresh {
		t.Error("import did not capture the published generation")
	}
	deadline := time.Now().Add(5 * time.Second)
	for importRunning(app) && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if importRunning(app) {
		t.Fatal("import did not terminate")
	}
	state, err := loadImportSession(app.DB, id)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if state.State != "completed" || state.RowsLoaded != 2 || count != 2 {
		t.Errorf("live generation import state=%s rows=%d committed=%d; wantcompleted/2/2", state.State, state.RowsLoaded, count)
	}
}

// Reload may legitimately interrupt an already-running import; the outcome
// must remain atomic. This control isolates the unsynchronized Stop read from
// that allowed cancellation by checking the actual concurrent launch under -race.
func TestImportLaunchConcurrentStopPublication(t *testing.T) {
	app := newStopGenerationImportApp(t)
	for i := 0; i < 4; i++ {
		id := fmt.Sprintf("stoprace%02d", i)
		content := "sku,qty\n" + id + ",1\n"
		sess := &importSession{ID: id, TableName: "products", Format: "csv", BytesTotal: int64(len(content)), SHA256: stageString(t, app, id, content)}
		insertSession(t, app, sess)
		ready, finished := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(finished)
			close(ready)
			for j := 0; j < 8; j++ {
				app.mu.Lock()
				close(app.Stop)
				app.Stop = make(chan struct{})
				app.mu.Unlock()
				time.Sleep(time.Millisecond)
			}
		}()
		<-ready
		launchErr := startImport(app, sess)
		<-finished
		if launchErr != nil {
			t.Fatal(launchErr)
		}
		deadline := time.Now().Add(5 * time.Second)
		for importRunning(app) && time.Now().Before(deadline) {
			time.Sleep(time.Millisecond)
		}
		if importRunning(app) {
			t.Fatal("import worker did not finish")
		}
		state, err := loadImportSession(app.DB, id)
		if err != nil {
			t.Fatal(err)
		}
		if !((state.State == "completed" && state.RowsLoaded == 1) || (state.State == "failed" && state.RowsLoaded == 0)) {
			t.Fatalf("unexpected terminal result %s/%d", state.State, state.RowsLoaded)
		}
		var count int64
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM products WHERE sku=?", id).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if count != state.RowsLoaded {
			t.Fatalf("terminal %s reports %d rows but committed %d", state.State, state.RowsLoaded, count)
		}
	}
}
