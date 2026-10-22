//go:build !cli

package main

import (
	"testing"
	"time"
)

func TestAppWorkersStopOnReloadAndAreTracked(t *testing.T) {
	tests := []struct {
		name   string
		setup  func(*testing.T, *App)
		start  func(*App)
		verify func(*testing.T, *App)
	}{
		{
			name: "retention",
			setup: func(t *testing.T, app *App) {
				mustExec(t, app.DB, `ALTER TABLE notes ADD COLUMN created_at DATETIME`)
				mustExec(t, app.DB, `INSERT INTO notes(user_id, title, created_at) VALUES (1, 'oldnote', '2000-01-01T00:00:00Z')`)
			},
			start: func(app *App) {
				StartRetentionWorker(app, []RetentionPolicy{{Table: "notes", Column: "created_at", TTL: time.Hour}})
			},
			verify: func(t *testing.T, app *App) {
				var count int
				if err := app.DB.QueryRow(`SELECT COUNT(*) FROM notes WHERE title = 'oldnote'`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 1 {
					t.Fatalf("retention changed oldnote after stop: count=%d", count)
				}
			},
		},
		{
			name:  "scheduler",
			start: StartSchedulerSweeper,
			verify: func(t *testing.T, app *App) {
				var count int
				if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_scheduled_tasks`).Scan(&count); err != nil {
					t.Fatal(err)
				}
				if count != 0 {
					t.Fatalf("scheduler changed empty task set after stop: count=%d", count)
				}
			},
		},
		{
			name: "aggregate",
			start: func(app *App) {
				StartAggregateWorker(app, []AggregateConfig{{Name: "approved", SQL: `SELECT 'approved'`, Refresh: time.Hour}})
			},
			verify: func(t *testing.T, app *App) {
				var value string
				if err := app.DB.QueryRow(`SELECT value FROM _benmore_aggregates WHERE name = 'approved'`).Scan(&value); err != nil {
					t.Fatal(err)
				}
				if value != "approved" {
					t.Fatalf("aggregate value after stop = %q, want approved", value)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			app, _ := auditApp(t)
			// Drain the canonical fixture's scheduler so a sibling worker cannot
			// make an untracked worker under test look tracked.
			app.mu.Lock()
			close(app.Stop)
			app.mu.Unlock()
			app.workerWG.Wait()
			app.jobWG.Wait()
			app.mu.Lock()
			app.Stop = make(chan struct{})
			app.mu.Unlock()
			if tt.setup != nil {
				tt.setup(t, app)
			}
			originalStop := app.Stop
			tt.start(app)

			waited := make(chan struct{})
			go func() {
				app.workerWG.Wait()
				// The scheduler runs app flows, so it is tracked with the job
				// runners (bounded shutdown drain), not the plain workers.
				app.jobWG.Wait()
				close(waited)
			}()
			select {
			case <-waited:
				t.Fatal("worker was not tracked while its stop channel remained open")
			case <-time.After(50 * time.Millisecond):
			}

			freshStop := make(chan struct{})
			app.mu.Lock()
			close(originalStop)
			app.Stop = freshStop
			app.mu.Unlock()
			select {
			case <-waited:
			case <-time.After(time.Second):
				t.Fatal("worker did not stop after its captured stop channel closed")
			}

			tt.verify(t, app)
			app.Shutdown()
		})
	}
}
