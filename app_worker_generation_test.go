//go:build !cli

package main

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"runtime/pprof"
	"strings"
	"testing"
	"time"
)

// Labels distinguish these actual workers from unrelated fixture/background
// goroutines. They are inherited at spawn and disappear when the worker exits.
func generationWorkerAlive(t *testing.T, label string) bool {
	t.Helper()
	var profile bytes.Buffer
	if err := pprof.Lookup("goroutine").WriteTo(&profile, 1); err != nil {
		t.Fatal(err)
	}
	return strings.Contains(profile.String(), fmt.Sprintf("%q:%q", "worker-generation", label))
}

func waitGenerationWorker(t *testing.T, label string, alive bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for generationWorkerAlive(t, label) != alive {
		if time.Now().After(deadline) {
			t.Fatalf("worker %s alive=%v, want %v", label, !alive, alive)
		}
		time.Sleep(time.Millisecond)
	}
}

func TestAppMaintenanceWorkersBindBeforeSpawn(t *testing.T) {
	// A literal public IP avoids DNS; the day-long interval means this fixture
	// never ships a request. No production guard or transport is replaced.
	t.Setenv("BENMORE_AUDIT_WEBHOOK_URL", "https://8.8.8.8/unused-fixture")
	t.Setenv("BENMORE_AUDIT_WEBHOOK_SECRET", strings.Repeat("fixture", 8))
	t.Setenv("BENMORE_AUDIT_WEBHOOK_INTERVAL", "24h")
	workers := []struct {
		name  string
		start func(*App)
	}{
		{"presence", StartPresenceSweeper},
		{"wal", StartAppWALMaintenance},
		{"sessions", CleanExpiredSessions},
		{"roles", StartRoleExpirySweeper},
		{"locks", StartLockCleanupWorker},
		{"audit", StartAuditShipper},
		{"cron", StartCronScheduler},
	}
	for _, worker := range workers {
		t.Run(worker.name, func(t *testing.T) {
			app, cleanup := newTestApp(t)
			defer cleanup()
			if err := app.DB.Ping(); err != nil {
				t.Fatal(err)
			}
			app.Stop = make(chan struct{})
			var labels []string
			defer func() {
				app.mu.Lock()
				select {
				case <-app.Stop:
				default:
					close(app.Stop)
				}
				app.mu.Unlock()
				for _, label := range labels {
					waitGenerationWorker(t, label, false)
				}
			}()
			if worker.name == "cron" {
				app.Cron = &CronConfig{Jobs: []CronJob{{ID: "generation", Schedule: "every 24h"}}}
				if err := ensureCronStateTable(app); err != nil {
					t.Fatal(err)
				}
				if _, err := app.DB.Exec("INSERT INTO _benmore_cron_state(job_id,last_fire) VALUES (?,?)", "generation", time.Now().UTC().Format(time.RFC3339)); err != nil {
					t.Fatal(err)
				}
			}
			// Publication and startup must synchronize. Unlike a scheduler-only
			// stress loop, this also detects an unlocked pre-spawn field read.
			app.mu.Lock()
			entered, returned := make(chan struct{}), make(chan struct{})
			label := t.Name() + "/locked"
			labels = append(labels, label)
			go func() {
				close(entered)
				pprof.Do(context.Background(), pprof.Labels("worker-generation", label), func(context.Context) { worker.start(app) })
				close(returned)
			}()
			<-entered
			select {
			case <-returned:
				t.Error("worker startup returned while stop-generation publication was locked")
			case <-time.After(25 * time.Millisecond):
			}
			app.mu.Unlock()
			select {
			case <-returned:
			case <-time.After(5 * time.Second):
				t.Fatal("worker startup remained blocked after publication unlocked")
			}
			waitGenerationWorker(t, label, true)
			app.mu.Lock()
			close(app.Stop)
			app.Stop = make(chan struct{})
			app.mu.Unlock()
			waitGenerationWorker(t, label, false)

			// Bias the actual worker toward delayed execution, then retire the
			// generation immediately after startup returns. Repetition is a
			// scheduling stress control, not a claim of deterministic scheduling.
			for i := 0; i < 8; i++ {
				label = fmt.Sprintf("%s/delayed-%d", t.Name(), i)
				labels = append(labels, label)
				previous := runtime.GOMAXPROCS(1)
				pprof.Do(context.Background(), pprof.Labels("worker-generation", label), func(context.Context) { worker.start(app) })
				app.mu.Lock()
				close(app.Stop)
				fresh := make(chan struct{})
				app.Stop = fresh
				app.mu.Unlock()
				runtime.GOMAXPROCS(previous)
				// Even on failure, close the fresh generation before DB cleanup.
				func() {
					defer func() {
						app.mu.Lock()
						close(fresh)
						app.Stop = make(chan struct{})
						app.mu.Unlock()
					}()
					waitGenerationWorker(t, label, false)
				}()
			}
		})
	}
}
