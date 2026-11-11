//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

const scheduledBackupNameLayout = "20060102T150405Z"

func writeScheduledBackupName(t *testing.T, dir, name string) string {
	t.Helper()
	backupDir := filepath.Join(dir, backupDirName)
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(backupDir, name)
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func scheduledBackupAt(t *testing.T, dir string, taken time.Time) string {
	t.Helper()
	return writeScheduledBackupName(t, dir, scheduledBackupPrefix+taken.UTC().Format(scheduledBackupNameLayout)+".db")
}

// waitForScheduledBackup polls until a scheduled-* backup other than the
// excluded ones exists, calling tick between polls.
func waitForScheduledBackup(t *testing.T, dir string, within time.Duration, tick func(), exclude ...string) string {
	t.Helper()
	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		for _, path := range listScheduledBackups(dir) {
			fresh := true
			for _, old := range exclude {
				fresh = fresh && path != old
			}
			if fresh {
				return path
			}
		}
		if tick != nil {
			tick()
		}
		time.Sleep(50 * time.Millisecond)
	}
	return ""
}

// A restart used to start a fresh interval timer, so the schedule began again
// at every start. The newest scheduled backup on disk now anchors it: with that
// backup already an interval old, the restarted worker backs up at once.
func TestScheduledBackupDueAfterRestart(t *testing.T) {
	app, _ := newTestApp(t)
	t.Cleanup(app.Shutdown)
	mustExec(t, app.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT)`)
	old := scheduledBackupAt(t, app.Dir, time.Now().Add(-2*time.Hour))

	StartBackupWorker(app, &BackupConfig{Interval: time.Hour, Keep: 1})
	fresh := waitForScheduledBackup(t, app.Dir, 10*time.Second, nil, old)
	if fresh == "" {
		t.Fatal("restarted worker did not take the overdue backup; the schedule restarted with the worker")
	}
	app.Shutdown()
	// Keep still applies to the backup taken at start.
	if got := listScheduledBackups(app.Dir); len(got) != 1 || got[0] != fresh {
		t.Fatalf("keep 1 left %v", got)
	}
}

// The observed case: an app with no scheduled backup yet, pushed more often
// than its interval. Each push hot-reloads the app and restarts the worker,
// which used to restart the interval, so no backup was ever taken.
func TestScheduledBackupSurvivesHotReloads(t *testing.T) {
	app, _ := newTestApp(t)
	t.Cleanup(app.Shutdown)
	mustExec(t, app.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT)`)
	config := &BackupConfig{Interval: 1500 * time.Millisecond, Keep: 3}
	StartBackupWorker(app, config)

	reloads, last := 0, time.Now()
	reload := func() {
		if time.Since(last) < 300*time.Millisecond {
			return
		}
		// hotReloadApp's worker generation swap, then the restart buildAppMux does.
		app.mu.Lock()
		close(app.Stop)
		app.Stop = make(chan struct{})
		app.mu.Unlock()
		StartBackupWorker(app, config)
		reloads++
		last = time.Now()
	}
	if waitForScheduledBackup(t, app.Dir, 10*time.Second, reload) == "" {
		t.Fatalf("no scheduled backup across %d reloads, each sooner than the %s interval", reloads, config.Interval)
	}
	if reloads < 3 {
		t.Fatalf("only %d reloads before the backup; the fixture did not reload faster than the interval", reloads)
	}
}

func TestScheduledBackupDelay(t *testing.T) {
	now := time.Date(2026, 10, 29, 12, 0, 0, 0, time.UTC)
	interval := 10 * time.Minute
	cases := []struct {
		name  string
		since time.Time
		files []string
		want  time.Duration
	}{
		{name: "no backup: one interval after the first start", since: now, want: interval},
		{name: "no backup: reloads keep the first start", since: now.Add(-3 * time.Minute), want: 7 * time.Minute},
		{name: "no backup: overdue since the first start", since: now.Add(-time.Hour), want: 0},
		{
			name:  "newest backup anchors, not the start",
			since: now,
			files: []string{
				scheduledBackupPrefix + now.Add(-13*time.Minute).Format(scheduledBackupNameLayout) + ".db",
				scheduledBackupPrefix + now.Add(-3*time.Minute).Format(scheduledBackupNameLayout) + ".db",
			},
			want: 7 * time.Minute,
		},
		{
			name:  "overdue backup is due now",
			since: now,
			files: []string{scheduledBackupPrefix + now.Add(-25*time.Minute).Format(scheduledBackupNameLayout) + ".db"},
			want:  0,
		},
		{
			name:  "exactly one interval old is due now",
			since: now,
			files: []string{scheduledBackupPrefix + now.Add(-interval).Format(scheduledBackupNameLayout) + ".db"},
			want:  0,
		},
		{
			name:  "a future-dated backup is not an anchor",
			since: now,
			files: []string{
				scheduledBackupPrefix + now.Add(time.Hour).Format(scheduledBackupNameLayout) + ".db",
				scheduledBackupPrefix + now.Add(-4*time.Minute).Format(scheduledBackupNameLayout) + ".db",
			},
			want: 6 * time.Minute,
		},
		{
			name:  "other backups and unparsable names are ignored",
			since: now.Add(-2 * time.Minute),
			files: []string{
				backupPrefix + now.Add(-time.Minute).Format(scheduledBackupNameLayout) + ".db",
				scheduledBackupPrefix + "manual.db",
			},
			want: 8 * time.Minute,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, name := range tc.files {
				writeScheduledBackupName(t, dir, name)
			}
			if got := scheduledBackupDelay(dir, interval, tc.since, now); got != tc.want {
				t.Fatalf("delay = %s, want %s", got, tc.want)
			}
		})
	}
}

// Two worker generations can reach a due backup together (a reload does not
// wait for the old worker). The second must see the first one's backup and
// wait, not take another under the same timestamp name.
func TestScheduledBackupTakenOncePerInterval(t *testing.T) {
	app, _ := newTestApp(t)
	t.Cleanup(app.Shutdown)
	mustExec(t, app.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT)`)
	old := scheduledBackupAt(t, app.Dir, time.Now().Add(-2*time.Hour))
	config := &BackupConfig{Interval: time.Hour, Keep: 5}
	since := time.Now()

	if wait := runDueScheduledBackup(app, config, since); wait != config.Interval {
		t.Fatalf("after a backup wait = %s, want the interval", wait)
	}
	if wait := runDueScheduledBackup(app, config, since); wait <= 0 || wait > config.Interval {
		t.Fatalf("second generation wait = %s, want the rest of the interval", wait)
	}
	if got := listScheduledBackups(app.Dir); len(got) != 2 || got[0] != old {
		t.Fatalf("backups = %v, want the old one plus exactly one new", got)
	}

	// A failed attempt leaves no newer file; the worker still waits a full
	// interval rather than retrying in a loop.
	broken, _ := newTestApp(t)
	t.Cleanup(broken.Shutdown)
	mustExec(t, broken.DB, `CREATE TABLE notes (id INTEGER PRIMARY KEY)`)
	if err := os.MkdirAll(filepath.Join(broken.Dir, ".benmore"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(broken.Dir, backupDirName), []byte("not a directory"), 0600); err != nil {
		t.Fatal(err)
	}
	if wait := runDueScheduledBackup(broken, config, since.Add(-2*time.Hour)); wait != config.Interval {
		t.Fatalf("after a failed backup wait = %s, want the interval", wait)
	}
}
