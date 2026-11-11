//go:build !cli

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func openedIdentity(t *testing.T, dir string) dbFileIdentity {
	t.Helper()
	dev, ino, err := dbFileDevIno(filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	return dbFileIdentity{Dev: dev, Ino: ino}
}

// After a refused auto-recovery the unit restarts (Restart=always). Each
// later start must fail at once - no quick_check, no REINDEX on the file it
// promised to leave alone - so systemd's start limit can quarantine the unit;
// and anything that changes the situation lets the next start try again.
func TestRefusedRecoveryFailsFastUntilSomethingChanges(t *testing.T) {
	cases := []struct {
		name   string
		change func(t *testing.T, dir, old string)
	}{
		{"operator restores the old snapshot", func(t *testing.T, dir, old string) {
			if err := restoreDatabase(dir, old); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Lstat(recoveryRefusedPath(dir)); err == nil {
				t.Fatal("restore left the refusal record of the file it replaced")
			}
		}},
		{"operator raises the age limit", func(t *testing.T, dir, _ string) {
			t.Setenv(autoRestoreMaxAgeEnv, "72h")
		}},
		{"a newer snapshot appears", func(t *testing.T, dir, old string) {
			data, err := os.ReadFile(old)
			if err != nil {
				t.Fatal(err)
			}
			name := "pre-migrate-" + time.Now().UTC().Add(-time.Hour).Format("20060102T150405Z") + ".db"
			writeTestFile(t, dir, filepath.Join(backupDirName, name), string(data))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			c := countBootChecks(t)
			dir := populatedFixture(t, c)
			old := oldSnapshotOnly(t, dir)

			if _, err := startServedApp(dir); !errors.Is(err, errAutoRestoreRefused) {
				t.Fatalf("first start: %v, want refused", err)
			}
			if q, _ := c.take(); q != 1 {
				t.Fatalf("first start ran quick_check %d times, want 1", q)
			}
			if _, err := os.Lstat(recoveryRefusedPath(dir)); err != nil {
				t.Fatalf("the refusal was not recorded: %v", err)
			}
			before, _ := readDBFileIdentity(filepath.Join(dir, "data.db"))
			for i := 0; i < 3; i++ {
				start := time.Now()
				_, err := startServedApp(dir)
				if !errors.Is(err, errAutoRestoreRefused) || !strings.Contains(err.Error(), "unchanged since") {
					t.Fatalf("restart %d: %v, want the standing refusal", i, err)
				}
				if q, _ := c.take(); q != 0 {
					t.Fatalf("restart %d re-read the file (quick_check=%d)", i, q)
				}
				if d := time.Since(start); d > 2*time.Second {
					t.Fatalf("restart %d took %s; a standing refusal must fail at once", i, d)
				}
			}
			if after, _ := readDBFileIdentity(filepath.Join(dir, "data.db")); after != before {
				t.Fatal("a standing refusal touched the file it left in place")
			}

			tc.change(t, dir, old)
			app, err := startServedApp(dir)
			if err != nil {
				t.Fatalf("start after the change: %v", err)
			}
			app.Shutdown()
			if _, err := os.Lstat(recoveryRefusedPath(dir)); err == nil {
				t.Fatal("the refusal record outlived the change")
			}
		})
	}
}

// Any change to the refused file itself (an operator's repair) clears the
// refusal; the file is then checked like any other.
func TestRefusalClearsWhenTheFileChanges(t *testing.T) {
	c := countBootChecks(t)
	dir := populatedFixture(t, c)
	oldSnapshotOnly(t, dir)
	if _, err := startServedApp(dir); !errors.Is(err, errAutoRestoreRefused) {
		t.Fatalf("first start: %v, want refused", err)
	}
	// The operator replaces the file with a good copy by hand.
	good := bootFixture(t)
	bootServed(t, good).Shutdown()
	c.take()
	data, err := os.ReadFile(filepath.Join(good, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	os.Remove(filepath.Join(dir, "data.db"))
	if err := os.WriteFile(filepath.Join(dir, "data.db"), data, 0660); err != nil {
		t.Fatal(err)
	}
	app, err := startServedApp(dir)
	if err != nil {
		t.Fatalf("start after a hand repair: %v", err)
	}
	app.Shutdown()
	if q, _ := c.take(); q != 1 {
		t.Fatalf("the repaired file was not checked (quick_check=%d)", q)
	}
}

// A snapshot dated in the future has no trustworthy age.
func TestFutureDatedSnapshotIsNotRestoredUnattended(t *testing.T) {
	c := countBootChecks(t)
	dir := populatedFixture(t, c)
	old := oldSnapshotOnly(t, dir)
	future := filepath.Join(filepath.Dir(old), "pre-migrate-"+time.Now().UTC().Add(2*time.Hour).Format("20060102T150405Z")+".db")
	if err := os.Rename(old, future); err != nil {
		t.Fatal(err)
	}
	_, err := startServedApp(dir)
	if !errors.Is(err, errAutoRestoreRefused) || !strings.Contains(err.Error(), "in the future") {
		t.Fatalf("start with a future-dated snapshot: %v, want refused", err)
	}
	if matches, _ := corruptCopies(dir); len(matches) != 0 {
		t.Fatal("the original was moved aside")
	}
	// Within the clock-skew tolerance it is treated as current.
	if age := backupAge(filepath.Join(dir, "pre-migrate-"+time.Now().UTC().Add(time.Minute).Format("20060102T150405Z")+".db")); age < -autoRestoreClockSkew {
		t.Fatalf("a minute of skew counted as the future: %s", age)
	}
}

// A marker vouches only for the file this process opened. One swapped in under
// the running process was never checked by it.
func TestMarkerOnlyForTheFileThisProcessOpened(t *testing.T) {
	dir := bootFixture(t)
	c := countBootChecks(t)
	settle(t, dir, c)
	app := bootServed(t, dir)
	db := filepath.Join(dir, "data.db")
	data, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(db+".swap", data, 0660); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(db+".swap", db); err != nil {
		t.Fatal(err)
	}
	app.Shutdown()
	if _, err := os.Lstat(cleanShutdownMarkerPath(dir)); err == nil {
		t.Fatal("a marker vouched for a data.db swapped in under the running process")
	}
}
