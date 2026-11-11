//go:build !cli

package main

// A refused auto-recovery stays refused without re-reading the file.
//
// When the open finds the database corrupt and only an old snapshot to restore
// (migrate.go, autoRestoreMaxAge), it leaves the file in place and fails the
// start. The unit restarts it (Restart=always, RestartSec=2), and systemd
// quarantines a unit only after 5 starts in 300s. A large database spends most
// of a minute in each quick_check, so the starts never come fast enough: the
// unit would restart forever, reading the whole file twice and re-running
// REINDEX (which can commit) on every attempt, on the file it promised to leave
// alone.
//
// So the refusal writes .benmore/db-recovery-refused.json, bound to the file's
// stat identity (device, inode, size, mtime, ctime), the auto-restore age limit
// in force and the newest snapshot on disk. A later start whose file, limit and
// newest snapshot all still match fails at once with the same message, before
// SQLite opens the file: no quick_check, no REINDEX, and the unit reaches its
// start limit within seconds. Anything that changes the situation clears it: a
// restore (benmore restore, PITR and refresh-dev delete it with the other state
// records), any change to the file, a new snapshot, or an operator raising
// BENMORE_AUTO_RESTORE_MAX_AGE.

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	recoveryRefusedName    = "db-recovery-refused.json"
	recoveryRefusedVersion = 1
)

type recoveryRefusal struct {
	Version   int            `json:"version"`
	File      dbFileIdentity `json:"file"`
	MaxAge    string         `json:"max_age"`
	Newest    string         `json:"newest_snapshot"`
	Message   string         `json:"message"`
	RefusedAt time.Time      `json:"refused_at"`
}

func recoveryRefusedPath(dir string) string {
	return filepath.Join(dir, ".benmore", recoveryRefusedName)
}

func newestAutoRestoreCandidate(dir string) string {
	if candidates := autoRestoreCandidates(dir); len(candidates) > 0 {
		return filepath.Base(candidates[0])
	}
	return ""
}

// recordRecoveryRefusal notes a refused auto-recovery for the file as it is
// now. Best effort: without it the next start checks the file again.
func recordRecoveryRefusal(dir string, refusal error) {
	if foreignAppDirs.Load() {
		return
	}
	ident, err := readDBFileIdentity(filepath.Join(dir, "data.db"))
	if err == nil {
		var data []byte
		data, err = json.Marshal(recoveryRefusal{
			Version:   recoveryRefusedVersion,
			File:      ident,
			MaxAge:    autoRestoreMaxAge().String(),
			Newest:    newestAutoRestoreCandidate(dir),
			Message:   refusal.Error(),
			RefusedAt: time.Now().UTC(),
		})
		if err == nil {
			err = writeStateFile(dir, recoveryRefusedName, data)
		}
	}
	if err != nil {
		log.Printf("auto-restore: refusal not recorded (%v); the next start checks the database again", err)
	}
}

// standingRecoveryRefusal returns the recorded refusal when nothing has
// changed since it was made, and clears a record that no longer applies. It
// runs before SQLite opens the file.
func standingRecoveryRefusal(dir string) error {
	path := recoveryRefusedPath(dir)
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	var refusal recoveryRefusal
	stillApplies := err == nil && json.Unmarshal(data, &refusal) == nil && refusal.Version == recoveryRefusedVersion
	if stillApplies {
		ident, identErr := readDBFileIdentity(filepath.Join(dir, "data.db"))
		stillApplies = identErr == nil && ident == refusal.File &&
			refusal.MaxAge == autoRestoreMaxAge().String() &&
			refusal.Newest == newestAutoRestoreCandidate(dir)
	}
	if !stillApplies {
		if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			log.Printf("auto-restore: could not clear a stale refusal record: %v", err)
		} else {
			log.Printf("auto-restore: the database, its snapshots or the age limit changed since the last refusal; checking it again")
		}
		return nil
	}
	log.Printf("DB AUTO-RECOVERY REFUSED (unchanged since %s): %s", refusal.RefusedAt.Format(time.RFC3339), refusal.Message)
	return fmt.Errorf("%w (unchanged since %s; restore with benmore restore or PITR, or raise %s): %s",
		errAutoRestoreRefused, refusal.RefusedAt.Format(time.RFC3339), autoRestoreMaxAgeEnv, refusal.Message)
}
