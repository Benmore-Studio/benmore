//go:build !cli

package main

// When the loader runs the post-migration PRAGMA integrity_check.
//
// The check reads every page and cross-checks every index against its table
// (32.9s for a 778 MB app), so it runs only when the schema changed. It runs
// once per load, after the load's last schema-writing step (a column added to
// a table also reaches its versioning history table and full-text index after
// Migrate). A failure runs REINDEX and checks again (index damage rebuilds
// from the tables with no loss), then restores the load's first pre-migrate
// snapshot. It is due when:
//
//   - the load's schema step changed the schema (the schema cookie moved), or
//   - for the app's own boot: the open could not verify the file (a degraded
//     reopen, a backup recovery swapped in), or any table, index or migration
//     changed since the last check that passed on this file, whoever changed
//     it (this load's user migrations or framework steps, a hot reload, a
//     validation load, an operator's DDL), or that check is
//     older than the clean-shutdown marker's re-check bound (7-10 days).
//     .benmore/db-integrity.json records the schema fingerprint and the file
//     (device, inode) of that last check; every path that swaps in another
//     data.db deletes it (forgetDatabaseStateFiles).
//
// A validation load (checkOnly) checks only when it added columns itself, as
// before, and leaves everything else to the app's own boot.
//
// The fingerprint is the definition of every object that owns a b-tree, which
// is what integrity_check verifies: tables (full-text shadow tables included)
// and indexes, without rootpages, plus the migration ledger, so a data-only
// migration counts as a change too. Triggers and views own no pages, and
// framework steps drop and reinstall them on every boot. A missing, unreadable
// or foreign record means "changed".

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

const (
	integrityLedgerName    = "db-integrity.json"
	integrityLedgerVersion = 1
)

type integrityLedger struct {
	Version     int       `json:"version"`
	Dev         uint64    `json:"dev"`
	Ino         uint64    `json:"ino"`
	Fingerprint string    `json:"schema_fingerprint"`
	CheckedAt   time.Time `json:"checked_at"`
}

func integrityLedgerPath(dir string) string {
	return filepath.Join(dir, ".benmore", integrityLedgerName)
}

// schemaFingerprint hashes the table and index definitions and the migration
// ledger. It reads only sqlite_schema and _benmore_migrations.
func schemaFingerprint(db *sql.DB) (string, error) {
	h := sha256.New()
	rows, err := db.Query(`SELECT type, name, tbl_name, COALESCE(sql, '') FROM main.sqlite_schema
		WHERE type IN ('table', 'index') AND name NOT LIKE 'sqlite\_%' ESCAPE '\' ORDER BY type, name`)
	if err != nil {
		return "", err
	}
	for rows.Next() {
		var kind, name, table, def string
		if err := rows.Scan(&kind, &name, &table, &def); err != nil {
			rows.Close()
			return "", err
		}
		fmt.Fprintf(h, "%q %q %q %q\n", kind, name, table, def)
	}
	if err := rows.Close(); err != nil {
		return "", err
	}
	if exists, err := tableExists(db, "_benmore_migrations"); err != nil {
		return "", err
	} else if exists {
		rows, err := db.Query(`SELECT name FROM _benmore_migrations ORDER BY name`)
		if err != nil {
			return "", err
		}
		h.Write([]byte("migrations\n"))
		for rows.Next() {
			var name sql.NullString
			if err := rows.Scan(&name); err != nil {
				rows.Close()
				return "", err
			}
			fmt.Fprintf(h, "%q\n", name.String)
		}
		if err := rows.Close(); err != nil {
			return "", err
		}
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// dbFileDevIno identifies data.db without following a link.
func dbFileDevIno(dbPath string) (dev, ino uint64, err error) {
	info, err := os.Lstat(dbPath)
	if err != nil {
		return 0, 0, err
	}
	if !info.Mode().IsRegular() {
		return 0, 0, errors.New("data.db is not a regular file")
	}
	_, ino, dev, ok := fileStampSys(info)
	if !ok {
		return 0, 0, errors.New("file identity is not available on this platform")
	}
	return dev, ino, nil
}

// integrityCheckedSinceChange reports whether the last passing integrity_check
// on this file saw the schema it has now, or why not.
func integrityCheckedSinceChange(dir string, db *sql.DB) (bool, string) {
	data, err := os.ReadFile(integrityLedgerPath(dir))
	if err != nil {
		return false, "no record of a passing integrity_check"
	}
	var ledger integrityLedger
	if json.Unmarshal(data, &ledger) != nil || ledger.Version != integrityLedgerVersion {
		return false, "integrity record malformed"
	}
	dev, ino, err := dbFileDevIno(filepath.Join(dir, "data.db"))
	if err != nil {
		return false, "database identity unavailable: " + err.Error()
	}
	if dev != ledger.Dev || ino != ledger.Ino {
		return false, "the database file was replaced since its last integrity_check"
	}
	fingerprint, err := schemaFingerprint(db)
	if err != nil {
		return false, "schema fingerprint unavailable: " + err.Error()
	}
	if fingerprint != ledger.Fingerprint {
		return false, "the schema changed since the last integrity_check"
	}
	// The same bound as the clean-shutdown marker: a file whose schema never
	// changes is still checked in full every 7-10 days.
	if ledger.CheckedAt.IsZero() || !time.Now().Before(cleanShutdownCheckDue(ledger.CheckedAt, dev, ino)) {
		return false, "periodic integrity_check (last " + ledger.CheckedAt.UTC().Format(time.RFC3339) + ")"
	}
	return true, ""
}

// verifyLoadedSchema runs a load's post-migration integrity_check when it is
// due, after the load's last schema-writing step. schemaStepApplied says the
// schema step (Prisma, CREATE TABLE, Migrate, deferred DDL) bumped the schema
// cookie; migratedColumns counts Migrate's own changes; restoreFrom is the
// load's first snapshot, which a failing check restores.
func verifyLoadedSchema(app *App, checkOnly, schemaStepApplied bool, migratedColumns int, restoreFrom string, lease *appMCPAuthorityLease) error {
	dir, db := app.Dir, app.DB
	verify, why := true, "this load changed the schema"
	switch {
	case checkOnly:
		// A validation load (the router's check, `benmore check`) checks only
		// the columns it added itself; the app's own boot sees the rest change.
		verify = migratedColumns > 0
	case app.dbLocalSQLite && app.dbVerifiedAt.IsZero():
		// The open could not verify the file (a degraded reopen after failed
		// recovery, a backup recovery swapped in): no record may vouch for it.
		why = "the open could not verify the database"
	case !schemaStepApplied:
		var current bool
		current, why = integrityCheckedSinceChange(dir, db)
		verify = !current
	}
	if !verify {
		if checkOnly {
			return nil
		}
		log.Printf("  database: integrity_check skipped - no table, index or migration changed since the last check passed")
		return reportPostMigrationDrift(dir, db)
	}
	log.Printf("  database: integrity_check (%s)", why)
	checkedAt := time.Now()
	if err := verifyPostMigrationAndRestoreWithLease(dir, db, restoreFrom, lease); err != nil {
		return err
	}
	app.dbVerifiedAt = checkedAt
	if err := recordIntegrityCheck(dir, db); err != nil {
		log.Printf("  database: integrity_check passed but could not be recorded (%v); the next start checks again", err)
	}
	return nil
}

// recordIntegrityCheck notes a passing integrity_check of the current schema.
// Best effort: without the record the next boot checks again. Only a process
// that owns the app directory writes it: one that does not (the router, the
// tenant helper) works in directories a tenant controls, where .benmore could
// be a link to elsewhere, and it never loads an app anyway (errForeignAppLoad).
func recordIntegrityCheck(dir string, db *sql.DB) error {
	if foreignAppDirs.Load() {
		return errors.New("not recorded from a process that does not own the app directory")
	}
	dev, ino, err := dbFileDevIno(filepath.Join(dir, "data.db"))
	if err != nil {
		return err
	}
	fingerprint, err := schemaFingerprint(db)
	if err != nil {
		return err
	}
	data, err := json.Marshal(integrityLedger{
		Version:     integrityLedgerVersion,
		Dev:         dev,
		Ino:         ino,
		Fingerprint: fingerprint,
		CheckedAt:   time.Now().UTC(),
	})
	if err != nil {
		return err
	}
	return writeStateFile(dir, integrityLedgerName, data)
}
