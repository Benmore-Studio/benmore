//go:build !cli

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// Revision ledger retirement. The row-revision triggers run on every write to
// an enrolled table, and the ledger keeps a tombstone for every deleted row,
// for as long as they are installed. Nothing uses them once the connector is
// disabled (paused or revoked: exposure off) or the app no longer declares
// mcp.yaml, so they are removed then: the owner's enrollment record is marked
// retired first, then the triggers and both sidecars (tombstones included) go
// in one transaction. Enabling approved writes again re-enrolls through
// repair: a fresh incarnation seeded from the current rows. Turning off only
// approved writes keeps the ledger, because exposed reads still cite row
// revisions.

const appMCPRevisionRetireTimeout = 30 * time.Second

// appMCPRevisionLedgerInstalled reports whether any revision trigger or
// sidecar exists in the app database.
func appMCPRevisionLedgerInstalled(ctx context.Context, db *sql.DB) (bool, error) {
	var n int
	err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM main.sqlite_schema WHERE (type='trigger' AND substr(name,1,17)='_benmore_mcp_rev_') OR (type='table' AND name IN (?,?))`, appMCPRevisionTablesName, appMCPRowRevisionsName).Scan(&n)
	return n > 0, err
}

// retireAppMCPRevisionLedger removes the ledger unless the connector is
// exposed with a declared manifest. It holds the write-policy lease
// throughout, so no enrollment or approved write runs alongside it. retired
// is false when nothing was installed or the ledger is still in use.
func retireAppMCPRevisionLedger(ctx context.Context, app *App, manifestPresent bool) (retired bool, err error) {
	if ctx == nil || app == nil || app.DB == nil {
		return false, errors.New("revision ledger retirement requires an app database")
	}
	if installed, err := appMCPRevisionLedgerInstalled(ctx, app.DB); err != nil || !installed {
		return false, err
	}
	policyCtx, release, lease, err := acquireAppMCPWritePolicy(ctx, app.Dir)
	if err != nil {
		return false, err
	}
	defer release()
	state, err := lease.read()
	switch {
	case os.IsNotExist(err):
		// No owner state, so no enrollment verifies; a later enable mints a
		// new owner epoch and repairs.
	case err != nil:
		return false, err
	case state.Exposed && manifestPresent:
		return false, nil
	default:
		if err := invalidateAppMCPWritesWithLease(lease); err != nil {
			return false, err
		}
		if err := markAppMCPRevisionEnrollmentRetired(lease); err != nil {
			return false, err
		}
	}
	tx, err := app.DB.BeginTx(policyCtx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()
	mainPath, err := mainDatabasePathForQuerier(&appMCPWriteTxQuerier{ctx: policyCtx, tx: tx})
	if err != nil || canonicalDBPath(mainPath) != canonicalDBPath(filepath.Join(app.Dir, "data.db")) {
		if err == nil {
			err = errors.New("revision ledger belongs to another app database")
		}
		return false, err
	}
	triggers, err := appMCPExistingRevisionTriggers(tx)
	if err != nil {
		return false, err
	}
	for name := range triggers {
		if _, err := tx.Exec("DROP TRIGGER main." + quoteIdent(name)); err != nil {
			return false, fmt.Errorf("remove revision trigger: %w", err)
		}
	}
	for _, name := range []string{appMCPRowRevisionsName, appMCPRevisionTablesName} {
		if _, err := tx.Exec("DROP TABLE IF EXISTS main." + quoteIdent(name)); err != nil {
			return false, fmt.Errorf("remove revision sidecar: %w", err)
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

// markAppMCPRevisionEnrollmentRetired records, before any database change,
// that the next write enable must repair. A crash after it leaves the ledger
// for the next retirement, and the enable still repairs.
func markAppMCPRevisionEnrollmentRetired(lease *appMCPAuthorityLease) error {
	enrollment, err := readAppMCPRevisionEnrollment(lease)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("revision enrollment record is unusable: %w", err)
	}
	if enrollment.State == "retired" {
		return nil
	}
	owner, err := lease.read()
	if err != nil {
		return err
	}
	return writeAppMCPRevisionEnrollmentWithLease(lease, &appMCPRevisionEnrollment{
		Version: 1, App: enrollment.App, OwnerEpoch: owner.Epoch, EnrollmentID: enrollment.EnrollmentID,
		State: "retired", TableNames: append([]string(nil), enrollment.TableNames...), Tables: []appMCPRevisionEnrollmentTable{},
	})
}

// retireUnusedAppMCPRevisionLedger runs at start-up, so a ledger left by a
// connector disabled before (whose retirement failed) or by an mcp.yaml since
// removed does not keep taxing the app's writes.
func retireUnusedAppMCPRevisionLedger(app *App) {
	if app == nil || app.DB == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), appMCPRevisionRetireTimeout)
	defer cancel()
	if installed, err := appMCPRevisionLedgerInstalled(ctx, app.DB); err != nil || !installed {
		return
	}
	// A withheld connector keeps its ledger: the manifest is still there and
	// comes back once the source is reviewed again.
	retired, err := retireAppMCPRevisionLedger(ctx, app, app.MCP != nil || app.mcpWithheld != "")
	if err != nil {
		log.Printf("MCP revision ledger: could not remove an unused ledger: %v", err)
	} else if retired {
		log.Printf("MCP revision ledger: removed (connector disabled or mcp.yaml removed)")
	}
}
