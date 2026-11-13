//go:build !cli

package main

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// MigrateResult describes what migrations would be or were applied.
type MigrateResult struct {
	Added   []string // "table.column TYPE"
	Skipped []string // columns that already exist
	Blocked []string // destructive changes that need --force
	// Retained lists differences between the schema and the live database
	// that the app's load leaves as they are: a live column the schema no
	// longer declares keeps its data (force or not), a nullability or type
	// change is not rebuilt (Migrate rebuilds nullability only with force).
	// They used to be Blocked, so promote demanded force for them, applied
	// nothing, and stayed blocked on every later promote (round-2 finding
	// L7), and every start logged them as needing --force.
	Retained []string
}

// migrationColumnAdd is one additive ADD COLUMN a migration applies.
type migrationColumnAdd struct {
	table string
	col   Column
}

// migrationRebuild is one force-only nullability rebuild of a table.
type migrationRebuild struct {
	table string
	fixes map[string]bool
}

// migrationPlan is what Migrate will change, read from the live schema without
// changing it. The loader asks for it before deciding whether a pre-migrate
// snapshot is worth taking, so the decision and the apply come from the same
// comparison.
type migrationPlan struct {
	result   *MigrateResult
	adds     []migrationColumnAdd
	rebuilds []migrationRebuild
	// missingTables lists schema tables absent from the database. LoadSchema
	// creates them before Migrate runs, so one still missing here is a change
	// nothing else accounted for.
	missingTables []string
}

// changes reports whether applying the plan writes the schema.
func (p *migrationPlan) changes() bool {
	return len(p.adds) > 0 || len(p.rebuilds) > 0 || len(p.missingTables) > 0
}

// planMigration compares the schema tables against the live database. It only
// reads (sqlite_schema and table_info).
func planMigration(db mutationQuerier, tables []Table, force bool) (*migrationPlan, error) {
	plan := &migrationPlan{result: &MigrateResult{}}
	result := plan.result

	for _, table := range tables {
		exists, err := tableExists(db, table.Name)
		if err != nil {
			return plan, err
		}

		if !exists {
			// Table doesn't exist - the CREATE TABLE in LoadSchema handles this
			for _, col := range table.Columns {
				result.Added = append(result.Added, fmt.Sprintf("%s.%s %s (new table)", table.Name, col.Name, col.Type))
			}
			plan.missingTables = append(plan.missingTables, table.Name)
			continue
		}

		// Table exists - check for new columns
		liveCols, err := tableColumnsWith(db, table.Name)
		if err != nil {
			return plan, err
		}

		liveColByName := make(map[string]Column)
		for _, c := range liveCols {
			liveColByName[strings.ToLower(c.Name)] = c
		}

		// nullFixes collects columns whose nullability diverges and that we'll
		// apply via a single table rebuild (SQLite has no ALTER COLUMN DROP
		// NOT NULL). Keyed lowercased col name → desired NotNull (from schema).
		nullFixes := make(map[string]bool)
		var newAdds []Column

		for _, col := range table.Columns {
			if liveCol, ok := liveColByName[strings.ToLower(col.Name)]; ok {
				result.Skipped = append(result.Skipped, fmt.Sprintf("%s.%s", table.Name, col.Name))
				// Column exists in both - reconcile ATTRIBUTES the simple
				// ADD/DROP path misses. Nullability change (NOT NULL ⇄ NULL)
				// needs a table rebuild; it's neither additive nor a drop, so
				// pre-2.7 it was silently skipped and schema/DB diverged.
				// Skip PK columns: SQLite reports notnull=0 for INTEGER
				// PRIMARY KEY (rowid alias) even though it's effectively
				// NOT NULL, which would false-positive into a rebuild loop.
				if col.NotNull != liveCol.NotNull && !col.PK && !liveCol.PK {
					from, to := nullLabel(liveCol.NotNull), nullLabel(col.NotNull)
					if force {
						nullFixes[strings.ToLower(col.Name)] = col.NotNull
						result.Added = append(result.Added,
							fmt.Sprintf("REBUILD %s.%s nullability (%s → %s)", table.Name, col.Name, from, to))
					} else {
						// The load never rebuilds a table: the column stays
						// as it is. Reported as DiffSchema reports it.
						result.Retained = append(result.Retained, retainedNullability(table.Name, col.Name, liveCol.NotNull, col.NotNull))
					}
				}
				continue
			}

			newAdds = append(newAdds, col)
		}

		for _, col := range newAdds {
			plan.adds = append(plan.adds, migrationColumnAdd{table: table.Name, col: col})
		}

		// Defer nullability rebuilds to after the additive pass (see Migrate).
		if force && len(nullFixes) > 0 {
			plan.rebuilds = append(plan.rebuilds, migrationRebuild{table: table.Name, fixes: nullFixes})
		}

		// A live column the schema does not declare keeps its data: no
		// migration drops a column on its own, force or not. This used to
		// say "not in schema.sql (use --force to drop)" on every start of a
		// schema.prisma app, a file it does not have and a flag hosted apps
		// do not have.
		schemaColMap := make(map[string]bool)
		for _, c := range table.Columns {
			schemaColMap[strings.ToLower(c.Name)] = true
		}
		for _, liveCol := range liveCols {
			if !schemaColMap[strings.ToLower(liveCol.Name)] {
				result.Retained = append(result.Retained, retainedUndeclaredColumn(table.Name, liveCol.Name))
			}
		}
	}
	return plan, nil
}

// Migrate compares schema.sql tables against the live database and applies non-destructive changes.
func Migrate(db *sql.DB, tables []Table, force bool) (*MigrateResult, error) {
	// Collect every additive ADD COLUMN across ALL tables and apply them in ONE
	// transaction (below), so a failure on a later table rolls back the columns
	// already added to earlier tables - no half-migrated cross-table schema.
	// Nullability rebuilds (force-only, per-table by nature) are deferred to
	// after the additive pass for the same reason.
	plan, err := planMigration(db, tables, force)
	result := plan.result
	if err != nil {
		return result, err
	}
	pendingAdds, pendingRebuilds := plan.adds, plan.rebuilds

	// Apply every additive ADD COLUMN across all tables in ONE transaction.
	// SQLite DDL is transactional inside an explicit tx, so any single failure
	// rolls back ALL adds - earlier tables are never left half-migrated.
	if len(pendingAdds) > 0 {
		tx, err := db.BeginTx(withLongWriteTx(context.Background(), "schema migration"), nil)
		if err != nil {
			return result, err
		}
		committed := false
		defer func() {
			if !committed {
				_ = tx.Rollback()
			}
		}()
		for _, pa := range pendingAdds {
			if _, err := tx.Exec(buildAlterAdd(pa.table, pa.col)); err != nil {
				return result, fmt.Errorf("migrate %s.%s: %w", pa.table, pa.col.Name, err)
			}
		}
		if err := tx.Commit(); err != nil {
			return result, fmt.Errorf("commit additive migration: %w", err)
		}
		committed = true
		for _, pa := range pendingAdds {
			result.Added = append(result.Added, fmt.Sprintf("%s.%s %s", pa.table, pa.col.Name, pa.col.Type))
		}
	}

	// Apply collected nullability changes with ONE rebuild per table, after the
	// additive pass so the rebuilt table includes the freshly-added columns.
	// Transform flips NotNull for the diverged columns, preserving every other
	// column's live attributes. A NULL→NOT NULL tightening that would orphan
	// existing NULL rows fails inside the rebuild's tx and rolls back cleanly.
	for _, pr := range pendingRebuilds {
		fixes := pr.fixes
		if err := rebuildTable(db, pr.table, func(c Column) *Column {
			if want, ok := fixes[strings.ToLower(c.Name)]; ok {
				c.NotNull = want
			}
			return &c
		}); err != nil {
			return result, fmt.Errorf("rebuild %s for nullability change: %w", pr.table, err)
		}
	}

	return result, nil
}

// DiffSchema returns what migrations would run without executing them:
// Added for the columns and tables the load creates, Retained for the
// differences it leaves in place. It never fills Blocked: the app's load
// (Migrate without force, the only way it runs) drops no column and rebuilds
// no table for nullability, so nothing here is destructive. Destructive
// changes come from removed models and migration files (promoteDiffFromSource).
func DiffSchema(db *sql.DB, tables []Table) (*MigrateResult, error) {
	result := &MigrateResult{}

	for _, table := range tables {
		exists, err := tableExists(db, table.Name)
		if err != nil {
			return result, err
		}

		if !exists {
			for _, col := range table.Columns {
				result.Added = append(result.Added, fmt.Sprintf("CREATE TABLE %s → %s %s", table.Name, col.Name, col.Type))
			}
			continue
		}

		liveCols, err := GetTableColumns(db, table.Name)
		if err != nil {
			return result, err
		}

		liveColByName := make(map[string]Column)
		for _, c := range liveCols {
			liveColByName[strings.ToLower(c.Name)] = c
		}

		for _, col := range table.Columns {
			if liveCol, ok := liveColByName[strings.ToLower(col.Name)]; ok {
				// Attribute divergence the load never rebuilds. PK columns
				// excluded (see Migrate - SQLite rowid-alias notnull quirk).
				if col.NotNull != liveCol.NotNull && !col.PK && !liveCol.PK {
					result.Retained = append(result.Retained, retainedNullability(table.Name, col.Name, liveCol.NotNull, col.NotNull))
				}
				if col.Type != "" && liveCol.Type != "" && !sqliteTypesMatch(col.Type, liveCol.Type) {
					result.Retained = append(result.Retained, retainedColumnType(table.Name, col.Name, liveCol.Type, col.Type))
				}
				continue
			}
			result.Added = append(result.Added, fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s %s", table.Name, col.Name, col.Type))
		}

		schemaColMap := make(map[string]bool)
		for _, c := range table.Columns {
			schemaColMap[strings.ToLower(c.Name)] = true
		}
		for _, liveCol := range liveCols {
			if !schemaColMap[strings.ToLower(liveCol.Name)] {
				result.Retained = append(result.Retained, retainedUndeclaredColumn(table.Name, liveCol.Name))
			}
		}
	}

	return result, nil
}

// Retained entries start "<table>.<column>: " so expandContractGuidance and
// readers can tell which column each names.
const retainedUndeclaredMarker = ": in the database but not in the schema"

func retainedUndeclaredColumn(table, col string) string {
	return fmt.Sprintf("%s.%s%s - kept with its data (no migration drops a column on its own). To drop it, add a migrations/ file with `ALTER TABLE %s DROP COLUMN %s;`; promote asks for force before that file runs.", table, col, retainedUndeclaredMarker, ddlIdent(table), ddlIdent(col))
}

func retainedNullability(table, col string, liveNotNull, schemaNotNull bool) string {
	return fmt.Sprintf("%s.%s: the database column is %s, the schema says %s - kept as it is (a nullability change needs a table rebuild in a migrations/ file).", table, col, nullLabel(liveNotNull), nullLabel(schemaNotNull))
}

func retainedColumnType(table, col, liveType, schemaType string) string {
	return fmt.Sprintf("%s.%s: the database column is %s, the schema says %s - kept as it is; values are stored with the %s column's affinity (a type change needs a new field and a copy in a migrations/ file).", table, col, liveType, schemaType, liveType)
}

func expandContractGuidance(diff *MigrateResult) []string {
	if diff == nil {
		return nil
	}
	adds := parseAdditiveColumnChanges(diff.Added)
	drops := append(parseBlockedDropColumnChanges(diff.Blocked), parseRetainedUndeclaredColumns(diff.Retained)...)
	var guidance []string
	for _, add := range adds {
		for _, drop := range drops {
			if !strings.EqualFold(add.Table, drop.Table) {
				continue
			}
			guidance = append(guidance, fmt.Sprintf(
				"rename-shaped %s.%s -> %s.%s: use expand/contract. Promote adds %s.%s and keeps %s.%s with its data; dual-write and backfill %s.%s, switch reads to %s.%s with fallback, then drop the old column in a migrations/ file (`ALTER TABLE %s DROP COLUMN %s;`), which promote runs only with force, after backup verification.",
				drop.Table, drop.Column, add.Table, add.Column, add.Table, add.Column, drop.Table, drop.Column, add.Table, add.Column, add.Table, add.Column, ddlIdent(drop.Table), ddlIdent(drop.Column),
			))
		}
	}
	if len(guidance) == 0 && len(diff.Blocked) > 0 {
		guidance = append(guidance, "contract phase required: destructive schema changes are force-gated. Prefer an expand/contract rollout: add compatible columns first, dual-write/backfill, switch reads, then force only the final drop after backup verification.")
	}
	return guidance
}

type additiveColumnChange struct {
	Table  string
	Column string
	Type   string
}

func parseAdditiveColumnChanges(added []string) []additiveColumnChange {
	var out []additiveColumnChange
	for _, item := range added {
		fields := strings.Fields(item)
		if len(fields) >= 7 &&
			strings.EqualFold(fields[0], "ALTER") &&
			strings.EqualFold(fields[1], "TABLE") &&
			strings.EqualFold(fields[3], "ADD") &&
			strings.EqualFold(fields[4], "COLUMN") {
			out = append(out, additiveColumnChange{
				Table:  fields[2],
				Column: fields[5],
				Type:   strings.Join(fields[6:], " "),
			})
			continue
		}
		parts := strings.Fields(item)
		if len(parts) >= 2 && strings.Contains(parts[0], ".") {
			tableCol := strings.SplitN(parts[0], ".", 2)
			if len(tableCol) == 2 {
				out = append(out, additiveColumnChange{
					Table:  tableCol[0],
					Column: tableCol[1],
					Type:   strings.Join(parts[1:], " "),
				})
			}
		}
	}
	return out
}

type blockedDropColumnChange struct {
	Table  string
	Column string
}

// parseRetainedUndeclaredColumns reads the columns DiffSchema found in the
// database but not in the schema (retainedUndeclaredColumn).
func parseRetainedUndeclaredColumns(retained []string) []blockedDropColumnChange {
	var out []blockedDropColumnChange
	for _, item := range retained {
		tableCol, _, ok := strings.Cut(item, retainedUndeclaredMarker)
		if !ok {
			continue
		}
		if table, col, ok := strings.Cut(tableCol, "."); ok {
			out = append(out, blockedDropColumnChange{Table: table, Column: col})
		}
	}
	return out
}

func parseBlockedDropColumnChanges(blocked []string) []blockedDropColumnChange {
	var out []blockedDropColumnChange
	for _, item := range blocked {
		trimmed := strings.TrimSpace(item)
		if strings.HasPrefix(trimmed, "DROP COLUMN ") {
			rest := strings.TrimPrefix(trimmed, "DROP COLUMN ")
			tableCol, _, _ := strings.Cut(rest, " ")
			if table, col, ok := strings.Cut(tableCol, "."); ok {
				out = append(out, blockedDropColumnChange{Table: table, Column: col})
			}
			continue
		}
		if strings.HasPrefix(trimmed, "DROP ") {
			rest := strings.TrimPrefix(trimmed, "DROP ")
			tableCol, _, _ := strings.Cut(rest, " ")
			if table, col, ok := strings.Cut(tableCol, "."); ok {
				out = append(out, blockedDropColumnChange{Table: table, Column: col})
			}
		}
	}
	return out
}

// nullLabel renders a column's nullability for migration notices.
func nullLabel(notNull bool) string {
	if notNull {
		return "NOT NULL"
	}
	return "NULL"
}

func buildAlterAdd(table string, col Column) string {
	// Names are left bare here: this is the schema-apply path (the author's
	// own CREATE/ALTER), and it is consistent with the Prisma/SQL migration
	// emitters. A column name that is not a plain identifier fails the ALTER
	// loudly and rolls the migration back, rather than silently creating a
	// column whose name needs quoting everywhere it is later read. Runtime
	// reads of the resulting tables are quoted regardless. The one name that
	// is quoted is an SQL reserved word (ddlIdent): `order` is a plain
	// identifier the statement could not otherwise take.
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", ddlIdent(table), ddlIdent(col.Name)))
	if col.Type != "" {
		sb.WriteString(" " + col.Type)
	}
	if col.Default != "" {
		sb.WriteString(" DEFAULT " + col.Default)
	}
	return sb.String()
}

func tableExists(db mutationQuerier, name string) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&count)
	return count > 0, err
}

// ===== Pre-migration backup & rollback =====

const (
	backupDirName = ".benmore/backups"
	backupPrefix  = "pre-migrate-"
	// maxBackups is how many pre-migrate-* snapshots an app keeps. Each is a
	// whole-database copy, taken only by a start that changes the schema
	// (schemaSnapshotReason) or runs a new build or storage configuration
	// (bootStateSnapshotReason), and never kept twice for an unchanged
	// database (backupDatabase reuses the newest); auto-recovery and restore
	// pick among them, and scheduled-* backups have their own keep count. Ten
	// per app came to 31 GB across the fleet against 3.5 GB of live data while
	// every restart took one.
	maxBackups       = 3
	backupPermission = 0640
	backupDirMode    = os.ModeSetgid | 0770
)

// checkBackupMinInterval spaces the pre-migrate snapshots that validation
// loads take. A validation load (the check tool, `benmore check`, serve's boot
// check) is a full app load, and a snapshot is a whole-database copy (VACUUM
// INTO), so a check loop against a 100 MB database that keeps finding a schema
// change would otherwise write 100 MB per call.
const checkBackupMinInterval = 10 * time.Minute

// recentPreMigrateBackup reports whether a non-empty pre-migrate snapshot newer
// than maxAge already exists for the app.
func recentPreMigrateBackup(dir string, maxAge time.Duration) bool {
	entries, err := backupDirEntries(dir)
	if err != nil {
		return false
	}
	cutoff := time.Now().Add(-maxAge)
	for _, info := range entries {
		if info.IsDir() || !strings.HasPrefix(info.Name(), backupPrefix) || !strings.HasSuffix(info.Name(), ".db") {
			continue
		}
		if info.Size() > 0 && info.ModTime().After(cutoff) {
			return true
		}
	}
	return false
}

// backupDirEntries lists .benmore/backups (lstat of each entry). In a process
// that works on directories owned by other accounts (foreignAppDirs: the
// tenant helper's backup-local) the directory is reached through directory
// handles, so a .benmore or backups that is a link to another app's is
// refused instead of listed, and later pruned (cleanupOldBackups).
func backupDirEntries(dir string) ([]os.FileInfo, error) {
	if !foreignAppDirs.Load() {
		entries, err := os.ReadDir(filepath.Join(dir, backupDirName))
		if err != nil {
			return nil, err
		}
		infos := make([]os.FileInfo, 0, len(entries))
		for _, e := range entries {
			if info, err := e.Info(); err == nil {
				infos = append(infos, info)
			}
		}
		return infos, nil
	}
	backups, err := openForeignBackupDir(dir)
	if err != nil {
		return nil, err
	}
	defer backups.Close()
	names, err := backups.names()
	if err != nil {
		return nil, err
	}
	infos := make([]os.FileInfo, 0, len(names))
	for _, name := range names {
		if info, err := backups.lstat(name); err == nil {
			infos = append(infos, info)
		}
	}
	return infos, nil
}

// removeBackupFile removes one snapshot (and a companion -wal) from
// .benmore/backups, through directory handles in a foreignAppDirs process.
func removeBackupFile(dir, name string) {
	if !foreignAppDirs.Load() {
		path := filepath.Join(dir, backupDirName, name)
		os.Remove(path)
		os.Remove(path + "-wal")
		return
	}
	backups, err := openForeignBackupDir(dir)
	if err != nil {
		log.Printf("  backup cleanup: %s skipped: %v", name, err)
		return
	}
	defer backups.Close()
	// os.Root.Remove unlinks the entry itself: a link is removed, never followed.
	backups.root.Remove(name)
	backups.root.Remove(name + "-wal")
}

// backupChmod changes a backup's mode; tests replace it to act like a unit
// with RestrictSUIDSGID=yes, which refuses any chmod carrying a set-id bit.
var backupChmod = os.Chmod

func prepareBackupDir(backupDir string) error {
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return fmt.Errorf("create backup dir: %w", err)
	}
	// RestrictSUIDSGID=yes blocks even a no-op chmod carrying the setgid bit.
	// Avoid that syscall when the parent already supplied the desired mode,
	// but keep a real permission mismatch boot-fatal: a backup the router
	// cannot verify is not a usable recovery point.
	st, err := os.Stat(backupDir)
	if err != nil {
		return fmt.Errorf("stat backup dir: %w", err)
	}
	if tenantDataLockedFor(filepath.Dir(filepath.Dir(backupDir))) {
		// The tenant-data lock (tenant_data_lock_marker.go): snapshots are the
		// app account's alone and the router never reads them. Owner-only is
		// right as it is; anything wider is only ever narrowed (no set-id
		// bit, so RestrictSUIDSGID never refuses it).
		if perm := st.Mode().Perm(); perm&0o077 != 0 {
			if err := backupChmod(backupDir, perm&^0o077); err != nil {
				return fmt.Errorf("set backup dir permissions: %w", err)
			}
		}
	} else if st.Mode().Perm() != backupDirMode.Perm() {
		// 0770, with or without the setgid bit, is right: the app runs with
		// Group=benmore, so its snapshots get the router's group either way.
		// Anything else (a lock switched off or rolled back half-way leaves
		// 0700) is repaired: to 02770 where allowed, else to 0770 without a
		// set-id bit, because a unit with RestrictSUIDSGID=yes refuses the
		// setgid chmod and a refused pre-migrate snapshot is fatal on prod.
		if err := backupChmod(backupDir, backupDirMode); err != nil {
			if err2 := backupChmod(backupDir, backupDirMode.Perm()); err2 != nil {
				return fmt.Errorf("set backup dir permissions: %w", errors.Join(err, err2))
			}
		}
	}
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return fmt.Errorf("list backups for permission repair: %w", err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".db") {
			continue
		}
		path := filepath.Join(backupDir, entry.Name())
		info, err := os.Stat(path)
		if err != nil {
			return fmt.Errorf("stat backup %s for permission repair: %w", entry.Name(), err)
		}
		if err := ensureBackupFilePermission(path, info.Mode(), backupChmod); err != nil {
			return fmt.Errorf("repair backup permissions for %s: %w", entry.Name(), err)
		}
	}
	return nil
}

func backupFilePermissionNeedsRepair(mode os.FileMode) bool {
	const specialBits = os.ModeSetuid | os.ModeSetgid | os.ModeSticky
	return mode.Perm() != backupPermission || mode&specialBits != 0
}

// ensureBackupFilePermission gives the snapshot at path (in the instance's
// .benmore/backups) its mode.
func ensureBackupFilePermission(path string, mode os.FileMode, chmod func(string, os.FileMode) error) error {
	if tenantDataLockedFor(filepath.Dir(filepath.Dir(filepath.Dir(path)))) {
		// Under the tenant-data lock a snapshot is owner-only: accepted as it
		// is, anything wider narrowed, never widened back to 0640.
		const specialBits = os.ModeSetuid | os.ModeSetgid | os.ModeSticky
		if mode.Perm()&0o077 == 0 && mode&specialBits == 0 {
			return nil
		}
		return chmod(path, mode.Perm()&^0o077)
	}
	if !backupFilePermissionNeedsRepair(mode) {
		// The router may have created a correctly protected snapshot as its
		// own user. Avoid a no-op chmod that systemd may reject.
		return nil
	}
	return chmod(path, backupPermission)
}

// setBackupFileMode gives a snapshot just written its mode: 0640 for the
// router's group, or owner-only under the tenant-data lock.
func setBackupFileMode(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	return ensureBackupFilePermission(path, info.Mode(), backupChmod)
}

// backupDatabase writes a consistent snapshot of data.db to
// .benmore/backups/pre-migrate-{timestamp}.db before schema migrations
// run. Returns the backup path on success, or empty string if no
// database exists to back up.
//
// Pre-2.7.32 this raw-`io.Copy`'d data.db + data.db-wal separately -
// fundamentally wrong for a database in WAL mode. The main file
// holds the BASE state; new writes go to the WAL until checkpoint.
// Two independent reads of those files during active writes produce
// an internally inconsistent snapshot - and if that snapshot was the
// only one left when auto-recovery fired, it would lose every row
// committed between the last full checkpoint and the wedge.
//
// Now we use SQLite's online `VACUUM INTO` primitive. It opens a
// read-only snapshot of the live DB, walks every page, and writes
// them into a fresh file in one atomic operation - no -wal sibling
// to worry about, guaranteed internally consistent even under heavy
// write traffic. Plus it's smaller (no free pages, no WAL frames).
//
// Falls back to file-copy only when VACUUM INTO is unavailable
// (extremely unlikely - every SQLite >= 3.27 supports it).
//
// A copy byte-identical to the newest snapshot already on disk is deleted and
// that snapshot's path returned: it holds the same database. A migration that
// fails fails every start, and systemd restarts the unit several times in a
// few seconds; each start used to add a copy of the same database, and the
// next successful start's retention (maxBackups) then removed the older,
// different snapshots, once the only copy taken before a column drop.
func backupDatabase(dir string) (string, error) {
	if foreignAppDirs.Load() {
		// The app's own snapshot path, for its own process; the tenant
		// helper's backup-local calls foreignDirBackupDatabase itself.
		return "", errForeignAppLoad
	}
	dbPath := filepath.Join(dir, "data.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return "", nil // no database to back up
	}

	backupDir := filepath.Join(dir, backupDirName)
	if err := prepareBackupDir(backupDir); err != nil {
		return "", err
	}

	timestamp := time.Now().UTC().Format("20060102T150405Z")
	backupPath := filepath.Join(backupDir, backupPrefix+timestamp+".db")

	// Collision guard. The timestamp is only second-granular, so when a process
	// restarts twice inside the same second (classic systemd crash loop) the
	// name repeats. VACUUM INTO REFUSES to write to an existing path, which used
	// to bubble up as a FATAL pre-migrate-backup error on prod
	// (preMigrationBackupFailureIsFatal) → exit 1 → systemd restart → same
	// second → same collision → the loop fed itself (this caused a real outage;
	// the restart counter hit 24). Resolve it deterministically instead of
	// crashing:
	//   - a zero-byte file is a partial from a killed VACUUM: delete + reuse it.
	//   - a real same-second backup already exists: pick a unique sibling name
	//     (pid + counter) so we never hit "output file already exists".
	if fi, statErr := os.Stat(backupPath); statErr == nil {
		if fi.Size() == 0 {
			_ = os.Remove(backupPath)
		} else {
			for n := 1; ; n++ {
				cand := filepath.Join(backupDir, fmt.Sprintf("%s%s-%d-%d.db", backupPrefix, timestamp, os.Getpid(), n))
				if _, e := os.Stat(cand); os.IsNotExist(e) {
					backupPath = cand
					break
				}
			}
		}
	}

	previous := newestPreMigrateBackup(dir)
	if err := sqliteVacuumInto(dbPath, backupPath); err != nil {
		// Don't leave a half-written file behind if the snapshot failed.
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("vacuum into backup: %w", err)
	}
	// VACUUM INTO rebuilds the database from its content (every table and
	// index rewritten in key order, no free pages, no WAL frames), so an
	// unchanged database gives the same bytes however its file changed in
	// between: a checkpoint, a quick_check, a reopen. Any difference, a different SQLite version included, or a read
	// error keeps the new copy. The earlier snapshot keeps its name (and the
	// age auto-recovery reads from it), so paths already logged or held by
	// this load stay valid.
	if previous != "" && sameFileBytes(previous, backupPath) {
		removeBackupFile(dir, filepath.Base(backupPath))
		log.Printf("  backup: the database is unchanged since %s; reusing it", filepath.Base(previous))
		return previous, nil
	}
	// VACUUM INTO honors the source's encryption settings but writes
	// with the default mode (0644 minus umask). Keep backups owner-writable
	// and group-readable so the trusted router can verify/restore them;
	// sibling tenants cannot traverse one another's app directories.
	if err := setBackupFileMode(backupPath); err != nil {
		return "", fmt.Errorf("set backup permissions: %w", err)
	}

	log.Printf("  backup: %s", backupPath)
	return backupPath, nil
}

// sqliteVacuumInto opens `srcPath` and runs `VACUUM INTO 'dstPath'`.
// The source is opened read-only so we never block a writer; SQLite
// itself takes a consistent snapshot of every page under the hood.
// `dstPath` must not exist - VACUUM INTO refuses to overwrite as a
// safety belt.
func sqliteVacuumInto(srcPath, dstPath string) error {
	if err := refuseRouterTenantData(srcPath); err != nil {
		return err
	}
	// `mode=ro` + `immutable=0` lets us read the live file without
	// taking a writer lock. We deliberately don't pass _journal_mode
	// here - VACUUM INTO's read snapshot doesn't need WAL semantics
	// on the source connection.
	dsn := srcPath + "?mode=ro"
	src, err := sql.Open("sqlite3", dsn)
	if err != nil {
		return fmt.Errorf("open source read-only: %w", err)
	}
	defer src.Close()
	if err := src.Ping(); err != nil {
		return fmt.Errorf("ping source: %w", err)
	}
	// VACUUM INTO is single-statement, parameter-free. The path must
	// be a SQL string literal - escape any embedded single quotes by
	// doubling them (filenames with quotes are not a real case but
	// the escape is cheap).
	escaped := strings.ReplaceAll(dstPath, "'", "''")
	if _, err := src.Exec("VACUUM INTO '" + escaped + "'"); err != nil {
		return fmt.Errorf("exec VACUUM INTO: %w", err)
	}
	return nil
}

// cleanupOldBackups removes all but the N most recent backups.
func cleanupOldBackups(dir string, keep int) {
	backups := listBackups(dir)
	if len(backups) <= keep {
		return
	}
	// backups are sorted oldest-first by timestamp (listBackups)
	toRemove := backups[:len(backups)-keep]
	for _, path := range toRemove {
		removeBackupFile(dir, filepath.Base(path)) // and its companion WAL if present
		log.Printf("  backup cleanup: removed %s", filepath.Base(path))
	}
}

// listBackups returns the pre-migrate-* backup file paths, oldest first. They
// are ordered by timestamp as auto-recovery orders them (backupTimestamp): a
// same-second sibling (pre-migrate-<ts>-<pid>-<n>.db) is newer than
// pre-migrate-<ts>.db, although a plain name sort puts it first.
func listBackups(dir string) []string {
	backupDir := filepath.Join(dir, backupDirName)
	entries, err := backupDirEntries(dir)
	if err != nil {
		return nil
	}

	var backups []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, backupPrefix) && strings.HasSuffix(name, ".db") && !strings.HasSuffix(name, "-wal") {
			backups = append(backups, filepath.Join(backupDir, name))
		}
	}
	sortBackupsByTimestamp(backups)
	return backups
}

// newestPreMigrateBackup returns the newest pre-migrate snapshot (by the
// timestamp in its name, as listBackups orders them) that is a non-empty
// regular file, or "".
func newestPreMigrateBackup(dir string) string {
	backups := listBackups(dir)
	for i := len(backups) - 1; i >= 0; i-- {
		if info, err := os.Lstat(backups[i]); err == nil && info.Mode().IsRegular() && info.Size() > 0 {
			return backups[i]
		}
	}
	return ""
}

// sameFileBytes reports whether two regular files hold exactly the same bytes.
// It stops at the first difference; an error reading either counts as a
// difference.
func sameFileBytes(a, b string) bool {
	fa, err := os.Open(a)
	if err != nil {
		return false
	}
	defer fa.Close()
	fb, err := os.Open(b)
	if err != nil {
		return false
	}
	defer fb.Close()
	sa, errA := fa.Stat()
	sb, errB := fb.Stat()
	if errA != nil || errB != nil || !sa.Mode().IsRegular() || !sb.Mode().IsRegular() || sa.Size() != sb.Size() {
		return false
	}
	bufA, bufB := make([]byte, 1<<20), make([]byte, 1<<20)
	for {
		na, errA := io.ReadFull(fa, bufA)
		nb, errB := io.ReadFull(fb, bufB)
		if na != nb || !bytes.Equal(bufA[:na], bufB[:nb]) {
			return false
		}
		endA := errA == io.EOF || errA == io.ErrUnexpectedEOF
		endB := errB == io.EOF || errB == io.ErrUnexpectedEOF
		if (errA != nil && !endA) || (errB != nil && !endB) || endA != endB {
			return false
		}
		if endA {
			return true
		}
	}
}

func preparePreMigrationBackup(dir string, hadDBBeforeOpen bool) (string, error) {
	if !hadDBBeforeOpen {
		return "", nil
	}
	backupPath, err := backupDatabase(dir)
	if err != nil {
		// Backstop to the collision guard in backupDatabase: if the snapshot
		// failed ONLY because the target already exists, a consistent
		// pre-migrate backup is already on disk for this moment - we are not
		// flying blind, so this must NEVER be fatal (it was the crash-loop
		// trigger). Proceed without a fresh snapshot.
		if strings.Contains(err.Error(), "output file already exists") {
			log.Printf("  backup: a same-second pre-migrate snapshot already exists; proceeding")
			return "", nil
		}
		if preMigrationBackupFailureIsFatal(dir) {
			return "", fmt.Errorf("pre-migrate backup: %w", err)
		}
		log.Printf("  backup warning: %s", err)
		return "", nil
	}
	return backupPath, nil
}

// preMigrationBackupFailureIsFatal decides whether a failed pre-migration
// backup aborts the migrate (prod) or only warns (dev).
//
// The app directory basename IS the platform-assigned instance subdomain
// (e.g. "<sub>" for prod, "<sub>-dev" for dev), so IsDevSubdomain on it is the
// authoritative env signal - it is not tenant-controllable. Any directory that
// doesn't classify as a dev subdomain (self-hosted `serve` dirs, the `_platform`
// root app, unknown names) falls through to fatal/fail-closed, which is the
// safe default: better to refuse a migration than run one with no backup.
func preMigrationBackupFailureIsFatal(dir string) bool {
	return !IsDevSubdomain(filepath.Base(dir))
}

func ensurePreMigrationBackupWritable(dir string) error {
	backupDir := filepath.Join(dir, backupDirName)
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		// IDENTITY SEAM (v2.7.194): this preflight often runs in the
		// ROUTER process (promote), but the backup itself is taken by the
		// PER-APP process at boot, running as the app dir's owner. On the
		// platform host .benmore/ is 0700 per-tenant-user-owned, so the
		// router's own write probe gets EACCES even though the app
		// process backs up fine - that false negative blocked every
		// promote after the first ("prod pre-migrate backup dir is not
		// writable: permission denied"). When WE can't write but the dir
		// belongs to another user who can, the preflight passes.
		if os.IsPermission(err) && writableByOwningUser(dir) {
			return nil
		}
		return fmt.Errorf("create backup dir: %w", err)
	}
	probe, err := os.CreateTemp(backupDir, ".write-check-*")
	if err != nil {
		if os.IsPermission(err) && writableByOwningUser(backupDir) {
			return nil
		}
		return fmt.Errorf("create backup-dir probe: %w", err)
	}
	name := probe.Name()
	if err := probe.Close(); err != nil {
		_ = os.Remove(name)
		return fmt.Errorf("close backup-dir probe: %w", err)
	}
	if err := os.Remove(name); err != nil {
		return fmt.Errorf("remove backup-dir probe: %w", err)
	}
	return nil
}

// validateSQLiteDB checks that a file is a valid SQLite database.
func validateSQLiteDB(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open: %w", err)
	}
	defer f.Close()

	// SQLite databases start with the 16-byte header "SQLite format 3\000"
	header := make([]byte, 16)
	n, err := f.Read(header)
	if err != nil || n < 16 {
		return fmt.Errorf("not a valid SQLite database (too small)")
	}
	if string(header) != "SQLite format 3\000" {
		return fmt.Errorf("not a valid SQLite database (bad header)")
	}
	return nil
}

// isCorruptDBErr reports whether the error from db.Ping / db.Query
// indicates the SQLite file is unreadable due to corruption (vs a
// permission, missing-file, or transient error). Three SQLite
// messages cover the failure modes auto-recovery should handle:
//
//   - "file is not a database" - the header bytes are not the
//     SQLite magic. Either the file was truncated mid-write, a
//     non-SQLite file got dropped in its place, or the WAL got
//     desynced from the main file (the post-migration symptom).
//   - "database disk image is malformed" - pages don't pass the
//     internal consistency check.
//   - "disk I/O error" - usually means the file's inode is gone
//     (someone unlinked it under the running handle, or a
//     filesystem-level operation invalidated the open fd).
//
// Anything else (permissions, locked, missing-table) returns false:
// auto-recovery only fires on hard-corruption signatures so we don't
// nuke a perfectly fine database during a transient hiccup.
func isCorruptDBErr(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "file is not a database") ||
		strings.Contains(msg, "database disk image is malformed") ||
		strings.Contains(msg, "disk I/O error")
}

// autoRestoreFromBackup tries to bring the app back to life when
// data.db is unreadable. Returns (true, nil) if a backup was found,
// validated, and swapped in; (false, err) if no usable backup exists.
//
// Strategy:
//  1. List every pre-migrate-*.db in .benmore/backups/ (newest first).
//  2. For each candidate, run validateSQLiteDB to make sure the
//     backup itself isn't also corrupt (otherwise we'd be replacing
//     a bad file with another bad file and looping forever).
//  3. The corrupt original is moved to data.db.corrupt-<ts> rather
//     than deleted, so an operator can post-mortem it.
//  4. The chosen backup is copied (not moved - leaves the backup
//     dir intact for further recovery attempts) into data.db's
//     place, with the WAL/SHM siblings removed for a clean open.
//
// Logs every step. On success the caller re-opens the DB; on failure
// the original cause error is returned so the caller decides whether
// to log.Fatalf or return up the stack.
func autoRestoreFromBackup(dir string, cause error) (bool, error) {
	return autoRestoreFromBackupInternal(dir, cause, nil, false)
}

func autoRestoreFromBackupWithLease(dir string, cause error, lease *appMCPAuthorityLease) (bool, error) {
	return autoRestoreFromBackupInternal(dir, cause, lease, true)
}

func autoRestoreFromBackupInternal(dir string, cause error, lease *appMCPAuthorityLease, policyHeld bool) (bool, error) {
	backupDir := filepath.Join(dir, backupDirName)

	candidates := autoRestoreCandidates(dir)
	if len(candidates) == 0 {
		return false, fmt.Errorf("auto-restore: no backups found in %s (cause: %v)", backupDir, cause)
	}

	var pickedBackup string
	for _, cand := range candidates {
		if err := validateSQLiteDB(cand); err == nil {
			pickedBackup = cand
			break
		} else {
			log.Printf("auto-restore: skipping unreadable backup %s: %s", filepath.Base(cand), err)
		}
	}
	if pickedBackup == "" {
		return false, fmt.Errorf("auto-restore: all %d backups are also corrupt (cause: %v)", len(candidates), cause)
	}
	// Swapping in an old snapshot silently drops every write since it was
	// taken. Pre-migrate snapshots are no longer refreshed by every restart, so
	// only a recent one is restored without a person deciding. A snapshot dated
	// in the future (clock skew, a hand-named file) has no trustworthy age.
	age, maxAge := backupAge(pickedBackup), autoRestoreMaxAge()
	if age < -autoRestoreClockSkew {
		log.Printf("DB AUTO-RECOVERY REFUSED: newest snapshot is dated %s in the future; restore with benmore restore or PITR (%s)",
			(-age).Round(time.Minute), filepath.Base(pickedBackup))
		return false, fmt.Errorf("%w: newest snapshot %s is dated %s in the future, so its age is unknown; the database was left in place - restore with benmore restore or PITR (cause: %v)",
			errAutoRestoreRefused, filepath.Base(pickedBackup), (-age).Round(time.Minute), cause)
	}
	if age > maxAge {
		log.Printf("DB AUTO-RECOVERY REFUSED: newest snapshot is %s old; restore with benmore restore or PITR (%s, limit %s, %s)",
			age.Round(time.Minute), filepath.Base(pickedBackup), maxAge, autoRestoreMaxAgeEnv)
		return false, fmt.Errorf("%w: newest snapshot %s is %s old (limit %s); the database was left in place - restore with benmore restore or PITR (cause: %v)",
			errAutoRestoreRefused, filepath.Base(pickedBackup), age.Round(time.Minute), maxAge, cause)
	}

	var corruptDest string
	var err error
	if policyHeld {
		if err := invalidateAppMCPForRestoreWithLease(lease); err != nil {
			return false, fmt.Errorf("auto-restore connector invalidation: %w", err)
		}
		corruptDest, err = swapInBackupWithLease(dir, pickedBackup, cause, lease)
	} else {
		corruptDest, err = swapInBackup(dir, pickedBackup, cause)
	}
	if err != nil {
		return false, fmt.Errorf("auto-restore: %w", err)
	}
	log.Printf("auto-restore: restored data.db ← %s (snapshot %s old); original kept at %s",
		filepath.Base(pickedBackup), age.Round(time.Second), filepath.Base(corruptDest))
	return true, nil
}

// autoRestoreMaxAgeDefault is the oldest snapshot auto-recovery restores on
// its own. autoRestoreMaxAgeEnv (a Go duration, e.g. 72h) overrides it; it is
// a platform-reserved key (tenantReservedEnvKey), so an app's environment
// cannot raise it.
const (
	autoRestoreMaxAgeDefault = 24 * time.Hour
	autoRestoreMaxAgeEnv     = "BENMORE_AUTO_RESTORE_MAX_AGE"
)

// autoRestoreClockSkew is how far in the future a snapshot's timestamp may be
// before its age counts as unknown.
const autoRestoreClockSkew = 5 * time.Minute

// errAutoRestoreRefused marks an auto-recovery that found only snapshots too
// old (or of unknown age) to restore unattended.
var errAutoRestoreRefused = errors.New("auto-recovery refused")

// autoRestoreCandidates lists the snapshots auto-recovery may restore, newest
// first: pre-migrate-* and scheduled-* files in .benmore/backups, ordered by
// the timestamp in the name, not the whole name, so a recent pre-migrate-*
// backup isn't shadowed by an older scheduled-* one.
func autoRestoreCandidates(dir string) []string {
	backupDir := filepath.Join(dir, backupDirName)
	var candidates []string
	if entries, err := os.ReadDir(backupDir); err == nil {
		for _, e := range entries {
			n := e.Name()
			if strings.HasSuffix(n, "-wal") || strings.HasSuffix(n, "-shm") || !strings.HasSuffix(n, ".db") {
				continue
			}
			if strings.HasPrefix(n, backupPrefix) || strings.HasPrefix(n, scheduledBackupPrefix) {
				candidates = append(candidates, filepath.Join(backupDir, n))
			}
		}
	}
	sort.Slice(candidates, func(i, j int) bool {
		return backupTimestamp(candidates[i]) > backupTimestamp(candidates[j])
	})
	return candidates
}

func autoRestoreMaxAge() time.Duration {
	if raw := strings.TrimSpace(os.Getenv(autoRestoreMaxAgeEnv)); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			return d
		}
		log.Printf("auto-restore: %s=%q is not a positive duration; using %s", autoRestoreMaxAgeEnv, raw, autoRestoreMaxAgeDefault)
	}
	return autoRestoreMaxAgeDefault
}

// backupAge is how long ago a snapshot was taken: the UTC timestamp in its
// name, else its modification time.
func backupAge(path string) time.Duration {
	ts := backupTimestamp(path)
	if len(ts) >= len("20060102T150405Z") {
		if taken, err := time.Parse("20060102T150405Z", ts[:len("20060102T150405Z")]); err == nil {
			return time.Since(taken)
		}
	}
	if info, err := os.Stat(path); err == nil {
		return time.Since(info.ModTime())
	}
	return time.Duration(1<<63 - 1)
}

func swapInBackup(dir, backupPath string, cause error) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	release, lease, err := beginAppMCPRestorePolicy(ctx, dir)
	if err != nil {
		return "", fmt.Errorf("connector restore lease: %w", err)
	}
	defer release()
	return swapInBackupWithLease(dir, backupPath, cause, lease)
}

// corruptCopyPath names where auto-recovery moves the corrupt original:
// .benmore/backups/data.db.corrupt-<ts>, with the snapshots (and, under the
// router tenant-data lock, closed to the router with them). It used to sit next
// to data.db for good, where it kept whatever mode the database had. Only when
// the backups directory cannot be prepared does it fall back to that place.
func corruptCopyPath(dir string) string {
	name := "data.db.corrupt-" + time.Now().UTC().Format("20060102T150405Z")
	backupDir := filepath.Join(dir, backupDirName)
	if err := prepareBackupDir(backupDir); err != nil {
		log.Printf("auto-recovery: %v; keeping the corrupt original next to data.db", err)
		return filepath.Join(dir, name)
	}
	return filepath.Join(backupDir, name)
}

func swapInBackupWithLease(dir, backupPath string, cause error, lease *appMCPAuthorityLease) (string, error) {
	if err := validateSQLiteDB(backupPath); err != nil {
		return "", fmt.Errorf("invalid backup: %w", err)
	}
	dbPath := filepath.Join(dir, "data.db")
	// Records about the file being replaced must not describe its successor.
	if err := forgetDatabaseStateFiles(dir); err != nil {
		return "", fmt.Errorf("remove the replaced database's state records: %w", err)
	}
	// Move the corrupt original aside so operators can post-mortem
	// (NEVER delete on auto-recovery - data loss should require a
	// deliberate human decision).
	corruptDest := corruptCopyPath(dir)
	if err := os.Rename(dbPath, corruptDest); err != nil {
		return "", fmt.Errorf("couldn't move failed database aside: %w", err)
	}
	// WAL/SHM next to the corrupt main file are now stale - move them too.
	_ = os.Rename(dbPath+"-wal", corruptDest+"-wal")
	_ = os.Rename(dbPath+"-shm", corruptDest+"-shm")

	// Copy the picked backup into place. Copy not rename so the
	// backup file stays in .benmore/backups/ - if the restored file
	// itself somehow fails to open, the next OpenDB attempt has the
	// same candidates to choose from.
	if cause != nil {
		log.Printf("backup restore: swapping in %s after %v", filepath.Base(backupPath), cause)
	}
	src, err := os.Open(backupPath)
	if err != nil {
		// Best-effort rollback: put the corrupt original back so we
		// don't end up with NO data.db at all.
		_ = os.Rename(corruptDest, dbPath)
		return "", fmt.Errorf("open backup: %w", err)
	}
	defer src.Close()
	dst, err := os.OpenFile(dbPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0660)
	if err != nil {
		_ = os.Rename(corruptDest, dbPath)
		return "", fmt.Errorf("create new data.db: %w", err)
	}
	if _, err := io.Copy(dst, src); err != nil {
		_ = dst.Close()
		_ = os.Rename(corruptDest, dbPath)
		return "", fmt.Errorf("copy backup: %w", err)
	}
	if err := dst.Close(); err != nil {
		return "", fmt.Errorf("close: %w", err)
	}
	// An older backup must not revive credentials revoked since it was taken.
	// The moved-aside original is the live state; when it is unreadable every
	// restored session, token and grant is revoked instead.
	if _, err := carryForwardRestoreCredentials(context.Background(), dir, corruptDest, dbPath, "auto-recovery"); err != nil {
		_ = os.Remove(dbPath)
		_ = os.Remove(dbPath + "-journal")
		_ = os.Rename(corruptDest, dbPath)
		_ = os.Rename(corruptDest+"-wal", dbPath+"-wal")
		_ = os.Rename(corruptDest+"-shm", dbPath+"-shm")
		return "", fmt.Errorf("carry credentials into the restored database: %w", err)
	}
	// The restored file is owned by WHOEVER ran the recovery. When that's
	// not the per-app user (router-side restore paths), the app process
	// could read but never write it - a crash loop at its next migration.
	// Align ownership with the app dir (no-op when already correct).
	chownToDirOwner(dbPath, dir)

	// A brand-new file now sits at dbPath (the old inode was renamed aside), so
	// any cached router handle is pointing at the wrong file. Rollback paths
	// rename the ORIGINAL inode back and are therefore unaffected.
	notifyDBFileReplaced(dbPath)
	return corruptDest, nil
}

func verifyPostMigrationAndRestore(dir string, db *sql.DB, backupPath string) error {
	return verifyPostMigrationAndRestoreWithLease(dir, db, backupPath, nil)
}

func verifyPostMigrationAndRestoreWithLease(dir string, db *sql.DB, backupPath string, lease *appMCPAuthorityLease) error {
	if err := postMigrationIntegrityCheck(db); err != nil {
		log.Printf("DB CORRUPTION (integrity_check) in %s: %v", dir, err)
		// Index damage rebuilds from the table data with no loss, as at open
		// (db.go); only what REINDEX cannot fix restores the snapshot.
		if _, rxErr := db.Exec("REINDEX"); rxErr == nil && postMigrationIntegrityCheck(db) == nil {
			log.Printf("DB REPAIR: %s - rebuilt indexes via REINDEX after integrity_check (no data loss)", dir)
			return reportPostMigrationDrift(dir, db)
		}
		return restoreAfterPostMigrationFailureWithLease(dir, db, backupPath, fmt.Errorf("integrity_check failed: %w", err), lease)
	}
	return reportPostMigrationDrift(dir, db)
}

// postMigrationIntegrityCheck is the full PRAGMA integrity_check the loader
// runs after a schema change. A variable so tests can count the runs.
var postMigrationIntegrityCheck = sqliteIntegrityCheck

// reportPostMigrationDrift logs columns the schema declares that the database
// lacks. It reads only table_info, so a load that changed nothing still runs it.
func reportPostMigrationDrift(dir string, db *sql.DB) error {
	models, err := LoadSchemaModelsForDrift(dir)
	if err != nil {
		return fmt.Errorf("post-migration drift load: %w", err)
	}
	if len(models) == 0 {
		return nil
	}
	drifts, err := DetectSchemaDrift(db, models)
	if err != nil {
		return fmt.Errorf("post-migration drift check: %w", err)
	}
	missingAdds := expectedAddMissingDrifts(drifts)
	if len(missingAdds) > 0 {
		// A column the drift parser expects is not physically present even
		// though Migrate reported success. This is NOT corruption, so we do NOT
		// auto-restore: the (older) pre-migrate backup also lacks the column, so
		// restoring it would (a) revert every write since the backup and (b)
		// re-detect the same drift on the next boot -> permanent crash-loop with
		// silent data loss. Surface it loudly and keep serving so an operator
		// can reconcile the schema. Only genuine corruption (the integrity_check
		// above) triggers an auto-restore.
		log.Printf("  WARNING: expected column(s) missing after migration: %s — serving anyway; reconcile the schema. NOT auto-restoring (would revert newer data and crash-loop).", formatDriftSummary(missingAdds))
	}
	logSchemaDrift(drifts)
	return nil
}

// maxLoggedDrifts bounds the per-issue lines one app load logs.
const maxLoggedDrifts = 20

// logSchemaDrift logs one line per drift issue after the count. It used to
// promise "the drift report below" and print none. Each issue's advice is a
// paragraph, so the log names the issue and `benmore check` explains it.
func logSchemaDrift(drifts []SchemaDrift) {
	if len(drifts) == 0 {
		return
	}
	log.Printf("  schema drift: %d issue(s) - `benmore check` explains each:", len(drifts))
	for i, d := range drifts {
		if i == maxLoggedDrifts {
			log.Printf("    ... and %d more", len(drifts)-maxLoggedDrifts)
			break
		}
		loc := d.Table
		if d.Column != "" {
			loc += "." + d.Column
		}
		log.Printf("    [%s] %s", d.Kind, loc)
	}
}

// sqliteQuickCheck runs PRAGMA quick_check - a fast structural b-tree scan that
// catches page-level corruption (malformed/2nd-reference) WITHOUT the expensive
// index-vs-table content cross-check that integrity_check does. Cheap enough to
// run on every boot; index/table mismatches are still caught by the
// post-migration integrity_check. Returns nil when the db reports "ok".
func sqliteQuickCheck(db *sql.DB) error {
	var msg string
	if err := db.QueryRow("PRAGMA quick_check(1)").Scan(&msg); err != nil {
		return err
	}
	if msg != "ok" {
		return fmt.Errorf("%s", msg)
	}
	return nil
}

func sqliteIntegrityCheck(db *sql.DB) error {
	rows, err := db.Query("PRAGMA integrity_check")
	if err != nil {
		return err
	}
	defer rows.Close()
	var problems []string
	for rows.Next() {
		var msg string
		if err := rows.Scan(&msg); err != nil {
			return err
		}
		if msg != "ok" {
			problems = append(problems, msg)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if len(problems) > 0 {
		return fmt.Errorf("%s", strings.Join(problems, "; "))
	}
	return nil
}

func expectedAddMissingDrifts(drifts []SchemaDrift) []SchemaDrift {
	var out []SchemaDrift
	for _, d := range drifts {
		if d.Kind == "missing_column" {
			out = append(out, d)
		}
	}
	return out
}

func formatDriftSummary(drifts []SchemaDrift) string {
	parts := make([]string, 0, len(drifts))
	for _, d := range drifts {
		if d.Column != "" {
			parts = append(parts, d.Table+"."+d.Column+" "+d.Kind)
		}
	}
	if len(parts) == 0 {
		return "unknown drift"
	}
	return strings.Join(parts, ", ")
}

func restoreAfterPostMigrationFailure(dir string, db *sql.DB, backupPath string, cause error) error {
	return restoreAfterPostMigrationFailureWithLease(dir, db, backupPath, cause, nil)
}

func restoreAfterPostMigrationFailureWithLease(dir string, db *sql.DB, backupPath string, cause error, lease *appMCPAuthorityLease) error {
	_ = db.Close()
	if backupPath == "" {
		return fmt.Errorf("post-migration verification failed with no backup to restore: %w", cause)
	}
	var err error
	if lease != nil {
		if err = invalidateAppMCPForRestoreWithLease(lease); err == nil {
			_, err = swapInBackupWithLease(dir, backupPath, cause, lease)
		}
	} else if os.Getenv("BENMORE_MCP_AUTHORITY_DIR") == "" {
		_, err = swapInBackupWithLease(dir, backupPath, cause, nil)
	} else {
		_, err = swapInBackup(dir, backupPath, cause)
	}
	if err != nil {
		return fmt.Errorf("post-migration verification failed and restore failed: %w (original: %v)", err, cause)
	}
	return fmt.Errorf("post-migration verification failed; auto-restored pre-migrate backup: %w", cause)
}

// restoreDatabase copies a backup file over data.db.
// The caller must close the active DB connection before calling this.
func restoreDatabase(dir string, backupPath string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	release, lease, err := beginAppMCPRestorePolicy(ctx, dir)
	if err != nil {
		return fmt.Errorf("connector restore lease: %w", err)
	}
	defer release()
	// Stages an earlier restore never removed go first; one that holds the
	// selected backup stays.
	keep := ""
	if rel, err := filepath.Rel(dir, backupPath); err == nil {
		keep, _ = restoreStageRel(rel)
	}
	sweepRestoreStages(dir, keep, 0)
	candidate, cleanup, err := prepareRestoreSnapshot(ctx, dir, backupPath)
	if err != nil {
		return err
	}
	defer cleanup()
	// The data rolls back; sign-in state stays what it is now.
	if _, err := carryForwardRestoreCredentials(ctx, dir, filepath.Join(dir, "data.db"), candidate, "local restore"); err != nil {
		return fmt.Errorf("carry live credentials into the restored database: %w", err)
	}
	_, err = installRestoreSnapshotWithLease(dir, candidate, lease)
	return err
}

// ===== Scheduled backups =====

const scheduledBackupPrefix = "scheduled-"

// scheduledBackup creates a scheduled backup of data.db.
// Returns the backup path on success.
func scheduledBackup(dir string) (string, error) {
	dbPath := filepath.Join(dir, "data.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return "", nil // no database to back up
	}

	backupDir := filepath.Join(dir, backupDirName)
	if err := prepareBackupDir(backupDir); err != nil {
		return "", err
	}

	timestamp := time.Now().UTC().Format("20060102T150405Z")
	backupPath := filepath.Join(backupDir, scheduledBackupPrefix+timestamp+".db")

	// Use VACUUM INTO for a transactionally-consistent snapshot, exactly like
	// backupDatabase. The previous raw io.Copy of data.db plus a SEPARATE copy
	// of the -wal under active writes produced an internally inconsistent
	// backup (the WAL frames and the base file could disagree) - if such a
	// backup were later selected by restore/auto-recovery it could fail
	// validation or silently lose committed transactions.
	if err := sqliteVacuumInto(dbPath, backupPath); err != nil {
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("vacuum into scheduled backup: %w", err)
	}
	if err := setBackupFileMode(backupPath); err != nil {
		return "", fmt.Errorf("set scheduled backup permissions: %w", err)
	}

	return backupPath, nil
}

// listScheduledBackups returns sorted scheduled backup file paths (oldest first).
func listScheduledBackups(dir string) []string {
	backupDir := filepath.Join(dir, backupDirName)
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return nil
	}

	var backups []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasPrefix(name, scheduledBackupPrefix) && strings.HasSuffix(name, ".db") && !strings.HasSuffix(name, "-wal") {
			backups = append(backups, filepath.Join(backupDir, name))
		}
	}
	sort.Strings(backups)
	return backups
}

// cleanupScheduledBackups removes all but the N most recent scheduled backups.
func cleanupScheduledBackups(dir string, keep int) {
	backups := listScheduledBackups(dir)
	if len(backups) <= keep {
		return
	}
	toRemove := backups[:len(backups)-keep]
	for _, path := range toRemove {
		os.Remove(path)
		os.Remove(path + "-wal")
		log.Printf("  scheduled backup cleanup: removed %s", filepath.Base(path))
	}
}

// StartBackupWorker starts a background goroutine that creates periodic database backups.
// Respects the keep count to prevent disk exhaustion.
//
// Every hot reload and restart starts a new worker, so the schedule is not
// counted from the worker's own start: a fresh interval timer per start meant
// an app pushed more often than its interval never got a scheduled backup
// (interval 10m, a push every 1-3 minutes: none for 17 minutes). The first
// backup is due one interval after the newest scheduled-* backup on disk, or,
// with none yet, one interval after the first worker start in this process.
func StartBackupWorker(app *App, config *BackupConfig) {
	if config == nil || config.Interval <= 0 {
		return
	}
	started := time.Now()
	app.scheduledBackupSince.CompareAndSwap(nil, &started)
	since := *app.scheduledBackupSince.Load()
	app.startWorker("backup.scheduled", func(stop <-chan struct{}) {
		wait := scheduledBackupDelay(app.Dir, config.Interval, since, time.Now())
		timer := time.NewTimer(wait)
		defer timer.Stop()
		log.Printf("  backup: scheduled every %s (keep %d), next in %s", config.Interval, config.Keep, wait.Round(time.Second))
		for {
			select {
			case <-stop:
				return
			case <-timer.C:
			}
			select {
			case <-stop:
				return
			default:
			}
			timer.Reset(runDueScheduledBackup(app, config, since))
		}
	})
}

// runDueScheduledBackup takes a scheduled backup if one is due and returns how
// long to wait before the next check. A reload starts the new worker without
// waiting for the old one, which may be part-way through a backup: the lock
// and the re-check under it make the new worker wait for that backup instead
// of taking a second one with the same timestamp name, whose failed VACUUM
// INTO would remove the other's file.
func runDueScheduledBackup(app *App, config *BackupConfig, since time.Time) time.Duration {
	app.scheduledBackupMu.Lock()
	defer app.scheduledBackupMu.Unlock()
	if wait := scheduledBackupDelay(app.Dir, config.Interval, since, time.Now()); wait > 0 {
		return wait
	}
	// After an attempt, success or not, wait a full interval: a failure leaves
	// no newer file, and re-reading the directory would retry it at once.
	path, err := scheduledBackup(app.Dir)
	if err != nil {
		log.Printf("  backup error: %s", err)
		return config.Interval
	}
	if path != "" {
		log.Printf("  backup: %s", filepath.Base(path))
		cleanupScheduledBackups(app.Dir, config.Keep)
	}
	return config.Interval
}

// scheduledBackupDelay is how long after now the next scheduled backup is due:
// one interval after the newest scheduled-* backup in dir (zero if that is
// already past), or one interval after since when there is none. A file dated
// after now (a clock that moved back) is not an anchor; it would otherwise
// hold off every backup until the clock caught up.
func scheduledBackupDelay(dir string, interval time.Duration, since, now time.Time) time.Duration {
	anchor := since
	var newest time.Time
	for _, path := range listScheduledBackups(dir) {
		taken, ok := backupNameTime(path)
		if ok && !taken.After(now) && taken.After(newest) {
			newest = taken
		}
	}
	if !newest.IsZero() {
		anchor = newest
	}
	return max(anchor.Add(interval).Sub(now), 0)
}

// backupNameTime is the UTC time in a backup's file name.
func backupNameTime(path string) (time.Time, bool) {
	const layout = "20060102T150405Z"
	ts := backupTimestamp(path)
	if len(ts) < len(layout) {
		return time.Time{}, false
	}
	taken, err := time.Parse(layout, ts[:len(layout)])
	return taken, err == nil
}

// backupTimestamp extracts the sortable UTC timestamp (20060102T150405Z) from a
// backup filename, stripping whichever prefix it carries. Sorting by this rather
// than the whole filename prevents the PREFIX from dominating the order: a
// scheduled-* backup is not "newer" than a pre-migrate-* one just because
// 's' > 'p'. Without this, rollback/auto-restore could pick a days-old scheduled
// backup over a minutes-old pre-migrate one and silently discard recent data.
func backupTimestamp(path string) string {
	b := filepath.Base(path)
	b = strings.TrimSuffix(b, ".db")
	b = strings.TrimPrefix(b, backupPrefix)
	b = strings.TrimPrefix(b, scheduledBackupPrefix)
	return b
}

// sortBackupsByTimestamp orders backup paths oldest-first by their timestamp
// suffix (prefix-independent).
func sortBackupsByTimestamp(backups []string) {
	sort.Slice(backups, func(i, j int) bool {
		return backupTimestamp(backups[i]) < backupTimestamp(backups[j])
	})
}

// listAllBackups returns all backup file paths (both pre-migrate and scheduled), sorted oldest first.
func listAllBackups(dir string) []string {
	backupDir := filepath.Join(dir, backupDirName)
	entries, err := os.ReadDir(backupDir)
	if err != nil {
		return nil
	}

	var backups []string
	for _, entry := range entries {
		name := entry.Name()
		if strings.HasSuffix(name, ".db") && !strings.HasSuffix(name, "-wal") {
			if strings.HasPrefix(name, backupPrefix) || strings.HasPrefix(name, scheduledBackupPrefix) {
				backups = append(backups, filepath.Join(backupDir, name))
			}
		}
	}
	// Sort by timestamp suffix, not filename: the two prefixes would otherwise
	// order all scheduled-* after all pre-migrate-* regardless of recency.
	sortBackupsByTimestamp(backups)
	return backups
}
