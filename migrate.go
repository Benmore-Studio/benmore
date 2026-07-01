//go:build !cli

package main

import (
	"database/sql"
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
}

// Migrate compares schema.sql tables against the live database and applies non-destructive changes.
func Migrate(db *sql.DB, tables []Table, force bool) (*MigrateResult, error) {
	result := &MigrateResult{}
	// Collect every additive ADD COLUMN across ALL tables and apply them in ONE
	// transaction (below), so a failure on a later table rolls back the columns
	// already added to earlier tables - no half-migrated cross-table schema.
	// Nullability rebuilds (force-only, per-table by nature) are deferred to
	// after the additive pass for the same reason.
	type pendingAdd struct {
		table string
		col   Column
	}
	type pendingRebuild struct {
		table string
		fixes map[string]bool
	}
	var pendingAdds []pendingAdd
	var pendingRebuilds []pendingRebuild

	for _, table := range tables {
		exists, err := tableExists(db, table.Name)
		if err != nil {
			return result, err
		}

		if !exists {
			// Table doesn't exist - the CREATE TABLE in LoadSchema handles this
			for _, col := range table.Columns {
				result.Added = append(result.Added, fmt.Sprintf("%s.%s %s (new table)", table.Name, col.Name, col.Type))
			}
			continue
		}

		// Table exists - check for new columns
		liveCols, err := GetTableColumns(db, table.Name)
		if err != nil {
			return result, err
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
						result.Blocked = append(result.Blocked, fmt.Sprintf(
							"ALTER %s.%s nullability (DB %s → schema %s) - BLOCKED (requires --force to rebuild table)",
							table.Name, col.Name, from, to))
					}
				}
				continue
			}

			newAdds = append(newAdds, col)
		}

		for _, col := range newAdds {
			pendingAdds = append(pendingAdds, pendingAdd{table: table.Name, col: col})
		}

		// Defer nullability rebuilds to after the additive pass (see below).
		if force && len(nullFixes) > 0 {
			pendingRebuilds = append(pendingRebuilds, pendingRebuild{table: table.Name, fixes: nullFixes})
		}

		// Check for columns in DB but not in schema (potential drops)
		schemaColMap := make(map[string]bool)
		for _, c := range table.Columns {
			schemaColMap[strings.ToLower(c.Name)] = true
		}
		for _, liveCol := range liveCols {
			if !schemaColMap[strings.ToLower(liveCol.Name)] {
				result.Blocked = append(result.Blocked, fmt.Sprintf("DROP %s.%s - column exists in DB but not in schema.sql (use --force to drop)", table.Name, liveCol.Name))
			}
		}
	}

	// Apply every additive ADD COLUMN across all tables in ONE transaction.
	// SQLite DDL is transactional inside an explicit tx, so any single failure
	// rolls back ALL adds - earlier tables are never left half-migrated.
	if len(pendingAdds) > 0 {
		tx, err := db.Begin()
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

// DiffSchema returns what migrations would run without executing them.
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
				// Preview attribute divergence (nullability) the same way the
				// destructive-drop case is surfaced. PK columns excluded (see
				// Migrate - SQLite rowid-alias notnull quirk).
				if col.NotNull != liveCol.NotNull && !col.PK && !liveCol.PK {
					result.Blocked = append(result.Blocked, fmt.Sprintf(
						"ALTER %s.%s nullability (DB %s → schema %s) - requires --force to rebuild table",
						table.Name, col.Name, nullLabel(liveCol.NotNull), nullLabel(col.NotNull)))
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
				result.Blocked = append(result.Blocked, fmt.Sprintf("DROP COLUMN %s.%s - BLOCKED (destructive, requires --force)", table.Name, liveCol.Name))
			}
		}
	}

	return result, nil
}

func expandContractGuidance(diff *MigrateResult) []string {
	if diff == nil {
		return nil
	}
	adds := parseAdditiveColumnChanges(diff.Added)
	drops := parseBlockedDropColumnChanges(diff.Blocked)
	var guidance []string
	for _, add := range adds {
		for _, drop := range drops {
			if !strings.EqualFold(add.Table, drop.Table) {
				continue
			}
			guidance = append(guidance, fmt.Sprintf(
				"rename-shaped %s.%s -> %s.%s: use expand/contract. First promote the additive column without force, dual-write and backfill %s.%s, switch reads to %s.%s with fallback, then use force only for the final contract drop after backup verification.",
				drop.Table, drop.Column, add.Table, add.Column, add.Table, add.Column, add.Table, add.Column,
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
	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("ALTER TABLE %s ADD COLUMN %s", table, col.Name))
	if col.Type != "" {
		sb.WriteString(" " + col.Type)
	}
	if col.Default != "" {
		sb.WriteString(" DEFAULT " + col.Default)
	}
	return sb.String()
}

func tableExists(db *sql.DB, name string) (bool, error) {
	var count int
	err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?", name).Scan(&count)
	return count > 0, err
}

// ===== Pre-migration backup & rollback =====

const (
	backupDirName    = ".benmore/backups"
	backupPrefix     = "pre-migrate-"
	maxBackups       = 10
	backupPermission = 0600
)

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
func backupDatabase(dir string) (string, error) {
	dbPath := filepath.Join(dir, "data.db")
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		return "", nil // no database to back up
	}

	backupDir := filepath.Join(dir, backupDirName)
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", fmt.Errorf("create backup dir: %w", err)
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

	if err := sqliteVacuumInto(dbPath, backupPath); err != nil {
		// Don't leave a half-written file behind if the snapshot failed.
		_ = os.Remove(backupPath)
		return "", fmt.Errorf("vacuum into backup: %w", err)
	}
	// VACUUM INTO honors the source's encryption settings but writes
	// with the default mode (0644 minus umask). Tighten to match the
	// rest of the backup-dir contract.
	_ = os.Chmod(backupPath, backupPermission)

	log.Printf("  backup: %s", backupPath)
	return backupPath, nil
}

// sqliteVacuumInto opens `srcPath` and runs `VACUUM INTO 'dstPath'`.
// The source is opened read-only so we never block a writer; SQLite
// itself takes a consistent snapshot of every page under the hood.
// `dstPath` must not exist - VACUUM INTO refuses to overwrite as a
// safety belt.
func sqliteVacuumInto(srcPath, dstPath string) error {
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
	// backups are sorted oldest-first by name (timestamps sort lexicographically)
	toRemove := backups[:len(backups)-keep]
	for _, path := range toRemove {
		os.Remove(path)
		os.Remove(path + "-wal") // cleanup companion WAL if present
		log.Printf("  backup cleanup: removed %s", filepath.Base(path))
	}
}

// listBackups returns sorted backup file paths (oldest first).
func listBackups(dir string) []string {
	backupDir := filepath.Join(dir, backupDirName)
	entries, err := os.ReadDir(backupDir)
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
	sort.Strings(backups)
	return backups
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
	backupDir := filepath.Join(dir, backupDirName)

	// Collect candidates - both pre-migrate-* and scheduled-* qualify.
	var candidates []string
	if entries, err := os.ReadDir(backupDir); err == nil {
		for _, e := range entries {
			n := e.Name()
			if strings.HasSuffix(n, "-wal") || strings.HasSuffix(n, "-shm") {
				continue
			}
			if !strings.HasSuffix(n, ".db") {
				continue
			}
			if strings.HasPrefix(n, backupPrefix) || strings.HasPrefix(n, scheduledBackupPrefix) {
				candidates = append(candidates, filepath.Join(backupDir, n))
			}
		}
	}
	if len(candidates) == 0 {
		return false, fmt.Errorf("auto-restore: no backups found in %s (cause: %v)", backupDir, cause)
	}
	// Newest first - sort by the timestamp suffix, not the whole filename, so a
	// recent pre-migrate-* backup isn't shadowed by an older scheduled-* one
	// (the prefix would otherwise dominate a plain string sort).
	sort.Slice(candidates, func(i, j int) bool {
		return backupTimestamp(candidates[i]) > backupTimestamp(candidates[j])
	})

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

	corruptDest, err := swapInBackup(dir, pickedBackup, cause)
	if err != nil {
		return false, fmt.Errorf("auto-restore: %w", err)
	}
	log.Printf("auto-restore: restored data.db ← %s; original kept at %s",
		filepath.Base(pickedBackup), filepath.Base(corruptDest))
	return true, nil
}

func swapInBackup(dir, backupPath string, cause error) (string, error) {
	if err := validateSQLiteDB(backupPath); err != nil {
		return "", fmt.Errorf("invalid backup: %w", err)
	}
	dbPath := filepath.Join(dir, "data.db")
	// Move the corrupt original aside so operators can post-mortem
	// (NEVER delete on auto-recovery - data loss should require a
	// deliberate human decision).
	corruptDest := dbPath + ".corrupt-" + time.Now().UTC().Format("20060102T150405Z")
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

	return corruptDest, nil
}

func verifyPostMigrationAndRestore(dir string, db *sql.DB, backupPath string) error {
	if err := sqliteIntegrityCheck(db); err != nil {
		return restoreAfterPostMigrationFailure(dir, db, backupPath, fmt.Errorf("integrity_check failed: %w", err))
	}
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
	if len(drifts) > 0 {
		log.Printf("  schema drift: %d issue(s) - see the drift report below", len(drifts))
	}
	return nil
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
	_ = db.Close()
	if backupPath == "" {
		return fmt.Errorf("post-migration verification failed with no backup to restore: %w", cause)
	}
	if _, err := swapInBackup(dir, backupPath, cause); err != nil {
		return fmt.Errorf("post-migration verification failed and restore failed: %w (original: %v)", err, cause)
	}
	return fmt.Errorf("post-migration verification failed; auto-restored pre-migrate backup: %w", cause)
}

// restoreDatabase copies a backup file over data.db.
// The caller must close the active DB connection before calling this.
func restoreDatabase(dir string, backupPath string) error {
	if err := validateSQLiteDB(backupPath); err != nil {
		return fmt.Errorf("invalid backup: %w", err)
	}

	dbPath := filepath.Join(dir, "data.db")

	// Remove WAL and SHM files for a clean restore
	os.Remove(dbPath + "-wal")
	os.Remove(dbPath + "-shm")

	src, err := os.Open(backupPath)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer src.Close()

	dst, err := os.OpenFile(dbPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		return fmt.Errorf("open database for restore: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return fmt.Errorf("restore copy: %w", err)
	}

	// Also restore WAL if the backup has one
	walBackup := backupPath + "-wal"
	if _, err := os.Stat(walBackup); err == nil {
		walSrc, err := os.Open(walBackup)
		if err == nil {
			defer walSrc.Close()
			walDst, err := os.OpenFile(dbPath+"-wal", os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
			if err == nil {
				defer walDst.Close()
				io.Copy(walDst, walSrc)
			}
		}
	}

	return nil
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
	if err := os.MkdirAll(backupDir, 0700); err != nil {
		return "", fmt.Errorf("create backup dir: %w", err)
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
	_ = os.Chmod(backupPath, backupPermission)

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
func StartBackupWorker(app *App, config *BackupConfig) {
	if config == nil || config.Interval <= 0 {
		return
	}
	safeGo("backup.scheduled", func() {
		ticker := time.NewTicker(config.Interval)
		defer ticker.Stop()
		log.Printf("  backup: scheduled every %s (keep %d)", config.Interval, config.Keep)
		for range ticker.C {
			path, err := scheduledBackup(app.Dir)
			if err != nil {
				log.Printf("  backup error: %s", err)
				continue
			}
			if path != "" {
				log.Printf("  backup: %s", filepath.Base(path))
				cleanupScheduledBackups(app.Dir, config.Keep)
			}
		}
	})
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
