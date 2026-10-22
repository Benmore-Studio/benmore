//go:build !cli

package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// RenameColumn and DropColumn use SQLite's native schema transformations. A
// dependency error is not evidence of an old SQLite version: rebuilding after
// any such error used to drop constraints and cascade-delete dependent rows.
func RenameColumn(db *sql.DB, table, oldName, newName string) error {
	_, err := db.Exec(fmt.Sprintf("ALTER TABLE %s RENAME COLUMN %s TO %s", quoteIdent(table), quoteIdent(oldName), quoteIdent(newName)))
	if err != nil {
		return fmt.Errorf("rename %s.%s: %w", table, oldName, err)
	}
	log.Printf("MIGRATE: renamed %s.%s → %s", table, oldName, newName)
	return nil
}

func DropColumn(db *sql.DB, table, column string) error {
	_, err := db.Exec(fmt.Sprintf("ALTER TABLE %s DROP COLUMN %s", quoteIdent(table), quoteIdent(column)))
	if err != nil {
		return fmt.Errorf("drop %s.%s (remove dependent indexes or triggers explicitly first): %w", table, column, err)
	}
	log.Printf("MIGRATE: dropped %s.%s", table, column)
	return nil
}

func AlterColumnType(db *sql.DB, table, column, newType string) error {
	return rebuildTable(db, table, func(col Column) *Column {
		if col.Name == column {
			col.Type = newType
		}
		return &col
	})
}

// rebuildTable changes column types/nullability while preserving the original
// table constraints/options, every index and every trigger. Referenced parent
// tables require an explicit migration: DROP TABLE can execute ON DELETE
// actions even inside a transaction, so refuse before any DDL or copying.
func rebuildTable(db *sql.DB, table string, transform func(Column) *Column) error {
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = rebuildTableInTx(tx, table, func(original, temporary string, cols []Column) (string, error) {
		oldCols, nextCols := map[string]Column{}, map[string]Column{}
		for _, col := range cols {
			next := transform(col)
			if next == nil || next.Name != col.Name || next.PK != col.PK || next.Default != col.Default {
				return "", fmt.Errorf("only column type and nullability changes are supported")
			}
			key := sqliteIdentifierFold(col.Name)
			oldCols[key], nextCols[key] = col, *next
		}
		return rebuildCreateSQL(original, temporary, oldCols, nextCols)
	})
	if err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit rebuild: %w", err)
	}
	log.Printf("MIGRATE: rebuilt table %s", table)
	return nil
}

// rebuildTableInTx shares the preservation and refusal rules with Prisma
// relation repairs. The caller owns the transaction; returned SQL is the exact
// rebuild journal, including statements attempted before an error.
func rebuildTableInTx(tx *sql.Tx, table string, rewrite func(string, string, []Column) (string, error)) (statements []string, err error) {
	exec := func(statement string) error {
		statements = append(statements, statement+";")
		_, err := tx.Exec(statement)
		return err
	}
	if err := checkTableRebuildReferences(tx, table); err != nil {
		return statements, err
	}

	cols, err := tableColumnsWith(tx, table)
	if err != nil {
		return statements, err
	}
	if len(cols) == 0 {
		return statements, fmt.Errorf("rebuild: table %s has no ordinary columns", table)
	}
	oldCols := map[string]Column{}
	var names []string
	for _, col := range cols {
		key := sqliteIdentifierFold(col.Name)
		oldCols[key] = col
		names = append(names, col.Name)
	}
	// Hidden rowids are observable (including by external-content FTS). Copy
	// them too, even when the primary key is TEXT or rows have gaps.
	var withoutRowID int
	if err := tx.QueryRow("SELECT wr FROM pragma_table_list WHERE schema='main' AND name=?", table).Scan(&withoutRowID); err != nil {
		return statements, fmt.Errorf("inspect rebuild table options: %w", err)
	}
	if withoutRowID == 0 {
		rowID := ""
		for _, candidate := range []string{"rowid", "_rowid_", "oid"} {
			if _, shadowed := oldCols[candidate]; !shadowed {
				rowID = candidate
				break
			}
		}
		if rowID == "" {
			return statements, fmt.Errorf("rebuild %s: all hidden rowid aliases are shadowed; use an explicit migration", table)
		}
		names = append([]string{rowID}, names...)
	}
	var original string
	if err := tx.QueryRow("SELECT sql FROM sqlite_schema WHERE type='table' AND name=?", table).Scan(&original); err != nil {
		return statements, fmt.Errorf("read rebuild schema: %w", err)
	}
	tmpTable := table + "_migrate_tmp"
	createSQL, err := rewrite(original, tmpTable, cols)
	if err != nil {
		return statements, fmt.Errorf("rebuild %s: %w", table, err)
	}

	rows, err := tx.Query(`SELECT name, sql FROM sqlite_schema
		WHERE tbl_name=? AND type IN ('index','trigger') AND sql IS NOT NULL
		ORDER BY type, name`, table)
	if err != nil {
		return statements, fmt.Errorf("read rebuild dependencies: %w", err)
	}
	var dependencies [][2]string
	for rows.Next() {
		var name, ddl string
		if err := rows.Scan(&name, &ddl); err != nil {
			rows.Close()
			return statements, err
		}
		dependencies = append(dependencies, [2]string{name, ddl})
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return statements, err
	}
	// Preserve AUTOINCREMENT's high-water mark even if the largest rows were
	// deleted before this migration; recreating it from MAX(id) reuses IDs.
	var sequence sql.NullInt64
	if dbTableExists(tx, "sqlite_sequence") {
		err := tx.QueryRow("SELECT seq FROM sqlite_sequence WHERE name=?", table).Scan(&sequence)
		if err != nil && err != sql.ErrNoRows {
			return statements, err
		}
	}

	if err := exec(createSQL); err != nil {
		return statements, fmt.Errorf("create rebuild table: %w", err)
	}
	columns := strings.Join(quoteIdents(names), ", ")
	if err := exec(fmt.Sprintf("INSERT INTO %s (%s) SELECT %s FROM %s", quoteIdent(tmpTable), columns, columns, quoteIdent(table))); err != nil {
		return statements, fmt.Errorf("copy rebuild data: %w", err)
	}
	// Validate even if a caller opened SQLite with foreign_keys disabled.
	if err := validateTableForeignKeys(tx, tmpTable); err != nil {
		return statements, err
	}
	if err := exec("DROP TABLE " + quoteIdent(table)); err != nil {
		return statements, fmt.Errorf("drop old: %w", err)
	}
	if err := exec(fmt.Sprintf("ALTER TABLE %s RENAME TO %s", quoteIdent(tmpTable), quoteIdent(table))); err != nil {
		return statements, fmt.Errorf("rename rebuild table: %w", err)
	}
	for _, dependency := range dependencies {
		if err := exec(dependency[1]); err != nil {
			return statements, fmt.Errorf("restore rebuild dependency %s: %w", dependency[0], err)
		}
	}
	if sequence.Valid {
		if err := exec(fmt.Sprintf("UPDATE sqlite_sequence SET seq=MAX(seq, %d) WHERE name='%s'", sequence.Int64, strings.ReplaceAll(table, "'", "''"))); err != nil {
			return statements, err
		}
	}
	return statements, nil
}

// Shared with read-only upgrade preflight: DROP TABLE may run ON DELETE
// actions, so automatic rebuilds refuse incoming references before any DDL.
func checkTableRebuildReferences(q mutationQuerier, table string) error {
	var child string
	err := q.QueryRow(`SELECT m.name FROM sqlite_schema AS m
		JOIN pragma_foreign_key_list(m.name) AS f
		WHERE m.type='table' AND f."table" = ? COLLATE NOCASE LIMIT 1`, table).Scan(&child)
	if err == nil {
		return fmt.Errorf("rebuild %s: referenced by foreign key in %s; use an explicit migration that preserves related rows", table, child)
	}
	if err != sql.ErrNoRows {
		return fmt.Errorf("inspect rebuild foreign keys: %w", err)
	}
	return nil
}

// Rewrite only the requested column attributes in the catalog DDL. Building
// from PRAGMA table_info alone loses UNIQUE/CHECK/FK/COLLATE, generated columns,
// composite keys, WITHOUT ROWID and STRICT. All untouched SQL is retained.
func rebuildCreateSQL(original, temporary string, oldCols, nextCols map[string]Column) (string, error) {
	tokens := sqlTokenize(original)
	if len(tokens) < 4 || !strings.EqualFold(tokens[0].text, "CREATE") || !strings.EqualFold(tokens[1].text, "TABLE") {
		return "", fmt.Errorf("unsupported table declaration")
	}
	start, end, depth := -1, -1, 0
	for _, token := range tokens {
		if token.kind != sqlTokPunct {
			continue
		}
		if token.text == "(" {
			if start < 0 {
				start = token.start
			}
			depth++
		} else if token.text == ")" {
			depth--
			if depth == 0 && start >= 0 {
				end = token.start
				break
			}
		}
	}
	if start < 0 || end < 0 {
		return "", fmt.Errorf("unsupported table declaration")
	}
	parts := splitSchemaParts(original[start+1 : end])
	for i, part := range parts {
		parsed := parseColumnDef(part)
		if parsed == nil {
			continue
		} // table constraint, retained verbatim
		key := sqliteIdentifierFold(parsed.Name)
		old, exists := oldCols[key]
		if !exists {
			continue
		} // generated column, not copied or changed
		var err error
		parts[i], err = rebuildColumnSQL(part, old, nextCols[key])
		if err != nil {
			return "", err
		}
	}
	return "CREATE TABLE " + quoteIdent(temporary) + " (" + strings.Join(parts, ", ") + ")" + original[end+1:], nil
}

func rebuildColumnSQL(definition string, old, next Column) (string, error) {
	tokens := sqlTokenize(definition)
	type edit struct {
		start, end int
		text       string
	}
	var edits []edit
	depth, typeEnd, removed := 0, len(definition), false
	for i := 1; i < len(tokens); i++ {
		token := tokens[i]
		if token.kind == sqlTokPunct {
			if token.text == "(" {
				depth++
			}
			if token.text == ")" {
				depth--
			}
			continue
		}
		if depth != 0 || token.kind != sqlTokWord {
			continue
		}
		switch strings.ToUpper(token.text) {
		case "PRIMARY", "NOT", "NULL", "UNIQUE", "CHECK", "DEFAULT", "COLLATE", "REFERENCES", "GENERATED", "AS", "CONSTRAINT":
			if typeEnd == len(definition) {
				typeEnd = token.start
			}
		}
		if old.NotNull && !next.NotNull && strings.EqualFold(token.text, "NOT") && i+1 < len(tokens) && tokens[i+1].kind == sqlTokWord && strings.EqualFold(tokens[i+1].text, "NULL") {
			start, end := token.start, tokens[i+1].end
			if i >= 3 && tokens[i-2].kind == sqlTokWord && strings.EqualFold(tokens[i-2].text, "CONSTRAINT") {
				start = tokens[i-2].start
			}
			if i+4 < len(tokens) && strings.EqualFold(tokens[i+2].text, "ON") && strings.EqualFold(tokens[i+3].text, "CONFLICT") {
				end = tokens[i+4].end
			}
			edits = append(edits, edit{start, end, ""})
			removed = true
		}
	}
	if old.Type != next.Type {
		edits = append(edits, edit{tokens[0].end, typeEnd, " " + quoteDeclType(next.Type) + " "})
	}
	if old.NotNull && !next.NotNull && !removed {
		return "", fmt.Errorf("cannot remove implicit NOT NULL from %s", old.Name)
	}
	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	for _, e := range edits {
		definition = definition[:e.start] + e.text + definition[e.end:]
	}
	if !old.NotNull && next.NotNull {
		definition += " NOT NULL"
	}
	return definition, nil
}

// RunMigrationFile executes a .sql migration file.
// isBenignMigrationError reports whether a migration statement error means the
// desired schema change is ALREADY in place (so the statement can be skipped
// as a no-op). These are SQLite schema-level errors that do NOT poison the
// surrounding transaction, so the rest of the migration file still applies.
func isBenignMigrationError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "duplicate column name") ||
		strings.Contains(msg, "already exists")
}

// sqlQuerier is the read surface shared by *sql.DB and *sql.Tx, so schema
// checks can run against whichever handle the caller is inside.
type sqlQuerier interface {
	Query(query string, args ...any) (*sql.Rows, error)
}

// dbColumnExists reports whether a live table has a given column.
func dbColumnExists(q sqlQuerier, table, col string) bool {
	rows, err := q.Query("SELECT 1 FROM pragma_table_info(?) WHERE name = ?", table, col)
	if err != nil {
		return false
	}
	defer rows.Close()
	return rows.Next()
}

// dbTableExists reports whether a table exists.
func dbTableExists(q sqlQuerier, table string) bool {
	rows, err := q.Query("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", table)
	if err != nil {
		return false
	}
	defer rows.Close()
	return rows.Next()
}

// renameColumnStmtRe captures `ALTER TABLE <t> RENAME [COLUMN] <src> TO <tgt>`.
// The optional COLUMN keyword covers SQLite's legacy rename-column form; a
// table rename (`RENAME TO <x>`) cannot match because it has no <src> token
// before TO.
var renameColumnStmtRe = regexp.MustCompile(
	`(?is)^\s*ALTER\s+TABLE\s+["'\[]?(\w+)["'\]]?\s+RENAME\s+(?:COLUMN\s+)?["'\[]?(\w+)["'\]]?\s+TO\s+["'\[]?(\w+)["'\]]?\s*;?\s*$`,
)

// renameTableStmtRe captures `ALTER TABLE <src> RENAME TO <tgt>`.
var renameTableStmtRe = regexp.MustCompile(
	`(?is)^\s*ALTER\s+TABLE\s+["'\[]?(\w+)["'\]]?\s+RENAME\s+TO\s+["'\[]?(\w+)["'\]]?\s*;?\s*$`,
)

// isRenameAlreadyApplied reports whether a failed RENAME statement's desired
// end state is ALREADY in place: the rename source is gone but the target
// exists. This happens on fresh databases - the schema sync creates the
// TARGET column/table directly, so a handwritten `ALTER TABLE x RENAME COLUMN
// old TO new` fails with `no such column: old` even though the schema is
// exactly what the migration wanted. Deliberately narrow: the statement must
// be a pure RENAME, the error must name the missing source, and the target's
// existence (and the source's absence) is verified against the live schema
// via q - never inferred from the error text alone. Anything else still
// fails the migration.
func isRenameAlreadyApplied(q sqlQuerier, stmt string, err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if m := renameColumnStmtRe.FindStringSubmatch(stmt); m != nil {
		table, src, tgt := m[1], m[2], m[3]
		return strings.Contains(msg, "no such column") &&
			strings.Contains(msg, strings.ToLower(src)) &&
			!dbColumnExists(q, table, src) &&
			dbColumnExists(q, table, tgt)
	}
	if m := renameTableStmtRe.FindStringSubmatch(stmt); m != nil {
		src, tgt := m[1], m[2]
		return strings.Contains(msg, "no such table") &&
			strings.Contains(msg, strings.ToLower(src)) &&
			!dbTableExists(q, src) &&
			dbTableExists(q, tgt)
	}
	return false
}

func RunMigrationFile(db *sql.DB, path, name, recordSQL string) error {
	return runMigrationFileCtx(context.Background(), db, path, name, recordSQL)
}

// runMigrationFileCtx applies one migration file; the context bounds every
// statement (an interrupted statement rolls the whole file back).
func runMigrationFileCtx(ctx context.Context, db *sql.DB, path, name, recordSQL string) error {
	data, err := readFileBytes(path)
	if err != nil {
		return err
	}
	return runMigrationDataCtx(ctx, db, data, name, recordSQL)
}

func runMigrationDataCtx(ctx context.Context, db *sql.DB, data []byte, name, recordSQL string) error {
	// Files generated by ApplyPrismaMigration carry both UP and DOWN
	// sections separated by `-- DOWN --`. We only run the UP block
	// here. Without this guard, on a fresh deploy where the data.db
	// is empty but migrations/ has prior files, this function used to
	// execute the entire file - creating tables in the UP section
	// then immediately dropping them via the DOWN section. The table
	// looked like it appeared (CREATE succeeded), then vanished, with
	// a misleading "applied 0001" log line.
	//
	// Legacy migration files without a `-- DOWN --` marker still run
	// in full via extractMigrationSection's fallback (returns the
	// whole body as UP).
	upSQL, _ := extractMigrationSection(string(data))

	statements := splitStatements(upSQL)
	// Apply every statement in the file inside ONE transaction so a mid-file
	// failure rolls the whole file back instead of committing a partial prefix.
	// Without this, a file that failed on statement N left 1..N-1 committed but
	// unrecorded, so the next boot re-ran from the top and the already-applied
	// prefix errored ("duplicate column") forever - a wedged, half-migrated
	// schema. Rolling back on failure means a retry always starts clean.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	for _, stmt := range statements {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" || strings.HasPrefix(stmt, "--") {
			continue
		}
		// SQLite itself checks UNIQUE in this transaction. A separate GROUP BY
		// preflight treats NULL as duplicate, misses partial/collated semantics,
		// and cannot see a dedupe performed by preceding migration statements.
		if err := dropFrameworkIndexesForStatement(tx, stmt); err != nil { // scoping_indexes.go
			return fmt.Errorf("migration %s: %w", truncate(stmt, 60), err)
		}
		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			// Idempotency: if the desired change is ALREADY present (the column /
			// table / index was created by an earlier schema sync or a prior
			// partial run), skip the statement instead of failing the file. A
			// "duplicate column name" used to abort the whole migration, which
			// then never got recorded in _benmore_migrations and re-ran on EVERY
			// boot - emitting `migration warning: ... duplicate column name: X`
			// in perpetuity. SQLite leaves the transaction usable after these
			// schema-level errors, so the remaining statements still apply.
			if isBenignMigrationError(err) {
				log.Printf("  migration: skipping already-applied statement (%v)", err)
				continue
			}
			// Same idempotency for RENAMEs: a fresh DB gets the TARGET
			// column/table straight from the schema sync, so the rename's
			// source is missing but the end state is already correct
			// (e.g. `RENAME COLUMN role TO solar_role` in a user migration
			// on a DB born with solar_role). Without this the file rolled back,
			// never recorded, and warned on every boot. Checked against the
			// tx so it sees renames from earlier statements in this file.
			if isRenameAlreadyApplied(tx, stmt, err) {
				log.Printf("  migration: skipping already-applied rename (%v)", err)
				continue
			}
			return fmt.Errorf("migration %s: %w", truncate(stmt, 60), err)
		}
	}
	// Record inside the SAME tx: apply + record are atomic, so a crash between
	// them can no longer leave an applied-but-unrecorded file that re-runs.
	if _, err := tx.ExecContext(ctx, recordSQL, name); err != nil {
		return fmt.Errorf("record migration %s: %w", name, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit migration: %w", err)
	}
	committed = true
	return nil
}

// RunMigrations checks for a migrations/ directory and runs any .sql files
// that haven't been run yet (tracked in _benmore_migrations table).
func RunMigrations(db *sql.DB, dir string) error {
	return runMigrations(db, dir, nil)
}

func runMigrations(db *sql.DB, dir string, beforeApply func() error) error {
	return runMigrationsCtx(context.Background(), db, dir, beforeApply)
}

// beforeApply runs once, immediately before the first pending migration. Keep
// backup selection next to the authoritative ledger check so an unchanged
// startup/reload never copies the entire database just to discover no work.
func runMigrationsCtx(ctx context.Context, db *sql.DB, dir string, beforeApply func() error) error {
	return runMigrationsCtxFromSources(ctx, db, dir, beforeApply, nil)
}
func runMigrationsCtxFromSources(ctx context.Context, db *sql.DB, dir string, beforeApply func() error, captured map[string][]byte) error {
	names, err := migrationSourceNames(dir, captured)
	if err != nil {
		return fmt.Errorf("read migrations: %w", err)
	}
	if names == nil {
		return nil
	}
	migrationsDir := filepath.Join(dir, "migrations")

	// Legacy (schema.sql-only) apps: ensure a tracking table. On schema.prisma
	// apps ApplyPrismaMigration already created a richer 5-column table
	// (source/source_hash NOT NULL), so this IF NOT EXISTS is a no-op there.
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_migrations (
		name TEXT PRIMARY KEY,
		applied_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`); err != nil {
		return fmt.Errorf("create migration ledger: %w", err)
	}

	// The table has two possible shapes; satisfy whichever exists.
	recordSQL := "INSERT INTO _benmore_migrations (name) VALUES (?)"
	if dbColumnExists(db, "_benmore_migrations", "source") {
		recordSQL = "INSERT INTO _benmore_migrations (name, source, source_hash) VALUES (?, '', '')"
	}

	for _, n := range names {

		// Check if already applied
		var count int
		if err := db.QueryRow("SELECT COUNT(*) FROM _benmore_migrations WHERE name = ?", n).Scan(&count); err != nil {
			return fmt.Errorf("migration dedupe check %s: %w", n, err)
		}
		if count > 0 {
			continue
		}
		if beforeApply != nil {
			if err := beforeApply(); err != nil {
				return err
			}
			beforeApply = nil
		}

		data, err := readMigrationSource(dir, n, captured)
		if err == nil {
			err = runMigrationDataCtx(ctx, db, data, n, recordSQL)
		}
		if err != nil {
			if ctx.Err() != nil {
				// Out of time is not a defect in the file: leave it in place for the
				// app's own boot, which has no deadline.
				return fmt.Errorf("migration %s did not finish within the validation time limit (it is applied when the app itself starts): %w", n, err)
			}
			// Rename so a persistently-failing file does not re-attempt every
			// reload/boot (mirrors ApplyPrismaMigration's .failed handling).
			// Fixing = the user renames it back.
			// A captured failure cannot rename a file which may now contain
			// unrelated replacement bytes. Ordinary disk loads keep their behavior.
			if captured == nil {
				failed := filepath.Join(migrationsDir, n+".failed.sql")
				if rnErr := os.Rename(filepath.Join(migrationsDir, n), failed); rnErr != nil {
					log.Printf("  migration: could not rename failed file %s: %v", n, rnErr)
				}
			}
			return fmt.Errorf("migration %s: %w", n, err)
		}
		log.Printf("  migration: applied %s", n)
	}

	return nil
}

// runUserMigrationsWithBackup snapshots the DB only when there are pending
// migrations/*.sql. Used on both cold boot and the SIGHUP reload path so a
// deploy-triggered reload applies newly shipped migrations with a safety net.
func runUserMigrationsWithBackup(db *sql.DB, dir string) error {
	return runUserMigrationsCtx(context.Background(), db, dir, false)
}

// checkMigrationTimeout bounds user migrations applied by a validation load in
// the router. The migration SQL is tenant-authored, and a statement that never
// finishes (a recursive CTE with no end) would otherwise pin a router core,
// and be retried by every subsequent edit. The app's own boot has no deadline.
var checkMigrationTimeout = 30 * time.Second

// runUserMigrationsCtx applies pending migrations. checkOnly (a router-side
// validation load) bounds the run by checkMigrationTimeout and reuses a recent
// snapshot instead of copying the database again.
func runUserMigrationsCtx(ctx context.Context, db *sql.DB, dir string, checkOnly bool) error {
	return runUserMigrationsFromSources(ctx, db, dir, checkOnly, nil)
}
func runUserMigrationsFromSources(ctx context.Context, db *sql.DB, dir string, checkOnly bool, captured map[string][]byte) error {
	if checkOnly {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, checkMigrationTimeout)
		defer cancel()
	}
	return runMigrationsCtxFromSources(ctx, db, dir, func() error {
		if checkOnly && recentPreMigrateBackup(dir, checkBackupMinInterval) {
			return nil
		}
		_, err := preparePreMigrationBackup(dir, true)
		return err
	}, captured)
}

// pendingUserMigrations reports migrations/*.sql not yet recorded as applied
// (pending) and any *.failed.sql (failed), for CLI surfacing so a deploy never
// silently leaves a migration unapplied.
func pendingUserMigrations(db *sql.DB, dir string) (pending, failed []string) {
	entries, err := os.ReadDir(filepath.Join(dir, "migrations"))
	if err != nil {
		return nil, nil
	}
	for _, e := range entries {
		n := e.Name()
		if strings.HasSuffix(n, ".failed.sql") {
			failed = append(failed, n)
			continue
		}
		if !strings.HasSuffix(n, ".sql") {
			continue
		}
		var c int
		db.QueryRow("SELECT COUNT(*) FROM _benmore_migrations WHERE name = ?", n).Scan(&c)
		if c == 0 {
			pending = append(pending, n)
		}
	}
	return pending, failed
}

func readFileBytes(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// The same ordered migration inputs drive candidate routing and execution.
func migrationSourceNames(dir string, captured map[string][]byte) ([]string, error) {
	var names []string
	if captured != nil {
		for name := range captured {
			if filepath.Base(name) != name || name == "." || name == ".." {
				return nil, fmt.Errorf("invalid captured migration name")
			}
			if strings.HasSuffix(name, ".sql") && !strings.HasSuffix(name, ".failed.sql") {
				names = append(names, name)
			}
		}
		sort.Strings(names)
		return names, nil
	}
	entries, err := os.ReadDir(filepath.Join(dir, "migrations"))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names = make([]string, 0, len(entries))
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() && strings.HasSuffix(name, ".sql") && !strings.HasSuffix(name, ".failed.sql") {
			names = append(names, name)
		}
	}
	return names, nil
}
func readMigrationSource(dir, name string, captured map[string][]byte) ([]byte, error) {
	if captured == nil {
		return readFileBytes(filepath.Join(dir, "migrations", name))
	}
	data, exists := captured[name]
	if !exists || data == nil {
		return nil, fmt.Errorf("missing captured migration input")
	}
	return data, nil
}
