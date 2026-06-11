//go:build !cli

package main

// Prisma → SQL migration generator. When the agent edits schema.prisma
// the runtime computes a diff against the previously-applied state and
// writes a numbered SQL file under migrations/. The file is git-trackable,
// readable, and gives the developer (and the agent in future sessions)
// a historical record of schema changes - same model Prisma, Rails,
// Django, and Alembic all use.
//
// State tracking:
//   _benmore_migrations table   id, name, applied_at, source
//
// On every app load:
//   1. Read schema.prisma, parse to models.
//   2. Read the most recent _benmore_migrations.source (the snapshot
//      of schema.prisma at last apply).
//   3. Diff old models vs new models.
//   4. If empty diff → no-op.
//   5. Else → write migrations/NNNN_<slug>.sql with the diff SQL,
//      apply it, record the row.

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

// MigrationDiff describes what changed between two schema snapshots.
// It carries enough structure that the SQL emitter and the
// human-readable summary can be generated from one source of truth.
type MigrationDiff struct {
	TablesAdded   []PrismaModel        // new model: CREATE TABLE + indexes + triggers
	TablesDropped []string             // model removed: DROP TABLE
	ColumnsAdded  map[string][]PrismaField // table → new fields: ALTER ADD COLUMN
	IndexesAdded  map[string][]PrismaIndex // table → new @@index entries
	UniquesAdded  map[string][]PrismaIndex // table → new @@unique entries
	Warnings      []string                  // schema changes we can't safely auto-apply
}

// Empty reports whether the diff actually changes anything.
func (d MigrationDiff) Empty() bool {
	return len(d.TablesAdded) == 0 &&
		len(d.TablesDropped) == 0 &&
		len(d.ColumnsAdded) == 0 &&
		len(d.IndexesAdded) == 0 &&
		len(d.UniquesAdded) == 0
}

// DiffSchemas computes the changes needed to transform `prev` into `curr`.
// Both arguments are the parsed PrismaModel slices from
// ParsePrismaSchema. Order in either slice doesn't matter.
//
// What we can express as SQL:
//   - New table → CREATE TABLE (with indexes + triggers)
//   - Dropped table → DROP TABLE
//   - New column on existing table → ALTER TABLE ADD COLUMN
//   - New @@index → CREATE INDEX
//   - New @@unique → CREATE UNIQUE INDEX
//
// What we can't safely auto-apply (surfaced as warnings):
//   - Column type changed (would require a table rebuild + data copy)
//   - Column dropped (SQLite supports DROP COLUMN in 3.35+ but
//     destructive - better to make the user explicit about it)
//   - Column renamed (looks like drop+add at the diff level; ambiguous)
//   - Default value changed (no portable ALTER)
//   - Constraint changes (NOT NULL on existing rows etc.)
func DiffSchemas(prev, curr []PrismaModel) MigrationDiff {
	d := MigrationDiff{
		ColumnsAdded: map[string][]PrismaField{},
		IndexesAdded: map[string][]PrismaIndex{},
		UniquesAdded: map[string][]PrismaIndex{},
	}

	prevByName := map[string]PrismaModel{}
	for _, m := range prev {
		prevByName[m.Name] = m
	}
	currByName := map[string]PrismaModel{}
	for _, m := range curr {
		currByName[m.Name] = m
	}

	// New tables.
	for _, m := range curr {
		if _, ok := prevByName[m.Name]; !ok {
			d.TablesAdded = append(d.TablesAdded, m)
		}
	}
	// Dropped tables.
	for _, m := range prev {
		if _, ok := currByName[m.Name]; !ok {
			d.TablesDropped = append(d.TablesDropped, m.Table)
		}
	}
	// Per-table column + index diffs.
	for _, currModel := range curr {
		prevModel, ok := prevByName[currModel.Name]
		if !ok {
			continue // handled above as TablesAdded
		}
		prevCols := map[string]PrismaField{}
		for _, f := range prevModel.Fields {
			prevCols[f.Column] = f
		}
		currCols := map[string]PrismaField{}
		for _, f := range currModel.Fields {
			currCols[f.Column] = f
		}
		// New columns.
		for _, f := range currModel.Fields {
			if _, ok := prevCols[f.Column]; !ok {
				d.ColumnsAdded[currModel.Table] = append(d.ColumnsAdded[currModel.Table], f)
			}
		}
		// Dropped columns (warning, not auto-applied).
		for _, f := range prevModel.Fields {
			if _, ok := currCols[f.Column]; !ok {
				d.Warnings = append(d.Warnings, fmt.Sprintf(
					"column dropped: %s.%s - not auto-applied. Run `ALTER TABLE %s DROP COLUMN %s` manually if you really want to drop the data.",
					currModel.Table, f.Column, currModel.Table, f.Column))
			}
		}
		// Changed columns (type / nullability / default - also warnings).
		for col, currF := range currCols {
			prevF, ok := prevCols[col]
			if !ok {
				continue
			}
			if prevF.Type != currF.Type {
				d.Warnings = append(d.Warnings, fmt.Sprintf(
					"column type changed: %s.%s %s → %s - SQLite can't ALTER type in place. Rebuild the table by hand if needed.",
					currModel.Table, col, prevF.Type, currF.Type))
			}
			if prevF.Optional != currF.Optional {
				d.Warnings = append(d.Warnings, fmt.Sprintf(
					"nullability changed: %s.%s - not auto-applied (would error on rows that violate the new constraint).",
					currModel.Table, col))
			}
		}
		// New indexes (by column-list signature).
		prevIdx := map[string]bool{}
		for _, i := range prevModel.Indexes {
			prevIdx[strings.Join(i.Columns, ",")] = true
		}
		for _, i := range currModel.Indexes {
			if !prevIdx[strings.Join(i.Columns, ",")] {
				d.IndexesAdded[currModel.Table] = append(d.IndexesAdded[currModel.Table], i)
			}
		}
		prevUnq := map[string]bool{}
		for _, i := range prevModel.Uniques {
			prevUnq[strings.Join(i.Columns, ",")] = true
		}
		for _, i := range currModel.Uniques {
			if !prevUnq[strings.Join(i.Columns, ",")] {
				d.UniquesAdded[currModel.Table] = append(d.UniquesAdded[currModel.Table], i)
			}
		}
	}

	// Deterministic order for stable migration files.
	sort.SliceStable(d.TablesAdded, func(i, j int) bool { return d.TablesAdded[i].Name < d.TablesAdded[j].Name })
	sort.Strings(d.TablesDropped)
	return d
}

// migrationUpDownMarker separates the UP and DOWN sections of a
// migration file. The applier reads everything before this marker;
// the rollback journal reads everything after it.
const migrationUpDownMarker = "-- DOWN --"

// EmitMigrationSQL turns a diff into the SQL we'll write to the
// migration file AND execute against the live database. The file has
// two halves separated by `-- DOWN --`:
//   - UP: the forward statements (executed on apply)
//   - DOWN: the reverse statements (executed on `migrate rollback`)
//
// Top of the file is a header comment naming the diff in
// human-readable form.
// migrationBodyHash hashes a migration's SQL with comment + blank lines
// stripped, so a re-emitted copy of the same diff (which differs only in
// the `-- Generated:` header and `-- Migration:` name) keys identically.
func migrationBodyHash(sqlText string) string {
	var b strings.Builder
	for _, line := range strings.Split(sqlText, "\n") {
		t := strings.TrimSpace(line)
		if t == "" || strings.HasPrefix(t, "--") {
			continue
		}
		b.WriteString(t)
		b.WriteByte('\n')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// findExistingFailedDup returns the basename of an existing .failed file
// in migDir whose SQL body matches sqlText, or "" when this failure is
// new. Used to keep ONE .failed artifact per distinct broken migration
// instead of one per retry.
func findExistingFailedDup(migDir, sqlText string) string {
	want := migrationBodyHash(sqlText)
	entries, err := os.ReadDir(migDir)
	if err != nil {
		return ""
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".failed") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(migDir, e.Name()))
		if err != nil {
			continue
		}
		if migrationBodyHash(string(data)) == want {
			return e.Name()
		}
	}
	return ""
}

func EmitMigrationSQL(diff MigrationDiff, name, timestamp string) string {
	var out strings.Builder
	fmt.Fprintf(&out, "-- Migration: %s\n", name)
	fmt.Fprintf(&out, "-- Generated: %s\n", timestamp)
	out.WriteString("--\n")
	for _, w := range diff.Warnings {
		fmt.Fprintf(&out, "-- WARNING: %s\n", w)
	}
	if len(diff.Warnings) > 0 {
		out.WriteString("--\n")
	}

	out.WriteString("-- UP --\n")
	out.WriteString(emitUpSQL(diff))
	out.WriteString("\n")
	out.WriteString(migrationUpDownMarker)
	out.WriteString("\n")
	out.WriteString(emitDownSQL(diff))
	return out.String()
}

// emitUpSQL renders the forward direction of a diff.
func emitUpSQL(diff MigrationDiff) string {
	var out strings.Builder

	// Dropped tables first - frees up the namespace before new CREATEs.
	for _, t := range diff.TablesDropped {
		fmt.Fprintf(&out, "DROP TABLE IF EXISTS %s;\n", t)
	}
	if len(diff.TablesDropped) > 0 {
		out.WriteString("\n")
	}

	// New tables (with their indexes + @updatedAt triggers).
	if len(diff.TablesAdded) > 0 {
		out.WriteString(EmitSQL(diff.TablesAdded))
	}

	// New columns on existing tables.
	if len(diff.ColumnsAdded) > 0 {
		out.WriteString("\n")
		var tables []string
		for t := range diff.ColumnsAdded {
			tables = append(tables, t)
		}
		sort.Strings(tables)
		for _, t := range tables {
			for _, f := range diff.ColumnsAdded[t] {
				parts := []string{f.Column, f.Type}
				if !f.Optional {
					if f.Default == "" {
						parts = append(parts, "NOT NULL DEFAULT ''")
					} else {
						parts = append(parts, "NOT NULL")
					}
				}
				if f.Default != "" {
					parts = append(parts, "DEFAULT "+f.Default)
				}
				fmt.Fprintf(&out, "ALTER TABLE %s ADD COLUMN %s;\n", t, strings.Join(parts, " "))
				if f.IsUnique {
					fmt.Fprintf(&out, "CREATE UNIQUE INDEX IF NOT EXISTS uniq_%s_%s ON %s(%s);\n", t, f.Column, t, f.Column)
				}
				// @updatedAt added on an existing table needs the
				// AFTER UPDATE trigger to fire on row mutations.
				// The initial CREATE TABLE path handles this via
				// EmitSQL; the ALTER path is the gap we close here.
				if f.UpdatedAt {
					fmt.Fprintf(&out,
						"CREATE TRIGGER IF NOT EXISTS trg_%s_%s_updated\n"+
							"AFTER UPDATE ON %s\n"+
							"FOR EACH ROW BEGIN\n"+
							"  UPDATE %s SET %s = CURRENT_TIMESTAMP WHERE rowid = NEW.rowid;\n"+
							"END;\n",
						t, f.Column, t, t, f.Column)
				}
			}
		}
	}

	// New @@index entries.
	if len(diff.IndexesAdded) > 0 {
		out.WriteString("\n")
		var tables []string
		for t := range diff.IndexesAdded {
			tables = append(tables, t)
		}
		sort.Strings(tables)
		for _, t := range tables {
			for _, idx := range diff.IndexesAdded[t] {
				fmt.Fprintf(&out, "CREATE INDEX IF NOT EXISTS idx_%s_%s ON %s(%s);\n",
					t, strings.Join(idx.Columns, "_"),
					t, strings.Join(idx.Columns, ", "))
			}
		}
	}

	// New @@unique entries.
	if len(diff.UniquesAdded) > 0 {
		var tables []string
		for t := range diff.UniquesAdded {
			tables = append(tables, t)
		}
		sort.Strings(tables)
		for _, t := range tables {
			for _, idx := range diff.UniquesAdded[t] {
				fmt.Fprintf(&out, "CREATE UNIQUE INDEX IF NOT EXISTS uniq_%s_%s ON %s(%s);\n",
					t, strings.Join(idx.Columns, "_"),
					t, strings.Join(idx.Columns, ", "))
			}
		}
	}

	return out.String()
}

// emitDownSQL renders the reverse direction of a diff. Each UP
// statement gets a paired DOWN statement that undoes it. Where SQLite
// can't safely undo a forward change (column type changes, dropped
// columns without backup), we emit a `-- skip:` comment so the file
// stays self-documenting about what won't be reversed.
//
// Note: TablesDropped's reverse would require the OLD column shape
// to CREATE TABLE again. The applier stores the previous schema
// source in _benmore_migrations.source, so the rollback command
// re-parses + re-emits the dropped-table CREATE from there rather
// than relying on this file. Same for column drops if we ever
// add them.
func emitDownSQL(diff MigrationDiff) string {
	var out strings.Builder

	// Reverse @@unique additions.
	if len(diff.UniquesAdded) > 0 {
		var tables []string
		for t := range diff.UniquesAdded {
			tables = append(tables, t)
		}
		sort.Strings(tables)
		for _, t := range tables {
			for _, idx := range diff.UniquesAdded[t] {
				fmt.Fprintf(&out, "DROP INDEX IF EXISTS uniq_%s_%s;\n",
					t, strings.Join(idx.Columns, "_"))
			}
		}
	}

	// Reverse @@index additions.
	if len(diff.IndexesAdded) > 0 {
		var tables []string
		for t := range diff.IndexesAdded {
			tables = append(tables, t)
		}
		sort.Strings(tables)
		for _, t := range tables {
			for _, idx := range diff.IndexesAdded[t] {
				fmt.Fprintf(&out, "DROP INDEX IF EXISTS idx_%s_%s;\n",
					t, strings.Join(idx.Columns, "_"))
			}
		}
	}

	// Reverse column additions - SQLite supports DROP COLUMN as of 3.35.
	if len(diff.ColumnsAdded) > 0 {
		var tables []string
		for t := range diff.ColumnsAdded {
			tables = append(tables, t)
		}
		sort.Strings(tables)
		for _, t := range tables {
			for _, f := range diff.ColumnsAdded[t] {
				if f.UpdatedAt {
					fmt.Fprintf(&out, "DROP TRIGGER IF EXISTS trg_%s_%s_updated;\n", t, f.Column)
				}
				if f.IsUnique {
					fmt.Fprintf(&out, "DROP INDEX IF EXISTS uniq_%s_%s;\n", t, f.Column)
				}
				fmt.Fprintf(&out, "ALTER TABLE %s DROP COLUMN %s;\n", t, f.Column)
			}
		}
	}

	// Reverse table additions - drop them (children before parents would
	// matter for FKs, but our model store doesn't track that ordering
	// reliably; SQLite's foreign_keys pragma is OFF by default so DROP
	// works regardless).
	if len(diff.TablesAdded) > 0 {
		// Drop in reverse-name order for determinism.
		names := make([]string, len(diff.TablesAdded))
		for i, m := range diff.TablesAdded {
			names[i] = m.Table
		}
		sort.Sort(sort.Reverse(sort.StringSlice(names)))
		for _, n := range names {
			fmt.Fprintf(&out, "DROP TABLE IF EXISTS %s;\n", n)
		}
	}

	// Reverse table drops: re-emit the dropped table's CREATE from the
	// previous source. This is best-effort; the rollback applier
	// re-parses the prior source to get accurate CREATE statements
	// (see rollbackPrismaMigration). Emit a sentinel comment so the
	// file documents which drops would need to be recovered.
	for _, t := range diff.TablesDropped {
		fmt.Fprintf(&out, "-- recreate %s - applier re-emits from previous schema source\n", t)
	}

	return out.String()
}

// extractMigrationSection splits a migration file into UP / DOWN halves.
// Either may be empty (a no-op migration on one direction).
func extractMigrationSection(content string) (up, down string) {
	idx := strings.Index(content, migrationUpDownMarker)
	if idx < 0 {
		// No DOWN marker - treat entire file as UP. Backwards-compat
		// with the v1 migrations that pre-dated this format.
		return content, ""
	}
	up = content[:idx]
	down = content[idx+len(migrationUpDownMarker):]
	// Strip leading "-- UP --" header if present in the up half.
	up = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(up), "-- UP --"))
	down = strings.TrimSpace(down)
	return up, down
}

// describeDiff produces the short slug that goes in the migration
// file name. The agent skims `migrations/` and reads the slug to
// know what each migration did.
func describeDiff(d MigrationDiff) string {
	if len(d.TablesAdded) == 1 && len(d.TablesDropped) == 0 && len(d.ColumnsAdded) == 0 {
		return "create_" + d.TablesAdded[0].Table
	}
	if len(d.TablesDropped) == 1 && len(d.TablesAdded) == 0 && len(d.ColumnsAdded) == 0 {
		return "drop_" + d.TablesDropped[0]
	}
	if len(d.TablesAdded) == 0 && len(d.TablesDropped) == 0 && len(d.ColumnsAdded) == 1 {
		// Single table, single column → "add_<col>_to_<table>"
		for t, cols := range d.ColumnsAdded {
			if len(cols) == 1 {
				return "add_" + cols[0].Column + "_to_" + t
			}
			return "alter_" + t
		}
	}
	parts := []string{}
	if len(d.TablesAdded) > 0 {
		parts = append(parts, fmt.Sprintf("add_%d_tables", len(d.TablesAdded)))
	}
	if len(d.TablesDropped) > 0 {
		parts = append(parts, fmt.Sprintf("drop_%d_tables", len(d.TablesDropped)))
	}
	if len(d.ColumnsAdded) > 0 {
		cols := 0
		for _, fs := range d.ColumnsAdded {
			cols += len(fs)
		}
		parts = append(parts, fmt.Sprintf("add_%d_cols", cols))
	}
	if len(parts) == 0 {
		return "update"
	}
	return strings.Join(parts, "_")
}

// ApplyPrismaMigration runs the migration lifecycle for one app:
// parse schema.prisma, diff against the most recent applied
// snapshot, write the new migration file, apply, record.
//
// Returns the migration's filename (or "" if no diff) and the
// compiled SQL that should be passed to LoadSchema's existing
// executor for IF-NOT-EXISTS idempotency. The caller still runs
// the standard schema execution path - this function just keeps
// the migrations/ folder + _benmore_migrations table in sync.
// reconcileDiffAgainstLive drops migration steps that would conflict
// with what the live database already contains. The point: make the
// migration ADD COLUMN / CREATE INDEX statements idempotent against
// drift between the parsed-from-_benmore_migrations "prev" schema and
// the actual live tables. Without this, beacon's "duplicate column
// name: thumbnail_url" loop fired every restart.
//
// What's reconciled:
//
//   - ColumnsAdded: drop entries whose column already exists in the
//     live PRAGMA table_info(<table>).
//   - IndexesAdded: drop entries whose index name already exists in
//     sqlite_master.
//   - UniquesAdded: same as IndexesAdded.
//   - TablesAdded: dropped entirely if the table already exists.
//
// What's NOT reconciled (still warnings):
//
//   - Column type / nullability / default changes - too many ways for
//     SQLite's affinity rules to mis-coerce. The agent gets the
//     warning and decides.
func reconcileDiffAgainstLive(diff MigrationDiff, db *sql.DB) MigrationDiff {
	// Build the live snapshot: which tables exist + which columns each
	// has + which indexes are named what. Best-effort - on any read
	// error we leave the diff untouched so the loud-fail path stays
	// the same as before.
	liveTables := map[string]bool{}
	liveColumns := map[string]map[string]bool{}
	tableRows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		return diff
	}
	for tableRows.Next() {
		var name string
		if err := tableRows.Scan(&name); err != nil {
			continue
		}
		liveTables[name] = true
	}
	tableRows.Close()
	for table := range liveTables {
		cols := map[string]bool{}
		colRows, err := db.Query(`SELECT name FROM pragma_table_info(?)`, table)
		if err != nil {
			continue
		}
		for colRows.Next() {
			var n string
			if err := colRows.Scan(&n); err == nil {
				cols[n] = true
			}
		}
		colRows.Close()
		liveColumns[table] = cols
	}
	liveIndexes := map[string]bool{}
	idxRows, err := db.Query(`SELECT name FROM sqlite_master WHERE type='index'`)
	if err == nil {
		for idxRows.Next() {
			var n string
			if err := idxRows.Scan(&n); err == nil {
				liveIndexes[n] = true
			}
		}
		idxRows.Close()
	}

	// Drop already-present TablesAdded.
	keptTables := diff.TablesAdded[:0]
	for _, m := range diff.TablesAdded {
		if !liveTables[m.Table] {
			keptTables = append(keptTables, m)
		}
	}
	diff.TablesAdded = keptTables

	// Drop already-present ColumnsAdded entries (per table).
	for table, fields := range diff.ColumnsAdded {
		liveCols := liveColumns[table]
		kept := fields[:0]
		for _, f := range fields {
			if !liveCols[f.Column] {
				kept = append(kept, f)
			}
		}
		if len(kept) == 0 {
			delete(diff.ColumnsAdded, table)
		} else {
			diff.ColumnsAdded[table] = kept
		}
	}

	// Drop already-present indexes / unique constraints. The emitted
	// SQL uses CREATE INDEX IF NOT EXISTS / CREATE UNIQUE INDEX IF
	// NOT EXISTS anyway, so this is belt-and-braces - but it also
	// keeps Empty() honest: an idempotent re-run with nothing real
	// to do reports diff.Empty()==true and skips writing a migration
	// file altogether.
	keepNamedIndex := func(byTable map[string][]PrismaIndex, prefix string) {
		for table, list := range byTable {
			kept := list[:0]
			for _, idx := range list {
				name := indexName(prefix, table, idx)
				if !liveIndexes[name] {
					kept = append(kept, idx)
				}
			}
			if len(kept) == 0 {
				delete(byTable, table)
			} else {
				byTable[table] = kept
			}
		}
	}
	keepNamedIndex(diff.IndexesAdded, "idx")
	keepNamedIndex(diff.UniquesAdded, "uniq")

	return diff
}

// indexName mirrors the convention EmitMigrationSQL uses when writing
// CREATE INDEX / CREATE UNIQUE INDEX statements. Keeping both sides in
// sync here lets us pre-check existence without re-parsing SQL.
func indexName(prefix, table string, idx PrismaIndex) string {
	return prefix + "_" + table + "_" + strings.Join(idx.Columns, "_")
}

func ApplyPrismaMigration(db *sql.DB, dir, prismaSrc string) (string, error) {
	// Ensure the tracking table exists. Idempotent.
	if _, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS _benmore_migrations (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			name TEXT NOT NULL,
			applied_at DATETIME DEFAULT CURRENT_TIMESTAMP,
			source TEXT NOT NULL,
			source_hash TEXT NOT NULL
		)
	`); err != nil {
		return "", fmt.Errorf("create _benmore_migrations: %w", err)
	}

	currModels, err := ParsePrismaSchema(prismaSrc)
	if err != nil {
		return "", err
	}

	// Fast path: same source as the last applied migration → no-op.
	hash := schemaHash(prismaSrc)
	var lastHash, lastSource string
	row := db.QueryRow(`SELECT source_hash, source FROM _benmore_migrations ORDER BY id DESC LIMIT 1`)
	_ = row.Scan(&lastHash, &lastSource)
	if lastHash == hash {
		return "", nil
	}

	var prevModels []PrismaModel
	if lastSource != "" {
		prevModels, _ = ParsePrismaSchema(lastSource)
	}
	diff := DiffSchemas(prevModels, currModels)
	// Reconcile the diff against the LIVE schema before emitting SQL.
	// Pre-2.7.37 the diff was prev→curr only, so when the live DB
	// had ALTER'd state that the prev model didn't know about (e.g.
	// a prior partial migration, a manual ALTER, a hot-reload where
	// _benmore_migrations got truncated), the regenerated SQL would
	// try ADD COLUMN again and crash with "duplicate column name".
	// Beacon's `duplicate column name: thumbnail_url` debug session
	// was exactly this shape. Now: filter the diff against the live
	// PRAGMA table_info so already-present columns / indexes are
	// dropped from the migration.
	diff = reconcileDiffAgainstLive(diff, db)
	if diff.Empty() {
		// Source bytes changed (e.g. whitespace) but the parsed model
		// list is identical. Record the new hash so we stop diffing
		// on every boot, but don't write a migration file.
		_, _ = db.Exec(`INSERT INTO _benmore_migrations (name, source, source_hash) VALUES (?, ?, ?)`,
			"no_schema_change", prismaSrc, hash)
		return "", nil
	}

	// Number the migration. Format: NNNN_YYYYMMDDHHMMSS_<slug>.sql so
	// they sort lexicographically and the timestamp + slug are both
	// readable.
	migDir := filepath.Join(dir, "migrations")
	if err := os.MkdirAll(migDir, 0755); err != nil {
		return "", fmt.Errorf("create migrations/: %w", err)
	}
	next := nextMigrationNumber(migDir)
	timestamp := time.Now().UTC().Format("20060102T150405Z")
	slug := describeDiff(diff)
	filename := fmt.Sprintf("%04d_%s_%s.sql", next, timestamp, slug)
	filePath := filepath.Join(migDir, filename)

	sqlText := EmitMigrationSQL(diff, slug, timestamp)
	if err := os.WriteFile(filePath, []byte(sqlText), 0644); err != nil {
		return "", fmt.Errorf("write migration: %w", err)
	}

	// Apply the migration atomically. Every statement runs inside a
	// single transaction so a mid-batch failure leaves the database
	// in its pre-migration state. The _benmore_migrations row is
	// recorded inside the same transaction - either everything
	// commits (schema + bookkeeping in lockstep) or nothing does.
	//
	// SQLite quirk: CREATE TRIGGER / DROP TRIGGER inside a
	// transaction is fine, but `CREATE TABLE` followed by `INSERT`
	// into that table all in one tx works as expected. ALTER TABLE
	// ADD COLUMN is transactional too as of SQLite 3.25+.
	tx, err := db.Begin()
	if err != nil {
		return filename, fmt.Errorf("begin migration tx: %w", err)
	}
	rollback := func(cause error) (string, error) {
		_ = tx.Rollback()
		// Move the failed migration to <filename>.failed so it stays
		// visible to operators (the SQL that broke is the most valuable
		// artifact for debugging) but DOESN'T trigger the
		// `_benmore_migrations table doesn't have a row → re-emit same
		// diff → fail again → ...` infinite loop that pre-v2.7.8
		// deletion caused. The .failed file is skipped by RunMigrations
		// (it only reads *.sql), and ApplyPrismaMigration's diff path
		// sees only the schema source hash - it doesn't care about
		// files on disk for the fast-path check.
		//
		// On next boot, the diff will re-emit the same migration with a
		// fresh timestamp + name. If the underlying schema bug is fixed,
		// the new migration succeeds. If not, the failure DEDUPS against
		// the .failed file already on disk (same SQL body, comments
		// stripped) and the retry copy is deleted - pre-v2.7.167 every
		// boot appended ANOTHER timestamped .failed file (one field
		// report counted 391 in 8 days on a single instance).
		failedPath := filePath + ".failed"
		if dup := findExistingFailedDup(filepath.Dir(filePath), sqlText); dup != "" {
			_ = os.Remove(filePath)
			log.Printf("MIGRATION FAILED (same failure already recorded at migrations/%s - retry copy not kept). Cause: %s",
				dup, cause)
		} else if mvErr := os.Rename(filePath, failedPath); mvErr != nil {
			// Fall back to delete if rename couldn't work (cross-fs etc).
			_ = os.Remove(filePath)
		} else {
			log.Printf("MIGRATION FAILED - kept the SQL at migrations/%s.failed for inspection. Cause: %s",
				filepath.Base(filename), cause)
		}
		return "", fmt.Errorf("apply migration %s: %w", filename, cause)
	}
	// Apply only the UP section. The DOWN section lives in the file
	// for the rollback journal to read later - it must not run
	// during a forward apply.
	upSQL, _ := extractMigrationSection(sqlText)
	for _, stmt := range splitStatements(upSQL) {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" || strings.HasPrefix(stmt, "--") {
			continue
		}
		if _, err := tx.Exec(stmt); err != nil {
			return rollback(fmt.Errorf("%s: %w", truncate(stmt, 100), err))
		}
	}
	if _, err := tx.Exec(`INSERT INTO _benmore_migrations (name, source, source_hash) VALUES (?, ?, ?)`,
		filename, prismaSrc, hash); err != nil {
		return rollback(fmt.Errorf("record migration: %w", err))
	}
	if err := tx.Commit(); err != nil {
		return rollback(fmt.Errorf("commit migration: %w", err))
	}
	return filename, nil
}

// RollbackPrismaMigration undoes the most recent N applied migrations.
// For each, it reads the file's DOWN section, executes the reverse
// statements inside a transaction, deletes the row from
// _benmore_migrations, and (if delete=true) removes the migration
// file from disk.
//
// Tables dropped by the forward migration are recreated by re-emitting
// the previous schema's CREATE TABLE statements from the second-most-
// recent _benmore_migrations.source - the file's DOWN section can't
// hold the dropped table's shape because we don't know its columns
// when emitting forward.
//
// Returns the list of rolled-back migration filenames (most-recent
// first). On the first error, stops and reports it; rows already
// rolled back are kept rolled back (each was its own transaction).
func RollbackPrismaMigration(db *sql.DB, dir string, count int, deleteFiles bool) ([]string, error) {
	if count <= 0 {
		count = 1
	}
	rows, err := db.Query(
		`SELECT id, name, source FROM _benmore_migrations ORDER BY id DESC LIMIT ?`,
		count)
	if err != nil {
		return nil, fmt.Errorf("list migrations: %w", err)
	}
	type migRow struct {
		id     int64
		name   string
		source string
	}
	var pending []migRow
	for rows.Next() {
		var m migRow
		if err := rows.Scan(&m.id, &m.name, &m.source); err != nil {
			rows.Close()
			return nil, fmt.Errorf("scan migration row: %w", err)
		}
		pending = append(pending, m)
	}
	rows.Close()
	if len(pending) == 0 {
		return nil, fmt.Errorf("no migrations to roll back")
	}

	migDir := filepath.Join(dir, "migrations")
	var done []string

	for i, m := range pending {
		// File path for this migration. The name column stores the
		// filename verbatim, so we just join.
		path := filepath.Join(migDir, m.name)
		fileData, err := os.ReadFile(path)
		if err != nil {
			return done, fmt.Errorf("read %s: %w", m.name, err)
		}
		_, downSQL := extractMigrationSection(string(fileData))

		// Figure out which prior source we should use as the
		// "restored" state. After rolling THIS migration back, the
		// schema should match the source from the migration BEFORE
		// this one. That's whatever row has the next-lower id in
		// _benmore_migrations - which may NOT be in the rollback set
		// (if we're only rolling back the most recent and prior
		// migrations stay applied, prior == row with id = m.id-1...
		// but ids aren't guaranteed contiguous, so query by ordering).
		var priorSource string
		if i+1 < len(pending) {
			// Next-deeper migration in the rollback set is the
			// "prior" relative to m.
			priorSource = pending[i+1].source
		} else {
			// We're at the deepest rollback. Ask the DB for the
			// migration that comes just before m in id order - that
			// row stays applied, so it's the schema state we should
			// restore TO.
			_ = db.QueryRow(
				`SELECT source FROM _benmore_migrations WHERE id < ? ORDER BY id DESC LIMIT 1`,
				m.id).Scan(&priorSource)
		}

		// Re-emit CREATE TABLE for any tables this migration dropped.
		// We discover them by diffing the prior source against the
		// current source (one we're rolling back from): tables that
		// exist in prior but not current need to be recreated.
		var recreateSQL string
		if priorSource != "" {
			priorModels, _ := ParsePrismaSchema(priorSource)
			currModels, _ := ParsePrismaSchema(m.source)
			currNames := map[string]bool{}
			for _, cm := range currModels {
				currNames[cm.Name] = true
			}
			var toRecreate []PrismaModel
			for _, pm := range priorModels {
				if !currNames[pm.Name] {
					toRecreate = append(toRecreate, pm)
				}
			}
			if len(toRecreate) > 0 {
				recreateSQL = EmitSQL(toRecreate)
			}
		}

		tx, err := db.Begin()
		if err != nil {
			return done, fmt.Errorf("begin rollback tx: %w", err)
		}
		txRollback := func(cause error) error {
			_ = tx.Rollback()
			return fmt.Errorf("rollback %s: %w", m.name, cause)
		}
		// First the DOWN statements from the file.
		for _, stmt := range splitStatements(downSQL) {
			stmt = strings.TrimSpace(stmt)
			if stmt == "" || strings.HasPrefix(stmt, "--") {
				continue
			}
			if _, err := tx.Exec(stmt); err != nil {
				return done, txRollback(fmt.Errorf("%s: %w", truncate(stmt, 100), err))
			}
		}
		// Then recreate dropped tables.
		if recreateSQL != "" {
			for _, stmt := range splitStatements(recreateSQL) {
				stmt = strings.TrimSpace(stmt)
				if stmt == "" || strings.HasPrefix(stmt, "--") {
					continue
				}
				if _, err := tx.Exec(stmt); err != nil {
					return done, txRollback(fmt.Errorf("recreate %s: %w", truncate(stmt, 100), err))
				}
			}
		}
		// Drop the bookkeeping row.
		if _, err := tx.Exec(`DELETE FROM _benmore_migrations WHERE name = ?`, m.name); err != nil {
			return done, txRollback(fmt.Errorf("delete row: %w", err))
		}
		if err := tx.Commit(); err != nil {
			return done, txRollback(err)
		}

		if deleteFiles {
			_ = os.Remove(path)
		}
		done = append(done, m.name)
	}
	return done, nil
}

// nextMigrationNumber scans migrations/ for the highest existing
// NNNN_ prefix and returns the next integer. Starts at 1.
func nextMigrationNumber(migDir string) int {
	entries, err := os.ReadDir(migDir)
	if err != nil {
		return 1
	}
	max := 0
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		m := migrationNumberRe.FindStringSubmatch(e.Name())
		if m == nil {
			continue
		}
		var n int
		fmt.Sscanf(m[1], "%d", &n)
		if n > max {
			max = n
		}
	}
	return max + 1
}

var migrationNumberRe = regexp.MustCompile(`^(\d+)_`)

func schemaHash(src string) string {
	h := sha256.Sum256([]byte(src))
	return hex.EncodeToString(h[:])
}
