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
	tx, err := db.BeginTx(withLongWriteTx(context.Background(), "table rebuild "+table), nil)
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

// migrationStatementAlreadyApplied reports whether a migration statement that
// failed with err has nothing left to do on this database, and names the case
// for the log line. The user-migration runner and the reuse of a pending file
// for a schema.prisma change (prisma_migrate_adopt.go) share it, so a file
// meets the same tolerance on every path that runs it.
func migrationStatementAlreadyApplied(q sqlQuerier, stmt string, err error) (string, bool) {
	switch {
	case isBenignMigrationError(err):
		return "already-applied statement", true
	case isRenameAlreadyApplied(q, stmt, err):
		// A fresh DB gets the TARGET column/table straight from the schema
		// sync, so the rename's source is missing but the end state is
		// already correct (e.g. `RENAME COLUMN role TO solar_role` in a user
		// migration on a DB born with solar_role).
		return "already-applied rename", true
	case isDropAlreadyApplied(q, stmt, err):
		return migrationSkippedAsDrop, true
	}
	return "", false
}

// migrationSkippedAsDrop is migrationStatementAlreadyApplied's name for a
// drop whose target the database does not hold.
const migrationSkippedAsDrop = "a drop of what this database does not hold"

// migrationSkippedDrop is a statement of a migration file that was skipped
// because the database does not hold what it names.
//
// A drop (Statement 0): skipping is right for a database built after the
// column left the schema, and it is also what happens to a drop whose name is
// misspelt, which used to fail loudly.
//
// Any other statement, on a database that is new in this load (Statement is
// its place in the file, from 1; migrate_new_database.go): right for a file
// written for a shape the schema has since left, and also what a misspelt
// name gets there.
//
// So every run that can answer someone (the write's dry run, a promote's and
// a restore's) hands these back as warnings, and a load logs them.
type migrationSkippedDrop struct {
	File    string `json:"file"`
	Kind    string `json:"kind"`    // column, table or index
	Missing string `json:"missing"` // table.column, column, table or index name
	// Statement and Verb are set for a statement that is not a drop: its
	// place in the file's statements and its leading keyword.
	Statement int    `json:"statement,omitempty"`
	Verb      string `json:"verb,omitempty"`
}

// warning is the line a builder reads.
func (d migrationSkippedDrop) warning() string {
	if d.Statement > 0 {
		what := fmt.Sprintf("statement %d", d.Statement)
		if d.Verb != "" {
			what += " (" + d.Verb + ")"
		}
		return fmt.Sprintf("migrations/%s: %s names `%s`, a %s the current schema does not have, so this new database skips the statement and runs the rest of the file (the file still counts as applied; a database that has the %s runs the statement). If the name is misspelt, the statement did nothing here.", d.File, what, d.Missing, d.Kind, d.Kind)
	}
	return fmt.Sprintf("migrations/%s: this drop names `%s`, which this database does not have, so the statement is skipped (the file still counts as applied). If the name is misspelt, the %s it was meant to drop is still there.", d.File, d.Missing, d.Kind)
}

// migrationSkipLog collects the skipped statements of one run. File is the
// file whose statements are running.
type migrationSkipLog struct {
	File  string
	drops []migrationSkippedDrop
}

type migrationSkipLogKey struct{}

// withMigrationSkipLog returns a context whose migration statements record
// what they skip. A context that already has a log keeps it.
func withMigrationSkipLog(ctx context.Context) (context.Context, *migrationSkipLog) {
	if l, _ := ctx.Value(migrationSkipLogKey{}).(*migrationSkipLog); l != nil {
		return ctx, l
	}
	l := &migrationSkipLog{}
	return context.WithValue(ctx, migrationSkipLogKey{}, l), l
}

// add records d, under the running file when d names none. A statement a run
// executes twice is one entry.
func (l *migrationSkipLog) add(d migrationSkippedDrop) migrationSkippedDrop {
	if l == nil {
		return d
	}
	if d.File == "" {
		d.File = l.File
	}
	if len(l.drops) >= migrationSkippedDropMax {
		return d
	}
	for _, have := range l.drops {
		if have == d {
			return d
		}
	}
	l.drops = append(l.drops, d)
	return d
}

// noteMigrationSkip records stmt, skipped as what, in ctx's log when it has
// one and the skip is a drop.
func noteMigrationSkip(ctx context.Context, file, stmt, what string) {
	l, _ := ctx.Value(migrationSkipLogKey{}).(*migrationSkipLog)
	drop, ok := parseMigrationPureDrop(stmt)
	if l == nil || what != migrationSkippedAsDrop || !ok {
		return
	}
	d := migrationSkippedDrop{File: file, Kind: "table", Missing: drop.table}
	switch {
	case drop.index != "":
		d.Kind, d.Missing = "index", drop.index
	case drop.column != "":
		d.Kind, d.Missing = "column", drop.table+"."+drop.column
	}
	l.add(d)
}

// migrationSkippedDropMax bounds the skipped statements one run reports.
const migrationSkippedDropMax = 20

// migrationSkippedStatementMax bounds the statement position a report
// carries.
const migrationSkippedStatementMax = 1_000_000

// migrationPureDrop is a statement that is exactly one drop in the main
// schema and nothing else: of a column (table and column), a table (table) or
// an index (index).
type migrationPureDrop struct {
	table, column, index string
}

// parseMigrationPureDrop reads stmt as `ALTER TABLE t DROP [COLUMN] c`,
// `DROP TABLE t` or `DROP INDEX i`, with the shared SQLite lexer (comments,
// quoting and a `main.` qualifier read as SQLite reads them). Any other
// statement, a name in another schema, a second statement or a trailing token
// is not one. `IF EXISTS` forms are left out: they cannot fail for a missing
// target.
func parseMigrationPureDrop(stmt string) (migrationPureDrop, bool) {
	statements := sqlTokenStatements(sqlTokenize(stmt))
	if len(statements) != 1 {
		return migrationPureDrop{}, false
	}
	toks, i := statements[0], 0
	kw := func(word string) bool {
		if i < len(toks) && toks[i].kind == sqlTokWord && strings.EqualFold(toks[i].text, word) {
			i++
			return true
		}
		return false
	}
	// name reads [main .] name; "" for none or a name in another schema.
	name := func() string {
		if i+2 < len(toks) && toks[i+1].kind == sqlTokPunct && toks[i+1].text == "." {
			if toks[i].kind == sqlTokPunct || !strings.EqualFold(toks[i].text, "main") {
				return ""
			}
			i += 2
		}
		if i >= len(toks) || toks[i].kind == sqlTokPunct {
			return ""
		}
		i++
		return toks[i-1].text
	}
	var drop migrationPureDrop
	switch {
	case kw("DROP"):
		switch {
		case kw("TABLE"):
			drop.table = name()
		case kw("INDEX"):
			drop.index = name()
		}
	case kw("ALTER"):
		if !kw("TABLE") {
			return migrationPureDrop{}, false
		}
		drop.table = name()
		if drop.table == "" || !kw("DROP") {
			return migrationPureDrop{}, false
		}
		// COLUMN is optional, and a column may itself be named column.
		if i+1 < len(toks) {
			kw("COLUMN")
		}
		if drop.column = name(); drop.column == "" {
			return migrationPureDrop{}, false
		}
	}
	if i != len(toks) || (drop.table == "" && drop.index == "") {
		return migrationPureDrop{}, false
	}
	return drop, true
}

// isDropAlreadyApplied reports whether a failed drop names something this
// database does not hold, so the statement has nothing to do here. A database
// built from the current schema never had the column a removed field left
// behind elsewhere, and the file that drops it (`ALTER TABLE t DROP COLUMN
// c;`, the recipe a push prints) failed there with `no such column`; SQLite
// has no DROP COLUMN IF EXISTS to write instead. The same holds for a table
// or index the schema no longer creates. Deliberately narrow: the statement
// is exactly one drop, SQLite's error is the missing-target one, and the
// absence is read from the live schema through q, never from the error text
// alone (dropping a column a trigger still reads also says "no such column").
// A check that cannot be made counts as "not applied": the file fails.
func isDropAlreadyApplied(q sqlQuerier, stmt string, err error) bool {
	if err == nil {
		return false
	}
	drop, ok := parseMigrationPureDrop(stmt)
	if !ok {
		return false
	}
	msg := strings.ToLower(err.Error())
	if drop.index != "" {
		held, qerr := migrationSchemaHolds(q, `SELECT 1 FROM main.sqlite_master WHERE type = 'index' AND name = ? COLLATE NOCASE`, drop.index)
		return qerr == nil && !held && strings.Contains(msg, "no such index")
	}
	tableHeld, qerr := migrationSchemaHolds(q, `SELECT 1 FROM main.sqlite_master WHERE type IN ('table', 'view') AND name = ? COLLATE NOCASE`, drop.table)
	if qerr != nil {
		return false
	}
	if !tableHeld {
		// The table is gone, and any column of it with it.
		return strings.Contains(msg, "no such table")
	}
	if drop.column == "" {
		return false
	}
	// table_xinfo also lists generated columns, which table_info leaves out.
	columnHeld, qerr := migrationSchemaHolds(q, `SELECT 1 FROM pragma_table_xinfo(?, 'main') WHERE name = ? COLLATE NOCASE`, drop.table, drop.column)
	return qerr == nil && !columnHeld && strings.Contains(msg, "no such column")
}

// migrationSchemaHolds reports whether query returns a row.
func migrationSchemaHolds(q sqlQuerier, query string, args ...any) (bool, error) {
	rows, err := q.Query(query, args...)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	held := rows.Next()
	return held, rows.Err()
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
	// Apply every statement in the file inside ONE transaction so a mid-file
	// failure rolls the whole file back instead of committing a partial prefix.
	// Without this, a file that failed on statement N left 1..N-1 committed but
	// unrecorded, so the next boot re-ran from the top and the already-applied
	// prefix errored ("duplicate column") forever - a wedged, half-migrated
	// schema. Rolling back on failure means a retry always starts clean.
	tx, err := db.BeginTx(withLongWriteTx(ctx, "user migration "+name), nil)
	if err != nil {
		return fmt.Errorf("begin migration tx: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := runMigrationStatementsTx(ctx, tx, data); err != nil {
		return err
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

// migrationStatementError is a failed migration statement: its text reads as
// err's, and Statement carries the whole statement for whoever reports it.
type migrationStatementError struct {
	Statement string
	err       error
}

func (e *migrationStatementError) Error() string { return e.err.Error() }
func (e *migrationStatementError) Unwrap() error { return e.err }

// runMigrationStatementsTx runs a migration file's UP section in tx. The
// runner and the write-time dry run (migration_dry_run.go) share it, so they
// agree on which statements run and which failures are tolerated.
func runMigrationStatementsTx(ctx context.Context, tx *sql.Tx, data []byte) error {
	upSQL, _ := extractMigrationSection(string(data))
	// Decided once, before anything in the file runs
	// (migration_framework_guard.go).
	hipaa := migrationUnderHIPAA(ctx, tx)
	position := 0 // of the statement in the file, from 1
	for _, stmt := range splitStatements(upSQL) {
		stmt = strings.TrimSpace(stmt)
		if stmt == "" || strings.HasPrefix(stmt, "--") {
			continue
		}
		position++
		// SQLite itself checks UNIQUE in this transaction. A separate GROUP BY
		// preflight treats NULL as duplicate, misses partial/collated semantics,
		// and cannot see a dedupe performed by preceding migration statements.
		if err := refuseAuditTableStatement(tx, stmt); err != nil { // audit_append_only.go
			return &migrationStatementError{stmt, fmt.Errorf("migration %s: %w", truncate(stmt, 60), err)}
		}
		if err := dropFrameworkIndexesForStatement(tx, stmt); err != nil { // scoping_indexes.go
			return &migrationStatementError{stmt, fmt.Errorf("migration %s: %w", truncate(stmt, 60), err)}
		}
		if _, err := tx.ExecContext(ctx, appMigrationSQL(hipaa, stmt)); err != nil {
			var refused *appSQLRefusedError
			if errors.As(err, &refused) {
				return &migrationStatementError{stmt, fmt.Errorf("migration %s: %w", truncate(stmt, 60), err)}
			}
			// Idempotency: if the desired change is ALREADY present (the column /
			// table / index was created by an earlier schema sync or a prior
			// partial run), skip the statement instead of failing the file. A
			// "duplicate column name" used to abort the whole migration, which
			// then never got recorded in _benmore_migrations and re-ran on EVERY
			// boot - emitting `migration warning: ... duplicate column name: X`
			// in perpetuity. SQLite leaves the transaction usable after these
			// schema-level errors, so the remaining statements still apply.
			// Checked against the tx so it sees what earlier statements in
			// this file did.
			if what, ok := migrationStatementAlreadyApplied(tx, stmt, err); ok {
				log.Printf("  migration: skipping %s: %s (%v)", what, truncate(stmt, 80), err)
				noteMigrationSkip(ctx, "", stmt, what)
				continue
			}
			// A database that is new in this load never had what an older
			// file names (migrate_new_database.go).
			if skipped, ok := migrationStatementStaleOnNewDatabase(ctx, tx, stmt, position, err); ok {
				l, _ := ctx.Value(migrationSkipLogKey{}).(*migrationSkipLog)
				log.Printf("  WARNING: %s", l.add(skipped).warning())
				continue
			}
			return &migrationStatementError{stmt, fmt.Errorf("migration %s: %w", truncate(stmt, 60), err)}
		}
	}
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
	ctx = withMigrationAppDir(ctx, dir, readFileInRoot)
	// What the files skip is logged under the file's name.
	ctx, skips := withMigrationSkipLog(ctx)
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

		skips.File = n
		data, err := readMigrationSource(dir, n, captured)
		if err == nil {
			// A file that drops data gets the line a destructive generated
			// migration prints, so the log says what the reload deleted.
			if drops, dropErr := migrationDataDrops(db, string(data)); dropErr == nil && len(drops) > 0 {
				log.Printf("DESTRUCTIVE MIGRATION %s: %s", n, strings.Join(drops, ", "))
			}
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
		path, err := preparePreMigrationBackup(dir, true)
		noteLoadSnapshot(ctx, path) // the loader restores it if the load's integrity_check fails
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
