//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"path"
	"path/filepath"
	"strings"
)

// What a user migration file (migrations/*.sql) would delete from a database
// when the user-migration runner applies it. One reading of the file serves
// promote's preview and gate, the restore check, the write gate for a pushed
// migration file and the runner's own log line, so they cannot disagree about
// which statements lose data.

// userMigrationFileName is the ledger name of the file at path (relative to
// the app) when the user-migration runner applies it: a .sql file directly in
// migrations/ that is not a set-aside .failed.sql (migrationSourceNames).
func userMigrationFileName(rel string) (string, bool) {
	dir, name := path.Split(path.Clean(filepath.ToSlash(rel)))
	if dir != "migrations/" || !strings.HasSuffix(name, ".sql") || strings.HasSuffix(name, ".failed.sql") {
		return "", false
	}
	return name, true
}

// migrationDataDrops lists the statements in the UP section of one migration
// file that would remove data db holds: a table holding rows that the file
// drops, under its own name or under a name it renamed the table to, and a
// column holding a non-NULL value that it drops. A table dropped while the
// file fills another table that ends up under its name (the generator's
// rebuild, or a rename to <name>_old followed by a copy into a new <name>) is
// not counted here.
//
// This is a reading of the text. The write gate, promote and restore also run
// the file in a rolled-back transaction and compare the data before and after
// it (migration_loss.go); this reading is what they use when that run reaches
// no verdict, and the line the runner logs.
//
// Statements are read with the shared SQLite lexer (sql_scan.go), so comments,
// quoting, a schema-qualified name and several statements on one line read as
// SQLite reads them; a regex over the text missed a statement that began with a
// block comment or named main.<table>.
func migrationDataDrops(db *sql.DB, content string) ([]string, error) {
	up, _ := extractMigrationSection(content)
	exists := func(name string) bool {
		live, err := migrationLiveTable(db, name)
		return err == nil && live != ""
	}
	lineage := followMigrationTables(migrationSchemaStatements(up), exists)
	var drops []string
	for _, ev := range lineage.events {
		t := ev.table
		if t.origin == "" {
			continue
		}
		if ev.column != "" {
			if n, err := migrationColumnValues(db, t.origin, ev.originColumn); err != nil {
				return nil, err
			} else if n > 0 {
				drops = append(drops, fmt.Sprintf("DROP COLUMN %s.%s (%d rows with a value)", ev.written, ev.column, n))
			}
			continue
		}
		if lineage.refilled(t) {
			continue
		}
		if n, err := migrationTableRows(db, t.origin); err != nil {
			return nil, err
		} else if n > 0 {
			drops = append(drops, t.dropLine(t.origin, ev.written, n))
		}
	}
	return drops, nil
}

// migrationTableLineage follows one table through a migration's UP section.
type migrationTableLineage struct {
	// origin is the table the database holds under this name when the file
	// starts; "" for a table the file creates.
	origin string
	// renames are the names the file gives it, in order.
	renames []string
	// filled: the file inserts into it, or created it AS SELECT.
	filled bool
	// columns maps a renamed column's current name (lower case) to its name
	// when the file starts.
	columns map[string]string
	// dropped is the name it was dropped under; "" while it lives.
	dropped string
}

// columnOrigin is the name column had when the file started.
func (t *migrationTableLineage) columnOrigin(column string) string {
	if orig, ok := t.columns[strings.ToLower(column)]; ok {
		return orig
	}
	return column
}

// columnNow is the name the file leaves column (its name at the start) under.
func (t *migrationTableLineage) columnNow(column string) string {
	for now, orig := range t.columns {
		if strings.EqualFold(orig, column) {
			return now
		}
	}
	return column
}

// dropLine says what dropping the table under name loses: the n rows table
// origin held when the file started.
func (t *migrationTableLineage) dropLine(origin, name string, n int64) string {
	if len(t.renames) == 0 {
		return fmt.Sprintf("DROP TABLE %s (%d rows)", name, n)
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%s: %d rows, by", origin, n)
	for _, to := range t.renames {
		fmt.Fprintf(&b, " RENAME TO %s +", to)
	}
	fmt.Fprintf(&b, " DROP TABLE %s", name)
	return b.String()
}

// migrationLineageEvent is a drop, in statement order: of the table, or of
// one of its columns (column as written, originColumn its name at the start).
type migrationLineageEvent struct {
	table                *migrationTableLineage
	written              string
	column, originColumn string
}

// migrationLineage is what the file does to the tables it names.
type migrationLineage struct {
	// live maps a lower-case name to the table under it now; nil when the
	// file renamed or dropped the table that held the name.
	live map[string]*migrationTableLineage
	// byOrigin maps the lower-case name of a database table to its lineage.
	byOrigin map[string]*migrationTableLineage
	events   []migrationLineageEvent
}

// refilled reports whether a table the file filled ends up under the dropped
// table's name, or under the name its rows had when the file started.
func (l *migrationLineage) refilled(t *migrationTableLineage) bool {
	for name, other := range l.live {
		if other != nil && other != t && other.filled &&
			(strings.EqualFold(name, t.dropped) || strings.EqualFold(name, t.origin)) {
			return true
		}
	}
	return false
}

// table is the lineage of the database table that started out as name, if
// the file named it.
func (l *migrationLineage) table(name string) *migrationTableLineage {
	return l.byOrigin[strings.ToLower(name)]
}

// followMigrationTables runs the statements over names. exists reports
// whether the database holds a table (for CREATE TABLE IF NOT EXISTS).
func followMigrationTables(statements []migrationSchemaStatement, exists func(string) bool) *migrationLineage {
	l := &migrationLineage{live: map[string]*migrationTableLineage{}, byOrigin: map[string]*migrationTableLineage{}}
	resolve := func(name string) *migrationTableLineage {
		key := strings.ToLower(name)
		if t, ok := l.live[key]; ok {
			return t
		}
		t := &migrationTableLineage{origin: name}
		l.live[key] = t
		if _, ok := l.byOrigin[key]; !ok {
			l.byOrigin[key] = t
		}
		return t
	}
	for _, st := range statements {
		switch st.kind {
		case migrationStmtDropTable:
			if t := resolve(st.table); t != nil {
				t.dropped = st.table
				l.events = append(l.events, migrationLineageEvent{table: t, written: st.table})
			}
			l.live[strings.ToLower(st.table)] = nil
		case migrationStmtRenameTable:
			t := resolve(st.table)
			l.live[strings.ToLower(st.table)] = nil
			if t != nil {
				t.renames = append(t.renames, st.to)
			}
			l.live[strings.ToLower(st.to)] = t
		case migrationStmtCreateTable:
			if st.ifNotExists {
				if t, ok := l.live[strings.ToLower(st.table)]; (ok && t != nil) || (!ok && exists(st.table)) {
					continue
				}
			}
			l.live[strings.ToLower(st.table)] = &migrationTableLineage{filled: st.filled}
		case migrationStmtInsert:
			if t := resolve(st.table); t != nil {
				t.filled = true
			}
		case migrationStmtDropColumn:
			if t := resolve(st.table); t != nil {
				l.events = append(l.events, migrationLineageEvent{table: t, written: st.table, column: st.column, originColumn: t.columnOrigin(st.column)})
				delete(t.columns, strings.ToLower(st.column))
			}
		case migrationStmtRenameColumn:
			if t := resolve(st.table); t != nil {
				orig := t.columnOrigin(st.column)
				if t.columns == nil {
					t.columns = map[string]string{}
				}
				delete(t.columns, strings.ToLower(st.column))
				t.columns[strings.ToLower(st.to)] = orig
			}
		}
	}
	return l
}

type migrationStatementKind int

const (
	migrationStmtDropTable migrationStatementKind = iota + 1
	migrationStmtDropColumn
	migrationStmtRenameTable
	migrationStmtRenameColumn
	migrationStmtCreateTable
	migrationStmtInsert
)

// migrationSchemaStatement is what one statement does to a main-schema table:
// table is the table it names; column and to the column and new name of a
// column drop or rename and the new name of a table rename.
type migrationSchemaStatement struct {
	kind        migrationStatementKind
	table       string
	column, to  string
	ifNotExists bool // CREATE TABLE IF NOT EXISTS
	filled      bool // CREATE TABLE ... AS SELECT
}

// migrationSchemaStatements reads the table drops, column drops, table and
// column renames, table creations and inserts in a migration's UP section,
// in order. A name in another schema (temp, or an attached database) is not
// the app's data and is skipped.
func migrationSchemaStatements(up string) []migrationSchemaStatement {
	var out []migrationSchemaStatement
	for _, toks := range sqlTokenStatements(sqlTokenize(up)) {
		i := sqlStatementVerbIndex(toks)
		kw := func(word string) bool {
			if i < len(toks) && toks[i].kind == sqlTokWord && strings.EqualFold(toks[i].text, word) {
				i++
				return true
			}
			return false
		}
		// name reads [schema .] name and reports whether it is in main.
		name := func() (string, bool) {
			if i >= len(toks) || toks[i].kind == sqlTokPunct {
				return "", false
			}
			first := toks[i].text
			i++
			if i < len(toks) && toks[i].kind == sqlTokPunct && toks[i].text == "." {
				i++
				if i >= len(toks) || toks[i].kind == sqlTokPunct {
					return "", false
				}
				table := toks[i].text
				i++
				return table, strings.EqualFold(first, "main")
			}
			return first, true
		}
		switch {
		case kw("DROP"):
			if !kw("TABLE") {
				continue
			}
			if kw("IF") && !kw("EXISTS") {
				continue
			}
			if table, main := name(); main && table != "" {
				out = append(out, migrationSchemaStatement{kind: migrationStmtDropTable, table: table})
			}
		case kw("ALTER"):
			if !kw("TABLE") {
				continue
			}
			table, main := name()
			if !main || table == "" {
				continue
			}
			switch {
			case kw("DROP"):
				if kw("CONSTRAINT") {
					continue
				}
				kw("COLUMN")
				if column, _ := name(); column != "" {
					out = append(out, migrationSchemaStatement{kind: migrationStmtDropColumn, table: table, column: column})
				}
			case kw("RENAME"):
				if kw("TO") {
					if to, _ := name(); to != "" {
						out = append(out, migrationSchemaStatement{kind: migrationStmtRenameTable, table: table, to: to})
					}
					continue
				}
				kw("COLUMN")
				column, _ := name()
				if column != "" && kw("TO") {
					if to, _ := name(); to != "" {
						out = append(out, migrationSchemaStatement{kind: migrationStmtRenameColumn, table: table, column: column, to: to})
					}
				}
			}
		case kw("CREATE"):
			if kw("TEMP") || kw("TEMPORARY") || !kw("TABLE") {
				continue
			}
			st := migrationSchemaStatement{kind: migrationStmtCreateTable}
			if kw("IF") {
				if !kw("NOT") || !kw("EXISTS") {
					continue
				}
				st.ifNotExists = true
			}
			table, main := name()
			if !main || table == "" {
				continue
			}
			st.table, st.filled = table, kw("AS")
			out = append(out, st)
		case kw("INSERT"), kw("REPLACE"):
			if kw("OR") {
				i++ // the conflict resolution
			}
			if !kw("INTO") {
				continue
			}
			if table, main := name(); main && table != "" {
				out = append(out, migrationSchemaStatement{kind: migrationStmtInsert, table: table})
			}
		}
	}
	return out
}

// migrationApplied reports whether db's ledger records the migration name:
// the runner applies a file once, so rewriting an applied one changes nothing.
func migrationApplied(db *sql.DB, name string) (bool, error) {
	if ok, err := tableExists(db, "_benmore_migrations"); err != nil || !ok {
		return false, err
	}
	var n int
	err := db.QueryRow(`SELECT COUNT(*) FROM _benmore_migrations WHERE name = ?`, name).Scan(&n)
	return n > 0, err
}

// migrationLiveTable is the live name of a main-schema table, matched without
// case as SQLite matches names; "" when there is none.
func migrationLiveTable(db *sql.DB, table string) (string, error) {
	var live string
	err := db.QueryRow(`SELECT name FROM sqlite_master WHERE type = 'table' AND name = ? COLLATE NOCASE`, table).Scan(&live)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return live, err
}

func migrationTableRows(db *sql.DB, table string) (int64, error) {
	live, err := migrationLiveTable(db, table)
	if err != nil || live == "" {
		return 0, err
	}
	var n int64
	err = db.QueryRow("SELECT COUNT(*) FROM " + quoteIdent(live)).Scan(&n)
	return n, err
}

func migrationColumnValues(db *sql.DB, table, column string) (int64, error) {
	live, err := migrationLiveTable(db, table)
	if err != nil || live == "" {
		return 0, err
	}
	var liveColumn string
	err = db.QueryRow(`SELECT name FROM pragma_table_info(?) WHERE name = ? COLLATE NOCASE`, live, column).Scan(&liveColumn)
	if err == sql.ErrNoRows {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var n int64
	err = db.QueryRow("SELECT COUNT(*) FROM " + quoteIdent(live) + " WHERE " + quoteIdent(liveColumn) + " IS NOT NULL").Scan(&n)
	return n, err
}
