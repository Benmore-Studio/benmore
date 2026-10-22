//go:build !cli

package main

// Framework-managed indexes on scoping columns.
//
// Every auto-CRUD list, read and member-of check filters on the same few
// columns - the owner (user_id), the tenant key (groups.key), relation
// columns (?include= expansion, child tables), and the membership table's
// (join, user) pair inside the member-of EXISTS. Only @@index/@@unique in
// schema.prisma ever created an index, so in most apps each of those was a
// full table scan, and the member-of EXISTS a correlated scan per row.
//
// EnsureScopingIndexes adds `CREATE INDEX IF NOT EXISTS idx_bm_<table>_<cols>`
// for those columns on the LIVE database at app start and hot reload. It
// works from live metadata (PRAGMA table_info / foreign_key_list /
// index_list) rather than EmitSQL, so it covers schema.sql apps, columns
// that predate the current schema file and existing databases, and it leaves
// EmitSQL's output - which migration files and promote's diff are built
// from - unchanged. Promote is unaffected: its diff compares columns, and
// prod builds the same indexes when it next starts.
//
// Rules: additive only (never drops or rewrites an index); skipped when any
// existing non-partial index (user-declared, UNIQUE, primary-key autoindex
// or framework) already leads with the same column; non-unique, so it can
// never reject a write. The idx_bm_ prefix marks the index as
// framework-owned: dropFrameworkIndexesForColumn removes them before a
// DROP COLUMN (SQLite refuses to drop an indexed column), and connector
// revision digests ignore them.

import (
	"database/sql"
	"fmt"
	"log"
	"regexp"
	"strings"
	"time"
)

const frameworkIndexPrefix = "idx_bm_"

type scopingIndexSpec struct {
	table string
	cols  []string
}

func (s scopingIndexSpec) name() string {
	return frameworkIndexPrefix + s.table + "_" + strings.Join(s.cols, "_")
}

func (s scopingIndexSpec) createSQL() string {
	quoted := make([]string, len(s.cols))
	for i, c := range s.cols {
		quoted[i] = quoteIdent(c)
	}
	return fmt.Sprintf("CREATE INDEX IF NOT EXISTS %s ON %s(%s)",
		quoteIdent(s.name()), quoteIdent(s.table), strings.Join(quoted, ", "))
}

// EnsureScopingIndexes creates the missing framework scoping indexes for
// app's live database and returns the names it created.
func EnsureScopingIndexes(app *App) []string {
	if app == nil || app.DB == nil {
		return nil
	}
	specs, err := planScopingIndexes(app)
	if err != nil {
		log.Printf("  scoping indexes: skipped (%v)", err)
		return nil
	}
	var created []string
	for _, s := range specs {
		start := time.Now()
		if _, err := app.DB.Exec(s.createSQL()); err != nil {
			log.Printf("  scoping index %s: %v", s.name(), err)
			continue
		}
		created = append(created, s.name())
		log.Printf("  scoping index: %s on %s(%s) in %s", s.name(), s.table, strings.Join(s.cols, ", "), time.Since(start).Round(time.Millisecond))
	}
	return created
}

// planScopingIndexes returns the indexes EnsureScopingIndexes would create.
func planScopingIndexes(app *App) ([]scopingIndexSpec, error) {
	tables, err := GetTableNames(app.DB)
	if err != nil {
		return nil, err
	}
	live := map[string]string{} // folded name -> live name
	for _, t := range tables {
		live[sqliteIdentifierFold(t)] = t
	}

	// Composite (join, user) indexes on membership tables come first, so a
	// single-column FK index on the join column doesn't then shadow them.
	var wanted []scopingIndexSpec
	seen := map[string]bool{}
	want := func(table string, cols ...string) {
		key := sqliteIdentifierFold(table + "\x00" + strings.Join(cols, "\x00"))
		if !seen[key] {
			seen[key] = true
			wanted = append(wanted, scopingIndexSpec{table: table, cols: cols})
		}
	}
	for _, t := range tables {
		for _, op := range []AccessOp{OpRead, OpUpdate, OpDelete} {
			rule := memberOfFor(app, t, op)
			if rule == nil {
				continue
			}
			if mt, ok := live[sqliteIdentifierFold(rule.Table)]; ok {
				want(mt, rule.JoinCol, rule.UserCol)
			}
			// Child tables join on their own copy of the parent key.
			want(t, rule.JoinCol)
		}
	}
	if g := app.Group; g != nil && g.Table != "" && g.UserField != "" {
		if mt, ok := live[sqliteIdentifierFold(g.Table)]; ok {
			want(mt, g.UserField) // session group resolution looks members up by user
		}
	}
	for _, t := range tables {
		if strings.HasSuffix(t, "_history") {
			continue // versioning history: append-only, not a CRUD read path
		}
		want(t, "user_id")
		if app.Group != nil && app.Group.Key != "" {
			want(t, app.Group.Key)
		}
		fks, err := GetForeignKeys(app.DB, t)
		if err == nil {
			for col := range fks {
				want(t, col)
			}
		}
	}

	var out []scopingIndexSpec
	for _, s := range wanted {
		ok, err := scopingIndexNeeded(app.DB, s)
		if err != nil {
			return nil, err
		}
		if ok {
			out = append(out, s)
		}
	}
	return out, nil
}

var scopingIdentRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// scopingIndexNeeded reports whether s names existing columns that no
// non-partial index already leads with, and that are not the rowid alias.
func scopingIndexNeeded(db *sql.DB, s scopingIndexSpec) (bool, error) {
	if !scopingIdentRe.MatchString(s.table) {
		return false, nil
	}
	cols, err := GetTableColumns(db, s.table)
	if err != nil {
		return false, err
	}
	byName := map[string]Column{}
	pkCount := 0
	for _, c := range cols {
		byName[sqliteIdentifierFold(c.Name)] = c
		if c.PK {
			pkCount++
		}
	}
	for i, c := range s.cols {
		if !scopingIdentRe.MatchString(c) {
			return false, nil
		}
		col, ok := byName[sqliteIdentifierFold(c)]
		if !ok {
			return false, nil
		}
		s.cols[i] = col.Name
		// An INTEGER PRIMARY KEY is the rowid: already the table's key.
		if i == 0 && col.PK && pkCount == 1 && strings.EqualFold(col.Type, "INTEGER") {
			return false, nil
		}
	}
	leading, err := indexLeadingColumns(db, s.table)
	if err != nil {
		return false, err
	}
	return !leading[sqliteIdentifierFold(s.cols[0])], nil
}

// indexLeadingColumns returns the folded first column of every non-partial
// index on table (primary-key and UNIQUE autoindexes included).
func indexLeadingColumns(db *sql.DB, table string) (map[string]bool, error) {
	rows, err := db.Query("SELECT name, partial FROM pragma_index_list(?)", table)
	if err != nil {
		return nil, err
	}
	var names []string
	for rows.Next() {
		var name string
		var partial int
		if err := rows.Scan(&name, &partial); err != nil {
			rows.Close()
			return nil, err
		}
		if partial == 0 {
			names = append(names, name)
		}
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for _, name := range names {
		var col sql.NullString
		err := db.QueryRow("SELECT name FROM pragma_index_info(?) WHERE seqno = 0", name).Scan(&col)
		if err == sql.ErrNoRows {
			continue
		}
		if err != nil {
			return nil, err
		}
		if col.Valid { // NULL = expression / rowid key
			out[sqliteIdentifierFold(col.String)] = true
		}
	}
	return out, nil
}

// dropColumnStmtRe matches `ALTER TABLE t DROP [COLUMN] c` (optionally
// quoted identifiers) so migration runners can clear framework indexes first.
var dropColumnStmtRe = regexp.MustCompile("(?is)^\\s*ALTER\\s+TABLE\\s+(?:main\\.)?[\"`\\[]?([A-Za-z_][A-Za-z0-9_]*)[\"`\\]]?\\s+DROP\\s+(?:COLUMN\\s+)?[\"`\\[]?([A-Za-z_][A-Za-z0-9_]*)[\"`\\]]?\\s*;?\\s*$")

type sqlExecQuerier interface {
	Exec(string, ...any) (sql.Result, error)
	Query(string, ...any) (*sql.Rows, error)
}

// dropFrameworkIndexesForStatement drops the framework scoping indexes that
// would make stmt fail when stmt is an `ALTER TABLE ... DROP COLUMN`. SQLite
// refuses to drop an indexed column, and these indexes were added by the
// framework, not the app author, so a schema change that removes the column
// must not fail on them. Other statements are a no-op. Indexes the author
// declared are never touched.
func dropFrameworkIndexesForStatement(db sqlExecQuerier, stmt string) error {
	m := dropColumnStmtRe.FindStringSubmatch(stmt)
	if m == nil {
		return nil
	}
	return dropFrameworkIndexesForColumn(db, m[1], m[2])
}

func dropFrameworkIndexesForColumn(db sqlExecQuerier, table, column string) error {
	rows, err := db.Query(`SELECT il.name FROM pragma_index_list(?) AS il
		WHERE il.name LIKE 'idx\_bm\_%' ESCAPE '\'
		  AND EXISTS (SELECT 1 FROM pragma_index_info(il.name) AS ii WHERE ii.name = ? COLLATE NOCASE)`, table, column)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			rows.Close()
			return err
		}
		names = append(names, n)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, n := range names {
		if _, err := db.Exec("DROP INDEX IF EXISTS " + quoteIdent(n)); err != nil {
			return err
		}
	}
	return nil
}

// isFrameworkScopingIndex reports whether an index name is framework-owned.
func isFrameworkScopingIndex(name string) bool {
	return strings.HasPrefix(name, frameworkIndexPrefix)
}
