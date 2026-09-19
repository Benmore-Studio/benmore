//go:build !cli

package main

// SQLite FTS5 full-text search, auto-wired from `@@fulltext([cols])`
// in schema.prisma. Apps don't write SQL - the framework creates a
// <table>_fts virtual table + INSERT/UPDATE/DELETE triggers + a
// /api/<table>?q=foo handler path. Results are ranked by FTS5's
// built-in BM25, fall back to title-LIKE on engines without FTS5
// (none of the SQLite builds we ship lack it, but defensive code).
//
// Schema example:
//
//   model Note {
//     id    Int    @id @default(autoincrement())
//     title String
//     body  String @default("")
//     @@fulltext([title, body])
//   }
//
// Resulting wire:
//
//   GET /api/notes?q=invoice  → ranked by FTS5 BM25, no LIKE fallback.
//
// The trigger set keeps the FTS index in sync with the canonical
// table - INSERTs add to FTS, UPDATEs replace the row, DELETEs purge
// from FTS. content='<table>' content_rowid='id' is the standard
// "contentless-with-source" form: rows live in the canonical table,
// FTS only stores the tokenized columns.

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

// annotateFullTextFromPrisma reads schema.prisma (if present) and
// attaches the parsed @@fulltext column lists to the matching
// Table.FullText slices. No-op when schema.prisma doesn't exist -
// the app uses LIKE-based fallback search transparently.
func annotateFullTextFromPrisma(dir string, tables []Table) {
	prismaPath := filepath.Join(dir, "schema.prisma")
	data, err := os.ReadFile(prismaPath)
	if err != nil {
		return
	}
	models, err := ParsePrismaSchema(string(data))
	if err != nil {
		return
	}
	byTable := map[string]*PrismaModel{}
	for i := range models {
		byTable[models[i].Table] = &models[i]
	}
	for i := range tables {
		m, ok := byTable[tables[i].Name]
		if !ok {
			continue
		}
		for _, idx := range m.FullText {
			tables[i].FullText = append(tables[i].FullText, idx.Columns)
		}
	}
}

// EnsureFTSTables reconciles indexes after schema migrations. Unchanged
// definitions are read-only no-ops, including indexes from earlier releases.
// A creation, definition change, or trigger repair rebuilds from canonical data
// in one transaction, so a failure leaves the previous index and triggers intact.
func EnsureFTSTables(db *sql.DB, tables []Table) error {
	for _, t := range tables {
		if len(t.FullText) == 0 || len(t.FullText[0]) == 0 {
			continue
		}
		// The first @@fulltext entry is the runtime's search column set.
		if err := ensureOneFTS(db, t.Name, t.FullText[0]); err != nil {
			return fmt.Errorf("fts %s: %w", t.Name, err)
		}
	}
	return nil
}

type ftsTriggerDefinition struct {
	name string
	sql  string
}

type ftsIndexDefinition struct {
	table    string
	index    string
	create   string
	triggers []ftsTriggerDefinition
}

func makeFTSDefinition(table string, cols []string) (ftsIndexDefinition, error) {
	d := ftsIndexDefinition{table: table, index: table + "_fts"}
	if !safeIdent(table) {
		return d, fmt.Errorf("unsafe table name %q", table)
	}
	for _, col := range cols {
		if !safeIdent(col) {
			return d, fmt.Errorf("unsafe column name %q", col)
		}
	}
	d.create = fmt.Sprintf(
		`CREATE VIRTUAL TABLE %s USING fts5(%s, content='%s', content_rowid='id', tokenize='trigram')`,
		d.index, strings.Join(cols, ", "), table,
	)
	colList := strings.Join(cols, ", ")
	newRefs, oldRefs := make([]string, len(cols)), make([]string, len(cols))
	for i, col := range cols {
		newRefs[i], oldRefs[i] = "new."+col, "old."+col
	}
	d.triggers = []ftsTriggerDefinition{
		{d.index + "_ai", fmt.Sprintf(`CREATE TRIGGER %s_ai AFTER INSERT ON %s BEGIN INSERT INTO %s(rowid, %s) VALUES (new.id, %s); END`,
			d.index, table, d.index, colList, strings.Join(newRefs, ", "))},
		{d.index + "_ad", fmt.Sprintf(`CREATE TRIGGER %s_ad AFTER DELETE ON %s BEGIN INSERT INTO %s(%s, rowid, %s) VALUES('delete', old.id, %s); END`,
			d.index, table, d.index, d.index, colList, strings.Join(oldRefs, ", "))},
		{d.index + "_au", fmt.Sprintf(`CREATE TRIGGER %s_au AFTER UPDATE ON %s BEGIN INSERT INTO %s(%s, rowid, %s) VALUES('delete', old.id, %s); INSERT INTO %s(rowid, %s) VALUES (new.id, %s); END`,
			d.index, table, d.index, d.index, colList, strings.Join(oldRefs, ", "), d.index, colList, strings.Join(newRefs, ", "))},
	}
	return d, nil
}

// sqlite_master is the persisted definition fingerprint: SQLite removes IF NOT
// EXISTS when storing the CREATE statement, including on older framework builds.
// Generated identifiers have no spaces, so whitespace/case normalization is safe.
func normalizeFTSDefinition(sql string) string {
	return strings.ToLower(strings.Join(strings.Fields(sql), " "))
}

func (d ftsIndexDefinition) matches(db mutationQuerier) (indexMatches, triggersMatch bool, err error) {
	var existingSQL string
	err = db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name=? COLLATE NOCASE`, d.index).Scan(&existingSQL)
	if err != nil && err != sql.ErrNoRows {
		return false, false, err
	}
	if existingSQL != "" {
		normalized := normalizeFTSDefinition(existingSQL)
		compact := strings.ReplaceAll(normalized, " ", "")
		if !strings.HasPrefix(normalized, "create virtual table ") || !strings.Contains(compact, "usingfts5(") ||
			!strings.Contains(compact, "content='"+strings.ToLower(d.table)+"'") {
			return false, false, fmt.Errorf("refusing to replace %s: not an external-content FTS5 index for %s", d.index, d.table)
		}
	}
	indexMatches = normalizeFTSDefinition(existingSQL) == normalizeFTSDefinition(d.create)
	triggersMatch = true
	for _, trigger := range d.triggers {
		var table, storedSQL string
		err := db.QueryRow(`SELECT tbl_name, sql FROM sqlite_master WHERE type='trigger' AND name=? COLLATE NOCASE`, trigger.name).Scan(&table, &storedSQL)
		if err != nil && err != sql.ErrNoRows {
			return false, false, err
		}
		if table != "" && !strings.EqualFold(table, d.table) {
			return false, false, fmt.Errorf("trigger %s belongs to another table", trigger.name)
		}
		if normalizeFTSDefinition(storedSQL) != normalizeFTSDefinition(trigger.sql) {
			triggersMatch = false
		}
	}
	return indexMatches, triggersMatch, nil
}

func ensureOneFTS(db *sql.DB, table string, cols []string) error {
	d, err := makeFTSDefinition(table, cols)
	if err != nil {
		return err
	}
	indexMatches, triggersMatch, err := d.matches(db)
	if err != nil || (indexMatches && triggersMatch) {
		return err
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// Another process may have reconciled it while this one waited for the
	// app database's immediate transaction lock. Recheck before writing.
	indexMatches, triggersMatch, err = d.matches(tx)
	if err != nil {
		return err
	}
	if indexMatches && triggersMatch {
		return nil
	}
	for _, trigger := range d.triggers {
		if _, err := tx.Exec("DROP TRIGGER IF EXISTS " + trigger.name); err != nil {
			return fmt.Errorf("remove trigger: %w", err)
		}
	}
	if !indexMatches {
		if _, err := tx.Exec("DROP TABLE IF EXISTS " + d.index); err != nil {
			return fmt.Errorf("replace index: %w", err)
		}
		if _, err := tx.Exec(d.create); err != nil {
			return fmt.Errorf("create index: %w", err)
		}
	}
	for _, trigger := range d.triggers {
		if _, err := tx.Exec(trigger.sql); err != nil {
			return fmt.Errorf("create trigger: %w", err)
		}
	}
	// A missing/changed trigger may have let writes escape indexing. Rebuild
	// for both definition changes and trigger repairs before committing.
	if _, err := tx.Exec(fmt.Sprintf(`INSERT INTO %s(%s) VALUES('rebuild')`, d.index, d.index)); err != nil {
		return fmt.Errorf("rebuild index: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit index: %w", err)
	}
	log.Printf("  fts: %s indexed on (%s)", table, strings.Join(cols, ", "))
	return nil
}

// escapeFTS5Query transforms a user-supplied search string into a safe
// FTS5 MATCH expression. Each whitespace-separated token becomes a
// quoted phrase, with embedded double-quotes doubled per FTS5's escape
// rule. Multi-token queries join as implicit AND.
//
// Why: FTS5 MATCH has its own syntax where `.`, `:`, `*`, `@`, `(`,
// `)`, `"` are special. One app.s `?q=alice.garcia@cyberdyne.ai`
// hit `fts5: syntax error near "."` - a literal email or a UUID or
// any value-with-punctuation became un-searchable. Quoting as a phrase
// makes every special char literal:
//
//	?q=alice                          → "alice"
//	?q=alice cooper                   → "alice" "cooper"            (AND)
//	?q=alice.garcia@cyberdyne.ai      → "alice.garcia@cyberdyne.ai"
//	?q=he said "hi"                   → "he" "said" """hi"""
//
// Power users who want raw FTS5 syntax (OR, NEAR, prefix-*) write a
// custom flow that exec's the MATCH expression directly. The auto-CRUD
// path optimizes for the 99% case: "find rows containing this string."
func escapeFTS5Query(q string) string {
	tokens := strings.Fields(q)
	if len(tokens) == 0 {
		return ""
	}
	parts := make([]string, 0, len(tokens))
	for _, t := range tokens {
		escaped := strings.ReplaceAll(t, `"`, `""`)
		parts = append(parts, `"`+escaped+`"`)
	}
	return strings.Join(parts, " ")
}

// ftsTrigramUsable reports whether every whitespace token in q is ≥3 runes -
// the minimum the trigram tokenizer can index/match. A query with any shorter
// token (e.g. "ab", or "ab cdef") can't be served by trigram MATCH (the short
// token's phrase matches nothing → AND yields zero rows), so the CRUD path
// falls back to LIKE for those.
func ftsTrigramUsable(q string) bool {
	toks := strings.Fields(q)
	if len(toks) == 0 {
		return false
	}
	for _, t := range toks {
		if len([]rune(t)) < 3 {
			return false
		}
	}
	return true
}

// buildFTSLikeFallback builds a case-insensitive substring WHERE clause across
// the FTS columns, for queries too short for trigram. %/_/\ in the query are
// escaped so they're literal, not LIKE wildcards. Not index-accelerated, but
// sub-3-char queries are rare and result sets are bounded.
func buildFTSLikeFallback(table string, cols []string, q string) (string, []any) {
	esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(q)
	like := "%" + esc + "%"
	parts := make([]string, 0, len(cols))
	args := make([]any, 0, len(cols))
	for _, c := range cols {
		if !safeIdent(c) {
			continue
		}
		parts = append(parts, fmt.Sprintf(`%s.%s LIKE ? ESCAPE '\'`, table, c))
		args = append(args, like)
	}
	if len(parts) == 0 {
		return "", nil
	}
	return "(" + strings.Join(parts, " OR ") + ")", args
}

// FTSTableFor returns the FTS virtual table name + columns for a
// given canonical table, or "" if not indexed. The CRUD handler
// calls this when ?q= is present.
func FTSTableFor(tables []Table, name string) (string, []string) {
	for _, t := range tables {
		if t.Name != name {
			continue
		}
		if len(t.FullText) == 0 || len(t.FullText[0]) == 0 {
			return "", nil
		}
		return t.Name + "_fts", t.FullText[0]
	}
	return "", nil
}

// safeIdent reports whether s is a SQL identifier we can safely
// concatenate. Mirrors sanitizeIdent semantics from operations_extras.go
// but available to fts.go callers without circular deps.
func safeIdent(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_') {
			return false
		}
	}
	return true
}
