//go:build !cli

package main

// SQLite FTS5 full-text search, auto-wired from `@@fulltext([cols])`
// in schema.prisma. Apps don't write SQL — the framework creates a
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
// table — INSERTs add to FTS, UPDATEs replace the row, DELETEs purge
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
// Table.FullText slices. No-op when schema.prisma doesn't exist —
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

// EnsureFTSTables creates the <table>_fts virtual table + sync
// triggers for every table that declared @@fulltext. Idempotent.
// Run after migrations so the canonical tables exist.
func EnsureFTSTables(db *sql.DB, tables []Table) {
	for _, t := range tables {
		if len(t.FullText) == 0 {
			continue
		}
		// Use the FIRST @@fulltext entry as the FTS column set. SQLite
		// allows multiple FTS indexes per table but it's unusual; if
		// apps want that, they can declare it manually in migrations.
		cols := t.FullText[0]
		if len(cols) == 0 {
			continue
		}
		ensureOneFTS(db, t.Name, cols)
	}
}

func ensureOneFTS(db *sql.DB, table string, cols []string) {
	ftsTable := table + "_fts"
	// Sanity: column identifiers must be safe. We control the input
	// (Prisma parser already validated) but double-check.
	for _, c := range cols {
		if !safeIdent(c) {
			log.Printf("fts: skipping %s — unsafe column name %q", table, c)
			return
		}
	}
	if !safeIdent(table) {
		return
	}

	// Trigram tokenizer → true SUBSTRING ("contains") search, case-
	// insensitive. The default tokenizer only matches WHOLE tokens, so
	// ?q=test missed "testing" / "contest" / "mytest" and matched only a
	// standalone "test" token — read as flaky search and forced apps onto
	// client-side fuzzy matching. Trigram indexes every 3-char window so a
	// quoted phrase MATCH finds the substring anywhere in the column.
	//
	// Migrate legacy (non-trigram) FTS tables: detect by the stored CREATE
	// SQL and DROP+recreate. FTS is derived data — the rebuild below
	// repopulates it from the content table, so this is lossless.
	var existingSQL string
	_ = db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='table' AND name=?`, ftsTable).Scan(&existingSQL)
	if existingSQL != "" && !strings.Contains(strings.ToLower(existingSQL), "trigram") {
		if _, err := db.Exec(fmt.Sprintf(`DROP TABLE IF EXISTS %s`, ftsTable)); err != nil {
			log.Printf("fts: drop legacy %s for trigram migration: %s", ftsTable, err)
		} else {
			log.Printf("  fts: migrating %s to trigram (substring search)", ftsTable)
		}
	}

	create := fmt.Sprintf(
		`CREATE VIRTUAL TABLE IF NOT EXISTS %s USING fts5(%s, content='%s', content_rowid='id', tokenize='trigram')`,
		ftsTable, strings.Join(cols, ", "), table,
	)
	if _, err := db.Exec(create); err != nil {
		log.Printf("fts: create %s: %s", ftsTable, err)
		return
	}

	// Triggers: keep FTS row-for-row in sync with the canonical table.
	// "delete-insert" on UPDATE because FTS5 doesn't have a native
	// UPDATE rowid path.
	colList := strings.Join(cols, ", ")
	newRefs := make([]string, len(cols))
	oldRefs := make([]string, len(cols))
	for i, c := range cols {
		newRefs[i] = "new." + c
		oldRefs[i] = "old." + c
	}
	stmts := []string{
		fmt.Sprintf(`DROP TRIGGER IF EXISTS %s_ai`, ftsTable),
		fmt.Sprintf(`DROP TRIGGER IF EXISTS %s_ad`, ftsTable),
		fmt.Sprintf(`DROP TRIGGER IF EXISTS %s_au`, ftsTable),
		fmt.Sprintf(`CREATE TRIGGER %s_ai AFTER INSERT ON %s BEGIN INSERT INTO %s(rowid, %s) VALUES (new.id, %s); END`,
			ftsTable, table, ftsTable, colList, strings.Join(newRefs, ", ")),
		fmt.Sprintf(`CREATE TRIGGER %s_ad AFTER DELETE ON %s BEGIN INSERT INTO %s(%s, rowid, %s) VALUES('delete', old.id, %s); END`,
			ftsTable, table, ftsTable, ftsTable, colList, strings.Join(oldRefs, ", ")),
		fmt.Sprintf(`CREATE TRIGGER %s_au AFTER UPDATE ON %s BEGIN INSERT INTO %s(%s, rowid, %s) VALUES('delete', old.id, %s); INSERT INTO %s(rowid, %s) VALUES (new.id, %s); END`,
			ftsTable, table, ftsTable, ftsTable, colList, strings.Join(oldRefs, ", "), ftsTable, colList, strings.Join(newRefs, ", ")),
	}
	for _, s := range stmts {
		if _, err := db.Exec(s); err != nil {
			log.Printf("fts: trigger: %s — %s", s, err)
			return
		}
	}

	// Backfill any existing rows that pre-date the FTS index. Safe to
	// run on every boot — the INSERT OR REPLACE semantics of the
	// rebuild command keep it idempotent.
	if _, err := db.Exec(fmt.Sprintf(`INSERT INTO %s(%s) VALUES('rebuild')`, ftsTable, ftsTable)); err != nil {
		log.Printf("fts: rebuild %s: %s", ftsTable, err)
	}
	log.Printf("  fts: %s indexed on (%s)", table, strings.Join(cols, ", "))
}

// escapeFTS5Query transforms a user-supplied search string into a safe
// FTS5 MATCH expression. Each whitespace-separated token becomes a
// quoted phrase, with embedded double-quotes doubled per FTS5's escape
// rule. Multi-token queries join as implicit AND.
//
// Why: FTS5 MATCH has its own syntax where `.`, `:`, `*`, `@`, `(`,
// `)`, `"` are special. One app.s `?q=alice.garcia@cyberdyne.ai`
// hit `fts5: syntax error near "."` — a literal email or a UUID or
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

// ftsTrigramUsable reports whether every whitespace token in q is ≥3 runes —
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
