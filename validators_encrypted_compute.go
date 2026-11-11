//go:build !cli

package main

// Computed fields and aggregates that read an encrypted column.
//
// computed.yaml `expr:`/`sql:` and app.yaml `aggregates:` SQL run in SQLite on
// the stored value, and an encrypted column stores ciphertext (enc:v2:...).
// `substr(ssn, -4)` gave hex from the ciphertext (a new value on every write
// and every key rotation, readable by viewers who see ssn masked),
// `length(col)` the plaintext's length, `SUM(salary)` a silent 0, while push
// and `benmore check` stayed clean (round 2026-11-05). /api/_query refuses
// SUM/AVG/MIN/MAX over an encrypted column for the same reason.
//
// Such a field or aggregate is refused when it is written (write_file,
// edit_file, push, deploy) and is an error in `benmore check`, filed on the
// file that holds it (computed.yaml or app.yaml). A write of encrypted.yaml,
// app.yaml (its legacy encrypted: section) or schema.prisma that makes one
// read an encrypted column is refused too, naming it, unless the batch writes
// that file next (pending). The load never refuses one: an app that already
// has such a field keeps loading and computing what it did.
//
// Which columns a field reads is SQLite's answer, not a text match: each one
// is compiled against an in-memory copy of schema.prisma's tables with an
// authorizer recording every column read (as the page-query read boundary
// does, page_query_reads.go), so qualified names, aliases, subqueries and
// joins resolve as at run time. An expr: is compiled inside the trigger the
// load installs for it (computedExprTriggerSQL). A field the copy cannot
// compile (a table only a migration creates, an error another check reports)
// is not judged.
//
// The uses that work on ciphertext stay allowed: a null test (col IS NULL, IS
// NOT NULL, ISNULL, NOTNULL, NOT NULL) and COUNT(col). They are rewritten to
// read nothing before the field is compiled (encryptedComputeAnalysisSQL).
// benmore_decrypt(col) is not exempt: it would copy plaintext derived from the
// field into a column every reader sees unmasked.

import (
	"bytes"
	"context"
	"database/sql"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"

	"github.com/mattn/go-sqlite3"
)

// encryptedComputeInputs are the files whose content decides these problems.
var encryptedComputeInputs = map[string]bool{"schema.prisma": true, "app.yaml": true, "encrypted.yaml": true, "computed.yaml": true}

type encryptedComputeProblem struct {
	file    string // computed.yaml or app.yaml: the file that holds the field
	key     string // identity of the problem across two states of the app
	message string
}

const encryptedComputeWhy = "Computed fields and aggregates run in SQLite on the stored value, and an encrypted column stores ciphertext (enc:v2:...), not the plaintext. " +
	"Text functions, ||, comparisons and arithmetic over it give values derived from the ciphertext (different on every write, changed by every key rotation, and shown to readers who see the field masked), " +
	"and SUM, AVG, MIN and MAX give a wrong number with no error. benmore_decrypt(col) would copy plaintext into a column every reader sees unmasked. " +
	"Only a null test (col IS NULL, col IS NOT NULL) and COUNT(col) work on an encrypted column, and those are allowed."

const encryptedComputeFix = "Keep the value you need in its own plain column and write it where the plaintext is: from the client, together with the record (a last-4 column next to the encrypted one), " +
	"or in the flow that writes the record (e.g. `substr(:ssn, -4)` bound in its `run: sql` step). If the column does not need encryption at rest, remove it from encrypted.yaml instead. " +
	"An app that already has such a field keeps loading; only writes and `benmore check` refuse it."

// encryptedComputeProblems lists every computed field and aggregate that reads
// an encrypted column, or nil when there is nothing to judge.
func encryptedComputeProblems(src loadRefSource) []encryptedComputeProblem {
	appData := src.read("app.yaml")
	encData := src.read("encrypted.yaml")
	enc := parseEncryptedFieldsConfig(encData, appData)
	if enc == nil {
		return nil
	}
	computed := encryptedComputeComputedConfig(src.read("computed.yaml"))
	aggregates := encryptedComputeAggregateSQL(appData)
	if computed == nil && len(aggregates) == 0 {
		return nil
	}
	schemaData := src.read("schema.prisma")
	if schemaData == nil {
		return nil
	}
	models, err := ParsePrismaSchema(string(schemaData))
	if err != nil || len(models) == 0 {
		return nil
	}

	// Folded table → folded column → "table.column" as declared, and which
	// file declares it (encrypted.yaml wins per table over app.yaml).
	fromFile := parseEncryptedFieldsConfig(encData, nil)
	encrypted := map[string]map[string]string{}
	declaredIn := map[string]string{}
	for table, defs := range enc.Fields {
		t := sqliteIdentifierFold(table)
		if encrypted[t] == nil {
			encrypted[t] = map[string]string{}
		}
		declaredIn[t] = "app.yaml (encrypted:)"
		if fromFile != nil && fromFile.Fields[table] != nil {
			declaredIn[t] = "encrypted.yaml"
		}
		for _, def := range defs {
			encrypted[t][sqliteIdentifierFold(def.Column)] = table + "." + def.Column
		}
	}

	compiler, err := newSQLReadCompiler(EmitSQL(models))
	if err != nil {
		return nil
	}
	defer compiler.close()

	var out []encryptedComputeProblem
	report := func(file, id, label string, reads *pageQueryReads, skipTable, skipColumn string) {
		if reads == nil {
			return
		}
		var hits []string
		for table, columns := range reads.tables {
			t := sqliteIdentifierFold(table)
			for column := range columns {
				if t == sqliteIdentifierFold(skipTable) && column == sqliteIdentifierFold(skipColumn) {
					continue
				}
				if name, ok := encrypted[t][column]; ok {
					hits = append(hits, t+"\x00"+name)
				}
			}
		}
		slices.Sort(hits)
		for _, hit := range slices.Compact(hits) {
			t, name, _ := strings.Cut(hit, "\x00")
			out = append(out, encryptedComputeProblem{
				file:    file,
				key:     id + ":" + sqliteIdentifierFold(name),
				message: fmt.Sprintf("%s: %s reads %s, which %s encrypts.", file, label, name, declaredIn[t]),
			})
		}
	}
	if computed != nil {
		for _, table := range slices.Sorted(maps.Keys(computed.Fields)) {
			for _, column := range slices.Sorted(maps.Keys(computed.Fields[table])) {
				cf := computed.Fields[table][column]
				if cf == nil || computedFieldIdentError(cf) != nil {
					continue
				}
				field := sqliteIdentifierFold(cf.Table) + "." + sqliteIdentifierFold(cf.Column)
				if cf.Expr != "" {
					reads := compiler.exprReads(cf.Table, cf.Column, encryptedComputeAnalysisSQL(cf.Expr))
					report("computed.yaml", "computed-expr:"+field, fmt.Sprintf("%s.%s (expr)", cf.Table, cf.Column), reads, cf.Table, cf.Column)
				}
				if cf.SQL != "" && len(cf.Triggers) > 0 {
					reads := compiler.statementReads(encryptedComputeAnalysisSQL(cf.SQL))
					report("computed.yaml", "computed-sql:"+field, fmt.Sprintf("%s.%s (sql)", cf.Table, cf.Column), reads, "", "")
				}
			}
		}
	}
	for _, name := range slices.Sorted(maps.Keys(aggregates)) {
		reads := compiler.statementReads(encryptedComputeAnalysisSQL(aggregates[name]))
		report("app.yaml", "aggregate:"+name, "aggregate "+name, reads, "", "")
	}
	return out
}

// encryptedComputeComputedConfig is computed.yaml as the load reads it, or nil
// for an empty or unreadable file (other checks report those).
func encryptedComputeComputedConfig(data []byte) *ComputedFieldConfig {
	if len(bytes.TrimSpace(data)) == 0 {
		return nil
	}
	var document map[string]any
	if decodeConfigYAML(data, &document) != nil || len(document) == 0 {
		return nil
	}
	config := parseComputedFieldsYAML(data)
	if config == nil || len(config.Fields) == 0 {
		return nil
	}
	return config
}

// encryptedComputeAggregateSQL is app.yaml's aggregates: name → sql. It reads
// the section without parseAggregateConfig, which logs about refresh values.
func encryptedComputeAggregateSQL(appData []byte) map[string]string {
	if appData == nil {
		return nil
	}
	var raw map[string]any
	if decodeConfigYAML(appData, &raw) != nil {
		return nil
	}
	section, _ := raw["aggregates"].(map[string]any)
	out := map[string]string{}
	for name, v := range section {
		entry, _ := v.(map[string]any)
		if query, _ := entry["sql"].(string); strings.TrimSpace(query) != "" {
			out[name] = query
		}
	}
	return out
}

// sqlReadCompiler compiles statements against an in-memory schema and reports
// the columns each one reads. Nothing it compiles is run: statements are only
// prepared, and the analysis trigger an expr: needs is dropped again.
type sqlReadCompiler struct {
	db        *sql.DB
	conn      *sql.Conn
	ctx       context.Context
	recording atomic.Pointer[pageQueryReads]
}

func newSQLReadCompiler(ddl string) (*sqlReadCompiler, error) {
	if strings.TrimSpace(ddl) == "" {
		return nil, fmt.Errorf("no schema")
	}
	db, err := sql.Open(sqliteMaintenanceDriver, ":memory:")
	if err != nil {
		return nil, err
	}
	// One connection: every pooled :memory: connection is its own database.
	db.SetMaxOpenConns(1)
	c := &sqlReadCompiler{db: db, ctx: context.Background()}
	if c.conn, err = db.Conn(c.ctx); err != nil {
		db.Close()
		return nil, err
	}
	if _, err := c.conn.ExecContext(c.ctx, ddl); err != nil {
		c.close()
		return nil, err
	}
	err = c.conn.Raw(func(raw any) error {
		sqlite, ok := sqliteConnOf(raw)
		if !ok {
			return fmt.Errorf("read analysis requires the SQLite authorizer")
		}
		sqlite.RegisterAuthorizer(func(action int, arg1, arg2, database string) int {
			if action == sqlite3.SQLITE_READ {
				if r := c.recording.Load(); r != nil {
					r.record(arg1, arg2)
				}
			}
			return sqlite3.SQLITE_OK
		})
		return nil
	})
	if err != nil {
		c.close()
		return nil, err
	}
	return c, nil
}

func (c *sqlReadCompiler) close() {
	if c.conn != nil {
		c.conn.Close()
	}
	c.db.Close()
}

// prepare compiles one statement and returns what it reads, or nil when it
// does not compile.
func (c *sqlReadCompiler) prepare(statement string) *pageQueryReads {
	reads := &pageQueryReads{}
	c.recording.Store(reads)
	stmt, err := c.conn.PrepareContext(c.ctx, statement)
	c.recording.Store(nil)
	if err != nil {
		return nil
	}
	stmt.Close()
	return reads
}

// statementReads is what every statement of text reads (the driver runs each
// of them), or nil when one does not compile.
func (c *sqlReadCompiler) statementReads(text string) *pageQueryReads {
	all := &pageQueryReads{}
	compiled := false
	for strings.TrimSpace(text) != "" {
		n, ok := sqliteStatementLen(text, false)
		if !ok {
			break
		}
		reads := c.prepare(text[:n])
		if reads == nil {
			return nil
		}
		for table, columns := range reads.tables {
			for column := range columns {
				all.record(table, column)
			}
		}
		compiled = true
		text = text[n:]
	}
	if !compiled {
		return nil
	}
	return all
}

// exprReads is what a same-row expression reads inside the trigger the load
// installs for it, compiled by the insert that fires it.
func (c *sqlReadCompiler) exprReads(table, column, expr string) *pageQueryReads {
	name, create := computedExprTriggerSQL(&ComputedField{Table: table, Column: column, Expr: expr}, "insert")
	if _, err := c.conn.ExecContext(c.ctx, create); err != nil {
		return nil
	}
	defer c.conn.ExecContext(c.ctx, "DROP TRIGGER IF EXISTS "+quoteIdent(name))
	return c.prepare("INSERT INTO " + quoteIdent(table) + " DEFAULT VALUES")
}

// encryptedComputeNotRefs are keywords a null test can follow that are not
// column references.
var encryptedComputeNotRefs = map[string]bool{
	"AND": true, "BETWEEN": true, "BY": true, "CASE": true, "CURRENT_DATE": true, "CURRENT_TIME": true, "CURRENT_TIMESTAMP": true,
	"DISTINCT": true, "ELSE": true, "END": true, "ESCAPE": true, "FALSE": true, "GLOB": true, "IN": true, "IS": true, "LIKE": true,
	"NOT": true, "NULL": true, "ON": true, "OR": true, "SELECT": true, "THEN": true, "TRUE": true, "WHEN": true, "WHERE": true,
}

// encryptedComputeAnalysisSQL replaces each column reference that only a null
// test or COUNT(col) reads with NULL, so compiling the result reports no read
// of it. Everything else, quoting and parameters included, is left as written.
func encryptedComputeAnalysisSQL(text string) string {
	toks := sqlTokenize(text)
	word := func(i int) string {
		if i < 0 || i >= len(toks) || toks[i].kind != sqlTokWord {
			return ""
		}
		return strings.ToUpper(toks[i].text)
	}
	punct := func(i int, p string) bool {
		return i >= 0 && i < len(toks) && pageQueryIsPunct(toks[i], p)
	}
	type span struct{ start, end int }
	var spans []span
	for i := 0; i < len(toks); i++ {
		if !pageQueryName(toks[i]) || punct(i-1, ".") || encryptedComputeNotRefs[word(i)] {
			continue
		}
		// A reference is name, schema.table.column or table.column.
		j := i + 1
		for j+1 < len(toks) && j-i < 5 && punct(j, ".") && pageQueryName(toks[j+1]) {
			j += 2
		}
		if punct(j, "(") {
			continue // a function call
		}
		// next is the first token after the null test or COUNT( ), 0 for
		// neither.
		next := 0
		switch {
		case word(j) == "ISNULL" || word(j) == "NOTNULL":
			next = j + 1
		case word(j) == "IS" && word(j+1) == "NULL", word(j) == "NOT" && word(j+1) == "NULL":
			next = j + 2
		case word(j) == "IS" && word(j+1) == "NOT" && word(j+2) == "NULL":
			next = j + 3
		case word(i-2) == "COUNT" && punct(i-1, "(") && punct(j, ")"):
			next = j + 1
		}
		if next == 0 {
			i = j - 1
			continue
		}
		spans = append(spans, span{toks[i].start, toks[j-1].end})
		i = next - 1
	}
	if len(spans) == 0 {
		return text
	}
	var b strings.Builder
	last := 0
	for _, s := range spans {
		b.WriteString(text[last:s.start])
		b.WriteString("NULL")
		last = s.end
	}
	b.WriteString(text[last:])
	return b.String()
}

// encryptedComputeWriteCheck judges a write of path (relative to dir) with
// content, the way loadRefWriteCheck does: a problem in the written file is
// refused, and so is one this write introduces in another file, unless the
// batch writes that file next (pending), where it is judged in turn.
func encryptedComputeWriteCheck(dir, path, content string, pending map[string]bool) string {
	rel := filepath.ToSlash(filepath.Clean(path))
	if dir == "" || !encryptedComputeInputs[rel] {
		return ""
	}
	after := encryptedComputeProblems(loadRefSource{dir: dir, written: rel, content: content})
	if len(after) == 0 {
		return ""
	}
	// Problems already there are not this write's doing; a file checked with
	// its current content (`benmore check`) changes nothing.
	var before map[string]bool
	if disk := readAppFileOrNil(dir, rel); disk == nil || string(disk) != content {
		before = map[string]bool{}
		for _, p := range encryptedComputeProblems(loadRefSource{dir: dir}) {
			before[p.key] = true
		}
	}
	var own, broken []string
	files := map[string]bool{}
	for _, p := range after {
		switch {
		case p.file == rel:
			own = append(own, p.message)
		case before == nil || before[p.key]:
		case pending[p.file]:
		default:
			broken = append(broken, "  - "+p.message)
			files[p.file] = true
		}
	}
	var parts []string
	if len(own) > 0 {
		parts = append(parts, fmt.Sprintf("antipattern [computed-encrypted-column] %s\n%s\n%s", strings.Join(own, "\n"), encryptedComputeWhy, encryptedComputeFix))
	}
	if len(broken) > 0 {
		names := strings.Join(slices.Sorted(maps.Keys(files)), " and ")
		parts = append(parts, fmt.Sprintf("antipattern [computed-encrypted-column] %s not written: with it, %s would compute on encrypted columns:\n%s\n%s\n"+
			"Change those first (push the fixed %s before %s), or write them together with `benmore deploy`, which checks each file against the others.",
			rel, names, strings.Join(broken, "\n"), encryptedComputeWhy, names, rel))
	}
	return strings.Join(parts, "\n\n")
}
