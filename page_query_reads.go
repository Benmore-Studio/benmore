//go:build !cli

package main

// Read boundary of a page's authored SQL: a gotmpl page's `queries:` and a
// mustache page's <query> tags (sql= and the from= shorthand). /api/_query and
// `sources:` build their own single-table SQL, so they know where every column
// came from. These queries can join, alias and compute anything, and they used
// to go through the generic scan: every enc: value was decrypted for whoever
// opened the page, nothing was masked, hidden or read-audited. Both page
// engines call runPageQuery.
//
// Provenance comes from two places that do not depend on what the result calls
// a column:
//
//   - SQLite's authorizer reports every table and column the statement reads
//     while it compiles, through views and subqueries too. That decides read
//     auditing and which encrypted fields the query touched.
//   - An enc:v2 value carries its table and column in its authenticated data,
//     so a sealed value keeps its own field's policy under any alias, and when
//     it has been copied into an ordinary column.
//
// Anything that stays unproven is masked. In particular an unmask that depends
// on the row (owner, tenant role) needs a row whose identity belongs to the
// field; see pageQuerySource.

import (
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/mattn/go-sqlite3"
)

// pageQueryAuditType is the query_type of a read-audit row from authored SQL.
const pageQueryAuditType = "page_query"

// pageQueryReads is what SQLite said one statement reads: table name (as the
// schema spells it) to folded column names. A table read with no column
// (COUNT(*)) has the empty column.
type pageQueryReads struct {
	mu     sync.Mutex
	tables map[string]map[string]bool
}

func (r *pageQueryReads) record(table, column string) {
	if table == "" {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.tables == nil {
		r.tables = map[string]map[string]bool{}
	}
	if r.tables[table] == nil {
		r.tables[table] = map[string]bool{}
	}
	r.tables[table][sqliteIdentifierFold(column)] = true
}

func (r *pageQueryReads) tableNames() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	names := make([]string, 0, len(r.tables))
	for name := range r.tables {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func (r *pageQueryReads) readColumn(table, column string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	for name, columns := range r.tables {
		if sqliteIdentifierFold(name) == sqliteIdentifierFold(table) && columns[sqliteIdentifierFold(column)] {
			return true
		}
	}
	return false
}

// pinnedConnQuerier runs the shared scan on one connection, whose authorizer
// is the one recording this statement.
type pinnedConnQuerier struct {
	ctx  context.Context
	conn *sql.Conn
}

func (q pinnedConnQuerier) Query(query string, args ...any) (*sql.Rows, error) {
	return q.conn.QueryContext(q.ctx, query, args...)
}

func (q pinnedConnQuerier) QueryRow(query string, args ...any) *sql.Row {
	return q.conn.QueryRowContext(q.ctx, query, args...)
}

func (q pinnedConnQuerier) QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error) {
	return q.conn.QueryContext(ctx, query, args...)
}

// queryPageRows runs one page query, recording its reads and applying the
// policy to every row. The policy must be built before this: the connection is
// held for the whole scan, so nothing in the row path may need another one.
func queryPageRows(parent context.Context, db *sql.DB, policy *pageQueryPolicy, guard *appSQLScope, query string, args ...any) ([]map[string]any, *pageQueryReads, error) {
	// A page query is app-authored SQL (app_sql_guard.go). Its own authorizer
	// below replaces the connection's default, so it applies the scope itself.
	if err := guard.begin(query); err != nil {
		return nil, nil, err
	}
	ctx, cancel := withQueryDeadline(parent)
	defer cancel()
	conn, err := db.Conn(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer conn.Close()

	reads := &pageQueryReads{}
	// The driver keeps a registered callback until the connection closes, so
	// the callback holds only this slot, emptied once the query is done.
	var recording atomic.Pointer[pageQueryReads]
	recording.Store(reads)
	var key []byte
	err = conn.Raw(func(raw any) error {
		sqlite, ok := sqliteConnOf(raw)
		if !ok {
			return fmt.Errorf("page query requires the SQLite authorizer")
		}
		main := sqlite.GetFilename("main")
		if keys := cryptoKeysForDBPath(main); keys != nil {
			key = keys.aes
		} else if !isolateAppEnvironment.Load() {
			key = appEncryptionKey
		}
		// The connection's default authorizer keeps applying underneath.
		limited := effectiveDBStorageLimit(canonicalDBPath(main)) > 0
		sqlite.RegisterAuthorizer(func(action int, arg1, arg2, database string) int {
			if guard.authorize(action, arg1, arg2, database) == sqlite3.SQLITE_DENY {
				return sqlite3.SQLITE_DENY
			}
			if action == sqlite3.SQLITE_READ {
				if r := recording.Load(); r != nil {
					r.record(arg1, arg2)
				}
			}
			if limited {
				return authorizeStorageCeiling(action, arg1, arg2, database)
			}
			return sqlite3.SQLITE_OK
		})
		return nil
	})
	if err != nil {
		return nil, nil, err
	}
	defer func() {
		recording.Store(nil)
		_ = conn.Raw(func(raw any) error {
			restoreConnAuthorizer(mustSQLiteConn(raw))
			return nil
		})
	}()
	rows, err := queryRowsWithKeyContextDecrypt(ctx, pinnedConnQuerier{ctx: ctx, conn: conn}, key, policy.rowDecryptor(reads), query, args...)
	if err != nil {
		return nil, nil, guard.end(err)
	}
	return rows, reads, nil
}

// pageEncryptedField is one declared encrypted field and what this viewer may
// see of it through this query.
type pageEncryptedField struct {
	table, column string
	access        encryptedFieldAccess
}

type pageQueryPolicy struct {
	fields []pageEncryptedField
}

// newPageQueryPolicy resolves the viewer's access to every declared field up
// front, because resolving it can read the database. source is the query's
// proven row source (nil when none can be proven); ownerScoped says the page
// limits every query to the viewer's rows (scope: owner).
func newPageQueryPolicy(app *App, session *Session, source *pageQuerySource, ownerScoped bool) *pageQueryPolicy {
	policy := &pageQueryPolicy{}
	if app == nil || app.Encrypted == nil {
		return policy
	}
	for table, defs := range app.Encrypted.Fields {
		for _, def := range defs {
			access := encryptedFieldAccessFor(app, app.DB, table, def, session)
			policy.fields = append(policy.fields, pageEncryptedField{
				table: table, column: def.Column,
				access: source.provenAccess(table, access, ownerScoped),
			})
		}
	}
	sort.Slice(policy.fields, func(i, j int) bool {
		a, b := policy.fields[i], policy.fields[j]
		if a.table != b.table {
			return a.table < b.table
		}
		return a.column < b.column
	})
	return policy
}

// class names everything about the viewer that the policy's masking depends
// on: for each declared field, the access left after provenAccess. Two viewers
// with the same class get byte-identical results from the same statement and
// arguments, so a shared result cache keys on it (<query cache=>). An owner or
// tenant unmask the query proves carries the viewer's user or tenant id, so
// such viewers never share an entry; viewers with no unmask role share one.
func (p *pageQueryPolicy) class() string {
	var b strings.Builder
	for _, f := range p.fields {
		a := f.access
		fmt.Fprintf(&b, "%q.%q:%t:%q:%q:%d;", f.table, f.column, a.allRows, a.tenantColumn, a.tenantID, a.ownerID)
	}
	return b.String()
}

// runPageQuery is the whole read boundary of one authored page query: it runs
// the statement under the viewer's policy (queryPageRows), strips hidden
// columns and writes the read audit. It returns the tables the statement read,
// which a cached result needs to audit later renders and to be invalidated.
// A failed query returns its error and audits nothing.
func runPageQuery(parent context.Context, app *App, r *http.Request, session *Session, policy *pageQueryPolicy, query string, args ...any) ([]map[string]any, []string, error) {
	rows, reads, err := queryPageRows(parent, app.DB, policy, &appSQLScope{hipaa: app.hipaa()}, query, args...)
	if err != nil {
		return nil, nil, err
	}
	stripPageQueryHiddenColumns(app, rows, reads)
	tables := reads.tableNames()
	if err := logPageQueryTables(app, r, tables, session); err != nil {
		return nil, nil, err
	}
	return rows, tables, nil
}

// queryContext is the request's context, so a client that leaves cancels its
// page queries; renders outside a request (PDF, MCP render) use Background.
// queryPageRows adds the default statement deadline either way.
func (ctx *RenderContext) queryContext() context.Context {
	if ctx.Request != nil {
		return ctx.Request.Context()
	}
	return context.Background()
}

// rowDecryptor decrypts and masks in the scan, ahead of the declared-type
// coercion: a value the viewer may see still comes back as its column's type.
func (p *pageQueryPolicy) rowDecryptor(reads *pageQueryReads) rowDecryptFunc {
	var (
		prepared bool
		read     []*pageEncryptedField
		named    map[string][]*pageEncryptedField
	)
	return func(row map[string]any, key []byte) {
		// The statement compiled before its first row, so its reads are known.
		if !prepared {
			prepared = true
			named = map[string][]*pageEncryptedField{}
			for i := range p.fields {
				field := &p.fields[i]
				if reads.readColumn(field.table, field.column) {
					read = append(read, field)
					name := sqliteIdentifierFold(field.column)
					named[name] = append(named[name], field)
				}
			}
		}
		for column, value := range row {
			if value == nil {
				continue
			}
			text, isText := value.(string)
			if isText && cryptoIsEncrypted(text) {
				row[column] = p.openCell(column, text, key, read, row)
				continue
			}
			// Not ciphertext, yet named like an encrypted field this query
			// read: benmore_decrypt(email) AS email, or an ordinary column
			// sharing the name in a join. The two look alike here, so the
			// field's policy applies to both.
			if fields := named[sqliteIdentifierFold(column)]; len(fields) > 0 && !pageFieldsAllow(fields, row) {
				row[column] = maskValue(value)
			}
		}
	}
}

func (p *pageQueryPolicy) openCell(column, text string, key []byte, read []*pageEncryptedField, row map[string]any) string {
	if len(key) == 0 {
		logDecryptFailureThrottled(column)
		return decryptFailMask
	}
	plain, err := fieldDecryptCtx(key, "", text)
	if err != nil {
		logDecryptFailureThrottled(column)
		return decryptFailMask
	}
	// GCM has authenticated the context by now. Without one (v1, or sealed
	// with no field) every encrypted field the query read is a candidate. No
	// declared field means no stated audience, and benmore_decrypt() in the
	// SQL remains the explicit way to show such a value.
	fields := read
	if table, field, ok := ciphertextField(text); ok {
		fields = nil
		for i := range p.fields {
			candidate := &p.fields[i]
			if sqliteIdentifierFold(candidate.table) == sqliteIdentifierFold(table) && sqliteIdentifierFold(candidate.column) == sqliteIdentifierFold(field) {
				fields = []*pageEncryptedField{candidate}
				break
			}
		}
	}
	if len(fields) > 0 && pageFieldsAllow(fields, row) {
		return plain
	}
	return encryptedFieldMask
}

func pageFieldsAllow(fields []*pageEncryptedField, row map[string]any) bool {
	for _, field := range fields {
		if !field.access.allowsRow(row) {
			return false
		}
	}
	return true
}

// ciphertextField returns the table and column an enc:v2 value was sealed for.
// Only a caller that has opened the value may rely on the answer.
func ciphertextField(value string) (table, column string, ok bool) {
	body, isV2 := strings.CutPrefix(value, encPrefixV2)
	if !isV2 {
		return "", "", false
	}
	head, _, found := strings.Cut(body, ":")
	if !found {
		return "", "", false
	}
	aad, err := hex.DecodeString(head)
	if err != nil {
		return "", "", false
	}
	table, column, ok = cryptoParseAAD(aad)
	return table, column, ok && table != "" && column != ""
}

// stripPageQueryHiddenColumns applies apiHiddenColumn to the tables the query
// read. A result column is judged by the tables that hold it, so a joined
// table's declaration does not hide another's column; framework tables and a
// name no table holds count against every table read. A column the author
// renames (password_hash AS h) is their explicit choice, like a flow selecting
// it by name.
func stripPageQueryHiddenColumns(app *App, rows []map[string]any, reads *pageQueryReads) {
	tables := reads.tableNames()
	if len(tables) == 0 {
		return
	}
	hidden := map[string]bool{}
	isHidden := func(column string) bool {
		verdict, known := hidden[column]
		if known {
			return verdict
		}
		var holders []string
		for _, table := range tables {
			if strings.HasPrefix(table, "_benmore_") || hasColumn(app, table, column) {
				holders = append(holders, table)
			}
		}
		if len(holders) == 0 {
			holders = tables
		}
		for _, table := range holders {
			if apiHiddenColumn(app, table, column) {
				verdict = true
				break
			}
		}
		hidden[column] = verdict
		return verdict
	}
	for _, row := range rows {
		for column := range row {
			if isHidden(column) {
				delete(row, column)
			}
		}
	}
}

// logPageQueryTables writes one read-audit event per audited table the query
// read, whichever way it reached it (join, subquery, view). A render served
// from a cached result reads the same tables, so it is logged the same way.
// An error (compliance: hipaa, the audit row not written) fails the render.
func logPageQueryTables(app *App, r *http.Request, tables []string, session *Session) error {
	for _, table := range tables {
		if IsReadAudited(app, table) {
			if err := LogReadAccess(app, r, table, "", pageQueryAuditType, session); err != nil {
				return err
			}
		}
	}
	return nil
}

// pageQuerySource describes a query whose rows provably come from one row
// source: one SELECT, one FROM naming one table, no join. Only then does a
// result column named user_id or the tenant key say whose row a field belongs
// to. In `SELECT o.user_id, c.email FROM orders o JOIN customers c ...` the
// viewer owns the order, not the customer, and a self-join has the same
// problem while reading just one table. The authored text is the input because
// the statement cannot be rewritten to add a hidden projection the way
// /api/_query does. A nil source means no row identity can be trusted.
type pageQuerySource struct {
	table      string
	qualifiers map[string]bool
	terms      []pageQueryTerm
	// ownerRows: the WHERE clause requires user_id = <the viewer's id> at its
	// top level.
	ownerRows bool
}

// pageQueryViewerParam reports whether the bind parameter starting at toks[0]
// is the viewer's own user id, and how many tokens it spans. Each page engine
// binds differently, so each supplies its own.
type pageQueryViewerParam func(toks []sqlToken) (span int, viewer bool)

// gotmplViewerParam: a gotmpl query's :user_id is always the session user
// (resolveBind), and binds NULL without one.
func gotmplViewerParam(toks []sqlToken) (int, bool) {
	if len(toks) >= 2 && pageQueryIsPunct(toks[0], ":") && toks[1].kind == sqlTokWord && toks[1].text == "user_id" && toks[1].start == toks[0].end {
		return 2, true
	}
	return 0, false
}

// boundViewerParam reads the statement a mustache <query> tag runs, after its
// template values were bound (bindTemplateSQL, ExpandShorthand): a ? whose
// argument is the viewer's id proves the rows are the viewer's, whichever
// template value supplied it ({{user_id}}, :current_user, owned=). The n-th ?
// is args[n] only when the statement holds nothing but plain ? markers, so a
// numbered (?2) or named (:x, @x, $x) parameter, or a count that does not
// match the arguments, proves nothing.
func boundViewerParam(sqlText string, args []any, session *Session) pageQueryViewerParam {
	never := func([]sqlToken) (int, bool) { return 0, false }
	if session == nil || session.UserID == 0 {
		return never
	}
	toks := sqlTokenize(sqlText)
	ordinal := map[int]int{}
	for i, tok := range toks {
		adjacentWord := i+1 < len(toks) && toks[i+1].kind == sqlTokWord && toks[i+1].start == tok.end
		switch {
		case pageQueryIsPunct(tok, "?"):
			if adjacentWord {
				return never
			}
			ordinal[tok.start] = len(ordinal)
		case (pageQueryIsPunct(tok, ":") || pageQueryIsPunct(tok, "@")) && adjacentWord:
			return never
		case tok.kind == sqlTokWord && strings.HasPrefix(tok.text, "$"):
			return never
		}
	}
	if len(ordinal) != len(args) {
		return never
	}
	viewer := fmt.Sprint(session.UserID)
	return func(toks []sqlToken) (int, bool) {
		if len(toks) == 0 || !pageQueryIsPunct(toks[0], "?") {
			return 0, false
		}
		n, ok := ordinal[toks[0].start]
		return 1, ok && args[n] != nil && fmt.Sprint(args[n]) == viewer
	}
}

// pageQueryTerm is one projection term: output is its result name when that
// can be told, ref the source column it passes through unchanged.
type pageQueryTerm struct {
	star        bool
	output, ref string
}

var pageQueryClauseWords = map[string]bool{"WHERE": true, "GROUP": true, "HAVING": true, "ORDER": true, "LIMIT": true, "WINDOW": true}

func pageQueryWord(tok sqlToken) string {
	if tok.kind != sqlTokWord {
		return ""
	}
	return strings.ToUpper(tok.text)
}

func pageQueryIsPunct(tok sqlToken, text string) bool {
	return tok.kind == sqlTokPunct && tok.text == text
}

func pageQueryName(tok sqlToken) bool {
	return tok.kind == sqlTokWord || tok.kind == sqlTokIdent
}

func parsePageQuerySource(sqlText string, viewer pageQueryViewerParam) *pageQuerySource {
	toks := sqlTokenize(sqlText)
	for len(toks) > 0 && pageQueryIsPunct(toks[len(toks)-1], ";") {
		toks = toks[:len(toks)-1]
	}
	if len(toks) == 0 || pageQueryWord(toks[0]) != "SELECT" {
		return nil
	}
	from := -1
	for i, tok := range toks {
		if pageQueryIsPunct(tok, ";") {
			return nil
		}
		switch pageQueryWord(tok) {
		case "SELECT":
			if i != 0 {
				return nil
			}
		case "JOIN":
			return nil
		case "FROM":
			if from >= 0 {
				return nil
			}
			from = i
		}
	}
	if from < 0 || from+1 >= len(toks) || !pageQueryName(toks[from+1]) {
		return nil
	}
	source := &pageQuerySource{table: toks[from+1].text, qualifiers: map[string]bool{sqliteIdentifierFold(toks[from+1].text): true}}
	next := from + 2
	if next < len(toks) && pageQueryWord(toks[next]) == "AS" {
		next++
		if next >= len(toks) || !pageQueryName(toks[next]) {
			return nil
		}
		source.qualifiers[sqliteIdentifierFold(toks[next].text)] = true
		next++
	} else if next < len(toks) && pageQueryName(toks[next]) && !pageQueryClauseWords[pageQueryWord(toks[next])] {
		source.qualifiers[sqliteIdentifierFold(toks[next].text)] = true
		next++
	}
	// A comma, a dot (schema-qualified name), an open paren (table-valued
	// function), INDEXED BY or anything else unrecognized ends the proof.
	if next < len(toks) && !pageQueryClauseWords[pageQueryWord(toks[next])] {
		return nil
	}
	source.terms = source.parseTerms(toks[1:from])
	source.ownerRows = source.whereRequiresOwner(toks[next:], viewer)
	return source
}

func (s *pageQuerySource) parseTerms(toks []sqlToken) []pageQueryTerm {
	if len(toks) > 0 {
		if word := pageQueryWord(toks[0]); word == "DISTINCT" || word == "ALL" {
			toks = toks[1:]
		}
	}
	var terms []pageQueryTerm
	depth, start := 0, 0
	for i, tok := range toks {
		switch {
		case pageQueryIsPunct(tok, "("):
			depth++
		case pageQueryIsPunct(tok, ")"):
			depth--
		case pageQueryIsPunct(tok, ",") && depth == 0:
			terms = append(terms, s.parseTerm(toks[start:i]))
			start = i + 1
		}
	}
	return append(terms, s.parseTerm(toks[start:]))
}

func (s *pageQuerySource) parseTerm(toks []sqlToken) pageQueryTerm {
	var term pageQueryTerm
	if n := len(toks); n >= 2 && pageQueryName(toks[n-1]) {
		prev := toks[n-2]
		if pageQueryName(prev) || prev.kind == sqlTokLiteral || pageQueryIsPunct(prev, ")") {
			term.output = toks[n-1].text
			toks = toks[:n-1]
			if pageQueryWord(prev) == "AS" {
				toks = toks[:len(toks)-1]
			}
		}
	}
	switch {
	case len(toks) == 1 && pageQueryIsPunct(toks[0], "*"):
		term.star = true
	case len(toks) == 1 && pageQueryName(toks[0]):
		term.ref = toks[0].text
	case len(toks) == 3 && pageQueryIsPunct(toks[1], ".") && pageQueryName(toks[0]) && s.qualifiers[sqliteIdentifierFold(toks[0].text)]:
		if pageQueryIsPunct(toks[2], "*") {
			term.star = true
		} else if pageQueryName(toks[2]) {
			term.ref = toks[2].text
		}
	}
	if term.output == "" {
		term.output = term.ref
	}
	return term
}

// projects reports whether the result's column of this name is the source
// table's own column. Any other term producing the same name disproves it.
func (s *pageQuerySource) projects(column string) bool {
	want := sqliteIdentifierFold(column)
	found := false
	for _, term := range s.terms {
		if term.star {
			found = true
			continue
		}
		if sqliteIdentifierFold(term.output) != want {
			continue
		}
		if sqliteIdentifierFold(term.ref) != want {
			return false
		}
		found = true
	}
	return found
}

// whereRequiresOwner proves every row belongs to the caller: user_id = <the
// viewer's id> (as viewer recognizes it) as a top-level conjunct. OR, BETWEEN
// (whose AND is not a conjunction) and CASE make the shape unprovable,
// whatever else the clause holds.
func (s *pageQuerySource) whereRequiresOwner(toks []sqlToken, viewer pageQueryViewerParam) bool {
	if viewer == nil {
		return false
	}
	if len(toks) == 0 || pageQueryWord(toks[0]) != "WHERE" {
		return false
	}
	toks = toks[1:]
	depth := 0
	end := len(toks)
	for i, tok := range toks {
		word := pageQueryWord(tok)
		switch {
		case pageQueryIsPunct(tok, "("):
			depth++
		case pageQueryIsPunct(tok, ")"):
			depth--
		case word == "OR" || word == "BETWEEN" || word == "CASE":
			return false
		case depth == 0 && pageQueryClauseWords[word]:
			end = i
		}
		if end != len(toks) {
			break
		}
	}
	toks = toks[:end]
	depth = 0
	for i, tok := range toks {
		if pageQueryIsPunct(tok, "(") {
			depth++
		} else if pageQueryIsPunct(tok, ")") {
			depth--
		}
		if depth != 0 || !pageQueryName(tok) || sqliteIdentifierFold(tok.text) != "user_id" {
			continue
		}
		before := i
		if i >= 2 && pageQueryIsPunct(toks[i-1], ".") && pageQueryName(toks[i-2]) && s.qualifiers[sqliteIdentifierFold(toks[i-2].text)] {
			before = i - 2
		}
		if before > 0 && pageQueryWord(toks[before-1]) != "AND" {
			continue
		}
		if i+2 >= len(toks) || !pageQueryIsPunct(toks[i+1], "=") {
			continue
		}
		span, isViewer := viewer(toks[i+2:])
		if !isViewer {
			continue
		}
		if after := i + 2 + span; after == len(toks) || pageQueryWord(toks[after]) == "AND" {
			return true
		}
	}
	return false
}

// provenAccess narrows a viewer's access to what this query's shape can prove.
// A global decision (allRows) needs no row; a per-row one survives only for the
// query's own single source and the identity columns it really returns.
func (s *pageQuerySource) provenAccess(table string, access encryptedFieldAccess, ownerScoped bool) encryptedFieldAccess {
	if access.allRows {
		return access
	}
	if s == nil || sqliteIdentifierFold(s.table) != sqliteIdentifierFold(table) {
		return encryptedFieldAccess{}
	}
	if access.ownerID != 0 {
		if ownerScoped || s.ownerRows {
			return encryptedFieldAccess{allRows: true}
		}
		if !s.projects("user_id") {
			access.ownerID = 0
		}
	}
	if access.tenantColumn != "" && !s.projects(access.tenantColumn) {
		access.tenantColumn = ""
	}
	return access
}
