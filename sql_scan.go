//go:build !cli

package main

import (
	"bufio"
	"errors"
	"io"
	"strings"
	"unicode"
)

// --- shared SQL quoting/comment grammar ---
//
// Round 1 of this file's review taught the splitter and the comment
// stripper about " (double-quoted identifiers) alongside the existing '
// (string literals) - and round 2 found the SAME class of bug still
// live, because SQLite has FOUR quoting forms, not two: '...' (string),
// "..." (identifier), [...] (MS Access compat identifier), and `...`
// (MySQL compat identifier). Bolting on a third and fourth special case
// the same way the second one was bolted on is exactly how this drifted
// in the first place - three call sites, each hand-implementing its own
// idea of "what counts as quoted", is a structural invitation for one of
// them to fall behind.
//
// sqlByteKind + scanSQLFrom implement
// SQLite's complete quoting + comment grammar, and every consumer
// (splitSQLStatements, stripRestoreSQLComments, stripSQLLiterals) is
// built on top of it rather than re-implementing any part of it. A fifth
// quoting form, if SQLite ever grew one, would only need to change here.

// sqlByteKind classifies one byte of a SQL script.
type sqlByteKind int

const (
	sqlCode           sqlByteKind = iota
	sqlInSingleQuote              // '...'  string literal
	sqlInDoubleQuote              // "..."  identifier
	sqlInBracket                  // [...]  identifier (MS Access compat)
	sqlInBacktick                 // `...`  identifier (MySQL compat)
	sqlInLineComment              // -- ... \n
	sqlInBlockComment             // /* ... */
)

// quoted reports whether this byte is inside ANY of the four quoting
// forms (as opposed to code or a comment).
func (k sqlByteKind) quoted() bool {
	switch k {
	case sqlInSingleQuote, sqlInDoubleQuote, sqlInBracket, sqlInBacktick:
		return true
	}
	return false
}

// sqlByteSource abstracts "read the next byte" + "peek at the byte after
// that" so scanSQLFrom's grammar can run identically over a streaming
// io.Reader (splitSQLStatements, which genuinely needs to stream a
// multi-gigabyte dump without holding it in memory) and over an in-memory
// string (stripRestoreSQLComments / stripSQLLiterals, called TWICE per
// statement by guardRestoreStatement).
//
// This split exists because a round-3 review measured scanSQL's
// unconditional bufio.NewReaderSize(r, 1<<20) costing ~2 MiB per
// guardRestoreStatement call (one buffer per strip call, called twice)
// regardless of statement size: a 1.7 MB / 20,000-statement dump took
// 1.28s and 41.9 GB allocated in guard overhead alone (~1.33 MB/s - about
// 13 minutes for a 1 GB dump), all while holding one open write
// transaction blocking every other write to the app. stringByteSource
// below walks the string directly by index: no bufio, no io.Reader
// wrapping, no allocation beyond the tiny struct itself - see
// TestGuardRestoreStatementAllocationBudget / BenchmarkGuardRestoreStatement.
type sqlByteSource interface {
	next() (b byte, ok bool)
	peekIsNext(want byte) bool
	// err reports a genuine read error - non-nil only when a prior next()
	// returned ok=false because the underlying source actually failed,
	// never on ordinary end-of-input.
	err() error
}

// readerByteSource is the genuinely-streaming source, used only by
// splitSQLStatements via scanSQL.
type readerByteSource struct {
	br   *bufio.Reader
	rerr error
}

func (s *readerByteSource) next() (byte, bool) {
	b, err := s.br.ReadByte()
	if err != nil {
		if err != io.EOF {
			s.rerr = err
		}
		return 0, false
	}
	return b, true
}

func (s *readerByteSource) peekIsNext(want byte) bool {
	b, err := s.br.Peek(1)
	return err == nil && len(b) == 1 && b[0] == want
}

func (s *readerByteSource) err() error { return s.rerr }

// stringByteSource is the zero-bufio, in-memory-string source, used by
// stripRestoreSQLComments and stripSQLLiterals via scanSQLBytes.
type stringByteSource struct {
	s   string
	pos int
}

func (s *stringByteSource) next() (byte, bool) {
	if s.pos >= len(s.s) {
		return 0, false
	}
	b := s.s[s.pos]
	s.pos++
	return b, true
}

func (s *stringByteSource) peekIsNext(want byte) bool {
	return s.pos < len(s.s) && s.s[s.pos] == want
}

func (s *stringByteSource) err() error { return nil }

// scanSQL streams r and calls visit(b, kind) for every byte - the
// genuinely-streaming entry point onto scanSQLFrom, used by
// splitSQLStatements. See scanSQLBytes for the zero-allocation, in-
// memory-string entry point used everywhere else.
//
// A non-nil error from visit stops the scan immediately (no further
// bytes are read) and is returned - this is what lets splitSQLStatements
// honour its documented "a callback error stops the walk immediately"
// contract without scanning the rest of a multi-gigabyte file for
// nothing. A genuine underlying read error (not clean EOF) is also
// surfaced, via readerByteSource.err() after the scan completes.
func scanSQL(r io.Reader, visit func(b byte, kind sqlByteKind) error) error {
	src := &readerByteSource{br: bufio.NewReaderSize(r, 1<<20)}
	if err := scanSQLFrom(src, visit); err != nil {
		return err
	}
	return src.err()
}

// scanSQLBytes runs the exact same grammar as scanSQL directly over an
// in-memory string, through stringByteSource - no bufio.Reader, no
// io.Reader wrapping, no allocation beyond that tiny struct. See
// sqlByteSource's doc comment for why this exists.
func scanSQLBytes(s string, visit func(b byte, kind sqlByteKind) error) error {
	return scanSQLFrom(&stringByteSource{s: s}, visit)
}

// scanSQLFrom is the ONE implementation of SQLite's quoting + comment
// grammar. scanSQL and scanSQLBytes are both thin entry points onto it,
// differing only in which sqlByteSource they hand it - never in how
// bytes get classified.
//
// Comment/quote-open detection is lookahead-based (peekIsNext), deciding
// whether "-" or "/" starts a comment BEFORE classifying that byte - not
// a reactive "check the previous byte" approach. The star opening a block
// comment cannot also close it: "/*/" is unterminated, while "/**/" closes.
//
// Unterminated quotes/comments run to end of input and the scan returns
// nil (not an error) - SQLite itself would reject an unterminated quoted
// literal as a syntax error and treats an unterminated block comment as
// running to EOF; either way there is no MORE input for scanSQLFrom to
// classify, so ending the scan cleanly (leaving guardRestoreStatement's
// caller, tx.Exec, to reject the malformed statement) is correct here.
func scanSQLFrom(src sqlByteSource, visit func(b byte, kind sqlByteKind) error) error {
	// consumeQuoted reads and classifies bytes as `kind` until (and
	// including) closeByte closes the region, or input ends. Doubled
	// delimiters are not specially handled here: once closeByte is seen
	// the region ends, and the OUTER dispatch loop's normal open-
	// delimiter check naturally reopens a new region if the very next
	// byte is the same delimiter again - which reproduces SQLite's
	// doubling-escape for the three kinds that support it ('/"/`) and
	// correctly reproduces "no escape form" for [...] (a lone ']' can
	// never re-open a bracket region, matching the reference table:
	// brackets have no escape).
	consumeQuoted := func(kind sqlByteKind, closeByte byte) error {
		for {
			b, ok := src.next()
			if !ok {
				return nil
			}
			if err := visit(b, kind); err != nil {
				return err
			}
			if b == closeByte {
				return nil
			}
		}
	}

	for {
		c, ok := src.next()
		if !ok {
			break
		}

		switch c {
		case '\'':
			if err := visit(c, sqlInSingleQuote); err != nil {
				return err
			}
			if err := consumeQuoted(sqlInSingleQuote, '\''); err != nil {
				return err
			}
		case '"':
			if err := visit(c, sqlInDoubleQuote); err != nil {
				return err
			}
			if err := consumeQuoted(sqlInDoubleQuote, '"'); err != nil {
				return err
			}
		case '[':
			if err := visit(c, sqlInBracket); err != nil {
				return err
			}
			if err := consumeQuoted(sqlInBracket, ']'); err != nil {
				return err
			}
		case '`':
			if err := visit(c, sqlInBacktick); err != nil {
				return err
			}
			if err := consumeQuoted(sqlInBacktick, '`'); err != nil {
				return err
			}
		case '-':
			if !src.peekIsNext('-') {
				if err := visit(c, sqlCode); err != nil {
					return err
				}
				continue
			}
			if err := visit(c, sqlInLineComment); err != nil {
				return err
			}
			for {
				nc, ok := src.next()
				if !ok {
					return nil
				}
				if nc == '\n' {
					// The newline that TERMINATES a line comment is not
					// part of the comment text - deliver it as ordinary
					// code so a caller reconstructing source text (or
					// relying on it as a separator) sees it.
					if err := visit(nc, sqlCode); err != nil {
						return err
					}
					break
				}
				if err := visit(nc, sqlInLineComment); err != nil {
					return err
				}
			}
		case '/':
			if !src.peekIsNext('*') {
				if err := visit(c, sqlCode); err != nil {
					return err
				}
				continue
			}
			if err := visit(c, sqlInBlockComment); err != nil {
				return err
			}
			star, ok := src.next() // known present: peekIsNext('*') above just confirmed it
			if !ok {
				return nil
			}
			if err := visit(star, sqlInBlockComment); err != nil {
				return err
			}
			for {
				nc, ok := src.next()
				if !ok {
					return nil // unterminated block comment runs to EOF (SQLite behavior)
				}
				// Require the closing '*' to be a DIFFERENT star than the
				// one that opened this comment (already consumed above) -
				// this is what makes "/*/" not self-close.
				if nc == '*' && src.peekIsNext('/') {
					if err := visit(nc, sqlInBlockComment); err != nil {
						return err
					}
					slash, ok := src.next()
					if !ok {
						return nil
					}
					if err := visit(slash, sqlInBlockComment); err != nil {
						return err
					}
					break
				}
				if err := visit(nc, sqlInBlockComment); err != nil {
					return err
				}
			}
		default:
			if err := visit(c, sqlCode); err != nil {
				return err
			}
		}
	}
	return nil
}

// stripSQLLiterals blanks ALL FOUR quoted-region kinds (string literals
// and every identifier-quoting form) so keyword tokenisation and the
// stray-semicolon guard cannot be fooled by data sitting inside any of
// them. Only meant to run on already comment-stripped input (i.e.
// stripRestoreSQLComments' output) - it does not special-case comment
// bytes because none should remain by the time this runs.
func stripSQLLiterals(s string) string {
	var b strings.Builder
	b.Grow(len(s))
	_ = scanSQLBytes(s, func(c byte, kind sqlByteKind) error {
		if kind.quoted() {
			b.WriteByte(' ')
		} else {
			b.WriteByte(c)
		}
		return nil
	})
	return b.String()
}

// stripSQLComments removes comments while respecting every SQLite quoting
// form. Restore validation and read-only queries share this implementation.
func stripSQLComments(sql string) string {
	var b strings.Builder
	b.Grow(len(sql))
	inBlockComment := false
	var prevByte byte
	_ = scanSQLBytes(sql, func(c byte, kind sqlByteKind) error {
		if kind == sqlInLineComment {
			// Dropped entirely. No synthetic separator is needed: the
			// closing '\n' is delivered as sqlCode (see scanSQLFrom) and
			// written normally below, which already separates whatever
			// comes before the comment from whatever comes after it.
			prevByte = c
			return nil
		}
		if kind == sqlInBlockComment {
			inBlockComment = true
			// prevByte=='*' && c=='/' is THIS comment instance closing.
			// Emitting the separating space HERE (at close), not at open,
			// is what makes adjacent comments ("SELECT/*a*//*b*/1") each
			// get their own space, rather than one per contiguous run.
			if prevByte == '*' && c == '/' {
				b.WriteByte(' ')
				inBlockComment = false
			}
			prevByte = c
			return nil
		}
		inBlockComment = false
		prevByte = c
		b.WriteByte(c)
		return nil
	})
	// An unterminated block comment still contributes a separator.
	if inBlockComment {
		b.WriteByte(' ')
	}
	return b.String()
}

// --- write-target extraction ---
//
// sqlWriteTargets reports which table each INSERT / REPLACE / UPDATE /
// DELETE statement in a script writes, so flow SQL steps can announce the
// same realtime table events auto-CRUD does (flows_realtime.go). It walks
// tokens produced over scanSQLBytes: a quoted region becomes one identifier
// or string token, comments separate tokens, and ';' outside every quoting
// form ends a statement - the boundaries splitSQLStatements uses.

type sqlTokenKind int

const (
	sqlTokWord    sqlTokenKind = iota // bare keyword or identifier
	sqlTokIdent                       // "..." / [...] / `...` identifier, delimiters removed
	sqlTokLiteral                     // '...' string; SQLite also accepts one as a table name
	sqlTokPunct                       // any other single code byte
)

type sqlToken struct {
	kind       sqlTokenKind
	text       string
	start, end int // byte span in the original SQL, preserving executable expressions
}

// sqlWrite is one statement's write target: the table as written (schema
// qualifier removed) and "insert", "update" or "delete".
type sqlWrite struct {
	Table  string
	Action string
}

func sqlIdentByte(b byte) bool {
	return b == '_' || b == '$' || b >= 0x80 ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

// sqlTokenize splits s into tokens. Consecutive bytes of one quoting kind
// form one token, which is what SQLite's doubled-delimiter escape ("a""b")
// means.
func sqlTokenize(s string) []sqlToken {
	var toks []sqlToken
	var word, quoted strings.Builder
	qkind := sqlCode
	offset, wordStart, quoteStart := 0, 0, 0
	flushWord := func() {
		if word.Len() > 0 {
			toks = append(toks, sqlToken{kind: sqlTokWord, text: word.String(), start: wordStart, end: wordStart + word.Len()})
			word.Reset()
		}
	}
	flushQuoted := func() {
		if quoted.Len() == 0 {
			return
		}
		raw := quoted.String()
		quoted.Reset()
		qkind = sqlCode
		open, closing := raw[0], raw[0]
		if open == '[' {
			closing = ']'
		}
		body := raw[1:]
		if n := len(body); n > 0 && body[n-1] == closing {
			body = body[:n-1]
		}
		if open != '[' { // brackets have no escape form
			body = strings.ReplaceAll(body, string([]byte{closing, closing}), string(closing))
		}
		kind := sqlTokIdent
		if open == '\'' {
			kind = sqlTokLiteral
		}
		toks = append(toks, sqlToken{kind: kind, text: body, start: quoteStart, end: quoteStart + len(raw)})
	}
	_ = scanSQLBytes(s, func(b byte, kind sqlByteKind) error {
		i := offset
		offset++
		if kind.quoted() {
			flushWord()
			if kind != qkind {
				flushQuoted()
				qkind = kind
			}
			if quoted.Len() == 0 {
				quoteStart = i
			}
			quoted.WriteByte(b)
			return nil
		}
		flushQuoted()
		if kind == sqlInLineComment || kind == sqlInBlockComment {
			flushWord()
			return nil
		}
		if sqlIdentByte(b) {
			if word.Len() == 0 {
				wordStart = i
			}
			word.WriteByte(b)
			return nil
		}
		flushWord()
		switch b {
		case ' ', '\t', '\n', '\r', '\f', '\v':
		default:
			toks = append(toks, sqlToken{kind: sqlTokPunct, text: string(b), start: i, end: i + 1})
		}
		return nil
	})
	flushQuoted()
	flushWord()
	return toks
}

// sqlWriteTargets returns the write target of every statement in s, in order,
// and the number of non-empty statements. Statements that write nothing
// (SELECT, VALUES, DDL, PRAGMA, ...) and writes to a schema other than main
// (temp or attached tables) contribute no target.
func sqlWriteTargets(s string) ([]sqlWrite, int) {
	var writes []sqlWrite
	statements := 0
	var cur []sqlToken
	flush := func() {
		if len(cur) == 0 {
			return
		}
		statements++
		if w, ok := sqlStatementWrite(cur); ok {
			writes = append(writes, w)
		}
		cur = cur[:0]
	}
	for _, t := range sqlTokenize(s) {
		if t.kind == sqlTokPunct && t.text == ";" {
			flush()
			continue
		}
		cur = append(cur, t)
	}
	flush()
	return writes, statements
}

// sqlStatementVerbIndex returns the position of a tokenized statement's own
// verb: token 0, or for a WITH statement the first SELECT / VALUES / INSERT /
// REPLACE / UPDATE / DELETE outside every parenthesis (CTE bodies are
// parenthesized and may only hold a SELECT). len(toks) when a WITH statement
// has none.
func sqlStatementVerbIndex(toks []sqlToken) int {
	kw := func(i int, word string) bool {
		return i < len(toks) && toks[i].kind == sqlTokWord && strings.EqualFold(toks[i].text, word)
	}
	if !kw(0, "WITH") {
		return 0
	}
	depth := 0
	i := 1
	for ; i < len(toks); i++ {
		if toks[i].kind == sqlTokPunct {
			switch toks[i].text {
			case "(":
				depth++
			case ")":
				if depth > 0 {
					depth--
				}
			}
			continue
		}
		if depth == 0 && (kw(i, "SELECT") || kw(i, "VALUES") || kw(i, "INSERT") ||
			kw(i, "REPLACE") || kw(i, "UPDATE") || kw(i, "DELETE")) {
			break
		}
	}
	return i
}

// sqlTokenStatements splits a token stream into its non-empty statements at
// every ';' outside a quoting form - the boundaries sqlWriteTargets counts.
func sqlTokenStatements(toks []sqlToken) [][]sqlToken {
	var statements [][]sqlToken
	start := 0
	for i, t := range toks {
		if t.kind == sqlTokPunct && t.text == ";" {
			if i > start {
				statements = append(statements, toks[start:i])
			}
			start = i + 1
		}
	}
	if start < len(toks) {
		statements = append(statements, toks[start:])
	}
	return statements
}

// sqlStatementReturns reports whether a tokenized statement carries a
// RETURNING clause. RETURNING is a reserved word in SQLite: outside a quoting
// form it can only be the clause keyword, never a column, alias or table name
// (`SELECT returning FROM t` is a syntax error), so a bare word is the clause.
// Only a bind parameter spelled `:returning` / `@returning` looks the same to
// the lexer, and is skipped.
func sqlStatementReturns(toks []sqlToken) bool {
	for i, t := range toks {
		if t.kind != sqlTokWord || !strings.EqualFold(t.text, "RETURNING") {
			continue
		}
		if i > 0 {
			if p := toks[i-1]; p.kind == sqlTokPunct && (p.text == ":" || p.text == "@") && p.end == t.start {
				continue
			}
		}
		return true
	}
	return false
}

func sqlStatementWrite(toks []sqlToken) (sqlWrite, bool) {
	kw := func(i int, word string) bool {
		return i < len(toks) && toks[i].kind == sqlTokWord && strings.EqualFold(toks[i].text, word)
	}
	i := sqlStatementVerbIndex(toks)
	var action string
	switch {
	case kw(i, "INSERT"):
		i++
		if kw(i, "OR") {
			i += 2 // OR REPLACE / IGNORE / ABORT / FAIL / ROLLBACK
		}
		if !kw(i, "INTO") {
			return sqlWrite{}, false
		}
		i++
		action = "insert"
	case kw(i, "REPLACE"):
		i++
		if !kw(i, "INTO") {
			return sqlWrite{}, false
		}
		i++
		action = "insert"
	case kw(i, "UPDATE"):
		i++
		if kw(i, "OR") {
			i += 2
		}
		action = "update"
	case kw(i, "DELETE"):
		i++
		if !kw(i, "FROM") {
			return sqlWrite{}, false
		}
		i++
		action = "delete"
	default:
		return sqlWrite{}, false
	}
	name := func(j int) (string, bool) {
		if j >= len(toks) || toks[j].kind == sqlTokPunct || toks[j].text == "" {
			return "", false
		}
		return toks[j].text, true
	}
	table, ok := name(i)
	if !ok {
		return sqlWrite{}, false
	}
	if i+1 < len(toks) && toks[i+1].kind == sqlTokPunct && toks[i+1].text == "." {
		if !strings.EqualFold(table, "main") {
			return sqlWrite{}, false // temp.* or an attached database
		}
		if table, ok = name(i + 2); !ok {
			return sqlWrite{}, false
		}
	}
	return sqlWrite{Table: table, Action: action}, true
}

// --- text the driver can run ---
//
// A text handed to the driver's Query or Prepare must hold a statement in
// every part the driver compiles. Its Query path compiles the text one
// statement at a time: SQLite skips whitespace, comments and stray `;`,
// compiles up to the next `;`, and the driver goes on with what is left
// (strings.TrimSpace of it) until that is empty. A part that holds no statement
// at all - a comment after the last `;`, a second `;`, a text that is only a
// comment - compiles to nothing. Exec skips such a part. Query runs only the
// last part of a text, so when that part is empty it answers with an empty
// result that has no columns and the statement before it never runs: its rows
// are lost, a write does not happen, and no error says so. A prepared
// statement that is run on nothing takes the process down inside the driver
// (go-sqlite3 v1.14.52; up to v1.14.42 Query did the same). Prepare compiles
// only the first part.
//
// Text the framework did not write itself (tool and API input, SQL and SQL
// conditions from app files, and framework SQL with such a fragment inside)
// goes through sqlRunnableText before Query, QueryRow or Prepare.

// errNoSQLStatement is what a caller returns for a text in which
// sqlRunnableText finds no statement.
var errNoSQLStatement = errors.New("no SQL statement")

// sqlRunnableText returns the text the driver can run in place of query, and
// false when query holds no statement at all (the caller returns
// errNoSQLStatement and never calls the driver).
//
// A text every part of which holds a statement is returned as it is, so a
// working query keeps its statements, their order, their parameters and its
// result column names (SQLite names an unaliased column after its source text,
// trailing comment included). Otherwise the text ends where its last
// statement does: `SELECT 1; -- note`, `SELECT 1; /* note */` and `SELECT 1;;`
// become `SELECT 1;`. An empty statement between two statements
// (`SELECT 1;; SELECT 2`) needs nothing: SQLite skips a leading `;`.
//
// The walk follows the driver, not the shared lexer above: parts are split
// where SQLite's own tokenizer sees a `;` (sqliteTokenLen), and each remainder
// is trimmed the way the driver trims it. Every `;` outside a token counts as
// the end of a statement. The one statement that holds such a `;`, CREATE
// TRIGGER, is therefore read as several parts; each of them still starts with a
// token, so a complete trigger is left alone, and a text cut inside an
// unfinished one was an error before and stays one.
func sqlRunnableText(query string) (string, bool) {
	text := query
	if i := strings.IndexByte(text, 0); i >= 0 {
		text = text[:i] // SQLite reads a C string and never sees what follows a NUL
	}
	if strings.IndexByte(text, ';') < 0 {
		// No `;`, so one statement at most: the usual case, decided at the
		// first token.
		if _, ok := sqliteStatementLen(text, true); !ok {
			return "", false
		}
		return query, true
	}
	start := 0 // where the part the driver compiles next begins
	cut := 0   // where the last statement found ends, after its `;`
	for {
		n, ok := sqliteStatementLen(text[start:], false)
		if !ok {
			if cut == 0 {
				return "", false
			}
			return query[:cut], true
		}
		cut = start + n
		rest := text[cut:]
		part := strings.TrimSpace(rest)
		if part == "" {
			return query, true
		}
		// The driver trims both ends of what is left; the trimmed end is
		// never compiled again.
		start = cut + len(rest) - len(strings.TrimLeftFunc(rest, unicode.IsSpace))
		text = text[:start+len(part)]
	}
}

// sqliteStatementLen is how much of text SQLite consumes to compile one
// statement: leading whitespace, comments and `;`, then every token up to and
// including the next `;` (or the end of text). ok is false when text holds
// nothing but whitespace, comments and `;`, which compiles to no statement.
// With firstOnly it stops at the first token and only ok is meaningful.
func sqliteStatementLen(text string, firstOnly bool) (n int, ok bool) {
	for n < len(text) {
		size, class := sqliteTokenLen(text[n:])
		n += size
		switch class {
		case sqliteTokenSkipped:
		case sqliteTokenSemi:
			if ok {
				return n, true
			}
		default:
			if firstOnly {
				return n, true
			}
			ok = true
		}
	}
	return n, ok
}

type sqliteTokenClass int

const (
	sqliteTokenParsed  sqliteTokenClass = iota // handed to the parser, or refused by it as illegal
	sqliteTokenSkipped                         // whitespace, a comment, a byte-order mark
	sqliteTokenSemi                            // `;`
)

// sqliteTokenLen is the length and class of the token at the start of z
// (non-empty, no NUL): SQLite's sqlite3GetToken, kept only as far as where a
// token ends and whether the parser ever sees it. It differs from the shared
// lexer above where SQLite does: a parameter may carry a parenthesized suffix
// that holds quotes, `;` and `--` (`$name(...)`), a byte-order mark is
// whitespace, and `/*` as the last two bytes is not a comment. The gates built
// on the shared lexer are not changed by this.
func sqliteTokenLen(z string) (int, sqliteTokenClass) {
	at := func(i int) byte {
		if i < len(z) {
			return z[i]
		}
		return 0
	}
	c := z[0]
	switch {
	case c == ' ' || c == '\t' || c == '\n' || c == '\f' || c == '\r':
		i := 1
		for sqliteIsSpace(at(i)) {
			i++
		}
		return i, sqliteTokenSkipped
	case c == ';':
		return 1, sqliteTokenSemi
	case c == '-':
		switch at(1) {
		case '-':
			i := 2
			for i < len(z) && z[i] != '\n' {
				i++
			}
			return i, sqliteTokenSkipped
		case '>':
			if at(2) == '>' {
				return 3, sqliteTokenParsed
			}
			return 2, sqliteTokenParsed
		}
		return 1, sqliteTokenParsed
	case c == '/':
		if at(1) != '*' || at(2) == 0 {
			return 1, sqliteTokenParsed
		}
		// The `*` that opens the comment does not also close it; a comment
		// without an end runs to the end of the text.
		i, ch := 3, at(2)
		for ch != '*' || at(i) != '/' {
			if ch = at(i); ch == 0 {
				break
			}
			i++
		}
		if ch != 0 {
			i++
		}
		return i, sqliteTokenSkipped
	case c == '\'' || c == '"' || c == '`':
		i := 1
		for ; i < len(z); i++ {
			if z[i] == c {
				if at(i+1) != c {
					return i + 1, sqliteTokenParsed
				}
				i++ // a doubled delimiter is the delimiter itself
			}
		}
		return len(z), sqliteTokenParsed // no end: an illegal token
	case c == '[':
		i := 1
		for i < len(z) {
			i++
			if z[i-1] == ']' {
				break
			}
		}
		return i, sqliteTokenParsed
	case c == '.' && !sqliteIsDigit(at(1)):
		return 1, sqliteTokenParsed
	case c == '.' || sqliteIsDigit(c):
		i := 0
		digits := func(digit func(byte) bool) {
			for digit(at(i)) || at(i) == '_' {
				i++
			}
		}
		if c == '0' && (at(1) == 'x' || at(1) == 'X') && sqliteIsHexDigit(at(2)) {
			i = 3
			digits(sqliteIsHexDigit)
		} else {
			digits(sqliteIsDigit)
			if at(i) == '.' {
				i++
				digits(sqliteIsDigit)
			}
			if (at(i) == 'e' || at(i) == 'E') && (sqliteIsDigit(at(i+1)) ||
				((at(i+1) == '+' || at(i+1) == '-') && sqliteIsDigit(at(i+2)))) {
				i += 2
				digits(sqliteIsDigit)
			}
		}
		for sqliteIdentByte(at(i)) {
			i++
		}
		return i, sqliteTokenParsed
	case c == '?':
		i := 1
		for sqliteIsDigit(at(i)) {
			i++
		}
		return i, sqliteTokenParsed
	case c == '$' || c == '@' || c == ':' || c == '#':
		i, named := 1, false
		for ; i < len(z); i++ {
			ch := z[i]
			if sqliteIdentByte(ch) {
				named = true
				continue
			}
			if ch == '(' && named {
				for {
					i++
					if ch = at(i); ch == 0 || sqliteIsSpace(ch) || ch == ')' {
						break
					}
				}
				if ch == ')' {
					i++
				}
				break
			}
			if ch == ':' && at(i+1) == ':' {
				i++
				continue
			}
			break
		}
		return i, sqliteTokenParsed
	case (c == 'x' || c == 'X') && at(1) == '\'':
		i := 2
		for sqliteIsHexDigit(at(i)) {
			i++
		}
		if at(i) != '\'' || i%2 != 0 {
			for i < len(z) && z[i] != '\'' {
				i++
			}
		}
		if i < len(z) {
			i++
		}
		return i, sqliteTokenParsed
	case c == 0xEF && at(1) == 0xBB && at(2) == 0xBF:
		return 3, sqliteTokenSkipped
	case sqliteIdentByte(c): // a keyword or identifier; `$` and digits start other tokens above
		i := 1
		for sqliteIdentByte(at(i)) {
			i++
		}
		return i, sqliteTokenParsed
	case c == '=' && at(1) == '=',
		c == '<' && (at(1) == '=' || at(1) == '>' || at(1) == '<'),
		c == '>' && (at(1) == '=' || at(1) == '>'),
		c == '!' && at(1) == '=',
		c == '|' && at(1) == '|':
		return 2, sqliteTokenParsed
	}
	return 1, sqliteTokenParsed // one-byte punctuation, or a byte SQLite refuses
}

func sqliteIsSpace(b byte) bool { return b == ' ' || (b >= '\t' && b <= '\r') }

func sqliteIsDigit(b byte) bool { return b >= '0' && b <= '9' }

func sqliteIsHexDigit(b byte) bool {
	return sqliteIsDigit(b) || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// sqliteIdentByte is SQLite's IdChar: what a keyword, identifier or parameter
// name continues with.
func sqliteIdentByte(b byte) bool {
	return b == '_' || b == '$' || b >= 0x80 || sqliteIsDigit(b) ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z')
}
