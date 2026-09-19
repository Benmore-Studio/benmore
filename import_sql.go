//go:build !cli

package main

// Bulk import - Mode B, owner-only SQL restore.
//
// Authority note: this grants NOTHING new. The app owner already holds
// arbitrary INSERT/UPDATE/DELETE on every table in their own app through
// `sql` with write:true (mcp_tools_composers.go:130-178), bounded only by
// MCP's 8 MB body cap. Mode B is that same authority with a larger pipe
// and multi-statement support.
//
// The guard is an ALLOWLIST of first verbs (INSERT/UPDATE/DELETE/REPLACE/
// WITH), not a denylist of forbidden ones. An earlier denylist
// (bannedRestorePrefixes, now removed) enumerated forbidden DDL
// spellings and was always one spelling behind: a round-3 review found
// CREATE UNIQUE INDEX, CREATE TEMP TABLE, CREATE VIRTUAL TABLE, and bare
// COMMIT all passed it on HEAD. COMMIT was the serious one - it commits
// runSQLRestoreInner's own transaction early, so everything staged after
// it runs OUTSIDE the deferred rollback and the feature's headline
// "atomic always, a failure leaves zero rows" guarantee silently stopped
// holding. An allowlist rejects everything else BY CONSTRUCTION - DDL in
// any spelling, transaction control (BEGIN/COMMIT/ROLLBACK/END/
// SAVEPOINT/RELEASE), PRAGMA, VACUUM, ANALYZE, REINDEX, and anything a
// future SQLite release invents - with no enumeration gap to fall behind
// on. WITH is allowed because CTE-driven INSERT/UPDATE/DELETE is
// legitimate in dumps; SQLite's own grammar only lets a CTE prefix a
// SELECT/INSERT/UPDATE/DELETE, never a DDL or transaction-control
// statement, so WITH cannot smuggle either.
//
// Layered on top of the allowlist:
//   - load_extension, attach, detach, and pragma are ALSO matched via a
//     raw, \b-anchored, case-insensitive regex against the COMPLETELY
//     UNPROCESSED statement text (same shape as the reference path's
//     attachDetachRe, mcp_tools_composers.go:33) - not through
//     stripRestoreSQLComments/stripSQLLiterals at all. Deliberate belt-
//     and-suspenders: a future gap in scanSQL's grammar that swallows a
//     ';' would blank a smuggled token from the stripped text AND the
//     semicolon that would otherwise flag it, in the SAME failure - a
//     check that never touches the stripper cannot be defeated the same
//     way. Known, accepted cost: a row that legitimately contains one of
//     these words as DATA (e.g. a blog post about the load_extension()
//     function) is rejected - an atomic, loud failure, not silent data
//     loss. drop/create/alter/update are deliberately NOT raw-checked
//     this way: those words appear constantly in ordinary prose and row
//     data, and the allowlist above already protects them correctly
//     without that false-positive cost.
//   - PRAGMA gets a named error message: the canonical `sqlite3 db .dump`
//     output opens with "PRAGMA foreign_keys=OFF; BEGIN TRANSACTION;" and
//     closes with "COMMIT;" - Mode B's single most likely input therefore
//     fails at statement 1 unless that prologue/epilogue is stripped
//     first, and the message says so explicitly.
//   - Defense in depth: a statement whose comment/literal-stripped form
//     still contains a semicolon is rejected outright, mirroring the
//     single-statement enforcement in sanitizeConsoleQuery
//     (platform_dashboard.go:196). The guard is only as sound as
//     splitSQLStatements' idea of a statement boundary; if the two ever
//     disagree, this is what turns that disagreement into a hard failure
//     instead of chained execution (this driver runs ';'-joined
//     statements via a single tx.Exec call).
//
// stripRestoreSQLComments below is a deliberate DUPLICATE of
// stripSQLComments (mcp_tools_data.go), not a reuse. That file - and
// attachDetachRe in mcp_tools_composers.go - carry the build tag
// `!cli && platform`, but this file (like the rest of the bulk-import
// surface: import.go, import_http.go, import_run.go) is plain `!cli` so
// the framework and cloud editions get Mode B too (server.go's comment
// on RegisterImportRoutes: "the framework edition gets it without the
// platform"). Importing a platform-only symbol here would break those
// two editions' builds, so the (small, self-contained) comment-stripping
// logic is copied rather than shared. Keep the two in sync if either
// changes - import_sql_stripper_drift_test.go (platform-tagged) asserts
// they agree on a shared corpus.

import (
	"bufio"
	"compress/gzip"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

// allowedRestoreVerbs is the fail-closed core of Mode B's guard: a
// restore statement is accepted ONLY if its first keyword is one of
// these. See the file header for why this replaced an enumerate-what-is-
// forbidden denylist.
var allowedRestoreVerbs = map[string]bool{
	"INSERT": true, "UPDATE": true, "DELETE": true, "REPLACE": true, "WITH": true,
}

// ddlVerbs / transactionControlVerbs exist ONLY to choose a helpful,
// specific error message for the rejections users will actually hit -
// allowedRestoreVerbs above is the actual gate; nothing here widens or
// narrows what is permitted, so an unlisted DDL/control keyword still
// falls through to the generic message rather than being silently let
// through.
var ddlVerbs = map[string]bool{"CREATE": true, "ALTER": true, "DROP": true, "TRUNCATE": true}
var transactionControlVerbs = map[string]bool{
	"BEGIN": true, "COMMIT": true, "ROLLBACK": true, "END": true,
	"SAVEPOINT": true, "RELEASE": true,
}

// rawPragmaRe / rawAttachDetachRe mirror attachDetachRe's shape exactly
// (mcp_tools_composers.go:33) - \b-anchored, case-insensitive, matched
// against the RAW, completely unprocessed statement text. Word-anchored
// so "pragmatic"/"attached"/"detached" in prose don't false-positive.
// See the file header for why these run alongside (not instead of) the
// verb allowlist and the tokenised checks further down.
var rawPragmaRe = regexp.MustCompile(`(?i)\bPRAGMA\b`)
var rawAttachDetachRe = regexp.MustCompile(`(?i)\b(ATTACH|DETACH)\b`)

// errPragmaNotPermitted names the situation explicitly rather than just
// saying "no": the canonical `sqlite3 db .dump` output - Mode B's single
// most likely real input - opens with "PRAGMA foreign_keys=OFF; BEGIN
// TRANSACTION;" and closes with "COMMIT;", so a raw .dump file fails
// here on statement 1 with no other explanation unless told what to do
// about it. Strip that prologue/epilogue before staging: CREATE TABLE is
// banned too (restores are for rows, table shape comes from
// schema.prisma) and the runner already wraps the whole restore in one
// transaction.
var errPragmaNotPermitted = fmt.Errorf("PRAGMA is not permitted in a restore - if this came from `sqlite3 .dump`, strip its \"PRAGMA foreign_keys=OFF;\" / \"BEGIN TRANSACTION;\" / \"COMMIT;\" prologue and epilogue first; schema.prisma governs table shape, and the restore already runs inside one transaction")

// bannedRestoreTokens are rejected anywhere in a statement (after
// comment-stripping and literal-blanking), not just as a prefix - an
// ATTACH buried in a subquery is still an ATTACH. This is the SECOND,
// grammar-aware layer behind the raw checks above; see the file header.
var bannedRestoreTokens = map[string]bool{
	"ATTACH": true, "DETACH": true, "LOAD_EXTENSION": true, "PRAGMA": true,
}

// guardRestoreStatement rejects anything Mode B must not execute.
func guardRestoreStatement(stmt string) error {
	// Raw checks FIRST, on the completely unprocessed stmt - see the file
	// header for why these exist alongside, not instead of, everything
	// below.
	if strings.Contains(strings.ToLower(stmt), "load_extension") {
		return fmt.Errorf("load_extension is not permitted in a restore")
	}
	if rawPragmaRe.MatchString(stmt) {
		return errPragmaNotPermitted
	}
	if rawAttachDetachRe.MatchString(stmt) {
		return fmt.Errorf("ATTACH/DETACH DATABASE is not permitted in a restore - it would cross tenant boundaries. Each app's SQL is scoped to its own database.")
	}

	bare := strings.ToUpper(strings.TrimSpace(stripRestoreSQLComments(stmt)))
	if bare == "" {
		return nil
	}

	// Collapse whitespace runs (space/tab/newline) to a single space
	// before extracting the first verb. stripRestoreSQLComments preserves
	// whitespace verbatim, and generated SQL dumps - the only thing Mode
	// B ingests - sometimes wrap a keyword across lines.
	normalized := strings.Join(strings.Fields(bare), " ")
	verb := normalized
	if i := strings.IndexByte(normalized, ' '); i >= 0 {
		verb = normalized[:i]
	}
	if !allowedRestoreVerbs[verb] {
		switch {
		case ddlVerbs[verb]:
			return fmt.Errorf("schema DDL (%s) is not permitted in a restore - create tables through schema.prisma so the framework loaders stay in sync", verb)
		case verb == "PRAGMA":
			// Unreachable in practice (rawPragmaRe above already caught
			// it) - kept as defense in depth, and so the named message
			// still applies if that ever changes.
			return errPragmaNotPermitted
		case transactionControlVerbs[verb]:
			return fmt.Errorf("%s is not permitted in a restore - the runner already wraps the whole script in one transaction; a %s in the script would commit or unwind it early and break the restore's atomicity guarantee", verb, verb)
		default:
			return fmt.Errorf("statement type %q is not permitted in a restore - only INSERT, UPDATE, DELETE, REPLACE, and WITH (CTE) statements are allowed; table shape comes from schema.prisma and the runner supplies its own transaction", verb)
		}
	}

	// literalStripped blanks ALL FOUR quoted-region kinds, so a banned
	// token can't hide inside any of them and a stray semicolon inside a
	// legitimately quoted identifier doesn't false-positive the check
	// below.
	literalStripped := stripSQLLiterals(bare)
	for _, tok := range strings.FieldsFunc(literalStripped, func(r rune) bool {
		return !(r == '_' || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9'))
	}) {
		if !bannedRestoreTokens[tok] {
			continue
		}
		if tok == "PRAGMA" {
			return errPragmaNotPermitted
		}
		return fmt.Errorf("%s is not permitted in a restore", tok)
	}

	// Defense in depth: if a semicolon survives comment- and literal-
	// stripping, this "single statement" (as splitSQLStatements handed it
	// to us) actually contains more than one - the splitter and this
	// guard have disagreed about a boundary. That must never become
	// chained execution: tx.Exec on this driver runs ';'-joined
	// statements, so a guard/splitter mismatch here is not cosmetic, it's
	// the whole security control failing. Reject rather than execute.
	if strings.Contains(literalStripped, ";") {
		return fmt.Errorf("statement contains a semicolon outside any string literal - the restore splitter and executor disagree about statement boundaries, refusing rather than risking chained execution")
	}
	return nil
}

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
// sqlByteKind + scanSQLFrom below are the fix: ONE function implements
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
// a reactive "check the previous byte" approach. This matters for two
// reasons: (1) it means the star that OPENS a block comment can never
// simultaneously satisfy the check that CLOSES it, so "/*/" is correctly
// NOT a self-closing comment (confirmed against a real sqlite3 CLI - the
// minimum valid self-closing form is "/**/"); (2) it keeps
// stripRestoreSQLComments byte-for-byte compatible with the pre-existing,
// already-battle-tested stripSQLComments (mcp_tools_data.go) algorithm
// shape, which uses the same lookahead approach - see
// import_sql_stripper_drift_test.go.
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

// stripRestoreSQLComments removes -- line comments and /* */ block
// comments while respecting all four SQLite quoting forms, so a
// literal/identifier containing "--" or "/*" - in ANY of the four forms -
// cannot hide real SQL from guardRestoreStatement or fake-close a comment
// early. Built on scanSQLBytes; behaviourally matches stripSQLComments
// (mcp_tools_data.go) on the corpus the two are specified to agree on
// (single/double quotes, both comment forms) - see the file header for
// why this is a copy of that logic rather than a shared call, and
// import_sql_stripper_drift_test.go for the corpus comparison.
func stripRestoreSQLComments(sql string) string {
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
			// get their own space - matching stripSQLComments
			// (mcp_tools_data.go), which writes one space per comment it
			// skips, not one per contiguous run of them.
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
	// An unterminated block comment runs to EOF without ever satisfying
	// the close check above - stripSQLComments still writes its one
	// separating space unconditionally in that case (its skip-loop falls
	// through to the same WriteByte(' ') whether it broke on a real close
	// or ran off the end of input), so match that here too.
	if inBlockComment {
		b.WriteByte(' ')
	}
	return b.String()
}

// splitSQLStatements streams a script and invokes fn once per statement.
// It splits on semicolons that are outside ALL FOUR SQLite quoting forms
// and both comment forms (scanSQL), so a semicolon inside a value or ANY
// kind of quoted identifier never splits a statement - and, just as
// importantly, a "--" or "/*" that appears INSIDE a quoted region of any
// kind never flips the scanner into comment state and swallows the rest
// of the script into one statement. (This file's review caught this bug
// twice: round 1 for double-quoted regions, round 2 for [bracket] and
// `backtick` regions - which is exactly why the fix is a single shared
// grammar instead of a per-quote-kind special case in three places.)
// Streaming means a multi-gigabyte dump is never held in memory.
//
// A callback error stops the walk immediately (scanSQL itself stops
// reading) and is returned.
func splitSQLStatements(r io.Reader, fn func(string) error) error {
	var cur strings.Builder

	flush := func() error {
		stmt := strings.TrimSpace(cur.String())
		cur.Reset()
		if stmt == "" {
			return nil
		}
		return fn(stmt)
	}

	err := scanSQL(r, func(c byte, kind sqlByteKind) error {
		if kind == sqlCode && c == ';' {
			return flush()
		}
		cur.WriteByte(c)
		return nil
	})
	if err != nil {
		return err
	}
	return flush()
}

// runSQLRestore performs the restore synchronously. Exported behaviour: on
// return, the _benmore_imports row is in a terminal state. Mirrors
// runImport's (import_run.go) outer-terminal-bookkeeping-in-one-defer
// pattern exactly, including recover(): without it a panic mid-restore
// would leave the _benmore_imports row stuck non-terminal forever (the
// client polls indefinitely with nothing logged), leak the importProgress
// entry, AND - because the deferred closure would otherwise read err's
// zero value - get recorded as a false "completed" with 0 statements
// applied. The panic is re-raised once cleanup has run so safeGo's own
// recover still logs it.
//
// importProgress.Delete runs UNCONDITIONALLY, before the success/failure
// branch - not just on success. Before this fix, a failed restore left
// the live progress-map entry in place, so handleImportStatus (which
// prefers the in-memory count while an entry exists) kept reporting the
// row count as of the moment the guard tripped for an import whose
// transaction had already rolled back to zero rows: a silently-wrong
// success signal on the failure path.
func runSQLRestore(app *App, sess *importSession) error {
	var applied int64
	var err error
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("panic during SQL restore: %v", rec)
			defer panic(rec)
		}
		importProgress.Delete(sess.ID)
		if err != nil {
			changed, serr := saveImportStateIf(app.DB, sess.ID, "running", "failed", 0, err.Error())
			if serr != nil {
				log.Printf("IMPORT %s: failed to persist failed state: %v", sess.ID, serr)
			}
			if !changed {
				return
			}
			// See the matching comment in runImport (import_run.go): a
			// "failed" session is terminal and never resumed, so the
			// staged bytes are purged here rather than left to rely on a
			// client-side DELETE that handleImportCancel now correctly
			// refuses for a terminal state (review round 2 minor).
			purgeImportStaging(app, sess.ID)
			return
		}
		purgeImportStaging(app, sess.ID)

		// Mode B is the most powerful write path in the feature -
		// arbitrary multi-statement DML across arbitrary tables with no
		// per-table gate - so it gets an audit entry and a broadcast the
		// same as Mode A does, not a quieter version of them. table_name
		// is "" because a script can touch many tables in one restore;
		// "refresh" (rather than a row-specific action) matches the
		// existing fallback broadcastSQLWrite (mcp_tools_composers.go)
		// already uses for an opaque, not-attributable-to-one-table SQL
		// write. Email: sess.CreatedBySubject - Mode B is OWNER-ONLY
		// (always an owner token, CreatedBy is always the 0 sentinel), so
		// without this every production restore of "the most powerful
		// write path in the feature" audited as user_id=0, user_email=''
		// - see the matching comment in import_run.go's runImport.
		LogAudit(app, "import", "", "",
			&Session{UserID: sess.CreatedBy, Email: sess.CreatedBySubject},
			nil,
			map[string]any{"statements": applied, "bytes": sess.BytesTotal, "sha256": sess.SHA256, "format": "sql"},
		)
		BroadcastUnscoped(app, "", "refresh")
		log.Printf("IMPORT %s: SQL restore applied %d statements", sess.ID, applied)
	}()

	applied, err = runSQLRestoreInner(app, sess)
	return err
}

// runSQLRestoreInner does the actual restore and returns the count of
// statements applied on success. Returning it directly (rather than
// making the caller re-read importProgress by id) matters for the same
// reason runImportInner does it: if that map entry were ever absent for
// any reason, reading it back would silently report 0 for what was
// actually a successful restore.
//
// The reader chain mirrors runImportInner's exactly: stagedRawReader (RAW
// bytes, no gzip unwrap) tee'd into the hasher BEFORE any gzip decoding,
// because bytes_total/sha256 both describe the bytes the client actually
// uploaded - compressed, if sess.Gzip - which is the only stream the
// client can ever measure. stagedReader (import.go) unwraps gzip
// internally and so cannot be used here without hashing the wrong stream.
func runSQLRestoreInner(app *App, sess *importSession) (int64, error) {
	stop := sess.stop
	if stop == nil {
		stop = app.Stop
	}
	staged, err := stagedBytes(app, sess.ID)
	if err != nil {
		return 0, fmt.Errorf("stat staged chunks: %w", err)
	}
	if staged != sess.BytesTotal {
		return 0, fmt.Errorf("staged %d bytes but the session declared %d - upload is incomplete", staged, sess.BytesTotal)
	}

	raw, err := stagedRawReader(app, sess.ID)
	if err != nil {
		return 0, err
	}
	defer raw.Close()

	hasher := sha256.New()
	tee := io.TeeReader(raw, hasher)

	var src io.Reader = tee
	if sess.Gzip {
		gz, err := gzip.NewReader(tee)
		if err != nil {
			return 0, fmt.Errorf("open gzip stream: %w", err)
		}
		defer gz.Close()
		// Same runtime decompression-bomb backstop as runImportInner
		// (import_run.go) - bounded on the DECOMPRESSED output, never
		// trusting a declared uncompressed_bytes alone.
		src = &boundedReader{r: gz, limit: gzipExpansionBound(sess)}
	}

	tx, err := app.DB.Begin()
	if err != nil {
		return 0, fmt.Errorf("begin: %w", err)
	}
	committed := false
	defer func() {
		if !committed {
			tx.Rollback()
		}
	}()

	// *atomic.Int64, exactly what import_run.go stores under this same
	// map, so importProgressOf works for either runner.
	progress := &atomic.Int64{}
	importProgress.Store(sess.ID, progress)

	var applied int64
	walkErr := splitSQLStatements(src, func(stmt string) error {
		if err := guardRestoreStatement(stmt); err != nil {
			return fmt.Errorf("statement %d: %w", applied+1, err)
		}
		if _, err := tx.Exec(stmt); err != nil {
			return fmt.Errorf("statement %d: %w", applied+1, err)
		}
		applied++
		progress.Store(applied)
		// Per-statement select on app.Stop, mirroring runImportInner's
		// per-row check (import_run.go) - CLAUDE.md's background-worker
		// rule ("per-app workers... select on app.Stop") applied to Mode A
		// but was never carried over to this walk, so a multi-GB restore
		// ignored shutdown entirely: with startImport's in-flight guard
		// held the whole time, that left the app unable to cleanly stop
		// until the restore finished on its own.
		select {
		case <-stop:
			return fmt.Errorf("app shutting down after %d statements - restore rolled back", applied)
		default:
		}
		return nil
	})
	if walkErr != nil {
		return 0, walkErr
	}
	if applied == 0 {
		return 0, fmt.Errorf("script contained no executable statements")
	}

	// Drain any bytes not consumed by the statement walk (trailing
	// whitespace, or - for gzip - bytes gzip.Reader left unread past its
	// end-of-stream trailer) so the hash covers the whole staged file.
	io.Copy(io.Discard, tee)
	if got := hex.EncodeToString(hasher.Sum(nil)); got != sess.SHA256 {
		return 0, fmt.Errorf("checksum mismatch: staged data hashes to %s but the session declared %s", got, sess.SHA256)
	}

	if err := completeImport(tx, sess.ID, applied); err != nil {
		return 0, fmt.Errorf("complete import: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	committed = true
	return applied, nil
}

// --- owner proof ---
//
// Ownership is proved by possession of the app's server secret. On the
// hosted platform the router (which has already authenticated the owner)
// mints a short-lived token signed with the TARGET app's own secret - the
// same handoff shape the OAuth broker uses. Self-hosted, the CLI reads
// BENMORE_SERVER_SECRET directly. One mechanism, both editions.
//
// serverSecret can be an ephemeral per-process value when
// BENMORE_SERVER_SECRET is unset (auth.go init()) - a token minted before
// a restart then fails to verify after one, same as CSRF/signed-URL
// tokens already do in that configuration. That's an accepted, pre-
// existing trade-off of the server-secret model, not something new here;
// the fix is operational (set BENMORE_SERVER_SECRET), not code.
//
// The token is scoped to a single app (its audience is app.Dir - the same
// value importFlagFor/importCreateLimiter already use as this feature's
// app-identity key). `benmore host` loads many apps into ONE process
// sharing one serverSecret (host.go LoadApp), so without an audience a
// token minted for app A would verify against app B too - and Mode B has
// no per-table gate downstream, so that would be an arbitrary cross-
// tenant write. This is exactly the problem the OAuth broker's single-
// audience handoff assertion (security.md 31e) exists to prevent; the
// owner token uses the same shape.

// importTokenTTL bounds how long a minted owner token is usable,
// enforced on the VERIFY side regardless of what exp the token itself
// carries - a future or compromised minter cannot issue a longer-lived
// token than this ceiling permits. Short-lived because it stands in for
// a live admin session for the whole import - staging + commit should
// complete well inside this window; a long-running SQL restore's OWN
// wall-clock time doesn't matter, the token is only checked at the HTTP
// boundary before the load starts.
const importTokenTTL = 10 * time.Minute

// mintImportOwnerToken issues a token valid until exp, scoped to app and
// subject, signed with this PROCESS's own serverSecret - the shape a
// self-hosted `benmore serve` app (and its co-located CLI, reading the
// same BENMORE_SERVER_SECRET) uses. subject is the human-identifiable
// actor the token stands for (a platform user's email, hosted; a
// best-effort local identity, self-hosted) - see the payload-shape
// comment on mintImportOwnerTokenWithSecret for why it exists.
func mintImportOwnerToken(app *App, exp time.Time, subject string) string {
	return mintImportOwnerTokenWithSecret(app, exp, serverSecret, subject)
}

// mintImportOwnerTokenWithSecret is mintImportOwnerToken parameterized on
// the signing secret. The router mints on behalf of a TENANT app it does
// NOT share a process (or a serverSecret) with, so it must sign with THAT
// app's own secret - read from .benmore/server-secret via appServerSecret,
// platform_import_token.go's mint handler - never the router's own global
// serverSecret. Both callers must produce this exact payload shape:
// verifyImportOwnerToken is the single verifier for either origin.
//
// Payload: "import.<exp_unix>.<base64(subject)>.<app.Dir>". subject is
// carried base64-RawURLEncoding'd, NOT as raw text, because it is
// attacker-adjacent-but-legitimate free text (a platform user's email) -
// RawURLEncoding's alphabet never contains '.', which is what lets
// verifyImportOwnerToken split the payload unambiguously into exactly
// four fields even though BOTH subject (an email) and app.Dir (a
// filesystem path) may themselves legitimately contain dots. Encoding
// only the field that risks colliding with the delimiter, rather than
// (say) encoding the whole payload, keeps exp and the "import" tag
// human-readable in a decoded token for anyone debugging one.
func mintImportOwnerTokenWithSecret(app *App, exp time.Time, secret, subject string) string {
	encSubject := base64.RawURLEncoding.EncodeToString([]byte(subject))
	payload := fmt.Sprintf("import.%d.%s.%s", exp.Unix(), encSubject, app.Dir)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." +
		base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

// verifyImportOwnerToken checks signature, expiry, the importTokenTTL
// ceiling, and audience (app.Dir) - in that order, so the audience
// comparison only ever runs against a payload already proven authentic
// by the (constant-time) MAC check. Comparing a non-secret audience
// string with `!=` leaks nothing an attacker could use: without a valid
// MAC first, they never reach that comparison with a payload of their
// choosing. The audience check is unchanged in strength by the subject
// field added alongside it - it is still the last, and only, comparison
// that decides pass/fail once the MAC and TTL both hold.
//
// Returns the token's subject on success - "", false on any failure, so
// a caller can't accidentally treat a rejected token's zero-value subject
// as a legitimate (if anonymous) one.
func verifyImportOwnerToken(app *App, token string) (subject string, ok bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", false
	}
	mac := hmac.New(sha256.New, []byte(serverSecret))
	mac.Write(payload)
	if !hmac.Equal(sig, mac.Sum(nil)) {
		return "", false
	}
	// SplitN(...,4): "import", exp, base64(subject), then app.Dir gets
	// whatever remains - app.Dir can itself legitimately contain '.'
	// characters (path segments, extensions), so it must be the LAST
	// field, never split further. subject is base64, which cannot itself
	// contain '.', so it can't be mistaken for a delimiter either.
	fields := strings.SplitN(string(payload), ".", 4)
	if len(fields) != 4 || fields[0] != "import" {
		return "", false
	}
	exp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return "", false
	}
	now := time.Now()
	if now.Unix() >= exp {
		return "", false
	}
	if time.Unix(exp, 0).Sub(now) > importTokenTTL {
		return "", false
	}
	if fields[3] != app.Dir {
		return "", false
	}
	decSubject, err := base64.RawURLEncoding.DecodeString(fields[2])
	if err != nil {
		return "", false
	}
	return string(decSubject), true
}

// importOwnerToken reports whether the request carries a valid owner
// token scoped to app, and if so, the subject it was minted for.
func importOwnerToken(app *App, r *http.Request) (subject string, ok bool) {
	tok := r.Header.Get("X-Benmore-Import-Token")
	if tok == "" {
		return "", false
	}
	return verifyImportOwnerToken(app, tok)
}
