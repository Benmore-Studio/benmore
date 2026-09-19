//go:build !cli

package main

import (
	"bufio"
	"io"
	"strings"
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
