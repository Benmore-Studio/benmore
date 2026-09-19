//go:build !cli

package main

import (
	"fmt"
	"os"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestGuardRestoreStatementRejectsDDL(t *testing.T) {
	// DDL stays rejected for the same reason sql(write:true) rejects it
	// (mcp_tools_composers.go:166): raw DDL desyncs the framework loaders
	// from schema.prisma, which is the condition prisma_prune cleans up.
	for _, stmt := range []string{
		"CREATE TABLE t (id INTEGER)",
		"  create table t (id integer)",
		"ALTER TABLE products ADD COLUMN x TEXT",
		"DROP TABLE products",
		"DROP INDEX idx_products",
		"TRUNCATE products",
	} {
		if err := guardRestoreStatement(stmt); err == nil {
			t.Errorf("DDL must be rejected: %q", stmt)
		}
	}
}

// TestGuardRestoreStatementRejectsWhitespaceSplitDDL is the Important-2
// fix: a raw HasPrefix against "DROP TABLE" misses "DROP\nTABLE" or
// "DROP  TABLE" entirely, and generated SQL dumps - the only thing Mode B
// ingests - commonly wrap DDL across lines.
func TestGuardRestoreStatementRejectsWhitespaceSplitDDL(t *testing.T) {
	for _, stmt := range []string{
		"DROP\nTABLE products",
		"DROP  TABLE products",
		"ALTER\tTABLE products ADD COLUMN x TEXT",
		"CREATE\n\tTABLE t (id INTEGER)",
	} {
		if err := guardRestoreStatement(stmt); err == nil {
			t.Errorf("whitespace-split DDL must still be rejected: %q", stmt)
		}
	}
}

// TestGuardRestoreStatementRejectsPragma is the Important-2 fix: PRAGMA
// writable_schema=ON is the only way to make sqlite_master writable,
// which is otherwise the backstop against a plain UPDATE reaching the
// schema table.
func TestGuardRestoreStatementRejectsPragma(t *testing.T) {
	for _, stmt := range []string{
		"PRAGMA writable_schema=ON",
		"pragma writable_schema = on",
	} {
		if err := guardRestoreStatement(stmt); err == nil {
			t.Errorf("PRAGMA must be rejected: %q", stmt)
		}
	}
}

func TestGuardRestoreStatementRejectsAttachAndExtensions(t *testing.T) {
	for _, stmt := range []string{
		"ATTACH DATABASE '/opt/benmore/apps/other/data.db' AS other",
		"attach database 'x' as y",
		"DETACH DATABASE other",
		"SELECT load_extension('/tmp/evil.so')",
		"INSERT INTO t VALUES (load_extension('x'))",
	} {
		if err := guardRestoreStatement(stmt); err == nil {
			t.Errorf("must be rejected: %q", stmt)
		}
	}
}

// TestGuardRestoreStatementAllowlistRejectsUnlistedVerbs is the round-3
// Important-1 fix. guardRestoreStatement used to be a DENYLIST
// (bannedRestorePrefixes) that enumerated forbidden DDL spellings and was
// always one spelling behind - the reviewer reproduced every one of these
// as PERMITTED against HEAD. COMMIT was the serious one: it commits
// runSQLRestoreInner's own transaction early, silently breaking the
// "atomic always, a failure leaves zero rows" guarantee that is the
// feature's headline promise. The fix is an ALLOWLIST of first verbs
// (INSERT/UPDATE/DELETE/REPLACE/WITH); everything else is rejected by
// construction, with no enumeration gap to fall behind on.
func TestGuardRestoreStatementAllowlistRejectsUnlistedVerbs(t *testing.T) {
	for _, stmt := range []string{
		"COMMIT",
		"BEGIN TRANSACTION",
		"CREATE UNIQUE INDEX idx ON products(sku)",
		"CREATE TEMP TABLE evil (x TEXT)",
		"CREATE VIRTUAL TABLE v USING fts5(x)",
		"ROLLBACK",
		"END",
		"SAVEPOINT s",
		"RELEASE s",
		"VACUUM",
		"ANALYZE",
		"CREATE TRIGGER trg AFTER INSERT ON products BEGIN SELECT 1; END",
		"CREATE VIEW v AS SELECT * FROM products",
	} {
		if err := guardRestoreStatement(stmt); err == nil {
			t.Errorf("must be rejected by the verb allowlist: %q", stmt)
		}
	}
}

// TestGuardRestoreStatementAllowsWithCTE proves the allowlist doesn't
// over-reject: CTE-driven INSERT/UPDATE/DELETE is legitimate in dumps,
// and SQLite's own grammar only lets a CTE prefix a SELECT/INSERT/
// UPDATE/DELETE - never DDL or transaction control - so WITH cannot be
// used to smuggle either.
func TestGuardRestoreStatementAllowsWithCTE(t *testing.T) {
	stmt := "WITH x AS (SELECT 1) INSERT INTO t SELECT * FROM x"
	if err := guardRestoreStatement(stmt); err != nil {
		t.Errorf("a CTE-driven INSERT must be allowed: %v", err)
	}
}

// TestRunSQLRestoreCommitCannotBreakAtomicity is the end-to-end
// regression for the reviewer's most serious finding: a script that
// smuggles a COMMIT after a real row-producing statement must not be
// able to commit runSQLRestoreInner's transaction early. The whole
// restore must fail and leave zero rows.
func TestRunSQLRestoreCommitCannotBreakAtomicity(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	script := "INSERT INTO products (sku, qty) VALUES ('A', 1);\nCOMMIT;\n"
	sum := stageString(t, app, "commitbreak1", script)
	sess := &importSession{
		ID: "commitbreak1", TableName: "", Format: "sql",
		BytesTotal: int64(len(script)), SHA256: sum,
	}
	insertSession(t, app, sess)

	if err := runSQLRestore(app, sess); err == nil {
		t.Fatal("expected the embedded COMMIT to fail the restore")
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 0 {
		t.Fatalf("after a rejected restore %d rows survived, want 0 - COMMIT must not have broken atomicity", n)
	}
}

func TestRunSQLRestoreGzipAllowsExactDecompressedBound(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	script := strings.Repeat("INSERT INTO products (sku, qty) VALUES ('A', 1);\n", 1000)
	compressed, sum := stageGzip(t, app, "sqlgzexact", script)
	sess := &importSession{
		ID: "sqlgzexact", Format: "sql", Gzip: true,
		BytesTotal: compressed, UncompressedBytes: int64(len(script)), SHA256: sum,
	}
	if gzipExpansionBound(sess) != int64(len(script)) {
		t.Fatalf("fixture does not reach the declared exact bound: bound=%d script=%d", gzipExpansionBound(sess), len(script))
	}
	insertSession(t, app, sess)
	if err := runSQLRestore(app, sess); err != nil {
		t.Fatalf("Mode B exact-bound gzip restore: %v", err)
	}

	var rows int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM products`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1000 {
		t.Fatalf("Mode B exact-bound gzip restore loaded %d rows, want 1000", rows)
	}
}

// TestGuardRestoreStatementRawChecksAreWordBoundaryAnchored is the
// round-3 Important-2 fix's false-positive guard: the raw attach/detach/
// pragma checks are \b-anchored (same shape as attachDetachRe,
// mcp_tools_composers.go:33) so ordinary identifiers like "attached_at"/
// "detached_at" - ATTACH/DETACH as a PREFIX of a longer word, not a
// standalone word - must not trip them.
func TestGuardRestoreStatementRawChecksAreWordBoundaryAnchored(t *testing.T) {
	stmt := "INSERT INTO events (attached_at, detached_at) VALUES ('2020-01-01', '2020-01-02')"
	if err := guardRestoreStatement(stmt); err != nil {
		t.Errorf("attached_at/detached_at must not trip the word-boundary-anchored ATTACH/DETACH check: %v", err)
	}
}

// TestGuardRestoreStatementAllocationBudget guards against the
// regression a round-3 review measured on HEAD: scanSQL's unconditional
// bufio.NewReaderSize(r, 1<<20), called twice per guardRestoreStatement
// invocation (stripRestoreSQLComments + stripSQLLiterals), allocated
// ~2 MiB per call regardless of statement size. On a 1.7 MB / 20,000-
// statement dump that measured 1.28s and 41.9 GB allocated in guard
// overhead alone (~1.33 MB/s - roughly 13 minutes for a 1 GB dump), all
// while holding one open write transaction blocking every other write to
// the app. The fix routes the two per-statement helpers through a
// zero-bufio string fast path (scanSQLBytes); this test pins a generous
// budget so a future change can't silently reintroduce the per-statement
// megabyte buffer.
func TestGuardRestoreStatementAllocationBudget(t *testing.T) {
	if raceEnabled {
		t.Skip("allocation byte counts are inflated by race detector shadow-memory instrumentation (~19 KB/call measured, still two orders of magnitude below the ~2 MiB/call regression this guards against) - not a meaningful budget under -race")
	}
	stmt := "INSERT INTO products (sku, qty) VALUES ('A', 1)"
	guardRestoreStatement(stmt) // warm up (e.g. one-time regexp compilation caching)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	const n = 2000
	for i := 0; i < n; i++ {
		_ = guardRestoreStatement(stmt)
	}
	runtime.ReadMemStats(&after)

	bytesPerCall := float64(after.TotalAlloc-before.TotalAlloc) / n
	// Generous headroom over the small-alloc, no-bufio shape the fix
	// produces - the point of this budget is "nowhere near 2 MiB", not a
	// tight pin that would make routine refactors flaky.
	const budget = 4096
	if bytesPerCall > budget {
		t.Fatalf("guardRestoreStatement allocates ~%.0f bytes/call, want <= %d (regression toward the pre-fix ~2 MiB-per-call scanSQL buffer?)", bytesPerCall, budget)
	}
}

// BenchmarkGuardRestoreStatement gives `go test -bench` visibility into
// the per-statement cost the allocation-budget test above pins a ceiling
// on.
func BenchmarkGuardRestoreStatement(b *testing.B) {
	stmt := "INSERT INTO products (sku, qty) VALUES ('A', 1)"
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = guardRestoreStatement(stmt)
	}
}

// TestGuardRestoreStatementRejectsLoadExtensionHiddenByQuoteDesync is the
// Important-3 fix. Before it, an apostrophe inside a double-quoted region
// desynchronised stripSQLLiterals' single-quote-only toggle: the '
// inside "o'" opened a phantom literal that blanked everything up to the
// next real ', including the LOAD_EXTENSION token, and the guard passed.
func TestGuardRestoreStatementRejectsLoadExtensionHiddenByQuoteDesync(t *testing.T) {
	stmt := `INSERT INTO t SELECT "o'", load_extension('/tmp/e.so')`
	if err := guardRestoreStatement(stmt); err == nil {
		t.Fatalf("load_extension hidden behind a quote-toggle desync must still be rejected: %q", stmt)
	}
}

// TestGuardRestoreStatementRejectsEmbeddedSemicolon is the guard-side half
// of the Critical fix: a "statement" that still contains a semicolon
// after comment- and literal-stripping means the splitter and the guard
// disagree about a boundary, and that must never reach tx.Exec (this
// driver runs ';'-joined statements as one call).
func TestGuardRestoreStatementRejectsEmbeddedSemicolon(t *testing.T) {
	stmt := "INSERT INTO products (sku) VALUES ('A'); DROP TABLE products"
	if err := guardRestoreStatement(stmt); err == nil {
		t.Fatalf("a statement carrying an embedded semicolon must be rejected: %q", stmt)
	}
}

// TestGuardRestoreStatementEmbeddedSemicolonCheckIgnoresQuotedOnes proves
// the defense-in-depth semicolon check doesn't false-positive on a
// legitimate semicolon sitting inside a quoted value or identifier - only
// a semicolon OUTSIDE any quoted region trips it.
func TestGuardRestoreStatementEmbeddedSemicolonCheckIgnoresQuotedOnes(t *testing.T) {
	for _, stmt := range []string{
		"INSERT INTO products (sku) VALUES ('a;b')",
		`INSERT INTO "weird;table" (sku) VALUES ('a')`,
		"INSERT INTO t (x) SELECT 1 AS [we;ird]",
		"INSERT INTO t (x) SELECT 1 AS `we;ird`",
	} {
		if err := guardRestoreStatement(stmt); err != nil {
			t.Errorf("a semicolon inside a quoted region must not be rejected: %q: %v", stmt, err)
		}
	}
}

func TestGuardRestoreStatementAllowsDML(t *testing.T) {
	for _, stmt := range []string{
		"INSERT INTO products (sku, qty) VALUES ('A', 1)",
		"insert into products values (1,'A',2,null)",
		"UPDATE products SET qty = 0 WHERE sku = 'A'",
		"DELETE FROM products WHERE qty < 0",
	} {
		if err := guardRestoreStatement(stmt); err != nil {
			t.Errorf("DML must be allowed, %q rejected: %v", stmt, err)
		}
	}
}

func TestGuardRestoreStatementIgnoresKeywordsInsideLiterals(t *testing.T) {
	// A product literally named "DROP TABLE" must not trip the guard -
	// the check tokenises rather than substring-matching.
	stmt := "INSERT INTO products (sku) VALUES ('DROP TABLE joke')"
	if err := guardRestoreStatement(stmt); err != nil {
		t.Errorf("a keyword inside a string literal must not be rejected: %v", err)
	}
}

func TestSplitSQLStatements(t *testing.T) {
	script := `
-- a comment; with a semicolon
INSERT INTO t VALUES (1);
INSERT INTO t VALUES ('semi; inside a literal');
INSERT INTO t VALUES (2)
`
	var got []string
	err := splitSQLStatements(strings.NewReader(script), func(s string) error {
		got = append(got, s)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("split produced %d statements, want 3: %#v", len(got), got)
	}
	if !strings.Contains(got[1], "semi; inside a literal") {
		t.Errorf("a semicolon inside a string literal must not split: %q", got[1])
	}
}

// TestSplitSQLStatementsProtectsDoubleQuotedRegions is the CRITICAL fix.
// Before it, splitSQLStatements tracked only ' and had no case for ", so
// a "--" or "/*" sitting inside a double-quoted region flipped the
// scanner into comment state and swallowed everything after it -
// including a real ';' and a smuggled DDL statement - into one
// accumulated "statement" that then passed guardRestoreStatement on its
// first keyword and reached tx.Exec as one ';'-chained string. Both the
// line-comment and block-comment variants of the bypass are covered.
func TestSplitSQLStatementsProtectsDoubleQuotedRegions(t *testing.T) {
	cases := []struct {
		name   string
		script string
	}{
		{
			name:   "double-quoted line-comment marker",
			script: `INSERT INTO products (sku) VALUES ("a--b"); DROP TABLE products;`,
		},
		{
			name:   "double-quoted block-comment marker",
			script: `INSERT INTO products (sku) VALUES ("a/*b"); DROP TABLE products;`,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			err := splitSQLStatements(strings.NewReader(c.script), func(s string) error {
				got = append(got, s)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 2 {
				t.Fatalf("split produced %d statement(s), want 2 (the double-quoted \"--\"/\"/*\" must not swallow the rest of the script): %#v", len(got), got)
			}
			if strings.Contains(got[0], "DROP") {
				t.Fatalf("the DROP TABLE statement leaked into the first split statement: %q", got[0])
			}
		})
	}
}

// TestSplitSQLStatementsHandlesDoubledDoubleQuotes proves the doubled-
// quote escape ("") inside a double-quoted region doesn't prematurely
// close it and doesn't cause a split.
func TestSplitSQLStatementsHandlesDoubledDoubleQuotes(t *testing.T) {
	script := `INSERT INTO products (sku) VALUES ('x'); INSERT INTO t (name) VALUES ("a""b");`
	var got []string
	err := splitSQLStatements(strings.NewReader(script), func(s string) error {
		got = append(got, s)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("split produced %d statement(s), want 2: %#v", len(got), got)
	}
}

// TestSplitSQLStatementsBlockCommentDoesNotSelfClose covers the small
// parser-disagreement fix noted alongside the Critical one: "/*/" is not
// a valid self-closing block comment in SQL (the minimum is "/**/"). If
// the splitter treated it as closed, content meant to still be commented
// out would become live SQL.
func TestSplitSQLStatementsBlockCommentDoesNotSelfClose(t *testing.T) {
	script := "INSERT INTO t VALUES (1); /*/ DROP TABLE t; */ INSERT INTO t VALUES (2);"
	var got []string
	err := splitSQLStatements(strings.NewReader(script), func(s string) error {
		got = append(got, s)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// "/*/" does not self-close, so the whole "/*/ ... */" span - including
	// the semicolon after "DROP TABLE t" - is ONE inert comment that runs
	// through to the LATER real "*/", not two statements split at that
	// inner semicolon.
	if len(got) != 2 {
		t.Fatalf("split produced %d statement(s), want 2 (the whole /*/ ... */ span must stay one comment, not split at the semicolon inside it): %#v", len(got), got)
	}
	// The DROP text sits inside a real (if oddly-shaped) SQL comment, so
	// guardRestoreStatement must see it as the harmless trailing INSERT it
	// actually is once the comment is stripped - not as executable DDL.
	// (stripRestoreSQLComments treats "/*/" the same way stripSQLComments
	// does - see the drift test - so this isn't a guard/splitter mismatch,
	// just real SQL comment semantics.)
	if err := guardRestoreStatement(got[1]); err != nil {
		t.Fatalf("a DROP hidden inside a legitimately-open (if oddly-shaped) block comment must not trip the DDL guard: %v (statement: %q)", err, got[1])
	}
}

// TestSplitSQLStatementsProtectsBracketAndBacktickRegions is the round-2
// Critical fix: SQLite has FOUR quoting forms, not two. The round-1 fix
// taught the splitter about " but not [...] (MS Access compat) or
// `...` (MySQL compat) - a "--" or "/*" inside either of THOSE regions
// flips the scanner into comment state and swallows a smuggled statement
// the exact same way the "-fixed bypass did. These are the reviewer's
// own reproduced cases, reproduced here as a real go test.
func TestSplitSQLStatementsProtectsBracketAndBacktickRegions(t *testing.T) {
	cases := []struct {
		name   string
		script string
	}{
		{"bracket line-comment marker", "INSERT INTO products (sku) SELECT 'x' AS [a--b]; DROP TABLE products;"},
		{"backtick line-comment marker", "INSERT INTO products (sku) SELECT 'x' AS `a--b`; DROP TABLE products;"},
		{"bracket block-comment marker", "INSERT INTO products (sku) SELECT 'x' AS [a/*b]; ATTACH DATABASE '/tmp/o.db' AS o;"},
		{"backtick block-comment marker", "INSERT INTO products (sku) SELECT 'x' AS `a/*b`; ATTACH DATABASE '/tmp/o.db' AS o;"},
		{"bracket marker before UPDATE", "INSERT INTO products (sku) SELECT 'x' AS [a--b]; UPDATE secret SET v='pwned';"},
		{"bracket marker before newline-prefixed smuggled statement", "INSERT INTO products (sku) SELECT 'x' AS [a--b];\nDROP TABLE products;"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			err := splitSQLStatements(strings.NewReader(c.script), func(s string) error {
				got = append(got, s)
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 2 {
				t.Fatalf("split produced %d statement(s), want 2 (the bracket/backtick-quoted \"--\"/\"/*\" must not swallow the rest of the script): %#v", len(got), got)
			}
			// The smuggled statement must stand ALONE as got[1], not be
			// glued into got[0] (which is what "swallowed into one
			// statement" looked like pre-fix: len(got)==1 with the whole
			// script as a single blob).
			first := strings.ToUpper(got[0])
			for _, banned := range []string{"DROP", "ATTACH", "PRAGMA", "UPDATE SECRET"} {
				if strings.Contains(first, banned) {
					t.Fatalf("the smuggled statement leaked into the FIRST split statement instead of standing alone: got[0]=%q got[1]=%q", got[0], got[1])
				}
			}
		})
	}
}

// TestRunSQLRestoreRejectsSmuggledDDLViaBracketAndBacktick is the round-2
// Critical fix, end to end: the reviewer's reproduced PoCs run through
// the real runSQLRestore path. Before the fix each of these executed
// BOTH statements (the harmless INSERT and the smuggled
// DROP/ATTACH/PRAGMA) via one tx.Exec call, with runSQLRestore reporting
// success. (The reviewer's fourth PoC - a smuggled UPDATE - is covered
// separately below: UPDATE is legitimate DML Mode B always permits, so
// the fix for it is not rejection, it's that the statement is now
// correctly split out and independently counted rather than riding along
// unaccounted for - see TestRunSQLRestoreCountsBracketSmuggledUpdate.)
func TestRunSQLRestoreRejectsSmuggledDDLViaBracketAndBacktick(t *testing.T) {
	cases := []struct {
		name   string
		script string
	}{
		{"bracket hides DROP TABLE", "INSERT INTO products (sku) SELECT 'x' AS [a--b]; DROP TABLE products;"},
		{"backtick hides DROP TABLE", "INSERT INTO products (sku) SELECT 'x' AS `a--b`; DROP TABLE products;"},
		{"bracket block-comment hides ATTACH", "INSERT INTO products (sku) SELECT 'x' AS [a/*b]; ATTACH DATABASE '/tmp/o.db' AS o;"},
		{"bracket hides PRAGMA writable_schema", "INSERT INTO products (sku) SELECT 'x' AS [a--b]; PRAGMA writable_schema=ON;"},
	}
	for i, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			app, cleanup := newImportTestApp(t)
			defer cleanup()
			mustExec(t, app.DB, "CREATE TABLE secret (v TEXT)")

			id := "bypasstest" + strconv.Itoa(i)
			sum := stageString(t, app, id, c.script)
			sess := &importSession{
				ID: id, TableName: "", Format: "sql",
				BytesTotal: int64(len(c.script)), SHA256: sum,
			}
			insertSession(t, app, sess)

			if err := runSQLRestore(app, sess); err == nil {
				t.Fatalf("expected the smuggled statement to fail the restore: %s", c.script)
			}
			// The whole point: products must still exist (no DROP), and
			// must be EMPTY (the whole restore is atomic - the harmless
			// first INSERT must not survive either).
			var n int
			if err := app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n); err != nil {
				t.Fatalf("products table must still exist: %v", err)
			}
			if n != 0 {
				t.Fatalf("after a rejected restore %d rows survived, want 0", n)
			}
		})
	}
}

// TestRunSQLRestoreCountsBracketSmuggledUpdate is the positive-case
// companion: an UPDATE hidden behind the same [bracket]-comment trick is
// legitimate DML Mode B always permits (the owner already holds it via
// sql(write:true)), so the fix's job here isn't to reject it - it's to
// make sure it's no longer silently unaccounted for. Pre-fix, this whole
// script landed as ONE tx.Exec call reported as "1 statement applied"
// (an audit-log lie: two statements actually ran). Post-fix it must be
// two independently-counted, independently-guarded statements.
func TestRunSQLRestoreCountsBracketSmuggledUpdate(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	script := "INSERT INTO products (sku, qty) SELECT 'x' AS [a--b], 1; UPDATE products SET qty=2 WHERE sku='x';"
	sum := stageString(t, app, "bracketupd1", script)
	sess := &importSession{
		ID: "bracketupd1", TableName: "", Format: "sql",
		BytesTotal: int64(len(script)), SHA256: sum,
	}
	insertSession(t, app, sess)

	if err := runSQLRestore(app, sess); err != nil {
		t.Fatalf("runSQLRestore: %v", err)
	}
	got, err := loadImportSession(app.DB, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.RowsLoaded != 2 {
		t.Fatalf("rows_loaded (statements applied) = %d, want 2 - the UPDATE must be counted as its own statement, not silently riding along inside the INSERT's", got.RowsLoaded)
	}
	var qty int
	if err := app.DB.QueryRow("SELECT qty FROM products WHERE sku='x'").Scan(&qty); err != nil {
		t.Fatal(err)
	}
	if qty != 2 {
		t.Fatalf("qty = %d, want 2 (the UPDATE must actually have applied)", qty)
	}
}

// TestSplitSQLStatementsNegativeCases proves the four-quote-kind grammar
// fix does not over-reject real, benign SQL.
func TestSplitSQLStatementsNegativeCases(t *testing.T) {
	t.Run("semicolon inside a genuine string value", func(t *testing.T) {
		var got []string
		err := splitSQLStatements(strings.NewReader("INSERT INTO t VALUES ('a;b');"), func(s string) error {
			got = append(got, s)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("split produced %d statement(s), want 1: %#v", len(got), got)
		}
	})

	t.Run("semicolon inside a bracket identifier", func(t *testing.T) {
		var got []string
		err := splitSQLStatements(strings.NewReader("INSERT INTO t (x) SELECT 1 AS [we;ird];"), func(s string) error {
			got = append(got, s)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("split produced %d statement(s), want 1 (a semicolon inside [...] must not split): %#v", len(got), got)
		}
	})

	t.Run("legitimate multi-line INSERT", func(t *testing.T) {
		script := "INSERT INTO products (\n  sku,\n  qty\n) VALUES (\n  'A',\n  1\n);"
		var got []string
		err := splitSQLStatements(strings.NewReader(script), func(s string) error {
			got = append(got, s)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 1 {
			t.Fatalf("split produced %d statement(s), want 1: %#v", len(got), got)
		}
	})

	t.Run("single-quoted comment marker followed by a real second statement", func(t *testing.T) {
		script := "INSERT INTO t VALUES ('a--b'); INSERT INTO t VALUES ('c');"
		var got []string
		err := splitSQLStatements(strings.NewReader(script), func(s string) error {
			got = append(got, s)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if len(got) != 2 {
			t.Fatalf("split produced %d statement(s), want 2: %#v", len(got), got)
		}
	})
}

func TestSplitSQLStatementsStopsOnCallbackError(t *testing.T) {
	script := "INSERT INTO t VALUES (1);\nDROP TABLE t;\nINSERT INTO t VALUES (2);"
	var seen int
	err := splitSQLStatements(strings.NewReader(script), func(s string) error {
		seen++
		return guardRestoreStatement(s)
	})
	if err == nil {
		t.Fatal("expected the DROP to abort the walk")
	}
	if seen != 2 {
		t.Fatalf("walked %d statements, want 2 (stop at the DROP)", seen)
	}
}

func TestRunSQLRestoreIsAtomic(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	// Second statement is DDL, which the guard rejects. The first
	// statement's row must not survive.
	script := "INSERT INTO products (sku, qty) VALUES ('A', 1);\nDROP TABLE products;\n"
	sum := stageString(t, app, "sqlrest1", script)
	sess := &importSession{
		ID: "sqlrest1", TableName: "", Format: "sql",
		BytesTotal: int64(len(script)), SHA256: sum,
	}
	insertSession(t, app, sess)

	if err := runSQLRestore(app, sess); err == nil {
		t.Fatal("expected the DDL statement to fail the restore")
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 0 {
		t.Fatalf("after a failed atomic restore %d rows survived, want 0", n)
	}
}

// TestRunSQLRestoreRejectsSmuggledDDLViaDoubleQuote is the end-to-end
// Critical-fix regression test: the exact reviewer PoC, run through the
// real runSQLRestore path rather than the splitter in isolation. Before
// the fix this landed the 'A' row AND dropped the products table in one
// tx.Exec call; after the fix the whole script is rejected atomically.
func TestRunSQLRestoreRejectsSmuggledDDLViaDoubleQuote(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	script := `INSERT INTO products (sku) VALUES ("a--b"); DROP TABLE products;`
	sum := stageString(t, app, "sqlrest3", script)
	sess := &importSession{
		ID: "sqlrest3", TableName: "", Format: "sql",
		BytesTotal: int64(len(script)), SHA256: sum,
	}
	insertSession(t, app, sess)

	if err := runSQLRestore(app, sess); err == nil {
		t.Fatal("expected the smuggled DROP TABLE to fail the restore")
	}
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n); err != nil {
		t.Fatalf("products table must still exist (DROP TABLE must not have executed): %v", err)
	}
	if n != 0 {
		t.Fatalf("after a rejected restore %d rows survived, want 0", n)
	}
}

func TestRunSQLRestoreLoadsMultipleStatements(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	script := "INSERT INTO products (sku, qty) VALUES ('A', 1);\n" +
		"INSERT INTO products (sku, qty) VALUES ('B', 2);\n"
	sum := stageString(t, app, "sqlrest2", script)
	sess := &importSession{
		ID: "sqlrest2", TableName: "", Format: "sql",
		BytesTotal: int64(len(script)), SHA256: sum,
	}
	insertSession(t, app, sess)

	if err := runSQLRestore(app, sess); err != nil {
		t.Fatalf("runSQLRestore: %v", err)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 2 {
		t.Fatalf("loaded %d rows, want 2", n)
	}
}

// TestRunSQLRestoreHonoursAppStop is the I2 fix: runImportInner
// (import_run.go) already selects on app.Stop per row, but the SQL
// restore's statement walk never carried the same check, so a multi-GB
// restore ignored shutdown entirely - violating CLAUDE.md's background-
// worker rule ("per-app workers... select on app.Stop"). app.Stop is
// pre-closed here (rather than racing a goroutine to close it mid-walk,
// which a 2-statement script executes too fast to observe reliably) so
// the FIRST statement's post-exec check trips deterministically; the
// second statement's INSERT must never run, and the whole restore must
// roll back atomically like any other failure.
func TestRunSQLRestoreHonoursAppStop(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	app.Stop = make(chan struct{})
	close(app.Stop)

	script := "INSERT INTO products (sku, qty) VALUES ('A', 1);\n" +
		"INSERT INTO products (sku, qty) VALUES ('B', 2);\n"
	sum := stageString(t, app, "sqlreststop1", script)
	sess := &importSession{
		ID: "sqlreststop1", TableName: "", Format: "sql",
		BytesTotal: int64(len(script)), SHA256: sum,
	}
	insertSession(t, app, sess)

	err := runSQLRestore(app, sess)
	if err == nil {
		t.Fatal("expected a closed app.Stop to abort the restore")
	}
	if !strings.Contains(err.Error(), "shutting down") {
		t.Fatalf("error = %v, want it to mention shutting down", err)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 0 {
		t.Fatalf("a shutdown-interrupted restore landed %d rows, want 0 (atomic rollback)", n)
	}
}

// TestRunSQLRestoreAbortsOnDecompressionBomb mirrors
// TestRunImportAbortsOnDecompressionBomb (import_run_test.go) for Mode B:
// the runtime decompression-bomb guard must apply to the SQL restore path
// too, not just Mode A - a declared/assumed uncompressed_bytes is a
// client claim on both paths.
// TestRunSQLRestoreAbortsOnDecompressionBomb is the runtime-guard fix
// (originally C1, re-pinned post HIGH-1 - see the CSV-path equivalent,
// TestRunImportAbortsOnDecompressionBomb, for the full rationale). A
// genuine bomb - decompressed content whose ratio against the COMPRESSED
// bytes vastly exceeds defaultGzipExpansionRatio (20x) - must still abort
// atomically (zero rows). The script here is maximally repetitive
// (identical statement repeated ~100k times) specifically so its real
// compression ratio lands far past the 20x backstop.
func TestRunSQLRestoreAbortsOnDecompressionBomb(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	var b strings.Builder
	for i := 0; i < 100000; i++ {
		b.WriteString("INSERT INTO products (sku, qty) VALUES ('A', 1);\n")
	}
	script := b.String()

	compLen, sum := stageGzip(t, app, "sqlrestbomb1", script)
	sess := &importSession{
		ID: "sqlrestbomb1", TableName: "", Format: "sql", Gzip: true,
		BytesTotal: compLen, SHA256: sum, // UncompressedBytes left undeclared (0)
	}
	insertSession(t, app, sess)

	if ratioBound := compLen * defaultGzipExpansionRatio; int64(len(script)) <= ratioBound {
		t.Fatalf("test fixture is not a genuine bomb: decompressed %d bytes must exceed compressed*ratio (%d)", len(script), ratioBound)
	}

	if err := runSQLRestore(app, sess); err == nil {
		t.Fatal("expected the decompression-bomb guard to abort a restore whose real ratio exceeds the compressed-bytes-based backstop")
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 0 {
		t.Fatalf("aborted decompression-bomb restore still landed %d rows, want 0", n)
	}
}

// TestRunSQLRestoreGzipHintSmallerThanCompressedDoesNotLowerCeiling is the
// SQL-restore-path half of the HIGH-1 fix (see the CSV-path equivalent,
// TestRunImportGzipHintSmallerThanCompressedDoesNotLowerCeiling): an
// ordinary (moderate-ratio) restore script whose declared uncompressed_bytes
// is smaller than the compressed upload itself - always a lie - must not
// have its runtime ceiling lowered below compressedBytes *
// defaultGzipExpansionRatio, since both Mode A and Mode B share
// gzipExpansionBound (import_run.go).
func TestRunSQLRestoreGzipHintSmallerThanCompressedDoesNotLowerCeiling(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	var b strings.Builder
	for i := 0; i < 500; i++ {
		fmt.Fprintf(&b, "INSERT INTO products (sku, qty) VALUES ('SKU%d', %d);\n", i, i)
	}
	script := b.String()

	compLen, sum := stageGzip(t, app, "sqlresthint1", script)
	if int64(64) >= compLen {
		t.Fatalf("test fixture invalid: the hint (64) must be smaller than the compressed size (%d) to exercise this guard", compLen)
	}
	sess := &importSession{
		ID: "sqlresthint1", TableName: "", Format: "sql", Gzip: true,
		BytesTotal: compLen, SHA256: sum,
		UncompressedBytes: 64, // smaller than compLen itself - always a lie
	}
	insertSession(t, app, sess)

	if err := runSQLRestore(app, sess); err != nil {
		t.Fatalf("runSQLRestore with a too-small hint on an ordinary script must succeed (the ratio floor must dominate): %v", err)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 500 {
		t.Fatalf("loaded %d rows, want 500", n)
	}
}

// TestRunSQLRestoreFailureClearsProgressAndReportsZeroRows is the
// Important-4 fix. Before it, importProgress.Delete only ran on the
// success path, so after a FAILED restore handleImportStatus (which
// prefers the live in-memory count) kept reporting a stale non-zero row
// count for a transaction that had actually rolled back to zero - a
// silently-wrong success signal on the failure path.
func TestRunSQLRestoreFailureClearsProgressAndReportsZeroRows(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	// The first statement applies (and bumps the live progress counter to
	// 1) before the second, DDL, statement fails the whole restore.
	script := "INSERT INTO products (sku, qty) VALUES ('A', 1);\nDROP TABLE products;\n"
	sum := stageString(t, app, "sqlrest4", script)
	sess := &importSession{
		ID: "sqlrest4", TableName: "", Format: "sql",
		BytesTotal: int64(len(script)), SHA256: sum,
	}
	insertSession(t, app, sess)

	if err := runSQLRestore(app, sess); err == nil {
		t.Fatal("expected the DDL statement to fail the restore")
	}

	if _, ok := importProgressOf(sess.ID); ok {
		t.Fatal("importProgress entry must be cleared after a failed restore, not left at its last live value")
	}

	got, err := loadImportSession(app.DB, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "failed" {
		t.Fatalf("state = %q, want failed", got.State)
	}
	if got.RowsLoaded != 0 {
		t.Fatalf("rows_loaded = %d, want 0 for a failed (rolled back) restore", got.RowsLoaded)
	}
}

func TestRunSQLRestoreRollsBackWhenCompletionCannotBeRecorded(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	EnsureAuditLogTable(app.DB)

	script := "INSERT INTO products (sku, qty) VALUES ('A', 1);\n"
	sum := stageString(t, app, "sqlatomic1", script)
	sess := &importSession{
		ID: "sqlatomic1", Format: "sql",
		BytesTotal: int64(len(script)), SHA256: sum,
	}
	insertSession(t, app, sess)
	mustExec(t, app.DB, `CREATE TRIGGER reject_import_completion BEFORE UPDATE OF state ON _benmore_imports
		WHEN NEW.state = 'completed' BEGIN SELECT RAISE(ABORT, 'completion blocked'); END`)

	if err := runSQLRestore(app, sess); err == nil {
		t.Fatal("completion-state failure must fail the restore")
	}
	var rows, audits int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM products`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'import'`).Scan(&audits); err != nil {
		t.Fatal(err)
	}
	got, err := loadImportSession(app.DB, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if rows != 0 || got.State != "failed" || got.RowsLoaded != 0 || audits != 0 {
		t.Fatalf("completion failure must leave no success: rows=%d state=%q progress=%d audits=%d", rows, got.State, got.RowsLoaded, audits)
	}
}

// TestRunSQLRestorePurgesStagingOnFailure mirrors
// TestRunImportPurgesStagingOnFailure (import_run_test.go) for Mode B:
// before the review round 2 fix, runSQLRestore's terminal defer only
// purged staging on the success branch, leaving a failed restore's staged
// script on disk forever (a "failed" session is never resumed, and
// handleImportCancel now correctly refuses to DELETE a terminal state).
func TestRunSQLRestorePurgesStagingOnFailure(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	script := "INSERT INTO products (sku, qty) VALUES ('A', 1);\nDROP TABLE products;\n"
	sum := stageString(t, app, "sqlrest5", script)
	sess := &importSession{
		ID: "sqlrest5", TableName: "", Format: "sql",
		BytesTotal: int64(len(script)), SHA256: sum,
	}
	insertSession(t, app, sess)

	dir := importStagingDir(app, "sqlrest5")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("precondition failed: staging dir must exist before the run: %v", err)
	}

	if err := runSQLRestore(app, sess); err == nil {
		t.Fatal("expected the DDL statement to fail the restore")
	}

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("staging dir must be purged after a FAILED restore too, got stat err = %v", err)
	}
}

// TestRunSQLRestoreWritesAuditEntry is the Important-5 fix: Mode B is the
// most powerful write path in the feature and must not be untraceable.
func TestRunSQLRestoreWritesAuditEntry(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	EnsureAuditLogTable(app.DB)

	script := "INSERT INTO products (sku, qty) VALUES ('A', 1);\n"
	sum := stageString(t, app, "sqlrest5", script)
	sess := &importSession{
		ID: "sqlrest5", TableName: "", Format: "sql",
		BytesTotal: int64(len(script)), SHA256: sum, CreatedBy: 1,
	}
	insertSession(t, app, sess)

	if err := runSQLRestore(app, sess); err != nil {
		t.Fatalf("runSQLRestore: %v", err)
	}

	var n int
	var newValues string
	err := app.DB.QueryRow(
		`SELECT COUNT(*), MAX(new_values) FROM _benmore_audit_log WHERE action='import' AND user_id=1`,
	).Scan(&n, &newValues)
	if err != nil {
		t.Fatal(err)
	}
	if n == 0 {
		t.Fatal("a completed Mode B restore must write an audit log entry")
	}
	if !strings.Contains(newValues, `"statements":1`) {
		t.Errorf("audit entry must record the statement count: %s", newValues)
	}
}

// TestRunSQLRestoreAuditEntryCarriesSubject is the I3 fix applied to Mode
// B specifically: Mode B is OWNER-ONLY, so CreatedBy is ALWAYS the 0
// sentinel in production (no per-app _benmore_users row an owner token
// could point at) - without CreatedBySubject, "the most powerful write
// path in the feature" audited as user_id=0, user_email=”.
func TestRunSQLRestoreAuditEntryCarriesSubject(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	EnsureAuditLogTable(app.DB)

	script := "INSERT INTO products (sku, qty) VALUES ('A', 1);\n"
	sum := stageString(t, app, "sqlrest5b", script)
	sess := &importSession{
		ID: "sqlrest5b", TableName: "", Format: "sql",
		BytesTotal: int64(len(script)), SHA256: sum,
		CreatedBy:        0, // the owner-token sentinel
		CreatedBySubject: "owner@self-hosted",
	}
	insertSession(t, app, sess)

	if err := runSQLRestore(app, sess); err != nil {
		t.Fatalf("runSQLRestore: %v", err)
	}

	var email string
	err := app.DB.QueryRow(
		`SELECT user_email FROM _benmore_audit_log WHERE action='import' AND user_id=0 ORDER BY id DESC LIMIT 1`,
	).Scan(&email)
	if err != nil {
		t.Fatal(err)
	}
	if email != "owner@self-hosted" {
		t.Fatalf("audit row user_email = %q, want %q", email, "owner@self-hosted")
	}
}

func TestImportOwnerTokenRejectsForgery(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	prev := serverSecret
	serverSecret = "test-secret-for-import-owner-token-0000"
	defer func() { serverSecret = prev }()

	good := mintImportOwnerToken(app, time.Now().Add(5*time.Minute), "owner@example.com")
	subject, ok := verifyImportOwnerToken(app, good)
	if !ok {
		t.Fatal("a freshly minted token must verify")
	}
	// I3 fix: the subject round-trips through mint -> verify.
	if subject != "owner@example.com" {
		t.Fatalf("subject = %q, want %q", subject, "owner@example.com")
	}
	if _, ok := verifyImportOwnerToken(app, good+"x"); ok {
		t.Fatal("a tampered token must not verify")
	}
	if _, ok := verifyImportOwnerToken(app, ""); ok {
		t.Fatal("an empty token must not verify")
	}
	expired := mintImportOwnerToken(app, time.Now().Add(-1*time.Minute), "owner@example.com")
	if _, ok := verifyImportOwnerToken(app, expired); ok {
		t.Fatal("an expired token must not verify")
	}
}

// TestImportOwnerTokenRejectsCrossAppToken is the Important-6 fix: on
// `benmore host`, many apps share one process and one serverSecret
// (host.go LoadApp), so without an audience a token minted for app A
// would verify against app B too - and Mode B has no per-table gate
// downstream, making that an arbitrary cross-tenant write.
func TestImportOwnerTokenRejectsCrossAppToken(t *testing.T) {
	appA, cleanupA := newImportTestApp(t)
	defer cleanupA()
	appB, cleanupB := newImportTestApp(t)
	defer cleanupB()
	if appA.Dir == appB.Dir {
		t.Fatal("test apps must have distinct Dir values for this test to mean anything")
	}

	prev := serverSecret
	serverSecret = "test-secret-shared-by-both-apps-000000"
	defer func() { serverSecret = prev }()

	tokenForA := mintImportOwnerToken(appA, time.Now().Add(5*time.Minute), "owner@example.com")
	if _, ok := verifyImportOwnerToken(appA, tokenForA); !ok {
		t.Fatal("a token must verify against the app it was minted for")
	}
	if _, ok := verifyImportOwnerToken(appB, tokenForA); ok {
		t.Fatal("a token minted for app A must not verify against app B")
	}
}

// TestImportOwnerTokenRejectsBeyondTTLCeiling proves the TTL ceiling is
// enforced on the VERIFY side regardless of what exp the token itself
// carries - a future or compromised minter cannot issue a longer-lived
// token than importTokenTTL permits.
func TestImportOwnerTokenRejectsBeyondTTLCeiling(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	prev := serverSecret
	serverSecret = "test-secret-for-import-ttl-ceiling-000"
	defer func() { serverSecret = prev }()

	tooLong := mintImportOwnerToken(app, time.Now().Add(importTokenTTL+time.Hour), "owner@example.com")
	if _, ok := verifyImportOwnerToken(app, tooLong); ok {
		t.Fatal("a token whose exp exceeds importTokenTTL from now must not verify")
	}

	withinCeiling := mintImportOwnerToken(app, time.Now().Add(importTokenTTL-time.Minute), "owner@example.com")
	if _, ok := verifyImportOwnerToken(app, withinCeiling); !ok {
		t.Fatal("a token within the TTL ceiling must verify")
	}
}
