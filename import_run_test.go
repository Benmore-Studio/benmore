//go:build !cli

package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newImportTestApp(t *testing.T) (*App, func()) {
	t.Helper()
	app, cleanup := newTestApp(t)
	EnsureImportsTable(app)
	mustExec(t, app.DB, `CREATE TABLE products (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sku TEXT,
		qty INTEGER,
		user_id INTEGER
	)`)
	return app, cleanup
}

func stageString(t *testing.T, app *App, id, content string) string {
	t.Helper()
	if _, err := writeImportChunk(app, id, 0, strings.NewReader(content)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(content))
	return hex.EncodeToString(sum[:])
}

// stageGzip gzip-compresses content, stages the COMPRESSED bytes (that is
// what a real client uploads for a gzip import), and returns the
// compressed byte count and its sha256 - the pair a correct client sends
// as bytes_total/sha256, since the compressed stream is the only one the
// client can measure.
func stageGzip(t *testing.T, app *App, id, content string) (compressedLen int64, sum string) {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	if _, err := gw.Write([]byte(content)); err != nil {
		t.Fatal(err)
	}
	if err := gw.Close(); err != nil {
		t.Fatal(err)
	}
	compressed := buf.Bytes()
	if _, err := writeImportChunk(app, id, 0, bytes.NewReader(compressed)); err != nil {
		t.Fatal(err)
	}
	h := sha256.Sum256(compressed)
	return int64(len(compressed)), hex.EncodeToString(h[:])
}

// stageFileStreaming stages an ON-DISK fixture by streaming it straight
// into the same 32 MiB part-file layout the HTTP chunk-upload path produces
// (writeImportChunk), hashing it as it goes. Unlike stageString/stageGzip
// above, it never holds the fixture in memory: io.Copy's internal buffer is
// bounded (32 KB) regardless of chunk or file size, because the source here
// is a *os.File wrapped in io.TeeReader, not a string already in RAM. This
// is what TestRunImportAtTargetScale uses for the 50.5 MB fixture -
// stageString stays exactly as-is for every other (small, in-memory) test
// in this file, since re-deriving it for two rows of CSV would just add
// indirection with no memory benefit at that size.
func stageFileStreaming(t *testing.T, app *App, id, path string) (bytesTotal int64, sha256hex string) {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	hasher := sha256.New()
	tee := io.TeeReader(f, hasher)
	for chunk := 0; ; chunk++ {
		// writeImportChunk enforces the 32 MiB ceiling on whatever it reads
		// in ONE call (import.go:123, mirroring the real HTTP path where
		// r.Body is naturally bounded per PUT). tee itself is a continuous
		// stream over the whole file, so without this per-call LimitReader
		// the first call would happily read past 32 MiB and trip
		// errImportChunkTooLarge - the cap has to be applied here, once per
		// chunk, not left to writeImportChunk's own internal limiter (which
		// exists to catch a caller that already promised no more than that).
		written, err := writeImportChunk(app, id, chunk, io.LimitReader(tee, maxImportChunkBytes))
		if err != nil {
			t.Fatalf("stage chunk %d: %v", chunk, err)
		}
		bytesTotal += written
		if written < maxImportChunkBytes {
			// The underlying reader hit EOF before filling this chunk -
			// nothing more to stage.
			break
		}
	}
	return bytesTotal, hex.EncodeToString(hasher.Sum(nil))
}

func insertSession(t *testing.T, app *App, s *importSession) {
	t.Helper()
	gz := 0
	if s.Gzip {
		gz = 1
	}
	_, err := app.DB.Exec(`INSERT INTO _benmore_imports
		(id, table_name, format, gzip, bytes_total, uncompressed_bytes, sha256,
		 null_as, state, created_by, created_by_subject)
		VALUES (?,?,?,?,?,?,?,?,'running',1,?)`,
		s.ID, s.TableName, s.Format, gz, s.BytesTotal, s.UncompressedBytes,
		s.SHA256, s.NullAs, s.CreatedBySubject)
	if err != nil {
		t.Fatal(err)
	}
}

func TestImportableColumnsExcludesProtectedAndPK(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	cols, err := importableColumns(app.DB, "products", app)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range cols {
		names = append(names, c.Name)
	}
	// id is the primary key (autoincrement); user_id is protected against
	// mass assignment exactly as handleCreate treats it.
	want := []string{"sku", "qty"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Fatalf("importableColumns = %v, want %v", names, want)
	}
}

func TestGetTableColumnsMarksAllCompositePrimaryKeys(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	mustExec(t, app.DB, `CREATE TABLE composite_keys (left_key TEXT, right_key INTEGER, value TEXT, PRIMARY KEY (left_key, right_key))`)
	cols, err := GetTableColumns(app.DB, "composite_keys")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, col := range cols {
		got[col.Name] = col.PK
	}
	if !got["left_key"] || !got["right_key"] || got["value"] {
		t.Fatalf("composite primary-key metadata = %#v, want left_key and right_key only", got)
	}
}

// TestValidateImportColumnsNormalizesLikeCSVHeaderParsing pins the
// header-normalization fix: a caller posting `columns` directly (any
// third-party client not going through `benmore import`'s own
// csvHeaderColumns, which already normalizes locally) with a leading BOM
// or surrounding whitespace on a name must be accepted exactly as if the
// file's own header had that same BOM/whitespace - newCSVSource
// (import_parse.go) already tolerates it at load time, so rejecting it
// here would only reject a file the loader itself would go on to accept.
func TestValidateImportColumnsNormalizesLikeCSVHeaderParsing(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	// A BOM on the first name and surrounding whitespace on the second -
	// the two things normalizeImportHeaderName strips.
	if err := validateImportColumns(app.DB, "products", app, []string{"\uFEFFsku", " qty "}); err != nil {
		t.Fatalf("validateImportColumns rejected BOM/whitespace-decorated but otherwise valid names: %v", err)
	}

	// An actually-unknown column must still be rejected post-normalization.
	if err := validateImportColumns(app.DB, "products", app, []string{" bogus "}); err == nil {
		t.Fatal("validateImportColumns must still reject a genuinely unknown column after normalization")
	}
}

func TestRunImportLoadsCSV(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	content := "sku,qty\nA,1\nB,2\nC,3\n"
	sum := stageString(t, app, "run0001a", content)
	sess := &importSession{
		ID: "run0001a", TableName: "products", Format: "csv",
		BytesTotal: int64(len(content)), SHA256: sum,
	}
	insertSession(t, app, sess)

	if err := runImport(app, sess); err != nil {
		t.Fatalf("runImport: %v", err)
	}

	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 3 {
		t.Fatalf("loaded %d rows, want 3", n)
	}
	var sku string
	var qty int
	app.DB.QueryRow("SELECT sku, qty FROM products WHERE sku='B'").Scan(&sku, &qty)
	if qty != 2 {
		t.Fatalf("B qty = %d, want 2", qty)
	}

	got, _ := loadImportSession(app.DB, "run0001a")
	if got.State != "completed" {
		t.Fatalf("state = %q, want completed", got.State)
	}
	if got.RowsLoaded != 3 {
		t.Fatalf("rows_loaded = %d, want 3", got.RowsLoaded)
	}
}

func TestRunImportNDJSONPreservesLargeInteger(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	const value = "9007199254740993"
	content := `{"sku":"A","qty":` + value + "}\n"
	sum := stageString(t, app, "runndjson53", content)
	sess := &importSession{
		ID: "runndjson53", TableName: "products", Format: "ndjson",
		BytesTotal: int64(len(content)), SHA256: sum,
	}
	insertSession(t, app, sess)
	if err := runImport(app, sess); err != nil {
		t.Fatalf("runImport: %v", err)
	}

	var got string
	if err := app.DB.QueryRow(`SELECT CAST(qty AS TEXT) FROM products WHERE sku = 'A'`).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != value {
		t.Fatalf("stored NDJSON integer = %q, want %q", got, value)
	}
}

func TestBoundedReaderAllowsExactLimitAndRejectsExtraByte(t *testing.T) {
	got, err := io.ReadAll(&boundedReader{r: strings.NewReader("abc"), limit: 3})
	if err != nil || string(got) != "abc" {
		t.Fatalf("exact-limit stream = %q, %v; want abc and no error", got, err)
	}

	got, err = io.ReadAll(&boundedReader{r: strings.NewReader("abcd"), limit: 3})
	if string(got) != "abc" || err == nil || !strings.Contains(err.Error(), "exceeds 3 bytes") {
		t.Fatalf("one-byte-over-limit stream = %q, %v; want abc and limit error", got, err)
	}
}

func TestRunImportGzipAllowsExactDecompressedBound(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	content := "sku,qty\n" + strings.Repeat("A,1\n", 1000)
	compressed, sum := stageGzip(t, app, "rungzexacta", content)
	sess := &importSession{
		ID: "rungzexacta", TableName: "products", Format: "csv", Gzip: true,
		BytesTotal: compressed, UncompressedBytes: int64(len(content)), SHA256: sum,
	}
	if gzipExpansionBound(sess) != int64(len(content)) {
		t.Fatalf("fixture does not reach the declared exact bound: bound=%d content=%d", gzipExpansionBound(sess), len(content))
	}
	insertSession(t, app, sess)
	if err := runImport(app, sess); err != nil {
		t.Fatalf("Mode A exact-bound gzip import: %v", err)
	}

	var rows int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM products`).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1000 {
		t.Fatalf("Mode A exact-bound gzip import loaded %d rows, want 1000", rows)
	}
}

// TestRunImportAuditEntryCarriesSubject is the I3 fix: an owner-token
// import always has CreatedBy == 0 (the sentinel - no per-app
// _benmore_users row to point at), so without CreatedBySubject the audit
// row's user_email column dropped to empty string even though the caller
// (an admin session, or an owner token) had a real identity at request
// time. CreatedBySubject is what survives into the async runner (import
// sessions are looked up fresh from the DB row, not carried from the HTTP
// request's ephemeral Session).
func TestRunImportAuditEntryCarriesSubject(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	EnsureAuditLogTable(app.DB)

	content := "sku,qty\nA,1\n"
	sum := stageString(t, app, "run0001b", content)
	sess := &importSession{
		ID: "run0001b", TableName: "products", Format: "csv",
		BytesTotal: int64(len(content)), SHA256: sum,
		CreatedBySubject: "owner@example.com",
	}
	insertSession(t, app, sess)

	if err := runImport(app, sess); err != nil {
		t.Fatalf("runImport: %v", err)
	}

	var email string
	err := app.DB.QueryRow(
		`SELECT user_email FROM _benmore_audit_log WHERE action='import' ORDER BY id DESC LIMIT 1`,
	).Scan(&email)
	if err != nil {
		t.Fatal(err)
	}
	if email != "owner@example.com" {
		t.Fatalf("audit row user_email = %q, want %q", email, "owner@example.com")
	}
}

func TestRunImportIsAtomicOnBadRow(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE strict (id INTEGER PRIMARY KEY, n INTEGER NOT NULL)")

	// The failing row is LAST, so a non-atomic implementation would have
	// already written the first two. All-or-nothing means zero survive.
	// The empty field is quoted ("") rather than a bare trailing blank
	// line: encoding/csv treats a genuinely blank line as ignorable and
	// skips it entirely (verified against stdlib), so a bare "\n\n" would
	// never reach Next() as a row at all and this test would pass for the
	// wrong reason - 2 good rows loaded, no NOT NULL violation ever hit.
	content := "n\n1\n2\n\"\"\n"
	sum := stageString(t, app, "run0002a", content)
	sess := &importSession{
		ID: "run0002a", TableName: "strict", Format: "csv",
		BytesTotal: int64(len(content)), SHA256: sum,
	}
	insertSession(t, app, sess)

	if err := runImport(app, sess); err == nil {
		t.Fatal("expected the NOT NULL violation to fail the import")
	}

	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM strict").Scan(&n)
	if n != 0 {
		t.Fatalf("after a failed atomic import %d rows survived, want 0", n)
	}
	got, _ := loadImportSession(app.DB, "run0002a")
	if got.State != "failed" {
		t.Fatalf("state = %q, want failed", got.State)
	}
	if got.Error == "" {
		t.Fatal("failed import must record why")
	}
}

func TestRunImportRollsBackWhenCompletionCannotBeRecorded(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	EnsureAuditLogTable(app.DB)

	content := "sku,qty\nA,1\n"
	sum := stageString(t, app, "runatomic1", content)
	sess := &importSession{
		ID: "runatomic1", TableName: "products", Format: "csv",
		BytesTotal: int64(len(content)), SHA256: sum,
	}
	insertSession(t, app, sess)
	mustExec(t, app.DB, `CREATE TRIGGER reject_import_completion BEFORE UPDATE OF state ON _benmore_imports
		WHEN NEW.state = 'completed' BEGIN SELECT RAISE(ABORT, 'completion blocked'); END`)

	if err := runImport(app, sess); err == nil {
		t.Fatal("completion-state failure must fail the import")
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

// TestRunImportPurgesStagingOnFailure is the review round 2 minor fix:
// before it, runImport's terminal defer only called purgeImportStaging on
// the SUCCESS branch (err == nil) - a failed load left its staged chunk
// file on disk forever, since a "failed" session is never resumed
// (handleImportCreate only matches 'staging' rows) and, after this same
// round's fix, handleImportCancel now correctly REFUSES to DELETE a
// terminal-state session (so the CLI's own best-effort cleanup can no
// longer reach it either). The purge has to happen here, as part of the
// same terminal transition that writes "failed".
func TestRunImportPurgesStagingOnFailure(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, "CREATE TABLE strict2 (id INTEGER PRIMARY KEY, n INTEGER NOT NULL)")

	content := "n\n1\n\"\"\n"
	sum := stageString(t, app, "run0003a", content)
	sess := &importSession{
		ID: "run0003a", TableName: "strict2", Format: "csv",
		BytesTotal: int64(len(content)), SHA256: sum,
	}
	insertSession(t, app, sess)

	dir := importStagingDir(app, "run0003a")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("precondition failed: staging dir must exist before the run: %v", err)
	}

	if err := runImport(app, sess); err == nil {
		t.Fatal("expected the NOT NULL violation to fail the import")
	}

	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("staging dir must be purged after a FAILED load too, got stat err = %v", err)
	}
}

func TestRunImportRejectsChecksumMismatch(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	content := "sku,qty\nA,1\n"
	stageString(t, app, "run0003a", content)
	sess := &importSession{
		ID: "run0003a", TableName: "products", Format: "csv",
		BytesTotal: int64(len(content)),
		SHA256:     "0000000000000000000000000000000000000000000000000000000000000000",
	}
	insertSession(t, app, sess)

	if err := runImport(app, sess); err == nil {
		t.Fatal("expected a checksum mismatch to fail the import")
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 0 {
		t.Fatalf("corrupt upload landed %d rows, want 0", n)
	}
}

func TestRunImportRejectsSizeMismatch(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	content := "sku,qty\nA,1\n"
	sum := stageString(t, app, "run0004a", content)
	sess := &importSession{
		ID: "run0004a", TableName: "products", Format: "csv",
		BytesTotal: int64(len(content)) + 999, // client claimed more than landed
		SHA256:     sum,
	}
	insertSession(t, app, sess)

	if err := runImport(app, sess); err == nil {
		t.Fatal("a short upload must not be loaded as if complete")
	}
}

func TestRunImportRejectsEmptyResultFromNonEmptyFile(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	// Header only, no data rows. A "successful" import of zero rows from a
	// non-empty file is exactly the silent failure the repo rule forbids.
	content := "sku,qty\n"
	sum := stageString(t, app, "run0005a", content)
	sess := &importSession{
		ID: "run0005a", TableName: "products", Format: "csv",
		BytesTotal: int64(len(content)), SHA256: sum,
	}
	insertSession(t, app, sess)

	if err := runImport(app, sess); err == nil {
		t.Fatal("a file with no data rows must be a hard error, not a silent success")
	}
}

func TestRunImportLoadsNDJSON(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	content := "{\"sku\":\"A\",\"qty\":1}\n{\"sku\":\"B\",\"qty\":2}\n"
	sum := stageString(t, app, "run0006a", content)
	sess := &importSession{
		ID: "run0006a", TableName: "products", Format: "ndjson",
		BytesTotal: int64(len(content)), SHA256: sum,
	}
	insertSession(t, app, sess)

	if err := runImport(app, sess); err != nil {
		t.Fatalf("runImport: %v", err)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 2 {
		t.Fatalf("loaded %d rows, want 2", n)
	}
}

func TestRunImportIgnoresProtectedColumnInFile(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	// user_id is protected. A file naming it must be rejected at header
	// validation rather than silently honoured.
	content := "sku,user_id\nA,999\n"
	sum := stageString(t, app, "run0007a", content)
	sess := &importSession{
		ID: "run0007a", TableName: "products", Format: "csv",
		BytesTotal: int64(len(content)), SHA256: sum,
	}
	insertSession(t, app, sess)

	if err := runImport(app, sess); err == nil {
		t.Fatal("a file naming a protected column must be rejected")
	}
}

func TestRunImportHonoursDefaultForOmittedColumn(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE withdefault (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sku TEXT,
		status TEXT NOT NULL DEFAULT 'active'
	)`)

	// The file omits `status` entirely. The INSERT must omit it too, so
	// SQLite applies the DEFAULT - binding NULL here would violate NOT NULL
	// and, on a nullable column, would silently overwrite the default.
	content := "sku\nA\nB\n"
	sum := stageString(t, app, "run0009a", content)
	sess := &importSession{
		ID: "run0009a", TableName: "withdefault", Format: "csv",
		BytesTotal: int64(len(content)), SHA256: sum,
	}
	insertSession(t, app, sess)

	if err := runImport(app, sess); err != nil {
		t.Fatalf("runImport: %v", err)
	}
	var status string
	if err := app.DB.QueryRow("SELECT status FROM withdefault WHERE sku='A'").Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "active" {
		t.Fatalf("status = %q, want the column DEFAULT %q", status, "active")
	}
}

func TestRunImportScales(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping bulk load in -short mode")
	}
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	var b strings.Builder
	b.WriteString("sku,qty\n")
	const rows = 100000
	for i := 0; i < rows; i++ {
		fmt.Fprintf(&b, "SKU%d,%d\n", i, i)
	}
	content := b.String()
	sum := stageString(t, app, "run0008a", content)
	sess := &importSession{
		ID: "run0008a", TableName: "products", Format: "csv",
		BytesTotal: int64(len(content)), SHA256: sum,
	}
	insertSession(t, app, sess)

	if err := runImport(app, sess); err != nil {
		t.Fatalf("runImport: %v", err)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != rows {
		t.Fatalf("loaded %d rows, want %d", n, rows)
	}
}

func TestRunImportLoadsGzipCSV(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	content := "sku,qty\nA,1\nB,2\n"
	// bytes_total/sha256 both describe the COMPRESSED bytes - the only
	// stream a real client can measure, since it never sees its own
	// decompressed output.
	compLen, sum := stageGzip(t, app, "rungz001a", content)
	sess := &importSession{
		ID: "rungz001a", TableName: "products", Format: "csv", Gzip: true,
		BytesTotal: compLen, SHA256: sum,
	}
	insertSession(t, app, sess)

	if err := runImport(app, sess); err != nil {
		t.Fatalf("runImport: %v", err)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 2 {
		t.Fatalf("loaded %d rows, want 2", n)
	}
	got, _ := loadImportSession(app.DB, "rungz001a")
	if got.State != "completed" {
		t.Fatalf("state = %q, want completed", got.State)
	}
	if got.RowsLoaded != 2 {
		t.Fatalf("rows_loaded = %d, want 2", got.RowsLoaded)
	}
}

func TestRunImportGzipRejectsUncompressedDigest(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	content := "sku,qty\nA,1\n"
	compLen, _ := stageGzip(t, app, "rungz002a", content)
	// The declared digest is of the UNCOMPRESSED content - the mistake a
	// naive implementation (hash after the gzip unwrap) would demand from
	// a client that only ever has the compressed bytes to hash. Pinning
	// this shut is the other half of the bytes_total/sha256-describe-the-
	// staged-bytes contract: it must fail in this direction too, not just
	// succeed when given the (correct) compressed digest.
	uncompressedSum := sha256.Sum256([]byte(content))
	sess := &importSession{
		ID: "rungz002a", TableName: "products", Format: "csv", Gzip: true,
		BytesTotal: compLen,
		SHA256:     hex.EncodeToString(uncompressedSum[:]),
	}
	insertSession(t, app, sess)

	if err := runImport(app, sess); err == nil {
		t.Fatal("a session whose SHA256 is the uncompressed digest must fail - bytes_total/sha256 both describe the staged (compressed) bytes")
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 0 {
		t.Fatalf("wrong-digest gzip import landed %d rows, want 0", n)
	}
}

// TestRunImportAbortsOnDecompressionBomb is the runtime-guard fix
// (originally C1, re-pinned post HIGH-1): a genuine bomb - decompressed
// content whose ratio against the COMPRESSED bytes vastly exceeds
// defaultGzipExpansionRatio (20x) - must still abort atomically (zero
// rows), regardless of whether uncompressed_bytes was declared. The
// content here is a highly repetitive CSV (identical row repeated
// ~makeup 500k times) specifically so its real compression ratio lands
// far past the 20x backstop - unlike the old fixture (moderate ~4-6x
// ratio, small declared hint), which HIGH-1 exists precisely to STOP
// treating as a bomb (see
// TestRunImportGzipHintSmallerThanCompressedDoesNotLowerCeiling below).
func TestRunImportAbortsOnDecompressionBomb(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	var b strings.Builder
	b.WriteString("sku,qty\n")
	for i := 0; i < 500000; i++ {
		b.WriteString("A,1\n")
	}
	content := b.String() // ~2MB of maximally-repetitive text: real ratio in the hundreds-to-thousands, far past defaultGzipExpansionRatio

	compLen, sum := stageGzip(t, app, "rungzbomb1", content)
	sess := &importSession{
		ID: "rungzbomb1", TableName: "products", Format: "csv", Gzip: true,
		BytesTotal: compLen, SHA256: sum, // UncompressedBytes left undeclared (0)
	}
	insertSession(t, app, sess)

	if ratioBound := compLen * defaultGzipExpansionRatio; int64(len(content)) <= ratioBound {
		t.Fatalf("test fixture is not a genuine bomb: decompressed %d bytes must exceed compressed*ratio (%d)", len(content), ratioBound)
	}

	if err := runImport(app, sess); err == nil {
		t.Fatal("expected the decompression-bomb guard to abort a load whose real ratio exceeds the compressed-bytes-based backstop")
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 0 {
		t.Fatalf("aborted decompression-bomb import still landed %d rows, want 0", n)
	}
	got, _ := loadImportSession(app.DB, "rungzbomb1")
	if got.State != "failed" {
		t.Fatalf("state = %q, want failed", got.State)
	}
}

// TestRunImportGzipHintSmallerThanCompressedDoesNotLowerCeiling is the
// HIGH-1 fix: a declared/hinted uncompressed_bytes smaller than the
// compressed upload is ALWAYS a lie (you cannot gzip-compress N bytes down
// to more than N bytes), so it must never lower the runtime ceiling below
// compressedBytes * defaultGzipExpansionRatio. This is exactly the shape a
// wrapped (>4 GiB, ISIZE mod 2^32) or last-member-only (multi-member
// stream) hint produces - see gzipUncompressedSizeHint's doc comment. The
// content here is ordinary (moderate ~4-8x ratio, nowhere near a genuine
// bomb); pre-HIGH-1 this same fixture with the same absurdly-small hint
// (64) was the OLD TestRunImportAbortsOnDecompressionBomb, asserting
// abort - that assertion was itself the bug this test now proves fixed.
func TestRunImportGzipHintSmallerThanCompressedDoesNotLowerCeiling(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	var b strings.Builder
	b.WriteString("sku,qty\n")
	for i := 0; i < 2000; i++ {
		fmt.Fprintf(&b, "SKU%d,%d\n", i, i)
	}
	content := b.String()

	compLen, sum := stageGzip(t, app, "rungzhint1", content)
	if int64(64) >= compLen {
		t.Fatalf("test fixture invalid: the hint (64) must be smaller than the compressed size (%d) to exercise this guard", compLen)
	}
	sess := &importSession{
		ID: "rungzhint1", TableName: "products", Format: "csv", Gzip: true,
		BytesTotal: compLen, SHA256: sum,
		UncompressedBytes: 64, // smaller than compLen itself - always a lie
	}
	insertSession(t, app, sess)

	if err := runImport(app, sess); err != nil {
		t.Fatalf("runImport with a too-small hint on ordinary content must succeed (the ratio floor must dominate): %v", err)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 2000 {
		t.Fatalf("loaded %d rows, want 2000", n)
	}
}

// TestRunImportMultiMemberGzipLoadsDespiteLastMemberOnlyHint is the other
// HIGH-1 half: gzipUncompressedSizeHint reads only the LAST 4 bytes of the
// file - the LAST member's ISIZE in a multi-member stream (RFC 1952,
// produced by e.g. `cat a.gz b.gz`) - while gzip.Reader's default
// Multistream(true) transparently decodes every member as one continuous
// logical stream. So a real multi-member upload whose true total vastly
// exceeds what the (structurally partial) hint claims must still load in
// full, not abort as a false-positive bomb.
func TestRunImportMultiMemberGzipLoadsDespiteLastMemberOnlyHint(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	const rows = 3000
	const member2Rows = 500 // last member is deliberately much smaller than the total
	lines := make([]string, rows)
	for i := 0; i < rows; i++ {
		lines[i] = fmt.Sprintf("SKU%d,%d\n", i, i)
	}
	part1 := "sku,qty\n" + strings.Join(lines[:rows-member2Rows], "")
	part2 := strings.Join(lines[rows-member2Rows:], "")
	full := part1 + part2

	gzMember := func(s string) []byte {
		var buf bytes.Buffer
		gw := gzip.NewWriter(&buf)
		if _, err := gw.Write([]byte(s)); err != nil {
			t.Fatal(err)
		}
		if err := gw.Close(); err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	// Two independently-gzipped MEMBERS, concatenated raw - the RFC 1952
	// shape of `cat a.gz b.gz`, not a single gzip.Writer call.
	combined := append(gzMember(part1), gzMember(part2)...)

	if _, err := writeImportChunk(app, "rungzmulti1", 0, bytes.NewReader(combined)); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(combined)

	// The hint a buggy client computes from ISIZE alone: ONLY member 2's
	// uncompressed length, far smaller than the true total (len(full)).
	lastMemberHint := int64(len(part2))
	if lastMemberHint >= int64(len(full)) {
		t.Fatalf("test fixture invalid: last-member hint (%d) must be smaller than the true total (%d)", lastMemberHint, len(full))
	}

	sess := &importSession{
		ID: "rungzmulti1", TableName: "products", Format: "csv", Gzip: true,
		BytesTotal: int64(len(combined)), SHA256: hex.EncodeToString(sum[:]),
		UncompressedBytes: lastMemberHint,
	}
	insertSession(t, app, sess)

	if err := runImport(app, sess); err != nil {
		t.Fatalf("runImport on a multi-member gzip with a last-member-only hint: %v", err)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != rows {
		t.Fatalf("loaded %d rows, want %d (multi-member gzip must decode BOTH members, not just the first)", n, rows)
	}
}

// TestRunImportGzipFallbackRatioAllowsUndeclaredNormalContent proves the
// undeclared-uncompressed-size fallback (defaultGzipExpansionRatio) is
// generous enough not to false-positive on an ordinary, non-bomb gzip
// upload - the guard exists to catch genuine bombs, not to require every
// caller to declare uncompressed_bytes.
func TestRunImportGzipFallbackRatioAllowsUndeclaredNormalContent(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()

	content := "sku,qty\nA,1\nB,2\n"
	compLen, sum := stageGzip(t, app, "rungzok1", content)
	sess := &importSession{
		ID: "rungzok1", TableName: "products", Format: "csv", Gzip: true,
		BytesTotal: compLen, SHA256: sum, // UncompressedBytes left at 0 (undeclared)
	}
	insertSession(t, app, sess)

	if err := runImport(app, sess); err != nil {
		t.Fatalf("runImport with undeclared uncompressed_bytes on ordinary content: %v", err)
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM products").Scan(&n)
	if n != 2 {
		t.Fatalf("loaded %d rows, want 2", n)
	}
}

func TestStartImportGuardIsPerApp(t *testing.T) {
	appA, cleanupA := newImportTestApp(t)
	defer cleanupA()
	appB, cleanupB := newImportTestApp(t)
	defer cleanupB()

	content := "sku,qty\nA,1\n"

	sumA := stageString(t, appA, "runconc01", content)
	sessA := &importSession{
		ID: "runconc01", TableName: "products", Format: "csv",
		BytesTotal: int64(len(content)), SHA256: sumA,
	}
	insertSession(t, appA, sessA)

	// Hold appA's in-flight flag busy directly, rather than racing a real
	// background load to catch it mid-flight (a real tiny CSV finishes
	// too fast to observe reliably, and a sleep-based race is exactly the
	// kind of flaky timing guess to avoid). This is a load "we control":
	// the flag state is deterministic before either startImport call.
	flagA := importFlagFor(appA)
	if !flagA.CompareAndSwap(false, true) {
		t.Fatal("expected to acquire appA's flag from a clean state")
	}
	defer flagA.Store(false)

	if err := startImport(appA, sessA); err == nil {
		t.Fatal("a second startImport for the SAME app must be refused while one is in flight")
	}
	if !importRunning(appA) {
		t.Fatal("importRunning(appA) should report true while appA's flag is held")
	}

	// A different app's guard must be independent: appB's startImport must
	// NOT be refused just because appA is (deterministically) in flight.
	sumB := stageString(t, appB, "runconc02", content)
	sessB := &importSession{
		ID: "runconc02", TableName: "products", Format: "csv",
		BytesTotal: int64(len(content)), SHA256: sumB,
	}
	insertSession(t, appB, sessB)

	if err := startImport(appB, sessB); err != nil {
		t.Fatalf("startImport for a different app must not be blocked by appA's in-flight import: %v", err)
	}

	// appB's load is real and asynchronous (safeGo) - wait for it to clear
	// its own flag before this test's cleanup closes appB's DB out from
	// under that goroutine. The content is a single row, so this resolves
	// almost immediately; the deadline only bounds a genuine hang.
	deadline := time.Now().Add(5 * time.Second)
	for importRunning(appB) {
		if time.Now().After(deadline) {
			t.Fatal("appB's import did not finish before the test deadline")
		}
		time.Sleep(time.Millisecond)
	}

	got, err := loadImportSession(appB.DB, "runconc02")
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "completed" {
		t.Fatalf("appB state = %q, want completed", got.State)
	}
}

func TestStartImportCapturesStopAtLaunch(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	app.Stop = make(chan struct{})
	content := "sku,qty\n" + strings.Repeat("A,1\n", 10000)
	sum := stageString(t, app, "stopcap01", content)
	sess := &importSession{ID: "stopcap01", TableName: "products", Format: "csv", BytesTotal: int64(len(content)), SHA256: sum}
	insertSession(t, app, sess)

	if err := startImport(app, sess); err != nil {
		t.Fatal(err)
	}
	newStop := make(chan struct{})
	app.Stop = newStop
	close(newStop)

	deadline := time.Now().Add(5 * time.Second)
	for importRunning(app) {
		if time.Now().After(deadline) {
			t.Fatal("import did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	got, err := loadImportSession(app.DB, sess.ID)
	if err != nil {
		t.Fatal(err)
	}
	if got.State != "completed" || got.RowsLoaded != 10000 {
		t.Fatalf("launch-time stop was not retained: state=%q rows=%d", got.State, got.RowsLoaded)
	}
}

// TestRunImportAtTargetScale loads the real catalogue-migration shape this
// feature was built for: 3,288,666 rows into a narrow 3-column table, one
// transaction, one prepared statement. It is opt-in (BENMORE_BIG_IMPORT_FIXTURE
// must name an on-disk CSV fixture of that size) so CI never attempts a
// multi-minute, approximately 50.5 MB load. Generate the fixture with a single streaming
// awk command (inlined here, not pointed at a doc path - a prior version
// cited docs/superpowers/sdd/2026-08-10-bulk-import/task-8-report.md, which
// doesn't exist in a clone since .superpowers/sdd/ is gitignored, making the
// command this test's own throughput claim rests on unreachable):
//
//	awk 'BEGIN{
//	  print "product_id,ingredient_id,amount"
//	  for (i = 0; i < 3288666; i++) print (i%118296)","(i%18384)","(i%100)
//	}' > /tmp/big.csv
//
// then run:
//
//	BENMORE_BIG_IMPORT_FIXTURE=/tmp/big.csv go test -run TestRunImportAtTargetScale -timeout 30m -v .
//
// This test deliberately does NOT read the fixture into memory (the brief's
// first draft did, via os.ReadFile + stageString): reading the whole fixture would
// double the process's resident memory for no reason the runner itself ever
// pays - see stageFileStreaming above, which streams the fixture straight
// into the same 32 MiB staging-chunk layout the real HTTP upload path uses.
func TestRunImportAtTargetScale(t *testing.T) {
	path := os.Getenv("BENMORE_BIG_IMPORT_FIXTURE")
	if path == "" {
		t.Skip("set BENMORE_BIG_IMPORT_FIXTURE=/path/to/big.csv to run the 3.3M-row load at target scale")
	}

	const wantRows = 3288666

	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureImportsTable(app)
	mustExec(t, app.DB, `CREATE TABLE catalog_product_ingredients (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		product_id INTEGER, ingredient_id INTEGER, amount INTEGER)`)

	bytesTotal, sum := stageFileStreaming(t, app, "bigload1", path)
	t.Logf("staged fixture: %d bytes (%.1f MB)", bytesTotal, float64(bytesTotal)/1e6)

	sess := &importSession{
		ID: "bigload1", TableName: "catalog_product_ingredients", Format: "csv",
		BytesTotal: bytesTotal, SHA256: sum,
	}
	insertSession(t, app, sess)

	// Sample HeapAlloc on a ticker for the duration of the load rather than
	// just before/after: the design's "constant memory regardless of file
	// size" claim is about the load itself, and a single before/after pair
	// can miss a mid-load spike (or, just as misleadingly, land right after
	// a GC pass and under-report). atomic.Uint64 because this goroutine and
	// the test goroutine both touch peakHeap.
	var peakHeap atomic.Uint64
	stopSample := make(chan struct{})
	sampleDone := make(chan struct{})
	go func() {
		defer close(sampleDone)
		var ms runtime.MemStats
		ticker := time.NewTicker(250 * time.Millisecond)
		defer ticker.Stop()
		for {
			runtime.ReadMemStats(&ms)
			for {
				old := peakHeap.Load()
				if ms.HeapAlloc <= old || peakHeap.CompareAndSwap(old, ms.HeapAlloc) {
					break
				}
			}
			select {
			case <-stopSample:
				return
			case <-ticker.C:
			}
		}
	}()

	start := time.Now()
	err := runImport(app, sess)
	elapsed := time.Since(start)
	close(stopSample)
	<-sampleDone

	if err != nil {
		t.Fatalf("runImport: %v", err)
	}

	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM catalog_product_ingredients").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != wantRows {
		t.Fatalf("loaded %d rows, want %d", n, wantRows)
	}

	t.Logf("loaded %d rows in %s (%.0f rows/sec)", n, elapsed, float64(n)/elapsed.Seconds())
	t.Logf("peak heap during load: %.1f MB (fixture on disk: %.1f MB)",
		float64(peakHeap.Load())/1e6, float64(bytesTotal)/1e6)
}
