//go:build !cli

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestEnsureImportsTableIsIdempotent(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	EnsureImportsTable(app)
	EnsureImportsTable(app) // must not error on second call

	var n int
	err := app.DB.QueryRow(
		"SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='_benmore_imports'").Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("_benmore_imports table count = %d, want 1", n)
	}
}

func TestImportsTableIsNotAutoCRUDVisible(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureImportsTable(app)
	mustExec(t, app.DB, "CREATE TABLE products (id INTEGER PRIMARY KEY, sku TEXT)")

	names, err := GetTableNames(app.DB)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if n == "_benmore_imports" {
			t.Fatal("_benmore_imports must not appear in GetTableNames - it would get CRUD routes")
		}
	}
}

func TestWriteImportChunkIsIdempotent(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	// Writing the same chunk index twice must leave exactly one part file
	// with the latest content - a retried PUT after a network blip must
	// not duplicate data into the assembled stream.
	if _, err := writeImportChunk(app, "imp00001", 0, strings.NewReader("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := writeImportChunk(app, "imp00001", 0, strings.NewReader("hello")); err != nil {
		t.Fatal(err)
	}
	if _, err := writeImportChunk(app, "imp00001", 1, strings.NewReader(" world")); err != nil {
		t.Fatal(err)
	}

	got, err := receivedChunks(app, "imp00001")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0] != 0 || got[1] != 1 {
		t.Fatalf("receivedChunks = %v, want [0 1]", got)
	}

	rc, err := stagedReader(app, "imp00001", false)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	if string(data) != "hello world" {
		t.Fatalf("assembled = %q, want %q", data, "hello world")
	}
}

func TestStagedReaderAssemblesInNumericOrder(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	// Chunk 10 must follow chunk 9, not sort lexically between 1 and 2.
	// Uploads arrive out of order when a client retries a gap.
	for _, n := range []int{10, 2, 9, 1, 0} {
		if _, err := writeImportChunk(app, "imp00002", n, strings.NewReader(string(rune('a'+n)))); err != nil {
			t.Fatal(err)
		}
	}
	rc, err := stagedReader(app, "imp00002", false)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()
	data, _ := io.ReadAll(rc)
	if string(data) != "abcjk" { // indices 0,1,2,9,10 -> a,b,c,j,k
		t.Fatalf("assembled = %q, want %q", data, "abcjk")
	}
}

func TestStagedBytesSumsParts(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	writeImportChunk(app, "imp00003", 0, strings.NewReader("12345"))
	writeImportChunk(app, "imp00003", 1, strings.NewReader("678"))

	n, err := stagedBytes(app, "imp00003")
	if err != nil {
		t.Fatal(err)
	}
	if n != 8 {
		t.Fatalf("stagedBytes = %d, want 8", n)
	}
}

func TestImportPreflightRejectsOverCeiling(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	t.Setenv("BENMORE_MAX_IMPORT_BYTES", "1024")
	if err := importPreflight(app, 2048, false, 0); err == nil {
		t.Fatal("expected rejection above the configured ceiling")
	}
	if err := importPreflight(app, 512, false, 0); err != nil {
		t.Fatalf("512 bytes under a 1024 ceiling should pass, got: %v", err)
	}
}

func TestImportPreflightRejectsNonPositive(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if err := importPreflight(app, 0, false, 0); err == nil {
		t.Fatal("zero-byte import must be rejected")
	}
	if err := importPreflight(app, -1, false, 0); err == nil {
		t.Fatal("negative byte count must be rejected")
	}
}

// TestImportDiskNeededIsThreeXForNonGzip pins the C1 fix: the staged copy
// sits on disk for the ENTIRE load (purgeImportStaging only runs in the
// terminal defer, after the transaction), so a non-gzip import needs
// wantBytes (staged copy) + 2*wantBytes (data + WAL) = 3x, not the old 2x
// that left only 1x for data+WAL when the actual need is ~2x.
func TestImportDiskNeededIsThreeXForNonGzip(t *testing.T) {
	if got, want := importDiskNeeded(100, false, 0), int64(300); got != want {
		t.Fatalf("importDiskNeeded(100, false, 0) = %d, want %d (3x)", got, want)
	}
	if got, want := importDiskNeeded(1, false, 0), int64(3); got != want {
		t.Fatalf("importDiskNeeded(1, false, 0) = %d, want %d", got, want)
	}
}

// TestImportDiskNeededUsesDeclaredUncompressedForGzip pins the C1 fix's
// gzip half: sizing off the COMPRESSED wantBytes alone undercounts by the
// compression ratio - the data+WAL term must be sized off the declared
// uncompressed_bytes when the caller supplies one.
func TestImportDiskNeededUsesDeclaredUncompressedForGzip(t *testing.T) {
	got := importDiskNeeded(50, true, 1000)
	want := int64(50 + 2*1000) // staged (compressed) copy + 2x the DECOMPRESSED data
	if got != want {
		t.Fatalf("importDiskNeeded(50, true, 1000) = %d, want %d", got, want)
	}
}

// TestImportDiskNeededAndGzipExpansionBoundAgree pins the structural fix:
// importDataBytes (feeding importDiskNeeded/importCommitDiskNeeded, the
// DISK gate) and gzipExpansionBound (the RUNTIME bomb guard) must always
// derive "how many decompressed bytes might this produce" from the exact
// same figure - gzipDecompressedBound - across a spread of inputs: hint
// above the ratio floor, hint below it, hint absent (0), and hint at the
// create-time plausibility cap (maxPlausibleGzipRatio * wantBytes, the
// largest value importPreflight lets through).
//
// The case that matters most: bytes=1GB, uncompressed_bytes=1000. Before
// this fix, importDataBytes (and therefore the disk gate) sized off the
// raw 1000-byte hint - passing every preflight gate while the runtime
// guard was independently authorized to emit up to
// bytes*defaultGzipExpansionRatio = 20GB into an open transaction. The
// disk requirement must reflect that same 20GB ceiling, not the tiny hint.
func TestImportDiskNeededAndGzipExpansionBoundAgree(t *testing.T) {
	const oneGB = int64(1) << 30

	cases := []struct {
		name              string
		wantBytes         int64
		uncompressedBytes int64
	}{
		{"hint far below the ratio floor (the disagreement case)", oneGB, 1000},
		{"hint above the ratio floor", 1024, 1024 * 100},
		{"hint absent - pure ratio fallback", 1024, 0},
		{"hint exactly at the ratio floor", 50, 1000}, // 50 * defaultGzipExpansionRatio(20) == 1000
		{"hint at the create-time plausibility cap", 1024, 1024 * maxPlausibleGzipRatio},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			sess := &importSession{BytesTotal: c.wantBytes, UncompressedBytes: c.uncompressedBytes}
			runtimeCeiling := gzipExpansionBound(sess)
			diskDataBytes := importDataBytes(c.wantBytes, true /* gzipped */, c.uncompressedBytes)
			if diskDataBytes != runtimeCeiling {
				t.Fatalf("importDataBytes(%d, true, %d) = %d, but gzipExpansionBound = %d for the same inputs - the disk gate and the runtime guard disagree",
					c.wantBytes, c.uncompressedBytes, diskDataBytes, runtimeCeiling)
			}
		})
	}

	// Concretely: the disagreement case's disk requirement must be sized
	// off the 20GB runtime ceiling (bytes*defaultGzipExpansionRatio), not
	// the 1000-byte hint - the whole point of the fix.
	uncompressedHint := int64(1000)
	got := importDiskNeeded(oneGB, true, uncompressedHint)
	wantFloor := oneGB * defaultGzipExpansionRatio // 20 GB, the runtime guard's actual ceiling
	if got < 2*wantFloor {
		t.Fatalf("importDiskNeeded(%d, true, %d) = %d, must reflect ~2x the %d byte runtime ceiling, not the tiny declared hint",
			oneGB, uncompressedHint, got, wantFloor)
	}
}

// TestImportDiskNeededFallsBackToRatioWhenUncompressedUnknown pins the
// undeclared-gzip fallback: a generous fixed ratio of the compressed size,
// not the compressed size itself (which is what let a 50 MB .csv.gz
// expanding to 5 GB pass a check that measured 100 MB pre-fix).
func TestImportDiskNeededFallsBackToRatioWhenUncompressedUnknown(t *testing.T) {
	got := importDiskNeeded(50, true, 0)
	want := int64(50 + 2*50*defaultGzipExpansionRatio)
	if got != want {
		t.Fatalf("importDiskNeeded(50, true, 0) = %d, want %d", got, want)
	}
	// Sanity: the fallback must be strictly larger than the naive (wrong)
	// 3x-of-compressed-bytes a non-gzip-aware preflight would compute.
	if got <= importDiskNeeded(50, false, 0) {
		t.Fatalf("gzip fallback (%d) must exceed the non-gzip 3x figure (%d)", got, importDiskNeeded(50, false, 0))
	}
}

// TestImportDiskNeededOverflowSaturates is the MEDIUM-2 fix: a naive
// `wantBytes + 2*dataBytes` wraps NEGATIVE for an attacker/bug-sized
// uncompressedBytes near 1<<62 (importDiskNeeded(1024, true, 1<<62) used to
// return -9223372036854774784), which then makes `free < need` FALSE on
// every real machine - the disk gate silently passes instead of rejecting
// an obviously-impossible claim. The fixed arithmetic must saturate to a
// large POSITIVE value instead of wrapping.
func TestImportDiskNeededOverflowSaturates(t *testing.T) {
	got := importDiskNeeded(1024, true, int64(1)<<62)
	if got < 0 {
		t.Fatalf("importDiskNeeded(1024, true, 1<<62) = %d, must not be negative (overflow wrap)", got)
	}
	if got < 1024 {
		t.Fatalf("importDiskNeeded(1024, true, 1<<62) = %d, must saturate to a LARGE positive value, not collapse to something below wantBytes", got)
	}
}

// TestImportPreflightRejectsNegativeUncompressedBytes is the MEDIUM-2
// range check: handleImportCreate never range-checked req.UncompressedBytes
// before this fix, so a negative claim reached importDiskNeeded's
// arithmetic unfiltered.
func TestImportPreflightRejectsNegativeUncompressedBytes(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	if err := importPreflight(app, 1024, true, -1); err == nil {
		t.Fatal("a negative uncompressed_bytes must be rejected at create")
	}
}

// TestImportPreflightRejectsImplausibleUncompressedBytes is the MEDIUM-2
// plausibility check: an uncompressed_bytes claim wildly out of proportion
// to the declared (compressed) upload size must be rejected at create,
// before it ever reaches importDiskNeeded/gzipExpansionBound.
func TestImportPreflightRejectsImplausibleUncompressedBytes(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	t.Setenv("BENMORE_MAX_IMPORT_BYTES", "9223372036854775807")
	if err := importPreflight(app, 1024, true, int64(1)<<62); err == nil {
		t.Fatal("an implausible uncompressed_bytes claim (a huge multiple of the declared bytes) must be rejected at create")
	}
	// A plausible claim (well inside maxPlausibleGzipRatio) must still pass
	// this specific gate (the disk-arithmetic gate may still apply
	// separately - that's TestImportPreflightRejectsWhenDiskArithmeticExceedsFree).
	if err := importPreflight(app, 1024, true, 1024*100); err != nil {
		t.Fatalf("a 100x-of-compressed uncompressed_bytes claim should not be rejected as implausible: %v", err)
	}
}

// TestImportPreflightRejectsWhenDiskArithmeticExceedsFree proves the
// disk-gate rejection is reachable through importPreflight, not just in the
// pure importDiskNeeded arithmetic above. A synthetic free-disk reading keeps
// the projection small enough to clear the platform plan gate first.
func TestImportPreflightRejectsWhenDiskArithmeticExceedsFree(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	origFreeDisk := freeDiskBytes
	freeDiskBytes = func(string) (int64, error) { return 1, nil }
	defer func() { freeDiskBytes = origFreeDisk }()

	wantBytes := int64(1024)
	uncompressedBytes := wantBytes * 100
	err := importPreflight(app, wantBytes, true, uncompressedBytes)
	if err == nil {
		t.Fatal("expected a disk-arithmetic rejection for an import whose data footprint vastly exceeds any real free disk")
	}
	if !strings.Contains(err.Error(), "insufficient disk") {
		t.Fatalf("expected a disk-gate error (\"insufficient disk: ...\"), got a different rejection: %v", err)
	}
}

// TestImportCommitDiskNeededDoesNotDoubleCountStagedCopy is the MEDIUM-3
// fix, pinned as pure arithmetic: at commit time the staged copy is
// ALREADY on disk (already reflected in the free-disk measurement), so
// the outstanding need is 2x the data footprint only - NOT
// stagedBytes + 2x data (that's the CREATE-time figure, importDiskNeeded,
// which correctly includes it because free disk at create predates
// staging).
func TestImportCommitDiskNeededDoesNotDoubleCountStagedCopy(t *testing.T) {
	if got, want := importCommitDiskNeeded(100, false, 0), int64(200); got != want {
		t.Fatalf("importCommitDiskNeeded(100, false, 0) = %d, want %d (2x data only, no staged-copy term)", got, want)
	}
	// Cross-check against the (correct, unchanged) create-time figure: the
	// commit-time need must be EXACTLY stagedBytes less than the
	// create-time need for the same inputs - that's precisely the staged
	// copy this fix stops double-counting.
	staged := int64(4096)
	create := importDiskNeeded(staged, true, 0)
	commit := importCommitDiskNeeded(staged, true, 0)
	if want := create - staged; commit != want {
		t.Fatalf("importCommitDiskNeeded(%d, true, 0) = %d, want %d (importDiskNeeded's figure minus the staged-copy term)", staged, commit, want)
	}
}

// TestImportCommitDoesNotRejectWhenDiskUnchangedFromCreate is the MEDIUM-3
// fix at the HTTP layer: an import that passed create's disk gate must not
// be rejected at commit's disk gate when free disk hasn't actually
// changed. freeDiskBytes (a package-level var, overridable in tests) is
// swapped for a synthetic value in the exact band the bug lived in: free
// disk right after staging is F0 - bytesTotal under the real syscall's
// semantics, which clears the CORRECT 2x-data-only commit requirement but
// would have failed the old (buggy) staged+2x-data commit requirement -
// pre-fix this sequence 413'd at commit despite create having already
// accepted the exact same import.
func TestImportCommitDoesNotRejectWhenDiskUnchangedFromCreate(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mux := http.NewServeMux()
	RegisterImportRoutes(mux, app)
	sessCookie := seedAdminSession(t, app)

	content := "sku,qty\nA,1\n"
	bytesTotal := int64(len(content))
	// F0 at exactly 3x bytesTotal (create's minimum: bytes + 2*data) - the
	// smallest free-disk figure create still accepts, so "nothing about the
	// disk changed since create" is the literal scenario under test.
	free := bytesTotal*3 + 1024 // small margin so integer rounding can't flake this
	origFreeDisk := freeDiskBytes
	freeDiskBytes = func(string) (int64, error) { return free, nil }
	defer func() { freeDiskBytes = origFreeDisk }()

	sum := sha256.Sum256([]byte(content))
	hexSum := hex.EncodeToString(sum[:])
	createBody := `{"table":"products","format":"csv","bytes":` + strconv.FormatInt(bytesTotal, 10) + `,"sha256":"` + hexSum + `"}`
	req := authedRequest("POST", "/api/_import", createBody, sessCookie)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("create status = %d, want 200: %s", rec.Code, rec.Body.String())
	}
	var created struct {
		ImportID string `json:"import_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil || created.ImportID == "" {
		t.Fatalf("create failed: %s", rec.Body.String())
	}

	req = authedRequest("PUT", "/api/_import/"+created.ImportID+"/chunk/0", content, sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("chunk status = %d, want 200: %s", rec.Code, rec.Body.String())
	}

	// Simulate "the staged copy landed and free disk dropped by exactly
	// bytesTotal, nothing else touched the disk" - free disk at commit
	// time is F0 - bytesTotal under the real syscall's semantics.
	freeDiskBytes = func(string) (int64, error) { return free - bytesTotal, nil }

	req = authedRequest("POST", "/api/_import/"+created.ImportID+"/commit", "", sessCookie)
	rec = httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	if rec.Code == http.StatusRequestEntityTooLarge {
		t.Fatalf("commit rejected for disk when nothing about the disk changed since create (double-count regression): %s", rec.Body.String())
	}
	if rec.Code != http.StatusAccepted {
		t.Fatalf("commit status = %d, want 202: %s", rec.Code, rec.Body.String())
	}

	// Drain the background load (startImport's goroutine) before this test
	// returns and its deferred cleanup closes app.DB out from under it -
	// same wait-for-terminal-state pattern as TestImportEndToEnd.
	for i := 0; i < 100; i++ {
		sess, err := loadImportSession(app.DB, created.ImportID)
		if err == nil && (sess.State == "completed" || sess.State == "failed") {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSaveAndLoadImportSession(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureImportsTable(app)

	_, err := app.DB.Exec(`INSERT INTO _benmore_imports
		(id, table_name, format, gzip, bytes_total, sha256, null_as, state, created_by)
		VALUES ('abc', 'products', 'csv', 0, 100, 'deadbeef', '', 'staging', 7)`)
	if err != nil {
		t.Fatal(err)
	}

	sess, err := loadImportSession(app.DB, "abc")
	if err != nil {
		t.Fatal(err)
	}
	if sess.TableName != "products" || sess.Format != "csv" || sess.BytesTotal != 100 {
		t.Fatalf("loaded session = %+v", sess)
	}
	if sess.CreatedBy != 7 {
		t.Fatalf("CreatedBy = %d, want 7", sess.CreatedBy)
	}

	if err := saveImportState(app.DB, "abc", "failed", 42, "boom"); err != nil {
		t.Fatal(err)
	}
	sess, _ = loadImportSession(app.DB, "abc")
	if sess.State != "failed" || sess.RowsLoaded != 42 || sess.Error != "boom" {
		t.Fatalf("after saveImportState: %+v", sess)
	}
}

func TestStagingDirIsUnderDotBenmore(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	// .benmore/ is gitignored (git_app.go:87), which is what keeps a
	// 270MB staging file out of the per-app git mirror and GitHub sync.
	dir := importStagingDir(app, "xyz")
	want := filepath.Join(app.Dir, ".benmore", "imports", "xyz")
	if dir != want {
		t.Fatalf("importStagingDir = %q, want %q", dir, want)
	}
}

func TestStagedReaderAssemblesLazilyWithSmallReads(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	// Force the reader through many 1-byte Reads spanning several parts,
	// rather than one big io.ReadAll gulp, to exercise the
	// close-current/open-next transition directly instead of only ever
	// observing it in aggregate.
	id := "imp00004"
	parts := []string{"aaa", "bb", "c", "dddd", "ee"}
	for n, s := range parts {
		if _, err := writeImportChunk(app, id, n, strings.NewReader(s)); err != nil {
			t.Fatal(err)
		}
	}
	rc, err := stagedReader(app, id, false)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	var got strings.Builder
	buf := make([]byte, 1)
	for {
		n, err := rc.Read(buf)
		if n > 0 {
			got.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	want := "aaabbcddddee"
	if got.String() != want {
		t.Fatalf("assembled = %q, want %q", got.String(), want)
	}
}

func TestStagedReaderCloseMidStreamIsSafeAndIdempotent(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	id := "imp00005"
	writeImportChunk(app, id, 0, strings.NewReader("hello"))
	writeImportChunk(app, id, 1, strings.NewReader("world"))

	rc, err := stagedReader(app, id, false)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 2)
	if _, err := rc.Read(buf); err != nil {
		t.Fatal(err)
	}
	// Close while part-0 is still open (only 2 of its 5 bytes were read).
	// Must release cleanly, and a second Close (e.g. a defer stacked on
	// top of an explicit early Close) must not error or double-close.
	if err := rc.Close(); err != nil {
		t.Fatalf("first Close: %v", err)
	}
	if err := rc.Close(); err != nil {
		t.Fatalf("second Close must be a no-op, got: %v", err)
	}
}

func TestStagedReaderMissingPartMidStreamErrors(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	id := "imp00006"
	writeImportChunk(app, id, 0, strings.NewReader("hello"))
	writeImportChunk(app, id, 1, strings.NewReader("world"))

	rc, err := stagedReader(app, id, false)
	if err != nil {
		t.Fatal(err)
	}
	defer rc.Close()

	// partIndices already ran (inside stagedReader); delete part-1 before
	// the lazy reader gets to it, simulating a purge/cancel racing an
	// in-flight read.
	if err := os.Remove(filepath.Join(importStagingDir(app, id), "part-1")); err != nil {
		t.Fatal(err)
	}

	data, err := io.ReadAll(rc)
	if err == nil {
		t.Fatalf("expected an error surfacing the missing chunk, got a clean read of %q", data)
	}
	// The stream must not silently truncate - part-0's data should have
	// come through before the error on part-1, not be swallowed by it.
	if string(data) != "hello" {
		t.Fatalf("data before the error = %q, want %q", data, "hello")
	}
}

func TestWriteImportChunkRejectsPathTraversalID(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	// The import id reaches the filesystem. A traversing id must never
	// escape the staging root.
	if _, err := writeImportChunk(app, "../../etc", 0, strings.NewReader("x")); err == nil {
		t.Fatal("traversing import id must be rejected")
	}
	if _, err := os.Stat(filepath.Join(app.Dir, "..", "..", "etc")); err == nil {
		t.Fatal("traversal actually wrote outside the app dir")
	}
}

// TestRecoverInterruptedImportsFailsRunningSessions is the I1 fix: a
// process restart mid-load (every platform deploy restarts
// benmore-app@*) used to leave a "running" row wedged permanently - its
// transaction died with the old process, but nothing ever told the
// bookkeeping row that. EnsureImportsTable is called once per app load
// (RegisterImportRoutes), so calling it a SECOND time here simulates
// exactly that restart.
func TestRecoverInterruptedImportsFailsRunningSessions(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureImportsTable(app)

	if _, err := writeImportChunk(app, "recover01", 0, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO _benmore_imports
		(id, table_name, format, gzip, bytes_total, sha256, null_as, state, created_by)
		VALUES ('recover01','products','csv',0,1,'deadbeef','','running',1)`); err != nil {
		t.Fatal(err)
	}

	EnsureImportsTable(app) // simulates the process restart

	sess, err := loadImportSession(app.DB, "recover01")
	if err != nil {
		t.Fatal(err)
	}
	if sess.State != "failed" {
		t.Fatalf("state after recovery = %q, want failed", sess.State)
	}
	if sess.Error == "" {
		t.Fatal("a recovered session must record why, not just change state silently")
	}
	if _, err := os.Stat(importStagingDir(app, "recover01")); !os.IsNotExist(err) {
		t.Fatalf("staging must be purged for a recovered session, stat err = %v", err)
	}
}

func TestRecoverInterruptedImportsLeavesLocalRunningImportAlone(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureImportsTable(app)

	if _, err := writeImportChunk(app, "recover05", 0, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO _benmore_imports
		(id, table_name, format, gzip, bytes_total, sha256, null_as, state, created_by)
		VALUES ('recover05','products','csv',0,1,'deadbeef','','running',1)`); err != nil {
		t.Fatal(err)
	}
	flag := importFlagFor(app)
	if !flag.CompareAndSwap(false, true) {
		t.Fatal("expected clean in-process import flag")
	}
	defer flag.Store(false)

	recoverInterruptedImports(app)
	sess, err := loadImportSession(app.DB, "recover05")
	if err != nil {
		t.Fatal(err)
	}
	if sess.State != "running" {
		t.Fatalf("local in-process import was recovered as %q", sess.State)
	}
	if _, err := os.Stat(importStagingDir(app, "recover05")); err != nil {
		t.Fatalf("local in-process staging must survive recovery: %v", err)
	}
}

// TestRecoverInterruptedImportsSweepsAbandonedStaging is the I1 sweep
// extension: a session that was created but never committed has NO other
// trigger that ever moves it - the CLI's resume match needs the ORIGINAL
// client still running - so it must age out after importStagingSweepAge.
// A session still within the window must be left alone.
func TestRecoverInterruptedImportsSweepsAbandonedStaging(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureImportsTable(app)

	if _, err := writeImportChunk(app, "recover02", 0, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO _benmore_imports
		(id, table_name, format, gzip, bytes_total, sha256, null_as, state, created_by, created_at)
		VALUES ('recover02','products','csv',0,1,'deadbeef','','staging',1, datetime('now','-25 hours'))`); err != nil {
		t.Fatal(err)
	}
	if _, err := writeImportChunk(app, "recover03", 0, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO _benmore_imports
		(id, table_name, format, gzip, bytes_total, sha256, null_as, state, created_by)
		VALUES ('recover03','products','csv',0,1,'deadbeef','','staging',1)`); err != nil {
		t.Fatal(err)
	}

	EnsureImportsTable(app) // simulates the process restart

	old, err := loadImportSession(app.DB, "recover02")
	if err != nil {
		t.Fatal(err)
	}
	if old.State != "failed" {
		t.Fatalf("25h-old staging session state = %q, want failed", old.State)
	}
	if _, err := os.Stat(importStagingDir(app, "recover02")); !os.IsNotExist(err) {
		t.Fatal("abandoned staging must be purged")
	}

	fresh, err := loadImportSession(app.DB, "recover03")
	if err != nil {
		t.Fatal(err)
	}
	if fresh.State != "staging" {
		t.Fatalf("a fresh staging session must survive the sweep, got state = %q", fresh.State)
	}
	if _, err := os.Stat(importStagingDir(app, "recover03")); err != nil {
		t.Fatal("a fresh staging session's staged chunk must survive the sweep")
	}
}

// TestRecoverInterruptedImportsDoesNotSweepUnderClusterMode is the
// MEDIUM-4 fix: cluster mode (BENMORE_CLUSTER=true) is a supported
// configuration where two processes share one data.db for the same app.
// A "running" row this process didn't start might be a load genuinely
// IN FLIGHT on a sibling instance right now - a sweep can't tell the two
// apart, so it must not run at all under cluster mode, even though the
// per-app.DB scoping already makes it safe against cross-TENANT damage.
func TestRecoverInterruptedImportsDoesNotSweepUnderClusterMode(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	EnsureImportsTable(app)

	if _, err := writeImportChunk(app, "recover04", 0, strings.NewReader("x")); err != nil {
		t.Fatal(err)
	}
	if _, err := app.DB.Exec(`INSERT INTO _benmore_imports
		(id, table_name, format, gzip, bytes_total, sha256, null_as, state, created_by)
		VALUES ('recover04','products','csv',0,1,'deadbeef','','running',1)`); err != nil {
		t.Fatal(err)
	}

	t.Setenv("BENMORE_CLUSTER", "true")
	EnsureImportsTable(app) // simulates a SIBLING instance starting up in cluster mode

	sess, err := loadImportSession(app.DB, "recover04")
	if err != nil {
		t.Fatal(err)
	}
	if sess.State != "running" {
		t.Fatalf("state after a cluster-mode EnsureImportsTable call = %q, want running (unswept - another instance may genuinely own this load)", sess.State)
	}
	if _, err := os.Stat(importStagingDir(app, "recover04")); err != nil {
		t.Fatal("staging must survive: a cluster-mode sweep must not purge a row it cannot prove is actually interrupted")
	}
}

// TestEnsureImportsTableMigratesTableMissingNewColumns is the MEDIUM-5
// fix: a data.db that already has _benmore_imports from BEFORE
// uncompressed_bytes/created_by_subject existed (an earlier build of this
// branch, or any future column addition following the same pattern) must
// not fail every loadImportSession/create INSERT with "no such column" -
// CREATE TABLE IF NOT EXISTS is a no-op once the table exists, so the
// columns must land via ALTER TABLE, unconditionally, on every
// EnsureImportsTable call.
func TestEnsureImportsTableMigratesTableMissingNewColumns(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	// The table as it existed before uncompressed_bytes/created_by_subject
	// were added - the exact shape a pre-migration data.db has on disk.
	mustExec(t, app.DB, `CREATE TABLE _benmore_imports (
		id TEXT PRIMARY KEY,
		table_name TEXT NOT NULL,
		format TEXT NOT NULL,
		gzip INTEGER NOT NULL DEFAULT 0,
		bytes_total INTEGER NOT NULL,
		sha256 TEXT NOT NULL,
		null_as TEXT NOT NULL DEFAULT '',
		state TEXT NOT NULL DEFAULT 'staging',
		rows_loaded INTEGER NOT NULL DEFAULT 0,
		error TEXT NOT NULL DEFAULT '',
		created_by INTEGER NOT NULL DEFAULT 0,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		started_at DATETIME,
		completed_at DATETIME
	)`)

	EnsureImportsTable(app) // must migrate in the two new columns, not error

	// loadImportSession selects both new columns by name - it must not fail
	// with "no such column" against a freshly-migrated pre-existing table.
	if _, err := app.DB.Exec(`INSERT INTO _benmore_imports
		(id, table_name, format, gzip, bytes_total, sha256, null_as, state, created_by)
		VALUES ('mig01','products','csv',0,1,'deadbeef','','staging',1)`); err != nil {
		t.Fatalf("insert into migrated table: %v", err)
	}
	sess, err := loadImportSession(app.DB, "mig01")
	if err != nil {
		t.Fatalf("loadImportSession against a migrated table: %v", err)
	}
	if sess.UncompressedBytes != 0 || sess.CreatedBySubject != "" {
		t.Fatalf("migrated columns should default to zero-value, got UncompressedBytes=%d CreatedBySubject=%q", sess.UncompressedBytes, sess.CreatedBySubject)
	}

	// The create-time INSERT (handleImportCreate's shape) must also work
	// against the migrated table - it writes both new columns explicitly.
	if _, err := app.DB.Exec(`INSERT INTO _benmore_imports
		(id, table_name, format, gzip, bytes_total, uncompressed_bytes, sha256,
		 null_as, state, created_by, created_by_subject)
		VALUES ('mig02','products','csv',0,1,500,'deadbeef','','staging',1,'a@b.test')`); err != nil {
		t.Fatalf("insert using the new columns against a migrated table: %v", err)
	}
}
