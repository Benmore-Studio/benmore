//go:build !cli

package main

// Bulk import - session record, on-disk staging, and preflight.
//
// Design: docs/superpowers/specs/2026-08-10-bulk-import-design.md
//
// Chunks are staged as individual part files under
// <appdir>/.benmore/imports/<id>/. That directory is gitignored
// (git_app.go:87), so a 270 MB staging file never reaches the per-app git
// mirror or GitHub sync. Assembly opens the parts one at a time in numeric
// order (lazyPartsReader) - nothing is ever concatenated on disk, nothing
// is held in memory, and descriptor use stays O(1) regardless of chunk
// count.

import (
	"compress/gzip"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

// maxImportChunkBytes bounds a single PUT. 32 MB sits well inside
// Cloudflare's ~100 MB request-body cap with margin for headers and any
// future edge that is stricter.
const maxImportChunkBytes = 32 << 20

// errImportChunkTooLarge is the sentinel writeImportChunk returns when a
// chunk exceeds maxImportChunkBytes. The HTTP layer (import_http.go)
// distinguishes this, via errors.Is, from every OTHER write failure
// (mkdir/create/copy/close/rename - disk full, permissions, etc): those are
// server-side faults that must not be reported to the client as a 413
// ("send a smaller chunk" is useless advice for a full disk) and must not
// leak the absolute staging path in a client-visible error message.
var errImportChunkTooLarge = errors.New("chunk exceeds maximum chunk size")

// defaultMaxImportBytes is the per-file ceiling when
// BENMORE_MAX_IMPORT_BYTES is unset. It is a denial-of-service backstop,
// not a capability limit - the real bounds are free disk and plan quota.
const defaultMaxImportBytes int64 = 50 << 30

// importIDRe constrains an import id to characters that are safe as a
// single path segment. The id reaches the filesystem, so this is the guard
// that makes traversal structurally impossible rather than filtered - the
// character class (no '.' or '/') is what does the work, not the length.
// Real ids are 32 hex characters (minted in the HTTP layer); the 8-char
// floor is a sanity bound, not load-bearing for the traversal guard.
var importIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{8,64}$`)

// importSession mirrors one _benmore_imports row.
type importSession struct {
	ID         string
	TableName  string
	Format     string // "csv" | "ndjson" | "sql"
	Gzip       bool
	BytesTotal int64
	// UncompressedBytes is the caller's declared decompressed size for a
	// gzip import - a CLIENT CLAIM, not a server-verified fact. 0 means
	// "not declared", which falls back to a generous ratio of BytesTotal
	// (defaultGzipExpansionRatio) both for the disk preflight and for the
	// runtime decompression-bomb guard (import_run.go / import_sql.go).
	UncompressedBytes int64
	SHA256            string
	NullAs            string
	State             string // staging | running | completed | failed | cancelled
	RowsLoaded        int64
	Error             string
	CreatedBy         int64
	// CreatedBySubject is the human-readable identity behind CreatedBy -
	// the admin session's real email, or an owner token's subject
	// (verifyImportOwnerToken, import_sql.go) when CreatedBy is the 0
	// sentinel an owner token always carries (it has no per-app
	// _benmore_users row to point at). Threaded into the audit log's
	// user_email column so an owner-token import - "the most powerful
	// write path in the feature" - is attributable to a real actor
	// instead of dropping to an empty string.
	CreatedBySubject string
	stop             <-chan struct{}
}

// EnsureImportsTable creates the import bookkeeping table and recovers
// from a process restart mid-load. The name is _benmore_-prefixed, so
// GetTableNames (db.go:508) filters it out and it never receives auto-CRUD
// routes.
func EnsureImportsTable(app *App) {
	db := app.DB
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_imports (
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
	// uncompressed_bytes and created_by_subject (MEDIUM-5): added after this
	// table's original CREATE TABLE IF NOT EXISTS shipped, following the
	// same ALTER-TABLE-ADD-COLUMN pattern as EnsureSessionsTable (auth_sessions.go),
	// EnsureRoleColumn (roles.go) and the analytics table (analytics.go).
	// Without this, any data.db that already has _benmore_imports from an
	// earlier build of this branch fails every loadImportSession and every
	// create INSERT with "no such column" - CREATE TABLE IF NOT EXISTS is a
	// no-op once the table exists, so adding a column to the literal only
	// ever helps a BRAND NEW database. db.Exec's error is intentionally
	// discarded (matching every sibling ALTER TABLE call in this codebase):
	// on a database that already has the column this errors "duplicate
	// column name", which is the expected, harmless outcome.
	db.Exec(`ALTER TABLE _benmore_imports ADD COLUMN uncompressed_bytes INTEGER NOT NULL DEFAULT 0`)
	db.Exec(`ALTER TABLE _benmore_imports ADD COLUMN created_by_subject TEXT NOT NULL DEFAULT ''`)
	recoverInterruptedImports(app)
}

// importStagingSweepAge is how long a session may sit in "staging" -
// created but never committed - before the startup sweep below treats it
// as abandoned. Nothing else ever transitions such a row: the CLI's
// resume match (handleImportCreate) needs the ORIGINAL client to still be
// running and re-POST the identical create request, so a crashed or
// forgotten upload otherwise leaves its staged bytes on disk, and the row
// itself, forever. 24h is generous next to importPollTimeout (2h, the
// CLI's own poll ceiling for a COMMITTED load) while still bounding the
// leak to a day.
const importStagingSweepAge = 24 * time.Hour

// recoverInterruptedImports runs once per app load - called from
// EnsureImportsTable, itself called from RegisterImportRoutes inside
// buildAppMux, which runs at process start for every app instance
// (`benmore serve`, `benmore host` LoadApp, and every `benmore-app@*`
// restart a platform deploy triggers - CLAUDE.md's background-worker
// rule exists because of exactly this class of restart).
//
// Two sweeps, both terminal-izing rows nothing else will ever move:
//
//  1. A "running" row: its transaction died with the old process (SQLite
//     has no way to resume an in-flight write across a restart, and WAL
//     recovery on next open rolls back anything not committed), so the
//     target table already has zero rows from it - marking the
//     bookkeeping row "failed" here just makes it match reality instead
//     of wedging permanently (commit 409s "already running", cancel
//     409s "running is refused", status polls a frozen row count
//     forever, with no client action able to clear any of it).
//  2. A "staging" row older than importStagingSweepAge: see that
//     constant's comment - an abandoned upload otherwise never leaves
//     staging.
//
// Both branches purge staging unconditionally; purgeImportStaging wraps
// os.RemoveAll, so purging an already-clean directory is a no-op.
//
// MEDIUM-4: gated on !IsClusterMode(). This function is scoped to app.DB,
// so it can never touch another TENANT's data - but cluster mode
// (BENMORE_CLUSTER=true, pubsub.go) is a supported configuration where TWO
// PROCESSES share the SAME data.db for the SAME app. A sweep cannot tell
// "interrupted by my own restart" apart from "running right now in another
// instance of this same process": a second instance starting up would
// otherwise sweep the FIRST instance's genuinely in-flight "running" import
// to "failed" and os.RemoveAll its staging out from under it - killing a
// live multi-minute load. A boot-id/PID stamp on the "running" row (so the
// sweep only reclaims rows IT started) would be strictly better, but that
// widens this fix well past a targeted patch (a new column, a stamp write
// on every startImport, a comparison here); the environmental gate is the
// contained fix and cluster deployments already accept that some
// process-restart bookkeeping is coarser than single-instance mode (see
// ratelimit.go's own cluster-mode carve-out).
//
// The consequence, stated plainly (this trade-off is invisible anywhere
// else - the api(at:"import") "resume" topic does not mention cluster mode
// at all): under BENMORE_CLUSTER=true, NEITHER sweep ever runs, for any
// row, ever. A wedged "running" row from a crashed process is not merely
// slower to clear than single-instance mode's "next restart" - it is
// PERMANENTLY unrecoverable by anything client-visible: commit keeps
// 409ing "already running", cancel keeps refusing a "running" row, and
// GET /api/_import/{id}/status polls a frozen row count forever, because
// no process restart is ever safe to treat as "my own crash" in a
// multi-process deployment. Same story for a "staging" row abandoned past
// importStagingSweepAge - it never ages out. The only recovery path is a
// manual operator intervention: `benmore sql <app> "UPDATE
// _benmore_imports SET state='failed' WHERE id='<id>'" --write` (and,
// separately, remove the row's staged bytes under
// .benmore/imports/<id>/ if disk needs reclaiming - the sweep's
// purgeImportStaging call is exactly what never runs here).
func recoverInterruptedImports(app *App) {
	if IsClusterMode() {
		return
	}
	flag := importFlagFor(app)
	if !flag.CompareAndSwap(false, true) {
		return
	}
	defer flag.Store(false)
	db := app.DB

	// selectAndFail collects the ids matching `where` BEFORE mutating
	// anything (so it never conflates a row this call is about to fail
	// with one a prior sweep already failed for a different reason), then
	// transitions each to "failed" and purges its staging. Selecting
	// first, rather than matching on the error text an UPDATE just wrote,
	// keeps the two sweeps independent of each other's error strings.
	selectAndFail := func(where, errMsg string, args ...any) {
		rows, err := db.Query(`SELECT id FROM _benmore_imports WHERE `+where, args...)
		if err != nil {
			return
		}
		var ids []string
		for rows.Next() {
			var id string
			if rows.Scan(&id) == nil {
				ids = append(ids, id)
			}
		}
		rows.Close()
		for _, id := range ids {
			res, err := db.Exec(`UPDATE _benmore_imports
				SET state='failed', rows_loaded=0, error=?, completed_at=datetime('now')
				WHERE id=? AND `+where, append([]any{errMsg, id}, args...)...)
			if err != nil {
				continue
			}
			if n, _ := res.RowsAffected(); n == 1 {
				purgeImportStaging(app, id)
			}
		}
	}

	// 1. Running -> failed. Its transaction died with the old process, so
	// the target table already has zero rows from it (see the doc comment
	// above) - this just makes the bookkeeping row match reality.
	selectAndFail("state='running'", "interrupted by a process restart")

	// 2. Staging older than importStagingSweepAge -> failed. Computed in
	// Go (not a SQL 'now', '-24 hours' literal) so the cutoff stays tied
	// to the one named constant rather than drifting from it.
	cutoff := time.Now().Add(-importStagingSweepAge).UTC().Format("2006-01-02 15:04:05")
	selectAndFail("state='staging' AND created_at < ?",
		fmt.Sprintf("staging abandoned - no commit within %s of creation", importStagingSweepAge),
		cutoff)
}

// importStagingDir returns the per-import staging directory.
func importStagingDir(app *App, id string) string {
	return filepath.Join(app.Dir, ".benmore", "imports", id)
}

// writeImportChunk stores chunk n, returning the bytes written. The write
// is temp-then-rename, which makes a retried PUT idempotent: a partial
// write from an interrupted request never becomes a visible part file.
func writeImportChunk(app *App, id string, n int, r io.Reader) (int64, error) {
	if !importIDRe.MatchString(id) {
		return 0, fmt.Errorf("invalid import id")
	}
	if n < 0 {
		return 0, fmt.Errorf("invalid chunk index %d", n)
	}
	dir := importStagingDir(app, id)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return 0, fmt.Errorf("create staging dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, ".part-*")
	if err != nil {
		return 0, fmt.Errorf("create temp chunk: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName) // no-op once the rename succeeds

	written, err := io.Copy(tmp, io.LimitReader(r, maxImportChunkBytes+1))
	if err != nil {
		tmp.Close()
		return 0, fmt.Errorf("write chunk: %w", err)
	}
	if written > maxImportChunkBytes {
		tmp.Close()
		return 0, fmt.Errorf("%w: got %d bytes, limit is %d", errImportChunkTooLarge, written, int64(maxImportChunkBytes))
	}
	if err := tmp.Close(); err != nil {
		return 0, fmt.Errorf("close chunk: %w", err)
	}
	if err := os.Rename(tmpName, filepath.Join(dir, fmt.Sprintf("part-%d", n))); err != nil {
		return 0, fmt.Errorf("commit chunk: %w", err)
	}
	return written, nil
}

// partIndices returns the chunk indices present on disk, ascending.
func partIndices(app *App, id string) ([]int, error) {
	if !importIDRe.MatchString(id) {
		return nil, fmt.Errorf("invalid import id")
	}
	entries, err := os.ReadDir(importStagingDir(app, id))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var idx []int
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), "part-") {
			continue
		}
		n, err := strconv.Atoi(strings.TrimPrefix(e.Name(), "part-"))
		if err != nil {
			continue
		}
		idx = append(idx, n)
	}
	// Numeric sort, not lexical: chunk 10 follows 9, and clients upload
	// out of order when retrying a gap.
	sort.Ints(idx)
	return idx, nil
}

// receivedChunks reports which chunk indices have landed, so a resuming
// client can re-send only the gaps.
func receivedChunks(app *App, id string) ([]int, error) {
	return partIndices(app, id)
}

// stagedReader assembles the parts into one stream without concatenating
// them on disk. The caller must Close.
func stagedReader(app *App, id string, gzipped bool) (io.ReadCloser, error) {
	idx, err := partIndices(app, id)
	if err != nil {
		return nil, err
	}
	if len(idx) == 0 {
		return nil, fmt.Errorf("no chunks staged for import %s", id)
	}

	rc := &lazyPartsReader{dir: importStagingDir(app, id), idx: idx}
	if !gzipped {
		return rc, nil
	}
	gz, err := gzip.NewReader(rc)
	if err != nil {
		rc.Close()
		return nil, fmt.Errorf("open gzip stream: %w", err)
	}
	return &gzipPartReader{Reader: gz, gz: gz, under: rc}, nil
}

// lazyPartsReader assembles part-N files into one stream, opening at most
// one at a time. A naive io.MultiReader over pre-opened *os.Files costs an
// FD per chunk - O(chunks) descriptors to assemble a single stream, which
// at the 50 GiB default ceiling and 32 MiB chunks is ~1600 open FDs for
// ONE import. This keeps descriptor use O(1): the current part is closed
// the instant it hits EOF, before the next one is opened.
type lazyPartsReader struct {
	dir    string
	idx    []int // ascending chunk indices, from partIndices
	pos    int   // idx[pos] is the next part to open
	cur    *os.File
	closed bool
}

func (l *lazyPartsReader) Read(p []byte) (int, error) {
	if l.closed {
		return 0, fmt.Errorf("read from closed import stream")
	}
	for {
		if l.cur == nil {
			if l.pos >= len(l.idx) {
				return 0, io.EOF
			}
			n := l.idx[l.pos]
			f, err := os.Open(filepath.Join(l.dir, fmt.Sprintf("part-%d", n)))
			if err != nil {
				// A part vanishing mid-assembly (e.g. a racing purge) must
				// surface as an error, not a stream that quietly ends
				// early and looks like a complete, if short, import.
				return 0, fmt.Errorf("open chunk %d: %w", n, err)
			}
			l.pos++
			l.cur = f
		}
		n, err := l.cur.Read(p)
		if n > 0 {
			return n, nil
		}
		if err == io.EOF {
			cerr := l.cur.Close()
			l.cur = nil
			if cerr != nil {
				return 0, cerr
			}
			continue // advance to the next part
		}
		if err != nil {
			l.cur.Close()
			l.cur = nil
			return 0, err
		}
	}
}

// Close releases whichever part is currently open, if any, and is
// idempotent - a caller that Closes after an error and again via defer
// must not double-close the underlying file.
func (l *lazyPartsReader) Close() error {
	if l.closed {
		return nil
	}
	l.closed = true
	if l.cur == nil {
		return nil
	}
	err := l.cur.Close()
	l.cur = nil
	return err
}

type gzipPartReader struct {
	io.Reader
	gz    *gzip.Reader
	under io.Closer
}

func (g *gzipPartReader) Close() error {
	err := g.gz.Close()
	if cerr := g.under.Close(); err == nil {
		err = cerr
	}
	return err
}

// stagedBytes totals the staged parts, used to verify the declared size
// before a load starts.
func stagedBytes(app *App, id string) (int64, error) {
	idx, err := partIndices(app, id)
	if err != nil {
		return 0, err
	}
	dir := importStagingDir(app, id)
	var total int64
	for _, n := range idx {
		fi, err := os.Stat(filepath.Join(dir, fmt.Sprintf("part-%d", n)))
		if err != nil {
			return 0, err
		}
		total += fi.Size()
	}
	return total, nil
}

// purgeImportStaging removes an import's staged chunks.
func purgeImportStaging(app *App, id string) {
	if !importIDRe.MatchString(id) {
		return
	}
	os.RemoveAll(importStagingDir(app, id))
}

// maxImportBytes returns the configured per-file ceiling.
func maxImportBytes() int64 {
	if v := os.Getenv("BENMORE_MAX_IMPORT_BYTES"); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			return n
		}
	}
	return defaultMaxImportBytes
}

// defaultGzipExpansionRatio bounds decompressed size when a gzip create
// request omits uncompressed_bytes. It is a DoS backstop, not a promise:
// text/CSV routinely compresses better than this, but the point of a
// fallback ratio is to survive an UNDECLARED expansion factor, not to
// model a specific one. Consumed by gzipDecompressedBound (import.go), the
// single function both the disk preflight (importDataBytes ->
// importDiskNeeded / importCommitDiskNeeded) and the runtime
// decompression-bomb guard (gzipExpansionBound, import_run.go) call - so
// the two never disagree about what "undeclared" means, and - since
// MEDIUM-1/the structural fix that unified them - it is also the FLOOR
// BOTH impose on a declared/hinted uncompressed_bytes that comes in
// smaller than a plausible ratio of the compressed upload would imply.
const defaultGzipExpansionRatio = 20

// maxPlausibleGzipRatio bounds a CLIENT-DECLARED uncompressed_bytes at
// create time: reject a claim more than this many times the declared
// (compressed) bytes as implausible, independent of the absolute ceiling
// check below. It is deliberately far more generous than
// defaultGzipExpansionRatio (20x, a realistic assumption for ordinary
// text/CSV) - this exists only to catch a garbage or malicious value (a
// typo, a unit confusion, an attacker probing the disk-preflight
// arithmetic), not to model real compression behavior. The runtime
// decompression-bomb guard (gzipExpansionBound) is what actually protects
// against a genuine bomb; this is a create-time sanity bound on the CLAIM.
const maxPlausibleGzipRatio = 10000

// importSaturatingMul multiplies two non-negative int64s, clamping to
// math.MaxInt64 instead of wrapping into a negative number on overflow.
// importDiskNeeded/gzipExpansionBound multiply a client-influenced byte
// count (uncompressed_bytes, bytes_total) by a fixed ratio; a
// client-declared value near 1<<62 wraps a naive `a*b` negative, which
// then makes every `free < need` disk gate that exists to catch exactly
// this kind of claim silently PASS instead of reject (MEDIUM-2).
func importSaturatingMul(a, b int64) int64 {
	if a <= 0 || b <= 0 {
		return 0
	}
	if a > math.MaxInt64/b {
		return math.MaxInt64
	}
	return a * b
}

// importSaturatingAdd adds two non-negative int64s, clamping to math.MaxInt64
// instead of wrapping on overflow. Same MEDIUM-2 rationale as
// importSaturatingMul - the sum `wantBytes + 2*dataBytes` must saturate UP, not
// wrap negative, so it can never defeat the `free < need` comparison that
// depends on `need` staying positive.
func importSaturatingAdd(a, b int64) int64 {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a > math.MaxInt64-b {
		return math.MaxInt64
	}
	return a + b
}

// gzipDecompressedBound is the ONE function that answers "how many
// decompressed bytes might this gzip import produce?" Both halves of the
// gzip contract call it and only it: the CREATE/COMMIT-time disk
// arithmetic (importDataBytes below, in turn importDiskNeeded /
// importCommitDiskNeeded) and the RUNTIME decompression-bomb guard
// (gzipExpansionBound, import_run.go, which wraps this for the
// *importSession-shaped callers in import_run.go/import_sql.go). Before
// this, the two computed the bound independently and disagreed in the
// unsafe direction: declare bytes=1GB, uncompressed_bytes=1000, and the
// disk gate sized off the raw 1000-byte hint (~1GB from the staged copy
// alone) while the runtime guard was independently authorized to emit up
// to bytes*defaultGzipExpansionRatio = 20GB into an open transaction - a
// disk gate is worthless if it is sized off a smaller ceiling than the
// guard it exists to backstop actually enforces.
//
// Returns max(uncompressedBytes, wantBytes * defaultGzipExpansionRatio):
// a declared/hinted uncompressed_bytes can only ever RAISE the bound
// above the ratio floor, never lower it below what the compressed size
// alone already implies is plausible. This matters because
// gzipUncompressedSizeHint (cli_import.go) UNDER-claims by construction
// on exactly the advertised paths - gzip's ISIZE trailer is the
// decompressed size mod 2^32 (wraps for anything over 4 GiB) and
// describes only the last member of a multi-member stream (`cat a.gz
// b.gz`) - so a hint below the ratio floor is exactly the case that must
// not be trusted at face value.
//
// Cost, stated plainly: a gzip import now needs disk headroom for the
// worst case the runtime guard will actually permit, not for the
// (possibly under-claiming) declared hint. Sizing the disk gate off a
// smaller number than the guard enforces is how a load runs the disk out
// mid-transaction instead of failing preflight in milliseconds.
func gzipDecompressedBound(wantBytes, uncompressedBytes int64) int64 {
	ratioBound := importSaturatingMul(wantBytes, defaultGzipExpansionRatio)
	if uncompressedBytes > ratioBound {
		return uncompressedBytes
	}
	return ratioBound
}

// importDataBytes returns the on-disk footprint of the LOADED DATA once an
// import completes - not the staged copy. For a non-gzip upload the staged
// bytes ARE the data (dataBytes == wantBytes). For a gzip upload the
// footprint is gzipDecompressedBound(wantBytes, uncompressedBytes) - see
// that function's doc comment for why this is a floor, not a straight
// pass-through of the declared hint. Shared by importDiskNeeded
// (create-time: wantBytes is the declared upload size) and
// importCommitDiskNeeded (commit-time: wantBytes is the ACTUALLY staged
// size) so the two never compute "the data footprint" differently.
func importDataBytes(wantBytes int64, gzipped bool, uncompressedBytes int64) int64 {
	if !gzipped {
		return wantBytes
	}
	return gzipDecompressedBound(wantBytes, uncompressedBytes)
}

// importDiskNeeded computes the free-disk bytes an import needs to land AT
// CREATE TIME, given what the create request declared. Pure arithmetic -
// no syscall - so the 3x/gzip-bound math is directly unit-testable
// independent of the test machine's actual free disk; importDiskCheck
// below is the only caller that adds the syscall.
//
// The staged copy (wantBytes) sits on disk for the ENTIRE load, not just
// the upload: purgeImportStaging only runs in the terminal defer, after
// the transaction (import_run.go runImport / import_sql.go
// runSQLRestore), so at load time free disk is already F - wantBytes
// before a single data page or WAL frame is written. On top of that, the
// atomic load needs roughly 2x its DATA footprint - once for the table's
// own pages, once for the write-ahead log, which holds every dirty page
// until commit. See importCommitDiskNeeded for the COMMIT-time variant,
// where the staged copy is already on disk and therefore already
// reflected in the free-disk measurement - demanding it again there
// double-counts (MEDIUM-3).
func importDiskNeeded(wantBytes int64, gzipped bool, uncompressedBytes int64) int64 {
	dataBytes := importDataBytes(wantBytes, gzipped, uncompressedBytes)
	return importSaturatingAdd(wantBytes, importSaturatingMul(2, dataBytes))
}

// importCommitDiskNeeded computes the free-disk bytes STILL needed AT
// COMMIT TIME, after stagedBytes has already been written to disk. Unlike
// importDiskNeeded (create-time, where free disk F0 predates the staged
// copy, so the requirement is F0 >= wantBytes + 2*dataBytes), free disk at
// commit is ALREADY F0 - stagedBytes - the staged copy is not a future
// cost, it already happened and the syscall already sees it missing.
// Passing stagedBytes again as the staged-copy term (as importDiskNeeded
// does) double-counts it, demanding F1 >= stagedBytes + 2*dataBytes when
// the true remaining need is only 2*dataBytes - which rejects, at commit,
// an import that had every reason to pass (nothing about the disk
// changed) on free disk in [stagedBytes+2*dataBytes, 2*stagedBytes+2*
// dataBytes) - destroying the "fail in milliseconds" property C1 exists to
// protect, after the client has already paid for the full upload
// (MEDIUM-3).
func importCommitDiskNeeded(stagedBytes int64, gzipped bool, uncompressedBytes int64) int64 {
	dataBytes := importDataBytes(stagedBytes, gzipped, uncompressedBytes)
	return importSaturatingMul(2, dataBytes)
}

// importDiskCheck is importDiskNeeded plus the actual free-disk syscall -
// the CREATE-time half of the pair. See importCommitDiskCheck for the
// commit-time counterpart (importCommitDiskNeeded, not importDiskNeeded -
// MEDIUM-3).
func importDiskCheck(app *App, wantBytes int64, gzipped bool, uncompressedBytes int64) error {
	free, err := freeDiskBytes(app.Dir)
	if err != nil {
		// Non-fatal: a preflight that cannot measure disk simply does not
		// apply this gate.
		return nil
	}
	need := importDiskNeeded(wantBytes, gzipped, uncompressedBytes)
	if free < need {
		return fmt.Errorf("insufficient disk: import needs ~%d bytes (staged copy + data + write-ahead log) but only %d are free", need, free)
	}
	return nil
}

// importCommitDiskCheck is handleImportCommit's disk gate: it re-checks
// free disk against GROUND TRUTH (the ACTUALLY staged byte count and
// CURRENT free disk) right before starting the load - create-time
// preflight only ever saw a DECLARED size and whatever free disk existed
// minutes-to-hours earlier. It is NOT importDiskCheck reused with the
// staged count as wantBytes: at commit time the staged copy is already on
// disk (already reflected in the freeDiskBytes syscall), so the
// outstanding need is importCommitDiskNeeded's 2x-data-only figure, not
// importDiskNeeded's staged-copy-plus-2x-data figure (MEDIUM-3).
func importCommitDiskCheck(app *App, stagedBytes int64, gzipped bool, uncompressedBytes int64) error {
	free, err := freeDiskBytes(app.Dir)
	if err != nil {
		return nil
	}
	need := importCommitDiskNeeded(stagedBytes, gzipped, uncompressedBytes)
	if free < need {
		return fmt.Errorf("insufficient disk: import needs ~%d more bytes (data + write-ahead log) but only %d are free", need, free)
	}
	return nil
}

// importPreflight rejects an import that cannot possibly land, before the
// client uploads a single byte. Gates:
//
//  1. The configured ceiling (DoS backstop).
//  2. uncompressed_bytes range/plausibility (MEDIUM-2): never negative,
//     never past the configured ceiling, never an implausible multiple of
//     the declared (compressed) bytes.
//  3. The plan storage cap, projected from current database bytes plus
//     the loaded data and transient WAL. Staging is not database usage.
//  4. Free disk - see importDiskNeeded for the arithmetic.
//
// A 270 MB upload that cannot land must fail in milliseconds, not forty
// minutes in.
func importPreflight(app *App, wantBytes int64, gzipped bool, uncompressedBytes int64) error {
	if wantBytes <= 0 {
		return fmt.Errorf("bytes must be a positive count of the file's size")
	}
	if ceiling := maxImportBytes(); wantBytes > ceiling {
		return fmt.Errorf("import of %d bytes exceeds the %d byte ceiling (raise BENMORE_MAX_IMPORT_BYTES to allow it)", wantBytes, ceiling)
	}
	if uncompressedBytes < 0 {
		return fmt.Errorf("uncompressed_bytes must not be negative")
	}
	if uncompressedBytes > 0 {
		if ceiling := maxImportBytes(); uncompressedBytes > ceiling {
			return fmt.Errorf("uncompressed_bytes of %d exceeds the %d byte import ceiling (raise BENMORE_MAX_IMPORT_BYTES to allow it)", uncompressedBytes, ceiling)
		}
		if ratioCap := importSaturatingMul(wantBytes, maxPlausibleGzipRatio); uncompressedBytes > ratioCap {
			return fmt.Errorf("uncompressed_bytes of %d is implausible for a %d byte upload (exceeds a %dx expansion ratio) - omit uncompressed_bytes to let the server assume a generous fallback ratio instead", uncompressedBytes, wantBytes, maxPlausibleGzipRatio)
		}
	}
	if reason, blocked := checkStorageCap(app, importCommitDiskNeeded(wantBytes, gzipped, uncompressedBytes)); blocked {
		return fmt.Errorf("storage cap reached: %s", reason)
	}
	return importDiskCheck(app, wantBytes, gzipped, uncompressedBytes)
}

// freeDiskBytes reports bytes available to an unprivileged process on the
// filesystem holding dir. An error is non-fatal to the caller: a preflight
// that cannot measure disk simply does not apply that gate. A package-level
// var (not a plain func) so tests can inject a synthetic free-disk value -
// the real syscall can't be made to report an arbitrary figure, and the
// MEDIUM-3 commit-vs-create double-count regression is only observable at
// a specific free-disk band, not in the pure importDiskNeeded arithmetic.
var freeDiskBytes = realFreeDiskBytes

// loadImportSession reads one session row.
func loadImportSession(db *sql.DB, id string) (*importSession, error) {
	var s importSession
	var gz int
	err := db.QueryRow(`SELECT id, table_name, format, gzip, bytes_total,
		uncompressed_bytes, sha256, null_as, state, rows_loaded, error,
		created_by, created_by_subject
		FROM _benmore_imports WHERE id = ?`, id).
		Scan(&s.ID, &s.TableName, &s.Format, &gz, &s.BytesTotal,
			&s.UncompressedBytes, &s.SHA256, &s.NullAs, &s.State, &s.RowsLoaded,
			&s.Error, &s.CreatedBy, &s.CreatedBySubject)
	if err != nil {
		return nil, err
	}
	s.Gzip = gz != 0
	return &s, nil
}

// saveImportState records a terminal (or transitional) state. Progress
// during a run is NOT written here - see importProgress in import_run.go
// for why an in-flight transaction cannot publish its own row count.
func saveImportState(db *sql.DB, id, state string, rows int64, errMsg string) error {
	_, err := db.Exec(`UPDATE _benmore_imports
		SET state = ?, rows_loaded = ?, error = ?,
		    completed_at = CASE WHEN ? IN ('completed','failed','cancelled')
		                        THEN datetime('now') ELSE completed_at END
		WHERE id = ?`, state, rows, errMsg, state, id)
	return err
}

func saveImportStateIf(db *sql.DB, id, from, state string, rows int64, errMsg string) (bool, error) {
	res, err := db.Exec(`UPDATE _benmore_imports
		SET state = ?, rows_loaded = ?, error = ?,
		    completed_at = CASE WHEN ? IN ('completed','failed','cancelled')
		                        THEN datetime('now') ELSE completed_at END
		WHERE id = ? AND state = ?`, state, rows, errMsg, state, id, from)
	if err != nil {
		return false, err
	}
	n, err := res.RowsAffected()
	return n == 1, err
}
