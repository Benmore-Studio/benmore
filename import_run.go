//go:build !cli

package main

// Bulk import - the load runner.
//
// One transaction per file, one prepared statement reused for every row,
// and a streaming parser. Memory is constant regardless of file size.
//
// Two deliberate departures from how /ingest behaves, both required by
// all-or-nothing semantics:
//   - A bad row aborts the whole load instead of being skipped and counted.
//   - Per-row hooks, audit rows, broadcasts and webhook fan-out are not
//     fired. 3.3M hook firings is the difference between a 40-second load
//     and one that never finishes; this surface is for reference data.
//
// Progress is kept in memory, NOT in the _benmore_imports row. An
// uncommitted transaction cannot publish its own row count - a write from
// the same transaction is invisible to readers, and a write from a second
// connection would deadlock against SQLite's single writer. importProgress
// is what GET /api/_import/{id} reads while a load is in flight.

import (
	"compress/gzip"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// importProgress maps import id -> rows loaded so far, for in-flight loads.
var importProgress sync.Map

// gzipExpansionBound returns the byte count runImportInner/
// runSQLRestoreInner refuse to let a decompressed stream exceed - the
// RUNTIME half of the gzip-bomb guard. It is a thin *importSession-shaped
// wrapper over gzipDecompressedBound (import.go), the ONE function that
// answers "how many decompressed bytes might this produce?" - the
// CREATE/COMMIT-time disk arithmetic (importDataBytes, import.go) calls
// the same function, so the disk gate and this runtime guard can never
// drift back out of sync. See gzipDecompressedBound's doc comment for the
// full rationale (the ISIZE-wraps / multi-member-stream under-claim cases
// that make the ratio floor necessary) and importDataBytes's for the
// disk-side consequence. A declared UncompressedBytes is a CLIENT CLAIM,
// not a server-verified fact - trusting it alone would let a claim of
// "500MB" mask a payload that actually expands to 500GB, so this bound is
// enforced by counting real bytes as they emerge from gzip.Reader, not by
// trusting the claim.
func gzipExpansionBound(sess *importSession) int64 {
	return gzipDecompressedBound(sess.BytesTotal, sess.UncompressedBytes)
}

// boundedReader aborts a read once more than limit bytes have passed
// through it. Wrapped around gzip.Reader's OUTPUT (never its input) in
// runImportInner/runSQLRestoreInner, this is what turns "the decompressed
// stream exceeds its declared/assumed bound" from a disk-exhaustion
// eventuality into an immediate, atomic (zero rows land - it surfaces as
// an ordinary error from the row source or statement walk, which already
// aborts the whole transaction) failure.
type boundedReader struct {
	r     io.Reader
	limit int64
	read  int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if b.read >= b.limit {
		var extra [1]byte
		if n, err := b.r.Read(extra[:]); n == 0 {
			return 0, err
		}
		return 0, fmt.Errorf("decompressed stream exceeds %d bytes (declared or assumed uncompressed size) - refusing to continue (possible decompression bomb)", b.limit)
	}
	if room := b.limit - b.read; int64(len(p)) > room {
		p = p[:room]
	}
	n, err := b.r.Read(p)
	b.read += int64(n)
	return n, err
}

// importFlags tracks whether an import is in flight, keyed by app.Dir -
// the same per-app-instance key import.go's own staging paths use
// (importStagingDir). The guard must be PER APP, not process-global:
// `benmore host` loads many apps into one process (host.go LoadApp), each
// with its own data.db, so one tenant's SQLite writer has nothing to do
// with another tenant's. A process-wide guard would let one tenant's
// 40-minute import return "already running" to every other tenant on the
// box. A struct field on App would need touching types.go, which sits
// outside this file's owned surface, so a package-level map keyed by the
// already-unique app.Dir is the more contained fix.
var importFlags sync.Map // app.Dir (string) -> *atomic.Bool

// importFlagFor returns the in-flight flag for this app, creating it on
// first use. LoadOrStore is atomic, so two callers racing on an app.Dir
// neither has seen yet still converge on the same one flag.
func importFlagFor(app *App) *atomic.Bool {
	v, _ := importFlags.LoadOrStore(app.Dir, &atomic.Bool{})
	return v.(*atomic.Bool)
}

// importProgressOf returns the live row count for an in-flight import.
func importProgressOf(id string) (int64, bool) {
	v, ok := importProgress.Load(id)
	if !ok {
		return 0, false
	}
	p, ok := v.(*atomic.Int64)
	if !ok {
		return 0, false
	}
	return p.Load(), true
}

// importRunning reports whether an import is currently in flight for this
// app. Per-app, same as the startImport guard - see importFlags.
func importRunning(app *App) bool { return importFlagFor(app).Load() }

// importableColumns returns the columns a bulk import may write: every
// column except the primary key and the mass-assignment-protected set.
// The protected set matches handleCreate and handleStreamingIngest, plus
// the configured tenant key and in-tenant role field.
func importableColumns(db *sql.DB, table string, app *App) ([]Column, error) {
	cols, err := GetTableColumns(db, table)
	if err != nil {
		return nil, err
	}
	protected := map[string]bool{
		"user_id": true, "created_at": true, "updated_at": true,
		"password_hash": true, "role": true,
	}
	if app != nil && app.Group != nil && app.Group.Key != "" {
		protected[app.Group.Key] = true
	}
	if app != nil && app.Group != nil && app.Group.RoleField != "" &&
		app.Group.Table != "" && table == app.Group.Table {
		protected[app.Group.RoleField] = true
	}

	var out []Column
	for _, c := range cols {
		if c.PK || protected[c.Name] {
			continue
		}
		out = append(out, c)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("table %s has no importable columns", table)
	}
	return out, nil
}

// validateImportColumns checks a caller-DECLARED column list (the
// importCreateReq.Columns field, import_http.go) against the importable
// set at CREATE time, before a single byte uploads - the pre-upload
// fast-fail the design promises (spec: "An unknown or protected column
// fails the session before any bytes are uploaded"). Without this, the
// same rejection only ever happened inside runImportInner's header check,
// which a caller only reaches after paying for the ENTIRE upload and
// commit - the concrete cost being a CSV exported from a source table
// that still carries its own `id` primary key, learned 270 MB too late.
//
// Each declared name is run through normalizeImportHeaderName (strip a
// leading BOM, trim whitespace) before matching, identically to how
// newCSVSource (import_parse.go) treats the actual file header at load
// time. `benmore import` already normalizes locally before sending this
// field (cli_import.go csvHeaderColumns), so this only matters for a
// third-party client posting raw header names directly - without it, such
// a caller got a spurious 400 for a file the loader itself would accept.
func validateImportColumns(db *sql.DB, table string, app *App, want []string) error {
	cols, err := importableColumns(db, table, app)
	if err != nil {
		return err
	}
	allowed := make(map[string]bool, len(cols))
	for _, c := range cols {
		allowed[c.Name] = true
	}
	var bad []string
	for _, name := range want {
		norm := normalizeImportHeaderName(name)
		if !allowed[norm] {
			bad = append(bad, name)
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("column(s) %s are not importable (unknown, the primary key, or protected against mass assignment) - remove them from the file or the declared columns list", strings.Join(bad, ", "))
	}
	return nil
}

// startImport launches a load in a dedicated goroutine.
//
// The in-flight guard is per app (importFlagFor) and uses CompareAndSwap
// to make the check-and-set atomic without a separate mutex - the
// previous version's mutex only ever protected that one compare-and-set,
// which CompareAndSwap already does on its own.
//
// It deliberately does NOT use _benmore_jobs: that worker is serial
// (jobs.go:518), so a multi-minute import parked there would starve every
// hook, email, notification and webhook for the app, and its exponential
// backoff would silently re-run a multi-million-row load on a transient
// error. Failure here is terminal; the client re-commits explicitly.
func startImport(app *App, sess *importSession) error {
	flag := importFlagFor(app)
	if !flag.CompareAndSwap(false, true) {
		return fmt.Errorf("an import is already running for this app")
	}
	startImportWithGuard(app, sess, flag)
	return nil
}

func startImportWithGuard(app *App, sess *importSession, flag *atomic.Bool) {
	sess.stop = app.Stop

	safeGo("import:"+sess.ID, func() {
		defer flag.Store(false)
		var err error
		if sess.Format == "sql" {
			err = runSQLRestore(app, sess)
		} else {
			err = runImport(app, sess)
		}
		if err != nil {
			log.Printf("IMPORT %s FAILED (%s): %v", sess.ID, sess.TableName, err)
		}
	})
}

// runImport performs the load synchronously. Exported behaviour: on
// return, the _benmore_imports row is in a terminal state and, on failure,
// zero rows from this file exist in the target table.
//
// Outer terminal bookkeeping - progress-map cleanup, failure persistence,
// staging purge, audit, broadcast - lives in one defer so it still runs
// if runImportInner panics; without it a panic mid-load left the
// _benmore_imports row stuck non-terminal forever (the client polls
// indefinitely with nothing logged) and leaked the importProgress entry.
// recover() is needed (not just a bare defer) to correctly classify a
// panic as a FAILURE: without it, the deferred closure would read err's
// zero value and record a panicked load as "completed" with 0 rows -
// silently wrong, worse than the leak it would replace. The panic is
// re-raised once cleanup has run so safeGo's own recover still logs it.
func runImport(app *App, sess *importSession) error {
	var rows int64
	var err error
	defer func() {
		if rec := recover(); rec != nil {
			err = fmt.Errorf("panic during import: %v", rec)
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
			// A "failed" session is terminal - the resume match
			// (handleImportCreate) only ever resumes 'staging' rows, so a
			// retry of the identical file always starts a brand-new
			// session regardless. The staged bytes serve no further
			// purpose once the state transition above lands; leaving them
			// was an orphaned-disk-space bug (review round 2 minor: the
			// CLI's own cleanup previously went through DELETE
			// /api/_import/{id}, which handleImportCancel now correctly
			// REFUSES for a terminal state to protect sess.Error from
			// being overwritten - so the purge has to happen here,
			// unconditionally, as part of terminal bookkeeping, the same
			// as the success path already does below).
			purgeImportStaging(app, sess.ID)
			return
		}
		purgeImportStaging(app, sess.ID)

		// Email: sess.CreatedBySubject - not just UserID: sess.CreatedBy -
		// so an owner-token import (CreatedBy is always the 0 sentinel; no
		// per-app _benmore_users row to point at) still lands a real
		// actor in the audit row's user_email column instead of an empty
		// string. CreatedBySubject was captured at create time from the
		// authorizing Session's Email (import_http.go handleImportCreate)
		// - the real admin email for an admin session, or the owner
		// token's subject (verifyImportOwnerToken, import_sql.go) for a
		// token-authenticated caller.
		LogAudit(app, "import", sess.TableName, "",
			&Session{UserID: sess.CreatedBy, Email: sess.CreatedBySubject},
			nil,
			map[string]any{"rows": rows, "bytes": sess.BytesTotal, "sha256": sess.SHA256, "format": sess.Format},
		)
		Broadcast(app, sess.TableName, "insert", nil)
		log.Printf("IMPORT %s: %d rows into %s", sess.ID, rows, sess.TableName)
	}()

	rows, err = runImportInner(app, sess)
	return err
}

// stagedRawReader opens the staged chunks as one stream with NO gzip
// unwrap - the same on-disk bytes stagedBytes measures and the client's
// declared checksum describes, compressed or not. runImportInner tees
// its hasher off of this raw stream and applies gzip decoding (if any)
// downstream of that tee; see the comment at the call site for why.
// stagedReader (import.go) does the gzip unwrap internally by design and
// isn't reusable for that, so this sits alongside it as the raw-stream
// equivalent, kept here rather than in import.go to stay inside this
// file's owned surface.
func stagedRawReader(app *App, id string) (io.ReadCloser, error) {
	idx, err := partIndices(app, id)
	if err != nil {
		return nil, err
	}
	if len(idx) == 0 {
		return nil, fmt.Errorf("no chunks staged for import %s", id)
	}
	return &lazyPartsReader{dir: importStagingDir(app, id), idx: idx}, nil
}

// runImportInner does the actual load and returns the row count on
// success. Returning it directly (rather than making the caller re-read
// importProgress by id) matters: if that map entry were ever absent for
// any reason, reading it back would silently report 0 rows for what was
// actually a successful load - exactly the silent-failure class this
// codebase forbids.
func runImportInner(app *App, sess *importSession) (int64, error) {
	stop := sess.stop
	if stop == nil {
		stop = app.Stop
	}
	// Size check first - it costs a few stat calls and catches a truncated
	// upload before any parsing work. stagedBytes sums the on-disk part
	// files, which for a gzip upload are the COMPRESSED bytes - see the
	// tee comment below for why bytes_total/sha256 must describe that same
	// (possibly compressed) stream.
	staged, err := stagedBytes(app, sess.ID)
	if err != nil {
		return 0, fmt.Errorf("stat staged chunks: %w", err)
	}
	if staged != sess.BytesTotal {
		return 0, fmt.Errorf("staged %d bytes but the session declared %d - upload is incomplete", staged, sess.BytesTotal)
	}

	cols, err := importableColumns(app.DB, sess.TableName, app)
	if err != nil {
		return 0, err
	}

	raw, err := stagedRawReader(app, sess.ID)
	if err != nil {
		return 0, err
	}
	defer raw.Close()

	// bytes_total and sha256 both describe the UPLOADED bytes - compressed,
	// if sess.Gzip - because that is the only stream the client can ever
	// measure. So the tee sits on the RAW stream, before any gzip unwrap:
	// hashing the decompressed stream instead would demand a checksum the
	// client has no way to have produced, and every gzip import would fail
	// the checksum check after doing all the parsing work.
	hasher := sha256.New()
	tee := io.TeeReader(raw, hasher)

	var parseSrc io.Reader = tee
	if sess.Gzip {
		gz, err := gzip.NewReader(tee)
		if err != nil {
			return 0, fmt.Errorf("open gzip stream: %w", err)
		}
		defer gz.Close()
		// Bounded on the DECOMPRESSED output, not the (already
		// size-checked) compressed input - see boundedReader's doc
		// comment. This is the runtime backstop for the exact hole the
		// disk preflight alone can't close: bytes_total/sha256 describe
		// the compressed upload, so a 50 MB .csv.gz claiming a modest
		// uncompressed_bytes (or none at all) that actually expands to
		// 5 GB would otherwise sail through the size check and only be
		// caught by running out of disk mid-load - or not at all, on a
		// box with room to spare.
		parseSrc = &boundedReader{r: gz, limit: gzipExpansionBound(sess)}
	}

	// The source returns the EFFECTIVE column list - the columns this file
	// actually provides. The INSERT is built from that list, not from every
	// importable column, so a column the file omits takes its DEFAULT
	// instead of being explicitly bound NULL.
	var src rowSource
	var effective []Column
	switch sess.Format {
	case "csv":
		src, effective, err = newCSVSource(parseSrc, cols, sess.NullAs)
	case "ndjson":
		src, effective, err = newNDJSONSource(parseSrc, cols)
	default:
		return 0, fmt.Errorf("unsupported import format %q", sess.Format)
	}
	if err != nil {
		return 0, err
	}

	names := make([]string, len(effective))
	marks := make([]string, len(effective))
	for i, c := range effective {
		names[i] = c.Name
		marks[i] = "?"
	}
	// Column names come from GetTableColumns, never from user input, so
	// this interpolation cannot carry injected SQL. Values are always bound.
	insertSQL := fmt.Sprintf("INSERT INTO %s (%s) VALUES (%s)",
		sess.TableName, strings.Join(names, ", "), strings.Join(marks, ", "))

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

	stmt, err := tx.Prepare(insertSQL)
	if err != nil {
		return 0, fmt.Errorf("prepare insert: %w", err)
	}
	defer stmt.Close()

	progress := &atomic.Int64{}
	importProgress.Store(sess.ID, progress)

	var parsed int64
	lastBeat := time.Now()
	for {
		vals, err := src.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("row %d: %w", parsed+1, err)
		}
		if _, err := stmt.Exec(vals...); err != nil {
			return 0, fmt.Errorf("row %d: %w", parsed+1, err)
		}
		parsed++
		if time.Since(lastBeat) > 2*time.Second {
			progress.Store(parsed)
			lastBeat = time.Now()
		}
		select {
		case <-stop:
			return 0, fmt.Errorf("app shutting down after %d rows - import rolled back", parsed)
		default:
		}
	}
	progress.Store(parsed)

	// Silent failure is a bug: a non-empty file that produced no rows is an
	// error, not a success. This is the guard that would have caught the
	// for_each-over-a-missing-key class of failure described in CLAUDE.md.
	if parsed == 0 {
		return 0, fmt.Errorf("parsed 0 rows from a %d byte file - nothing was imported", sess.BytesTotal)
	}

	// Drain any bytes not consumed while parsing - a trailing newline after
	// the last CSV record, or (for gzip) any raw bytes gzip.Reader left
	// unread once it hit its end-of-stream trailer - so the hash covers
	// the whole staged file, compressed or not.
	io.Copy(io.Discard, tee)
	if got := hex.EncodeToString(hasher.Sum(nil)); got != sess.SHA256 {
		return 0, fmt.Errorf("checksum mismatch: staged data hashes to %s but the session declared %s", got, sess.SHA256)
	}

	if err := completeImport(tx, sess.ID, parsed); err != nil {
		return 0, fmt.Errorf("complete import: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, fmt.Errorf("commit: %w", err)
	}
	committed = true
	return parsed, nil
}

func completeImport(tx *sql.Tx, id string, rows int64) error {
	res, err := tx.Exec(`UPDATE _benmore_imports
		SET state = 'completed', rows_loaded = ?, error = '', completed_at = datetime('now')
		WHERE id = ? AND state = 'running'`, rows, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return fmt.Errorf("import is no longer running")
	}
	return nil
}
