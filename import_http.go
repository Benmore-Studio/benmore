//go:build !cli

package main

// Bulk import - HTTP surface.
//
//   POST   /api/_import                 create a session
//   PUT    /api/_import/{id}/chunk/{n}  stage chunk n
//   POST   /api/_import/{id}/commit     verify and start the load
//   GET    /api/_import/{id}            status
//   DELETE /api/_import/{id}            cancel and purge
//
// Chunking is mandatory, not an optimisation: the origin only accepts
// Cloudflare-fronted connections (host.go:566) and Cloudflare caps request
// bodies at ~100 MB and origin response time at ~100 s. A 270 MB
// single-request upload cannot work.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// importCreateLimiter bounds session creation. Chunk PUTs are not limited
// here - a legitimate 50 GB import is thousands of them.
//
// This is ONE process-lifetime limiter shared by every app buildAppMux
// registers (host.go LoadApp loads many tenants into one process). Its key
// MUST therefore carry app identity, not just the user id: _benmore_users
// ids are per-app autoincrement, so "user 1" of tenant A and "user 1" of
// tenant B are different people who would otherwise share one 10/minute
// bucket - letting tenant A exhaust tenant B's ability to create imports.
// See importFlagFor (import_run.go) for the same app-identity requirement
// on the in-flight guard, keyed by the same app.Dir.
var importCreateLimiter = NewRateLimiter(10, time.Minute)

// importTableAllowed reports whether a table may be an import target.
// Resolution goes through GetTableNames, which already filters _benmore_%
// and sqlite_% (db.go:508) - so framework tables are unreachable
// structurally, with no deny-list to maintain or forget.
func importTableAllowed(app *App, table string) bool {
	names, err := GetTableNames(app.DB)
	if err != nil {
		return false
	}
	for _, n := range names {
		if n == table {
			return true
		}
	}
	return false
}

// importCallerAuthorized enforces the table-independent half of the Mode A
// gate: CSRF (Bearer bypass, GET exempt), a live session, and admin-or-owner.
// It is split from the per-table half so a caller can be authenticated
// BEFORE any table name is resolved - otherwise the 404-vs-403 difference
// tells an anonymous prober which tables the app has.
func importCallerAuthorized(w http.ResponseWriter, r *http.Request, app *App) (*Session, bool) {
	// An owner token is verified here (not just shape-checked) via
	// importOwnerToken, and - like Bearer auth - never rides a session
	// cookie, so it is exempt from the CSRF check on the same grounds as
	// isBearerAuth below: a cross-site page can neither read nor set this
	// header, so there is no session to ride. Without this exemption a
	// token-bearing request (e.g. from `benmore import`, which holds no
	// cookie and no CSRF token) would 403 on the CSRF gate before the
	// owner-token check below ever ran.
	subject, viaOwnerToken := importOwnerToken(app, r)
	// Cheap/orthogonal checks FIRST, validateCSRF LAST: Go evaluates &&
	// left to right, so putting validateCSRF first meant it ran (and
	// logged a REJECT line, auth_csrf.go validateCSRFReason) on EVERY legitimate token- or
	// Bearer-authenticated request before either short-circuit ever had a
	// chance to apply - one spurious security-log line per 32 MiB chunk
	// PUT on a real `benmore import` run. GET (status) is side-effect-free
	// and a cross-site GET can't read the response anyway, so requiring a
	// token here buys no protection while forcing a browser poller to mint
	// one on every tick. Matches the rest of the codebase - locks.go and
	// versioning.go both call validateCSRF only from their mutating
	// handlers, never from a GET.
	if r.Method != http.MethodGet && !viaOwnerToken && !isBearerAuth(r) && !validateCSRF(r) {
		httpError(w, "Invalid CSRF token", http.StatusForbidden)
		return nil, false
	}
	// An owner token stands in for an admin session. The CLI authenticates
	// as a PLATFORM user, which has no identity in this app's
	// _benmore_users, so without this the headline `benmore import` command
	// would only work for an owner who also holds an app admin account.
	// Possession of the app's server secret IS proof of ownership - the
	// same authority `sql --write` already grants over every table.
	// Email carries the token's SUBJECT (the platform user's email, or a
	// self-hosted CLI's best-effort local identity) rather than a fixed
	// placeholder, so the audit trail this session eventually feeds
	// (created_by_subject, LogAudit in import_run.go/import_sql.go) can
	// attribute the import to a real actor instead of an empty string.
	if viaOwnerToken {
		return &Session{UserID: 0, Email: subject}, true
	}
	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return nil, false
	}
	// IsAdminBypass, not IsAdmin: a stepped-in admin (act-as) must not
	// bulk-load into the tenant it stepped into. See types.go:622.
	if !session.IsAdminBypass() {
		httpJSON(w, http.StatusForbidden, map[string]any{
			"error": "bulk import requires an admin or owner session",
		})
		return nil, false
	}
	return session, true
}

// importTableAuthorized enforces the per-table half: write scope plus the
// declarative access: rules. A member with write access to the table still
// fails, because importCallerAuthorized already required admin-or-owner.
func importTableAuthorized(w http.ResponseWriter, r *http.Request, app *App, session *Session, table string) bool {
	if err := checkScope(session, table, "write"); err != nil {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return false
	}
	return EnforceCRUDAccess(w, r, app, table, OpWrite, 0)
}

// newImportID mints a 32-hex-char random import id. crypto/rand.Read's
// error is checked (M6 review fix) - a silently-ignored failure here
// would hand an all-zero (or otherwise non-random) id to importIDRe's
// caller, which reaches the filesystem as a directory name.
func newImportID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("generate import id: %w", err)
	}
	return hex.EncodeToString(b), nil
}

// RegisterImportRoutes wires the import endpoints onto an app mux.
func RegisterImportRoutes(mux *http.ServeMux, app *App) {
	EnsureImportsTable(app)

	mux.HandleFunc("POST /api/_import", func(w http.ResponseWriter, r *http.Request) {
		handleImportCreate(w, r, app)
	})
	mux.HandleFunc("PUT /api/_import/{id}/chunk/{n}", func(w http.ResponseWriter, r *http.Request) {
		handleImportChunk(w, r, app)
	})
	mux.HandleFunc("POST /api/_import/{id}/commit", func(w http.ResponseWriter, r *http.Request) {
		handleImportCommit(w, r, app)
	})
	mux.HandleFunc("GET /api/_import/{id}", func(w http.ResponseWriter, r *http.Request) {
		handleImportStatus(w, r, app)
	})
	mux.HandleFunc("DELETE /api/_import/{id}", func(w http.ResponseWriter, r *http.Request) {
		handleImportCancel(w, r, app)
	})
}

type importCreateReq struct {
	Table  string `json:"table"`
	Format string `json:"format"`
	Gzip   bool   `json:"gzip"`
	Bytes  int64  `json:"bytes"`
	// UncompressedBytes is optional and only meaningful when Gzip is
	// true: the caller's best-effort declared decompressed size, used to
	// size the disk preflight and the runtime decompression-bomb guard
	// accurately instead of falling back to a generous ratio of the
	// (compressed) Bytes. `benmore import` supplies this CHEAPLY by
	// reading gzip's own ISIZE trailer field rather than decompressing
	// (cli_import.go gzipUncompressedSizeHint) - it is a hint, not a
	// server-verified fact, so it is never trusted alone (see
	// runImportInner / runSQLRestoreInner).
	UncompressedBytes int64  `json:"uncompressed_bytes"`
	SHA256            string `json:"sha256"`
	NullAs            string `json:"null_as"`
	// Columns is optional: the caller's declared header/key list for a
	// CSV/NDJSON file. When present it is validated against the table's
	// importable columns HERE, before a single chunk uploads (spec
	// "An unknown or protected column fails the session before any bytes
	// are uploaded") - catching, for example, a source-table export that
	// still carries its own `id` primary key BEFORE the caller pays for
	// uploading and committing the whole file. `benmore import` supplies
	// this for CSV by reading just the header line locally
	// (cli_import.go csvHeaderColumns). NDJSON has no header, so this is
	// optional for it; without it, NDJSON's shape is still validated at
	// load time from the first object's keys (newNDJSONSource).
	Columns []string `json:"columns,omitempty"`
}

func handleImportCreate(w http.ResponseWriter, r *http.Request, app *App) {
	var req importCreateReq
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<16)).Decode(&req); err != nil {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid JSON body"})
		return
	}

	// Order matters: authenticate FIRST, then resolve the table. Checking
	// table existence before auth would tell an anonymous caller which
	// tables an app has, one 404-vs-403 probe at a time. The per-table
	// access check needs a table name, so the gate is split in two: prove
	// there is an admin/owner session, then resolve the table, then run
	// the per-table access rules.
	session, ok := importCallerAuthorized(w, r, app)
	if !ok {
		return
	}
	// A second, redundant verification (not reused from
	// importCallerAuthorized's own call) - pre-existing, out of scope for
	// this pass (review M4). The subject is discarded here: session.Email
	// already carries it from importCallerAuthorized's return.
	_, viaOwnerToken := importOwnerToken(app, r)

	switch req.Format {
	case "csv", "ndjson":
		// Mode A: table is required and must be importable.
	case "sql":
		// Mode B: owner-only, and the target table is whatever the
		// script names - so `table` is not used. importCallerAuthorized
		// having already accepted an admin session is not enough here:
		// Mode B is a multi-statement, multi-table write with no
		// per-table access check downstream, so it specifically requires
		// the stronger owner-token proof regardless of how the caller
		// authenticated above.
		if !viaOwnerToken {
			httpJSON(w, http.StatusForbidden, map[string]any{
				"error": "SQL restore requires an owner token (X-Benmore-Import-Token)",
			})
			return
		}
	default:
		httpJSON(w, http.StatusBadRequest, map[string]any{
			"error": "format must be \"csv\", \"ndjson\" or \"sql\"",
		})
		return
	}

	// Mode B has no single target table - the script names its own - so
	// the table gates below only apply to Mode A. importTableAllowed keeps
	// _benmore_* structurally unreachable regardless of who is asking.
	if req.Format != "sql" && !importTableAllowed(app, req.Table) {
		httpJSON(w, http.StatusNotFound, map[string]any{
			"error": fmt.Sprintf("table %q is not an importable table", req.Table),
		})
		return
	}
	// An owner token already proved full ownership authority - the same
	// authority sql(write:true) grants over every table - so the
	// per-table write-scope/access: check is redundant for it and is
	// skipped, same as it is unconditionally skipped for Mode B above.
	if req.Format != "sql" && !viaOwnerToken && !importTableAuthorized(w, r, app, session, req.Table) {
		return
	}
	gz := 0
	if req.Gzip {
		gz = 1
	}
	// Mode B's script names its own tables, so table_name is stored empty
	// rather than whatever (unused) value the caller sent as `table`.
	table := req.Table
	if req.Format == "sql" {
		table = ""
	}

	// Resume support: `benmore import` re-run after a dropped connection
	// (or a client that just crashed mid-upload) posts the IDENTICAL create
	// request - same table/format/gzip/bytes/sha256, same caller. Without
	// this, newImportID() below hands back a SECOND id every time, so the
	// "skip chunks already received" logic in the CLI always sees an empty
	// received_chunks list for its brand-new session and re-uploads from
	// byte zero - the resume feature was dead code. Matching on sha256 (not
	// just the other fields) is what makes reusing a session safe: a
	// DIFFERENT file can never collide onto someone else's in-progress
	// session, even if table/format/gzip/bytes_total happen to coincide.
	// Only 'staging' sessions are eligible - once a session has moved to
	// running/completed/failed/cancelled, a matching create request starts
	// a fresh one (its own rate-limit/size/shape checks below still apply).
	var resumeID string
	lookupErr := app.DB.QueryRow(`SELECT id FROM _benmore_imports
		WHERE state='staging' AND table_name=? AND format=? AND gzip=?
		  AND sha256=? AND bytes_total=? AND null_as=? AND uncompressed_bytes=?
		  AND created_by=? AND created_by_subject=?
		ORDER BY created_at DESC LIMIT 1`,
		table, req.Format, gz, req.SHA256, req.Bytes, req.NullAs, req.UncompressedBytes,
		session.UserID, session.Email).Scan(&resumeID)
	if lookupErr == nil && resumeID != "" {
		httpJSON(w, http.StatusOK, map[string]any{
			"import_id":  resumeID,
			"chunk_size": int64(maxImportChunkBytes),
			"state":      "staging",
		})
		return
	}

	// app.Dir, not just the user id, in the key - see the comment on
	// importCreateLimiter's declaration for why. Only reached for a
	// genuinely NEW session - a resumed one (above) doesn't consume a
	// rate-limit slot, so a flaky-link retry loop can't exhaust it.
	if !importCreateLimiter.Allow(fmt.Sprintf("import:app:%s:user:%d", app.Dir, session.UserID)) {
		httpJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many import sessions; try again shortly"})
		return
	}

	// Size gate BEFORE the sha256 shape check: an oversized request should
	// 413 regardless of whether the caller also botched the checksum field.
	// Checking cheaper/orthogonal validations first would otherwise let a
	// malformed sha256 mask a too-large upload behind a 400.
	if err := importPreflight(app, req.Bytes, req.Gzip, req.UncompressedBytes); err != nil {
		httpJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": err.Error()})
		return
	}
	if len(req.SHA256) != 64 {
		httpJSON(w, http.StatusBadRequest, map[string]any{
			"error": "sha256 must be the hex-encoded SHA-256 of the file",
		})
		return
	}
	if req.Format != "sql" {
		// Fail before the upload if the table has nothing importable.
		// Mode B has no single target table to check.
		if _, err := importableColumns(app.DB, req.Table, app); err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
			return
		}
		// Fail before the upload if the CALLER'S declared column list
		// names anything unknown, primary-key, or mass-assignment
		// protected - the concrete case this catches is a CSV exported
		// from the source table that still carries its own `id` column,
		// which importableColumns always excludes (Mode A regenerates
		// PKs; see api(at:"import") for why Mode B is the FK-preserving
		// answer). Optional: Columns is empty unless the caller (the CLI,
		// for CSV) supplied it, in which case NDJSON's shape stays
		// validated at load time instead (import_run.go newNDJSONSource).
		if len(req.Columns) > 0 {
			if err := validateImportColumns(app.DB, req.Table, app, req.Columns); err != nil {
				httpJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
		}
	}

	id, err := newImportID()
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}
	_, err = app.DB.Exec(`INSERT INTO _benmore_imports
		(id, table_name, format, gzip, bytes_total, uncompressed_bytes, sha256,
		 null_as, state, created_by, created_by_subject)
		VALUES (?,?,?,?,?,?,?,?, 'staging', ?, ?)`,
		id, table, req.Format, gz, req.Bytes, req.UncompressedBytes, req.SHA256,
		req.NullAs, session.UserID, session.Email)
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}

	httpJSON(w, http.StatusOK, map[string]any{
		"import_id":  id,
		"chunk_size": int64(maxImportChunkBytes),
		"state":      "staging",
	})
}

// importSessionFor loads the session named in the path and re-runs the
// authorisation gate against its target table.
func importSessionFor(w http.ResponseWriter, r *http.Request, app *App) (*importSession, bool) {
	// Same ordering rule as create: authenticate before the id is used to
	// look anything up, so an unknown-vs-known import id is not a probe.
	session, ok := importCallerAuthorized(w, r, app)
	if !ok {
		return nil, false
	}
	sess, err := loadImportSession(app.DB, r.PathValue("id"))
	if err != nil {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "unknown import"})
		return nil, false
	}
	// Mode B has no single target table to authorize against - the owner
	// token (required at create time for every "sql"-format session) is
	// re-checked here too, so a chunk/commit/status/cancel call on a Mode B
	// session can't be driven by a plain admin session alone.
	if sess.Format == "sql" {
		if _, ok := importOwnerToken(app, r); !ok {
			httpJSON(w, http.StatusForbidden, map[string]any{
				"error": "SQL restore requires an owner token",
			})
			return nil, false
		}
		return sess, true
	}
	// An owner token already proved full ownership authority, so the
	// per-table write-scope/access: check is redundant for it - same as
	// at create time.
	if _, viaOwnerToken := importOwnerToken(app, r); !viaOwnerToken && !importTableAuthorized(w, r, app, session, sess.TableName) {
		return nil, false
	}
	return sess, true
}

func handleImportChunk(w http.ResponseWriter, r *http.Request, app *App) {
	sess, ok := importSessionFor(w, r, app)
	if !ok {
		return
	}
	if sess.State != "staging" {
		httpJSON(w, http.StatusConflict, map[string]any{
			"error": fmt.Sprintf("import is %s; chunks can only be added while staging", sess.State),
		})
		return
	}
	n, err := strconv.Atoi(r.PathValue("n"))
	if err != nil || n < 0 {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "chunk index must be a non-negative integer"})
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxImportChunkBytes+1)
	written, err := writeImportChunk(app, sess.ID, n, r.Body)
	if err != nil {
		// Only the oversize case is a client problem worth a 413 + the
		// (safe) error text. Every other writeImportChunk failure - mkdir,
		// create-temp, copy, close, rename - is a server-side fault (disk
		// full, permissions) whose wrapped text carries the absolute
		// staging path (e.g. "mkdir /opt/benmore/apps/<sub>/.benmore/...:
		// permission denied"). Sending that verbatim as a 413 both
		// discloses host layout and misleads the client into retrying with
		// smaller chunks, which cannot fix a full disk.
		if errors.Is(err, errImportChunkTooLarge) {
			httpJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": err.Error()})
			return
		}
		log.Printf("IMPORT %s: chunk %d write failed: %v", sess.ID, n, err)
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}
	current, err := loadImportSession(app.DB, sess.ID)
	if err != nil || current.State != "staging" {
		part := filepath.Join(importStagingDir(app, sess.ID), fmt.Sprintf("part-%d", n))
		if rmErr := os.Remove(part); rmErr != nil && !os.IsNotExist(rmErr) {
			log.Printf("IMPORT %s: remove raced chunk %d: %v", sess.ID, n, rmErr)
		}
		httpJSON(w, http.StatusConflict, map[string]any{"error": "import is no longer staging"})
		return
	}

	// Cap the staged total at what the session declared. Without this an
	// authenticated admin can stage unbounded bytes to disk and only find
	// out at commit - a disk-exhaustion vector preflight cannot see,
	// because preflight only ever sees the DECLARED size. Recomputing
	// after the write (rather than before) keeps the idempotent-retry case
	// correct: re-PUTing an existing chunk replaces it rather than adding
	// to the total.
	if staged, serr := stagedBytes(app, sess.ID); serr == nil && staged > sess.BytesTotal {
		os.Remove(filepath.Join(importStagingDir(app, sess.ID), fmt.Sprintf("part-%d", n)))
		httpJSON(w, http.StatusRequestEntityTooLarge, map[string]any{
			"error": fmt.Sprintf("chunk would bring the staged total to %d bytes, past the %d declared for this import", staged, sess.BytesTotal),
		})
		return
	}

	httpJSON(w, http.StatusOK, map[string]any{"chunk": n, "bytes": written})
}

func handleImportCommit(w http.ResponseWriter, r *http.Request, app *App) {
	sess, ok := importSessionFor(w, r, app)
	if !ok {
		return
	}
	if sess.State != "staging" {
		httpJSON(w, http.StatusConflict, map[string]any{
			"error": fmt.Sprintf("import is already %s", sess.State),
		})
		return
	}
	flag := importFlagFor(app)
	if !flag.CompareAndSwap(false, true) {
		httpJSON(w, http.StatusConflict, map[string]any{"error": "an import is already running for this app"})
		return
	}
	started := false
	defer func() {
		if !started {
			flag.Store(false)
		}
	}()
	rollback := func() {
		if _, err := saveImportStateIf(app.DB, sess.ID, "running", "staging", 0, ""); err != nil {
			log.Printf("IMPORT %s: failed to roll back commit state: %v", sess.ID, err)
		}
	}

	// Conditional transition FIRST, BEFORE the byte check - not after, and
	// not an unconditional saveImportState. Two concurrent commits on the
	// SAME import id both pass the state check above (neither has written
	// anything yet). If the byte check ran first: (a) with an unconditional
	// state write, both proceed to startImport, one wins the per-app CAS
	// (importFlagFor), and the loser's failure handler used to
	// unconditionally write the row BACK to "staging" WHILE the winner's
	// goroutine was actively reading the staging directory that "staging"
	// state permits handleImportChunk to append to and handleImportCancel
	// to purge; (b) even switched to a conditional write, the loser could
	// still race the WINNER's own load completing (a tiny file loads in
	// microseconds) and purging its staging directory before the loser's
	// stagedBytes call runs, producing a confusing 400 "staged 0 bytes"
	// instead of a clean 409. Doing the WHERE-guarded UPDATE first makes it
	// the SOLE gate: only the winner ever proceeds past this line for a
	// given row (loser sees rowsAffected==0, backs off 409, never touches
	// the row), so every check after this point runs against a row this
	// handler exclusively owns.
	res, err := app.DB.Exec(
		`UPDATE _benmore_imports SET state='running', rows_loaded=0, error='' WHERE id=? AND state='staging'`,
		sess.ID)
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		httpJSON(w, http.StatusConflict, map[string]any{"error": "import is already committed"})
		return
	}

	staged, err := stagedBytes(app, sess.ID)
	if err != nil {
		// Safe to revert unconditionally on every path below: the
		// WHERE-guarded UPDATE above proved this handler is the exclusive
		// owner of this row's staging->running transition, so nothing else
		// could have moved it since.
		rollback()
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
		return
	}
	if staged != sess.BytesTotal {
		rollback()
		httpJSON(w, http.StatusBadRequest, map[string]any{
			"error":          fmt.Sprintf("staged %d bytes but the session declared %d", staged, sess.BytesTotal),
			"staged_bytes":   staged,
			"declared_bytes": sess.BytesTotal,
		})
		return
	}
	if reason, blocked := checkStorageCap(app, importCommitDiskNeeded(staged, sess.Gzip, sess.UncompressedBytes)); blocked {
		rollback()
		httpJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": "storage cap reached: " + reason})
		return
	}

	// Re-run the disk check against GROUND TRUTH: the create-time
	// preflight (importPreflight) only ever saw a DECLARED byte count and
	// whatever free disk existed minutes-to-hours earlier, before the
	// caller spent that whole window uploading chunks onto the same
	// filesystem it's about to load into. This is the one point that
	// knows both numbers for real - staged (just verified == declared,
	// above) and CURRENT free disk - so it's the only point that can
	// catch "another import (or anything else) ate the disk since
	// create" before committing to a multi-minute load that can't land.
	//
	// importCommitDiskCheck, NOT importDiskCheck: the staged copy is
	// already ON DISK at this point (already reflected in the freeDiskBytes
	// syscall below), so demanding it again as a "staged copy" term
	// double-counts it (MEDIUM-3) - see importCommitDiskNeeded's doc
	// comment for the exact false-rejection band this produced.
	if err := importCommitDiskCheck(app, staged, sess.Gzip, sess.UncompressedBytes); err != nil {
		rollback()
		httpJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": err.Error()})
		return
	}

	// The commit owns the per-app guard from before its state transition;
	// hand that guard to the runner rather than releasing a recovery window.
	startImportWithGuard(app, sess, flag)
	started = true
	httpJSON(w, http.StatusAccepted, map[string]any{
		"import_id":  sess.ID,
		"state":      "running",
		"status_url": "/api/_import/" + sess.ID,
	})
}

func handleImportStatus(w http.ResponseWriter, r *http.Request, app *App) {
	sess, ok := importSessionFor(w, r, app)
	if !ok {
		return
	}
	chunks, _ := receivedChunks(app, sess.ID)
	rows := sess.RowsLoaded
	// A running load reports from memory: its transaction has not
	// committed, so the persisted row count is still zero.
	if live, ok := importProgressOf(sess.ID); ok {
		rows = live
	}
	// sess.Error is surfaced verbatim, including raw driver text such as
	// "NOT NULL constraint failed: strict.n" (see runImport / saveImportState
	// in import_run.go). That is the SQL detail production normally
	// suppresses (security.md control 38), but this endpoint sits behind
	// the same Mode A gate as commit/chunk: only an admin or the table's
	// owner - someone who already has write access to the table and could
	// see its schema through `benmore describe`/`sql` anyway - ever reaches
	// it, and the raw text is the only way that caller can tell WHICH row
	// or column in their file is malformed. Suppressing it here would trade
	// a real usability need for a confidentiality boundary that doesn't
	// exist at this authorization tier. This decision depends on
	// importCallerAuthorized staying at least this strict (admin-or-owner,
	// never a broader "any authenticated write-scoped member") - if that
	// gate is ever relaxed, this passthrough must be revisited.
	httpJSON(w, http.StatusOK, map[string]any{
		"import_id":       sess.ID,
		"table":           sess.TableName,
		"state":           sess.State,
		"rows_loaded":     rows,
		"bytes_total":     sess.BytesTotal,
		"received_chunks": chunks,
		"error":           sess.Error,
	})
}

func handleImportCancel(w http.ResponseWriter, r *http.Request, app *App) {
	sess, ok := importSessionFor(w, r, app)
	if !ok {
		return
	}
	// Refuse a cancel on ANY terminal state, not just "running" (review
	// round 2 minor). Two failure modes without this:
	//   1. Cancelling a "failed" session overwrote state/error to
	//      "cancelled"/"cancelled by caller", destroying the ONLY record
	//      of why a load failed - the CLI's own best-effort cleanup used
	//      to do exactly this on the "failed" poll branch, and any other
	//      REST caller could too. There is also nothing to purge: a
	//      failed load's runImport has already run its own terminal path
	//      (import_run.go).
	//   2. The concurrent-create race: two identical creates can resume
	//      onto the SAME session (the resume fix, round 1); the loser's
	//      commit gets a 409 and calls cancel. If the winner's load has
	//      ALREADY reached "completed" by then, a cancel that doesn't
	//      check for terminal states rewrites the row to "cancelled" /
	//      rows_loaded=0 out from under the winner - so the winner's own
	//      poll reports "Import was cancelled" and exits 1 despite a
	//      fully successful load. Refusing every terminal state (not just
	//      "running") closes this too.
	// "state" is included alongside "error" so a caller can distinguish
	// WHICH terminal state blocked the cancel without a second GET.
	switch sess.State {
	case "running":
		httpJSON(w, http.StatusConflict, map[string]any{
			"error": "import is running; wait for it to finish or fail",
			"state": sess.State,
		})
		return
	case "completed", "failed", "cancelled":
		httpJSON(w, http.StatusConflict, map[string]any{
			"error": fmt.Sprintf("import already %s; nothing to cancel", sess.State),
			"state": sess.State,
		})
		return
	}
	changed, err := saveImportStateIf(app.DB, sess.ID, "staging", "cancelled", 0, "cancelled by caller")
	if err != nil {
		httpError(w, "Server error", http.StatusInternalServerError)
		return
	}
	if !changed {
		current, err := loadImportSession(app.DB, sess.ID)
		if err != nil {
			httpError(w, "Server error", http.StatusInternalServerError)
			return
		}
		httpJSON(w, http.StatusConflict, map[string]any{"error": fmt.Sprintf("import already %s; nothing to cancel", current.State), "state": current.State})
		return
	}
	purgeImportStaging(app, sess.ID)
	httpJSON(w, http.StatusOK, map[string]any{"import_id": sess.ID, "state": "cancelled"})
}
