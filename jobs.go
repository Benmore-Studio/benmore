//go:build !cli

package main

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"
)

// txCommitGuard wraps an in-flight *sql.Tx so it is finalized (rolled back)
// exactly once, even if the caller's stack unwinds via a PANIC between
// Begin() and the caller's own explicit commit/rollback logic.
//
// The pattern: `defer guard.rollbackUnlessHandled()` immediately after
// Begin() - before running any step/flow logic - then call
// guard.MarkHandled() right alongside every explicit Commit()/Rollback()
// call on the normal paths. If a panic unwinds the stack before reaching
// those explicit calls, MarkHandled was never called, so the deferred
// rollbackUnlessHandled fires and finalizes the tx; on the normal
// success/error paths it becomes a no-op.
//
// This closes the gap that both runCronJob (cron.go) and executeFlowJob
// (below) had: a panic inside executeSteps unwound straight past the
// commit/rollback logic to an OUTER recover() (runCronJob's own, or
// processNextJob's top-level one), which only logs the panic - the
// *sql.Tx itself was never finalized. Its connection was never returned to
// the pool, and under SQLite WAL an unreturned write-tx holds the app's
// write lock until restart (review finding). See TestJobTxCommitGuard* in
// jobs_transaction_test.go for a direct regression test of this exact
// panic path.
type txCommitGuard struct {
	tx      *sql.Tx
	handled bool
}

// rollbackUnlessHandled is the function to `defer`. No-op if MarkHandled
// was already called (the normal commit/rollback path ran to completion)
// or if the guard wraps no tx (non-transactional run).
func (g *txCommitGuard) rollbackUnlessHandled() {
	if g == nil || g.tx == nil || g.handled {
		return
	}
	if err := g.tx.Rollback(); err != nil && err != sql.ErrTxDone {
		log.Printf("txCommitGuard: panic-path rollback error: %s", err)
	}
}

// MarkHandled tells the guard the tx has already been explicitly committed
// or rolled back by the normal code path, so the deferred
// rollbackUnlessHandled becomes a no-op. Call it right next to EVERY
// explicit Commit()/Rollback() - including when Commit() itself returns an
// error, since database/sql treats the Tx as done either way and a second
// Rollback attempt would just be a harmless (but confusing) sql.ErrTxDone.
func (g *txCommitGuard) MarkHandled() {
	if g != nil {
		g.handled = true
	}
}

// EnsureJobsTable creates the background jobs table.
func EnsureJobsTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_jobs (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		job_type TEXT NOT NULL DEFAULT 'flow',
		flow_name TEXT NOT NULL DEFAULT '',
		payload TEXT,
		status TEXT DEFAULT 'pending',
		attempts INTEGER DEFAULT 0,
		max_attempts INTEGER DEFAULT 3,
		error TEXT,
		run_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		not_before DATETIME,
		started_at DATETIME,
		completed_at DATETIME,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	db.Exec("CREATE INDEX IF NOT EXISTS idx_jobs_status ON _benmore_jobs(status, run_at)")
	// Add job_type column if upgrading from older schema
	db.Exec("ALTER TABLE _benmore_jobs ADD COLUMN job_type TEXT NOT NULL DEFAULT 'flow'")
	// Capability token for the public status endpoint (v2.7.145). The
	// status_url handed to an async-flow submitter carries this unguessable
	// token; without it a serial job id could be enumerated to read other
	// tenants' (or anonymous) job status + error strings. Best-effort ALTER
	// covers both fresh and upgraded tables.
	db.Exec("ALTER TABLE _benmore_jobs ADD COLUMN status_token TEXT")
	// Lease expiry for in-flight ('running') jobs (H-2). A claimed job carries
	// a lease the worker heartbeats while it runs; if the worker dies the lease
	// expires and a recovery pass can act on the orphan. Without a lease an
	// orphaned 'running' job either sticks forever or (worse) gets blindly
	// re-run. Best-effort ALTER covers fresh + upgraded tables.
	db.Exec("ALTER TABLE _benmore_jobs ADD COLUMN lease_expires_at DATETIME")
	// Optional idempotency/uniqueness key (PR #10). Active jobs (pending/running)
	// sharing a key collapse to the existing job instead of duplicating work
	// (double-click, client retry, redelivered webhook). The partial UNIQUE
	// index enforces this only while a job is active; completed/failed rows
	// release the key. Best-effort ALTER covers fresh + upgraded tables.
	db.Exec("ALTER TABLE _benmore_jobs ADD COLUMN unique_key TEXT")
	db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_unique_active ON _benmore_jobs(unique_key) WHERE unique_key IS NOT NULL AND unique_key != '' AND status IN ('pending', 'running')")
	// Retry gate that preserves ordering (review finding #11). The strictly
	// ordered reconcile chains (sync_project / release_window) guarantee order
	// purely via strictly-increasing PAST run_at on the single serial worker.
	// The old retry path rewrote run_at = now + backoff - a FUTURE time later
	// than every queued `-1 days` stamp - so a transient blip on an early stage
	// let its retry land AFTER the whole chain, running reveal/reconcile on a
	// board missing that source's facts. A failed attempt now keeps its
	// original run_at and instead sets not_before to the backoff time; the
	// claim query treats not_before as a head-of-line gate so the retry stays
	// in its original position and never jumps behind later stages. Best-effort
	// ALTER covers fresh + upgraded tables.
	db.Exec("ALTER TABLE _benmore_jobs ADD COLUMN not_before DATETIME")
	// Partial index over ONLY the pending, backing-off rows (not_before set).
	// processNextJob's scoped ordering gate runs a correlated NOT EXISTS looking
	// for an earlier same-project predecessor that is currently in backoff; that
	// set is normally tiny (backoff happens only on real failures), and this
	// index keeps the subquery from scanning the whole pending backlog to find
	// it. Idempotent; the not_before column exists by now (CREATE + ALTER above).
	db.Exec("CREATE INDEX IF NOT EXISTS idx_jobs_backoff ON _benmore_jobs(run_at) WHERE status = 'pending' AND not_before IS NOT NULL")
	// The claim's NOT EXISTS probes the backing-off rows of the CANDIDATE's
	// project. Indexing the project expression over that same partial set
	// turns the probe into one index seek per candidate instead of a walk of
	// every backing-off row with four json_extract calls each. The expression
	// is guarded by json_valid so a malformed payload can neither fail an
	// UPDATE that moves its row into backoff (index maintenance would raise
	// "malformed JSON") nor error the claim query (it counts as group-less).
	// The claim query must spell the expression identically for SQLite to
	// match the index (jobProjectExprK / jobProjectExprJ).
	db.Exec("CREATE INDEX IF NOT EXISTS idx_jobs_backoff_project ON _benmore_jobs(" + jobProjectExpr("payload") + ", run_at) WHERE status = 'pending' AND not_before IS NOT NULL")
	// Reload can overlap worker generations. Probe the small running set by
	// project without scanning every historical job for each pending candidate.
	if _, err := db.Exec("CREATE INDEX IF NOT EXISTS idx_jobs_running_project ON _benmore_jobs(" + jobProjectExpr("payload") + ") WHERE status = 'running'"); err != nil {
		log.Printf("jobs: running-project index unavailable: %v", err)
	}
}

// jobProjectExpr is the ordering-group expression for a payload column
// reference. It is shared by the expression index and the claim query.
func jobProjectExpr(payloadCol string) string {
	return "(CASE WHEN json_valid(" + payloadCol + ") THEN json_extract(" + payloadCol + ", '$.project_id') END)"
}

var (
	jobProjectExprJ = jobProjectExpr("j.payload")
	jobProjectExprK = jobProjectExpr("k.payload")
)

// jobClaimSQL selects the next claimable job (see processNextJob for the
// ordering-gate semantics). The NOT EXISTS probes use the backoff-project and
// running-project partial indexes. This selection must be part of the atomic
// UPDATE below when actually claiming work.
var jobClaimSQL = `
		SELECT j.id, j.job_type, j.flow_name, j.payload, j.attempts, j.max_attempts
		FROM _benmore_jobs j
		WHERE j.status = 'pending'
		  AND j.run_at <= datetime('now')
		  AND (j.not_before IS NULL OR j.not_before <= datetime('now'))
		  AND NOT EXISTS (
		        SELECT 1 FROM _benmore_jobs k
		         WHERE k.status = 'pending'
		           AND k.run_at <= datetime('now')
		           AND k.not_before IS NOT NULL AND k.not_before > datetime('now')
		           AND ` + jobProjectExprJ + ` IS NOT NULL
		           AND ` + jobProjectExprK + ` IS NOT NULL
		           AND ` + jobProjectExprK + `
		               IS ` + jobProjectExprJ + `
		           AND (k.run_at < j.run_at
		                OR (k.run_at = j.run_at AND k.id < j.id))
		  )
		  AND NOT EXISTS (
		        SELECT 1 FROM _benmore_jobs k
		         WHERE k.status = 'running'
		           AND ` + jobProjectExprJ + ` IS NOT NULL
		           AND ` + jobProjectExprK + ` IS ` + jobProjectExprJ + `
		  )
		ORDER BY j.run_at ASC, j.id ASC
		LIMIT 1
	`

// Claim and group exclusion share SQLite's atomic write statement. RETURNING
// reports the pre-claim attempt count expected by execution/retry bookkeeping.
// QueryRow.Scan closes the returning rows before any job body is executed.
var jobClaimAndStartSQL = `UPDATE _benmore_jobs
	SET status = 'running', started_at = datetime('now'),
	    attempts = attempts + 1, lease_expires_at = ?
	WHERE status = 'pending' AND id = (SELECT id FROM (` + jobClaimSQL + `))
	RETURNING id, job_type, flow_name, payload, attempts - 1, max_attempts`

// defaultJobsLeaseTTL bounds how long a claimed job may run before its lease is
// considered orphaned. The worker heartbeats (extends) the lease on this
// cadence while the job body runs, so a live worker never loses its claim;
// only a crashed/hung worker lets the lease lapse. Sized well above a typical
// hook/flow runtime; long jobs are kept alive by the heartbeat.
const defaultJobsLeaseTTL = 5 * time.Minute

// jobsLeaseTTL resolves the effective lease window, overridable per-deployment
// via the BENMORE_JOB_LEASE_SECONDS env var (the main knob for crash-recovery
// latency: shorter recovers faster but heartbeats more often). Invalid or
// absent values fall back to the 5m default.
func jobsLeaseTTL() time.Duration {
	if v := os.Getenv("BENMORE_JOB_LEASE_SECONDS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return defaultJobsLeaseTTL
}

// jobsHeartbeatInterval is how often the running worker re-extends its lease.
// Must be comfortably below the lease window so a brief stall never drops the
// claim (one third gives two renewal chances before expiry). A 1s floor keeps
// it sane for very short test windows. (H-2: a fixed lease with no heartbeat
// let a second worker re-run any job that outran the lease.)
func jobsHeartbeatInterval() time.Duration {
	hb := jobsLeaseTTL() / 3
	if hb < time.Second {
		hb = time.Second
	}
	return hb
}

// jobsRerunSafeTypes is the allowlist of job types whose side effects are
// idempotent enough to re-run after a worker crash mid-execution (C-1:
// at-least-once delivery). Lease-recovery only requeues these; every other
// type is failed-closed rather than risk a duplicate email / webhook / SQL
// mutation.
//
//   - "flow" / "hook" are NOT here: their bodies can send mail or mutate rows
//     and the framework can't prove a partial run left no trace.
//   - "cron" is NOT here either: a cron body runs the SAME arbitrary flow steps
//     (run: api/email/sql) as a flow job, so it is not categorically safe to
//     re-run. Cron recovery is handled CONDITIONALLY in jobsRecoverOrphanedJobs
//     (only when the cron opted into at-least-once retries with budget left).
//   - "webhook_subscription" is the one genuinely safe entry: subscribers are
//     contractually expected to dedupe deliveries by id/HMAC.
func jobsRerunSafeTypes() map[string]bool {
	safe := map[string]bool{
		"webhook_subscription": true,
	}
	for _, typ := range splitCommaList(os.Getenv("BENMORE_JOB_RERUN_SAFE_TYPES")) {
		if typ != "" {
			safe[typ] = true
		}
	}
	return safe
}

// EnqueueJob adds a flow job to the background queue.
//
// `run_at` is stored in SQLite's `datetime()` text format -
// `2006-01-02 15:04:05` with a literal space separator, no `T`, no
// `Z`. The worker compares it to `datetime('now')` in SQL text-wise:
// using RFC3339 here put `T`(84) where `datetime('now')` puts ` `(32),
// so the lexicographic `<=` check never fired and async-enqueued jobs
// sat forever in `pending` while every hook job (which already used
// `datetime('now')` directly) ran fine.
const sqliteDateTimeLayout = "2006-01-02 15:04:05"

type jobEnqueueExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
	QueryRow(query string, args ...any) *sql.Row
}

// EnqueueJob returns (id, statusToken, error). statusToken is the unguessable
// capability the caller embeds in the status_url so the submitter (authed OR
// anonymous) can poll GET /api/_jobs/{id}/status?token=... without exposing
// every job to id-enumeration.
func EnqueueJob(db *sql.DB, flowName string, payload map[string]any, runAt *time.Time) (int64, string, error) {
	return enqueueTypedJob(db, "flow", "", flowName, payload, runAt, jobEnqueueOpts{})
}

func EnqueueJobUnique(db *sql.DB, uniqueKey, flowName string, payload map[string]any, runAt *time.Time) (int64, string, error) {
	return enqueueTypedJob(db, "flow", uniqueKey, flowName, payload, runAt, jobEnqueueOpts{})
}

func EnqueueJobTx(tx *sql.Tx, flowName string, payload map[string]any, runAt *time.Time) (int64, string, error) {
	return enqueueTypedJob(tx, "flow", "", flowName, payload, runAt, jobEnqueueOpts{})
}

func EnqueueJobTxUnique(tx *sql.Tx, uniqueKey, flowName string, payload map[string]any, runAt *time.Time) (int64, string, error) {
	return enqueueTypedJob(tx, "flow", uniqueKey, flowName, payload, runAt, jobEnqueueOpts{})
}

// EnqueueCronJob enqueues a durable cron run.
//
// maxAttempts is the per-cron retry budget; pass 1 to preserve the
// historical at-most-once behavior (a failing step is NOT retried), or
// >1 to opt into at-least-once retries. See cron.go cronMaxAttempts for
// how a cron definition selects this (review finding #2).
//
// dedupAnyStatus closes the same-minute duplicate-fire window (review
// finding #1): the cron unique_key is minute-specific
// (cron:<id>:<minute>), so the existence of ANY prior row with that key
// - including a `completed` one - means that minute already fired. The
// generic active-only dedup would let a completed row be re-enqueued
// after a restart inside the same minute; for cron we additionally
// collapse against completed/failed rows so a lost last_fire can never
// cause a double fire.
func EnqueueCronJob(db *sql.DB, cronID, uniqueKey string, payload map[string]any, runAt *time.Time, maxAttempts int) (int64, string, error) {
	return enqueueTypedJob(db, "cron", uniqueKey, cronID, payload, runAt, jobEnqueueOpts{
		maxAttempts:    maxAttempts,
		dedupAnyStatus: true,
	})
}

// jobEnqueueOpts carries optional, type-specific enqueue behavior so the
// generic enqueue path stays a single code path.
type jobEnqueueOpts struct {
	// maxAttempts overrides the column DEFAULT (3) when > 0.
	maxAttempts int
	// dedupAnyStatus, when set, treats a matching unique_key in ANY status
	// (including completed/failed) as a duplicate to collapse against.
	dedupAnyStatus bool
}

func enqueueTypedJob(exec jobEnqueueExecer, jobType, uniqueKey, flowName string, payload map[string]any, runAt *time.Time, opts jobEnqueueOpts) (int64, string, error) {
	uniqueKey = strings.TrimSpace(uniqueKey)
	if uniqueKey != "" {
		if id, token, ok := findJobByUniqueKey(exec, uniqueKey, opts.dedupAnyStatus); ok {
			return id, token, nil
		}
	}
	// Surface marshal failures rather than silently enqueuing an
	// empty/partial body: a payload that fails to marshal (e.g. a
	// non-serializable value) would otherwise run the flow with no input.
	data, err := json.Marshal(payload)
	if err != nil {
		return 0, "", fmt.Errorf("marshal job payload: %w", err)
	}
	ra := time.Now()
	if runAt != nil {
		ra = *runAt
	}
	token := generateToken(18)
	// err is already declared by the json.Marshal above; only result is new.
	var result sql.Result
	if opts.maxAttempts > 0 {
		result, err = exec.Exec(
			"INSERT INTO main._benmore_jobs (job_type, flow_name, payload, run_at, status_token, unique_key, max_attempts) VALUES (?, ?, ?, ?, ?, ?, ?)",
			jobType, flowName, string(data), ra.UTC().Format(sqliteDateTimeLayout), token, nullIfEmpty(uniqueKey), opts.maxAttempts,
		)
	} else {
		result, err = exec.Exec(
			"INSERT INTO main._benmore_jobs (job_type, flow_name, payload, run_at, status_token, unique_key) VALUES (?, ?, ?, ?, ?, ?)",
			jobType, flowName, string(data), ra.UTC().Format(sqliteDateTimeLayout), token, nullIfEmpty(uniqueKey),
		)
	}
	if err != nil {
		if uniqueKey != "" && isUniqueJobConstraintErr(err) {
			if id, token, ok := findJobByUniqueKey(exec, uniqueKey, opts.dedupAnyStatus); ok {
				return id, token, nil
			}
			// On the Tx path (*sql.Tx), go-sqlite3 takes a read snapshot at
			// the transaction's first read, so a row committed by a competing
			// transaction AFTER that snapshot is invisible to the recovery
			// SELECT above. We still know the key is held by an active job
			// (the UNIQUE index just rejected our INSERT), so treat this as a
			// successful idempotent no-op rather than surfacing the raw
			// constraint error and failing the whole flow transaction. The id
			// is unknown from inside the stale snapshot, so return 0 / no token;
			// the caller's enqueue is a dedup no-op against the winner. (Tx
			// callers needing the winner's id/token should re-read after commit.)
			if _, isTx := exec.(*sql.Tx); isTx {
				return 0, "", nil
			}
		}
		return 0, "", err
	}
	id, err := result.LastInsertId()
	return id, token, err
}

// mutationJobEnqueuer is implemented by a mutation transaction whose owner must
// learn about, and may stamp, every durable job the mutation queues (a
// connector command records each one as an effect). Anything else queues
// the job as is.
type mutationJobEnqueuer interface {
	enqueueMutationJob(kind, table, action, jobType, flowName string, payload map[string]any) error
}

// enqueueMutationJob queues the job a hook or webhook subscription needs, in
// the mutation's own transaction. kind is "hook" or "webhook".
func enqueueMutationJob(tx mutationTx, kind, table, action, jobType, flowName string, payload map[string]any) error {
	if q, ok := tx.(mutationJobEnqueuer); ok {
		return q.enqueueMutationJob(kind, table, action, jobType, flowName, payload)
	}
	_, _, err := enqueueTypedJob(tx, jobType, "", flowName, payload, nil, jobEnqueueOpts{})
	return err
}

// findJobByUniqueKey looks up an existing job by unique_key. When
// anyStatus is false it only matches active (pending/running) rows - the
// partial-index semantics that let a key be reused once the prior job
// finished. When anyStatus is true it matches a row in any status, used
// by cron's minute-specific keys so a completed run can never be
// re-enqueued for the same minute (review finding #1).
func findJobByUniqueKey(q jobEnqueueExecer, uniqueKey string, anyStatus bool) (int64, string, bool) {
	var id int64
	var token string
	query := `
		SELECT id, COALESCE(status_token, '')
		FROM main._benmore_jobs
		WHERE unique_key = ?
		  AND status IN ('pending', 'running')
		ORDER BY id DESC
		LIMIT 1
	`
	if anyStatus {
		query = `
		SELECT id, COALESCE(status_token, '')
		FROM main._benmore_jobs
		WHERE unique_key = ?
		ORDER BY id DESC
		LIMIT 1
	`
	}
	if err := q.QueryRow(query, uniqueKey).Scan(&id, &token); err != nil {
		return 0, "", false
	}
	// Guard against legacy pre-status_token rows carrying the same key:
	// returning an empty token would make the caller build a status_url the
	// status endpoint rejects. Treat a tokenless row as "no usable dedup hit"
	// so a fresh row (with a token) is inserted instead of handing back a
	// broken status URL.
	if token == "" {
		return 0, "", false
	}
	return id, token, true
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

// isUniqueJobConstraintErr reports whether err is the UNIQUE-constraint
// violation from idx_jobs_unique_active. It matches the typed go-sqlite3 error
// (ErrConstraint + ErrConstraintUnique extended code) rather than scraping the
// error string, which is fragile across driver/SQLite versions and locales.
func isUniqueJobConstraintErr(err error) bool {
	var sqliteErr sqlite3.Error
	if errors.As(err, &sqliteErr) {
		return sqliteErr.Code == sqlite3.ErrConstraint &&
			sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique
	}
	return false
}

// EnqueueHookJob adds a hook execution job to the background queue.
// Hooks are enqueued instead of executed in goroutines - this provides
// durability (survives crashes), retry on failure, and visibility. The row's
// encrypted.yaml values are sealed (sealJobPayloadRow); a job whose row can't
// be sealed is not queued.
func EnqueueHookJob(app *App, hook Hook, table string, row map[string]any) {
	db := app.DB
	payload := hookJobPayload(hook, table, row)
	if err := sealJobPayloadRow(db, app, table, payload); err != nil {
		log.Printf("HOOK [%s] not queued: %s", table, err)
		return
	}
	data, _ := json.Marshal(payload)
	db.Exec(
		"INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at) VALUES ('hook', 'hook', ?, datetime('now'))",
		string(data),
	)
}

// hookJobPayload serializes a Hook + its row into the durable job payload the
// worker later reconstructs via hookFromJobPayload. Every action the Hook can
// carry MUST be represented here or it is silently dropped crossing the queue
// (review finding #1: `sms:` and `ws:` were absent, so those hooks fired,
// reported job success, and did nothing). Keep this in lockstep with
// hookFromJobPayload. The event's table rides along so delivery can tell
// which row columns are hidden (hookDefaultBody).
func hookJobPayload(hook Hook, table string, row map[string]any) map[string]any {
	h := map[string]any{
		"sql":     hook.SQL,
		"webhook": hook.Webhook,
		"body":    hook.Body,
	}
	if table != "" {
		h["table"] = table
	}
	if hook.Email != nil {
		h["email_to"] = hook.Email.To
		h["email_subject"] = hook.Email.Subject
		h["email_template"] = hook.Email.Template
	}
	if hook.Notify != nil {
		h["notify"] = marshalNotifyHook(hook.Notify)
	}
	if hook.SMS != nil {
		h["sms"] = map[string]any{"to": hook.SMS.To, "body": hook.SMS.Body}
	}
	if hook.WS != nil {
		h["ws"] = map[string]any{"room": hook.WS.Room, "payload": hook.WS.Payload}
	}
	return map[string]any{"_hook": h, "_row": row}
}

// StartJobWorker runs a background goroutine that processes pending jobs.
// It exits when app.Stop is closed (hot reload / shutdown) so a build
// session's many pushes don't leave a pile of duplicate workers behind -
// pre-fix the loop had no Stop select and was re-spawned by buildAppMux on
// every SIGHUP, so N pushes meant N+1 concurrent workers all racing to
// claim the same jobs. Adaptive cadence: drain back-to-back while the queue
// is non-empty, idle at 1s when empty (the old fixed 1s sleep capped
// throughput at one job/second regardless of backlog).
//
// The worker is tracked (app.startJobRunner), so a `serve` process's
// Shutdown lets the job in progress finish (up to jobDrainTimeout) before it
// closes the database. Untracked, a restart closed the database under the
// running job: its remaining steps failed, its final status write failed
// with them, and the row stayed 'running' until lease recovery marked it
// failed as a crash.
func StartJobWorker(app *App) {
	EnsureJobsTable(app.DB)

	app.startJobRunner("jobs.worker", func(stop <-chan struct{}) {
		recoverCheck := time.NewTicker(jobsHeartbeatInterval())
		defer recoverCheck.Stop()
		jobsRecoverOrphanedJobs(app) // sweep stale leases left by a previous crash on startup
		for {
			select {
			case <-stop:
				return
			default:
			}
			if processNextJob(app) {
				continue // a job ran - more may be queued, drain without sleeping
			}
			select {
			case <-stop:
				return
			case <-recoverCheck.C:
				// Periodically reclaim jobs whose worker died mid-flight.
				jobsRecoverOrphanedJobs(app)
			case <-time.After(1 * time.Second):
			}
		}
	})

	log.Printf("  jobs: background worker started")
}

// serveJobDrainTimeout is how long a single-app `serve` process's Shutdown
// waits for the job or scheduled flow in progress. The hosted unit's
// TimeoutStopSec is 15s and the HTTP drain before it is usually immediate.
const serveJobDrainTimeout = 8 * time.Second

// jobsRecoverRequeueGuard limits a crash requeue to jobs with attempts left.
// attempts is counted at claim, so a job whose body kills the process (an
// out-of-memory step, a hung upstream past the lease) exhausts max_attempts
// instead of being claimed, crashing the worker and requeued forever.
const jobsRecoverRequeueGuard = " AND attempts < max_attempts"

// jobsRecoverOrphanedJobs handles 'running' jobs whose lease has expired - the
// signature of a worker that crashed mid-execution.
//
// C-1 invariant (at-least-once vs duplicate side effects): the job body runs
// OUTSIDE the claim transaction, so we cannot know whether a crashed job's
// emails/webhooks/mutations already fired. Re-running could duplicate them.
// We therefore fail CLOSED: only job types on the jobsRerunSafeTypes allowlist
// (proven idempotent) are requeued to 'pending'; all others are marked
// 'failed' with an explanatory error so an admin can inspect/retry rather than
// risk a silent duplicate delivery.
func jobsRecoverOrphanedJobs(app *App) {
	now := time.Now().UTC().Format(sqliteDateTimeLayout)
	// Requeue only the safe-to-rerun types.
	for jobType := range jobsRerunSafeTypes() {
		app.DB.Exec(
			"UPDATE _benmore_jobs SET status = 'pending', lease_expires_at = NULL WHERE status = 'running' AND job_type = ? AND lease_expires_at IS NOT NULL AND lease_expires_at < ?"+jobsRecoverRequeueGuard+" AND json_valid(payload) = 1 AND json_type(payload, '$._mcp_effect') IS NULL",
			jobType, now,
		)
	}
	for _, flowName := range idempotentFlowJobNames(app) {
		app.DB.Exec(
			"UPDATE _benmore_jobs SET status = 'pending', lease_expires_at = NULL WHERE status = 'running' AND job_type = 'flow' AND flow_name = ? AND lease_expires_at IS NOT NULL AND lease_expires_at < ?"+jobsRecoverRequeueGuard,
			flowName, now,
		)
	}
	// Cron jobs run arbitrary flow steps, so they're only re-run when the cron
	// definition opted into at-least-once retries (max_attempts > 1) AND has
	// retry budget left. An at-most-once cron (max_attempts == 1) falls through
	// to the fail-closed sweep below so a partial side effect isn't duplicated;
	// it will fire again on its next schedule anyway.
	app.DB.Exec(
		"UPDATE _benmore_jobs SET status = 'pending', lease_expires_at = NULL WHERE status = 'running' AND job_type = 'cron' AND max_attempts > 1 AND attempts < max_attempts AND lease_expires_at IS NOT NULL AND lease_expires_at < ?",
		now,
	)
	// Everything else: fail closed rather than re-run a non-idempotent body.
	res, err := app.DB.Exec(
		"UPDATE _benmore_jobs SET status = 'failed', error = 'worker died mid-execution; not re-run to avoid duplicate side effects (C-1)', completed_at = datetime('now') WHERE status = 'running' AND lease_expires_at IS NOT NULL AND lease_expires_at < ?",
		now,
	)
	if err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			log.Printf("jobs: failed %d orphaned job(s) with expired lease (worker crash; not re-run to avoid duplicate side effects)", n)
		}
	}
}

func idempotentFlowJobNames(app *App) []string {
	if app == nil {
		return nil
	}
	app.mu.RLock()
	flows := append([]Flow(nil), app.Flows...)
	app.mu.RUnlock()
	var names []string
	for _, flow := range flows {
		if flow.Idempotent {
			names = append(names, flow.Name)
		}
	}
	return names
}

// processNextJob claims and runs at most one job. Returns true if a job was
// claimed (so the caller can drain a backlog without idling).
func processNextJob(app *App) (worked bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("JOB WORKER PANIC: %v", r)
		}
	}()

	// Claim the next CLAIMABLE pending job. A job is claimable when it is due
	// (run_at has arrived), it is not itself still in retry backoff (not_before
	// has passed), and no earlier-ordered predecessor IN ITS OWN ordering group
	// is still backing off. A currently running member also holds its group
	// until it reaches a terminal/retry state. ORDER BY run_at ASC picks the
	// head of line among the claimable set.
	var id int64
	var jobType, flowName, payload string
	var attempts, maxAttempts int

	// Ordering gate (review finding #11), SCOPED to the ordering group (fix for
	// the #186 head-of-line stall). #186's strict retry ordering is only
	// required WITHIN a single reconcile chain, never across the whole shared
	// `_benmore_jobs` queue. Every genuinely-ordered reconcile chain is stamped
	// with its project_id in the payload - sync_project / release_window /
	// enqueue_extraction / sync_all_projects / blueprint_sync all enqueue via
	// `json_object('project_id', …)` (verified) - so the ordering GROUP is that
	// project_id, extracted from the payload JSON.
	//
	// A NULL project_id means "not part of any ordered chain", and such a job
	// can NEITHER gate NOR be gated:
	//   - `k.project_id IS NOT NULL` in the predecessor filter means a
	//     group-less job (hook, transcribe-brief async flow, webhook_subscription
	//     delivery, cron) NEVER forms an ordering gate, so a backing-off one of
	//     those can't freeze hook/notification/email delivery sharing the NULL
	//     bucket. This was the real residual: transcribe-brief (payload
	//     {submission_id,user_id}, ~90s terminal backoff when whisper/ffmpeg is
	//     absent) and webhook_subscription (max_attempts=3, backs off on a dead
	//     5xx subscriber) both sit in the NULL bucket with hooks.
	//   - `j.project_id IS NOT NULL` inside the NOT EXISTS short-circuits the
	//     whole gate for a group-less CANDIDATE, so it is always claimable
	//     (subject only to its own not_before) and never blocked by anyone.
	// The two together mean the gate applies ONLY among jobs sharing the SAME
	// NON-NULL project_id. Groups are matched with SQLite's `IS` (not `=`) so a
	// robustly-typed compare of two identical project_ids holds regardless of
	// json_extract's storage class.
	//
	// Effect: a backing-off job gates ONLY the later-ordered jobs of its OWN
	// project. A hook, a transcribe-brief/webhook job, a DIFFERENT project's
	// chain, or any group-less flow stays claimable instead of stalling behind a
	// poison job for the whole backoff window (~90s/attempt, worse during an
	// upstream outage). Pre-fix the gate keyed off the GLOBAL head-of-line, so
	// one backing-off pipeline job - perpetually the smallest run_at, stamped
	// `-1 day` - froze chat/notification hooks, emails, and every other job.
	// The selection and transition are one write statement: an overlapping
	// worker cannot claim another member of the same project from a stale
	// pre-claim view. Even an expired running lease holds the group until the
	// existing orphan-recovery policy transitions that row; expiry alone does
	// not authorize concurrent external effects.
	leaseUntil := time.Now().Add(jobsLeaseTTL()).UTC().Format(sqliteDateTimeLayout)
	if err := app.DB.QueryRow(jobClaimAndStartSQL, leaseUntil).Scan(&id, &jobType, &flowName, &payload, &attempts, &maxAttempts); err != nil {
		return false // no due claimable job, or a transient database refusal
	}

	// H-2: heartbeat the lease while the job body runs so a job that legitimately
	// outruns jobsLeaseTTL is not treated as orphaned and re-run concurrently by
	// a second worker. The heartbeat stops as soon as the body returns.
	defer startJobLeaseHeartbeat(app, id)()

	// Malformed persisted input cannot become an empty, successful job. A
	// retry cannot repair the bytes, so finish it as failed before any handler
	// or effect bookkeeping sees partially decoded values. JSON null remains
	// valid because enqueueTypedJob produces it for a nil payload map.
	var data map[string]any
	var jobErr error
	if err := json.Unmarshal([]byte(payload), &data); err != nil {
		jobErr = jobNotRetryable{errors.New("invalid job payload: expected a JSON object or null")}
		data = nil
	}
	if data == nil {
		data = make(map[string]any)
	}

	// A job queued by a connector command carries the grant that committed it:
	// it runs only while that grant and the app's authority are still current.
	if jobErr == nil {
		appMCPRecordEffectAttempt(app, data, attempts > 0)
		jobErr = appMCPEffectGate(app, data)
	}

	switch {
	case jobErr != nil:
	case jobType == "hook":
		jobErr = executeHookJob(app, data)
	case jobType == "cron":
		jobErr = executeCronJob(app, flowName, data)
	case jobType == "webhook_subscription":
		jobErr = executeWebhookSubscriptionJob(data, app)
	case jobType == appMCPTransferJobType:
		jobErr = appMCPDeliverExternalTransfer(app, id, data)
	default: // "flow"
		if run := testJobExecutors[jobType]; run != nil {
			jobErr = run(app, flowName, data)
			break
		}
		jobErr = executeFlowJob(app, flowName, data)
	}

	// Every terminal/transition below clears lease_expires_at so a finished or
	// requeued job is never mistaken for an orphan by jobsRecoverOrphanedJobs.
	if jobErr != nil {
		var final jobNotRetryable
		if attempts+1 >= maxAttempts || errors.As(jobErr, &final) {
			res, updateErr := app.DB.Exec("UPDATE _benmore_jobs SET status = 'failed', error = ?, completed_at = datetime('now'), lease_expires_at = NULL WHERE id = ? AND status = 'running' AND attempts = ?",
				jobErr.Error(), id, attempts+1)
			if updateErr == nil {
				if changed, _ := res.RowsAffected(); changed == 1 {
					appMCPRecordEffectTelemetry(app, data, appMCPJobEffectOutcome(jobErr), 1)
				}
			}
			log.Printf("JOB FAILED [%s/%s] #%d: %s (no more retries)", jobType, flowName, id, jobErr)
		} else {
			// LOWER: cap the backoff shift so a high attempt count can't overflow
			// the shift (1<<attempts wraps negative around attempt 58 -> a
			// negative/zero duration -> hot retry loop). Cap at 2^16 * 30s (~22d).
			shift := uint(attempts)
			if shift > 16 {
				shift = 16
			}
			backoff := time.Duration(1<<shift) * 30 * time.Second
			// Preserve run_at (review finding #11): the strictly-ordered
			// reconcile chains order jobs by run_at on the single serial
			// worker, so re-stamping run_at to a future time would let this
			// retry land AFTER the whole chain. Keep the original run_at and
			// gate the re-claim with not_before instead - the head-of-line
			// check in the claim query keeps the retry in its original slot.
			notBefore := time.Now().Add(backoff)
			app.DB.Exec("UPDATE _benmore_jobs SET status = 'pending', error = ?, not_before = ?, lease_expires_at = NULL WHERE id = ? AND status = 'running' AND attempts = ?",
				jobErr.Error(), notBefore.UTC().Format(sqliteDateTimeLayout), id, attempts+1)
			log.Printf("JOB RETRY [%s/%s] #%d: %s (attempt %d, not_before %s)", jobType, flowName, id, jobErr, attempts+1, notBefore.Format("15:04:05"))
		}
	} else {
		res, updateErr := app.DB.Exec("UPDATE _benmore_jobs SET status = 'completed', completed_at = datetime('now'), lease_expires_at = NULL WHERE id = ? AND status = 'running' AND attempts = ?", id, attempts+1)
		if updateErr == nil {
			if changed, _ := res.RowsAffected(); changed == 1 {
				appMCPRecordEffectTelemetry(app, data, appMCPJobEffectOutcome(nil), 1)
			}
		}
	}
	return true
}

// flowJobActorLive re-checks, when the job runs, the account an async flow
// was queued for. The request's gates (auth, role, permissions, tenant) ran
// at enqueue, but the job can run much later (a backlog, retries with
// backoff, crash requeue): an account deactivated, forced to replace its
// password (a reset after a compromise) or deleted in the meantime must not
// have work done under its identity, a role- or permission-gated flow needs
// the role or permission to still be held, and the tenant the job was queued
// in (user_group_id) holds for a non-admin only while the account's
// membership is live - the rule a request applies to a session's tenant.
// jobNotRetryable marks a job error that a retry can't change (the job
// fails at once instead of backing off max_attempts times).
type jobNotRetryable struct{ error }

func (e jobNotRetryable) Unwrap() error { return e.error }

func flowJobActorLive(app *App, flow *Flow, saved *flowJobActorSnapshot, data map[string]any) (*Session, error) {
	actor, err := flowJobActorCheck(app, flow, saved, data)
	if err != nil {
		return nil, jobNotRetryable{err}
	}
	return actor, nil
}

func flowJobActorCheck(app *App, flow *Flow, saved *flowJobActorSnapshot, data map[string]any) (*Session, error) {
	userID := saved.UserID
	actor := &Session{UserID: userID}
	var deactivated sql.NullString
	var verified, grandfathered int
	err := app.DB.QueryRow("SELECT COALESCE(email,''), COALESCE(role,'user'), deactivated_at, COALESCE(verified,0), COALESCE(email_grandfathered,0) FROM _benmore_users WHERE id=? AND COALESCE(password_change_required,0)=0", userID).
		Scan(&actor.Email, &actor.Role, &deactivated, &verified, &grandfathered)
	if err != nil {
		return nil, fmt.Errorf("the account this job was queued for is missing or must replace its password; not run")
	}
	if deactivated.Valid && deactivated.String != "" {
		return nil, fmt.Errorf("the account this job was queued for is deactivated; not run")
	}
	if app.Design != nil && app.Design.Auth["require_verified"] == "true" && verified != 1 {
		return nil, fmt.Errorf("the account this job was queued for is not verified; not run")
	}
	actor.Verified, actor.EmailGrandfathered = verified == 1, grandfathered == 1
	if gid, ok := data["user_group_id"].(string); ok {
		actor.GroupID = gid
	}
	actor.GlobalAdmin = actor.Role == "admin" || UserHasGlobalAdminGrant(app.DB, userID)
	if saved.Version != 0 {
		actor.GroupID, actor.ActingAsGroup = saved.GroupID, saved.ActingAsGroup
		actor.Scopes, actor.CredentialScopes = saved.Scopes, saved.CredentialScopes
		actor.connectorGrant = saved.ConnectorGrant
		actor.ImpersonatorUserID, actor.ImpersonatorEmail = saved.ImpersonatorUserID, saved.ImpersonatorEmail
		// A promotion after enqueue must not make the queued credential an
		// administrator. Current grants may only narrow the saved authority.
		actor.GlobalAdmin = actor.GlobalAdmin && saved.GlobalAdmin
		if actor.Role == "admin" && !saved.GlobalAdmin {
			actor.Role = ""
		}
		if saved.ActingAsGroup != "" && !actor.IsAdmin() {
			return nil, fmt.Errorf("the account this job was queued for can no longer act as its tenant; not run")
		}
	} else {
		// Legacy payloads cannot prove they were direct, unscoped sign-ins.
		actor.connectorGrant = true
	}
	// A non-admin keeps the job's tenant only if a request by the account
	// would still be in it: getSession keeps a cached tenant while its
	// membership is live and otherwise re-resolves one by email. An admin
	// keeps the tenant it worked in.
	if g := app.Group; actor.GroupID != "" && g != nil && g.Table != "" && g.UserField != "" && !actor.IsAdmin() &&
		!groupMembershipLive(app.DB, g, actor, actor.GroupID) && ResolveGroupID(app.DB, g, actor.Email) != actor.GroupID {
		return nil, fmt.Errorf("the account this job was queued for is no longer a member of the job's tenant; not run")
	}
	actor.Roles = LoadSessionRoles(app.DB, userID, actor.Role, actor.EffectiveGroupID())
	actor, err = applySessionRoleScopesWith(app, app.DB, actor, "")
	if err != nil {
		return nil, fmt.Errorf("reload queued flow actor roles: %w", err)
	}
	if saved.Version != 0 {
		kept := make([]string, 0, len(actor.Roles))
		for _, live := range actor.Roles {
			for _, original := range saved.Roles {
				if live == original {
					kept = append(kept, live)
					break
				}
			}
		}
		actor.Roles = kept
		if !slices.Contains(kept, actor.Role) {
			actor.Role = ""
		}
		if app.Roles != nil {
			actor.accessTables = app.Roles.accessTables
			if roleScopes := app.Roles.ResolveScopesForRoles(kept); roleScopes != "" {
				actor.Scopes = intersectScopes(actor.Scopes, roleScopes)
			} else {
				actor.Scopes = "_none_:read"
			}
			actor.Permissions = strings.Fields(actor.Scopes)
		}
	}
	if flow.Role != "" && !HasAnyRole(actor, []string{flow.Role}) {
		return nil, fmt.Errorf("the account this job was queued for no longer holds role %q; not run", flow.Role)
	}
	if len(flow.Permissions) > 0 && !scopesWithin(actor.Scopes, strings.Join(flow.Permissions, " ")) {
		return nil, fmt.Errorf("the account this job was queued for no longer holds the flow's permissions; not run")
	}
	return actor, nil
}

// startJobLeaseHeartbeat extends a claimed job's lease until the returned
// stop function is called (when the job body returns). It deliberately does
// not listen on app.Stop: a hot reload closes that channel while the old
// worker is still running this job to completion, and a heartbeat that quit
// there let the lease lapse under a live job, so the new generation's
// recovery sweep failed it - or requeued it (webhook deliveries, idempotent
// flows, retrying crons) and ran it a second time concurrently.
func startJobLeaseHeartbeat(app *App, id int64) func() {
	done := make(chan struct{})
	safeGo(fmt.Sprintf("jobs.heartbeat:%d", id), func() {
		ticker := time.NewTicker(jobsHeartbeatInterval())
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				next := time.Now().Add(jobsLeaseTTL()).UTC().Format(sqliteDateTimeLayout)
				app.DB.Exec("UPDATE _benmore_jobs SET lease_expires_at = ? WHERE id = ? AND status = 'running'", next, id)
			}
		}
	})
	return func() { close(done) }
}

// testJobExecutors lets tests run a job body they control (a job that blocks
// until released) through the real claim/heartbeat/finish path. Empty in
// production; job types never reach it from a payload.
var testJobExecutors = map[string]func(app *App, flowName string, data map[string]any) error{}

func executeFlowJob(app *App, flowName string, data map[string]any) error {
	var targetFlow *Flow
	// Snapshot app.Flows under the lock: reloadAppConfig reassigns it on hot
	// reload, and this is the busiest reader (every flow job + the scheduler
	// sweeper). Reading the field while it's reassigned is a data race.
	app.mu.RLock()
	flows := app.Flows
	app.mu.RUnlock()
	for _, flow := range flows {
		if flow.Name == flowName {
			f := flow
			targetFlow = &f
			break
		}
	}
	if targetFlow == nil {
		return fmt.Errorf("flow not found: %s", flowName)
	}
	if targetFlow.Command != nil || targetFlow.Trigger.Type == "command" {
		return fmt.Errorf("command declarations cannot execute as ordinary jobs")
	}

	// An async HTTP flow's payload is request input; restore its taint set so
	// the sql_dynamic guard sees what the synchronous path would have.
	requestKeys := takeFlowRequestKeys(data)
	secretKeys := takeFlowSecretKeys(data)
	actor, err := takeFlowJobActor(data)
	if err != nil {
		return jobNotRetryable{err}
	}
	var session *Session
	if actor != nil {
		session, err = flowJobActorLive(app, targetFlow, actor, data)
		if err != nil {
			return err
		}
	}
	ctx := &FlowContext{
		App:         app,
		Data:        data,
		Params:      make(map[string]string),
		RequestKeys: requestKeys,
		SecretKeys:  secretKeys,
		Session:     session,
		Writes:      newFlowWriteLog(),
	}
	// Mirror scalar Data values into Params so `:name` placeholders +
	// any code path that reads from ctx.Params (interpolateCtxSafe's
	// first pass, role checks, etc.) sees the same values the HTTP
	// handler would have populated. Complex values (slice/map) are
	// JSON-encoded - mirrors the JSON-body path in executeFlowHTTP.
	for k, v := range data {
		switch val := v.(type) {
		case string:
			ctx.Params[k] = val
		case bool, float64, int, int64:
			ctx.Params[k] = fmt.Sprintf("%v", val)
		default:
			if b, err := json.Marshal(v); err == nil {
				ctx.Params[k] = string(b)
			}
		}
	}
	// guard guarantees the *sql.Tx is finalized exactly once on every path -
	// success (commit), step failure (rollback), AND a panic inside
	// executeSteps. See the txCommitGuard doc comment above for the full
	// rationale; registered immediately after Begin(), before executeSteps,
	// so it fires during panic unwinding before the panic reaches
	// processNextJob's top-level recover().
	var guard *txCommitGuard
	if targetFlow.Transaction {
		tx, err := app.DB.Begin()
		if err != nil {
			return fmt.Errorf("begin transaction: %w", err)
		}
		ctx.Tx = tx
		guard = &txCommitGuard{tx: tx}
		defer guard.rollbackUnlessHandled()
	}

	executeSteps(ctx, targetFlow.Steps)
	if ctx.Tx != nil {
		if ctx.Error != nil {
			rbErr := ctx.Tx.Rollback()
			guard.MarkHandled()
			if rbErr != nil && rbErr != sql.ErrTxDone {
				log.Printf("job flow %s: tx rollback error: %s", flowName, rbErr)
			}
			announceFlowWrites(ctx, false)
			return ctx.Error
		}
		commitErr := ctx.Tx.Commit()
		// Whether Commit succeeded or failed, the tx is done from
		// database/sql's perspective - mark handled either way so the
		// deferred guard never double-calls Rollback/Commit.
		guard.MarkHandled()
		announceFlowWrites(ctx, commitErr == nil)
		if commitErr != nil {
			return fmt.Errorf("commit transaction: %w", commitErr)
		}
		return nil
	}
	announceFlowWrites(ctx, false)
	return ctx.Error
}

func executeHookJob(app *App, data map[string]any) error {
	hookData, _ := data["_hook"].(map[string]any)
	if hookData == nil {
		return fmt.Errorf("missing _hook in payload")
	}
	table, _ := hookData["table"].(string)
	rowData, err := openJobPayloadRow(app, data, table)
	if err != nil {
		return err
	}
	if rowData == nil {
		rowData = make(map[string]any)
	}

	hook := hookFromJobPayload(hookData)
	_, commandEffect := data[appMCPEffectKey]

	// Refuse ambiguous tenant routing before running any hook effect.
	if hook.WS != nil && app.Group != nil && app.Group.Key != "" {
		group := rowData[app.Group.Key]
		if group == nil || fmt.Sprint(group) == "" || fmt.Sprint(group) == "0" {
			return fmt.Errorf("ws hook requires the row's tenant key %q", app.Group.Key)
		}
	}
	if err := executeHookResult(app, hook, table, rowData); err != nil && commandEffect {
		// A connector-command effect is never reported delivered without evidence,
		// and a partial run is never retried (that could send twice).
		return webhookDeliveryError(err, true)
	}
	// Use the same schema-aware SQL target recognition as transactional
	// hooks. The prefix-only extractor missed auto-membership SQL because
	// it starts with a marker comment and quotes its destination table.
	// Publication remains unscoped: the dispatcher enforces each reader's
	// live credential, read scope and named/tableless event visibility.
	if hook.SQL != "" {
		app.mu.RLock()
		targets := canonicalHookRefreshTargets(app, hook.SQL, "")
		app.mu.RUnlock()
		for _, table := range targets {
			BroadcastUnscoped(app, table, "refresh")
		}
	}
	return nil
}

// hookFromJobPayload reconstructs a Hook from the serialized `_hook` map a hook
// job carries. Keep in lockstep with hookJobPayload: every action serialized
// there MUST be rebuilt here, or the worker silently drops it (review finding
// #1 - the missing `sms`/`ws` branches meant those hooks fired and sent
// nothing).
func hookFromJobPayload(hookData map[string]any) Hook {
	hook := Hook{
		SQL:     hookPayloadStr(hookData["sql"]),
		Webhook: hookPayloadStr(hookData["webhook"]),
		Body:    hookPayloadStr(hookData["body"]),
	}

	if to, ok := hookData["email_to"]; ok && to != nil {
		hook.Email = &EmailHook{
			To:       fmt.Sprintf("%v", to),
			Subject:  fmt.Sprintf("%v", hookData["email_subject"]),
			Template: fmt.Sprintf("%v", hookData["email_template"]),
		}
	}

	if notifyRaw, ok := hookData["notify"]; ok && notifyRaw != nil {
		if notifyMap, ok := notifyRaw.(map[string]any); ok {
			hook.Notify = unmarshalNotifyHook(notifyMap)
		}
	}

	if smsRaw, ok := hookData["sms"]; ok && smsRaw != nil {
		if m, ok := smsRaw.(map[string]any); ok {
			hook.SMS = &SMSHook{
				To:   hookPayloadStr(m["to"]),
				Body: hookPayloadStr(m["body"]),
			}
		}
	}

	if wsRaw, ok := hookData["ws"]; ok && wsRaw != nil {
		if m, ok := wsRaw.(map[string]any); ok {
			hook.WS = &WSHook{
				Room:    hookPayloadStr(m["room"]),
				Payload: hookPayloadStr(m["payload"]),
			}
		}
	}

	return hook
}

// hookPayloadStr coerces a JSON-decoded payload value to a string, mapping both
// a missing key and an explicit null to "" (not Go's "<nil>", which would leak
// into interpolated SQL / message bodies).
func hookPayloadStr(v any) string {
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// FlushJobs processes all pending jobs synchronously. Used in tests to
// drain the job queue before assertions on async hook side effects.
//
// DELIBERATE TEST-ONLY DIVERGENCE FROM THE PRODUCTION CLAIM PATH: `flush:
// "jobs"` means "run everything that is DUE NOW". The production worker
// (processNextJob) honours the review-finding-#11 ordering gate - it refuses to
// claim a job while an earlier-ordered predecessor in the SAME ordering group
// (project_id) is still in its retry backoff (not_before in the future) - and
// WAITS for not_before to elapse. A synchronous test cannot wait (backoff
// starts at 30s and grows), so once processNextJob can claim NOTHING (every due
// job is gated by its own group) we FAST-FORWARD the earliest gated job's
// not_before to now and re-drain instead of stopping. This keeps the drain
// deterministic: any unrelated job that failed once and is sitting in backoff
// (e.g. an async transcribe job with no whisper model in CI) can no longer
// wedge the queue and silently swallow a later test's hook side effects.
//
// Ordering is still preserved WITHIN a drain. We fast-forward ONLY the earliest
// gated due job (smallest run_at among the due, gated rows) - never the whole
// set - and processNextJob's claim query always picks the smallest run_at first
// within a group, so a gated head still executes BEFORE any later-run_at job in
// its group once it is unblocked (the strict-chain guarantee
// TestRetryDoesNotReorderStrictChain pins). The worker's production claim path
// is untouched.
func FlushJobs(app *App) {
	for {
		var count int64
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_jobs WHERE status = 'pending' AND run_at <= datetime('now')").Scan(&count)
		if count == 0 {
			return
		}
		if processNextJob(app) {
			continue
		}
		// processNextJob claimed nothing while jobs are due (count > 0): every due
		// job is gated by an earlier-ordered same-group predecessor in retry
		// backoff. Fast-forward the single earliest-run_at gated job so `flush`
		// can proceed. Targeting the earliest gated row (ORDER BY run_at ASC LIMIT
		// 1) - not every gated row - is what keeps strict-chain ordering intact
		// across the drain.
		res, err := app.DB.Exec(`
			UPDATE _benmore_jobs SET not_before = NULL
			WHERE id = (
				SELECT id FROM _benmore_jobs
				WHERE status = 'pending' AND run_at <= datetime('now')
				  AND not_before IS NOT NULL AND not_before > datetime('now')
				ORDER BY run_at ASC LIMIT 1
			)`)
		if err != nil {
			return
		}
		// Nothing was gated to fast-forward yet processNextJob still claimed
		// nothing (e.g. a transient claim error): stop rather than spin.
		if n, _ := res.RowsAffected(); n == 0 {
			return
		}
	}
}

// CleanOldJobs prunes old jobs hourly (pruneOldJobs). Exits on app.Stop
// so it isn't re-spawned-without-end on every hot reload.
func CleanOldJobs(app *App) {
	app.startWorker("jobs.cleanup", func(stop <-chan struct{}) {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				pruneOldJobs(app.DB)
			}
		}
	})
}

// pruneOldJobs removes completed jobs after 7 days and failed jobs after 30
// (a payload holds the whole written row or the flow's enqueue values). A
// failed connector-command effect is kept: its row is the evidence the
// operation's effect status reads (a missing row reads as unknown, not
// failed or blocked), and push reconciliation reads failed transfer jobs.
func pruneOldJobs(db *sql.DB) {
	db.Exec("DELETE FROM _benmore_jobs WHERE status = 'completed' AND completed_at < datetime('now', '-7 days')")
	db.Exec("DELETE FROM _benmore_jobs WHERE status = 'failed' AND COALESCE(completed_at, created_at) < datetime('now', '-30 days') AND job_type != ? AND NOT "+jobRetryIsEffectSQL, appMCPTransferJobType)
}

// jobPayloadRedacted replaces a protected value in a job payload read back.
const jobPayloadRedacted = "[redacted]"

// redactJobPayloadForRead returns a job's payload for an admin or agent to
// read (GET /api/_jobs/{id}, describe_jobs). The stored payload is what
// delivery uses and is never changed, so hooks, webhooks and flows get the
// row they were queued with; but that copy holds every column of the
// written row - hidden credential columns, decrypted encrypted fields - and
// enqueue values derived from env, none of which an admin can otherwise
// read. Every map in the payload (the `_row` of a hook or webhook job, the
// top level of a flow job, nested objects) loses the values of keys named
// like a hidden column (appSecretColumn, `old_` deltas and dotted paths
// included), encrypted-field columns of any table and blind-index siblings,
// and a flow job loses the values its __benmore_secret_keys marks. The table
// a row came from is not recorded, so a name hidden in any table is redacted
// everywhere. A payload that is not a JSON object is withheld whole.
func redactJobPayloadForRead(app *App, payload any) any {
	if payload == nil {
		return nil
	}
	text, ok := payload.(string)
	if !ok || text == "" {
		return jobPayloadRedacted
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	var doc map[string]any
	if err := decoder.Decode(&doc); err != nil || doc == nil {
		return jobPayloadRedacted
	}
	marked := map[string]bool{}
	if list, ok := doc[flowSecretKeysPayloadField].([]any); ok {
		for _, k := range list {
			if s, ok := k.(string); ok {
				marked[s] = true
			}
		}
	}
	var redact func(m map[string]any, top bool)
	redact = func(m map[string]any, top bool) {
		for k, v := range m {
			if (top && marked[k]) || jobPayloadHiddenKey(app, k) {
				m[k] = jobPayloadRedacted
				continue
			}
			switch child := v.(type) {
			case map[string]any:
				redact(child, false)
			case []any:
				for _, item := range child {
					if im, ok := item.(map[string]any); ok {
						redact(im, false)
					}
				}
			}
		}
	}
	redact(doc, true)
	out, err := json.Marshal(doc)
	if err != nil {
		return jobPayloadRedacted
	}
	return string(out)
}

// jobPayloadHiddenKey reports whether a payload key names a column whose
// value no read surface returns: hidden by name, encrypted in any table, or
// a blind-index sibling.
func jobPayloadHiddenKey(app *App, key string) bool {
	if i := strings.LastIndexByte(key, '.'); i >= 0 {
		key = key[i+1:]
	}
	key = strings.TrimPrefix(key, "old_")
	if appSecretColumn(nil, "", key) || strings.HasSuffix(key, blindColSuffix) {
		return true
	}
	if app != nil && app.Encrypted != nil {
		for _, defs := range app.Encrypted.Fields {
			for _, def := range defs {
				if strings.EqualFold(def.Column, key) {
					return true
				}
			}
		}
	}
	return false
}

// jobRetryIsEffectSQL is 1 for a job queued by a connector command (its
// payload carries _mcp_effect), else 0.
const jobRetryIsEffectSQL = "(CASE WHEN json_valid(payload) = 1 THEN json_type(payload, '$._mcp_effect') IS NOT NULL ELSE 0 END)"

// RegisterJobsAPI sets up job visibility and management endpoints.
func RegisterJobsAPI(mux appRouteRegistrar, app *App) {
	// GET /api/_jobs - list jobs (admin only)
	mux.HandleFunc("GET /api/_jobs", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdminConsole() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}

		status := r.URL.Query().Get("status") // optional filter: pending, running, completed, failed
		limit := r.URL.Query().Get("limit")
		if limit == "" {
			limit = "50"
		}

		query := "SELECT id, job_type, flow_name, status, attempts, max_attempts, error, run_at, started_at, completed_at, created_at FROM _benmore_jobs"
		var args []any
		if status != "" {
			query += " WHERE status = ?"
			args = append(args, status)
		}
		query += " ORDER BY created_at DESC LIMIT ?"
		args = append(args, limit)

		rows, err := queryMetadataRows(app.DB, query, args...)
		if err != nil {
			serverErrorJSON(w, r, app, "_jobs", err, "query failed")
			return
		}

		stats := JobStats(app.DB)
		httpJSON(w, http.StatusOK, map[string]any{"jobs": rows, "stats": stats})
	})

	// GET /api/_jobs/{id}/status - poll for an async-flow submitter. Returns
	// {id, flow_name, status, error, timestamps}. AUTHORIZATION: a serial job
	// id is guessable, and status/error can leak SQL text / upstream bodies /
	// cross-tenant flow detail, so this is NOT open to "any session". Caller
	// must present EITHER the capability token from the status_url (the only
	// thing that also works for anonymous async flows) OR an admin session.
	// A bad/absent token returns 404 (same as a missing id) so it isn't an
	// enumeration oracle. (v2.7.145 - previously fully anonymous + unscoped.)
	mux.HandleFunc("GET /api/_jobs/{id}/status", func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		var (
			jobID                                    int64
			flowName, status, errMsg, storedToken    string
			startedAt, completedAt, runAt, createdAt sql.NullString
		)
		err := app.DB.QueryRow(
			"SELECT id, flow_name, status, COALESCE(error,''), COALESCE(status_token,''), started_at, completed_at, run_at, created_at FROM _benmore_jobs WHERE id = ?",
			id,
		).Scan(&jobID, &flowName, &status, &errMsg, &storedToken, &startedAt, &completedAt, &runAt, &createdAt)
		if err != nil {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "job not found"})
			return
		}
		// Authorize: admin session, or a constant-time match on the capability
		// token. Anything else is indistinguishable from "not found".
		token := r.URL.Query().Get("token")
		sess := getSession(app, r)
		if !(sess != nil && sess.IsAdminConsole()) {
			if storedToken == "" || subtle.ConstantTimeCompare([]byte(token), []byte(storedToken)) != 1 {
				httpJSON(w, http.StatusNotFound, map[string]any{"error": "job not found"})
				return
			}
		}
		resp := map[string]any{
			"job_id":    jobID,
			"flow_name": flowName,
			"status":    status,
		}
		if errMsg != "" {
			resp["error"] = errMsg
		}
		if startedAt.Valid {
			resp["started_at"] = startedAt.String
		}
		if completedAt.Valid {
			resp["completed_at"] = completedAt.String
		}
		if runAt.Valid {
			resp["run_at"] = runAt.String
		}
		if createdAt.Valid {
			resp["created_at"] = createdAt.String
		}
		httpJSON(w, http.StatusOK, resp)
	})

	// GET /api/_jobs/{id} - get specific job
	mux.HandleFunc("GET /api/_jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdminConsole() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}

		id := r.PathValue("id")
		rows, err := queryMetadataRows(app.DB, "SELECT * FROM _benmore_jobs WHERE id = ?", id)
		if err != nil || len(rows) == 0 {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "job not found"})
			return
		}
		rows[0]["payload"] = redactJobPayloadForRead(app, rows[0]["payload"])

		httpJSON(w, http.StatusOK, rows[0])
	})

	// POST /api/_jobs/{id}/retry - retry a failed job
	mux.HandleFunc("POST /api/_jobs/{id}/retry", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdminConsole() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}
		// Admin cookie sessions need CSRF like every other mutation; a
		// bodyless cross-site POST could otherwise re-run a failed job.
		if !requireCSRF(w, r) {
			return
		}

		id := r.PathValue("id")
		// A connector-command effect that failed (blocked, or an unknown
		// delivery outcome) is never re-run: a replay could deliver twice
		// (appMCPEffectGate). The UPDATE repeats the guard.
		var effect int
		app.DB.QueryRow("SELECT "+jobRetryIsEffectSQL+" FROM _benmore_jobs WHERE id = ? AND status = 'failed'", id).Scan(&effect)
		if effect == 1 {
			httpJSON(w, http.StatusConflict, map[string]any{"error": "a connector command effect is never re-run; it was not retried"})
			return
		}
		result, err := app.DB.Exec(
			// Clear not_before so an admin-triggered retry runs immediately
			// rather than inheriting a stale backoff gate (review finding #11).
			"UPDATE _benmore_jobs SET status = 'pending', run_at = datetime('now'), not_before = NULL, error = NULL WHERE id = ? AND status = 'failed' AND NOT "+jobRetryIsEffectSQL,
			id,
		)
		if err != nil {
			serverErrorJSON(w, r, app, "_jobs retry", err, "retry failed")
			return
		}
		affected, _ := result.RowsAffected()
		if affected == 0 {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "job not found or not in failed state"})
			return
		}

		httpJSON(w, http.StatusOK, map[string]any{"status": "retrying"})
	})

	// DELETE /api/_jobs/{id} - delete a job
	mux.HandleFunc("DELETE /api/_jobs/{id}", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdminConsole() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}
		if !requireCSRF(w, r) {
			return
		}

		id := r.PathValue("id")
		result, err := app.DB.Exec("DELETE FROM _benmore_jobs WHERE id = ?", id)
		if err != nil {
			serverErrorJSON(w, r, app, "_jobs delete", err, "delete failed")
			return
		}
		affected, _ := result.RowsAffected()
		if affected == 0 {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "job not found"})
			return
		}

		httpJSON(w, http.StatusOK, map[string]any{"status": "deleted"})
	})
}

// JobStats returns job queue statistics.
func JobStats(db *sql.DB) map[string]int64 {
	stats := make(map[string]int64)
	// LOWER: parameterize the status literal instead of fmt.Sprintf-ing it into
	// the SQL. The values are a fixed allowlist today, but a parameterized query
	// keeps this off the string-building path so a future caller can't turn it
	// into an injection vector.
	for _, status := range []string{"pending", "running", "completed", "failed"} {
		var count int64
		db.QueryRow("SELECT COUNT(*) FROM _benmore_jobs WHERE status = ?", status).Scan(&count)
		stats[status] = count
	}
	return stats
}
