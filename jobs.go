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
}

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
			"INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at, status_token, unique_key, max_attempts) VALUES (?, ?, ?, ?, ?, ?, ?)",
			jobType, flowName, string(data), ra.UTC().Format(sqliteDateTimeLayout), token, nullIfEmpty(uniqueKey), opts.maxAttempts,
		)
	} else {
		result, err = exec.Exec(
			"INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at, status_token, unique_key) VALUES (?, ?, ?, ?, ?, ?)",
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
		FROM _benmore_jobs
		WHERE unique_key = ?
		  AND status IN ('pending', 'running')
		ORDER BY id DESC
		LIMIT 1
	`
	if anyStatus {
		query = `
		SELECT id, COALESCE(status_token, '')
		FROM _benmore_jobs
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
// durability (survives crashes), retry on failure, and visibility.
func EnqueueHookJob(db *sql.DB, hook Hook, row map[string]any) {
	data, _ := json.Marshal(hookJobPayload(hook, row))
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
// hookFromJobPayload.
func hookJobPayload(hook Hook, row map[string]any) map[string]any {
	h := map[string]any{
		"sql":     hook.SQL,
		"webhook": hook.Webhook,
		"body":    hook.Body,
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
func StartJobWorker(app *App) {
	EnsureJobsTable(app.DB)

	safeGo("jobs.worker", func() {
		stop := app.Stop // capture once: hot reload reassigns app.Stop; reading the field in the loop would race the swap and could miss the close (goroutine leak)
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
			"UPDATE _benmore_jobs SET status = 'pending', lease_expires_at = NULL WHERE status = 'running' AND job_type = ? AND lease_expires_at IS NOT NULL AND lease_expires_at < ?",
			jobType, now,
		)
	}
	for _, flowName := range idempotentFlowJobNames(app) {
		app.DB.Exec(
			"UPDATE _benmore_jobs SET status = 'pending', lease_expires_at = NULL WHERE status = 'running' AND job_type = 'flow' AND flow_name = ? AND lease_expires_at IS NOT NULL AND lease_expires_at < ?",
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
	// is still backing off. ORDER BY run_at ASC picks the head of line among the
	// claimable set.
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
	err := app.DB.QueryRow(`
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
		           AND json_extract(j.payload, '$.project_id') IS NOT NULL
		           AND json_extract(k.payload, '$.project_id') IS NOT NULL
		           AND json_extract(k.payload, '$.project_id')
		               IS json_extract(j.payload, '$.project_id')
		           AND (k.run_at < j.run_at
		                OR (k.run_at = j.run_at AND k.id < j.id))
		  )
		ORDER BY j.run_at ASC, j.id ASC
		LIMIT 1
	`).Scan(&id, &jobType, &flowName, &payload, &attempts, &maxAttempts)

	if err != nil {
		return false // nothing claimable: no due jobs, or all due jobs are gated
	}

	// Atomically claim: only transition pending->running, and only if WE win
	// the race. With >1 worker (e.g. a transient overlap across a reload) two
	// goroutines can SELECT the same id; the AND status='pending' guard +
	// RowsAffected check ensures exactly one runs it, preventing duplicate
	// emails / webhook deliveries / double-executed SQL hooks.
	leaseUntil := time.Now().Add(jobsLeaseTTL()).UTC().Format(sqliteDateTimeLayout)
	res, claimErr := app.DB.Exec("UPDATE _benmore_jobs SET status = 'running', started_at = datetime('now'), attempts = attempts + 1, lease_expires_at = ? WHERE id = ? AND status = 'pending'", leaseUntil, id)
	if claimErr != nil {
		return false
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return true // another worker claimed it first; keep draining
	}

	// H-2: heartbeat the lease while the job body runs so a job that legitimately
	// outruns jobsLeaseTTL is not treated as orphaned and re-run concurrently by
	// a second worker. The heartbeat stops as soon as the body returns (done).
	hbDone := make(chan struct{})
	defer close(hbDone)
	safeGo(fmt.Sprintf("jobs.heartbeat:%d", id), func() {
		stop := app.Stop // capture once: hot reload reassigns app.Stop; reading the field in the loop would race the swap and could miss the close (goroutine leak)
		ticker := time.NewTicker(jobsHeartbeatInterval())
		defer ticker.Stop()
		for {
			select {
			case <-hbDone:
				return
			case <-stop:
				return
			case <-ticker.C:
				next := time.Now().Add(jobsLeaseTTL()).UTC().Format(sqliteDateTimeLayout)
				app.DB.Exec("UPDATE _benmore_jobs SET lease_expires_at = ? WHERE id = ? AND status = 'running'", next, id)
			}
		}
	})

	// Parse payload
	var data map[string]any
	json.Unmarshal([]byte(payload), &data)
	if data == nil {
		data = make(map[string]any)
	}

	var jobErr error

	switch jobType {
	case "hook":
		jobErr = executeHookJob(app, data)
	case "cron":
		jobErr = executeCronJob(app, flowName, data)
	case "webhook_subscription":
		jobErr = executeWebhookSubscriptionJob(data, app.Dir)
	default: // "flow"
		jobErr = executeFlowJob(app, flowName, data)
	}

	// Every terminal/transition below clears lease_expires_at so a finished or
	// requeued job is never mistaken for an orphan by jobsRecoverOrphanedJobs.
	if jobErr != nil {
		if attempts+1 >= maxAttempts {
			app.DB.Exec("UPDATE _benmore_jobs SET status = 'failed', error = ?, completed_at = datetime('now'), lease_expires_at = NULL WHERE id = ?",
				jobErr.Error(), id)
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
			app.DB.Exec("UPDATE _benmore_jobs SET status = 'pending', error = ?, not_before = ?, lease_expires_at = NULL WHERE id = ?",
				jobErr.Error(), notBefore.UTC().Format(sqliteDateTimeLayout), id)
			log.Printf("JOB RETRY [%s/%s] #%d: %s (attempt %d, not_before %s)", jobType, flowName, id, jobErr, attempts+1, notBefore.Format("15:04:05"))
		}
	} else {
		app.DB.Exec("UPDATE _benmore_jobs SET status = 'completed', completed_at = datetime('now'), lease_expires_at = NULL WHERE id = ?", id)
	}
	return true
}

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

	ctx := &FlowContext{
		App:    app,
		Data:   data,
		Params: make(map[string]string),
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
			return ctx.Error
		}
		commitErr := ctx.Tx.Commit()
		// Whether Commit succeeded or failed, the tx is done from
		// database/sql's perspective - mark handled either way so the
		// deferred guard never double-calls Rollback/Commit.
		guard.MarkHandled()
		if commitErr != nil {
			return fmt.Errorf("commit transaction: %w", commitErr)
		}
	}
	return ctx.Error
}

func executeHookJob(app *App, data map[string]any) error {
	hookData, _ := data["_hook"].(map[string]any)
	rowData, _ := data["_row"].(map[string]any)
	if hookData == nil {
		return fmt.Errorf("missing _hook in payload")
	}
	if rowData == nil {
		rowData = make(map[string]any)
	}

	hook := hookFromJobPayload(hookData)

	executeHook(app.DB, hook, rowData, app.Dir)
	// Fire an SSE refresh broadcast if the hook's SQL was a mutating
	// statement. An earlier app build: an on_insert messages hook bumped
	// conversations.last_message_at via raw SQL but emitted no SSE,
	// so receivers' sidebars stayed stale until they clicked away
	// and back. The same root cause as v2.7.35's N11 (sql --write
	// SSE), now on the hook execution path.
	if hook.SQL != "" {
		if table := extractTableFromStmt(hook.SQL); table != "" {
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

// CleanOldJobs removes completed jobs older than 7 days. Exits on app.Stop
// so it isn't re-spawned-without-end on every hot reload.
func CleanOldJobs(app *App) {
	safeGo("jobs.cleanup", func() {
		stop := app.Stop // capture once: hot reload reassigns app.Stop; reading the field in the loop would race the swap and could miss the close (goroutine leak)
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				app.DB.Exec("DELETE FROM _benmore_jobs WHERE status = 'completed' AND completed_at < datetime('now', '-7 days')")
			}
		}
	})
}

// RegisterJobsAPI sets up job visibility and management endpoints.
func RegisterJobsAPI(mux *http.ServeMux, app *App) {
	// GET /api/_jobs - list jobs (admin only)
	mux.HandleFunc("GET /api/_jobs", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdmin() {
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

		rows, err := QueryRows(app.DB, query, args...)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
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
		if !(sess != nil && sess.IsAdmin()) {
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
		if session == nil || !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}

		id := r.PathValue("id")
		rows, err := QueryRows(app.DB, "SELECT * FROM _benmore_jobs WHERE id = ?", id)
		if err != nil || len(rows) == 0 {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "job not found"})
			return
		}

		httpJSON(w, http.StatusOK, rows[0])
	})

	// POST /api/_jobs/{id}/retry - retry a failed job
	mux.HandleFunc("POST /api/_jobs/{id}/retry", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}

		id := r.PathValue("id")
		result, err := app.DB.Exec(
			// Clear not_before so an admin-triggered retry runs immediately
			// rather than inheriting a stale backoff gate (review finding #11).
			"UPDATE _benmore_jobs SET status = 'pending', run_at = datetime('now'), not_before = NULL, error = NULL WHERE id = ? AND status = 'failed'",
			id,
		)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "retry failed"})
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
		if session == nil || !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}

		id := r.PathValue("id")
		result, err := app.DB.Exec("DELETE FROM _benmore_jobs WHERE id = ?", id)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "delete failed"})
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
