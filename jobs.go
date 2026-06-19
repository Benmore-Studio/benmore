//go:build !cli

package main

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

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
	// Lease deadline for crash recovery. A worker sets this when it claims a
	// job; if the process dies before completion, the next worker pass can
	// recover the stale running job instead of leaving it stuck forever.
	db.Exec("ALTER TABLE _benmore_jobs ADD COLUMN lease_expires_at DATETIME")
	// Lease owner token. A worker stamps a fresh random token when it claims a
	// job and renews (heartbeats) the lease while the job runs. Recovery only
	// reclaims a lease once it is *expired* (the owner stopped heartbeating),
	// so a slow-but-alive worker can never have its in-flight job reclaimed and
	// double-executed by an overlapping worker - the lease being expired is now
	// proof the owner is gone, not merely that the job is long-running.
	db.Exec("ALTER TABLE _benmore_jobs ADD COLUMN lease_owner TEXT")
	// One-time backfill: jobs left `running` by pre-lease code have a NULL
	// lease and would otherwise be stuck forever. Give them a lease anchored at
	// started_at so the normal recovery sweep can pick them up. Best-effort.
	db.Exec("UPDATE _benmore_jobs SET lease_expires_at = datetime(COALESCE(started_at, created_at, datetime('now')), '+5 minutes') WHERE status = 'running' AND lease_expires_at IS NULL")
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

// jobLeaseDuration is how long a claimed job's lease is valid before a
// recovery sweep may reclaim it. It is a *renewal window*, NOT a maximum job
// runtime: a running worker heartbeats its lease forward every
// jobLeaseHeartbeat (see runWithLeaseHeartbeat), so a job may legitimately run
// far longer than this without becoming reclaimable. The lease only expires
// when the owning worker stops heartbeating - i.e. the process actually died.
//
// Overridable per-app via the BENMORE_JOB_LEASE_SECONDS env var (see
// jobLeaseDurationFor); finding #6 - this is the most load-bearing tuning knob
// for crash-recovery latency, so it should not be a hard-coded constant.
const jobLeaseDuration = 5 * time.Minute

// jobLeaseHeartbeatFor is how often a running worker renews its lease, derived
// from the effective lease window. It must be comfortably shorter than the
// window so a brief stall (GC pause, slow DB write) does not let the lease
// lapse while the worker is still alive; one third gives two renewal chances
// before expiry. A floor of 1s keeps it sane for very short test windows.
func jobLeaseHeartbeatFor(leaseDur time.Duration) time.Duration {
	hb := leaseDur / 3
	if hb < time.Second {
		hb = time.Second
	}
	return hb
}

// jobLeaseDurationFor resolves the effective lease window, allowing a
// per-deployment override via BENMORE_JOB_LEASE_SECONDS. Invalid or absent
// values fall back to the jobLeaseDuration default.
func jobLeaseDurationFor() time.Duration {
	if v := os.Getenv("BENMORE_JOB_LEASE_SECONDS"); v != "" {
		if secs, err := strconv.Atoi(v); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
	}
	return jobLeaseDuration
}

// recoveryBackoff mirrors the normal failure-path backoff (jobs.go retry
// branch) so a job that reliably kills its worker (panic, OOM, segfault) is
// re-queued with the same exponential delay rather than hot-looping on
// immediate re-pickup. attempts is the row's current attempt count.
func recoveryBackoff(attempts int) time.Duration {
	if attempts < 0 {
		attempts = 0
	}
	return time.Duration(1<<uint(attempts)) * 30 * time.Second
}

type jobEnqueueExecer interface {
	Exec(query string, args ...any) (sql.Result, error)
}

// EnqueueJob returns (id, statusToken, error). statusToken is the unguessable
// capability the caller embeds in the status_url so the submitter (authed OR
// anonymous) can poll GET /api/_jobs/{id}/status?token=... without exposing
// every job to id-enumeration.
func EnqueueJob(db *sql.DB, flowName string, payload map[string]any, runAt *time.Time) (int64, string, error) {
	return enqueueJob(db, flowName, payload, runAt)
}

func EnqueueJobTx(tx *sql.Tx, flowName string, payload map[string]any, runAt *time.Time) (int64, string, error) {
	return enqueueJob(tx, flowName, payload, runAt)
}

func enqueueJob(exec jobEnqueueExecer, flowName string, payload map[string]any, runAt *time.Time) (int64, string, error) {
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
	result, err := exec.Exec(
		"INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at, status_token) VALUES ('flow', ?, ?, ?, ?)",
		flowName, string(data), ra.UTC().Format(sqliteDateTimeLayout), token,
	)
	if err != nil {
		return 0, "", err
	}
	id, err := result.LastInsertId()
	return id, token, err
}

// EnqueueHookJob adds a hook execution job to the background queue.
// Hooks are enqueued instead of executed in goroutines - this provides
// durability (survives crashes), retry on failure, and visibility.
func EnqueueHookJob(db *sql.DB, hook Hook, row map[string]any) {
	payload := map[string]any{
		"_hook": map[string]any{
			"sql":     hook.SQL,
			"webhook": hook.Webhook,
			"body":    hook.Body,
		},
		"_row": row,
	}
	if hook.Email != nil {
		payload["_hook"].(map[string]any)["email_to"] = hook.Email.To
		payload["_hook"].(map[string]any)["email_subject"] = hook.Email.Subject
		payload["_hook"].(map[string]any)["email_template"] = hook.Email.Template
	}
	if hook.Notify != nil {
		payload["_hook"].(map[string]any)["notify"] = marshalNotifyHook(hook.Notify)
	}
	data, _ := json.Marshal(payload)
	db.Exec(
		"INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at) VALUES ('hook', 'hook', ?, datetime('now'))",
		string(data),
	)
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
		for {
			select {
			case <-app.Stop:
				return
			default:
			}
			if processNextJob(app) {
				continue // a job ran - more may be queued, drain without sleeping
			}
			select {
			case <-app.Stop:
				return
			case <-time.After(1 * time.Second):
			}
		}
	})

	log.Printf("  jobs: background worker started")
}

// processNextJob claims and runs at most one job. Returns true if a job was
// claimed (so the caller can drain a backlog without idling).
func processNextJob(app *App) (worked bool) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("JOB WORKER PANIC: %v", r)
		}
	}()

	recoverStaleRunningJobs(app.DB, time.Now())

	// Claim the next pending job
	var id int64
	var jobType, flowName, payload string
	var attempts, maxAttempts int

	err := app.DB.QueryRow(`
		SELECT id, job_type, flow_name, payload, attempts, max_attempts
		FROM _benmore_jobs
		WHERE status = 'pending' AND run_at <= datetime('now')
		ORDER BY run_at ASC LIMIT 1
	`).Scan(&id, &jobType, &flowName, &payload, &attempts, &maxAttempts)

	if err != nil {
		return false // no jobs
	}

	// Atomically claim: only transition pending->running, and only if WE win
	// the race. With >1 worker (e.g. a transient overlap across a reload) two
	// goroutines can SELECT the same id; the AND status='pending' guard +
	// RowsAffected check ensures exactly one runs it, preventing duplicate
	// emails / webhook deliveries / double-executed SQL hooks.
	leaseDur := jobLeaseDurationFor()
	leaseOwner := generateToken(18)
	leaseUntil := time.Now().Add(leaseDur).UTC().Format(sqliteDateTimeLayout)
	res, claimErr := app.DB.Exec("UPDATE _benmore_jobs SET status = 'running', started_at = datetime('now'), attempts = attempts + 1, lease_expires_at = ?, lease_owner = ? WHERE id = ? AND status = 'pending'", leaseUntil, leaseOwner, id)
	if claimErr != nil {
		return false
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return true // another worker claimed it first; keep draining
	}

	// Keep the lease fresh for as long as this worker is alive and running the
	// job. Without renewal a job that legitimately runs longer than the lease
	// window would be reclaimed by a recovery sweep and double-executed (the
	// finding #1 hole). The heartbeat only matches `lease_owner = ?`, so a
	// reclaimed/re-leased job is not stomped by the previous owner.
	stopHeartbeat := startLeaseHeartbeat(app, id, leaseOwner, leaseDur)

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
	case "webhook_subscription":
		jobErr = executeWebhookSubscriptionJob(data, app.Dir)
	default: // "flow"
		jobErr = executeFlowJob(app, flowName, data)
	}

	// Stop heartbeating before finalizing so a renewal can't race the terminal
	// write. All terminal writes are guarded by `lease_owner = ?`: if recovery
	// already reclaimed this job (our lease lapsed and a new owner picked it
	// up), we must not stomp the new owner's run with our stale result.
	stopHeartbeat()

	if jobErr != nil {
		if attempts+1 >= maxAttempts {
			app.DB.Exec("UPDATE _benmore_jobs SET status = 'failed', error = ?, completed_at = datetime('now'), lease_expires_at = NULL, lease_owner = NULL WHERE id = ? AND lease_owner = ?",
				jobErr.Error(), id, leaseOwner)
			log.Printf("JOB FAILED [%s/%s] #%d: %s (no more retries)", jobType, flowName, id, jobErr)
		} else {
			backoff := recoveryBackoff(attempts)
			nextRun := time.Now().Add(backoff)
			app.DB.Exec("UPDATE _benmore_jobs SET status = 'pending', error = ?, run_at = ?, lease_expires_at = NULL, lease_owner = NULL WHERE id = ? AND lease_owner = ?",
				jobErr.Error(), nextRun.UTC().Format(sqliteDateTimeLayout), id, leaseOwner)
			log.Printf("JOB RETRY [%s/%s] #%d: %s (attempt %d, next at %s)", jobType, flowName, id, jobErr, attempts+1, nextRun.Format("15:04:05"))
		}
	} else {
		app.DB.Exec("UPDATE _benmore_jobs SET status = 'completed', completed_at = datetime('now'), lease_expires_at = NULL, lease_owner = NULL WHERE id = ? AND lease_owner = ?", id, leaseOwner)
	}
	return true
}

// startLeaseHeartbeat renews the lease for job id (owned by leaseOwner) every
// jobLeaseHeartbeat until the returned stop func is called. The renewal is
// scoped to `lease_owner = ?` so once a recovery sweep reclaims an expired
// lease (and a new owner stamps its own token), the old worker's heartbeat
// becomes a no-op and cannot resurrect the lease. The stop func is idempotent.
func startLeaseHeartbeat(app *App, id int64, leaseOwner string, leaseDur time.Duration) func() {
	done := make(chan struct{})
	var once sync.Once
	stop := func() { once.Do(func() { close(done) }) }
	safeGo("jobs.lease-heartbeat", func() {
		ticker := time.NewTicker(jobLeaseHeartbeatFor(leaseDur))
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-app.Stop:
				return
			case <-ticker.C:
				leaseUntil := time.Now().Add(leaseDur).UTC().Format(sqliteDateTimeLayout)
				app.DB.Exec(
					"UPDATE _benmore_jobs SET lease_expires_at = ? WHERE id = ? AND status = 'running' AND lease_owner = ?",
					leaseUntil, id, leaseOwner,
				)
			}
		}
	})
	return stop
}

// recoverStaleRunningJobs sweeps `running` jobs whose lease has actually
// expired (the owning worker stopped heartbeating, i.e. its process died) and
// either re-queues them for retry or fails them at max attempts. The
// `lease_expires_at IS NOT NULL` guard means a freshly-claimed row that has not
// yet stamped a lease is never touched.
// jobRerunSafeTypes is the allowlist of job types whose side effects are
// idempotent enough to safely re-run after a worker crashes mid-execution.
// Lease recovery re-queues ONLY these types; every other orphaned job is
// failed closed instead of being re-run.
//
// C-1 (at-least-once vs duplicate side effects): a job body runs OUTSIDE the
// claim transaction, so when a worker dies mid-flight we cannot know whether
// its email/webhook/SQL side effects already fired. Re-queuing a non-idempotent
// job (e.g. a "send email" flow) would deliver it a second time. "flow" and
// hook jobs are therefore intentionally NOT listed here. Add a type only once
// its handler is proven idempotent (e.g. guarded by a per-job completion
// marker that makes a second run a no-op).
var jobRerunSafeTypes = map[string]bool{
	// (none today)
}

func recoverStaleRunningJobs(db *sql.DB, now time.Time) {
	nowStr := now.UTC().Format(sqliteDateTimeLayout)

	// Recovery is FAIL-CLOSED (C-1). Step 1: re-queue ONLY the job types proven
	// idempotent (jobRerunSafeTypes) that are below max attempts, applying the
	// same exponential backoff as the normal failure path (finding #2) so a job
	// that reliably kills its worker doesn't hot-loop. The prior `error` is
	// preserved (appended to) rather than overwritten (nit).
	for jobType := range jobRerunSafeTypes {
		retryRes, retryErr := db.Exec(`
			UPDATE _benmore_jobs
			SET status = 'pending',
			    error = TRIM(COALESCE(error || '; ', '') || 'worker lease expired; retrying (idempotent type)'),
			    run_at = datetime(?, '+' || ((1 << attempts) * 30) || ' seconds'),
			    lease_expires_at = NULL,
			    lease_owner = NULL
			WHERE status = 'running'
			  AND lease_expires_at IS NOT NULL
			  AND lease_expires_at <= ?
			  AND job_type = ?
			  AND attempts < max_attempts
		`, nowStr, nowStr, jobType)
		if retryErr != nil {
			log.Printf("JOB RECOVERY: re-queue sweep failed for %q: %v", jobType, retryErr)
		} else if n, _ := retryRes.RowsAffected(); n > 0 {
			log.Printf("JOB RECOVERY: re-queued %d stale idempotent %q job(s) for retry", n, jobType)
		}
	}

	// Step 2: fail CLOSED every orphan still stuck - i.e. every 'running' job
	// whose lease expired that was NOT re-queued above (a non-idempotent type,
	// or an idempotent type already at max attempts). The orphan no longer
	// sticks in 'running' forever, but it is marked 'failed' and NEVER re-run,
	// because re-running a crashed non-idempotent job risks a duplicate side
	// effect (double-sent email, double webhook, double SQL mutation). An
	// operator can inspect the failed row and re-trigger deliberately if safe.
	failRes, failErr := db.Exec(`
		UPDATE _benmore_jobs
		SET status = 'failed',
		    error = TRIM(COALESCE(error || '; ', '') || 'worker died mid-execution; not re-run to avoid duplicate side effects (C-1)'),
		    completed_at = ?,
		    lease_expires_at = NULL,
		    lease_owner = NULL
		WHERE status = 'running'
		  AND lease_expires_at IS NOT NULL
		  AND lease_expires_at <= ?
	`, nowStr, nowStr)
	if failErr != nil {
		log.Printf("JOB RECOVERY: fail sweep failed: %v", failErr)
	} else if n, _ := failRes.RowsAffected(); n > 0 {
		log.Printf("JOB RECOVERY: failed %d orphaned job(s) (worker crash; not re-run to avoid duplicate side effects)", n)
	}
}

func executeFlowJob(app *App, flowName string, data map[string]any) error {
	var targetFlow *Flow
	for _, flow := range app.Flows {
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
	if targetFlow.Transaction {
		tx, err := app.DB.Begin()
		if err != nil {
			return fmt.Errorf("begin transaction: %w", err)
		}
		ctx.Tx = tx
	}

	executeSteps(ctx, targetFlow.Steps)
	if ctx.Tx != nil {
		if ctx.Error != nil {
			_ = ctx.Tx.Rollback()
			return ctx.Error
		}
		if err := ctx.Tx.Commit(); err != nil {
			return fmt.Errorf("commit transaction: %w", err)
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

	hook := Hook{
		SQL:     fmt.Sprintf("%v", hookData["sql"]),
		Webhook: fmt.Sprintf("%v", hookData["webhook"]),
		Body:    fmt.Sprintf("%v", hookData["body"]),
	}
	if hook.SQL == "<nil>" {
		hook.SQL = ""
	}
	if hook.Webhook == "<nil>" {
		hook.Webhook = ""
	}
	if hook.Body == "<nil>" {
		hook.Body = ""
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

// FlushJobs processes all pending jobs synchronously. Used in tests to
// drain the job queue before assertions on async hook side effects.
func FlushJobs(app *App) {
	for {
		var count int64
		app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_jobs WHERE status = 'pending' AND run_at <= datetime('now')").Scan(&count)
		if count == 0 {
			return
		}
		processNextJob(app)
	}
}

// CleanOldJobs removes completed jobs older than 7 days. Exits on app.Stop
// so it isn't re-spawned-without-end on every hot reload.
func CleanOldJobs(app *App) {
	safeGo("jobs.cleanup", func() {
		ticker := time.NewTicker(1 * time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-app.Stop:
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
			"UPDATE _benmore_jobs SET status = 'pending', run_at = datetime('now'), error = NULL WHERE id = ? AND status = 'failed'",
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
	for _, status := range []string{"pending", "running", "completed", "failed"} {
		var count int64
		db.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM _benmore_jobs WHERE status = '%s'", status)).Scan(&count)
		stats[status] = count
	}
	return stats
}
