//go:build !cli

package main

import (
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"
)

// EnsureJobsTable creates the background jobs table.
//
// Guards against a nil handle: callers in normal flows have an
// initialized DB (the scheduler/worker only run after OpenDB), but a
// nil db would otherwise panic on the first Exec. Treat nil as a no-op
// so a half-initialized App reaching here degrades gracefully instead
// of crashing (review finding #5).
func EnsureJobsTable(db *sql.DB) {
	if db == nil {
		return
	}
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
	// Optional idempotency/uniqueness key. Active jobs with the same key
	// collapse to the existing job instead of duplicating work.
	db.Exec("ALTER TABLE _benmore_jobs ADD COLUMN unique_key TEXT")
	db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_jobs_unique_active ON _benmore_jobs(unique_key) WHERE unique_key IS NOT NULL AND unique_key != '' AND status IN ('pending', 'running')")
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

const jobLeaseDuration = 5 * time.Minute

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
	data, _ := json.Marshal(payload)
	ra := time.Now()
	if runAt != nil {
		ra = *runAt
	}
	token := generateToken(18)
	var (
		result sql.Result
		err    error
	)
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
		}
		return 0, "", err
	}
	id, err := result.LastInsertId()
	return id, token, err
}

func findActiveJobByUniqueKey(q jobEnqueueExecer, uniqueKey string) (int64, string, bool) {
	return findJobByUniqueKey(q, uniqueKey, false)
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
	err := q.QueryRow(query, uniqueKey).Scan(&id, &token)
	return id, token, err == nil
}

func nullIfEmpty(s string) any {
	if s == "" {
		return nil
	}
	return s
}

func isUniqueJobConstraintErr(err error) bool {
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "unique") &&
		(strings.Contains(msg, "idx_jobs_unique_active") || strings.Contains(msg, "unique_key"))
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
	leaseUntil := time.Now().Add(jobLeaseDuration).UTC().Format(sqliteDateTimeLayout)
	res, claimErr := app.DB.Exec("UPDATE _benmore_jobs SET status = 'running', started_at = datetime('now'), attempts = attempts + 1, lease_expires_at = ? WHERE id = ? AND status = 'pending'", leaseUntil, id)
	if claimErr != nil {
		return false
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return true // another worker claimed it first; keep draining
	}

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

	if jobErr != nil {
		if attempts+1 >= maxAttempts {
			app.DB.Exec("UPDATE _benmore_jobs SET status = 'failed', error = ?, completed_at = datetime('now'), lease_expires_at = NULL WHERE id = ?",
				jobErr.Error(), id)
			log.Printf("JOB FAILED [%s/%s] #%d: %s (no more retries)", jobType, flowName, id, jobErr)
		} else {
			backoff := time.Duration(1<<uint(attempts)) * 30 * time.Second
			nextRun := time.Now().Add(backoff)
			app.DB.Exec("UPDATE _benmore_jobs SET status = 'pending', error = ?, run_at = ?, lease_expires_at = NULL WHERE id = ?",
				jobErr.Error(), nextRun.UTC().Format(sqliteDateTimeLayout), id)
			log.Printf("JOB RETRY [%s/%s] #%d: %s (attempt %d, next at %s)", jobType, flowName, id, jobErr, attempts+1, nextRun.Format("15:04:05"))
		}
	} else {
		app.DB.Exec("UPDATE _benmore_jobs SET status = 'completed', completed_at = datetime('now'), lease_expires_at = NULL WHERE id = ?", id)
	}
	return true
}

func recoverStaleRunningJobs(db *sql.DB, now time.Time) {
	nowStr := now.UTC().Format(sqliteDateTimeLayout)
	db.Exec(`
		UPDATE _benmore_jobs
		SET status = 'pending',
		    error = 'worker lease expired; retrying',
		    run_at = ?,
		    lease_expires_at = NULL
		WHERE status = 'running'
		  AND lease_expires_at IS NOT NULL
		  AND lease_expires_at <= ?
		  AND attempts < max_attempts
	`, nowStr, nowStr)
	db.Exec(`
		UPDATE _benmore_jobs
		SET status = 'failed',
		    error = 'worker lease expired after max attempts',
		    completed_at = ?,
		    lease_expires_at = NULL
		WHERE status = 'running'
		  AND lease_expires_at IS NOT NULL
		  AND lease_expires_at <= ?
		  AND attempts >= max_attempts
	`, nowStr, nowStr)
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
