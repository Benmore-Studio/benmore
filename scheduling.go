package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// scheduling.go - per-record deferred tasks + approvals. The framework's
// cron is global; this adds "do X for THIS record at THIS time" (reminders,
// SLAs, dunning, scheduled flow runs) and a lightweight human-in-the-loop
// approval primitive. Powers the Reminder / ScheduleAction / Approval
// components. A per-app sweeper (tied to app.Stop) fires due tasks: every
// reminder becomes an in-app notification; a scheduled flow also runs it.

// ─── tables ──────────────────────────────────────────────────────────
func EnsureSchedulingTables(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_scheduled_tasks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		user_id INTEGER NOT NULL,
		kind TEXT NOT NULL DEFAULT 'reminder',   -- reminder | flow
		title TEXT NOT NULL DEFAULT 'Reminder',
		message TEXT DEFAULT '',
		flow TEXT DEFAULT '',
		body TEXT DEFAULT '',                     -- JSON args for kind=flow
		table_name TEXT DEFAULT '',
		row_id TEXT DEFAULT '',
		run_at DATETIME NOT NULL,
		status TEXT NOT NULL DEFAULT 'pending',   -- pending | done | cancelled | failed
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		fired_at DATETIME
	)`)
	db.Exec(`CREATE INDEX IF NOT EXISTS idx_sched_due ON _benmore_scheduled_tasks(status, run_at)`)
	// claimed_at records when a sweeper flipped a task to 'running' so an
	// orphan left behind by a crashed worker can be recovered (the table has
	// no lease otherwise). Best-effort ALTER covers fresh + upgraded tables.
	db.Exec(`ALTER TABLE _benmore_scheduled_tasks ADD COLUMN claimed_at DATETIME`)
	db.Exec(`ALTER TABLE _benmore_scheduled_tasks ADD COLUMN authorization TEXT NOT NULL DEFAULT ''`)
	db.Exec(`ALTER TABLE _benmore_scheduled_tasks ADD COLUMN last_error TEXT NOT NULL DEFAULT ''`)
	// recoveries counts how often a task was found orphaned in 'running' and
	// put back; sweepScheduledTasks fails a task that keeps killing its worker
	// instead of re-firing it forever.
	db.Exec(`ALTER TABLE _benmore_scheduled_tasks ADD COLUMN recoveries INTEGER NOT NULL DEFAULT 0`)
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_approvals (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		table_name TEXT NOT NULL,
		row_id TEXT NOT NULL,
		requested_by INTEGER NOT NULL,
		requested_email TEXT DEFAULT '',
		approver_id INTEGER,
		approver_email TEXT DEFAULT '',
		title TEXT DEFAULT '',
		status TEXT NOT NULL DEFAULT 'pending',   -- pending | approved | rejected
		note TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		decided_at DATETIME
	)`)
}

// approvalRequestLimiter caps approval requests per account (each one can
// notify the named approver): approvalRequestBurst per approvalRequestWindow,
// per app. Any signed-in account may name any user as approver, so without a
// cap one account could flood that user's notifications.
const (
	approvalRequestBurst  = 30
	approvalRequestWindow = 10 * time.Minute
)

var approvalRequestLimiter = NewRateLimiter(approvalRequestBurst, approvalRequestWindow)

// RegisterSchedulingAPI wires the scheduled-tasks + approvals endpoints
// and starts the per-app sweeper.
func RegisterSchedulingAPI(mux appRouteRegistrar, app *App) {
	EnsureSchedulingTables(app.DB)
	StartSchedulerSweeper(app)

	registerSchedulingAPI(mux, app)
}

func registerSchedulingAPI(mux appRouteRegistrar, app *App) {
	// ── Scheduled tasks ──
	mux.HandleFunc("POST /api/_scheduled", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		var b struct {
			Kind    string          `json:"kind"`
			Title   string          `json:"title"`
			Message string          `json:"message"`
			Flow    string          `json:"flow"`
			Body    json.RawMessage `json:"body"`
			Table   string          `json:"table"`
			RowID   string          `json:"row_id"`
			RunAt   string          `json:"run_at"`
		}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.RunAt == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "run_at (RFC3339) required"})
			return
		}
		when, err := parseWhen(b.RunAt)
		if err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid run_at: use RFC3339 or a duration like 2h/30m"})
			return
		}
		kind := b.Kind
		if kind != "flow" {
			kind = "reminder"
		}
		authorization := ""
		if kind == "flow" {
			if !credentialManagementSession(app, session) {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": "schedule flows from a login session outside act-as/support mode"})
				return
			}
			authorization = marshalScheduledAuthority(session)
			flow, err := schedulableFlow(app, b.Flow, session)
			if err != nil {
				httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
				return
			}
			var body map[string]any
			if len(b.Body) > 0 && (json.Unmarshal(b.Body, &body) != nil || body == nil) {
				httpJSON(w, http.StatusBadRequest, map[string]any{"error": "body must be a JSON object"})
				return
			}
			if _, err := scheduledFlowRequest(flow, string(b.Body)); err != nil {
				httpJSON(w, http.StatusBadRequest, map[string]any{"error": err.Error()})
				return
			}
		}

		title := b.Title
		if title == "" {
			title = "Reminder"
		}
		res, err := app.DB.Exec(
			`INSERT INTO _benmore_scheduled_tasks (user_id, kind, title, message, flow, body, table_name, row_id, run_at, authorization) VALUES (?,?,?,?,?,?,?,?,?,?)`,
			session.UserID, kind, title, b.Message, b.Flow, string(b.Body), b.Table, b.RowID, when.UTC().Format(time.RFC3339), authorization,
		)
		if err != nil {
			serverErrorJSON(w, r, app, "_schedule", err, "schedule failed")
			return
		}
		id, _ := res.LastInsertId()
		httpJSON(w, http.StatusOK, map[string]any{"id": id, "run_at": when.UTC().Format(time.RFC3339), "status": "pending"})
	})
	mux.HandleFunc("GET /api/_scheduled", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		q := "SELECT id, kind, title, message, flow, table_name, row_id, run_at, status, fired_at, last_error FROM _benmore_scheduled_tasks WHERE user_id = ?"
		args := []any{session.UserID}
		if t := r.URL.Query().Get("table"); t != "" {
			q += " AND table_name = ?"
			args = append(args, t)
		}
		if rid := r.URL.Query().Get("row_id"); rid != "" {
			q += " AND row_id = ?"
			args = append(args, rid)
		}
		q += " ORDER BY run_at ASC LIMIT 200"
		rows, err := queryMetadataRows(app.DB, q, args...)
		if err != nil {
			serverErrorJSON(w, r, app, "_schedule", err, "query failed")
			return
		}
		httpJSON(w, http.StatusOK, map[string]any{"tasks": rows})
	})
	mux.HandleFunc("DELETE /api/_scheduled/{id}", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		app.DB.Exec("UPDATE _benmore_scheduled_tasks SET status='cancelled' WHERE id = ? AND user_id = ? AND status IN ('pending','blocked')", r.PathValue("id"), session.UserID)
		httpJSON(w, http.StatusOK, map[string]any{"status": "cancelled"})
	})

	// ── Approvals ──
	mux.HandleFunc("POST /api/_approvals", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		var b struct {
			Table         string `json:"table"`
			RowID         string `json:"row_id"`
			ApproverEmail string `json:"approver_email"`
			Title         string `json:"title"`
		}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil || b.Table == "" || b.RowID == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "table and row_id required"})
			return
		}
		// An approval on an app record joins that record's approval history,
		// which every reader of the record sees (GET below), so only a caller
		// who can read the record may request one. A table name that is not
		// an app table is a free-form label and stays private to the
		// requester and approver.
		if appHasTable(app, b.Table) && !canAccessRow(app, b.Table, b.RowID, session) {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "record not found"})
			return
		}
		// The same request while it is still pending returns that approval
		// rather than storing and notifying again (a double submit, or a
		// loop aimed at the approver's notifications).
		var existing int64
		if app.DB.QueryRow(`SELECT id FROM _benmore_approvals WHERE table_name = ? AND row_id = ? AND requested_by = ?
			AND approver_email = ? AND title = ? AND status = 'pending' ORDER BY id LIMIT 1`,
			b.Table, b.RowID, session.UserID, b.ApproverEmail, b.Title).Scan(&existing) == nil {
			httpJSON(w, http.StatusOK, map[string]any{"id": existing, "status": "pending"})
			return
		}
		if ok, retry, _ := approvalRequestLimiter.Check(appLimiterKey(app, "approval", strconv.FormatInt(session.UserID, 10))); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
			httpJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many approval requests; try again later"})
			return
		}
		var approverID sql.NullInt64
		if b.ApproverEmail != "" {
			app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = ?", b.ApproverEmail).Scan(&approverID)
		}
		res, err := app.DB.Exec(
			`INSERT INTO _benmore_approvals (table_name, row_id, requested_by, requested_email, approver_id, approver_email, title) VALUES (?,?,?,?,?,?,?)`,
			b.Table, b.RowID, session.UserID, session.Email, nullableInt(approverID), b.ApproverEmail, b.Title,
		)
		if err != nil {
			serverErrorJSON(w, r, app, "_approvals", err, "request failed")
			return
		}
		id, _ := res.LastInsertId()
		if approverID.Valid {
			CreateNotification(app.DB, approverID.Int64, "Approval requested", b.Title, "info", "")
		}
		httpJSON(w, http.StatusOK, map[string]any{"id": id, "status": "pending"})
	})
	mux.HandleFunc("GET /api/_approvals", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		q := "SELECT id, table_name, row_id, requested_by, requested_email, approver_email, title, status, note, created_at, decided_at FROM _benmore_approvals WHERE 1=1"
		args := []any{}
		t, rid := r.URL.Query().Get("table"), r.URL.Query().Get("row_id")
		if t != "" {
			q += " AND table_name = ?"
			args = append(args, t)
		}
		if rid != "" {
			q += " AND row_id = ?"
			args = append(args, rid)
		}
		// Approvals name people (emails), carry titles and decision notes,
		// and have no tenant column. Besides an admin, a caller sees the
		// approvals they requested or are asked to decide, and every approval
		// on a record they can read (the Approval component's history).
		if !session.IsAdminBypass() && !(t != "" && rid != "" && canAccessRow(app, t, rid, session)) {
			q += " AND (requested_by = ? OR approver_id = ?"
			args = append(args, session.UserID, session.UserID)
			if email := sessionGrantEmail(session); email != "" {
				q += " OR approver_email = ?"
				args = append(args, email)
			}
			q += ")"
		}
		// "mine" = pending approvals assigned to me (to act on).
		if r.URL.Query().Get("mine") == "1" {
			// An approval addressed by email belongs to a verified address.
			if email := sessionGrantEmail(session); email != "" {
				q += " AND (approver_id = ? OR approver_email = ?)"
				args = append(args, session.UserID, email)
			} else {
				q += " AND approver_id = ?"
				args = append(args, session.UserID)
			}
		}
		q += " ORDER BY created_at DESC LIMIT 200"
		rows, err := queryMetadataRows(app.DB, q, args...)
		if err != nil {
			serverErrorJSON(w, r, app, "_approvals", err, "query failed")
			return
		}
		httpJSON(w, http.StatusOK, map[string]any{"approvals": rows})
	})
	mux.HandleFunc("POST /api/_approvals/{id}/decide", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		if !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		var b struct {
			Decision string `json:"decision"` // approved | rejected
			Note     string `json:"note"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		if b.Decision != "approved" && b.Decision != "rejected" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "decision must be approved or rejected"})
			return
		}
		// Only the assigned approver (or an admin) may decide.
		var approverID sql.NullInt64
		var approverEmail, requestedEmail, title string
		var requestedBy int64
		app.DB.QueryRow("SELECT approver_id, approver_email, requested_by, requested_email, title FROM _benmore_approvals WHERE id = ?", r.PathValue("id")).
			Scan(&approverID, &approverEmail, &requestedBy, &requestedEmail, &title)
		isApprover := (approverID.Valid && approverID.Int64 == session.UserID) || (approverEmail != "" && approverEmail == sessionGrantEmail(session))
		if !isApprover && !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "not the assigned approver"})
			return
		}
		res, err := app.DB.Exec("UPDATE _benmore_approvals SET status=?, note=?, decided_at=? WHERE id=? AND status='pending'",
			b.Decision, b.Note, time.Now().UTC().Format(time.RFC3339), r.PathValue("id"))
		if err != nil {
			serverErrorJSON(w, r, app, "_approvals", err, "update failed")
			return
		}
		// Only the decision that changed the approval notifies the
		// requester; repeating it changes nothing and stays quiet.
		if n, _ := res.RowsAffected(); n == 1 {
			CreateNotification(app.DB, requestedBy, "Approval "+b.Decision, title, map[string]string{"approved": "success", "rejected": "warning"}[b.Decision], "")
		}
		httpJSON(w, http.StatusOK, map[string]any{"status": b.Decision})
	})
}

// parseWhen accepts RFC3339 or a Go duration ("2h", "30m") relative to now.
func parseWhen(s string) (time.Time, error) {
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if d, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(d), nil
	}
	return time.Time{}, errInvalidWhen
}

var errInvalidWhen = &timeParseError{}

type timeParseError struct{}

func (e *timeParseError) Error() string { return "invalid time" }

func nullableInt(n sql.NullInt64) any {
	if n.Valid {
		return n.Int64
	}
	return nil
}

// StartSchedulerSweeper fires due scheduled tasks every 30s until app.Stop.
func StartSchedulerSweeper(app *App) {
	if app == nil || app.DB == nil {
		return
	}
	// Tracked, so a `serve` process's Shutdown lets a sweep in progress (a
	// scheduled flow mid-run) finish before it closes the database.
	app.startJobRunner("scheduling.sweeper", func(stop <-chan struct{}) {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				select {
				case <-stop:
					return
				default:
				}
				sweepScheduledTasks(app)
			}
		}
	})
}

// schedTaskRecoveryTTL bounds how long a task may sit 'running' without its
// claim being refreshed before it's treated as orphaned by a crashed worker
// and re-queued. The sweeper refreshes claimed_at while a task runs
// (startScheduledTaskHeartbeat), so a slow flow is not mistaken for an orphan
// and fired a second time by the next generation's sweeper after a reload.
const schedTaskRecoveryTTL = 5 * time.Minute

// schedTaskHeartbeatInterval is how often a running task's claim is refreshed.
var schedTaskHeartbeatInterval = time.Minute

// schedTaskMaxRecoveries is how many times an orphaned task is put back
// before it is failed: a task whose run kills the process every time would
// otherwise be re-fired forever.
const schedTaskMaxRecoveries = 3

// startScheduledTaskHeartbeat refreshes a claimed task's claimed_at until the
// returned stop function is called.
func startScheduledTaskHeartbeat(app *App, id any) func() {
	done := make(chan struct{})
	safeGo("scheduling.heartbeat", func() {
		ticker := time.NewTicker(schedTaskHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				app.DB.Exec("UPDATE _benmore_scheduled_tasks SET claimed_at=? WHERE id=? AND status='running'", time.Now().UTC().Format(time.RFC3339), id)
			}
		}
	})
	return func() { close(done) }
}

var errScheduledFlowRateLimited = errors.New("flow rate limit reached; task will retry before executing any steps")

func sweepScheduledTasks(app *App) {
	now := time.Now().UTC()
	// Recover orphans: a task stuck 'running' past the TTL belongs to a worker
	// that died mid-fire (the sweeper would otherwise have set it done/failed).
	// Reset to pending so it fires again instead of being stranded forever.
	cutoff := now.Add(-schedTaskRecoveryTTL).Format(time.RFC3339)
	app.DB.Exec(
		"UPDATE _benmore_scheduled_tasks SET status='failed', claimed_at=NULL, fired_at=?, last_error=? WHERE status='running' AND claimed_at IS NOT NULL AND claimed_at <= ? AND recoveries >= ?",
		now.Format(time.RFC3339), fmt.Sprintf("worker died while running this task %d times; not run again", schedTaskMaxRecoveries+1), cutoff, schedTaskMaxRecoveries)
	app.DB.Exec(
		"UPDATE _benmore_scheduled_tasks SET status='pending', claimed_at=NULL, recoveries = recoveries + 1 WHERE status='running' AND claimed_at IS NOT NULL AND claimed_at <= ?",
		cutoff)

	rows, err := queryMetadataRows(app.DB,
		"SELECT id, user_id, kind, title, message, flow, body, authorization, last_error FROM _benmore_scheduled_tasks WHERE status IN ('pending','blocked') AND run_at <= ? ORDER BY CASE WHEN status='pending' THEN 0 ELSE 1 END, COALESCE(claimed_at,''), run_at ASC LIMIT 50",
		now.Format(time.RFC3339))
	if err != nil {
		return
	}
	for _, t := range rows {
		id := t["id"]
		kind, _ := t["kind"].(string)
		authorization, _ := t["authorization"].(string)
		if kind == "flow" {
			_, _, migrated, err := prepareScheduledFlow(app, t)
			if err != nil {
				reason := err.Error()
				if old, _ := t["last_error"].(string); old != reason {
					log.Printf("SCHEDULE blocked task=%v: %s", id, reason)
				}
				app.DB.Exec("UPDATE _benmore_scheduled_tasks SET status='blocked', last_error=?, claimed_at=? WHERE id=? AND status IN ('pending','blocked')", reason, now.Format(time.RFC3339Nano), id)
				continue
			}
			if authorization == "" {
				authorization = migrated
				t["authorization"] = migrated
			}
		}

		// H-15: atomically claim this task before doing any work. Mirrors
		// processNextJob's claim - flip pending->running only if WE win the
		// race (RowsAffected == 1). Without this guard two overlapping sweepers
		// (e.g. a transient overlap across a hot reload) both SELECT the same
		// pending row and double-fire its notification / scheduled flow.
		claim, claimErr := app.DB.Exec(
			"UPDATE _benmore_scheduled_tasks SET status='running', claimed_at=?, authorization=?, last_error='' WHERE id = ? AND status IN ('pending','blocked')",
			now.Format(time.RFC3339), authorization, id)
		if claimErr != nil {
			continue
		}
		if n, _ := claim.RowsAffected(); n != 1 {
			continue // another sweeper claimed it first
		}
		uid := toInt64(t["user_id"])
		title, _ := t["title"].(string)
		msg, _ := t["message"].(string)
		status := "done"
		lastError := ""
		if kind, _ := t["kind"].(string); kind == "flow" {
			stopHeartbeat := startScheduledTaskHeartbeat(app, id)
			err := executeScheduledFlow(app, t)
			stopHeartbeat()
			if err != nil {
				if errors.Is(err, errScheduledFlowRateLimited) {
					status, lastError = "blocked", err.Error()
				} else {
					status = "failed"
					lastError = "flow execution failed; see server log"
					log.Printf("SCHEDULE failed task=%v: %s", id, err)
				}
			}
		}

		if title == "" {
			title = "Reminder"
		}
		if status == "done" {
			CreateNotification(app.DB, uid, title, msg, "info", "")
		}
		var firedAt any
		if status != "blocked" {
			firedAt = time.Now().UTC().Format(time.RFC3339)
		}
		app.DB.Exec("UPDATE _benmore_scheduled_tasks SET status=?, fired_at=?, last_error=? WHERE id=?", status, firedAt, lastError, id)
	}
}

// HTTP flows retain their ordinary authorization policy. Non-HTTP service
// flows require a global administrator; scheduling cannot expose cron/event SQL
// to ordinary users. Request-signature and account-erasure flows are not delegable.
func schedulableFlow(app *App, name string, actor *Session) (*Flow, error) {
	if actor == nil || actor.ActingAsGroup != "" {
		return nil, fmt.Errorf("task owner is not authorized")
	}
	app.mu.RLock()
	defer app.mu.RUnlock()
	for _, flow := range app.Flows {
		if flow.Name != name {
			continue
		}
		if flow.Verify != "" || flow.VerifyConfig != nil || flowHasPurgeCurrentUser(flow.Steps) {
			return nil, fmt.Errorf("flow requires a live signed request or account-erasure confirmation")
		}
		if flow.Trigger.Type != "http" && !actor.GlobalAdmin {
			return nil, fmt.Errorf("internal flow requires a global administrator")
		}
		if flow.Role != "" && !HasAnyRole(actor, []string{flow.Role}) {
			return nil, fmt.Errorf("task owner no longer has the flow's required role")
		}
		if len(flow.Permissions) > 0 && !scopesWithin(actor.Scopes, strings.Join(flow.Permissions, " ")) {
			return nil, fmt.Errorf("task owner lacks the flow's required permissions")
		}
		// The scheduler is already a durable worker. Execute async HTTP definitions
		// inline here so request taint and actor permissions survive every step.
		flow.Async = false
		return &flow, nil
	}
	return nil, fmt.Errorf("scheduled flow no longer exists")
}

func executeScheduledFlow(app *App, task map[string]any) error {
	actor, flow, _, err := prepareScheduledFlow(app, task)
	if err != nil {
		return err
	}
	body, _ := task["body"].(string)
	if body == "" {
		body = "{}"
	}
	r, err := scheduledFlowRequest(flow, body)
	if err != nil {
		return err
	}
	w := &scheduledFlowResponse{header: make(http.Header)}
	if err := executeFlowHTTPAs(app, flow, w, r, actor); err != nil {
		return err
	}
	if w.status >= 400 {
		return fmt.Errorf("scheduled flow returned HTTP %d", w.status)
	}
	return nil
}

type scheduledFlowResponse struct {
	header http.Header
	status int
}

func (w *scheduledFlowResponse) Header() http.Header { return w.header }
func (w *scheduledFlowResponse) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *scheduledFlowResponse) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = 200
	}
	return len(b), nil
}
