package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"reflect"
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
		status TEXT NOT NULL DEFAULT 'pending',   -- scheduledTaskStatuses: pending | blocked | running | done | failed | cancelled
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
		status TEXT NOT NULL DEFAULT 'pending',   -- approvalStatuses: pending | approved | rejected
		note TEXT DEFAULT '',
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		decided_at DATETIME
	)`)
	ensureApprovalPendingUnique(db)
}

// ensureApprovalPendingUnique drops the pending-request unique index an
// earlier build created: the account purge blanks approver_email, which can
// make two pending requests identical and then rolled back every deletion of
// that account. The create is one atomic INSERT ... WHERE NOT EXISTS instead.
func ensureApprovalPendingUnique(db *sql.DB) {
	db.Exec(`DROP INDEX IF EXISTS idx_approvals_pending_unique`)
}

// Status values of _benmore_approvals and _benmore_scheduled_tasks. The
// tables predate CHECK constraints and are not rebuilt for one; writers keep
// to these sets.
const (
	approvalStatusPending  = "pending"
	approvalStatusApproved = "approved"
	approvalStatusRejected = "rejected"

	scheduledTaskPending   = "pending"
	scheduledTaskBlocked   = "blocked"
	scheduledTaskRunning   = "running"
	scheduledTaskDone      = "done"
	scheduledTaskFailed    = "failed"
	scheduledTaskCancelled = "cancelled"
)

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
		// CSRF check (skip for Bearer-only requests; a session cookie keeps it).
		if !isBearerAuth(r) && !validateCSRF(r) {
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
			RowID   recordRowID     `json:"row_id"`
			RunAt   string          `json:"run_at"`
		}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": requestBodyDecodeError(err)})
			return
		}
		if b.RunAt == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "run_at required: an RFC3339 time or a duration like 2h/30m"})
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
				httpJSON(w, http.StatusForbidden, map[string]any{"error": scheduleCreateRefusal(err)})
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
			session.UserID, kind, title, b.Message, b.Flow, string(b.Body), b.Table, string(b.RowID), when.UTC().Format(time.RFC3339), authorization,
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
		// CSRF check (skip for Bearer-only requests; a session cookie keeps it).
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		// The answer names what is stored: it used to be 200 "cancelled" for
		// a task that had fired, was running, was not the caller's or did not
		// exist, and for a failed write.
		cancelled, stored, err := cancelScheduledTask(app.DB, r.PathValue("id"), session.UserID)
		switch {
		case err != nil:
			serverErrorJSON(w, r, app, "_schedule", err, "cancel failed")
		case cancelled:
			httpJSON(w, http.StatusOK, map[string]any{"status": "cancelled"})
		case stored == "":
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "scheduled task not found"})
		default:
			httpJSON(w, http.StatusConflict, map[string]any{"error": "scheduled task already " + stored, "status": stored})
		}
	})

	// ── Approvals ──
	mux.HandleFunc("POST /api/_approvals", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}
		// CSRF check (skip for Bearer-only requests; a session cookie keeps it).
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		// A support-impersonation or tooling "as" session acts for the user but
		// is driven by someone else (often an admin): letting it request here
		// and decide there would let one person approve their own request.
		if delegatedIdentitySession(app, session) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "a support or delegated session cannot request or decide approvals"})
			return
		}
		var b struct {
			Table         string      `json:"table"`
			RowID         recordRowID `json:"row_id"`
			ApproverEmail string      `json:"approver_email"`
			Title         string      `json:"title"`
		}
		if err := json.NewDecoder(r.Body).Decode(&b); err != nil {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": requestBodyDecodeError(err)})
			return
		}
		if b.Table == "" || b.RowID == "" {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "table and row_id required"})
			return
		}
		// The table in the schema's spelling: SQLite resolves a table name in
		// any letter case, so `Docs` is the app's `docs` and gets its checks.
		b.Table = approvalTableName(app, b.Table)
		// An approval on an app record joins that record's approval history,
		// which every reader of the record sees (GET below), so only a caller
		// who can read the record may request one. A table name that is not
		// an app table is a free-form label and stays private to the
		// requester and approver.
		if appHasTable(app, b.Table) && !canAccessRow(app, b.Table, string(b.RowID), session) {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "record not found"})
			return
		}
		// One address in any letter case, as at sign-in: stored and looked up
		// normalized, or `BOB@example.com` would reach nobody. ASCII letters
		// only, matching the COLLATE NOCASE lookups (approval_assignee.go).
		b.ApproverEmail = approvalAddressKey(b.ApproverEmail)
		// The account that has proven the address, if any (approval_assignee.go).
		// It is bound and notified below only when the record admits it as
		// approver (approval_audience.go).
		approverID, err := approvalApproverByEmail(app.DB, b.ApproverEmail)
		if err != nil {
			serverErrorJSON(w, r, app, "_approvals", err, "request failed")
			return
		}
		// Checked before the pending-duplicate lookup, so a legacy self-assigned
		// pending row cannot be re-submitted into a 200.
		// Nobody approves their own request: a status='approved' row is only
		// evidence of a second person's decision if the requester cannot name
		// themselves as the approver.
		if (approverID.Valid && approverID.Int64 == session.UserID) || (b.ApproverEmail != "" && strings.EqualFold(b.ApproverEmail, session.Email)) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "the approver must be someone other than the requester"})
			return
		}
		// The same request while it is still pending returns that approval
		// rather than storing and notifying again (a double submit, or a
		// loop aimed at the approver's notifications).
		var existing int64
		if app.DB.QueryRow(`SELECT id FROM _benmore_approvals WHERE table_name = ? AND row_id = ? AND requested_by = ?
			AND approver_email = ? COLLATE NOCASE AND title = ? AND status = 'pending' ORDER BY id LIMIT 1`,
			b.Table, string(b.RowID), session.UserID, b.ApproverEmail, b.Title).Scan(&existing) == nil {
			httpJSON(w, http.StatusOK, map[string]any{"id": existing, "status": "pending"})
			return
		}
		if ok, retry, _ := approvalRequestLimiter.Check(appLimiterKey(app, "approval", strconv.FormatInt(session.UserID, 10))); !ok {
			w.Header().Set("Retry-After", strconv.Itoa(int(retry.Seconds())+1))
			httpJSON(w, http.StatusTooManyRequests, map[string]any{"error": "too many approval requests; try again later"})
			return
		}
		// One statement runs under SQLite's write lock, so a concurrent
		// identical submit that stored the pending request first makes this
		// insert nothing; answer the stored one.
		res, err := app.DB.Exec(
			`INSERT INTO _benmore_approvals (table_name, row_id, requested_by, requested_email, approver_email, title)
			SELECT ?,?,?,?,?,? WHERE NOT EXISTS (SELECT 1 FROM _benmore_approvals WHERE table_name = ? AND row_id = ? AND requested_by = ?
				AND approver_email = ? AND title = ? AND status = 'pending')`,
			b.Table, string(b.RowID), session.UserID, session.Email, b.ApproverEmail, b.Title,
			b.Table, string(b.RowID), session.UserID, b.ApproverEmail, b.Title,
		)
		if err != nil {
			serverErrorJSON(w, r, app, "_approvals", err, "request failed")
			return
		}
		if n, _ := res.RowsAffected(); n == 0 {
			if err := app.DB.QueryRow(`SELECT id FROM _benmore_approvals WHERE table_name = ? AND row_id = ? AND requested_by = ?
				AND approver_email = ? AND title = ? AND status = 'pending' ORDER BY id LIMIT 1`,
				b.Table, string(b.RowID), session.UserID, b.ApproverEmail, b.Title).Scan(&existing); err != nil {
				serverErrorJSON(w, r, app, "_approvals", err, "request failed")
				return
			}
			httpJSON(w, http.StatusOK, map[string]any{"id": existing, "status": approvalStatusPending})
			return
		}
		id, _ := res.LastInsertId()
		// An account outside the record's tenant is not bound or notified:
		// the request is stored and answered like one naming an address
		// nobody holds, which says nothing about the account.
		if approverID.Valid {
			bound, err := approvalBindApprover(app, id, approverID.Int64, b.Table, string(b.RowID))
			if err != nil {
				serverErrorJSON(w, r, app, "_approvals", err, "request failed")
				return
			}
			if bound {
				CreateNotification(app.DB, approverID.Int64, "Approval requested", b.Title, "info", "")
			}
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
		written, rid := r.URL.Query().Get("table"), r.URL.Query().Get("row_id")
		// The table in the schema's spelling, as a request stores it, plus the
		// name as written: a request stored under another letter case of a
		// table name is a label (requester and approver only, below).
		t := approvalTableName(app, written)
		if t != "" {
			q += " AND table_name IN (?, ?)"
			args = append(args, t, written)
		}
		if rid != "" {
			q += " AND row_id = ?"
			args = append(args, rid)
		}
		// Approvals name people (emails), carry titles and decision notes,
		// and have no tenant column. Besides an admin, a caller sees the
		// approvals they requested or are asked to decide, and every approval
		// on a record they can read (the Approval component's history).
		// An approval addressed by email belongs to a verified address, and
		// one on a tenant's record to an account of that tenant
		// (approvalApproverSQL, the same test /decide applies).
		assigned, assignedArgs := approvalApproverSQL(app, session)
		if !session.IsAdminBypass() {
			if t != "" && rid != "" && canAccessRow(app, t, rid, session) {
				q += " AND (table_name = ? OR requested_by = ? OR " + assigned + ")"
				args = append(args, t)
			} else {
				q += " AND (requested_by = ? OR " + assigned + ")"
			}
			args = append(append(args, session.UserID), assignedArgs...)
		}
		// "mine" = pending approvals assigned to me (to act on).
		if r.URL.Query().Get("mine") == "1" {
			q += " AND " + assigned
			args = append(args, assignedArgs...)
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
		// CSRF check (skip for Bearer-only requests; a session cookie keeps it).
		if !isBearerAuth(r) && !validateCSRF(r) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
			return
		}
		// A support-impersonation or tooling "as" session acts for the user but
		// is driven by someone else (often an admin): letting it request here
		// and decide there would let one person approve their own request.
		if delegatedIdentitySession(app, session) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "a support or delegated session cannot request or decide approvals"})
			return
		}
		var b struct {
			Decision string `json:"decision"` // approved | rejected
			Note     string `json:"note"`
		}
		json.NewDecoder(r.Body).Decode(&b)
		if b.Decision != approvalStatusApproved && b.Decision != approvalStatusRejected {
			httpJSON(w, http.StatusBadRequest, map[string]any{"error": "decision must be approved or rejected"})
			return
		}
		// Only the assigned approver (or an admin) may decide. Assigned is the
		// test the list applies (approvalApproverSQL): a request addressed by
		// email belongs to the account that has proven that address, and one
		// on a tenant's record only while that account is in the tenant.
		var isApprover bool
		var requestedEmail, title string
		var requestedBy int64
		id := r.PathValue("id")
		assigned, assignedArgs := approvalApproverSQL(app, session)
		scanErr := app.DB.QueryRow("SELECT COALESCE("+assigned+", 0), requested_by, requested_email, title FROM _benmore_approvals WHERE id = ?", append(assignedArgs, id)...).
			Scan(&isApprover, &requestedBy, &requestedEmail, &title)
		if scanErr != nil && !errors.Is(scanErr, sql.ErrNoRows) {
			serverErrorJSON(w, r, app, "_approvals", scanErr, "query failed")
			return
		}
		if !isApprover && !session.IsAdminConsole() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "not the assigned approver"})
			return
		}
		// Only an admin reaches here for an id that does not exist (a
		// non-approver was refused above, so the 403 is no existence oracle).
		if errors.Is(scanErr, sql.ErrNoRows) {
			httpJSON(w, http.StatusNotFound, map[string]any{"error": "approval not found"})
			return
		}
		// The requester never decides their own request, admin or not (a
		// legacy self-assigned row stays pending until someone else decides).
		if session.UserID == requestedBy || (requestedEmail != "" && strings.EqualFold(requestedEmail, session.Email)) {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "the requester cannot decide their own request"})
			return
		}
		res, err := app.DB.Exec("UPDATE _benmore_approvals SET status=?, note=?, decided_at=? WHERE id=? AND status='pending'",
			b.Decision, b.Note, time.Now().UTC().Format(time.RFC3339), id)
		if err != nil {
			serverErrorJSON(w, r, app, "_approvals", err, "update failed")
			return
		}
		// The response must name what is stored. A decision that changed
		// nothing answers with the stored status: repeating the same
		// decision (with the same note, or none) stays 200 and quiet, anything
		// else is a 409.
		if n, _ := res.RowsAffected(); n != 1 {
			var current string
			var storedNote sql.NullString
			if err := app.DB.QueryRow("SELECT status, note FROM _benmore_approvals WHERE id = ?", id).Scan(&current, &storedNote); err != nil {
				// Deleted since the first read (an account purge): the caller
				// was entitled to know it existed, so it is simply gone now.
				if errors.Is(err, sql.ErrNoRows) {
					httpJSON(w, http.StatusNotFound, map[string]any{"error": "approval not found"})
					return
				}
				serverErrorJSON(w, r, app, "_approvals", err, "query failed")
				return
			}
			// A repeat is a 200 only when it asks for what is stored; a
			// different note would be dropped silently, so that is a 409 too.
			if current == b.Decision && (b.Note == "" || b.Note == storedNote.String) {
				httpJSON(w, http.StatusOK, map[string]any{"status": current})
				return
			}
			httpJSON(w, http.StatusConflict, map[string]any{"error": "approval already " + current, "status": current})
			return
		}
		CreateNotification(app.DB, requestedBy, "Approval "+b.Decision, title, map[string]string{"approved": "success", "rejected": "warning"}[b.Decision], "")
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

// schedTaskStampLayout is the one format of claimed_at: UTC with fixed-width
// nanoseconds, so the text column orders and compares lexically. A claim
// stamp is also the claim's identity (see startScheduledTaskHeartbeat).
const schedTaskStampLayout = "2006-01-02T15:04:05.000000000Z"

func schedTaskStamp() string { return time.Now().UTC().Format(schedTaskStampLayout) }

// startScheduledTaskHeartbeat refreshes a claimed task's claimed_at, a
// compare-and-swap from the stamp this run holds to a new one, until the
// returned stop function is called. Stop waits for the refresher to end and
// returns the stamp the claim holds now, which the final UPDATE must match:
// if another sweeper recovered and re-claimed the task, the swap changes no
// row, the refresher stops and the stale stamp makes the final UPDATE lose.
func startScheduledTaskHeartbeat(app *App, id any, stamp string) func() string {
	done := make(chan struct{})
	final := make(chan string, 1)
	safeGo("scheduling.heartbeat", func() {
		defer func() { final <- stamp }()
		ticker := time.NewTicker(schedTaskHeartbeatInterval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				next := schedTaskStamp()
				res, err := app.DB.Exec("UPDATE _benmore_scheduled_tasks SET claimed_at=? WHERE id=? AND status='running' AND claimed_at=?", next, id, stamp)
				if err != nil {
					continue // keep the stamp and retry on the next tick
				}
				if n, _ := res.RowsAffected(); n != 1 {
					return // the claim is no longer ours
				}
				stamp = next
			}
		}
	})
	return func() string { close(done); return <-final }
}

var errScheduledFlowRateLimited = errors.New("flow rate limit reached; task will retry before executing any steps")

func sweepScheduledTasks(app *App) {
	now := time.Now().UTC()
	// Recover orphans: a task stuck 'running' past the TTL belongs to a worker
	// that died mid-fire (the sweeper would otherwise have set it done/failed).
	// Reset to pending so it fires again instead of being stranded forever.
	cutoff := now.Add(-schedTaskRecoveryTTL).Format(schedTaskStampLayout)
	app.DB.Exec(
		"UPDATE _benmore_scheduled_tasks SET status='failed', claimed_at=NULL, fired_at=?, last_error=? WHERE status='running' AND claimed_at IS NOT NULL AND claimed_at <= ? AND recoveries >= ?",
		now.Format(time.RFC3339), fmt.Sprintf("worker died while running this task %d times; not run again", schedTaskMaxRecoveries+1), cutoff, schedTaskMaxRecoveries)
	// A flow task may have run steps (sent mail, charged a card) before its
	// worker died, and the table cannot tell how far it got. As for jobs (C-1,
	// jobsRecoverOrphanedJobs) it is re-run only when its flow is declared
	// idempotent; otherwise it fails closed for an admin to look at. Reminders
	// only post a notification and keep being re-pended.
	notRerunnable, notRerunnableArgs := "kind = 'flow'", []any{}
	if idem := idempotentFlowJobNames(app); len(idem) > 0 {
		notRerunnable += " AND COALESCE(flow,'') NOT IN (?" + strings.Repeat(",?", len(idem)-1) + ")"
		for _, name := range idem {
			notRerunnableArgs = append(notRerunnableArgs, name)
		}
	}
	// Each statement's error is checked and logged: the re-pend below also
	// excludes the not-rerunnable tasks, so a failed fail-closed statement
	// (SQLITE_BUSY) leaves them 'running' for the next sweep instead of
	// re-running them.
	closed, err := app.DB.Exec(
		"UPDATE _benmore_scheduled_tasks SET status='failed', claimed_at=NULL, fired_at=?, last_error=? WHERE status='running' AND claimed_at IS NOT NULL AND claimed_at <= ? AND "+notRerunnable,
		append([]any{now.Format(time.RFC3339), "worker died while running this flow task; not run again because the flow is not marked idempotent (it may already have run some steps)", cutoff}, notRerunnableArgs...)...)
	if err != nil {
		log.Printf("SCHEDULE recovery (fail closed) failed: %v", err)
	} else if n, _ := closed.RowsAffected(); n > 0 {
		// Nobody else learns of this: GET /api/_scheduled lists only the owner's tasks.
		log.Printf("SCHEDULE failed closed: %d orphaned flow task(s) not re-run (the flow is not idempotent)", n)
	}
	if _, err := app.DB.Exec(
		"UPDATE _benmore_scheduled_tasks SET status='pending', claimed_at=NULL, recoveries = recoveries + 1 WHERE status='running' AND claimed_at IS NOT NULL AND claimed_at <= ? AND recoveries < ? AND NOT ("+notRerunnable+")",
		append([]any{cutoff, schedTaskMaxRecoveries}, notRerunnableArgs...)...); err != nil {
		log.Printf("SCHEDULE recovery (re-pend) failed: %v", err)
	}

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
				app.DB.Exec("UPDATE _benmore_scheduled_tasks SET status='blocked', last_error=?, claimed_at=? WHERE id=? AND status IN ('pending','blocked')", reason, schedTaskStamp(), id)
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
		// The stamp is taken here, at the claim, not at the sweep's start: a
		// sweep that has run for minutes would otherwise write claims that are
		// already old enough for another sweeper to recover.
		stamp := schedTaskStamp()
		claim, claimErr := app.DB.Exec(
			"UPDATE _benmore_scheduled_tasks SET status='running', claimed_at=?, authorization=?, last_error='' WHERE id = ? AND status IN ('pending','blocked')",
			stamp, authorization, id)
		if claimErr != nil {
			continue
		}
		if n, _ := claim.RowsAffected(); n != 1 {
			continue // another sweeper claimed it first
		}
		uid := toInt64(t["user_id"])
		title, _ := t["title"].(string)
		msg, _ := t["message"].(string)
		status := scheduledTaskDone
		lastError := ""
		if kind, _ := t["kind"].(string); kind == "flow" {
			stopHeartbeat := startScheduledTaskHeartbeat(app, id, stamp)
			err := executeScheduledFlow(app, t)
			stamp = stopHeartbeat()
			if err != nil {
				if errors.Is(err, errScheduledFlowRateLimited) {
					status, lastError = scheduledTaskBlocked, err.Error()
				} else {
					status = scheduledTaskFailed
					lastError = "flow execution failed; see server log"
					// The raw step error can quote an api URL with its env token.
					log.Printf("SCHEDULE failed task=%v: %s", id, jobErrorText(app, errorText(err)))
				}
			}
		}

		if title == "" {
			title = "Reminder"
		}
		if status == scheduledTaskDone {
			CreateNotification(app.DB, uid, title, msg, "info", "")
		}
		var firedAt any
		if status != scheduledTaskBlocked {
			firedAt = time.Now().UTC().Format(time.RFC3339)
		}
		// Record the result only for the run that still holds the claim; a
		// stale finisher must not overwrite a recovered, re-claimed run.
		fin, finErr := app.DB.Exec("UPDATE _benmore_scheduled_tasks SET status=?, fired_at=?, last_error=? WHERE id=? AND status='running' AND claimed_at=?", status, firedAt, lastError, id, stamp)
		if finErr != nil {
			log.Printf("SCHEDULE could not record result task=%v: %v", id, finErr)
		} else if n, _ := fin.RowsAffected(); n != 1 {
			log.Printf("SCHEDULE lost claim task=%v: result %q not recorded (the claim was recovered or replaced)", id, status)
		}
	}
}

// recordRowID is a request's row_id: the id of the record a task or approval
// is about. Record ids are usually integers and clients send them as JSON
// numbers, so a number is accepted as well as a string; both are stored as
// text. It used to be a plain string field, so `"row_id": 1` failed to decode
// and the scheduling route blamed run_at (round 2026-11-05).
type recordRowID string

var errRecordRowIDType = errors.New("row_id must be a string or an integer")

func (id *recordRowID) UnmarshalJSON(data []byte) error {
	text := strings.TrimSpace(string(data))
	switch {
	case text == "null":
		*id = ""
		return nil
	case strings.HasPrefix(text, `"`):
		var s string
		if err := json.Unmarshal(data, &s); err != nil {
			return errRecordRowIDType
		}
		*id = recordRowID(s)
		return nil
	}
	n, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return errRecordRowIDType
	}
	*id = recordRowID(strconv.FormatInt(n, 10))
	return nil
}

// requestBodyDecodeError says why a JSON request body could not be decoded,
// in the request's terms: a field of the wrong type is named, a body that is
// not one JSON object says so. The decoder's own text names Go types.
func requestBodyDecodeError(err error) string {
	if errors.Is(err, errRecordRowIDType) {
		return errRecordRowIDType.Error()
	}
	var typeErr *json.UnmarshalTypeError
	if errors.As(err, &typeErr) && typeErr.Field != "" {
		want := "a string"
		switch typeErr.Type.Kind() {
		case reflect.Bool:
			want = "a boolean"
		case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64,
			reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64,
			reflect.Float32, reflect.Float64:
			want = "a number"
		case reflect.Map, reflect.Struct:
			want = "an object"
		case reflect.Slice, reflect.Array:
			want = "a list"
		}
		return fmt.Sprintf("%q must be %s, not a JSON %s", typeErr.Field, want, typeErr.Value)
	}
	return "request body must be a JSON object"
}

// The reasons schedulableFlow gives. They are stored as a blocked task's
// last_error when the sweeper re-checks a task before it fires, so they are
// worded for an existing task; scheduleCreateRefusal words them for the
// caller creating one.
var (
	errScheduledFlowMissing     = errors.New("scheduled flow no longer exists")
	errScheduledFlowRole        = errors.New("task owner no longer has the flow's required role")
	errScheduledFlowPermissions = errors.New("task owner lacks the flow's required permissions")
)

// scheduleCreateRefusal is the answer to POST /api/_scheduled when the caller
// may not schedule the flow. A role gate the caller never passed was reported
// as "task owner no longer has the flow's required role" (round 2026-11-05).
func scheduleCreateRefusal(err error) string {
	switch {
	case errors.Is(err, errScheduledFlowMissing):
		return "no flow with this name exists"
	case errors.Is(err, errScheduledFlowRole):
		return "you do not hold the role this flow requires"
	case errors.Is(err, errScheduledFlowPermissions):
		return "your credential lacks the permissions this flow requires"
	}
	return err.Error()
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
		if flow.Role != "" && !flowRoleAllowed(actor, flow.Role) {
			return nil, errScheduledFlowRole
		}
		if len(flow.Permissions) > 0 && !scopesWithin(actor.Scopes, strings.Join(flow.Permissions, " ")) {
			return nil, errScheduledFlowPermissions
		}
		// The run happens under the scheduling credential, so a scoped one
		// may schedule only a flow it could call directly: refused once the
		// operator enforces the rule, noted until then
		// (flows_scoped_credentials.go).
		if scopedFlowUnpermitted(&flow, actor) {
			if scopedFlowsRequirePermissions() {
				return nil, fmt.Errorf("a scoped credential can schedule only a flow that declares permissions: within its scopes")
			}
			logScopedFlowAdvisory(app, &flow, actor, false)
		}
		// The scheduler is already a durable worker. Execute async HTTP definitions
		// inline here so request taint and actor permissions survive every step.
		flow.Async = false
		return &flow, nil
	}
	return nil, errScheduledFlowMissing
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
