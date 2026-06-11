package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
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

// RegisterSchedulingAPI wires the scheduled-tasks + approvals endpoints
// and starts the per-app sweeper.
func RegisterSchedulingAPI(mux *http.ServeMux, app *App) {
	EnsureSchedulingTables(app.DB)
	StartSchedulerSweeper(app)

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
		title := b.Title
		if title == "" {
			title = "Reminder"
		}
		res, err := app.DB.Exec(
			`INSERT INTO _benmore_scheduled_tasks (user_id, kind, title, message, flow, body, table_name, row_id, run_at) VALUES (?,?,?,?,?,?,?,?,?)`,
			session.UserID, kind, title, b.Message, b.Flow, string(b.Body), b.Table, b.RowID, when.UTC().Format(time.RFC3339),
		)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "schedule failed"})
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
		q := "SELECT id, kind, title, message, flow, table_name, row_id, run_at, status, fired_at FROM _benmore_scheduled_tasks WHERE user_id = ?"
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
		rows, err := QueryRows(app.DB, q, args...)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
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
		app.DB.Exec("UPDATE _benmore_scheduled_tasks SET status='cancelled' WHERE id = ? AND user_id = ? AND status='pending'", r.PathValue("id"), session.UserID)
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
		var approverID sql.NullInt64
		if b.ApproverEmail != "" {
			app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = ?", b.ApproverEmail).Scan(&approverID)
		}
		res, err := app.DB.Exec(
			`INSERT INTO _benmore_approvals (table_name, row_id, requested_by, requested_email, approver_id, approver_email, title) VALUES (?,?,?,?,?,?,?)`,
			b.Table, b.RowID, session.UserID, session.Email, nullableInt(approverID), b.ApproverEmail, b.Title,
		)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "request failed"})
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
		if t := r.URL.Query().Get("table"); t != "" {
			q += " AND table_name = ?"
			args = append(args, t)
		}
		if rid := r.URL.Query().Get("row_id"); rid != "" {
			q += " AND row_id = ?"
			args = append(args, rid)
		}
		// "mine" = pending approvals assigned to me (to act on).
		if r.URL.Query().Get("mine") == "1" {
			q += " AND (approver_id = ? OR approver_email = ?)"
			args = append(args, session.UserID, session.Email)
		}
		q += " ORDER BY created_at DESC LIMIT 200"
		rows, err := QueryRows(app.DB, q, args...)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
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
		isApprover := (approverID.Valid && approverID.Int64 == session.UserID) || (approverEmail != "" && approverEmail == session.Email)
		if !isApprover && !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "not the assigned approver"})
			return
		}
		_, err := app.DB.Exec("UPDATE _benmore_approvals SET status=?, note=?, decided_at=? WHERE id=? AND status='pending'",
			b.Decision, b.Note, time.Now().UTC().Format(time.RFC3339), r.PathValue("id"))
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "update failed"})
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
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-app.Stop:
				return
			case <-ticker.C:
				sweepScheduledTasks(app)
			}
		}
	}()
}

func sweepScheduledTasks(app *App) {
	rows, err := QueryRows(app.DB,
		"SELECT id, user_id, kind, title, message, flow, body FROM _benmore_scheduled_tasks WHERE status='pending' AND run_at <= ? ORDER BY run_at ASC LIMIT 50",
		time.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return
	}
	for _, t := range rows {
		id := t["id"]
		uid := toInt64(t["user_id"])
		title, _ := t["title"].(string)
		msg, _ := t["message"].(string)
		status := "done"
		if kind, _ := t["kind"].(string); kind == "flow" {
			if flow, _ := t["flow"].(string); flow != "" {
				var data map[string]any
				if bs, _ := t["body"].(string); bs != "" {
					json.Unmarshal([]byte(bs), &data)
				}
				if err := executeFlowJob(app, flow, data); err != nil {
					status = "failed"
				}
			}
		}
		if title == "" {
			title = "Reminder"
		}
		CreateNotification(app.DB, uid, title, msg, "info", "")
		app.DB.Exec("UPDATE _benmore_scheduled_tasks SET status=?, fired_at=? WHERE id=?", status, time.Now().UTC().Format(time.RFC3339), id)
	}
}
