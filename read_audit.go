//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Read audit logging: tracks WHO read WHAT WHEN for compliance (HIPAA, SOC2, GDPR).
// Developer configures which tables are read-audited via read_audit: in app.yaml.
// Writes are batched to avoid a DB insert on every API read.

// EnsureReadAuditTable creates the read audit log table.
func EnsureReadAuditTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_read_audit (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		table_name TEXT NOT NULL,
		row_id TEXT,
		query_type TEXT NOT NULL,
		user_id INTEGER NOT NULL,
		user_email TEXT NOT NULL,
		created_at DATETIME DEFAULT CURRENT_TIMESTAMP
	)`)
	db.Exec("CREATE INDEX IF NOT EXISTS idx_read_audit_table ON _benmore_read_audit(table_name, created_at DESC)")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_read_audit_user ON _benmore_read_audit(user_id, created_at DESC)")
}

// readAuditBuffer batches read audit entries and flushes periodically.
type readAuditBuffer struct {
	mu      sync.Mutex
	pending []readAuditEntry
	db      *sql.DB
	sync    bool // synchronous writes for HIPAA-critical apps
}

type readAuditEntry struct {
	Table     string
	RowID     string // empty for list queries
	QueryType string // "list" or "read"
	UserID    int64
	Email     string
}

var globalReadAudit *readAuditBuffer

// InitReadAudit starts the read audit buffer with periodic flush.
// Pass syncMode=true for HIPAA-critical apps (no data loss on crash).
func InitReadAudit(db *sql.DB, syncMode bool) {
	EnsureReadAuditTable(db)
	globalReadAudit = &readAuditBuffer{
		db:   db,
		sync: syncMode,
	}
	if syncMode {
		log.Printf("  read-audit: synchronous mode (HIPAA-compliant, no data loss)")
	}
	safeGo("readAudit.flush", func() {
		for {
			time.Sleep(5 * time.Second)
			globalReadAudit.flush()
		}
	})
}

// LogReadAccess records a read event. Batched by default (5s flush).
// For HIPAA-critical apps where no audit entry can be lost, the developer
// can set auth.read_audit_sync: true in app.yaml for synchronous writes.
func LogReadAccess(table, rowID, queryType string, session *Session) {
	if globalReadAudit == nil || session == nil {
		return
	}

	entry := readAuditEntry{
		Table:     table,
		RowID:     rowID,
		QueryType: queryType,
		UserID:    session.UserID,
		Email:     session.Email,
	}

	if globalReadAudit.sync {
		// Synchronous: write immediately, no data loss on crash
		globalReadAudit.db.Exec(
			"INSERT INTO _benmore_read_audit (table_name, row_id, query_type, user_id, user_email) VALUES (?, ?, ?, ?, ?)",
			entry.Table, entry.RowID, entry.QueryType, entry.UserID, entry.Email)
		return
	}

	globalReadAudit.mu.Lock()
	globalReadAudit.pending = append(globalReadAudit.pending, entry)
	globalReadAudit.mu.Unlock()
}

func (rab *readAuditBuffer) flush() {
	rab.mu.Lock()
	pending := rab.pending
	rab.pending = nil
	rab.mu.Unlock()

	if len(pending) == 0 {
		return
	}

	tx, err := rab.db.Begin()
	if err != nil {
		log.Printf("READ AUDIT flush error: %s", err)
		return
	}
	stmt, err := tx.Prepare("INSERT INTO _benmore_read_audit (table_name, row_id, query_type, user_id, user_email) VALUES (?, ?, ?, ?, ?)")
	if err != nil {
		tx.Rollback()
		return
	}
	for _, e := range pending {
		stmt.Exec(e.Table, e.RowID, e.QueryType, e.UserID, e.Email)
	}
	stmt.Close()
	tx.Commit()
}

// FlushReadAudit forces immediate write of pending entries. Used in tests.
func FlushReadAudit() {
	if globalReadAudit != nil {
		globalReadAudit.flush()
	}
}

// IsReadAudited checks if a table is configured for read audit logging.
func IsReadAudited(app *App, table string) bool {
	if app.Design == nil {
		return false
	}
	ra, ok := app.Design.Auth["read_audit"]
	if !ok {
		return false
	}
	// "read_audit: contacts,deals,patients" or "read_audit: *"
	if ra == "*" {
		return true
	}
	for _, t := range splitComma(ra) {
		if t == table {
			return true
		}
	}
	return false
}

func splitComma(s string) []string {
	var result []string
	for _, part := range strings.Split(s, ",") {
		t := strings.TrimSpace(part)
		if t != "" {
			result = append(result, t)
		}
	}
	return result
}

// RegisterReadAuditAPI sets up the compliance query endpoint.
func RegisterReadAuditAPI(mux *http.ServeMux, app *App) {
	// GET /api/_audit/reads - query read access logs.
	// Admin: sees all logs. Regular user: sees only their own (GDPR right of access).
	mux.HandleFunc("GET /api/_audit/reads", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}

		FlushReadAudit() // ensure current data

		table := r.URL.Query().Get("table")
		userID := r.URL.Query().Get("user_id")
		rowID := r.URL.Query().Get("row_id")
		limit := r.URL.Query().Get("limit")
		if limit == "" {
			limit = "100"
		}

		query := "SELECT table_name, row_id, query_type, user_id, user_email, created_at FROM _benmore_read_audit WHERE 1=1"
		var args []any

		// Non-admin users can only see their own read history
		if !session.IsAdmin() {
			query += " AND user_id = ?"
			args = append(args, session.UserID)
			// Ignore user_id filter param for non-admins (forced to own)
			userID = ""
		}

		if table != "" {
			query += " AND table_name = ?"
			args = append(args, table)
		}
		if userID != "" {
			query += " AND user_id = ?"
			args = append(args, userID)
		}
		if rowID != "" {
			query += " AND row_id = ?"
			args = append(args, rowID)
		}

		query += " ORDER BY created_at DESC LIMIT ?"
		args = append(args, limit)

		rows, err := QueryRows(app.DB, query, args...)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rows)
	})
}
