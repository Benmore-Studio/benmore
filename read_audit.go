//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	readAuditDefaultLimit = 100
	readAuditMaxLimit     = 1000
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

// InitReadAudit starts the read audit buffer with periodic flush.
// Pass syncMode=true to write each read immediately rather than buffer it.
func InitReadAudit(app *App, syncMode bool) {
	EnsureReadAuditTable(app.DB)
	app.mu.Lock()
	if app.readAudit == nil {
		app.readAudit = &readAuditBuffer{db: app.DB}
	}
	buffer := app.readAudit
	app.mu.Unlock()
	buffer.mu.Lock()
	buffer.sync = syncMode
	buffer.mu.Unlock()
	if syncMode {
		log.Printf("  read-audit: synchronous writes enabled")
	}
	app.startWorker("readAudit.flush", func(stop <-chan struct{}) {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		defer buffer.flush()
		for {
			select {
			case <-stop:
				return
			case <-ticker.C:
				buffer.flush()
			}
		}
	})
}

func appReadAudit(app *App) *readAuditBuffer {
	if app == nil {
		return nil
	}
	if app.auditOwner != nil {
		return appReadAudit(app.auditOwner)
	}
	app.mu.RLock()
	defer app.mu.RUnlock()
	return app.readAudit
}

// LogReadAccess records a read event. Batched by default (5s flush).
// Set auth.read_audit_sync: true in app.yaml for synchronous writes. Database
// failures still need operational handling; this buffer is not a durable queue.
func LogReadAccess(app *App, table, rowID, queryType string, session *Session) {
	buffer := appReadAudit(app)
	if buffer == nil || session == nil {
		return
	}

	entry := readAuditEntry{
		Table:     table,
		RowID:     rowID,
		QueryType: queryType,
		UserID:    session.UserID,
		Email:     session.Email,
	}

	buffer.mu.Lock()
	syncMode := buffer.sync
	if !syncMode {
		buffer.pending = append(buffer.pending, entry)
	}
	buffer.mu.Unlock()
	if syncMode {
		// Synchronous: write immediately instead of waiting for the flush.
		buffer.db.Exec(
			"INSERT INTO _benmore_read_audit (table_name, row_id, query_type, user_id, user_email) VALUES (?, ?, ?, ?, ?)",
			entry.Table, entry.RowID, entry.QueryType, entry.UserID, entry.Email)
	}
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
func FlushReadAudit(app *App) {
	if buffer := appReadAudit(app); buffer != nil {
		buffer.flush()
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
func RegisterReadAuditAPI(mux appRouteRegistrar, app *App) {
	// GET /api/_audit/reads - query read access logs.
	// Admin: sees all logs. Regular user: sees only their own (GDPR right of access).
	mux.HandleFunc("GET /api/_audit/reads", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}

		limit := readAuditDefaultLimit
		if raw := r.URL.Query().Get("limit"); raw != "" {
			parsed, err := strconv.Atoi(raw)
			if err != nil || parsed < 1 || parsed > readAuditMaxLimit {
				httpJSON(w, http.StatusBadRequest, map[string]any{"error": "limit must be an integer between 1 and 1000"})
				return
			}
			limit = parsed
		}

		FlushReadAudit(app) // ensure current data for this app only

		table := r.URL.Query().Get("table")
		userID := r.URL.Query().Get("user_id")
		rowID := r.URL.Query().Get("row_id")

		query := "SELECT table_name, row_id, query_type, user_id, user_email, created_at FROM _benmore_read_audit WHERE 1=1"
		var args []any

		// Non-admin users can only see their own read history
		if !session.IsAdminConsole() {
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

		rows, err := queryMetadataRows(app.DB, query, args...)
		if err != nil {
			serverErrorJSON(w, r, app, "_read_audit", err, "query failed")
			return
		}

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(rows)
	})
}
