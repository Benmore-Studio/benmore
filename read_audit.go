//go:build !cli

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

// EnsureReadAuditTable creates the read audit log table. client_ip was added
// later (an additive column; rows from before it hold NULL).
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
	if cols, err := GetTableColumns(db, "_benmore_read_audit"); err == nil && !hasColumnInList(cols, "client_ip") {
		if _, err := db.Exec(`ALTER TABLE _benmore_read_audit ADD COLUMN client_ip TEXT`); err != nil {
			log.Printf("READ AUDIT: add client_ip column: %v", err)
		}
	}
}

// readAuditBuffer batches read audit entries and flushes periodically.
type readAuditBuffer struct {
	mu      sync.Mutex
	pending []readAuditEntry
	db      *sql.DB
	sync    bool // synchronous writes (auth.read_audit_sync, always under compliance: hipaa)
}

type readAuditEntry struct {
	Table     string
	RowID     string // empty for list queries
	QueryType string // "list", "read", "flow_sql", "admin_list", ...
	UserID    int64  // 0 for an anonymous or system read
	Email     string // the reader's address, "anonymous" or "system:<query type>"
	IP        string // client address of the HTTP request, empty without one
}

const readAuditInsertSQL = "INSERT INTO _benmore_read_audit (table_name, row_id, query_type, user_id, user_email, client_ip) VALUES (?, ?, ?, ?, ?, ?)"

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

// errReadAuditUnavailable is a hipaa read of an audited table in a process
// that has no read audit to record it in.
var errReadAuditUnavailable = errors.New("read audit is not running")

// LogReadAccess records a read of an audited table (callers check
// IsReadAudited). The reader is the session, else "anonymous" for an HTTP
// request (r) without one, else "system:<queryType>" (a cron, job or event
// flow); the client address comes from r. Batched by default (5s flush);
// auth.read_audit_sync: true, and always compliance: hipaa, write it before
// returning.
//
// An anonymous read is recorded only under compliance: hipaa, and never for a
// table whose read mode is anon/everyone (public data: recording every crawler
// hit would fill an append-only table nothing may delete).
//
// Under compliance: hipaa a failed write returns an error and the caller
// refuses the read (fail closed). Otherwise the error is logged and nil is
// returned, so the read goes on as before.
func LogReadAccess(app *App, r *http.Request, table, rowID, queryType string, session *Session) error {
	entry, buffer, syncMode, err := readAuditEvent(app, r, table, rowID, queryType, session)
	if err != nil || !syncMode {
		return err
	}
	return writeReadAuditEntries(app, buffer, []readAuditEntry{entry})
}

// readAuditEvent builds the event for a read and queues it when the app
// batches; syncMode reports that the caller must write it. A read that is not
// recorded (anonymous outside hipaa or on a public table, no buffer outside
// hipaa) returns syncMode false and no error.
func readAuditEvent(app *App, r *http.Request, table, rowID, queryType string, session *Session) (readAuditEntry, *readAuditBuffer, bool, error) {
	entry := readAuditEntry{Table: table, RowID: rowID, QueryType: queryType}
	if session == nil && r != nil && (!app.hipaa() || tablePubliclyReadable(app, table)) {
		return entry, nil, false, nil
	}
	buffer := appReadAudit(app)
	if buffer == nil {
		if app.hipaa() {
			return entry, nil, false, errReadAuditUnavailable
		}
		return entry, nil, false, nil
	}
	switch {
	case session != nil:
		entry.UserID, entry.Email = session.UserID, session.Email
	case r != nil:
		entry.Email = "anonymous"
	default:
		entry.Email = "system:" + queryType
	}
	if r != nil {
		entry.IP = clientIP(r)
	}
	buffer.mu.Lock()
	syncMode := buffer.sync || app.hipaa()
	if !syncMode {
		buffer.pending = append(buffer.pending, entry)
	}
	buffer.mu.Unlock()
	return entry, buffer, syncMode, nil
}

// tablePubliclyReadable reports a table whose effective read mode is anon or
// everyone, decided as realtimeAudienceFor decides it.
func tablePubliclyReadable(app *App, table string) bool {
	if app == nil || app.Access == nil {
		return false
	}
	grouped := app.Group != nil && app.Group.Key != "" && hasColumn(app, table, app.Group.Key)
	mode := app.Access.ModeFor(table, OpRead, hasColumn(app, table, "user_id"), grouped)
	return mode == "anon" || mode == "everyone"
}

// writeReadAuditEntries writes synchronous events on the app's own pool.
func writeReadAuditEntries(app *App, buffer *readAuditBuffer, entries []readAuditEntry) error {
	err := buffer.write(entries)
	if err == nil {
		return nil
	}
	for _, e := range entries {
		log.Printf("READ AUDIT write failed (%s %s by %s): %v", e.QueryType, e.Table, readAuditLogActor(e), err)
	}
	if app.hipaa() {
		return fmt.Errorf("read audit: %w", err)
	}
	return nil
}

// flushFlowTxReadAudit writes the read events a transactional flow collected
// (auditFlowSQLRead), once its transaction has committed or rolled back: a
// read happened either way, and the rows may already have left the app (a
// `run: api` step before the failure). Called from announceFlowWrites, which
// every transaction owner calls after Commit/Rollback has returned, so the
// write never waits on the flow's own lock and never rolls back with it.
// Under compliance: hipaa a failed write is also kept on ctx.readAuditErr, so
// the HTTP owner answers 5xx instead of releasing the buffered rows.
func flushFlowTxReadAudit(ctx *FlowContext) {
	if ctx == nil || ctx.App == nil || ctx.Writes == nil {
		return
	}
	entries := ctx.Writes.takeReads()
	if len(entries) == 0 {
		return
	}
	buffer := appReadAudit(ctx.App)
	if buffer == nil {
		log.Printf("READ AUDIT LOST: %d read events of a transactional flow not recorded: read audit is not running; the rows were read and may already have left the app", len(entries))
		if ctx.App.hipaa() {
			ctx.readAuditErr = errors.New("read audit is not running")
		}
		return
	}
	if err := buffer.write(entries); err != nil {
		level := "READ AUDIT"
		if ctx.App.hipaa() {
			level = "READ AUDIT LOST (compliance: hipaa)"
			ctx.readAuditErr = fmt.Errorf("read audit write failed: %w", err)
		}
		log.Printf("%s: %d read events of a transactional flow not recorded after its transaction ended; the rows were read and may already have left the app: %v", level, len(entries), err)
	}
}

// readAuditLogActor names the reader in a log line by id, never by address.
func readAuditLogActor(e readAuditEntry) string {
	if e.UserID != 0 {
		return fmt.Sprintf("user %d", e.UserID)
	}
	return e.Email
}

// readAuditRefused answers a read whose required audit row could not be
// written (compliance: hipaa): a 5xx, never the rows.
func readAuditRefused(w http.ResponseWriter, r *http.Request, app *App, table string, err error) {
	serverErrorJSON(w, r, app, table, err, "read audit unavailable")
}

func (rab *readAuditBuffer) flush() {
	rab.mu.Lock()
	pending := rab.pending
	rab.pending = nil
	rab.mu.Unlock()

	if len(pending) == 0 {
		return
	}
	if err := rab.write(pending); err != nil {
		// The buffer is not a durable queue: these events are lost. Say so.
		log.Printf("READ AUDIT flush failed, %d read events not recorded: %v", len(pending), err)
	}
}

func (rab *readAuditBuffer) write(pending []readAuditEntry) error {
	tx, err := rab.db.Begin()
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.Prepare(readAuditInsertSQL)
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, e := range pending {
		if _, err := stmt.Exec(e.Table, e.RowID, e.QueryType, e.UserID, e.Email, e.IP); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// auditFlowSQLRead records a flow `run: sql` / `sql_dynamic` statement that
// produces a result set (any SELECT, even one matching no row, and a write
// with RETURNING): one read event per audited table it names (query_type
// flow_sql). The reader is the flow's session, else "anonymous" for a public
// request (hipaa only, never a public table), else "system:flow_sql" (cron,
// jobs, data events). Inside a transaction the events are written after it
// ends (flushFlowTxReadAudit).
func auditFlowSQLRead(ctx *FlowContext, query string) error {
	if ctx.command != nil {
		// shortcut: an approved connector command runs under an authorizer
		// that refuses _benmore_* writes and holds the write lock; its reads
		// are recorded by the command's own sealed operation and audit rows,
		// not here. Route through a framework-admitted insert if commands
		// need read events too.
		return nil
	}
	var sync []readAuditEntry
	var buffer *readAuditBuffer
	for _, table := range readAuditedSQLTables(ctx.App, query) {
		entry, b, syncMode, err := readAuditEvent(ctx.App, ctx.Request, table, "", "flow_sql", ctx.Session)
		if err != nil {
			return err
		}
		if syncMode {
			sync, buffer = append(sync, entry), b
		}
	}
	if len(sync) == 0 {
		return nil
	}
	if ctx.Tx != nil {
		// The transaction holds the write lock, and an event written through
		// it would roll back with a failed run although the read happened:
		// write it once the transaction has ended (flushFlowTxReadAudit).
		if ctx.Writes == nil {
			ctx.Writes = newFlowWriteLog()
		}
		ctx.Writes.addReads(sync)
		return nil
	}
	return writeReadAuditEntries(ctx.App, buffer, sync)
}

// readAuditedSQLTables lists the read-audited app tables a statement names.
// shortcut: a token match, so a view over an audited table is not seen; page
// queries use SQLite's authorizer (page_query_reads.go), which a flow's pooled
// or transaction connection does not install. Move flow SQL onto that
// authorizer if views over audited tables become common.
func readAuditedSQLTables(app *App, query string) []string {
	if app == nil || app.Design == nil {
		return nil
	}
	if _, set := app.Design.Auth["read_audit"]; !set && !app.hipaa() {
		return nil // nothing is audited: skip the scan
	}
	seen := map[string]bool{}
	var out []string
	for _, tok := range sqlTokenize(stripSQLComments(query)) {
		if tok.kind != sqlTokWord && tok.kind != sqlTokIdent {
			continue
		}
		for _, t := range app.Tables {
			if !seen[t.Name] && sqliteIdentifierFold(t.Name) == sqliteIdentifierFold(tok.text) && IsReadAudited(app, t.Name) {
				seen[t.Name] = true
				out = append(out, t.Name)
			}
		}
	}
	return out
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
		// compliance: hipaa audits every table unless read_audit names them.
		return app.hipaa()
	}
	// "read_audit: contacts,deals,patients" or "read_audit: *"
	if ra == "*" {
		return true
	}
	listed := false
	for _, t := range splitComma(ra) {
		if t == table {
			return true
		}
		if app.hipaa() && !listed && !appHasTable(app, t) {
			listed = true
		}
	}
	// compliance: hipaa fails closed: a list naming no table of the app (a
	// typo, a removed model) audits every table instead of leaving one out.
	return listed
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

		query := "SELECT table_name, row_id, query_type, user_id, user_email, client_ip, created_at FROM _benmore_read_audit WHERE 1=1"
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
