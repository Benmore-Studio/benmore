//go:build !cli

package main

import (
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

const lockTTL = 30 * time.Second

// EnsureLocksTable creates the _benmore_locks table if it doesn't exist.
func EnsureLocksTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_locks (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		table_name TEXT NOT NULL,
		row_id TEXT NOT NULL,
		user_id INTEGER NOT NULL,
		user_email TEXT NOT NULL,
		locked_at DATETIME DEFAULT CURRENT_TIMESTAMP,
		expires_at DATETIME NOT NULL,
		UNIQUE(table_name, row_id)
	)`)
}

// RegisterLockRoutes registers lock acquire/release/status endpoints for all tables.
func RegisterLockRoutes(mux *http.ServeMux, app *App) {
	tables, err := GetTableNames(app.DB)
	if err != nil {
		return
	}

	lockLimiter := NewRateLimiterStoppable(30, time.Minute, app.Stop) // 30 lock acquisitions per minute

	for _, table := range tables {
		t := table // capture for closure

		// POST /api/{table}/{id}/lock - acquire lock
		mux.HandleFunc(fmt.Sprintf("POST /api/%s/{id}/lock", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) {
				return
			}
			// Rate limit lock acquisition
			key := r.RemoteAddr
			if session := getSession(app, r); session != nil {
				key = fmt.Sprintf("user:%d", session.UserID)
			}
			if !lockLimiter.Allow(key) {
				http.Error(w, `{"error":"rate limit exceeded"}`, http.StatusTooManyRequests)
				return
			}
			handleLockAcquire(w, r, app, t)
		})

		// DELETE /api/{table}/{id}/lock - release lock
		mux.HandleFunc(fmt.Sprintf("DELETE /api/%s/{id}/lock", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) {
				return
			}
			handleLockRelease(w, r, app, t)
		})

		// GET /api/{table}/{id}/lock - check lock status
		mux.HandleFunc(fmt.Sprintf("GET /api/%s/{id}/lock", t), func(w http.ResponseWriter, r *http.Request) {
			if requireAPIAuth(w, r, app, t) {
				return
			}
			handleLockStatus(w, r, app, t)
		})
	}
}

// extractLockID extracts the row ID from the request using Go 1.22 path values.
func extractLockID(r *http.Request) string {
	return r.PathValue("id")
}

// handleLockAcquire acquires a lock on a record. Idempotent for the same user.
func handleLockAcquire(w http.ResponseWriter, r *http.Request, app *App, table string) {
	id := extractLockID(r)
	if id == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "missing record ID"})
		return
	}

	// CSRF check (skip for Bearer auth)
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	// Scope check: user must have write access to this table
	if err := checkScope(session, table, "write"); err != nil {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": err.Error()})
		return
	}

	// Verify the caller can actually access this row before locking it.
	// Canonical rowScopeClause via canAccessRow - act-as aware, group OR
	// owner OR ACL, admin (not stepped-in) bypass. Pre-consolidation this was
	// user_id-ONLY, so a group-scoped table without user_id let any authed
	// caller lock any row across tenants (contention/DoS + existence oracle).
	if !canAccessRow(app, table, id, session) {
		// Distinguish "doesn't exist" from "exists but not yours": an admin-
		// bypass caller that still can't see it means the row is gone.
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "access denied"})
		return
	}

	expiresAt := time.Now().Add(lockTTL).UTC().Format("2006-01-02 15:04:05")

	// Try to acquire the lock. If already locked by someone else and not expired, reject.
	// First, delete any expired lock on this row.
	app.DB.Exec(`DELETE FROM _benmore_locks WHERE table_name = ? AND row_id = ? AND expires_at < datetime('now')`,
		table, id)

	// Check if there's an active lock by another user
	var existingUserID int64
	var existingEmail string
	var existingExpires string
	err := app.DB.QueryRow(
		`SELECT user_id, user_email, expires_at FROM _benmore_locks WHERE table_name = ? AND row_id = ?`,
		table, id,
	).Scan(&existingUserID, &existingEmail, &existingExpires)

	if err == nil {
		// Lock exists
		if existingUserID == session.UserID {
			// Same user - extend the lock (idempotent)
			app.DB.Exec(
				`UPDATE _benmore_locks SET expires_at = ?, locked_at = CURRENT_TIMESTAMP WHERE table_name = ? AND row_id = ?`,
				expiresAt, table, id,
			)
			httpJSON(w, http.StatusOK, map[string]any{
				"status":     "locked",
				"locked_by":  session.Email,
				"expires_at": expiresAt,
			})
			return
		}
		// Different user holds the lock
		httpJSON(w, http.StatusConflict, map[string]any{
			"error":      "record is locked by another user",
			"locked_by":  existingEmail,
			"expires_at": existingExpires,
		})
		return
	}

	// No active lock - acquire it
	_, err = app.DB.Exec(
		`INSERT INTO _benmore_locks (table_name, row_id, user_id, user_email, expires_at) VALUES (?, ?, ?, ?, ?)`,
		table, id, session.UserID, session.Email, expiresAt,
	)
	if err != nil {
		// Race condition: another user inserted the lock between our SELECT and
		// this INSERT, so the UNIQUE(table_name,row_id) constraint fired.
		// LOWER: detect this structurally via the driver's typed error code
		// (sqlite3.ErrConstraint / extended ErrConstraintUnique) instead of
		// string-matching "UNIQUE constraint" - the message text is fragile
		// (driver/version/locale dependent) and a wording change would silently
		// turn a benign lock-race into a 500. Fall back to the substring match
		// only if the error isn't a typed *sqlite3.Error (e.g. wrapped).
		var sqliteErr sqlite3.Error
		isUnique := errors.As(err, &sqliteErr) &&
			sqliteErr.ExtendedCode == sqlite3.ErrConstraintUnique
		if isUnique || strings.Contains(err.Error(), "UNIQUE constraint") {
			httpJSON(w, http.StatusConflict, map[string]any{"error": "record is locked by another user"})
			return
		}
		httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "failed to acquire lock"})
		return
	}

	httpJSON(w, http.StatusOK, map[string]any{
		"status":     "locked",
		"locked_by":  session.Email,
		"expires_at": expiresAt,
	})
}

// handleLockRelease releases a lock on a record. Only the lock owner or an admin can release.
func handleLockRelease(w http.ResponseWriter, r *http.Request, app *App, table string) {
	id := extractLockID(r)
	if id == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "missing record ID"})
		return
	}

	// CSRF check (skip for Bearer auth)
	if !validateCSRF(r) && !isBearerAuth(r) {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "invalid CSRF token"})
		return
	}

	session := getSession(app, r)
	if session == nil {
		httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
		return
	}

	// Check if lock exists
	var lockUserID int64
	err := app.DB.QueryRow(
		`SELECT user_id FROM _benmore_locks WHERE table_name = ? AND row_id = ?`,
		table, id,
	).Scan(&lockUserID)

	if err != nil {
		httpJSON(w, http.StatusNotFound, map[string]any{"error": "no active lock on this record"})
		return
	}

	// Only the lock owner or admin can release
	if lockUserID != session.UserID && !session.IsAdmin() {
		httpJSON(w, http.StatusForbidden, map[string]any{"error": "only the lock owner can release this lock"})
		return
	}

	app.DB.Exec(`DELETE FROM _benmore_locks WHERE table_name = ? AND row_id = ?`, table, id)

	httpJSON(w, http.StatusOK, map[string]any{"status": "unlocked"})
}

// handleLockStatus checks whether a record is currently locked.
func handleLockStatus(w http.ResponseWriter, r *http.Request, app *App, table string) {
	id := extractLockID(r)
	if id == "" {
		httpJSON(w, http.StatusBadRequest, map[string]any{"error": "missing record ID"})
		return
	}

	// Clean expired locks first
	app.DB.Exec(`DELETE FROM _benmore_locks WHERE table_name = ? AND row_id = ? AND expires_at < datetime('now')`,
		table, id)

	var userEmail string
	var lockedAt, expiresAt string
	err := app.DB.QueryRow(
		`SELECT user_email, locked_at, expires_at FROM _benmore_locks WHERE table_name = ? AND row_id = ?`,
		table, id,
	).Scan(&userEmail, &lockedAt, &expiresAt)

	if err != nil {
		httpJSON(w, http.StatusOK, map[string]any{"locked": false})
		return
	}

	httpJSON(w, http.StatusOK, map[string]any{
		"locked":     true,
		"locked_by":  userEmail,
		"locked_at":  lockedAt,
		"expires_at": expiresAt,
	})
}

// CheckLock checks if a record is locked by another user.
// Returns (true, lockedByEmail) if locked by someone else, (false, "") otherwise.
func CheckLock(db *sql.DB, table, rowID string, userID int64) (bool, string) {
	// Clean expired lock for this specific row
	db.Exec(`DELETE FROM _benmore_locks WHERE table_name = ? AND row_id = ? AND expires_at < datetime('now')`,
		table, rowID)

	var lockUserID int64
	var lockEmail string
	err := db.QueryRow(
		`SELECT user_id, user_email FROM _benmore_locks WHERE table_name = ? AND row_id = ?`,
		table, rowID,
	).Scan(&lockUserID, &lockEmail)

	if err != nil {
		return false, "" // no lock
	}

	if lockUserID == userID {
		return false, "" // locked by the same user - allow
	}

	return true, lockEmail
}

// StartLockCleanupWorker runs a background goroutine that deletes expired locks every 10 seconds.
// Exits cleanly when app.Stop is closed (e.g. during hot reload), so the goroutine
// doesn't leak and spam errors against a closed DB handle.
func StartLockCleanupWorker(app *App) {
	safeGo("locks.cleanup", func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-app.Stop:
				return
			case <-ticker.C:
				// Re-check Stop in case it was closed while we were blocked on the tick
				select {
				case <-app.Stop:
					return
				default:
				}
				if _, err := app.DB.Exec(`DELETE FROM _benmore_locks WHERE expires_at < datetime('now')`); err != nil {
					log.Printf("[locks] cleanup error: %v", err)
				}
			}
		}
	})
}

// lockErrorResponse returns the appropriate error response for a lock conflict.
// In dev mode, includes the lock holder email. In production, hides it.
func lockErrorResponse(devMode bool, lockedBy string) map[string]any {
	resp := map[string]any{
		"error": "record is locked by another user",
	}
	if devMode {
		resp["locked_by"] = lockedBy
	}
	return resp
}
