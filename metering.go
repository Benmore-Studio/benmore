//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Usage metering: a generic counter system. The runtime provides the
// storage and increment primitive. The developer defines what to count
// via metering.yaml - or the runtime auto-counts requests and mutations
// when metering is enabled. No enforcement, no opinions about billing.

// EnsureUsageTable creates the usage counter table.
func EnsureUsageTable(db *sql.DB) {
	db.Exec(`CREATE TABLE IF NOT EXISTS _benmore_usage (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		scope TEXT NOT NULL,
		metric TEXT NOT NULL,
		count INTEGER DEFAULT 0,
		period TEXT NOT NULL,
		UNIQUE(scope, metric, period)
	)`)
	db.Exec("CREATE INDEX IF NOT EXISTS idx_usage_lookup ON _benmore_usage(scope, period)")
}

// usageBuffer batches increments in memory and flushes to DB periodically.
type usageBuffer struct {
	mu      sync.Mutex
	pending map[string]int64 // "scope|metric|period" → count
	db      *sql.DB
}

var globalUsage *usageBuffer

// InitMetering starts the usage counter system.
func InitMetering(db *sql.DB) {
	EnsureUsageTable(db)
	globalUsage = &usageBuffer{
		pending: make(map[string]int64),
		db:      db,
	}
	safeGo("metering.flush", func() {
		for {
			time.Sleep(10 * time.Second)
			globalUsage.flush()
		}
	})
	log.Printf("  metering: usage counter active")
}

// Increment adds 1 to a counter. Scope is whatever the developer wants:
// a user ID, a group ID, an org name, "global" - the runtime doesn't care.
// Metric is the name of the thing being counted. Period is auto-set to
// current month (YYYY-MM) unless the caller provides a custom one.
func Increment(scope, metric string) {
	if globalUsage == nil {
		return
	}
	period := time.Now().UTC().Format("2006-01")
	key := scope + "|" + metric + "|" + period
	globalUsage.mu.Lock()
	globalUsage.pending[key]++
	globalUsage.mu.Unlock()
}

// IncrementN adds N to a counter.
func IncrementN(scope, metric string, n int64) {
	if globalUsage == nil || n == 0 {
		return
	}
	period := time.Now().UTC().Format("2006-01")
	key := scope + "|" + metric + "|" + period
	globalUsage.mu.Lock()
	globalUsage.pending[key] += n
	globalUsage.mu.Unlock()
}

func (ub *usageBuffer) flush() {
	ub.mu.Lock()
	pending := ub.pending
	ub.pending = make(map[string]int64)
	ub.mu.Unlock()

	for key, count := range pending {
		parts := strings.SplitN(key, "|", 3)
		if len(parts) != 3 {
			continue
		}
		_, err := ub.db.Exec(`
			INSERT INTO _benmore_usage (scope, metric, count, period)
			VALUES (?, ?, ?, ?)
			ON CONFLICT(scope, metric, period) DO UPDATE SET count = count + ?`,
			parts[0], parts[1], count, parts[2], count)
		if err != nil {
			log.Printf("METERING flush error: %s", err)
		}
	}
}

// FlushUsage forces immediate write of pending counters. Used in tests.
func FlushUsage() {
	if globalUsage != nil {
		globalUsage.flush()
	}
}

// meterScope returns the scope key for a session: group ID if available, else user ID.
func meterScope(session *Session) string {
	if session.HasGroup() {
		return fmt.Sprintf("group:%s", session.GroupID)
	}
	return fmt.Sprintf("user:%d", session.UserID)
}

// RegisterUsageAPI sets up the usage metrics endpoint.
func RegisterUsageAPI(mux *http.ServeMux, app *App) {
	// GET /api/_usage - current period metrics for the authenticated scope
	mux.HandleFunc("GET /api/_usage", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil {
			httpJSON(w, http.StatusUnauthorized, map[string]any{"error": "authentication required"})
			return
		}

		FlushUsage() // ensure current data
		scope := meterScope(session)
		period := time.Now().UTC().Format("2006-01")

		rows, err := app.DB.Query(
			"SELECT metric, count FROM _benmore_usage WHERE scope = ? AND period = ?",
			scope, period)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
			return
		}
		defer rows.Close()

		metrics := make(map[string]int64)
		for rows.Next() {
			var metric string
			var count int64
			rows.Scan(&metric, &count)
			metrics[metric] = count
		}

		// Live gauges: total rows across developer tables
		var totalRows int64
		for _, table := range app.Tables {
			if strings.HasPrefix(table.Name, "_benmore_") {
				continue
			}
			var c int64
			app.DB.QueryRow(fmt.Sprintf("SELECT COUNT(*) FROM \"%s\"", table.Name)).Scan(&c)
			totalRows += c
		}
		metrics["total_rows"] = totalRows

		// Storage: DB + uploads size
		if fi, err := os.Stat(app.Dir + "/data.db"); err == nil {
			metrics["storage_bytes"] = fi.Size()
		}

		httpJSON(w, http.StatusOK, map[string]any{
			"scope":   scope,
			"period":  period,
			"metrics": metrics,
		})
	})

	// GET /api/_usage/history - all periods for a scope (admin)
	mux.HandleFunc("GET /api/_usage/history", func(w http.ResponseWriter, r *http.Request) {
		session := getSession(app, r)
		if session == nil || !session.IsAdmin() {
			httpJSON(w, http.StatusForbidden, map[string]any{"error": "admin required"})
			return
		}

		scope := r.URL.Query().Get("scope")
		if scope == "" {
			scope = meterScope(session)
		}

		rows, err := QueryRows(app.DB,
			"SELECT metric, count, period FROM _benmore_usage WHERE scope = ? ORDER BY period DESC, metric",
			scope)
		if err != nil {
			httpJSON(w, http.StatusInternalServerError, map[string]any{"error": "query failed"})
			return
		}
		httpJSON(w, http.StatusOK, rows)
	})
}
