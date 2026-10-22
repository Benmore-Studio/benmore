//go:build !cli

package main

// Optional retention for _benmore_audit_log. OFF by default: the framework
// never deletes audit history unless the operator asks it to.
//
// BENMORE_AUDIT_RETENTION (per-app env, e.g. "400d", "2y", "8760h") enables
// an hourly sweep that deletes audit rows whose created_at is older than the
// TTL. Values under one day are refused. When the audit shipper is
// configured (BENMORE_AUDIT_WEBHOOK_URL), only rows the shipper has already
// delivered (id <= _benmore_audit_shipper_cursor.last_shipped_id) are
// eligible, so retention can never delete an entry before it reaches the
// long-term store. Deletes run in bounded batches so the sweep never holds
// the write lock for long.

import (
	"database/sql"
	"log"
	"os"
	"strings"
	"time"
)

const (
	auditRetentionBatch    = 1000
	auditRetentionInterval = time.Hour
	auditRetentionMinTTL   = 24 * time.Hour
)

// auditRetentionTTL returns the configured TTL, or 0 when retention is off.
func auditRetentionTTL(raw string) time.Duration {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0
	}
	ttl := parseTTLDuration(raw)
	if ttl < auditRetentionMinTTL {
		log.Printf("audit-retention: ignoring BENMORE_AUDIT_RETENTION=%q (want a duration of at least 1d, e.g. 400d)", raw)
		return 0
	}
	return ttl
}

// StartAuditRetentionWorker starts the sweep when BENMORE_AUDIT_RETENTION is
// set for the app; otherwise it does nothing.
func StartAuditRetentionWorker(app *App) {
	if app == nil || app.DB == nil {
		return
	}
	ttl := auditRetentionTTL(GetEnv(app.Dir, "BENMORE_AUDIT_RETENTION"))
	if ttl == 0 {
		return
	}
	shipperGated := strings.TrimSpace(os.Getenv("BENMORE_AUDIT_WEBHOOK_URL")) != ""
	log.Printf("  audit retention: deleting audit rows older than %s (shipped rows only: %v)", formatDuration(ttl), shipperGated)
	app.startWorker("audit.retention", func(stop <-chan struct{}) {
		timer := time.NewTimer(time.Minute)
		defer timer.Stop()
		for {
			select {
			case <-stop:
				return
			case <-timer.C:
			}
			if n, err := sweepAuditLog(app.DB, ttl, shipperGated, time.Now(), stop); err != nil {
				log.Printf("audit-retention: %v", err)
			} else if n > 0 {
				log.Printf("audit-retention: deleted %d audit row(s) older than %s", n, formatDuration(ttl))
			}
			timer.Reset(auditRetentionInterval)
		}
	})
}

// sweepAuditLog deletes expired audit rows in batches and returns how many
// it deleted.
func sweepAuditLog(db *sql.DB, ttl time.Duration, shipperGated bool, now time.Time, stop <-chan struct{}) (int64, error) {
	cutoff := now.UTC().Add(-ttl).Format("2006-01-02 15:04:05")
	maxID := int64(-1) // -1: no shipper bound
	if shipperGated {
		if err := db.QueryRow("SELECT last_shipped_id FROM " + auditShipperCursorTable + " WHERE id = 1").Scan(&maxID); err != nil {
			if err == sql.ErrNoRows || strings.Contains(err.Error(), "no such table") {
				return 0, nil // nothing shipped yet: nothing is eligible
			}
			return 0, err
		}
	}
	var total int64
	for {
		select {
		case <-stop:
			return total, nil
		default:
		}
		res, err := db.Exec(`DELETE FROM _benmore_audit_log WHERE id IN (
			SELECT id FROM _benmore_audit_log
			WHERE created_at < ? AND (? < 0 OR id <= ?)
			ORDER BY id LIMIT ?)`, cutoff, maxID, maxID, auditRetentionBatch)
		if err != nil {
			return total, err
		}
		n, _ := res.RowsAffected()
		total += n
		if n < auditRetentionBatch {
			return total, nil
		}
	}
}
