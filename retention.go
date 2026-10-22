//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"strings"
	"time"
)

// Data retention / TTL: declarative data lifecycle management.
// Developer configures retention policies in app.yaml. The runtime
// hard-deletes expired rows on a schedule and logs deletions for
// compliance proof (GDPR data minimization, right to erasure).

// RetentionPolicy defines a TTL for a single table.
type RetentionPolicy struct {
	Table  string
	TTL    time.Duration
	Column string // timestamp column to check (default: created_at)
}

type retentionFileConfig struct {
	Policies []struct {
		Table  string `yaml:"table"`
		TTL    string `yaml:"ttl"`
		Column string `yaml:"column"`
	} `yaml:"policies"`
}

// LoadRetentionConfig reads retention policies from either a dedicated
// retention.yaml file or the retention: section of app.yaml.
//
// retention.yaml format (preferred, used by HIPAA-grade client apps):
//
//	policies:
//	  - table: activity_log
//	    ttl: "90d"
//	    column: created_at
//	  - table: data_requests
//	    ttl: "1y"
//
// app.yaml inline format (legacy, still supported):
//
//	retention:
//	  activity_log: "90d"
//	  data_requests: {ttl: "1y", column: "uploaded_at"}
//
// Both sources are merged - dedicated file takes precedence on table
// name conflicts.
func LoadRetentionConfig(dir string) []RetentionPolicy {
	retentionData, _ := os.ReadFile(dir + "/retention.yaml")
	appData, _ := os.ReadFile(dir + "/app.yaml")
	return parseRetentionConfig(retentionData, appData)
}

func parseRetentionConfig(retentionData, appData []byte) []RetentionPolicy {
	var policies []RetentionPolicy
	seen := map[string]bool{}

	// 1. Dedicated retention.yaml (preferred)
	{
		var wrapper retentionFileConfig
		if yamlUnmarshal(retentionData, &wrapper) == nil {
			for _, p := range wrapper.Policies {
				ttl := parseTTLDuration(p.TTL)
				if ttl == 0 {
					continue
				}
				col := p.Column
				if col == "" {
					col = "created_at"
				}
				policies = append(policies, RetentionPolicy{
					Table: p.Table, TTL: ttl, Column: col,
				})
				seen[p.Table] = true
			}
		}
	}

	// 2. app.yaml inline retention: map (fallback/legacy)
	{
		var raw map[string]any
		if yamlUnmarshal(appData, &raw) == nil {
			if retentionRaw, ok := raw["retention"].(map[string]any); ok {
				for table, v := range retentionRaw {
					if seen[table] {
						continue
					}
					switch val := v.(type) {
					case string:
						ttl := parseTTLDuration(val)
						if ttl > 0 {
							policies = append(policies, RetentionPolicy{
								Table: table, TTL: ttl, Column: "created_at",
							})
						}
					case map[string]any:
						ttlStr, _ := val["ttl"].(string)
						col, _ := val["column"].(string)
						if col == "" {
							col = "created_at"
						}
						ttl := parseTTLDuration(ttlStr)
						if ttl > 0 {
							policies = append(policies, RetentionPolicy{
								Table: table, TTL: ttl, Column: col,
							})
						}
					}
				}
			}
		}
	}

	return policies
}

// parseTTLDuration parses "90d", "24h", "30m", "1y" etc.
func parseTTLDuration(s string) time.Duration {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0
	}
	// Try standard Go duration
	if d, err := time.ParseDuration(s); err == nil {
		return d
	}
	// Days: "90d"
	var n int
	if _, err := fmt.Sscanf(s, "%dd", &n); err == nil && n > 0 {
		return time.Duration(n) * 24 * time.Hour
	}
	// Years: "1y"
	if _, err := fmt.Sscanf(s, "%dy", &n); err == nil && n > 0 {
		return time.Duration(n) * 365 * 24 * time.Hour
	}
	return 0
}

// StartRetentionWorker runs the TTL enforcement loop.
// Checks every hour, hard-deletes expired rows, logs for compliance.
func StartRetentionWorker(app *App, policies []RetentionPolicy) {
	if len(policies) == 0 {
		return
	}

	for _, p := range policies {
		log.Printf("  retention: %s → %s (column: %s)", p.Table, formatDuration(p.TTL), p.Column)
	}

	app.startWorker("retention.sweep", func(stop <-chan struct{}) {
		timer := time.NewTimer(5 * time.Second)
		defer timer.Stop()
		for {
			select {
			case <-stop:
				return
			case <-timer.C:
			}
			select {
			case <-stop:
				return
			default:
			}
			enforceRetention(app.DB, policies)
			timer.Reset(time.Hour)
		}
	})
}

// enforceRetention processes all retention policies.
func enforceRetention(db *sql.DB, policies []RetentionPolicy) {
	enforceRetentionAt(db, policies, time.Now())
}

func enforceRetentionAt(db *sql.DB, policies []RetentionPolicy, now time.Time) {
	for _, p := range policies {
		cutoff := now.Add(-p.TTL).UTC().Format(time.RFC3339Nano)

		// Compare instants, not text: SQLite CURRENT_TIMESTAMP uses a space,
		// while API timestamps use T and may carry an offset. Invalid timestamps
		// yield NULL and are retained rather than guessed to be expired.
		// The column is qualified (quoteColumn), so a policy naming a column
		// the table lacks is logged; written as a lone quoted name SQLite
		// read it as a string and the policy deleted nothing without a word.
		// Such a policy still purges soft-deleted rows below, as it did.
		var affected int64
		result, err := db.Exec(
			"DELETE FROM "+quoteIdent(p.Table)+" WHERE julianday("+quoteColumn(p.Table, p.Column)+") < julianday(?)",
			cutoff)
		if err != nil {
			log.Printf("RETENTION ERROR [%s]: %s", p.Table, err)
			if !strings.Contains(err.Error(), "no such column") {
				continue
			}
		} else {
			affected, _ = result.RowsAffected()
		}
		if affected > 0 {
			log.Printf("RETENTION: deleted %d rows from %s (older than %s)", affected, p.Table, formatDuration(p.TTL))
			// Compliance proof: log deletion to audit trail
			LogAuditDB(db, "ttl_delete", p.Table, "",
				&Session{Email: "system:retention"},
				nil,
				map[string]any{
					"rows_deleted": affected,
					"ttl":          formatDuration(p.TTL),
					"cutoff":       cutoff,
				})
		}

		// Also purge soft-deleted rows beyond TTL (if table has deleted_at)
		// These are rows the user already "deleted" but are still on disk
		var hasDeletedAt int
		db.QueryRow("SELECT COUNT(*) FROM pragma_table_info(?) WHERE name='deleted_at'", p.Table).Scan(&hasDeletedAt)
		if hasDeletedAt > 0 {
			purgeResult, err := db.Exec(
				"DELETE FROM "+quoteIdent(p.Table)+" WHERE deleted_at IS NOT NULL AND julianday(deleted_at) < julianday(?)",
				cutoff)
			if err == nil {
				purged, _ := purgeResult.RowsAffected()
				if purged > 0 {
					log.Printf("RETENTION: purged %d soft-deleted rows from %s", purged, p.Table)
					LogAuditDB(db, "ttl_purge", p.Table, "",
						&Session{Email: "system:retention"},
						nil,
						map[string]any{
							"rows_purged": purged,
							"ttl":         formatDuration(p.TTL),
						})
				}
			}
		}
	}
}

// RunRetentionNow executes retention policies synchronously. Used in tests
// via `flush: retention` to ensure TTL deletions happen before assertions.
func RunRetentionNow(app *App) {
	policies := app.retentionConfig()
	if len(policies) > 0 {
		enforceRetention(app.DB, policies)
	}
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days >= 365 && days%365 == 0 {
		return fmt.Sprintf("%dy", days/365)
	}
	if days > 0 {
		return fmt.Sprintf("%dd", days)
	}
	return d.String()
}
