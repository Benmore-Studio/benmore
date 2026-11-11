//go:build !cli

package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"time"
)

// Data retention / TTL: declarative data lifecycle management.
// Developer configures retention policies in retention.yaml. The runtime
// hard-deletes expired rows on a schedule and logs deletions for
// compliance proof (GDPR data minimization, right to erasure).
//
// The file is read by parseRetentionDocument (retention_document.go), the
// one reader the load, the sweep and the write gate share.

// RetentionPolicy defines a TTL for a single table.
type RetentionPolicy struct {
	Table  string
	TTL    time.Duration
	Column string // timestamp column to check (default: created_at)
}

// LoadRetentionConfig reads the policies of dir's retention.yaml that run:
//
//	policies:
//	  - table: activity_log
//	    ttl: "90d"
//	    column: created_at
//	  - table: data_requests
//	    ttl: "1y"
//
// A policy with a problem (an unknown key, a framework table) is left out and
// logged at load (logRetentionProblems). app.yaml's inline `retention:` map is
// not read: the write gate has always refused that key, and the runtime ran
// it anyway.
func LoadRetentionConfig(dir string) []RetentionPolicy {
	retentionData, _ := os.ReadFile(dir + "/retention.yaml")
	return parseRetentionConfig(retentionData)
}

func parseRetentionConfig(retentionData []byte) []RetentionPolicy {
	doc, err := parseRetentionDocument(retentionData)
	if err != nil {
		return nil
	}
	return doc.Policies
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
	if len(policies) == 0 {
		return
	}
	// Whatever handed over the policies, the sweep deletes only from the
	// app's own tables: GetTableNames leaves out the framework's tables and
	// SQLite's own by construction (the list bulk import uses), so no policy
	// can reach an account, a session, audit history or a job. A failure to
	// read that list deletes nothing.
	own, err := retentionSweepTables(db)
	if err != nil {
		log.Printf("RETENTION ERROR: the app's tables could not be listed (%s); nothing is deleted in this sweep", err)
		return
	}
	for _, p := range policies {
		table, ok := own[sqliteIdentifierFold(p.Table)]
		if !ok {
			log.Printf("RETENTION NOT RUNNING [%s]: %s is not one of the app's own tables, so nothing is deleted from it. %s", p.Table, p.Table, retentionOwnTablesRule)
			continue
		}
		// The policy's column must be a column of the table. A policy on a
		// column the table lacks used to log an error and still purge the
		// table's soft-deleted rows; it does not run at all.
		column, hasDeletedAt, err := retentionSweepColumns(db, table, p.Column)
		if err != nil {
			log.Printf("RETENTION ERROR [%s]: %s", table, err)
			continue
		}
		if column == "" {
			log.Printf("RETENTION NOT RUNNING [%s]: %s has no column %q, so nothing is deleted from it. Fix `column:` in retention.yaml.", table, table, p.Column)
			continue
		}
		cutoff := now.Add(-p.TTL).UTC().Format(time.RFC3339Nano)

		// Compare instants, not text: SQLite CURRENT_TIMESTAMP uses a space,
		// while API timestamps use T and may carry an offset. Invalid timestamps
		// yield NULL and are retained rather than guessed to be expired.
		expired := "julianday(" + quoteColumn(table, column) + ") < julianday(?)"
		history := retentionHistoryTable(db, table)
		swept, err := retentionDelete(db, table, history, expired, cutoff)
		// Stored versions of rows that left the table some other way (an API
		// delete) age out by the same column.
		aged, agedErr := retentionAgeOutHistory(db, table, history, column, cutoff)
		swept.versions += aged
		retentionReport(db, "ttl_delete", table, p.TTL, cutoff, swept)
		if err != nil {
			log.Printf("RETENTION ERROR [%s]: %s", table, err)
			continue
		}
		if agedErr != nil {
			log.Printf("RETENTION ERROR [%s]: stored versions of deleted rows were not aged out: %s", table, agedErr)
		}

		// Also purge soft-deleted rows beyond TTL (if table has deleted_at)
		// These are rows the user already "deleted" but are still on disk
		if hasDeletedAt {
			purged, err := retentionDelete(db, table, history, "deleted_at IS NOT NULL AND julianday(deleted_at) < julianday(?)", cutoff)
			retentionReport(db, "ttl_purge", table, p.TTL, cutoff, purged)
			if err != nil {
				log.Printf("RETENTION ERROR [%s]: soft-deleted rows were not purged: %s", table, err)
			}
		}
	}
}

// retentionSwept is what one delete of a sweep did to a table.
type retentionSwept struct {
	deleted  int64 // rows deleted
	skipped  int64 // expired rows kept because a row of another table still references them
	versions int64 // stored versions (<table>_history rows) deleted with them
}

// retentionReport logs what a delete of a sweep did and, when it deleted rows
// or stored versions, writes its audit row (compliance proof: the counts,
// never the rows). action is ttl_delete (by the policy's column) or ttl_purge
// (soft-deleted rows).
func retentionReport(db *sql.DB, action, table string, ttl time.Duration, cutoff string, swept retentionSwept) {
	if swept.skipped > 0 {
		log.Printf("RETENTION [%s]: %d expired rows were kept because rows of another table still reference them. Give that table its own policy and list it before %s.", table, swept.skipped, table)
	}
	if swept.deleted == 0 && swept.versions == 0 {
		return
	}
	note := ""
	if swept.versions > 0 {
		note = fmt.Sprintf(" and %d stored versions", swept.versions)
	}
	values := map[string]any{"ttl": formatDuration(ttl)}
	if action == "ttl_purge" {
		log.Printf("RETENTION: purged %d soft-deleted rows from %s%s", swept.deleted, table, note)
		values["rows_purged"] = swept.deleted
	} else {
		log.Printf("RETENTION: deleted %d rows from %s (older than %s)%s", swept.deleted, table, formatDuration(ttl), note)
		values["rows_deleted"] = swept.deleted
		values["cutoff"] = cutoff
	}
	if swept.versions > 0 {
		values["history_rows_deleted"] = swept.versions
	}
	if swept.skipped > 0 {
		values["rows_skipped"] = swept.skipped
	}
	LogAuditDB(db, action, table, "", &Session{Email: "system:retention"}, nil, values)
}

// retentionBatchSize is how many expired rows one transaction of a sweep
// deletes. Tests lower it.
var retentionBatchSize = 500

// retentionDelete deletes the rows of table that match where (one bound
// value: the cutoff), a batch per transaction, and returns what it did. A
// returned error stops the table's sweep; the counts are what was done before.
//
// One row still referenced.  The delete used to be one statement, so a single
// expired row that a row of another table still referenced (a foreign key
// without ON DELETE CASCADE) failed it as a whole, every hour, and no expired
// row of that table was ever deleted. A batch that fails that way is deleted
// row by row; the referenced rows are kept and counted (skipped).
//
// Stored versions.  A table with content history keeps every earlier state of
// a row in <table>_history, and its delete trigger records the final state of
// each deleted row there too. Retention that left those copies did not remove
// the data. So when the table has a framework history table
// (history: retentionHistoryTable, currently versioned or retained from when
// it was), every stored version of the rows a batch deletes goes in the same
// transaction as the rows; a row that stays keeps its versions. The audit log
// is never touched: audit rows are kept or deleted only by
// BENMORE_AUDIT_RETENTION.
func retentionDelete(db *sql.DB, table, history, where, cutoff string) (swept retentionSwept, err error) {
	// A WITHOUT ROWID table (only a hand-written migration makes one) has no
	// rowid to batch by: it keeps the single statement it always had.
	var ddl string
	if err := db.QueryRow(`SELECT COALESCE(sql, '') FROM main.sqlite_schema WHERE type = 'table' AND name = ?`, table).Scan(&ddl); err != nil {
		return swept, err
	}
	if strings.Contains(strings.ToUpper(ddl), "WITHOUT ROWID") {
		result, err := db.Exec("DELETE FROM "+quoteIdent(table)+" WHERE "+where, cutoff)
		if err != nil {
			return swept, err
		}
		swept.deleted, _ = result.RowsAffected()
		return swept, nil
	}
	columns, err := mainTableColumnsWith(db, table)
	if err != nil {
		return swept, err
	}
	rowID, err := versionHistoryRowID(columns) // a name for the rowid no column shadows
	if err != nil {
		return swept, err
	}
	selectIDs := "SELECT " + rowID
	if history != "" {
		selectIDs += ", id"
	}
	selectIDs += " FROM " + quoteIdent(table) + " WHERE (" + where + ")"
	var last any
	for {
		query, args := selectIDs, []any{cutoff}
		if last != nil {
			query += " AND " + rowID + " > ?"
			args = append(args, last)
		}
		rows, err := db.Query(query+" ORDER BY "+rowID+" LIMIT ?", append(args, retentionBatchSize)...)
		if err != nil {
			return swept, err
		}
		var rowIDs, ids []any
		for rows.Next() {
			var rid int64
			var id any
			dest := []any{&rid}
			if history != "" {
				dest = append(dest, &id)
			}
			if err := rows.Scan(dest...); err != nil {
				rows.Close()
				return swept, err
			}
			rowIDs, ids = append(rowIDs, rid), append(ids, id)
		}
		if err := errors.Join(rows.Err(), rows.Close()); err != nil {
			return swept, err
		}
		if len(rowIDs) == 0 {
			return swept, nil
		}
		last = rowIDs[len(rowIDs)-1]
		batch, err := retentionDeleteBatch(db, table, history, rowID, where, cutoff, rowIDs, ids)
		swept.deleted, swept.skipped, swept.versions = swept.deleted+batch.deleted, swept.skipped+batch.skipped, swept.versions+batch.versions
		if err != nil {
			return swept, err
		}
	}
}

// retentionHistoryTable is table's framework history table, or "" when it has
// none. An object of that name that is not framework history (a view, an app
// table with its own triggers) is not the sweep's to edit.
func retentionHistoryTable(db *sql.DB, table string) string {
	history := table + "_history"
	exists, err := versionHistoryExists(db, history)
	if err != nil {
		log.Printf("RETENTION [%s]: %s is not read as version history (%s); the sweep leaves it alone", table, history, err)
		return ""
	}
	if !exists {
		return ""
	}
	return history
}

// retentionDeleteBatch deletes one batch of expired rows (by rowid) in one
// transaction, with the stored versions of the rows that went (by id).
func retentionDeleteBatch(db *sql.DB, table, history, rowID, where, cutoff string, rowIDs, ids []any) (swept retentionSwept, err error) {
	tx, err := db.BeginTx(withWriteTxLabel(context.Background(), "retention sweep"), nil)
	if err != nil {
		return swept, err
	}
	defer tx.Rollback()
	marks := "?" + strings.Repeat(", ?", len(rowIDs)-1)
	var before int64
	if history != "" {
		if err := tx.QueryRow("SELECT COUNT(*) FROM "+quoteIdent(history)+" WHERE id IN ("+marks+")", ids...).Scan(&before); err != nil {
			return swept, err
		}
	}
	// The condition is checked again: a row may have changed since it was listed.
	result, err := tx.Exec("DELETE FROM "+quoteIdent(table)+" WHERE "+rowID+" IN ("+marks+") AND ("+where+")", append(slices.Clone(rowIDs), cutoff)...)
	switch {
	case err == nil:
		swept.deleted, _ = result.RowsAffected()
	case !retentionForeignKeyFailure(err):
		return swept, err
	default:
		// SQLite undid that statement and nothing else. Delete the batch
		// row by row and keep the rows something still references.
		for _, rid := range rowIDs {
			result, err := tx.Exec("DELETE FROM "+quoteIdent(table)+" WHERE "+rowID+" = ? AND ("+where+")", rid, cutoff)
			if retentionForeignKeyFailure(err) {
				swept.skipped++
				continue
			}
			if err != nil {
				return retentionSwept{}, err
			}
			n, _ := result.RowsAffected()
			swept.deleted += n
		}
	}
	if history != "" {
		// Every version of the batch's rows that are gone: the earlier
		// states and the final state the delete trigger just recorded.
		if _, err := tx.Exec("DELETE FROM "+quoteIdent(history)+" WHERE id IN ("+marks+") AND id NOT IN (SELECT id FROM "+quoteIdent(table)+" WHERE id IN ("+marks+"))", append(slices.Clone(ids), ids...)...); err != nil {
			return retentionSwept{}, err
		}
		// What is left are the versions of the rows that stayed, which the
		// transaction did not add to: the difference existed before it.
		var after int64
		if err := tx.QueryRow("SELECT COUNT(*) FROM "+quoteIdent(history)+" WHERE id IN ("+marks+")", ids...).Scan(&after); err != nil {
			return retentionSwept{}, err
		}
		swept.versions = before - after
	}
	if err := tx.Commit(); err != nil {
		return retentionSwept{}, err
	}
	return swept, nil
}

func retentionForeignKeyFailure(err error) bool {
	return err != nil && strings.Contains(err.Error(), "FOREIGN KEY constraint failed")
}

// retentionAgeOutHistory deletes the stored versions of rows that are no
// longer in table (deleted through the API, or by a cascade) once the
// policy's column, as that version holds it, is older than the cutoff: a copy
// in <table>_history is kept no longer than the row itself would have been.
// A version whose column is NULL or not a timestamp is kept, like a row.
// Versions of rows that are still in the table are never touched.
func retentionAgeOutHistory(db *sql.DB, table, history, column, cutoff string) (int64, error) {
	if history == "" {
		return 0, nil
	}
	columns, err := mainTableColumnsWith(db, history)
	if err != nil || !versionHasColumn(columns, column) {
		return 0, err
	}
	result, err := db.Exec("DELETE FROM "+quoteIdent(history)+" WHERE julianday("+quoteColumn(history, column)+") < julianday(?) AND NOT EXISTS (SELECT 1 FROM "+quoteIdent(table)+" WHERE "+quoteColumn(table, "id")+" = "+quoteColumn(history, "id")+")", cutoff)
	if err != nil {
		return 0, err
	}
	n, _ := result.RowsAffected()
	return n, nil
}

// retentionSweepTables maps the folded name of each of the app's own tables
// to its stored name: the tables a policy may delete from.
func retentionSweepTables(db *sql.DB) (map[string]string, error) {
	names, err := GetTableNames(db)
	if err != nil {
		return nil, err
	}
	own := make(map[string]string, len(names))
	for _, name := range names {
		own[sqliteIdentifierFold(name)] = name
	}
	return own, nil
}

// retentionSweepColumns returns table's column named want as the table spells
// it ("" when the table has none) and whether the table has deleted_at.
func retentionSweepColumns(db *sql.DB, table, want string) (column string, hasDeletedAt bool, err error) {
	columns, err := mainTableColumnsWith(db, table)
	if err != nil {
		return "", false, err
	}
	for _, c := range columns {
		if sqliteIdentifierFold(c.Name) == sqliteIdentifierFold(want) {
			column = c.Name
		}
		if c.Name == "deleted_at" {
			hasDeletedAt = true
		}
	}
	return column, hasDeletedAt, nil
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
