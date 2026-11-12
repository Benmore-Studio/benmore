//go:build !cli

package main

// A restore keeps the audit rows of the credential changes it keeps.
//
// The carry-forward (restore_credentials.go) leaves the restored database with
// the live password hashes, deactivations, sessions, passkeys and connector
// grants. The audit rows that record how they got that way are newer than the
// snapshot and went with the replaced database: the restored one showed a
// password that had changed and no record of the change.
// carryForwardRestoreAudit copies those rows from the live database into the
// candidate, in the credential transaction:
//
//   - Which rows: the ones whose table_name is the account table, the role
//     grants or a credential table of the restore registries
//     (restoreAuditTables). Every framework writer of an account, role or
//     credential event names one of them: password_change,
//     required_password_change, password_reset, the unverified-account claims,
//     role_changed and the role_* grant events, the passkey_* events,
//     account_purge, impersonate, the act-as and tooling session events, the
//     connector grant and credential events, what the admin panel and operator
//     SQL write to those tables, and earlier restore_credentials rows. Rows of
//     app tables are not copied: their data went back to the snapshot.
//   - Newer than the snapshot: recorded at or after the newest audit time the
//     snapshot holds, and not already in it. Within that last second a row
//     the snapshot holds is recognised by its content, or (when account
//     erasure or session rekeying has since rewritten it live) by its action,
//     table, row, actor and time, so nothing is copied twice.
//   - Unchanged: time, actor and values are the stored ones. A row keeps its
//     id when the candidate has never handed that id out; otherwise it takes
//     the next one, so every copied row sorts after the snapshot's own rows
//     and the audit shipper's cursor reaches it.
//   - Marked: restore_carried_at holds the time of the restore that first
//     copied the row (NULL on every row written in place).
//
// Rows are only ever inserted, with a free id, which the append-only triggers
// of a compliance: hipaa database allow (audit_append_only.go). Accounts the
// restore drops keep their rows: they are history.
//
// With no readable live database there is nothing to copy; the summary says
// why. A live database whose audit log alone cannot be read, or a candidate
// that refuses a copied row (an app's own trigger on the audit table), does
// not stop the restore, which is usually the way out of a damaged database:
// no row is copied, the summary and the log say why, and the replaced
// database, kept beside the backups, still holds them.

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"
	"time"
)

const (
	// auditRestoreCarriedColumn marks an audit row a restore copied from the
	// database it replaced, with the time of that restore.
	auditRestoreCarriedColumn = "restore_carried_at"

	restoreAuditSkippedUnreadable = "live_unreadable"
	restoreAuditSkippedNoLive     = "no_live_database"
	restoreAuditSkippedNoLog      = "no_live_audit_log"
)

// restoreAuditColumns are the columns of an audit row a restore copies as
// stored. Both databases must have the first three; the rest are copied when
// both have them (a snapshot can predate the impersonator columns).
var restoreAuditColumns = []string{"action", "table_name", "created_at", "row_id", "user_id", "user_email", "old_values", "new_values", "impersonator_user_id", "impersonator_email"}

// restoreAuditIdentity are the columns nothing rewrites after a row is
// written. Account erasure blanks addresses and values and session rekeying
// replaces a legacy session id (compared in its stored form), so a row the
// snapshot holds is still recognised after either.
var restoreAuditIdentity = []string{"action", "table_name", "row_id", "user_id", "created_at"}

// restoreAuditRowsSummary reports the audit rows a restore copied. Counts only.
type restoreAuditRowsSummary struct {
	// Carried: audit rows of account, role and credential events newer than
	// the snapshot, copied from the live database.
	Carried int `json:"carried"`
	// Skipped: why there was nothing to copy from (restoreAuditSkipped*).
	Skipped string `json:"skipped,omitempty"`
	// LiveError: why the live audit log could not be read, when the rest of
	// the live database could.
	LiveError string `json:"live_error,omitempty"`
	// Error: why the rows read could not be written to the restored copy
	// (none were).
	Error string `json:"error,omitempty"`
}

// note says, for the log line, why nothing was read.
func (a *restoreAuditRowsSummary) note() string {
	switch {
	case a.Error != "":
		return " (they could not be written: " + a.Error + ")"
	case a.LiveError != "":
		return " (the live audit log could not be read: " + a.LiveError + ")"
	case a.Skipped != "":
		return " (" + a.Skipped + ")"
	}
	return ""
}

// restoreAuditTables are the table_name values of the audit rows a restore
// copies: the account table, the role grants and every credential table of
// the restore registries.
func restoreAuditTables() []string {
	names := []string{"_benmore_users", "_benmore_user_roles"}
	for _, spec := range restoreGrantTables {
		names = append(names, spec.name)
	}
	return append(names, restoreMCPTables...)
}

// restoreAuditRow is one live audit row inside the window.
type restoreAuditRow struct {
	id       int64
	values   []any // restoreAuditColumns both databases have, as stored
	carried  any   // the live row's own mark
	identity string
}

// restoreAuditKey hashes the given stored values, each with its storage class
// and length, so no two different rows share a key.
func restoreAuditKey(values ...any) string {
	h := sha256.New()
	for _, v := range values {
		k := credKey(v)
		fmt.Fprintf(h, "%d:%s", len(k), k)
	}
	return string(h.Sum(nil))
}

// carryForwardRestoreAudit copies the live audit rows of account, role and
// credential events newer than the snapshot into the candidate. skipped names
// why the credential pass has no live database to read ("" when it has one).
func carryForwardRestoreAudit(ctx context.Context, tx *sql.Tx, livePath, skipped string) (*restoreAuditRowsSummary, error) {
	summary := &restoreAuditRowsSummary{Skipped: skipped}
	if skipped != "" {
		return summary, nil
	}
	cand, err := readCredTable(ctx, tx, auditLogTable, false, []string{})
	if err != nil || cand == nil {
		return summary, err
	}
	live, err := openRestoreDB("sqlite3", livePath, "ro", "")
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		summary.LiveError = err.Error()
		return summary, nil
	}
	defer live.Close()
	live.SetMaxOpenConns(1)
	rows, w, liveErr, err := newerLiveAuditRows(ctx, tx, live, cand, summary)
	if err == nil && liveErr != nil && ctx.Err() != nil {
		err = ctx.Err()
	}
	if err != nil {
		return nil, err
	}
	if liveErr != nil {
		summary.LiveError = liveErr.Error()
		return summary, nil
	}
	if len(rows) == 0 {
		return summary, nil
	}
	// All of them or none: a row the candidate refuses (an app's own trigger
	// on the audit table) undoes the rows before it and is reported. The
	// restore goes on, and the replaced database keeps every row.
	if _, err := tx.ExecContext(ctx, "SAVEPOINT restore_audit_rows"); err != nil {
		return nil, err
	}
	err = insertCarriedAuditRows(ctx, tx, cand, w, rows)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if _, undo := tx.ExecContext(ctx, "ROLLBACK TO restore_audit_rows"); undo != nil {
			return nil, errors.Join(err, undo)
		}
		summary.Error = err.Error()
		log.Printf("restore: %d audit rows of account and credential events could not be copied into the restored database (%v); they remain in the replaced database", len(rows), err)
	} else {
		summary.Carried = len(rows)
	}
	if _, err := tx.ExecContext(ctx, "RELEASE restore_audit_rows"); err != nil {
		return nil, err
	}
	return summary, nil
}

// insertCarriedAuditRows writes rows into the candidate's audit log, marked.
func insertCarriedAuditRows(ctx context.Context, tx *sql.Tx, cand *credTable, w restoreAuditWindow, rows []restoreAuditRow) error {
	if !cand.has[auditRestoreCarriedColumn] {
		if _, err := tx.ExecContext(ctx, "ALTER TABLE "+auditLogTable+" ADD COLUMN "+auditRestoreCarriedColumn+" DATETIME"); err != nil {
			return err
		}
	}
	// AUTOINCREMENT records the highest id ever handed out, so an id a
	// deleted row once had counts as taken.
	var seq, highest sql.NullInt64
	_ = tx.QueryRowContext(ctx, "SELECT seq FROM sqlite_sequence WHERE name = ?", auditLogTable).Scan(&seq)
	if err := tx.QueryRowContext(ctx, "SELECT MAX(id) FROM "+auditLogTable).Scan(&highest); err != nil {
		return err
	}
	high := max(seq.Int64, highest.Int64)
	cols := append(slices.Clone(w.cols), auditRestoreCarriedColumn)
	insert := func(withID bool) (*sql.Stmt, error) {
		names := quoteIdents(cols)
		if withID {
			names = append(names, "id")
		}
		return tx.PrepareContext(ctx, "INSERT INTO "+auditLogTable+" ("+strings.Join(names, ", ")+") VALUES (?"+strings.Repeat(", ?", len(names)-1)+")")
	}
	keepID, err := insert(true)
	if err != nil {
		return err
	}
	defer keepID.Close()
	newID, err := insert(false)
	if err != nil {
		return err
	}
	defer newID.Close()
	now := time.Now().UTC().Format("2006-01-02 15:04:05")
	for _, row := range rows {
		carried := row.carried
		if credText(carried) == "" {
			carried = now
		}
		args := append(slices.Clone(row.values), carried)
		if row.id > high {
			if _, err := keepID.ExecContext(ctx, append(args, row.id)...); err != nil {
				return err
			}
			high = row.id
			continue
		}
		res, err := newID.ExecContext(ctx, args...)
		if err != nil {
			return err
		}
		if id, err := res.LastInsertId(); err == nil && id > high {
			high = id
		}
	}
	return nil
}

// restoreAuditWindow is what both databases are asked for: the columns both
// have, and the rows at or after the snapshot's newest audit time.
type restoreAuditWindow struct {
	cols   []string
	where  string
	args   []any
	idents []int // positions in cols of restoreAuditIdentity
}

// selectFrom is the window's SELECT over one database's audit log, each
// column as an expression so the driver returns the stored value untouched.
func (w restoreAuditWindow) selectFrom(extra ...string) string {
	selects := slices.Clone(extra)
	for _, col := range w.cols {
		selects = append(selects, "+"+quoteIdent(col))
	}
	return "SELECT " + strings.Join(selects, ", ") + " FROM " + auditLogTable + " WHERE " + w.where + " ORDER BY id"
}

// keys returns a row's content key and its identity key.
func (w restoreAuditWindow) keys(values []any) (content, identity string) {
	ident := make([]any, len(w.idents))
	for i, pos := range w.idents {
		ident[i] = values[pos]
		if w.cols[pos] == "row_id" && credText(values[1]) == "_benmore_sessions" {
			ident[i] = credSessionKey(values[pos])
		}
	}
	return restoreAuditKey(values...), restoreAuditKey(ident...)
}

// newerLiveAuditRows reads the live audit rows of account, role and
// credential events the candidate does not hold, oldest first. liveErr is a
// failure to read the live database (nothing is copied, the restore goes on);
// err is the candidate's and stops the restore.
func newerLiveAuditRows(ctx context.Context, tx *sql.Tx, live *sql.DB, cand *credTable, summary *restoreAuditRowsSummary) (newer []restoreAuditRow, w restoreAuditWindow, liveErr, err error) {
	lt, liveErr := readCredTable(ctx, live, auditLogTable, false, []string{})
	if liveErr != nil {
		return nil, w, liveErr, nil
	}
	if lt == nil {
		summary.Skipped = restoreAuditSkippedNoLog
		return nil, w, nil, nil
	}
	// action, table_name and created_at lead restoreAuditColumns, so they
	// lead w.cols too: keys reads the table name at position 1.
	for _, col := range append([]string{"id"}, restoreAuditColumns[:3]...) {
		if !cand.has[col] {
			return nil, w, nil, fmt.Errorf("audit log column %s is missing", col)
		}
		if !lt.has[col] {
			return nil, w, fmt.Errorf("live audit log column %s is missing", col), nil
		}
	}
	w.cols = present(restoreAuditColumns, cand, lt)
	for _, col := range restoreAuditIdentity {
		if pos := slices.Index(w.cols, col); pos >= 0 {
			w.idents = append(w.idents, pos)
		}
	}
	tables := restoreAuditTables()
	w.where = "table_name IN (?" + strings.Repeat(", ?", len(tables)-1) + ")"
	for _, name := range tables {
		w.args = append(w.args, name)
	}
	// The snapshot's newest audit time. A row dated ahead of the clock (an
	// app's own INSERT can carry any created_at) does not move it, and a row
	// with no readable time is compared by content on both sides.
	var newest sql.NullString
	if err := tx.QueryRowContext(ctx, "SELECT MAX(datetime(created_at)) FROM "+auditLogTable+" WHERE datetime(created_at) <= datetime('now')").Scan(&newest); err != nil {
		return nil, w, nil, err
	}
	if newest.Valid {
		w.where += " AND (datetime(created_at) IS NULL OR datetime(created_at) >= ?)"
		w.args = append(w.args, newest.String)
	}
	scan := func(q credQuerier, query string, extra int, each func(lead, values []any)) error {
		rows, err := q.QueryContext(ctx, query, w.args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			all := make([]any, extra+len(w.cols))
			ptrs := make([]any, len(all))
			for i := range all {
				ptrs[i] = &all[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				return err
			}
			each(all[:extra], all[extra:])
		}
		return rows.Err()
	}
	// What the candidate already holds inside the window.
	byContent, byIdentity := map[string][]int{}, map[string][]int{}
	var held []bool
	if err := scan(tx, w.selectFrom(), 0, func(_, values []any) {
		content, identity := w.keys(values)
		byContent[content] = append(byContent[content], len(held))
		byIdentity[identity] = append(byIdentity[identity], len(held))
		held = append(held, true)
	}); err != nil {
		return nil, w, nil, err
	}
	take := func(index map[string][]int, key string) bool {
		for _, i := range index[key] {
			if held[i] {
				held[i] = false
				return true
			}
		}
		return false
	}
	extra := []string{"id", "NULL"}
	if lt.has[auditRestoreCarriedColumn] {
		extra[1] = "+" + auditRestoreCarriedColumn
	}
	var unmatched []restoreAuditRow
	if liveErr := scan(live, w.selectFrom(extra...), len(extra), func(lead, values []any) {
		row := restoreAuditRow{values: values, carried: lead[1]}
		row.id, _ = credInt(lead[0])
		var content string
		content, row.identity = w.keys(values)
		if !take(byContent, content) {
			unmatched = append(unmatched, row)
		}
	}); liveErr != nil {
		return nil, w, liveErr, nil
	}
	// A row the snapshot holds whose content was rewritten live since.
	for _, row := range unmatched {
		if !take(byIdentity, row.identity) {
			newer = append(newer, row)
		}
	}
	return newer, w, nil, nil
}
