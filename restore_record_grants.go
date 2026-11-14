//go:build !cli

package main

// A restore does not bring back a record share that was taken away.
//
// A record-level grant (_benmore_permissions) gives one email address access
// to one row. Rolled back with the data, a share revoked after the snapshot
// was in force again. carryForwardRestoreRecordGrants, in the credential
// transaction and after the roles, leaves every address with no more than it
// holds in BOTH databases:
//
//   - A snapshot grant the live database still holds (same table, row, grant
//     type and address, compared as stored) and that has not expired there is
//     kept, with what both permissions give (lowerRecordPermission) and the
//     earlier of the two expiry times.
//   - A snapshot grant the live database no longer holds, or holds expired,
//     is deleted. Nothing shared since the snapshot is added.
//   - A snapshot grant the live database can never have held is kept: the
//     restore is disaster recovery onto a recreated or different database,
//     and a share, unlike a session, cannot be issued again by signing in.
//     The live database never held it when it never held the row
//     (restoreLiveRows.held) or never held the account the address belongs to
//     (liveAccountEvidence, the role rule's test). An address no snapshot
//     account holds is not known to be new, so the row decides alone.
//
// With no readable live database the grants stay as the snapshot has them and
// the summary says why; refresh-dev's copy keeps its own.

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"strings"
)

const restoreRecordGrantsTable = "_benmore_permissions"

// restoreRecordGrantKey is what identifies a record grant (the table's
// UNIQUE key).
var restoreRecordGrantKey = []string{"resource_type", "resource_id", "grant_type", "grantee_id"}

// restoreRecordGrantSummary reports what a restore did to record grants.
// Counts only.
type restoreRecordGrantSummary struct {
	// Skipped: why the grants were left as the snapshot has them
	// (restoreAuditSkippedUnreadable, restoreAuditSkippedNoLive).
	Skipped string `json:"skipped,omitempty"`
	// Kept / Removed: snapshot grants still held live (and the ones the live
	// database never held), and the ones revoked or expired since.
	Kept    int `json:"kept"`
	Removed int `json:"removed"`
	// PermissionLowered / ExpiryShortened: kept grants that took a lower
	// permission or an earlier expiry from the live one.
	PermissionLowered int `json:"permission_lowered"`
	ExpiryShortened   int `json:"expiry_shortened"`
	// KeptUnknown: kept grants on a row or to an account the live database
	// never held. Note says so in a sentence.
	KeptUnknown int    `json:"kept_unknown"`
	Note        string `json:"note,omitempty"`
}

// lowerRecordPermission is the permission a grant held in both databases has
// after a restore: what both give. admin gives everything; edit and delete
// each give view and not each other; a name the access check does not know
// gives nothing.
func lowerRecordPermission(snapshot, live string) string {
	_, knownSnapshot := permissionLevel[snapshot]
	_, knownLive := permissionLevel[live]
	switch {
	case snapshot == live || !knownSnapshot:
		return snapshot
	case !knownLive || snapshot == "admin":
		return live
	case live == "admin":
		return snapshot
	}
	return "view"
}

// restoreLiveExpiry applies a live grant's expiry to the snapshot's: whether
// the grant is in force live by the runtime's own test (no expiry, or one
// ahead), and whether the live expiry is the earlier of the two.
func restoreLiveExpiry(ctx context.Context, tx *sql.Tx, live, snapshot any) (current, earlier bool, err error) {
	if live == nil {
		return true, false, nil
	}
	err = tx.QueryRowContext(ctx, `SELECT COALESCE(datetime(?) > datetime('now'), 0),
		COALESCE(? IS NULL OR datetime(?) < datetime(?), 0)`, live, snapshot, live, snapshot).Scan(&current, &earlier)
	return current, earlier, err
}

// restoreLiveRows answers whether the live database ever held a row of one of
// its tables. It is the account evidence (liveAccountEvidence) for any table.
type restoreLiveRows struct {
	ctx    context.Context
	db     *sql.DB                // the live database, read-only; nil: it could not be opened
	seq    map[string]int64       // the highest id each AUTOINCREMENT table handed out
	shared map[string]bool        // table and row id of every live record grant
	tables map[string]*liveRowIDs // per table, read on first use
	audit  *bool                  // whether the live audit log can be asked
}

// liveRowIDs is what the live database says about one table's ids.
type liveRowIDs struct {
	exists bool  // a table with an id column
	high   int64 // the highest whole-number id it holds or handed out
	failed bool  // it could not be read
}

func restoreRowKey(table, id string) string { return table + "\x00" + id }

// held reports whether the live database ever held row id of table: a live
// record grant names it; its id is a whole number at or below the highest the
// table handed out (its AUTOINCREMENT sequence, and the highest it holds); the
// table holds a row with that id; or a live audit row is about it (its
// deletion among them). A table or audit log that cannot be read does not say
// the row was never there: the row counts as held, so a grant is never kept
// on the strength of a failed read.
func (e *restoreLiveRows) held(table, id string) bool {
	if e.shared[restoreRowKey(table, id)] || e.db == nil {
		return true
	}
	t := e.table(table)
	if t.failed {
		return true
	}
	if t.exists {
		if n, err := strconv.ParseInt(strings.TrimSpace(id), 10, 64); err == nil && n <= t.high {
			return true
		}
		var found bool
		if err := e.db.QueryRowContext(e.ctx, "SELECT EXISTS (SELECT 1 FROM "+quoteIdent(table)+" WHERE id = ?)", id).Scan(&found); err != nil || found {
			return true
		}
	}
	if e.audit == nil {
		audit, err := readCredTable(e.ctx, e.db, auditLogTable, false, []string{})
		if err != nil {
			return true
		}
		ok := audit != nil && audit.has["table_name"] && audit.has["row_id"]
		e.audit = &ok
	}
	if !*e.audit {
		return false
	}
	var found bool
	err := e.db.QueryRowContext(e.ctx, "SELECT EXISTS (SELECT 1 FROM "+auditLogTable+" WHERE table_name = ? AND row_id = ?)", table, id).Scan(&found)
	return err != nil || found
}

// table reads what the live database says about table's ids, once.
func (e *restoreLiveRows) table(table string) *liveRowIDs {
	if t := e.tables[table]; t != nil {
		return t
	}
	t := &liveRowIDs{high: e.seq[table]}
	e.tables[table] = t
	info, err := readCredTable(e.ctx, e.db, table, false, []string{})
	if err != nil {
		t.failed = true
		log.Printf("restore: the live table %q could not be read (%v); its rows count as held", table, err)
		return t
	}
	if info == nil || !info.has["id"] {
		return t
	}
	t.exists = true
	var high sql.NullInt64
	if err := e.db.QueryRowContext(e.ctx, "SELECT MAX(id) FROM "+quoteIdent(table)+" WHERE typeof(id) = 'integer'").Scan(&high); err != nil {
		t.failed = true
		log.Printf("restore: the live table %q could not be read (%v); its rows count as held", table, err)
	} else if high.Int64 > t.high {
		t.high = high.Int64
	}
	return t
}

// newRestoreLiveRows opens the live database for row evidence. The caller
// closes it.
func newRestoreLiveRows(ctx context.Context, livePath string, live map[string]*credTable) (*restoreLiveRows, func()) {
	e := &restoreLiveRows{ctx: ctx, seq: map[string]int64{}, shared: map[string]bool{}, tables: map[string]*liveRowIDs{}}
	if seq := live[restoreSequenceTable]; seq != nil {
		for i := range seq.rows {
			if n, ok := credInt(seq.get(i, "seq")); ok {
				e.seq[credText(seq.get(i, "name"))] = n
			}
		}
	}
	if lg := live[restoreRecordGrantsTable]; lg != nil {
		for i := range lg.rows {
			e.shared[restoreRowKey(credText(lg.get(i, "resource_type")), credText(lg.get(i, "resource_id")))] = true
		}
	}
	db, err := openRestoreDB("sqlite3", livePath, "ro", "")
	if err != nil {
		log.Printf("restore: the live database could not be opened for row evidence (%v); every row counts as held", err)
		return e, func() {}
	}
	db.SetMaxOpenConns(1)
	e.db = db
	return e, func() { db.Close() }
}

// restoreUnknownGrantees are the addresses of snapshot accounts the live
// database never held (the role rule's accounts that keep their roles), as the
// candidate holds them now. An address a live account holds, or an account the
// live database did hold, is not one of them.
func restoreUnknownGrantees(ctx context.Context, tx *sql.Tx, live map[string]*credTable, pairs map[int64]int64) (map[string]bool, error) {
	unknown := map[string]bool{}
	users, err := readCredTable(ctx, tx, "_benmore_users", false, []string{"id", "email"})
	if err != nil || users == nil || !users.has["id"] || !users.has["email"] {
		return unknown, err
	}
	heldLive := liveAccountEvidence(live)
	known := map[string]bool{}
	if lu := live["_benmore_users"]; lu != nil {
		for i := range lu.rows {
			known[credEmail(lu.get(i, "email"))] = true
		}
	}
	for i := range users.rows {
		email := credEmail(users.get(i, "email"))
		id, ok := credInt(users.get(i, "id"))
		if _, matched := pairs[id]; !ok || matched || heldLive(id) {
			known[email] = true
		} else if email != "" {
			unknown[email] = true
		}
	}
	for email := range known {
		delete(unknown, email)
	}
	return unknown, nil
}

// carryForwardRestoreRecordGrants applies the live record grants to the
// candidate. skipped names why there is no live state ("" when live is set).
func carryForwardRestoreRecordGrants(ctx context.Context, tx *sql.Tx, live map[string]*credTable, livePath string, pairs map[int64]int64, skipped string) (*restoreRecordGrantSummary, error) {
	summary := &restoreRecordGrantSummary{Skipped: skipped}
	if live == nil {
		return summary, nil
	}
	grants, err := readCredTable(ctx, tx, restoreRecordGrantsTable, true, nil)
	if err != nil || grants == nil || len(grants.rows) == 0 {
		return summary, err
	}
	for _, col := range append([]string{"permission"}, restoreRecordGrantKey...) {
		if !grants.has[col] {
			return nil, fmt.Errorf("record grant column %s is missing", col)
		}
	}
	keyOf := func(t *credTable, i int) string {
		parts := make([]string, len(restoreRecordGrantKey))
		for k, col := range restoreRecordGrantKey {
			parts[k] = credKey(t.get(i, col))
		}
		return strings.Join(parts, "\x00")
	}
	lg := live[restoreRecordGrantsTable]
	if lg != nil && len(present(append([]string{"permission"}, restoreRecordGrantKey...), lg)) != len(restoreRecordGrantKey)+1 {
		lg = nil // no comparable live grant: none is known to be held
	}
	liveGrant := map[string]int{}
	if lg != nil {
		for i := range lg.rows {
			liveGrant[keyOf(lg, i)] = i
		}
	}
	rows, closeRows := newRestoreLiveRows(ctx, livePath, live)
	defer closeRows()
	unknownGrantee, err := restoreUnknownGrantees(ctx, tx, live, pairs)
	if err != nil {
		return nil, err
	}
	for i := range grants.rows {
		j, found := liveGrant[keyOf(grants, i)]
		if !found {
			byUser := credText(grants.get(i, "grant_type")) == "user"
			if (byUser && unknownGrantee[credEmail(grants.get(i, "grantee_id"))]) ||
				!rows.held(credText(grants.get(i, "resource_type")), credText(grants.get(i, "resource_id"))) {
				summary.Kept++
				summary.KeptUnknown++
				continue
			}
		}
		var current, earlier bool
		if found {
			if current, earlier, err = restoreLiveExpiry(ctx, tx, lg.get(j, "expires_at"), grants.get(i, "expires_at")); err != nil {
				return nil, err
			}
		}
		if !current {
			if _, err := tx.ExecContext(ctx, "DELETE FROM "+restoreRecordGrantsTable+" WHERE rowid = ?", grants.rowid[i]); err != nil {
				return nil, err
			}
			summary.Removed++
			continue
		}
		var cols []string
		var values []any
		had := credText(grants.get(i, "permission"))
		if want := lowerRecordPermission(had, credText(lg.get(j, "permission"))); want != had {
			cols, values = append(cols, "permission"), append(values, want)
			summary.PermissionLowered++
		}
		if earlier && grants.has["expires_at"] {
			cols, values = append(cols, "expires_at"), append(values, lg.get(j, "expires_at"))
			summary.ExpiryShortened++
		}
		if err := updateRow(ctx, tx, restoreRecordGrantsTable, grants.rowid[i], cols, values); err != nil {
			return nil, err
		}
		summary.Kept++
	}
	if summary.KeptUnknown > 0 {
		summary.Note = fmt.Sprintf("%d record grant(s) of the snapshot are on a row or to an account the replaced database never held, so they are kept as the snapshot has them.", summary.KeptUnknown)
	}
	return summary, nil
}

// logLine is the record-grant part of the restore's log line.
func (r *restoreRecordGrantSummary) logLine() string {
	if r.Skipped != "" {
		return "record grants left as the snapshot has them (" + r.Skipped + ")"
	}
	return fmt.Sprintf("record grants: %d kept (%d with a lower live permission, %d with an earlier live expiry, %d the replaced database never held), %d removed",
		r.Kept, r.PermissionLowered, r.ExpiryShortened, r.KeptUnknown, r.Removed)
}
