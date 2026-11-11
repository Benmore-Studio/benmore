//go:build !cli

package main

// Restoring a database snapshot rolls back data, never work that already ran.
//
// A snapshot holds the queue as it was when it was taken: jobs waiting to run
// (an email, a webhook delivery, an async flow) and scheduled tasks waiting
// for their time. Most of that has run since. Installed as it is, the
// restarted worker and scheduler would run all of it a second time: the same
// messages to the same recipients, the same deliveries, the same scheduled
// flows. carryForwardRestoreQueue settles the queue of the restore candidate
// in the credential transaction (restore_credentials.go), for every row the
// snapshot still has queued (restoreQueueTable.active):
//
//   - The live database holds the same row (same id and created_at; an id an
//     earlier restore let the sequence hand out again is a different row):
//     the row takes its live execution state. Finished work stays finished, a
//     run the restore cut off is left to the worker's own crash recovery, and
//     a row still waiting keeps the attempts it has used.
//   - The live database held the row and no longer does (no row has its id,
//     and the live table has handed that id out): it finished and was cleaned
//     up, or was deleted. It is held: finished with the reason, never run.
//     Only the id says so. A row of another timeline (dev restored to its own
//     data after a refresh from production) whose id the live table has
//     passed and no longer holds is held too: holding costs an admin a retry,
//     a second run cannot be taken back.
//   - The live database never held the row (a later id than it ever handed
//     out, or the id is a different row's): nothing ran it, it stays queued.
//   - Nothing says what the live database ran (there is none, it cannot be
//     read, or it has no such table): a row whose time has come may have run
//     and is held; one whose run_at is still ahead cannot have run and stays
//     queued.
//
// Only rows the snapshot has queued are written, and they only stay queued or
// leave the queue, so no write can collide with the unique index over active
// jobs. Counts go into the restore's summary and its audit row.
//
// refresh-dev's copy of production holds its whole queue instead
// (holdRefreshedQueue): production runs its own.
//
// Interval cron schedules are covered next door: _benmore_cron_state is one
// of restoreLiveStateTables, so `every 24h` counts from the live last run.

import (
	"context"
	"database/sql"
	"fmt"
	"slices"
	"strings"
)

// restoreQueueTable is one framework work queue.
type restoreQueueTable struct {
	name string
	// active: the statuses of a row the worker or sweeper still acts on (it
	// runs the row, or settles a run a dead worker left). Any other status is
	// finished.
	active []string
	// state: the columns written as a row moves through the queue. A restore
	// takes them from the live row.
	state []string
	// held and reason: the status of a row that is not to run, and the column
	// that says why. stamp is set to the time of the hold and clear to NULL.
	held, reason, stamp, clear string
}

var restoreQueueTables = []restoreQueueTable{
	{
		name:   "_benmore_jobs",
		active: []string{"pending", "running"},
		state:  []string{"status", "attempts", "error", "not_before", "started_at", "completed_at", "lease_expires_at"},
		held:   "failed", reason: "error", stamp: "completed_at", clear: "lease_expires_at",
	},
	{
		name:   "_benmore_scheduled_tasks",
		active: []string{"pending", "blocked", "running"},
		state:  []string{"status", "fired_at", "last_error", "claimed_at", "recoveries"},
		held:   "cancelled", reason: "last_error",
	},
}

const (
	restoreHeldGone    = "still queued in the restored snapshot, but the live database no longer had it (it had finished and been cleaned up, or was deleted); not run again"
	restoreHeldUnknown = "still queued in the restored snapshot and already due, and nothing readable in the live database says whether it ran; not run again"
)

// restoreQueueSummary reports what a restore did to the rows the snapshot had
// queued, per table. Counts only.
type restoreQueueSummary struct {
	// Finished: the live database had finished them; they keep that outcome.
	Finished map[string]int `json:"finished,omitempty"`
	// Held: taken out of the queue because they may have run, or the live
	// database had removed them.
	Held map[string]int `json:"held,omitempty"`
	// Waiting: left queued; the worker or sweeper runs them when due.
	Waiting map[string]int `json:"waiting,omitempty"`
	// LiveError: why the live queue could not be read, when the rest of the
	// live database could.
	LiveError string `json:"live_error,omitempty"`
}

// isActive reports whether a stored status is one the queue still acts on.
func (q restoreQueueTable) isActive(status any) bool {
	return slices.Contains(q.active, credText(status))
}

// activeIn is `status IN (...)` over the active statuses, with its arguments.
func (q restoreQueueTable) activeIn() (string, []any) {
	args := make([]any, len(q.active))
	for i, status := range q.active {
		args[i] = status
	}
	return "status IN (?" + strings.Repeat(", ?", len(args)-1) + ")", args
}

// holdSet is the SET clause, with its arguments, that takes a row out of the
// queue. A snapshot can predate a column, so it names only those has lists.
func (q restoreQueueTable) holdSet(has map[string]bool, reason string) (string, []any) {
	set, args := []string{"status = ?"}, []any{q.held}
	if has[q.reason] {
		set, args = append(set, quoteIdent(q.reason)+" = ?"), append(args, reason)
	}
	if q.stamp != "" && has[q.stamp] {
		set = append(set, quoteIdent(q.stamp)+" = datetime('now')")
	}
	if q.clear != "" && has[q.clear] {
		set = append(set, quoteIdent(q.clear)+" = NULL")
	}
	return strings.Join(set, ", "), args
}

// holdQueuedRows takes every row a queue table still has queued out of the
// queue, with reason. 0 when the database has no such table.
func holdQueuedRows(ctx context.Context, tx *sql.Tx, q restoreQueueTable, reason string) (int, error) {
	t, err := readCredTable(ctx, tx, q.name, false, []string{})
	if err != nil || t == nil || !t.has["status"] {
		return 0, err
	}
	set, args := q.holdSet(t.has, reason)
	in, inArgs := q.activeIn()
	res, err := tx.ExecContext(ctx, "UPDATE "+quoteIdent(q.name)+" SET "+set+" WHERE "+in, append(args, inArgs...)...)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	return int(n), nil
}

// carryForwardRestoreQueue settles the candidate's queued work against the
// live database at livePath. liveReadable false: the credential pass found no
// live database, or could not read it.
func carryForwardRestoreQueue(ctx context.Context, tx *sql.Tx, livePath string, liveReadable bool) (*restoreQueueSummary, error) {
	summary := &restoreQueueSummary{Finished: map[string]int{}, Held: map[string]int{}, Waiting: map[string]int{}}
	var live *sql.DB
	if liveReadable {
		db, err := openRestoreDB("sqlite3", livePath, "ro", "")
		if err != nil && ctx.Err() != nil {
			return nil, ctx.Err()
		}
		if err != nil {
			summary.LiveError = err.Error()
		} else {
			defer db.Close()
			db.SetMaxOpenConns(1)
			live = db
		}
	}
	for _, q := range restoreQueueTables {
		if err := carryForwardQueueTable(ctx, tx, live, q, summary); err != nil {
			return nil, fmt.Errorf("%s: %w", q.name, err)
		}
	}
	return summary, nil
}

// liveQueueTable answers what the live database knows of a queue table's rows.
type liveQueueTable struct {
	byID *sql.Stmt // created_at, then cols, of the row with an id
	cols []string  // the execution-state columns both databases have
	high int64     // the highest id the live table has handed out
}

// openLiveQueueTable prepares the live lookups for q. nil with no error: the
// live database has no such table, or not one whose rows can be told apart.
func openLiveQueueTable(ctx context.Context, live *sql.DB, q restoreQueueTable, cand *credTable) (*liveQueueTable, error) {
	t, err := readCredTable(ctx, live, q.name, false, []string{})
	if err != nil || t == nil || !t.has["id"] || !t.has["created_at"] || !t.has["status"] {
		return nil, err
	}
	lt := &liveQueueTable{cols: present(q.state, cand, t)}
	// AUTOINCREMENT records the highest id ever handed out, so a row deleted
	// since still counts; a table without it has only the rows it holds.
	var seq, highest sql.NullInt64
	_ = live.QueryRowContext(ctx, "SELECT seq FROM sqlite_sequence WHERE name = ?", q.name).Scan(&seq)
	if err := live.QueryRowContext(ctx, "SELECT MAX(id) FROM "+quoteIdent(q.name)).Scan(&highest); err != nil {
		return nil, err
	}
	lt.high = max(seq.Int64, highest.Int64)
	selects := []string{"+created_at"}
	for _, col := range lt.cols {
		selects = append(selects, "+"+quoteIdent(col))
	}
	// `+col`: the stored value, as readCredTable reads it.
	lt.byID, err = live.PrepareContext(ctx, "SELECT "+strings.Join(selects, ", ")+" FROM "+quoteIdent(q.name)+" WHERE id = ?")
	if err != nil {
		return nil, err
	}
	return lt, nil
}

// row returns the live row with id: its created_at and execution state.
// found false: the live table holds no row with that id.
func (lt *liveQueueTable) row(ctx context.Context, id int64) (createdAt any, state []any, found bool, err error) {
	values := make([]any, 1+len(lt.cols))
	ptrs := make([]any, len(values))
	for i := range values {
		ptrs[i] = &values[i]
	}
	switch err := lt.byID.QueryRowContext(ctx, id).Scan(ptrs...); err {
	case nil:
		return values[0], values[1:], true, nil
	case sql.ErrNoRows:
		return nil, nil, false, nil
	default:
		return nil, nil, false, err
	}
}

func carryForwardQueueTable(ctx context.Context, tx *sql.Tx, live *sql.DB, q restoreQueueTable, summary *restoreQueueSummary) error {
	cand, err := readCredTable(ctx, tx, q.name, false, []string{})
	if err != nil || cand == nil {
		return err
	}
	for _, col := range []string{"id", "status", "created_at", "run_at"} {
		if !cand.has[col] {
			return nil // not a queue this binary's worker could run
		}
	}
	// What the snapshot still has queued; due: its time has come, or cannot
	// be read. Collected before any write: the transaction is one connection.
	type queued struct {
		rowid, id int64
		createdAt any
		due       bool
	}
	in, inArgs := q.activeIn()
	rows, err := tx.QueryContext(ctx, "SELECT rowid, +id, +created_at, datetime(run_at) IS NULL OR datetime(run_at) <= datetime('now') FROM "+quoteIdent(q.name)+" WHERE "+in+" ORDER BY rowid", inArgs...)
	if err != nil {
		return err
	}
	var work []queued
	for rows.Next() {
		var r queued
		var id any
		if err := rows.Scan(&r.rowid, &id, &r.createdAt, &r.due); err != nil {
			rows.Close()
			return err
		}
		r.id, _ = credInt(id)
		work = append(work, r)
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if err := rows.Close(); err != nil || len(work) == 0 {
		return err
	}

	// A live queue that cannot be read is no reason to refuse the restore
	// (the usual reason for one is a damaged database): from the failure on,
	// nothing says what ran, exactly as with no live database.
	liveFailed := func(err error) error {
		if ctx.Err() != nil {
			return ctx.Err() // a cancelled restore must stop, not read as damage
		}
		if summary.LiveError == "" {
			summary.LiveError = q.name + ": " + err.Error()
		}
		return nil
	}
	var lt *liveQueueTable
	if live != nil {
		if lt, err = openLiveQueueTable(ctx, live, q, cand); err != nil {
			if err := liveFailed(err); err != nil {
				return err
			}
		}
	}
	known := lt != nil
	if known {
		defer lt.byID.Close()
	}
	hold := func(r queued, reason string) error {
		set, args := q.holdSet(cand.has, reason)
		if _, err := tx.ExecContext(ctx, "UPDATE "+quoteIdent(q.name)+" SET "+set+" WHERE rowid = ?", append(args, r.rowid)...); err != nil {
			return err
		}
		summary.Held[q.name]++
		return nil
	}
	for _, r := range work {
		var liveCreated any
		var state []any
		found := false
		if known {
			if liveCreated, state, found, err = lt.row(ctx, r.id); err != nil {
				if err := liveFailed(err); err != nil {
					return err
				}
				known = false
			}
		}
		switch {
		case !known:
			if !r.due {
				summary.Waiting[q.name]++
			} else if err := hold(r, restoreHeldUnknown); err != nil {
				return err
			}
		case found && r.createdAt != nil && liveCreated != nil && credKey(r.createdAt) == credKey(liveCreated):
			if err := updateRow(ctx, tx, q.name, r.rowid, lt.cols, state); err != nil {
				return err
			}
			if q.isActive(state[slices.Index(lt.cols, "status")]) {
				summary.Waiting[q.name]++
			} else {
				summary.Finished[q.name]++
			}
		case !found && r.id <= lt.high:
			if err := hold(r, restoreHeldGone); err != nil {
				return err
			}
		default:
			summary.Waiting[q.name]++
		}
	}
	return nil
}
