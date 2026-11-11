package main

import (
	"database/sql"
	"errors"
)

// cancelScheduledTask cancels userID's task id while it is still pending or
// blocked. When it cancels nothing it reports the stored status instead:
// stored is "" when the user has no task with that id (a missing task and
// another user's look the same, so an id cannot be probed), else the status
// that refused the cancel (running, done, failed or cancelled).
//
// The guarded UPDATE and the read share one write transaction. The sweeper
// moves tasks back to pending (orphan recovery) and to blocked, so a read
// after a separate UPDATE could report a task as "already pending".
func cancelScheduledTask(db *sql.DB, id string, userID int64) (cancelled bool, stored string, err error) {
	tx, err := db.Begin()
	if err != nil {
		return false, "", err
	}
	defer tx.Rollback()
	res, err := tx.Exec("UPDATE _benmore_scheduled_tasks SET status='cancelled' WHERE id = ? AND user_id = ? AND status IN ('pending','blocked')", id, userID)
	if err != nil {
		return false, "", err
	}
	if n, _ := res.RowsAffected(); n == 1 {
		if err := tx.Commit(); err != nil {
			return false, "", err
		}
		return true, "", nil
	}
	err = tx.QueryRow("SELECT status FROM _benmore_scheduled_tasks WHERE id = ? AND user_id = ?", id, userID).Scan(&stored)
	if errors.Is(err, sql.ErrNoRows) {
		return false, "", nil
	}
	return false, stored, err
}
