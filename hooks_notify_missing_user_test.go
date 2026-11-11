//go:build !cli

package main

import (
	"database/sql"
	"strings"
	"testing"
)

// A hook `notify:` whose user id names no account (a task created with
// assignee_id 999) stored an orphan notification and its job completed with
// no error: the account later given id 999 would have read another tenant's
// task title. The notification is now skipped and the completed job keeps
// the reason; a notify to a real account is unchanged.
func TestHookNotifyToMissingUserIsSkippedAndRecorded(t *testing.T) {
	app, _ := auditApp(t)
	EnsureJobsTable(app.DB)
	sid := createCrudScopeSession(t, app, "assignee@example.com", "user", "", "")
	assignee := GetSessionFromDB(app.DB, sid).UserID
	hook := Hook{Notify: &NotifyHook{UserID: "{{assignee_id}}", Title: "Assigned: {{title}}"}}

	runJob := func(row map[string]any) (status, errText string) {
		t.Helper()
		EnqueueHookJob(app, hook, "notes", row)
		if !processNextJob(app) {
			t.Fatal("hook job was not claimed")
		}
		var jobErr sql.NullString
		if err := app.DB.QueryRow("SELECT status, error FROM _benmore_jobs WHERE job_type = 'hook' ORDER BY id DESC LIMIT 1").Scan(&status, &jobErr); err != nil {
			t.Fatal(err)
		}
		return status, jobErr.String
	}
	countFor := func(uid int64) int {
		var n int
		if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_notifications WHERE user_id = ?", uid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	status, errText := runJob(map[string]any{"id": 1, "assignee_id": 999, "title": "tenant-b secret plan"})
	if countFor(999) != 0 {
		t.Fatal("a notify to a user id no account has stored a notification")
	}
	if status != "completed" || !strings.Contains(errText, "hook notify skipped: no account has user_id 999") {
		t.Fatalf("job for a missing recipient = %q, error %q; want completed with the skip reason", status, errText)
	}

	status, errText = runJob(map[string]any{"id": 2, "assignee_id": assignee, "title": "real task"})
	if countFor(assignee) != 1 || status != "completed" || errText != "" {
		t.Fatalf("notify to a real account: rows %d, status %q, error %q; want one row, completed, no error", countFor(assignee), status, errText)
	}
	var title string
	if err := app.DB.QueryRow("SELECT title FROM _benmore_notifications WHERE user_id = ?", assignee).Scan(&title); err != nil || title != "Assigned: real task" {
		t.Fatalf("notification title = %q, %v", title, err)
	}
	if _, err := CreateNotification(app.DB, 4242, "direct", "", "info", ""); err != errNotificationRecipientMissing {
		t.Fatalf("CreateNotification for a missing account = %v; want errNotificationRecipientMissing", err)
	}
}
