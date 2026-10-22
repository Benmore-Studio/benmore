//go:build !cli

package main

import (
	"testing"
)

// A scheduled flow re-checks its owner's tenant membership when it runs. That
// check must use the same live-membership rules as a request: soft-deleted or
// inactive rows and unverified email-keyed rows grant nothing, and a
// membership table keyed by user id is matched by user id.
func TestScheduledTaskMembershipMustBeLive(t *testing.T) {
	for _, mode := range []string{"live", "soft_deleted", "inactive", "unverified", "user_id_live", "user_id_soft_deleted"} {
		t.Run(mode, func(t *testing.T) {
			app, mux := auditApp(t)
			auditExec(t, app.DB, "ALTER TABLE members ADD COLUMN deleted_at DATETIME")
			auditExec(t, app.DB, "ALTER TABLE members ADD COLUMN active INTEGER DEFAULT 1")
			auditExec(t, app.DB, "CREATE TABLE uid_members (id INTEGER PRIMARY KEY, org_id TEXT, member_id INTEGER, deleted_at DATETIME)")
			byUserID := mode == "user_id_live" || mode == "user_id_soft_deleted"
			if byUserID {
				app.Group = &GroupConfig{Table: "uid_members", Key: "org_id", UserField: "member_id"}
			}
			sid := createCrudScopeSession(t, app, "delegate@example.com", "user", "a", "")
			uid := GetSessionFromDB(app.DB, sid).UserID
			if byUserID {
				auditExec(t, app.DB, "INSERT INTO uid_members(org_id,member_id) VALUES ('a',?)", uid)
			} else {
				auditExec(t, app.DB, "INSERT INTO members(org_id,email) VALUES ('a','delegate@example.com')")
			}
			app.Flows = []Flow{{Name: "existing", Auth: "required", Trigger: FlowTrigger{Type: "http", Method: "POST"}, Steps: []FlowStep{{Type: "sql", SQL: "INSERT INTO notes(user_id,title) VALUES (:user_id, :_group_id)"}}}}
			w := auditPost(mux, sid, "/api/_scheduled", "", `{"kind":"flow","flow":"existing","run_at":"2000-01-01T00:00:00Z"}`, true)
			if w.Code != 200 {
				t.Fatalf("schedule failed: %d %s", w.Code, w.Body.String())
			}
			switch mode {
			case "soft_deleted":
				auditExec(t, app.DB, "UPDATE members SET deleted_at = CURRENT_TIMESTAMP")
			case "inactive":
				app.Group.ActiveField = "active"
				auditExec(t, app.DB, "UPDATE members SET active = 0")
			case "unverified":
				auditExec(t, app.DB, "UPDATE _benmore_users SET verified = 0, email_grandfathered = 0 WHERE id = ?", uid)
			case "user_id_soft_deleted":
				auditExec(t, app.DB, "UPDATE uid_members SET deleted_at = CURRENT_TIMESTAMP")
			}
			tasks, err := QueryRows(app.DB, "SELECT * FROM _benmore_scheduled_tasks")
			if err != nil || len(tasks) != 1 {
				t.Fatalf("task query: %v", err)
			}
			actor, _, _, err := prepareScheduledFlow(app, tasks[0])
			if mode == "live" || mode == "user_id_live" {
				if err != nil || actor.GroupID != "a" {
					t.Fatalf("live membership refused: actor=%+v err=%v", actor, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("task ran on a membership that is no longer live (group %q)", actor.GroupID)
			}
		})
	}
}
