//go:build !cli

package main

import (
	"fmt"
	"strings"
	"testing"
)

// The actual previous-release schema, without the new authorization columns.
func auditLegacyScheduleSchema(t *testing.T, app *App) {
	t.Helper()
	auditExec(t, app.DB, "DROP TABLE _benmore_scheduled_tasks")
	auditExec(t, app.DB, `CREATE TABLE _benmore_scheduled_tasks (
 id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER NOT NULL,
 kind TEXT NOT NULL DEFAULT 'reminder', title TEXT NOT NULL DEFAULT 'Reminder',
 message TEXT DEFAULT '', flow TEXT DEFAULT '', body TEXT DEFAULT '',
 table_name TEXT DEFAULT '', row_id TEXT DEFAULT '', run_at DATETIME NOT NULL,
 status TEXT NOT NULL DEFAULT 'pending', created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
 fired_at DATETIME, claimed_at DATETIME)`)
}

func TestAuditSchedulerLegacyUpgrade(t *testing.T) {
	for _, mode := range []string{"http", "async", "get", "internal_admin", "internal_user", "role_required", "ambiguous_tenant"} {
		t.Run(mode, func(t *testing.T) {
			app, _ := auditApp(t)
			auditLegacyScheduleSchema(t, app)
			role := "user"
			if mode == "internal_admin" {
				role = "admin"
			}
			sid := createCrudScopeSession(t, app, "legacy@example.com", role, "", "")
			uid := GetSessionFromDB(app.DB, sid).UserID
			auditExec(t, app.DB, "DELETE FROM _benmore_sessions")
			f := Flow{Name: "existing", Auth: "required", Transaction: true, Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/action/:record"}, Steps: []FlowStep{{Type: "sql", SQL: "INSERT INTO notes(user_id,title) VALUES (:user_id, :record || '/' || :label || '/' || :user_role || '/' || {{user.role}})"}}}
			if mode == "async" {
				f.Async = true
			}
			if mode == "get" {
				f.Trigger.Method = "GET"
			}
			if strings.HasPrefix(mode, "internal_") {
				f.Trigger.Type = "cron"
			}
			if mode == "role_required" {
				f.Role = "admin"
			}
			if mode == "ambiguous_tenant" {
				auditExec(t, app.DB, "INSERT INTO members(org_id,email) VALUES ('a','legacy@example.com'),('b','legacy@example.com')")
			}
			app.Flows = []Flow{f}
			const body = `{"record":"123","label":"kept","user_role":"forged","user":{"role":"forged"}}`
			auditExec(t, app.DB, "INSERT INTO _benmore_scheduled_tasks(id,user_id,kind,flow,body,run_at) VALUES (42,?,'flow','existing',?,'2000-01-01T00:00:00Z')", uid, body)
			// Repeated schema upgrades preserve every scheduled record.
			EnsureSchedulingTables(app.DB)
			EnsureSchedulingTables(app.DB)
			sweepScheduledTasks(app)
			sweepScheduledTasks(app)
			var status, keptBody, due, auth, reason string
			var fired any
			if err := app.DB.QueryRow("SELECT status,body,run_at,authorization,last_error,fired_at FROM _benmore_scheduled_tasks WHERE id=42").Scan(&status, &keptBody, &due, &auth, &reason, &fired); err != nil {
				t.Fatal(err)
			}
			if keptBody != body || due != "2000-01-01T00:00:00Z" {
				t.Fatalf("upgrade changed task payload or due time: %q %q", keptBody, due)
			}
			var effects, notifications int
			app.DB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&effects)
			app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_notifications").Scan(&notifications)
			blocked := mode == "internal_user" || mode == "role_required" || mode == "ambiguous_tenant"
			if blocked {
				if status != "blocked" || reason == "" || effects != 0 || notifications != 0 || fired != nil {
					t.Fatalf("unauthorized legacy task lost or executed: status=%s reason=%s effects=%d notifications=%d fired=%v", status, reason, effects, notifications, fired)
				}
				return
			}
			var owner int64
			var title string
			app.DB.QueryRow("SELECT user_id,title FROM notes").Scan(&owner, &title)
			if status != "done" || effects != 1 || notifications != 1 || owner != uid || title != "123/kept/"+role+"/"+role || auth == "" || strings.Contains(auth, sid) {
				t.Fatalf("legacy task not preserved: status=%s effects=%d notifications=%d owner=%d title=%q auth=%q", status, effects, notifications, owner, title, auth)
			}
		})
	}
}

func TestAuditSchedulerDelegationRevocation(t *testing.T) {
	for _, mode := range []string{"role", "tenant", "scopes", "promotion"} {
		t.Run(mode, func(t *testing.T) {
			app, mux := auditApp(t)
			sid := createCrudScopeSession(t, app, "delegate@example.com", "editor", "a", "")
			auditExec(t, app.DB, "UPDATE _benmore_sessions SET scopes='notes:read' WHERE id=?", sid)
			uid := GetSessionFromDB(app.DB, sid).UserID
			auditExec(t, app.DB, "INSERT INTO members(org_id,email) VALUES ('a','delegate@example.com')")
			app.Roles = &RolesConfig{Roles: map[string]RoleDef{"editor": {Scopes: "notes:read"}, "admin": {Scopes: "*"}}}
			app.Flows = []Flow{{Name: "existing", Auth: "required", Trigger: FlowTrigger{Type: "http", Method: "POST"}, Steps: []FlowStep{{Type: "sql", SQL: "INSERT INTO notes(user_id,title) VALUES (:user_id, '{{user.role}}')"}}}}
			w := auditPost(mux, sid, "/api/_scheduled", "", `{"kind":"flow","flow":"existing","run_at":"2000-01-01T00:00:00Z"}`, true)
			if w.Code != 200 {
				t.Fatalf("schedule failed: %d %s", w.Code, w.Body.String())
			}
			switch mode {
			case "role":
				auditExec(t, app.DB, "UPDATE _benmore_users SET role='user' WHERE id=?", uid)
			case "tenant":
				auditExec(t, app.DB, "DELETE FROM members")
			case "scopes":
				app.Roles.Roles["editor"] = RoleDef{Scopes: "rooms:read"}
			case "promotion":
				auditExec(t, app.DB, "UPDATE _benmore_users SET role='admin' WHERE id=?", uid)
			}
			tasks, err := QueryRows(app.DB, "SELECT * FROM _benmore_scheduled_tasks")
			if err != nil || len(tasks) != 1 {
				t.Fatalf("task query: %v", err)
			}
			actor, _, _, err := prepareScheduledFlow(app, tasks[0])
			if mode == "role" || mode == "tenant" {
				if err == nil {
					t.Fatal("revoked delegation accepted")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if actor.Role != "editor" || actor.IsAdmin() || hasScope(actor, "rooms", "read") || (mode == "scopes" && hasScope(actor, "notes", "read")) {
				t.Fatalf("task gained permissions: %+v", actor)
			}
			if mode == "promotion" {
				sweepScheduledTasks(app)
				var role string
				if err := app.DB.QueryRow("SELECT title FROM notes").Scan(&role); err != nil || role != "editor" {
					t.Fatalf("user.role escaped delegation: role=%q error=%v", role, err)
				}
			}
		})
	}
}

func TestAuditSchedulerBlockedTasksDoNotStarveQueue(t *testing.T) {
	app, _ := auditApp(t)
	sid := createCrudScopeSession(t, app, "queue@example.com", "user", "", "")
	uid := GetSessionFromDB(app.DB, sid).UserID
	for i := 0; i < 55; i++ {
		auditExec(t, app.DB, "INSERT INTO _benmore_scheduled_tasks(user_id,kind,flow,run_at) VALUES (?,'flow',?,'2000-01-01T00:00:00Z')", uid, fmt.Sprintf("missing-%d", i))
	}
	auditExec(t, app.DB, "INSERT INTO _benmore_scheduled_tasks(user_id,kind,run_at) VALUES (?,'reminder','2000-01-02T00:00:00Z')", uid)
	sweepScheduledTasks(app)
	sweepScheduledTasks(app)
	var done int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_scheduled_tasks WHERE kind='reminder' AND status='done'").Scan(&done)
	if done != 1 {
		t.Fatal("held tasks starved a valid reminder")
	}
	// Restore a late task; blocked records rotate through the queue as well.
	app.Flows = []Flow{{Name: "missing-54", Trigger: FlowTrigger{Type: "http", Method: "POST"}, Steps: []FlowStep{{Type: "sql", SQL: "INSERT INTO notes(title) VALUES ('recovered')"}}}}
	sweepScheduledTasks(app)
	sweepScheduledTasks(app)
	app.DB.QueryRow("SELECT COUNT(*) FROM notes WHERE title='recovered'").Scan(&done)
	if done != 1 {
		t.Fatal("restored blocked task did not recover in place")
	}
}

func TestAuditSchedulerRateLimitDefersWithoutDuplicateEffects(t *testing.T) {
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "rate@example.com", "user", "", "")
	app.Flows = []Flow{{Name: "limited", RateLimit: parseRateLimit("1/hour per user"), Trigger: FlowTrigger{Type: "http", Method: "POST"}, Steps: []FlowStep{{Type: "sql", SQL: "INSERT INTO notes(title) VALUES ('once')"}}}}
	for i := 0; i < 2; i++ {
		w := auditPost(mux, sid, "/api/_scheduled", "", `{"kind":"flow","flow":"limited","run_at":"2000-01-01T00:00:00Z"}`, true)
		if w.Code != 200 {
			t.Fatal(w.Body.String())
		}
	}
	sweepScheduledTasks(app)
	var held, effects int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_scheduled_tasks WHERE status='blocked' AND fired_at IS NULL").Scan(&held)
	app.DB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&effects)
	if held != 1 || effects != 1 {
		t.Fatalf("rate limit lost or ran a task: held=%d effects=%d", held, effects)
	}
	limiter := flowLimiterFor(app, &app.Flows[0])
	limiter.mu.Lock()
	clear(limiter.visitors)
	limiter.mu.Unlock()
	sweepScheduledTasks(app)
	sweepScheduledTasks(app)
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_scheduled_tasks WHERE status='done'").Scan(&held)
	app.DB.QueryRow("SELECT COUNT(*) FROM notes").Scan(&effects)
	if held != 2 || effects != 2 {
		t.Fatalf("retry lost or duplicated effects: done=%d effects=%d", held, effects)
	}
}
