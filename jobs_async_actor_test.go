//go:build !cli

package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// An async flow's request gates run at enqueue; the job may run much later
// (backlog, retries, crash requeue). The worker re-checks the account the
// job was queued for: deactivated, forced to replace its password, or no
// longer holding the flow's role means the job does nothing.
func TestAsyncFlowJobRechecksQueuingAccount(t *testing.T) {
	cases := []struct {
		name, role, flowRole, change string
		wantRun                      bool
	}{
		{"active account runs", "user", "", "", true},
		{"deactivated account", "user", "", "UPDATE _benmore_users SET deactivated_at = datetime('now')", false},
		{"password reset pending", "user", "", "UPDATE _benmore_users SET password_change_required = 1", false},
		{"deleted account", "user", "", "DELETE FROM _benmore_users", false},
		{"role still held", "admin", "admin", "", true},
		{"role revoked", "admin", "admin", "UPDATE _benmore_users SET role = 'user'", false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			app, _ := auditApp(t)
			EnsureJobsTable(app.DB)
			sid := createCrudScopeSession(t, app, "queuer@example.com", c.role, "", "")
			flow := Flow{Name: "slow_sync", Auth: "required", Role: c.flowRole, Async: true,
				Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/slow-sync"},
				Steps:   []FlowStep{{Type: "sql", SQL: "INSERT INTO notes (user_id, title) VALUES (:user_id, 'ran')"}}}
			app.Flows = []Flow{flow}

			r := httptest.NewRequest("POST", "/api/slow-sync", strings.NewReader(`{"__benmore_job_actor": 999}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer "+sid)
			w := httptest.NewRecorder()
			executeFlowHTTP(app, &app.Flows[0], w, r)
			if w.Code != 202 {
				t.Fatalf("enqueue = %d %s", w.Code, w.Body.String())
			}
			if c.change != "" {
				auditExec(t, app.DB, c.change)
			}
			FlushJobs(app)

			var ran int
			app.DB.QueryRow("SELECT COUNT(*) FROM notes WHERE title = 'ran'").Scan(&ran)
			if c.wantRun && ran != 1 {
				var status, errMsg string
				app.DB.QueryRow("SELECT status, COALESCE(error,'') FROM _benmore_jobs").Scan(&status, &errMsg)
				t.Fatalf("job for a live account did not run: %s %s", status, errMsg)
			}
			if !c.wantRun {
				if ran != 0 {
					t.Fatal("job ran for an account that lost its authority after queuing")
				}
				var status string
				var attempts int
				app.DB.QueryRow("SELECT status, attempts FROM _benmore_jobs").Scan(&status, &attempts)
				if status != "failed" || attempts != 1 {
					t.Fatalf("refused job: status=%s attempts=%d, want failed after one attempt", status, attempts)
				}
			}
		})
	}
}

// The worker also re-checks what the request gates checked about the tenant
// and the flow's permissions: a job queued in a tenant the account has since
// left, or for a flow whose permission the account's roles no longer grant,
// does nothing - the same rules a request applies (a non-admin's cached
// tenant holds only while its membership is live) and scheduled flow tasks
// apply at run time.
func TestAsyncFlowJobRechecksTenantAndPermissions(t *testing.T) {
	cases := []struct {
		name, role, change string
		perms              []string
		wantRun            bool
	}{
		{"tenant member runs", "user", "", nil, true},
		// A user_field whose name doesn't say email but holds addresses: a
		// request re-resolves the tenant by email every time, so the job
		// keeps it while the membership exists.
		{"email held in a column not named for email", "user", "USERFIELD:login", nil, true},
		{"email held in a column not named for email, removed", "user", "USERFIELD:login|DELETE FROM crew", nil, false},
		{"tenant membership removed", "user", "DELETE FROM members WHERE email = 'queuer@example.com'", nil, false},
		{"tenant membership soft-moved", "user", "UPDATE members SET org_id = 'tenant-b' WHERE email = 'queuer@example.com'", nil, false},
		{"admin keeps the tenant it worked in", "admin", "DELETE FROM members WHERE email = 'queuer@example.com'", nil, true},
		{"unverified address of an email-keyed membership", "user", "UPDATE _benmore_users SET verified = 0, email_grandfathered = 0", nil, false},
		{"permission still granted", "editor", "", []string{"orgdocs:write"}, true},
		{"permission revoked", "editor", "UPDATE _benmore_users SET role = 'viewer'", []string{"orgdocs:write"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			app, _ := auditApp(t)
			EnsureJobsTable(app.DB)
			app.Roles = &RolesConfig{Roles: map[string]RoleDef{
				"user": {Scopes: "orgdocs:write"}, "editor": {Scopes: "orgdocs:write"},
				"viewer": {Scopes: "orgdocs:read"}, "admin": {Scopes: "orgdocs:write"},
			}}
			auditExec(t, app.DB, "INSERT INTO members (id, org_id, email) VALUES (1, 'tenant-a', 'queuer@example.com')")
			change := c.change
			if rest, ok := strings.CutPrefix(change, "USERFIELD:login"); ok {
				auditExec(t, app.DB, "CREATE TABLE crew (id INTEGER PRIMARY KEY, org_id TEXT, login TEXT)")
				auditExec(t, app.DB, "INSERT INTO crew VALUES (1, 'tenant-a', 'queuer@example.com')")
				app.Group = &GroupConfig{Table: "crew", Key: "org_id", UserField: "login"}
				change = strings.TrimPrefix(rest, "|")
			}
			sid := createCrudScopeSession(t, app, "queuer@example.com", c.role, "tenant-a", "")
			if c.role == "admin" {
				auditExec(t, app.DB, "UPDATE _benmore_sessions SET acting_as_group = 'tenant-a' WHERE id = ?", sessionStorageKey(sid))
			}
			flow := Flow{Name: "tenant_sync", Auth: "required", Permissions: c.perms, Async: true,
				Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/tenant-sync"},
				Steps:   []FlowStep{{Type: "sql", SQL: "INSERT INTO orgdocs (org_id, title) VALUES (:user_group_id, 'ran')"}}}
			app.Flows = []Flow{flow}

			r := httptest.NewRequest("POST", "/api/tenant-sync", strings.NewReader(`{}`))
			r.Header.Set("Content-Type", "application/json")
			r.Header.Set("Authorization", "Bearer "+sid)
			w := httptest.NewRecorder()
			executeFlowHTTP(app, &app.Flows[0], w, r)
			if w.Code != 202 {
				t.Fatalf("enqueue = %d %s", w.Code, w.Body.String())
			}
			if change != "" {
				auditExec(t, app.DB, change)
			}
			FlushJobs(app)

			var ran int
			app.DB.QueryRow("SELECT COUNT(*) FROM orgdocs WHERE title = 'ran' AND org_id = 'tenant-a'").Scan(&ran)
			var status, errMsg string
			app.DB.QueryRow("SELECT status, COALESCE(error,'') FROM _benmore_jobs").Scan(&status, &errMsg)
			if c.wantRun && ran != 1 {
				t.Fatalf("job did not run: %s %s", status, errMsg)
			}
			if !c.wantRun && (ran != 0 || status != "failed") {
				t.Fatalf("job ran in a tenant or with a permission the account lost: ran=%d status=%s", ran, status)
			}
		})
	}
}
