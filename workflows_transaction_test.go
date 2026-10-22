//go:build !cli

package main

import (
	"net/http"
	"testing"
	"time"
)

func TestWorkflowTransitionRollsBackHookEffects(t *testing.T) {
	for _, failure := range []string{"before-denial", "update-failure", "after-failure", "audit-failure", "success"} {
		t.Run(failure, func(t *testing.T) {
			app, wf, cleanup := newWorkflowTenantApp(t)
			defer cleanup()
			// Transaction helpers must use the transaction's connection, never
			// reach back through app.DB while holding its only connection.
			app.DB.SetMaxOpenConns(1)
			uid := workflowTestUser(t, app, "operator@example.test")
			addMember(t, app, "A", uid, "approver")
			mustExec(t, app.DB, "CREATE TABLE transition_effects (id INTEGER PRIMARY KEY, reason TEXT)")
			mustExec(t, app.DB, "INSERT INTO orders (id, org_id, user_id, status) VALUES (1,'A',1,'pending')")
			app.Hooks = &HookConfig{
				BeforeUpdate: map[string][]Hook{"orders": {{SQL: "INSERT INTO transition_effects(reason) VALUES ('before')"}}},
				OnUpdate: map[string][]Hook{"orders": {
					{SQL: "INSERT INTO transition_effects(reason) VALUES ('after')"},
					{Webhook: "https://hooks.example.test/updated"},
				}},
			}
			wf.OnTransition = map[string][]Hook{"approved": {
				{SQL: "INSERT INTO transition_effects(reason) VALUES ('transition')"},
				{Webhook: "https://hooks.example.test/transitioned"},
			}}
			wantStatus := http.StatusInternalServerError
			switch failure {
			case "before-denial":
				app.Hooks.BeforeUpdate["orders"] = append(app.Hooks.BeforeUpdate["orders"], Hook{SQL: "SELECT 'approval refused' AS error"})
				wantStatus = http.StatusUnprocessableEntity
			case "update-failure":
				mustExec(t, app.DB, "CREATE TRIGGER refuse_state BEFORE UPDATE ON orders BEGIN SELECT RAISE(ABORT, 'state refused'); END")
			case "after-failure":
				app.Hooks.OnUpdate["orders"] = append(app.Hooks.OnUpdate["orders"], Hook{SQL: "INSERT INTO nonexistent_table(value) VALUES ('refused')"})
			case "audit-failure":
				mustExec(t, app.DB, "CREATE TRIGGER refuse_audit BEFORE INSERT ON _benmore_audit_log BEGIN SELECT RAISE(ABORT, 'audit refused'); END")
			case "success":
				wantStatus = http.StatusOK
			}
			sid := CreateSession(app.DB, uid, "operator@example.test", "A", time.Hour)
			response := transitionAs(app, wf, sid, "1", "approved")
			if response.Code != wantStatus {
				t.Fatalf("HTTP=%d want=%d body=%s", response.Code, wantStatus, response.Body.String())
			}
			var effects, jobs, audits int
			var state string
			for query, dest := range map[string]*int{
				"SELECT COUNT(*) FROM transition_effects":                           &effects,
				"SELECT COUNT(*) FROM _benmore_jobs":                                &jobs,
				"SELECT COUNT(*) FROM _benmore_audit_log WHERE action='transition'": &audits,
			} {
				if err := app.DB.QueryRow(query).Scan(dest); err != nil {
					t.Fatal(err)
				}
			}
			if err := app.DB.QueryRow("SELECT status FROM orders WHERE id=1").Scan(&state); err != nil {
				t.Fatal(err)
			}
			if failure == "success" {
				if state != "approved" || effects != 3 || jobs != 2 || audits != 1 {
					t.Fatalf("commit incomplete: state=%s effects=%d jobs=%d audits=%d", state, effects, jobs, audits)
				}
			} else if state != "pending" || effects != 0 || jobs != 0 || audits != 0 {
				t.Fatalf("failed transition committed effects: state=%s effects=%d jobs=%d audits=%d", state, effects, jobs, audits)
			}
		})
	}
}
