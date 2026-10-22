//go:build !cli && !windows

package main

import (
	"context"
	"strings"
	"testing"
)

func TestAppMCPCommandParityValidatorRefusalRollsBack(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixture(t)
	commandParityGeneration(app, func(generation *appMCPRuntimeGeneration) {
		generation.validators = &ValidatorConfig{Rules: map[string][]ValidatorRule{"tasks": {{Rule: "title != 'Source-backed task'", Error: "command title rejected"}}}}
		generation.view.Validators = generation.validators
	})
	if _, err := runHookedCommand(t, app, sessionID); err == nil || !strings.Contains(err.Error(), "command title rejected") {
		t.Fatalf("validator did not refuse command: %v", err)
	}
	assertCommandTaskUnchanged(t, app)
	if n := hookCount(t, app, `SELECT count(*) FROM activities`); n != 0 {
		t.Fatalf("validator refusal left %d activity rows", n)
	}
}

func TestAppMCPCommandParityComputedFieldRunsInTransaction(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixture(t)
	computed := &ComputedFieldConfig{Fields: map[string]map[string]*ComputedField{"tasks": {
		"title": {Table: "tasks", Column: "title", Expr: "status"},
	}}}
	commandParityGeneration(app, func(generation *appMCPRuntimeGeneration) {
		generation.computed = computed
		generation.view.Computed = computed
	})
	InstallComputedTriggers(app.DB, computed)
	if _, err := runHookedCommand(t, app, sessionID); err != nil {
		t.Fatalf("command with computed field: %v", err)
	}
	var title string
	if err := app.DB.QueryRow(`SELECT title FROM tasks WHERE id=?`, 1).Scan(&title); err != nil || title != "done" {
		t.Fatalf("computed value = %q, %v; want done", title, err)
	}
}

func TestAppMCPCommandParityEncryptedFieldCiphertextAndAllowedReadback(t *testing.T) {
	flow := strings.Replace(hookTaskFlow, "UPDATE tasks SET status = 'done',", "UPDATE tasks SET title = 'secret-value', status = 'done',", 1)
	flow = strings.Replace(flow, "a.actor_email FROM tasks AS t", "t.title AS actor_email FROM tasks AS t", 1)
	if flow == hookTaskFlow || !strings.Contains(flow, "t.title AS actor_email") {
		t.Fatal("encrypted-field fixture changes did not apply")
	}
	app, sessionID, _ := newCommandProviderTaskFixtureWithSource(t, flow)
	encrypted := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"tasks": {{Column: "title", Roles: []string{"editor"}}}}}
	commandParityGeneration(app, func(generation *appMCPRuntimeGeneration) {
		generation.view.Encrypted = encrypted
	})
	InstallEncryptionTriggers(app.DB, encrypted)
	readback, err := runHookedCommand(t, app, sessionID)
	if err != nil {
		t.Fatalf("command with encrypted field: %v", err)
	}
	if readback["actor_email"] != "secret-value" {
		t.Fatalf("authorized command readback title = %#v", readback["actor_email"])
	}
	var stored string
	if err := app.DB.QueryRow(`SELECT title FROM tasks WHERE id=?`, 1).Scan(&stored); err != nil || !strings.HasPrefix(stored, "enc:") {
		t.Fatalf("encrypted field was stored as %q (%v)", stored, err)
	}
}

func TestAppMCPCommandParityWorkflowRoleGuard(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixture(t)
	workflows := &WorkflowConfig{Workflows: map[string]*Workflow{"tasks": {
		Name: "task-state", Table: "tasks", Field: "status", Initial: "open", States: []string{"open", "done"},
		Transitions: map[string]map[string]Transition{"open": {"done": {Role: "admin"}}},
	}}}
	commandParityGeneration(app, func(generation *appMCPRuntimeGeneration) {
		generation.workflows = workflows
		generation.view.Workflows = workflows
	})
	if _, err := runHookedCommand(t, app, sessionID); err == nil || !strings.Contains(err.Error(), "role 'admin' required") {
		t.Fatalf("workflow role guard did not refuse command: %v", err)
	}
	assertCommandTaskUnchanged(t, app)
}

func TestAppMCPCommandParityEventFlowQueuedWithEffectID(t *testing.T) {
	h := newEffectHarness(t, "")
	flow := Flow{Name: "task-updated", Trigger: FlowTrigger{Type: "on_update", Table: "tasks"}}
	commandParityGeneration(h.app, func(generation *appMCPRuntimeGeneration) {
		generation.flows = append(generation.flows, flow)
		generation.view.Flows = append(generation.view.Flows, flow)
	})
	id := h.prepare()
	h.approveOK(id)
	out, code := h.commit(id)
	if code != "" {
		t.Fatalf("command commit: %s", code)
	}
	receipt, _ := out["receipt"].(map[string]any)
	items := effectItems(t, effectsOf(t, receipt))
	if len(items) != 1 || items[0]["kind"] != "flow" || items[0]["target"] != "tasks.update" {
		t.Fatalf("event-flow effects: %#v", items)
	}
	var jobID, jobType, flowName string
	if err := h.app.DB.QueryRow(`SELECT CAST(id AS TEXT),job_type,flow_name FROM _benmore_jobs`).Scan(&jobID, &jobType, &flowName); err != nil {
		t.Fatal(err)
	}
	if jobID != items[0]["id"] || jobType != "flow" || flowName != "task-updated" {
		t.Fatalf("effect does not link the event-flow job: id=%s type=%s flow=%s effects=%#v", jobID, jobType, flowName, items)
	}
}

// The in-tenant membership role that satisfies a workflow transition's `role:`
// must be the one the CRUD transition route accepts (hasWorkflowRole): the same
// stored role either passes both or neither.
func TestAppMCPCommandParityWorkflowMembershipRoleMatchesCRUD(t *testing.T) {
	for _, stored := range []string{"approver", "APPROVER", "Approver"} {
		t.Run(stored, func(t *testing.T) {
			app, sessionID, _ := newUnenrolledCommandProviderTaskFixtureWithManifest(t, hookTaskFlow, "", func(_ *AppMCPManifest, dir string) {
				writeTestFile(t, dir, "schema.sql", `CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, email TEXT NOT NULL, user_id INTEGER NOT NULL, role TEXT);
CREATE TABLE projects (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL);
CREATE TABLE tasks (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, org_id TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL, completed_by INTEGER, completed_at TEXT);
CREATE TABLE activities (id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL, actor_user_id INTEGER NOT NULL, actor_email TEXT NOT NULL, event TEXT NOT NULL);
`)
			})
			if _, err := app.DB.Exec(`UPDATE members SET role=?`, stored); err != nil {
				t.Fatal(err)
			}
			if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
				t.Fatal(err)
			}
			generation := snapshotAppMCPGeneration(app)
			if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation); err != nil {
				t.Fatal(err)
			}
			if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
				t.Fatal(err)
			}
			workflows := &WorkflowConfig{Workflows: map[string]*Workflow{"tasks": {
				Name: "task-state", Table: "tasks", Field: "status", Initial: "open", States: []string{"open", "done"},
				Transitions: map[string]map[string]Transition{"open": {"done": {Role: "approver"}}},
			}}}
			commandParityGeneration(app, func(generation *appMCPRuntimeGeneration) {
				generation.workflows = workflows
				generation.view.Workflows = workflows
			})
			crudActor, err := loadStoredSessionChecked(app.DB, true, sessionID)
			if err != nil || crudActor == nil {
				t.Fatalf("load actor session: %v", err)
			}
			crudAllows := hasWorkflowRole(app, crudActor, "approver")
			_, err = runHookedCommand(t, app, sessionID)
			commandAllows := err == nil
			if err != nil && !strings.Contains(err.Error(), "role 'approver' required") {
				t.Fatalf("command failed for another reason: %v", err)
			}
			if stored == "approver" && !crudAllows {
				t.Fatal("fixture membership role was not resolved by the CRUD route")
			}
			if commandAllows != crudAllows {
				t.Fatalf("stored role %q: CRUD transition allows=%t, approved command allows=%t", stored, crudAllows, commandAllows)
			}
		})
	}
}

// A data-event flow queued by a command runs on the row the command wrote, so
// the written columns are request input in the worker exactly as they are when
// CRUD runs the same flow synchronously (flowEventRowTaint): a sql_dynamic step
// that splices one of them into SQL text must refuse, not execute.
func TestAppMCPCommandParityEventFlowKeepsRowTaint(t *testing.T) {
	h := newEffectHarness(t, "")
	flow := Flow{Name: "task-updated", Trigger: FlowTrigger{Type: "on_update", Table: "tasks"}, Steps: []FlowStep{
		{Name: "dyn", Type: "sql_dynamic", SQL: "INSERT INTO activities(task_id,actor_user_id,actor_email,event) VALUES (1,1,'x','{{title}}')"},
	}}
	commandParityGeneration(h.app, func(generation *appMCPRuntimeGeneration) {
		generation.flows = append(generation.flows, flow)
		generation.view.Flows = append(generation.view.Flows, flow)
	})
	h.commitApproved()
	var payload string
	if err := h.app.DB.QueryRow(`SELECT payload FROM _benmore_jobs WHERE job_type='flow'`).Scan(&payload); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(payload, flowRequestKeysPayloadField) {
		t.Fatalf("command event-flow job carries no request-taint set: %s", payload)
	}
	FlushJobs(h.app)
	if n := h.count(`SELECT count(*) FROM activities WHERE event='Source-backed task'`); n != 0 {
		t.Fatal("a command-written row column reached sql_dynamic as raw SQL text")
	}
	var status, jobError string
	if err := h.app.DB.QueryRow(`SELECT status, COALESCE(error,'') FROM _benmore_jobs WHERE job_type='flow'`).Scan(&status, &jobError); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(jobError, "request-sourced") {
		t.Fatalf("event-flow job was not refused by the sql_dynamic guard: status=%s error=%q", status, jobError)
	}
}

func commandParityGeneration(app *App, configure func(*appMCPRuntimeGeneration)) {
	base := snapshotAppMCPGeneration(app)
	generation := *base
	generation.view = base.view
	configure(&generation)
	app.mu.Lock()
	app.mcpGeneration = &generation
	app.Validators = generation.validators
	app.Computed = generation.computed
	app.Encrypted = generation.view.Encrypted
	app.Workflows = generation.workflows
	app.Flows = append([]Flow(nil), generation.flows...)
	app.mu.Unlock()
}

func TestAppMCPCommandParityStillRefusesUnsupportedBeforeHook(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, `before_update:
  tasks:
    - ws: {room: "task", payload: "{}"}
`)
	_, err := runHookedCommand(t, app, sessionID)
	if err == nil || !strings.Contains(err.Error(), "before-hooks must be read-only SQL") {
		t.Fatalf("unsupported before-hook was not refused: %v", err)
	}
	assertCommandTaskUnchanged(t, app)
}

// An approved command must not update a row another user holds an edit lock
// on, exactly as PATCH, /api/_transaction and the transition route refuse it
// (CheckLock). The refusal is a retryable conflict; the actor's own lock and an
// expired lock do not block.
func TestAppMCPCommandParityRespectsForeignEditLock(t *testing.T) {
	for _, tc := range []struct {
		name    string
		holder  int64
		expires string
		refused bool
	}{
		{"other user", 999, "+1 hour", true},
		{"own lock", 0, "+1 hour", false},
		{"expired", 999, "-1 hour", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, sessionID, actorID := newCommandProviderTaskFixture(t)
			EnsureLocksTable(app.DB)
			holder := tc.holder
			if holder == 0 {
				holder = actorID
			}
			if _, err := app.DB.Exec(`INSERT INTO _benmore_locks(table_name,row_id,user_id,user_email,expires_at) VALUES('tasks','1',?,'editor@example.com',datetime('now',?))`, holder, tc.expires); err != nil {
				t.Fatal(err)
			}
			crudLocked, _ := CheckLock(app.DB, "tasks", "1", actorID)
			_, err := runHookedCommand(t, app, sessionID)
			if crudLocked != tc.refused {
				t.Fatalf("fixture: CRUD lock decision = %t, want %t", crudLocked, tc.refused)
			}
			if tc.refused {
				if err == nil || appMCPCommandErrorClass(err) != "conflict" {
					t.Fatalf("command updated a row locked by another user: %v", err)
				}
				assertCommandTaskUnchanged(t, app)
				return
			}
			if err != nil {
				t.Fatalf("command refused without a foreign lock: %v", err)
			}
		})
	}
}
