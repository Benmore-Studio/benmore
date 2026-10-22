//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"
	"time"
)

func workflowTimestampFixture(t *testing.T, initial string) (*App, *Workflow, string) {
	t.Helper()
	app, wf, cleanup := newWorkflowTenantApp(t)
	t.Cleanup(cleanup)
	app.DB.Close()
	db, err := sql.Open("sqlite3_benmore", filepath.Join(app.Dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	app.DB = db
	app.DB.SetMaxOpenConns(1)
	mustExec(t, app.DB, "ALTER TABLE orders ADD COLUMN title TEXT DEFAULT 'original'")
	mustExec(t, app.DB, "ALTER TABLE orders ADD COLUMN updated_at DATETIME")
	refreshTableColumns(t, app, "orders")
	mustExec(t, app.DB, prismaUpdatedAtTriggerSQL("orders", "updated_at"))
	if err := InstallVersioningTriggers(app.DB, &VersionedConfig{Tables: []string{"orders"}}, nil); err != nil {
		t.Fatal(err)
	}
	uid := workflowTestUser(t, app, "versions@example.test")
	addMember(t, app, "A", uid, "approver")
	if _, err := app.DB.Exec("INSERT INTO orders(id,org_id,user_id,status,updated_at) VALUES(1,'A',?,'pending',?)", uid, initial); err != nil {
		t.Fatal(err)
	}
	wf.Transitions["approved"] = map[string]Transition{"pending": {}}
	return app, wf, CreateSession(app.DB, uid, "versions@example.test", "A", time.Hour)
}
func workflowStoredTimestamp(t *testing.T, app *App) string {
	t.Helper()
	var token string
	if err := app.DB.QueryRow("SELECT CAST(updated_at AS TEXT) FROM orders WHERE id=1").Scan(&token); err != nil {
		t.Fatal(err)
	}
	return token
}
func TestWorkflowTransitionAdvancesTimestampAndRejectsCycleToken(t *testing.T) {
	for _, initial := range []string{time.Now().UTC().Format("2006-01-02 15:04:05"), "2099-01-01 00:00:00.123456789"} {
		t.Run(initial, func(t *testing.T) {
			app, wf, sid := workflowTimestampFixture(t, initial)
			prior := initial
			for _, target := range []string{"approved", "pending", "approved"} {
				w := transitionAs(app, wf, sid, "1", target)
				if w.Code != http.StatusOK {
					t.Fatalf("transition: %d %s", w.Code, w.Body.String())
				}
				next := workflowStoredTimestamp(t, app)
				before, ok := parseUpdateTimestamp(prior)
				after, nextOK := parseUpdateTimestamp(next)
				if !ok || !nextOK || !after.After(before) {
					t.Errorf("workflow version did not advance: %q -> %q", prior, next)
				}
				prior = next
			}
			w := canonicalPatch(app, sid, "orders", "1", "application/json", fmt.Sprintf(`{"title":"stale overwrite","_expected_updated_at":%q}`, initial))
			if w.Code != http.StatusConflict {
				t.Fatalf("pre-cycle token accepted: %d %s", w.Code, w.Body.String())
			}
			rows, err := QueryRows(app.DB, "SELECT CAST(_valid_from AS TEXT) AS start,CAST(_valid_to AS TEXT) AS end FROM orders_history WHERE id=1 ORDER BY _version")
			if err != nil {
				t.Fatal(err)
			}
			if len(rows) != 3 {
				t.Fatalf("history=%v", rows)
			}
			for _, r := range rows {
				start, ok := parseUpdateTimestamp(fmt.Sprint(r["start"]))
				end, endOK := parseUpdateTimestamp(fmt.Sprint(r["end"]))
				if !ok || !endOK || !end.After(start) {
					t.Errorf("empty or inverted history=%v", r)
				}
			}
		})
	}
}
func TestWorkflowTransitionTimestampRollsBackWithHook(t *testing.T) {
	app, wf, sid := workflowTimestampFixture(t, "2099-01-01 00:00:00.123456789")
	app.Hooks = &HookConfig{OnUpdate: map[string][]Hook{"orders": {{SQL: "INSERT INTO missing_table(value) VALUES(1)"}}}}
	before := workflowStoredTimestamp(t, app)
	w := transitionAs(app, wf, sid, "1", "approved")
	if w.Code != http.StatusInternalServerError || workflowStoredTimestamp(t, app) != before {
		t.Fatalf("failed transition changed timestamp: %d %s", w.Code, w.Body.String())
	}
	var n int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM orders_history").Scan(&n); err != nil || n != 0 {
		t.Fatalf("rollback history=%d err=%v", n, err)
	}
}
func TestWorkflowTimeoutAdvancesTimestamp(t *testing.T) {
	app, wf, _ := workflowTimestampFixture(t, "2099-01-01 00:00:00.123456789")
	before := workflowStoredTimestamp(t, app)
	applied, err := applyWorkflowTimeout(app, wf, "1", "pending", "approved")
	if err != nil || !applied {
		t.Fatalf("timeout=%v %v", applied, err)
	}
	after := workflowStoredTimestamp(t, app)
	old, _ := parseUpdateTimestamp(before)
	next, _ := parseUpdateTimestamp(after)
	if !next.After(old) {
		t.Fatalf("timeout version regressed: %s -> %s", before, after)
	}
	applied, err = applyWorkflowTimeout(app, wf, "1", "pending", "approved")
	if err != nil || applied || workflowStoredTimestamp(t, app) != after {
		t.Fatalf("stale timeout changed version: %v %v", applied, err)
	}
	applied, err = applyWorkflowTimeout(app, wf, "999", "pending", "approved")
	if err != nil || applied {
		t.Fatalf("missing timeout=%v %v", applied, err)
	}
}
