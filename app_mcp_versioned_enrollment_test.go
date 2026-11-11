//go:build !cli && !windows

package main

import (
	"context"
	"strings"
	"testing"

	"github.com/mattn/go-sqlite3"
)

const versionedCommandAppConfig = `groups: {table: members, key: org_id, user_field: email}
roles:
  editor: {scopes: [tasks:read, tasks:write]}
access:
  projects: {all: group}
  tasks: {all: group}
  activities: {all: group}
`

// newVersionedCommandFixture is the command task app with `versioned:` in
// app.yaml, so tables the command writes carry the framework's own history
// triggers. configure may add more reviewed source.
func newVersionedCommandFixture(t *testing.T, flow, hooks, versioned string, configure func(dir string)) (*App, string, int64) {
	t.Helper()
	app, sessionID, userID := newUnenrolledCommandProviderTaskFixtureWithManifest(t, flow, hooks, func(_ *AppMCPManifest, dir string) {
		writeTestFile(t, dir, "app.yaml", versionedCommandAppConfig+"versioned: "+versioned+"\n")
		if configure != nil {
			configure(dir)
		}
	})
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatal(err)
	}
	var triggers int
	if err := app.DB.QueryRow(`SELECT count(*) FROM main.sqlite_schema WHERE type='trigger' AND tbl_name='tasks' AND name IN ('_benmore_ver_tasks_update','_benmore_ver_tasks_delete')`).Scan(&triggers); err != nil || triggers != 2 {
		t.Fatalf("fixture did not install the history triggers: %d %v", triggers, err)
	}
	return app, sessionID, userID
}

func newPlainVersionedCommandFixture(t *testing.T) (*App, string, int64) {
	return newVersionedCommandFixture(t, commandTaskFlowFixture, "", "[tasks]", nil)
}

func TestAppMCPVersionedTableTakesApprovedWritesAndRecordsTheVersion(t *testing.T) {
	app, sessionID, userID := newPlainVersionedCommandFixture(t)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, snapshotAppMCPGeneration(app)); err != nil {
		t.Fatalf("a table with the framework's own history triggers was refused: %v", err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, snapshotAppMCPGeneration(app)); err != nil {
		t.Fatalf("enable writes on a versioned table: %v", err)
	}
	origin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}
	prepared, err := prepareCommandTask(t, app, origin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := applyCommandTask(t, app, origin, prepared); err != nil {
		t.Fatalf("command apply on a versioned table: %v", err)
	}
	// The version is the state the command replaced, written by the same
	// statement, and it names the user who approved the command.
	rows, err := app.DB.Query(`SELECT status, _version, _change_type, _changed_by FROM tasks_history WHERE id=1 ORDER BY _version`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	count := 0
	for rows.Next() {
		var status, changeType string
		var version int
		var changedBy any
		if err := rows.Scan(&status, &version, &changeType, &changedBy); err != nil {
			t.Fatal(err)
		}
		count++
		if status != "open" || version != 1 || changeType != "update" {
			t.Fatalf("version row = status %q version %d type %q; want the replaced state", status, version, changeType)
		}
		if got, ok := changedBy.(int64); !ok || got != userID {
			t.Fatalf("_changed_by = %v; want the command's actor %d", changedBy, userID)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("approved write recorded %d versions; want exactly 1", count)
	}
	var status string
	if err := app.DB.QueryRow(`SELECT status FROM tasks WHERE id=1`).Scan(&status); err != nil || status != "done" {
		t.Fatalf("command did not apply: %q %v", status, err)
	}
}

func TestAppMCPHistoryTriggerThatDiffersFromTheGeneratedOneStaysRefused(t *testing.T) {
	replace := func(t *testing.T, app *App, name, ddl string) {
		t.Helper()
		if _, err := app.DB.Exec(`DROP TRIGGER ` + name); err != nil {
			t.Fatal(err)
		}
		if _, err := app.DB.Exec(ddl); err != nil {
			t.Fatal(err)
		}
	}
	enroll := func(app *App) error {
		_, err := initializeAppMCPRevisionEnrollment(context.Background(), app, snapshotAppMCPGeneration(app))
		return err
	}
	t.Run("same name, different body", func(t *testing.T) {
		app, _, _ := newPlainVersionedCommandFixture(t)
		replace(t, app, "_benmore_ver_tasks_delete", `CREATE TRIGGER "_benmore_ver_tasks_delete" BEFORE DELETE ON "tasks" FOR EACH ROW BEGIN DELETE FROM members; END`)
		if err := enroll(app); err == nil || !strings.Contains(err.Error(), `unrecognized or changed trigger "_benmore_ver_tasks_delete"`) {
			t.Fatalf("a same-name trigger with another body was accepted: %v", err)
		}
	})
	t.Run("generated body with one statement added", func(t *testing.T) {
		app, _, _ := newPlainVersionedCommandFixture(t)
		var ddl string
		if err := app.DB.QueryRow(`SELECT sql FROM main.sqlite_schema WHERE name='_benmore_ver_tasks_update'`).Scan(&ddl); err != nil {
			t.Fatal(err)
		}
		tampered := strings.TrimSuffix(strings.TrimSpace(ddl), "END") + "DELETE FROM activities; END"
		if tampered == ddl {
			t.Fatal("fixture could not extend the generated trigger")
		}
		replace(t, app, "_benmore_ver_tasks_update", tampered)
		if err := enroll(app); err == nil || !strings.Contains(err.Error(), `unrecognized or changed trigger "_benmore_ver_tasks_update"`) {
			t.Fatalf("an extended history trigger was accepted: %v", err)
		}
	})
	t.Run("history prefix on a table that is not versioned", func(t *testing.T) {
		app, _, _ := newPlainVersionedCommandFixture(t)
		if _, err := app.DB.Exec(`CREATE TRIGGER "_benmore_ver_activities_delete" BEFORE DELETE ON "activities" FOR EACH ROW BEGIN DELETE FROM members; END`); err != nil {
			t.Fatal(err)
		}
		if err := enroll(app); err == nil || !strings.Contains(err.Error(), `unrecognized or changed trigger "_benmore_ver_activities_delete"`) {
			t.Fatalf("a history-named trigger on an unversioned table was accepted: %v", err)
		}
	})
	t.Run("trigger on the history table", func(t *testing.T) {
		app, _, _ := newPlainVersionedCommandFixture(t)
		if _, err := app.DB.Exec(`CREATE TRIGGER history_side_effect AFTER INSERT ON "tasks_history" FOR EACH ROW BEGIN DELETE FROM members; END`); err != nil {
			t.Fatal(err)
		}
		if err := enroll(app); err == nil || !strings.Contains(err.Error(), "tasks_history") {
			t.Fatalf("a trigger on the history table was accepted: %v", err)
		}
	})
}

// An encrypted column makes the history triggers call the benmore_history_*
// functions, and an on_update hook writes a second versioned table from the
// hook-write scope: both have to pass the command connection's authorizer.
func TestAppMCPVersionedEncryptedTableAndHookWriteRecordVersions(t *testing.T) {
	hooks := "on_update:\n  tasks:\n    - sql: UPDATE projects SET org_id = org_id WHERE id = {{project_id}}\n"
	app, sessionID, userID := newVersionedCommandFixture(t, commandTaskFlowFixture, hooks, "[tasks, projects]", func(dir string) {
		writeTestFile(t, dir, "encrypted.yaml", "tables:\n  tasks:\n    fields:\n      - title\n")
	})
	var ddl string
	if err := app.DB.QueryRow(`SELECT sql FROM main.sqlite_schema WHERE name='_benmore_ver_tasks_update'`).Scan(&ddl); err != nil || !strings.Contains(ddl, "benmore_history_encrypt(") || !strings.Contains(ddl, "benmore_history_normalized(") {
		t.Fatalf("fixture history trigger does not seal the encrypted column: %q %v", ddl, err)
	}
	generation := snapshotAppMCPGeneration(app)
	enrollment, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation)
	if err != nil {
		t.Fatalf("versioned tables with an encrypted column were refused: %v", err)
	}
	for _, name := range enrollment.TableNames {
		if strings.HasSuffix(name, "_history") {
			t.Fatalf("a history table joined the revision universe: %v", enrollment.TableNames)
		}
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
		t.Fatal(err)
	}
	if n := hookCount(t, app, `SELECT count(*) FROM tasks_history`) + hookCount(t, app, `SELECT count(*) FROM projects_history`); n != 0 {
		t.Fatalf("fixture seeding recorded %d versions", n)
	}
	if _, err := runHookedCommand(t, app, sessionID); err != nil {
		t.Fatalf("command on versioned tables with a hook: %v", err)
	}
	var title, status string
	var changedBy int64
	if err := app.DB.QueryRow(`SELECT title, status, _changed_by FROM tasks_history WHERE id=1 AND _version=1 AND _change_type='update'`).Scan(&title, &status, &changedBy); err != nil {
		t.Fatalf("the command's update recorded no version: %v", err)
	}
	if !strings.HasPrefix(title, "enc:") || status != "open" || changedBy != userID {
		t.Fatalf("task version = title %q status %q changed_by %d; want the sealed replaced row by actor %d", title, status, changedBy, userID)
	}
	if n := hookCount(t, app, `SELECT count(*) FROM tasks_history`); n != 1 {
		t.Fatalf("one command update recorded %d task versions", n)
	}
	// The hook's write is part of the approved command too.
	if n := hookCount(t, app, `SELECT count(*) FROM projects_history WHERE id=7 AND _change_type='update' AND _changed_by=?`, userID); n != 1 {
		t.Fatalf("the hook's update of a versioned table recorded %d attributed versions; want 1", n)
	}
}

// The native update tool goes through the generic CRUD update, which names
// its actor itself. Its fixture table has an encrypted field, a computed
// field and updated_at, so this also pins the generated text for all three.
func TestAppMCPNativeUpdateOnVersionedTableRecordsTheVersion(t *testing.T) {
	canonicalUpdateFixtureAppConfig = "versioned: [notes]\n"
	t.Cleanup(func() { canonicalUpdateFixtureAppConfig = "" })
	f := newCanonicalUpdateFixture(t, "", "", "")
	projected, _, err := applyAppMCPCanonicalUpdate(context.Background(), f.pin, "notes_update_title", canonicalTitleUpdate("after"), f.now)
	if err != nil || projected["title"] != "after" {
		t.Fatalf("native update on a versioned table: %v %v", projected, err)
	}
	if n := hookCount(t, f.app, `SELECT count(*) FROM notes_history WHERE id=1 AND title='before' AND _change_type='update' AND _changed_by=?`, f.uid); n != 1 {
		t.Fatalf("native update recorded %d attributed versions of the replaced row; want 1", n)
	}
}

func TestAppMCPCommandGuardAdmitsOnlyWhatAHistoryTriggerDoes(t *testing.T) {
	history := map[string]bool{"tasks_history": true}
	ok := func(code int) bool { return code == sqlite3.SQLITE_OK }
	apply := &appMCPCommandExecution{phase: "apply", allowedWrites: map[string]bool{"tasks": true}, verifiedHistoryWrites: history}
	if !ok(apply.authorize(sqlite3.SQLITE_INSERT, "tasks_history", "", "main")) || !ok(apply.authorize(sqlite3.SQLITE_READ, "Tasks_History", "_version", "main")) ||
		!ok(apply.authorize(sqlite3.SQLITE_FUNCTION, "", "benmore_history_start", "")) {
		t.Fatal("apply refused what a verified history trigger does")
	}
	for name, code := range map[string]int{
		"update a version":          apply.authorize(sqlite3.SQLITE_UPDATE, "tasks_history", "status", "main"),
		"delete a version":          apply.authorize(sqlite3.SQLITE_DELETE, "tasks_history", "", "main"),
		"another history table":     apply.authorize(sqlite3.SQLITE_INSERT, "projects_history", "", "main"),
		"history in another schema": apply.authorize(sqlite3.SQLITE_INSERT, "tasks_history", "", "temp"),
	} {
		if ok(code) {
			t.Errorf("apply allowed: %s", name)
		}
	}
	for _, exec := range []*appMCPCommandExecution{
		{phase: "apply", allowedWrites: map[string]bool{"tasks": true}},
		{phase: "readback", allowedReads: map[string]bool{"tasks": true}, verifiedHistoryWrites: history},
		{phase: "apply", internal: true, verifiedHistoryWrites: history},
	} {
		if ok(exec.authorize(sqlite3.SQLITE_FUNCTION, "", "benmore_history_normalized", "")) || ok(exec.authorize(sqlite3.SQLITE_INSERT, "tasks_history", "", "main")) {
			t.Errorf("history access outside an apply write on a versioned table: phase %q internal %v", exec.phase, exec.internal)
		}
	}
	// Command SQL may not call the trigger's functions by name.
	if name := commandTriggerOnlyCall(`UPDATE tasks SET title = benmore_history_encrypt(title, 'tasks', 'title') WHERE id = :id`); name != "benmore_history_encrypt" {
		t.Errorf("authored call of a history function was not refused: %q", name)
	}
	if commandVerifiedTriggerFunction("benmore_history_normalized") {
		t.Error("a history function was admitted to app-authored triggers")
	}
	hookWrite := appMCPCommandAuthorizerPolicy{metadataOp: appMCPCommandMetadataHookWrite, verifiedHistoryWrites: history}
	hookRead := appMCPCommandAuthorizerPolicy{metadataOp: appMCPCommandMetadataHookRead, verifiedHistoryWrites: history}
	if !ok(authorizeCommandHook(hookWrite, sqlite3.SQLITE_INSERT, "tasks_history", "", "main")) {
		t.Error("hook-write scope refused a verified history trigger's insert")
	}
	if ok(authorizeCommandHook(hookWrite, sqlite3.SQLITE_UPDATE, "tasks_history", "status", "main")) || ok(authorizeCommandHook(hookWrite, sqlite3.SQLITE_DELETE, "tasks_history", "", "main")) ||
		ok(authorizeCommandHook(hookRead, sqlite3.SQLITE_INSERT, "tasks_history", "", "main")) {
		t.Error("a hook scope may rewrite or delete a version")
	}
	actor := &appMCPCommandExecution{metadataOp: appMCPCommandMetadataVersionActor, verifiedHistoryWrites: history}
	if !ok(actor.authorize(sqlite3.SQLITE_UPDATE, "tasks_history", "_changed_by", "main")) || !ok(actor.authorize(sqlite3.SQLITE_READ, "tasks_history", "_changed_by", "main")) {
		t.Fatal("attribution scope refused its own statement")
	}
	for name, code := range map[string]int{
		"another history column": actor.authorize(sqlite3.SQLITE_UPDATE, "tasks_history", "status", "main"),
		"an app table":           actor.authorize(sqlite3.SQLITE_UPDATE, "tasks", "_changed_by", "main"),
		"an unverified history":  actor.authorize(sqlite3.SQLITE_UPDATE, "projects_history", "_changed_by", "main"),
		"insert":                 actor.authorize(sqlite3.SQLITE_INSERT, "tasks_history", "", "main"),
		"delete":                 actor.authorize(sqlite3.SQLITE_DELETE, "tasks_history", "", "main"),
		"read an app table":      actor.authorize(sqlite3.SQLITE_READ, "tasks", "status", "main"),
		"a function":             actor.authorize(sqlite3.SQLITE_FUNCTION, "", "benmore_history_encrypt", ""),
	} {
		if ok(code) {
			t.Errorf("attribution scope allowed: %s", name)
		}
	}
}

// A custom field added to a versioned table creates its history triggers
// again. On an enrolled table they must not end up ahead of the revision
// triggers, or the enrollment is refused until the next reload.
func TestVersioningRefreshOfOneTableKeepsRevisionTriggersFirst(t *testing.T) {
	app, _, _ := newPlainVersionedCommandFixture(t)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, snapshotAppMCPGeneration(app)); err != nil {
		t.Fatal(err)
	}
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if _, err := tx.Exec(`ALTER TABLE tasks ADD COLUMN note TEXT`); err != nil {
		t.Fatal(err)
	}
	if err := installVersioningForTableTx(tx, "tasks", app.Encrypted, app.computedConfig(), nil); err != nil {
		t.Fatal(err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if table, err := appMCPRevisionTriggerOrderProblem(app.DB, []string{"tasks"}); err != nil || table != "" {
		t.Fatalf("history triggers fire before the revision triggers on %q (%v)", table, err)
	}
	var ddl string
	if err := app.DB.QueryRow(`SELECT sql FROM main.sqlite_schema WHERE name='_benmore_ver_tasks_update'`).Scan(&ddl); err != nil || !strings.Contains(ddl, `"note"`) {
		t.Fatalf("history trigger was not rebuilt for the new column: %q %v", ddl, err)
	}
}
