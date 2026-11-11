//go:build !cli && !windows

package main

import (
	"context"
	"database/sql"
	"strings"
	"testing"
	"time"

	"github.com/mattn/go-sqlite3"
)

// The task fixture's schema plus two tables that only reference what the
// command writes: SQLite's foreign-key enforcement reads their key columns
// while the command inserts into activities (the revision triggers make that
// INSERT a multi-write statement, so SQLite scans the children).
const commandFKScanSchema = `CREATE TABLE members (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL, email TEXT NOT NULL, user_id INTEGER NOT NULL);
CREATE TABLE projects (id INTEGER PRIMARY KEY, org_id TEXT NOT NULL);
CREATE TABLE tasks (id INTEGER PRIMARY KEY, project_id INTEGER NOT NULL, org_id TEXT NOT NULL, title TEXT NOT NULL, status TEXT NOT NULL, completed_by INTEGER, completed_at TEXT);
CREATE TABLE activities (id INTEGER PRIMARY KEY, task_id INTEGER NOT NULL, actor_user_id INTEGER NOT NULL, actor_email TEXT NOT NULL, event TEXT NOT NULL);
CREATE TABLE attachments (id INTEGER PRIMARY KEY, activity_id INTEGER REFERENCES activities(id), note TEXT, secret TEXT);
CREATE TABLE attachment_notes (id INTEGER PRIMARY KEY, org_id TEXT, activity_ref INTEGER, note TEXT, FOREIGN KEY (activity_ref) REFERENCES Activities(id) DEFERRABLE INITIALLY DEFERRED);
CREATE TABLE unrelated (id INTEGER PRIMARY KEY, project_id INTEGER REFERENCES projects(id), note TEXT);
`

func newCommandFKScanFixture(t *testing.T, flowSource string) (*App, string, int64) {
	t.Helper()
	app, sessionID, userID := newUnenrolledCommandProviderTaskFixtureWithManifest(t, flowSource, "", func(_ *AppMCPManifest, dir string) {
		writeTestFile(t, dir, "schema.sql", commandFKScanSchema)
	})
	if _, err := updateAppMCPEpoch(app.Dir, true, false, true); err != nil {
		t.Fatalf("establish fixture owner: %v", err)
	}
	generation := snapshotAppMCPGeneration(app)
	if _, err := initializeAppMCPRevisionEnrollment(context.Background(), app, generation); err != nil {
		t.Fatalf("enroll fixture: %v", err)
	}
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), app, generation); err != nil {
		t.Fatalf("enable fixture: %v", err)
	}
	return app, sessionID, userID
}

// An approved command that inserts into a table other tables reference must
// commit: SQLite reads the children's key columns to enforce the constraint,
// and that is not a read the command makes.
func TestAppMCPCommandInsertIntoReferencedTableCommits(t *testing.T) {
	app, sessionID, _ := newCommandFKScanFixture(t, commandTaskFlowFixture)
	origin := appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}
	prepared, err := prepareCommandTask(t, app, origin)
	if err != nil {
		t.Fatalf("prepare: %v", err)
	}
	readback, err := applyCommandTask(t, app, origin, prepared)
	if err != nil {
		t.Fatalf("apply into a referenced table failed: %v", err)
	}
	if readback["status"] != "done" {
		t.Fatalf("readback: %#v", readback)
	}
	var activities int
	if err := app.DB.QueryRow(`SELECT count(*) FROM activities WHERE task_id=1`).Scan(&activities); err != nil || activities != 1 {
		t.Fatalf("activity not committed: %d %v", activities, err)
	}
}

// The admission is exactly the enforcement read: a child's key column, while
// a write statement runs. Command SQL still cannot name the child table, and
// no other column of it (or of a table referencing an unwritten parent) opens.
func TestAppMCPCommandForeignKeyScanAdmissionIsExact(t *testing.T) {
	app, sessionID, _ := newCommandFKScanFixture(t, commandTaskFlowFixture)
	generation := snapshotAppMCPGeneration(app)
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: generation, toolName: "complete_item", origin: appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessionID}, now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		reads, err := cap.foreignKeyChildScanReads(cap.effectTables())
		if err != nil {
			t.Fatalf("derive child scan reads: %v", err)
		}
		for _, want := range []string{"attachments\x00activity_id", "attachment_notes\x00activity_ref"} {
			if !reads[want] {
				t.Fatalf("child key column %q missing from %v", want, reads)
			}
		}
		for key := range reads {
			if strings.HasPrefix(key, "unrelated\x00") || strings.HasSuffix(key, "\x00note") || strings.HasSuffix(key, "\x00secret") {
				t.Fatalf("admitted a read SQLite's enforcement does not make: %q", key)
			}
		}
		guard := cap.guard
		// A write statement in apply: the child key column is admitted, its
		// other columns and an unwritten parent's children are not.
		if err := cap.enterPhase("apply", []string{"tasks"}, []string{"tasks", "activities"}, false); err != nil {
			t.Fatal(err)
		}
		cases := []struct {
			table, column string
			want          int
		}{
			{"attachments", "activity_id", sqlite3.SQLITE_OK},
			{"ATTACHMENTS", "Activity_ID", sqlite3.SQLITE_OK},
			{"attachment_notes", "activity_ref", sqlite3.SQLITE_OK},
			{"attachments", "secret", sqlite3.SQLITE_DENY},
			{"attachments", "note", sqlite3.SQLITE_DENY},
			{"attachments", "", sqlite3.SQLITE_DENY},
			{"unrelated", "project_id", sqlite3.SQLITE_DENY},
		}
		for _, tc := range cases {
			if got := guard.authorize(sqlite3.SQLITE_READ, tc.table, tc.column, "main"); got != tc.want {
				t.Errorf("write-phase read %s.%s = %d, want %d", tc.table, tc.column, got, tc.want)
			}
		}
		if got := guard.authorize(sqlite3.SQLITE_READ, "attachments", "activity_id", "temp"); got != sqlite3.SQLITE_DENY {
			t.Errorf("non-main child read admitted: %d", got)
		}
		cap.leavePhase()
		// A read-only statement (prepare, readback, or an apply SELECT) makes no
		// enforcement reads, so nothing is admitted there.
		for _, phase := range []string{"prepare", "readback", "apply"} {
			if err := cap.enterPhase(phase, []string{"tasks"}, []string{"tasks", "activities"}, true); err != nil {
				t.Fatal(err)
			}
			if got := guard.authorize(sqlite3.SQLITE_READ, "attachments", "activity_id", "main"); got != sqlite3.SQLITE_DENY {
				t.Errorf("%s read-only statement admitted a child key read", phase)
			}
			cap.leavePhase()
		}
		// Authored command SQL that names the child table is still refused by
		// the declared-table inventory, before any authorizer runs.
		leak := "INSERT INTO activities(task_id,actor_user_id,actor_email,event) SELECT t.id,1,'a@example.com',(SELECT max(activity_id) FROM attachments) FROM tasks AS t WHERE t.id=1"
		declared := append(appMCPCommandReadTables(cap.command, "apply"), cap.command.Writes...)
		if err := cap.validateSQLPhase(leak, "apply", declared); err == nil || !strings.Contains(err.Error(), "undeclared table") {
			t.Fatalf("command SQL naming an undeclared child table was not refused: %v", err)
		}
		return false, nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// SQLite's own behaviour the fix depends on: the child scan happens for a
// multi-write INSERT into a referenced table, and reads only the child's key
// column. If SQLite ever reads more, this fails before the admission widens.
func TestSQLiteForeignKeyChildScanReadsOnlyKeyColumns(t *testing.T) {
	db, err := sql.Open("sqlite3", "file:"+t.TempDir()+"/fk.db?_foreign_keys=on")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	for _, stmt := range strings.Split(strings.TrimSpace(commandFKScanSchema), "\n") {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`CREATE TRIGGER activities_ai AFTER INSERT ON activities BEGIN SELECT 1; END`); err != nil {
		t.Fatal(err)
	}
	conn, err := db.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	var reads []string
	if err := conn.Raw(func(raw any) error {
		mustSQLiteConn(raw).RegisterAuthorizer(func(action int, arg1, arg2, _ string) int {
			if action == sqlite3.SQLITE_READ {
				reads = append(reads, arg1+"."+arg2)
			}
			return sqlite3.SQLITE_OK
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), `INSERT INTO activities(task_id,actor_user_id,actor_email,event) VALUES(1,1,'a@example.com','x')`); err != nil {
		t.Fatal(err)
	}
	_ = conn.Raw(func(raw any) error { mustSQLiteConn(raw).RegisterAuthorizer(nil); return nil })
	got := map[string]bool{}
	for _, read := range reads {
		got[strings.ToLower(read)] = true
	}
	if !got["attachments.activity_id"] || !got["attachment_notes.activity_ref"] {
		t.Fatalf("expected SQLite to scan both children's key columns, saw %v", reads)
	}
	for read := range got {
		if read != "attachments.activity_id" && read != "attachment_notes.activity_ref" {
			t.Fatalf("SQLite made an enforcement read the admission does not cover: %q (all: %v)", read, reads)
		}
	}
}
