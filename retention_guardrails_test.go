//go:build !cli && !windows

package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

// retention.yaml may name only the app's own tables, and only with the keys
// the framework reads. These tests load a real app from source files, the way
// a deployed app carries a file the write gate never saw.

const retentionGuardSchema = `model Event {
  id        Int       @id @default(autoincrement())
  title     String
  createdAt DateTime  @default(now()) @map("created_at")
  updatedAt DateTime  @default(now()) @updatedAt @map("updated_at")
  deletedAt DateTime? @map("deleted_at")
}

model Note {
  id        Int      @id @default(autoincrement())
  title     String
  createdAt DateTime @default(now()) @map("created_at")
}
`

// retentionGuardApp loads an app with events and notes tables and the given
// retention.yaml and app.yaml, and returns it with everything the load logged.
func retentionGuardApp(t *testing.T, appYAML, retentionYAML string) (*App, *bytes.Buffer) {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", appYAML)
	writeTestFile(t, dir, "schema.prisma", retentionGuardSchema)
	if retentionYAML != "" {
		writeTestFile(t, dir, "retention.yaml", retentionYAML)
	}
	logs := guardCaptureLog(t)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	t.Cleanup(app.Shutdown)
	if err := EnsureUsersTable(app.DB); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(app.DB)
	EnsureAuditLogTable(app.DB)
	EnsureJobsTable(app.DB)
	return app, logs
}

// guardCaptureLog collects the standard logger's output for the test.
func guardCaptureLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var buf bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&buf)
	t.Cleanup(func() { log.SetOutput(previous) })
	return &buf
}

func guardCount(t *testing.T, db *sql.DB, query string, args ...any) int {
	t.Helper()
	var n int
	if err := db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

// seedAgedFrameworkRows writes an account, a session, an audit row and a
// finished job that are all three days old.
func seedAgedFrameworkRows(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, q := range []string{
		`INSERT INTO _benmore_users (username, email, password_hash, role, created_at) VALUES ('old', 'old@retention.test', 'x', 'user', datetime('now', '-3 days'))`,
		`INSERT INTO _benmore_sessions (id, user_id, email, created_at, expires_at) VALUES ('sha256:aged', 1, 'old@retention.test', datetime('now', '-3 days'), datetime('now', '+30 days'))`,
		`INSERT INTO _benmore_audit_log (action, table_name, row_id, user_email, created_at) VALUES ('update', 'events', '1', 'old@retention.test', datetime('now', '-3 days'))`,
		`INSERT INTO _benmore_jobs (job_type, payload, status, created_at) VALUES ('hook', '{}', 'pending', datetime('now', '-3 days'))`,
	} {
		mustExec(t, db, q)
	}
}

const retentionFrameworkTablesYAML = `policies:
  - table: events
    ttl: "1d"
  - table: _benmore_users
    ttl: "1d"
  - table: _benmore_audit_log
    ttl: "1d"
  - table: _benmore_sessions
    ttl: "1d"
  - table: _benmore_jobs
    ttl: "1d"
`

// A deployed retention.yaml that names framework tables deletes nothing from
// them: not the account, not its session, not audit history, not queued jobs.
// The app-table policy next to it keeps working. It deleted the three-day-old
// account and the audit row (compliance: hipaa included for the account).
func TestRetentionPolicyOnFrameworkTablesDeletesNothing(t *testing.T) {
	for name, appYAML := range map[string]string{
		"plain": "auth:\n  identifier: email\n",
		"hipaa": "compliance: hipaa\nauth:\n  identifier: email\n",
	} {
		t.Run(name, func(t *testing.T) {
			app, logs := retentionGuardApp(t, appYAML, retentionFrameworkTablesYAML)
			// A served hipaa app has the append-only audit triggers.
			if err := ensureAuditAppendOnly(app); err != nil {
				t.Fatal(err)
			}
			logRetentionProblemsForTest(app)
			seedAgedFrameworkRows(t, app.DB)
			mustExec(t, app.DB, `INSERT INTO events (title, created_at) VALUES ('expired', datetime('now', '-3 days')), ('fresh', datetime('now'))`)
			auditBefore := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'update'`)

			RunRetentionNow(app)

			if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_users WHERE email = 'old@retention.test'`); n != 1 {
				t.Errorf("the account was deleted by a retention policy (rows left: %d)", n)
			}
			if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_sessions WHERE id = 'sha256:aged'`); n != 1 {
				t.Errorf("the session was deleted by a retention policy (rows left: %d)", n)
			}
			if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'update'`); n != auditBefore {
				t.Errorf("audit history was deleted by a retention policy (%d rows before, %d after)", auditBefore, n)
			}
			if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_jobs`); n != 1 {
				t.Errorf("the queued job was deleted by a retention policy (rows left: %d)", n)
			}
			// The app's own table is still swept, and only its expired row.
			if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM events WHERE title = 'expired'`); n != 0 {
				t.Errorf("the expired event must be deleted (rows left: %d)", n)
			}
			if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM events WHERE title = 'fresh'`); n != 1 {
				t.Errorf("the fresh event must stay (rows: %d)", n)
			}
			if got := app.retentionConfig(); len(got) != 1 || got[0].Table != "events" {
				t.Errorf("only the events policy may load, got %+v", got)
			}
			if !strings.Contains(logs.String(), "_benmore_users") {
				t.Errorf("the load must log the refused policy; log:\n%s", logs.String())
			}
		})
	}
}

// The sweep itself refuses a framework table, whatever handed it the policy.
func TestRetentionSweepRefusesFrameworkTablesAtRunTime(t *testing.T) {
	app, logs := retentionGuardApp(t, "auth:\n  identifier: email\n", "")
	seedAgedFrameworkRows(t, app.DB)
	mustExec(t, app.DB, `INSERT INTO events (title, created_at) VALUES ('expired', datetime('now', '-3 days'))`)
	policies := []RetentionPolicy{
		{Table: "_benmore_users", Column: "created_at", TTL: time.Hour},
		{Table: "_BENMORE_USERS", Column: "created_at", TTL: time.Hour},
		{Table: "_benmore_audit_log", Column: "created_at", TTL: time.Hour},
		{Table: "_benmore_sessions", Column: "created_at", TTL: time.Hour},
		{Table: "sqlite_sequence", Column: "seq", TTL: time.Hour},
		{Table: "events", Column: "created_at", TTL: time.Hour},
	}
	enforceRetentionAt(app.DB, policies, time.Now())
	for table, want := range map[string]int{"_benmore_users": 1, "_benmore_sessions": 1, "_benmore_jobs": 1, "events": 0} {
		if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM `+table); n != want {
			t.Errorf("%s: %d rows after the sweep, want %d", table, n, want)
		}
	}
	if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'update'`); n != 1 {
		t.Errorf("audit history: %d rows after the sweep, want 1", n)
	}
	if !strings.Contains(logs.String(), "_benmore_users") || !strings.Contains(strings.ToLower(logs.String()), "not one of the app's own tables") {
		t.Errorf("the refusal must be logged, naming the table; log:\n%s", logs.String())
	}
}

// The write gate (write_file, push, deploy, `benmore check`) refuses a policy
// on a framework table. It accepted the file.
func TestRetentionWriteGateRefusesFrameworkTables(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "auth:\n  identifier: email\n")
	writeTestFile(t, dir, "schema.prisma", retentionGuardSchema)
	for _, table := range []string{"_benmore_users", "_benmore_audit_log", "_benmore_sessions", "_Benmore_Users", "sqlite_sequence", "sqlite_master"} {
		msg := ValidateOnWriteIn(dir, "retention.yaml", "policies:\n  - table: "+table+"\n    ttl: \"30d\"\n")
		if !strings.Contains(msg, table) || !strings.Contains(msg, "only the app's own tables") {
			t.Errorf("%s: the gate must refuse a framework table and say why, got %q", table, msg)
		}
	}
	if msg := ValidateOnWriteIn(dir, "retention.yaml", "policies:\n  - table: events\n    ttl: \"30d\"\n  - table: notes\n    ttl: \"1y\"\n    column: created_at\n"); msg != "" {
		t.Errorf("a policy on the app's own tables must pass, got %q", msg)
	}
	// `benmore check` reads the file from disk through the same gate.
	writeTestFile(t, dir, "retention.yaml", "policies:\n  - table: _benmore_users\n    ttl: \"30d\"\n")
	found := false
	for _, f := range RunSourceCheck(dir, "").Findings {
		if f.Severity == "error" && f.File == "retention.yaml" && strings.Contains(f.Message, "_benmore_users") {
			found = true
		}
	}
	if !found {
		t.Error("benmore check must report the framework table as an error on retention.yaml")
	}
}

// An unknown key in a policy (col: for column:) made the policy fall back to
// created_at and delete by it. The policy does not run, the load says so, and
// the write gate refuses the file naming the key.
func TestRetentionUnknownKeyNeverFallsBackToAnotherColumn(t *testing.T) {
	doc := "policies:\n  - table: events\n    ttl: \"1d\"\n    col: updated_at\n  - table: notes\n    ttl: \"1d\"\n"
	app, logs := retentionGuardApp(t, "auth:\n  identifier: email\n", doc)
	// Created three days ago, touched just now: a policy on updated_at keeps it.
	mustExec(t, app.DB, `INSERT INTO events (title, created_at, updated_at) VALUES ('old-but-touched', datetime('now', '-3 days'), datetime('now'))`)
	mustExec(t, app.DB, `INSERT INTO notes (title, created_at) VALUES ('expired', datetime('now', '-3 days'))`)
	logRetentionProblemsForTest(app)
	RunRetentionNow(app)
	if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM events`); n != 1 {
		t.Fatalf("a policy with an unknown key must not delete by created_at (events left: %d)", n)
	}
	// The well-formed policy beside it still runs.
	if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM notes`); n != 0 {
		t.Errorf("the notes policy must still run (notes left: %d)", n)
	}
	if !strings.Contains(logs.String(), `"col"`) || !strings.Contains(logs.String(), "events") {
		t.Errorf("the load must log the skipped policy and its unknown key; log:\n%s", logs.String())
	}
	msg := ValidateOnWriteIn(app.Dir, "retention.yaml", doc)
	if !strings.Contains(msg, `"col"`) || !strings.Contains(msg, "column") {
		t.Errorf("the gate must refuse the unknown key and name the keys a policy takes, got %q", msg)
	}
}

// A policy whose column the table lacks logged an error and still purged the
// table's soft-deleted rows. It does not run at all, and the gate refuses it.
func TestRetentionPolicyOnMissingColumnDoesNotRun(t *testing.T) {
	doc := "policies:\n  - table: events\n    ttl: \"1d\"\n    column: expires_at\n"
	app, logs := retentionGuardApp(t, "auth:\n  identifier: email\n", doc)
	mustExec(t, app.DB, `INSERT INTO events (title, created_at, deleted_at) VALUES ('trashed-long-ago', datetime('now', '-9 days'), datetime('now', '-3 days'))`)
	RunRetentionNow(app)
	if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM events`); n != 1 {
		t.Fatalf("a policy on a column the table lacks must delete nothing (events left: %d)", n)
	}
	if !strings.Contains(logs.String(), "expires_at") {
		t.Errorf("the skipped policy must be logged with its column; log:\n%s", logs.String())
	}
	msg := ValidateOnWriteIn(app.Dir, "retention.yaml", doc)
	if !strings.Contains(msg, "expires_at") || !strings.Contains(msg, "no column") {
		t.Errorf("the gate must refuse a column the table lacks, got %q", msg)
	}
	// A table the app does not have is refused the same way.
	msg = ValidateOnWriteIn(app.Dir, "retention.yaml", "policies:\n  - table: evnts\n    ttl: \"1d\"\n")
	if !strings.Contains(msg, "evnts") || !strings.Contains(msg, "not a table of this app") {
		t.Errorf("the gate must refuse a table the app does not have, got %q", msg)
	}
}

// The write gate and the load read a ttl with one parser: what the load
// refuses the gate refuses, with the load's own message, and what the load
// accepts the gate accepts. The gate accepted "2w", 30 and "0d".
func TestRetentionGateAndLoadAgreeOnEveryDocument(t *testing.T) {
	cases := map[string]string{
		"ttl 2w":              "policies:\n  - table: events\n    ttl: \"2w\"\n",
		"ttl bare number":     "policies:\n  - table: events\n    ttl: 30\n",
		"ttl zero":            "policies:\n  - table: events\n    ttl: \"0d\"\n",
		"ttl negative":        "policies:\n  - table: events\n    ttl: \"-5d\"\n",
		"ttl missing":         "policies:\n  - table: events\n",
		"table missing":       "policies:\n  - ttl: \"30d\"\n",
		"table not a name":    "policies:\n  - table: \"events; DROP TABLE notes\"\n    ttl: \"30d\"\n",
		"column not a name":   "policies:\n  - table: events\n    ttl: \"30d\"\n    column: \"created_at) OR (1=1\"\n",
		"policies not a list": "policies:\n  events: \"30d\"\n",
		"policy not a map":    "policies:\n  - events\n",
		"two documents":       "policies: []\n---\npolicies: []\n",
		"days":                "policies:\n  - table: events\n    ttl: \"90d\"\n",
		"years":               "policies:\n  - table: events\n    ttl: \"1y\"\n",
		"go duration":         "policies:\n  - table: events\n    ttl: \"36h\"\n",
		"unquoted":            "policies:\n  - table: events\n    ttl: 90d\n    column: updated_at\n",
		"empty list":          "policies: []\n",
		"empty file":          "",
		"only a comment":      "# no policies yet\n",
	}
	for name, doc := range cases {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "app.yaml", "auth:\n  identifier: email\n")
			writeTestFile(t, dir, "schema.prisma", retentionGuardSchema)
			writeTestFile(t, dir, "retention.yaml", doc)
			_, loadErr := loadRuntimeConfig(dir)
			gate := ValidateOnWriteIn(dir, "retention.yaml", doc)
			if (loadErr != nil) != (gate != "") {
				t.Fatalf("load error %v, gate %q: the gate must refuse exactly what the load refuses", loadErr, gate)
			}
			if loadErr != nil && !strings.Contains(gate, loadErr.Error()) {
				t.Errorf("the gate must give the load's message %q, got %q", loadErr, gate)
			}
		})
	}
}

// app.yaml's inline `retention:` was refused by the write gate and still run
// by the runtime. Neither accepts it now: nothing is deleted, the load says
// where policies go, and the gate's refusal names retention.yaml.
func TestInlineRetentionInAppYAMLIsNotRun(t *testing.T) {
	appYAML := "auth:\n  identifier: email\nretention:\n  events: \"1d\"\n  notes: {ttl: \"1d\", column: created_at}\n"
	app, logs := retentionGuardApp(t, appYAML, "")
	mustExec(t, app.DB, `INSERT INTO events (title, created_at) VALUES ('expired', datetime('now', '-3 days'))`)
	mustExec(t, app.DB, `INSERT INTO notes (title, created_at) VALUES ('expired', datetime('now', '-3 days'))`)
	logRetentionProblemsForTest(app)
	RunRetentionNow(app)
	if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM events`) + guardCount(t, app.DB, `SELECT COUNT(*) FROM notes`); n != 2 {
		t.Fatalf("inline retention: must not run (rows left: %d of 2)", n)
	}
	if got := LoadRetentionConfig(app.Dir); len(got) != 0 {
		t.Errorf("the loader must read no policy from app.yaml, got %+v", got)
	}
	if !strings.Contains(logs.String(), "retention.yaml") || !strings.Contains(logs.String(), "app.yaml") {
		t.Errorf("the load must say that app.yaml retention: is not read; log:\n%s", logs.String())
	}
	msg := ValidateOnWriteIn(app.Dir, "app.yaml", appYAML)
	if !strings.Contains(msg, "retention") || !strings.Contains(msg, "retention.yaml") {
		t.Errorf("the gate must refuse inline retention: and point at retention.yaml, got %q", msg)
	}
}

// The three table-keyed forms the fleet's retention.yaml files have. Each is
// read as no policy and has never deleted a row.
var retentionLegacyForms = map[string]struct {
	doc  string
	want []RetentionPolicy
}{
	"one table": {
		doc:  "# keep the delivery log 90 days\nevents:\n  ttl: 90d\n  column: created_at\n",
		want: []RetentionPolicy{{Table: "events", TTL: 90 * 24 * time.Hour, Column: "created_at"}},
	},
	"several tables": {
		doc:  "notes:\n  ttl: 2190d\n\nevents:\n  ttl: \"30d\"\n  column: updated_at\n",
		want: []RetentionPolicy{{Table: "notes", TTL: 2190 * 24 * time.Hour, Column: "created_at"}, {Table: "events", TTL: 30 * 24 * time.Hour, Column: "updated_at"}},
	},
	"tables key with ttl_days": {
		doc:  "tables:\n  events:\n    ttl_days: 90\n    timestamp_column: updated_at\n  notes:\n    ttl_days: 180\n    timestamp_column: created_at\n",
		want: []RetentionPolicy{{Table: "events", TTL: 90 * 24 * time.Hour, Column: "updated_at"}, {Table: "notes", TTL: 180 * 24 * time.Hour, Column: "created_at"}},
	},
}

// seedRetentionLegacyRows writes, for events and notes, one row older than
// every ttl above and one fresh row.
func seedRetentionLegacyRows(t *testing.T, db *sql.DB) {
	t.Helper()
	mustExec(t, db, `INSERT INTO events (title, created_at, updated_at) VALUES ('ancient', datetime('now', '-9 years'), datetime('now', '-9 years')), ('fresh', datetime('now'), datetime('now'))`)
	mustExec(t, db, `INSERT INTO notes (title, created_at) VALUES ('ancient', datetime('now', '-9 years')), ('fresh', datetime('now'))`)
}

// A table-keyed retention.yaml is not refused: the gate accepts the write (so
// a push or deploy of an app that carries one goes through), `benmore check`
// and the post-write check carry a warning that says the file has never run
// and prints it as a policies: list, and the app keeps deleting nothing.
func TestRetentionTableKeyedFormWarnsAndPrintsTheCorrectedFile(t *testing.T) {
	for name, form := range retentionLegacyForms {
		t.Run(name, func(t *testing.T) {
			app, logs := retentionGuardApp(t, "auth:\n  identifier: email\n", form.doc)
			seedRetentionLegacyRows(t, app.DB)

			// The write gate, alone and as a deploy's batch write.
			if msg := ValidateOnWriteIn(app.Dir, "retention.yaml", form.doc); msg != "" {
				t.Fatalf("the gate must not refuse the table-keyed form, got %q", msg)
			}
			if msg, _ := ValidateOnWriteInBatch(app.Dir, "retention.yaml", form.doc, true, []string{"app.yaml"}); msg != "" {
				t.Fatalf("a deploy's write of the file must not be refused, got %q", msg)
			}
			// `benmore check`, the check after a write of the file and
			// `benmore test`'s source check: a warning, no error.
			for _, written := range []string{"", "retention.yaml", "app.yaml"} {
				report := RunSourceCheck(app.Dir, written)
				if report.Errors != 0 {
					t.Fatalf("check after a write of %q has errors: %+v", written, report.Findings)
				}
				warned := false
				for _, f := range report.Findings {
					if f.File == "retention.yaml" && f.Severity == "warning" && strings.Contains(f.Message, "no policy is running") &&
						strings.Contains(f.Message, "has never run and nothing has been deleted") && strings.Contains(f.Message, "policies:\n  - table: ") {
						warned = true
					}
				}
				if !warned {
					t.Fatalf("check after a write of %q must warn with the corrected file: %+v", written, report.Findings)
				}
			}
			if failed := sourceCheckTestResults(app.Dir); len(failed) != 0 {
				t.Fatalf("benmore test must not fail its source check: %+v", failed)
			}

			// The deployed file keeps deleting nothing, and the load says so once.
			logRetentionProblemsForTest(app)
			logRetentionProblemsForTest(app)
			RunRetentionNow(app)
			if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM events`) + guardCount(t, app.DB, `SELECT COUNT(*) FROM notes`); n != 4 {
				t.Fatalf("the table-keyed file must keep deleting nothing (rows left: %d of 4)", n)
			}
			if n := strings.Count(logs.String(), "RETENTION NOT RUNNING: retention.yaml: no policy is running"); n != 1 {
				t.Errorf("the load must log the warning once, logged %d times:\n%s", n, logs.String())
			}

			// The printed file is the one the loader accepts, with the
			// author's tables, ttl and column.
			doc, err := parseRetentionDocument([]byte(form.doc))
			if err != nil || doc.Legacy == nil || len(doc.Policies) != 0 || len(doc.Problems) != 0 {
				t.Fatalf("the form must be read as the table-keyed form and no policy: %+v (%v)", doc, err)
			}
			corrected := doc.Legacy.correctedFile()
			if !strings.Contains(retentionLegacyWarning(app.Dir, form.doc), corrected) {
				t.Fatalf("the warning must print the corrected file:\n%s", corrected)
			}
			fixed, err := parseRetentionDocument([]byte(corrected))
			if err != nil || len(fixed.Problems) != 0 || fixed.Legacy != nil || !reflect.DeepEqual(fixed.Policies, form.want) {
				t.Fatalf("the corrected file must load as %+v, got %+v (%v) from:\n%s", form.want, fixed, err, corrected)
			}
			if msg := ValidateOnWriteIn(app.Dir, "retention.yaml", corrected); msg != "" {
				t.Fatalf("the corrected file must pass the gate, got %q", msg)
			}

			// Pasted in, it deletes exactly the rows the author meant.
			writeTestFile(t, app.Dir, "retention.yaml", corrected)
			RunRetentionNow(app)
			for _, p := range form.want {
				if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM `+p.Table+` WHERE title = 'ancient'`); n != 0 {
					t.Errorf("the corrected file must delete the expired row of %s (left: %d)", p.Table, n)
				}
				if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM `+p.Table+` WHERE title = 'fresh'`); n != 1 {
					t.Errorf("the corrected file must keep the fresh row of %s (rows: %d)", p.Table, n)
				}
			}
			named := map[string]bool{}
			for _, p := range form.want {
				named[p.Table] = true
			}
			for _, table := range []string{"events", "notes"} {
				if !named[table] && guardCount(t, app.DB, `SELECT COUNT(*) FROM `+table) != 2 {
					t.Errorf("%s is not in the file and must keep both rows", table)
				}
			}
		})
	}
}

// Only a file that converts cleanly is the table-keyed form. Everything else
// that is not a policies: list is still refused.
func TestRetentionShapesThatAreStillRefused(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "auth:\n  identifier: email\n")
	writeTestFile(t, dir, "schema.prisma", retentionGuardSchema)
	for name, tc := range map[string]struct{ doc, want string }{
		"framework table at the top level":  {"_benmore_users:\n  ttl: 30d\n", `"_benmore_users"`},
		"framework table under tables":      {"tables:\n  _benmore_audit_log:\n    ttl_days: 30\n", `"tables"`},
		"entry with a key it does not take": {"events:\n  ttl: 30d\n  col: updated_at\n", `"events"`},
		"entry with an unreadable ttl":      {"events:\n  ttl: 2w\n", `"events"`},
		"entry with ttl and ttl_days":       {"events:\n  ttl: 30d\n  ttl_days: 30\n", `"events"`},
		"entry without a ttl":               {"events:\n  column: created_at\n", `"events"`},
		"one good entry and one bad":        {"events:\n  ttl: 30d\nnotes:\n  ttl: soon\n", `"notes"`},
		"policies beside a table":           {"policies:\n  - table: events\n    ttl: 30d\nnotes:\n  ttl: 30d\n", `"notes"`},
		"a test file's shape":               {"sweep_deletes_rows:\n  steps:\n    - flush: retention\n", `"sweep_deletes_rows"`},
		"policy on a framework table":       {"policies:\n  - table: _benmore_users\n    ttl: 30d\n", "only the app's own tables"},
		"policy with an unknown key":        {"policies:\n  - table: events\n    ttl: 30d\n    col: updated_at\n", `"col"`},
		"policy on a missing column":        {"policies:\n  - table: events\n    ttl: 30d\n    column: expires_at\n", "no column"},
		"policy with an unreadable ttl":     {"policies:\n  - table: events\n    ttl: 2w\n", "positive ttl"},
	} {
		msg := ValidateOnWriteIn(dir, "retention.yaml", tc.doc)
		if !strings.Contains(msg, tc.want) {
			t.Errorf("%s: the gate must still refuse it naming %s, got %q", name, tc.want, msg)
		}
		if retentionLegacyWarning(dir, tc.doc) != "" {
			t.Errorf("%s: must not be read as the table-keyed form", name)
		}
	}
}

// The admin health report says which retention policies run. An app whose
// retention.yaml is keyed by table name is listed with "no policy is running".
func TestHealthReportListsRetentionThatIsNotRunning(t *testing.T) {
	retentionCheck := func(t *testing.T, retentionYAML string) map[string]any {
		t.Helper()
		app, _ := retentionGuardApp(t, "auth:\n  identifier: email\n", retentionYAML)
		sid := seedAdminSession(t, app)
		mux := http.NewServeMux()
		mux.HandleFunc("GET /health", healthHandler(app))
		req := httptest.NewRequest(http.MethodGet, "/health", nil)
		req.Header.Set("Authorization", "Bearer "+sid)
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var body struct {
			Status string         `json:"status"`
			Checks map[string]any `json:"checks"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil || rec.Code != http.StatusOK || body.Status != "healthy" {
			t.Fatalf("health: %d %s (%v)", rec.Code, rec.Body.String(), err)
		}
		check, _ := body.Checks["retention"].(map[string]any)
		return check
	}
	legacy := retentionCheck(t, "events:\n  ttl: 90d\n  column: created_at\n")
	if legacy["status"] != "not_running" || legacy["note"] != "retention.yaml: no policy is running" || legacy["policies_running"] != float64(0) {
		t.Errorf("a table-keyed file must be listed as not running, got %v", legacy)
	}
	if detail, _ := legacy["detail"].(string); !strings.Contains(detail, "policies:\n  - table: events") {
		t.Errorf("the report must carry the corrected file, got %v", legacy["detail"])
	}
	running := retentionCheck(t, "policies:\n  - table: events\n    ttl: 90d\n")
	if running["status"] != "ok" || running["policies_running"] != float64(1) || running["note"] != nil {
		t.Errorf("a file whose policy runs must be listed ok, got %v", running)
	}
	partly := retentionCheck(t, "policies:\n  - table: events\n    ttl: 90d\n  - table: _benmore_users\n    ttl: 90d\n")
	if partly["status"] != "degraded" || partly["policies_running"] != float64(1) || partly["not_running"] == nil {
		t.Errorf("a file with one policy that does not run must be listed degraded, got %v", partly)
	}
	if none := retentionCheck(t, ""); none != nil {
		t.Errorf("an app without retention has no retention check, got %v", none)
	}
}

// The framework's own clean-up of its tables is not a retention policy and
// keeps working: the audit retention sweep (also under the hipaa append-only
// triggers), the expired-session clean-up and the job pruner.
func TestFrameworkOwnCleanupOfItsTablesStillRuns(t *testing.T) {
	for name, appYAML := range map[string]string{
		"plain": "auth:\n  identifier: email\n",
		"hipaa": "compliance: hipaa\nauth:\n  identifier: email\n",
	} {
		t.Run(name, func(t *testing.T) {
			app, _ := retentionGuardApp(t, appYAML, "policies:\n  - table: events\n    ttl: \"1d\"\n")
			if err := ensureAuditAppendOnly(app); err != nil {
				t.Fatal(err)
			}
			before := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_audit_log`)
			mustExec(t, app.DB, `INSERT INTO _benmore_audit_log (action, table_name, row_id, created_at) VALUES ('update', 'events', '1', datetime('now', '-400 days')), ('update', 'events', '2', datetime('now'))`)
			n, err := sweepAuditLog(app.DB, 180*24*time.Hour, false, time.Now(), make(chan struct{}))
			if err != nil || n != 1 {
				t.Fatalf("audit retention sweep deleted %d (%v), want the one old row", n, err)
			}
			if left := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_audit_log`); left != before+1 {
				t.Fatalf("audit rows left = %d, want %d", left, before+1)
			}

			mustExec(t, app.DB, `INSERT INTO _benmore_sessions (id, user_id, email, created_at, expires_at) VALUES ('sha256:expired', 1, 'a@b.test', datetime('now', '-40 days'), datetime('now', '-1 days')), ('sha256:live', 1, 'a@b.test', datetime('now'), datetime('now', '+1 days'))`)
			EnsureSessionsTable(app.DB)
			if left := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_sessions`); left != 1 {
				t.Fatalf("expired-session clean-up left %d sessions, want the live one", left)
			}

			mustExec(t, app.DB, `INSERT INTO _benmore_jobs (job_type, payload, status, created_at, completed_at) VALUES ('hook', '{}', 'completed', datetime('now', '-9 days'), datetime('now', '-8 days')), ('hook', '{}', 'completed', datetime('now'), datetime('now')), ('hook', '{}', 'failed', datetime('now', '-40 days'), datetime('now', '-31 days'))`)
			pruneOldJobs(app.DB)
			if left := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_jobs`); left != 1 {
				t.Fatalf("job pruning left %d jobs, want the recent one", left)
			}
		})
	}
}

// logRetentionProblemsForTest runs what a served start logs about
// retention.yaml and app.yaml (server.go calls it before the sweep starts).
func logRetentionProblemsForTest(app *App) {
	logRetentionProblems(app)
}

// A retention.yaml the app already carries with a policy that does not run is
// refused when it is written and is an error in `benmore check`, but does not
// fail a push of another file: that write did not put it there.
func TestDeployedRetentionProblemDoesNotFailOtherWrites(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "auth:\n  identifier: email\n")
	writeTestFile(t, dir, "schema.prisma", retentionGuardSchema)
	writeTestFile(t, dir, "retention.yaml", "policies:\n  - table: events\n    ttl: 30d\n    col: updated_at\n")
	severity := func(written string) string {
		for _, f := range RunSourceCheck(dir, written).Findings {
			if f.File == "retention.yaml" && strings.Contains(f.Message, `"col"`) {
				return f.Severity
			}
		}
		return ""
	}
	for written, want := range map[string]string{"": "error", "retention.yaml": "error", "app.yaml": "warning", "schema.prisma": "warning"} {
		if got := severity(written); got != want {
			t.Errorf("check after a write of %q: the retention.yaml finding is %q, want %q", written, got, want)
		}
	}
	if report := RunSourceCheck(dir, "app.yaml"); report.Errors != 0 {
		t.Errorf("a push of app.yaml must not fail over the deployed retention.yaml: %+v", report.Findings)
	}
}

// Only the app's own retention.yaml and computed.yaml are judged: a test file
// that shares the name (tests/retention.yaml) is not a retention policy.
func TestGuardrailGatesJudgeOnlyTheAppRootFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "auth:\n  identifier: email\n")
	writeTestFile(t, dir, "schema.prisma", retentionGuardSchema)
	testFile := "sweep_deletes_expired_rows:\n  steps:\n    - flush: \"retention\"\n"
	for _, path := range []string{"tests/retention.yaml", "tests/computed.yaml", filepath.Join(dir, "tests", "retention.yaml")} {
		if msg := ValidateOnWriteIn(dir, path, testFile); msg != "" {
			t.Errorf("%s is a test file and must pass, got %q", path, msg)
		}
	}
	for _, path := range []string{"retention.yaml", "./retention.yaml", filepath.Join(dir, "retention.yaml")} {
		if msg := ValidateOnWriteIn(dir, path, testFile); !strings.Contains(msg, "top-level key") {
			t.Errorf("%s is the app's retention.yaml and must be judged, got %q", path, msg)
		}
	}
}

// A retention policy that left copies did not do its job: a versioned table
// keeps every earlier state of a row in <table>_history, and its delete
// trigger adds the final state. The sweep removes the stored versions of the
// rows it deletes, with them. Versions of rows that stay, history of a row
// that left the table another way, and the audit log are not touched.
func TestRetentionRemovesStoredVersionsOfTheRowsItDeletes(t *testing.T) {
	app, _ := retentionGuardApp(t, "auth:\n  identifier: email\nversioned:\n  - events\n", "policies:\n  - table: events\n    ttl: \"1d\"\n")
	for _, q := range []string{
		`INSERT INTO events (id, title, created_at, updated_at) VALUES (1, 'expired v1', datetime('now', '-3 days'), datetime('now', '-3 days'))`,
		`INSERT INTO events (id, title, created_at, updated_at) VALUES (2, 'fresh v1', datetime('now'), datetime('now'))`,
		`INSERT INTO events (id, title, created_at, updated_at) VALUES (3, 'deleted by its owner', datetime('now', '-3 days'), datetime('now', '-3 days'))`,
		`INSERT INTO events (id, title, created_at, updated_at, deleted_at) VALUES (4, 'trashed v1', datetime('now'), datetime('now'), NULL)`,
		`UPDATE events SET title = 'expired v2' WHERE id = 1`,
		`UPDATE events SET title = 'expired v3' WHERE id = 1`,
		`UPDATE events SET title = 'fresh v2' WHERE id = 2`,
		`INSERT INTO events (id, title, created_at, updated_at) VALUES (5, 'deleted by its owner today', datetime('now'), datetime('now'))`,
		`DELETE FROM events WHERE id IN (3, 5)`,
		`UPDATE events SET title = 'trashed v2', deleted_at = datetime('now', '-3 days') WHERE id = 4`,
		`INSERT INTO _benmore_audit_log (action, table_name, row_id, user_email, old_values) VALUES ('update', 'events', '1', 'editor@retention.test', '{"title":"expired v1"}')`,
	} {
		mustExec(t, app.DB, q)
	}
	versions := func(id int) int {
		return guardCount(t, app.DB, `SELECT COUNT(*) FROM events_history WHERE id = ?`, id)
	}
	if versions(1) != 2 || versions(2) != 1 || versions(3) != 1 || versions(4) != 1 || versions(5) != 1 {
		t.Fatalf("fixture: versions before the sweep are %d, %d, %d, %d, %d; want 2, 1, 1, 1, 1", versions(1), versions(2), versions(3), versions(4), versions(5))
	}

	RunRetentionNow(app)

	if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM events WHERE id IN (1, 4)`); n != 0 {
		t.Fatalf("the expired row and the row trashed three days ago must be deleted (left: %d)", n)
	}
	if versions(1) != 0 {
		t.Errorf("the expired row is still readable from events_history (%d versions)", versions(1))
	}
	if versions(4) != 0 {
		t.Errorf("the purged soft-deleted row is still readable from events_history (%d versions)", versions(4))
	}
	if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM events WHERE id = 2`); n != 1 || versions(2) != 1 {
		t.Errorf("the fresh row and its one version must stay (row: %d, versions: %d)", n, versions(2))
	}
	// A row its owner deleted through the API left a copy in history. The
	// copy ages out by the policy's column like the row would have; the copy
	// of a row deleted today stays until then.
	if versions(3) != 0 {
		t.Errorf("the stored version of a row deleted three days ago must age out with a 1d ttl (versions: %d)", versions(3))
	}
	if versions(5) != 1 {
		t.Errorf("the stored version of a row deleted today is younger than the ttl and must stay (versions: %d)", versions(5))
	}
	// The audit log keeps what it recorded about the deleted row, and says
	// how many stored versions went with the rows.
	if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_audit_log WHERE user_email = 'editor@retention.test'`); n != 1 {
		t.Errorf("the audit row about the deleted row must stay (rows: %d)", n)
	}
	if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'ttl_delete' AND table_name = 'events' AND new_values LIKE '%"rows_deleted":1%' AND new_values LIKE '%"history_rows_deleted":3%'`); n != 1 {
		t.Errorf("the ttl_delete audit row must count the row, its two stored versions and the aged-out one (rows: %d)", n)
	}
	if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'ttl_purge' AND table_name = 'events' AND new_values LIKE '%"history_rows_deleted":1%'`); n != 1 {
		t.Errorf("the ttl_purge audit row must count the stored version (rows: %d)", n)
	}
}

// One expired row that a row of another table still references used to fail
// the table's delete as a whole, every hour. It is kept (with its stored
// versions) and counted; every other expired row goes, in batches.
func TestRetentionSkipsReferencedRowsAndDeletesTheRest(t *testing.T) {
	previous := retentionBatchSize
	retentionBatchSize = 2
	t.Cleanup(func() { retentionBatchSize = previous })

	app, logs := retentionGuardApp(t, "auth:\n  identifier: email\nversioned:\n  - events\n", "policies:\n  - table: events\n    ttl: \"1d\"\n")
	mustExec(t, app.DB, `CREATE TABLE attendees (id INTEGER PRIMARY KEY, event_id INTEGER REFERENCES events(id))`)
	for id := 1; id <= 7; id++ {
		age := "-3 days"
		if id == 7 {
			age = "-1 hours"
		}
		mustExecArgs(t, app.DB, `INSERT INTO events (id, title, created_at, updated_at) VALUES (?, 'v1', datetime('now', ?), datetime('now', ?))`, id, age, age)
		mustExecArgs(t, app.DB, `UPDATE events SET title = 'v2' WHERE id = ?`, id)
	}
	mustExec(t, app.DB, `INSERT INTO attendees (event_id) VALUES (3), (3), (6)`)

	RunRetentionNow(app)

	left := func(table string) string {
		rows, err := app.DB.Query(`SELECT DISTINCT id FROM ` + table + ` ORDER BY id`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var ids []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				t.Fatal(err)
			}
			ids = append(ids, id)
		}
		return strings.Join(ids, ",")
	}
	if got := left("events"); got != "3,6,7" {
		t.Fatalf("events left: %s; want the two referenced rows and the fresh one (3,6,7)", got)
	}
	if got := left("events_history"); got != "3,6,7" {
		t.Fatalf("history left for ids %s; want only the rows that stayed (3,6,7)", got)
	}
	if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'ttl_delete' AND table_name = 'events' AND new_values LIKE '%"rows_deleted":4%' AND new_values LIKE '%"rows_skipped":2%' AND new_values LIKE '%"history_rows_deleted":4%'`); n != 1 {
		t.Errorf("the audit row must count 4 deleted, 2 skipped and 4 stored versions (rows: %d)", n)
	}
	if !strings.Contains(logs.String(), "2 expired rows were kept because rows of another table still reference them") {
		t.Errorf("the skipped rows must be logged; log:\n%s", logs.String())
	}
	// A sweep that only skips writes no audit row.
	audits := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'ttl_delete'`)
	RunRetentionNow(app)
	if n := guardCount(t, app.DB, `SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'ttl_delete'`); n != audits {
		t.Errorf("a sweep that deletes nothing must not write an audit row (%d before, %d after)", audits, n)
	}
	// Once nothing references them, they go with their versions.
	mustExec(t, app.DB, `DELETE FROM attendees`)
	RunRetentionNow(app)
	if events, history := left("events"), left("events_history"); events != "7" || history != "7" {
		t.Fatalf("after the references are gone: events %s, history %s; want only the fresh row 7", events, history)
	}
}
