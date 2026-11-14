//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const hipaaCronAppYAML = "site_name: schedules\ncompliance: hipaa\nauth:\n  identifier: email\n"

const hipaaCronSchema = "model Hold {\n  id Int @id @default(autoincrement())\n  expired Int @default(0)\n  until String?\n  @@map(\"holds\")\n}\n\nmodel Tally {\n  id Int @id @default(autoincrement())\n  n Int @default(0)\n  @@map(\"tallies\")\n}\n"

// A cron.yaml job's own SQL is outside the audit log like a flow's: under
// `compliance: hipaa` a job that writes a table of the app and inserts no
// audit row is named, in each shape cron.yaml takes. A job that names a flow
// is the flow file's to report.
func TestHIPAAUnauditedCronWrites(t *testing.T) {
	const audit = `INSERT INTO _benmore_audit_log (action, table_name, user_email, new_values) VALUES ('update', 'holds', 'system:expire_holds', json_object('expired', 1))`
	cases := []struct {
		name string
		yaml string
		want []string // one substring per expected problem, in order
	}{
		{"a named job's sql: line", "expire_holds:\n  schedule: \"every 15m\"\n  sql: \"UPDATE holds SET expired = 1 WHERE until < datetime('now')\"\n",
			[]string{`job "expire_holds" writes holds with its own SQL and inserts no row into _benmore_audit_log`}},
		{"a jobs list entry's sql: line", "jobs:\n  - id: expire_holds\n    schedule: \"every 15m\"\n    sql: \"DELETE FROM holds WHERE expired = 1\"\n",
			[]string{`job "expire_holds" writes holds`}},
		{"run: steps", "tidy:\n  schedule: \"@daily\"\n  run:\n    - sql: \"SELECT id FROM holds WHERE expired = 1\"\n      name: old\n    - sql: \"INSERT INTO tallies (n) VALUES (1)\"\n",
			[]string{`job "tidy" writes tallies`}},
		{"a write nested in a loop, under steps:", "tidy:\n  schedule: \"@daily\"\n  steps:\n    - sql: \"SELECT id FROM holds WHERE expired = 1\"\n      name: old\n    - for_each: old\n      as: h\n      steps:\n        - sql: \"DELETE FROM holds WHERE id = {{h.id}}\"\n        - sql: \"UPDATE tallies SET n = n + 1\"\n",
			[]string{`job "tidy" writes holds, tallies`}},
		{"a write in an else branch", "tidy:\n  schedule: \"@daily\"\n  run:\n    - if: \"1 = 2\"\n      steps:\n        - sql: \"SELECT 1\"\n      else:\n        - sql: \"UPDATE tallies SET n = 0\"\n",
			[]string{`job "tidy" writes tallies`}},
		{"the write and its audit row", "expire_holds:\n  schedule: \"every 15m\"\n  run:\n    - sql: \"UPDATE holds SET expired = 1 WHERE until < datetime('now')\"\n    - sql: \"" + audit + "\"\n", nil},
		{"the audit row in a nested step", "expire_holds:\n  schedule: \"every 15m\"\n  run:\n    - sql: \"UPDATE holds SET expired = 1\"\n    - if: \"1 = 1\"\n      steps:\n        - sql: \"" + audit + "\"\n", nil},
		{"a read", "report:\n  schedule: \"@daily\"\n  sql: \"SELECT COUNT(*) AS n FROM holds\"\n", nil},
		{"a write of a framework table only", "sweep:\n  schedule: \"@daily\"\n  sql: \"DELETE FROM _benmore_notifications WHERE created_at < datetime('now', '-90 days')\"\n", nil},
		{"a job that names a flow", "nightly:\n  schedule: \"@daily\"\n  flow: nightly_close\n", nil},
		{"two jobs, one audited", "a_first:\n  schedule: \"@daily\"\n  sql: \"UPDATE tallies SET n = 0\"\nb_second:\n  schedule: \"@daily\"\n  run:\n    - sql: \"UPDATE holds SET expired = 1\"\n    - sql: \"" + audit + "\"\n",
			[]string{`job "a_first" writes tallies`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if msg := ValidateOnWriteIn("", "cron.yaml", c.yaml); msg != "" {
				t.Fatalf("the write gate refuses the file: %s", msg)
			}
			cfg, err := parseCronYAML([]byte(c.yaml))
			if err != nil {
				t.Fatal(err)
			}
			got := hipaaUnauditedCronProblems(cfg)
			if len(got) != len(c.want) {
				t.Fatalf("%d problems, want %d: %q", len(got), len(c.want), got)
			}
			for i, want := range c.want {
				if !strings.Contains(got[i], want) {
					t.Errorf("problem %d = %q, want it to contain %q", i, got[i], want)
				}
				// The advice is the schedule's: no signed-in user to bind.
				if !strings.Contains(got[i], "'system:") || strings.Contains(got[i], ":user_id") {
					t.Errorf("problem %d does not tell a schedule to name its actor as a literal: %q", i, got[i])
				}
			}
		})
	}
}

// `benmore check`, the check after a write of cron.yaml and the one after a
// write of app.yaml report the job; a write of a flow file does not repeat
// it, an app without `compliance: hipaa` gets none, and nothing is refused.
func TestHIPAACronCheckFollowsAWrite(t *testing.T) {
	const cron = "expire_holds:\n  schedule: \"every 15m\"\n  sql: \"UPDATE holds SET expired = 1 WHERE until < datetime('now')\"\nnightly:\n  schedule: \"@daily\"\n  flow: nightly_close\n"
	const flow = "on:\n  request: { method: POST, path: /api/nightly-close, auth: required }\njobs:\n  nightly_close:\n    steps:\n      - run: sql\n        with:\n          query: \"SELECT COUNT(*) AS n FROM holds\"\n      - run: respond\n        with: { json: { ok: true } }\n"
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", hipaaCronAppYAML)
	writeTestFile(t, dir, "schema.prisma", hipaaCronSchema)
	writeTestFile(t, dir, "cron.yaml", cron)
	writeTestFile(t, dir, "flows/nightly_close.yaml", flow)

	for _, written := range []string{"", "cron.yaml", "app.yaml"} {
		rpt := RunSourceCheck(dir, written)
		for _, f := range rpt.Findings {
			if f.Severity == "error" {
				t.Fatalf("written %q: the write gate refuses %s: %s", written, f.File, f.Message)
			}
		}
		got := hipaaFlowCheckFindings(rpt)
		if len(got) != 1 {
			t.Fatalf("written %q: %d compliance warnings, want 1: %v", written, len(got), got)
		}
		f := got[0]
		if f.File != "cron.yaml" || f.Severity != "warning" || f.Docs != "audit.flow_writes" ||
			!strings.Contains(f.Message, `cron.yaml: job "expire_holds" writes holds with its own SQL and inserts no row into _benmore_audit_log`) {
			t.Fatalf("written %q: %+v", written, f)
		}
	}
	if got := hipaaFlowCheckFindings(RunSourceCheck(dir, "flows/nightly_close.yaml")); len(got) != 0 {
		t.Fatalf("a write of a flow file repeats the cron.yaml warning: %v", got)
	}
	// The post-write answer of a push of cron.yaml carries it.
	kept := writeRelevantFindings("cron.yaml", RunSourceCheck(dir, "cron.yaml").Findings)
	if got := hipaaFlowCheckFindings(CheckReport{Findings: kept}); len(got) != 1 {
		t.Fatalf("the answer to a write of cron.yaml drops its warning: %v", kept)
	}

	writeTestFile(t, dir, "app.yaml", strings.Replace(hipaaCronAppYAML, "compliance: hipaa\n", "", 1))
	for _, written := range []string{"", "cron.yaml"} {
		if got := hipaaFlowCheckFindings(RunSourceCheck(dir, written)); len(got) != 0 {
			t.Fatalf("written %q: an app without compliance: hipaa is warned: %v", written, got)
		}
	}
}

// What the warning tells a job to add works: in a hipaa app, whose audit log
// is append-only, a job written as `run:` with the write and an audit INSERT
// leaves the row, and the check is silent about it.
func TestHIPAACronJobWritesItsOwnAuditRow(t *testing.T) {
	const cron = `expire_holds:
  schedule: "0 3 1 1 *"
  run:
    - sql: "UPDATE holds SET expired = 1 WHERE expired = 0"
    - sql: "INSERT INTO _benmore_audit_log (action, table_name, user_email, new_values) VALUES ('update', 'holds', 'system:expire_holds', json_object('expired', 1))"
`
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", hipaaCronAppYAML)
	writeTestFile(t, dir, "schema.prisma", hipaaCronSchema)
	writeTestFile(t, dir, "cron.yaml", cron)
	if got := hipaaFlowCheckFindings(RunSourceCheck(dir, "")); len(got) != 0 {
		t.Fatalf("the audited job is warned about: %v", got)
	}
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	mustExec(t, app.DB, `INSERT INTO holds (expired) VALUES (0)`)
	cfg, err := parseCronYAML([]byte(cron))
	if err != nil || len(cfg.Jobs) != 1 {
		t.Fatalf("parse cron.yaml: %v", err)
	}
	if err := runCronJob(app, cfg.Jobs[0], nil); err != nil {
		t.Fatalf("the job failed: %v", err)
	}
	var expired, audited int
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM holds WHERE expired = 1`).Scan(&expired); err != nil {
		t.Fatal(err)
	}
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_audit_log WHERE action = 'update' AND table_name = 'holds' AND user_email = 'system:expire_holds'`).Scan(&audited); err != nil {
		t.Fatal(err)
	}
	if expired != 1 || audited != 1 {
		t.Fatalf("after the job: %d expired holds, %d audit rows; want 1 and 1", expired, audited)
	}
}

// A flow that answers with a whole `SELECT *` row of a table with encrypted
// fields hands the clear value to every caller it admits in any app, so the
// warning does not wait for `compliance: hipaa`. The unaudited-write advice
// stays hipaa's.
func TestWholeRowFlowResponseWarnsWithoutHIPAA(t *testing.T) {
	dir := configGapFixtureDir(t, "hipaa-flow-checks")
	appYAML, err := os.ReadFile(filepath.Join(dir, "app.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	plain := strings.Replace(string(appYAML), "compliance: hipaa\n", "", 1)
	if plain == string(appYAML) {
		t.Fatal("the fixture's app.yaml does not set compliance: hipaa")
	}
	writeTestFile(t, dir, "app.yaml", plain)

	for _, written := range []string{"", "flows/patient-row.yaml", "app.yaml"} {
		rpt := RunSourceCheck(dir, written)
		var got []CheckFinding
		for _, f := range rpt.Findings {
			if f.Severity == "error" {
				t.Fatalf("written %q: the write gate refuses %s: %s", written, f.File, f.Message)
			}
			if strings.Contains(f.Message, "responds with whole rows") {
				got = append(got, f)
			}
			if strings.Contains(f.Message, "inserts no row into _benmore_audit_log") {
				t.Errorf("written %q: an app without compliance: hipaa gets the audit advice: %s", written, f.Message)
			}
		}
		if len(got) != 1 {
			t.Fatalf("written %q: %d whole-row warnings, want 1: %v", written, len(got), got)
		}
		f := got[0]
		if f.File != "flows/patient-row.yaml" || f.Severity != "warning" || f.Docs != "encryption.flow_results" ||
			!strings.Contains(f.Message, "responds with whole rows of step \"p\", whose query selects `*` from patients") ||
			!strings.Contains(f.Message, "column ssn in clear") {
			t.Fatalf("written %q: %+v", written, f)
		}
	}
	// The other flows of the fixture name their columns or respond with none.
	if got := wholeRowFlowFindings(RunSourceCheck(dir, "flows/patient-card.yaml")); len(got) != 0 {
		t.Fatalf("a flow that names its columns is warned: %v", got)
	}

	// Without encrypted fields a `SELECT *` response is an ordinary one.
	if err := os.Remove(filepath.Join(dir, "encrypted.yaml")); err != nil {
		t.Fatal(err)
	}
	if got := wholeRowFlowFindings(RunSourceCheck(dir, "")); len(got) != 0 {
		t.Fatalf("an app with no encrypted field is warned: %v", got)
	}
}

// wholeRowFlowFindings is the whole-row warnings of a check report.
func wholeRowFlowFindings(rpt CheckReport) []CheckFinding {
	var out []CheckFinding
	for _, f := range rpt.Findings {
		if f.Source == "encryption" {
			out = append(out, f)
		}
	}
	return out
}
