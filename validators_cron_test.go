//go:build !cli

package main

import (
	"strings"
	"testing"
)

func TestCronYAMLRefusesKeysTheSchedulerIgnores(t *testing.T) {
	cases := []struct{ name, yaml, want string }{
		{"enabled false kept the job running", "nightly:\n  schedule: \"0 3 * * *\"\n  sql: \"DELETE FROM sessions_log\"\n  enabled: false\n", `unknown key "enabled"`},
		{"timezone", "digest:\n  schedule: \"0 9 * * 1\"\n  flow: send_digest\n  timezone: America/New_York\n", `unknown key "timezone"`},
		{"retries in the jobs list", "jobs:\n  - id: sync\n    schedule: every 15m\n    flow: sync\n    retries: 3\n", `unknown key "retries"`},
		{"when guard on an inline step", "purge:\n  schedule: \"@daily\"\n  run:\n    - sql: \"DELETE FROM drafts\"\n      when: \"1 = 0\"\n", `unknown step key "when"`},
		{"nested inline step", "fanout:\n  schedule: \"@hourly\"\n  run:\n    - sql: \"SELECT id FROM t\"\n      name: rows\n    - for_each: rows\n      as: r\n      steps:\n        - sql: \"UPDATE t SET n = n + 1\"\n          expect_rows: \">0\"\n", `run[1].steps[0]: unknown step key "expect_rows"`},
		{"email step key", "digest:\n  schedule: \"@daily\"\n  run:\n    - email: { to: \"a@example.com\", subject: hi, template: digest, from: \"x@example.com\" }\n", `unknown key "from"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if _, err := parseCronYAML([]byte(c.yaml)); err != nil {
				t.Fatalf("fixture must still load (deployed files keep running): %v", err)
			}
			if msg := ValidateOnWriteIn("", "cron.yaml", c.yaml); !strings.Contains(msg, c.want) {
				t.Fatalf("write gate = %q; want %q", msg, c.want)
			}
		})
	}
	for _, ok := range []string{
		"nightly:\n  schedule: \"0 3 * * *\"\n  sql: \"SELECT 1\"\n  max_attempts: 2\n",
		"jobs:\n  - id: sync\n    schedule: every 15m\n    flow: sync\n    max_attempts: 1\n",
		"inline:\n  schedule: \"@hourly\"\n  steps:\n    - sql: \"SELECT 1\"\n",
	} {
		if msg := ValidateOnWriteIn("", "cron.yaml", ok); msg != "" {
			t.Errorf("valid cron.yaml refused:\n%s\n%s", ok, msg)
		}
	}
}

// api(at:"cron") says a job takes `flow | sql | run | steps` in either shape.
// The map shape read `sql:`; the jobs list dropped it and refused the job as
// "requires either flow or inline steps". Both shapes now take the same keys.
func TestCronSQLJobInBothShapes(t *testing.T) {
	for name, src := range map[string]string{
		"jobs list": "jobs:\n  - id: mark_stale\n    schedule: \"every 1m\"\n    sql: \"UPDATE bookings SET stale = 1 WHERE stale = 0\"\n",
		"map":       "mark_stale:\n  schedule: \"every 1m\"\n  sql: \"UPDATE bookings SET stale = 1 WHERE stale = 0\"\n",
	} {
		t.Run(name, func(t *testing.T) {
			cfg, err := parseCronYAML([]byte(src))
			if err != nil {
				t.Fatal(err)
			}
			if len(cfg.Jobs) != 1 || len(cfg.Jobs[0].Steps) != 1 || cfg.Jobs[0].Steps[0].Type != "sql" || !strings.Contains(cfg.Jobs[0].Steps[0].SQL, "SET stale = 1") {
				t.Fatalf("sql job did not become one sql step: %+v", cfg.Jobs)
			}
			if msg := ValidateOnWriteIn("", "cron.yaml", src); msg != "" {
				t.Fatalf("write gate refused a documented job: %s", msg)
			}
		})
	}
	for _, c := range []struct{ name, yaml, want string }{
		{"sql with run", "jobs:\n  - id: x\n    schedule: \"@daily\"\n    sql: \"SELECT 1\"\n    run:\n      - sql: \"SELECT 2\"\n", "mixes sql with another action"},
		{"sql with flow", "x:\n  schedule: \"@daily\"\n  sql: \"SELECT 1\"\n  flow: f\n", "mixes sql with another action"},
		{"nothing to run", "jobs:\n  - id: x\n    schedule: \"@daily\"\n", "flow: <flow name>, sql:"},
	} {
		if _, err := parseCronYAML([]byte(c.yaml)); err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: err=%v, want %q", c.name, err, c.want)
		}
	}
}

// A cron job naming a flow the app doesn't define failed every run with
// "flow not found" while the write gate and `benmore check` passed it.
func TestCronYAMLRefusesUnknownFlow(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "flows/sync_all.yaml", "on:\n  schedule:\n    cron: \"@daily\"\njobs:\n  main:\n    steps:\n      - run: sql\n        with: {query: \"SELECT 1\"}\n")
	writeTestFile(t, dir, "flows.yaml", "on:\n  request: {method: POST, path: /api/a}\njobs:\n  first:\n    steps:\n      - run: respond\n        with: {json: {ok: true}}\n")
	good := "jobs:\n  - id: nightly\n    schedule: \"@daily\"\n    flow: sync_all\n  - id: other\n    schedule: \"@hourly\"\n    flow: first\n"
	if msg := ValidateOnWriteIn(dir, "cron.yaml", good); msg != "" {
		t.Fatalf("cron.yaml naming defined flows refused: %s", msg)
	}
	bad := "nightly:\n  schedule: \"@daily\"\n  flow: nosuchflow\n"
	msg := ValidateOnWriteIn(dir, "cron.yaml", bad)
	for _, want := range []string{`flow "nosuchflow" is not defined`, "sync_all", "first"} {
		if !strings.Contains(msg, want) {
			t.Fatalf("write gate = %q; want it to contain %q", msg, want)
		}
	}
	// Without an app dir (a bare file check) there is nothing to compare to.
	if msg := ValidateOnWriteIn("", "cron.yaml", bad); msg != "" {
		t.Fatalf("dirless check refused: %s", msg)
	}

	// `benmore check` reports it, and so does the check after a flow write
	// that removed the flow the job names.
	writeTestFile(t, dir, "cron.yaml", bad)
	if !checkReportHas(runCheck(dir, "", false), "cron.yaml", "nosuchflow") {
		t.Fatal("benmore check did not report the missing flow")
	}
	writeTestFile(t, dir, "cron.yaml", good)
	if report := runCheck(dir, "", false); checkReportHas(report, "cron.yaml", "not defined") {
		t.Fatalf("benmore check refused defined flows: %+v", report.Findings)
	}
	writeTestFile(t, dir, "flows/sync_all.yaml", "on:\n  schedule:\n    cron: \"@daily\"\njobs:\n  renamed_a:\n    steps:\n      - run: sql\n        with: {query: \"SELECT 1\"}\n  renamed_b:\n    steps:\n      - run: sql\n        with: {query: \"SELECT 2\"}\n")
	if !checkReportHas(RunSourceCheck(dir, "flows/sync_all.yaml"), "cron.yaml", `flow "sync_all" is not defined`) {
		t.Fatal("the check after a flow write did not report the cron job it broke")
	}

	// A cron.yaml line that already named a missing flow is reported on an
	// unrelated flow write as a warning, not an error: it is not that write's
	// doing, and refusing would block every flow push until cron.yaml is fixed.
	writeTestFile(t, dir, "cron.yaml", bad)
	writeTestFile(t, dir, "flows/other.yaml", "on:\n  request: {method: POST, path: /api/other}\njobs:\n  main:\n    steps:\n      - run: respond\n        with: {json: {ok: true}}\n")
	report := RunSourceCheck(dir, "flows/other.yaml")
	if checkReportHas(report, "cron.yaml", "nosuchflow") {
		t.Fatalf("an unrelated flow write was refused for an existing cron line: %+v", report.Findings)
	}
	warned := false
	for _, f := range report.Findings {
		warned = warned || (f.Severity == "warning" && strings.Contains(f.Message, "cron.yaml") && strings.Contains(f.Message, "nosuchflow"))
	}
	if !warned {
		t.Fatalf("the existing broken cron line was not reported as a warning: %+v", report.Findings)
	}
}

func checkReportHas(report CheckReport, file, text string) bool {
	for _, f := range report.Findings {
		if f.File == file && f.Severity == "error" && strings.Contains(f.Message, text) {
			return true
		}
	}
	return false
}
