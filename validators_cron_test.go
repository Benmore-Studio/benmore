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
