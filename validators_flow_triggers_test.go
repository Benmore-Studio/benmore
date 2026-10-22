//go:build !cli

package main

import (
	"strings"
	"testing"
)

func TestFlowTriggerProblemsRefusedAtWriteTime(t *testing.T) {
	steps := "jobs:\n  run:\n    steps:\n      - query: \"SELECT 1\"\n"
	cases := []struct {
		name, on, want string
	}{
		{"cron the scheduler can't evaluate", "on:\n  schedule: { cron: \"every 1d\" }\n", "would never run"},
		{"weekday 7", "on:\n  schedule: { cron: \"0 9 * * 7\" }\n", "would never run"},
		{"robfig @every", "on:\n  schedule: { cron: \"@every 5m\" }\n", "would never run"},
		{"missing cron", "on:\n  schedule: {}\n", "needs `cron:`"},
		{"unknown event op", "on:\n  event: { table: notes, op: updated }\n", "falls back to insert"},
		{"missing event op", "on:\n  event: { table: notes }\n", "falls back to insert"},
		{"two triggers", "on:\n  request: { method: POST, path: /api/sync, auth: required }\n  schedule: { cron: \"@daily\" }\n", "only `request` would be used"},
		{"unknown mode", "on:\n  request: { method: POST, path: /api/sync, auth: required, mode: background }\n", "runs inline"},
		{"unknown auth", "on:\n  request: { method: POST, path: /api/sync, auth: members }\n", "not a recognized value"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			content := tc.on + steps
			msg := ValidateOnWriteIn("", "flows/sync.yaml", content)
			if !strings.Contains(msg, tc.want) {
				t.Fatalf("write gate = %q; want %q", msg, tc.want)
			}
			// A deployed file with the problem still loads (lenient reading).
			if _, err := parseGHAFlowFile("flows/sync.yaml", []byte(content)); err != nil {
				t.Fatalf("loader refused a deployed file: %v", err)
			}
		})
	}

	for _, on := range []string{
		"on:\n  schedule: { cron: \"*/15 * * * *\" }\n",
		"on:\n  schedule: { cron: \"every 24h\" }\n",
		"on:\n  event: { table: notes, op: delete }\n",
		"on:\n  request: { method: POST, path: /api/sync, auth: none, mode: async }\n",
		"on:\n  request: { method: POST, path: /api/sync, auth: required }\n",
	} {
		if msg := ValidateOnWriteIn("", "flows/sync.yaml", on+steps); msg != "" {
			t.Errorf("valid trigger refused:\n%s\n%s", on, msg)
		}
	}
}

// benmore check runs the cron.yaml validator on the file itself (it was
// reached only through the app load, which is skipped once any other file
// has an error, and then reported without the file name).
func TestCheckValidatesCronYAML(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "cron.yaml", "nightly:\n  schedule: \"0 3 * * 7\"\n  sql: \"SELECT 1\"\n")
	writeTestFile(t, dir, "hooks.yaml", "on_create:\n  notes: []\n") // an unrelated error elsewhere
	rpt := RunCompleteCheck(dir, "")
	for _, f := range rpt.Findings {
		if f.File == "cron.yaml" && strings.Contains(f.Message, "nightly") {
			return
		}
	}
	t.Fatalf("benmore check missed the invalid cron schedule: %+v", rpt.Findings)
}
