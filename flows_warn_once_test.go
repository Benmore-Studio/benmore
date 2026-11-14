//go:build !cli && !windows

package main

import (
	"bytes"
	"log"
	"path/filepath"
	"strings"
	"testing"
)

// A deployed flow file with something the write gate warns about logs a
// WARNING line when the app loads it. Every reader of the flow files logged
// the line again: `benmore serve` checks the source before it loads it, so a
// start (and a reload that restarts the process) logged each flow warning
// three times, twice from the check, which also prints it as a finding; and
// every later check of the app logged it twice more. The load that serves
// the app logs it, once; the check reports its finding and logs nothing.
func TestFlowWarningsAreLoggedOncePerLoad(t *testing.T) {
	t.Setenv("BENMORE_TEST_BOOT", "0")
	authority, err := filepath.EvalSymlinks(epochFixture(t))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteHTMLScaffoldFiles(dir, "Warning fixture"); err != nil {
		t.Fatal(err)
	}
	const flow = `on:
  request:
    method: GET
    path: /api/report
    auth: required
jobs:
  report:
    steps:
      - id: user_id
        run: sql
        with: { query: "SELECT 1 AS n" }
      - run: respond
        with: { status: 200, body: { ok: true } }
`
	writeTestFile(t, dir, "flows/report.yaml", flow)
	const warning = "is named like the signed-in caller's `user_id`"

	var logged bytes.Buffer
	before := log.Writer()
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(before) })

	// A start, in serve's order: the source check, then the load.
	report := RunCompleteCheck(dir, "")
	found := false
	for _, f := range report.Findings {
		found = found || f.Severity == "warning" && f.File == "flows/report.yaml" && strings.Contains(f.Message, warning)
	}
	if !found {
		t.Errorf("the check does not report the flow warning as a finding: %+v", report.Findings)
	}
	if n := strings.Count(logged.String(), warning); n != 0 {
		t.Errorf("the check logged the flow warning %d times beside its finding:\n%s", n, warningLines(logged.String()))
	}
	app, err := loadApp(dir)
	if err != nil {
		log.SetOutput(before)
		t.Fatalf("load: %v\n%s", err, logged.String())
	}
	t.Cleanup(func() { app.Shutdown() })
	previous := hostedHotHandler
	hostedHotHandler = &hotHandler{}
	t.Cleanup(func() { hostedHotHandler = previous })
	if n := strings.Count(logged.String(), warning); n != 1 {
		t.Errorf("the check and the start together logged the flow warning %d times, want once:\n%s", n, warningLines(logged.String()))
	}

	logged.Reset()
	if err := hotReloadApp(app, false); err != nil {
		log.SetOutput(before)
		t.Fatalf("reload: %v\n%s", err, logged.String())
	}
	if n := strings.Count(logged.String(), warning); n != 1 {
		t.Errorf("a reload logged the flow warning %d times, want once:\n%s", n, warningLines(logged.String()))
	}

	// A file that changes is judged again: its new warning is logged, and the
	// old one, which no longer applies, is not.
	writeTestFile(t, dir, "flows/report.yaml", strings.Replace(flow, "id: user_id", "id: user_email", 1))
	logged.Reset()
	if err := hotReloadApp(app, false); err != nil {
		log.SetOutput(before)
		t.Fatalf("second reload: %v\n%s", err, logged.String())
	}
	if n := strings.Count(logged.String(), "is named like the signed-in caller's `user_email`"); n != 1 {
		t.Errorf("the changed file's warning was logged %d times, want once:\n%s", n, warningLines(logged.String()))
	}
	if strings.Contains(logged.String(), warning) {
		t.Errorf("the reload logged a warning of the file's earlier content:\n%s", warningLines(logged.String()))
	}
}

func warningLines(logged string) string {
	var out []string
	for _, line := range strings.Split(logged, "\n") {
		if strings.Contains(line, "WARNING") {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}
