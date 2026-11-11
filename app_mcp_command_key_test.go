//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A command app with no ENCRYPTION_KEY passed mcp review, mcp check, benmore
// check and the push write gate, then every reload refused with "operation
// lifecycle requires configured ENCRYPTION_KEY". The checks now say so.
func TestMCPCommandsWithoutEncryptionKeyAreReportedByChecks(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "") // restored after the test
	os.Unsetenv("ENCRYPTION_KEY")  // an empty process value would override env.yaml
	root := t.TempDir()
	writeTestFile(t, root, "schema.sql", "CREATE TABLE members(id INTEGER PRIMARY KEY, org_id TEXT, email TEXT);\nCREATE TABLE notes(id TEXT PRIMARY KEY, status TEXT);\n")
	writeTestFile(t, root, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\n")
	writeActualLifecycleCommandFixture(t, root)

	if !appSourceDeclaresMCPCommands(root) {
		t.Fatal("a reviewed manifest with a command flow was not recognised")
	}
	report, err := inspectAppMCPSource(root)
	if err != nil {
		t.Fatalf("mcp check: %v", err)
	}
	if len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "requires configured ENCRYPTION_KEY") {
		t.Fatalf("mcp check did not report the missing key: %v", report.Warnings)
	}
	for _, written := range []string{"", "mcp.yaml", "flows/complete_note.yaml"} {
		if !hasCommandKeyFinding(runCheckWithLive(root, written, written == "", func(string) []CheckFinding { return nil })) {
			t.Fatalf("check after writing %q did not report the missing key", written)
		}
	}
	if hasCommandKeyFinding(RunSourceCheck(root, "static/app.tsx")) {
		t.Fatal("an unrelated write re-scanned every flow for the key warning")
	}

	writeTestFile(t, root, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("ab", 32)+"\n")
	if report, err := inspectAppMCPSource(root); err != nil || len(report.Warnings) != 0 {
		t.Fatalf("a configured key still warned: %v %v", err, report)
	}
	if hasCommandKeyFinding(RunSourceCheck(root, "mcp.yaml")) {
		t.Fatal("a configured key still produced a check finding")
	}
}

func hasCommandKeyFinding(report CheckReport) bool {
	for _, f := range report.Findings {
		if f.Source == "mcp_connector" && strings.Contains(f.Message, "requires configured ENCRYPTION_KEY") {
			return f.Severity == "warning"
		}
	}
	return false
}

// The router runs the detection over a tenant's directory: it needs mcp.yaml
// and a real command flow, and never follows a link out of the app.
func TestAppSourceDeclaresMCPCommandsShape(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "flows/plain.yaml", "on: {request: {method: GET, path: /api/x}}\njobs: {}\n")
	writeTestFile(t, dir, "flows/approve.yaml", "command:\n  version: 1\n")
	if appSourceDeclaresMCPCommands(dir) {
		t.Fatal("command flows without mcp.yaml need no key")
	}
	writeTestFile(t, dir, "mcp.yaml", "version: 1\n")
	if !appSourceDeclaresMCPCommands(dir) {
		t.Fatal("mcp.yaml with a command flow was not recognised")
	}
	if err := os.Remove(filepath.Join(dir, "flows/approve.yaml")); err != nil {
		t.Fatal(err)
	}
	if appSourceDeclaresMCPCommands(dir) {
		t.Fatal("a flow mentioning no command declaration was taken for one")
	}
	outside := filepath.Join(t.TempDir(), "elsewhere.yaml")
	if err := os.WriteFile(outside, []byte("command:\n  version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(dir, "flows/linked.yaml")); err != nil {
		t.Fatal(err)
	}
	if appSourceDeclaresMCPCommands(dir) {
		t.Fatal("detection followed a flow link out of the app")
	}
}
