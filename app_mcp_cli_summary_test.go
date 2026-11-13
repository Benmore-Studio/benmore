//go:build !cli && !windows

package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

// `benmore mcp check` and `mcp review --reviewed` print the whole inspection
// document (the route inventory of the app, over 100 KB for the scaffold).
// Scripts read that document, so it stays the default; --summary prints what a
// person looks for: the verdict, the digests, the reviewed tools and the
// warnings.
func TestAppMCPCheckAndReviewSummary(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);")
	writeTestFile(t, dir, "app.yaml", "name: summary\n")
	var authored []string
	for _, line := range strings.Split(appMCPManifestFixture(), "\n") {
		if !strings.HasPrefix(line, "contract_digest:") && !strings.HasPrefix(line, "execution_digest:") {
			authored = append(authored, line)
		}
	}
	writeTestFile(t, dir, "mcp.yaml", strings.Join(authored, "\n"))

	run := func(args ...string) string {
		t.Helper()
		var out bytes.Buffer
		if err := runAppMCPCLI(args, &out); err != nil {
			t.Fatalf("mcp %s: %v", strings.Join(args, " "), err)
		}
		return out.String()
	}
	reviewed := run("review", dir, "--reviewed", "--summary")

	// The default is the document, as before.
	var report appMCPInspection
	full := run("check", dir)
	if err := json.Unmarshal([]byte(full), &report); err != nil || !report.SourceValid || len(report.Inventory) == 0 || len(report.ContractDigest) != 64 {
		t.Fatalf("mcp check without --summary is not the inspection document: %v\n%.300s", err, full)
	}

	for name, summary := range map[string]string{
		"review":            reviewed,
		"check":             run("check", dir, "--summary"),
		"check, flag first": run("check", "--summary", dir),
	} {
		if json.Valid([]byte(summary)) || len(summary) > 4096 {
			t.Errorf("%s --summary is not a short text (%d bytes):\n%.600s", name, len(summary), summary)
		}
		for _, want := range []string{
			"source valid",
			"contract_digest: " + report.ContractDigest,
			"execution_digest: " + report.ExecutionDigest,
			"list_notes",
			"not checked here:",
			"physical_database_and_pending_migrations",
		} {
			if !strings.Contains(summary, want) {
				t.Errorf("%s --summary lacks %q:\n%s", name, want, summary)
			}
		}
		if !strings.Contains(summary, "inventory: ") || strings.Contains(summary, `"inventory"`) {
			t.Errorf("%s --summary should count the inventory, not print it:\n%s", name, summary)
		}
	}
	if !strings.Contains(reviewed, "mcp.yaml now carries these digests") || !strings.Contains(reviewed, "does not enable access") {
		t.Errorf("review --summary does not say what review did:\n%s", reviewed)
	}
	if strings.Contains(run("check", dir, "--summary"), "now carries") {
		t.Error("check --summary claims to have written mcp.yaml")
	}

	// Anything else after the directory is still a usage error.
	for _, args := range [][]string{{"check", dir, "--short"}, {"check", dir, "--summary", "--summary"}, {"review", dir, "--summary"}, {"review", dir, "--reviewed", "extra"}} {
		var out bytes.Buffer
		if err := runAppMCPCLI(args, &out); err == nil || !strings.Contains(err.Error(), "usage:") {
			t.Errorf("mcp %s: err %v, want a usage error", strings.Join(args, " "), err)
		}
	}
}

func TestAppMCPSummaryListsWarnings(t *testing.T) {
	var out bytes.Buffer
	report := &appMCPInspection{SourceValid: true, ConnectorEnabled: true, ContractDigest: strings.Repeat("a", 64), ExecutionDigest: strings.Repeat("b", 64),
		Inventory:     []appMCPInventoryEntry{{Kind: "crud", State: "exposed"}, {Kind: "crud", State: "command-only"}, {Kind: "request_flow", State: "command-only"}},
		ReviewedTools: []map[string]any{{"name": "close_ticket", "effect": "write", "approval": "owner"}, {"name": "list_tickets", "effect": "read"}},
		Unmeasured:    []string{"host_client_acceptance"},
		Warnings:      []string{"command close_ticket: its SQL has no predicate tied to the caller"}}
	if err := writeAppMCPSummary(&out, "check", report); err != nil {
		t.Fatal(err)
	}
	got := out.String()
	for _, want := range []string{
		"mcp check: source valid, 2 reviewed tools\n",
		"tools: close_ticket (write, approval owner), list_tickets (read)\n",
		"inventory: 3 entries (2 crud, 1 request_flow); 2 command-only, 1 exposed\n",
		"warnings: 1\n  - command close_ticket: its SQL has no predicate tied to the caller\n",
		"not checked here: host_client_acceptance\n",
		"benmore mcp check <appdir>",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary lacks %q:\n%s", want, got)
		}
	}
	out.Reset()
	if err := writeAppMCPSummary(&out, "check", &appMCPInspection{SourceValid: true}); err != nil {
		t.Fatal(err)
	}
	if got := out.String(); !strings.Contains(got, "no mcp.yaml: the app declares no connector") || strings.Contains(got, "contract_digest") || !strings.Contains(got, "warnings: none") {
		t.Errorf("summary of an app without mcp.yaml:\n%s", got)
	}
}
