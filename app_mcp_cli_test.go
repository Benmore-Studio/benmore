//go:build !cli && !windows

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func appMCPCLIReport(t *testing.T, args ...string) (*appMCPInspection, []byte, error) {
	t.Helper()
	var out bytes.Buffer
	err := runAppMCPCLI(args, &out)
	if err != nil {
		return nil, out.Bytes(), err
	}
	dec := json.NewDecoder(bytes.NewReader(out.Bytes()))
	var report appMCPInspection
	if err := dec.Decode(&report); err != nil {
		t.Fatalf("decode CLI report: %v; output=%q", err, out.String())
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		t.Fatalf("expected one JSON report, trailing decode=%v", err)
	}
	return &report, out.Bytes(), nil
}

func TestAppMCPCLIHelpIsAvailableBeforeSourceAccess(t *testing.T) {
	for _, command := range []string{"review", "inspect", "check", "generate"} {
		for _, flag := range []string{"--help", "-h"} {
			var out bytes.Buffer
			if err := runAppMCPCLI([]string{command, ".", flag}, &out); err != nil || !strings.Contains(out.String(), "Usage: benmore mcp "+command) {
				t.Errorf("%s %s: output=%q err=%v", command, flag, out.String(), err)
			}
		}
	}
	var out bytes.Buffer
	if err := runAppMCPCLI(nil, &out); err != nil || !strings.Contains(out.String(), "App-facing MCP source commands") {
		t.Fatalf("top-level help: output=%q err=%v", out.String(), err)
	}
}

func TestAppMCPCLIReviewRequiresAttestationAndChecksBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);")
	lines := strings.Split(appMCPManifestFixture(), "\n")
	var authored []string
	for _, line := range lines {
		if !strings.HasPrefix(line, "contract_digest:") && !strings.HasPrefix(line, "execution_digest:") {
			authored = append(authored, line)
		}
	}
	writeTestFile(t, dir, "mcp.yaml", strings.Join(authored, "\n"))
	original, _ := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if _, err := parseAppMCPManifest(original); err == nil {
		t.Fatal("unsealed manifest accepted by runtime parser")
	}
	if err := runAppMCPCLI([]string{"review", dir}, io.Discard); err == nil {
		t.Fatal("review without explicit attestation accepted")
	}
	report, _, err := appMCPCLIReport(t, "review", dir, "--reviewed")
	if err != nil || !report.SourceValid {
		t.Fatalf("review: %+v %v", report, err)
	}
	if _, err := inspectAppMCPSource(dir); err != nil {
		t.Fatalf("reviewed source fails check: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
		t.Fatalf("review opened app data: %v", err)
	}
	writeTestFile(t, dir, "index.html", "<main>changed source</main>")
	if _, err := inspectAppMCPSource(dir); err == nil {
		t.Fatal("source edit retained old review")
	}
	if _, _, err := appMCPCLIReport(t, "review", dir, "--reviewed"); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "mcp.yaml", string(original))
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE different (id INTEGER PRIMARY KEY);")
	if err := runAppMCPCLI([]string{"review", dir, "--reviewed"}, io.Discard); err == nil {
		t.Fatal("unresolved tool binding reviewed")
	}
	after, _ := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if !bytes.Equal(original, after) {
		t.Fatal("failed review replaced manifest")
	}
	entries, _ := os.ReadDir(dir)
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".mcp-review-") {
			t.Fatal("review left temporary source")
		}
	}
}

func appMCPCLIEntry(t *testing.T, report *appMCPInspection, kind, name string) appMCPInventoryEntry {
	t.Helper()
	for _, entry := range report.Inventory {
		if entry.Kind == kind && entry.Name == name {
			return entry
		}
	}
	t.Fatalf("missing inventory entry %s %q", kind, name)
	return appMCPInventoryEntry{}
}

func TestAppMCPCLIInventoryAndReadOnlyClassification(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);\nCREATE TABLE work_items (id INTEGER PRIMARY KEY);")
	// One read tool, one native write declaration (not exposed in v1) and one command tool.
	manifest, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	update, err := parseAppMCPManifest([]byte(appMCPUpdateManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	manifest.Tools = append(manifest.Tools, update.Tools[0], commandManifest().Tools[0])
	manifestBytes, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "mcp.yaml", string(manifestBytes))
	writeTestFile(t, dir, "flows/complete_item.yaml", commandFixtureForManifest)
	writeTestFile(t, dir, "index.html", "<main>Fixture</main>")
	writeTestFile(t, dir, "static/notes.tsx", "export const Notes = () => null")
	writeTestFile(t, dir, "flows/read.yaml", `on:
  request:
    method: GET
    path: /api/read-notes
    inputs:
      query: {type: text, required: true}
jobs:
  read:
    steps:
      - run: sql
        query: SELECT 1
`)
	writeTestFile(t, dir, "flows/event.yaml", `on:
  event: {table: notes, op: insert}
jobs:
  notify:
    steps:
      - run: sql
        query: SELECT 1
`)
	writeTestFile(t, dir, "cron.yaml", `nightly:
    schedule: '@daily'
    run:
      - sql: SELECT 1
`)
	reviewAppMCPFixture(t, dir)
	report, _, err := appMCPCLIReport(t, "inspect", dir, "--json")
	if err != nil {
		t.Fatal(err)
	}
	if report.Version != 1 || !report.ConnectorEnabled || !report.SourceValid {
		t.Fatalf("report header: %+v", report)
	}
	get := appMCPCLIEntry(t, report, "crud", "GET /api/notes")
	if get.State != "exposed" || !strings.HasPrefix(get.Source, "crud.go:") || !appMCPCLIContainsString(get.Tools, "list_notes") {
		t.Fatalf("reviewed GET inventory: %+v", get)
	}
	for _, pattern := range []string{"POST /api/notes", "PATCH /api/notes", "PATCH /api/notes/", "DELETE /api/notes/", "POST /api/notes/batch", "PATCH /api/notes/batch", "DELETE /api/notes/batch", "POST /api/notes/ingest"} {
		entry := appMCPCLIEntry(t, report, "crud", pattern)
		if entry.State != "command-only" || len(entry.Tools) != 0 {
			t.Errorf("%s unexpectedly exposed: %+v", pattern, entry)
		}
	}

	flow := appMCPCLIEntry(t, report, "request_flow", "read")
	if flow.State != "command-only" || flow.Source != "flows/read.yaml" || flow.Inputs["query"].Type != "text" || !flow.Inputs["query"].Required {
		t.Errorf("request flow inventory/input source: %+v", flow)
	}
	command := appMCPCLIEntry(t, report, "command_flow", "complete_item")
	if command.State != "command" || command.Effect != "write" || command.Approval != "first_party" || command.Binding != "command:complete_item" || len(command.Tools) != 1 || command.Tools[0] != "complete_item" {
		t.Errorf("command flow classification: %+v", command)
	}
	nativeWrite := appMCPCLIEntry(t, report, "native_write_tool", "notes_update_title")
	if nativeWrite.State != "disabled" || nativeWrite.Reason != "v1 exposes writes only through approved commands" {
		t.Errorf("native table.update classification: %+v", nativeWrite)
	}
	event := appMCPCLIEntry(t, report, "on_insert_flow", "event")
	if event.State != "disabled" || event.Source != "flows/event.yaml" {
		t.Errorf("event flow classification: %+v", event)
	}
	cron := appMCPCLIEntry(t, report, "scheduled_job", "nightly")
	if cron.State != "disabled" || cron.Source != "cron.yaml" {
		t.Errorf("cron classification: %+v", cron)
	}
	if entry := appMCPCLIEntry(t, report, "ui_entrypoint", "/"); entry.State != "disabled" {
		t.Errorf("page classification: %+v", entry)
	}
	if entry := appMCPCLIEntry(t, report, "ui_source", "static/notes.tsx"); entry.State != "unresolved" {
		t.Errorf("source classification: %+v", entry)
	}
	upload := appMCPCLIEntry(t, report, "artifact_route", "POST /api/_upload")
	if upload.State != "disabled" {
		t.Errorf("upload artifact classification: %+v", upload)
	}
}

func TestAppMCPCLIAbsentManifestDisablesConnector(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	report, _, err := appMCPCLIReport(t, "inspect", dir, "--json")
	if err != nil {
		t.Fatal(err)
	}
	if report.ConnectorEnabled || !report.SourceValid {
		t.Fatalf("absent manifest status: %+v", report)
	}
}

func TestAppMCPCLIOutputIsDeterministicJSON(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, dir)
	_, first, err := appMCPCLIReport(t, "inspect", dir, "--json")
	if err != nil {
		t.Fatal(err)
	}
	_, second, err := appMCPCLIReport(t, "check", dir)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) {
		t.Fatalf("inspect/check output differs\ninspect: %s\ncheck: %s", first, second)
	}
}

func TestAppMCPCLICheckRejectsDigestDriftAndShadowRoute(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, dir)
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, body TEXT);")
	if _, _, err := appMCPCLIReport(t, "check", dir); err == nil {
		t.Fatal("check accepted source digest drift")
	}
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "mcp.yaml", strings.Replace(appMCPManifestFixture(), "operation: table.list", "operation: table.read", 1))
	writeTestFile(t, dir, "flows/shadow.yaml", `on:
  request: {method: GET, path: /api/notes/:id}
jobs:
  shadow:
    steps:
      - run: sql
        query: SELECT 1
`)
	reviewAppMCPFixture(t, dir)
	if _, _, err := appMCPCLIReport(t, "check", dir); err == nil {
		t.Fatal("check accepted canonical shadow route")
	}
}

func TestAppMCPCLIRejectsInvalidArguments(t *testing.T) {
	for _, args := range [][]string{
		{"unknown", "app"}, {"inspect", "app"}, {"inspect", "app", "--text"},
		{"inspect", "app", "--json", "extra"}, {"check"}, {"check", "app", "extra"},
	} {
		var out bytes.Buffer
		if err := runAppMCPCLI(args, &out); err == nil {
			t.Errorf("accepted args %q", args)
		}
	}
	var help bytes.Buffer
	if err := runAppMCPCLI(nil, &help); err != nil || !strings.Contains(help.String(), "benmore mcp review") {
		t.Fatalf("no-args help: %q %v", help.String(), err)
	}
}

func TestAppMCPCLIPreflightRejectsUndeployableExecutionSources(t *testing.T) {
	blocked := []string{
		"static/.env", "flows/env.yaml", "static/data.db-wal", "flows/.git/config",
		"static/.agents/SKILL.md", "static/screenshots-1/a.png", "flows/env.yaml/child.yaml",
		"static/src/bm.d.ts",
	}
	for _, path := range blocked {
		t.Run(path, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
			writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
			if _, err := reviewAppMCPSource(dir); err != nil {
				t.Fatalf("initial review: %v", err)
			}
			writeTestFile(t, dir, path, "blocked source")
			before, err := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			for _, operation := range []struct {
				name string
				run  func() error
			}{
				{"review", func() error { _, err := reviewAppMCPSource(dir); return err }},
				{"inspect", func() error { _, err := inspectAppMCPSource(dir); return err }},
				{"check", func() error { return runAppMCPCLI([]string{"check", dir}, io.Discard) }},
			} {
				err := operation.run()
				blockedPath := appMCPExpectedProtectedPath(path)
				if err == nil || !strings.Contains(err.Error(), blockedPath) || !strings.Contains(err.Error(), "remove or rename") {
					t.Errorf("%s should identify undeployable %s; got %v", operation.name, path, err)
				}
			}
			after, err := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("preflight changed mcp.yaml: %v", err)
			}
		})
	}
}

func appMCPExpectedProtectedPath(path string) string {
	parts := strings.Split(filepath.ToSlash(path), "/")
	for i := 1; i < len(parts); i++ {
		segment := parts[i]
		if sourceManifestExcluded(segment, true) || sourceManifestExcluded(segment, false) {
			return strings.Join(parts[:i+1], "/")
		}
	}
	return filepath.ToSlash(path)
}

func TestAppMCPCLICommandsDoNotMutateAppFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, dir)
	writeTestFile(t, dir, "data.db", "sentinel database bytes")
	writeTestFile(t, dir, "env.yaml", "SENTINEL: fixture-only")
	writeTestFile(t, dir, ".benmore/marker", "sentinel marker")
	before := appMCPCLIFileSnapshot(t, dir)
	for _, args := range [][]string{{"inspect", dir, "--json"}, {"check", dir}} {
		if _, _, err := appMCPCLIReport(t, args...); err != nil {
			t.Fatalf("%v: %v", args, err)
		}
	}
	if after := appMCPCLIFileSnapshot(t, dir); !appMCPCLIFilesEqual(before, after) {
		t.Fatalf("CLI mutated app files\nbefore: %#v\nafter: %#v", before, after)
	}
}

func appMCPCLIFileSnapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	if err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		sum := sha256.Sum256(data)
		files[filepath.ToSlash(rel)] = hex.EncodeToString(sum[:])
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return files
}

func appMCPCLIFilesEqual(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

func appMCPCLIContainsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

// a Finder/AppleDouble sidecar in static/ or flows/ is never
// deployed or loaded, so review, inspect and check ignore it and the sealed
// digests stay identical with or without it.
func TestAppMCPCLIIgnoresMetadataSidecars(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, dir)
	sealed, err := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"static/.DS_Store", "flows/._a.yaml", "static/img/Thumbs.db"} {
		writeTestFile(t, dir, p, "junk")
	}
	if _, err := inspectAppMCPSource(dir); err != nil {
		t.Fatalf("inspect: %v", err)
	}
	if err := runAppMCPCLI([]string{"check", dir}, io.Discard); err != nil {
		t.Fatalf("check with sidecars: %v", err)
	}
	reviewAppMCPFixture(t, dir)
	resealed, _ := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if !bytes.Equal(sealed, resealed) {
		t.Fatal("sidecars changed the sealed digests")
	}
}
