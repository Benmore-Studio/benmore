//go:build !cli && !windows

package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func reviewArraySpelling(source, field, spelling string) string {
	line := field + ": []\n"
	if spelling == "omitted" {
		return strings.Replace(source, line, "", 1)
	}
	return strings.Replace(source, line, field+": "+spelling+"\n", 1)
}

func reviewRoundtripFixture(t *testing.T, dir, source string) *appMCPInspection {
	t.Helper()
	writeTestFile(t, dir, "mcp.yaml", source)
	manifestPath := filepath.Join(dir, "mcp.yaml")
	if err := os.Chmod(manifestPath, 0600); err != nil {
		t.Fatal(err)
	}
	before := appMCPCLIFileSnapshot(t, dir)
	report, _, err := appMCPCLIReport(t, "review", dir, "--reviewed")
	if err != nil || !report.SourceValid {
		t.Fatalf("review must seal its own serialized manifest: report=%+v err=%v", report, err)
	}
	sealed, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := inspectAppMCPSource(dir); err != nil {
		t.Fatalf("review output failed read-only source check: %v", err)
	}
	if _, _, err := appMCPCLIReport(t, "review", dir, "--reviewed"); err != nil {
		t.Fatalf("second review: %v", err)
	}
	again, err := os.ReadFile(manifestPath)
	if err != nil || !bytes.Equal(sealed, again) {
		t.Fatalf("unchanged reviewed source must reseal identically: %v", err)
	}
	after := appMCPCLIFileSnapshot(t, dir)
	delete(before, "mcp.yaml")
	delete(after, "mcp.yaml")
	if !appMCPCLIFilesEqual(before, after) {
		t.Fatalf("review changed source or opened a database: before=%v after=%v", before, after)
	}
	if info, err := os.Stat(manifestPath); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("review lost manifest permissions: %v %v", info, err)
	}
	return report
}

func TestAppMCPCLIReviewOptionalArraysRoundtrip(t *testing.T) {
	for _, resources := range []string{"omitted", "null", "[]"} {
		for _, connections := range []string{"omitted", "null", "[]"} {
			t.Run(resources+"_resources_"+connections+"_connections", func(t *testing.T) {
				dir := t.TempDir()
				writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
				source := reviewArraySpelling(appMCPManifestFixture(), "resources", resources)
				source = reviewArraySpelling(source, "connections", connections)
				if resources == "null" || connections == "null" {
					reviewRoundtripRefusesNull(t, dir, source)
					return
				}
				report := reviewRoundtripFixture(t, dir, source)
				if entry := appMCPCLIEntry(t, report, "crud", "GET /api/notes"); entry.State != "exposed" {
					t.Fatalf("native read binding changed: %+v", entry)
				}
			})
		}
	}
	for _, tools := range []string{"omitted", "null", "[]"} {
		t.Run(tools+"_tools", func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
			source := "version: 1\nconnector: {id: fixture, name: Fixture, version: '1'}\ntools: []\nresources: []\nconnections: []\n"
			if tools == "null" {
				reviewRoundtripRefusesNull(t, dir, reviewArraySpelling(source, "tools", tools))
				return
			}
			reviewRoundtripFixture(t, dir, reviewArraySpelling(source, "tools", tools))
		})
	}
}

func reviewRoundtripRefusesNull(t *testing.T, dir, source string) {
	t.Helper()
	writeTestFile(t, dir, "mcp.yaml", source)
	before := appMCPCLIFileSnapshot(t, dir)
	if err := runAppMCPCLI([]string{"review", dir, "--reviewed"}, io.Discard); err == nil || !strings.Contains(err.Error(), "cannot be null") {
		t.Fatalf("explicit null must retain the strict manifest refusal: %v", err)
	}
	if after := appMCPCLIFileSnapshot(t, dir); !appMCPCLIFilesEqual(before, after) {
		t.Fatal("invalid null declaration changed source")
	}
}

func TestAppMCPCLIReviewCommandOptionalArraysRoundtrip(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE work_items (id INTEGER PRIMARY KEY, title TEXT);")
	writeTestFile(t, dir, "flows/complete_item.yaml", commandFixtureForManifest)
	data, err := yaml.Marshal(commandManifest())
	if err != nil {
		t.Fatal(err)
	}
	source := reviewArraySpelling(reviewArraySpelling(string(data), "resources", "omitted"), "connections", "omitted")
	report := reviewRoundtripFixture(t, dir, source)
	entry := appMCPCLIEntry(t, report, "command_flow", "complete_item")
	if entry.State != "command" || entry.Approval != "first_party" || entry.Effect != "write" {
		t.Fatalf("review changed private command classification: %+v", entry)
	}
}

func TestAppMCPCLIReviewPreservesSealedArrayContractsUntilExplicitReview(t *testing.T) {
	for _, spelling := range []string{"omitted", "[]"} {
		t.Run(spelling, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
			source := reviewArraySpelling(reviewArraySpelling(appMCPManifestFixture(), "resources", spelling), "connections", spelling)
			manifest, err := parseAppMCPManifest([]byte(source))
			if err != nil {
				t.Fatal(err)
			}
			contract, execution, err := appMCPDigests(dir, manifest)
			if err != nil {
				t.Fatal(err)
			}
			// Preserve the original wire spelling: marshaling here would hide the bug.
			source = strings.Replace(source, strings.Repeat("a", 64), contract, 1)
			source = strings.Replace(source, strings.Repeat("b", 64), execution, 1)
			writeTestFile(t, dir, "mcp.yaml", source)
			before := appMCPCLIFileSnapshot(t, dir)
			report, err := inspectAppMCPSource(dir)
			if err != nil || report.ContractDigest != contract || report.ExecutionDigest != execution {
				t.Fatalf("read-only load invalidated an existing sealed contract: %+v %v", report, err)
			}
			if after := appMCPCLIFileSnapshot(t, dir); !appMCPCLIFilesEqual(before, after) {
				t.Fatal("inspection rewrote existing sealed source")
			}
			if err := runAppMCPCLI([]string{"review", dir}, io.Discard); err == nil {
				t.Fatal("review without attestation accepted")
			}
			if after := appMCPCLIFileSnapshot(t, dir); !appMCPCLIFilesEqual(before, after) {
				t.Fatal("unattested review changed existing sealed source")
			}
			reviewRoundtripFixture(t, dir, source)
		})
	}
}

func TestAppMCPCLIReviewSerializationRetainsSchemaValues(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	source := strings.Replace(appMCPManifestFixture(), "input_schema: {type: object, additionalProperties: false}", `input_schema:
      type: object
      additionalProperties: false
      required: []
      properties:
        limit: {type: integer, minimum: 0, maximum: 9007199254740991, enum: [0, 9007199254740991]}
        label: {type: [string, "null"], enum: ["1", null, "2026-10-21"], maxLength: 40}
        options: {type: object, additionalProperties: false, properties: {}, required: []}
        ratio: {type: number, minimum: -0.25, maximum: 1.5, enum: [0.5, 1]}`, 1)
	source = strings.Replace(source, "description: Read reviewed note fields", "description: Read reviewed note fields\n    labels: {}\n    review_changes: []", 1)
	before, err := parseAppMCPManifestForReview([]byte(source))
	if err != nil {
		t.Fatal(err)
	}
	before.ExecutionSources = appMCPExecutionSourcesRuntime
	wantDigest, err := appMCPContractDigest(before)
	if err != nil {
		t.Fatal(err)
	}
	report := reviewRoundtripFixture(t, dir, source)
	if report.ContractDigest != wantDigest {
		t.Fatalf("schema normalization changed contract values: want %s got %s", wantDigest, report.ContractDigest)
	}
}

func TestAppMCPCLIReviewSerializationFailurePreservesSource(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE different (id INTEGER PRIMARY KEY);")
	source := reviewArraySpelling(appMCPManifestFixture(), "resources", "omitted")
	writeTestFile(t, dir, "mcp.yaml", source)
	writeTestFile(t, dir, "index.html", "<main>Unchanged</main>")
	before := appMCPCLIFileSnapshot(t, dir)
	if err := runAppMCPCLI([]string{"review", dir, "--reviewed"}, io.Discard); err == nil {
		t.Fatal("review accepted unresolved source binding")
	}
	if after := appMCPCLIFileSnapshot(t, dir); !appMCPCLIFilesEqual(before, after) {
		t.Fatal("failed review mutated app source, created a DB, or left a temporary manifest")
	}
}
