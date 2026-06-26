//go:build !cli

package main

// Tests for the unified RunCompleteCheck - the single entry point
// shared by `benmore check` (CLI) and the post-write loop in the
// MCP. Goal: writing a broken file should surface every related
// issue in one report, ranked by severity, with prescriptive
// migrations in each message.

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeApp(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		full := filepath.Join(dir, name)
		os.MkdirAll(filepath.Dir(full), 0755)
		if err := os.WriteFile(full, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// Orphaned tables (in DB, no `model` in schema.prisma) were previously
// silently suppressed in RunCompleteCheck - the "informational only"
// justification didn't hold up: auto-CRUD still mounts /api/<table>
// against them, which can shadow or panic-collide with a flow at the
// same path, and agents that hit an unexpected table in describe()
// hallucinate explanations ("framework template inference"). Now
// surface as warnings with a prescriptive fix.
func TestRunCompleteCheck_OrphanedTableSurfacedAsWarning(t *testing.T) {
	dir := writeApp(t, map[string]string{
		"app.yaml": `seo:
  site_name: T`,
		"schema.prisma": `model Note {
  id    Int    @id @default(autoincrement())
  title String
}`,
	})
	// Open the live DB the app will hit and create an extra table
	// that no model declares. This simulates the "agent removed
	// model Shipment from schema.prisma, but Prisma migrations are
	// additive so the shipments table sticks around" footgun.
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE shipments (id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT)`); err != nil {
		t.Fatal(err)
	}
	db.Close()

	rpt := RunCompleteCheck(dir, "")

	var found bool
	for _, f := range rpt.Findings {
		if f.Source == "drift" && strings.Contains(f.Message, "extra_table") && strings.Contains(f.Message, "shipments") {
			found = true
			if f.Severity != "warning" {
				t.Errorf("orphan table should be warning, got severity=%q", f.Severity)
			}
			if !strings.Contains(f.Message, "prisma_prune") {
				t.Errorf("orphan warning should suggest prisma_prune, got: %s", f.Message)
			}
		}
	}
	if !found {
		t.Errorf("expected extra_table warning for shipments, got:\n%s", FormatReport(rpt))
	}
}

func TestRunCompleteCheck_CleanApp(t *testing.T) {
	dir := writeApp(t, map[string]string{
		"app.yaml": `seo:
  site_name: T
theme: zinc`,
		"schema.prisma": `model Note {
  id    Int    @id @default(autoincrement())
  title String
}`,
	})
	rpt := RunCompleteCheck(dir, "")
	if !rpt.Clean() {
		t.Errorf("expected clean, got errors:\n%s", FormatReport(rpt))
	}
}

func TestRunCompleteCheck_BadPrismaSurfacesSyntaxError(t *testing.T) {
	dir := writeApp(t, map[string]string{
		"app.yaml": `seo:
  site_name: T`,
		"schema.prisma": `model Note {
  id missing_type_keyword @id
`, /* unclosed brace */
	})
	rpt := RunCompleteCheck(dir, "")
	if rpt.Clean() {
		t.Fatal("expected errors for unclosed model")
	}
	found := false
	for _, f := range rpt.Findings {
		if f.Source == "syntax" && f.File == "schema.prisma" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected syntax error on schema.prisma, got:\n%s", FormatReport(rpt))
	}
}

func TestRunCompleteCheck_MultipleErrorsAtOnce(t *testing.T) {
	// Goal: a multi-file mistake produces one finding per file, not
	// just the first one. The agent should see everything in one
	// response so they can fix in one turn.
	dir := writeApp(t, map[string]string{
		"app.yaml": `made_up_key: yes`,
		"hooks.yaml": `on_create:
  notes:
    - sql: SELECT 1`,
		"schema.prisma": `model Note {
  id Int @id @default(autoincrement())
  title String
}`,
	})
	rpt := RunCompleteCheck(dir, "")
	if rpt.Errors < 2 {
		t.Errorf("expected >= 2 errors, got %d:\n%s", rpt.Errors, FormatReport(rpt))
	}
	// Verify each error has prescriptive content.
	for _, f := range rpt.Findings {
		if f.Severity != "error" {
			continue
		}
		if len(f.Message) < 30 {
			t.Errorf("error message too short to be actionable: %q", f.Message)
		}
	}
}

func TestRunCompleteCheck_CrossFileWarning(t *testing.T) {
	// hooks.yaml references a table that doesn't exist in
	// schema.prisma - that's a warning, NOT an error (the agent
	// might be writing schema next).
	dir := writeApp(t, map[string]string{
		"schema.prisma": `model Note {
  id Int @id @default(autoincrement())
}`,
		"hooks.yaml": `on_insert:
  contacts:
    - sql: SELECT 1`,
	})
	rpt := RunCompleteCheck(dir, "")
	if rpt.Errors > 0 {
		t.Errorf("orphan ref should be warning, not error:\n%s", FormatReport(rpt))
	}
	if rpt.Warnings == 0 {
		t.Errorf("expected cross-file warning, got none:\n%s", FormatReport(rpt))
	}
}

func TestRunCompleteCheck_FormatReport(t *testing.T) {
	// FormatReport is the CLI-facing renderer. Verify both clean and
	// dirty paths produce sensible strings.
	clean := FormatReport(CheckReport{})
	if !strings.Contains(clean, "clean") {
		t.Errorf("clean report should mention 'clean', got: %s", clean)
	}
	dirty := FormatReport(CheckReport{
		Errors:   1,
		Findings: []CheckFinding{{Severity: "error", Source: "syntax", File: "x.html", Message: "bad"}},
	})
	if !strings.Contains(dirty, "1 error") || !strings.Contains(dirty, "x.html") {
		t.Errorf("dirty report missing fields: %s", dirty)
	}
}

func TestAgentDocs_LegacyTopicsRedirectToBuild(t *testing.T) {
	// We collapsed 17 topics into one. Calling help with any of the
	// legacy names must still return the `build` body - back-compat
	// for older client code or callers who remember the old names.
	// ("deploy" is no longer legacy - it grew back into its own doc
	// with the cloud edition.)
	for _, legacy := range []string{
		"auth", "pages", "queries", "directives", "flows", "hooks",
		"workflows", "schema", "security", "quickstart", "realtime",
		"gotchas", "overview", "cli", "mcp",
	} {
		body := AgentDocs(legacy)
		if body == "" {
			t.Errorf("legacy topic %q resolved to empty body", legacy)
			continue
		}
		// `build`'s H1 is "# Build a Benmore app".
		if !strings.Contains(body, "Build a Benmore app") {
			preview := body
			if len(preview) > 200 {
				preview = preview[:200]
			}
			t.Errorf("legacy topic %q didn't redirect to build, got:\n%s", legacy, preview)
		}
	}
}

func TestAgentDocs_TopicsList(t *testing.T) {
	// After consolidation: `build` (the one app-building guide) plus
	// `deploy` (the cloud-edition ship guide, added with the open-core
	// split). A new topic is a deliberate act - update this list.
	topics := AgentDocsTopics()
	want := []string{"build", "deploy"}
	if len(topics) != len(want) {
		t.Fatalf("expected topics %v, got %v", want, topics)
	}
	for i := range want {
		if topics[i] != want[i] {
			t.Fatalf("expected topics %v, got %v", want, topics)
		}
	}
}
