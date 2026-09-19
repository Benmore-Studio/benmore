//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFailedReloadPreservesConfigWorkersAndHandler(t *testing.T) {
	for _, failure := range []string{"workflow syntax", "workflow shape", "schema", "deferred DDL", "user migration"} {
		t.Run(failure, func(t *testing.T) {
			app, cleanup := newTestApp(t)
			defer cleanup()
			app.Stop = make(chan struct{})
			defer func() { close(app.Stop) }()
			oldStop := app.Stop
			oldWorkflows := &WorkflowConfig{Workflows: map[string]*Workflow{"existing": {Name: "existing"}}}
			oldDesign := &DesignConfig{CSS: "none"}
			app.Design, app.Workflows = oldDesign, oldWorkflows
			writeTestFile(t, app.Dir, "app.yaml", "theme: replacement\n")
			switch failure {
			case "workflow syntax":
				writeTestFile(t, app.Dir, "workflows.yaml", "broken: [\n")
				writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE should_not_exist(id INTEGER);")
			case "workflow shape":
				writeTestFile(t, app.Dir, "workflows.yaml", "broken: scalar\n")
			case "schema":
				writeTestFile(t, app.Dir, "schema.sql", "THIS IS INVALID SQL;")
			case "deferred DDL":
				writeTestFile(t, app.Dir, "schema.sql", "CREATE INDEX broken_index ON missing_table(id);")
			case "user migration":
				writeTestFile(t, app.Dir, "migrations/0001_invalid.sql", "THIS IS INVALID SQL;")
			}
			previousHotHandler := hostedHotHandler
			handler := &hotHandler{}
			handler.swap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusAccepted) }))
			hostedHotHandler = handler
			defer func() { hostedHotHandler = previousHotHandler }()

			if err := hotReloadApp(app, false); err == nil {
				t.Fatal("invalid reload reported success")
			}
			if app.Design != oldDesign || app.Workflows != oldWorkflows || app.Stop != oldStop {
				t.Fatal("failed reload published replacement configuration or worker generation")
			}
			select {
			case <-oldStop:
				t.Fatal("failed reload stopped the existing workers")
			default:
			}
			rec := httptest.NewRecorder()
			hostedHotHandler.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
			if rec.Code != http.StatusAccepted {
				t.Fatalf("previous handler no longer serves: %d", rec.Code)
			}
			if failure == "workflow syntax" {
				var count int
				if err := app.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name='should_not_exist'").Scan(&count); err != nil || count != 0 {
					t.Fatalf("invalid workflow reached schema mutation: count=%d err=%v", count, err)
				}
			}
		})
	}
}

func TestWorkflowReloadAcceptsValidReplacementAndIntentionalRemoval(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	writeTestFile(t, app.Dir, "workflows.yaml", `orders:
  table: orders
  field: status
  initial: pending
  transitions:
    pending:
      shipped: {role: admin}
`)
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	if app.Workflows == nil || app.Workflows.Workflows["orders"].Transitions["pending"]["shipped"].Role != "admin" {
		t.Fatalf("valid replacement was not loaded: %#v", app.Workflows)
	}
	if err := os.Remove(filepath.Join(app.Dir, "workflows.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfig(app); err != nil || app.Workflows != nil {
		t.Fatalf("intentional removal failed: workflows=%v err=%v", app.Workflows, err)
	}
}

func TestInvalidWorkflowsRejectedByWriteCheckAndStartup(t *testing.T) {
	for _, source := range []string{"broken: [\n", "broken: scalar\n"} {
		dir := t.TempDir()
		writeTestFile(t, dir, "workflows.yaml", source)
		if msg := ValidateOnWriteIn(dir, "workflows.yaml", source); !strings.Contains(msg, "workflows.yaml") {
			t.Fatalf("write validator missed invalid workflows: %q", msg)
		}
		report := RunCompleteCheck(dir, "workflows.yaml")
		if report.Clean() {
			t.Fatal("app check missed invalid workflows")
		}
		if _, err := loadApp(dir); err == nil || !strings.Contains(err.Error(), "workflows.yaml") {
			t.Fatalf("startup accepted invalid workflows: %v", err)
		}
		if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
			t.Fatalf("invalid workflows reached database initialization: %v", err)
		}
	}
}
