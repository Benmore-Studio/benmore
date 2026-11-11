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

const sameTableSchema = `model Order {
  id            Int      @id @default(autoincrement())
  title         String   @default("")
  status        String   @default("draft")
  paymentStatus String   @default("unpaid") @map("payment_status")
  userId        Int      @map("user_id")
  createdAt     DateTime @default(now()) @map("created_at")
  updatedAt     DateTime @default(now()) @updatedAt @map("updated_at")

  @@map("orders")
}

model Invoice {
  id        Int      @id @default(autoincrement())
  status    String   @default("unpaid")
  userId    Int      @map("user_id")
  updatedAt DateTime @default(now()) @updatedAt @map("updated_at")

  @@map("invoices")
}
`

const sameTableOneWorkflow = `fulfilment:
  table: orders
  field: status
  initial: draft
  states: [draft, shipped]
  transitions:
    draft:
      shipped: {}
`

// sameTableSecondWorkflow is a second state machine on the table named table.
func sameTableSecondWorkflow(table string) string {
	return `payment:
  table: ` + table + `
  field: payment_status
  initial: unpaid
  states: [unpaid, paid]
  transitions:
    unpaid:
      paid: { role: admin }
`
}

func sameTableApp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: two workflows one table\nauth:\n  identifier: email\n")
	writeTestFile(t, dir, "schema.prisma", sameTableSchema)
	return dir
}

// The write gate, `benmore check` and the loader all refuse a second workflow
// on a table. It used to pass both gates and then panic http.ServeMux at the
// next reload and at every start (the transition routes were registered once
// per workflow), so the app could not run again until the file was fixed.
func TestSecondWorkflowOnATableIsRefusedByWriteGateCheckAndLoad(t *testing.T) {
	for _, table := range []string{"orders", "Orders", "ORDERS"} {
		t.Run(table, func(t *testing.T) {
			dir := sameTableApp(t)
			source := sameTableOneWorkflow + sameTableSecondWorkflow(table)

			gate := ValidateOnWriteIn(dir, "workflows.yaml", source)
			for _, want := range []string{"workflows.yaml", "fulfilment", "payment", "orders", "one workflow per table"} {
				if !strings.Contains(gate, want) {
					t.Fatalf("write gate refusal does not mention %q: %q", want, gate)
				}
			}

			writeTestFile(t, dir, "workflows.yaml", source)
			report := RunSourceCheck(dir, "workflows.yaml")
			found := false
			for _, f := range report.Findings {
				if f.Severity == "error" && f.File == "workflows.yaml" && strings.Contains(f.Message, "one workflow per table") {
					found = true
				}
			}
			if !found {
				t.Fatalf("benmore check did not report the second workflow: %+v", report.Findings)
			}

			app, err := loadApp(dir)
			if app != nil {
				app.Shutdown()
			}
			if err == nil || !strings.Contains(err.Error(), "one workflow per table") {
				t.Fatalf("loading the app must fail with the refusal, got: %v", err)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(statErr) {
				t.Fatalf("the refused workflows.yaml reached database initialization: %v", statErr)
			}
		})
	}
}

// One workflow per table on two tables is the supported shape and stays so.
func TestWorkflowsOnDifferentTablesAreAccepted(t *testing.T) {
	dir := sameTableApp(t)
	source := sameTableOneWorkflow + sameTableSecondWorkflow("invoices")
	source = strings.Replace(source, "field: payment_status", "field: status", 1)
	if gate := ValidateOnWriteIn(dir, "workflows.yaml", source); gate != "" {
		t.Fatalf("write gate refused one workflow per table: %s", gate)
	}
	writeTestFile(t, dir, "workflows.yaml", source)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	mux, err := buildAppMuxChecked(app, false, "https://fixture.example.com")
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/api/orders/1/transitions", "/api/invoices/1/transitions"} {
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://fixture.example.com"+path, nil))
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("GET %s: want the transition route's 401 for an anonymous caller, got %d", path, rec.Code)
		}
	}
}

// A reload that brings in a second workflow on a table is rejected like any
// other malformed workflows.yaml: before the database, the published
// configuration or the workers change, with the previous handler serving.
func TestReloadWithSecondWorkflowOnATableKeepsThePreviousApp(t *testing.T) {
	dir := sameTableApp(t)
	writeTestFile(t, dir, "workflows.yaml", sameTableOneWorkflow)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	handler := &hotHandler{}
	handler.swap(wrapMiddleware(buildAppMux(app, false, "https://fixture.example.com"), app, false))
	previous := hostedHotHandler
	hostedHotHandler = handler
	t.Cleanup(func() { hostedHotHandler = previous })

	transitions := func() int {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://fixture.example.com/api/orders/1/transitions", nil))
		return rec.Code
	}
	if code := transitions(); code != http.StatusUnauthorized {
		t.Fatalf("before the reload: want the transition route's 401, got %d", code)
	}

	oldWorkflows, oldStop := app.Workflows, app.Stop
	generation := app.reloadGeneration.Load()
	writeTestFile(t, dir, "workflows.yaml", sameTableOneWorkflow+sameTableSecondWorkflow("orders"))

	err = hotReloadApp(app, false)
	if err == nil || !strings.Contains(err.Error(), "one workflow per table") {
		t.Fatalf("the reload must be rejected with the refusal, got: %v", err)
	}
	if app.Workflows != oldWorkflows || len(app.Workflows.Workflows) != 1 {
		t.Fatalf("the rejected reload published its workflows: %+v", app.Workflows)
	}
	if app.Stop != oldStop {
		t.Fatal("the rejected reload retired the worker generation")
	}
	select {
	case <-oldStop:
		t.Fatal("the rejected reload stopped the running workers")
	default:
	}
	if app.reloadGeneration.Load() != generation {
		t.Fatal("the rejected reload advanced the reload generation")
	}
	if code := transitions(); code != http.StatusUnauthorized {
		t.Fatalf("after the rejected reload the previous handler must still serve the transition route, got %d", code)
	}

	// Fixing the file reloads normally.
	writeTestFile(t, dir, "workflows.yaml", sameTableOneWorkflow)
	if err := hotReloadApp(app, false); err != nil {
		t.Fatalf("reload of the corrected file: %v", err)
	}
	if app.reloadGeneration.Load() != generation+1 {
		t.Fatal("the corrected reload did not complete")
	}
}

// The fixture app, run as CI runs every testdata fixture (`benmore test
// --app` on a copy): the source check refuses workflows.yaml and the load is
// a failed setup step, exactly the failures tests/expected-failures.txt
// lists. The runner used to panic on it.
func TestSameTableFixtureAppIsRefusedNotCrashed(t *testing.T) {
	fixture := filepath.Join("testdata", "workflow_same_table_refused")
	listed, err := os.ReadFile(filepath.Join(fixture, "tests", "expected-failures.txt"))
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]bool{}
	for _, line := range strings.Fields(string(listed)) {
		expected[line] = true
	}

	results, runErr := runServerTestsOnCopy(fixture, "app")
	if runErr == nil || !strings.Contains(runErr.Error(), "one workflow per table") {
		t.Fatalf("the fixture must fail to load with the refusal, got: %v", runErr)
	}
	failed := map[string]bool{}
	for _, r := range results {
		if r.File == "SUMMARY" || r.Pass {
			continue
		}
		if !expected[r.File] {
			t.Fatalf("unexpected failure %s / %s: %s", r.File, r.Test, r.Message)
		}
		if !strings.Contains(r.Message, "one workflow per table") {
			t.Fatalf("%s failed for another reason: %s", r.File, r.Message)
		}
		failed[r.File] = true
	}
	for file := range expected {
		if !failed[file] {
			t.Fatalf("expected %s to fail, results: %+v", file, results)
		}
	}
}
