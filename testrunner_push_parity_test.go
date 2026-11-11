//go:build !cli

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"
)

// `benmore test` fails on a file the platform write gate refuses. A flow under
// the reserved /api/v1/ prefix used to load and pass its tests locally, where
// nothing else serves that prefix, while a push to the hosted dev instance
// refused it.
func TestServerTestFailsOnWhatThePushRefuses(t *testing.T) {
	flow := func(path string) string {
		return `on:
  request:
    method: GET
    path: ` + path + `
jobs:
  main:
    steps:
      - run: respond
        with:
          body: {ok: true}
`
	}
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "app.yaml", "auth: {identifier: email}\n")
	writeTestFile(t, dir, "flows/collection.yaml", flow("/api/v1/collection"))
	if gate := ValidateOnWriteIn(dir, "flows/collection.yaml", flow("/api/v1/collection")); !strings.Contains(gate, "reserved prefix") {
		t.Fatalf("the write gate no longer refuses /api/v1/ (got %q); this test assumes it does", gate)
	}
	failures := sourceCheckTestResults(dir)
	if len(failures) != 1 || failures[0].Pass || failures[0].File != "flows/collection.yaml" ||
		!strings.Contains(failures[0].Message, `"/api/v1/"`) || !strings.Contains(failures[0].Message, "write gate refuse") {
		t.Fatalf("benmore test does not fail a flow the push refuses: %+v", failures)
	}
	if testResultsPassed(append(failures, AppTestResult{Test: "passing", Pass: true})) {
		t.Fatal("a run with a source-check failure counted as passed")
	}

	// The name the app moved to passes, and a warning alone is not a failure.
	writeTestFile(t, dir, "flows/collection.yaml", flow("/api/me/collection"))
	if failures := sourceCheckTestResults(dir); len(failures) != 0 {
		t.Fatalf("a flow the push accepts failed the source check: %+v", failures)
	}
}

// A cookie-authenticated JSON step carries the CSRF token in X-CSRF-Token, as
// the browser SDK sends it. Before, only form steps carried a token, so a test
// could reach a CSRF-checked JSON route only over Bearer, which skips CSRF, and
// what a signed-in page sends went untested.
func TestRunnerSendsCSRFOnCookieJSONSteps(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model Note {
  id Int @id @default(autoincrement())
  title String
  user_id Int?
  @@map("notes")
}
`)
	writeTestFile(t, dir, "app.yaml", "auth: {identifier: email}\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)

	file := AppTestFile{Name: "json_csrf", Tests: map[string]AppTestCase{
		"cookie_json": {AsUser: "owner@example.com", Steps: []AppTestStep{
			{API: "POST /api/notes", JSON: map[string]any{"title": "from json"}, Expect: AppTestExpect{Status: 200}},
			{API: "POST /api/notes/batch", JSONArray: []any{map[string]any{"title": "batch one"}}, Expect: AppTestExpect{Status: 200}},
			{SQL: "SELECT id FROM notes WHERE title IN ('from json', 'batch one')", Expect: AppTestExpect{Rows: expectRows(2)}},
		}},
		// Anonymous steps still send nothing: the token is the session's.
		"anon_json": {Anon: true, Steps: []AppTestStep{
			{API: "POST /api/notes", JSON: map[string]any{"title": "anon"}, Expect: AppTestExpect{StatusIn: []int{401, 403}}},
		}},
	}}
	ran := 0
	for _, r := range RunAllTests(app, []AppTestFile{file}, false) {
		if r.File == "SUMMARY" {
			continue
		}
		ran++
		if !r.Pass {
			t.Errorf("%s/%s: %s %+v", r.File, r.Test, r.Message, r.Steps)
		}
	}
	if ran != 2 {
		t.Fatalf("ran %d tests, want 2", ran)
	}
}

func TestServerTestCommandSubprocess(t *testing.T) {
	if os.Getenv("BENMORE_TEST_SERVER_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"benmore", "test"}, os.Args[i+1:]...)
			if !serverDispatch("test") {
				t.Fatal("test command was not dispatched")
			}
			os.Exit(0)
		}
	}
	t.Fatal("missing test arguments")
}

// runServerTestCommand runs `benmore test <args>` in a child process and
// returns its exit code, its stdout decoded as the --json result array, and
// its stderr.
func runServerTestCommand(t *testing.T, args ...string) (int, []AppTestResult, string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], append([]string{"-test.run=^TestServerTestCommandSubprocess$", "--"}, args...)...)
	cmd.Dir = t.TempDir()
	for _, entry := range os.Environ() {
		if !strings.HasPrefix(entry, "BENMORE_") {
			cmd.Env = append(cmd.Env, entry)
		}
	}
	cmd.Env = append(cmd.Env, "BENMORE_TEST_SERVER_TEST=1", "BENMORE_HOME="+t.TempDir(), "BENMORE_TELEMETRY=0")
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	code := 0
	if err := cmd.Run(); err != nil {
		exit, ok := err.(*exec.ExitError)
		if !ok {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	var results []AppTestResult
	if err := json.Unmarshal(stdout.Bytes(), &results); err != nil {
		t.Fatalf("--json stdout is not a result array (%v):\n%s\nstderr:\n%s", err, stdout.String(), stderr.String())
	}
	return code, results, stderr.String()
}

func serverTestSummary(results []AppTestResult) *AppTestResult {
	for i := range results {
		if results[i].File == "SUMMARY" && results[i].Test == "TOTAL" {
			return &results[i]
		}
	}
	return nil
}

// workspaceState reads every file under dir, so a run can be shown to leave
// the workspace exactly as it was.
func workspaceState(t *testing.T, dir string) map[string]string {
	t.Helper()
	state := map[string]string{}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		state[filepath.ToSlash(rel)] = string(data)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return state
}

// `benmore test` refused every linked workspace ("refusing to reset data.db
// ... looks like a deployed app (.benmore/ present)"): cloud deploy and pull
// write .benmore/app, and the test run's own app load wrote .benmore/app_id,
// so even a clean copy was refused on its second run. It now runs on a
// disposable copy of the source and leaves the workspace - its data.db,
// uploads and .benmore/ - exactly as it was.
func TestServerTestRunsInALinkedWorkspaceWithoutTouchingIt(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "app.yaml", "auth: {identifier: email}\n")
	writeTestFile(t, dir, "schema.prisma", "model Note {\n  id Int @id @default(autoincrement())\n  title String\n  user_id Int?\n  @@map(\"notes\")\n}\n")
	writeTestFile(t, dir, "tests/notes.yaml", `create_note:
  as_user: "owner@example.com"
  steps:
    - api: "POST /api/notes"
      data:
        title: "from the test"
      expect:
        status: 200
    - sql: "SELECT id FROM notes"
      expect:
        rows: 1
`)
	writeTestFile(t, dir, ".benmore/app", "fixture-app\n")
	writeTestFile(t, dir, "uploads/kept.txt", "workspace upload")
	db, err := sql.Open("sqlite3", filepath.Join(dir, "data.db"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, user_id INTEGER); INSERT INTO notes (title) VALUES ('workspace row')`); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	before := workspaceState(t, dir)

	for run := 1; run <= 2; run++ {
		code, results, stderr := runServerTestCommand(t, dir, "--app", "--json")
		summary := serverTestSummary(results)
		if code != 0 || summary == nil || !summary.Pass || !strings.Contains(summary.Message, "1/1 tests passed") {
			t.Fatalf("run %d: exit %d summary %+v\nresults %+v\nstderr:\n%s", run, code, summary, results, stderr)
		}
		if after := workspaceState(t, dir); !reflect.DeepEqual(before, after) {
			t.Fatalf("run %d changed the workspace:\nbefore %v\nafter  %v", run, workspacePaths(before), workspacePaths(after))
		}
	}
}

func workspacePaths(m map[string]string) []string {
	keys := mapKeys(m)
	sort.Strings(keys)
	return keys
}

// A run that cannot reach the tests says so in --json: a failed result for the
// step that stopped it and a SUMMARY entry. The refused run used to print only
// the source-check result, so a JSON consumer could not tell nothing ran.
func TestServerTestJSONReportsRunsThatDidNotStart(t *testing.T) {
	t.Run("load failure", func(t *testing.T) {
		dir, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, dir, "app.yaml", "auth: [not, a, mapping]\n")
		code, results, stderr := runServerTestCommand(t, dir, "--json")
		summary := serverTestSummary(results)
		if code != 1 || summary == nil || summary.Pass || !strings.Contains(summary.Message, "did not run") {
			t.Fatalf("exit %d summary %+v results %+v\nstderr:\n%s", code, summary, results, stderr)
		}
		if setup := results[len(results)-2]; setup.Pass || setup.File != "setup" || setup.Test != "load app" {
			t.Fatalf("no failed setup result before the summary: %+v", results)
		}
	})
	// A hosted app instance (the router writes .benmore/server-secret into
	// every instance under the apps directory) is not a place to run tests.
	t.Run("hosted app instance", func(t *testing.T) {
		dir, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, dir, "app.yaml", "auth: {identifier: email}\n")
		writeTestFile(t, dir, ".benmore/server-secret", "secret\n")
		before := workspaceState(t, dir)
		code, results, stderr := runServerTestCommand(t, dir, "--json")
		summary := serverTestSummary(results)
		if code != 1 || summary == nil || summary.Pass || len(results) != 2 || results[0].Test != "hosted app" || !strings.Contains(results[0].Message, "hosted app instance") {
			t.Fatalf("exit %d results %+v\nstderr:\n%s", code, results, stderr)
		}
		if after := workspaceState(t, dir); !reflect.DeepEqual(before, after) {
			t.Fatalf("a refused run changed the hosted app dir: %v", workspacePaths(after))
		}
	})
}

// `benmore test` keeps the app's env.yaml in its copy (the app loads its
// configuration from it, as the in-place run did); every other secret file,
// database, upload and .benmore/ entry stays out, as in verify's copy.
func TestServerTestCopyKeepsOnlyTheAppEnvFile(t *testing.T) {
	src := t.TempDir()
	for _, name := range []string{"app.yaml", "env.yaml", "static/env.yaml", ".env", "secrets.yaml", "server.pem", "data.db", "data.db-wal", "uploads/a.txt", ".benmore/app", "tests/a.yaml"} {
		writeTestFile(t, src, name, "x: y\n")
	}
	dst := filepath.Join(t.TempDir(), "copy")
	if err := copyTestSource(src, dst, true); err != nil {
		t.Fatal(err)
	}
	if got := workspacePaths(workspaceState(t, dst)); !reflect.DeepEqual(got, []string{"app.yaml", "env.yaml", "tests/a.yaml"}) {
		t.Fatalf("copied %v", got)
	}
}
