//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// ===== App Test Types =====

// AppTestFile represents a collection of named test cases (from YAML or generated).
type AppTestFile struct {
	Name  string // filename without extension, or "_framework_*" for generated
	Tests map[string]AppTestCase
}

// AppTestCase represents a single named test case.
type AppTestCase struct {
	Setup  []AppTestSetup `yaml:"setup"`
	Steps  []AppTestStep  `yaml:"steps"`
	Users  []AppTestUser  `yaml:"users"` // pre-create these users before running steps (for multi-actor tests)
	AsUser string         `yaml:"as_user"`
	AsRole string         `yaml:"as_role"` // "admin" to create user with admin role (default: "user")
	Anon   bool           `yaml:"anon"`    // true = no auth, no CSRF injection
	// Skip, set only by the framework test generator, is why it could not
	// build this journey for the app (a required parent the test identity
	// cannot create, a column no client may set). The runner reports the
	// case as skipped with that reason instead of running it.
	Skip string `yaml:"-"`
	// Problem, set when the test is read from its file, is why the runner
	// refuses it (a key it does not read, no steps, a step with no action:
	// testrunner_strict.go). The runner fails the case with that reason
	// instead of running it.
	Problem string `yaml:"-"`
}

// AppTestSetup is a setup step (SQL or seed data).
type AppTestSetup struct {
	SQL string `yaml:"sql"`
}

// AppTestStep is a single test action + assertions.
type AppTestStep struct {
	// Action: exactly one of these. The `step` tag marks a field as an action
	// and names the kind of step it makes; an `expect` key is checked only by
	// the kind its own `step` tag names (AppTestExpect, testrunner_strict.go).
	API     string         `yaml:"api" step:"http"`          // "POST /api/contacts" or "GET /api/contacts"
	Get     string         `yaml:"get" step:"http"`          // shorthand for GET
	Post    string         `yaml:"post" step:"http"`         // shorthand for POST
	SQL     string         `yaml:"sql" step:"sql"`           // execute SQL and check results
	Flush   string         `yaml:"flush" step:"flush"`       // drain async queue: "jobs" flushes the job worker, "scheduled" runs one scheduled-task sweep
	SetAuth string         `yaml:"set_auth" step:"set_auth"` // switch Bearer token: "{{my_token}}" or "none" for anonymous
	Data    map[string]any `yaml:"data"`                     // form data for POST/PATCH
	JSON    map[string]any `yaml:"json"`                     // JSON object body for POST/PATCH

	// JSONArray sends a raw JSON array body (e.g., for batch endpoints)
	JSONArray []any `yaml:"json_array"`

	// NDJSON sends newline-delimited JSON (one object per line, for streaming ingest)
	NDJSON []map[string]any `yaml:"ndjson"`

	// Files sends a multipart/form-data body: one file part per entry (form
	// field name -> file) plus the Data fields. `files: {}` sends a multipart
	// body with fields only.
	Files map[string]AppTestFilePart `yaml:"files"`

	// Modifiers
	Bearer bool              `yaml:"bearer"` // use Bearer token instead of cookie
	Save   map[string]string `yaml:"save"`   // capture response fields as named variables. e.g., save: {contact_id: "id", token: "token"}

	// Assertions
	Expect AppTestExpect `yaml:"expect"`

	// DurationAttempts, set only by the framework test generator (it is not a
	// key of a test file), makes `expect.max_duration` the bound on the
	// FASTEST of up to this many requests: a request that passes everything
	// else and only took too long is sent again, and the step passes at the
	// first one within the bound. The time of one request is the handler's
	// work plus whatever the machine was doing at that moment, so a single
	// measurement fails a cheap endpoint on a busy machine; a handler that is
	// really slow is slow on every request and still fails.
	DurationAttempts int `yaml:"-"`
}

// AppTestFilePart is one file of a `files:` step.
type AppTestFilePart struct {
	Name    string `yaml:"name"`    // file name sent with the part, e.g. "scan.txt"
	Content string `yaml:"content"` // the file's bytes, as text
}

// AppTestExpect defines what to assert about the response. The `step` tag
// names the kind of step (AppTestStep) that checks the key; on a step of any
// other kind the key is never looked at, so the runner refuses it there.
type AppTestExpect struct {
	Status      int               `yaml:"status" step:"http"`
	StatusIn    []int             `yaml:"status_in" step:"http"` // any-of acceptable statuses (access-controlled endpoints)
	Redirect    string            `yaml:"redirect" step:"http"`
	Contains    any               `yaml:"contains" step:"http"`     // string or []string
	NotContains any               `yaml:"not_contains" step:"http"` // string or []string
	JSONField   map[string]any    `yaml:"json" step:"http"`         // exact field match
	JSONLength  *int              `yaml:"json_length" step:"http"`  // array length; nil = not checked, 0 = empty
	Rows        *int              `yaml:"rows" step:"sql"`          // for SQL steps; nil = not checked, 0 = no rows
	Headers     map[string]string `yaml:"headers" step:"http"`
	MaxDuration string            `yaml:"max_duration" step:"http"` // e.g., "5ms", "100ms"
}

// expectContains returns the contains values as a string slice.
func expectContains(v any) []string {
	if v == nil {
		return nil
	}
	switch val := v.(type) {
	case string:
		if val == "" {
			return nil
		}
		return []string{val}
	case []any:
		var out []string
		for _, item := range val {
			if s, ok := item.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return val
	}
	return nil
}

// AppTestResult represents the outcome of one test case.
type AppTestResult struct {
	File     string              `json:"file"`
	Test     string              `json:"test"`
	Pass     bool                `json:"pass"`
	Skipped  bool                `json:"skipped,omitempty"` // not run; Message says why (Pass stays true)
	Message  string              `json:"message,omitempty"`
	Duration string              `json:"duration,omitempty"`
	Steps    []AppTestStepResult `json:"steps,omitempty"`
	// Warnings are what the test did that its author may not have meant and
	// that does not fail it (unsavedStepVarWarning).
	Warnings []string `json:"warnings,omitempty"`
}

// AppTestStepResult is the result of one step within a test.
type AppTestStepResult struct {
	Action  string `json:"action"`
	Pass    bool   `json:"pass"`
	Message string `json:"message,omitempty"`
}

// ===== Unified Test Runner =====

// RunAllTests runs both generated framework tests and developer-written YAML tests.
// Developer tests run first so their test users get predictable auto-increment IDs.
//
// A tests/ file the runner cannot load is a failed result in every mode, also
// when includeDisk leaves the app's own tests out (`benmore test --framework`):
// it used to be skipped without a word, so the run printed the other files and
// exited 0. So is a test the runner cannot read in full (testrunner_strict.go).
func RunAllTests(app *App, generated []AppTestFile, includeDisk bool) []AppTestResult {
	var testFiles []AppTestFile

	// Developer tests first (predictable user IDs)
	diskFiles, results := loadTestFilesFromDisk(app.Dir)
	if includeDisk {
		testFiles = append(testFiles, diskFiles...)
	} else {
		// The app's own tests are left out, but one the runner refuses (a key
		// it does not read, no steps) is a failed result in every mode, like
		// a file it cannot load.
		results = append(results, unreadTestResults(diskFiles)...)
	}

	// Framework tests second
	testFiles = append(testFiles, generated...)

	if len(testFiles) == 0 {
		return append(results, AppTestResult{
			File: "tests/", Test: "discovery", Pass: false,
			Message: "No tests to run",
		})
	}

	// Start test server
	handler, err := testServerHandler(app)
	if err != nil {
		return append(results, AppTestResult{Test: "server", Pass: false, Message: "Cannot start test server: " + err.Error()})
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return append(results, AppTestResult{Test: "server", Pass: false, Message: "Cannot start test server"})
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()

	server := &http.Server{Addr: fmt.Sprintf("127.0.0.1:%d", port), Handler: handler}
	go server.ListenAndServe()
	defer server.Close()
	time.Sleep(300 * time.Millisecond)

	base := fmt.Sprintf("http://localhost:%d", port)

	// Run tests
	for _, tf := range testFiles {
		for testName, tc := range tf.Tests {
			result := runSingleTest(app, base, tf.Name, testName, tc)
			results = append(results, result)
		}
	}

	return append(results, testRunSummary(results))
}

// testRunSummary is the SUMMARY entry of a run: what `--json` output carries
// where the text output prints its first line, counted the same way
// (testResultCounts).
func testRunSummary(results []AppTestResult) AppTestResult {
	total, passed := testResultCounts(results)
	message := fmt.Sprintf("%d/%d tests passed", passed, total)
	if skipped := testResultSkipped(results); skipped > 0 {
		message += fmt.Sprintf(", %d skipped", skipped)
	}
	return AppTestResult{File: "SUMMARY", Test: "TOTAL", Pass: passed == total, Message: message}
}

// RunAppTests discovers and runs developer-written test files from tests/ directory.
func RunAppTests(app *App) []AppTestResult {
	diskFiles, unloaded := loadTestFilesFromDisk(app.Dir)
	if len(diskFiles) == 0 && len(unloaded) == 0 {
		return []AppTestResult{{
			File: "tests/", Test: "discovery", Pass: false,
			Message: fmt.Sprintf("No tests/ directory or no .yaml files in %s", app.Dir),
		}}
	}
	return RunAllTests(app, nil, true)
}

func printTestResults(results []AppTestResult, asJSON bool) {
	if asJSON {
		b, err := json.MarshalIndent(results, "", "  ")
		if err != nil {
			fmt.Printf(`{"error":%q}`+"\n", err.Error())
			return
		}
		fmt.Println(string(b))
		return
	}
	writeTestResults(os.Stdout, results)
}

// writeTestResults writes the text form of a run: the counts, then a line for
// each result with what failed and what it warns about under it.
func writeTestResults(w io.Writer, results []AppTestResult) {
	total, passed := testResultCounts(results)
	counts := fmt.Sprintf("test: %d/%d passed", passed, total)
	if skipped := testResultSkipped(results); skipped > 0 {
		counts += fmt.Sprintf(", %d skipped", skipped)
	}
	warnings := 0
	for _, r := range results {
		warnings += len(r.Warnings)
	}
	if warnings == 1 {
		counts += ", 1 warning"
	} else if warnings > 1 {
		counts += fmt.Sprintf(", %d warnings", warnings)
	}
	fmt.Fprintln(w, counts)
	for _, r := range results {
		if r.File == "SUMMARY" && r.Test == "TOTAL" {
			continue
		}
		status := "PASS"
		if !r.Pass {
			status = "FAIL"
		}
		label := r.Test
		if r.File != "" {
			label = r.File + "/" + r.Test
		}
		if r.Skipped {
			fmt.Fprintf(w, "SKIP %s\n  %s\n", label, r.Message)
			continue
		}
		if r.Duration != "" {
			fmt.Fprintf(w, "%s %s (%s)\n", status, label, r.Duration)
		} else {
			fmt.Fprintf(w, "%s %s\n", status, label)
		}
		if !r.Pass && r.Message != "" {
			fmt.Fprintf(w, "  %s\n", r.Message)
		}
		for _, step := range r.Steps {
			if step.Pass {
				continue
			}
			fmt.Fprintf(w, "  - %s: %s\n", step.Action, step.Message)
		}
		for _, warning := range r.Warnings {
			fmt.Fprintf(w, "  WARNING: %s\n", warning)
		}
	}
}

func testResultsPassed(results []AppTestResult) bool {
	for _, r := range results {
		if !r.Pass {
			return false
		}
	}
	return len(results) > 0
}

// sourceCheckTestPrefix starts the test name of a source-check result.
const sourceCheckTestPrefix = "source check"

// sourceCheckTestResults is a failed result for each error the source layers
// of a check report (RunSourceCheck: the per-file validators of the write gate
// and the cross-file checks; the database is never opened). `benmore test`
// loaded and ran an app the platform refuses to accept: a flow under the
// reserved /api/v1/ prefix passed locally, where nothing else serves that
// prefix, and a push to the hosted dev instance refused it. Warnings are not
// failures; the tests still run so one run shows everything.
func sourceCheckTestResults(dir string) []AppTestResult {
	var out []AppTestResult
	for _, f := range RunSourceCheck(dir, "").Findings {
		if f.Severity != "error" {
			continue
		}
		out = append(out, AppTestResult{File: f.File, Test: sourceCheckTestPrefix + " (" + f.Source + ")", Pass: false,
			Message: withDocsLine(f.Message+" (`benmore push` and the platform write gate refuse this file)", f.Docs)})
	}
	return out
}

// testResultCounts counts the tests that ran; skipped ones are not counted
// (testResultSkipped).
func testResultCounts(results []AppTestResult) (total, passed int) {
	for _, r := range results {
		if r.File == "SUMMARY" && r.Test == "TOTAL" || r.Skipped {
			continue
		}
		total++
		if r.Pass {
			passed++
		}
	}
	return total, passed
}

func testResultSkipped(results []AppTestResult) int {
	skipped := 0
	for _, r := range results {
		if r.Skipped {
			skipped++
		}
	}
	return skipped
}

// loadTestFilesFromDisk reads the .yaml/.yml files directly under tests/. It
// returns the files it loaded and a failed result for each one it could not
// load (unreadable, not YAML, not test cases, empty, more than one document).
// Such a file used to be skipped with a bare `continue`: a list under `json:`
// dropped every test in its file, the run reported the other files and exited
// 0. Directories (tests/journeys/) and other file types are not test files.
func loadTestFilesFromDisk(dir string) ([]AppTestFile, []AppTestResult) {
	testsDir := filepath.Join(dir, "tests")
	entries, err := os.ReadDir(testsDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, []AppTestResult{{File: "tests/", Test: "load", Pass: false,
			Message: withDocsLine("cannot read the tests directory: "+fileErrorReason(err), testFileLoadDocs)}}
	}

	var testFiles []AppTestFile
	var unloaded []AppTestResult
	for _, entry := range entries {
		rel := "tests/" + entry.Name()
		if entry.IsDir() || !isAppTestFile(rel) {
			continue
		}
		data, err := os.ReadFile(filepath.Join(testsDir, entry.Name()))
		if err != nil {
			unloaded = append(unloaded, unloadedTestFile(rel, appTestFileNotLoaded+"the file cannot be read: "+fileErrorReason(err)))
			continue
		}
		tests, problem := decodeAppTestFile(data)
		if problem != "" {
			unloaded = append(unloaded, unloadedTestFile(rel, problem))
			continue
		}

		// A refused test's reason names its file: the result carries only the
		// file's name without the directory and extension (appTestFileName).
		for testName, tc := range tests {
			if tc.Problem != "" {
				tc.Problem = rel + ": " + tc.Problem
				tests[testName] = tc
			}
		}

		testFiles = append(testFiles, AppTestFile{Name: appTestFileName(rel), Tests: tests})
	}

	return testFiles, unloaded
}

// isAppTestFile reports an app-relative path the runner reads as a test file:
// a .yaml/.yml file directly under tests/.
func isAppTestFile(rel string) bool {
	rel = filepath.ToSlash(rel)
	return path.Dir(rel) == "tests" && (strings.HasSuffix(rel, ".yaml") || strings.HasSuffix(rel, ".yml"))
}

// appTestFileName is how every result names the test file at the
// app-relative path rel: the file's name without the directory and the
// extension (tests/notes.yaml: notes). A file that did not load was named by
// its path, so one run named its test files two ways.
func appTestFileName(rel string) string {
	name := path.Base(filepath.ToSlash(rel))
	return strings.TrimSuffix(strings.TrimSuffix(name, ".yaml"), ".yml")
}

// unloadedTestFile is the failed result for a tests/ file that was not run.
// Its message starts with the file's path, as the reason of a test that is
// not run does.
func unloadedTestFile(rel, problem string) AppTestResult {
	return AppTestResult{File: appTestFileName(rel), Test: "load", Pass: false, Message: withDocsLine(rel+": "+problem, testFileLoadDocs)}
}

// Where the runner's own refusals are documented, as `benmore check` names
// them for the same file (checkSourceDocs["tests"]).
const (
	testFileLoadDocs  = "verification.test_file_load" // a file that is not loaded
	testKeysDocs      = "verification.test_keys"      // a test that is not read in full
	testVariablesDocs = "verification.test_variables" // `{{name}}` and the test users' tokens
)

// fileErrorReason is err without the path of the disposable copy a test run
// reads.
func fileErrorReason(err error) string {
	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return pathErr.Err.Error()
	}
	return err.Error()
}

const (
	appTestFileNotLoaded = "cannot load this test file, so none of its tests ran: "
	appTestFileNotYAML   = "it is not valid YAML ("
	appTestFileShape     = "A test file is a mapping of test name to test case (`my_test:` with `steps:` under it)."
	appTestFileEmpty     = "this test file defines no tests (it is empty or holds only comments). Add a test, or delete the file."
)

// appTestDecodeWords puts a YAML decode error into the words of a test file:
// the decoder names Go types ("cannot unmarshal !!seq into map[string]interface {}").
var appTestDecodeWords = strings.NewReplacer(
	"yaml: unmarshal errors:\n", "",
	"map[string]main.AppTestCase", "a mapping of test name to test case",
	"main.AppTestCase", "a test case (a mapping with `steps:`)",
	"[]main.AppTestSetup", "a list of setup steps",
	"main.AppTestSetup", "a setup step (a mapping with `sql:`)",
	"[]main.AppTestStep", "a list of steps",
	"main.AppTestStep", "a step (a mapping)",
	"main.AppTestExpect", "an `expect:` mapping",
	"[]main.AppTestUser", "a list of users",
	"[]map[string]interface {}", "a list of mappings",
	"map[string]interface {}", "a mapping",
	"map[string]string", "a mapping of text values",
	"[]interface {}", "a list",
	"[]string", "a list of text values",
	"[]int", "a list of numbers",
	"*int", "a number",
	"!!seq", "a list",
	"!!map", "a mapping",
	"!!str", "text",
	"!!int", "a number",
	"!!float", "a number",
	"!!bool", "true or false",
	"!!null", "an empty value",
	"cannot unmarshal", "cannot read",
)

// decodeAppTestFile decodes one test file the way the runner reads it. It
// returns the file's test cases, or what is wrong with the file in words a
// builder can act on. A test the runner refuses carries the reason in Problem
// (readAppTestFile). `benmore check` reports the same text as a warning
// (appTestFileWarning), so the two cannot disagree about a file.
func decodeAppTestFile(data []byte) (map[string]AppTestCase, string) {
	tests, problems, fileProblem := readAppTestFile(data)
	if fileProblem != "" {
		return nil, fileProblem
	}
	for name, found := range problems {
		tc := tests[name]
		tc.Problem = appTestProblemText(found)
		tests[name] = tc
	}
	return tests, ""
}

// readAppTestFile decodes one test file and returns its test cases, per test
// the problems the runner refuses it for (appTestCaseProblems; tests it reads
// in full have no entry), and what is wrong with the file as a whole when it
// cannot be loaded.
func readAppTestFile(data []byte) (map[string]AppTestCase, map[string][]appTestProblem, string) {
	fail := func(problem string) (map[string]AppTestCase, map[string][]appTestProblem, string) {
		return nil, nil, problem
	}
	if err := checkYAMLShape(data); err != nil {
		return fail(appTestFileNotLoaded + err.Error())
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	var doc yaml.Node
	if err := dec.Decode(&doc); err != nil {
		if err == io.EOF {
			return fail(appTestFileEmpty)
		}
		return fail(appTestFileNotLoaded + appTestFileNotYAML + strings.TrimPrefix(err.Error(), "yaml: ") + ").")
	}
	// The decoder reads one document; tests after a `---` would never run.
	for {
		var extra yaml.Node
		err := dec.Decode(&extra)
		if err == io.EOF {
			break
		}
		if err != nil {
			return fail(appTestFileNotLoaded + appTestFileNotYAML + strings.TrimPrefix(err.Error(), "yaml: ") + ").")
		}
		if !emptyYAMLDocument(&extra) {
			return fail(appTestFileNotLoaded + "it holds more than one YAML document (separated by `---`), and only the first would be read. Put every test in one document.")
		}
	}
	if emptyYAMLDocument(&doc) {
		return fail(appTestFileEmpty)
	}
	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		kind := "a single value"
		if root.Kind == yaml.SequenceNode {
			kind = "a list"
		}
		return fail(appTestFileNotLoaded + "its top level is " + kind + ". " + appTestFileShape)
	}
	var tests map[string]AppTestCase
	if err := doc.Decode(&tests); err != nil {
		reason := strings.Join(strings.Fields(appTestDecodeWords.Replace(err.Error())), " ")
		return fail(appTestFileNotLoaded + reason + ". " + appTestFileShape + " `data:` and `json:` take a mapping; send a list with `json_array:`.")
	}
	if len(tests) == 0 {
		return fail(appTestFileEmpty)
	}
	// Each test against the node it was decoded from: the keys the decode
	// dropped, and what leaves the test checking nothing.
	problems := map[string][]appTestProblem{}
	for i := 0; i+1 < len(root.Content); i += 2 {
		name := root.Content[i]
		tc, ok := tests[name.Value]
		if !ok {
			continue
		}
		found := appTestCaseProblems(tc, root.Content[i+1])
		for p := range found {
			if found[p].Line == 0 {
				found[p].Line = name.Line
			}
		}
		if len(found) > 0 {
			sort.SliceStable(found, func(a, b int) bool { return found[a].Line < found[b].Line })
			problems[name.Value] = found
		}
	}
	return tests, problems, ""
}

// emptyYAMLDocument reports a document with no content: nothing at all, or
// an explicit null.
func emptyYAMLDocument(doc *yaml.Node) bool {
	if doc.Kind == 0 || len(doc.Content) == 0 {
		return true
	}
	root := doc.Content[0]
	return root.Kind == yaml.ScalarNode && root.Tag == "!!null"
}

// appTestFileWarning is what `benmore check` and the write gate say about a
// test file `benmore test` cannot load ("" for any other path, and for a file
// that loads). A warning: a push of the file is not refused; the test run is
// what fails.
func appTestFileWarning(rel, content string) string {
	if !isAppTestFile(rel) {
		return ""
	}
	tests, problem := decodeAppTestFile([]byte(content))
	if problem != "" {
		return "`benmore test` fails on this file: " + problem
	}
	// Tests the runner refuses, in name order; the first few carry their
	// reason and the rest are counted.
	var refused []string
	for _, name := range slices.Sorted(maps.Keys(tests)) {
		if tests[name].Problem != "" {
			refused = append(refused, name)
		}
	}
	if len(refused) == 0 {
		return ""
	}
	const shown = 5
	var parts []string
	for _, name := range refused[:min(shown, len(refused))] {
		parts = append(parts, name+": "+tests[name].Problem)
	}
	if more := len(refused) - shown; more > 0 {
		parts = append(parts, fmt.Sprintf("and %d more", more))
	}
	what := fmt.Sprintf("%d tests of this file without running them", len(refused))
	if len(refused) == 1 {
		what = "a test of this file without running it"
	}
	return "`benmore test` fails " + what + ": " + strings.Join(parts, " | ") + ". Run as written, the part named would be skipped and the test would report a pass."
}

func buildTestMux(app *App) (*http.ServeMux, error) {
	return buildAppMuxChecked(app, true, "http://localhost")
}

// testServerHandler is what `benmore test` sends its requests to: the app's
// routes behind the layers of the server chain (wrapMiddleware, dev mode) that
// decide what a client is answered, in the server's order. The account-hold
// gates were missing, so an account that must enroll MFA or replace a
// temporary password got the bare 401 / the page where the server answers 403
// mfa_enrollment_required / password_change_required or redirects, and a test
// could not assert the documented answer. The per-request session cache is
// here because those gates and the handler share one session lookup on the
// server.
//
// Left out on purpose:
//   - rate limiting: a suite sends more requests a minute than one client may;
//   - the request-body cap: only a body over the cap (10 MB unless
//     MAX_REQUEST_BODY_BYTES is set) is answered differently (413);
//   - CORS: it acts on an Origin header, which a test step cannot send;
//   - the visitor-password gate (DEMO_PASSWORD): tests exercise the app behind it;
//   - request logging, the request-log table and metrics: they record a
//     request and do not change its answer;
//   - panic recovery: a panicking handler ends the step with a failed request
//     instead of the server's 500 page;
//   - gzip (off in dev mode) and the hosted router's data channel.
func testServerHandler(app *App) (http.Handler, error) {
	mux, err := buildTestMux(app)
	if err != nil {
		return nil, err
	}
	handler := accountHoldMiddleware(mux, app)
	handler = securityHeaders(handler, true, app)
	return requestSessionCacheMiddleware(handler), nil
}

// auditStepSQLHint is added to a step's SQL error when the append-only
// triggers of a compliance: hipaa app refused it: the error alone
// ("_benmore_audit_log is append-only") does not say that setup: SQL is the
// place for it (runSingleTest lifts the triggers there).
func auditStepSQLHint(stmt string, err error) string {
	if err == nil || !mentionsAuditTable(stmt) || !strings.Contains(err.Error(), "is append-only") {
		return ""
	}
	return ". Under compliance: hipaa a test step cannot change an audit table. Move this statement to the test's `setup:` list, whose SQL may (it runs before the steps), or assert on the rows with a SELECT step."
}

func runSingleTest(app *App, base, fileName, testName string, tc AppTestCase) AppTestResult {
	start := time.Now()
	result := AppTestResult{
		File: fileName,
		Test: testName,
		Pass: true,
	}
	if tc.Skip != "" {
		result.Skipped = true
		result.Message = "skipped: " + tc.Skip
		return result
	}
	if refused, ok := unreadTestResult(fileName, testName, tc); ok {
		return refused
	}

	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Get auth if as_user specified (before setup so {{user_id}} is available)
	var cookies []*http.Cookie
	var bearerToken string
	var testUserID int64

	if !tc.Anon && tc.AsUser != "" {
		role := "user"
		if tc.AsRole != "" {
			role = tc.AsRole
		}
		cookies, bearerToken, testUserID = loginTestUser(app, tc.AsUser, role)
	}

	// The `users:` accounts exist before setup runs, so setup SQL can look one
	// up by email. They used to be created after it: a seed row owned by one
	// (`(SELECT id FROM _benmore_users WHERE email = ...)`) got NULL.
	userTokens := map[string]string{}
	for _, user := range tc.Users {
		// An entry that names a role gives the account that role, also when
		// an earlier test of the run created it with another.
		role := "user"
		if user.Role != "" {
			role = user.Role
		}
		if _, token, _ := loginTestUserAs(app, user.Email, role, user.Role != ""); token != "" {
			userTokens[testUserTokenVar(user.Email)] = token
		}
	}

	// Run setup steps ({{user_id}} is substituted with the authenticated user's ID)
	for _, setup := range tc.Setup {
		if setup.SQL != "" {
			sql := setup.SQL
			if testUserID > 0 {
				sql = strings.ReplaceAll(sql, "{{user_id}}", fmt.Sprintf("%d", testUserID))
			}
			var err error
			if mentionsAuditTable(sql) { // hipaa apps keep the audit tables append-only
				_, err = execAuditMutable(app.DB, sql)
			} else {
				_, err = app.DB.Exec(sql)
			}
			if err != nil {
				result.Pass = false
				result.Message = fmt.Sprintf("Setup failed: %s", err)
				result.Duration = time.Since(start).String()
				return result
			}
		}
	}

	// Run test steps with variable capture and substitution.
	// Steps capture response fields with `save: {name: field}`, read back as
	// {{name}}. {{user_id}} is the authenticated user's ID.
	vars := make(map[string]string)
	if testUserID > 0 {
		vars["user_id"] = fmt.Sprintf("%d", testUserID)
	}
	// Each test user's session token is the variable <local part>_token
	// (bob@example.com: bob_token), so a step can act as that user with
	// `set_auth: "bob_token"`. The `users:` accounts used to be created and
	// their sessions thrown away: nothing in a test could act as one where
	// the token exchange needs a second factor (compliance: hipaa).
	maps.Copy(vars, userTokens)
	if bearerToken != "" {
		vars[testUserTokenVar(tc.AsUser)] = bearerToken
	}
	anon := tc.Anon
	for i, step := range tc.Steps {
		// `expect` is read from the step as written: a value another field
		// received is never scanned for a second variable.
		expect, expectProblem := substituteExpectVars(step.Expect, vars)
		if warning := unsavedStepVarWarning(i+1, step, vars); warning != "" {
			result.Warnings = append(result.Warnings, warning)
		}
		step = substituteVars(step, vars)
		step.Expect = expect

		// set_auth: switch the auth context for this and all subsequent steps
		if step.SetAuth != "" {
			if step.SetAuth == "none" {
				cookies = nil
				bearerToken = ""
				anon = true
			} else {
				// A Bearer token: the value itself (a token a step saved,
				// written {{name}}), or the saved variable the value names.
				cookies = nil
				bearerToken = step.SetAuth
				if token, named := vars[step.SetAuth]; named {
					bearerToken = token
				}
				anon = false
			}
			if len(step.Save) > 0 {
				problem := withDocsLine(testSaveEntries(step.Save)+" saved nothing: a `set_auth:` step has no response to save from", testVariablesDocs)
				result.Steps = append(result.Steps, AppTestStepResult{Action: "set_auth", Pass: false, Message: problem})
				result.Pass = false
				result.Message = fmt.Sprintf("Step %d failed: %s", i+1, problem)
				break
			}
			result.Steps = append(result.Steps, AppTestStepResult{Action: "set_auth", Pass: true})
			continue
		}

		if expectProblem != "" {
			result.Steps = append(result.Steps, AppTestStepResult{Action: testStepLabel(step), Pass: false, Message: expectProblem})
			result.Pass = false
			result.Message = fmt.Sprintf("Step %d failed: %s", i+1, expectProblem)
			break
		}

		stepResult, response := executeTestStepWithCapture(app, base, client, cookies, bearerToken, anon, step)

		// A step that passed saves its `save:` entries; one that saves
		// nothing fails the step (saveTestStepVars). A step that failed
		// reports its own failure.
		if stepResult.Pass && len(step.Save) > 0 {
			if problem := saveTestStepVars(step, response, vars); problem != "" {
				stepResult.Pass = false
				stepResult.Message = problem
			}
		}
		result.Steps = append(result.Steps, stepResult)
		if !stepResult.Pass {
			result.Pass = false
			result.Message = fmt.Sprintf("Step %d failed: %s", i+1, stepResult.Message)
			break
		}
	}

	result.Duration = time.Since(start).String()
	return result
}

// testStepResponse is what a step answered, for its `save:` entries: the
// fields of a JSON object response or of the first row of an SQL step. With
// no fields, NoFields says why.
type testStepResponse struct {
	Fields   map[string]any
	NoFields string
	Row      bool // the fields are the columns of a row
}

// executeTestStepWithCapture runs a step and returns its result and what it
// answered, for the step loop to save variables from.
func executeTestStepWithCapture(app *App, base string, client *http.Client, cookies []*http.Cookie, bearerToken string, anon bool, step AppTestStep) (AppTestStepResult, testStepResponse) {
	// An SQL step saves from the first row its statement returns: a SELECT,
	// or a write with RETURNING. The statement runs once.
	if step.SQL != "" {
		sqlResult, rows := executeSQLTestStep(app, step)
		if len(rows) == 0 {
			return sqlResult, testStepResponse{NoFields: "the statement returned no rows"}
		}
		return sqlResult, testStepResponse{Fields: rows[0], Row: true}
	}
	if _, _, isRequest := testStepRequestLine(step); !isRequest {
		result, _ := executeTestStepRaw(app, base, client, cookies, bearerToken, anon, step)
		return result, testStepResponse{NoFields: "a `" + strings.SplitN(testStepLabel(step), ":", 2)[0] + ":` step has no response to save from"}
	}

	result, body := executeTestStepRaw(app, base, client, cookies, bearerToken, anon, step)
	const notObject = "the response is not a JSON object "
	trimmed := bytes.TrimSpace(body)
	if len(trimmed) == 0 {
		return result, testStepResponse{NoFields: notObject + "(its body is empty)"}
	}
	var parsed any
	if err := json.Unmarshal(trimmed, &parsed); err != nil {
		return result, testStepResponse{NoFields: notObject + "(its body is not JSON: " + truncate(string(trimmed), 80) + ")"}
	}
	switch val := parsed.(type) {
	case map[string]any:
		return result, testStepResponse{Fields: val}
	case []any:
		return result, testStepResponse{NoFields: notObject + "(it is a JSON array)"}
	}
	return result, testStepResponse{NoFields: notObject + "(it is the JSON value " + truncate(string(trimmed), 80) + ")"}
}

// testSaveEntries writes `save:` entries as a test file holds them, in name
// order.
func testSaveEntries(save map[string]string) string {
	parts := make([]string, 0, len(save))
	for _, name := range slices.Sorted(maps.Keys(save)) {
		parts = append(parts, name+": "+save[name])
	}
	return "`save: {" + strings.Join(parts, ", ") + "}`"
}

// saveTestStepVars saves the `save:` entries of a step that passed into vars
// and returns why one saved nothing, "" when every entry saved a value: the
// response has no fields, lacks the field, or holds null there. Such an entry
// used to save nothing without a word, and the `{{name}}` of a later step was
// sent as written: `get: "/api/notes/{{id}}"` with `expect: {status: 404}`
// passed whatever the app answers for a real id. The entries that found a
// value are saved either way.
func saveTestStepVars(step AppTestStep, response testStepResponse, vars map[string]string) string {
	problem := ""
	for _, name := range slices.Sorted(maps.Keys(step.Save)) {
		field := step.Save[name]
		value, present := response.Fields[field]
		if present && value != nil {
			vars[name] = fmt.Sprintf("%v", value)
			continue
		}
		if problem != "" {
			continue
		}
		entry, what, has := "`save: {"+name+": "+field+"}`", "field", "the response"
		if response.Row {
			what, has = "column", "the first row"
		}
		switch {
		case response.Fields == nil:
			problem = entry + " saved nothing: " + response.NoFields
		case present:
			problem = fmt.Sprintf("%s saved nothing: `%s` is null in %s", entry, field, has)
		default:
			keys := slices.Sorted(maps.Keys(response.Fields))
			const shown = 30
			list := codeList(keys[:min(shown, len(keys))])
			if more := len(keys) - shown; more > 0 {
				list += fmt.Sprintf(" and %d more", more)
			}
			if list == "" {
				list = "none"
			}
			problem = fmt.Sprintf("%s saved nothing: %s has no %s `%s` (it has: %s)", entry, has, what, field, list)
		}
		if !response.Row {
			problem += ". `save` takes a top-level field of a JSON object response"
		}
		problem += fmt.Sprintf(". A later `{{%s}}` would be sent as written, and a check of that step could pass for the wrong reason", name)
	}
	return withDocsLine(problem, testVariablesDocs)
}

// unsavedStepVarWarning is the warning for step n (as written, before its
// variables are read) when it holds a `{{name}}` outside `expect` that
// nothing saved, "" when it holds none. The text is sent as written: a path
// with the braces in it names nothing, so `expect: {status: 404}` after it
// passes whatever the app's rules are. A warning and not a failure, because a
// test may send template text on purpose. As in `expect`, only letters,
// digits, `_` and `-` between the braces make a name.
func unsavedStepVarWarning(n int, step AppTestStep, vars map[string]string) string {
	var found, names []string
	scan := func(place string, texts ...string) {
		var refs []string
		for _, text := range texts {
			for _, ref := range testVarRef.FindAllStringSubmatch(text, -1) {
				if _, saved := vars[ref[1]]; saved || !testVarName.MatchString(ref[1]) || slices.Contains(refs, "`"+ref[0]+"`") {
					continue
				}
				refs = append(refs, "`"+ref[0]+"`")
				if !slices.Contains(names, ref[1]) {
					names = append(names, ref[1])
				}
			}
		}
		if len(refs) > 0 {
			sort.Strings(refs)
			found = append(found, strings.Join(refs, ", ")+" in "+place)
		}
	}
	var body []string
	var collect func(v any)
	collect = func(v any) {
		switch val := v.(type) {
		case string:
			body = append(body, val)
		case map[string]any:
			for _, item := range val {
				collect(item)
			}
		case []any:
			for _, item := range val {
				collect(item)
			}
		}
	}
	collect(step.Data)
	collect(step.JSON)
	collect(step.JSONArray)
	for _, line := range step.NDJSON {
		collect(line)
	}
	for _, part := range step.Files {
		body = append(body, part.Name, part.Content)
	}
	scan("the path", step.API, step.Get, step.Post)
	scan("the SQL", step.SQL)
	scan("`set_auth`", step.SetAuth)
	scan("the body", body...)
	if len(found) == 0 {
		return ""
	}
	sort.Strings(names)
	known := "nothing is saved yet"
	if len(vars) > 0 {
		known = "saved so far: " + codeList(slices.Sorted(maps.Keys(vars)))
	}
	return withDocsLine(fmt.Sprintf("step %d: %s was sent as written, because no earlier step of this test saved %s (%s). A check of the step can then pass for the wrong reason: a path that holds the braces answers 404 whatever the app's access rules are. Text the test means to send needs no change",
		n, strings.Join(found, " and "), codeList(names), known), testVariablesDocs)
}

// testVarRef is a `{{name}}` reference: two braces around text that holds no
// brace. One pattern for every field of a step.
var testVarRef = regexp.MustCompile(`\{\{([^{}]+)\}\}`)

// testVarName is the shape of a name `expect` requires to be saved: letters,
// digits, `_` and `-`. Other text between braces (`{{ spaced }}`,
// `{{user.email}}`, `{{#each}}`) is template text an app may render or store,
// and stays text unless a variable of exactly that name was saved.
var testVarName = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

// replaceTestVars replaces each `{{name}}` of s that names a saved variable
// with its value, in one pass: a value is written as it is and never scanned
// for another variable. A `{{name}}` nothing saved stays as written.
func replaceTestVars(s string, vars map[string]string) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	return testVarRef.ReplaceAllStringFunc(s, func(ref string) string {
		if value, saved := vars[ref[2:len(ref)-2]]; saved {
			return value
		}
		return ref
	})
}

// testUserTokenVar names the variable that holds a test user's session token:
// the part of the email before the `@`, then `_token`.
func testUserTokenVar(email string) string {
	local, _, _ := strings.Cut(email, "@")
	return local + "_token"
}

// substituteVars replaces all {{var_name}} references in step strings with captured values.
func substituteVars(step AppTestStep, vars map[string]string) AppTestStep {
	replace := func(s string) string { return replaceTestVars(s, vars) }
	step.API = replace(step.API)
	step.Get = replace(step.Get)
	step.Post = replace(step.Post)
	step.SQL = replace(step.SQL)
	step.SetAuth = replace(step.SetAuth)
	// Substitute in JSON body values (for transaction IDs, etc.)
	if step.JSON != nil {
		step.JSON = substituteVarsInMap(step.JSON, vars)
	}
	if step.Data != nil {
		step.Data = substituteVarsInMap(step.Data, vars)
	}
	if step.JSONArray != nil {
		step.JSONArray = substituteVarsInSlice(step.JSONArray, vars)
	}
	if step.NDJSON != nil {
		ndjson := make([]map[string]any, len(step.NDJSON))
		for i, obj := range step.NDJSON {
			ndjson[i] = substituteVarsInMap(obj, vars)
		}
		step.NDJSON = ndjson
	}
	if step.Files != nil {
		files := make(map[string]AppTestFilePart, len(step.Files))
		for field, part := range step.Files {
			files[field] = AppTestFilePart{Name: replace(part.Name), Content: replace(part.Content)}
		}
		step.Files = files
	}
	return step
}

// substituteVarsInMap recursively replaces {{var}} in map string values.
func substituteVarsInMap(m map[string]any, vars map[string]string) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = substituteVarsInValue(v, vars)
	}
	return out
}

// substituteVarsInSlice recursively replaces {{var}} in slice elements.
func substituteVarsInSlice(s []any, vars map[string]string) []any {
	out := make([]any, len(s))
	for i, v := range s {
		out[i] = substituteVarsInValue(v, vars)
	}
	return out
}

func substituteVarsInValue(v any, vars map[string]string) any {
	switch val := v.(type) {
	case string:
		return replaceTestVars(val, vars)
	case map[string]any:
		return substituteVarsInMap(val, vars)
	case []any:
		return substituteVarsInSlice(val, vars)
	}
	return v
}

// substituteExpectVars reads the saved variables into every text of a step's
// `expect` (redirect, contains, not_contains, the paths and values of json,
// the values of headers) and returns why the step cannot be checked, "" when
// it can:
//
//   - a `{{name}}` no earlier step saved. `expect` used to keep such text as
//     written, also for a saved name, so `not_contains: "{{secret}}"` compared
//     the response with those characters and passed on every response;
//   - a `contains`, `not_contains` or `redirect` whose whole text is a saved
//     value that is empty, which the check would skip.
//
// The step's own maps and lists are left as they are.
func substituteExpectVars(expect AppTestExpect, vars map[string]string) (AppTestExpect, string) {
	problem := ""
	// read substitutes into one text of `expect.<key>`. needsText marks a
	// check that an empty text turns off.
	read := func(key, text string, needsText bool) string {
		for _, ref := range testVarRef.FindAllStringSubmatch(text, -1) {
			if _, saved := vars[ref[1]]; saved || !testVarName.MatchString(ref[1]) || problem != "" {
				continue
			}
			known := "nothing is saved yet"
			if len(vars) > 0 {
				known = "saved so far: " + codeList(slices.Sorted(maps.Keys(vars)))
			}
			problem = fmt.Sprintf("`expect.%s` reads `%s`, but no earlier step of this test saved `%s` (%s), so the step was not run: compared as written, the check would prove nothing. Braces that are text and not a variable: leave the pair open (`{{%s`)", key, ref[0], ref[1], known, ref[1])
		}
		out := replaceTestVars(text, vars)
		if needsText && out == "" && text != "" && problem == "" {
			problem = fmt.Sprintf("`expect.%s` reads `%s`, whose saved value is empty, so the step was not run: the check would compare nothing", key, text)
		}
		return out
	}
	var walk func(key string, v any, needsText bool) any
	walk = func(key string, v any, needsText bool) any {
		switch val := v.(type) {
		case string:
			return read(key, val, needsText)
		case []string:
			out := make([]string, len(val))
			for i, item := range val {
				out[i] = read(key, item, needsText)
			}
			return out
		case []any:
			out := make([]any, len(val))
			for i, item := range val {
				out[i] = walk(key, item, needsText)
			}
			return out
		case map[string]any:
			out := make(map[string]any, len(val))
			for k, item := range val {
				out[read(key, k, false)] = walk(key, item, false)
			}
			return out
		}
		return v
	}
	expect.Redirect = read("redirect", expect.Redirect, true)
	expect.Contains = walk("contains", expect.Contains, true)
	expect.NotContains = walk("not_contains", expect.NotContains, true)
	if expect.JSONField != nil {
		expect.JSONField, _ = walk("json", expect.JSONField, false).(map[string]any)
	}
	if expect.Headers != nil {
		headers := make(map[string]string, len(expect.Headers))
		for name, value := range expect.Headers {
			headers[name] = read("headers", value, false)
		}
		expect.Headers = headers
	}
	return expect, withDocsLine(problem, testVariablesDocs)
}

// testStepRequestLine is the method and path of a request step (`api`, `get`,
// `post`); ok is false for any other step.
func testStepRequestLine(step AppTestStep) (method, path string, ok bool) {
	switch {
	case step.API != "":
		if parts := strings.SplitN(step.API, " ", 2); len(parts) == 2 {
			return parts[0], parts[1], true
		}
		return "GET", step.API, true
	case step.Get != "":
		return "GET", step.Get, true
	case step.Post != "":
		return "POST", step.Post, true
	}
	return "", "", false
}

// testStepLabel names a step in a result, as running it would.
func testStepLabel(step AppTestStep) string {
	if method, path, ok := testStepRequestLine(step); ok {
		return method + " " + path
	}
	if step.SQL != "" {
		return fmt.Sprintf("SQL: %s", truncate(step.SQL, 60))
	}
	if step.Flush != "" {
		return "flush: " + step.Flush
	}
	return "step"
}

// buildTestStepRequest is the request a step sends, before its credential is
// attached (a session cookie or a Bearer token; neither for an anonymous
// step). A cookie-authenticated step carries the CSRF token as a page of the
// app would send it: in the `_csrf` field of a form or multipart body, and in
// X-CSRF-Token for a JSON body or no body. A step with no body used to put
// the token in a form body for POST, PATCH and DELETE; the server reads a form
// body only on POST, PUT and PATCH, so every such DELETE answered 403 "Invalid
// CSRF token" (and a PUT sent no token at all). A form or multipart step on
// any other method sends the header beside its field for the same reason.
func buildTestStepRequest(base string, step AppTestStep, method, path string, anon, useBearer bool) (*http.Request, error) {
	var body io.Reader
	contentType := ""
	csrf := !anon && !useBearer
	csrfHeader := false
	formBodyRead := method == http.MethodPost || method == http.MethodPut || method == http.MethodPatch

	switch {
	case step.NDJSON != nil:
		var lines []string
		for _, obj := range step.NDJSON {
			line, _ := json.Marshal(obj)
			lines = append(lines, string(line))
		}
		body = strings.NewReader(strings.Join(lines, "\n"))
		contentType = "application/x-ndjson"
		csrfHeader = true
	case step.JSONArray != nil:
		data, _ := json.Marshal(step.JSONArray)
		body = strings.NewReader(string(data))
		contentType = "application/json"
		csrfHeader = true
	case step.JSON != nil:
		data, _ := json.Marshal(step.JSON)
		body = strings.NewReader(string(data))
		contentType = "application/json"
		csrfHeader = true
	case step.Files != nil:
		// multipart/form-data, as a browser form with a file input sends it:
		// the CSRF token and the data fields, then one part per file.
		var buf bytes.Buffer
		mw := multipart.NewWriter(&buf)
		if csrf {
			_ = mw.WriteField("_csrf", generateCSRFToken())
		}
		for _, k := range slices.Sorted(maps.Keys(step.Data)) {
			_ = mw.WriteField(k, fmt.Sprintf("%v", step.Data[k]))
		}
		for _, field := range slices.Sorted(maps.Keys(step.Files)) {
			part := step.Files[field]
			if fw, err := mw.CreateFormFile(field, part.Name); err == nil {
				_, _ = io.WriteString(fw, part.Content)
			}
		}
		_ = mw.Close()
		body = &buf
		contentType = mw.FormDataContentType()
		csrfHeader = !formBodyRead
	case step.Data != nil:
		formData := url.Values{}
		if csrf {
			formData.Set("_csrf", generateCSRFToken())
		}
		for k, v := range step.Data {
			formData.Set(k, fmt.Sprintf("%v", v))
		}
		body = strings.NewReader(formData.Encode())
		contentType = "application/x-www-form-urlencoded"
		csrfHeader = !formBodyRead
	default:
		// No body: the token travels in the header for every method that
		// changes something.
		csrfHeader = method != http.MethodGet && method != http.MethodHead && method != http.MethodOptions
	}

	req, err := http.NewRequest(method, base+path, body)
	if err != nil {
		return nil, err
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	if csrf && csrfHeader {
		req.Header.Set("X-CSRF-Token", generateCSRFToken())
	}
	return req, nil
}

func executeTestStepRaw(app *App, base string, client *http.Client, cookies []*http.Cookie, bearerToken string, anon bool, step AppTestStep) (AppTestStepResult, []byte) {
	method, path, isRequest := testStepRequestLine(step)
	if !isRequest {
		if step.SQL != "" {
			result, _ := executeSQLTestStep(app, step)
			return result, nil
		}
		if step.Flush != "" {
			return executeFlushStep(app, step), nil
		}
		// runSingleTest refuses such a test before its first step; a step
		// with no action never becomes a request for the empty path.
		return AppTestStepResult{Action: "step", Pass: false, Message: "this step has no action"}, nil
	}

	action := fmt.Sprintf("%s %s", method, path)

	// Use Bearer auth if explicitly requested OR if we have a token but no cookies
	// (set_auth switches to token-only auth)
	useBearer := bearerToken != "" && (step.Bearer || len(cookies) == 0)

	// One request, timed from before it is built until its body is read.
	send := func() (AppTestStepResult, []byte, time.Duration, bool) {
		stepStart := time.Now()
		req, err := buildTestStepRequest(base, step, method, path, anon, useBearer)
		if err != nil {
			return AppTestStepResult{Action: action, Pass: false, Message: fmt.Sprintf("Request error: %s", err)}, nil, 0, false
		}

		// Auth: Bearer token or cookies (never both, never for anon)
		if !anon {
			if useBearer {
				req.Header.Set("Authorization", "Bearer "+bearerToken)
			} else {
				for _, c := range cookies {
					req.AddCookie(c)
				}
			}
		}

		resp, err := client.Do(req)
		if err != nil {
			return AppTestStepResult{Action: action, Pass: false, Message: fmt.Sprintf("Request failed: %s", err)}, nil, 0, false
		}
		defer resp.Body.Close()
		respBody, _ := io.ReadAll(resp.Body)

		elapsed := time.Since(stepStart)

		// Run assertions
		result := checkAssertions(action, resp, respBody, step.Expect, elapsed)
		// onlySlow: the answer is the expected one and nothing but its time
		// failed the step.
		onlySlow := false
		if !result.Pass && testStepOverMaxDuration(step.Expect, elapsed) {
			timeless := step.Expect
			timeless.MaxDuration = ""
			onlySlow = checkAssertions(action, resp, respBody, timeless, elapsed).Pass
		}
		return result, respBody, elapsed, onlySlow
	}

	var took []string
	for {
		result, respBody, elapsed, onlySlow := send()
		took = append(took, elapsed.String())
		if !onlySlow || len(took) >= step.DurationAttempts {
			if onlySlow && len(took) > 1 {
				maxDur, _ := time.ParseDuration(step.Expect.MaxDuration)
				result.Message = fmt.Sprintf("Took %s in %d requests (every one over the bound), max allowed %s",
					strings.Join(took, ", "), len(took), maxDur)
			}
			return result, respBody
		}
	}
}

// testStepOverMaxDuration reports whether a request took longer than the
// step's `expect.max_duration` allows.
func testStepOverMaxDuration(expect AppTestExpect, elapsed time.Duration) bool {
	if expect.MaxDuration == "" {
		return false
	}
	maxDur, err := time.ParseDuration(expect.MaxDuration)
	return err == nil && elapsed > maxDur
}

// executeSQLTestStep runs an SQL step once and returns its result and the
// rows the statement returned.
func executeSQLTestStep(app *App, step AppTestStep) (AppTestStepResult, []map[string]any) {
	action := fmt.Sprintf("SQL: %s", truncate(step.SQL, 60))

	rows, err := QueryRows(app.DB, step.SQL)
	if err != nil {
		return AppTestStepResult{Action: action, Pass: false, Message: fmt.Sprintf("SQL error: %s%s", err, auditStepSQLHint(step.SQL, err))}, nil
	}

	// Check row count expectation
	if step.Expect.Rows != nil {
		if len(rows) != *step.Expect.Rows {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Expected %d rows, got %d", *step.Expect.Rows, len(rows)),
			}, rows
		}
	}

	return AppTestStepResult{Action: action, Pass: true}, rows
}

func executeFlushStep(app *App, step AppTestStep) AppTestStepResult {
	switch step.Flush {
	case "errors":
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := flushErrorReports(ctx, app); err != nil {
			return AppTestStepResult{Action: "flush: errors", Message: err.Error()}
		}
		return AppTestStepResult{Action: "flush: errors", Pass: true}
	case "jobs":
		FlushJobs(app)
		return AppTestStepResult{Action: "flush: jobs", Pass: true}
	case "retention":
		RunRetentionNow(app)
		return AppTestStepResult{Action: "flush: retention", Pass: true}
	case "scheduled":
		sweepScheduledTasks(app)
		return AppTestStepResult{Action: "flush: scheduled", Pass: true}
	default:
		return AppTestStepResult{
			Action:  "flush: " + step.Flush,
			Pass:    false,
			Message: fmt.Sprintf("unknown flush target '%s' (valid: jobs, retention, scheduled, errors)", step.Flush),
		}
	}
}

func checkAssertions(action string, resp *http.Response, body []byte, expect AppTestExpect, elapsed time.Duration) AppTestStepResult {
	// Status code. `status_in` (any-of) takes precedence over `status`
	// (exact) - it lets the auto-CRUD generator accept either success or a
	// well-formed access-control denial on tables it can't prove are
	// writable by the synthetic test user (groups / RBAC / before-hooks are
	// invisible to the generator). 5xx and 400 are never in the set, so real
	// errors still fail.
	if len(expect.StatusIn) > 0 {
		ok := false
		for _, s := range expect.StatusIn {
			if resp.StatusCode == s {
				ok = true
				break
			}
		}
		if !ok {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Expected status in %v, got %d. Body: %s", expect.StatusIn, resp.StatusCode, truncate(string(body), 200)),
			}
		}
	} else if expect.Status > 0 && resp.StatusCode != expect.Status {
		return AppTestStepResult{
			Action: action, Pass: false,
			Message: fmt.Sprintf("Expected status %d, got %d. Body: %s", expect.Status, resp.StatusCode, truncate(string(body), 200)),
		}
	}

	// Default: expect 200 for GET, 200/201 for POST
	if expect.Status == 0 && len(expect.StatusIn) == 0 {
		if resp.StatusCode >= 400 {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("HTTP %d. Body: %s", resp.StatusCode, truncate(string(body), 200)),
			}
		}
	}

	// Redirect
	if expect.Redirect != "" {
		loc := resp.Header.Get("Location")
		if !strings.Contains(loc, expect.Redirect) {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Expected redirect to '%s', got '%s'", expect.Redirect, loc),
			}
		}
	}

	// Body contains (supports string or list of strings)
	for _, want := range expectContains(expect.Contains) {
		if !strings.Contains(string(body), want) {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Body does not contain '%s'", want),
			}
		}
	}

	// Body not contains (supports string or list of strings)
	for _, reject := range expectContains(expect.NotContains) {
		if strings.Contains(string(body), reject) {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Body should not contain '%s'", reject),
			}
		}
	}

	// JSON field assertions
	if expect.JSONField != nil {
		var parsed any
		if err := json.Unmarshal(body, &parsed); err != nil {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Response is not valid JSON: %s", err),
			}
		}

		for key, expectedVal := range expect.JSONField {
			actualVal := jsonLookup(parsed, key)
			expected := fmt.Sprintf("%v", expectedVal)
			actual := fmt.Sprintf("%v", actualVal)
			if actual != expected {
				return AppTestStepResult{
					Action: action, Pass: false,
					Message: fmt.Sprintf("JSON field '%s': expected '%s', got '%s'", key, expected, actual),
				}
			}
		}
	}

	// JSON array length
	if expect.JSONLength != nil {
		var parsed any
		if err := json.Unmarshal(body, &parsed); err != nil {
			return AppTestStepResult{Action: action, Pass: false, Message: "Response is not valid JSON"}
		}
		// A response that is not an array has no length to compare: the
		// expectation was skipped, so `json_length: 3` passed on an object.
		arr, ok := parsed.([]any)
		if !ok {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Expected a JSON array of length %d, but the response is not an array. Body: %s", *expect.JSONLength, truncate(string(body), 200)),
			}
		}
		if len(arr) != *expect.JSONLength {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Expected JSON array length %d, got %d", *expect.JSONLength, len(arr)),
			}
		}
	}

	// Headers
	for key, expected := range expect.Headers {
		actual := resp.Header.Get(key)
		if actual != expected {
			return AppTestStepResult{
				Action: action, Pass: false,
				Message: fmt.Sprintf("Header '%s': expected '%s', got '%s'", key, expected, actual),
			}
		}
	}

	// Max duration
	if testStepOverMaxDuration(expect, elapsed) {
		maxDur, _ := time.ParseDuration(expect.MaxDuration)
		return AppTestStepResult{
			Action: action, Pass: false,
			Message: fmt.Sprintf("Took %s, max allowed %s", elapsed, maxDur),
		}
	}

	return AppTestStepResult{Action: action, Pass: true, Message: elapsed.String()}
}

// jsonLookup extracts a value from parsed JSON using dot notation.
// Supports: "status", "errors[0].field", "[0].name"
func jsonLookup(data any, path string) any {
	parts := strings.Split(path, ".")
	current := data

	for _, part := range parts {
		if current == nil {
			return nil
		}

		// Array index: "errors[0]" or "[0]"
		if idx := strings.Index(part, "["); idx >= 0 {
			key := part[:idx]
			idxStr := strings.TrimSuffix(part[idx+1:], "]")
			var arrIdx int
			fmt.Sscanf(idxStr, "%d", &arrIdx)

			if key != "" {
				if m, ok := current.(map[string]any); ok {
					current = m[key]
				}
			}

			if arr, ok := current.([]any); ok && arrIdx < len(arr) {
				current = arr[arrIdx]
			} else {
				return nil
			}
			continue
		}

		// Object field
		if m, ok := current.(map[string]any); ok {
			current = m[part]
		} else {
			return nil
		}
	}

	return current
}

// loginTestUser creates a test user with the given role and returns cookies, bearer token, and user ID.
// An account that exists keeps the role it has.
func loginTestUser(app *App, email string, role string) ([]*http.Cookie, string, int64) {
	return loginTestUserAs(app, email, role, false)
}

// loginTestUserAs is loginTestUser; with setRole an account that already
// exists is given the role too (a `users:` entry that names one).
func loginTestUserAs(app *App, email string, role string, setRole bool) ([]*http.Cookie, string, int64) {
	EnsureUsersTable(app.DB)
	EnsureSessionsTable(app.DB)

	var id int64
	err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = ?", email).Scan(&id)
	if err == nil && setRole {
		app.DB.Exec("UPDATE _benmore_users SET role = ? WHERE id = ? AND role IS NOT ?", role, id, role)
	}
	if err != nil {
		hash, _ := generateBcryptHash([]byte("testpass123"))
		username := GenerateUniqueUsername(app.DB, strings.Split(email, "@")[0], 0)
		// Test identities stand for real signed-in users, whose email is
		// verified: email-keyed memberships and shares need that.
		result, insertErr := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES (?, ?, ?, ?, 1)", username, email, string(hash), role)
		if insertErr != nil {
			// Retry once - database may be locked by concurrent operations
			time.Sleep(100 * time.Millisecond)
			result, insertErr = app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES (?, ?, ?, ?, 1)", username, email, string(hash), role)
		}
		if result != nil {
			id, _ = result.LastInsertId()
		}
	}

	// A signed-in holder of a role auth.require_mfa_for_roles lists has
	// enrolled a factor; without one every session of the account is held for
	// enrollment. Test users stand for signed-in users, and the runner works
	// on a disposable copy, so such a test user gets a factor nobody knows.
	if id > 0 && mfaEnrollmentConfigured(app) && !CheckMFA(app.DB, id) && userRequiresMFAEnrollment(app, id) {
		secret := make([]byte, 20)
		rand.Read(secret)
		app.DB.Exec("UPDATE _benmore_users SET totp_secret=? WHERE id=?", base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(secret), id)
	}

	groupID := ResolveGroupID(app.DB, app.Group, email)
	sessionID := CreateSession(app.DB, id, email, groupID, app.SessionDuration)

	cookies := []*http.Cookie{{
		Name:  sessionCookieName,
		Value: sessionID,
	}}

	return cookies, sessionID, id
}

// expectRows builds an SQL step's row-count expectation; 0 is a real check.
func expectRows(n int) *int { return &n }
