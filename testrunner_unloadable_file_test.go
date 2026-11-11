//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// unloadableTestFiles are tests/ files `benmore test` cannot run, each with a
// phrase its failed result must carry. The runner used to skip every one of
// them without a word: the run printed the other files and exited 0.
var unloadableTestFiles = []struct{ name, body, want string }{
	// The reviewed shape: `json:` takes a mapping, the step gave it a list.
	{"list_under_json.yaml", "create_two:\n  as_user: \"a@test.com\"\n  steps:\n    - api: \"POST /api/notes/batch\"\n      json:\n        - {title: \"Alice\"}\n        - {title: \"Bob\"}\n      expect:\n        status: 200\n", "line 6: cannot read a list into a mapping"},
	{"empty.yaml", "", "defines no tests"},
	{"comment_only.yaml", "# tests to come\n", "defines no tests"},
	{"top_level_list.yaml", "- get: \"/health\"\n  expect:\n    status: 200\n", "mapping of test name"},
	{"scalar.yml", "just a sentence\n", "mapping of test name"},
	{"two_documents.yaml", "first:\n  anon: true\n  steps:\n    - get: \"/health\"\n      expect:\n        status: 200\n---\nsecond:\n  anon: true\n  steps:\n    - get: \"/health\"\n      expect:\n        status: 500\n", "more than one YAML document"},
	{"not_yaml.yaml", "first:\n  steps: [\n", "tests ran"},
}

func unloadableTestApp(t *testing.T, withBadFiles bool) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "runnerapp")
	writeTestFile(t, dir, "schema.prisma", "model Note {\n  id Int @id @default(autoincrement())\n  title String\n  userId Int @map(\"user_id\")\n}\n")
	writeTestFile(t, dir, "app.yaml", "site_name: Runner\nauth: {identifier: email}\n")
	writeTestFile(t, dir, "tests/good.yaml", "good_test:\n  anon: true\n  steps:\n    - get: \"/health\"\n      expect:\n        status: 200\n")
	// A leading document marker and a trailing one are still one document.
	writeTestFile(t, dir, "tests/marked.yaml", "---\nmarked_test:\n  anon: true\n  steps:\n    - get: \"/health\"\n      expect:\n        status: 200\n...\n")
	// Not test files: a directory of browser journeys and a text list.
	writeTestFile(t, dir, "tests/journeys/home.yaml", "name: home\npath: /\nassertions:\n  - {visible: \"main\"}\n")
	writeTestFile(t, dir, "tests/expected-failures.txt", "# none\n")
	if withBadFiles {
		for _, f := range unloadableTestFiles {
			writeTestFile(t, dir, "tests/"+f.name, f.body)
		}
	}
	return dir
}

// `benmore test` names every tests/ file it cannot load and fails the run, in
// each mode. Before, a file that did not decode into test cases (a list under
// `json:`), an empty file and a file whose top level is not a mapping were
// dropped: 4 broken files beside one good one printed "32/32 passed", exit 0.
func TestBenmoreTestFailsOnATestFileItCannotLoad(t *testing.T) {
	dir := unloadableTestApp(t, true)
	for _, mode := range []string{"all", "app", "framework"} {
		t.Run(mode, func(t *testing.T) {
			results, err := runServerTestsOnCopy(dir, mode)
			if err != nil {
				t.Fatalf("the run did not reach the tests: %v", err)
			}
			byFile := map[string]AppTestResult{}
			ran := map[string]bool{}
			var summary *AppTestResult
			for i, r := range results {
				if r.File == "SUMMARY" {
					summary = &results[i]
					continue
				}
				if r.Test == "load" {
					byFile[r.File] = r
					continue
				}
				ran[r.File+"/"+r.Test] = r.Pass
			}
			for _, f := range unloadableTestFiles {
				r, ok := byFile["tests/"+f.name]
				if !ok {
					t.Errorf("tests/%s was dropped: no result names it", f.name)
					continue
				}
				if r.Pass || r.Skipped {
					t.Errorf("tests/%s is reported as %+v, want a failed result", f.name, r)
				}
				if !strings.Contains(r.Message, f.want) {
					t.Errorf("tests/%s: message %q does not say %q", f.name, r.Message, f.want)
				}
				// Builder-facing text: no Go type names from the decoder.
				for _, internal := range []string{"main.", "interface {}", "!!seq", "!!str", "!!map"} {
					if strings.Contains(r.Message, internal) {
						t.Errorf("tests/%s: message carries decoder internals (%q): %s", f.name, internal, r.Message)
					}
				}
			}
			if len(byFile) != len(unloadableTestFiles) {
				t.Errorf("load failures = %d files, want %d: %+v", len(byFile), len(unloadableTestFiles), byFile)
			}
			if testResultsPassed(results) {
				t.Error("the run counts as passed (exit 0) with test files it could not load")
			}
			if summary == nil || summary.Pass {
				t.Errorf("SUMMARY = %+v, want a failed summary", summary)
			}
			// The files that do load still run, in the modes that run app tests.
			for _, test := range []string{"good/good_test", "marked/marked_test"} {
				pass, did := ran[test]
				if mode == "framework" {
					if did {
						t.Errorf("--framework ran the app test %s", test)
					}
					continue
				}
				if !did || !pass {
					t.Errorf("%s: ran=%v pass=%v, want it to run and pass beside the broken files", test, did, pass)
				}
			}
			// Second document of two_documents.yaml: reported, never half-run.
			if _, did := ran["two_documents/first"]; did {
				t.Error("a file with two YAML documents ran its first document and dropped the second")
			}
		})
	}
}

// The same app without the broken files passes: a directory under tests/, a
// non-YAML file and document markers around one document are not failures.
func TestBenmoreTestLoadsEveryWellFormedTestFile(t *testing.T) {
	dir := unloadableTestApp(t, false)
	for _, mode := range []string{"app", "framework"} {
		results, err := runServerTestsOnCopy(dir, mode)
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		for _, r := range results {
			if !r.Pass {
				t.Errorf("%s: %s/%s failed: %s", mode, r.File, r.Test, r.Message)
			}
		}
		if !testResultsPassed(results) {
			t.Errorf("%s: a clean app did not pass", mode)
		}
	}
	files, unloaded := loadTestFilesFromDisk(dir)
	if len(unloaded) != 0 || len(files) != 2 {
		t.Fatalf("loaded %d files with %d failures, want 2 and 0: %+v", len(files), len(unloaded), unloaded)
	}
}

// A run whose only test file cannot be loaded says so instead of "no tests".
func TestBenmoreTestAppModeWithOnlyAnUnloadableFile(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "onlybad")
	writeTestFile(t, dir, "app.yaml", "site_name: Only bad\n")
	writeTestFile(t, dir, "tests/broken.yaml", "- not: a mapping\n")
	results, err := runServerTestsOnCopy(dir, "app")
	if err != nil {
		t.Fatal(err)
	}
	named := false
	for _, r := range results {
		if r.File == "tests/broken.yaml" && r.Test == "load" && !r.Pass {
			named = true
		}
	}
	if !named || testResultsPassed(results) {
		t.Fatalf("the unloadable file is not reported as a failure: %+v", results)
	}
}

// `benmore check` and the write gate report the file too, as a warning filed
// on it: a push is not refused, and `benmore test` is what fails.
func TestCheckWarnsOnATestFileTheRunnerCannotLoad(t *testing.T) {
	dir := unloadableTestApp(t, true)
	report := RunSourceCheck(dir, "")
	warned := map[string]string{}
	for _, f := range report.Findings {
		if f.Source != "tests" {
			continue
		}
		if f.Severity != "warning" {
			t.Errorf("%s is a %s, want a warning (a push of a test file is not refused)", f.File, f.Severity)
		}
		warned[filepath.ToSlash(f.File)] = f.Message
	}
	for _, f := range unloadableTestFiles {
		if f.name == "not_yaml.yaml" || f.name == "two_documents.yaml" {
			// Not YAML, or two documents: the per-file validator already
			// refuses these, so the warning is not added on top of its error.
			if _, ok := warned["tests/"+f.name]; ok || !checkHasError(report, "tests/"+f.name) {
				t.Errorf("tests/%s: want one syntax error and no warning; warned=%v", f.name, ok)
			}
			continue
		}
		msg, ok := warned["tests/"+f.name]
		if !ok || !strings.Contains(msg, f.want) || !strings.Contains(msg, "benmore test") {
			t.Errorf("check does not warn about tests/%s with %q: %q (all findings: %+v)", f.name, f.want, msg, report.Findings)
		}
	}
	for _, clean := range []string{"tests/good.yaml", "tests/marked.yaml", "tests/journeys/home.yaml"} {
		if msg, ok := warned[clean]; ok {
			t.Errorf("check warns about %s: %s", clean, msg)
		}
	}
	// The write of one such file answers with that file's warning.
	body, err := os.ReadFile(filepath.Join(dir, "tests", "list_under_json.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if refusal := ValidateOnWriteIn(dir, "tests/list_under_json.yaml", string(body)); refusal != "" {
		t.Errorf("the write gate refuses the file (%q); it is a warning", refusal)
	}
	after := RunSourceCheck(dir, "tests/list_under_json.yaml")
	found := false
	for _, f := range after.Findings {
		if f.Source == "tests" && filepath.ToSlash(f.File) == "tests/list_under_json.yaml" {
			found = true
		} else if f.Source == "tests" {
			t.Errorf("a write of one test file repeats another file's warning: %+v", f)
		}
	}
	if !found {
		t.Errorf("the write of tests/list_under_json.yaml carries no warning: %+v", after.Findings)
	}
}

// Every fixture app's test files load, except the ones a fixture lists in
// tests/expected-failures.txt as files that must not (the test-file-not-loaded
// fixture, which CI runs through the real binary). Fixture CI reads `benmore
// test --app --json`, where a dropped file was invisible.
func TestFixtureAppTestFilesLoadOrAreExpectedNotTo(t *testing.T) {
	apps, err := filepath.Glob(filepath.Join("testdata", "*", "tests"))
	if err != nil || len(apps) < 20 {
		t.Fatalf("found %d fixture apps with tests/ (%v)", len(apps), err)
	}
	expectedSomewhere := false
	for _, tests := range apps {
		expected := map[string]bool{}
		if listed, err := os.ReadFile(filepath.Join(tests, "expected-failures.txt")); err == nil {
			for _, line := range strings.Split(string(listed), "\n") {
				if line = strings.TrimSpace(line); isAppTestFile(line) {
					expected[line] = true
				}
			}
		}
		_, unloaded := loadTestFilesFromDisk(filepath.Dir(tests))
		for _, r := range unloaded {
			if !expected[r.File] {
				t.Errorf("%s: %s: %s", filepath.Dir(tests), r.File, r.Message)
			}
			delete(expected, r.File)
			expectedSomewhere = true
		}
		for file := range expected {
			t.Errorf("%s: %s is listed as a file that must not load, but it loads", filepath.Dir(tests), file)
		}
	}
	if !expectedSomewhere {
		t.Error("no fixture exercises a test file that cannot be loaded (testdata/test-file-not-loaded)")
	}
}

func checkHasError(report CheckReport, file string) bool {
	for _, f := range report.Findings {
		if f.Severity == "error" && filepath.ToSlash(f.File) == file {
			return true
		}
	}
	return false
}
