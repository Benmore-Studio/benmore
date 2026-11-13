//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// truthTestApp is a one-table app whose tests/ holds the given files.
func truthTestApp(t *testing.T, files map[string]string) string {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "truthapp")
	writeTestFile(t, dir, "schema.prisma", "model Note {\n  id Int @id @default(autoincrement())\n  title String\n  body String @default(\"\")\n  userId Int @map(\"user_id\")\n}\n")
	writeTestFile(t, dir, "app.yaml", "site_name: Truth\nauth: {identifier: email}\n")
	for name, body := range files {
		writeTestFile(t, dir, "tests/"+name, body)
	}
	return dir
}

// truthTestResults runs the app tests of dir and returns each test's result
// by "<file>/<test>".
func truthTestResults(t *testing.T, dir string) map[string]AppTestResult {
	t.Helper()
	results, err := runServerTestsOnCopy(dir, "app")
	if err != nil {
		t.Fatalf("the run did not reach the tests: %v", err)
	}
	out := map[string]AppTestResult{}
	for _, r := range results {
		out[r.File+"/"+r.Test] = r
	}
	return out
}

const truthCreateNote = "    - api: \"POST /api/notes\"\n      json: {title: \"VARKEY\"}\n      save: {nid: id, ntitle: title}\n      expect: {status: 200}\n"

// A saved variable is read inside `expect` as it is in a path or a body.
// Before, `expect` kept the text `{{ntitle}}`: `not_contains: "{{ntitle}}"`
// compared the response with those ten characters and could never fail, so a
// leak check written with a saved value passed whatever the response held,
// while `contains` and `json` with a variable could never pass.
func TestExpectReadsSavedVariables(t *testing.T) {
	dir := truthTestApp(t, map[string]string{"vars.yaml": "" +
		"leak_is_caught:\n  as_user: \"a@example.com\"\n  steps:\n" + truthCreateNote +
		"    - get: \"/api/notes/{{nid}}\"\n      expect:\n        status: 200\n        contains: \"VARKEY\"\n        not_contains: \"{{ntitle}}\"\n" +
		"leak_in_a_list_is_caught:\n  as_user: \"b@example.com\"\n  steps:\n" + truthCreateNote +
		"    - get: \"/api/notes/{{nid}}\"\n      expect:\n        not_contains: [\"nothing-like-this\", \"{{ntitle}}\"]\n" +
		"contains_text:\n  as_user: \"c@example.com\"\n  steps:\n" + truthCreateNote +
		"    - get: \"/api/notes/{{nid}}\"\n      expect:\n        contains: \"{{ntitle}}\"\n" +
		"contains_list:\n  as_user: \"d@example.com\"\n  steps:\n" + truthCreateNote +
		"    - get: \"/api/notes/{{nid}}\"\n      expect:\n        contains: [\"title\", \"{{ntitle}}\"]\n" +
		"json_value:\n  as_user: \"e@example.com\"\n  steps:\n" + truthCreateNote +
		"    - get: \"/api/notes/{{nid}}\"\n      expect:\n        json: {id: \"{{nid}}\", title: \"{{ntitle}}\", user_id: \"{{user_id}}\"}\n" +
		"json_value_differs:\n  as_user: \"f@example.com\"\n  steps:\n" + truthCreateNote +
		"    - get: \"/api/notes/{{nid}}\"\n      expect:\n        json: {title: \"not-{{ntitle}}\"}\n" +
		"header_value:\n  as_user: \"g@example.com\"\n  steps:\n" +
		"    - sql: \"SELECT 'nosniff' AS sniff\"\n      save: {sniff: sniff}\n" +
		"    - get: \"/health\"\n      expect:\n        headers: {X-Content-Type-Options: \"{{sniff}}\"}\n" +
		"other_users_value_is_absent:\n  as_user: \"h@example.com\"\n  steps:\n" + truthCreateNote +
		"    - sql: \"SELECT 'someone-elses-secret' AS secret\"\n      save: {secret: secret}\n" +
		"    - get: \"/api/notes/{{nid}}\"\n      expect:\n        not_contains: \"{{secret}}\"\n",
	})
	got := truthTestResults(t, dir)
	for _, name := range []string{"contains_text", "contains_list", "json_value", "header_value", "other_users_value_is_absent"} {
		if r, ok := got["vars/"+name]; !ok || !r.Pass {
			t.Errorf("%s: %+v, want a pass (the saved value is in the response)", name, r)
		}
	}
	for name, want := range map[string]string{
		"leak_is_caught":           "Body should not contain 'VARKEY'",
		"leak_in_a_list_is_caught": "Body should not contain 'VARKEY'",
		"json_value_differs":       "expected 'not-VARKEY', got 'VARKEY'",
	} {
		r, ok := got["vars/"+name]
		if !ok || r.Pass {
			t.Errorf("%s: %+v, want a failed result", name, r)
			continue
		}
		if !strings.Contains(r.Message, want) {
			t.Errorf("%s: message %q does not say %q", name, r.Message, want)
		}
	}
}

// A `{{name}}` in `expect` that no earlier step saved fails the step and names
// the variable: compared as text it made `not_contains` pass on any response.
// So does a saved value that is empty, which `contains`/`not_contains` would
// not compare at all. Braces that are not a `{{name}}` stay text.
func TestExpectWithAnUnsavedVariableFailsTheStep(t *testing.T) {
	dir := truthTestApp(t, map[string]string{"unsaved.yaml": "" +
		"not_contains_unsaved:\n  as_user: \"a@example.com\"\n  steps:\n" + truthCreateNote +
		"    - get: \"/api/notes/{{nid}}\"\n      expect:\n        not_contains: \"{{other_users_secret}}\"\n" +
		"json_unsaved:\n  as_user: \"b@example.com\"\n  steps:\n" + truthCreateNote +
		"    - get: \"/api/notes/{{nid}}\"\n      expect:\n        json: {title: \"{{titel}}\"}\n" +
		"empty_saved_value:\n  as_user: \"d@example.com\"\n  steps:\n" + truthCreateNote +
		"    - sql: \"SELECT '' AS blank\"\n      save: {blank: blank}\n" +
		"    - get: \"/api/notes/{{nid}}\"\n      expect:\n        not_contains: \"{{blank}}\"\n" +
		"braces_that_are_text:\n  as_user: \"e@example.com\"\n  steps:\n" + truthCreateNote +
		"    - get: \"/api/notes/{{nid}}\"\n      expect:\n        not_contains: [\"{{\", \"{{ spaced }}\", \"{{user.email}}\", \"{{#each}}\"]\n",
	})
	got := truthTestResults(t, dir)
	for name, want := range map[string][]string{
		"not_contains_unsaved": {"`expect.not_contains`", "`{{other_users_secret}}`", "no earlier step", "`nid`", "was not run"},
		"json_unsaved":         {"`expect.json`", "`{{titel}}`", "`ntitle`"},
		"empty_saved_value":    {"`{{blank}}`", "empty"},
	} {
		r, ok := got["unsaved/"+name]
		if !ok || r.Pass {
			t.Errorf("%s: %+v, want a failed result", name, r)
			continue
		}
		for _, phrase := range want {
			if !strings.Contains(r.Message, phrase) {
				t.Errorf("%s: message %q does not say %q", name, r.Message, phrase)
			}
		}
	}
	if r := got["unsaved/braces_that_are_text"]; !r.Pass {
		t.Errorf("braces that are not a {{name}} were read as a variable: %+v", r)
	}
}

// A cookie-authenticated step with no body sends the CSRF token in
// X-CSRF-Token. The runner put it in a form body, which the server does not
// read on a DELETE, so `api: "DELETE /api/notes/1"` answered 403 "Invalid CSRF
// token" in a test and 200 on the served app.
func TestBodilessStepsSendTheCSRFToken(t *testing.T) {
	dir := truthTestApp(t, map[string]string{"nobody.yaml": "" +
		"delete_plain:\n  as_user: \"a@example.com\"\n  steps:\n" + truthCreateNote +
		"    - api: \"DELETE /api/notes/{{nid}}\"\n      expect: {status: 200}\n" +
		"    - sql: \"SELECT id FROM notes WHERE id = {{nid}}\"\n      expect: {rows: 0}\n" +
		"patch_plain:\n  as_user: \"b@example.com\"\n  steps:\n" + truthCreateNote +
		"    - api: \"PATCH /api/notes/{{nid}}\"\n      expect: {status: 400, contains: \"No fields to update\"}\n" +
		"post_plain:\n  as_user: \"c@example.com\"\n  steps:\n" +
		"    - api: \"POST /api/notes\"\n      expect: {status_in: [400, 422], not_contains: \"CSRF\"}\n" +
		"put_plain:\n  as_user: \"d@example.com\"\n  steps:\n" +
		"    - api: \"PUT /api/notes/1\"\n      expect: {status: 404}\n" +
		"delete_anonymous_is_refused:\n  anon: true\n  steps:\n" +
		"    - api: \"DELETE /api/notes/1\"\n      expect: {status_in: [401, 403, 404]}\n",
	})
	for name, r := range truthTestResults(t, dir) {
		if strings.HasPrefix(name, "nobody/") && !r.Pass {
			t.Errorf("%s failed: %s", name, r.Message)
		}
	}
}

// The request the runner builds for a step with no body: the token travels in
// the header for every method that changes something, PUT included, and never
// for an anonymous or Bearer step.
func TestBodilessStepRequestCarriesTheTokenInTheHeader(t *testing.T) {
	for _, tc := range []struct {
		method       string
		anon, bearer bool
		wantHeader   bool
	}{
		{"DELETE", false, false, true},
		{"PATCH", false, false, true},
		{"PUT", false, false, true},
		{"POST", false, false, true},
		{"GET", false, false, false},
		{"DELETE", true, false, false},
		{"DELETE", false, true, false},
	} {
		req, err := buildTestStepRequest("http://localhost:1", AppTestStep{API: tc.method + " /api/notes/1"}, tc.method, "/api/notes/1", tc.anon, tc.bearer)
		if err != nil {
			t.Fatal(err)
		}
		if got := req.Header.Get("X-CSRF-Token") != ""; got != tc.wantHeader {
			t.Errorf("%s anon=%v bearer=%v: X-CSRF-Token sent=%v, want %v", tc.method, tc.anon, tc.bearer, got, tc.wantHeader)
		}
		if tc.method == "DELETE" && req.Body != nil && req.Body != http.NoBody {
			t.Errorf("DELETE anon=%v bearer=%v carries a body the server never reads", tc.anon, tc.bearer)
		}
	}
}

// One run, one count. The text summary counted the source-check results and
// the SUMMARY entry of --json did not (`4/11` beside `4/10`); a test file that
// is not YAML was reported twice (`source check (syntax)` and `load`); and a
// test-file refusal carried no docs address, unlike the same reason from
// `benmore check`.
func TestTestRunCountsAgreeAndRefusalsCarryADocsAddress(t *testing.T) {
	dir := truthTestApp(t, map[string]string{
		"good.yaml":        "good:\n  anon: true\n  steps:\n    - get: \"/health\"\n      expect: {status: 200}\n",
		"bad_syntax.yaml":  "first:\n  steps: [\n",
		"bad_empty.yaml":   "",
		"bad_nosteps.yaml": "no_steps_test:\n  anon: true\n",
		"bad_key.yaml":     "typo:\n  anon: true\n  steps:\n    - get: \"/health\"\n      expect:\n        contain: \"ok\"\n",
	})
	// A source-check error of another file still counts, in both summaries.
	writeTestFile(t, dir, "flows/reserved.yaml", "on: {request: {method: GET, path: /api/v1/reserved, auth: none}}\njobs:\n  run: {steps: [{run: respond, with: {status: 200, json: {ok: true}}}]}\n")
	for _, mode := range []string{"all", "app", "framework"} {
		t.Run(mode, func(t *testing.T) {
			results, err := runServerTestsOnCopy(dir, mode)
			if err != nil {
				t.Fatalf("the run did not reach the tests: %v", err)
			}
			total, passed := testResultCounts(results)
			var summary string
			perFile := map[string][]string{}
			sourceChecks := 0
			for _, r := range results {
				if r.File == "SUMMARY" {
					if summary != "" {
						t.Errorf("more than one SUMMARY entry: %q and %q", summary, r.Message)
					}
					summary = r.Message
					continue
				}
				perFile[r.File] = append(perFile[r.File], r.Test)
				if strings.HasPrefix(r.Test, "source check") {
					sourceChecks++
				}
				switch {
				case r.Test == "load":
					if !strings.Contains(r.Message, `docs: api(at:"verification.test_file_load")`) {
						t.Errorf("%s load failure has no docs address: %q", r.File, r.Message)
					}
				case strings.HasPrefix(r.Message, appTestNotRun):
					if !strings.Contains(r.Message, `docs: api(at:"verification.test_keys")`) {
						t.Errorf("%s/%s refusal has no docs address: %q", r.File, r.Test, r.Message)
					}
				}
			}
			if want := fmt.Sprintf("%d/%d tests passed", passed, total); !strings.HasPrefix(summary, want) {
				t.Errorf("SUMMARY says %q; the results (and the text summary) count %d/%d", summary, passed, total)
			}
			if got := perFile["bad_syntax"]; len(got) != 1 || got[0] != "load" || len(perFile["tests/bad_syntax.yaml"]) != 0 {
				t.Errorf("tests/bad_syntax.yaml is reported as %v (and %v under its path), want one `load` result", got, perFile["tests/bad_syntax.yaml"])
			}
			if sourceChecks == 0 {
				t.Error("the reserved-prefix flow is no longer a failed source check")
			}
		})
	}
}

// An app whose mcp.yaml binds a command loads only with an ENCRYPTION_KEY, and
// a workspace of a hosted app has no env.yaml: `benmore test` stopped at "load
// app: ... requires configured ENCRYPTION_KEY". The disposable copy gets a key
// of its own, which never reaches the workspace or the results.
func TestCommandAppLoadsForTestsWithoutAConfiguredKey(t *testing.T) {
	t.Setenv("ENCRYPTION_KEY", "")
	os.Unsetenv("ENCRYPTION_KEY")
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	authorityDir := filepath.Join(root, "authority")
	if err := os.Mkdir(authorityDir, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authorityDir)
	dir := filepath.Join(root, "commandapp")
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE members(id INTEGER PRIMARY KEY, org_id TEXT, email TEXT);\nCREATE TABLE notes(id TEXT PRIMARY KEY, status TEXT);\n")
	writeTestFile(t, dir, "app.yaml", "groups: {table: members, key: org_id, user_field: email}\n")
	writeTestFile(t, dir, "tests/health.yaml", "health:\n  anon: true\n  steps:\n    - get: \"/health\"\n      expect: {status: 200}\n")
	// Last: the manifest's digests cover the source as it is now. A stale
	// digest loads the app with the connector withheld, which needs no key.
	writeActualLifecycleCommandFixture(t, dir)

	for _, env := range []string{"", "OTHER_VALUE: preserved\n"} {
		if env == "" {
			_ = os.Remove(filepath.Join(dir, "env.yaml"))
		} else {
			writeTestFile(t, dir, "env.yaml", env)
		}
		results, err := runServerTestsOnCopy(dir, "app")
		if err != nil {
			t.Fatalf("env.yaml %q: the run did not reach the tests: %v", env, err)
		}
		ran := false
		for _, r := range results {
			if r.File == "health" && r.Test == "health" {
				ran = r.Pass
			}
			if !r.Pass {
				t.Errorf("env.yaml %q: %s/%s failed: %s", env, r.File, r.Test, r.Message)
			}
		}
		if !ran {
			t.Errorf("env.yaml %q: the app's test did not run and pass: %+v", env, results)
		}
		after, readErr := os.ReadFile(filepath.Join(dir, "env.yaml"))
		if env == "" && !os.IsNotExist(readErr) {
			t.Errorf("the run wrote env.yaml into the workspace: %q", after)
		}
		if env != "" && string(after) != env {
			t.Errorf("the run changed the workspace's env.yaml: %q", after)
		}
	}

	// The key is written into the copy only, beside what env.yaml already holds.
	writeTestFile(t, dir, "env.yaml", "OTHER_VALUE: preserved\n")
	copyDir, cleanup, err := disposableTestCopy(dir, "benmore-test-*", "commandapp", true)
	if err != nil {
		t.Fatal(err)
	}
	vars, err := readAppEnv(copyDir)
	cleanup()
	if err != nil || len(vars["ENCRYPTION_KEY"]) != 64 || vars["OTHER_VALUE"] != "preserved" {
		t.Errorf("the copy's environment: key of %d characters, OTHER_VALUE=%q, err=%v", len(vars["ENCRYPTION_KEY"]), vars["OTHER_VALUE"], err)
	}
	if os.Getenv("ENCRYPTION_KEY") != "" {
		t.Error("the test key reached the process environment")
	}

	// A key the app configures is the one the copy loads with.
	writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("ab", 32)+"\n")
	copyDir, cleanup, err = disposableTestCopy(dir, "benmore-test-*", "commandapp", true)
	if err != nil {
		t.Fatal(err)
	}
	defer cleanup()
	if got, _ := os.ReadFile(filepath.Join(copyDir, "env.yaml")); string(got) != "ENCRYPTION_KEY: "+strings.Repeat("ab", 32)+"\n" {
		t.Errorf("a configured key was replaced in the copy: %q", got)
	}
}

// The disposable copy lives under a path with no symbolic link in it, whatever
// TMPDIR is: on macOS the default TMPDIR is under /var, a link to /private/var,
// and an app refuses to load from a path that is not its canonical one.
func TestDisposableTestCopyIsUnderACanonicalPath(t *testing.T) {
	real, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(real, "tmp-link")
	target := filepath.Join(real, "tmp-real")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("cannot create a symbolic link here: %v", err)
	}
	t.Setenv("TMPDIR", link)
	src := truthTestApp(t, nil)
	for _, keepEnv := range []bool{true, false} {
		copyDir, cleanup, err := disposableTestCopy(src, "benmore-truth-*", "source", keepEnv)
		if err != nil {
			t.Fatal(err)
		}
		resolved, err := filepath.EvalSymlinks(copyDir)
		if err != nil || resolved != copyDir {
			t.Errorf("the copy is at %s, which resolves to %s (%v)", copyDir, resolved, err)
		}
		if !strings.HasPrefix(copyDir, target+string(filepath.Separator)) {
			t.Errorf("the copy is at %s, want it under TMPDIR's target %s", copyDir, target)
		}
		app, err := loadAppForServerTests(copyDir)
		if err != nil {
			t.Errorf("the app does not load from the copy: %v", err)
		} else {
			app.Shutdown()
		}
		cleanup()
		if _, err := os.Stat(filepath.Dir(copyDir)); !os.IsNotExist(err) {
			t.Errorf("the copy was not removed: %v", err)
		}
	}
}

// substituteExpectVars reads every text of `expect` and leaves the step's own
// maps as they were.
func TestSubstituteExpectVarsCoversEveryTextOfExpect(t *testing.T) {
	vars := map[string]string{"path": "/login", "word": "hello", "kind": "nosniff", "holder": "{{word}}"}
	in := AppTestExpect{
		Redirect:    "{{path}}?next=1",
		Contains:    []any{"{{word}}", "plain"},
		NotContains: "{{holder}}",
		JSONField:   map[string]any{"items[0].{{word}}": "{{word}}", "n": 5, "nested": map[string]any{"k": []any{"{{word}}"}}},
		Headers:     map[string]string{"X-Content-Type-Options": "{{kind}}"},
	}
	out, problem := substituteExpectVars(in, vars)
	if problem != "" {
		t.Fatalf("problem = %q, want none", problem)
	}
	if out.Redirect != "/login?next=1" {
		t.Errorf("redirect = %q", out.Redirect)
	}
	if got := expectContains(out.Contains); len(got) != 2 || got[0] != "hello" || got[1] != "plain" {
		t.Errorf("contains = %v", got)
	}
	// One pass: a saved value that looks like a variable is written as it is.
	if got := expectContains(out.NotContains); len(got) != 1 || got[0] != "{{word}}" {
		t.Errorf("not_contains = %v, want the saved value itself", got)
	}
	if out.JSONField["items[0].hello"] != "hello" || out.JSONField["n"] != 5 {
		t.Errorf("json = %v", out.JSONField)
	}
	if nested, _ := out.JSONField["nested"].(map[string]any); fmt.Sprint(nested["k"]) != "[hello]" {
		t.Errorf("json nested = %v", out.JSONField["nested"])
	}
	if out.Headers["X-Content-Type-Options"] != "nosniff" {
		t.Errorf("headers = %v", out.Headers)
	}
	if in.JSONField["items[0].{{word}}"] != "{{word}}" || in.Headers["X-Content-Type-Options"] != "{{kind}}" {
		t.Error("the step's own expect was changed; a second run of the test would read the first run's values")
	}
	for key, expect := range map[string]AppTestExpect{
		"redirect":     {Redirect: "{{nowhere}}"},
		"contains":     {Contains: "{{nowhere}}"},
		"not_contains": {NotContains: []any{"ok", "{{nowhere}}"}},
		"json":         {JSONField: map[string]any{"id": "{{nowhere}}"}},
		"headers":      {Headers: map[string]string{"Location": "{{nowhere}}"}},
	} {
		_, problem := substituteExpectVars(expect, vars)
		if !strings.Contains(problem, "`expect."+key+"`") || !strings.Contains(problem, "`{{nowhere}}`") || !strings.Contains(problem, `docs: api(at:"verification.test_variables")`) {
			t.Errorf("%s with an unsaved variable: problem = %q", key, problem)
		}
	}
}

const truthActorsTest = "" +
	"second_user_by_name:\n  as_user: \"alice@example.com\"\n  users: [\"bob@example.com\"]\n  steps:\n" + truthCreateNote +
	"    - set_auth: \"bob_token\"\n" +
	"    - get: \"/api/_auth/sessions\"\n      expect: {status: 200}\n" +
	"    - get: \"/api/notes\"\n      expect: {status: 200, json_length: 0, not_contains: \"{{ntitle}}\"}\n" +
	"    - api: \"POST /api/notes\"\n      json: {title: \"bobs-note\"}\n      save: {bob_note: id}\n      expect: {status: 200}\n" +
	"    - sql: \"SELECT n.id FROM notes n JOIN _benmore_users u ON u.id = n.user_id WHERE n.id = {{bob_note}} AND u.email = 'bob@example.com'\"\n      expect: {rows: 1}\n" +
	"    - set_auth: \"{{alice_token}}\"\n" +
	"    - get: \"/api/notes\"\n      expect: {status: 200, json_length: 1, contains: \"{{ntitle}}\", not_contains: \"bobs-note\"}\n" +
	"second_user_as_variable:\n  as_user: \"carol@example.com\"\n  users: [\"dave@example.com\"]\n  steps:\n" + truthCreateNote +
	"    - set_auth: \"{{dave_token}}\"\n" +
	"    - get: \"/api/notes/{{nid}}\"\n      expect: {status: 404}\n" +
	"    - get: \"/api/notes\"\n      expect: {status: 200, json_length: 0}\n" +
	"setup_sees_the_users:\n  as_user: \"erin@example.com\"\n  users: [\"frank@example.com\"]\n  setup:\n" +
	"    - sql: \"INSERT INTO notes (title, user_id) VALUES ('franks-seed', (SELECT id FROM _benmore_users WHERE email = 'frank@example.com'))\"\n  steps:\n" +
	"    - get: \"/api/notes\"\n      expect: {status: 200, not_contains: \"franks-seed\"}\n" +
	"    - set_auth: \"frank_token\"\n" +
	"    - get: \"/api/notes\"\n      expect: {status: 200, json_length: 1, contains: \"franks-seed\"}\n"

// A step acts as one of the test's `users:` accounts with the token the runner
// saves for it, `<local part>_token`, written as the bare name or as a
// variable. The accounts used to be created and their sessions dropped, so
// `set_auth: "bob_token"` sent those nine characters as the Bearer token and
// every later step answered 401. They exist before `setup:` runs, so a seed
// row can belong to one.
func TestStepsActAsTheUsersOfATest(t *testing.T) {
	dir := truthTestApp(t, map[string]string{"actors.yaml": truthActorsTest +
		"unknown_name_is_still_a_token:\n  as_user: \"gina@example.com\"\n  steps:\n" +
		"    - set_auth: \"nobody_token\"\n" +
		"    - get: \"/api/notes\"\n      expect: {status: 401}\n",
	})
	got := truthTestResults(t, dir)
	for _, name := range []string{"second_user_by_name", "second_user_as_variable", "setup_sees_the_users", "unknown_name_is_still_a_token"} {
		if r, ok := got["actors/"+name]; !ok || !r.Pass {
			t.Errorf("%s: %+v, want a pass", name, r)
		}
	}
}

// Under compliance: hipaa the token exchange needs an MFA code no test knows,
// so the saved token is the only way a test acts as a second user there. The
// fixture's own tests (CI runs them with `benmore test --app`) hold the case.
func TestStepsActAsTheUsersOfATestUnderHipaa(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "hipaa")
	if err := os.CopyFS(dir, os.DirFS(filepath.Join("testdata", "compliance-hipaa"))); err != nil {
		t.Fatal(err)
	}
	got := truthTestResults(t, dir)
	for _, name := range []string{"actors/second_account_reads_only_its_own_notes", "actors/token_exchange_needs_a_code_no_test_has"} {
		if r, ok := got[name]; !ok || !r.Pass {
			t.Errorf("%s: %+v, want a pass", name, r)
		}
	}
	for name, r := range got {
		if !r.Pass {
			t.Errorf("%s failed: %s", name, r.Message)
		}
	}
}
