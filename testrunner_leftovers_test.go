//go:build !cli

package main

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

// A `save:` that saves nothing fails its step. It used to save nothing
// without a word: the `{{name}}` of a later step was then sent as written, so
// `get: "/api/notes/{{nid}}"` asked for a row that cannot exist and
// `expect: {status: 404}` passed whatever the app's access rules said.
func TestSaveThatSavesNothingFailsItsStep(t *testing.T) {
	dir := truthTestApp(t, map[string]string{"saves.yaml": "" +
		"missing_field_then_404:\n  as_user: \"a@example.com\"\n  users: [\"b@example.com\"]\n  steps:\n" +
		"    - api: \"POST /api/notes\"\n      json: {title: \"VARKEY\"}\n      save: {nid: idd}\n      expect: {status: 200}\n" +
		"    - set_auth: \"b_token\"\n" +
		"    - get: \"/api/notes/{{nid}}\"\n      expect: {status: 404}\n" +
		"null_field:\n  as_user: \"c@example.com\"\n  steps:\n" +
		"    - sql: \"SELECT 1 AS one, NULL AS absent\"\n      save: {n: absent}\n" +
		"not_an_object:\n  as_user: \"d@example.com\"\n  steps:\n" +
		"    - get: \"/api/notes\"\n      save: {first: id}\n      expect: {status: 200}\n" +
		"sql_without_rows:\n  as_user: \"e@example.com\"\n  steps:\n" +
		"    - sql: \"SELECT id FROM notes WHERE title = 'no-such-note'\"\n      save: {nid: id}\n" +
		"sql_without_the_column:\n  as_user: \"f@example.com\"\n  steps:\n" +
		"    - sql: \"SELECT 7 AS seven, 8 AS eight\"\n      save: {n: nine}\n" +
		"sql_that_returns_no_row:\n  as_user: \"g@example.com\"\n  steps:\n" +
		"    - sql: \"UPDATE notes SET body = 'x' WHERE id = -1\"\n      save: {n: id}\n" +
		"save_on_a_step_with_no_response:\n  as_user: \"j@example.com\"\n  users: [\"k@example.com\"]\n  steps:\n" +
		"    - set_auth: \"k_token\"\n      save: {t: token}\n" +
		"save_on_a_flush:\n  as_user: \"l@example.com\"\n  steps:\n" +
		"    - flush: \"jobs\"\n      save: {n: count}\n" +
		"failed_step_keeps_its_own_message:\n  as_user: \"h@example.com\"\n  steps:\n" +
		"    - get: \"/api/notes/999999\"\n      save: {n: idd}\n      expect: {status: 200}\n" +
		"every_field_is_there:\n  as_user: \"i@example.com\"\n  steps:\n" + truthCreateNote +
		"    - sql: \"SELECT title AS t, '' AS blank FROM notes WHERE id = {{nid}}\"\n      save: {t: t, blank: blank}\n" +
		"    - get: \"/api/notes/{{nid}}\"\n      expect: {status: 200, contains: \"{{t}}\"}\n" +
		// A write that returns its row saves from it, and runs once.
		"    - sql: \"INSERT INTO notes (title, user_id) VALUES ('returned', {{user_id}}) RETURNING id\"\n      save: {rid: id}\n" +
		"    - get: \"/api/notes/{{rid}}\"\n      expect: {status: 200, contains: \"returned\"}\n" +
		"    - sql: \"SELECT id FROM notes WHERE title = 'returned'\"\n      expect: {rows: 1}\n",
	})
	got := truthTestResults(t, dir)
	for name, want := range map[string][]string{
		"missing_field_then_404":          {"Step 1 failed", "`save: {nid: idd}`", "the response has no field `idd`", "`id`", "`title`", "`user_id`", "`{{nid}}` would be sent as written", `docs: api(at:"verification.test_variables")`},
		"null_field":                      {"Step 1 failed", "`save: {n: absent}`", "`absent` is null in the first row"},
		"not_an_object":                   {"Step 1 failed", "`save: {first: id}`", "not a JSON object", "a JSON array"},
		"sql_without_rows":                {"Step 1 failed", "`save: {nid: id}`", "returned no rows"},
		"sql_without_the_column":          {"Step 1 failed", "`save: {n: nine}`", "the first row has no column `nine`", "`eight`, `seven`"},
		"sql_that_returns_no_row":         {"Step 1 failed", "`save: {n: id}`", "returned no rows"},
		"save_on_a_step_with_no_response": {"Step 1 failed", "`save: {t: token}`", "a `set_auth:` step has no response"},
		"save_on_a_flush":                 {"Step 1 failed", "`save: {n: count}`", "a `flush:` step has no response"},
	} {
		r, ok := got["saves/"+name]
		if !ok || r.Pass {
			t.Errorf("%s: %+v, want a failed result", name, r)
			continue
		}
		for _, phrase := range want {
			if !strings.Contains(r.Message, phrase) {
				t.Errorf("%s: message %q does not say %q", name, r.Message, phrase)
			}
		}
		if len(r.Steps) != 1 || r.Steps[0].Pass {
			t.Errorf("%s: steps %+v, want the saving step failed and nothing after it run", name, r.Steps)
		}
	}
	// A step that failed on its own says so; what it would have saved is
	// not the news.
	if r := got["saves/failed_step_keeps_its_own_message"]; r.Pass || !strings.Contains(r.Message, "Expected status 200, got 404") || strings.Contains(r.Message, "save:") {
		t.Errorf("a failed step with a save: %+v, want its own status failure", r)
	}
	// An empty text is a value; only a missing or null field saves nothing.
	if r, ok := got["saves/every_field_is_there"]; !ok || !r.Pass {
		t.Errorf("every_field_is_there: %+v, want a pass", r)
	}
}

// A `{{name}}` nothing saved, outside `expect`, is sent as written and the
// test's result says so in a warning. It is not a failure: a test may store
// template text on purpose.
func TestUnsavedVariableOutsideExpectWarns(t *testing.T) {
	dir := truthTestApp(t, map[string]string{"warns.yaml": "" +
		"in_the_path:\n  as_user: \"a@example.com\"\n  steps:\n" + truthCreateNote +
		"    - get: \"/api/notes/{{note_id}}\"\n      expect: {status_in: [400, 404]}\n" +
		"in_the_body:\n  as_user: \"b@example.com\"\n  steps:\n" +
		"    - api: \"POST /api/notes\"\n      json: {title: \"Dear {{first_name}}\", body: \"{{ spaced }} {{user.email}} {{#each}}\"}\n      save: {nid: id}\n      expect: {status: 200}\n" +
		"    - get: \"/api/notes/{{nid}}\"\n      expect: {status: 200}\n" +
		"in_the_sql:\n  as_user: \"c@example.com\"\n  steps:\n" +
		"    - sql: \"SELECT id FROM notes WHERE title = '{{nowhere}}'\"\n      expect: {rows: 0}\n" +
		"in_set_auth:\n  as_user: \"d@example.com\"\n  steps:\n" +
		"    - set_auth: \"{{my_token}}\"\n" +
		"    - get: \"/api/notes\"\n      expect: {status: 401}\n" +
		"everything_saved:\n  as_user: \"e@example.com\"\n  users: [\"f@example.com\"]\n  steps:\n" + truthCreateNote +
		"    - sql: \"SELECT id FROM notes WHERE id = {{nid}} AND user_id = {{user_id}}\"\n      expect: {rows: 1}\n" +
		"    - set_auth: \"{{f_token}}\"\n" +
		"    - get: \"/api/notes/{{nid}}\"\n      expect: {status: 404}\n",
	})
	got := truthTestResults(t, dir)
	for name, want := range map[string][]string{
		"in_the_path": {"step 2: `{{note_id}}` in the path was sent as written", "saved `note_id`", "`nid`", `docs: api(at:"verification.test_variables")`},
		"in_the_body": {"step 1", "`{{first_name}}`", "the body"},
		"in_the_sql":  {"step 1", "`{{nowhere}}`", "the SQL"},
		"in_set_auth": {"step 1", "`{{my_token}}`", "`set_auth`"},
	} {
		r, ok := got["warns/"+name]
		if !ok || !r.Pass {
			t.Errorf("%s: %+v, want a pass (an unsaved name outside expect is a warning)", name, r)
			continue
		}
		if len(r.Warnings) != 1 {
			t.Errorf("%s: warnings %q, want one", name, r.Warnings)
			continue
		}
		for _, phrase := range want {
			if !strings.Contains(r.Warnings[0], phrase) {
				t.Errorf("%s: warning %q does not say %q", name, r.Warnings[0], phrase)
			}
		}
		for _, text := range []string{"spaced", "user.email", "#each"} {
			if strings.Contains(r.Warnings[0], text) {
				t.Errorf("%s: warning names template text %q: %s", name, text, r.Warnings[0])
			}
		}
	}
	if r := got["warns/everything_saved"]; !r.Pass || len(r.Warnings) != 0 {
		t.Errorf("everything_saved: %+v, want a pass with no warning", r)
	}

	// The text output carries the warning under its test, passed or failed.
	var out bytes.Buffer
	writeTestResults(&out, []AppTestResult{
		{File: "warns", Test: "passes", Pass: true, Warnings: []string{"step 2 sends `{{x}}`"}},
		{File: "warns", Test: "fails", Pass: false, Message: "Step 1 failed: no", Warnings: []string{"step 1 sends `{{y}}`"}},
	})
	for _, want := range []string{"test: 1/2 passed, 2 warnings\n", "PASS warns/passes\n  WARNING: step 2 sends `{{x}}`\n", "FAIL warns/fails\n  Step 1 failed: no\n  WARNING: step 1 sends `{{y}}`\n"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("text output lacks %q:\n%s", want, out.String())
		}
	}
}

// Every result about a test file names it one way: the file's name without
// the directory and the extension, as each of its tests does. A file that
// did not load was `tests/<file>.yaml`.
func TestResultsNameATestFileOneWay(t *testing.T) {
	dir := truthTestApp(t, map[string]string{
		"good.yaml":        "good:\n  anon: true\n  steps:\n    - get: \"/health\"\n      expect: {status: 200}\n",
		"bad_syntax.yaml":  "first:\n  steps: [\n",
		"bad_list.yml":     "- not\n- tests\n",
		"bad_nosteps.yaml": "no_steps_test:\n  anon: true\n",
	})
	for _, mode := range []string{"all", "app", "framework"} {
		t.Run(mode, func(t *testing.T) {
			results, err := runServerTestsOnCopy(dir, mode)
			if err != nil {
				t.Fatalf("the run did not reach the tests: %v", err)
			}
			byName := map[string][]AppTestResult{}
			for _, r := range results {
				byName[r.File+"/"+r.Test] = append(byName[r.File+"/"+r.Test], r)
				if strings.HasPrefix(r.File, "tests/") && r.File != "tests/" {
					t.Errorf("result %s/%s names its file with the directory", r.File, r.Test)
				}
			}
			for name, path := range map[string]string{"bad_syntax/load": "tests/bad_syntax.yaml: ", "bad_list/load": "tests/bad_list.yml: "} {
				rs := byName[name]
				if len(rs) != 1 || rs[0].Pass {
					t.Errorf("%s: %+v, want one failed result", name, rs)
					continue
				}
				// The path is in the message, as for a test that is not run.
				if !strings.HasPrefix(rs[0].Message, path+appTestFileNotLoaded) {
					t.Errorf("%s: message %q does not start with the file's path", name, rs[0].Message)
				}
			}
			if rs := byName["bad_nosteps/no_steps_test"]; len(rs) != 1 || rs[0].Pass || !strings.Contains(rs[0].Message, "tests/bad_nosteps.yaml: ") {
				t.Errorf("bad_nosteps/no_steps_test: %+v, want one failed result that names tests/bad_nosteps.yaml", rs)
			}
			// A file that is not YAML is still one result, not the push's
			// syntax check as well.
			for _, r := range results {
				if strings.HasPrefix(r.Test, sourceCheckTestPrefix) && strings.Contains(r.File, "bad_syntax") {
					t.Errorf("bad_syntax.yaml is also reported as %s/%s", r.File, r.Test)
				}
			}
		})
	}
}

// A YAML file that does not parse and that no validator owns carries the
// address of the key about it. It carried `cron.contract`, the fallback of the
// check's syntax layer, whatever the file was.
func TestYAMLSyntaxErrorCarriesItsOwnAddress(t *testing.T) {
	dir := truthTestApp(t, map[string]string{"broken.yaml": "first:\n  steps: [\n"})
	writeTestFile(t, dir, "notes/fixtures.yaml", "rows: [\n")
	docs := map[string]string{}
	// The whole app, then the check of one written file (a full check reads
	// the files the framework loads, and the tests).
	for _, f := range append(RunSourceCheck(dir, "").Findings, RunSourceCheck(dir, "notes/fixtures.yaml").Findings...) {
		if f.Severity == "error" && f.Source == "syntax" {
			docs[filepath.ToSlash(f.File)] = f.Docs
		}
	}
	for file, want := range map[string]string{
		"tests/broken.yaml":   "verification.test_file_load",
		"notes/fixtures.yaml": "verification.yaml_syntax",
	} {
		if got, ok := docs[file]; !ok || got != want {
			t.Errorf("%s: syntax finding docs %q (found %v), want %q", file, got, ok, want)
		}
		refusal := ValidateOnWriteIn(dir, file, "rows: [\n")
		if !strings.Contains(refusal, "yaml syntax in "+file) || !strings.Contains(refusal, docsLine(want)) {
			t.Errorf("%s: write refusal %q does not carry %s", file, refusal, docsLine(want))
		}
	}
	// The source check of a test run words it the same way.
	for _, r := range sourceCheckTestResults(dir) {
		if strings.Contains(r.Message, "cron.contract") {
			t.Errorf("%s/%s points at cron.contract: %s", r.File, r.Test, r.Message)
		}
	}
	// A syntax finding with no address of its own gets none from the layer.
	if got := withFindingDocs([]CheckFinding{{Severity: "error", Source: "syntax", File: "x.yaml", Message: "x"}})[0].Docs; got != "" {
		t.Errorf("a syntax finding without an address is given %q", got)
	}
}

const usersWithRolesTest = "" +
	"roles_are_given:\n  as_user: \"owner@example.com\"\n  users:\n    - \"plain@example.com\"\n    - {email: \"boss@example.com\", role: admin}\n    - email: \"norole@example.com\"\n  steps:\n" + truthCreateNote +
	"    - sql: \"SELECT email FROM _benmore_users WHERE (email = 'boss@example.com' AND role = 'admin') OR (email IN ('plain@example.com', 'norole@example.com') AND role = 'user')\"\n      expect: {rows: 3}\n" +
	// The admin reads every row; the plain user reads its own, none.
	"    - set_auth: \"boss_token\"\n" +
	"    - get: \"/api/notes/{{nid}}\"\n      expect: {status: 200, contains: \"{{ntitle}}\"}\n" +
	"    - set_auth: \"plain_token\"\n" +
	"    - get: \"/api/notes/{{nid}}\"\n      expect: {status: 404}\n" +
	"    - set_auth: \"norole_token\"\n" +
	"    - get: \"/api/notes/{{nid}}\"\n      expect: {status: 404}\n" +
	// An account an earlier test created has the role this test gives it.
	"role_of_an_existing_account:\n  as_user: \"owner2@example.com\"\n" +
	"  users: [\"was-user@example.com\", {email: \"was-user@example.com\", role: \"admin\"}]\n  steps:\n" + truthCreateNote +
	"    - set_auth: \"was-user_token\"\n" +
	"    - get: \"/api/notes/{{nid}}\"\n      expect: {status: 200}\n"

// `users:` entries are an email, or a mapping of `email` and the `role` the
// account has in the test. Every entry was a plain address with role `user`:
// a mapping failed the whole file.
func TestUsersEntriesTakeARole(t *testing.T) {
	dir := truthTestApp(t, map[string]string{
		"roles.yaml": usersWithRolesTest,
		"refused.yaml": "" +
			"misspelled_role:\n  as_user: \"a@example.com\"\n  users:\n    - {email: \"b@example.com\", rol: admin}\n  steps:\n    - get: \"/health\"\n" +
			"no_email:\n  as_user: \"c@example.com\"\n  users:\n    - \"d@example.com\"\n    - {role: admin}\n  steps:\n    - get: \"/health\"\n" +
			"a_list:\n  as_user: \"e@example.com\"\n  users:\n    - [\"f@example.com\", admin]\n  steps:\n    - get: \"/health\"\n" +
			"still_runs:\n  as_user: \"g@example.com\"\n  users: [\"h@example.com\"]\n  steps:\n    - get: \"/health\"\n",
	})
	got := truthTestResults(t, dir)
	for _, name := range []string{"roles/roles_are_given", "roles/role_of_an_existing_account", "refused/still_runs"} {
		if r, ok := got[name]; !ok || !r.Pass {
			t.Errorf("%s: %+v, want a pass", name, r)
		}
	}
	for name, want := range map[string][]string{
		"misspelled_role": {appTestNotRun, "tests/refused.yaml: line 4:", "unknown key `rol` in `users` entry 1", "did you mean `role`?"},
		"no_email":        {appTestNotRun, "line 11:", "`users` entry 2 has no `email`"},
		"a_list":          {appTestNotRun, "line 17:", "`users` entry 1 is a list", "an email, or a mapping of `email` and `role`"},
	} {
		r, ok := got["refused/"+name]
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
	// `benmore check` says the same about the file, as a warning.
	if msg := appTestFileWarning("tests/refused.yaml", "t:\n  users:\n    - {email: \"b@example.com\", rol: admin}\n  steps:\n    - get: \"/health\"\n"); !strings.Contains(msg, "unknown key `rol` in `users` entry 1") {
		t.Errorf("check warning for a misspelled users key: %q", msg)
	}
}
