//go:build !cli

package main

import (
	"bytes"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

const strictFixture = "testdata/test-not-read-in-full"

// refusedFixtureTests are the tests of the fixture the runner must fail
// without running, by result (file/test), each with what its reason must say:
// the key, the nearest key it knows, and the file with the line.
var refusedFixtureTests = map[string][]string{
	"misspelled_expect/health_is_down":               {"tests/misspelled_expect.yaml: line 7:", "unknown key `expects` in step 1", "did you mean `expect`?"},
	"misspelled_steps/health_is_down":                {"tests/misspelled_steps.yaml: line 2:", "the test has no steps", "line 4: unknown key `step` in the test", "did you mean `steps`?"},
	"unknown_expect_key/health_names_a_missing_text": {"tests/unknown_expect_key.yaml: line 8:", "unknown key `contain` in `expect` of step 1", "did you mean `contains`?"},
	"no_steps/nothing_to_run":                        {"tests/no_steps.yaml: line 2:", "the test has no steps"},
	"step_without_action/expects_without_a_request":  {"tests/step_without_action.yaml: line 7:", "step 1 has no action", "`api`, `flush`, `get`, `post`, `set_auth`, `sql`"},
	"unknown_setup_key/setup_is_misspelled":          {"tests/unknown_setup_key.yaml: line 6:", "unknown key `sqll` in setup entry 1", "did you mean `sql`?", "setup entry 1 has no `sql:`"},
	"two_actions/request_and_sql_in_one_step":        {"tests/two_actions.yaml: line 6:", "step 1 has more than one action (`get`, `sql`)"},
	"expect_on_sql_step/sql_result_holds_a_text":     {"tests/expect_on_sql_step.yaml: line 8:", "step 1 is a `sql:` step, which never checks `expect.contains`", "it checks `rows`"},
	"number_under_contains/health_holds_a_number":    {"tests/number_under_contains.yaml: line 8:", "`expect.contains` of step 1 holds a number (424242)", "quote a number"},
}

// `benmore test` fails a test it cannot read in full, in each mode, and still
// runs the tests it can read. Every refused test of the fixture reported PASS
// before: `expects:` for `expect:` left the step with no assertion, `step:`
// for `steps:` and a test with no steps ran nothing, `contain:` under `expect`
// was dropped, a step with no action was sent as a GET for the empty path.
func TestBenmoreTestFailsATestItCannotReadInFull(t *testing.T) {
	for _, mode := range []string{"all", "app", "framework"} {
		t.Run(mode, func(t *testing.T) {
			results, err := runServerTestsOnCopy(strictFixture, mode)
			if err != nil {
				t.Fatalf("the run did not reach the tests: %v", err)
			}
			got := map[string]AppTestResult{}
			var summary *AppTestResult
			for i, r := range results {
				if r.File == "SUMMARY" {
					summary = &results[i]
					continue
				}
				got[r.File+"/"+r.Test] = r
			}
			for name, wants := range refusedFixtureTests {
				r, ok := got[name]
				if !ok {
					t.Errorf("%s: no result; a refused test must be reported in every mode", name)
					continue
				}
				if r.Pass || r.Skipped {
					t.Errorf("%s is reported as pass=%v skipped=%v, want a failed result", name, r.Pass, r.Skipped)
				}
				if len(r.Steps) != 0 || r.Duration != "" {
					t.Errorf("%s ran (steps %d, duration %q); a refused test runs nothing", name, len(r.Steps), r.Duration)
				}
				if !strings.HasPrefix(r.Message, appTestNotRun) {
					t.Errorf("%s: message does not start with %q: %s", name, appTestNotRun, r.Message)
				}
				for _, want := range wants {
					if !strings.Contains(r.Message, want) {
						t.Errorf("%s: message does not say %q: %s", name, want, r.Message)
					}
				}
				// Builder-facing text: no Go names from the structs.
				for _, internal := range []string{"main.", "AppTest", "yaml:\"", "interface {}"} {
					if strings.Contains(r.Message, internal) {
						t.Errorf("%s: message carries internals (%q): %s", name, internal, r.Message)
					}
				}
			}
			// The tests the runner reads in full run and pass in the modes
			// that run app tests, and are left out of --framework.
			readable := []string{"loads/health_answers", "loads/request_step_without_expect", "loads/every_kind_of_step", "loads/merged_from_an_anchor", "loads/uses_the_anchor"}
			for _, name := range readable {
				r, ran := got[name]
				if mode == "framework" {
					if ran {
						t.Errorf("--framework ran the app test %s", name)
					}
					continue
				}
				if !ran || !r.Pass {
					t.Errorf("%s: ran=%v result=%+v, want it to run and pass beside the refused tests", name, ran, r)
				}
			}
			if testResultsPassed(results) {
				t.Error("the run counts as passed (exit 0) with tests it could not read in full")
			}
			if summary == nil || summary.Pass {
				t.Errorf("SUMMARY = %+v, want a failed summary", summary)
			}
			// Nothing else of the fixture fails: the generated tests still run.
			for name, r := range got {
				if _, refused := refusedFixtureTests[name]; !refused && !r.Pass {
					t.Errorf("%s failed: %s", name, r.Message)
				}
			}
			if mode != "app" && !got["_framework_crud/list_notes"].Pass {
				t.Errorf("the generated tests did not run in mode %s: %+v", mode, got["_framework_crud/list_notes"])
			}
		})
	}
}

// strictSampleFile holds one test per problem the reader refuses and tests it
// must accept, for the checks below.
const strictSampleFile = `
shared: &shared
  as_user: "a@test.com"
  setup:
    - sql: "DELETE FROM notes"
  steps:
    - get: "/health"
      expect: {status: 200, contains: ["a", "b"], max_duration: "2s"}
    - sql: "SELECT 1"
      expect: {rows: 1}
    - flush: jobs
    - set_auth: none
    - api: "POST /api/_upload"
      files:
        doc: {name: a.txt, content: hello}
      save: {anything: goes, here: too}
      data: {free: form, nested: {keys: [1, 2]}}
      expect:
        json:
          "errors[0].field": 1
        headers: {X-Any-Header: "1"}
        status_in: [200, 401]
merged_ok:
  <<: *shared
merged_with_typo:
  <<: *shared
  as_usr: "b@test.com"
test_level:
  anon: true
  asuser: "a@test.com"
  steps: [{get: "/health"}]
setup_level:
  setup:
    - {sql: "SELECT 1", sq: "SELECT 2"}
  steps: [{get: "/health"}]
step_level:
  steps:
    - get: "/health"
      body: {title: x}
expect_level:
  steps:
    - get: "/health"
      expect: {status_code: 200}
files_level:
  steps:
    - api: "POST /api/_upload"
      files:
        doc: {name: a.txt, contents: hello}
far_from_any_key:
  steps:
    - get: "/health"
      timeout: 5
expect_key_on_the_step:
  steps:
    - get: "/health"
      status: 200
step_key_on_the_test:
  anon: true
  get: "/health"
  steps: [{get: "/health"}]
anchored_typo: &typo
  anon: true
  steps:
    - get: "/health"
      expects: {status: 500}
inherits_the_typo:
  <<: *typo
other_spelling:
  asUser: "a@test.com"
  steps:
    - get: "/health"
      expect: {not-contains: "x", statusIn: [200]}
empty_expect_values_on_a_sql_step:
  steps:
    - sql: "SELECT 1"
      expect: {status_in: [], headers: {}, json: {}}
empty_test:
empty_steps:
  steps: []
action_is_empty_text:
  steps:
    - get: ""
rows_on_a_request:
  steps:
    - get: "/health"
      expect: {rows: 0}
expect_on_set_auth:
  steps:
    - set_auth: none
      expect: {status: 200}
list_holds_a_mapping:
  steps:
    - get: "/health"
      expect:
        not_contains: ["fine", {oops: 1}]
duration_is_not_one:
  steps:
    - get: "/health"
      expect: {max_duration: quick}
status_and_status_in:
  steps:
    - get: "/health"
      expect: {status: 500, status_in: [200, 500]}
`

// The reader refuses exactly the tests of strictSampleFile that hold something
// the runner would skip, each for its own reason, and reads the rest in full:
// free-form values (`data`, `json`, `save`, `headers`) take any key, and a
// merge key is followed into the mapping it brings in.
func TestTestFileReaderRefusesWhatTheRunnerWouldSkip(t *testing.T) {
	tests, problems, fileProblem := readAppTestFile([]byte(strictSampleFile))
	if fileProblem != "" {
		t.Fatalf("the sample does not load: %s", fileProblem)
	}
	want := map[string][]string{ // test -> "kind key" of each problem, in line order
		"merged_with_typo":       {"unknown_key as_usr"},
		"test_level":             {"unknown_key asuser"},
		"setup_level":            {"unknown_key sq"},
		"step_level":             {"unknown_key body"},
		"expect_level":           {"unknown_key status_code"},
		"files_level":            {"unknown_key contents"},
		"far_from_any_key":       {"unknown_key timeout"},
		"expect_key_on_the_step": {"unknown_key status"},
		"step_key_on_the_test":   {"unknown_key get"},
		"anchored_typo":          {"unknown_key expects"},
		"inherits_the_typo":      {"unknown_key expects"},
		"other_spelling":         {"unknown_key asUser", "unknown_key not-contains", "unknown_key statusIn"},
		"empty_test":             {"no_steps "},
		"empty_steps":            {"no_steps "},
		"action_is_empty_text":   {"no_action "},
		"rows_on_a_request":      {"unchecked_expect get:rows"},
		"expect_on_set_auth":     {"unchecked_expect set_auth:status"},
		"list_holds_a_mapping":   {"bad_value not_contains"},
		"duration_is_not_one":    {"bad_value max_duration"},
		"status_and_status_in":   {"unchecked_expect status+status_in"},
	}
	for name := range tests {
		var got []string
		for _, p := range problems[name] {
			got = append(got, p.Kind+" "+p.Key)
			if p.Line == 0 {
				t.Errorf("%s: problem %q has no line", name, p.Text)
			}
		}
		if !slices.Equal(got, want[name]) {
			t.Errorf("%s: problems %q, want %q", name, got, want[name])
		}
	}
	// shared, merged_ok and empty_expect_values_on_a_sql_step are read in full.
	if len(tests) != len(want)+3 {
		t.Errorf("the sample decoded into %d tests, want %d", len(tests), len(want)+3)
	}
	// Where a key sits is named for the builder and counted by level.
	levels := map[string]string{"test_level": "test", "merged_with_typo": "test", "setup_level": "setup", "step_level": "step", "expect_level": "expect", "files_level": "files"}
	for name, level := range levels {
		if in := problems[name][0].In; in != level {
			t.Errorf("%s: unknown key reported at level %q, want %q", name, in, level)
		}
	}
	// The nearest key is named: the key it extends, the same key in another
	// spelling, the closest by edit distance. A key that belongs one level
	// down says where; with nothing near, the keys of the place are listed.
	texts := map[string]string{}
	for name, found := range problems {
		for _, p := range found {
			texts[name+" "+p.Key] = p.Text
		}
	}
	for at, want := range map[string]string{
		"expect_level status_code":      "unknown key `status_code` in `expect` of step 1 (did you mean `status`?)",
		"merged_with_typo as_usr":       "unknown key `as_usr` in the test (did you mean `as_user`?)",
		"setup_level sq":                "unknown key `sq` in setup entry 1 (did you mean `sql`?)",
		"files_level contents":          "unknown key `contents` in `files.doc` of step 1 (did you mean `content`?)",
		"other_spelling asUser":         "unknown key `asUser` in the test (did you mean `as_user`?)",
		"other_spelling not-contains":   "(did you mean `not_contains`?)",
		"other_spelling statusIn":       "(did you mean `status_in`?)",
		"expect_key_on_the_step status": "unknown key `status` in step 1 (it is a key of `expect:`; write it under `expect:`)",
		"step_key_on_the_test get":      "unknown key `get` in the test (it is a key of `steps:`; write it under `steps:`)",
		"far_from_any_key timeout":      "unknown key `timeout` in step 1 (the keys there: `api`, `bearer`, `data`, `expect`, `files`, `flush`, `get`, `json`, `json_array`, `ndjson`, `post`, `save`, `set_auth`, `sql`)",
	} {
		if !strings.Contains(texts[at], want) {
			t.Errorf("%s: %q does not say %q", at, texts[at], want)
		}
	}
	// decodeAppTestFile carries the same reasons on the test cases.
	decoded, problem := decodeAppTestFile([]byte(strictSampleFile))
	if problem != "" {
		t.Fatal(problem)
	}
	for name, tc := range decoded {
		if (tc.Problem != "") != (len(want[name]) > 0) {
			t.Errorf("%s: Problem=%q, want refused=%v", name, tc.Problem, len(want[name]) > 0)
		}
	}
}

// yamlDroppedKeys agrees with yaml.v3's own strict mode (KnownFields) on every
// test of the sample and of every fixture app: the reader refuses a key
// exactly when the decoder, told to be strict, refuses the document. That is
// what makes the struct tags the one list of keys.
func TestDroppedKeysMatchTheStrictDecoder(t *testing.T) {
	check := func(label string, data []byte) (strictRefused, dropped int) {
		var doc yaml.Node
		if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
			return 0, 0
		}
		root := doc.Content[0]
		for i := 0; i+1 < len(root.Content); i += 2 {
			name, node := root.Content[i].Value, root.Content[i+1]
			// One test as its own document, anchors resolved, for the strict decoder.
			var plain any
			if err := node.Decode(&plain); err != nil {
				continue
			}
			single, err := yaml.Marshal(plain)
			if err != nil {
				t.Fatalf("%s#%s: %v", label, name, err)
			}
			var tc AppTestCase
			dec := yaml.NewDecoder(bytes.NewReader(single))
			dec.KnownFields(true)
			strictErr := dec.Decode(&tc)
			var lenient AppTestCase
			if err := node.Decode(&lenient); err != nil {
				continue // a type error: the file is not loaded at all
			}
			keys := yamlDroppedKeys(node, reflect.TypeOf(AppTestCase{}))
			if (strictErr != nil) != (len(keys) > 0) {
				t.Errorf("%s#%s: strict decoder error %v, reader found dropped keys %+v", label, name, strictErr, keys)
			}
			for _, k := range keys {
				if !strings.Contains(strictErr.Error(), "field "+k.Key+" not found") {
					t.Errorf("%s#%s: the strict decoder does not name %q: %v", label, name, k.Key, strictErr)
				}
			}
			if strictErr != nil {
				strictRefused++
			}
			dropped += len(keys)
		}
		return strictRefused, dropped
	}
	refused, dropped := check("sample", []byte(strictSampleFile))
	if refused != 12 || dropped != 14 {
		t.Errorf("sample: strict decoder refuses %d tests, reader found %d dropped keys, want 12 and 14", refused, dropped)
	}
	files, err := filepath.Glob(filepath.Join("testdata", "*", "tests", "*.yaml"))
	if err != nil || len(files) < 60 {
		t.Fatalf("found %d fixture test files (%v)", len(files), err)
	}
	fixtureRefused := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		n, _ := check(file, data)
		fixtureRefused += n
	}
	if fixtureRefused < 4 {
		t.Errorf("the fixtures hold %d tests with a dropped key, want the ones of %s at least", fixtureRefused, strictFixture)
	}
}

// An action is a field of AppTestStep with a `step` tag, and the runner agrees:
// a step with exactly one of them set is run, a step with none is refused
// before it becomes a request. Every `expect` key names the kind of step that
// checks it, and that kind is one an action makes.
func TestStepAndExpectTagsDescribeTheRunner(t *testing.T) {
	app := accountHoldTestApp(t, "auth:\n  identifier: email\n")
	values := map[string]string{"api": "GET /health", "get": "/health", "post": "/api/notes", "sql": "SELECT 1", "flush": "jobs", "set_auth": "none"}
	kinds := map[string]bool{}
	st := reflect.TypeOf(AppTestStep{})
	cases := map[string]AppTestCase{}
	for i := range st.NumField() {
		f := st.Field(i)
		kind := f.Tag.Get("step")
		if kind == "" {
			// A field that is not an action never makes a step runnable.
			if f.Type.Kind() == reflect.String {
				t.Errorf("AppTestStep.%s is text without a `step` tag: an action needs the tag, so a step with only that key is refused", f.Name)
			}
			continue
		}
		kinds[kind] = true
		key := yamlFieldKey(f)
		value, ok := values[key]
		if !ok {
			t.Fatalf("no sample value for the action %q: add one to this test", key)
		}
		step := AppTestStep{}
		reflect.ValueOf(&step).Elem().Field(i).SetString(value)
		if keys, got := appTestStepActions(step); !slices.Equal(keys, []string{key}) || got != kind {
			t.Errorf("a step with only %q: actions %v kind %q", key, keys, got)
		}
		cases["only_"+key] = AppTestCase{AsUser: "a@test.com", Steps: []AppTestStep{step}}
	}
	if !slices.Equal(appTestActionKeys(), slices.Sorted(maps.Keys(values))) {
		t.Errorf("action keys %v, want the keys of %v", appTestActionKeys(), values)
	}
	cases["no_action"] = AppTestCase{Anon: true, Steps: []AppTestStep{{Expect: AppTestExpect{Status: 404}}}}
	cases["no_steps"] = AppTestCase{Anon: true}
	results := runAccountHoldTests(t, app, AppTestFile{Name: "actions", Tests: cases})
	for name, r := range results {
		refused := strings.HasPrefix(r.Message, appTestNotRun)
		switch name {
		case "no_action", "no_steps":
			if r.Pass || !refused {
				t.Errorf("%s: %+v, want it refused (a test built in Go is checked when it runs)", name, r)
			}
		default:
			if refused || len(r.Steps) != 1 {
				t.Errorf("%s: a step with one action must run: %+v", name, r)
			}
		}
	}
	// The dispatcher itself never turns a step with no action into a request.
	if r, _ := executeTestStepRaw(app, "http://127.0.0.1:1", nil, nil, "", true, AppTestStep{}); r.Pass || !strings.Contains(r.Message, "no action") {
		t.Errorf("a step with no action reached the dispatcher and was answered %+v", r)
	}

	et := reflect.TypeOf(AppTestExpect{})
	for i := range et.NumField() {
		f := et.Field(i)
		if kind := f.Tag.Get("step"); !kinds[kind] {
			t.Errorf("AppTestExpect.%s names the step kind %q, which no action makes (%v): on every step the key would be refused as never checked", f.Name, kind, kinds)
		}
	}
}

// Each `expect` key is really checked on the kind of step its tag names: a
// false expectation fails the step. A key added to AppTestExpect without a
// case here fails this test.
func TestEveryExpectKeyIsCheckedOnItsKindOfStep(t *testing.T) {
	app := accountHoldTestApp(t, "auth:\n  identifier: email\n")
	five, ninetyNine := 5, 99
	falseExpect := map[string]AppTestStep{
		"status":       {Get: "/health", Expect: AppTestExpect{Status: 500}},
		"status_in":    {Get: "/health", Expect: AppTestExpect{StatusIn: []int{500, 502}}},
		"redirect":     {Get: "/health", Expect: AppTestExpect{Redirect: "/somewhere-else"}},
		"contains":     {Get: "/health", Expect: AppTestExpect{Contains: "this text is not in the answer"}},
		"not_contains": {Get: "/health", Expect: AppTestExpect{NotContains: []any{"status"}}},
		"json":         {Get: "/health", Expect: AppTestExpect{JSONField: map[string]any{"status": "on fire"}}},
		"json_length":  {Get: "/api/notes", Expect: AppTestExpect{JSONLength: &ninetyNine}},
		"rows":         {SQL: "SELECT 1", Expect: AppTestExpect{Rows: &five}},
		"headers":      {Get: "/health", Expect: AppTestExpect{Headers: map[string]string{"X-Frame-Options": "ALLOWALL"}}},
		"max_duration": {Get: "/health", Expect: AppTestExpect{MaxDuration: "1ns"}},
	}
	et := reflect.TypeOf(AppTestExpect{})
	cases := map[string]AppTestCase{}
	for i := range et.NumField() {
		key := yamlFieldKey(et.Field(i))
		step, ok := falseExpect[key]
		if !ok {
			t.Fatalf("no false expectation for `expect.%s`: add one to this test", key)
		}
		if reflect.ValueOf(step.Expect).Field(i).IsZero() {
			t.Fatalf("the case for `expect.%s` does not set it", key)
		}
		_, kind := appTestStepActions(step)
		if tag := et.Field(i).Tag.Get("step"); tag != kind {
			t.Fatalf("`expect.%s` is tagged for %q steps and its case is a %q step", key, tag, kind)
		}
		cases[key] = AppTestCase{AsUser: "a@test.com", Steps: []AppTestStep{step}}
	}
	for key, r := range runAccountHoldTests(t, app, AppTestFile{Name: "expect", Tests: cases}) {
		if r.Pass || strings.HasPrefix(r.Message, appTestNotRun) || len(r.Steps) != 1 {
			t.Errorf("`expect.%s`: a false expectation must fail its step when it runs: %+v", key, r)
		}
	}
}

// What a step checks when it names no status, kept as it was and written down
// in api(at:"verification") -> test_keys: a request step fails on a status of
// 400 or above and passes its status check otherwise, with or without other
// expectations; a `sql:` step passes when its statement runs.
func TestStepWithoutAStatusFailsOnlyOn400OrAbove(t *testing.T) {
	app := accountHoldTestApp(t, "auth:\n  identifier: email\n")
	results := runAccountHoldTests(t, app, AppTestFile{Name: "default", Tests: map[string]AppTestCase{
		"ok_no_expect":         {Anon: true, Steps: []AppTestStep{{Get: "/health"}}},
		"ok_other_expect":      {Anon: true, Steps: []AppTestStep{{Get: "/health", Expect: AppTestExpect{Contains: "status"}}}},
		"missing_no_expect":    {Anon: true, Steps: []AppTestStep{{Get: "/no-such-page"}}},
		"missing_other_expect": {Anon: true, Steps: []AppTestStep{{Get: "/no-such-page", Expect: AppTestExpect{NotContains: "this text is not in the answer"}}}},
		"missing_named":        {Anon: true, Steps: []AppTestStep{{Get: "/no-such-page", Expect: AppTestExpect{Status: 404}}}},
		"sql_no_expect":        {Anon: true, Steps: []AppTestStep{{SQL: "SELECT 1"}}},
		"sql_error":            {Anon: true, Steps: []AppTestStep{{SQL: "SELECT * FROM no_such_table"}}},
	}})
	for name, want := range map[string]string{
		"ok_no_expect": "", "ok_other_expect": "", "missing_named": "", "sql_no_expect": "",
		"missing_no_expect": "HTTP 404", "missing_other_expect": "HTTP 404", "sql_error": "SQL error",
	} {
		r := results[name]
		if strings.HasPrefix(r.Message, appTestNotRun) || len(r.Steps) != 1 {
			t.Errorf("%s did not run: %+v", name, r)
		}
		if (want == "") != r.Pass || !strings.Contains(r.Message, want) {
			t.Errorf("%s: pass=%v message %q, want pass=%v with %q", name, r.Pass, r.Message, want == "", want)
		}
	}
}

// `json_length` on a response that is not a JSON array fails the step. It was
// skipped, so `json_length: 0` passed on an object.
func TestJSONLengthNeedsAnArray(t *testing.T) {
	app := accountHoldTestApp(t, "auth:\n  identifier: email\n")
	zero := 0
	results := runAccountHoldTests(t, app, AppTestFile{Name: "length", Tests: map[string]AppTestCase{
		"object": {Anon: true, Steps: []AppTestStep{{Get: "/health", Expect: AppTestExpect{Status: 200, JSONLength: &zero}}}},
		"array":  {AsUser: "a@test.com", Steps: []AppTestStep{{Get: "/api/notes", Expect: AppTestExpect{Status: 200, JSONLength: &zero}}}},
	}})
	if r := results["object"]; r.Pass || !strings.Contains(r.Message, "the response is not an array") {
		t.Errorf("json_length on an object: %+v, want a failed step that says so", r)
	}
	if r := results["array"]; !r.Pass {
		t.Errorf("json_length: 0 on an empty list: %+v, want a pass", r)
	}
}

// The generated framework tests of every fixture app are read in full: none
// is refused when built, and written out as YAML each decodes again under the
// strict reader with nothing dropped.
func TestGeneratedFrameworkTestsAreReadInFull(t *testing.T) {
	apps, err := filepath.Glob(filepath.Join("testdata", "*", "schema.prisma"))
	if err != nil || len(apps) < 20 {
		t.Fatalf("found %d fixture apps (%v)", len(apps), err)
	}
	loaded, generated := 0, 0
	for _, schema := range apps {
		src := filepath.Dir(schema)
		root, err := filepath.EvalSymlinks(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		dir := filepath.Join(root, filepath.Base(src))
		if err := copyTestSource(src, dir, true); err != nil {
			t.Fatal(err)
		}
		app, err := loadAppForServerTests(dir)
		if err != nil {
			continue // a fixture the loader must refuse
		}
		loaded++
		for _, tf := range GenerateFrameworkTests(app) {
			readable := map[string]AppTestCase{}
			for name, tc := range tf.Tests {
				if tc.Skip != "" {
					continue
				}
				generated++
				if _, refused := unreadTestResult(tf.Name, name, tc); refused {
					t.Errorf("%s: generated test %s/%s is refused: %s", src, tf.Name, name, appTestProblemText(appTestCaseProblems(tc, nil)))
				}
				readable[name] = tc
			}
			if len(readable) == 0 {
				continue
			}
			out, err := yaml.Marshal(readable)
			if err != nil {
				t.Fatalf("%s %s: %v", src, tf.Name, err)
			}
			decoded, problem := decodeAppTestFile(out)
			if problem != "" {
				t.Errorf("%s: generated file %s does not load as YAML: %s", src, tf.Name, problem)
				continue
			}
			for name, tc := range decoded {
				if tc.Problem != "" {
					t.Errorf("%s: generated test %s/%s is refused as YAML: %s", src, tf.Name, name, tc.Problem)
				}
			}
		}
		app.Shutdown()
	}
	t.Logf("checked %d generated tests of %d fixture apps", generated, loaded)
	if loaded < 20 || generated < 400 {
		t.Errorf("checked %d generated tests of %d fixture apps; want at least 400 of 20", generated, loaded)
	}
}

// `benmore check` and the write gate warn about a test the runner refuses,
// naming the test and the reason; the write is not refused (`benmore test` is
// what fails).
func TestCheckWarnsOnATestTheRunnerRefuses(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(root, "checked")
	if err := copyTestSource(strictFixture, dir, true); err != nil {
		t.Fatal(err)
	}
	// A file with several refused tests names the first five and counts the rest.
	var many strings.Builder
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		many.WriteString("typo_" + name + ":\n  anon: true\n  steps:\n    - get: \"/health\"\n      expects: {status: 500}\n")
	}
	many.WriteString("fine:\n  anon: true\n  steps:\n    - get: \"/health\"\n")
	writeTestFile(t, dir, "tests/many.yaml", many.String())

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
	for result, wants := range refusedFixtureTests {
		file, test, _ := strings.Cut(result, "/")
		msg, ok := warned["tests/"+file+".yaml"]
		if !ok {
			t.Errorf("check does not warn about tests/%s.yaml (all: %v)", file, warned)
			continue
		}
		for _, want := range append([]string{"`benmore test` fails", test + ":"}, wants[1:]...) {
			if !strings.Contains(msg, want) {
				t.Errorf("tests/%s.yaml: warning does not say %q: %s", file, want, msg)
			}
		}
	}
	if msg, ok := warned["tests/loads.yaml"]; ok {
		t.Errorf("check warns about the file the runner reads in full: %s", msg)
	}
	msg := warned["tests/many.yaml"]
	for _, want := range []string{"7 tests of this file", "typo_a: line 5: unknown key `expects`", "typo_e:", "and 2 more"} {
		if !strings.Contains(msg, want) {
			t.Errorf("tests/many.yaml: warning does not say %q: %s", want, msg)
		}
	}
	if strings.Contains(msg, "typo_f:") || strings.Contains(msg, "fine:") {
		t.Errorf("tests/many.yaml: warning names more than the first five refused tests: %s", msg)
	}
	// The write of such a file is accepted and answered with its warning.
	body, err := os.ReadFile(filepath.Join(dir, "tests", "misspelled_expect.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if refusal := ValidateOnWriteIn(dir, "tests/misspelled_expect.yaml", string(body)); refusal != "" {
		t.Errorf("the write gate refuses the file (%q); it is a warning", refusal)
	}
	found := false
	for _, f := range RunSourceCheck(dir, "tests/misspelled_expect.yaml").Findings {
		if f.Source == "tests" && filepath.ToSlash(f.File) == "tests/misspelled_expect.yaml" {
			found = true
		} else if f.Source == "tests" {
			t.Errorf("a write of one test file repeats another file's warning: %+v", f)
		}
	}
	if !found {
		t.Error("the write of tests/misspelled_expect.yaml carries no warning")
	}
}

// Every fixture app's tests are read in full, except the files a fixture lists
// in tests/expected-failures.txt by name (the test-not-read-in-full fixture,
// which CI runs through the real binary): there every test must be refused.
func TestFixtureAppTestsAreReadInFullOrExpectedNotToBe(t *testing.T) {
	apps, err := filepath.Glob(filepath.Join("testdata", "*", "tests"))
	if err != nil || len(apps) < 20 {
		t.Fatalf("found %d fixture apps with tests/ (%v)", len(apps), err)
	}
	refusedSomewhere := 0
	for _, tests := range apps {
		expected := map[string]bool{}
		if listed, err := os.ReadFile(filepath.Join(tests, "expected-failures.txt")); err == nil {
			for _, line := range strings.Split(string(listed), "\n") {
				if line = strings.TrimSpace(line); line != "" && !strings.HasPrefix(line, "#") {
					expected[line] = true
				}
			}
		}
		files, _ := loadTestFilesFromDisk(filepath.Dir(tests))
		for _, tf := range files {
			for name, tc := range tf.Tests {
				switch {
				case tc.Problem != "" && !expected[tf.Name]:
					t.Errorf("%s: %s/%s is refused: %s", filepath.Dir(tests), tf.Name, name, tc.Problem)
				case tc.Problem == "" && expected[tf.Name]:
					t.Errorf("%s: %s is listed as a file of refused tests, but the runner reads %s in full", filepath.Dir(tests), tf.Name, name)
				case tc.Problem != "":
					refusedSomewhere++
				}
			}
		}
	}
	if refusedSomewhere != len(refusedFixtureTests) {
		t.Errorf("the fixtures hold %d refused tests, want the %d of %s", refusedSomewhere, len(refusedFixtureTests), strictFixture)
	}
}
