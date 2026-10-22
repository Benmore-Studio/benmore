//go:build !cli

package main

// flowStepKeyTable against the loader: each key the table lists is read by
// convertGHASteps for that step type, and no key outside it is.

import (
	"maps"
	"os"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// stepKeyBase is the smallest step of a type: only what makes it that type.
func stepKeyBase(runType string) map[string]any {
	nested := []any{map[string]any{"run": "respond", "with": map[string]any{"status": 200}}}
	switch runType {
	case "if":
		return map[string]any{"if": "${{ steps.a.outputs.ok }}", "steps": nested}
	case "for_each":
		return map[string]any{"for_each": "${{ steps.a.outputs.rows }}", "steps": nested}
	case "parallel":
		return map[string]any{"run": "parallel", "steps": nested}
	}
	return map[string]any{"run": runType}
}

// stepKeyRootProbes holds, for every step-root key, a value the loader would
// keep if it read the key (and that differs from stepKeyBase's).
var stepKeyRootProbes = map[string]any{
	"id":          "probe_id",
	"if":          "${{ steps.probe.outputs.ok }}",
	"when":        "${{ steps.probe.outputs.ok }}",
	"query":       "SELECT 'probe'",
	"expect_rows": ">7",
	"params":      map[string]any{"probe": "1"},
	"steps":       []any{map[string]any{"run": "respond", "with": map[string]any{"status": 201}}},
	"else":        []any{map[string]any{"run": "respond", "with": map[string]any{"status": 202}}},
	"for_each":    "${{ steps.probe.outputs.rows }}",
	"as":          "probe_var",
	"on_error":    []any{map[string]any{"run": "respond", "with": map[string]any{"status": 500}}},
	"retry":       3,
	"retry_delay": "7s",
	"timeout":     "7s",
}

// stepKeyWithProbes are tried one by one under each `with:` key: text, a
// number, a map, and the list shapes a key may want. A key is read when any
// of them changes the loaded step. A respond step keeps only a media type as
// its content type and only an allowed header (flows_respond_headers.go).
var stepKeyWithProbes = []any{
	"probe",
	"text/csv",
	404,
	map[string]any{"probe_key": "probe_value"},
	map[string]any{"X-Probe": "probe"},
	[]any{404},
	[]any{map[string]any{"filename": "probe.txt", "content": "cHJvYmU="}},
}

// loadProbeStep runs one step, written as YAML, through the loader.
func loadProbeStep(t *testing.T, step map[string]any) (string, []FlowStep) {
	t.Helper()
	text, err := yaml.Marshal(step)
	if err != nil {
		t.Fatalf("marshal %v: %v", step, err)
	}
	var s FlowStepGHA
	if err := yamlUnmarshal(text, &s); err != nil {
		t.Fatalf("decode %s: %v", text, err)
	}
	return ghaStepRunType(s), convertGHASteps([]FlowStepGHA{s})
}

func cloneStepMap(step map[string]any) map[string]any {
	out := maps.Clone(step)
	if with, ok := step["with"].(map[string]any); ok {
		out["with"] = maps.Clone(with)
	}
	return out
}

// loaderReadsRootKey reports whether the loaded step of runType changes when
// key is written at the step root of base. skip is true when the key would
// make the step another type (a `query:` next to a bare `if:` is a SQL step).
func loaderReadsRootKey(t *testing.T, runType string, base map[string]any, key string) (read, skip bool) {
	t.Helper()
	_, before := loadProbeStep(t, base)
	probed := cloneStepMap(base)
	probed[key] = stepKeyRootProbes[key]
	got, after := loadProbeStep(t, probed)
	if got != runType {
		return false, true
	}
	return !reflect.DeepEqual(before, after), false
}

func loaderReadsWithKey(t *testing.T, runType, key string) bool {
	t.Helper()
	base := stepKeyBase(runType)
	_, before := loadProbeStep(t, base)
	for _, probe := range stepKeyWithProbes {
		probed := cloneStepMap(base)
		probed["with"] = map[string]any{key: probe}
		if _, after := loadProbeStep(t, probed); !reflect.DeepEqual(before, after) {
			return true
		}
	}
	return false
}

// The table has a row for every step type the loader converts, and no other.
func TestFlowStepKeyTableCoversEveryRunType(t *testing.T) {
	for runType := range flowRunTypes {
		if _, ok := flowStepKeyTable[runType]; !ok {
			t.Errorf("flowRunTypes has %q but flowStepKeyTable has no row for it: list the keys convertGHASteps reads for it", runType)
		}
	}
	for runType := range flowStepKeyTable {
		if !flowRunTypes[runType] {
			t.Errorf("flowStepKeyTable has a row for %q, which is not a step type", runType)
		}
	}
	for _, row := range flowStepLiveIgnoredKeys {
		if !flowRunTypes[row.runType] {
			t.Errorf("flowStepLiveIgnoredKeys names %q, which is not a step type", row.runType)
		}
	}
}

// stepKeyMappedNotRun are step-root keys convertGHASteps maps onto the
// FlowStep of a type although an ordinary flow never acts on them there, so
// the table leaves them out and the gate refuses them:
//   - `timeout`: mapped for every type because the command runtime bounds each
//     of its steps with it (executeStep); an ordinary flow reads it only in
//     execStepAPI, execStepCompute and execStepTranscribe.
//   - `retry` / `retry_delay` on a block: executeSteps would retry it, running
//     its finished steps again and still returning the first error.
//   - `expect_rows` off a SQL step: copied, never compared (expectRowsViolation
//     refuses it).
func stepKeyMappedNotRun(runType, key string) bool {
	row := flowStepKeyTable[runType]
	switch key {
	case "timeout":
		return !slices.Contains(row.root, "timeout")
	case "retry", "retry_delay":
		return row.block
	case "expect_rows":
		return !flowRunTypeCountsRows(runType)
	}
	return false
}

// Every step-root key FlowStepGHA declares, on every step type: the loader
// reads it exactly when the table says so. A key the loader starts reading
// fails here until its row lists it, and a row that lists a key the loader
// does not read fails too.
func TestFlowStepKeyTableMatchesLoaderAtTheStepRoot(t *testing.T) {
	for key := range flowStepKeys {
		if _, ok := stepKeyRootProbes[key]; !ok && key != "run" && key != "with" {
			t.Fatalf("FlowStepGHA has a new key %q: add a probe value for it to stepKeyRootProbes and decide its row in flowStepKeyTable", key)
		}
	}
	for _, runType := range slices.Sorted(maps.Keys(flowStepKeyTable)) {
		row := flowStepKeyTable[runType]
		for _, key := range slices.Sorted(maps.Keys(stepKeyRootProbes)) {
			base := stepKeyBase(runType)
			if key == "else" {
				// Read only next to an `if:` (the gate's other branch).
				if read, skip := loaderReadsRootKey(t, runType, base, key); !skip && read && runType != "if" {
					t.Errorf("%s: the loader reads `else` on a step with no `if:`; the gate refuses that shape as never run", runType)
				}
				base["if"] = "${{ steps.gate.outputs.ok }}"
			}
			read, skip := loaderReadsRootKey(t, runType, base, key)
			if skip {
				continue
			}
			want := row.readsRoot(key) || stepKeyMappedNotRun(runType, key)
			if read != want {
				t.Errorf("%s: step-root `%s`: loader reads it = %v, flowStepKeyTable (with stepKeyMappedNotRun) says %v", runType, key, read, want)
			}
			if _, live := flowStepLiveIgnored(runType, false, key); live && read {
				t.Errorf("%s: step-root `%s` is listed in flowStepLiveIgnoredKeys but the loader reads it now: move it into flowStepKeyTable", runType, key)
			}
		}
		// `with` is read through its keys.
		if want := row.anyWith || len(row.with) > 0; row.readsRoot("with") != want {
			t.Errorf("%s: readsRoot(with) = %v, want %v", runType, !want, want)
		}
	}
}

// stepKeyWithUniverse is every key worth probing under `with:`: all the keys
// any row lists, the ones deployed apps carry, every step-level key
// (`with.retry`, `with.if`, `with.id`) and two the loader never read.
func stepKeyWithUniverse() []string {
	keys := map[string]bool{"sql": true, "probe_unlisted": true}
	for _, row := range flowStepKeyTable {
		for _, key := range row.with {
			keys[key] = true
		}
	}
	for _, row := range flowStepLiveIgnoredKeys {
		if row.with {
			keys[row.key] = true
		}
	}
	for key := range flowStepKeys {
		keys[key] = true
	}
	return slices.Sorted(maps.Keys(keys))
}

// Every `with:` key, on every step type: read exactly when the table says so.
func TestFlowStepKeyTableMatchesLoaderUnderWith(t *testing.T) {
	for _, runType := range slices.Sorted(maps.Keys(flowStepKeyTable)) {
		row := flowStepKeyTable[runType]
		for _, key := range stepKeyWithUniverse() {
			read, want := loaderReadsWithKey(t, runType, key), row.readsWith(key)
			if read != want {
				t.Errorf("%s: `with.%s`: loader reads it = %v, flowStepKeyTable says %v", runType, key, read, want)
			}
			if _, live := flowStepLiveIgnored(runType, true, key); live && read {
				t.Errorf("%s: `with.%s` is listed in flowStepLiveIgnoredKeys but the loader reads it now: move it into flowStepKeyTable", runType, key)
			}
		}
	}
}

// A `with:` key the loader starts reading is a new string literal in
// flows_gha.go. It must be in some row of the table, which puts it in the
// probe universe above, where the per-type check then holds it to its row.
func TestFlowStepKeyTableKnowsEveryWithKeyTheLoaderNames(t *testing.T) {
	source, err := os.ReadFile("flows_gha.go")
	if err != nil {
		t.Fatal(err)
	}
	known := map[string]bool{}
	for _, row := range flowStepKeyTable {
		for _, key := range row.with {
			known[key] = true
		}
	}
	// `with["key"]` / `s.With["key"]`, and withDuration(x, "key").
	named := regexp.MustCompile(`(?:\b[wW]ith\["([a-z_]+)"\]|withDuration\([^,]+, "([a-z_]+)"\))`)
	found := 0
	for _, m := range named.FindAllStringSubmatch(string(source), -1) {
		key := m[1] + m[2]
		found++
		if !known[key] {
			t.Errorf("flows_gha.go reads `with.%s`, which no row of flowStepKeyTable lists", key)
		}
	}
	if found < 40 {
		t.Fatalf("found only %d `with:` reads in flows_gha.go; the loader's shape changed and this scan no longer sees it", found)
	}
}

// The gate reports a key the table does not list, at either position, and
// stays quiet for one it does.
func TestFlowStepKeyProblemsFollowTheTable(t *testing.T) {
	problems := func(step map[string]any) (refused, ignored []string) {
		doc := map[string]any{
			"on":   map[string]any{"request": map[string]any{"method": "POST", "path": "/api/p"}},
			"jobs": map[string]any{"p": map[string]any{"steps": []any{step}}},
		}
		text, err := yaml.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		var file FlowFileGHA
		if err := yamlUnmarshal(text, &file); err != nil {
			t.Fatalf("%s: %v", text, err)
		}
		return flowStepKeyProblems(string(text), file)
	}
	for _, runType := range slices.Sorted(maps.Keys(flowStepKeyTable)) {
		row := flowStepKeyTable[runType]
		// A SQL step needs its statement, or that is the problem reported.
		base := func() map[string]any {
			step := stepKeyBase(runType)
			if flowRunTypeCountsRows(runType) {
				step["with"] = map[string]any{"query": "SELECT 1"}
			}
			return step
		}
		for _, key := range slices.Sorted(maps.Keys(stepKeyRootProbes)) {
			if key == "when" || key == "expect_rows" || key == "else" {
				continue // their own gates; `else` is covered by the write-gate test
			}
			step := base()
			if key == "query" && flowRunTypeCountsRows(runType) {
				delete(step, "with")
			}
			step[key] = stepKeyRootProbes[key]
			var s FlowStepGHA
			text, _ := yaml.Marshal(step)
			if err := yamlUnmarshal(text, &s); err != nil || ghaStepRunType(s) != runType {
				continue
			}
			refused, ignored := problems(step)
			_, live := flowStepLiveIgnored(runType, false, key)
			switch {
			case row.readsRoot(key):
				if len(refused)+len(ignored) != 0 {
					t.Errorf("%s: step-root `%s` is in the table but reported: %v %v", runType, key, refused, ignored)
				}
			case live:
				if len(refused) != 0 || len(ignored) != 1 || !strings.Contains(ignored[0], "`"+key+"` is ignored") {
					t.Errorf("%s: step-root `%s` is carried by deployed apps: want one loader note and no refusal, got %v %v", runType, key, refused, ignored)
				}
			default:
				if len(refused) != 1 || !strings.Contains(refused[0], "`"+key+"`") {
					t.Errorf("%s: step-root `%s` is not in the table: want one refusal naming it, got %v (ignored %v)", runType, key, refused, ignored)
				}
			}
		}
		if len(row.with) == 0 && !row.anyWith && !flowStepHasLiveIgnoredWith(runType) {
			continue // the block's `with:` itself is refused above
		}
		for _, key := range stepKeyWithUniverse() {
			if key == "expect_rows" {
				continue
			}
			step := base()
			with, _ := step["with"].(map[string]any)
			if with == nil {
				with = map[string]any{}
			}
			if _, set := with[key]; !set {
				with[key] = "probe"
			}
			step["with"] = with
			refused, ignored := problems(step)
			_, live := flowStepLiveIgnored(runType, true, key)
			switch {
			case row.readsWith(key):
				if len(refused)+len(ignored) != 0 {
					t.Errorf("%s: `with.%s` is in the table but reported: %v %v", runType, key, refused, ignored)
				}
			case live:
				if len(refused) != 0 || len(ignored) != 1 || !strings.Contains(ignored[0], "`with."+key+"` is ignored") {
					t.Errorf("%s: `with.%s` is carried by deployed apps: want one loader note and no refusal, got %v %v", runType, key, refused, ignored)
				}
			default:
				if len(refused) != 1 || !strings.Contains(refused[0], "`with."+key+"`") {
					t.Errorf("%s: `with.%s` is not in the table: want one refusal naming it, got %v (ignored %v)", runType, key, refused, ignored)
				}
			}
		}
	}
	// On `run: set` every `with:` key is a variable, whatever its name.
	refused, ignored := problems(map[string]any{"run": "set", "with": map[string]any{"retry": "3", "timeout": "1s", "sql": "x", "if": "y", "payload": "z"}})
	if len(refused)+len(ignored) != 0 {
		t.Errorf("a `run: set` variable was reported: %v %v", refused, ignored)
	}
}
