//go:build !cli

package main

// A test the runner cannot read in full is failed, never run.
//
// yaml.v3 drops every mapping key the struct it decodes into does not declare.
// For a test file that meant `expects:` for `expect:` left a step with no
// assertion, `step:` for `steps:` left a test with no steps, `contain:` left an
// `expect` that checked nothing, and each of them reported PASS. A step with
// no action sent a GET for the empty path (the home page), and an `expect` key
// the step's action never looks at (`contains:` on a `sql:` step) was skipped
// the same way.
//
// One source of truth: the keys a mapping takes are the yaml tags of the
// struct the runner decodes it into (AppTestCase and what it holds), read by
// reflection, and which action checks which `expect` key is the `step` tag on
// those same fields. Nothing here lists a key.

import (
	"fmt"
	"maps"
	"reflect"
	"slices"
	"sort"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"
)

// yamlDroppedKey is a mapping key the decoder drops: the struct the mapping
// decodes into binds no field to it.
type yamlDroppedKey struct {
	Key   string
	Line  int
	Path  []any           // mapping keys (string) and list indexes (int) from the root to the mapping
	Known map[string]bool // the keys that struct binds
	// Under is the key of that struct whose own mapping (or list entries)
	// binds Key, "" when none does: `status:` written beside `expect:`
	// instead of under it.
	Under string
}

var yamlUnmarshalerType = reflect.TypeOf((*yaml.Unmarshaler)(nil)).Elem()

// yamlDroppedKeys walks node the way yaml.v3 decodes it into a value of type t
// and returns every mapping key that decode drops. Free-form values (a map, an
// `any`) take any key; a type that unmarshals itself is not looked into.
func yamlDroppedKeys(node *yaml.Node, t reflect.Type) []yamlDroppedKey {
	var out []yamlDroppedKey
	walkYAMLDroppedKeys(node, t, nil, &out, 0)
	return out
}

func walkYAMLDroppedKeys(n *yaml.Node, t reflect.Type, path []any, out *[]yamlDroppedKey, depth int) {
	if n == nil || depth > 64 {
		return
	}
	if n.Kind == yaml.AliasNode {
		n = n.Alias
		if n == nil {
			return
		}
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) > 0 {
			walkYAMLDroppedKeys(n.Content[0], t, path, out, depth+1)
		}
		return
	}
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if reflect.PointerTo(t).Implements(yamlUnmarshalerType) {
		return
	}
	at := func(step any) []any { return append(slices.Clone(path), step) }
	switch {
	case n.Kind == yaml.MappingNode && t.Kind() == reflect.Struct:
		fields, open := yamlStructFields(t)
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, value := n.Content[i], n.Content[i+1]
			if yamlMergeKey(key) {
				// `<<: *base` (or a list of them) is read into this same struct.
				if value.Kind == yaml.AliasNode && value.Alias != nil {
					value = value.Alias
				}
				if value.Kind == yaml.SequenceNode {
					for _, merged := range value.Content {
						walkYAMLDroppedKeys(merged, t, path, out, depth+1)
					}
				} else {
					walkYAMLDroppedKeys(value, t, path, out, depth+1)
				}
				continue
			}
			ft, ok := fields[key.Value]
			if !ok {
				if !open {
					known := make(map[string]bool, len(fields))
					under := ""
					for _, name := range slices.Sorted(maps.Keys(fields)) {
						known[name] = true
						if under == "" && yamlNestedStructBinds(fields[name], key.Value) {
							under = name
						}
					}
					*out = append(*out, yamlDroppedKey{Key: key.Value, Line: key.Line, Path: slices.Clone(path), Known: known, Under: under})
				}
				continue
			}
			walkYAMLDroppedKeys(value, ft, at(key.Value), out, depth+1)
		}
	case n.Kind == yaml.MappingNode && t.Kind() == reflect.Map:
		for i := 0; i+1 < len(n.Content); i += 2 {
			walkYAMLDroppedKeys(n.Content[i+1], t.Elem(), at(n.Content[i].Value), out, depth+1)
		}
	case n.Kind == yaml.SequenceNode && (t.Kind() == reflect.Slice || t.Kind() == reflect.Array):
		for i, item := range n.Content {
			walkYAMLDroppedKeys(item, t.Elem(), at(i), out, depth+1)
		}
	}
}

// yamlNestedStructBinds reports whether t, a struct or a list of structs,
// binds key.
func yamlNestedStructBinds(t reflect.Type, key string) bool {
	for t.Kind() == reflect.Pointer || t.Kind() == reflect.Slice || t.Kind() == reflect.Array {
		t = t.Elem()
	}
	if t.Kind() != reflect.Struct {
		return false
	}
	fields, _ := yamlStructFields(t)
	_, ok := fields[key]
	return ok
}

// nearestKnownKey returns the key of known that key most likely stands for, or
// "": the same key in another spelling (case, `-` for `_`), a key it extends
// or cuts short (`expects`, `status_code`, `contain`), else the closest by
// edit distance.
func nearestKnownKey(key string, known map[string]bool) string {
	fold := func(s string) string {
		return strings.ToLower(strings.NewReplacer("_", "", "-", "", " ", "").Replace(s))
	}
	names := slices.Sorted(maps.Keys(known))
	folded := fold(key)
	for _, name := range names {
		if fold(name) == folded {
			return name
		}
	}
	best, bestGap := "", 0
	for _, name := range names {
		n := fold(name)
		if len(n) < 3 || len(folded) < 3 || !(strings.HasPrefix(n, folded) || strings.HasPrefix(folded, n)) {
			continue
		}
		gap := len(n) - len(folded)
		if gap < 0 {
			gap = -gap
		}
		if best == "" || gap < bestGap {
			best, bestGap = name, gap
		}
	}
	if best != "" {
		return best
	}
	return closestStepID(key, known)
}

// yamlMergeKey reports the `<<` merge key (a quoted "<<" is an ordinary key).
func yamlMergeKey(key *yaml.Node) bool {
	return key.Kind == yaml.ScalarNode && key.Value == "<<" && (key.Tag == "" || key.Tag == "!" || key.Tag == "!!merge")
}

// yamlStructFields returns the keys yaml.v3 binds to t's fields, each with the
// field's type. open reports an inline map, which takes every other key.
func yamlStructFields(t reflect.Type) (fields map[string]reflect.Type, open bool) {
	fields = map[string]reflect.Type{}
	for i := range t.NumField() {
		f := t.Field(i)
		if f.PkgPath != "" && !f.Anonymous {
			continue
		}
		tag := f.Tag.Get("yaml")
		if tag == "" && !strings.Contains(string(f.Tag), ":") {
			tag = string(f.Tag)
		}
		if tag == "-" {
			continue
		}
		name, flags, _ := strings.Cut(tag, ",")
		if slices.Contains(strings.Split(flags, ","), "inline") {
			ft := f.Type
			for ft.Kind() == reflect.Pointer {
				ft = ft.Elem()
			}
			switch ft.Kind() {
			case reflect.Struct:
				inner, innerOpen := yamlStructFields(ft)
				maps.Copy(fields, inner)
				open = open || innerOpen
			case reflect.Map:
				open = true
			}
			continue
		}
		if name == "" {
			name = strings.ToLower(f.Name)
		}
		fields[name] = f.Type
	}
	return fields, open
}

// yamlNodeAt follows mapping keys (string) and list indexes (int) from n. It
// returns the node there and, when the last step is a mapping key, that key's
// node, whose line a message names. Both are nil when the path is not there.
func yamlNodeAt(n *yaml.Node, path ...any) (key, value *yaml.Node) {
	for _, step := range path {
		if n != nil && n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
			n = n.Content[0]
		}
		if n != nil && n.Kind == yaml.AliasNode {
			n = n.Alias
		}
		if n == nil {
			return nil, nil
		}
		key = nil
		switch s := step.(type) {
		case string:
			if n.Kind != yaml.MappingNode {
				return nil, nil
			}
			var found *yaml.Node
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value == s && !yamlMergeKey(n.Content[i]) {
					key, found = n.Content[i], n.Content[i+1]
				}
			}
			if found == nil {
				return nil, nil
			}
			n = found
		case int:
			if n.Kind != yaml.SequenceNode || s < 0 || s >= len(n.Content) {
				return nil, nil
			}
			n = n.Content[s]
		}
	}
	return key, n
}

// appTestProblem is one reason a test is failed instead of run.
type appTestProblem struct {
	// Kind: unknown_key, no_steps, no_action, many_actions, unchecked_expect,
	// bad_value or empty_setup.
	Kind string
	Key  string // the key the problem is about, when it is about one
	In   string // unknown_key: the mapping holding it (test, setup, step, expect, files)
	Line int    // 0 when the test has no source line (a generated test)
	Text string
}

const (
	// appTestNotRun starts the message of a test the runner refused.
	appTestNotRun = "not run: "
	// appTestNotRunWhy ends it.
	appTestNotRunWhy = ". `benmore test` fails a test it cannot read in full, because running it would skip that part and report a pass."
)

// appTestStepActions returns the action keys a step sets, in the struct's
// order, and the kind of step the first one makes (the field's `step` tag).
func appTestStepActions(step AppTestStep) (keys []string, kind string) {
	v, t := reflect.ValueOf(step), reflect.TypeOf(step)
	for i := range t.NumField() {
		k := t.Field(i).Tag.Get("step")
		if k == "" || v.Field(i).IsZero() {
			continue
		}
		if len(keys) == 0 {
			kind = k
		}
		keys = append(keys, yamlFieldKey(t.Field(i)))
	}
	return keys, kind
}

// appTestActionKeys are the keys that give a step its action.
func appTestActionKeys() []string {
	var keys []string
	t := reflect.TypeOf(AppTestStep{})
	for i := range t.NumField() {
		if t.Field(i).Tag.Get("step") != "" {
			keys = append(keys, yamlFieldKey(t.Field(i)))
		}
	}
	sort.Strings(keys)
	return keys
}

// appTestExpectKeysFor are the `expect` keys a step of the given kind checks.
func appTestExpectKeysFor(kind string) []string {
	var keys []string
	t := reflect.TypeOf(AppTestExpect{})
	for i := range t.NumField() {
		if kind != "" && t.Field(i).Tag.Get("step") == kind {
			keys = append(keys, yamlFieldKey(t.Field(i)))
		}
	}
	sort.Strings(keys)
	return keys
}

func yamlFieldKey(f reflect.StructField) string {
	name, _, _ := strings.Cut(f.Tag.Get("yaml"), ",")
	return name
}

func codeList(keys []string) string {
	if len(keys) == 0 {
		return ""
	}
	return "`" + strings.Join(keys, "`, `") + "`"
}

// appTestCaseProblems returns why the runner refuses tc: a key it does not
// read, no steps, a step with no action or more than one, an `expect` key the
// step's action never checks (or `status` beside `status_in`, which wins), an
// `expect` value it cannot compare, a setup entry with no SQL. node is the
// test's mapping in its file, for the unknown keys and the line numbers; nil
// for a test built in Go (a generated test), which has neither.
func appTestCaseProblems(tc AppTestCase, node *yaml.Node) []appTestProblem {
	var out []appTestProblem
	lineOf := func(path ...any) int {
		key, value := yamlNodeAt(node, path...)
		if key != nil {
			return key.Line
		}
		if value != nil && len(path) > 0 {
			return value.Line
		}
		return 0
	}
	for _, dropped := range yamlDroppedKeys(node, reflect.TypeOf(tc)) {
		in, place := appTestKeyPlace(dropped.Path)
		text := fmt.Sprintf("unknown key `%s` in %s", dropped.Key, place)
		if near := nearestKnownKey(dropped.Key, dropped.Known); near != "" {
			text += fmt.Sprintf(" (did you mean `%s`?)", near)
		} else if dropped.Under != "" {
			text += fmt.Sprintf(" (it is a key of `%s:`; write it under `%s:`)", dropped.Under, dropped.Under)
		} else {
			text += " (the keys there: " + codeList(slices.Sorted(maps.Keys(dropped.Known))) + ")"
		}
		out = append(out, appTestProblem{Kind: "unknown_key", Key: dropped.Key, In: in, Line: dropped.Line, Text: text})
	}
	if len(tc.Steps) == 0 {
		out = append(out, appTestProblem{Kind: "no_steps", Line: lineOf("steps"),
			Text: "the test has no steps, so it checks nothing (`steps:` takes a list of steps)"})
	}
	for i, setup := range tc.Setup {
		if strings.TrimSpace(setup.SQL) == "" {
			out = append(out, appTestProblem{Kind: "empty_setup", Line: lineOf("setup", i),
				Text: fmt.Sprintf("setup entry %d has no `sql:`, so it does nothing", i+1)})
		}
	}
	for i, step := range tc.Steps {
		n := i + 1
		actions, kind := appTestStepActions(step)
		switch {
		case len(actions) == 0:
			out = append(out, appTestProblem{Kind: "no_action", Line: lineOf("steps", i),
				Text: fmt.Sprintf("step %d has no action (give it one of %s)", n, codeList(appTestActionKeys()))})
			continue
		case len(actions) > 1:
			out = append(out, appTestProblem{Kind: "many_actions", Key: strings.Join(actions, "+"), Line: lineOf("steps", i),
				Text: fmt.Sprintf("step %d has more than one action (%s); a step runs one, so split it into one step for each", n, codeList(actions))})
			continue
		}
		expect, et := reflect.ValueOf(step.Expect), reflect.TypeOf(step.Expect)
		for f := range et.NumField() {
			if !appTestExpectSet(expect.Field(f)) || et.Field(f).Tag.Get("step") == kind {
				continue
			}
			key := yamlFieldKey(et.Field(f))
			text := fmt.Sprintf("step %d is a `%s:` step, which never checks `expect.%s`", n, actions[0], key)
			if checked := appTestExpectKeysFor(kind); len(checked) > 0 {
				text += " (it checks " + codeList(checked) + ")"
			} else {
				text += " (it checks nothing from `expect:`; assert in a step after it)"
			}
			out = append(out, appTestProblem{Kind: "unchecked_expect", Key: actions[0] + ":" + key, Line: lineOf("steps", i, "expect", key), Text: text})
		}
		if step.Expect.Status != 0 && len(step.Expect.StatusIn) > 0 {
			out = append(out, appTestProblem{Kind: "unchecked_expect", Key: "status+status_in", Line: lineOf("steps", i, "expect", "status"),
				Text: fmt.Sprintf("`expect` of step %d has both `status` and `status_in`; only `status_in` is checked, so keep one", n)})
		}
		for _, list := range []struct {
			key   string
			value any
		}{{"contains", step.Expect.Contains}, {"not_contains", step.Expect.NotContains}} {
			if what := appTestTextListProblem(list.value); what != "" {
				out = append(out, appTestProblem{Kind: "bad_value", Key: list.key, Line: lineOf("steps", i, "expect", list.key),
					Text: fmt.Sprintf("`expect.%s` of step %d holds %s, which is never compared: it takes text or a list of text (quote a number or true/false)", list.key, n, what)})
			}
		}
		if d := step.Expect.MaxDuration; d != "" {
			if _, err := time.ParseDuration(d); err != nil {
				out = append(out, appTestProblem{Kind: "bad_value", Key: "max_duration", Line: lineOf("steps", i, "expect", "max_duration"),
					Text: fmt.Sprintf("`expect.max_duration` of step %d is not a duration, so it is never checked (write it as `100ms` or `2s`)", n)})
			}
		}
	}
	sort.SliceStable(out, func(a, b int) bool { return out[a].Line < out[b].Line })
	return out
}

// appTestExpectSet reports an `expect` value that asks for a check: an empty
// list or mapping asks for none.
func appTestExpectSet(v reflect.Value) bool {
	switch v.Kind() {
	case reflect.Slice, reflect.Map:
		return v.Len() > 0
	}
	return !v.IsZero()
}

// appTestKeyPlace names the mapping an unknown key sits in: the level, for
// counting, and the words a builder reads.
func appTestKeyPlace(path []any) (in, place string) {
	if len(path) == 0 {
		return "test", "the test"
	}
	list, _ := path[0].(string)
	if len(path) == 1 {
		return list, "`" + list + "`"
	}
	index, _ := path[1].(int)
	entry := fmt.Sprintf("step %d", index+1)
	in = "step"
	if list == "setup" {
		entry, in = fmt.Sprintf("setup entry %d", index+1), "setup"
	}
	if len(path) == 2 {
		return in, entry
	}
	var rest []string
	for _, p := range path[2:] {
		rest = append(rest, fmt.Sprint(p))
	}
	return rest[0], "`" + strings.Join(rest, ".") + "` of " + entry
}

// appTestTextListProblem names what a `contains:` value holds that the runner
// never compares ("" when every value is text): it reads text or a list of
// text and skips anything else.
func appTestTextListProblem(v any) string {
	name := func(item any) string {
		switch item.(type) {
		case string:
			return ""
		case nil:
			return "an empty value"
		case bool:
			return "true or false"
		case int, int64, uint64, float64:
			return fmt.Sprintf("a number (%v)", item)
		case map[string]any, map[any]any:
			return "a mapping"
		case []any:
			return "a list inside the list"
		}
		return "a value that is not text"
	}
	switch val := v.(type) {
	case nil, string, []string:
		return ""
	case []any:
		for _, item := range val {
			if what := name(item); what != "" {
				return what
			}
		}
		return ""
	}
	return name(v)
}

// appTestProblemText joins the problems of one test into the reason its
// result carries ("" when there are none).
func appTestProblemText(problems []appTestProblem) string {
	parts := make([]string, 0, len(problems))
	for _, p := range problems {
		if p.Line > 0 {
			parts = append(parts, fmt.Sprintf("line %d: %s", p.Line, p.Text))
		} else {
			parts = append(parts, p.Text)
		}
	}
	return strings.Join(parts, "; ")
}

// unreadTestResult is the failed result of a test the runner refuses; ok is
// false for a test it reads in full. A test read from a file carries its
// problems (decodeAppTestFile, which has the source lines); a test built in Go
// is checked here.
func unreadTestResult(file, name string, tc AppTestCase) (result AppTestResult, ok bool) {
	problem := tc.Problem
	if problem == "" && tc.Skip == "" {
		problem = appTestProblemText(appTestCaseProblems(tc, nil))
	}
	if problem == "" {
		return AppTestResult{}, false
	}
	return AppTestResult{File: file, Test: name, Pass: false, Message: appTestNotRun + problem + appTestNotRunWhy}, true
}

// unreadTestResults are the failed results for the tests of files the runner
// refuses, for a run that leaves those files' other tests out.
func unreadTestResults(files []AppTestFile) []AppTestResult {
	var out []AppTestResult
	for _, tf := range files {
		for _, name := range slices.Sorted(maps.Keys(tf.Tests)) {
			if r, refused := unreadTestResult(tf.Name, name, tf.Tests[name]); refused {
				out = append(out, r)
			}
		}
	}
	return out
}
