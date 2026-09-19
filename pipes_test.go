//go:build !cli

package main

import (
	"strings"
	"testing"
)

// An earlier app build's canonical bug: `${{ X | default:'[]' }}` where X
// resolves to a slice (the typical `steps.fetch.outputs.json.hits`
// shape) returned Go's reflect-default formatting like
// "[map[id:1 title:foo]]" instead of valid JSON like
// `[{"id":1,"title":"foo"}]`. Downstream SQL params consuming the
// value via `json_each(:hits)` then crashed with "malformed JSON".
//
// stringifyForPipe now JSON-encodes complex types so `default` and
// every other string-handling pipe sees a valid JSON shape.
func TestStringifyForPipe_SlicePreservesJSON(t *testing.T) {
	value := []map[string]any{
		{"id": 1, "title": "foo"},
		{"id": 2, "title": "bar"},
	}
	got := stringifyForPipe(value)
	// Field order isn't guaranteed by Go's map iteration but
	// json.Marshal sorts map keys alphabetically.
	want := `[{"id":1,"title":"foo"},{"id":2,"title":"bar"}]`
	if got != want {
		t.Errorf("slice of maps:\n got %s\nwant %s", got, want)
	}
}

func TestStringifyForPipe_MapPreservesJSON(t *testing.T) {
	value := map[string]any{"id": 7, "name": "alice"}
	got := stringifyForPipe(value)
	want := `{"id":7,"name":"alice"}`
	if got != want {
		t.Errorf("map: got %s, want %s", got, want)
	}
}

func TestStringifyForPipe_Scalars(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{"hello", "hello"},
		{42, "42"},
		{3.14, "3.14"},
		{true, "true"},
		{nil, ""},
	}
	for _, c := range cases {
		got := stringifyForPipe(c.in)
		if got != c.want {
			t.Errorf("%v (%T): got %q, want %q", c.in, c.in, got, c.want)
		}
	}
}

// End-to-end through ApplyPipe - `| default:'[]'` against a non-empty
// slice should return the JSON shape, not Go's `%v` formatter.
func TestApplyPipe_DefaultPreservesJSONForSlice(t *testing.T) {
	hits := []map[string]any{{"id": 1, "title": "foo"}}
	got := ApplyPipe(hits, "default:'[]'")
	if !strings.HasPrefix(got, "[") || !strings.HasSuffix(got, "]") {
		t.Errorf("default on slice should be JSON array: %s", got)
	}
	// Must be parseable as JSON - that's the property we actually
	// care about because the downstream consumer is json_each().
	if strings.Contains(got, "map[") {
		t.Errorf("default on slice leaked Go's reflect shape: %s", got)
	}
}

// Default on the empty/missing case still uses the literal arg.
func TestApplyPipe_DefaultUsesArgWhenEmpty(t *testing.T) {
	got := ApplyPipe("", "default:'fallback'")
	if got != "fallback" {
		t.Errorf("default on empty: got %q, want fallback", got)
	}
	got2 := ApplyPipe(nil, "default:'[]'")
	if got2 != "[]" {
		t.Errorf("default on nil: got %q, want []", got2)
	}
}

// count/length still uses the type switch and works on slices.
func TestApplyPipe_LengthOnSlice(t *testing.T) {
	got := ApplyPipe([]any{1, 2, 3}, "length")
	if got != "3" {
		t.Errorf("length on slice: got %q, want 3", got)
	}
}
