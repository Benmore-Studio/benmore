//go:build !cli

package main

import (
	"strings"
	"testing"
)

// `{{n | pluralize:event}}` rendered "event" for 3 and "1" for 1. The pipe
// now outputs the word: the argument is the singular (plural adds "s"), or
// "singular,plural" for irregular words; with no argument it is the suffix.
func TestPluralizePipeOutputsTheWord(t *testing.T) {
	cases := []struct {
		value any
		pipe  string
		want  string
	}{
		{3, "pluralize:event", "events"},
		{int64(1), "pluralize:event", "event"},
		{0, "pluralize:event", "events"},
		{"1", "pluralize:event", "event"},
		{"2", "pluralize:'event'", "events"},
		{1.0, "pluralize:person,people", "person"},
		{float64(4), "pluralize:person, people", "people"},
		{nil, "pluralize:item", "items"},
		{1, "pluralize", ""},
		{7, "pluralize", "s"},
	}
	for _, tc := range cases {
		if got := ApplyPipe(tc.value, tc.pipe); got != tc.want {
			t.Errorf("ApplyPipe(%v, %q) = %q, want %q", tc.value, tc.pipe, got, tc.want)
		}
	}

	// In a page and in a flow template, the same registry.
	out := RenderMustache(`{{n}} {{n | pluralize:event}}, {{one}} {{one | pluralize:person,people}}, {{n}} item{{n | pluralize}}`, map[string]any{"n": int64(3), "one": int64(1)})
	if out != "3 events, 1 person, 3 items" {
		t.Errorf("mustache render = %q", out)
	}
	if v, ok := resolveBindRef("steps.count.n | pluralize:seat", map[string]any{"steps.count.n": int64(2)}); !ok || v != "seats" {
		t.Errorf("flow pipe = %v, %v; want seats", v, ok)
	}
}

// cents is dollars to whole cents for a payment API, not a formatter; its
// behaviour is unchanged. currency formats a dollar amount.
func TestCentsAndCurrencyPipesAsDocumented(t *testing.T) {
	for _, tc := range []struct {
		value any
		pipe  string
		want  string
	}{
		{25, "cents", "2500"},
		{"19.99", "cents", "1999"},
		{2500, "cents", "250000"},
		{2500, "currency", "$2,500"},
		{25.5, "currency", "$25.50"},
		{-3, "currency", "-$3"},
	} {
		if got := ApplyPipe(tc.value, tc.pipe); got != tc.want {
			t.Errorf("ApplyPipe(%v, %q) = %q, want %q", tc.value, tc.pipe, got, tc.want)
		}
	}
	if !strings.Contains(RenderMustache(`{{price | currency}}`, map[string]any{"price": 25.0}), "$25") {
		t.Error("currency in a page")
	}
}
