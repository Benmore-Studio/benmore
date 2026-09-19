//go:build !cli

package main

// Golden tests for CompileDirectives. The framework emits HTML - if
// that HTML is malformed (stray escapes, broken attribute quoting,
// nested unescaped quotes), the browser parses something useless
// and the user sees a button that does nothing. We've shipped that
// regression twice now (hx-target with `closest X, closest Y`, then
// hx-target with backslash-escaped CSS selectors). These tests pin
// the output so any future change to directives.go that breaks the
// shape fails at CI.
//
// Discipline: every change to a directive's emitted HTML must come
// with an updated golden here, and the new golden must pass
// validateEmittedAttrs (no `\"` in attribute values, balanced
// quotes, no unescaped angle brackets).

import (
	"regexp"
	"strings"
	"testing"
)

func TestCompileCreateDirective(t *testing.T) {
	in := `<form :create="todos"><input name="title"></form>`
	out := CompileDirectives(in)

	mustContain(t, out, `hx-post="/api/todos"`)
	mustContain(t, out, `hx-target="closest form"`)
	mustContain(t, out, `hx-swap="outerHTML"`)
	mustNotContain(t, out, `:create=`)
	assertWellFormedAttrs(t, out)
}

func TestCompileDeleteDirectiveStrict(t *testing.T) {
	in := `<button :delete="todos" :id="42" :confirm="Are you sure?">×</button>`
	out := CompileDirectives(in)

	mustContain(t, out, `hx-delete="/api/todos/42"`)
	mustContain(t, out, `hx-confirm="Are you sure?"`)
	mustNotContain(t, out, `:delete=`)
	mustNotContain(t, out, `:id=`)
	mustNotContain(t, out, `:confirm=`)
	assertWellFormedAttrs(t, out)
}

func TestCompileDeleteDirectiveURL(t *testing.T) {
	in := `<button :delete="/api/todos/42">×</button>`
	out := CompileDirectives(in)

	mustContain(t, out, `hx-delete="/api/todos/42"`)
	mustNotContain(t, out, `:delete=`)
	assertWellFormedAttrs(t, out)
}

func TestCompilePatchDirectiveStrict(t *testing.T) {
	in := `<button :patch="/api/todos/42" :set="done=1">✓</button>`
	out := CompileDirectives(in)

	mustContain(t, out, `hx-patch="/api/todos/42"`)
	mustNotContain(t, out, `:patch=`)
	mustNotContain(t, out, `:set=`)
	assertWellFormedAttrs(t, out)
}

func TestCompilePatchDirectiveURL(t *testing.T) {
	in := `<button :patch="/api/todos/42">toggle</button>`
	out := CompileDirectives(in)

	mustContain(t, out, `hx-patch="/api/todos/42"`)
	mustNotContain(t, out, `:patch=`)
	assertWellFormedAttrs(t, out)
}

// HxTargetUsesValidCSSSelectors pins the hx-target value for the
// row-removing directives. The previous bug here generated
// `[class*=\"row\"]` (literal backslash + quote), which truncated
// the attribute at the backslash and broke the selector. CSS
// attribute selectors must use single quotes inside the
// double-quoted HTML attribute.
func TestHxTargetUsesValidCSSSelectors(t *testing.T) {
	cases := []string{
		`<button :delete="todos" :id="1">x</button>`,
		`<button :delete="/api/todos/1">x</button>`,
		`<button :patch="/api/todos/1">x</button>`,
	}
	for _, in := range cases {
		out := CompileDirectives(in)
		if strings.Contains(out, `\"`) {
			t.Fatalf("backslash-escaped quote in emitted HTML - browsers will truncate the attribute:\n  input:  %s\n  output: %s", in, out)
		}
		if strings.Contains(out, `\\`) {
			t.Fatalf("backslash leaked into emitted HTML:\n  input:  %s\n  output: %s", in, out)
		}
		assertWellFormedAttrs(t, out)
	}
}

// ---------- helpers ----------

func mustContain(t *testing.T, s, sub string) {
	t.Helper()
	if !strings.Contains(s, sub) {
		t.Fatalf("missing %q in:\n%s", sub, s)
	}
}

func mustNotContain(t *testing.T, s, sub string) {
	t.Helper()
	if strings.Contains(s, sub) {
		t.Fatalf("should not contain %q but did, in:\n%s", sub, s)
	}
}

// testAttrRe matches HTML attributes (name="value"). Captures the value.
// Local to this test file - the framework has its own attrRe.
var testAttrRe = regexp.MustCompile(`\s([\w:\-]+)="([^"]*)"`)

// assertWellFormedAttrs catches the most common framework-side HTML
// emission bugs: literal backslash-quote in attribute values
// (truncates the attribute), unescaped less-than (closes the tag
// early), nested unescaped double quotes.
func assertWellFormedAttrs(t *testing.T, html string) {
	t.Helper()
	for _, m := range testAttrRe.FindAllStringSubmatch(html, -1) {
		name, val := m[1], m[2]
		if strings.Contains(val, `\"`) {
			t.Errorf("attribute %s contains literal `\\\"` - browsers truncate at the backslash. Value: %q", name, val)
		}
		if strings.ContainsRune(val, '<') {
			t.Errorf("attribute %s contains unescaped `<` - browsers may misparse. Value: %q", name, val)
		}
	}
}
