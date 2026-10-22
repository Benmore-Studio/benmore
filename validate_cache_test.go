//go:build !cli

package main

import (
	"reflect"
	"runtime"
	"testing"
)

func TestValidationRulesCachedPerPageSet(t *testing.T) {
	app := &App{Pages: map[string]*Page{
		"/a": {RawHTML: `<form :create="notes"><input name="title" :validate="required,minlen:3"></form>`},
	}}
	if got := ExtractValidationRules(app, "notes"); got["title"] != "required,minlen:3" {
		t.Fatalf("rules = %v", got)
	}
	// Callers may mutate the returned map; the cache must not change.
	ExtractValidationRules(app, "notes")["title"] = "tampered"
	if got := ExtractValidationRules(app, "notes"); got["title"] != "required,minlen:3" {
		t.Fatalf("cached rules were mutated through a returned map: %v", got)
	}
	// A reload assigns a new page map: rules follow it.
	app.Pages = map[string]*Page{
		"/a": {RawHTML: `<form :create="notes"><input :validate="email" name="contact"></form>`},
	}
	got := ExtractValidationRules(app, "notes")
	if got["contact"] != "email" || got["title"] != "" {
		t.Fatalf("rules after reload = %v", got)
	}
	if got := ExtractValidationRules(app, "other"); len(got) != 0 {
		t.Fatalf("unrelated table got rules: %v", got)
	}
}

func TestValidateRuleRegexCached(t *testing.T) {
	if err := validateRule("code", "AB12", `regex:^[A-Z]{2}\d{2}$`); err != nil {
		t.Fatalf("valid value rejected: %v", err)
	}
	if err := validateRule("code", "ab12", `regex:^[A-Z]{2}\d{2}$`); err == nil {
		t.Fatal("invalid value accepted")
	}
	if validateRuleRegex(`^[A-Z]{2}\d{2}$`) != validateRuleRegex(`^[A-Z]{2}\d{2}$`) {
		t.Fatal("pattern should be compiled once")
	}
	// An invalid pattern stays a no-op rule, as before.
	if err := validateRule("code", "x", "regex:("); err != nil {
		t.Fatalf("invalid pattern must not reject: %v", err)
	}
}

// The cache identified a page generation by its map's address only. After
// two hot reloads with no create in between, the first generation's map is
// garbage and a later generation's map can be allocated at the same address,
// which then matched the stale entry and served the first generation's rules.
func TestValidationRulesCacheSurvivesPageMapAddressReuse(t *testing.T) {
	gen := func(rule string) map[string]*Page {
		return map[string]*Page{"/a": {RawHTML: `<form :create="notes"><input name="title" :validate="` + rule + `"></form>`}}
	}
	app := &App{Pages: gen("required")}
	firstID := reflect.ValueOf(app.Pages).Pointer()
	if got := ExtractValidationRules(app, "notes")["title"]; got != "required" {
		t.Fatalf("first generation rules = %q", got)
	}
	app.Pages = gen("minlen:2") // reload with no create before the next one
	runtime.GC()
	runtime.GC()
	var keep []map[string]*Page
	for i := 0; i < 200000; i++ {
		m := gen("email")
		if reflect.ValueOf(m).Pointer() != firstID {
			keep = append(keep, m)
			continue
		}
		app.Pages = m
		if got := ExtractValidationRules(app, "notes")["title"]; got != "email" {
			t.Fatalf("a page generation allocated at a collected generation's address got its stale rules: %q", got)
		}
		return
	}
	runtime.KeepAlive(keep)
	// No address reuse happened: the cache held the old generation alive (or
	// the allocator chose otherwise); the current generation must still win.
	if got := ExtractValidationRules(app, "notes")["title"]; got != "minlen:2" {
		t.Fatalf("current generation rules = %q", got)
	}
}
