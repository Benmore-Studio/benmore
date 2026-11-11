//go:build !cli

package main

import (
	"strings"
	"testing"
)

// Finding 12: an <include> of a missing partial passed push and check, then
// every view rendered "Include error: ... not found". It is refused at write
// time for a single write; a batch write that defers its reload may be
// followed by the partial, so it is accepted and the post-write check
// reports it.
func TestWriteGateRefusesMissingIncludeTarget(t *testing.T) {
	dir := bundleCheckApp(t)
	page := "<!doctype html>\n<html><head><include src=\"partials/head.html\" /></head>\n<body><include src=\"partials/missing-footer.html\" /></body></html>\n"
	msg := ValidateOnWriteIn(dir, "static/probe-include.html", page)
	if !strings.Contains(msg, "neither static/partials/missing-footer.html nor partials/missing-footer.html exists") || strings.Contains(msg, "partials/head.html\" />:") {
		t.Fatalf("write gate = %q, want only the missing footer refused", msg)
	}
	if msg, _ := ValidateOnWriteInBatch(dir, "static/probe-include.html", page, true, nil); msg != "" {
		t.Fatalf("deferred batch write refused: %s", msg)
	}
	writeAppFile(t, dir, "static/probe-include.html", page)
	if f := findingFor(RunSourceCheck(dir, "static/probe-include.html"), "static/probe-include.html", "missing-footer.html exists"); f == nil || f.Source != "include" {
		t.Fatalf("post-write check did not report it: %+v", RunSourceCheck(dir, "static/probe-include.html").Findings)
	}
	if f := findingFor(runCheck(dir, "", false), "static/probe-include.html", "missing-footer.html"); f == nil {
		t.Fatal("benmore check did not report the missing include")
	}
	// Once the partial exists the page passes.
	writeAppFile(t, dir, "static/partials/missing-footer.html", "<footer>ok</footer>\n")
	if msg := ValidateOnWriteIn(dir, "static/probe-include.html", page); msg != "" {
		t.Fatalf("page refused after the partial was written: %s", msg)
	}
}

// Finding 12: `<include src="...">` without `/>`, single quotes or another
// attribute are left in the page unexpanded with no error. They are refused
// in every write (no later file makes them expand), naming the form that
// works.
func TestWriteGateRefusesIncludeTagsTheRuntimeLeavesUnexpanded(t *testing.T) {
	dir := bundleCheckApp(t)
	for _, tag := range []string{
		`<include src="partials/head.html">`,
		`<include src='partials/head.html' />`,
		`<include src="partials/head.html" class="x" />`,
		`<INCLUDE src="partials/head.html" />`,
	} {
		page := "<html><head>" + tag + "</head><body></body></html>\n"
		for name, msg := range map[string]string{
			"single": ValidateOnWriteIn(dir, "static/form.html", page),
			"batch":  func() string { m, _ := ValidateOnWriteInBatch(dir, "static/form.html", page, true, nil); return m }(),
		} {
			if !strings.Contains(msg, "is not expanded") || !strings.Contains(msg, `<include src="partials/head.html" />`) {
				t.Errorf("%s %s: write gate = %q, want a refusal suggesting the self-closing form", name, tag, msg)
			}
		}
		// The runtime indeed leaves it unexpanded: the refusal matches what
		// a visitor would get.
		if out := ProcessIncludes(page, nil, dir+"/static"); !strings.Contains(out, tag) {
			t.Errorf("%s was expanded by the runtime; the refusal is wrong", tag)
		}
	}
}

// What the runtime expands is accepted: a root partial that takes
// precedence, an include mentioned in an HTML comment, gotmpl pages (which
// never run the include pass), and a src that leaves its directory is
// refused like the runtime blocks it.
func TestIncludeCheckFollowsRuntimeResolution(t *testing.T) {
	dir := bundleCheckApp(t)
	writeAppFile(t, dir, "partials/banner.html", "<div>banner</div>\n")
	ok := map[string]string{
		"static/root-partial.html": `<body><include src="partials/banner.html" /></body>`,
		"static/commented.html":    "<!-- the <include> tag, e.g. <include src='partials/x.html'> -->\n<body></body>",
		"layouts/main.html":        `<body><include src="partials/banner.html" />{{content}}</body>`,
		"about.html":               "---\nengine: gotmpl\n---\n<p><include src=\"partials/nowhere.html\"></p>",
		"emails/welcome.html":      `<include src="partials/nowhere.html">`,
	}
	for rel, content := range ok {
		if msg := ValidateOnWriteIn(dir, rel, content); strings.Contains(msg, "<include>") {
			t.Errorf("%s refused: %s", rel, msg)
		}
	}
	for rel, content := range map[string]string{
		"static/escape.html": `<include src="../env.yaml" />`,
		"pricing.html":       `<include src="partials/nowhere.html" />`,
		"static/abs.html":    `<include src="/etc/passwd" />`,
	} {
		if msg := ValidateOnWriteIn(dir, rel, content); !strings.Contains(msg, "<include>") {
			t.Errorf("%s accepted: %q", rel, msg)
		}
	}
}

// A partial a page still includes is not deleted from under it.
func TestIncludeDeleteRefusalNamesPages(t *testing.T) {
	dir := bundleCheckApp(t)
	msg := includeDeleteRefusal(dir, "static/partials/head.html")
	for _, page := range []string{"static/index.html", "static/login.html", "static/signup.html"} {
		if !strings.Contains(msg, page) {
			t.Errorf("delete refusal %q does not name %s", msg, page)
		}
	}
	// A root partial of the same name takes over the static/ pages' include.
	writeAppFile(t, dir, "partials/head.html", "<meta charset=\"utf-8\">\n")
	if msg := includeDeleteRefusal(dir, "static/partials/head.html"); msg != "" {
		t.Errorf("delete refused although partials/head.html takes its place: %s", msg)
	}
	if msg := includeDeleteRefusal(dir, "static/favicon.svg"); msg != "" {
		t.Errorf("delete of a non-HTML file refused: %s", msg)
	}
}
