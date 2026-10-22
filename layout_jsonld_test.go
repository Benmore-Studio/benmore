package main

import (
	"encoding/json"
	"regexp"
	"strings"
	"testing"
)

var jsonLDScriptRe = regexp.MustCompile(`(?s)<script type="application/ld\+json">(.*?)</script>`)

// parseJSONLD extracts every JSON-LD block, fails the test if any is not
// valid JSON, and returns them keyed by @type.
func parseJSONLD(t *testing.T, head string) map[string]map[string]any {
	t.Helper()
	out := map[string]map[string]any{}
	for _, m := range jsonLDScriptRe.FindAllStringSubmatch(head, -1) {
		var obj map[string]any
		if err := json.Unmarshal([]byte(m[1]), &obj); err != nil {
			t.Fatalf("invalid JSON-LD %q: %v", m[1], err)
		}
		out[obj["@type"].(string)] = obj
	}
	return out
}

func seoTestApp(seo map[string]string, routes ...string) *App {
	pages := map[string]*Page{}
	for _, r := range routes {
		pages[r] = &Page{Route: r}
	}
	return &App{
		Dir:    "/tmp/seo-test-app",
		Design: &DesignConfig{SEO: seo, Colors: map[string]string{}},
		Pages:  pages,
	}
}

func TestSearchActionOnlyWhenSearchable(t *testing.T) {
	seo := map[string]string{"site_name": "Benmore", "url": "https://example.test", "description": "Framework"}
	home := &Page{Route: "/"}

	// No search page, no declared URL: no SearchAction at all.
	ld := parseJSONLD(t, buildSEOTags(seoTestApp(seo, "/", "/docs"), home, "Home"))
	site, ok := ld["WebSite"]
	if !ok {
		t.Fatal("homepage should emit a WebSite schema")
	}
	if _, has := site["potentialAction"]; has {
		t.Errorf("WebSite must not advertise a SearchAction without a /search page: %v", site)
	}
	if _, ok := ld["Organization"]; !ok {
		t.Error("homepage should still emit an Organization schema")
	}

	// A real /search page enables the framework default template.
	ld = parseJSONLD(t, buildSEOTags(seoTestApp(seo, "/", "/search"), home, "Home"))
	action, _ := ld["WebSite"]["potentialAction"].(map[string]any)
	target, _ := action["target"].(map[string]any)
	if target["urlTemplate"] != "https://example.test/search?q={search_term_string}" {
		t.Errorf("expected default SearchAction template, got %v", action)
	}

	// An explicit relative seo.search_url wins and is made absolute.
	custom := map[string]string{"site_name": "Benmore", "url": "https://example.test", "search_url": "/find?term={search_term_string}"}
	ld = parseJSONLD(t, buildSEOTags(seoTestApp(custom, "/"), home, "Home"))
	action, _ = ld["WebSite"]["potentialAction"].(map[string]any)
	target, _ = action["target"].(map[string]any)
	if target["urlTemplate"] != "https://example.test/find?term={search_term_string}" {
		t.Errorf("expected custom SearchAction template, got %v", action)
	}

	// A declared URL without the placeholder is unusable and is dropped.
	broken := map[string]string{"site_name": "Benmore", "url": "https://example.test", "search_url": "/find"}
	ld = parseJSONLD(t, buildSEOTags(seoTestApp(broken, "/", "/search"), home, "Home"))
	if _, has := ld["WebSite"]["potentialAction"]; has {
		t.Error("search_url without {search_term_string} must not produce a SearchAction")
	}

	// Non-homepage routes never carry WebSite/Organization.
	ld = parseJSONLD(t, buildSEOTags(seoTestApp(seo, "/", "/search", "/docs"), &Page{Route: "/docs"}, "Docs"))
	if _, has := ld["WebSite"]; has {
		t.Error("WebSite schema must only appear on the homepage")
	}
}

func TestJSONLDSurvivesHostileValues(t *testing.T) {
	seo := map[string]string{
		"site_name":   `Ben "quoted" & <co>`,
		"url":         "https://example.test",
		"description": `Line one "two" </script><script>alert(1)</script>`,
		"org":         `Org "Inc"`,
		"favicon":     "/favicon.png",
	}
	page := &Page{Route: "/deploy-an-app", Description: `Deploy "safely" </script>`}
	head := buildSEOTags(seoTestApp(seo, "/", "/deploy-an-app"), page, `Deploy "an" app`)
	ld := parseJSONLD(t, head)

	// Every block parsed (parseJSONLD fails otherwise). Now the values.
	if ld["WebPage"]["name"] != `Deploy "an" app` {
		t.Errorf("WebPage name lost its quotes: %v", ld["WebPage"]["name"])
	}
	if ld["WebPage"]["description"] != `Deploy "safely" </script>` {
		t.Errorf("WebPage description altered: %v", ld["WebPage"]["description"])
	}
	crumbs, _ := ld["BreadcrumbList"]["itemListElement"].([]any)
	if len(crumbs) != 2 {
		t.Fatalf("expected 2 breadcrumbs, got %v", crumbs)
	}
	last := crumbs[1].(map[string]any)
	if last["name"] != "Deploy An App" || last["item"] != "https://example.test/deploy-an-app" || last["position"] != float64(2) {
		t.Errorf("unexpected breadcrumb: %v", last)
	}

	// The raw serialized text must not contain a literal closing tag inside a
	// value: the only `</script>` occurrences are the real element closers.
	if got := strings.Count(head, "</script>"); got != len(jsonLDScriptRe.FindAllString(head, -1)) {
		t.Errorf("a JSON-LD value leaked a raw </script>: %d closers for %d blocks", got, len(jsonLDScriptRe.FindAllString(head, -1)))
	}

	// Homepage with the same hostile site name and org.
	ld = parseJSONLD(t, buildSEOTags(seoTestApp(seo, "/"), &Page{Route: "/"}, "Home"))
	if ld["WebSite"]["name"] != `Ben "quoted" & <co>` {
		t.Errorf("WebSite name altered: %v", ld["WebSite"]["name"])
	}
	if ld["Organization"]["name"] != `Org "Inc"` || ld["Organization"]["logo"] != "https://example.test/favicon.png" {
		t.Errorf("Organization altered: %v", ld["Organization"])
	}
}
