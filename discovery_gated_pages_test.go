//go:build !cli

package main

import (
	"strings"
	"testing"
)

// The sitemap, llms.txt and feed must not list any page an anonymous crawler
// can't fully reach.
func TestDiscoveryOmitsGatedPages(t *testing.T) {
	app := &App{Pages: map[string]*Page{
		"/":       {Route: "/", Title: "home-title", RawHTML: `<page>x</page>`},
		"/pro":    {Route: "/pro", Title: "pro-title", Description: "pro-desc", Require: "plan:pro", RawHTML: `<page require="plan:pro">x</page>`},
		"/staff":  {Route: "/staff", Title: "staff-title", Role: "admin", RawHTML: `<page role="admin" title="staff-title">x</page>`},
		"/secret": {Route: "/secret", Title: "secret-title", Auth: "required", RawHTML: `<page auth="required">x</page>`},
		"/login":  {Route: "/login", Title: "login-title", Type: "login", RawHTML: `<page type="login">x</page>`},
		"/hidden": {Route: "/hidden", Title: "hidden-title", Robots: "noindex", RawHTML: `<page>x</page>`},
		"/route":  {Route: "/route", Title: "route-title", Redirect: "admin:/admin", RawHTML: `<page redirect="admin:/admin">x</page>`},
	}}
	base := "https://fixture.example.com"
	outputs := map[string]string{
		"sitemap": GenerateSitemap(app, base),
		"llms":    GenerateLLMsTxt(app, base),
		"feed":    GenerateAtomFeed(app, base),
	}
	for name, out := range outputs {
		if !strings.Contains(out, base+"/") {
			t.Errorf("%s: public home page missing", name)
		}
		for _, gated := range []string{"/pro", "/staff", "/secret", "/login", "/hidden", "/route"} {
			if strings.Contains(out, base+gated) {
				t.Errorf("%s lists gated page %s", name, gated)
			}
		}
	}
}
