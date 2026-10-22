//go:build !cli

package main

import (
	"net/http"
	"testing"
)

// Any auth value other than an explicit opt-out gates the page; before, only
// the exact string "required" registered the sign-in check.
func TestPageAuthValuesOtherThanRequiredStillGate(t *testing.T) {
	app := ssrTestApp(t)
	ssrLoadPages(t, app, map[string]string{
		"a.html":    `<page auth="true"><h1>a</h1></page>`,
		"b.html":    `<page auth="Required"><h1>b</h1></page>`,
		"c.html":    "---\nauth: yes\n---\n<h1>c</h1>\n",
		"d.html":    `<page auth="login-please"><h1>d</h1></page>`,
		"open.html": `<page auth="none"><h1>open</h1></page>`,
	})
	mux := buildAppMux(app, false, "https://fixture.example.com")
	for _, path := range []string{"/a", "/b", "/c", "/d"} {
		if rec := ssrGet(mux, path, ""); rec.Code == http.StatusOK {
			t.Errorf("anonymous GET %s = 200; want a sign-in redirect", path)
		}
	}
	if rec := ssrGet(mux, "/open", ""); rec.Code != http.StatusOK {
		t.Errorf("auth=\"none\" page: status %d, want 200", rec.Code)
	}
	user := createCrudScopeSession(t, app, "u@example.com", "user", "", "")
	if rec := ssrGet(mux, "/a", user); rec.Code != http.StatusOK {
		t.Errorf("signed-in GET /a: status %d, want 200", rec.Code)
	}
}

func TestNormalizePageAuth(t *testing.T) {
	cases := map[string]string{
		"": "", "none": "none", "NONE": "none", "public": "none", "false": "none",
		"required": "required", " required ": "required", "true": "required", "optional": "required",
	}
	for in, want := range cases {
		if got := normalizePageAuth(in, "x.html"); got != want {
			t.Errorf("normalizePageAuth(%q) = %q, want %q", in, got, want)
		}
	}
}
