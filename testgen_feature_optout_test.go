//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestGeneratedFrameworkExpectationsFollowDisabledFeatureRoutes(t *testing.T) {
	no := false
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Paths = DiscoverAuthPaths(nil)
	app.Pages = map[string]*Page{}
	app.Design = &DesignConfig{Auth: map[string]string{"signup": "false", "api_tokens": "false"}, Features: &FeaturesConfig{Admin: &no, Docs: &no}}
	if !NeedsAuth(app) {
		t.Fatal("fixture must generate authentication tests")
	}
	byName := map[string]AppTestFile{
		"_framework_security": generateSecurityTests(app),
		"_framework_docs":     generateDocsTests(app),
		"_framework_auth":     generateAuthTests(app),
	}
	checks := []struct {
		file, name string
		want       int
	}{
		{"_framework_security", "admin_requires_auth", http.StatusNotFound},
		{"_framework_docs", "api_docs_json", http.StatusNotFound},
		{"_framework_docs", "api_docs_html", http.StatusNotFound},
		{"_framework_docs", "api_docs_markdown", http.StatusNotFound},
		{"_framework_auth", "signup_post_registered", http.StatusNotFound},
		{"_framework_auth", "token_endpoint", http.StatusNotFound},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			file, ok := byName[check.file]
			if !ok {
				t.Fatalf("missing generated file %q", check.file)
			}
			got, ok := file.Tests[check.name]
			if !ok || len(got.Steps) != 1 {
				t.Fatalf("missing generated case %q", check.name)
			}
			if got.Steps[0].Expect.Status != check.want {
				t.Errorf("generated status = %d, want %d", got.Steps[0].Expect.Status, check.want)
			}
		})
	}
}

func TestGeneratedFrameworkExpectationsKeepFeatureDefaultsEnabled(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Paths = DiscoverAuthPaths(nil)
	app.Pages = map[string]*Page{}
	app.Design = &DesignConfig{Auth: map[string]string{"identifier": "email"}}
	byName := map[string]AppTestFile{
		"_framework_security": generateSecurityTests(app),
		"_framework_docs":     generateDocsTests(app),
		"_framework_auth":     generateAuthTests(app),
	}
	checks := []struct {
		file, name string
		want       int
	}{
		{"_framework_security", "admin_requires_auth", http.StatusSeeOther},
		{"_framework_docs", "api_docs_json", http.StatusOK},
		{"_framework_docs", "api_docs_html", http.StatusOK},
		{"_framework_docs", "api_docs_markdown", http.StatusOK},
		{"_framework_auth", "signup_post_registered", http.StatusSeeOther},
		{"_framework_auth", "token_endpoint", http.StatusOK},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			got, ok := byName[check.file].Tests[check.name]
			if !ok || len(got.Steps) != 1 {
				t.Fatalf("missing generated case %q", check.name)
			}
			if got.Steps[0].Expect.Status != check.want {
				t.Errorf("generated status = %d, want %d", got.Steps[0].Expect.Status, check.want)
			}
		})
	}
}

func TestDisabledFeatureRoutesAre404AndDefaultsRemainRegistered(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		t.Run(map[bool]string{false: "default-enabled", true: "explicitly-disabled"}[disabled], func(t *testing.T) {
			app, cleanup := newTestApp(t)
			defer cleanup()
			app.DevMode = true
			app.Paths = DiscoverAuthPaths(nil)
			app.Pages = map[string]*Page{}
			app.Design = &DesignConfig{Auth: map[string]string{"identifier": "email"}, SEO: map[string]string{}}
			if disabled {
				no := false
				app.Design.Auth["signup"] = "false"
				app.Design.Auth["api_tokens"] = "false"
				app.Design.Features = &FeaturesConfig{Admin: &no, Docs: &no}
			}
			mux := buildAppRouteMux(app, false, "https://fixture.example", false, nil).ServeMux
			request := func(method, path, body string) int {
				req := httptest.NewRequest(method, path, strings.NewReader(body))
				if body != "" {
					req.Header.Set("Content-Type", "application/json")
				}
				rec := httptest.NewRecorder()
				mux.ServeHTTP(rec, req)
				return rec.Code
			}
			want := http.StatusSeeOther
			if disabled {
				want = http.StatusNotFound
			}
			if got := request(http.MethodGet, "/_admin", ""); got != want {
				t.Errorf("GET /_admin = %d, want %d", got, want)
			}
			if got := request(http.MethodGet, "/api/_docs", ""); disabled && got != http.StatusNotFound {
				t.Errorf("GET /api/_docs = %d, want 404", got)
			} else if !disabled && got == http.StatusNotFound {
				t.Errorf("GET /api/_docs = 404; default-enabled route must remain registered")
			}
			if got := request(http.MethodGet, "/docs", ""); disabled && got != http.StatusNotFound {
				t.Errorf("GET /docs = %d, want 404", got)
			} else if !disabled && got == http.StatusNotFound {
				t.Errorf("GET /docs = 404; default-enabled route must remain registered")
			}
			if got := request(http.MethodPost, app.Paths.Signup, `{}`); disabled && got != http.StatusNotFound {
				t.Errorf("POST %s = %d, want 404", app.Paths.Signup, got)
			} else if !disabled && got == http.StatusNotFound {
				t.Errorf("POST %s = 404; default-enabled route must remain registered", app.Paths.Signup)
			}
			if got := request(http.MethodPost, "/api/_auth/token", `{}`); disabled && got != http.StatusNotFound {
				t.Errorf("POST /api/_auth/token = %d, want 404", got)
			} else if !disabled && got == http.StatusNotFound {
				t.Errorf("POST /api/_auth/token = 404; default-enabled route must remain registered")
			}
		})
	}
}
