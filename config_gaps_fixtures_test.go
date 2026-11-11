//go:build !cli

package main

import (
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// configGapFixtureDir copies testdata/<name> (the fixture apps behind the
// aggregates, computed, retention, custom-field and app.yaml-key reference
// text) into a scratch directory, so a test never writes into testdata.
func configGapFixtureDir(t *testing.T, name string) string {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join("testdata", name)
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		writeTestFile(t, dir, rel, string(body))
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return dir
}

func configGapFixtureApp(t *testing.T, name string) *App {
	t.Helper()
	app, err := loadApp(configGapFixtureDir(t, name))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	return app
}

// The reference quotes these apps' files as its examples, so both halves of
// "the example works as written" are held here: the write gate accepts every
// source file, and the app's own tests/*.yaml (what `benmore test --app` and
// scripts/check-fixture-apps.py run) pass.
func TestConfigGapFixturesPassTheWriteGateAndTheirTests(t *testing.T) {
	for _, name := range []string{"derived-data", "app-yaml-switches"} {
		t.Run(name, func(t *testing.T) {
			dir := configGapFixtureDir(t, name)
			for _, f := range RunSourceCheck(dir, "").Findings {
				if f.Severity == "error" {
					t.Errorf("the write gate refuses %s: %s", f.File, f.Message)
				}
			}
			app, err := loadApp(dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(app.Shutdown)
			ran := 0
			for _, r := range RunAppTests(app) {
				if r.File == "SUMMARY" {
					continue
				}
				ran++
				if !r.Pass {
					t.Errorf("%s/%s: %s %+v", r.File, r.Test, r.Message, r.Steps)
				}
			}
			if ran == 0 {
				t.Fatal("the fixture ran no tests")
			}
		})
	}
}

// csp.style_src and csp.font_src widen the two directives they name and no
// other (a YAML test cannot assert part of a header).
func TestCSPStyleAndFontSourcesWidenTheirDirectives(t *testing.T) {
	t.Setenv("BENMORE_CF_ANALYTICS", "")
	app := configGapFixtureApp(t, "app-yaml-switches")
	h := securityHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), false, app)
	r := httptest.NewRequest("GET", "/about", nil)
	r.Host = "switches.example"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	policy := w.Header().Get("Content-Security-Policy")
	const origin = "https://cdn.example.com"
	seen := map[string]bool{}
	for _, directive := range strings.Split(policy, ";") {
		fields := strings.Fields(directive)
		if len(fields) == 0 {
			continue
		}
		has := false
		for _, source := range fields[1:] {
			has = has || source == origin
		}
		seen[fields[0]] = has
		if want := fields[0] == "style-src" || fields[0] == "font-src"; has != want {
			t.Errorf("%s lists %s: %v, want %v (policy: %s)", fields[0], origin, has, want, policy)
		}
	}
	for _, directive := range []string{"style-src", "font-src"} {
		if !seen[directive] {
			t.Errorf("no %s with %s in %q", directive, origin, policy)
		}
	}
	// The defaults stay: a value is appended, never a replacement.
	if !strings.Contains(policy, "style-src 'self'") || !strings.Contains(policy, "font-src 'self'") {
		t.Errorf("the default sources are gone: %s", policy)
	}
}
