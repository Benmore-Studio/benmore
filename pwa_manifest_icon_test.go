//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type manifestIconEntry struct {
	Src   string `json:"src"`
	Sizes string `json:"sizes"`
	Type  string `json:"type"`
}

func manifestIconEntries(t *testing.T, body string) []manifestIconEntry {
	t.Helper()
	var m struct {
		Icons []manifestIconEntry `json:"icons"`
	}
	if err := json.Unmarshal([]byte(body), &m); err != nil {
		t.Fatalf("manifest is not JSON: %v\n%s", err, body)
	}
	return m.Icons
}

// Every app's /manifest.json named /static/icon-512.png unless pwa.icon was
// set. The scaffold ships static/favicon.svg and no PNG, so a new app's
// manifest (linked from every page) listed an icon that answered 404.
func TestScaffoldManifestIconsAllLoad(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHTMLScaffoldFiles(dir, "Icon fixture"); err != nil {
		t.Fatal(err)
	}
	app, err := loadAppForServerTests(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	const origin = "https://icon.example.com"
	mux := buildAppMux(app, false, origin)
	get := func(target string) *httptest.ResponseRecorder {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, origin+target, nil))
		return w
	}

	w := get("/manifest.json")
	if w.Code != http.StatusOK {
		t.Fatalf("/manifest.json answered %d", w.Code)
	}
	icons := manifestIconEntries(t, w.Body.String())
	if len(icons) == 0 {
		t.Fatalf("manifest lists no icon:\n%s", w.Body.String())
	}
	for _, icon := range icons {
		if got := get(icon.Src); got.Code != http.StatusOK {
			t.Errorf("manifest icon %s answered %d", icon.Src, got.Code)
		}
	}
	if len(icons) != 1 || !strings.HasPrefix(icons[0].Src, "/static/favicon.svg") || icons[0].Type != "image/svg+xml" || icons[0].Sizes != "any" {
		t.Fatalf("a new app's manifest should list the scaffold's favicon.svg: %+v", icons)
	}

	// The scaffold's reviewed mcp.yaml makes the app serve /static/ from the
	// source captured at load. A PNG that reaches disk afterwards is not
	// served yet, so the manifest must not list it either: "exists" means
	// what the static handler answers with, not what is on disk.
	if appMCPManifestSnapshot(app) == nil {
		t.Fatal("the scaffold's starter mcp.yaml did not load")
	}
	if err := os.WriteFile(filepath.Join(dir, "static", "icon-512.png"), []byte("png"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := get("/static/icon-512.png"); got.Code != http.StatusNotFound {
		t.Fatalf("a file written after the reviewed load answered %d; this case no longer tests the captured source", got.Code)
	}
	for _, icon := range manifestIconEntries(t, get("/manifest.json").Body.String()) {
		if got := get(icon.Src); got.Code != http.StatusOK {
			t.Errorf("manifest icon %s answered %d once an unreviewed PNG was on disk", icon.Src, got.Code)
		}
	}
}

// The manifest keeps the configured icon (pwa.icon, else seo.favicon, else
// /static/icon-512.png) whenever it can be served, and otherwise names the
// first later choice the app does have, ending with static/favicon.svg.
func TestManifestIconFallsBackToAFileTheAppHas(t *testing.T) {
	const svg = `<svg xmlns="http://www.w3.org/2000/svg"/>`
	for _, c := range []struct {
		name       string
		pwa, seo   map[string]string
		files      []string
		wantSrc    string // prefix: a /static/ file that exists also carries ?v=
		wantSizes  []string
		wantType   string
		wantNoType bool
	}{
		{name: "no icon configured, favicon.svg only",
			files: []string{"favicon.svg"}, wantSrc: "/static/favicon.svg?v=", wantSizes: []string{"any"}, wantType: "image/svg+xml"},
		{name: "pwa section from the documented keys, no icon",
			pwa:   map[string]string{"name": "Events", "short_name": "Events", "theme_color": "#18181b", "background_color": "#ffffff", "offline": "true"},
			files: []string{"favicon.svg"}, wantSrc: "/static/favicon.svg?v=", wantSizes: []string{"any"}, wantType: "image/svg+xml"},
		{name: "the default PNG still wins when the app has it",
			files: []string{"favicon.svg", "icon-512.png"}, wantSrc: "/static/icon-512.png?v=", wantSizes: []string{"192x192", "512x512"}, wantType: "image/png"},
		{name: "pwa.icon names a missing file",
			pwa:   map[string]string{"icon": "/static/missing.png"},
			files: []string{"favicon.svg"}, wantSrc: "/static/favicon.svg?v=", wantSizes: []string{"any"}, wantType: "image/svg+xml"},
		{name: "pwa.icon missing, seo.favicon present",
			pwa: map[string]string{"icon": "/static/missing.png"}, seo: map[string]string{"favicon": "/static/logo.webp"},
			files: []string{"favicon.svg", "logo.webp"}, wantSrc: "/static/logo.webp?v=", wantSizes: []string{"192x192", "512x512"}, wantType: "image/webp"},
		{name: "seo.favicon names a missing file",
			seo:   map[string]string{"favicon": "/static/gone.png"},
			files: []string{"favicon.svg"}, wantSrc: "/static/favicon.svg?v=", wantSizes: []string{"any"}, wantType: "image/svg+xml"},
		{name: "seo.favicon present is used before the default",
			seo:   map[string]string{"favicon": "/static/logo.png"},
			files: []string{"favicon.svg", "icon-512.png", "logo.png"}, wantSrc: "/static/logo.png?v=", wantSizes: []string{"192x192", "512x512"}, wantType: "image/png"},
		{name: "an icon outside /static/ cannot be checked and is kept",
			pwa:   map[string]string{"icon": "/uploads/brand/icon.png"},
			files: []string{"favicon.svg"}, wantSrc: "/uploads/brand/icon.png", wantSizes: []string{"192x192", "512x512"}, wantType: "image/png"},
		{name: "an icon on another origin is kept",
			pwa:   map[string]string{"icon": "https://cdn.example.com/static/icon.png"},
			files: []string{"favicon.svg"}, wantSrc: "https://cdn.example.com/static/icon.png", wantSizes: []string{"192x192", "512x512"}, wantType: "image/png"},
		{name: "a protocol-relative icon is kept",
			pwa:   map[string]string{"icon": "//cdn.example.com/static/icon.png"},
			files: []string{"favicon.svg"}, wantSrc: "//cdn.example.com/static/icon.png", wantSizes: []string{"192x192", "512x512"}, wantType: "image/png"},
		{name: "a present icon written with a query is kept as written",
			pwa:   map[string]string{"icon": "/static/icon.png?rev=3"},
			files: []string{"favicon.svg", "icon.png"}, wantSrc: "/static/icon.png?rev=3", wantSizes: []string{"192x192", "512x512"}, wantType: "image/png"},
		{name: "a present icon with an escaped name is kept",
			pwa:   map[string]string{"icon": "/static/app%20icon.png"},
			files: []string{"favicon.svg", "app icon.png"}, wantSrc: "/static/app%20icon.png", wantSizes: []string{"192x192", "512x512"}, wantType: "image/png"},
		{name: "nothing to fall back to: the default path stays",
			wantSrc: "/static/icon-512.png", wantSizes: []string{"192x192", "512x512"}, wantType: "image/png"},
		{name: "nothing to fall back to: the configured path stays",
			pwa: map[string]string{"icon": "/static/missing.jpg"}, wantSrc: "/static/missing.jpg", wantSizes: []string{"192x192", "512x512"}, wantType: "image/jpeg"},
	} {
		t.Run(c.name, func(t *testing.T) {
			app := &App{Dir: t.TempDir(), Design: &DesignConfig{PWA: c.pwa, SEO: map[string]string{"site_name": "Events"}}}
			for k, v := range c.seo {
				app.Design.SEO[k] = v
			}
			static := filepath.Join(app.Dir, "static")
			if err := os.MkdirAll(static, 0o755); err != nil {
				t.Fatal(err)
			}
			for _, name := range c.files {
				if err := os.WriteFile(filepath.Join(static, name), []byte(svg), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			icons := manifestIconEntries(t, GenerateManifest(app))
			if len(icons) != len(c.wantSizes) {
				t.Fatalf("icons: %+v, want sizes %v", icons, c.wantSizes)
			}
			for i, icon := range icons {
				if !strings.HasPrefix(icon.Src, c.wantSrc) || icon.Sizes != c.wantSizes[i] || icon.Type != c.wantType {
					t.Fatalf("icon %d: %+v, want src %s… sizes %s type %s", i, icon, c.wantSrc, c.wantSizes[i], c.wantType)
				}
				// Every icon under /static/ that the manifest lists for an app
				// that has a file to list is one the static handler serves.
				if rel, ok := strings.CutPrefix(icon.Src, "/static/"); ok && len(c.files) > 0 {
					rel, _, _ = strings.Cut(rel, "?")
					rel = strings.ReplaceAll(rel, "%20", " ")
					rec := httptest.NewRecorder()
					serveStaticAsset(rec, httptest.NewRequest(http.MethodGet, icon.Src, nil), app, false, rel)
					if rec.Code != http.StatusOK {
						t.Fatalf("listed icon %s answered %d", icon.Src, rec.Code)
					}
				}
			}
		})
	}
}

// A link out of static/ is not served, so it is not an icon the app has.
func TestManifestIconIgnoresALinkOutOfStatic(t *testing.T) {
	app := &App{Dir: t.TempDir(), Design: &DesignConfig{PWA: map[string]string{"icon": "/static/icon.png"}, SEO: map[string]string{}}}
	static := filepath.Join(app.Dir, "static")
	if err := os.MkdirAll(static, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(static, "favicon.svg"), []byte("<svg/>"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(app.Dir, "env.yaml")
	if err := os.WriteFile(outside, []byte("KEY: value"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(static, "icon.png")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	icons := manifestIconEntries(t, GenerateManifest(app))
	if len(icons) != 1 || !strings.HasPrefix(icons[0].Src, "/static/favicon.svg?v=") {
		t.Fatalf("icons: %+v", icons)
	}
}

func writeIconCheckApp(t *testing.T, appYAML string, staticFiles ...string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "static"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(appYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, name := range staticFiles {
		if err := os.WriteFile(filepath.Join(dir, "static", name), []byte("<svg/>"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func iconWarnings(report CheckReport) []string {
	var out []string
	for _, f := range report.Findings {
		if f.Severity == "warning" && strings.Contains(f.Message, "manifest") && strings.Contains(f.Message, "icon") {
			out = append(out, f.File+": "+f.Message)
		}
	}
	return out
}

// `benmore check` and the write gate share one report (runCheck): both say
// when an app that asked for a `pwa:` manifest names an icon file it lacks.
func TestCheckWarnsWhenManifestIconFileIsMissing(t *testing.T) {
	const pwa = "site_name: Events\npwa:\n  name: Events\n  short_name: Events\n  offline: true\n"

	// No icon at all: the manifest's default path answers 404.
	dir := writeIconCheckApp(t, pwa)
	for name, report := range map[string]CheckReport{
		"full check":      RunSourceCheck(dir, ""),
		"app.yaml write":  RunSourceCheck(dir, "app.yaml"),
		"complete (live)": RunCompleteCheckWith(dir, func(string) []CheckFinding { return nil }),
	} {
		got := iconWarnings(report)
		if len(got) != 1 || !strings.Contains(got[0], "/static/icon-512.png") || !strings.HasPrefix(got[0], "app.yaml: ") {
			t.Fatalf("%s: warnings %q, want one naming /static/icon-512.png on app.yaml", name, got)
		}
		if report.Errors != 0 {
			t.Fatalf("%s: a missing icon must warn, not refuse: %+v", name, report.Findings)
		}
	}
	// A write of another file does not repeat an app.yaml warning.
	if err := os.WriteFile(filepath.Join(dir, "static", "notes.html"), []byte("<!DOCTYPE html><html><head><title>n</title></head><body></body></html>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := iconWarnings(RunSourceCheck(dir, "static/notes.html")); len(got) != 0 {
		t.Fatalf("a page write repeated the app.yaml icon warning: %q", got)
	}

	// pwa.icon names a missing file, the favicon stands in: the warning names
	// both the missing file and what the manifest lists instead.
	dir = writeIconCheckApp(t, pwa+"  icon: /static/app-icon.png\n", "favicon.svg")
	got := iconWarnings(RunSourceCheck(dir, ""))
	if len(got) != 1 || !strings.Contains(got[0], "/static/app-icon.png") || !strings.Contains(got[0], "/static/favicon.svg") {
		t.Fatalf("warnings %q, want one naming the missing pwa.icon and the favicon used instead", got)
	}

	// The same missing pwa.icon with nothing to stand in for it.
	dir = writeIconCheckApp(t, pwa+"  icon: /static/app-icon.png\n")
	got = iconWarnings(RunSourceCheck(dir, ""))
	if len(got) != 1 || !strings.Contains(got[0], "/static/app-icon.png") || !strings.Contains(got[0], "`pwa.icon`") || !strings.Contains(got[0], "404") {
		t.Fatalf("warnings %q, want one saying the pwa.icon file is missing and the icon answers 404", got)
	}
	// seo.favicon is the manifest's icon when pwa.icon is not set.
	dir = writeIconCheckApp(t, "site_name: Events\nseo:\n  favicon: /static/brand.png\npwa:\n  name: Events\n", "favicon.svg")
	got = iconWarnings(RunSourceCheck(dir, ""))
	if len(got) != 1 || !strings.Contains(got[0], "/static/brand.png") || !strings.Contains(got[0], "`seo.favicon`") {
		t.Fatalf("warnings %q, want one naming the missing seo.favicon", got)
	}

	for name, dir := range map[string]string{
		"pwa section, favicon.svg stands in for the default": writeIconCheckApp(t, pwa, "favicon.svg"),
		"pwa.icon present":      writeIconCheckApp(t, pwa+"  icon: /static/app-icon.png\n", "app-icon.png"),
		"default icon present":  writeIconCheckApp(t, pwa, "icon-512.png"),
		"icon outside /static/": writeIconCheckApp(t, pwa+"  icon: https://cdn.example.com/icon.png\n"),
		"no pwa section":        writeIconCheckApp(t, "site_name: Events\n"),
	} {
		if got := iconWarnings(RunSourceCheck(dir, "")); len(got) != 0 {
			t.Errorf("%s: unexpected icon warning %q", name, got)
		}
	}
}
