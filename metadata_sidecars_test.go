package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeSidecarFixture lays out an app with real pages, partials, and static
// files next to the desktop-metadata sidecars a macOS tar leaves behind.
func writeSidecarFixture(t *testing.T) string {
	t.Helper()
	// Resolve the temp dir: on macOS it sits under a /var → /private/var
	// symlink, and the serving path compares lexical containment first.
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	files := map[string]string{
		"index.html":                  `<page title="Home"><h1>Home</h1></page>`,
		"docs.html":                   `<page title="Docs"><h1>Docs</h1></page>`,
		"head.html":                   `<meta name="x" content="y">`,
		"._index.html":                "\x00\x05\x16\x07 apple double",
		"._docs.html":                 "\x00\x05\x16\x07 apple double",
		".DS_Store":                   "finder",
		"partials/nav.html":           `<nav>real</nav>`,
		"partials/._nav.html":         "\x00\x05\x16\x07 apple double",
		"static/index.html":           `<!doctype html><title>Static</title><h1>Static</h1>`,
		"static/guide.html":           `<!doctype html><title>Guide</title><h1>Guide</h1>`,
		"static/._guide.html":         "\x00\x05\x16\x07 apple double",
		"static/app.js":               `console.log(1)`,
		"static/._app.js":             "\x00\x05\x16\x07 apple double",
		"static/partials/._foot.html": "\x00\x05\x16\x07 apple double",
	}
	for rel, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestIsMetadataSidecar(t *testing.T) {
	yes := []string{"._index.html", "partials/._nav.html", "static/._llms.txt", ".DS_Store", "Thumbs.db", "desktop.ini", "a/b/.ds_store"}
	no := []string{"index.html", "_platform.html", ".gitignore", "_.html", "static/app.js", "partials/nav.html", "under_score.html"}
	for _, name := range yes {
		if !pathHasMetadataSidecar(name) {
			t.Errorf("%q should be a metadata sidecar", name)
		}
	}
	for _, name := range no {
		if pathHasMetadataSidecar(name) {
			t.Errorf("%q must not be treated as a metadata sidecar", name)
		}
	}
}

func TestLoadPagesSkipsMetadataSidecars(t *testing.T) {
	dir := writeSidecarFixture(t)
	pages, partials, err := LoadPages(dir)
	if err != nil {
		t.Fatal(err)
	}
	for route := range pages {
		if strings.Contains(route, "._") {
			t.Errorf("sidecar became a page route: %s", route)
		}
	}
	if _, ok := pages["/"]; !ok {
		t.Error("index.html should still load as /")
	}
	if _, ok := pages["/docs"]; !ok {
		t.Error("docs.html should still load as /docs")
	}
	if len(pages) != 2 {
		t.Errorf("expected exactly 2 pages, got %d: %v", len(pages), pages)
	}
	if _, ok := partials["partials/nav.html"]; !ok {
		t.Error("real partial should load")
	}
	if _, ok := partials["partials/._nav.html"]; ok {
		t.Error("sidecar partial must not load")
	}
	if reloaded := reloadPartials(dir); len(reloaded) != 1 {
		t.Errorf("reloadPartials should skip sidecars, got %v", reloaded)
	}

	app := &App{Dir: dir, Pages: pages}
	sitemap := GenerateSitemap(app, "https://example.test")
	if strings.Contains(sitemap, "._") {
		t.Errorf("sitemap lists a sidecar route: %s", sitemap)
	}
	if !strings.Contains(sitemap, "https://example.test/docs<") {
		t.Errorf("sitemap lost the real /docs route: %s", sitemap)
	}
}

func TestStaticRoutingRefusesMetadataSidecars(t *testing.T) {
	dir := writeSidecarFixture(t)
	app := &App{Dir: dir}

	// Clean-URL HTML routing: the real page serves, the sidecar is a miss
	// (and must not fall through to the SPA index either).
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/guide", true},
		{"/._guide", false},
		{"/._guide.html", false},
		{"/partials/._foot", false},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, tc.path, nil)
		req.Header.Set("Accept", "text/html")
		if got := serveStaticHTML(rec, req, app); got != tc.want {
			t.Errorf("serveStaticHTML(%s) = %v, want %v", tc.path, got, tc.want)
		}
	}

	// /static/ asset handler.
	for _, tc := range []struct {
		requested string
		want      int
	}{
		{"app.js", http.StatusOK},
		{"._app.js", http.StatusNotFound},
		{"partials/._foot.html", http.StatusNotFound},
	} {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/static/"+tc.requested, nil)
		serveStaticAsset(rec, req, app, true, tc.requested)
		if rec.Code != tc.want {
			t.Errorf("serveStaticAsset(%s) = %d, want %d", tc.requested, rec.Code, tc.want)
		}
	}
}

func TestValidateOnWriteRefusesMetadataSidecars(t *testing.T) {
	for _, path := range []string{"._index.html", "partials/._nav.html", "static/._llms.txt", ".DS_Store", "static/Thumbs.db"} {
		msg := ValidateOnWrite(path, "<h1>x</h1>")
		if !strings.Contains(msg, "forbidden path") || !strings.Contains(msg, "metadata sidecar") {
			t.Errorf("ValidateOnWrite(%q) should refuse a metadata sidecar, got %q", path, msg)
		}
	}
	if msg := ValidateOnWrite("_platform-notes.html", "<h1>x</h1>"); strings.Contains(msg, "metadata sidecar") {
		t.Errorf("underscore-prefixed real file wrongly refused: %q", msg)
	}
}
