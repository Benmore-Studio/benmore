//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const templateRootSecret = "template-outside-secret-7be4"

// templateRootFixture lays out <base>/outside (files an app must not reach)
// next to <base>/app and returns both directories.
func templateRootFixture(t *testing.T) (outside, appDir string) {
	t.Helper()
	base := t.TempDir()
	outside, appDir = filepath.Join(base, "outside"), filepath.Join(base, "app")
	writeTestFile(t, outside, "secret.html", "<p>"+templateRootSecret+"</p>")
	if err := os.MkdirAll(appDir, 0o755); err != nil {
		t.Fatal(err)
	}
	return outside, appDir
}

// templateRootLink makes <appDir>/<name> a symlink to target, creating the
// parent directory. A relative target is relative to the link's directory.
func templateRootLink(t *testing.T, appDir, name, target string) {
	t.Helper()
	path := filepath.Join(appDir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
}

// A root page that is a symlink leading outside the app was read with
// os.ReadFile and became a routable page holding the target's bytes. It is now
// unreadable, which fails the load the way a dangling link always has.
func TestLoadPagesRefusesPageSymlinkedOutOfApp(t *testing.T) {
	for name, target := range map[string]func(outside string) string{
		"absolute": func(outside string) string { return filepath.Join(outside, "secret.html") },
		"relative": func(string) string { return "../outside/secret.html" },
	} {
		t.Run(name, func(t *testing.T) {
			outside, appDir := templateRootFixture(t)
			writeTestFile(t, appDir, "index.html", "<h1>home</h1>")
			templateRootLink(t, appDir, "leak.html", target(outside))
			pages, _, err := LoadPages(appDir)
			for route, page := range pages {
				if strings.Contains(page.RawHTML, templateRootSecret) {
					t.Errorf("page %s holds a file from outside the app", route)
				}
			}
			if err == nil || !strings.HasPrefix(err.Error(), "read leak.html: ") {
				t.Errorf("LoadPages error = %v, want a read error naming leak.html", err)
			}
		})
	}
}

// A link that stays inside the app still loads, and a dangling link fails the
// load with the same error shape as before.
func TestLoadPagesKeepsInAppSymlinkAndDanglingLinkError(t *testing.T) {
	_, appDir := templateRootFixture(t)
	writeTestFile(t, appDir, "index.html", "<h1>home</h1>")
	writeTestFile(t, appDir, "shared/about-body.html", "<h1>about-in-app</h1>")
	templateRootLink(t, appDir, "about.html", "shared/about-body.html")
	pages, _, err := LoadPages(appDir)
	if err != nil {
		t.Fatal(err)
	}
	if pages["/about"] == nil || pages["/about"].RawHTML != "<h1>about-in-app</h1>" || pages["/"] == nil {
		t.Fatalf("in-app page link or plain page missing: %v", pages)
	}

	templateRootLink(t, appDir, "gone.html", "no-such-file.html")
	if _, _, err := LoadPages(appDir); err == nil || !strings.HasPrefix(err.Error(), "read gone.html: ") {
		t.Fatalf("dangling page link: err = %v, want a read error naming gone.html", err)
	}
}

func templateRootRender(t *testing.T, app *App, page *Page) string {
	t.Helper()
	out, err := RenderTemplate(app, page, &RenderContext{Data: map[string]any{}, App: app, Page: page})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return out
}

// layouts/<name>.html, read through app.readSourceFile, followed a symlink
// out of the app; the page then rendered inside the target's bytes. A refused
// layout renders like a missing one: the page without a layout.
func TestLayoutSymlinkedOutOfAppIsNotRendered(t *testing.T) {
	outside, appDir := templateRootFixture(t)
	templateRootLink(t, appDir, "layouts/leak.html", filepath.Join(outside, "secret.html"))
	templateRootLink(t, appDir, "layouts/leak-rel.html", "../../outside/secret.html")
	writeTestFile(t, appDir, "shared/shell.html", "<main data-shell>{{content}}</main>")
	templateRootLink(t, appDir, "layouts/ok.html", "../shared/shell.html")
	app := &App{Dir: appDir}

	missing := templateRootRender(t, app, &Page{Route: "/p", Layout: "no-such-layout", RawHTML: "<p>page-body</p>"})
	for _, layout := range []string{"leak", "leak-rel"} {
		out := templateRootRender(t, app, &Page{Route: "/p", Layout: layout, RawHTML: "<p>page-body</p>"})
		if strings.Contains(out, templateRootSecret) {
			t.Errorf("layout=%s rendered a file from outside the app: %q", layout, out)
		}
		if out != missing {
			t.Errorf("layout=%s: got %q, want the missing-layout render %q", layout, out, missing)
		}
	}
	if out := templateRootRender(t, app, &Page{Route: "/p", Layout: "ok", RawHTML: "<p>page-body</p>"}); out != "<main data-shell><p>page-body</p></main>" {
		t.Errorf("in-app layout link: got %q", out)
	}
}

// The layout name comes from the page's layout= value and is placed in the
// path as written: "../../outside/secret" opened <app>/../outside/secret.html.
// A name that climbs out of the app is now not found; one that stays inside
// the app still resolves there.
func TestPageLayoutValueCannotClimbOutOfApp(t *testing.T) {
	_, appDir := templateRootFixture(t)
	writeTestFile(t, appDir, "climb.html", `<page layout="../../outside/secret"><p>page-body</p></page>`)
	writeTestFile(t, appDir, "inside.html", `<page layout="../shared/shell"><p>page-body</p></page>`)
	writeTestFile(t, appDir, "shared/shell.html", "<main data-shell>{{content}}</main>")
	pages, partials, err := LoadPages(appDir)
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: appDir, Pages: pages, Partials: partials}
	if got := pages["/climb"].Layout; got != "../../outside/secret" {
		t.Fatalf("layout= value = %q, want it kept as written", got)
	}
	if out := templateRootRender(t, app, pages["/climb"]); strings.Contains(out, templateRootSecret) || !strings.Contains(out, "page-body") {
		t.Errorf("layout=../../outside/secret: got %q, want the page without a layout", out)
	}
	if out := templateRootRender(t, app, pages["/inside"]); out != "<main data-shell><p>page-body</p></main>" {
		t.Errorf("layout=../shared/shell (inside the app): got %q", out)
	}
}

// partials/kit.html is prepended to layout="none" pages straight from disk
// (not from the loaded partial map), so a kit linked outside the app was
// rendered on every such page; so was any kit under a linked partials/.
func TestKitSymlinkedOutOfAppIsNotInjected(t *testing.T) {
	for name, link := range map[string]func(t *testing.T, outside, appDir string){
		"kit file": func(t *testing.T, outside, appDir string) {
			templateRootLink(t, appDir, "partials/kit.html", filepath.Join(outside, "secret.html"))
		},
		"partials dir": func(t *testing.T, outside, appDir string) {
			writeTestFile(t, outside, "kit.html", "<style>/* "+templateRootSecret+" */</style>")
			templateRootLink(t, appDir, "partials", outside)
		},
	} {
		t.Run(name, func(t *testing.T) {
			outside, appDir := templateRootFixture(t)
			link(t, outside, appDir)
			app := &App{Dir: appDir}
			out := templateRootRender(t, app, &Page{Route: "/p", Layout: "none", RawHTML: "<p>page-body</p>"})
			if strings.Contains(out, templateRootSecret) || out != "<p>page-body</p>" {
				t.Errorf("got %q, want the page with no kit", out)
			}
		})
	}

	_, appDir := templateRootFixture(t)
	writeTestFile(t, appDir, "shared/kit.html", "<style>.kit{}</style>")
	templateRootLink(t, appDir, "partials/kit.html", "../shared/kit.html")
	app := &App{Dir: appDir}
	if out := templateRootRender(t, app, &Page{Route: "/p", Layout: "none", RawHTML: "<p>page-body</p>"}); out != "<style>.kit{}</style>\n<p>page-body</p>" {
		t.Errorf("in-app kit link: got %q", out)
	}
}

// head.html and theme.css are written into the <head> of every server-rendered
// shell; both followed a symlink out of the app.
func TestHeadAndThemeSymlinkedOutOfAppAreNotRendered(t *testing.T) {
	outside, appDir := templateRootFixture(t)
	writeTestFile(t, outside, "theme.css", "/* theme-"+templateRootSecret+" */")
	templateRootLink(t, appDir, "head.html", filepath.Join(outside, "secret.html"))
	templateRootLink(t, appDir, "theme.css", "../outside/theme.css")
	app := &App{Dir: appDir}
	shells := map[string]string{
		"wrapLayoutAt":  WrapLayout("<p>page-body</p>", "T", app, nil),
		"wrapHTMLShell": wrapHTMLShell("<p>page-body</p>", "T", app, nil, nil, "zinc", "dark", "", "", loadThemeCSS(app)),
	}
	for name, html := range shells {
		if strings.Contains(html, templateRootSecret) {
			t.Errorf("%s rendered a head.html or theme.css from outside the app", name)
		}
		if !strings.Contains(html, "page-body") {
			t.Errorf("%s lost the page: %q", name, html)
		}
	}

	_, appDir = templateRootFixture(t)
	writeTestFile(t, appDir, "shared/head.html", `<meta name="in-app-head" content="1">`)
	templateRootLink(t, appDir, "head.html", "shared/head.html")
	if html := WrapLayout("<p>x</p>", "T", &App{Dir: appDir}, nil); !strings.Contains(html, `<meta name="in-app-head" content="1">`) {
		t.Error("in-app head.html link is no longer rendered")
	}
}

// A flow `run: email` template passed the lexical containment check and was
// then read through the link. A refused template is "not found", as a missing
// one is.
func TestFlowEmailTemplateSymlinkedOutOfAppIsNotFound(t *testing.T) {
	outside, appDir := templateRootFixture(t)
	templateRootLink(t, appDir, "emails/leak.html", filepath.Join(outside, "secret.html"))
	writeTestFile(t, appDir, "shared/welcome.html", "<p>welcome-in-app</p>")
	templateRootLink(t, appDir, "emails/welcome.html", "../shared/welcome.html")
	ctx := &FlowContext{App: &App{Dir: appDir}, Data: map[string]any{}, Params: map[string]string{}}

	_, _, missingErr := resolveEmailBody(ctx, &FlowEmail{Template: "nope"})
	html, _, err := resolveEmailBody(ctx, &FlowEmail{Template: "leak"})
	if strings.Contains(html, templateRootSecret) {
		t.Errorf("email body holds a file from outside the app: %q", html)
	}
	if err == nil || missingErr == nil || err.Error() != strings.ReplaceAll(missingErr.Error(), "nope", "leak") {
		t.Errorf("refused template error = %v, want the missing-template error %v for this name", err, missingErr)
	}
	// A link inside the app, and a name written with a leading slash, read
	// the file they always did.
	for _, name := range []string{"welcome", "/emails/welcome.html"} {
		if html, _, err := resolveEmailBody(ctx, &FlowEmail{Template: name}); err != nil || html != "<p>welcome-in-app</p>" {
			t.Errorf("template %q: %q, %v", name, html, err)
		}
	}
}

// A hook's emails/<template>.html passed filepath.IsLocal and was then read
// through the link. A refused template falls back to the literal template
// text, as a missing one does.
func TestHookEmailTemplateSymlinkedOutOfAppIsNotRead(t *testing.T) {
	outside, appDir := templateRootFixture(t)
	templateRootLink(t, appDir, "emails/leak.html", filepath.Join(outside, "secret.html"))
	writeTestFile(t, appDir, "shared/welcome.html", "<p>welcome-in-app</p>")
	templateRootLink(t, appDir, "emails/welcome.html", "../shared/welcome.html")
	row := map[string]any{}
	if got := hookEmailBody(&EmailHook{Template: "leak"}, row, appDir); got != "leak" {
		t.Errorf("hook email body = %q, want the literal template name (as for a missing file)", got)
	}
	if got := hookEmailBody(&EmailHook{Template: "welcome"}, row, appDir); got != "<p>welcome-in-app</p>" {
		t.Errorf("in-app template link: %q", got)
	}

	// An emails/ directory that is itself a link out of the app.
	outside, appDir = templateRootFixture(t)
	writeTestFile(t, outside, "leak.html", "<p>"+templateRootSecret+"</p>")
	templateRootLink(t, appDir, "emails", outside)
	if got := hookEmailBody(&EmailHook{Template: "leak"}, row, appDir); got != "leak" {
		t.Errorf("linked emails/ directory: hook email body = %q", got)
	}
}

// readSourceFile is the seam behind the layout, kit, head, theme and flow
// email reads and the static/ overrides served verbatim (sitemap.xml,
// robots.txt, llms.txt): for an app without a reviewed mcp.yaml it reads
// through the app root; a reviewed app keeps reading its captured bytes.
func TestReadSourceFileStaysInsideAppDir(t *testing.T) {
	outside, appDir := templateRootFixture(t)
	writeTestFile(t, appDir, "app.yaml", "name: fixture\n")
	writeTestFile(t, appDir, "static/llms.txt", "in-app")
	templateRootLink(t, appDir, "static/robots.txt", filepath.Join(outside, "secret.html"))
	templateRootLink(t, appDir, "static/sitemap.xml", "../../outside/secret.html")
	templateRootLink(t, appDir, "static/llms-full.txt", "llms.txt")
	app := &App{Dir: appDir}

	for _, name := range []string{"static/robots.txt", "static/sitemap.xml", "../outside/secret.html", "layouts/../../outside/secret.html"} {
		if data, err := app.readSourceFile(name); err == nil {
			t.Errorf("readSourceFile(%q) read %q from outside the app", name, data)
		}
	}
	for name, want := range map[string]string{
		"app.yaml":             "name: fixture\n",
		"static/llms.txt":      "in-app",
		"static/llms-full.txt": "in-app",
		// Named as filepath.Join(app.Dir, name) named them: a leading
		// slash, and ".." after a directory that does not exist.
		"/static/llms.txt":           "in-app",
		"layouts/../static/llms.txt": "in-app",
	} {
		if data, err := app.readSourceFile(name); err != nil || string(data) != want {
			t.Errorf("readSourceFile(%q) = %q, %v; want %q", name, data, err, want)
		}
	}
	if _, err := app.readSourceFile("static/none.txt"); !os.IsNotExist(err) {
		t.Errorf("missing file: err = %v, want not-exist", err)
	}

	// app.yaml sections parsed on demand keep the loader's own read of that
	// file, so they cannot go missing from an app.yaml the loader accepted.
	writeTestFile(t, appDir, "app.yaml", "name: fixture\nversioned: [notes]\naggregates:\n  total: {sql: \"SELECT 1\", refresh: 5m}\n")
	if v, a := app.versionedConfig(), app.aggregateConfig(); v == nil || len(v.Tables) != 1 || len(a) != 1 {
		t.Errorf("versioned/aggregates from app.yaml: %+v, %+v", v, a)
	}
	_, linkedDir := templateRootFixture(t)
	templateRootLink(t, linkedDir, "app.yaml", filepath.Join(appDir, "app.yaml"))
	linked := &App{Dir: linkedDir}
	if (linked.versionedConfig() == nil) != (LoadVersionedConfig(linkedDir) == nil) || len(linked.aggregateConfig()) != len(LoadAggregateConfig(linkedDir)) {
		t.Error("on-demand app.yaml sections disagree with the loader's read of the same file")
	}

	// Reviewed app: captured bytes only, whatever is on disk.
	reviewed := &App{Dir: appDir, MCP: &AppMCPManifest{}, sourceFiles: map[string][]byte{
		"static/robots.txt": []byte("captured-robots"),
	}}
	if data, err := reviewed.readSourceFile("static/robots.txt"); err != nil || string(data) != "captured-robots" {
		t.Errorf("reviewed app: %q, %v; want its captured bytes", data, err)
	}
	if _, err := reviewed.readSourceFile("static/llms.txt"); !os.IsNotExist(err) {
		t.Errorf("reviewed app read a file its capture does not hold: %v", err)
	}
}
