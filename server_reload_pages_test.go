//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func rootPageReloadFixture(t *testing.T, files map[string]string) (*App, *hotHandler) {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "frontend:\n  stack: html\n")
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);\n")
	for name, content := range files {
		writeTestFile(t, dir, name, content)
	}
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	if app.MCP != nil {
		t.Fatal("fixture must exercise ordinary app reloads without an MCP manifest")
	}
	handler := &hotHandler{}
	handler.swap(wrapMiddleware(buildAppMux(app, false, "https://fixture.example.com"), app, false))
	previous := hostedHotHandler
	hostedHotHandler = handler
	t.Cleanup(func() { hostedHotHandler = previous })
	return app, handler
}

func rootPageReloadGet(handler http.Handler, path, token string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "https://fixture.example.com"+path, nil)
	req.Header.Set("Accept", "text/html")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	return rec
}

func TestRootPageHotReloadAddsRoute(t *testing.T) {
	const source = "---\nengine: gotmpl\nauth: none\nlayout: none\n---\n<output data-testid=\"inbox-count\">new-root-page</output>"
	app, handler := rootPageReloadFixture(t, map[string]string{
		"static/index.html": "<html><head><title>SPA fallback</title></head><body>existing-app-shell</body></html>",
	})
	if rec := rootPageReloadGet(handler, "/inbox-status", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "existing-app-shell") {
		t.Fatalf("initial unknown route must reproduce HTML app fallback: status %d", rec.Code)
	}
	writeTestFile(t, app.Dir, "inbox-status.html", source)

	// Cold startup is a positive control for this exact authored page. It
	// discovers the route that the already-running process must gain on reload.
	controlDir := t.TempDir()
	writeTestFile(t, controlDir, "app.yaml", "frontend:\n  stack: html\n")
	writeTestFile(t, controlDir, "inbox-status.html", source)
	control, err := loadApp(controlDir)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Shutdown()
	coldMux := buildAppMux(control, false, "https://fixture.example.com")
	if rec := rootPageReloadGet(coldMux, "/inbox-status", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "new-root-page") {
		t.Fatalf("cold-start positive control did not render the authored page: status %d", rec.Code)
	}
	if err := hotReloadApp(app, false); err != nil {
		t.Fatal(err)
	}
	if rec := rootPageReloadGet(handler, "/inbox-status", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "new-root-page") || strings.Contains(rec.Body.String(), "existing-app-shell") {
		t.Fatalf("successful reload did not activate new root page: status %d", rec.Code)
	}
}

func TestRootPageHotReloadRemovesRoute(t *testing.T) {
	app, handler := rootPageReloadFixture(t, map[string]string{
		"obsolete.html": `<page auth="none" layout="none">retired-page-content`,
	})
	if rec := rootPageReloadGet(handler, "/obsolete", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "retired-page-content") {
		t.Fatalf("initial page did not render: status %d", rec.Code)
	}
	if err := os.Remove(filepath.Join(app.Dir, "obsolete.html")); err != nil {
		t.Fatal(err)
	}
	if err := hotReloadApp(app, false); err != nil {
		t.Fatal(err)
	}
	if rec := rootPageReloadGet(handler, "/obsolete", ""); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "retired-page-content") || app.Pages["/obsolete"] != nil {
		t.Fatalf("successful reload retained deleted route: status %d", rec.Code)
	}
}

func TestRootPageHotReloadUpdatesAuthGate(t *testing.T) {
	app, handler := rootPageReloadFixture(t, map[string]string{
		"report.html": "---\nengine: gotmpl\nauth: none\nlayout: none\n---\npublic-before-reload",
	})
	if rec := rootPageReloadGet(handler, "/report", ""); rec.Code != http.StatusOK {
		t.Fatalf("initial public page: %d", rec.Code)
	}
	writeTestFile(t, app.Dir, "report.html", "---\nengine: gotmpl\nauth: required\nlayout: none\n---\nprivate-after-reload")
	if err := hotReloadApp(app, false); err != nil {
		t.Fatal(err)
	}
	if rec := rootPageReloadGet(handler, "/report", ""); rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login") || strings.Contains(rec.Body.String(), "private-after-reload") {
		t.Errorf("anonymous request bypassed replacement auth gate: status %d", rec.Code)
	}
	token := createCrudScopeSession(t, app, "page-reader@example.test", "user", "", "")
	if rec := rootPageReloadGet(handler, "/report", token); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "private-after-reload") {
		t.Errorf("signed-in positive control did not render replacement: status %d", rec.Code)
	}
}

func TestRootPageFailedReloadRetainsPublishedPages(t *testing.T) {
	app, handler := rootPageReloadFixture(t, map[string]string{
		"existing.html": `<page auth="none" layout="none">last-working-page`,
	})
	oldPage, oldStop, oldGeneration := app.Pages["/existing"], app.Stop, app.reloadGeneration.Load()
	writeTestFile(t, app.Dir, "existing.html", `<page auth="required" layout="none">rejected-page`)
	writeTestFile(t, app.Dir, "added.html", `<page auth="none" layout="none">rejected-new-route`)
	writeTestFile(t, app.Dir, "workflows.yaml", "invalid: [\n")
	if err := hotReloadApp(app, false); err == nil {
		t.Fatal("malformed workflow must reject the candidate generation")
	}
	if app.Pages["/existing"] != oldPage || app.Pages["/added"] != nil || app.Stop != oldStop || app.reloadGeneration.Load() != oldGeneration {
		t.Fatal("failed reload published candidate pages, worker state or generation")
	}
	if rec := rootPageReloadGet(handler, "/existing", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "last-working-page") || strings.Contains(rec.Body.String(), "rejected-page") {
		t.Fatalf("failed reload replaced active page: status %d", rec.Code)
	}
	if rec := rootPageReloadGet(handler, "/added", ""); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "rejected-new-route") {
		t.Fatalf("failed reload registered candidate route: status %d", rec.Code)
	}
}

func TestRootPageHotReloadRefreshesPartialsAndAuthPaths(t *testing.T) {
	app, handler := rootPageReloadFixture(t, map[string]string{
		"summary.html":      "---\nengine: gotmpl\nauth: none\nlayout: none\n---\n{{template \"nav\" .}}",
		"partials/nav.html": "old-navigation-partial",
		"private.html":      `<page auth="required" layout="none">private-page`,
	})
	if rec := rootPageReloadGet(handler, "/summary", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "old-navigation-partial") {
		t.Fatalf("initial partial did not render: status %d", rec.Code)
	}
	writeTestFile(t, app.Dir, "partials/nav.html", "new-navigation-partial")
	writeTestFile(t, app.Dir, "signin.html", `<page type="login" auth="none" layout="none">custom-signin-page`)
	if err := hotReloadApp(app, false); err != nil {
		t.Fatal(err)
	}
	if rec := rootPageReloadGet(handler, "/summary", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "new-navigation-partial") || strings.Contains(rec.Body.String(), "old-navigation-partial") {
		t.Errorf("successful reload retained old partial: status %d", rec.Code)
	}
	if rec := rootPageReloadGet(handler, "/private", ""); rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/signin") || app.Paths.Login != "/signin" {
		t.Errorf("successful reload missed custom login path: status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
	if rec := rootPageReloadGet(handler, "/signin", ""); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "custom-signin-page") {
		t.Errorf("custom login route did not activate: status %d", rec.Code)
	}
	if err := os.Remove(filepath.Join(app.Dir, "signin.html")); err != nil {
		t.Fatal(err)
	}
	if err := hotReloadApp(app, false); err != nil {
		t.Fatal(err)
	}
	if rec := rootPageReloadGet(handler, "/private", ""); rec.Code != http.StatusSeeOther || !strings.HasPrefix(rec.Header().Get("Location"), "/login") || app.Paths.Login != "/login" {
		t.Errorf("removing custom login did not restore default: status %d location %q", rec.Code, rec.Header().Get("Location"))
	}
}
