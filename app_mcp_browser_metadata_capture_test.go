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

func captureBrowserSources(t *testing.T, app *App, sources map[string]string) {
	t.Helper()
	app.MCP = &AppMCPManifest{sourceHashes: make(map[string]string, len(sources))}
	app.sourceFiles = make(map[string][]byte, len(sources))
	for path, source := range sources {
		data := []byte(source)
		app.sourceFiles[path] = data
		app.MCP.sourceHashes[path] = hashBytesSHA256(data)
		writeTestFile(t, app.Dir, path, source)
	}
}

func browserBundle(t *testing.T, app *App, mux *http.ServeMux) string {
	t.Helper()
	if mux == nil {
		mux = buildAppMux(app, true, "https://fixture.example.com")
	}
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/static/entry.js", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("GET /static/entry.js: %d %s", recorder.Code, recorder.Body.String())
	}
	return recorder.Body.String()
}

func TestAppMCPCapturedBrowserUsesReviewedResolverMetadata(t *testing.T) {
	app, _ := auditApp(t)
	sources := map[string]string{
		"static/entry.ts":       `import { choice } from "choice"; console.log(choice);`,
		"static/reviewed.ts":    `export const choice = "reviewed-choice";`,
		"static/alternative.ts": `export const choice = "disk-choice";`,
		"static/tsconfig.json":  `{"compilerOptions":{"paths":{"choice":["./reviewed.ts"]}}}`,
	}
	captureBrowserSources(t, app, sources)
	writeTestFile(t, app.Dir, "static/tsconfig.json", `{"compilerOptions":{"paths":{"choice":["./alternative.ts"]}}}`)

	body := browserBundle(t, app, nil)
	if !strings.Contains(body, "reviewed-choice") || strings.Contains(body, "disk-choice") {
		t.Fatalf("browser bundle did not use captured resolver metadata: %s", body)
	}
}

func TestAppMCPCapturedBrowserCompilesAfterStaticDirectoryRemoval(t *testing.T) {
	app, _ := auditApp(t)
	captureBrowserSources(t, app, map[string]string{
		"static/entry.ts": `console.log("captured-after-removal");`,
	})
	if err := os.RemoveAll(filepath.Join(app.Dir, "static")); err != nil {
		t.Fatal(err)
	}

	body := browserBundle(t, app, nil)
	if !strings.Contains(body, "captured-after-removal") {
		t.Fatalf("browser bundle omitted captured source after static removal: %s", body)
	}
}

func TestAppMCPLateTSXDoesNotReplaceCapturedTS(t *testing.T) {
	app, _ := auditApp(t)
	captureBrowserSources(t, app, map[string]string{
		"static/entry.ts": `console.log("captured-ts");`,
	})
	writeTestFile(t, app.Dir, "static/entry.tsx", `console.log("late-tsx");`)

	body := browserBundle(t, app, nil)
	if !strings.Contains(body, "captured-ts") || strings.Contains(body, "late-tsx") {
		t.Fatalf("late TSX changed captured TS browser output: %s", body)
	}
}

func TestAppMCPCapturedBrowserConditionalETagIs304NoStore(t *testing.T) {
	app, _ := auditApp(t)
	captureBrowserSources(t, app, map[string]string{
		"static/entry.ts": `console.log("etag-captured");`,
	})
	mux := buildAppMux(app, true, "https://fixture.example.com")
	browserBundle(t, app, mux)

	first := httptest.NewRecorder()
	mux.ServeHTTP(first, httptest.NewRequest(http.MethodGet, "/static/entry.js", nil))
	etag := first.Header().Get("ETag")
	if etag == "" {
		t.Fatal("browser JS response has no ETag")
	}
	conditional := httptest.NewRequest(http.MethodGet, "/static/entry.js", nil)
	conditional.Header.Set("If-None-Match", etag)
	second := httptest.NewRecorder()
	mux.ServeHTTP(second, conditional)
	if second.Code != http.StatusNotModified {
		t.Fatalf("conditional browser JS status = %d, want 304", second.Code)
	}
	// Browsers keep the module but revalidate before every use (the 304
	// above needs the stored copy); CDNs never store it.
	if cc := second.Header().Get("Cache-Control"); !strings.Contains(cc, "private") || !strings.Contains(cc, "no-cache") {
		t.Errorf("304 Cache-Control = %q, want private, no-cache", cc)
	}
	for _, header := range []string{"CDN-Cache-Control", "Cloudflare-CDN-Cache-Control"} {
		if !strings.Contains(second.Header().Get(header), "no-store") {
			t.Errorf("304 %s = %q, want no-store", header, second.Header().Get(header))
		}
	}
}
