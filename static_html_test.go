//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

// versionStaticAssets is the auto-versioning transform that closes the
// "I just edited the file but Cloudflare caches it immutable for a
// year" footgun. The behavior contract:
//
//   1. /static/*.css and /static/*.js refs in HTML get ?v=<mtime>
//      appended, mtime read from the actual file on disk
//   2. URLs that already have a query string are NOT rewritten
//      (idempotent against re-rendering; respects explicit versions)
//   3. URLs whose files don't exist on disk are NOT rewritten
//      (a real 404 should still surface, not a fake versioned URL)
//   4. /_internal/* and other prefixes are NOT rewritten (framework
//      libraries are versioned by the binary, not per-app)
//
// Each test corresponds to one bullet above so a regression in any
// single property fails a specific test rather than the whole suite.

func TestVersionStaticAssetsRewritesCSSAndJS(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	staticDir := filepath.Join(app.Dir, "static")
	if err := os.MkdirAll(staticDir, 0755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"styles.css", "app.js"} {
		path := filepath.Join(staticDir, name)
		if err := os.WriteFile(path, []byte("/* test */"), 0644); err != nil {
			t.Fatal(err)
		}
		// Pin mtime so the assertion is deterministic.
		fixed := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
		if err := os.Chtimes(path, fixed, fixed); err != nil {
			t.Fatal(err)
		}
	}

	html := []byte(`<link rel="stylesheet" href="/static/styles.css"><script src="/static/app.js"></script>`)
	out := string(versionStaticAssets(html, app))

	if !strings.Contains(out, `href="/static/styles.css?v=1779408000"`) {
		t.Errorf("CSS not versioned with mtime: %s", out)
	}
	if !strings.Contains(out, `src="/static/app.js?v=1779408000"`) {
		t.Errorf("JS not versioned with mtime: %s", out)
	}
}

func TestVersionStaticAssetsReversionsFrameworkOwnedURLs(t *testing.T) {
	// The framework owns `?v=<digits>` and replaces stale values with
	// the current mtime. Non-`v` query strings are author intent and
	// stay untouched. Pre-2.7.31 we preserved stale `?v=42`, which
	// created permanent dead zones the agent then worked around by
	// manually bumping v=2→3→5→6→7 across HTML files.
	app := &App{Dir: t.TempDir()}
	staticDir := filepath.Join(app.Dir, "static")
	os.MkdirAll(staticDir, 0755)
	path := filepath.Join(staticDir, "styles.css")
	os.WriteFile(path, []byte(""), 0644)
	fixed := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	os.Chtimes(path, fixed, fixed)

	html := []byte(`<link href="/static/styles.css?v=42"><link href="/static/styles.css?hash=abc">`)
	out := string(versionStaticAssets(html, app))

	// Framework-owned ?v=42 gets re-versioned with the fresh mtime.
	if !strings.Contains(out, `href="/static/styles.css?v=1779408000"`) {
		t.Errorf("stale ?v=42 should be re-versioned to fresh mtime: %s", out)
	}
	if strings.Contains(out, `?v=42`) {
		t.Errorf("stale ?v=42 leaked through: %s", out)
	}
	// Author-owned query strings stay untouched.
	if !strings.Contains(out, `href="/static/styles.css?hash=abc"`) {
		t.Errorf("explicit ?hash=abc should be preserved: %s", out)
	}
	// And we never produce a double query string.
	if strings.Contains(out, "?v=") && strings.Contains(out, "?v=") &&
		strings.Count(out, "?v=") > strings.Count(out, "href=") {
		t.Errorf("double-versioning bug: %s", out)
	}
}

func TestVersionStaticAssetsSkipsMissingFiles(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	// No file written - /static/ghost.css does NOT exist on disk.

	html := []byte(`<link href="/static/ghost.css">`)
	out := string(versionStaticAssets(html, app))

	if out != string(html) {
		t.Errorf("missing file should be left untouched, got: %s", out)
	}
}

func TestVersionStaticAssetsLeavesInternalAndOtherPrefixesAlone(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	html := []byte(`<script src="/_internal/htmx.js"></script><img src="/uploads/foo.png"><link href="https://cdn.example.com/style.css">`)
	out := string(versionStaticAssets(html, app))

	if out != string(html) {
		t.Errorf("non-/static/ URLs should be untouched, got: %s", out)
	}
}

func TestVersionStaticAssetsHandlesSingleQuotes(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	staticDir := filepath.Join(app.Dir, "static")
	os.MkdirAll(staticDir, 0755)
	path := filepath.Join(staticDir, "main.css")
	os.WriteFile(path, []byte(""), 0644)
	fixed := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	os.Chtimes(path, fixed, fixed)

	html := []byte(`<link href='/static/main.css'>`)
	out := string(versionStaticAssets(html, app))

	if !strings.Contains(out, `href='/static/main.css?v=1767225600'`) {
		t.Errorf("single-quoted attr not handled: %s", out)
	}
}

func TestVersionStaticAssetsJITWalksAllSiblingSources(t *testing.T) {
	// JIT compilation case: /static/app.js is compiled from app.tsx,
	// which imports huddle.tsx + room.tsx. Editing any imported module
	// changes the compiled bundle, so the URL version should track the
	// MAX mtime across all sources - not just the entry file. Pre-
	// 2.7.31 we only looked at the matching-stem source (.tsx for .js),
	// so an earlier app build's `golive.tsx` edit and an earlier app build's
	// `huddle.tsx` edit both failed to bump `?v=` even though the
	// compiled bundle changed.
	app := &App{Dir: t.TempDir()}
	staticDir := filepath.Join(app.Dir, "static")
	os.MkdirAll(staticDir, 0755)

	// Entry .tsx is older than a sibling import.
	entryPath := filepath.Join(staticDir, "app.tsx")
	os.WriteFile(entryPath, []byte("import './huddle';"), 0644)
	entryTime := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	os.Chtimes(entryPath, entryTime, entryTime)

	huddlePath := filepath.Join(staticDir, "huddle.tsx")
	os.WriteFile(huddlePath, []byte("export {}"), 0644)
	huddleTime := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	os.Chtimes(huddlePath, huddleTime, huddleTime)

	html := []byte(`<script src="/static/app.js"></script>`)
	out := string(versionStaticAssets(html, app))

	wantVer := strconv.FormatInt(huddleTime.Unix(), 10)
	if !strings.Contains(out, `src="/static/app.js?v=`+wantVer+`"`) {
		t.Errorf("JIT bundle should use max sibling mtime; got %s, want ?v=%s", out, wantVer)
	}
}

func TestVersionStaticAssetsJITUsesNewerSiblingOverStaleJS(t *testing.T) {
	// A real bug this guards against: the framework's embedded esbuild writes the
	// compiled bundle back to disk as app.js for fast-path serves.
	// After a push that edits notes.tsx (a non-entry sibling), the
	// .js mtime is still the LAST COMPILATION TIME - older than the
	// .tsx that was just written. Pre-fix we returned the .js mtime
	// because os.Stat succeeded; CF kept serving the cached bundle.
	app := &App{Dir: t.TempDir()}
	staticDir := filepath.Join(app.Dir, "static")
	os.MkdirAll(staticDir, 0755)

	// Compiled bundle from a past JIT run - older mtime.
	jsPath := filepath.Join(staticDir, "app.js")
	os.WriteFile(jsPath, []byte("/* compiled */"), 0644)
	stale := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	os.Chtimes(jsPath, stale, stale)

	// Entry .tsx (also stale).
	entryPath := filepath.Join(staticDir, "app.tsx")
	os.WriteFile(entryPath, []byte("import './notes';"), 0644)
	os.Chtimes(entryPath, stale, stale)

	// Non-entry sibling - freshly edited.
	notesPath := filepath.Join(staticDir, "notes.tsx")
	os.WriteFile(notesPath, []byte("export {}"), 0644)
	fresh := time.Date(2026, 5, 22, 0, 0, 0, 0, time.UTC)
	os.Chtimes(notesPath, fresh, fresh)

	html := []byte(`<script src="/static/app.js"></script>`)
	out := string(versionStaticAssets(html, app))

	wantVer := strconv.FormatInt(fresh.Unix(), 10)
	if !strings.Contains(out, `src="/static/app.js?v=`+wantVer+`"`) {
		t.Errorf("JIT bundle should prefer freshest source mtime over stale on-disk .js; got %s, want ?v=%s", out, wantVer)
	}
}

func TestVersionStaticAssetsIsIdempotentOnTwoPasses(t *testing.T) {
	app := &App{Dir: t.TempDir()}
	staticDir := filepath.Join(app.Dir, "static")
	os.MkdirAll(staticDir, 0755)
	os.WriteFile(filepath.Join(staticDir, "x.css"), []byte(""), 0644)

	html := []byte(`<link href="/static/x.css">`)
	once := versionStaticAssets(html, app)
	twice := versionStaticAssets(once, app)

	if string(once) != string(twice) {
		t.Errorf("second pass changed output:\n  once : %s\n  twice: %s", once, twice)
	}
}
