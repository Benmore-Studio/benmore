//go:build !cli

package main

import (
	"path/filepath"
	"testing"
)

// /static/app.js?v=<tree> is served public and immutable for a year, and the
// bytes behind it are the running release's esbuild output. A framework
// upgrade (new esbuild, compile options, a redaction fix) with an unchanged
// static/ tree must therefore produce a new ?v=, or browsers and Cloudflare
// keep the previous release's bundle under the old URL.
func TestStaticTreeVersionChangesWithFrameworkRelease(t *testing.T) {
	app := tsxServeApp(t, "SAME-SOURCE")
	static := filepath.Join(app.Dir, "static")
	oldRelease := version
	t.Cleanup(func() { version = oldRelease })

	version = "9.9.1"
	v1, ok := staticSourceTreeVersion(static)
	if !ok {
		t.Fatal("no tree version")
	}
	version = "9.9.2"
	v2, _ := staticSourceTreeVersion(static)
	if v1 == v2 {
		t.Fatalf("tree version %s did not change across framework releases", v1)
	}
	resetTSXCache()
	if got := serveTSX(t, app, "/static/app.js?v="+v1, nil).Header().Get("Cache-Control"); got == "public, max-age=31536000, immutable" {
		t.Fatal("the previous release's ?v= was served immutable with this release's bundle")
	}
}
