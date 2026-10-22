//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const includeTestSecret = "include-outside-secret-91c2"

// <include> reads used to pass a lexical containment check and then follow
// symlinks: partials/x.html linked to a file outside the app was rendered.
func TestIncludeDoesNotFollowSymlinkOutOfRoot(t *testing.T) {
	base := t.TempDir()
	if err := os.WriteFile(filepath.Join(base, "secret.txt"), []byte(includeTestSecret), 0o644); err != nil {
		t.Fatal(err)
	}
	appDir := filepath.Join(base, "app")
	if err := os.MkdirAll(filepath.Join(appDir, "partials"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "shared.html"), []byte("<p>shared</p>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(base, "secret.txt"), filepath.Join(appDir, "partials", "leak.html")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := os.Symlink("../../secret.txt", filepath.Join(appDir, "partials", "leak-rel.html")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../shared.html", filepath.Join(appDir, "partials", "ok.html")); err != nil {
		t.Fatal(err)
	}

	for _, src := range []string{"partials/leak.html", "partials/leak-rel.html"} {
		out := ProcessIncludes(`<include src="`+src+`" />`, nil, appDir)
		if strings.Contains(out, includeTestSecret) {
			t.Fatalf("include %s rendered a file outside the app: %q", src, out)
		}
		app := &App{Dir: appDir}
		if _, err := app.readAppInclude(src); err == nil {
			t.Fatalf("readAppInclude(%s) followed a symlink out of the app", src)
		}
	}
	if out := ProcessIncludes(`<include src="partials/ok.html" />`, nil, appDir); out != "<p>shared</p>" {
		t.Fatalf("in-app relative symlink should still resolve, got %q", out)
	}

	// The page loader's partial map (served before any disk read) skips
	// the escaping links too.
	_, partials, err := LoadPages(appDir)
	if err != nil {
		t.Fatal(err)
	}
	for name, body := range partials {
		if strings.Contains(body, includeTestSecret) {
			t.Fatalf("LoadPages loaded %s from outside the app", name)
		}
	}
	if partials["partials/ok.html"] != "<p>shared</p>" {
		t.Fatalf("in-app partial missing from LoadPages: %v", partials)
	}
}
