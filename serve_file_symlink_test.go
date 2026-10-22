package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// serve_file must not follow a link under uploads/ to bytes outside it.
func TestServeFileRefusesSymlinkOutOfUploads(t *testing.T) {
	root := t.TempDir()
	app := &App{Dir: filepath.Join(root, "app")}
	if err := os.MkdirAll(filepath.Join(app.Dir, "uploads"), 0o755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(root, "other-tenant-env.yaml")
	if err := os.WriteFile(secret, []byte("SECRET=1"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(secret, filepath.Join(app.Dir, "uploads", "leak.txt")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := os.WriteFile(filepath.Join(app.Dir, "uploads", "ok.txt"), []byte("fine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rec := serveFileForTest(t, app, "uploads/leak.txt"); rec.Code != http.StatusNotFound || strings.Contains(rec.Body.String(), "SECRET") {
		t.Fatalf("symlinked upload served: %d %q", rec.Code, rec.Body.String())
	}
	if rec := serveFileForTest(t, app, "uploads/ok.txt"); rec.Code != http.StatusOK || rec.Body.String() != "fine" {
		t.Fatalf("regular upload broke: %d %q", rec.Code, rec.Body.String())
	}
}

// A deployment that mounts uploads/ from another volume (uploads is itself a
// symlink) must keep serving its files.
func TestServeFileAllowsSymlinkedUploadsRoot(t *testing.T) {
	root := t.TempDir()
	app := &App{Dir: filepath.Join(root, "app")}
	real := filepath.Join(root, "volume", "uploads")
	if err := os.MkdirAll(real, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(app.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(real, filepath.Join(app.Dir, "uploads")); err != nil {
		t.Skip("symlinks unavailable")
	}
	if err := os.WriteFile(filepath.Join(real, "ok.txt"), []byte("fine"), 0o644); err != nil {
		t.Fatal(err)
	}
	if rec := serveFileForTest(t, app, "uploads/ok.txt"); rec.Code != http.StatusOK || rec.Body.String() != "fine" {
		t.Fatalf("file under a symlinked uploads root broke: %d %q", rec.Code, rec.Body.String())
	}
}
