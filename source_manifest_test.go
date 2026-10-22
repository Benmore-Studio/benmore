package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSourceManifestContentHashIgnoresVolatileMetadata(t *testing.T) {
	files := []SourceManifestFile{{Path: "app.yaml", SHA256: "abc", Size: 3}}
	a := SourceManifest{Files: files, GeneratedAt: time.Now().UTC().Format(time.RFC3339Nano), ServerGitHead: "one"}
	b := SourceManifest{Files: files, GeneratedAt: time.Now().Add(time.Hour).UTC().Format(time.RFC3339Nano), ServerGitHead: "two"}
	ha, err := SourceManifestContentHash(a)
	if err != nil {
		t.Fatal(err)
	}
	hb, err := SourceManifestContentHash(b)
	if err != nil {
		t.Fatal(err)
	}
	if ha != hb {
		t.Fatalf("content hash includes volatile metadata: %q != %q", ha, hb)
	}
}

func mf(path, sha string) SourceManifestFile {
	return SourceManifestFile{Path: path, SHA256: sha, Size: int64(len(sha))}
}

func manifest(files ...SourceManifestFile) SourceManifest {
	return SourceManifest{Version: sourceManifestVersion, Files: files}
}

func statusFor(t *testing.T, report SyncReport, path string) SyncFileStatus {
	t.Helper()
	for _, f := range report.Files {
		if f.Path == path {
			return f.Status
		}
	}
	t.Fatalf("missing diff for %s in %#v", path, report.Files)
	return ""
}

func TestDiffSourceManifestsClassifiesCoreCases(t *testing.T) {
	base := manifest(mf("clean.txt", "a"), mf("local.txt", "a"), mf("remote.txt", "a"), mf("both.txt", "a"), mf("del-local.txt", "a"), mf("del-remote.txt", "a"))
	local := manifest(mf("clean.txt", "a"), mf("local.txt", "b"), mf("remote.txt", "a"), mf("both.txt", "b"), mf("del-remote.txt", "a"), mf("local-only.txt", "x"))
	remote := manifest(mf("clean.txt", "a"), mf("local.txt", "a"), mf("remote.txt", "b"), mf("both.txt", "c"), mf("del-local.txt", "a"), mf("remote-only.txt", "y"))

	report := DiffSourceManifests(base, true, local, remote)
	cases := map[string]SyncFileStatus{
		"clean.txt":       SyncStatusSynced,
		"local.txt":       SyncStatusLocalChanged,
		"remote.txt":      SyncStatusRemoteChanged,
		"both.txt":        SyncStatusConflict,
		"del-local.txt":   SyncStatusDeletedLocal,
		"del-remote.txt":  SyncStatusDeletedRemote,
		"local-only.txt":  SyncStatusLocalOnly,
		"remote-only.txt": SyncStatusRemoteOnly,
	}
	for path, want := range cases {
		if got := statusFor(t, report, path); got != want {
			t.Fatalf("%s status = %s, want %s", path, got, want)
		}
	}
	if !report.HasConflicts || !report.HasDrift {
		t.Fatalf("expected conflict + drift report: %#v", report)
	}
}

func TestDiffSourceManifestsWithoutBaseTreatsDifferentSharedFileAsConflict(t *testing.T) {
	report := DiffSourceManifests(SourceManifest{}, false, manifest(mf("app.yaml", "local")), manifest(mf("app.yaml", "remote")))
	if got := statusFor(t, report, "app.yaml"); got != SyncStatusConflict {
		t.Fatalf("status = %s, want conflict", got)
	}
}

func TestBuildSourceManifestExcludesProtectedPaths(t *testing.T) {
	dir := t.TempDir()
	write := func(rel string) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(rel), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("app.yaml")
	write("env.yaml")
	write(".env")
	write(".env.production")
	write("secrets.yaml")
	write("certs/server.key")
	write("certs/server.pem")
	write("data.db")
	write("src/bm.d.ts")
	write("uploads/blob.txt")
	write(".benmore/remote.json")
	write(".agents/skills/private/SKILL.md")
	write("static/app.tsx")

	m, err := BuildSourceManifest(dir, SourceManifestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, f := range m.Files {
		got[f.Path] = true
	}
	for _, want := range []string{"app.yaml", "static/app.tsx"} {
		if !got[want] {
			t.Fatalf("expected %s in manifest: %#v", want, got)
		}
	}
	for _, excluded := range []string{"env.yaml", ".env", ".env.production", "secrets.yaml", "certs/server.key", "certs/server.pem", "data.db", "src/bm.d.ts", "uploads/blob.txt", ".benmore/remote.json", ".agents/skills/private/SKILL.md"} {
		if got[excluded] {
			t.Fatalf("protected path %s leaked into manifest: %#v", excluded, got)
		}
	}
}

func TestPruneDeletedRemoteFilesRemovesOnlyDeletedRemote(t *testing.T) {
	dir := t.TempDir()
	write := func(rel string) {
		t.Helper()
		path := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(rel), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write("gone.txt")
	write("nested/gone.txt")
	write("keep-local-only.txt")
	write("keep-conflict.txt")

	report := SyncReport{Files: []SyncFileDiff{
		{Path: "gone.txt", Status: SyncStatusDeletedRemote},
		{Path: "nested/gone.txt", Status: SyncStatusDeletedRemote},
		{Path: "keep-local-only.txt", Status: SyncStatusLocalOnly},
		{Path: "keep-conflict.txt", Status: SyncStatusConflict},
	}}
	if err := pruneDeletedRemoteFiles(dir, report); err != nil {
		t.Fatal(err)
	}
	for _, removed := range []string{"gone.txt", "nested/gone.txt"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(removed))); !os.IsNotExist(err) {
			t.Fatalf("%s still exists after prune (err=%v)", removed, err)
		}
	}
	for _, kept := range []string{"keep-local-only.txt", "keep-conflict.txt"} {
		if _, err := os.Stat(filepath.Join(dir, filepath.FromSlash(kept))); err != nil {
			t.Fatalf("%s should remain after prune: %v", kept, err)
		}
	}
}

func TestPruneDeletedRemoteFilesRejectsEscapingPath(t *testing.T) {
	err := pruneDeletedRemoteFiles(t.TempDir(), SyncReport{Files: []SyncFileDiff{{
		Path:   "../outside.txt",
		Status: SyncStatusDeletedRemote,
	}}})
	if err == nil {
		t.Fatal("expected escaping manifest path to fail")
	}
}

// M1: a partial remote manifest (server skipped unreadable files) must not
// cause the walk to report those files, and BuildSourceManifest must flag
// Partial so the pull path can refuse to prune them as deleted_remote.
func TestBuildSourceManifestFlagsPartialOnUnreadableFile(t *testing.T) {
	if os.Getuid() == 0 {
		t.Skip("root bypasses file permissions")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "readable.tsx"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(dir, "locked.tsx")
	if err := os.WriteFile(secret, []byte("nope"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(secret, 0000); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(secret, 0644)

	m, err := BuildSourceManifest(dir, SourceManifestOptions{App: "app"})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	if !m.Partial {
		t.Fatalf("expected Partial=true when a file is unreadable, got %#v", m)
	}
	for _, f := range m.Files {
		if f.Path == "locked.tsx" {
			t.Fatalf("unreadable file must not appear in manifest: %#v", m.Files)
		}
	}
}

// Task 16: a file deleted between the walk's lstat and the hash read (a
// deploy landing mid-request on a live app dir) must degrade the manifest to
// Partial=true, matching the permission-error treatment, instead of aborting
// the whole GET /platform/app-manifest with a 500. We simulate the
// disappearance deterministically via sourceManifestBeforeHash instead of
// racing a real goroutine against the walk.
func TestBuildSourceManifestTreatsFileDisappearingMidHashAsPartial(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keep.tsx"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	vanishing := filepath.Join(dir, "vanishing.tsx")
	if err := os.WriteFile(vanishing, []byte("gone soon"), 0644); err != nil {
		t.Fatal(err)
	}

	orig := sourceManifestBeforeHash
	defer func() { sourceManifestBeforeHash = orig }()
	sourceManifestBeforeHash = func(path string) {
		if filepath.Base(path) == "vanishing.tsx" {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
	}

	m, err := BuildSourceManifest(dir, SourceManifestOptions{App: "app"})
	if err != nil {
		t.Fatalf("BuildSourceManifest returned an error instead of a partial manifest: %v", err)
	}
	if !m.Partial {
		t.Fatalf("expected Partial=true when a file disappears mid-hash, got %#v", m)
	}
	gotPaths := map[string]bool{}
	for _, f := range m.Files {
		gotPaths[f.Path] = true
	}
	if gotPaths["vanishing.tsx"] {
		t.Fatalf("disappeared file must not appear in manifest: %#v", m.Files)
	}
	if !gotPaths["keep.tsx"] {
		t.Fatalf("expected keep.tsx to still be in manifest: %#v", m.Files)
	}
}

// The router builds manifests of app directories whose tenant process can
// rewrite them meanwhile. A regular file swapped for a link after the walk
// listed it, or a directory swapped while its files were being read, used to
// be followed: another app's file was hashed (and, on the verified promote
// path, copied) as if it were this app's code.
func TestBuildSourceManifestNeverHashesThroughASwappedLink(t *testing.T) {
	dir, outside := t.TempDir(), t.TempDir()
	write := func(root, rel, body string) {
		t.Helper()
		p := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0644); err != nil {
			t.Fatal(err)
		}
	}
	write(dir, "pages/a.html", "mine a")
	write(dir, "pages/b.html", "mine b")
	write(dir, "static/app.js", "mine js")
	write(outside, "secret.txt", "other tenant")
	write(outside, "pages/a.html", "other tenant")
	write(outside, "pages/b.html", "other tenant")

	orig := sourceManifestBeforeHash
	defer func() { sourceManifestBeforeHash = orig }()
	sourceManifestBeforeHash = func(path string) {
		switch filepath.Base(path) {
		case "a.html":
			// The directory being read becomes a link to another app's.
			if err := os.Rename(filepath.Join(dir, "pages"), filepath.Join(dir, "pages.moved")); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(outside, "pages"), filepath.Join(dir, "pages")); err != nil {
				t.Fatal(err)
			}
		case "app.js":
			// The file about to be read becomes a link to another app's.
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(filepath.Join(outside, "secret.txt"), path); err != nil {
				t.Fatal(err)
			}
		}
	}
	m, err := BuildSourceManifest(dir, SourceManifestOptions{})
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	theirs := hashBytesSHA256([]byte("other tenant"))
	got := map[string]string{}
	for _, f := range m.Files {
		got[f.Path] = f.SHA256
		if f.SHA256 == theirs {
			t.Errorf("%s carries the hash of another tenant's file", f.Path)
		}
	}
	if got["pages/a.html"] != hashBytesSHA256([]byte("mine a")) || got["pages/b.html"] != hashBytesSHA256([]byte("mine b")) {
		t.Errorf("the directory held open was not the one read: %v", got)
	}
	if _, listed := got["static/app.js"]; listed || !m.Partial {
		t.Errorf("a file that became a link must be left out and the manifest marked partial: listed=%v partial=%v", listed, m.Partial)
	}
}
