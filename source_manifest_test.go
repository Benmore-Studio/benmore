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
	for _, excluded := range []string{"env.yaml", ".env", ".env.production", "secrets.yaml", "certs/server.key", "certs/server.pem", "data.db", "src/bm.d.ts", "uploads/blob.txt", ".benmore/remote.json"} {
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

// Task 16: a file deleted between filepath.Walk's stat and hashFileSHA256's
// read (a deploy landing mid-request on a live app dir) must degrade the
// manifest to Partial=true, matching the permission-error treatment, instead
// of aborting the whole GET /platform/app-manifest with a 500. We simulate
// the disappearance deterministically via hashFileSHA256Fn instead of racing
// a real goroutine against filepath.Walk.
func TestBuildSourceManifestTreatsFileDisappearingMidHashAsPartial(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "keep.tsx"), []byte("ok"), 0644); err != nil {
		t.Fatal(err)
	}
	vanishing := filepath.Join(dir, "vanishing.tsx")
	if err := os.WriteFile(vanishing, []byte("gone soon"), 0644); err != nil {
		t.Fatal(err)
	}

	orig := hashFileSHA256Fn
	defer func() { hashFileSHA256Fn = orig }()
	hashFileSHA256Fn = func(path string) (string, error) {
		if filepath.Base(path) == "vanishing.tsx" {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		}
		return orig(path)
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
