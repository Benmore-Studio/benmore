//go:build !cli

package main

import (
	"gopkg.in/yaml.v3"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAppMCPDigestsBindContractAndExecution(t *testing.T) {
	dir := t.TempDir()
	manifest, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "flows/read.yaml", "SELECT 1")
	writeTestFile(t, dir, "static/shared/.env", "export const value = 1")
	contract, execution, err := appMCPDigests(dir, manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ContractDigest, manifest.ExecutionDigest = contract, execution
	writeTestFile(t, dir, "mcp.yaml", "the digests do not hash their own spelling")
	writeTestFile(t, dir, "env.yaml", "PRIVATE: fixture")
	writeTestFile(t, dir, "data.db", "runtime")
	if err := validateAppMCPDigests(dir, manifest); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dir, "static/shared/.env"))
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "static/shared/.env", "export const value = 2")
	if err := os.Chtimes(filepath.Join(dir, "static/shared/.env"), info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := validateAppMCPDigests(dir, manifest); err == nil {
		t.Fatal("same-mtime nested static dependency edit accepted")
	}
	c2, e2, err := appMCPDigests(dir, manifest)
	if err != nil || c2 != contract || e2 == execution {
		t.Fatalf("source edit fingerprints: %s %s %v", c2, e2, err)
	}
	manifest.Tools[0].Description += " changed"
	c3, e3, err := appMCPDigests(dir, manifest)
	if err != nil || c3 == c2 || e3 == e2 {
		t.Fatal("contract edit did not change both fingerprints")
	}
	if err := os.Symlink("flows/read.yaml", filepath.Join(dir, "linked.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := appMCPDigests(dir, manifest); err == nil {
		t.Fatal("unmeasured symlink source accepted")
	}
}

// Explicitly review fixture bytes after all source edits; negatives keep their original binding failure.
func reviewAppMCPFixture(t *testing.T, dir string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseAppMCPManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ContractDigest, manifest.ExecutionDigest, err = appMCPDigests(dir, manifest)
	if err != nil {
		t.Fatal(err)
	}
	data, err = yaml.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "mcp.yaml", string(data))
	return string(data)
}

// Changed execution source never runs as the reviewed connector. Startup
// loads the app from disk with the connector withheld (it used to refuse to
// start), the strict check still fails, and the write gate still refuses the
// stale manifest.
func TestAppMCPDigestsStaleSourceStartsWithoutConnector(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER);")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, dir)
	if _, err := loadRuntimeConfig(dir); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER, changed TEXT);")
	if _, err := loadRuntimeConfig(dir); err == nil {
		t.Fatal("strict load accepted changed execution source")
	}
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("stale review blocked startup: %v", err)
	}
	t.Cleanup(app.Shutdown)
	if generation := snapshotAppMCPGeneration(app); app.MCP != nil || app.mcpWithheld == "" || generation != nil && generation.manifest != nil {
		t.Fatal("connector loaded unreviewed execution source")
	}
	data, err := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if msg := ValidateOnWriteIn(dir, "mcp.yaml", string(data)); msg == "" {
		t.Fatal("write accepted stale execution digest")
	}
}

func TestAppMCPDigestsRejectInvalidUTF8Path(t *testing.T) {
	for _, invalid := range []byte{0xff, 0xfe} {
		files := []SourceManifestFile{{Path: "static/x" + string([]byte{invalid}) + ".js", SHA256: "fixture", Size: 1}}
		if _, err := appMCPExecutionFingerprint("fixture", 1, files); err == nil {
			t.Fatal("lossy JSON source path accepted")
		}
	}
}

// A reload of changed source publishes the app's new generation with the
// connector withheld (it used to keep serving the old generation): the
// connector never serves the unreviewed source, and a review restores it.
func TestAppMCPDigestsReloadWithholdsConnector(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER);")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, dir)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	if app.MCP == nil {
		t.Fatal("reviewed connector not loaded")
	}
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER);\nCREATE TABLE IF NOT EXISTS added (id INTEGER);")
	if err := reloadAppConfig(app); err != nil {
		t.Fatalf("stale review blocked reload: %v", err)
	}
	if generation := snapshotAppMCPGeneration(app); app.MCP != nil || app.mcpWithheld == "" || generation != nil && generation.manifest != nil {
		t.Fatal("connector still serves after its source changed")
	}
	reviewAppMCPFixture(t, dir)
	if err := reloadAppConfig(app); err != nil {
		t.Fatal(err)
	}
	if app.MCP == nil || app.mcpWithheld != "" {
		t.Fatal("review did not restore the connector")
	}
}

// validateAppMCPDigests runs several times per connector call; an unchanged
// source set must not be re-read each time, while any rewrite is still caught.
func TestAppMCPDigestCacheSkipsUnchangedSourceButCatchesRewrites(t *testing.T) {
	if _, ok := appMCPDigestFileStamp(mustLstat(t, t.TempDir())); !ok {
		t.Skip("no unix stat identity; the digest cache is disabled on this build")
	}
	previous := appMCPDigestRacyWindow
	const stableWindow = 20 * time.Millisecond
	appMCPDigestRacyWindow = stableWindow
	t.Cleanup(func() { appMCPDigestRacyWindow = previous })
	dir := t.TempDir()
	manifest, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "flows/read.yaml", "SELECT 1")
	writeTestFile(t, dir, "static/app.js", "export const value = 1")
	manifest.ContractDigest, manifest.ExecutionDigest, err = appMCPDigests(dir, manifest)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(60 * time.Millisecond) // past the racy window
	validate := func(wantHash bool) error {
		t.Helper()
		before := appMCPDigestWalks()
		err := validateAppMCPDigests(dir, manifest)
		if hashed := appMCPDigestWalks() != before; hashed != wantHash {
			t.Fatalf("full re-hash = %v, want %v (err %v)", hashed, wantHash, err)
		}
		return err
	}
	if err := validate(true); err != nil {
		t.Fatal(err)
	}
	if err := validate(false); err != nil {
		t.Fatalf("unchanged source: %v", err)
	}

	// Rewrite with the same size and the mtime restored: ctime still moves.
	path := filepath.Join(dir, "static/app.js")
	info := mustLstat(t, path)
	time.Sleep(30 * time.Millisecond)
	writeTestFile(t, dir, "static/app.js", "export const value = 2")
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := validate(true); err == nil {
		t.Fatal("same-size, same-mtime rewrite accepted from the cache")
	}
	if err := validate(true); err == nil {
		t.Fatal("rewritten source accepted after a failed check")
	}

	// Restore the reviewed bytes, let the cache take them, then replace the
	// file by rename (a new inode) with mtime matching the cached one.
	writeTestFile(t, dir, "static/app.js", "export const value = 1")
	time.Sleep(60 * time.Millisecond)
	if err := validate(true); err != nil {
		t.Fatal(err)
	}
	if err := validate(false); err != nil {
		t.Fatal(err)
	}
	cached := mustLstat(t, path)
	replacement := filepath.Join(dir, "static/app.js.tmp")
	if err := os.WriteFile(replacement, []byte("export const value = 3"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(replacement, cached.ModTime(), cached.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := validate(true); err == nil {
		t.Fatal("rename-replaced source accepted from the cache")
	}

	// A fresh file is never cached, and a cached result expires.
	writeTestFile(t, dir, "static/app.js", "export const value = 1")
	// Keep both checks inside the racy window even if a busy runner pauses
	// between the write and validation. The short window could already have
	// elapsed before the first check, legitimately allowing it to cache.
	appMCPDigestRacyWindow = time.Hour
	if err := validate(true); err != nil {
		t.Fatal(err)
	}
	if err := validate(true); err != nil {
		t.Fatal("source inside the racy window must be re-hashed, not cached")
	}
	appMCPDigestRacyWindow = stableWindow
	time.Sleep(60 * time.Millisecond)
	if err := validate(true); err != nil {
		t.Fatal(err)
	}
	key, _ := filepath.Abs(dir)
	appMCPDigestCache.Lock()
	entry := appMCPDigestCache.entries[key]
	entry.verified = entry.verified.Add(-appMCPDigestCacheMaxAge)
	appMCPDigestCache.entries[key] = entry
	appMCPDigestCache.Unlock()
	if err := validate(true); err != nil {
		t.Fatal(err)
	}

	// A different manifest never rides on another manifest's cached result.
	if err := validate(false); err != nil {
		t.Fatal(err)
	}
	changed := *manifest
	changed.Tools = append([]AppMCPTool(nil), manifest.Tools...)
	changed.Tools[0].Description += " changed"
	if err := validateAppMCPDigests(dir, &changed); err == nil {
		t.Fatal("changed contract accepted from the cache")
	}
}

func mustLstat(t *testing.T, path string) os.FileInfo {
	t.Helper()
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info
}
