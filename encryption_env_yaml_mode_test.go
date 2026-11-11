//go:build !cli && !windows

package main

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// A hosted app's router reads env.yaml through the directory's group to pin
// the key; elsewhere the file stays owner-only. The unit's UMask (0077) must
// not narrow the hosted mode.
func TestEnvYAMLModeFollowsHosting(t *testing.T) {
	old := syscall.Umask(0077)
	defer syscall.Umask(old)
	for _, hosted := range []bool{false, true} {
		value := ""
		want := os.FileMode(0600)
		if hosted {
			value, want = "1", 0640
		}
		t.Setenv("BENMORE_BIND_LOOPBACK", value)
		dir := t.TempDir()
		if err := appendToEnvYaml(dir, "ENCRYPTION_KEY", "k1"); err != nil {
			t.Fatal(err)
		}
		info, err := os.Stat(filepath.Join(dir, "env.yaml"))
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("hosted=%v append mode = %v, want %v", hosted, info.Mode().Perm(), want)
		}
		if err := os.Chmod(filepath.Join(dir, "env.yaml"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := replaceEnvYamlKey(dir, "ENCRYPTION_KEY", "k2"); err != nil {
			t.Fatal(err)
		}
		info, err = os.Stat(filepath.Join(dir, "env.yaml"))
		if err != nil || info.Mode().Perm() != want {
			t.Fatalf("hosted=%v rotation mode = %v, want %v", hosted, info.Mode().Perm(), want)
		}
	}
}

// Review finding (router tenant-data lock): the env.yaml writers chmodded and
// truncated through a link, so an env.yaml linked to data.db would have the
// database rewritten and given env.yaml's mode. Both refuse a link now.
func TestEnvYAMLWritersRefuseALink(t *testing.T) {
	t.Setenv("BENMORE_BIND_LOOPBACK", "1") // the hosted (group-readable) mode
	dir := t.TempDir()
	db := filepath.Join(dir, "data.db")
	if err := os.WriteFile(db, []byte("SQLite format 3\x00"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(db, filepath.Join(dir, "env.yaml")); err != nil {
		t.Fatal(err)
	}
	if err := appendToEnvYaml(dir, "ENCRYPTION_KEY", "k1"); err == nil {
		t.Fatal("appendToEnvYaml wrote through a link")
	}
	if err := replaceEnvYamlKey(dir, "ENCRYPTION_KEY", "k2"); err == nil {
		t.Fatal("replaceEnvYamlKey wrote through a link")
	}
	body, err := os.ReadFile(db)
	if err != nil || string(body) != "SQLite format 3\x00" {
		t.Fatalf("data.db behind env.yaml was changed: %q %v", body, err)
	}
	if info, _ := os.Stat(db); info.Mode().Perm() != 0o600 {
		t.Fatalf("data.db behind env.yaml became %v, want 600", info.Mode().Perm())
	}
}
