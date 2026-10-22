//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const autoFixTestForm = `<form><input type="password"></form>`

func TestAutoFixOrRefuseManifestStat(t *testing.T) {
	open := func(t *testing.T) (string, *os.Root) {
		dir := t.TempDir()
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { root.Close() })
		return dir, root
	}
	t.Run("absent manifest still auto-fixes", func(t *testing.T) {
		_, root := open(t)
		fixed, applied, refusal := autoFixOrRefuse(root, "static/login.html", autoFixTestForm)
		if refusal != "" || len(applied) == 0 || !strings.Contains(fixed, `method="POST"`) {
			t.Fatalf("fixed=%q applied=%v refusal=%q", fixed, applied, refusal)
		}
	})
	t.Run("present manifest refuses", func(t *testing.T) {
		dir, root := open(t)
		if err := os.WriteFile(filepath.Join(dir, "mcp.yaml"), []byte("version: 1\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, _, refusal := autoFixOrRefuse(root, "static/login.html", autoFixTestForm)
		if !strings.Contains(refusal, "reviewed mcp.yaml") {
			t.Fatalf("refusal=%q", refusal)
		}
	})
	t.Run("unreadable manifest fails closed", func(t *testing.T) {
		dir, root := open(t)
		// A self-referencing link makes Stat fail with something other than
		// "does not exist".
		if err := os.Symlink("mcp.yaml", filepath.Join(dir, "mcp.yaml")); err != nil {
			t.Skip(err)
		}
		fixed, applied, refusal := autoFixOrRefuse(root, "static/login.html", autoFixTestForm)
		if refusal == "" || fixed != autoFixTestForm || applied != nil {
			t.Fatalf("fixed=%q applied=%v refusal=%q", fixed, applied, refusal)
		}
		if !strings.Contains(refusal, "could not check") {
			t.Fatalf("refusal=%q", refusal)
		}
	})
}
