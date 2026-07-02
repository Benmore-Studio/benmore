//go:build !cli

package main

// Tests for the bare scaffold (v2.7.201): `benmore deploy` of an
// existing directory creates its app with template "bare" so the Notes
// demo scaffold never merges with the user's files. A demo file the
// local dir doesn't shadow (views/notes.tsx, the demo index.html, …)
// used to stay live in the deployed app - a chimera that 404'd on
// /api/notes and served the wrong front page.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestWriteBareScaffoldFilesInfraOnly(t *testing.T) {
	dir := t.TempDir()
	if err := WriteBareScaffoldFiles(dir, "Email Test"); err != nil {
		t.Fatalf("WriteBareScaffoldFiles: %v", err)
	}

	for _, want := range []string{"app.yaml", "tsconfig.json", "src/bm.d.ts", "CLAUDE.md"} {
		if _, err := os.Stat(filepath.Join(dir, want)); err != nil {
			t.Errorf("bare scaffold missing infra file %s: %v", want, err)
		}
	}

	// The whole point: no demo content. schema.prisma (Note model) and
	// everything under static/ belongs to the deploying directory.
	for _, demo := range []string{
		"schema.prisma",
		"static/index.html",
		"static/login.html",
		"static/signup.html",
		"static/app.tsx",
		"static/views/notes.tsx",
		"static/styles.css",
	} {
		if _, err := os.Stat(filepath.Join(dir, demo)); err == nil {
			t.Errorf("bare scaffold wrote demo file %s - it must not", demo)
		}
	}

	appYAML, err := os.ReadFile(filepath.Join(dir, "app.yaml"))
	if err != nil {
		t.Fatalf("read app.yaml: %v", err)
	}
	if !strings.Contains(string(appYAML), `site_name: "Email Test"`) {
		t.Errorf("bare app.yaml missing site_name, got:\n%s", appYAML)
	}
	if !strings.Contains(string(appYAML), "stack: html") {
		t.Errorf("bare app.yaml missing frontend.stack, got:\n%s", appYAML)
	}
}
