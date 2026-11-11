//go:build !cli

package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Messages that sent a builder the wrong way: each names the mistake.

func TestDocsSuggestsTheNearestTopicAndKey(t *testing.T) {
	code, _, _, stderr := docsForTest(t, "enviroments")
	if code != 1 || !strings.Contains(stderr, `Unknown topic: "enviroments"`) || !strings.Contains(stderr, "Did you mean: benmore docs environments\n") {
		t.Errorf("a misspelt topic: exit %d, stderr %q", code, stderr)
	}
	if code, _, _, stderr = docsForTest(t, "zzqqxx"); code != 1 || strings.Contains(stderr, "Did you mean") {
		t.Errorf("a name near nothing: exit %d, stderr %q", code, stderr)
	}
	// An addressed read of a misspelt topic, and a key near none of the
	// usual ways: both name the closest, and `nearest` is never null.
	if _, _, stdout, _ := docsForTest(t, "enviroments.env_vars"); !strings.Contains(stdout, "\"nearest\": [\n    \"environments\"") {
		t.Errorf("unknown topic by address: %s", stdout[:min(len(stdout), 300)])
	}
	if got := apiNearestKeys("envvarsz1", []string{"commands", "env_vars", "promote"}); len(got) != 1 || got[0] != "env_vars" {
		t.Errorf("closest by edits = %v, want [env_vars]", got)
	}
	if got := apiNearestKeys("zzz", []string{"commands", "env_vars"}); got == nil || len(got) != 0 {
		t.Errorf("nothing near = %#v, want an empty list", got)
	}
	if !strings.Contains(docsUsageLines, "changes, deploy)") {
		t.Errorf("the usage line leaves out a guide: %s", docsUsageLines)
	}
	if _, _, _, stderr = docsForTest(t, "index"); strings.Count(stderr, "read a topic with") != 1 {
		t.Errorf("docs index hint printed %d times: %q", strings.Count(stderr, "read a topic with"), stderr)
	}
}

func TestImportRefusalGivesEachColumnItsReason(t *testing.T) {
	app, _, _ := newWorkflowImportApp(t)
	err := validateImportColumns(app.DB, "docs", app, []string{"title", "status", "user_id", "id", "titel", "Title"})
	if err == nil {
		t.Fatal("the columns were accepted")
	}
	for _, want := range []string{
		"status (a workflow's state column: every imported row starts in the workflow's initial state, see import.workflow_state)",
		"user_id (the owner column: the import fills it, see import.owner)",
		"id (the primary key: the database assigns it)",
		"titel (no such column in docs)",
		"Title (the table spells it title)",
	} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal lacks %q:\n%s", want, err)
		}
	}
	if strings.Contains(err.Error(), "title (") || strings.Contains(err.Error(), "mass assignment") {
		t.Errorf("an importable column is named, or the one reason for all is back:\n%s", err)
	}
}

func TestNewScaffoldsIntoAnEmptyDirectory(t *testing.T) {
	root := t.TempDir()
	empty := filepath.Join(root, "fresh-app")
	if err := os.MkdirAll(filepath.Join(empty, ".git"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(empty)
	dir, err := scaffoldTargetDir(".")
	if err != nil || filepath.Base(dir) != "fresh-app" {
		t.Fatalf("an empty directory (with .git) = %q, %v; want its absolute path", dir, err)
	}
	if err := writeHTMLScaffoldFiles(dir, "", true); err != nil {
		t.Fatal(err)
	}
	if data, _ := os.ReadFile(filepath.Join(empty, "app.yaml")); !strings.Contains(string(data), `site_name: "Fresh-App"`) {
		t.Errorf("the app is not named after the directory: %s", data)
	}
	if _, err := scaffoldTargetDir("."); err == nil || !strings.Contains(err.Error(), "already exists and is not an empty directory") {
		t.Errorf("a directory holding an app = %v, want a refusal", err)
	}
	if dir, err := scaffoldTargetDir(filepath.Join(root, "not-there")); err != nil || dir != filepath.Join(root, "not-there") {
		t.Errorf("a new directory = %q, %v", dir, err)
	}
}

func TestTestCommandHoldsTheLoadLog(t *testing.T) {
	var out bytes.Buffer
	before := log.Writer()
	log.SetOutput(&out)
	defer log.SetOutput(before)

	release := holdLoadLog()
	for range 3 {
		log.Print("app load: phase=config status=started")
		log.Print("WARNING: flows/pay.yaml: role gate admits nobody")
	}
	release(false)
	if got := out.String(); strings.Count(got, "WARNING: flows/pay.yaml") != 1 || strings.Contains(got, "app load:") {
		t.Errorf("a load that worked printed:\n%s", got)
	}
	log.Print("after the load")
	if !strings.Contains(out.String(), "after the load") {
		t.Error("the log stayed held after the load")
	}

	out.Reset()
	release = holdLoadLog()
	log.Print("app load: phase=config status=failed")
	release(true)
	if !strings.Contains(out.String(), "phase=config status=failed") {
		t.Errorf("a failed load printed nothing of its log: %q", out.String())
	}
}
