//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestScaffoldSharedAgentContractMatchesEdition(t *testing.T) {
	dir := t.TempDir()
	if err := WriteBareScaffoldFiles(dir, "Fixture"); err != nil {
		t.Fatal(err)
	}
	shared, err := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	claude, err := os.ReadFile(filepath.Join(dir, "CLAUDE.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(claude), "@AGENTS.md") {
		t.Fatal("Claude does not import the shared contract")
	}
	hosted := editionName == "cloud" || editionName == "platform"
	for _, command := range []string{"benmore push", "benmore api", "benmore skill install --agent codex"} {
		if strings.Contains(string(shared), command) != hosted {
			t.Errorf("%s scaffold has wrong availability for %q", editionName, command)
		}
	}
	if strings.Contains(string(shared), "benmore dev") || strings.Contains(string(shared), "init-workspace") {
		t.Fatal("removed command in scaffold")
	}
}

func TestHTMLScaffoldCarriesQASelectorsAndStarterJourney(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHTMLScaffoldFiles(dir, "QA App"); err != nil {
		t.Fatal(err)
	}
	for file, ids := range map[string][]string{
		"static/index.html":  {`data-testid="note-form"`, `data-testid="note-add"`, `data-testid="signout"`, `data-testid="nav-login"`},
		"static/login.html":  {`data-testid="login-email"`, `data-testid="login-submit"`},
		"static/signup.html": {`data-testid="signup-email"`, `data-testid="signup-submit"`},
	} {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			if !strings.Contains(string(b), id) {
				t.Errorf("%s missing %s", file, id)
			}
		}
	}
	journey, err := os.ReadFile(filepath.Join(dir, "tests", "journeys", "home.yaml"))
	if err != nil {
		t.Fatalf("starter journey missing: %v", err)
	}
	for _, want := range []string{"name: home", "tags: [smoke]", "path: /", "assertions:", `{visible: "main"}`} {
		if !strings.Contains(string(journey), want) {
			t.Errorf("starter journey missing %q:\n%s", want, journey)
		}
	}
	guide, err := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(guide), "data-testid") || !strings.Contains(string(guide), `api(at:"qa")`) {
		t.Fatalf("scaffolded AGENTS.md must teach the QA selector convention:\n%s", guide)
	}
}
