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
