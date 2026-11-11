//go:build !cli && !windows

package main

import (
	"bytes"
	"io"
	"log"
	"os"
	"strings"
	"testing"
)

// Round 2026-11-04 (lifecycle finding 5j): `benmore mcp review --reviewed`
// printed the app's runtime registration log ("feedback: API registered",
// twice) on stderr. The review, check and inspect commands build the app's
// routes from source only; nothing they register serves, so they log nothing.
func TestAppMCPCLISourceCommandsLogNothing(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);")
	writeTestFile(t, dir, "app.yaml", "name: quiet\nfeatures:\n  feedback: true\n")
	var authored []string
	for _, line := range strings.Split(appMCPManifestFixture(), "\n") {
		if !strings.HasPrefix(line, "contract_digest:") && !strings.HasPrefix(line, "execution_digest:") {
			authored = append(authored, line)
		}
	}
	writeTestFile(t, dir, "mcp.yaml", strings.Join(authored, "\n"))

	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	for _, args := range [][]string{
		{"review", dir, "--reviewed"},
		{"check", dir},
		{"inspect", dir, "--json"},
	} {
		if err := runAppMCPCLI(args, io.Discard); err != nil {
			log.SetOutput(os.Stderr)
			t.Fatalf("mcp %s: %v", args[0], err)
		}
	}
	log.SetOutput(os.Stderr)
	if logged.Len() != 0 {
		t.Fatalf("mcp review/check/inspect logged app-load lines:\n%s", logged.String())
	}
}
