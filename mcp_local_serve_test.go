package main

import (
	"os"
	"path/filepath"
	"testing"
)

// --mcp-local accepts only the loopback http resource and
// gives the app a stable owner-only authority outside the app directory.
func TestMCPLocalServeResourceAndAuthority(t *testing.T) {
	app := &App{}
	if validAppMCPResource(app, "http://localhost:8080/api/_mcp") {
		t.Fatal("plain serve accepted an http resource")
	}
	app.MCPLocal = true
	if !validAppMCPResource(app, "http://localhost:8080/api/_mcp") || !validAppMCPResource(app, "http://127.0.0.1:8080/api/_mcp") {
		t.Fatal("--mcp-local refused the loopback resource")
	}
	if validAppMCPResource(app, "http://example.com/api/_mcp") || validAppMCPResource(app, "http://localhost:8080/api/_mcp/x") {
		t.Fatal("--mcp-local accepted a non-loopback or non-canonical resource")
	}

	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")
	os.Unsetenv("BENMORE_MCP_AUTHORITY_DIR")
	t.Setenv("XDG_CACHE_HOME", t.TempDir())
	t.Setenv("HOME", t.TempDir())
	appDir := t.TempDir()
	first, err := prepareMCPLocalAuthority(appDir)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(first)
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0o700 || pathWithinDir(realPathForContainment(appDir), first) {
		t.Fatalf("authority %s: %v %v", first, info, err)
	}
	os.Unsetenv("BENMORE_MCP_AUTHORITY_DIR")
	again, _ := prepareMCPLocalAuthority(appDir)
	if again != first {
		t.Fatalf("authority not stable across restarts: %s vs %s", first, again)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", filepath.Join(t.TempDir(), "chosen"))
	if got, _ := prepareMCPLocalAuthority(appDir); got != os.Getenv("BENMORE_MCP_AUTHORITY_DIR") {
		t.Fatalf("an operator-chosen authority was replaced: %s", got)
	}
}
