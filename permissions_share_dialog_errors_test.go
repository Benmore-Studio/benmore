//go:build !cli

package main

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestSDUIShareDialogNativeLoadErrors(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping component integration")
	}
	app, _, owner, reader := permissionRevokeFixture(t)
	// Auth routes are part of this fixture so revocation uses the native logout handler.
	app.Pages = map[string]*Page{"/": {Auth: "required", RawHTML: "fixture"}}
	app.Paths = DiscoverAuthPaths(app.Pages)
	mux := buildAppMux(app, false, "http://localhost")
	server := httptest.NewServer(mux)
	defer server.Close()
	cmd := exec.Command(node, "embedded/sdui_permissions_errors_test.mjs")
	cmd.Env = append(os.Environ(), "BM_TEST_URL="+server.URL, "BM_TEST_OWNER="+owner, "BM_TEST_READER="+reader)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("real ShareDialog load-error check failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "ShareDialog native load errors passed") {
		t.Fatalf("missing success: %s", output)
	}
}
