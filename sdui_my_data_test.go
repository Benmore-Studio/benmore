//go:build !cli

package main

import (
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// DownloadMyData read every readable table one capped page at a time and
// wrote [] for a table that failed, so a user's "my data" file was cut short
// or missing tables without a word, and an admin's held every user's rows.
// It now downloads the server-side export (GET /api/_my-data): the caller's
// own rows, complete, or an error that says nothing was downloaded.
func TestSDUIDownloadMyDataIsTheUsersCompleteExport(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping component integration")
	}
	app, sid := sduiExportApp(t)
	server := httptest.NewServer(buildAppMux(app, false, "http://localhost"))
	defer server.Close()
	// Exports switched off is a second app, configured before its server
	// starts: changing a served app's features under its request handlers
	// is a data race (the handlers read them with no lock).
	offApp, offSID := sduiExportApp(t)
	offApp.Design = &DesignConfig{Features: parseFeaturesConfig(map[string]any{"exports": false})}
	offServer := httptest.NewServer(buildAppMux(offApp, false, "http://localhost"))
	defer offServer.Close()
	run := func(url, mode, token string) {
		t.Helper()
		cmd := exec.Command(node, "embedded/sdui_my_data_test.mjs")
		cmd.Env = append(os.Environ(), "BM_TEST_URL="+url, "BM_TEST_TOKEN="+token, "BM_TEST_MODE="+mode)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("DownloadMyData %s check failed: %v\n%s", mode, err, output)
		}
		if !strings.Contains(string(output), "DownloadMyData "+mode+" passed") {
			t.Fatalf("missing success for %s: %s", mode, output)
		}
	}
	run(server.URL, "complete", sid)
	run(server.URL, "signed_out", "")
	run(offServer.URL, "disabled", offSID)
}
