//go:build !cli && !windows

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"gopkg.in/yaml.v3"
)

func renameExposureTool(t *testing.T, h *exposureHarness, from, to string) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.app.Dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseAppMCPManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	for i := range manifest.Tools {
		if manifest.Tools[i].Name == from {
			manifest.Tools[i].Name = to
		}
	}
	data, err = yaml.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, h.app.Dir, "mcp.yaml", string(data))
	reviewAppMCPFixture(t, h.app.Dir)
	if err := hotReloadApp(h.app, false); err != nil {
		t.Fatalf("valid reload refused: %v", err)
	}
}

// F09.1: a valid reload that removes a tool leaves its prepared and approved
// operations unusable: commit is refused, status never reports them live, and no
// business row changes.
func TestAppMCPReloadRemovingToolInvalidatesItsPendingOperations(t *testing.T) {
	installCanonicalHotHandler(t)
	h := newExposureHarness(t)
	prepared := h.prepareTask(1)
	approved := h.prepare()
	h.approveOK(approved)
	if h.status(prepared)["state"] != "prepared" || h.status(approved)["state"] != "approved" {
		t.Fatal("fixture operations are not pending")
	}
	renameExposureTool(t, h, "complete_item", "complete_item_v2")

	// The pre-reload connection no longer reaches the write surface at all.
	if _, err := h.client.CallTool(context.Background(), &sdk.CallToolParams{Name: appMCPCommitTool, Arguments: map[string]any{"operation_id": approved}}); err == nil {
		t.Fatal("pre-reload connection still committed after the tool was removed")
	}
	// Even a freshly authorized connection on the owner-re-enabled surface cannot touch them.
	if _, err := enableAppMCPRevisionEnrolledWrites(context.Background(), h.app, snapshotAppMCPGeneration(h.app)); err != nil {
		t.Fatalf("re-enable writes: %v", err)
	}
	fresh, err := createAppMCPNativeGrantFor(context.Background(), h.app, h.actorID, "17", "client-b2", h.resource, "complete_item_v2", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	client := appMCPClient(t, h.server, fresh.AccessToken, nil)
	for name, id := range map[string]string{"prepared": prepared, "approved": approved} {
		if out, code := h.call(client, appMCPCommitTool, map[string]any{"operation_id": id}); code == "" || out != nil {
			t.Errorf("%s operation committed after its tool was removed: %v", name, out)
		}
		if out, code := h.call(client, appMCPStatusTool, map[string]any{"operation_id": id}); code != "denied" && code != "expired_intent" && out["state"] != "expired" && out["state"] != "invalid" {
			t.Errorf("%s operation status after tool removal: code=%q out=%v", name, code, out)
		}
	}
	if h.taskDone() || h.count("SELECT count(*) FROM activities") != 0 || h.count("SELECT count(*) FROM _benmore_audit_log WHERE action='mcp_command_commit'") != 0 {
		t.Fatal("a removed tool's pending operation changed business data")
	}
	// Control: the surface is live, so only the removed tool's operations are dead
	// (this is not just the write-epoch rotation refusing everything).
	out, code := h.call(client, "complete_item_v2", map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
	if code != "" {
		t.Fatalf("renamed tool cannot prepare on the live surface: %q", code)
	}
	id, _ := out["operation_id"].(string)
	h.approveOK(id)
	if done, code := h.call(client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "" || done["outcome"] != "applied" || !h.taskDone() {
		t.Fatalf("operation under the surviving tool did not commit: %q %v", code, done)
	}
}
