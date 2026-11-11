//go:build !cli && !windows

package main

import (
	"os"
	"path/filepath"
	"testing"

	"go.yaml.in/yaml/v3"
)

// changeExposureToolDescription re-reviews the connector with an edited tool
// description (a new contract digest) and hot-reloads it, as an owner pushing
// a changed mcp.yaml does.
func changeExposureToolDescription(t *testing.T, h *exposureHarness) {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(h.app.Dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseAppMCPManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	before := manifest.ContractDigest
	manifest.Tools[0].Description += " Edited after review."
	if data, err = yaml.Marshal(manifest); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, h.app.Dir, "mcp.yaml", string(data))
	reviewAppMCPFixture(t, h.app.Dir)
	if err := hotReloadApp(h.app, false); err != nil {
		t.Fatalf("valid reload refused: %v", err)
	}
	if after := snapshotAppMCPGeneration(h.app).manifest.ContractDigest; after == before {
		t.Fatal("fixture edit did not change the contract digest")
	}
}

// An operation prepared before the connector's epochs rotated can never
// commit, and _commit says so with the answer _status gives: expired_intent.
// That holds for a plain off/on, and also when the owner changed the reviewed
// source before switching it back on (the usual reason to switch it off and
// on), where _commit used to answer a bare denied from the source check.
func TestAppMCPCommitAfterEpochRotationIsExpiredIntent(t *testing.T) {
	installCanonicalHotHandler(t)
	for _, tc := range []struct {
		name         string
		writesOnly   bool
		sourceChange bool
	}{
		{"writes off and on", true, false},
		{"full disable and enable", false, false},
		{"source changed, writes off and on", true, true},
		{"source changed, full disable and enable", false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newExposureHarness(t)
			id := h.prepare()
			h.approveOK(id)
			if err := connectorApply(t, h.app, "disable", tc.writesOnly); err != nil {
				t.Fatal(err)
			}
			if tc.sourceChange {
				changeExposureToolDescription(t, h)
			}
			if err := connectorApply(t, h.app, "enable", true); err != nil {
				t.Fatal(err)
			}
			h.client = appMCPClient(t, h.server, h.pair.AccessToken, nil)
			if state := h.status(id); state["state"] != "expired" || state["business"] != "not_committed" {
				t.Fatalf("status after rotation: %#v", state)
			}
			if _, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "expired_intent" {
				t.Fatalf("_commit after rotation = %q, want expired_intent", code)
			}
			if h.taskDone() || h.count("SELECT count(*) FROM activities") != 0 {
				t.Fatal("business row changed")
			}
		})
	}
}

// The expiry answer is given only to the caller the operation is bound to:
// another connection of the same person, or another person, still gets the
// opaque denied, so nothing about an operation they do not own leaks.
func TestAppMCPCommitExpiredOperationStaysOpaqueToOtherCallers(t *testing.T) {
	installCanonicalHotHandler(t)
	h := newExposureHarness(t)
	id := h.prepare()
	if err := connectorApply(t, h.app, "disable", false); err != nil {
		t.Fatal(err)
	}
	changeExposureToolDescription(t, h)
	if err := connectorApply(t, h.app, "enable", true); err != nil {
		t.Fatal(err)
	}
	other, err := createAppMCPNativeGrantFor(t.Context(), h.app, h.actorID, "17", "client-other", h.resource, "complete_item", appMCPClock())
	if err != nil {
		t.Fatal(err)
	}
	client := appMCPClient(t, h.server, other.AccessToken, nil)
	if _, code := h.call(client, appMCPCommitTool, map[string]any{"operation_id": id}); code != "denied" {
		t.Fatalf("another connection's _commit = %q, want denied", code)
	}
	if _, code := h.call(client, appMCPStatusTool, map[string]any{"operation_id": id}); code != "denied" {
		t.Fatalf("another connection's _status = %q, want denied", code)
	}
}
