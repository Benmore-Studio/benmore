//go:build !cli

package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// On hosted apps every HTML artifact failed: artifact.create answered
// incomplete_result (log: "store artifact: save upload: presign broker: file
// type not allowed") and artifact.export answered denied with nothing logged.
// The media broker refuses .html keys, so HTML bytes are now stored under a
// key it types as a download, and a failed export after authorization is
// reported like artifact.create reports it.
func TestHTMLArtifactExportIsStorableByTheMediaBroker(t *testing.T) {
	h := newExposureHarness(t)
	operationID := h.prepare()
	h.approveOK(operationID)
	if result, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": operationID}); code != "" || result["outcome"] != "applied" {
		t.Fatalf("command commit: code=%q result=%#v", code, result)
	}
	exported, code := h.call(h.client, mcpArtifactExportTool, map[string]any{"operation_id": operationID, "format": "html"})
	if code != "" {
		t.Fatalf("html export: %s", code)
	}
	var ref string
	if err := h.app.DB.QueryRow(`SELECT storage_ref FROM _benmore_mcp_artifacts WHERE id=?`, exported["artifact_id"]).Scan(&ref); err != nil {
		t.Fatal(err)
	}
	// The broker decides the stored type from the key alone.
	contentType, disposition, err := brokerObjectMeta(ref)
	if err != nil {
		t.Fatalf("the media broker refuses the HTML artifact key %s: %v", ref, err)
	}
	if contentType != "application/octet-stream" || !strings.HasPrefix(disposition, "attachment") {
		t.Fatalf("HTML artifact stored as %q / %q; it must never render from the media domain", contentType, disposition)
	}
	if !mcpArtifactFileName.MatchString(strings.TrimPrefix(ref, mcpArtifactStoragePrefix)) {
		t.Fatalf("the purge and orphan sweep do not recognise %s", ref)
	}
	// The authorized download still hands out the HTML report as a download.
	status, data := mcpArtifactGet(t, h.app, exported["artifact_id"].(string), h.cookie)
	if status != http.StatusOK || !strings.Contains(string(data), "<html") {
		t.Fatalf("artifact retrieval status=%d", status)
	}
}

func TestMCPArtifactExportStorageFailureIsNotDenied(t *testing.T) {
	h := newExposureHarness(t)
	operationID := h.prepare()
	h.approveOK(operationID)
	if result, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": operationID}); code != "" || result["outcome"] != "applied" {
		t.Fatalf("command commit: code=%q result=%#v", code, result)
	}
	// Storage that cannot take the bytes (a file where the directory goes).
	blocked := filepath.Join(h.app.Dir, filepath.FromSlash(mcpArtifactStoragePrefix))
	if err := os.MkdirAll(filepath.Dir(blocked), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(strings.TrimSuffix(blocked, string(filepath.Separator)), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, code := h.call(h.client, mcpArtifactExportTool, map[string]any{"operation_id": operationID, "format": "html"}); code != "incomplete_result" {
		t.Fatalf("storage failure after authorization: code=%q, want incomplete_result", code)
	}
	if _, code := h.call(h.client, mcpArtifactExportTool, map[string]any{"operation_id": strings.Repeat("0", 64), "format": "html"}); code != "denied" {
		t.Fatalf("unknown receipt: code=%q, want denied", code)
	}
}
