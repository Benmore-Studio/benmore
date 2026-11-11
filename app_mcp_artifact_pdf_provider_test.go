//go:build !cli

package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// fakeArtifactBrowser answers the version probe and runs render as given, so
// these tests never start a real Chrome.
func fakeArtifactBrowser(t *testing.T, render string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake browser requires a POSIX shell")
	}
	path := filepath.Join(t.TempDir(), "fake-chrome")
	script := "#!/bin/sh\nif [ \"$1\" = \"--version\" ]; then echo 'Fake Chrome 1.0'; exit 0; fi\n" + render + "\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	previous := artifactPDFBrowser
	artifactPDFBrowser = func() string { return path }
	t.Cleanup(func() { artifactPDFBrowser = previous })
}

// A render that runs past its deadline is a provider failure, though the
// error it returns is the context's and says nothing about PDF.
func TestAppMCPArtifactPDFTimeoutIsUnavailableProvider(t *testing.T) {
	fakeArtifactBrowser(t, "exec /bin/sleep 30")
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	_, err := renderAppMCPArtifactPDF(ctx, nil, []byte("<!doctype html><title>report</title>"))
	if !errors.Is(err, context.DeadlineExceeded) || appMCPArtifactFailureCode(err) != "unavailable_provider" {
		t.Fatalf("render timeout: err=%v code=%q, want a deadline classified unavailable_provider", err, appMCPArtifactFailureCode(err))
	}
	if code := appMCPArtifactFailureCode(errors.New("artifact exceeds 1 bytes")); code != "incomplete_result" {
		t.Fatalf("non-provider failure classified %q", code)
	}
}

func TestAppMCPReadArtifactPDFRendererFailureIsUnavailableProvider(t *testing.T) {
	fakeArtifactBrowser(t, "exit 3")
	e := newReadArtifactEnv(t, readArtifactYAML())
	if _, code := e.create(map[string]any{"tool": "forecast", "format": "pdf"}); code != "unavailable_provider" {
		t.Fatalf("crashed renderer: code=%q, want unavailable_provider", code)
	}
}

// The export tool reports denied for every refusal of the receipt; a renderer
// failure after the receipt is proven the caller's is not one of them.
func TestAppMCPArtifactExportPDFRendererFailureIsUnavailableProvider(t *testing.T) {
	fakeArtifactBrowser(t, "exit 3")
	h := newExposureHarness(t)
	operationID := h.prepare()
	h.approveOK(operationID)
	if result, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": operationID}); code != "" || result["outcome"] != "applied" {
		t.Fatalf("command commit: code=%q result=%#v", code, result)
	}
	if _, code := h.call(h.client, mcpArtifactExportTool, map[string]any{"operation_id": operationID, "format": "pdf"}); code != "unavailable_provider" {
		t.Fatalf("crashed renderer: code=%q, want unavailable_provider", code)
	}
	if _, code := h.call(h.client, mcpArtifactExportTool, map[string]any{"operation_id": "0000000000000000000000000000000000000000000000000000000000000000", "format": "pdf"}); code != "denied" {
		t.Fatalf("unknown receipt: code=%q, want denied", code)
	}
}
