//go:build !cli

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// TestRecorderMasksSecretSurfaces runs the generated recorder script against
// a fake DOM (embedded/recorder_mask_test.mjs). Recordings are read by app
// admins, so a token, TOTP secret, password value or reset link on another
// user's page must not reach them through a DOM snapshot, a value-attribute
// mutation, an input or click event or a recorded URL, while an ordinary
// page records exactly as before. Skipped without Node.
func TestRecorderMasksSecretSurfaces(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping recorder masking test")
	}
	script := RecorderScript(&App{DevMode: true}, true)
	script = strings.TrimSpace(script)
	script = strings.TrimPrefix(script, "<script>")
	script = strings.TrimSuffix(script, "</script>")
	if !strings.Contains(script, "sendBeacon") {
		t.Fatalf("recorder script not generated: %q", script)
	}
	path := filepath.Join(t.TempDir(), "recorder.js")
	if err := os.WriteFile(path, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(node, "embedded/recorder_mask_test.mjs", path).CombinedOutput()
	if err != nil {
		t.Fatalf("recorder masking failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "all recorder masking assertions passed") {
		t.Fatalf("recorder masking test did not report success:\n%s", out)
	}
}
