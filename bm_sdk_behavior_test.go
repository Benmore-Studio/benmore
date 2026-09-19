package main

import (
	"os/exec"
	"strings"
	"testing"
)

// TestEmbeddedBMSDKBehavior exercises the real runtime behavior of the
// bm.createStore + bm.query primitives (no-op suppression, persistence
// round-trip, concurrent-fetch dedupe, stale-time gating, optimistic mutate
// rollback, and invalidate/invalidateTable targeting) by running the
// embedded/bm_sdk_behavior_test.mjs harness under Node. It complements the
// symbol-presence smoke test in bm_sdk_surface_test.go. If Node is not
// available the test is skipped rather than failed, so CI without a JS runtime
// still passes.
func TestEmbeddedBMSDKBehavior(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping bm SDK behavioral tests")
	}
	cmd := exec.Command(node, "embedded/bm_sdk_behavior_test.mjs")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("bm SDK behavioral tests failed: %v\n%s", err, out)
	}
	if !strings.Contains(string(out), "all bm SDK behavioral assertions passed") {
		t.Fatalf("bm SDK behavioral tests did not report success:\n%s", out)
	}
}
