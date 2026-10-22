package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestEmbeddedBMAuthCacheBoundary(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping SDK auth cache behavior")
	}
	out, err := exec.Command(node, "embedded/bm_auth_cache_test.mjs").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "all bm auth cache assertions passed") {
		t.Fatalf("SDK auth cache behavior failed: %v\n%s", err, out)
	}
}
