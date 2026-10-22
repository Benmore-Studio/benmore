package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestEmbeddedBMLiveScoped(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping SDK callback ordering")
	}
	out, err := exec.Command(node, "embedded/bm_live_scoped_test.mjs").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "all live.scoped ordering and lifecycle assertions passed") {
		t.Fatalf("SDK live.scoped ordering failed: %v\n%s", err, out)
	}
}
