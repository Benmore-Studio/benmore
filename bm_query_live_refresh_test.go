package main

import (
	"os/exec"
	"strings"
	"testing"
)

func TestEmbeddedBMQueryLiveRefresh(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping query live refresh behavior")
	}
	out, err := exec.Command(node, "embedded/bm_query_live_refresh_test.mjs").CombinedOutput()
	if err != nil || !strings.Contains(string(out), "all bm query live refresh assertions passed") {
		t.Fatalf("SDK query live refresh behavior failed: %v\n%s", err, out)
	}
}
