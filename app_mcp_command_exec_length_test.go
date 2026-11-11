//go:build !cli && !windows

package main

import (
	"strings"
	"testing"
)

// An apply write without RETURNING runs under the same value-length bound as
// the row-producing path: an allowlisted zeroblob/printf/replace cannot build
// a value larger than appMCPResultLimit inside the app process.
func TestAppMCPCommandApplyExecHonorsLengthLimit(t *testing.T) {
	anchor := "completed_at = datetime('now') WHERE"
	if strings.Count(commandTaskFlowFixture, anchor) != 1 {
		t.Fatalf("fixture anchor %q not found once", anchor)
	}
	flow := strings.Replace(commandTaskFlowFixture, anchor, "completed_at = datetime('now'), title = zeroblob(8000000) WHERE", 1)
	h := newExposureHarnessWithFlow(t, flow, "")
	id := h.prepare()
	h.approveOK(id)
	out, code := h.call(h.client, appMCPCommitTool, map[string]any{"operation_id": id})
	if code == "" && out["outcome"] == "applied" {
		t.Fatalf("an over-length apply write committed: %#v", out)
	}
	if h.taskDone() || h.count("SELECT count(*) FROM tasks WHERE length(title) > ?", appMCPResultLimit) != 0 {
		t.Fatal("over-length value was written")
	}
}
