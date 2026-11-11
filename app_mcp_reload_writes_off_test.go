//go:build !cli && !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A source edit made mcp.yaml's review stale; after review and a push of
// mcp.yaml, approved writes (and auto-approve) were off and status gave no
// reason, while the docs said a review restores the connector as it was. The
// reset is deliberate (every hot reload may run different code, so the
// owner's approval ends with it), and status now says so until the owner
// changes a switch.
func TestAppMCPStatusExplainsWritesTurnedOffByAReload(t *testing.T) {
	installCanonicalHotHandler(t)
	app := enabledWritesFixture(t)
	schema, err := os.ReadFile(filepath.Join(app.Dir, "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	// The edit reloads with the connector withheld ...
	writeTestFile(t, app.Dir, "schema.sql", string(schema)+"\n-- changed\n")
	if err := hotReloadApp(app, false); err != nil {
		t.Fatal(err)
	}
	st := connectorStatus(t, app)
	if st.ApprovedWrites || !strings.Contains(st.ApprovedWritesOffReason, "turned off by a hot reload") {
		t.Fatalf("a reload turned writes off without saying so: %+v", st)
	}
	// ... and the review that restores it reloads again: exposure is back,
	// writes stay off, and the reason still says why.
	reviewAppMCPFixture(t, app.Dir)
	if err := hotReloadApp(app, false); err != nil {
		t.Fatal(err)
	}
	st = connectorStatus(t, app)
	if !st.Exposed || st.ApprovedWrites || !strings.Contains(st.ApprovedWritesOffReason, "enable --writes") || st.Problem != "" {
		t.Fatalf("after the review: %+v", st)
	}
	if strings.ContainsAny(st.ApprovedWritesOffReason, "/\\") {
		t.Fatalf("reason carries a path: %q", st.ApprovedWritesOffReason)
	}
	// The owner turns them back on: no reason. An owner-off afterwards is the
	// owner's own choice and is not blamed on the reload.
	if err := connectorApply(t, app, "enable", true); err != nil {
		t.Fatal(err)
	}
	if st = connectorStatus(t, app); !st.ApprovedWrites || st.ApprovedWritesOffReason != "" {
		t.Fatalf("re-enabled writes: %+v", st)
	}
	if err := connectorApply(t, app, "disable", true); err != nil {
		t.Fatal(err)
	}
	if st = connectorStatus(t, app); st.ApprovedWrites || st.ApprovedWritesOffReason != "" {
		t.Fatalf("owner-off was given a reload reason: %+v", st)
	}
	// A reload while writes are already off does not invent a cause.
	if err := hotReloadApp(app, false); err != nil {
		t.Fatal(err)
	}
	if st = connectorStatus(t, app); st.ApprovedWritesOffReason != "" {
		t.Fatalf("a reload with writes already off gave a reason: %+v", st)
	}
}
