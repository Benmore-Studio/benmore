//go:build !cli && !windows

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// restartServedApp is the in-process equivalent of `benmore serve` starting
// again over the same directory: the old process shuts down, then the same
// start sequence runs (startServedApp: boot check, start-up load, resume). The
// boot check used to be skipped here, which hid that its check-only load
// forgot the approval binding on every hosted start.
func restartServedApp(t *testing.T, app *App) *App {
	t.Helper()
	dir := app.Dir
	app.Shutdown()
	next, err := startServedApp(dir)
	if err != nil {
		t.Fatalf("restart: %v", err)
	}
	t.Cleanup(next.Shutdown)
	// StartServer builds the mux next; start-up housekeeping there must not
	// disturb a resumed approval.
	state, wasLive := appMCPWritesLive(next)
	buildAppMux(next, false, "http://localhost")
	if _, live := appMCPWritesLive(next); live != wasLive || wasLive && state == nil {
		t.Fatal("building the start-up mux changed the write state")
	}
	return next
}

func enabledWritesFixture(t *testing.T) *App {
	t.Helper()
	app, _, _ := newUnenrolledCommandProviderTaskFixture(t, commandTaskFlowFixture, "")
	if err := connectorApply(t, app, "enable", true); err != nil {
		t.Fatal(err)
	}
	if st := connectorStatus(t, app); !st.Exposed || !st.ApprovedWrites || st.Enrollment != "active" {
		t.Fatalf("writes not on before restart: %+v", st)
	}
	return app
}

// Issue #422: a restart with an unchanged reviewed source and a verified
// enrollment used to leave approved_writes false until the owner ran
// `enable --writes` again.
func TestAppMCPApprovedWritesSurviveARestart(t *testing.T) {
	app := enabledWritesFixture(t)
	before, _ := appMCPWritesLive(app)
	app = restartServedApp(t, app)
	st := connectorStatus(t, app)
	if !st.Exposed || !st.ApprovedWrites || st.Enrollment != "active" || st.ApprovedWritesOffReason != "" {
		t.Fatalf("writes did not resume after restart: %+v", st)
	}
	after, live := appMCPWritesLive(app)
	if !live {
		t.Fatal("approved writes are not live after the restart")
	}
	if after.ApprovedWriteEpoch == before.ApprovedWriteEpoch {
		t.Fatal("the write epoch did not rotate across the restart; a pre-restart operation could still commit")
	}
	if after.Epoch != before.Epoch {
		t.Fatal("a restart must not rotate the read epoch (it would revoke every grant)")
	}
	// And it keeps working across a second restart.
	app = restartServedApp(t, app)
	if _, live := appMCPWritesLive(app); !live {
		t.Fatal("writes lost on the second restart")
	}
}

func TestAppMCPApprovedWritesOwnerOffIsNotResumed(t *testing.T) {
	app := enabledWritesFixture(t)
	if err := connectorApply(t, app, "disable", true); err != nil {
		t.Fatal(err)
	}
	app = restartServedApp(t, app)
	if st := connectorStatus(t, app); st.ApprovedWrites || !st.Exposed || st.ApprovedWritesOffReason != "" {
		t.Fatalf("owner-off writes came back: %+v", st)
	}
	// Owner-off after a restart suspension also forgets the binding.
	app2 := enabledWritesFixture(t)
	// Simulate a suspended-but-unresumed start, then the owner switches off.
	if release, _, err := beginAppMCPStartupPolicyChange(t.Context(), app2.Dir); err != nil {
		t.Fatal(err)
	} else {
		release()
	}
	if state, err := currentAppMCPEpoch(app2.Dir); err != nil || state.ApprovedContractDigest == "" || *state.ApprovedWrites {
		t.Fatalf("suspension did not keep the binding: %+v %v", state, err)
	}
	if err := connectorApply(t, app2, "disable", true); err != nil {
		t.Fatal(err)
	}
	if state, err := currentAppMCPEpoch(app2.Dir); err != nil || state.ApprovedContractDigest != "" {
		t.Fatalf("owner-off kept the binding: %+v %v", state, err)
	}
	app2 = restartServedApp(t, app2)
	if _, live := appMCPWritesLive(app2); live {
		t.Fatal("owner-off after a suspension was resumed")
	}
}

func TestAppMCPApprovedWritesStayOffWhenReviewedSourceChanged(t *testing.T) {
	app := enabledWritesFixture(t)
	dir := app.Dir
	app.Shutdown()
	schema, err := os.ReadFile(filepath.Join(dir, "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	// An unreviewed change withholds the connector entirely.
	writeTestFile(t, dir, "schema.sql", string(schema)+"\n-- changed\n")
	stale := restartServedApp(t, app)
	st := connectorStatus(t, stale)
	if st.ApprovedWrites || !strings.Contains(st.ApprovedWritesOffReason, "review no longer matches") {
		t.Fatalf("unreviewed change: %+v", st)
	}
	// A reviewed change binds new digests, which the owner has not approved.
	reviewAppMCPFixture(t, dir)
	reviewed := restartServedApp(t, stale)
	st = connectorStatus(t, reviewed)
	if st.ApprovedWrites || !strings.Contains(st.ApprovedWritesOffReason, "digests changed") {
		t.Fatalf("reviewed change: %+v", st)
	}
	// The owner approves the new digests explicitly, and that survives a restart.
	if err := connectorApply(t, reviewed, "enable", true); err != nil {
		t.Fatal(err)
	}
	reviewed = restartServedApp(t, reviewed)
	if st = connectorStatus(t, reviewed); !st.ApprovedWrites || st.ApprovedWritesOffReason != "" {
		t.Fatalf("re-approved writes did not survive: %+v", st)
	}
}

func TestAppMCPApprovedWritesStayOffWithoutAVerifiedEnrollment(t *testing.T) {
	app := enabledWritesFixture(t)
	dir := app.Dir
	app.Shutdown()
	// Damage the revision ledger the enrollment attests, as an upgrade that
	// changes its triggers or a hand edit would.
	next, err := loadAppWithOptions(dir, appLoadOptions{startup: true})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := next.DB.Exec(`CREATE TRIGGER main.extra_task_trigger AFTER INSERT ON tasks BEGIN SELECT 1; END`); err != nil {
		t.Fatal(err)
	}
	next.Shutdown()
	restarted := restartServedApp(t, next)
	st := connectorStatus(t, restarted)
	if st.ApprovedWrites || st.ApprovedWritesOffReason == "" {
		t.Fatalf("unverifiable enrollment resumed or gave no reason: %+v", st)
	}
	if strings.ContainsAny(st.ApprovedWritesOffReason, "/\\") {
		t.Fatalf("reason carries a path: %q", st.ApprovedWritesOffReason)
	}
}

// Only a process start may resume. A reload, a restore or a revoke ends the
// approval for good, even though a restart follows.
func TestAppMCPApprovedWritesReloadRestoreAndRevokeNeverResume(t *testing.T) {
	installCanonicalHotHandler(t)
	app := enabledWritesFixture(t)
	if err := hotReloadApp(app, false); err != nil {
		t.Fatal(err)
	}
	if _, live := appMCPWritesLive(app); live {
		t.Fatal("writes stayed on across a reload")
	}
	app = restartServedApp(t, app)
	if _, live := appMCPWritesLive(app); live {
		t.Fatal("a reload's suspension was resumed by the next restart")
	}

	app = enabledWritesFixture(t)
	if err := invalidateAppMCPForRestore(app.Dir); err != nil {
		t.Fatal(err)
	}
	app = restartServedApp(t, app)
	if st := connectorStatus(t, app); st.ApprovedWrites || st.Exposed {
		t.Fatalf("restore resumed: %+v", st)
	}

	app = enabledWritesFixture(t)
	if err := connectorRevoke(t, app); err != nil {
		t.Fatal(err)
	}
	app = restartServedApp(t, app)
	if _, live := appMCPWritesLive(app); live {
		t.Fatal("revoke resumed")
	}
}

// Rollback contract documented in the release runbook: a runtime from before
// the digests existed decodes the state file with DisallowUnknownFields, so it
// cannot read one that carries them, and the operator's jq command (which
// preserves key order) restores a file that reader accepts byte for byte.
func TestAppMCPAuthorityStateRollbackStripCommand(t *testing.T) {
	jq, err := exec.LookPath("jq")
	if err != nil {
		t.Skip("jq not installed")
	}
	app := enabledWritesFixture(t)
	root, key, err := appMCPAuthorityRoot(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	data, err := root.ReadFile(key + ".json")
	if err != nil {
		t.Fatal(err)
	}
	legacy := func(b []byte) error {
		var old struct {
			Version                int    `json:"version"`
			App                    string `json:"app"`
			Epoch                  string `json:"epoch"`
			Exposed                bool   `json:"exposed"`
			ApprovedWrites         *bool  `json:"approved_writes,omitempty"`
			ApprovedWriteEpoch     string `json:"approved_write_epoch,omitempty"`
			ExternalExport         bool   `json:"external_export,omitempty"`
			PublicPublication      bool   `json:"public_publication,omitempty"`
			ExternalExportEpoch    string `json:"external_export_epoch,omitempty"`
			PublicPublicationEpoch string `json:"public_publication_epoch,omitempty"`
		}
		d := json.NewDecoder(bytes.NewReader(b))
		d.DisallowUnknownFields()
		if err := d.Decode(&old); err != nil {
			return err
		}
		canonical, _ := json.Marshal(old)
		if !bytes.Equal(bytes.TrimSpace(b), canonical) {
			return fmt.Errorf("noncanonical")
		}
		return nil
	}
	if legacy(data) == nil {
		t.Fatal("a pre-change reader accepted a state file carrying the approved digests")
	}
	// Keep this command identical to the one in docs/deployment/release-runbook.md.
	cmd := exec.Command(jq, "-c", "del(.approved_contract_digest, .approved_execution_digest, .auto_approve, .auto_approve_epoch)")
	cmd.Stdin = bytes.NewReader(data)
	stripped, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy(stripped); err != nil {
		t.Fatalf("a pre-change reader rejects the stripped state: %v\n%s", err, stripped)
	}
	// The current reader accepts the stripped file too (no digests: nothing resumes).
	if err := root.WriteFile(key+".json", stripped, 0600); err != nil {
		t.Fatal(err)
	}
	state, err := readAppMCPEpoch(root, key)
	if err != nil || state.ApprovedContractDigest != "" || state.Version != 2 {
		t.Fatalf("current reader rejects the stripped state: %v %+v", err, state)
	}
}
