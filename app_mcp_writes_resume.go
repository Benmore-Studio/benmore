//go:build !cli

package main

import (
	"context"
	"errors"
	"log"
	"os"
	"time"
)

// resumeAppMCPApprovedWrites runs once per served process, right after the
// start-up load. Loading suspends approved writes (a new process may carry new
// code, migrations or environment), but a plain restart or a runtime upgrade
// of an app whose reviewed digests are unchanged must not make the owner
// approve again. Writes come back only when ALL hold, decided under the owner
// lease: the owner state still records a suspension, its recorded contract and
// execution digests equal the loaded reviewed manifest's, the source still
// matches that manifest, read exposure is on, and the revision enrollment is
// active for the current owner epoch and verifies against the database
// (enableAppMCPRevisionEnrolledWrites). Anything else leaves writes off; the
// owner sees why in `mcp status` (approved_writes_off_reason) and re-enables
// with `enable --writes`, which re-enrolls if needed. Enrollment is never
// created or repaired here: that is an owner action.
func resumeAppMCPApprovedWrites(app *App) {
	if app == nil || app.DB == nil || os.Getenv("BENMORE_MCP_AUTHORITY_DIR") == "" {
		return
	}
	state, err := currentAppMCPEpoch(app.Dir)
	if err != nil || state.Version != 2 || state.ApprovedWrites == nil || *state.ApprovedWrites || state.ApprovedContractDigest == "" {
		return // nothing was suspended
	}
	generation := snapshotAppMCPGeneration(app)
	if generation == nil || generation.manifest == nil {
		log.Printf("MCP approved writes stay off after start: no reviewed mcp.yaml is loaded")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), appMCPControlTimeout)
	defer cancel()
	_, err = enableAppMCPRevisionEnrolledWritesAs(ctx, app, generation, true)
	switch {
	case err == nil:
		log.Printf("MCP approved writes resumed after start (reviewed digests unchanged, revision enrollment verified)")
	case errors.Is(err, errAppMCPNothingToResume):
		log.Printf("MCP approved writes stay off after start: the reviewed digests changed since writes were approved")
	default:
		log.Printf("MCP approved writes stay off after start: %v", err)
	}
}

// appMCPApprovedWritesOrAutoApproveOn reads the owner state without a lease,
// only to say afterwards why a reload turned writes off.
func appMCPApprovedWritesOrAutoApproveOn(dir string) bool {
	if os.Getenv("BENMORE_MCP_AUTHORITY_DIR") == "" {
		return false
	}
	state, err := currentAppMCPEpoch(dir)
	return err == nil && state.Version == 2 && state.ApprovedWrites != nil && (*state.ApprovedWrites || state.AutoApprove)
}

// appMCPReloadWritesOffReason is the reason after a hot reload turned approved
// writes off. Resetting is deliberate: a reload can load different code, so
// the owner's approval (bound to the reviewed digests) and auto-approve end
// with it, as do users' auto-approve consents, and only the owner turns them
// back on. A review that restores the connector does not restore them.
const appMCPReloadWritesOffReason = "turned off by a hot reload: any reload (a push or source write, including the one that left mcp.yaml's review stale and the one that loaded the new review) may run different code, so it turns approved writes and auto-approve off and ends users' auto-approve consent; once the reviewed source is loaded, run enable --writes (with --auto-approve if it was on), and users tick auto-approve again when they reconnect"

// appMCPWritesOffReason explains, with a fixed phrase and no raw error text, why
// writes are off when a start-up suspension is still recorded (the owner never
// switched them off), or when a hot reload of this process turned them off
// (reloadOffAt, unix nanoseconds; such a reload forgets the binding the other
// reasons read). Empty when writes are on or were turned off on purpose.
func appMCPWritesOffReason(st appMCPConnectorStatus, state *appMCPEpochState, generation *appMCPRuntimeGeneration, withheld bool, reloadOffAt int64) string {
	if state == nil || st.ApprovedWrites {
		return ""
	}
	if state.ApprovedContractDigest == "" {
		if reloadOffAt != 0 {
			return appMCPReloadWritesOffReason + " (at " + time.Unix(0, reloadOffAt).UTC().Format(time.RFC3339) + ")"
		}
		return ""
	}
	switch {
	case withheld:
		return "suspended at start: mcp.yaml's review no longer matches the source; review it, push mcp.yaml and run enable --writes"
	case generation == nil || generation.manifest == nil:
		return "suspended at start: no reviewed mcp.yaml is loaded; run enable --writes after it loads"
	case !SecureCompare(state.ApprovedContractDigest, generation.manifest.ContractDigest) || !SecureCompare(state.ApprovedExecutionDigest, generation.manifest.ExecutionDigest):
		return "suspended at start: the reviewed digests changed since writes were approved; review the change and run enable --writes"
	case !st.Exposed:
		return "suspended at start: read exposure is off; run enable --writes"
	case st.Enrollment != "active":
		return "suspended at start: revision enrollment is " + st.Enrollment + " and could not be verified; run enable --writes to re-enroll"
	}
	return "suspended at start: the revision enrollment did not verify against the database; run enable --writes (see the service log)"
}
