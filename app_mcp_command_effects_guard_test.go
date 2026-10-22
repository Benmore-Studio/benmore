//go:build !cli && !windows

package main

import (
	"context"
	"testing"
	"time"
)

// App hook SQL naming _benmore_jobs is already refused when the revision
// enrollment is built; this is the engine-level backstop: the hook-write scope
// refuses the insert unless framework code has opened the enqueue window.
func TestAppMCPEffectsHookWriteScopeRefusesJobInsertOutsideEnqueueWindow(t *testing.T) {
	app, sessionID, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, hookFiredOnUpdate)
	EnsureJobsTable(app.DB)
	err := appMCPWithCommandCapability(context.Background(), appMCPCommandRequest{
		app: app, generation: snapshotAppMCPGeneration(app), toolName: "complete_item", origin: hookFixtureOrigin(sessionID), now: time.Now().UTC(),
	}, func(cap *appMCPCommandCapability) (bool, error) {
		return false, cap.withNativeMetadata(appMCPCommandMetadataHookWrite, func() error {
			_, err := cap.tx.ExecContext(cap.ctx, `INSERT INTO _benmore_jobs(job_type,flow_name,payload) VALUES('flow','anything','{}')`)
			return err
		})
	})
	if err == nil {
		t.Fatal("hook-write scope accepted a job insert outside the enqueue window")
	}
}

func TestAppMCPEffectsMixedSQLAndDeliveryHookStaysRefused(t *testing.T) {
	h := newEffectHarness(t, `on_update:
  tasks:
    - sql: SELECT 1
      webhook: https://hooks.example.invalid/x
`)
	id := h.prepare()
	h.approveOK(id)
	if _, code := h.commit(id); code == "" || h.taskDone() {
		t.Fatalf("mixed hook was accepted (code %q)", code)
	}
}
