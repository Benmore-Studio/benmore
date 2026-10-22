//go:build !cli && !windows

package main

import (
	"strings"
	"testing"
	"time"
)

const effectNotifyHook = `on_update:
  tasks:
    - notify: "{{user_id}}"
      notify_title: Task done
      notify_body: "{{status}}"
`

// effectHarness is the exposure harness with the job and inbox tables a worker
// needs, and a helper that commits one approved operation.
func newEffectHarness(t *testing.T, hooks string) *exposureHarness {
	t.Helper()
	h := newExposureHarnessWithHooks(t, hooks)
	EnsureJobsTable(h.app.DB)
	EnsureNotificationsTable(h.app.DB)
	return h
}

func (h *exposureHarness) commitApproved() (string, map[string]any) {
	h.t.Helper()
	id := h.prepare()
	h.approveOK(id)
	out, code := h.commit(id)
	if code != "" {
		h.t.Fatalf("commit failed: %s", code)
	}
	return id, out
}

func effectsOf(t *testing.T, view map[string]any) map[string]any {
	t.Helper()
	effects, ok := view["effects"].(map[string]any)
	if !ok {
		t.Fatalf("no effects in %#v", view)
	}
	return effects
}

func effectItems(t *testing.T, effects map[string]any) []map[string]any {
	t.Helper()
	raw, _ := effects["items"].([]any)
	items := make([]map[string]any, len(raw))
	for i, item := range raw {
		items[i], _ = item.(map[string]any)
	}
	return items
}

func TestAppMCPEffectsHookJobQueuedInCommandTransactionAndDeliveredAfterWorker(t *testing.T) {
	h := newEffectHarness(t, effectNotifyHook)
	id := h.prepare()
	_, body, _ := h.review(h.cookie, id)
	if !strings.Contains(body, "create a notification") || strings.Contains(body, "No downstream effects") {
		t.Fatalf("review page does not disclose the queued effect: %s", body)
	}
	h.approveOK(id)
	out, code := h.commit(id)
	if code != "" || out["outcome"] != "applied" {
		t.Fatalf("commit: %q %#v", code, out)
	}
	if !h.taskDone() || h.count("SELECT count(*) FROM _benmore_jobs") != 1 {
		t.Fatal("business write or queued job missing after commit")
	}
	receipt, _ := out["receipt"].(map[string]any)
	effects := effectsOf(t, receipt)
	items := effectItems(t, effects)
	if effects["status"] != "pending" || len(items) != 1 || items[0]["kind"] != "hook" || items[0]["target"] != "tasks.update" || items[0]["status"] != "pending" {
		t.Fatalf("receipt effects: %#v", effects)
	}
	var jobID, payload string
	if err := h.app.DB.QueryRow("SELECT CAST(id AS TEXT), payload FROM _benmore_jobs").Scan(&jobID, &payload); err != nil || jobID != items[0]["id"] {
		t.Fatalf("effect id does not link the job: %q %v", jobID, err)
	}
	if !strings.Contains(payload, h.pair.GrantID) || strings.Contains(payload, h.pair.AccessToken) || strings.Contains(payload, h.pair.RefreshToken) {
		t.Fatalf("job must carry the grant id and never a token: %s", payload)
	}
	// The business commit and the delivery are reported independently.
	status := h.status(id)
	if status["business"] != "committed" || effectsOf(t, status)["status"] != "pending" {
		t.Fatalf("status before delivery: %#v", status)
	}
	// Replaying _commit returns the receipt and queues nothing.
	if again, code := h.commit(id); code != "" || again["outcome"] != "already_applied" || h.count("SELECT count(*) FROM _benmore_jobs") != 1 {
		t.Fatalf("replay re-enqueued or failed: %q %#v", code, again)
	}
	if h.count("SELECT count(*) FROM _benmore_notifications") != 0 {
		t.Fatal("effect delivered before the worker ran")
	}
	FlushJobs(h.app)
	if h.count("SELECT count(*) FROM _benmore_notifications WHERE title='Task done'") != 1 {
		t.Fatal("worker did not deliver the notification")
	}
	status = h.status(id)
	if status["business"] != "committed" || effectsOf(t, status)["status"] != "delivered" {
		t.Fatalf("status after delivery: %#v", status)
	}
}

func TestAppMCPEffectsEnqueueFailureAbortsCommandWithoutReceipt(t *testing.T) {
	h := newEffectHarness(t, effectNotifyHook)
	id := h.prepare()
	h.approveOK(id)
	if _, err := h.app.DB.Exec("ALTER TABLE _benmore_jobs RENAME TO _benmore_jobs_gone"); err != nil {
		t.Fatal(err)
	}
	if _, code := h.commit(id); code == "" {
		t.Fatal("commit succeeded although its effect could not be queued")
	}
	if h.taskDone() || h.count("SELECT count(*) FROM activities") != 0 {
		t.Fatal("a failed enqueue left business rows")
	}
	status := h.status(id)
	if status["business"] != "not_committed" || status["receipt"] != nil || effectsOf(t, status)["status"] != "none" {
		t.Fatalf("status after failed enqueue: %#v", status)
	}
}

func TestAppMCPEffectsWebhookSubscriptionQueuedNeverReportedDeliveredWithoutEvidence(t *testing.T) {
	h := newEffectHarness(t, "")
	adminCookie := createCrudScopeSession(t, h.app, "webhook-admin@example.com", "admin", "17", "")
	admin := GetSessionFromDB(h.app.DB, adminCookie)
	if _, err := h.app.DB.Exec(`INSERT INTO main._benmore_webhooks(user_id,url,secret,tables,events,active) VALUES(?,?,?,?,?,1)`, admin.UserID, "https://hooks.example.invalid/tasks", "fixture-secret", "tasks", "update"); err != nil {
		t.Fatal(err)
	}
	id, out := h.commitApproved()
	items := effectItems(t, effectsOf(t, out["receipt"].(map[string]any)))
	if len(items) != 1 || items[0]["kind"] != "webhook" || items[0]["status"] != "pending" {
		t.Fatalf("webhook effect not queued: %#v", out["receipt"])
	}
	if h.count("SELECT count(*) FROM _benmore_jobs WHERE job_type='webhook_subscription'") != 1 {
		t.Fatal("subscription delivery job missing")
	}
	// `.invalid` cannot be proven public, so SSRF protection blocks the send.
	if !processNextJob(h.app) {
		t.Fatal("worker did not claim the delivery")
	}
	if got := effectsOf(t, h.status(id))["status"]; got != appMCPEffectBlocked {
		t.Fatalf("unresolvable destination reported %q, want blocked", got)
	}
	var status string
	var attempts int
	if err := h.app.DB.QueryRow("SELECT status,attempts FROM _benmore_jobs WHERE job_type='webhook_subscription'").Scan(&status, &attempts); err != nil {
		t.Fatal(err)
	}
	if status != "failed" || attempts != 1 || processNextJob(h.app) {
		t.Fatalf("blocked delivery replayed: status=%q attempts=%d", status, attempts)
	}
	if got := effectsOf(t, h.status(id))["status"]; got == appMCPEffectDelivered {
		t.Fatalf("blocked delivery reported %q", got)
	}
}

func TestAppMCPEffectsRevokedGrantBlocksDeliveryWithoutRerunningBusiness(t *testing.T) {
	for name, revoke := range map[string]func(h *exposureHarness){
		"grant revoked": func(h *exposureHarness) {
			if err := revokeAppMCPGrant(h.app, h.pair.GrantID); err != nil {
				h.t.Fatal(err)
			}
		},
		"writes switched off": func(h *exposureHarness) {
			if _, err := setAppMCPApprovedWrites(h.app.Dir, false); err != nil {
				h.t.Fatal(err)
			}
		},
		"grant expired": func(h *exposureHarness) {
			if _, err := h.app.DB.Exec("UPDATE _benmore_mcp_grants SET expires_at=1"); err != nil {
				h.t.Fatal(err)
			}
		},
	} {
		h := newEffectHarness(t, effectNotifyHook)
		id, _ := h.commitApproved()
		revoke(h)
		FlushJobs(h.app)
		var status, jobError string
		if err := h.app.DB.QueryRow("SELECT status, COALESCE(error,'') FROM _benmore_jobs").Scan(&status, &jobError); err != nil {
			t.Fatal(err)
		}
		if status != "failed" || !strings.HasPrefix(jobError, appMCPEffectBlockedPrefix) {
			t.Fatalf("%s: job = %q %q, want blocked", name, status, jobError)
		}
		if h.count("SELECT count(*) FROM _benmore_notifications") != 0 {
			t.Fatalf("%s: a blocked effect was delivered", name)
		}
		if h.count("SELECT count(*) FROM tasks WHERE id=1 AND status='done'") != 1 || h.count("SELECT count(*) FROM activities WHERE event='completed'") != 1 {
			t.Fatalf("%s: business rows changed after the grant lapsed", name)
		}
		if got := appMCPEffectStatus(status, jobError, "", time.Now()); got != appMCPEffectBlocked {
			t.Fatalf("%s: effect status %q for operation %.8s", name, got, id)
		}
	}
}

func TestAppMCPEffectsLeaseExpiryNeverReplaysNonProvenEffect(t *testing.T) {
	h := newEffectHarness(t, effectNotifyHook)
	id, _ := h.commitApproved()
	// A worker claimed the job, then died: the lease lapsed with no result.
	if _, err := h.app.DB.Exec("UPDATE _benmore_jobs SET status='running', attempts=1, lease_expires_at='2000-01-01 00:00:00'"); err != nil {
		t.Fatal(err)
	}
	if got := effectsOf(t, h.status(id))["status"]; got != "unknown" {
		t.Fatalf("lapsed lease reported %q, want unknown", got)
	}
	jobsRecoverOrphanedJobs(h.app)
	FlushJobs(h.app)
	var status string
	if err := h.app.DB.QueryRow("SELECT status FROM _benmore_jobs").Scan(&status); err != nil || status != "failed" {
		t.Fatalf("orphaned hook job = %q %v, want failed (not requeued)", status, err)
	}
	if h.count("SELECT count(*) FROM _benmore_notifications") != 0 {
		t.Fatal("an unproven effect was re-run after its lease expired")
	}
	if got := effectsOf(t, h.status(id))["status"]; got != "unknown" {
		t.Fatalf("failed-closed orphan reported %q, want unknown", got)
	}
}

func TestAppMCPEffectStatusNeverClaimsDeliveredWithoutEvidence(t *testing.T) {
	now := time.Now()
	for _, tc := range []struct{ status, err, lease, want string }{
		{"pending", "", "", "pending"},
		{"running", "", now.Add(time.Minute).UTC().Format(sqliteDateTimeLayout), "pending"},
		{"running", "", "2000-01-01 00:00:00", "unknown"},
		{"completed", "", "", "delivered"},
		{"failed", "boom", "", "failed"},
		{"failed", "dropped: subscription removed", "", "failed"},
		{"failed", "blocked: the connector grant is revoked", "", "blocked"},
		{"failed", "unknown: webhook response was not confirmed", "", "unknown"},
		{"failed", "worker died mid-execution; not re-run", "", "unknown"},
		{"cancelled", "", "", "unknown"},
	} {
		if got := appMCPEffectStatus(tc.status, tc.err, tc.lease, now); got != tc.want {
			t.Errorf("%+v = %q, want %q", tc, got, tc.want)
		}
	}
	if appMCPEffectAggregate(nil) != "none" || appMCPEffectAggregate([]string{"delivered", "pending"}) != "pending" ||
		appMCPEffectAggregate([]string{"delivered", "failed"}) != "failed" || appMCPEffectAggregate([]string{"delivered"}) != "delivered" {
		t.Fatal("aggregate status")
	}
}
