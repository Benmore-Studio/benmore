//go:build !cli && !windows

package main

import (
	"testing"
)

func TestAppMCPEffectWebhookLeaseExpiryNeverReplays(t *testing.T) {
	h := newEffectHarness(t, "")
	adminCookie := createCrudScopeSession(t, h.app, "webhook-admin@example.com", "admin", "17", "")
	admin := GetSessionFromDB(h.app.DB, adminCookie)
	if _, err := h.app.DB.Exec(`INSERT INTO main._benmore_webhooks(user_id,url,secret,tables,events,active) VALUES(?,?,?,?,?,1)`, admin.UserID, "https://hooks.example.invalid/tasks", "fixture-secret", "tasks", "update"); err != nil {
		t.Fatal(err)
	}
	id, _ := h.commitApproved()
	if _, err := h.app.DB.Exec("UPDATE _benmore_jobs SET status='running', attempts=1, lease_expires_at='2000-01-01 00:00:00'"); err != nil {
		t.Fatal(err)
	}

	jobsRecoverOrphanedJobs(h.app)

	var status, jobError string
	if err := h.app.DB.QueryRow("SELECT status, error FROM _benmore_jobs").Scan(&status, &jobError); err != nil || status != "failed" {
		t.Fatalf("orphaned webhook effect = %q (%v), want failed", status, err)
	}
	if got := effectsOf(t, h.status(id))["status"]; got != "unknown" {
		t.Fatalf("unproven webhook delivery reported %q, want unknown", got)
	}
	if processNextJob(h.app) {
		t.Fatal("expired webhook effect was requeued and claimed")
	}
}
