//go:build !cli && !windows

package main

import (
	"strings"
	"testing"
)

// A connector command queues its hook and webhook-subscription effects inside
// the command transaction, under the hook-write authorizer. Their rows seal
// encrypted.yaml values the same way, and the hook still delivers.
func TestAppMCPCommandEffectJobsSealEncryptedColumns(t *testing.T) {
	h := newEffectHarness(t, effectNotifyHook)
	encrypted := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{"tasks": {{Column: "title"}}}}
	commandParityGeneration(h.app, func(generation *appMCPRuntimeGeneration) {
		generation.view.Encrypted = encrypted
	})
	InstallEncryptionTriggers(h.app.DB, encrypted)
	sealed, err := fieldEncryptCtx(cryptoKeyForQuerier(h.app.DB), "tasks", "title", "classified title")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.app.DB.Exec("UPDATE tasks SET title=? WHERE id=1", sealed); err != nil {
		t.Fatal(err)
	}
	adminCookie := createCrudScopeSession(t, h.app, "webhook-admin@example.com", "admin", "17", "")
	admin := GetSessionFromDB(h.app.DB, adminCookie)
	if _, err := h.app.DB.Exec(`INSERT INTO main._benmore_webhooks(user_id,url,secret,tables,events,active) VALUES(?,?,?,?,?,1)`, admin.UserID, "https://hooks.example.invalid/tasks", "fixture-secret", "tasks", "update"); err != nil {
		t.Fatal(err)
	}
	h.commitApproved()

	rows, err := h.app.DB.Query("SELECT job_type, payload FROM _benmore_jobs")
	if err != nil {
		t.Fatal(err)
	}
	kinds := map[string]bool{}
	for rows.Next() {
		var kind, payload string
		if err := rows.Scan(&kind, &payload); err != nil {
			t.Fatal(err)
		}
		kinds[kind] = true
		if strings.Contains(payload, "classified title") || !strings.Contains(payload, jobSealedRowField) {
			t.Errorf("%s effect job stores the encrypted title unsealed: %s", kind, payload)
		}
	}
	rows.Close()
	if !kinds["hook"] || !kinds["webhook_subscription"] {
		t.Fatalf("effect jobs queued: %v", kinds)
	}
	FlushJobs(h.app)
	if h.count("SELECT count(*) FROM _benmore_notifications WHERE title='Task done'") != 1 {
		t.Fatal("sealed hook effect was not delivered")
	}
}
