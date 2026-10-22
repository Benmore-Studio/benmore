//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A pending email change carries the address the user wanted next, and its
// confirmation link writes that address (marked verified) onto the account id.
// Erasing the account must remove it: otherwise the erased person's other
// address stays on record, and opening the link re-attaches it to the
// tombstone, which then blocks anyone else from registering that address.
func TestPurgeCurrentUserRemovesPendingEmailChange(t *testing.T) {
	t.Setenv("BENMORE_PUBLIC_URL", "https://app.real")
	app, cleanup := newPurgeTestApp(t)
	defer cleanup()
	app.Design = &DesignConfig{Auth: map[string]string{}, SEO: map[string]string{"url": "https://app.real"}}
	insertPurgeUser(t, app, 1, "owner@example.com")
	sessionID := CreateSession(app.DB, 1, "owner@example.com", "", time.Hour)
	ensureEmailChangesTable(app.DB)
	token := "pending-change-token"
	if _, err := app.DB.Exec(`INSERT INTO _benmore_email_changes(user_id,new_email,token_hash,expires_at) VALUES(1,'personal@elsewhere.example',?,?)`,
		hashResetToken(token), time.Now().Add(time.Hour).UTC().Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}

	flow := &Flow{
		Name:        "account-delete",
		Trigger:     FlowTrigger{Type: "http", Method: http.MethodPost, Path: "/api/account-delete"},
		Auth:        "required",
		Transaction: true,
		Steps: []FlowStep{
			{Name: "purge", Type: "purge_current_user", PurgeCurrentUserConfirm: "{{confirm}}"},
			{Type: "respond", Respond: &FlowRespond{Status: http.StatusOK, JSON: map[string]any{"deleted": true}}},
		},
	}
	req := httptest.NewRequest(http.MethodPost, "/api/account-delete", strings.NewReader(`{"confirm":"DELETE"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+sessionID)
	rr := httptest.NewRecorder()
	executeFlowHTTP(app, flow, rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("purge status=%d body=%s", rr.Code, rr.Body.String())
	}

	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_email_changes WHERE user_id=1", 0)
	if _, _, _, err := confirmEmailChange(app, token); err == nil {
		t.Fatal("a pre-erasure email-change link still applied")
	}
	assertCount(t, app, "SELECT COUNT(*) FROM _benmore_users WHERE id=1 AND email IS NULL", 1)
}
