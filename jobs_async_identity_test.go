//go:build !cli

package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

func roundTripFlowJobActor(t *testing.T, session *Session) *flowJobActorSnapshot {
	t.Helper()
	encoded, err := json.Marshal(map[string]any{flowJobActorPayloadField: snapshotFlowJobActor(session)})
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal(encoded, &payload); err != nil {
		t.Fatal(err)
	}
	saved, err := takeFlowJobActor(payload)
	if err != nil || saved == nil {
		t.Fatalf("decode queued identity: %v", err)
	}
	if _, exists := payload[flowJobActorPayloadField]; exists {
		t.Fatal("actor metadata remained in flow input")
	}
	return saved
}

func TestAsyncFlowJobRetainsDelegatedRestrictions(t *testing.T) {
	for _, kind := range []string{"direct", "acting_as", "impersonation", "connector", "scoped"} {
		t.Run(kind, func(t *testing.T) {
			app, _ := auditApp(t)
			token := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
			original := GetSessionFromDB(app.DB, token)
			switch kind {
			case "acting_as":
				original.ActingAsGroup = "tenant-a"
			case "impersonation":
				original.ImpersonatorUserID, original.ImpersonatorEmail = 91, "support@example.com"
			case "connector":
				original.connectorGrant = true
			case "scoped":
				original.Scopes, original.CredentialScopes = "orgdocs:read", "orgdocs:read"
			}
			actor, err := flowJobActorCheck(app, &Flow{}, roundTripFlowJobActor(t, original), map[string]any{"user_group_id": original.EffectiveGroupID()})
			if err != nil {
				t.Fatal(err)
			}
			if actor.EffectiveGroupID() != original.EffectiveGroupID() || actor.ActingAsGroup != original.ActingAsGroup ||
				actor.ImpersonatorUserID != original.ImpersonatorUserID || actor.connectorGrant != original.connectorGrant ||
				actor.CredentialScopes != original.CredentialScopes || actor.Scopes != original.Scopes {
				t.Fatalf("queued restrictions changed: original=%+v restored=%+v", original, actor)
			}
			if webhookCallerMayChooseContextURL(actor) != webhookCallerMayChooseContextURL(original) || actor.IsAdminBypass() != original.IsAdminBypass() {
				t.Fatal("queued identity gained a direct-admin policy allowance")
			}
		})
	}
}

func TestAsyncFlowJobAuthorityOnlyNarrows(t *testing.T) {
	app, _ := auditApp(t)
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{"editor": {Scopes: "orgdocs:read"}, "admin": {Scopes: "*"}}}
	token := createCrudScopeSession(t, app, "editor@example.com", "editor", "", "")
	original := applySessionRoleScopes(app, GetSessionFromDB(app.DB, token))
	saved := roundTripFlowJobActor(t, original)
	// A role definition can broaden while the job waits, but its original
	// effective scope is still the maximum this queued call may use.
	app.Roles.Roles["editor"] = RoleDef{Scopes: "orgdocs:write"}
	actor, err := flowJobActorCheck(app, &Flow{}, saved, nil)
	if err != nil || !hasScope(actor, "orgdocs", "read") || hasScope(actor, "orgdocs", "write") {
		t.Fatalf("scope widened: actor=%+v err=%v", actor, err)
	}
	auditExec(t, app.DB, "UPDATE _benmore_users SET role='admin' WHERE id=?", original.UserID)
	actor, err = flowJobActorCheck(app, &Flow{}, saved, nil)
	if err != nil || actor.IsAdmin() || webhookCallerMayChooseContextURL(actor) || HasAnyRole(actor, []string{"admin"}) {
		t.Fatalf("promotion elevated queued identity: actor=%+v err=%v", actor, err)
	}
	if _, err := flowJobActorCheck(app, &Flow{Role: "editor"}, saved, nil); err == nil {
		t.Fatal("job retained a revoked role")
	}
}

func TestAsyncFlowEnqueueCapturesServerOwnedRestrictions(t *testing.T) {
	app, _ := auditApp(t)
	EnsureJobsTable(app.DB)
	token := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "tenant-a")
	flow := Flow{Name: "queued", Auth: "required", Async: true, Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/queued"}}
	r := httptest.NewRequest("POST", "/queued", strings.NewReader(`{"__benmore_job_actor":{"version":1,"user_id":999,"global_admin":true}}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	if err := executeFlowHTTP(app, &flow, w, r); err != nil || w.Code != 202 {
		t.Fatalf("enqueue: %d %v %s", w.Code, err, w.Body.String())
	}
	var encoded string
	if err := app.DB.QueryRow("SELECT payload FROM _benmore_jobs").Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(encoded), &payload); err != nil {
		t.Fatal(err)
	}
	saved, err := takeFlowJobActor(payload)
	if err != nil || saved == nil || saved.UserID == 999 || saved.ActingAsGroup != "tenant-a" {
		t.Fatalf("server identity missing: %+v %v", saved, err)
	}
	actor, err := flowJobActorCheck(app, &flow, saved, payload)
	if err != nil || webhookCallerMayChooseContextURL(actor) || actor.EffectiveGroupID() != "tenant-a" {
		t.Fatalf("worker identity changed: %+v %v", actor, err)
	}
}

func TestAsyncFlowLegacyActorDoesNotGainDirectAuthority(t *testing.T) {
	app, _ := auditApp(t)
	token := createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
	uid := GetSessionFromDB(app.DB, token).UserID
	saved, err := takeFlowJobActor(map[string]any{flowJobActorPayloadField: float64(uid)})
	if err != nil {
		t.Fatal(err)
	}
	actor, err := flowJobActorCheck(app, &Flow{}, saved, map[string]any{"user_group_id": "tenant-a"})
	if err != nil || actor.EffectiveGroupID() != "tenant-a" || webhookCallerMayChooseContextURL(actor) || actor.IsAdminBypass() {
		t.Fatalf("legacy actor gained direct authority: %+v %v", actor, err)
	}
	if _, err := takeFlowJobActor(map[string]any{flowJobActorPayloadField: map[string]any{"version": 99, "user_id": uid}}); err == nil {
		t.Fatal("unknown actor format accepted")
	}
}

func TestEnqueueCannotSupplyReservedActorIdentity(t *testing.T) {
	app := newJobsTestApp(t)
	ctx := &FlowContext{App: app, Data: map[string]any{"claimed_actor": "123"}, Params: map[string]string{"claimed_actor": "123"}, RequestKeys: map[string]bool{"claimed_actor": true}}
	step := &FlowStep{Type: "enqueue", Enqueue: &FlowEnqueue{Flow: "worker", With: map[string]string{flowJobActorPayloadField: "{{claimed_actor}}", "message": "kept"}}}
	if err := execStepEnqueue(ctx, step); err != nil {
		t.Fatal(err)
	}
	var encoded string
	if err := app.DB.QueryRow("SELECT payload FROM _benmore_jobs").Scan(&encoded); err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if err := json.Unmarshal([]byte(encoded), &payload); err != nil {
		t.Fatal(err)
	}
	if _, exists := payload[flowJobActorPayloadField]; exists || payload["message"] != "kept" {
		t.Fatalf("unexpected authored payload: %v", payload)
	}
}
