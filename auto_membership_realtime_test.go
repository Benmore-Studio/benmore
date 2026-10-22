//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

// Replay the hosted bulletin feature using its actual authored config, a
// native parent create, the stored hook job and the normal SSE/WS dispatcher.
// The prior implementation committed enrollment but failed to recognize the
// synthesized SQL's comment marker and quoted target for refresh publication.
func TestAutoMembershipStoredJobRefreshesReaders(t *testing.T) {
	for _, shape := range []string{"synthesized", "comment only", "quoted target only", "simple positive"} {
		t.Run(shape, func(t *testing.T) {
			dir := writeApp(t, map[string]string{
				"app.yaml": `site_name: Bulletin
auto_memberships:
  staff_channels:
    table: staff_roster
    parent: channel_id
    user_field: member_id
    members: "role = 'editor' AND (deactivated_at IS NULL OR deactivated_at = '')"
access:
  default: {all: admin}
  staff_channels:
    read: member-of:staff_roster(channel_id=id,member_id)
    write: everyone
  staff_roster:
    read: member-of:staff_roster(channel_id,member_id)
    write: admin
`,
				"schema.prisma": `model StaffChannel {
  id Int @id @default(autoincrement())
  title String
  userId Int @map("user_id")
  members StaffMember[]
  @@map("staff_channels")
}
model StaffMember {
  id Int @id @default(autoincrement())
  channelId Int @map("channel_id")
  memberId Int @map("member_id")
  channel StaffChannel @relation(fields: [channelId], references: [id])
  @@unique([channelId, memberId])
  @@map("staff_roster")
}
`,
			})
			app, err := loadApp(dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(app.Shutdown)
			EnsureJobsTable(app.DB)
			EnsureAuditLogTable(app.DB)
			EnsureAPITokensTable(app.DB)
			EnsurePermissionsTable(app.DB)
			EnsureIdempotencyTable(app.DB)
			EnsureNotificationsTable(app.DB)
			EnsureWebhooksTable(app.DB)
			adminSID := createCrudScopeSession(t, app, "owner@example.com", "admin", "", "")
			editorSID := createCrudScopeSession(t, app, "editor@example.com", "editor", "", "")
			outsiderSID := createCrudScopeSession(t, app, "outsider@example.com", "user", "", "")
			revokedSID := createCrudScopeSession(t, app, "revoked@example.com", "user", "", "")
			if got := len(app.Hooks.OnInsert["staff_channels"]); got != 1 {
				t.Fatalf("synthesized hooks=%d", got)
			}
			hook := app.Hooks.OnInsert["staff_channels"][0]
			if shape == "quoted target only" || shape == "simple positive" {
				hook.SQL = strings.TrimSpace(strings.TrimPrefix(hook.SQL, autoMembershipMarker("staff_channels")))
			}
			if shape == "comment only" || shape == "simple positive" {
				hook.SQL = strings.Replace(hook.SQL, `"staff_roster"`, "staff_roster", 1)
			}
			app.Hooks.OnInsert["staff_channels"][0] = hook
			mux := http.NewServeMux()
			RegisterCRUD(mux, app)
			created := crudScopeRequest(t, mux, http.MethodPost, "/api/staff_channels", adminSID, map[string]any{"title": "private bulletin title"})
			if created.Code != http.StatusOK {
				t.Fatalf("parent create=%d %s", created.Code, created.Body.String())
			}
			var count int
			if err := app.DB.QueryRow("SELECT count(*) FROM staff_roster").Scan(&count); err != nil || count != 1 {
				t.Fatalf("native founder before worker: count=%d err=%v", count, err)
			}
			realtimeFlush()
			admin := subscribeFlowRealtime(t, app, adminSID)
			editor := subscribeFlowRealtime(t, app, editorSID)
			outsider := subscribeFlowRealtime(t, app, outsiderSID)
			revoked := subscribeFlowRealtime(t, app, revokedSID)
			rosterToken := auditToken(t, app, adminSID, "staff_roster:read")
			unrelatedToken := auditToken(t, app, adminSID, "staff_channels:read")
			rosterScoped := subscribeFlowRealtime(t, app, rosterToken)
			unrelatedScoped := subscribeFlowRealtime(t, app, unrelatedToken)
			if _, err := app.DB.Exec("DELETE FROM _benmore_sessions WHERE id=?", sessionStorageKey(revokedSID)); err != nil {
				t.Fatal(err)
			}
			var stored string
			if err := app.DB.QueryRow("SELECT payload FROM _benmore_jobs WHERE job_type='hook'").Scan(&stored); err != nil {
				t.Fatal(err)
			}
			var payload map[string]any
			if err := json.Unmarshal([]byte(stored), &payload); err != nil {
				t.Fatal(err)
			}
			if err := executeHookJob(app, payload); err != nil {
				t.Fatal(err)
			}
			if err := app.DB.QueryRow("SELECT count(*) FROM staff_roster").Scan(&count); err != nil || count != 2 {
				t.Fatalf("committed founder+editor enrollment: count=%d err=%v", count, err)
			}
			for name, sub := range map[string]*flowRealtimeSubscriber{"admin": admin, "editor": editor, "outsider": outsider, "revoked": revoked, "roster-token": rosterScoped, "unrelated-token": unrelatedScoped} {
				sse, ws := sub.drain()
				var wantSSE, wantWS []string
				if name == "admin" || name == "roster-token" {
					wantSSE = []string{`{"table":"staff_roster","action":"refresh"}`}
					wantWS = []string{`{"type":"change","table":"staff_roster","action":"refresh"}`}
				} else if name != "revoked" && name != "unrelated-token" {
					wantSSE = []string{realtimeGenericSSE}
					wantWS = []string{string(realtimeWSGenericRefresh)}
				}
				if !reflect.DeepEqual(sse, wantSSE) || !reflect.DeepEqual(ws, wantWS) {
					t.Errorf("%s committed roster refresh: sse=%q ws=%q want sse=%q ws=%q", name, sse, ws, wantSSE, wantWS)
				}
			}
			// Notification is only a hint: each subsequent native read keeps
			// the original membership boundary, including the outsider.
			assertListIDs(t, mux, editorSID, "/api/staff_channels", []float64{1})
			assertListIDs(t, mux, outsiderSID, "/api/staff_channels", nil)
			if rr := crudScopeRequest(t, mux, http.MethodGet, "/api/staff_roster", rosterToken, nil); rr.Code != http.StatusOK {
				t.Fatalf("roster token read=%d", rr.Code)
			}
			if rr := crudScopeRequest(t, mux, http.MethodGet, "/api/staff_roster", unrelatedToken, nil); rr.Code != http.StatusForbidden {
				t.Fatalf("unrelated token read=%d", rr.Code)
			}
			// A read-only stored hook must not publish an invalidation.
			if err := roundTripHookJob(t, app, hookJobPayload(Hook{SQL: "SELECT count(*) FROM staff_roster"}, "staff_channels", nil)); err != nil {
				t.Fatal(err)
			}
			if sse, ws := admin.drain(); len(sse)+len(ws) != 0 {
				t.Fatalf("read-only job published: %q %q", sse, ws)
			}
		})
	}
}
