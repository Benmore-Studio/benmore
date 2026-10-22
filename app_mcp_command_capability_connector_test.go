//go:build !cli && !windows

package main

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestAppMCPCommandCapabilityConnectorGrantFollowsRoleScopes(t *testing.T) {
	app, sessions := newCommandCapabilityFixture(t)
	generation := snapshotAppMCPGeneration(app)
	now := time.Now().UTC()
	uid := func(role string) int64 {
		var id int64
		if err := app.DB.QueryRow(`SELECT user_id FROM _benmore_sessions WHERE id=?`, sessions[role]).Scan(&id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	// The consent scope advertised for the command includes the capability.
	if scopes := appMCPLiveScopes(app, generation.manifest, generation); !scopesWithin(scopes, "billing:write") {
		t.Fatalf("connector scopes omit the capability: %q", scopes)
	}
	if _, err := createAppMCPNativeGrantFor(context.Background(), app, uid("viewer"), "17", "viewer-client", grantFixtureResource, "complete_item", now); err == nil {
		t.Fatal("connector grant issued to an account whose roles lack the capability")
	}
	state, err := currentAppMCPEpoch(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := createAppMCPNativeGrantFor(context.Background(), app, uid("admin"), "17", "admin-client", grantFixtureResource, "complete_item", now)
	if err != nil {
		t.Fatalf("capability grant: %v", err)
	}
	pin := appMCPWriteAuthorityPin{
		Origin: app, Generation: generation, CredentialHash: mustAppMCPCredentialHash(t, pair.AccessToken, "access"), GrantID: pair.GrantID,
		AppID: state.App, Epoch: state.Epoch, WriteEpoch: state.ApprovedWriteEpoch,
		Resource: grantFixtureResource, Client: "admin-client", Tenant: "17", UserID: uid("admin"),
		UserCreated: readUserCreatedForTest(t, app, uid("admin")), Permissions: strings.Fields(pair.Scopes),
	}
	if len(pin.Permissions) != 1 || pin.Permissions[0] != "billing:write" {
		t.Fatalf("grant scopes = %q", pair.Scopes)
	}
	origin := appMCPCommandOrigin{kind: appMCPCommandConnectorOrigin, connector: &pin}
	prepared, err := prepareCommandTask(t, app, origin)
	// A connector actor reads as the global admin role (it gets no bypass), same as a session.
	if err != nil || prepared.Preview["status"] != "admin:1" {
		t.Fatalf("connector prepare: %v %v", prepared, err)
	}
	if _, err := applyCommandTask(t, app, origin, prepared); err != nil {
		t.Fatalf("connector apply: %v", err)
	}
	var event string
	if err := app.DB.QueryRow(`SELECT event FROM activities WHERE task_id=1`).Scan(&event); err != nil || event != "admin:1" {
		t.Fatalf("connector apply bound %q (%v)", event, err)
	}
}

// ${{ user.role }} / ${{ user.is_admin }} are read live at every phase, so the
// operation seals them at prepare: a role change between the approved preview
// and the commit must refuse the commit and write nothing.
func TestAppMCPCommandSealsActorRoleBindingsAtPrepare(t *testing.T) {
	for _, promote := range []bool{false, true} {
		app, sessions := newCommandCapabilityFixture(t)
		ensureCommandAuditFixture(t, app)
		EnsureJobsTable(app.DB)
		generation := snapshotAppMCPGeneration(app)
		var uid int64
		if err := app.DB.QueryRow(`SELECT user_id FROM _benmore_sessions WHERE id=?`, sessions["editor"]).Scan(&uid); err != nil {
			t.Fatal(err)
		}
		pair, err := createAppMCPNativeGrantFor(context.Background(), app, uid, "17", "editor-client", grantFixtureResource, "complete_item", time.Now().UTC())
		if err != nil {
			t.Fatal(err)
		}
		grant, err := readAppMCPGrant(app.DB, pair.GrantID)
		if err != nil {
			t.Fatal(err)
		}
		origin, err := appMCPConnectorOrigin(app, generation, grant, &generation.manifest.Tools[0], pair.AccessToken, grantFixtureResource)
		if err != nil {
			t.Fatal(err)
		}
		request := appMCPCommandRequest{app: app, generation: generation, toolName: "complete_item", origin: origin, now: time.Now().UTC()}
		approve := request
		approve.origin = appMCPCommandOrigin{kind: appMCPCommandSessionOrigin, sessionID: sessions["editor"]}
		prepared, err := appMCPPrepareOperation(context.Background(), request, map[string]any{"arguments": map[string]any{"id": 1, "project_id": 7}})
		if err != nil || prepared.Preview["status"] != "editor:0" {
			t.Fatalf("prepare: %v %v", prepared, err)
		}
		if _, err := appMCPReviewOperation(context.Background(), approve, prepared.ID, "fixture-approved"); err != nil {
			t.Fatalf("approve: %v", err)
		}
		if promote {
			if _, err := app.DB.Exec(`UPDATE _benmore_users SET role='admin' WHERE id=?`, uid); err != nil {
				t.Fatal(err)
			}
		}
		commit, err := appMCPCommitOperation(context.Background(), request, prepared.ID)
		var done, events int
		if e := app.DB.QueryRow(`SELECT (SELECT count(*) FROM tasks WHERE status<>'open'), (SELECT count(*) FROM activities)`).Scan(&done, &events); e != nil {
			t.Fatal(e)
		}
		if promote {
			if err == nil || done != 0 || events != 0 {
				t.Fatalf("commit after promotion: view=%+v err=%v done=%d events=%d", commit, err, done, events)
			}
		} else if err != nil || commit.Outcome != "applied" || done == 0 || events != 1 {
			t.Fatalf("unchanged role commit: view=%+v err=%v done=%d events=%d", commit, err, done, events)
		}
	}
}
