//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
)

// sharingOffDialogApp turns record sharing off for the app and back on for
// docs, so one fixture has a table of each kind. The owner (team 1) has doc 1
// and tasks 1 and 2; each task holds a grant stored before sharing was turned
// off. The reader is a signed-in account outside the team.
func sharingOffDialogApp(t *testing.T) (app *App, mux *http.ServeMux, owner, reader string) {
	t.Helper()
	app, mux = sharingSwitchApp(t, sharingSwitchBase+"features:\n  sharing: off\naccess:\n  docs:\n    all: self\n    share: on\n")
	owner = createCrudScopeSession(t, app, "owner@example.com", "user", "1", "")
	reader = createCrudScopeSession(t, app, "reader@example.com", "user", "", "")
	crudScopeMustExec(t, app.DB, `INSERT INTO team_members (team_id, user_id) VALUES (1, 1)`)
	assertStatus(t, mux, http.MethodPost, "/api/docs", owner, map[string]any{"title": "plan"}, http.StatusOK)
	assertStatus(t, mux, http.MethodPost, "/api/notes", owner, map[string]any{"title": "team note"}, http.StatusOK)
	assertStatus(t, mux, http.MethodPost, "/api/tasks", owner, map[string]any{"title": "first"}, http.StatusOK)
	assertStatus(t, mux, http.MethodPost, "/api/tasks", owner, map[string]any{"title": "second"}, http.StatusOK)
	EnsurePermissionsTable(app.DB)
	crudScopeMustExec(t, app.DB, `INSERT INTO _benmore_permissions (resource_type, resource_id, grant_type, grantee_id, permission, granted_by) VALUES
		('tasks', '1', 'user', 'stored@example.com', 'view', 1),
		('tasks', '2', 'user', 'second@example.com', 'edit', 1)`)
	return app, mux, owner, reader
}

// /api/_schema tells a client whether record sharing is in force on each
// table: capabilities.sharing is there for every table, true or false, so a
// client can hide its share control without a request per row.
func TestRichSchemaReportsTheSharingSwitchForEveryTable(t *testing.T) {
	_, mux, owner, reader := sharingOffDialogApp(t)
	for name, token := range map[string]string{"owner": owner, "outside reader": reader} {
		rec := crudScopeRequest(t, mux, http.MethodGet, "/api/_schema", token, nil)
		var got struct {
			Tables map[string]struct {
				Capabilities map[string]any `json:"capabilities"`
			} `json:"tables"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || rec.Code != http.StatusOK {
			t.Fatalf("%s: GET /api/_schema: %d %s", name, rec.Code, rec.Body.String())
		}
		if len(got.Tables) == 0 {
			t.Fatalf("%s: the descriptor lists no table: %s", name, rec.Body.String())
		}
		for table, desc := range got.Tables {
			want := table == "docs" // on for docs, off everywhere else
			if on, isBool := desc.Capabilities["sharing"].(bool); !isBool || on != want {
				t.Errorf("%s: %s capabilities.sharing = %v, want %v as a boolean: %v", name, table, desc.Capabilities["sharing"], want, desc.Capabilities)
			}
			if _, isBool := desc.Capabilities["soft_delete"].(bool); !isBool {
				t.Errorf("%s: %s lost capabilities.soft_delete: %v", name, table, desc.Capabilities)
			}
		}
		if _, listed := got.Tables["tasks"]; !listed {
			t.Errorf("%s: tasks is not in the descriptor: %s", name, rec.Body.String())
		}
	}
	// The descriptor agrees with what the share endpoint does.
	assertStatus(t, mux, http.MethodPost, "/api/docs/1/share", owner, map[string]any{"email": "peer@example.com", "permission": "view"}, http.StatusOK)
	rec := crudScopeRequest(t, mux, http.MethodPost, "/api/tasks/1/share", owner, map[string]any{"email": "peer@example.com", "permission": "view"})
	if rec.Code != http.StatusForbidden || !strings.Contains(rec.Body.String(), sharingDisabledCode) {
		t.Fatalf("share on tasks: %d %s, want 403 %s", rec.Code, rec.Body.String(), sharingDisabledCode)
	}
}

// The browser SDK's share dialog, run against the real endpoints: on a table
// whose sharing is off it shows the "turned off" state instead of a form whose
// submit can only be refused.
func TestSDUIShareDialogShowsSharingTurnedOff(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping component integration")
	}
	app, mux, owner, reader := sharingOffDialogApp(t)
	server := httptest.NewServer(mux)
	defer server.Close()
	cmd := exec.Command(node, "embedded/sdui_share_dialog_sharing_off_test.mjs")
	cmd.Env = append(os.Environ(), "BM_TEST_URL="+server.URL, "BM_TEST_OWNER="+owner, "BM_TEST_READER="+reader)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ShareDialog sharing-off check failed: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "ShareDialog sharing-off state passed") {
		t.Fatalf("missing success: %s", output)
	}
	// Nothing was shared on the tables whose sharing is off; the one revoke
	// the dialog made is the only change there.
	var grantees string
	if err := app.DB.QueryRow(`SELECT COALESCE(group_concat(grantee_id, ','), '') FROM (SELECT grantee_id FROM _benmore_permissions WHERE resource_type = 'tasks' ORDER BY grantee_id)`).Scan(&grantees); err != nil {
		t.Fatal(err)
	}
	if grantees != "second@example.com" {
		t.Errorf("grants on tasks after the dialog run = %q, want only second@example.com", grantees)
	}
}
