//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestFlowPermissionsCanonicalHTTP(t *testing.T) {
	app, _ := auditApp(t)
	sid := seedMemberSession(t, app)
	uid := GetSessionFromDB(app.DB, sid).UserID
	mustExec(t, app.DB, "CREATE TABLE flow_effects (id INTEGER)")
	// Administrators remain bounded by credential scopes.
	if _, err := app.DB.Exec("UPDATE _benmore_users SET role='admin' WHERE id=?", uid); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "flows/scoped.yaml", `on:
  request:
    method: GET
    path: /api/scoped
    permissions: [notes:read, orgdocs:read]
jobs:
  read:
    steps:
      - query: INSERT INTO flow_effects VALUES (1)
      - run: respond
        with: {status: 200, body: {ok: true}}
`)
	flows, err := loadFlowsChecked(app.Dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 || len(flows[0].Permissions) != 2 {
		t.Fatalf("missing permissions: %+v", flows)
	}
	app.Flows = flows
	mux := http.NewServeMux()
	RegisterFlows(mux, app, flows)
	cases := []struct {
		scope  string
		status int
	}{
		{"", 401}, {"notes:read", 403}, {"orgdocs:read", 403},
		{"notes:read orgdocs:read", 200}, {"notes:write orgdocs:read", 200}, {"*", 200},
	}
	allowed := 0
	for _, tc := range cases {
		r := httptest.NewRequest("GET", "/api/scoped", nil)
		if tc.scope != "" {
			r.Header.Set("Authorization", "Bearer "+auditToken(t, app, sid, tc.scope))
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("scope %q: got %d %s, want %d", tc.scope, w.Code, w.Body.String(), tc.status)
		}
		if tc.status == 200 {
			allowed++
		}
		var count int
		if err := app.DB.QueryRow("SELECT count(*) FROM flow_effects").Scan(&count); err != nil || count != allowed {
			t.Fatalf("unauthorized work: count %d expected %d: %v", count, allowed, err)
		}
	}
	for _, scope := range []string{"notes:read", "notes:read orgdocs:read"} {
		actor := &Session{UserID: uid, Role: "admin", GlobalAdmin: true, Scopes: scope}
		want := scope == "notes:read orgdocs:read"
		if flowListedFor(flows[0], actor) != want {
			t.Fatalf("discovery widened scoped admin %q", scope)
		}
		_, err := schedulableFlow(app, flows[0].Name, actor)
		if (err == nil) != want {
			t.Fatalf("scheduling scope %q: %v", scope, err)
		}
	}
	// Existing unrestricted direct login remains usable.
	r := httptest.NewRequest("GET", "/api/scoped", nil)
	r.Header.Set("Authorization", "Bearer "+sid)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	if w.Code != 200 {
		t.Fatalf("direct login: %d %s", w.Code, w.Body.String())
	}
}

func TestFlowPermissionsRejectMalformedConfig(t *testing.T) {
	for _, declaration := range []string{"['']", "['*']", "['*:read']", "['notes:*']", "['notes:read notes:write']", "['notes:read', 'notes:read']", "[not_a_scope]", "['notes:* ']", "[' *:read']", "['notes:read', ' notes:read']", "notes:read", "[notes:read, {orgdocs: read}]"} {
		t.Run(declaration, func(t *testing.T) {
			dir := t.TempDir()
			source := "on:\n  request: {method: GET, path: /api/scoped, permissions: " + declaration + "}\njobs:\n  read:\n    steps:\n      - query: SELECT 1\n"
			writeTestFile(t, dir, "flows/scoped.yaml", source)
			if _, err := loadRuntimeConfig(dir); err == nil {
				t.Fatal("malformed scope accepted")
			}
			if msg := validateFlowsYAML(source); msg == "" {
				t.Fatalf("write validation: %q", msg)
			}
		})
	}
	dir := t.TempDir()
	writeTestFile(t, dir, "flows.yaml", "read:\n  trigger: GET /api/scoped\n  permissions: [notes:read]\n  steps:\n    - sql: SELECT 1\n")
	flows, err := loadFlowsChecked(dir, true)
	if err != nil || len(flows) != 1 || len(flows[0].Permissions) != 1 {
		t.Fatalf("legacy permission lost: %+v %v", flows, err)
	}
}
