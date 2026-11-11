//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"
)

// scopedFlowFixture is an app with one flow of each authorization shape: an
// auth-required write, a role: flow, a flow that declares permissions:, a
// public flow and an auth: optional flow. Every flow records the user id it
// ran for in flow_effects, so a test can tell "refused before any step" from
// "ran" and see which identity a run was bound to.
func scopedFlowFixture(t *testing.T) (*App, *http.ServeMux, string, int64) {
	t.Helper()
	app, _ := auditApp(t)
	sid := seedMemberSession(t, app)
	uid := GetSessionFromDB(app.DB, sid).UserID
	mustExec(t, app.DB, "UPDATE _benmore_users SET role = 'manager' WHERE id = "+strconv.FormatInt(uid, 10))
	mustExec(t, app.DB, "CREATE TABLE flow_effects (id INTEGER PRIMARY KEY AUTOINCREMENT, kind TEXT, user_id INTEGER)")
	flow := func(name, trigger string) {
		writeTestFile(t, app.Dir, "flows/"+name+".yaml", "on:\n  request:\n"+trigger+`jobs:
  run:
    steps:
      - run: sql
        with: { query: "INSERT INTO flow_effects (kind, user_id) VALUES ('`+name+`', :user_id)" }
      - run: respond
        with: { status: 201, body: { ok: true } }
`)
	}
	flow("write", "    method: POST\n    path: /api/request-day-off\n    auth: required\n")
	flow("role", "    method: POST\n    path: /api/team-summary\n    auth: required\n    role: manager\n")
	flow("permitted", "    method: POST\n    path: /api/scoped-write\n    auth: required\n    permissions: [notes:write]\n")
	flow("public", "    method: POST\n    path: /api/public-ping\n    auth: none\n")
	flow("optional", "    method: POST\n    path: /api/optional-ping\n    auth: optional\n")
	flows, err := loadFlowsChecked(app.Dir, true)
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 5 {
		t.Fatalf("loaded %d flows, want 5", len(flows))
	}
	app.Flows = flows
	mux := http.NewServeMux()
	RegisterFlows(mux, app, flows)
	return app, mux, sid, uid
}

// flowEffect returns how many runs of the named flow were recorded and the
// user id of the latest (-1 when that run was bound to no user).
func flowEffect(t *testing.T, app *App, kind string) (int, int64) {
	t.Helper()
	var n int
	var uid int64 = -1
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM flow_effects WHERE kind = ?", kind).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n > 0 {
		if err := app.DB.QueryRow("SELECT COALESCE(user_id, -1) FROM flow_effects WHERE kind = ? ORDER BY id DESC LIMIT 1", kind).Scan(&uid); err != nil {
			t.Fatal(err)
		}
	}
	return n, uid
}

func callFlowBearer(mux *http.ServeMux, path, cred string) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", path, strings.NewReader(`{"day":"2027-01-02"}`))
	r.Header.Set("Content-Type", "application/json")
	if cred != "" {
		r.Header.Set("Authorization", "Bearer "+cred)
	}
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// F1 (round 1105): a token minted with notes:read is a delegated, narrowed
// credential. Auto-CRUD narrows it, and flows that declare permissions:
// check it, but an auth-required flow, a role: flow and the identity a
// public flow binds took it as the full account: a read-only token wrote
// through a flow. With the operator's switch on, such a credential reaches a
// flow as its user only through the flow's declared permissions.
func TestScopedCredentialNeedsFlowPermissions(t *testing.T) {
	t.Setenv(scopedFlowsRequirePermissionsEnv, "1")
	app, mux, sid, uid := scopedFlowFixture(t)
	readOnlyToken := auditToken(t, app, sid, "notes:read")
	readOnlySession := CreateSession(app.DB, uid, "member@test.local", "", time.Hour, "notes:read")

	for _, cred := range []string{readOnlyToken, readOnlySession} {
		for _, c := range []struct{ path, kind string }{
			{"/api/request-day-off", "write"},
			{"/api/team-summary", "role"},
			{"/api/scoped-write", "permitted"}, // notes:read does not cover notes:write
		} {
			before, _ := flowEffect(t, app, c.kind)
			w := callFlowBearer(mux, c.path, cred)
			if w.Code != http.StatusForbidden {
				t.Fatalf("scoped credential on %s: %d %s, want 403", c.path, w.Code, w.Body.String())
			}
			if after, _ := flowEffect(t, app, c.kind); after != before {
				t.Fatalf("scoped credential ran %s before it was refused", c.path)
			}
			if c.kind != "permitted" {
				var body map[string]any
				_ = json.Unmarshal(w.Body.Bytes(), &body)
				if msg, _ := body["error"].(string); !strings.Contains(msg, "permissions:") {
					t.Fatalf("refusal on %s does not name the fix: %s", c.path, w.Body.String())
				}
			}
		}
		// Public and optional flows still answer, as they would for a caller
		// with no credential: the narrowed token is not bound as the user.
		for _, c := range []struct{ path, kind string }{
			{"/api/public-ping", "public"},
			{"/api/optional-ping", "optional"},
		} {
			before, _ := flowEffect(t, app, c.kind)
			if w := callFlowBearer(mux, c.path, cred); w.Code != http.StatusCreated {
				t.Fatalf("scoped credential on public %s: %d %s", c.path, w.Code, w.Body.String())
			}
			if after, bound := flowEffect(t, app, c.kind); after != before+1 || bound != -1 {
				t.Fatalf("scoped credential on %s ran as user %d (runs %d -> %d), want anonymous", c.path, bound, before, after)
			}
		}
	}

	// A credential whose scopes cover the flow's permissions runs it as its user.
	writer := auditToken(t, app, sid, "notes:write")
	if w := callFlowBearer(mux, "/api/scoped-write", writer); w.Code != http.StatusCreated {
		t.Fatalf("permitted scoped credential: %d %s", w.Code, w.Body.String())
	}
	if n, bound := flowEffect(t, app, "permitted"); n != 1 || bound != uid {
		t.Fatalf("permitted flow: runs %d bound to %d, want 1 run for user %d", n, bound, uid)
	}
	// The scope still does not open the flows that declare nothing.
	if w := callFlowBearer(mux, "/api/request-day-off", writer); w.Code != http.StatusForbidden {
		t.Fatalf("notes:write token on a flow without permissions: %d %s", w.Code, w.Body.String())
	}
	if n, _ := flowEffect(t, app, "write"); n != 0 {
		t.Fatalf("write flow ran %d times for scoped credentials", n)
	}

	// Unscoped credentials keep today's behaviour exactly: a full-access
	// token, an unscoped Bearer session and a cookie session run every flow
	// as the user.
	full := auditToken(t, app, sid, "*")
	for i, cred := range []string{full, sid} {
		for _, c := range []struct{ path, kind string }{
			{"/api/request-day-off", "write"},
			{"/api/team-summary", "role"},
			{"/api/scoped-write", "permitted"},
			{"/api/public-ping", "public"},
			{"/api/optional-ping", "optional"},
		} {
			before, _ := flowEffect(t, app, c.kind)
			if w := callFlowBearer(mux, c.path, cred); w.Code != http.StatusCreated {
				t.Fatalf("unscoped credential %d on %s: %d %s", i, c.path, w.Code, w.Body.String())
			}
			if after, bound := flowEffect(t, app, c.kind); after != before+1 || bound != uid {
				t.Fatalf("unscoped credential %d on %s: runs %d -> %d bound to %d, want user %d", i, c.path, before, after, bound, uid)
			}
		}
	}
	for _, c := range []struct{ path, kind string }{
		{"/api/request-day-off", "write"},
		{"/api/team-summary", "role"},
		{"/api/public-ping", "public"},
	} {
		before, _ := flowEffect(t, app, c.kind)
		r := httptest.NewRequest("POST", c.path, strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
		r.AddCookie(sessionCookie(sid, true, time.Hour))
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusCreated {
			t.Fatalf("cookie session on %s: %d %s", c.path, w.Code, w.Body.String())
		}
		if after, bound := flowEffect(t, app, c.kind); after != before+1 || bound != uid {
			t.Fatalf("cookie session on %s: runs %d -> %d bound to %d", c.path, before, after, bound)
		}
	}
	// Anonymous callers still get 401 on an auth-required flow.
	if w := callFlowBearer(mux, "/api/request-day-off", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous on auth-required flow: %d", w.Code)
	}
}

// A scheduled flow runs later under the credential that scheduled it, so,
// with the switch on, a narrowed credential may schedule only a flow it
// could call directly.
func TestScopedCredentialSchedulingNeedsFlowPermissions(t *testing.T) {
	t.Setenv(scopedFlowsRequirePermissionsEnv, "1")
	app, _, _, uid := scopedFlowFixture(t)
	scoped := &Session{UserID: uid, Role: "manager", Roles: []string{"manager"}, Scopes: "notes:write", CredentialScopes: "notes:write"}
	unscoped := &Session{UserID: uid, Role: "manager", Roles: []string{"manager"}}
	for _, name := range []string{"write", "role", "public", "optional"} {
		if _, err := schedulableFlow(app, name, scoped); err == nil || !strings.Contains(err.Error(), "permissions") {
			t.Fatalf("scoped credential scheduled %s: %v", name, err)
		}
		if _, err := schedulableFlow(app, name, unscoped); err != nil {
			t.Fatalf("unscoped credential could not schedule %s: %v", name, err)
		}
	}
	if _, err := schedulableFlow(app, "permitted", scoped); err != nil {
		t.Fatalf("scoped credential could not schedule a flow within its scopes: %v", err)
	}
	// /_internal/flows.json lists only what the caller can call.
	callable := map[string]bool{"permitted": true, "public": true, "optional": true}
	for _, f := range app.Flows {
		if got := flowListedFor(f, scoped); got != callable[f.Name] {
			t.Fatalf("flow %s listed=%v for a scoped credential, want %v", f.Name, got, callable[f.Name])
		}
		if !flowListedFor(f, unscoped) {
			t.Fatalf("flow %s hidden from an unscoped credential", f.Name)
		}
	}
}

// Until the operator turns the switch on, the rule is advisory: a scoped
// credential still runs every flow as before (hosted partner APIs depend on
// it), and the app log names each flow it reached without permissions:, once
// per app and flow every ten minutes, with the fix.
func TestScopedCredentialFlowsAdvisoryByDefault(t *testing.T) {
	t.Setenv(scopedFlowsRequirePermissionsEnv, "")
	app, mux, sid, uid := scopedFlowFixture(t)
	scopedFlowAdvisoryLogged.Range(func(k, _ any) bool { scopedFlowAdvisoryLogged.Delete(k); return true })
	var logged bytes.Buffer
	log.SetOutput(&logged)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })

	scoped := auditToken(t, app, sid, "notes:read")
	for round := 0; round < 2; round++ {
		for _, kind := range []string{"write", "role", "public", "optional"} {
			path := map[string]string{"write": "/api/request-day-off", "role": "/api/team-summary", "public": "/api/public-ping", "optional": "/api/optional-ping"}[kind]
			before, _ := flowEffect(t, app, kind)
			if w := callFlowBearer(mux, path, scoped); w.Code != http.StatusCreated {
				t.Fatalf("advisory mode refused %s: %d %s", path, w.Code, w.Body.String())
			}
			if after, bound := flowEffect(t, app, kind); after != before+1 || bound != uid {
				t.Fatalf("advisory mode changed %s: runs %d -> %d bound to %d, want user %d", path, before, after, bound, uid)
			}
		}
	}
	out := logged.String()
	for _, kind := range []string{"write", "role", "public", "optional"} {
		if n := strings.Count(out, "flow "+kind+" ["); n != 1 {
			t.Fatalf("flow %s logged %d times for two calls, want once:\n%s", kind, n, out)
		}
	}
	for _, want := range []string{`(scopes "notes:read")`, "declare on.request.permissions:", "A later release refuses this (403)", "as for an anonymous caller"} {
		if !strings.Contains(out, want) {
			t.Fatalf("advisory log lacks %q:\n%s", want, out)
		}
	}

	// A flow with permissions within the token's scopes is not noted, and
	// neither is an unscoped credential.
	logged.Reset()
	if w := callFlowBearer(mux, "/api/scoped-write", auditToken(t, app, sid, "notes:write")); w.Code != http.StatusCreated {
		t.Fatalf("permitted flow: %d %s", w.Code, w.Body.String())
	}
	scopedFlowAdvisoryLogged.Range(func(k, _ any) bool { scopedFlowAdvisoryLogged.Delete(k); return true })
	if w := callFlowBearer(mux, "/api/request-day-off", auditToken(t, app, sid, "*")); w.Code != http.StatusCreated {
		t.Fatalf("unscoped token: %d %s", w.Code, w.Body.String())
	}
	if strings.Contains(logged.String(), "scoped API token") {
		t.Fatalf("advisory noted a permitted or unscoped call:\n%s", logged.String())
	}

	// Scheduling and flow discovery keep their behaviour too.
	actor := &Session{UserID: uid, Role: "manager", Roles: []string{"manager"}, Scopes: "notes:read", CredentialScopes: "notes:read"}
	for _, f := range app.Flows {
		if _, err := schedulableFlow(app, f.Name, actor); f.Name != "permitted" && err != nil {
			t.Fatalf("advisory mode refused scheduling %s: %v", f.Name, err)
		}
		if f.Name != "permitted" && !flowListedFor(f, actor) {
			t.Fatalf("advisory mode hid %s from flows.json", f.Name)
		}
	}
}

// The switch is the operator's: an app's env.yaml can neither turn it on nor
// off, and app code never sees it (BENMORE_PLATFORM_* is runtime-private).
func TestScopedFlowsSwitchIgnoresAppEnvironment(t *testing.T) {
	for _, process := range []string{"", "1"} {
		t.Setenv(scopedFlowsRequirePermissionsEnv, process)
		dir := t.TempDir()
		appValue := "1"
		if process == "1" {
			appValue = "0"
		}
		writeTestFile(t, dir, "env.yaml", scopedFlowsRequirePermissionsEnv+": \""+appValue+"\"\n")
		if err := LoadEnv(dir); err != nil {
			t.Fatal(err)
		}
		if got := scopedFlowsRequirePermissions(); got != (process == "1") {
			t.Fatalf("env.yaml %s=%s changed the switch: enforced=%v with process value %q", scopedFlowsRequirePermissionsEnv, appValue, got, process)
		}
		if v := GetAppEnv(dir, scopedFlowsRequirePermissionsEnv); v != "" {
			t.Fatalf("app environment exposes the switch: %q", v)
		}
	}
}

// GET /api/_auth/users and /{id} list people (email, name, role). A
// narrowed credential reads them only when it carries _benmore_users:read,
// the scope named after the directory's access: key; unscoped credentials
// keep today's behaviour, also in an app whose role scopes never list it.
func TestScopedCredentialUserDirectoryNeedsScope(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	app.Access.rules["_benmore_users"] = map[AccessOp]string{OpRead: "everyone"}
	mux := http.NewServeMux()
	RegisterSettingsRoutes(mux, app)
	sid := seedMemberSession(t, app)
	uid := GetSessionFromDB(app.DB, sid).UserID
	res, err := app.DB.Exec(`INSERT INTO _benmore_users (username, email, password_hash, role) VALUES ('other', 'other@test.local', 'x', 'user')`)
	if err != nil {
		t.Fatal(err)
	}
	other, _ := res.LastInsertId()

	get := func(path, cred string, cookie bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest("GET", path, nil)
		if cookie {
			r.AddCookie(sessionCookie(cred, true, time.Hour))
		} else {
			r.Header.Set("Authorization", "Bearer "+cred)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	paths := []string{"/api/_auth/users", "/api/_auth/users/" + strconv.FormatInt(other, 10), "/api/_auth/users/" + strconv.FormatInt(uid, 10)}
	denied := []string{
		auditToken(t, app, sid, "notes:read"),
		auditToken(t, app, sid, "notes:write orgdocs:read"),
		CreateSession(app.DB, uid, "member@test.local", "", time.Hour, "notes:read"),
	}
	for _, cred := range denied {
		for _, path := range paths {
			if w := get(path, cred, false); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "other@test.local") {
				t.Fatalf("scoped credential without _benmore_users:read on %s: %d %s", path, w.Code, w.Body.String())
			}
		}
	}
	allowed := func(label, cred string, cookie bool) {
		t.Helper()
		w := get("/api/_auth/users", cred, cookie)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "other@test.local") {
			t.Fatalf("%s list: %d %s", label, w.Code, w.Body.String())
		}
		if w := get(paths[1], cred, cookie); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "other@test.local") {
			t.Fatalf("%s lookup: %d %s", label, w.Code, w.Body.String())
		}
	}
	allowed("_benmore_users:read token", auditToken(t, app, sid, "_benmore_users:read"), false)
	allowed("*:read token", auditToken(t, app, sid, "*:read"), false)
	allowed("full token", auditToken(t, app, sid, "*"), false)
	allowed("bearer session", sid, false)
	allowed("cookie session", sid, true)

	// Role scopes name app tables, not the directory: an unscoped sign-in in
	// an app with roles: is still governed by the access: rule alone.
	app.Roles = &RolesConfig{Roles: map[string]RoleDef{"user": {Scopes: "notes:read"}}}
	allowed("cookie session with roles", sid, true)
	for _, path := range paths {
		if w := get(path, denied[0], false); w.Code != http.StatusForbidden {
			t.Fatalf("scoped credential with roles on %s: %d %s", path, w.Code, w.Body.String())
		}
	}
}
