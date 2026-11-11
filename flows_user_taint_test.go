//go:build !cli

package main

import (
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// profileTaintFlow wraps steps in an auth-required request flow that answers
// with the rows of step r.
func profileTaintFlow(steps string) string {
	return `on:
  request:
    method: POST
    path: /api/dyn
    auth: required
jobs:
  dyn:
    steps:
` + steps + `      - run: respond
        with: { status: 200, json: { rows: "${{ steps.r.outputs.rows }}" } }
`
}

// runProfileTaintFlow parses source as a deployed flow file (the loader only
// logs write-gate problems) and runs it as the session token's caller.
func runProfileTaintFlow(t *testing.T, app *App, source, token string) (*httptest.ResponseRecorder, error) {
	t.Helper()
	flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "dyn.yaml"), []byte(source))
	if err != nil || len(flows) != 1 {
		t.Fatalf("parse flow: %v (%d flows)", err, len(flows))
	}
	f := flows[0]
	req := httptest.NewRequest(f.Trigger.Method, f.Trigger.Path, strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	rr := httptest.NewRecorder()
	return rr, executeFlowHTTP(app, &f, rr, req)
}

// A signed-in caller writes first_name (PATCH /api/_auth/profile, signup).
// Written into sql_dynamic text it was SQL injection: the round 2026-11-05
// builder read every account's email through `${{ user.first_name }}`. The
// value is request input now, directly and when routed through a set or a
// SQL echo; the account columns the framework owns stay usable.
func TestFlowProfileValueIsRequestInputForSQLDynamic(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")
	mustExec(t, app.DB, `UPDATE _benmore_users SET first_name = 'x'' UNION SELECT email FROM _benmore_users --' WHERE email = 'bob@example.com'`)

	for name, steps := range map[string]string{
		"direct": `      - id: r
        run: sql_dynamic
        query: "SELECT '${{ user.first_name }}' AS v"
`,
		"through set": `      - id: s
        run: set
        with: { n: "${{ user.first_name }}" }
      - id: r
        run: sql_dynamic
        query: "SELECT '${{ steps.s.outputs.n }}' AS v"
`,
		"through a sql echo": `      - id: e
        run: sql
        query: "SELECT :n AS n"
        params: { n: "${{ user.first_name }}" }
      - id: r
        run: sql_dynamic
        query: "SELECT '${{ steps.e.outputs.first.n }}' AS v"
`,
	} {
		rr, err := runProfileTaintFlow(t, app, profileTaintFlow(steps), bob)
		if strings.Contains(rr.Body.String(), "admin@example.com") {
			t.Fatalf("%s: the profile value was run as SQL and read another account: %d %s", name, rr.Code, rr.Body.String())
		}
		if err == nil || !strings.Contains(err.Error(), "request-sourced") || rr.Code == 200 {
			t.Errorf("%s: want the sql_dynamic request-input refusal, got %d %v", name, rr.Code, err)
		}
	}
	_, err := runProfileTaintFlow(t, app, profileTaintFlow(`      - id: r
        run: sql_dynamic
        query: "SELECT '${{ user.first_name }}' AS v"
`), bob)
	if err == nil || !strings.Contains(err.Error(), "PATCH /api/_auth/profile") {
		t.Errorf("the refusal should say the value is a caller-written profile value: %v", err)
	}

	// The same in the job worker: an async flow carries the profile taint.
	EnsureJobsTable(app.DB)
	asyncFlows, perr := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "dyn.yaml"), []byte(`on:
  request:
    method: POST
    path: /api/dyn
    auth: required
    mode: async
jobs:
  dyn:
    steps:
      - id: r
        run: sql_dynamic
        query: "INSERT INTO probe_out (v) SELECT '${{ user.first_name }}'"
`))
	if perr != nil || len(asyncFlows) != 1 {
		t.Fatalf("parse async flow: %v", perr)
	}
	mustExec(t, app.DB, `CREATE TABLE probe_out (v TEXT)`)
	app.mu.Lock()
	app.Flows = asyncFlows
	app.mu.Unlock()
	req := httptest.NewRequest("POST", "/api/dyn", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+bob)
	rec := httptest.NewRecorder()
	if err := executeFlowHTTP(app, &asyncFlows[0], rec, req); err != nil || rec.Code != 202 {
		t.Fatalf("async enqueue: %d %v", rec.Code, err)
	}
	FlushJobs(app)
	var status, jobErr string
	if err := app.DB.QueryRow("SELECT status, COALESCE(error,'') FROM _benmore_jobs").Scan(&status, &jobErr); err != nil {
		t.Fatalf("read job: %v", err)
	}
	var leakedRows int
	app.DB.QueryRow("SELECT COUNT(*) FROM probe_out WHERE v LIKE '%@example.com'").Scan(&leakedRows)
	if status == "completed" || leakedRows > 0 || !strings.Contains(jobErr, "request-sourced") {
		t.Fatalf("async flow ran the profile value as SQL: status=%q error=%q leaked rows=%d", status, jobErr, leakedRows)
	}

	// The account columns the framework owns are still server values (the
	// email is identity too, but never SQL text: TestFlowEmailIsNeverSQLDynamicText).
	rr, err := runProfileTaintFlow(t, app, profileTaintFlow(`      - id: r
        run: sql_dynamic
        query: "SELECT ${{ user.id }} AS id, '${{ user.role }}' AS role, ${{ user.verified }} AS verified"
`), bob)
	if err != nil || rr.Code != 200 || !strings.Contains(rr.Body.String(), `"verified":1`) || !strings.Contains(rr.Body.String(), `"role":"user"`) {
		t.Fatalf("identity columns in sql_dynamic: %d %s %v", rr.Code, rr.Body.String(), err)
	}
}

// The profile columns are tainted and, like a data event's row, stored data:
// the groups: tenant columns and the framework's account columns are not.
func TestFlowUserProfileKeysSkipServerOwnedColumns(t *testing.T) {
	ctx := &FlowContext{
		App: &App{Group: &GroupConfig{Key: "org_id", RoleField: "member_role"}},
		Data: map[string]any{"user": map[string]any{
			"id": 7, "email": "a@example.com", "role": "user", "verified": 1, "created_at": "x",
			"last_login_at": "x", "deactivated_at": nil, "password_change_required": 0,
			"org_id": "o1", "member_role": "owner",
			"first_name": "A", "last_name": "B", "username": "a", "plan": "pro", "company": "C",
		}},
	}
	markFlowUserProfileInput(ctx)
	want := []string{"user.company", "user.first_name", "user.last_name", "user.plan", "user.username"}
	if got := flowUserProfileKeys(ctx); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("profile keys = %v, want %v", got, want)
	}
	for _, k := range want {
		if !ctx.isTainted(k) || !ctx.computedKeys[k] {
			t.Errorf("%s: tainted=%v computed=%v, want both", k, ctx.isTainted(k), ctx.computedKeys[k])
		}
	}
	for _, ref := range []string{"{{user.id}}", "{{user.email}}", "{{user.role}}", "{{user.org_id}}", "{{user.member_role}}", "{{user_email}}"} {
		if key := ctx.taintedRef(ref); key != "" {
			t.Errorf("%s reads server-owned identity but is tainted by %q", ref, key)
		}
	}
	if key := ctx.taintedRef("{{ user | json }}"); key == "" {
		t.Error("the whole user object holds profile values and must be tainted")
	}
}

// A profile value in the host of a `run: api` call that carries the app's
// env secret let the caller choose where the secret went (the builder's
// last_name "httpbin.org" received it). It is refused like a request field,
// also when routed through a set; in the path it is still sent.
func TestFlowProfileValueCannotChooseSecretCallHost(t *testing.T) {
	app := secretTaintApp(t)
	bob := createCrudScopeSession(t, app, "bob@example.com", "user", "", "")
	mustExec(t, app.DB, `UPDATE _benmore_users SET last_name = '8.8.4.4' WHERE email = 'bob@example.com'`)

	run := func(steps string) (error, *secretTaintRecorder) {
		t.Helper()
		flow := secretTaintFlow(t, "host", `on:
  request:
    method: POST
    path: /api/host
    auth: required
jobs:
  host:
    steps:
`+steps+`      - run: respond
        with: { status: 200, body: "ok" }
`)
		rec := &secretTaintRecorder{}
		req := httptest.NewRequest("POST", flow.Trigger.Path, strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+bob)
		return executeFlowHTTPAsWithAPIClient(app, &flow, httptest.NewRecorder(), req, nil, rec.client()), rec
	}
	for name, steps := range map[string]string{
		"direct": `      - id: call
        run: api
        with:
          method: POST
          url: "https://${{ user.last_name }}/anything"
          json: { key: "${{ env.CLIENT_SECRET }}" }
`,
		"through set": `      - id: s
        run: set
        with: { h: "${{ user.last_name }}" }
      - id: call
        run: api
        with:
          method: POST
          url: "https://${{ steps.s.outputs.h }}/anything"
          json: { key: "${{ env.CLIENT_SECRET }}" }
`,
	} {
		err, rec := run(steps)
		if leaked := rec.leaked(); len(leaked) > 0 {
			t.Fatalf("%s: the env secret went to the host the caller wrote into their profile: %v", name, leaked)
		}
		if err == nil || !strings.Contains(err.Error(), "may not choose the scheme or host") {
			t.Errorf("%s: want the host refusal, got %v", name, err)
		}
	}

	// In the path the profile value is only data: the call goes to the
	// author's host.
	err, rec := run(`      - id: call
        run: api
        with:
          method: POST
          url: "https://8.8.8.8/users/${{ user.last_name }}"
          json: { key: "${{ env.CLIENT_SECRET }}" }
`)
	if err != nil || len(rec.sent) != 1 || !strings.HasPrefix(rec.sent[0], "https://8.8.8.8/users/8.8.4.4") {
		t.Fatalf("profile value in the path: err %v sent %v", err, rec.sent)
	}
}

// The write gate and `benmore check` refuse both shapes up front; the
// framework's account columns and a profile value in the path pass.
func TestWriteGateRefusesProfileValueAsRequestInput(t *testing.T) {
	dyn := func(expr string) string {
		return profileTaintFlow("      - id: r\n        run: sql_dynamic\n        query: \"SELECT '" + expr + "' AS v\"\n")
	}
	// (The whole `${{ user }}` object is a bare reference, which the existing
	// sql_dynamic check already refuses.)
	for _, expr := range []string{"${{ user.first_name }}", "${{ user.company | upper }}", "${{ user.nickname || user.email }}"} {
		if msg := ValidateOnWrite("flows/dyn.yaml", dyn(expr)); !strings.Contains(msg, "a profile value the caller writes") {
			t.Errorf("sql_dynamic %s: write gate = %q", expr, msg)
		}
	}
	for _, expr := range []string{"${{ user.id }}", "${{ user.role }}", "${{ user.verified }}", "${{ user.group_id }}", "${{ user.org_id }}"} {
		if msg := ValidateOnWrite("flows/dyn.yaml", dyn(expr)); msg != "" {
			t.Errorf("sql_dynamic %s is server-owned: write gate = %q", expr, msg)
		}
	}
	// A server-owned step output (the step must exist: an unknown step id is
	// refused on its own).
	stepOut := profileTaintFlow("      - id: x\n        run: sql\n        query: \"SELECT 'invoices' AS v\"\n" +
		"      - id: r\n        run: sql_dynamic\n        query: \"SELECT COUNT(*) AS n FROM ${{ steps.x.outputs.first.v }}\"\n")
	if msg := ValidateOnWrite("flows/dyn.yaml", stepOut); msg != "" {
		t.Errorf("sql_dynamic over a server-owned step output: write gate = %q", msg)
	}
	// The email is identity, but never sql_dynamic text.
	if msg := ValidateOnWrite("flows/dyn.yaml", dyn("${{ user.email }}")); !strings.Contains(msg, "the caller's email address") {
		t.Errorf("sql_dynamic ${{ user.email }}: write gate = %q", msg)
	}
	// with.query is the same statement.
	if msg := ValidateOnWrite("flows/dyn.yaml", profileTaintFlow("      - id: r\n        run: sql_dynamic\n        with: { query: \"SELECT '${{ user.last_name }}' AS v\" }\n")); !strings.Contains(msg, "user.last_name") {
		t.Errorf("sql_dynamic with.query: write gate = %q", msg)
	}

	api := func(url, extra string) string {
		return `on:
  request:
    method: POST
    path: /api/relay
    auth: required
jobs:
  main:
    steps:
      - id: call
        run: api
        with:
          url: "` + url + `"` + extra + `
      - run: respond
        with: { status: 200, body: "ok" }
`
	}
	const envHeader = "\n          headers: { X-Api-Key: \"${{ env.ECHO_API_KEY }}\" }"
	msg := ValidateOnWrite("flows/relay.yaml", api("https://${{ user.last_name }}/anything", envHeader))
	if !strings.Contains(msg, "would choose the scheme or host") || !strings.Contains(msg, "user.last_name") || !strings.Contains(msg, "written by the caller") {
		t.Fatalf("profile value as the host of a credentialed call: write gate = %q", msg)
	}
	for name, src := range map[string]string{
		"profile value in the path": api("https://api.example.com/u/${{ user.last_name }}", envHeader),
		"no credentials":            api("https://${{ user.last_name }}/anything", ""),
	} {
		if msg := ValidateOnWrite("flows/relay.yaml", src); strings.Contains(msg, "would choose the scheme or host") {
			t.Errorf("%s: write gate = %q", name, msg)
		}
	}
}

// The email is the caller's identity, but its text was chosen at signup and
// validAuthEmail accepts quotes and SQL comment characters, so an address
// spliced into sql_dynamic text was SQL injection. It is never sql_dynamic
// text, directly, as `{{user_email}}`, through a set, a SQL echo or an
// enqueue payload; bound with `:user_email` in `run: sql` it is still the
// caller's address, and it stays trusted outside sql_dynamic (a value a SQL
// step built from it may still name a credentialed call's host).
func TestFlowEmailIsNeverSQLDynamicText(t *testing.T) {
	app := secretTaintApp(t)
	const addr = "x'union/**/select/**/email/**/from/**/_benmore_users--@example.com"
	if !validAuthEmail(addr) {
		t.Fatalf("signup refuses %q now; pick an address it accepts", addr)
	}
	mallory := createCrudScopeSession(t, app, addr, "user", "", "")
	createCrudScopeSession(t, app, "admin@example.com", "admin", "", "")

	for name, steps := range map[string]string{
		"user.email": `      - id: r
        run: sql_dynamic
        query: "SELECT '${{ user.email }}' AS v"
`,
		"through set": `      - id: s
        run: set
        with: { e: "${{ user.email }}" }
      - id: r
        run: sql_dynamic
        query: "SELECT '${{ steps.s.outputs.e }}' AS v"
`,
		"through a sql echo": `      - id: e
        run: sql
        query: "SELECT :user_email AS e"
      - id: r
        run: sql_dynamic
        query: "SELECT '${{ steps.e.outputs.first.e }}' AS v"
`,
	} {
		rr, err := runProfileTaintFlow(t, app, profileTaintFlow(steps), mallory)
		if strings.Contains(rr.Body.String(), "admin@example.com") {
			t.Fatalf("%s: the address was run as SQL and read another account: %d %s", name, rr.Code, rr.Body.String())
		}
		if err == nil || !strings.Contains(err.Error(), "email address") || rr.Code == 200 {
			t.Errorf("%s: want the sql_dynamic email refusal, got %d %v", name, rr.Code, err)
		}
	}

	// The bare form (the write gate already refuses it as a request-param
	// shape, so it is built directly) and an enqueue payload.
	EnsureJobsTable(app.DB)
	worker := Flow{Name: "worker", Trigger: FlowTrigger{Type: "job"}, Steps: []FlowStep{
		{Name: "q", Type: "sql_dynamic", SQL: "SELECT '{{addr}}' AS v"},
	}}
	app.mu.Lock()
	app.Flows = []Flow{worker}
	app.mu.Unlock()
	run := func(steps ...FlowStep) error {
		t.Helper()
		steps = append(steps, FlowStep{Type: "respond", Respond: &FlowRespond{Status: 200, Body: "ok"}})
		flow := Flow{Name: "front", Auth: "required", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/front"}, Steps: steps}
		req := httptest.NewRequest("POST", "/api/front", strings.NewReader(`{}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+mallory)
		return executeFlowHTTP(app, &flow, httptest.NewRecorder(), req)
	}
	if err := run(FlowStep{Name: "q", Type: "sql_dynamic", SQL: "SELECT '{{user_email}}' AS v"}); err == nil || !strings.Contains(err.Error(), "email address") {
		t.Errorf("bare {{user_email}}: want the email refusal, got %v", err)
	}
	enqueue := func(addrValue string) (status, jobErr string) {
		t.Helper()
		app.DB.Exec(`DELETE FROM _benmore_jobs`)
		if err := run(FlowStep{Name: "e", Type: "enqueue", Enqueue: &FlowEnqueue{Flow: "worker", With: map[string]string{"addr": addrValue}}}); err != nil {
			t.Fatalf("enqueue flow: %v", err)
		}
		FlushJobs(app)
		if err := app.DB.QueryRow(`SELECT status, COALESCE(error,'') FROM _benmore_jobs WHERE flow_name = 'worker'`).Scan(&status, &jobErr); err != nil {
			t.Fatalf("read job: %v", err)
		}
		return status, jobErr
	}
	if status, jobErr := enqueue("{{user_email}}"); status == "completed" || !strings.Contains(jobErr, "email address") {
		t.Errorf("enqueued address reached sql_dynamic in the job flow: status=%q error=%q", status, jobErr)
	}
	if status, jobErr := enqueue("literal"); status != "completed" {
		t.Errorf("control: a literal payload must run: status=%q error=%q", status, jobErr)
	}

	// Bound in `run: sql`, the address is the caller's own, quotes and all.
	rr, err := runProfileTaintFlow(t, app, profileTaintFlow(`      - id: r
        run: sql
        query: "SELECT COUNT(*) AS n FROM _benmore_users WHERE email = :user_email"
`), mallory)
	if err != nil || rr.Code != 200 || !strings.Contains(rr.Body.String(), `"n":1`) {
		t.Fatalf("bound address in run: sql: %d %s %v", rr.Code, rr.Body.String(), err)
	}

	// Outside sql_dynamic the address stays identity: a SQL step that reads
	// it may still choose the host of a credentialed call.
	flow := secretTaintFlow(t, "hook", `on:
  request:
    method: POST
    path: /api/hook
    auth: required
jobs:
  hook:
    steps:
      - id: b
        run: sql
        query: "SELECT 'https://8.8.8.8' AS base WHERE :user_email <> ''"
      - id: call
        run: api
        with:
          method: POST
          url: "${{ steps.b.outputs.first.base }}/hook"
          json: { key: "${{ env.CLIENT_SECRET }}" }
      - run: respond
        with: { status: 200, body: "ok" }
`)
	rec := &secretTaintRecorder{}
	req := httptest.NewRequest("POST", "/api/hook", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+mallory)
	if err := executeFlowHTTPAsWithAPIClient(app, &flow, httptest.NewRecorder(), req, nil, rec.client()); err != nil || len(rec.sent) != 1 || !strings.HasPrefix(rec.sent[0], "https://8.8.8.8/hook") {
		t.Fatalf("email-keyed host lookup: err %v sent %v", err, rec.sent)
	}
}
