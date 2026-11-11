//go:build !cli

package main

// A step whose id is one of the runtime's identity names (`id: user`) wrote
// its outputs where the signed-in caller's values are read, so every
// `${{ user.* }}` after it was the step's row: a lookup of another account
// stood in for the caller for the rest of the flow.

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func identityStepApp(t *testing.T) (*App, int64, string, int64) {
	t.Helper()
	app := newGateApp(t,
		`CREATE TABLE accounts (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, email TEXT, role TEXT, plan_name TEXT)`,
		`CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT, user_id INTEGER)`)
	caller, sid := gateUser(t, app, "ann@example.com")
	other := caller + 41
	mustExec(t, app.DB, fmt.Sprintf(`INSERT INTO accounts (id, user_id, email, role, plan_name) VALUES (%d, %d, 'target@example.com', 'admin', 'scale')`, other, other))
	return app, caller, sid, other
}

func TestStepNamedLikeTheCallerDoesNotReplaceTheCaller(t *testing.T) {
	app, caller, sid, other := identityStepApp(t)
	flow := `on:
  request:
    method: POST
    path: /api/lookup
    auth: required
jobs:
  lookup:
    steps:
      - id: user
        run: sql
        with: { query: "SELECT user_id AS id, email, role, plan_name FROM accounts WHERE id = :target" }
      - id: wrote
        run: sql
        with:
          query: "INSERT INTO notes (body, user_id) VALUES (:body, :owner) RETURNING user_id"
          params: { body: "${{ user.email }}", owner: "${{ user.id }}" }
      - run: respond
        with:
          status: 200
          json:
            caller_id: "${{ user.id }}"
            caller_email: "${{ user.email }}"
            caller_role: "${{ user.role }}"
            step_id: "${{ steps.user.outputs.id }}"
            step_email: "${{ steps.user.outputs.email }}"
            step_role: "${{ steps.user.outputs.role }}"
            step_plan: "${{ steps.user.outputs.plan_name }}"
            plan_through_user: "${{ user.plan_name }}"
            bound_user_id: "${{ steps.wrote.outputs.user_id }}"
`
	rr := runProbeGHAFlow(t, app, flow, fmt.Sprintf(`{"target":%d}`, other), "Authorization", "Bearer "+sid)
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	body := rr.Body.String()
	for _, want := range []string{
		// The caller stays the caller.
		fmt.Sprintf(`"caller_id":%d`, caller), `"caller_email":"ann@example.com"`, `"caller_role":"user"`,
		fmt.Sprintf(`"bound_user_id":%d`, caller),
		// The step's outputs are read by its id.
		fmt.Sprintf(`"step_id":%d`, other), `"step_email":"target@example.com"`, `"step_role":"admin"`, `"step_plan":"scale"`,
		// A name the caller's own values do not have still reads the step's output.
		`"plan_through_user":"scale"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the answer does not hold %s:\n%s", want, body)
		}
	}
	if got := gateScalar(t, app, `SELECT body || '/' || user_id FROM notes`); got != fmt.Sprintf("ann@example.com/%d", caller) {
		t.Errorf("the note was written as %q, want the caller's email and id", got)
	}
}

// The other identity names are protected the same way, and a condition on
// the caller still reads the caller.
func TestStepNamedLikeAnIdentityValueKeepsThatValue(t *testing.T) {
	app, caller, sid, other := identityStepApp(t)
	flow := `on:
  request:
    method: POST
    path: /api/lookup
    auth: required
jobs:
  lookup:
    steps:
      - id: user_id
        run: sql
        with: { query: "SELECT user_id FROM accounts WHERE id = :target" }
      - id: user_email
        run: sql
        with: { query: "SELECT email FROM accounts WHERE id = :target" }
      - id: user
        run: sql
        with: { query: "SELECT user_id AS id, role FROM accounts WHERE id = :target" }
      - if: ${{ user.role }} == 'admin'
        run: respond
        with: { status: 200, json: { admin: true } }
      - run: respond
        with:
          status: 200
          json:
            caller_id: "${{ user_id }}"
            caller_email: "${{ user_email }}"
            step_user_id: "${{ steps.user_id.outputs.user_id }}"
            step_user_email: "${{ steps.user_email.outputs.email }}"
`
	rr := runProbeGHAFlow(t, app, flow, fmt.Sprintf(`{"target":%d}`, other), "Authorization", "Bearer "+sid)
	body := rr.Body.String()
	if rr.Code != http.StatusOK || strings.Contains(body, `"admin":true`) {
		t.Fatalf("the looked-up account's role was read as the caller's: %d %s", rr.Code, body)
	}
	for _, want := range []string{
		fmt.Sprintf(`"caller_id":%d`, caller), `"caller_email":"ann@example.com"`,
		fmt.Sprintf(`"step_user_id":%d`, other), `"step_user_email":"target@example.com"`,
	} {
		if !strings.Contains(body, want) {
			t.Errorf("the answer does not hold %s:\n%s", want, body)
		}
	}
}

// A flow nobody signs in to has no caller to protect: `id: user` reads as it
// did, by its id and through `user.<name>`. Deployed flows that look a user
// up by email (sign-in, password reset) are of this shape.
func TestStepNamedUserOnAFlowWithoutSignIn(t *testing.T) {
	app, _, _, other := identityStepApp(t)
	flow := `on:
  request:
    method: POST
    path: /api/find
jobs:
  find:
    steps:
      - id: user
        run: sql
        with: { query: "SELECT user_id AS id, email FROM accounts WHERE email = :email" }
      - if: ${{ !steps.user.outputs.rows }}
        run: respond
        with: { status: 404, json: { error: not_found } }
      - if: ${{ steps.user.outputs.id }} == ''
        run: respond
        with: { status: 404, json: { error: no_id } }
      - run: respond
        with:
          status: 200
          json:
            id: "${{ steps.user.outputs.id }}"
            email: "${{ steps.user.outputs.email }}"
            first_id: "${{ steps.user.outputs.rows[0].id }}"
            through_user: "${{ user.email }}"
`
	rr := runProbeGHAFlow(t, app, flow, `{"email":"target@example.com"}`)
	body := rr.Body.String()
	for _, want := range []string{fmt.Sprintf(`"id":%d`, other), `"email":"target@example.com"`, fmt.Sprintf(`"first_id":%d`, other), `"through_user":"target@example.com"`} {
		if rr.Code != http.StatusOK || !strings.Contains(body, want) {
			t.Errorf("the answer does not hold %s: %d %s", want, rr.Code, body)
		}
	}
	if rr := runProbeGHAFlow(t, app, flow, `{"email":"nobody@example.com"}`); rr.Code != http.StatusNotFound || !strings.Contains(rr.Body.String(), "not_found") {
		t.Errorf("no row: %d %s", rr.Code, rr.Body.String())
	}
}

// The request cannot fill in the outputs of a step named like an identity
// value, before the step runs or instead of it, and a failure still names
// the step by the id its author gave it.
func TestStepNamedUserCannotBeSuppliedByTheRequest(t *testing.T) {
	app, _, sid, _ := identityStepApp(t)
	flow := `on:
  request:
    method: POST
    path: /api/skip
    auth: required
jobs:
  skip:
    steps:
      - if: ${{ params.load }} == 'yes'
        id: user
        run: sql
        with: { query: "SELECT email FROM accounts WHERE id = :target" }
      - run: respond
        with: { status: 200, json: { step_email: "${{ steps.user.outputs.email | default:'(not loaded)' }}", caller_email: "${{ user.email }}" } }
`
	for _, body := range []string{
		`{"__benmore_step_user":{"email":"planted@example.com"}}`,
		`{"__benmore_step_user.email":"planted@example.com"}`,
		`{"user":{"email":"planted@example.com"}}`,
		`{"steps":{"user":{"outputs":{"email":"planted@example.com"}}}}`,
	} {
		rr := runProbeGHAFlow(t, app, flow, body, "Authorization", "Bearer "+sid)
		if rr.Code != http.StatusOK || strings.Contains(rr.Body.String(), "planted") || !strings.Contains(rr.Body.String(), `"caller_email":"ann@example.com"`) || !strings.Contains(rr.Body.String(), `"step_email":"(not loaded)"`) {
			t.Errorf("%s -> %d %s", body, rr.Code, rr.Body.String())
		}
	}
	failing := `on:
  request:
    method: POST
    path: /api/fail
    auth: required
jobs:
  fail:
    steps:
      - id: user
        run: sql
        with: { query: "SELECT email FROM no_such_table" }
`
	rr := runProbeGHAFlow(t, app, failing, `{}`, "Authorization", "Bearer "+sid)
	if rr.Code != http.StatusInternalServerError || !strings.Contains(rr.Body.String(), `"failed_step":"user"`) {
		t.Errorf("a failing step named user answered %d %s, want failed_step \"user\"", rr.Code, rr.Body.String())
	}
}

// The write gate accepts a step named like an identity value (deployed flows
// have `id: user`) and warns, naming a better id; the loader logs the same
// line; a step with a name of its own is not mentioned.
func TestStepNamedLikeAnIdentityValueWarns(t *testing.T) {
	flow := `on:
  request:
    method: POST
    path: /api/find
jobs:
  find:
    steps:
      - id: user
        run: sql
        with: { query: "SELECT email FROM accounts WHERE email = :email" }
      - id: account
        run: sql
        with: { query: "SELECT email FROM accounts WHERE email = :email" }
      - if: ${{ params.deep }} == 'yes'
        steps:
          - id: user_id
            run: sql
            with: { query: "SELECT user_id FROM accounts WHERE email = :email" }
      - run: respond
        with: { status: 200, json: { email: "${{ steps.user.outputs.email }}" } }
`
	if msg := validateFlowsYAML(flow); msg != "" {
		t.Fatalf("the gate refuses a file deployed apps carry:\n%s", msg)
	}
	warnings := ghaIdentityStepIDWarnings(flow)
	if len(warnings) != 2 {
		t.Fatalf("warnings = %q, want one for `user` and one for `user_id`", warnings)
	}
	for i, want := range [][]string{
		{`job "find" step "user" is named like the signed-in caller's ` + "`user`", "The caller's values always win", "`${{ steps.user.outputs.<name> }}`", "`id: account`"},
		{`step "user_id"`, "`${{ steps.user_id.outputs.<name> }}`", "`id: owner_id`"},
	} {
		for _, part := range want {
			if !strings.Contains(warnings[i], part) {
				t.Errorf("warning %d does not say %q: %s", i, part, warnings[i])
			}
		}
	}
	for _, id := range flowIdentityKeys {
		named := strings.Replace(flow, "id: account", "id: "+id, 1)
		if got := ghaIdentityStepIDWarnings(named); len(got) != 3 {
			t.Errorf("id: %s gives %d warnings, want 3", id, len(got))
		}
		if flowStepOutputKey(id) == id || flowStepDisplayName(flowStepOutputKey(id)) != id {
			t.Errorf("identity name %q is stored under %q", id, flowStepOutputKey(id))
		}
	}
	if flowStepOutputKey("account") != "account" || flowStepOutputKey("users") != "users" {
		t.Error("a step with a name of its own is stored under another key")
	}

	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "flows"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"schema.prisma":   "model Account {\n  id     Int    @id @default(autoincrement())\n  userId Int    @map(\"user_id\")\n  email  String\n  @@map(\"accounts\")\n}\n",
		"flows/find.yaml": flow,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for _, written := range []string{"flows/find.yaml", ""} {
		report := RunSourceCheck(dir, written)
		warned := 0
		for _, f := range report.Findings {
			if f.Severity == "error" {
				t.Errorf("check (written %q) has an error: %s", written, f.Message)
			}
			if f.Severity == "warning" && f.File == "flows/find.yaml" && strings.Contains(f.Message, "is named like the signed-in caller's") {
				warned++
			}
		}
		if warned != 2 {
			t.Errorf("check (written %q) has %d warnings about the step ids, want 2: %+v", written, warned, report.Findings)
		}
	}
	logged := captureLog(t, func() {
		if flows, err := parseGHAFlowFile(filepath.Join(dir, "flows", "find.yaml"), []byte(flow)); err != nil || len(flows) != 1 {
			t.Errorf("a deployed file must keep loading: %v", err)
		}
	})
	if !strings.Contains(logged, "WARNING") || !strings.Contains(logged, `step "user" is named like the signed-in caller's`) || strings.Contains(logged, `step "account"`) {
		t.Errorf("the loader log:\n%s", logged)
	}
}
