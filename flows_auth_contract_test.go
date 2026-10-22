//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// The flow HTTP gate compared auth against the exact string "required", so
// `auth: true`, `auth: yes`, `auth: Required` or a typo registered a PUBLIC
// endpoint. Anything but an explicit opt-out now requires sign-in, as pages do.
func TestFlowAuthValuesOtherThanRequiredStillGate(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	flow := func(auth string) string {
		return "on:\n  request:\n    method: POST\n    path: /api/secret\n    auth: " + auth + "\njobs:\n  secret:\n    steps:\n      - run: respond\n        with:\n          status: 200\n          body: { secret: \"s3cret\" }\n"
	}
	for _, auth := range []string{"true", "yes", "Required", "' required '", "logged_in"} {
		rr := runProbeGHAFlow(t, app, flow(auth), `{}`)
		if rr.Code != http.StatusUnauthorized || strings.Contains(rr.Body.String(), "s3cret") {
			t.Errorf("auth: %s answered an anonymous caller: %d %s", auth, rr.Code, rr.Body.String())
		}
	}
	for _, auth := range []string{"none", "public", "false"} {
		if rr := runProbeGHAFlow(t, app, flow(auth), `{}`); rr.Code != http.StatusOK {
			t.Errorf("auth: %s should stay public: %d %s", auth, rr.Code, rr.Body.String())
		}
	}
	sid := createCrudScopeSession(t, app, "u@example.com", "user", "", "")
	if rr := runProbeGHAFlow(t, app, flow("yes"), `{}`, "Authorization", "Bearer "+sid); rr.Code != http.StatusOK {
		t.Errorf("signed-in caller refused on auth: yes: %d %s", rr.Code, rr.Body.String())
	}
}

func TestLegacyFlowAuthNormalized(t *testing.T) {
	flows, err := parseLegacyFlowsYAML([]byte("secret:\n  trigger: POST /api/secret\n  auth: yes\n  steps:\n    - sql: SELECT 1\n"))
	if err != nil || len(flows) != 1 {
		t.Fatalf("parse: %v %d", err, len(flows))
	}
	if flows[0].Auth != "required" {
		t.Fatalf("legacy auth: yes = %q, want required", flows[0].Auth)
	}
}

const flowGateBase = "on:\n  request:\n    method: POST\n    path: /api/x\n%s\njobs:\n  x:\n    steps:\n%s"

func flowGateFile(request, steps string) string {
	if steps == "" {
		steps = "      - run: respond\n        with: { status: 200 }\n"
	}
	return strings.Replace(strings.Replace(flowGateBase, "%s", request, 1), "%s", steps, 1)
}

// Keys the flow parser drops must be refused at write time: several of them
// (roles, rate-limit, auth_required) would otherwise leave the endpoint with
// no gate while the file reads as gated.
func TestFlowWriteGateRefusesDroppedKeys(t *testing.T) {
	cases := map[string]string{
		"roles":         flowGateFile("    roles: admin", ""),
		"rate-limit":    flowGateFile("    rate-limit: 5/hour", ""),
		"auth_required": flowGateFile("    auth_required: true", ""),
		"expect_row":    flowGateFile("", "      - query: UPDATE t SET a = 1\n        expect_row: \"=1\"\n      - run: respond\n        with: { status: 200 }\n"),
		"nested name":   flowGateFile("", "      - if: ${{ params.a }}\n        steps:\n          - name: inner\n            run: respond\n            with: { status: 200 }\n      - run: respond\n        with: { status: 200 }\n"),
		"job if":        strings.Replace(flowGateFile("", ""), "  x:\n    steps:", "  x:\n    if: ${{ params.a }}\n    steps:", 1),
		"top env":       "env:\n  A: b\n" + flowGateFile("", ""),
		"on typo":       strings.Replace(flowGateFile("", ""), "on:\n", "on:\n  schedul: { cron: \"@daily\" }\n", 1),
		"input typo":    flowGateFile("    inputs:\n      a: { type: text, requred: true }", ""),
	}
	for name, content := range cases {
		msg := ValidateOnWrite("flows/x.yaml", content)
		if !strings.Contains(msg, "unknown key") {
			t.Errorf("%s: dropped key was accepted: %q", name, msg)
		}
	}
	if msg := ValidateOnWrite("flows/x.yaml", flowGateFile("    auth: required\n    role: admin\n    rate_limit: 5/hour per ip\n    transaction: true", "      - id: w\n        query: UPDATE t SET a = 1\n        expect_rows: \"=1\"\n        retry: 1\n      - run: respond\n        with: { status: 200 }\n")); msg != "" {
		t.Errorf("valid flow refused: %s", msg)
	}
}

func TestFlowWriteGateRefusesUnhonoredValues(t *testing.T) {
	cases := map[string]string{
		"auth":        flowGateFile("    auth: logged_in", ""),
		"mode":        flowGateFile("    mode: background", ""),
		"expect_rows": flowGateFile("", "      - query: UPDATE t SET a = 1\n        expect_rows: at least one\n      - run: respond\n        with: { status: 200 }\n"),
		"event op":    "on:\n  event:\n    table: notes\n    op: updated\njobs:\n  x:\n    steps:\n      - query: SELECT 1\n",
	}
	for name, content := range cases {
		if msg := ValidateOnWrite("flows/x.yaml", content); msg == "" {
			t.Errorf("%s: unhonored value accepted", name)
		}
	}
	for _, auth := range []string{"required", "none", "true", "public"} {
		if msg := ValidateOnWrite("flows/x.yaml", flowGateFile("    auth: "+auth, "")); msg != "" {
			t.Errorf("auth: %s refused: %s", auth, msg)
		}
	}
}
