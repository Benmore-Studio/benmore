//go:build !cli

package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"
)

// `auth: optional` lets anyone call the flow; a signed-in caller gets the
// identity an auth-required flow binds, an anonymous caller null identity.
// Before it, "Add to Slack" needed two routes (one signed in, one not).
func TestFlowAuthOptionalBindsIdentityOnlyWhenSignedIn(t *testing.T) {
	app := secretTaintApp(t)
	token := createCrudScopeSession(t, app, "optional-flow@example.com", "user", "", "")
	source := strings.Replace(responseValueFlow("", "      - run: respond\n        with:\n          json: { id: '${{ user.id }}', email: '${{ user.email }}', flat: '${{ user_id }}' }\n"), "    method: POST", "    method: GET\n    auth: optional", 1)
	if msg := ValidateOnWrite("flows/probe.yaml", source); msg != "" {
		t.Fatalf("write gate refused auth: optional: %s", msg)
	}
	flow := parseExpectRowsFlow(t, app, source)
	if flow.Auth != "optional" {
		t.Fatalf("loaded auth %q", flow.Auth)
	}
	run := func(signedIn bool) map[string]any {
		t.Helper()
		rr := httptest.NewRecorder()
		req := httptest.NewRequest("GET", "/api/probe?user=spoof&user_id=99", nil)
		if signedIn {
			req.AddCookie(sessionCookie(token, false, app.SessionDuration))
		}
		executeFlowHTTP(app, &flow, rr, req)
		if rr.Code != 200 {
			t.Fatalf("signed in %v: %d %s", signedIn, rr.Code, rr.Body.String())
		}
		var body map[string]any
		if err := json.Unmarshal(rr.Body.Bytes(), &body); err != nil {
			t.Fatalf("%s: %v", rr.Body.String(), err)
		}
		return body
	}
	anon := run(false)
	if anon["id"] != nil || anon["email"] != nil || anon["flat"] != nil {
		t.Fatalf("anonymous caller bound an identity: %v", anon)
	}
	me := run(true)
	if me["email"] != "optional-flow@example.com" || me["id"] == nil || me["id"] == float64(99) {
		t.Fatalf("signed-in caller identity: %v", me)
	}
	if !flowListedFor(flow, nil) {
		t.Fatal("an optional flow must be listed for anonymous callers")
	}
}
