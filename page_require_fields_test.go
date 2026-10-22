//go:build !cli

package main

import (
	"net/http"
	"testing"
)

func TestCheckRequireFieldsRefusesGateWithNoValidPart(t *testing.T) {
	user := map[string]any{"plan": "pro", "verified": int64(1)}
	cases := map[string]bool{
		"plan:pro":               true,
		"plan:free,pro":          true,
		"plan:pro verified:1":    true,
		"plan:enterprise":        false,
		"plan=pro":               false, // malformed: no field:value part at all
		":pro":                   false,
		"plan=pro verified":      false,
		"   ":                    false,
		"plan:pro nonsense_part": true, // valid part present; malformed extras stay ignored
	}
	for require, want := range cases {
		if got := checkRequireFields(require, user); got != want {
			t.Errorf("checkRequireFields(%q) = %v, want %v", require, got, want)
		}
	}
}

func TestMalformedPageRequireRefusesSignedInUsers(t *testing.T) {
	app := ssrTestApp(t)
	ssrLoadPages(t, app, map[string]string{
		"typo.html": `<page require="plan=pro"><h1>typo-gated</h1></page>`,
	})
	mux := buildAppMux(app, false, "https://fixture.example.com")
	user := createCrudScopeSession(t, app, "u@example.com", "user", "", "")
	if rec := ssrGet(mux, "/typo", user); rec.Code != http.StatusForbidden {
		t.Fatalf("page with malformed require=: status %d, want 403", rec.Code)
	}
}
