//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func profilePatch(t *testing.T, mux *http.ServeMux, sid string, body map[string]any) *httptest.ResponseRecorder {
	t.Helper()
	data, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPatch, "/api/_auth/profile", strings.NewReader(string(data)))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", authMintCSRFToken(sid))
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, r)
	return w
}

// `<page require="plan:pro">` gates on _benmore_users columns, so the
// self-service profile API must not let a user write one. Only the default
// display fields, auth.signup_fields and auth.profile_fields are editable.
func TestProfilePatchRejectsUndeclaredUserColumns(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	passwordChangeExec(t, app.DB, "ALTER TABLE _benmore_users ADD COLUMN plan TEXT DEFAULT 'free'")
	passwordChangeExec(t, app.DB, "ALTER TABLE _benmore_users ADD COLUMN company TEXT DEFAULT ''")
	passwordChangeExec(t, app.DB, "ALTER TABLE _benmore_users ADD COLUMN pronouns TEXT DEFAULT ''")
	app.Design = &DesignConfig{Auth: map[string]string{"signup_fields": "first_name,company"}}
	mux := http.NewServeMux()
	RegisterSettingsRoutes(mux, app)
	sid := seedMemberSession(t, app)
	uid := GetSessionFromDB(app.DB, sid).UserID
	plan := func() string {
		var p string
		app.DB.QueryRow("SELECT plan FROM _benmore_users WHERE id = ?", uid).Scan(&p)
		return p
	}

	w := profilePatch(t, mux, sid, map[string]any{"plan": "pro", "first_name": "Mallory"})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "auth.profile_fields") || !strings.Contains(w.Body.String(), "plan") {
		t.Fatalf("self-granted plan: %d %s", w.Code, w.Body.String())
	}
	if plan() != "free" {
		t.Fatalf("plan changed to %q", plan())
	}
	var first string
	app.DB.QueryRow("SELECT first_name FROM _benmore_users WHERE id = ?", uid).Scan(&first)
	if first == "Mallory" {
		t.Fatal("a refused PATCH still applied its other fields")
	}

	// Defaults and signup_fields stay editable; a round-trip that echoes
	// the current plan back unchanged is not a grant.
	w = profilePatch(t, mux, sid, map[string]any{"first_name": "Mel", "company": "Acme", "plan": "free", "roles": []any{"user"}})
	if w.Code != http.StatusOK {
		t.Fatalf("editable fields refused: %d %s", w.Code, w.Body.String())
	}
	var company string
	app.DB.QueryRow("SELECT first_name, company FROM _benmore_users WHERE id = ?", uid).Scan(&first, &company)
	if first != "Mel" || company != "Acme" {
		t.Fatalf("editable fields not saved: %q %q", first, company)
	}

	// auth.profile_fields opts extra columns in.
	if w := profilePatch(t, mux, sid, map[string]any{"pronouns": "they/them"}); w.Code != http.StatusForbidden {
		t.Fatalf("undeclared column accepted: %d %s", w.Code, w.Body.String())
	}
	app.Design.Auth["profile_fields"] = "pronouns, plan_note"
	if w := profilePatch(t, mux, sid, map[string]any{"pronouns": "they/them"}); w.Code != http.StatusOK {
		t.Fatalf("declared profile field refused: %d %s", w.Code, w.Body.String())
	}
	// Listing a protected column never makes it writable.
	app.Design.Auth["profile_fields"] = "role,verified"
	profilePatch(t, mux, sid, map[string]any{"role": "admin", "verified": 1})
	var role string
	var verified int
	app.DB.QueryRow("SELECT role, COALESCE(verified,0) FROM _benmore_users WHERE id = ?", uid).Scan(&role, &verified)
	if role != "user" || verified != 0 {
		t.Fatalf("protected columns written: role=%q verified=%d", role, verified)
	}
}
