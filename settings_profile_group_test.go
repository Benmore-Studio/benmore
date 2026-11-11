//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// B17: the frontend had no way to read its current tenant - bm.auth.me()
// (GET /api/_auth/profile) carried roles but no group id, so a page could
// not tell which workspace it was in or whether onboarding was still due.
func TestProfileReportsEffectiveGroup(t *testing.T) {
	app, _ := actAsCredentialApp(t)
	mux := http.NewServeMux()
	RegisterSettingsRoutes(mux, app)
	profile := func(token string) map[string]any {
		t.Helper()
		r := httptest.NewRequest(http.MethodGet, "/api/_auth/profile", nil)
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		if w.Code != http.StatusOK {
			t.Fatalf("profile = %d %s", w.Code, w.Body.String())
		}
		var out map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	member := createCrudScopeSession(t, app, "member@example.com", "user", "", "")
	memberID := GetSessionFromDB(app.DB, member).UserID
	if _, err := app.DB.Exec("INSERT INTO members (org_id, user_id) VALUES (7, ?)", memberID); err != nil {
		t.Fatal(err)
	}
	if got := profile(member)["group_id"]; got != "7" {
		t.Fatalf("member profile group_id = %#v, want \"7\" (resolved from the membership)", got)
	}

	loner := createCrudScopeSession(t, app, "loner@example.com", "user", "", "")
	if got, ok := profile(loner)["group_id"]; !ok || got != nil {
		t.Fatalf("tenant-less profile group_id = %#v (present %v), want null", got, ok)
	}

	// A user cannot claim a tenant through a stale session value: the session
	// row says 9, but without a live membership there the runtime drops it.
	stale := createCrudScopeSession(t, app, "stale@example.com", "user", "9", "")
	if got := profile(stale)["group_id"]; got != nil {
		t.Fatalf("profile reported a tenant without a live membership: %#v", got)
	}

	// An admin stepped into a tenant sees that tenant, as every scoped read does.
	admin := createCrudScopeSession(t, app, "boss@example.com", "admin", "", "7")
	if got := profile(admin)["group_id"]; got != "7" {
		t.Fatalf("stepped-in admin group_id = %#v, want \"7\"", got)
	}

	// A single-tenant app's profile is unchanged.
	app.Group = nil
	if _, ok := profile(member)["group_id"]; ok {
		t.Fatal("a single-tenant app's profile gained group_id")
	}
}
