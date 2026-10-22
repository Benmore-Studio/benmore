//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// An account that predates verified-only email grants (email_grandfathered)
// keeps its email-keyed tenant. Its sign-in sessions did, but a session built
// from a persistent API token never loaded the flag, so since the lazy tenant
// resolution started asking for the session's own proof the same account's
// bmr_/bma_ tokens resolved no tenant: integrations of long-standing users
// silently lost their tenant's rows.
func TestAPITokenOfGrandfatheredAccountKeepsEmailTenant(t *testing.T) {
	app, _ := auditApp(t) // groups: members(org_id, email)
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_users (id, username, email, password_hash, role, verified, email_grandfathered) VALUES (1, 'longtime', 'longtime@corp.example', 'x', 'user', 0, 1), (2, 'fresh', 'fresh@corp.example', 'x', 'user', 0, 0)")
	passwordChangeExec(t, app.DB, "INSERT INTO members (org_id, email) VALUES ('tenant-a', 'longtime@corp.example'), ('tenant-a', 'fresh@corp.example')")
	mint := func(userID int64) string {
		raw := "bmr_" + generateToken(32)
		passwordChangeExec(t, app.DB, "INSERT INTO _benmore_api_tokens (user_id, name, token_hash, scopes) VALUES (?, 't', ?, '*')", userID, hashToken(raw))
		return raw
	}
	resolve := func(bearer string) *Session {
		r := httptest.NewRequest(http.MethodGet, "/api/orgdocs", nil)
		r.Header.Set("Authorization", "Bearer "+bearer)
		return getSession(app, r)
	}

	// The account's own sign-in session has the tenant ...
	if s := resolve(CreateSession(app.DB, 1, "longtime@corp.example", "", time.Hour)); s == nil || s.GroupID != "tenant-a" {
		t.Fatalf("control: sign-in session of a grandfathered account: %+v", s)
	}
	// ... and so must its API token.
	if s := resolve(mint(1)); s == nil || s.GroupID != "tenant-a" || !s.EmailGrandfathered {
		t.Fatalf("API token of a grandfathered account resolved no tenant: %+v", s)
	}
	// An account that must still prove its address gets none either way.
	if s := resolve(mint(2)); s == nil || s.GroupID != "" {
		t.Fatalf("API token of an unproven account got a tenant: %+v", s)
	}
}
