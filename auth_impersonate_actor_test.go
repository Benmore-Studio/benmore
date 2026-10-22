//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Impersonation must not let one admin become another, and whatever the
// impersonation session changes has to name the admin who really acted, not
// only the user being impersonated.
func TestImpersonationRefusesAdminsAndAuditsRealActor(t *testing.T) {
	app, crud := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	mux := http.NewServeMux()
	RegisterAuthRoutes(mux, app)
	hash, _ := bcrypt.GenerateFromPassword([]byte(fixturePassword), bcrypt.MinCost)
	seed := func(email, role string) int64 {
		res, err := app.DB.Exec("INSERT INTO _benmore_users (username, email, password_hash, role, verified) VALUES (?, ?, ?, ?, 1)", strings.Split(email, "@")[0], email, string(hash), role)
		if err != nil {
			t.Fatal(err)
		}
		id, _ := res.LastInsertId()
		return id
	}
	adminID := seed("admin@example.com", "admin")
	otherAdminID := seed("other-admin@example.com", "admin")
	memberID := seed("member@example.com", "user")
	adminSID := CreateSession(app.DB, adminID, "admin@example.com", "", time.Hour)

	impersonate := func(target int64) *httptest.ResponseRecorder {
		body, _ := json.Marshal(map[string]any{"user_id": target, "password": fixturePassword})
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/impersonate", strings.NewReader(string(body)))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-CSRF-Token", authMintCSRFToken(adminSID))
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: adminSID})
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}
	if w := impersonate(otherAdminID); w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), `"token"`) {
		t.Fatalf("admin impersonated another admin: %d %s", w.Code, w.Body.String())
	}
	// A global admin grant in the join table counts as admin too.
	grantedID := seed("granted@example.com", "user")
	passwordChangeExec(t, app.DB, "INSERT INTO _benmore_user_roles (user_id, role) VALUES (?, 'admin')", grantedID)
	if w := impersonate(grantedID); w.Code != http.StatusForbidden {
		t.Fatalf("admin impersonated a granted admin: %d %s", w.Code, w.Body.String())
	}
	var n int
	app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_sessions WHERE COALESCE(is_impersonation,0)=1").Scan(&n)
	if n != 0 {
		t.Fatalf("impersonation sessions after refusals: %d", n)
	}

	w := impersonate(memberID)
	if w.Code != http.StatusOK {
		t.Fatalf("admin could not impersonate a member: %d %s", w.Code, w.Body.String())
	}
	var started map[string]any
	json.Unmarshal(w.Body.Bytes(), &started)
	tok, _ := started["token"].(string)
	if tok == "" {
		t.Fatal("no impersonation token")
	}
	// The admin logs out; the trail must still name them.
	DeleteSessionFromDB(app.DB, adminSID)
	body := strings.NewReader(`{"title":"written while impersonating"}`)
	r := httptest.NewRequest(http.MethodPost, "/api/notes", body)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("X-CSRF-Token", authMintCSRFToken(tok))
	r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tok})
	cw := httptest.NewRecorder()
	crud.ServeHTTP(cw, r)
	if cw.Code != http.StatusOK && cw.Code != http.StatusCreated {
		t.Fatalf("create as impersonated member: %d %s", cw.Code, cw.Body.String())
	}
	var userID, actorID int64
	var actorEmail string
	err := app.DB.QueryRow("SELECT user_id, COALESCE(impersonator_user_id,0), COALESCE(impersonator_email,'') FROM _benmore_audit_log WHERE table_name='notes' AND action='insert' ORDER BY id DESC LIMIT 1").Scan(&userID, &actorID, &actorEmail)
	if err != nil {
		t.Fatal(err)
	}
	if userID != memberID || actorID != adminID || actorEmail != "admin@example.com" {
		t.Fatalf("audit row user=%d impersonator=%d %q; want user=%d impersonator=%d admin@example.com", userID, actorID, actorEmail, memberID, adminID)
	}
	// An ordinary session leaves the impersonator columns empty.
	memberSID := CreateSession(app.DB, memberID, "member@example.com", "", time.Hour)
	LogAudit(app, "create", "notes", "x", GetSessionFromDB(app.DB, memberSID), nil, map[string]any{"title": "own"})
	app.DB.QueryRow("SELECT COALESCE(impersonator_user_id,0) FROM _benmore_audit_log WHERE row_id='x'").Scan(&actorID)
	if actorID != 0 {
		t.Fatalf("ordinary session recorded impersonator %d", actorID)
	}
}
