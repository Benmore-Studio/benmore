//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// Logout accepts Bearer callers (they skip CSRF), so it must end the Bearer
// session they present, not only a cookie session.
func TestLogoutRevokesBearerSession(t *testing.T) {
	app, _ := auditApp(t)
	app.Paths = DiscoverAuthPaths(nil)
	sid := seedMemberSession(t, app)
	uid := GetSessionFromDB(app.DB, sid).UserID
	apiToken := auditToken(t, app, sid, "*")
	bearer := CreateSession(app.DB, uid, "member@test.local", "", time.Hour)

	r := httptest.NewRequest(http.MethodPost, app.Paths.Logout, nil)
	r.Header.Set("Authorization", "Bearer "+bearer)
	w := httptest.NewRecorder()
	handleLogout(w, r, app)
	if GetSessionFromDB(app.DB, bearer) != nil {
		t.Fatalf("Bearer session survived logout (%d)", w.Code)
	}
	if GetSessionFromDB(app.DB, sid) == nil || GetSessionFromAPIToken(app.DB, apiToken) == nil {
		t.Fatal("logout revoked credentials it was not presented with")
	}
}
