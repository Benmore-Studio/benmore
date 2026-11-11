//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// `auth.api_tokens: false` refused minting (POST /api/_auth/token and
// /api/_auth/api-tokens) but every bmr_ token and every Bearer session the
// exchange had already issued kept reading and writing. While the switch is
// off they now stop authenticating, whatever carries them; the person's own
// sign-in sessions and OAuth access tokens (bma_) are unaffected, and
// switching the API back on restores the kept tokens.
func TestAPITokensSwitchOffStopsExistingAPICredentials(t *testing.T) {
	app := recoveryHardeningApp(t)
	const email = "worker@example.test"
	uid := recoveryUser(t, app, email, fixturePassword, 1)

	// Minted while the API is on.
	r := httptest.NewRequest(http.MethodPost, "/api/_auth/token", strings.NewReader(`{"email":"`+email+`","password":"`+fixturePassword+`"}`))
	r.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	handleTokenAuth(w, r, app)
	var exchanged struct {
		Token string `json:"token"`
	}
	if w.Code != http.StatusOK || json.Unmarshal(w.Body.Bytes(), &exchanged) != nil || exchanged.Token == "" {
		t.Fatalf("token exchange: %d %s", w.Code, w.Body.String())
	}
	userToken := "bmr_" + generateToken(32)
	oauthToken := "bma_" + generateToken(32)
	for _, tok := range []string{userToken, oauthToken} {
		if ok, err := insertAPITokenWithinCap(app.DB, uid, "fixture", hashToken(tok), "*", nil); !ok || err != nil {
			t.Fatalf("insert token: %v %v", ok, err)
		}
	}
	browser := createSignInSession(app.DB, uid, email, "", app.SessionDuration)
	legacy := CreateSession(app.DB, uid, email, "", app.SessionDuration)

	bearer := func(tok string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://app.example.test/api/notes", nil)
		r.Header.Set("Authorization", "Bearer "+tok)
		return r
	}
	cookie := func(tok string) *http.Request {
		r := httptest.NewRequest(http.MethodGet, "https://app.example.test/api/notes", nil)
		r.AddCookie(&http.Cookie{Name: sessionCookieName, Value: tok})
		return r
	}
	cases := []struct {
		name     string
		req      func() *http.Request
		offStays bool // still authenticates while the switch is off
	}{
		{"user API token", func() *http.Request { return bearer(userToken) }, false},
		{"exchange session as Bearer", func() *http.Request { return bearer(exchanged.Token) }, false},
		{"exchange session as cookie", func() *http.Request { return cookie(exchanged.Token) }, false},
		{"OAuth access token", func() *http.Request { return bearer(oauthToken) }, true},
		{"sign-in session as cookie", func() *http.Request { return cookie(browser) }, true},
		{"sign-in session as Bearer", func() *http.Request { return bearer(browser) }, true},
		// Unmarked sessions (the exchange's from before the marker, the test
		// runner's) cannot be told apart and keep working until they expire.
		{"unmarked session", func() *http.Request { return bearer(legacy) }, true},
	}
	check := func(state string, off bool) {
		t.Helper()
		for _, tc := range cases {
			s := getSession(app, tc.req())
			want := !off || tc.offStays
			if got := s != nil && s.UserID == uid; got != want {
				t.Errorf("%s, %s: authenticated=%t, want %t", state, tc.name, got, want)
			}
		}
	}
	check("switch on", false)
	app.Design.Auth["api_tokens"] = "false"
	check("switch off", true)
	var kept int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM _benmore_api_tokens WHERE user_id = ?", uid).Scan(&kept); err != nil || kept != 2 {
		t.Fatalf("tokens kept while off = %d (%v), want 2 so users can list and revoke them", kept, err)
	}
	delete(app.Design.Auth, "api_tokens")
	check("switch back on", false)
	var loginAt int64
	if err := app.DB.QueryRow("SELECT login_at FROM _benmore_sessions WHERE id = ?", sessionStorageKey(exchanged.Token)).Scan(&loginAt); err != nil || loginAt != loginAtTokenExchange {
		t.Errorf("exchange session login_at = %d (%v), want the exchange marker %d", loginAt, err, loginAtTokenExchange)
	}
}
