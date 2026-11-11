//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A token minted from a scoped session or a token-exchange session used to
// get no expiry when expires_in was empty, outliving the bounded session that
// minted it. It now expires no later than that session; a person's own
// sign-in session still mints a token without an expiry.
func TestAPITokenFromNarrowSessionExpiresWithIt(t *testing.T) {
	app := recoveryHardeningApp(t)
	const email = "minter@example.test"
	uid := recoveryUser(t, app, email, fixturePassword, 1)
	exchange := createTokenExchangeSession(app.DB, uid, email, "", time.Hour, "")
	scoped, err := createSessionWith(app.DB, uid, email, "", time.Hour, "notes:read")
	if err != nil {
		t.Fatal(err)
	}
	signIn := createSignInSession(app.DB, uid, email, "", app.SessionDuration)
	mint := func(tok, body string) (int, map[string]any) {
		r := httptest.NewRequest(http.MethodPost, "/api/_auth/api-tokens", strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Authorization", "Bearer "+tok)
		w := httptest.NewRecorder()
		handleCreateAPIToken(w, r, app)
		var out map[string]any
		json.Unmarshal(w.Body.Bytes(), &out)
		return w.Code, out
	}
	limit := time.Now().Add(time.Hour + time.Minute)
	for _, tc := range []struct{ name, tok, body string }{
		{"exchange, no expiry", exchange, `{"name":"a","scopes":"*"}`},
		{"exchange, longer expiry", exchange, `{"name":"b","scopes":"*","expires_in":"90d"}`},
		{"scoped, no expiry", scoped, `{"name":"c","scopes":"notes:read"}`},
	} {
		code, out := mint(tc.tok, tc.body)
		if code != http.StatusOK {
			t.Fatalf("%s: mint %d %v", tc.name, code, out)
		}
		var stored string
		if err := app.DB.QueryRow("SELECT COALESCE(expires_at,'') FROM _benmore_api_tokens WHERE token_hash=?", hashToken(out["token"].(string))).Scan(&stored); err != nil {
			t.Fatal(err)
		}
		exp, err := time.Parse(time.RFC3339, stored)
		if err != nil || exp.After(limit) {
			t.Fatalf("%s: token expires_at %q (%v), want no later than the minting session", tc.name, stored, err)
		}
	}
	code, out := mint(signIn, `{"name":"d","scopes":"*"}`)
	if code != http.StatusOK {
		t.Fatalf("sign-in mint %d %v", code, out)
	}
	var stored string
	app.DB.QueryRow("SELECT COALESCE(expires_at,'') FROM _benmore_api_tokens WHERE token_hash=?", hashToken(out["token"].(string))).Scan(&stored)
	if stored != "" {
		t.Fatalf("sign-in session's token got expiry %q, want none", stored)
	}
}
