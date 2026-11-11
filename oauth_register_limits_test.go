package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// Open client registration stores a row per call: it is budgeted per client
// address (an IPv6 client by its /64) and every path takes the connector
// endpoint's field limits.
func TestAppOAuthRegisterIsRateLimitedAndBounded(t *testing.T) {
	app, cleanup := newOAuthTestApp(t)
	defer cleanup()
	previous := oauthRegisterLimiter
	oauthRegisterLimiter = NewRateLimiter(2, time.Hour)
	t.Cleanup(func() { oauthRegisterLimiter = previous })

	register := func(remote, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "https://myapp.example.com/oauth/register", strings.NewReader(body))
		req.RemoteAddr = remote
		w := httptest.NewRecorder()
		appOAuthRegister(w, req, app)
		return w
	}
	ok := `{"client_name":"Client","redirect_uris":["https://client.example/cb"]}`
	long := func(n int) string { return strings.Repeat("a", n) }
	for i, c := range []struct{ name, body string }{
		{"name too long", `{"client_name":"` + long(oauthRegisterMaxName+1) + `","redirect_uris":["https://client.example/cb"]}`},
		{"redirect too long", `{"client_name":"x","redirect_uris":["https://client.example/` + long(oauthRegisterMaxRedirectLen) + `"]}`},
		{"scope too long", `{"client_name":"x","redirect_uris":["https://client.example/cb"],"scope":"` + long(oauthRegisterMaxScope+1) + `"}`},
	} {
		if w := register(fmt.Sprintf("198.51.100.%d:1234", 10+i), c.body); w.Code != http.StatusBadRequest {
			t.Errorf("%s: %d %s", c.name, w.Code, w.Body.String())
		}
	}
	redirects := make([]string, oauthRegisterMaxRedirects+1)
	for i := range redirects {
		redirects[i] = "https://client.example/cb"
	}
	many, _ := json.Marshal(map[string]any{"client_name": "x", "redirect_uris": redirects})
	if w := register("198.51.100.2:1234", string(many)); w.Code != http.StatusBadRequest {
		t.Errorf("17 redirect URIs: %d %s", w.Code, w.Body.String())
	}
	var stored int
	if err := app.DB.QueryRow("SELECT count(*) FROM _benmore_oauth_clients").Scan(&stored); err != nil || stored != 0 {
		t.Fatalf("over-limit metadata stored %d clients (err %v)", stored, err)
	}

	for i := 0; i < 2; i++ {
		if w := register("[2001:db8:1:2::1]:1234", ok); w.Code != http.StatusCreated {
			t.Fatalf("registration %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	// Another address in the same /64 shares the budget.
	w := register("[2001:db8:1:2::ffff]:1234", ok)
	if w.Code != http.StatusTooManyRequests || w.Header().Get("Retry-After") == "" {
		t.Fatalf("third registration from one /64: %d (Retry-After %q) %s", w.Code, w.Header().Get("Retry-After"), w.Body.String())
	}
	if w := register("[2001:db8:1:3::1]:1234", ok); w.Code != http.StatusCreated {
		t.Fatalf("another /64 was limited: %d %s", w.Code, w.Body.String())
	}
}
