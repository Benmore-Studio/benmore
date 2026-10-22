//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func presenceBeacon(mux *http.ServeMux, sid string, body map[string]string, origin string) int {
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest("POST", "https://app.example.com/api/_presence/heartbeat", strings.NewReader(string(raw)))
	// navigator.sendBeacon: the Blob's type, the cookies, no custom header.
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	if origin != "" {
		req.Header.Set("Origin", origin)
	}
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec.Code
}

// bm.presence marks "I left" with navigator.sendBeacon on pagehide. A beacon
// cannot set X-CSRF-Token, so the SDK puts the token in the JSON body as
// `_csrf` - which the CSRF check never read, so every beacon leave was 403
// and the member lingered until the 90-second sweep. The heartbeat endpoint
// now accepts the same token from its JSON body, under the same origin, HMAC
// and expiry checks.
func TestPresenceBeaconLeaveCarriesCSRFInBody(t *testing.T) {
	app, mux := presenceFixture(t)
	sid := createCrudScopeSession(t, app, "member@example.com", "user", "", "")
	other := createCrudScopeSession(t, app, "other@example.com", "user", "", "")
	present := func() int {
		t.Helper()
		_, members := presenceList(t, mux, sid, "lobby")
		return len(members)
	}
	join := func() {
		t.Helper()
		if code := presencePost(mux, sid, "lobby", "join"); code != 200 {
			t.Fatalf("join: %d", code)
		}
	}

	join()
	if code := presenceBeacon(mux, sid, map[string]string{"slug": "lobby", "action": "leave", "_csrf": authMintCSRFToken(sid)}, "https://app.example.com"); code != http.StatusOK {
		t.Fatalf("beacon leave with the session's CSRF token in the body: status %d, want 200", code)
	}
	if n := present(); n != 0 {
		t.Fatalf("beacon leave left %d member(s) present", n)
	}

	// The check is not weaker than the header's: no token, a forged token,
	// another session's token and a cross-site origin are all refused.
	join()
	for name, code := range map[string]int{
		"no token":            presenceBeacon(mux, sid, map[string]string{"slug": "lobby", "action": "leave"}, "https://app.example.com"),
		"forged token":        presenceBeacon(mux, sid, map[string]string{"slug": "lobby", "action": "leave", "_csrf": "abc|123|def"}, "https://app.example.com"),
		"other session token": presenceBeacon(mux, sid, map[string]string{"slug": "lobby", "action": "leave", "_csrf": authMintCSRFToken(other)}, "https://app.example.com"),
		"cross-site origin":   presenceBeacon(mux, sid, map[string]string{"slug": "lobby", "action": "leave", "_csrf": authMintCSRFToken(sid)}, "https://evil.example"),
	} {
		if code != http.StatusForbidden {
			t.Errorf("%s: status %d, want 403", name, code)
		}
	}
	if n := present(); n != 1 {
		t.Fatalf("a refused beacon removed the member (present=%d)", n)
	}
}

// The SDK and the handler have to agree on where the token travels.
func TestPresenceSDKBeaconSendsBodyToken(t *testing.T) {
	src, err := os.ReadFile("embedded/bm.js")
	if err != nil {
		t.Fatal(err)
	}
	i := strings.Index(string(src), "const sendBeaconLeave")
	if i < 0 {
		t.Fatal("bm.js: sendBeaconLeave not found")
	}
	block := string(src)[i:]
	if j := strings.Index(block, "navigator.sendBeacon"); j < 0 || !strings.Contains(block[:j], "_csrf: csrf") {
		t.Fatal("bm.js: the presence beacon no longer sends `_csrf` in its JSON body; the heartbeat handler reads it there")
	}
}
