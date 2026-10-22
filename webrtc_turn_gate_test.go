//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// TURN credentials relay arbitrary traffic on the provider account, so the
// ICE endpoint hands them only to signed-in callers, or to anyone when the
// app opts into anonymous realtime. Anonymous callers otherwise get STUN.
func TestWebRTCTURNCredentialsNeedSessionOrAnonymousOptIn(t *testing.T) {
	app, _ := auditApp(t)
	t.Setenv("BENMORE_PLATFORM_TURN_PROVIDER", "static")
	t.Setenv("BENMORE_PLATFORM_TURN_URL", "turn:turn.example.test:3478")
	t.Setenv("BENMORE_PLATFORM_TURN_USERNAME", "relay-user")
	t.Setenv("BENMORE_PLATFORM_TURN_CREDENTIAL", "relay-secret")
	mux := http.NewServeMux()
	RegisterWebRTCRoute(mux, app)
	fetch := func(cookie string) []iceServer {
		req := httptest.NewRequest("GET", "/api/_webrtc/ice", nil)
		if cookie != "" {
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: cookie})
		}
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out struct {
			IceServers []iceServer `json:"iceServers"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		return out.IceServers
	}
	hasTURN := func(list []iceServer) bool {
		for _, s := range list {
			if s.Credential != "" {
				return true
			}
		}
		return false
	}

	if list := fetch(""); hasTURN(list) || len(list) == 0 {
		t.Fatalf("anonymous caller got TURN credentials: %+v", list)
	}
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email) VALUES (7, 'u', 'u@example.test')`)
	sid := CreateSession(app.DB, 7, "u@example.test", "", time.Hour)
	if !hasTURN(fetch(sid)) {
		t.Fatal("signed-in caller did not get TURN credentials")
	}

	on := true
	if app.Design == nil {
		app.Design = &DesignConfig{}
	}
	if app.Design.Features == nil {
		app.Design.Features = &FeaturesConfig{}
	}
	app.Design.Features.WSAnonymous = &on
	if !hasTURN(fetch("")) {
		t.Fatal("anonymous caller on an ws_anonymous app did not get TURN credentials")
	}
}

type turnMintStub struct{ mints atomic.Int32 }

func (s *turnMintStub) RoundTrip(r *http.Request) (*http.Response, error) {
	n := s.mints.Add(1)
	body := fmt.Sprintf(`{"iceServers":{"urls":["turn:turn.example.test:3478"],"username":"u%d","credential":"c%d"}}`, n, n)
	return &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

// An anonymous caller's TURN credential (features.ws_anonymous) was cached
// per full client address, so an IPv6 client minted a new one from each
// address of its /64 and could spend the app's whole mint budget, leaving
// every new caller STUN only. Anonymous callers now share one credential per
// /64, as the rate limits key them.
func TestWebRTCAnonymousTURNKeyedByIPv6Prefix(t *testing.T) {
	app, _ := auditApp(t)
	on := true
	app.Design = &DesignConfig{Features: &FeaturesConfig{WSAnonymous: &on}}
	t.Setenv("BENMORE_PLATFORM_TURN_PROVIDER", "cloudflare")
	t.Setenv("BENMORE_PLATFORM_TURN_CF_APP_ID", "0123456789abcdef0123456789abcdef")
	t.Setenv("BENMORE_PLATFORM_TURN_CF_APP_TOKEN", "turn-token")
	stub := &turnMintStub{}
	old := http.DefaultClient.Transport
	http.DefaultClient.Transport = stub
	t.Cleanup(func() { http.DefaultClient.Transport = old })
	mux := http.NewServeMux()
	RegisterWebRTCRoute(mux, app)
	fetch := func(peer string) string {
		req := httptest.NewRequest("GET", "/api/_webrtc/ice", nil)
		req.RemoteAddr = net.JoinHostPort(peer, "40000")
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, req)
		var out struct {
			IceServers []iceServer `json:"iceServers"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out)
		for _, s := range out.IceServers {
			if s.Credential != "" {
				return s.Credential
			}
		}
		return ""
	}

	first := fetch("2001:db8:9:1::1")
	if first == "" {
		t.Fatal("anonymous caller on a ws_anonymous app got no TURN credential")
	}
	for i := 2; i <= 5; i++ {
		if got := fetch(fmt.Sprintf("2001:db8:9:1::%x", i)); got != first {
			t.Fatalf("address %d of the same /64 got credential %q, want the cached %q", i, got, first)
		}
	}
	if n := stub.mints.Load(); n != 1 {
		t.Errorf("one /64 minted %d TURN credentials, want 1", n)
	}
	if got := fetch("2001:db8:9:2::1"); got == "" || got == first {
		t.Errorf("another /64 got credential %q, want its own", got)
	}
}
