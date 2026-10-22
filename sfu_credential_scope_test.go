//go:build !cli

package main

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	platformCFAppID = "0123456789abcdef0123456789abcdef"
	tenantCFAppID   = "fedcba9876543210fedcba9876543210"
)

// cfRecorder answers Cloudflare Realtime calls and records which path each
// bearer token was sent to.
type cfRecorder struct {
	mu        sync.Mutex
	calls     []string // "<bearer> <path>"
	failPull  string   // non-empty: tracks/new answers 400 with this body
	sessionNo int
}

func (c *cfRecorder) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	c.calls = append(c.calls, strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")+" "+r.URL.EscapedPath())
	c.sessionNo++
	n := c.sessionNo
	fail := c.failPull
	c.mu.Unlock()
	status, body := 200, `{"sessionDescription":{"type":"answer","sdp":"v=0"}}`
	switch {
	case strings.HasSuffix(r.URL.Path, "/sessions/new"):
		body = fmt.Sprintf(`{"sessionId":"cf-session-%d"}`, n)
	case strings.Contains(r.URL.Path, "/turn/keys/"):
		body = `{"iceServers":{"urls":["turn:turn.example.test:3478"],"username":"u","credential":"c"}}`
	case fail != "":
		status, body = 400, fail
	}
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}},
		Body: io.NopCloser(strings.NewReader(body)), Request: r}, nil
}

func (c *cfRecorder) snapshot() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

func (c *cfRecorder) reset() {
	c.mu.Lock()
	c.calls = nil
	c.mu.Unlock()
}

func sfuScopeFixture(t *testing.T) (*App, *http.ServeMux, string, *cfRecorder) {
	t.Helper()
	app, _ := auditApp(t)
	EnsureBroadcastTable(app.DB)
	t.Setenv("BENMORE_PLATFORM_SFU_CF_APP_ID", platformCFAppID)
	t.Setenv("BENMORE_PLATFORM_SFU_CF_APP_TOKEN", "platform-sfu-token")
	rec := &cfRecorder{}
	old := http.DefaultTransport
	http.DefaultTransport = rec
	t.Cleanup(func() { http.DefaultTransport = old })
	mustExec(t, app.DB, `INSERT INTO _benmore_users (id, username, email) VALUES (1, 'a', 'a@example.test')`)
	sid := CreateSession(app.DB, 1, "a@example.test", "", time.Hour)
	mux := http.NewServeMux()
	RegisterBroadcastRoutes(mux, app)
	return app, mux, sid, rec
}

func sfuPost(mux *http.ServeMux, sid, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest("POST", path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sid})
	req.Header.Set("X-CSRF-Token", generateCSRFToken())
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, req)
	return rec
}

// The platform's Cloudflare token goes only to the platform's own Cloudflare
// app. A tenant that set SFU_CF_APP_ID alone used to have the platform token
// sent to a Cloudflare path of its choosing (another app id, or a path that
// walks out of /apps/<id>/).
func TestSFUPlatformTokenNeverPairsWithTenantAppID(t *testing.T) {
	app, mux, sid, rec := sfuScopeFixture(t)
	offer := `{"slug":"live","sdp":"v=0\r\na=mid:0\r\n"}`
	for _, tenantID := range []string{tenantCFAppID, "x/../../turn/keys/" + tenantCFAppID} {
		SetAppEnv(app.Dir, "SFU_CF_APP_ID", tenantID)
		rec.reset()
		sfuPost(mux, sid, "/api/_broadcast/publish", offer)
		calls := rec.snapshot()
		if len(calls) == 0 {
			t.Fatalf("tenant id %q: no SFU call made (the platform pair should still serve)", tenantID)
		}
		for _, call := range calls {
			if strings.HasPrefix(call, "platform-sfu-token ") && !strings.HasPrefix(call, "platform-sfu-token /v1/apps/"+platformCFAppID+"/") {
				t.Fatalf("tenant SFU_CF_APP_ID %q routed the platform token: %s", tenantID, call)
			}
		}
		mustExec(t, app.DB, `DELETE FROM _benmore_broadcasts`)
	}
}

// A complete tenant pair is used as a pair; an app id that is not hex is
// refused rather than placed in the request path.
func TestSFUTenantPairUsedTogetherAndIDMustBeHex(t *testing.T) {
	app, mux, sid, rec := sfuScopeFixture(t)
	offer := `{"slug":"live","sdp":"v=0\r\na=mid:0\r\n"}`
	SetAppEnv(app.Dir, "SFU_CF_APP_ID", tenantCFAppID)
	SetAppEnv(app.Dir, "SFU_CF_APP_TOKEN", "tenant-sfu-token")
	if w := sfuPost(mux, sid, "/api/_broadcast/publish", offer); w.Code != 200 {
		t.Fatalf("tenant pair publish: %d %s", w.Code, w.Body.String())
	}
	for _, call := range rec.snapshot() {
		if !strings.HasPrefix(call, "tenant-sfu-token /v1/apps/"+tenantCFAppID+"/") {
			t.Fatalf("tenant pair mixed with another scope: %s", call)
		}
	}
	mustExec(t, app.DB, `DELETE FROM _benmore_broadcasts`)
	SetAppEnv(app.Dir, "SFU_CF_APP_ID", "not-hex/../x")
	rec.reset()
	if w := sfuPost(mux, sid, "/api/_broadcast/publish", offer); w.Code != http.StatusServiceUnavailable || len(rec.snapshot()) != 0 {
		t.Fatalf("non-hex tenant app id: %d, calls %v", w.Code, rec.snapshot())
	}
}

// Cloudflare's error body is logged, never relayed to the browser.
func TestSFUFailureDoesNotRelayUpstreamDetail(t *testing.T) {
	_, mux, sid, rec := sfuScopeFixture(t)
	rec.failPull = `{"errorCode":"internal","errorDescription":"upstream-secret-detail"}`
	w := sfuPost(mux, sid, "/api/_broadcast/publish", `{"slug":"live","sdp":"v=0\r\na=mid:0\r\n"}`)
	if w.Code != http.StatusBadGateway || strings.Contains(w.Body.String(), "upstream-secret-detail") || strings.Contains(w.Body.String(), "detail") {
		t.Fatalf("publish failure relayed upstream detail: %d %s", w.Code, w.Body.String())
	}
}

// TURN credentials follow the same rule: the id and token come from one
// scope.
func TestTURNPlatformTokenNeverPairsWithTenantAppID(t *testing.T) {
	app, _ := auditApp(t)
	t.Setenv("BENMORE_PLATFORM_TURN_PROVIDER", "cloudflare")
	t.Setenv("BENMORE_PLATFORM_TURN_CF_APP_ID", platformCFAppID)
	t.Setenv("BENMORE_PLATFORM_TURN_CF_APP_TOKEN", "platform-turn-token")
	rec := &cfRecorder{}
	old := http.DefaultClient.Transport
	http.DefaultClient.Transport = rec
	t.Cleanup(func() { http.DefaultClient.Transport = old })

	SetAppEnv(app.Dir, "TURN_CF_APP_ID", tenantCFAppID)
	buildICEServers(app, "user:1")
	for _, call := range rec.snapshot() {
		if strings.HasPrefix(call, "platform-turn-token ") && call != "platform-turn-token /v1/turn/keys/"+platformCFAppID+"/credentials/generate" {
			t.Fatalf("tenant TURN_CF_APP_ID routed the platform token: %s", call)
		}
	}
	if len(rec.snapshot()) == 0 {
		t.Fatal("half a tenant pair should fall back to the platform pair")
	}

	rec.reset()
	SetAppEnv(app.Dir, "TURN_CF_APP_TOKEN", "tenant-turn-token")
	buildICEServers(app, "user:2")
	if calls := rec.snapshot(); len(calls) != 1 || calls[0] != "tenant-turn-token /v1/turn/keys/"+tenantCFAppID+"/credentials/generate" {
		t.Fatalf("tenant TURN pair: %v", calls)
	}

	rec.reset()
	SetAppEnv(app.Dir, "TURN_CF_APP_ID", "../../apps/x")
	buildICEServers(app, "user:3")
	if calls := rec.snapshot(); len(calls) != 0 {
		t.Fatalf("non-hex TURN app id was used: %v", calls)
	}
}
