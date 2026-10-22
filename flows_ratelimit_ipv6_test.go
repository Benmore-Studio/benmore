//go:build !cli

package main

import (
	"database/sql"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

// A flow's declared `rate_limit: "N/window per ip"` (and the IP fallback of
// the user/email/group scopes for anonymous callers) is the abuse cap on a
// public endpoint: sign-up helpers, invite redemption, code mailers. It keyed
// on the full client address, so an IPv6 client - routinely handed a whole
// /64 - took a fresh address per request and was never limited.
func TestFlowRateLimitCountsIPv6ByPrefix(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	app := &App{Dir: dir, DB: db}

	flow := &Flow{
		Name:      "send-code-ipv6-prefix",
		Trigger:   FlowTrigger{Type: "http", Method: "POST", Path: "/api/send-code"},
		RateLimit: &FlowRateLimit{Rate: 2, Window: time.Hour, Scope: "ip", Raw: "2/hour per ip"},
		Steps: []FlowStep{{
			Type:    "respond",
			Respond: &FlowRespond{Status: 200, JSON: map[string]any{"ok": true}},
		}},
	}
	call := func(ip string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/send-code", nil)
		req.RemoteAddr = net.JoinHostPort(ip, "5555")
		rr := httptest.NewRecorder()
		executeFlowHTTP(app, flow, rr, req)
		return rr.Code
	}
	for _, ip := range []string{"2001:db8:aa:bb::1", "2001:db8:aa:bb::2"} {
		if code := call(ip); code != http.StatusOK {
			t.Fatalf("request from %s within the limit: %d", ip, code)
		}
	}
	if code := call("2001:db8:aa:bb::3"); code != http.StatusTooManyRequests {
		t.Fatalf("a third address in the same /64 was not limited: %d", code)
	}
	if code := call("2001:db8:aa:cc::1"); code != http.StatusOK {
		t.Fatalf("another /64 has its own budget: %d", code)
	}
	if code := call("192.0.2.7"); code != http.StatusOK {
		t.Fatalf("IPv4 client: %d", code)
	}
}
