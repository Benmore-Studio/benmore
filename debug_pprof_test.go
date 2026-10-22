//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPprofRefusesNonLoopbackAddresses(t *testing.T) {
	for _, addr := range []string{":6060", "0.0.0.0:6060", "[::]:6060", "10.0.0.5:6060", "192.168.1.2:6060", "example.com:6060", "127.0.0.1", ""} {
		if err := pprofAddrAllowed(addr); err == nil {
			t.Errorf("%q accepted", addr)
		}
	}
	for _, addr := range []string{"127.0.0.1:6060", "[::1]:6060", "localhost:6060", "127.0.0.2:6060"} {
		if err := pprofAddrAllowed(addr); err != nil {
			t.Errorf("%q refused: %v", addr, err)
		}
	}
	if _, err := listenPprof("0.0.0.0:0", strings.Repeat("t", 32)); err == nil {
		t.Fatal("listenPprof bound a non-loopback address")
	}
	if _, err := listenPprof("127.0.0.1:0", ""); err == nil {
		t.Fatal("listenPprof started without a token")
	}
	if _, err := listenPprof("127.0.0.1:0", "short"); err == nil {
		t.Fatal("listenPprof accepted a short token")
	}
	ln, err := listenPprof("127.0.0.1:0", strings.Repeat("t", 32))
	if err != nil {
		t.Fatal(err)
	}
	ln.Close()
}

func TestPprofRequiresToken(t *testing.T) {
	token := strings.Repeat("s", 32)
	h := pprofHandler(token)
	for name, auth := range map[string]string{
		"missing": "",
		"wrong":   "Bearer " + strings.Repeat("x", 32),
		"prefix":  "Bearer " + token[:16],
		"scheme":  token,
	} {
		w := httptest.NewRecorder()
		r := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
		if auth != "" {
			r.Header.Set("Authorization", auth)
		}
		h.ServeHTTP(w, r)
		if w.Code != http.StatusUnauthorized {
			t.Errorf("%s token: status %d, want 401", name, w.Code)
		}
	}
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	h.ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "goroutine") {
		t.Fatalf("authorized index: %d", w.Code)
	}
	// An empty configured token never authorizes, even an empty header.
	w = httptest.NewRecorder()
	r = httptest.NewRequest(http.MethodGet, "/debug/pprof/", nil)
	r.Header.Set("Authorization", "Bearer ")
	pprofHandler("").ServeHTTP(w, r)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("empty token authorized: %d", w.Code)
	}
}
