//go:build !cli

package main

// Router-to-app proof for the forwarded-client headers.
//
// The router reaches every app over loopback and tells it the client address,
// scheme and vetted Host (X-Benmore-App, X-Forwarded-*). Loopback is shared by
// every tenant on the machine, so a process in tenant A could connect to
// tenant B's port and send the same headers. The router therefore also signs
// them: X-Benmore-Router-Sig is an HMAC-SHA256 keyed by the TARGET app's own
// server secret over the timestamp, method, Host, client address and scheme.
// An app trusts the marker only when the signature verifies inside a short
// clock window.
//
// The target app is bound implicitly: every instance (each tenant, prod and
// dev separately) has its own secret, which the router writes and hands to
// that instance alone, so a request the router signed for tenant A never
// verifies at tenant B and replaying it there gains nothing. _platform shares
// the router's own secret, which no tenant holds. Signing the subdomain too
// would add no protection.
//
// Signatures are REQUIRED by default (the router has signed since before this
// default changed, and router and apps ship the same binary). An operator
// whose fleet sits behind an older, non-signing router can set
// BENMORE_REQUIRE_ROUTER_SIG=0 (or false/no/off) on the app units to accept
// an unsigned marker during that rollout; any other value requires it.

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	routerSigHeader     = "X-Benmore-Router-Sig"
	routerSigTimeHeader = "X-Benmore-Router-Time"
	routerSigWindow     = 30 * time.Second
	routerSigMinSecret  = 32
)

// routerSigNow is the clock, replaceable in tests.
var routerSigNow = time.Now

// requireRouterSig reports whether an unsigned router marker is refused: true
// unless the operator explicitly turned BENMORE_REQUIRE_ROUTER_SIG off.
func requireRouterSig() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("BENMORE_REQUIRE_ROUTER_SIG"))) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

func routerSigMAC(secret, ts, method, host, ip, scheme string) string {
	// Domain-separated key so the signature is never valid for any other
	// use of the server secret (CSRF, signed URLs, handoff tokens).
	km := hmac.New(sha256.New, []byte(secret))
	km.Write([]byte("benmore-router-sig-v1-key"))
	m := hmac.New(sha256.New, km.Sum(nil))
	for _, part := range []string{ts, strings.ToUpper(method), strings.ToLower(host), ip, scheme} {
		// Length-prefix each field so none can borrow bytes from the next.
		m.Write([]byte(strconv.Itoa(len(part)) + ":" + part + "\n"))
	}
	return hex.EncodeToString(m.Sum(nil))
}

// signRouterHeaders adds the timestamp and signature for a request the
// router is about to send. h must already hold X-Forwarded-Proto (or leave it
// unset) exactly as the app will see it; ip is the X-Forwarded-For entry the
// router wrote. A missing or short secret signs nothing (the app then sees an
// unsigned marker, the legacy shape).
func signRouterHeaders(h http.Header, method, host, ip, secret string) bool {
	h.Del(routerSigHeader)
	h.Del(routerSigTimeHeader)
	if len(secret) < routerSigMinSecret {
		return false
	}
	ts := strconv.FormatInt(routerSigNow().Unix(), 10)
	h.Set(routerSigTimeHeader, ts)
	h.Set(routerSigHeader, routerSigMAC(secret, ts, method, host, ip, h.Get("X-Forwarded-Proto")))
	return true
}

// routerSigValid verifies the router's proof on r with this process's own
// server secret. The signed client address is the first X-Forwarded-For entry
// (the router writes it; the reverse proxy appends its peer after it).
func routerSigValid(r *http.Request) bool {
	if len(serverSecret) < routerSigMinSecret {
		return false
	}
	ts := r.Header.Get(routerSigTimeHeader)
	sig := r.Header.Get(routerSigHeader)
	if ts == "" || sig == "" {
		return false
	}
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	skew := routerSigNow().Sub(time.Unix(sec, 0))
	if skew < -routerSigWindow || skew > routerSigWindow {
		return false
	}
	ip := ""
	if hops := forwardedHops(r.Header.Values("X-Forwarded-For")); len(hops) > 0 {
		ip = hops[0]
	}
	want := routerSigMAC(serverSecret, ts, r.Method, r.Host, ip, r.Header.Get("X-Forwarded-Proto"))
	return hmac.Equal([]byte(want), []byte(sig))
}

// routerMarkerTrusted is the one question every consumer of the router's
// headers asks: did the platform router deliver this request? It needs a
// loopback peer, the X-Benmore-App marker and a valid router signature; only
// with BENMORE_REQUIRE_ROUTER_SIG explicitly off is the marker alone believed
// (an old router during rollout).
func routerMarkerTrusted(r *http.Request) bool {
	if !routerMarkerFromLoopback(r) {
		return false
	}
	return !requireRouterSig() || routerSigValid(r)
}

// routerMarkerSigned is routerMarkerTrusted without the rollout escape hatch:
// the signature must verify whatever BENMORE_REQUIRE_ROUTER_SIG says. Uses
// whose failure mode is account takeover rather than a shared rate-limit
// bucket (trusting the Host for emailed credential links) ask this instead.
func routerMarkerSigned(r *http.Request) bool {
	return routerMarkerFromLoopback(r) && routerSigValid(r)
}

func routerMarkerFromLoopback(r *http.Request) bool {
	if r.Header.Get("X-Benmore-App") == "" {
		return false
	}
	peer := r.RemoteAddr
	if h, _, err := net.SplitHostPort(peer); err == nil {
		peer = h
	}
	ip := net.ParseIP(peer)
	return ip != nil && ip.IsLoopback()
}
