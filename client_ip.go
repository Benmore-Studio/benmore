//go:build !cli

package main

// Client address resolution for per-IP limits, throttles and request logs.
//
// A forwarded address is believed only from a peer known to set it:
// Cloudflare's edge (CF-Connecting-IP, or the X-Forwarded-For entry it
// appends), a reverse proxy the operator declares with BENMORE_TRUST_PROXY,
// or - platform builds only - the router reaching an app over loopback with
// its X-Benmore-App marker (signed with the app's own secret, see
// router_sig.go, and required unless BENMORE_REQUIRE_ROUTER_SIG is set off;
// every reader of that marker goes through routerMarkerTrusted). Forwarded hops are walked from the right and the
// first untrusted one is the client, so entries a client writes itself are
// never reached. Anything else keys on the TCP peer: a client cannot choose
// its own rate-limit bucket by sending a header.

import (
	"net"
	"net/http"
	"os"
	"strings"
)

// cloudflareEdgeNets are Cloudflare's published edge ranges
// (https://www.cloudflare.com/ips-v4 and /ips-v6, checked 2026-09-23).
var cloudflareEdgeNets = parseTrustedNets(
	"173.245.48.0/20 103.21.244.0/22 103.22.200.0/22 103.31.4.0/22 " +
		"141.101.64.0/18 108.162.192.0/18 190.93.240.0/20 188.114.96.0/20 " +
		"197.234.240.0/22 198.41.128.0/17 162.158.0.0/15 104.16.0.0/13 " +
		"104.24.0.0/14 172.64.0.0/13 131.0.72.0/22 " +
		"2400:cb00::/32 2606:4700::/32 2803:f800::/32 2405:b500::/32 " +
		"2405:8100::/32 2a06:98c0::/29 2c0f:f248::/32")

// resolveClientIP returns the client address for r. trustRouter is true only
// in platform builds, where the router is the one thing that connects to an
// app over loopback with X-Benmore-App set.
func resolveClientIP(r *http.Request, trustRouter bool) string {
	peer := r.RemoteAddr
	if h, _, err := net.SplitHostPort(peer); err == nil {
		peer = h
	}
	ip := net.ParseIP(peer)
	if ip == nil {
		return peer
	}
	hops := forwardedHops(r.Header.Values("X-Forwarded-For"))
	if trustRouter && routerMarkerTrusted(r) {
		// The router writes the first entry; the proxy appends its own peer.
		if len(hops) > 0 {
			if first := parseHopIP(hops[0]); first != nil {
				return first.String()
			}
		}
		return ip.String()
	}
	proxies := operatorTrustedProxies()
	hop := ip
	for i := len(hops); ; i-- {
		if ipInNets(hop, cloudflareEdgeNets) {
			if cf := parseHopIP(r.Header.Get("CF-Connecting-IP")); cf != nil {
				return cf.String()
			}
		} else if !proxies.trusts(hop) {
			return hop.String()
		}
		if i == 0 {
			break
		}
		next := parseHopIP(hops[i-1])
		if next == nil {
			return hop.String()
		}
		hop = next
	}
	// Every hop is a proxy we trust; a lone proxy may name the client in
	// X-Real-IP instead of X-Forwarded-For.
	if len(hops) == 0 && proxies.trusts(ip) {
		if real := parseHopIP(r.Header.Get("X-Real-IP")); real != nil {
			return real.String()
		}
	}
	return hop.String()
}

// trustedProxies is the operator's BENMORE_TRUST_PROXY declaration: "1"
// (or true/yes/on) trusts loopback and private-network peers; otherwise the
// value is a list of addresses or CIDRs.
type trustedProxies struct {
	local bool
	nets  []*net.IPNet
}

func operatorTrustedProxies() trustedProxies {
	v := strings.TrimSpace(os.Getenv("BENMORE_TRUST_PROXY"))
	switch strings.ToLower(v) {
	case "", "0", "false", "no", "off":
		return trustedProxies{}
	case "1", "true", "yes", "on":
		return trustedProxies{local: true}
	}
	return trustedProxies{nets: parseTrustedNets(v)}
}

func (p trustedProxies) trusts(ip net.IP) bool {
	if p.local && (ip.IsLoopback() || ip.IsPrivate()) {
		return true
	}
	return ipInNets(ip, p.nets)
}

// parseTrustedNets parses a comma- or space-separated list of CIDRs and
// bare addresses; entries that parse as neither are ignored.
func parseTrustedNets(list string) []*net.IPNet {
	var nets []*net.IPNet
	for _, f := range strings.FieldsFunc(list, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' }) {
		if _, n, err := net.ParseCIDR(f); err == nil {
			nets = append(nets, n)
		} else if ip := net.ParseIP(f); ip != nil {
			bits := 128
			if ip.To4() != nil {
				ip, bits = ip.To4(), 32
			}
			nets = append(nets, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
		}
	}
	return nets
}

func ipInNets(ip net.IP, nets []*net.IPNet) bool {
	for _, n := range nets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// forwardedHops folds every X-Forwarded-For header into one ordered list.
func forwardedHops(values []string) []string {
	var hops []string
	for _, v := range values {
		for _, h := range strings.Split(v, ",") {
			if h = strings.TrimSpace(h); h != "" {
				hops = append(hops, h)
			}
		}
	}
	return hops
}

// parseHopIP accepts a bare address or one carrying a port ("1.2.3.4:80",
// "[2001:db8::1]:443").
func parseHopIP(s string) net.IP {
	s = strings.TrimSpace(s)
	if h, _, err := net.SplitHostPort(s); err == nil {
		s = h
	}
	return net.ParseIP(strings.Trim(s, "[]"))
}

// clientRateBucket is the rate-limit key for a resolved client address. IPv4
// addresses stand alone; an IPv6 client is keyed by its /64, because one
// subscriber is routinely handed a whole /64 and could rotate through its
// addresses to get a fresh budget on every request.
func clientRateBucket(ip string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil || parsed.To4() != nil {
		return ip
	}
	return parsed.Mask(net.CIDRMask(64, 128)).String() + "/64"
}
