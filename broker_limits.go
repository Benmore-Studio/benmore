package main

// Shared resource limits for the router's unix-socket brokers (email, SMS,
// presign). The connection gate (broker_conn_gate.go) bounds how many
// connections each tenant holds; these bound how long a connection may take
// to deliver its request, how much request memory tenants can pin at once,
// and how often a peer uid is resolved against the account database.

import (
	"errors"
	"io"
	"net"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"time"
)

// brokerRequestReadTimeout bounds the request-read phase separately from the
// handler's overall deadline. Clients write the whole request and half-close
// at once over a local socket (35 MiB arrives in well under a second), so a
// peer still sending after this is trickling bytes to pin a slot.
const brokerRequestReadTimeout = 5 * time.Second

// beginBrokerRead arms the short read deadline for the request phase; the
// handler re-arms its overall deadline once the request is decoded.
func beginBrokerRead(conn net.Conn, timeout time.Duration) {
	conn.SetReadDeadline(time.Now().Add(timeout))
}

// emailLargeRequestThreshold is where an email request stops being "small":
// past it the broker needs one of a few platform-wide large-request slots
// before buffering more. Ordinary transactional mail (OTP, reset, receipts)
// is a few KiB; only attachments get near it.
const emailLargeRequestThreshold = 1 << 20

// emailLargeSlots bounds tenant requests buffering past the threshold at
// once. Each may hold up to the 35 MiB request cap plus its decoded copy, so
// 3 slots keep tenant attachment buffering near 200-300 MiB instead of the
// 32 x 35 MiB the connection gate alone allowed. First-party callers (the
// router's own uid) never wait on it.
var emailLargeSlots = make(chan struct{}, 3)

var errBrokerBusy = errors.New("broker busy with large requests")

// largeRequestReader counts bytes read and, the first time the count passes
// threshold, takes a slot from slots (waiting at most wait). It holds the
// slot until release, which the handler calls once it no longer holds the
// request (after the send).
type largeRequestReader struct {
	r         io.Reader
	n         int64
	threshold int64
	slots     chan struct{}
	wait      time.Duration
	held      bool
	exempt    bool
}

func (l *largeRequestReader) Read(p []byte) (int, error) {
	if len(p) == 0 || l.held || l.exempt || l.n+int64(len(p)) <= l.threshold {
		n, err := l.r.Read(p)
		l.n += int64(n)
		return n, err
	}
	// Only pay for a slot once the request actually grows past the
	// threshold: read up to it first, then probe one byte so a request
	// that ends exactly at the threshold never waits.
	if room := l.threshold - l.n; room > 0 {
		n, err := l.r.Read(p[:room])
		l.n += int64(n)
		return n, err
	}
	n, err := l.r.Read(p[:1])
	if n == 0 {
		return 0, err
	}
	select {
	case l.slots <- struct{}{}:
		l.held = true
	case <-time.After(l.wait):
		return 0, errBrokerBusy
	}
	l.n += int64(n)
	return n, err
}

func (l *largeRequestReader) release() {
	if l.held {
		l.held = false
		<-l.slots
	}
}

// ─── peer uid → app identity cache ───────────────────────────────────────

// Resolving a uid parses the account database on every lookup. A positive
// result is reused for brokerUIDTTL: long enough to absorb a send burst,
// short enough that a uid freed by deprovision and reused by a new tenant
// cannot act as the old app for long. A miss (unknown uid, non-app user) is
// remembered only briefly, because a tenant's user appears at provisioning
// moments before its first broker call.
const (
	brokerUIDTTL     = 30 * time.Second
	brokerUIDMissTTL = 2 * time.Second
)

type brokerUIDEntry struct {
	prefix     string
	firstParty bool
	expires    time.Time
}

var (
	brokerUIDMu    sync.Mutex
	brokerUIDCache = map[int]brokerUIDEntry{}
	// brokerUIDLookup resolves a uid to a username; replaceable in tests.
	brokerUIDLookup = func(uid int) (string, error) {
		u, err := user.LookupId(strconv.Itoa(uid))
		if err != nil {
			return "", err
		}
		return u.Username, nil
	}
	brokerUIDNow = time.Now
)

// brokerUIDCacheMax bounds the map: the host has a few hundred app users, so
// anything past this is churn and the cache is simply reset.
const brokerUIDCacheMax = 4096

// prefixForUID maps a connecting uid to its app key prefix. Returns
// (prefix, firstParty). firstParty=true for the shared "benmore" user (the
// router and the _platform app), which is trusted to supply its own prefix.
func prefixForUID(uid int) (prefix string, firstParty bool) {
	now := brokerUIDNow()
	brokerUIDMu.Lock()
	if e, ok := brokerUIDCache[uid]; ok && now.Before(e.expires) {
		brokerUIDMu.Unlock()
		return e.prefix, e.firstParty
	}
	brokerUIDMu.Unlock()

	e := brokerUIDEntry{expires: now.Add(brokerUIDMissTTL)}
	if name, err := brokerUIDLookup(uid); err == nil {
		if name == "benmore" {
			e.firstParty = true
		} else if sub := strings.TrimPrefix(name, "benmore-app-"); sub != name && sub != "" {
			e.prefix = sub
		}
		if e.firstParty || e.prefix != "" {
			e.expires = now.Add(brokerUIDTTL)
		}
	}
	brokerUIDMu.Lock()
	if len(brokerUIDCache) >= brokerUIDCacheMax {
		brokerUIDCache = map[int]brokerUIDEntry{}
	}
	brokerUIDCache[uid] = e
	brokerUIDMu.Unlock()
	return e.prefix, e.firstParty
}
