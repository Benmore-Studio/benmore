//go:build !cli

package main

import (
	"net/http"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"
)

// App directories, rather than basenames, distinguish deployed environments.
func realtimeAppID(dir string) string {
	if dir == "" {
		return ""
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return ""
	}
	return filepath.Clean(abs)
}

func realtimeSameApp(a, b *App) bool {
	if a == nil || b == nil {
		return false
	}
	if a == b || (a.DB != nil && a.DB == b.DB) {
		return true
	}
	return a.Dir != "" && b.Dir != "" && realtimeAppID(a.Dir) == realtimeAppID(b.Dir)
}

// realtimeAnonClientKey is the address an anonymous stream counts against for
// the per-address connection caps: the router-resolved client, with an IPv6
// client keyed by its /64 (clientRateBucket) as the rate limits are. One
// subscriber is routinely handed a whole /64, and keying on the full address
// let it open a fresh allowance from every address in it until the hub's
// global cap - every user's realtime - was full.
func realtimeAnonClientKey(r *http.Request) string {
	return clientRateBucket(rateLimitClientHost(r))
}

// realtimePrincipalTTL bounds how long a connected stream trusts its last
// credential check. Fan-out reads the cached result, so one event costs no
// session lookups however many clients are connected. A revoked, expired,
// re-roled or tenant-switched session stops receiving events at most this long
// after the change; the connection itself is closed at the next heartbeat
// (25s SSE, 30s WebSocket), which always re-checks.
const realtimePrincipalTTL = 5 * time.Second

// realtimeRevalidations counts credential checks against the database; the
// fan-out benchmark reports it per broadcast.
var realtimeRevalidations atomic.Int64

// Keep the request credential, not just a connect-time admin flag. Revocation,
// expiry, role changes and tenant switches apply to established streams too.
type realtimePrincipal struct {
	app     *App
	request *http.Request
	session *Session
	// anonAdmitted reports whether the app still admits anonymous streams on
	// this transport. An anonymous principal stays valid only while it does:
	// a reload can turn features.ws_anonymous off, or add auth, under an
	// open stream. nil never re-checks (in-process callers).
	anonAdmitted func() bool
	// cache holds the last revalidation. nil re-checks on every call (the
	// shape tests and in-process callers construct directly).
	cache *realtimePrincipalCache
}

type realtimePrincipalCache struct {
	mu      sync.Mutex
	checked time.Time
	session *Session
	valid   bool
}

// withCache returns p with a revalidation cache seeded from the session the
// handler just resolved, so a fresh connection costs no extra lookup.
func (p realtimePrincipal) withCache() realtimePrincipal {
	p.cache = &realtimePrincipalCache{checked: time.Now(), session: p.session, valid: true}
	return p
}

// current returns the principal's live session, re-checking the credential at
// most once per realtimePrincipalTTL.
func (p realtimePrincipal) current() (*Session, bool) {
	c := p.cache
	if c == nil {
		return p.revalidate()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if time.Since(c.checked) < realtimePrincipalTTL {
		return c.session, c.valid
	}
	c.session, c.valid = p.revalidate()
	c.checked = time.Now()
	return c.session, c.valid
}

// refresh re-checks the credential now, regardless of the cache. Heartbeats
// use it so a revoked connection is closed on schedule.
func (p realtimePrincipal) refresh() (*Session, bool) {
	c := p.cache
	if c == nil {
		return p.revalidate()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.session, c.valid = p.revalidate()
	c.checked = time.Now()
	return c.session, c.valid
}

func (p realtimePrincipal) revalidate() (*Session, bool) {
	if p.request == nil {
		return p.session, true
	} // in-process synthetic clients
	realtimeRevalidations.Add(1)
	var current *Session
	if p.app != nil && p.app.DB != nil {
		current = getSession(p.app, p.request)
	}
	if p.session == nil {
		return nil, current == nil && (p.anonAdmitted == nil || p.anonAdmitted())
	}
	if current == nil || current.UserID != p.session.UserID ||
		current.EffectiveGroupID() != p.session.EffectiveGroupID() ||
		current.IsAdminBypass() != p.session.IsAdminBypass() {
		return nil, false
	}
	return current, true
}

func (p realtimePrincipal) canRead(table string, userID int64) bool {
	session, valid := p.current()
	if !valid || p.app == nil {
		return false
	}
	if table == notificationsTable {
		return session != nil && session.UserID == userID && notificationScopeError(session, "read") == nil
	}
	// Presence events name no slug or user; any signed-in stream may hear
	// them (presence itself requires sign-in).
	if table == presenceTable {
		return session != nil
	}
	return SessionCanAccessTable(p.app, table, OpRead, session) &&
		(session == nil || checkScope(session, table, "read") == nil)
}
