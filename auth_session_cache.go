//go:build !cli

package main

// Per-request session cache.
//
// getSession costs a sessions/users join, role-grant and admin-grant reads
// and, for tenant apps, membership checks - about five queries - and one
// request resolved it two or three times: the required-password-change gate,
// the handler, and the request log (plus analytics). requestSessionCacheMiddleware
// puts a holder in the request context; getSession answers from it when the
// same request presents the same credential again.
//
// Correctness rules:
//   - Entries are keyed by app and by the exact credential the request
//     carries (session cookie value and Authorization header), so an
//     in-process sub-request with another identity never reads them. Edge
//     bridge and private connector identities are never cached.
//   - Every hit returns a copy: callers adjust the Session they get.
//   - An entry lives at most requestSessionCacheTTL. Long-lived streams
//     (WebSocket, SSE) re-check their session on every event to see
//     revocation, so they get no holder at all, and the TTL bounds any
//     stream that doesn't announce itself.
//   - Code that changes the presenting session within a request (logout,
//     revocation, group switch, act-as, impersonation, password change or
//     reset, account deletion, email verification) calls
//     invalidateRequestSession so the next lookup reads the database.

import (
	"context"
	"net/http"
	"strings"
	"sync"
	"time"
)

const requestSessionCacheTTL = time.Second

type requestSessionCacheKey struct{}

type requestSessionEntry struct {
	app     *App
	cred    string
	at      time.Time
	session *Session // nil: the credential resolves to no session
}

type requestSessionHolder struct {
	mu      sync.Mutex
	entries []requestSessionEntry
}

// requestSessionCacheMiddleware installs the per-request holder.
func requestSessionCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if requestIsLongLivedStream(r) {
			next.ServeHTTP(w, r)
			return
		}
		ctx := context.WithValue(r.Context(), requestSessionCacheKey{}, &requestSessionHolder{})
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

// requestIsLongLivedStream reports a WebSocket upgrade or an EventSource.
func requestIsLongLivedStream(r *http.Request) bool {
	return strings.Contains(strings.ToLower(r.Header.Get("Upgrade")), "websocket") ||
		strings.Contains(r.Header.Get("Accept"), "text/event-stream")
}

func requestSessionHolderFor(r *http.Request) *requestSessionHolder {
	if r == nil {
		return nil
	}
	h, _ := r.Context().Value(requestSessionCacheKey{}).(*requestSessionHolder)
	return h
}

// requestSessionCredential is the cache key for the identity r presents, or
// false when that identity must be resolved every time.
func requestSessionCredential(r *http.Request) (string, bool) {
	if r.Header.Get("X-Benmore-Edge-User") != "" {
		return "", false // edge bridge: a signed, time-boxed per-request assertion
	}
	cookie := ""
	if c, err := requestSessionCookie(r); err == nil {
		cookie = c.Value
	}
	return cookie + "\x00" + r.Header.Get("Authorization"), true
}

func cloneSession(s *Session) *Session {
	if s == nil {
		return nil
	}
	c := *s
	if s.Roles != nil {
		c.Roles = append([]string(nil), s.Roles...)
	}
	if s.Permissions != nil {
		c.Permissions = append([]string(nil), s.Permissions...)
	}
	return &c
}

func (h *requestSessionHolder) get(app *App, cred string, now time.Time) (*Session, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for _, e := range h.entries {
		if e.app == app && e.cred == cred {
			if now.Sub(e.at) > requestSessionCacheTTL || now.Before(e.at) {
				return nil, false
			}
			return cloneSession(e.session), true
		}
	}
	return nil, false
}

func (h *requestSessionHolder) put(app *App, cred string, s *Session, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	entry := requestSessionEntry{app: app, cred: cred, at: now, session: cloneSession(s)}
	replaced := false
	for i := range h.entries {
		if h.entries[i].app == app && h.entries[i].cred == cred {
			h.entries[i] = entry
			replaced = true
			break
		}
	}
	if !replaced {
		h.entries = append(h.entries, entry)
	}
}

// invalidateRequestSession drops every cached session for this request, so
// the next getSession reads the database. Call it after changing the
// session (or account) the request presents.
func invalidateRequestSession(r *http.Request) {
	if h := requestSessionHolderFor(r); h != nil {
		h.mu.Lock()
		h.entries = nil
		h.mu.Unlock()
	}
}

// cachedRequestSession is the session for request-log and analytics
// middleware that runs around the handler. It is getSession, which already
// answers from this request's cache; after an invalidation (a logout, an
// account deletion) it reads the database again, so a request that erased
// its account doesn't log the erased identity.
func cachedRequestSession(app *App, r *http.Request) *Session {
	return getSession(app, r)
}
