//go:build !cli

package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"sync"
	"time"
)

// SSE (Server-Sent Events) for live-updating components.
// Usage: <table :model="deals" live /> - auto-refreshes when data changes.
//
// SECURITY: auth required when app has auth. Events filtered SERVER-SIDE
// by group scope - clients only receive events for their own group.
// No client-side filtering. The server never sends events the client
// shouldn't see.

// sseClient represents a connected SSE client with their auth scope.
type sseClient struct {
	principal realtimePrincipal
	ch        chan string
	userID    int64
	groupID   string
	isAdmin   bool
	appDir    string // per-user cap is per app (one process may host many)
	remoteIP  string // anonymous per-IP cap (realtimeAnonClientKey)
}

// LOWER (sse.go): SSE connections previously had no connection cap and no
// read/idle bound, so a client could open many streams and hold them open
// indefinitely (slow-loris style) to exhaust server goroutines/sockets.
//   - realtimeSSEMaxConnsGlobal caps total concurrent SSE streams.
//   - realtimeSSEMaxConnLifetime forces a stream to close after a bounded
//     time; EventSource clients auto-reconnect, so this is transparent to
//     legitimate users but reclaims connections held open by abusers.
const (
	realtimeSSEMaxConnsGlobal  = 5000
	realtimeSSEMaxConnLifetime = 30 * time.Minute
	// realtimeSSEMaxConnsPerUser mirrors wsMaxConnsPerUser: one signed-in
	// account may not hold every slot of the global pool.
	realtimeSSEMaxConnsPerUser = 10
	// realtimeSSEMaxConnsPerAnonIP mirrors realtimeWSMaxConnsPerAnonIP.
	realtimeSSEMaxConnsPerAnonIP = 30
)

// sseWriteTimeout bounds each write to a stream (an event or a keepalive).
// A client that stops reading fills its receive window; the blocked write
// then fails and the handler releases the stream instead of waiting forever.
var sseWriteTimeout = 30 * time.Second

// SSEHub manages SSE connections with per-client scoping.
type SSEHub struct {
	mu      sync.RWMutex
	clients map[*sseClient]bool
}

var sseHub = &SSEHub{clients: make(map[*sseClient]bool)}

// RegisterSSERoutes sets up the SSE endpoint.
func RegisterSSERoutes(mux appRouteRegistrar, app *App) {
	needsAuth := NeedsAuth(app)

	mux.HandleFunc("GET /sse/events", func(w http.ResponseWriter, r *http.Request) {
		// Same `features.ws_anonymous: true` flag controls SSE too.
		// Re-read per request so SIGHUP reloads pick up the toggle
		// without a full unit restart.
		wsAnonymous := app.Design != nil && app.Design.Features != nil &&
			app.Design.Features.WSAnonymous != nil && *app.Design.Features.WSAnonymous
		if !isSameOriginRequest(r) {
			http.Error(w, "cross-origin sse blocked", http.StatusForbidden)
			return
		}
		// Auth: require authentication if app has auth. Dev mode skips
		// the gate so HMR reload events reach pre-auth pages (the SPA
		// auth screen, for instance). Data events still respect scope
		// because deliverRealtimeChange filters anonymous clients out - only
		// framework-level reload events deliver to them.
		var client sseClient
		// Anonymous streams end when the app stops admitting them (the
		// same gate as below, re-read at each credential check).
		client.principal = realtimePrincipal{app: app, request: r, anonAdmitted: func() bool {
			return !NeedsAuth(app) || devReloadClientEnabled(app) || broadcastAllowAnon(app)
		}}
		// Allow anonymous SSE wherever the dev reload client is injected so
		// the injected EventSource is never rejected with 401. This must
		// track devReloadClientEnabled (DevMode || testing) exactly - the
		// injection gate and the auth gate cannot be allowed to drift, or
		// testing-mode pages would connect but get rejected and the reload
		// would never fire.
		reloadAllowedAnonymous := devReloadClientEnabled(app)
		if needsAuth && !reloadAllowedAnonymous && !wsAnonymous {
			session := getSession(app, r)
			if session == nil {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			client.userID = session.UserID
			client.groupID = session.EffectiveGroupID()
			client.isAdmin = session.IsAdminBypass()
			client.principal.session = session
		} else if needsAuth && (reloadAllowedAnonymous || wsAnonymous) {
			// Try to attach session metadata if present so the dev
			// connection still receives scoped data events when the
			// user is logged in.
			if session := getSession(app, r); session != nil {
				client.userID = session.UserID
				client.groupID = session.EffectiveGroupID()
				client.isAdmin = session.IsAdminBypass()
				client.principal.session = session
			}
		}
		if client.principal.session == nil && app.DB != nil {
			if session := getSession(app, r); session != nil {
				client.principal.session = session
				client.userID, client.groupID, client.isAdmin = session.UserID, session.EffectiveGroupID(), session.IsAdminBypass()
			}
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			serverError(w, r, app, "sse", errors.New("the response writer cannot flush"), "SSE not supported")
			return
		}

		// The HTTP server has a 30s WriteTimeout, which would otherwise
		// cut every SSE connection at exactly 30s and trigger Chrome's
		// ERR_INCOMPLETE_CHUNKED_ENCODING. Each write instead sets its own
		// deadline (sseWriteTimeout from now), so the stream can stay open
		// while a client that stops reading still releases the handler;
		// the 25s heartbeat below keeps proxies happy. The middleware
		// wrappers (statusCapture, responseWriter, gzipResponseWriter) all
		// need to implement Unwrap() http.ResponseWriter for this to walk
		// down to the underlying net.Conn - otherwise the call returns
		// ErrNotSupported.
		rc := http.NewResponseController(w)
		if err := rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout)); err != nil {
			log.Printf("  sse: could not set write deadline (%v) - connection will be cut by server WriteTimeout", err)
		}
		// send writes one frame under a fresh deadline; false ends the stream.
		send := func(frame string) bool {
			_ = rc.SetWriteDeadline(time.Now().Add(sseWriteTimeout))
			if _, err := io.WriteString(w, frame); err != nil {
				return false
			}
			if err := rc.Flush(); err != nil {
				if !errors.Is(err, http.ErrNotSupported) {
					return false
				}
				flusher.Flush()
			}
			return true
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no") // for nginx

		client.ch = make(chan string, 10)
		remoteIP := realtimeAnonClientKey(r)
		// LOWER: enforce the global SSE connection cap under the write
		// lock so the hub size can never exceed realtimeSSEMaxConnsGlobal,
		// even under a flood of concurrent connects.
		sseHub.mu.Lock()
		if len(sseHub.clients) >= realtimeSSEMaxConnsGlobal {
			sseHub.mu.Unlock()
			http.Error(w, "too many connections", http.StatusServiceUnavailable)
			return
		}
		if client.userID != 0 && !client.isAdmin {
			perUser := 0
			for c := range sseHub.clients {
				if c.userID == client.userID && c.appDir == app.Dir {
					perUser++
				}
			}
			if perUser >= realtimeSSEMaxConnsPerUser {
				sseHub.mu.Unlock()
				http.Error(w, "too many connections for this account", http.StatusTooManyRequests)
				return
			}
		}
		if client.userID == 0 {
			perIP := 0
			for c := range sseHub.clients {
				if c.userID == 0 && c.remoteIP == remoteIP {
					perIP++
				}
			}
			if perIP >= realtimeSSEMaxConnsPerAnonIP {
				sseHub.mu.Unlock()
				http.Error(w, "too many connections", http.StatusTooManyRequests)
				return
			}
		}
		client.appDir = app.Dir
		client.remoteIP = remoteIP
		// Fan-out reads the cached credential check (realtimePrincipalTTL).
		client.principal = client.principal.withCache()
		sseHub.clients[&client] = true
		sseHub.mu.Unlock()

		// client.ch is never closed: the dispatcher sends to a snapshot of
		// the hub after releasing its lock, so a send may land after this
		// handler unregisters. A buffered, unread channel is just collected.
		defer func() {
			sseHub.mu.Lock()
			delete(sseHub.clients, &client)
			sseHub.mu.Unlock()
		}()

		if !send(": connected\n\n") {
			return
		}

		// Heartbeat under the typical 30s proxy/idle timeout. Comments
		// (lines starting with ":") are ignored by EventSource clients
		// but keep intermediaries from closing the stream.
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()

		// LOWER: bound the connection lifetime. Without this an idle or
		// deliberately-stalled client could hold the stream (and its
		// goroutine) open forever. EventSource transparently reconnects
		// after the server closes, so capping lifetime is invisible to
		// legitimate clients but caps the resource an abuser can pin.
		maxLifetime := time.NewTimer(realtimeSSEMaxConnLifetime)
		defer maxLifetime.Stop()

		for {
			select {
			case <-maxLifetime.C:
				return
			case msg, ok := <-client.ch:
				if !ok {
					return
				}
				// Wire format: an optional "<event>|" prefix lets the
				// broadcaster choose the SSE event name (e.g. "reload"
				// for dev HMR). Messages without a prefix default to
				// "change" - the existing CRUD-invalidation contract.
				event := "change"
				data := msg
				if idx := indexByte(msg, '|'); idx > 0 && idx < 24 && isEventName(msg[:idx]) {
					event = msg[:idx]
					data = msg[idx+1:]
				}
				if !send(fmt.Sprintf("event: %s\ndata: %s\n\n", event, data)) {
					return
				}
			case <-ticker.C:
				if _, valid := client.principal.refresh(); !valid {
					return
				}
				if !send(": keepalive\n\n") {
					return
				}
			case <-r.Context().Done():
				return
			}
		}
	})

	log.Printf("  sse: /sse/events (live component updates, server-side scoped)")
}

// BroadcastChange notifies SSE clients that a table changed (unscoped).
// Retained for backward compatibility - callers should prefer Broadcast/BroadcastUnscoped.
func BroadcastChange(app *App, table, action string) {
	BroadcastChangeScoped(app, table, action, "", 0)
}

// BroadcastReload pushes an SSE "reload" event to every connected
// client. Used by dev-mode HMR: when src/*.{jsx,tsx,ts,js} changes and
// the bundle is recompiled, the framework tells every open browser
// tab to reload so the new bundle takes effect. Reload events ignore
// auth scope - they are framework-level, not data-level, and a
// reload signal carries no user data. No-op in production where
// HotRecompileJSX is never called.
func BroadcastReload(app *App, reason string) {
	if reason == "" {
		reason = "src-changed"
	}
	// The reloaded page must version its scripts from the files on disk,
	// not from a tree version memoized a moment before the change.
	if app != nil {
		invalidateStaticTreeVersion(app.Dir)
	}
	data, _ := json.Marshal(map[string]string{"reason": reason})
	payload := `reload|` + string(data)
	sseHub.mu.RLock()
	n := len(sseHub.clients)
	for c := range sseHub.clients {
		if !realtimeSameApp(app, c.principal.app) {
			continue
		}
		select {
		case c.ch <- payload:
		default:
		}
	}
	sseHub.mu.RUnlock()
	log.Printf("  hmr: broadcast reload to %d client(s) (%s)", n, reason)
}

// indexByte and isEventName are small helpers for the SSE message
// dispatch. Kept local rather than importing strings, since the
// existing file already does its own framing.
func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}

func isEventName(s string) bool {
	if len(s) == 0 || len(s) > 24 {
		return false
	}
	for _, c := range s {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// BroadcastChangeScoped broadcasts a change event with group and user scope.
// Invalidates query cache and pushes to the local SSE + WS hubs.
// In cluster mode, this is called by the event poller for events from other instances.
// Callers outside the poller should prefer Broadcast/BroadcastScopedDirect which
// handle cluster vs single-instance routing.
func BroadcastChangeScoped(app *App, table, action string, groupID string, userID int64) {
	InvalidateQueryCacheForTable(table)
	dispatchRealtimeChange(app, realtimeChange{table: table, action: action, groupID: groupID, userID: userID})
}

// SSEClientScript returns the JavaScript that auto-refreshes live components.
// Only connects if the page has [data-live] elements. No client-side filtering
// needed - the server only sends events the client is authorized to see.
const SSEClientScript = `
(function() {
  if (!document.querySelector('[data-live]') && !document.querySelector('[data-live-table]')) return;
  // Reuse a single shared EventSource so a page that also injects the dev
  // reload client does not open two connections (two sseClient entries) per
  // tab. The dev reload script attaches its own listener to the same source.
  var source = window.__bmSSE || (window.__bmSSE = new EventSource('/sse/events'));
  source.addEventListener('change', function(e) {
    try {
      var data = JSON.parse(e.data);
      var selector;
      if (data.table) {
        selector = '[data-live-table="' + data.table + '"]';
      } else if (data.action === 'refresh') {
        // Scoped and opaque writes may invalidate without naming a table.
        selector = '[data-live], [data-live-table]';
      } else {
        return;
      }
      document.querySelectorAll(selector).forEach(function(el) {
        htmx.trigger(el, 'refresh');
      });
    } catch(err) {}
  });
  // Let EventSource reconnect after stream rotation or a network interruption.
  // Non-200 responses (including 401/403) already stop native reconnection.
})();
`

// DevReloadClientScript listens for framework-level hot reload events.
// It is injected only in dev/testing pages, independent of live data
// components, so a plain static HTML page reloads after a SIGHUP swap.
const DevReloadClientScript = `
(function() {
  if (window.__bmDevReloadClient) return;
  window.__bmDevReloadClient = true;
  // Reuse the shared EventSource if SSEClientScript already opened one (live
  // page), otherwise open our own. Either way only a single connection per
  // tab is created.
  var source = window.__bmSSE || (window.__bmSSE = new EventSource('/sse/events'));
  source.addEventListener('reload', function() {
    if (window.__bmDevReloading) return;
    window.__bmDevReloading = true;
    // Defer briefly so the server can flush the SSE write and any rapidly
    // coalesced reload events settle before we navigate away.
    setTimeout(function() { window.location.reload(); }, 25);
  });
  // Preserve the shared stream's native reconnect behavior, as above.
})();
`

func devReloadClientEnabled(app *App) bool {
	return app != nil && (app.DevMode || app.FeatureEnabled("testing"))
}
