//go:build !cli

package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"time"
)

// SSE (Server-Sent Events) for live-updating components.
// Usage: <table :model="deals" live /> — auto-refreshes when data changes.
//
// SECURITY: auth required when app has auth. Events filtered SERVER-SIDE
// by group scope — clients only receive events for their own group.
// No client-side filtering. The server never sends events the client
// shouldn't see.

// sseClient represents a connected SSE client with their auth scope.
type sseClient struct {
	ch      chan string
	userID  int64
	groupID string
	isAdmin bool
}

// SSEHub manages SSE connections with per-client scoping.
type SSEHub struct {
	mu      sync.RWMutex
	clients map[*sseClient]bool
}

var sseHub = &SSEHub{clients: make(map[*sseClient]bool)}

// RegisterSSERoutes sets up the SSE endpoint.
func RegisterSSERoutes(mux *http.ServeMux, app *App) {
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
		// because broadcastToSSE filters anonymous clients out — only
		// framework-level reload events deliver to them.
		var client sseClient
		if needsAuth && !app.DevMode && !wsAnonymous {
			session := getSession(app, r)
			if session == nil {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
			client.userID = session.UserID
			client.groupID = session.GroupID
			client.isAdmin = session.IsAdmin()
		} else if needsAuth && (app.DevMode || wsAnonymous) {
			// Try to attach session metadata if present so the dev
			// connection still receives scoped data events when the
			// user is logged in.
			if session := getSession(app, r); session != nil {
				client.userID = session.UserID
				client.groupID = session.GroupID
				client.isAdmin = session.IsAdmin()
			}
		}

		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "SSE not supported", http.StatusInternalServerError)
			return
		}

		// The HTTP server has a 30s WriteTimeout, which would otherwise
		// cut every SSE connection at exactly 30s and trigger Chrome's
		// ERR_INCOMPLETE_CHUNKED_ENCODING. Clear the deadline for this
		// response so the stream can stay open indefinitely; the 25s
		// heartbeat below keeps proxies happy. The middleware wrappers
		// (statusCapture, responseWriter, gzipResponseWriter) all need
		// to implement Unwrap() http.ResponseWriter for this to walk
		// down to the underlying net.Conn — otherwise the call returns
		// ErrNotSupported silently.
		rc := http.NewResponseController(w)
		if err := rc.SetWriteDeadline(time.Time{}); err != nil {
			log.Printf("  sse: could not clear write deadline (%v) — connection will be cut by server WriteTimeout", err)
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no") // for nginx

		client.ch = make(chan string, 10)
		sseHub.mu.Lock()
		sseHub.clients[&client] = true
		sseHub.mu.Unlock()

		defer func() {
			sseHub.mu.Lock()
			delete(sseHub.clients, &client)
			sseHub.mu.Unlock()
			close(client.ch)
		}()

		fmt.Fprintf(w, ": connected\n\n")
		flusher.Flush()

		// Heartbeat under the typical 30s proxy/idle timeout. Comments
		// (lines starting with ":") are ignored by EventSource clients
		// but keep intermediaries from closing the stream.
		ticker := time.NewTicker(25 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case msg, ok := <-client.ch:
				if !ok {
					return
				}
				// Wire format: an optional "<event>|" prefix lets the
				// broadcaster choose the SSE event name (e.g. "reload"
				// for dev HMR). Messages without a prefix default to
				// "change" — the existing CRUD-invalidation contract.
				event := "change"
				data := msg
				if idx := indexByte(msg, '|'); idx > 0 && idx < 24 && isEventName(msg[:idx]) {
					event = msg[:idx]
					data = msg[idx+1:]
				}
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", event, data)
				flusher.Flush()
			case <-ticker.C:
				fmt.Fprintf(w, ": keepalive\n\n")
				flusher.Flush()
			case <-r.Context().Done():
				return
			}
		}
	})

	log.Printf("  sse: /sse/events (live component updates, server-side scoped)")
}

// BroadcastChange notifies SSE clients that a table changed (unscoped).
// Retained for backward compatibility — callers should prefer Broadcast/BroadcastUnscoped.
func BroadcastChange(table, action string) {
	BroadcastChangeScoped(table, action, "", 0)
}

// BroadcastReload pushes an SSE "reload" event to every connected
// client. Used by dev-mode HMR: when src/*.{jsx,tsx,ts,js} changes and
// the bundle is recompiled, the framework tells every open browser
// tab to reload so the new bundle takes effect. Reload events ignore
// auth scope — they are framework-level, not data-level, and a
// reload signal carries no user data. No-op in production where
// HotRecompileJSX is never called.
func BroadcastReload(reason string) {
	if reason == "" {
		reason = "src-changed"
	}
	payload := `reload|{"reason":"` + reason + `"}`
	sseHub.mu.RLock()
	n := len(sseHub.clients)
	for c := range sseHub.clients {
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
func BroadcastChangeScoped(table, action string, groupID string, userID int64) {
	InvalidateQueryCacheForTable(table)
	broadcastToSSE(table, action, groupID, userID)
	BroadcastWSChange(table, action, groupID, userID)
}

// SSEClientScript returns the JavaScript that auto-refreshes live components.
// Only connects if the page has [data-live] elements. No client-side filtering
// needed — the server only sends events the client is authorized to see.
const SSEClientScript = `
(function() {
  if (!document.querySelector('[data-live]') && !document.querySelector('[data-live-table]')) return;
  var source = new EventSource('/sse/events');
  source.addEventListener('change', function(e) {
    try {
      var data = JSON.parse(e.data);
      document.querySelectorAll('[data-live-table="' + data.table + '"]').forEach(function(el) {
        htmx.trigger(el, 'refresh');
      });
    } catch(err) {}
  });
  source.onerror = function() { source.close(); };
})();
`
