//go:build !cli

package main

import (
	"fmt"
	"log"
	"net/http"
	"runtime/debug"
)

// recoverMiddleware catches panics from any inner HTTP handler and returns
// a 500 response instead of crashing the entire process. Without this,
// a single bad page render or buggy hook could systemd-restart benmore
// and take down every hosted app on the box.
//
// MUST be the outermost middleware so it catches panics from the request
// logger, gzip, security headers, rate limiter, etc.
//
// Issue #2.
func recoverMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				stack := debug.Stack()
				log.Printf("PANIC %s %s — %v\n%s", r.Method, r.URL.Path, rec, stack)
				// Best-effort 500. If headers are already written, this is a
				// no-op and the client just sees a truncated response — which
				// is still better than a process crash.
				w.Header().Set("Content-Type", "text/html; charset=utf-8")
				w.WriteHeader(http.StatusInternalServerError)
				fmt.Fprint(w, `<!doctype html><html><head><title>Error</title></head><body style="font-family:system-ui,sans-serif;padding:40px;text-align:center"><h1>Something went wrong</h1><p style="color:#666">A server error occurred. The team has been notified.</p></body></html>`)
			}
		}()
		next.ServeHTTP(w, r)
	})
}

// safeGo spawns a background goroutine that recovers from panics, logs them,
// and prevents the process from crashing. Use for ANY long-lived background
// worker — jobs queue, SSE broadcaster, retention sweep, scheduled backups,
// aggregate refresh, lock cleanup, analytics flush, metering flush, etc.
//
// `name` appears in panic logs so we can identify which worker died.
//
// Issue #2 + #5.
func safeGo(name string, fn func()) {
	go func() {
		defer func() {
			if rec := recover(); rec != nil {
				log.Printf("PANIC in goroutine %q: %v\n%s", name, rec, debug.Stack())
			}
		}()
		fn()
	}()
}
