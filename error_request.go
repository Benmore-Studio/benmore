//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"regexp"
	"runtime"
	"strings"
)

var errorRouteIDRE = regexp.MustCompile(`^(?:[0-9]+|[0-9a-fA-F]{8,}|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$`)

func normalizeRoutePath(path string) string {
	parts := strings.Split(path, "/")
	for i, p := range parts {
		if errorRouteIDRE.MatchString(p) {
			parts[i] = ":id"
		}
	}
	return strings.Join(parts, "/")
}

func reportRequestFailure(app *App, r *http.Request, slot *requestLogSlot, status int) {
	if slot == nil || status < 500 || status == 503 || status == 507 {
		return
	}
	id := requestErrorID(r)
	slot.mu.Lock()
	if slot.reported {
		slot.mu.Unlock()
		return
	}
	slot.reported = true
	ev := errorEvent{Source: "server", Level: "error", Kind: "server", Type: slot.where, Message: slot.exportError,
		Method: r.Method, RequestID: id, Mechanism: "generic", Handled: true, pcs: slot.pcs, UserAgent: errorUserAgent(r.UserAgent())}
	if slot.panicked {
		ev.Level, ev.Mechanism, ev.Handled = "fatal", "panic", false
		ev.Type = "panic"
		ev.Message = slot.panicValue
	}
	slot.mu.Unlock()
	ev.Route = r.Pattern
	if ev.Route == "" {
		ev.Route = normalizeRoutePath(r.URL.Path)
	}
	if ev.Type == "" {
		ev.Type = "server_error"
	}
	if ev.Message == "" {
		ev.Kind = "http5xx"
		ev.Type = fmt.Sprintf("http_%d", status)
		ev.Message = fmt.Sprintf("%s %s answered %d", r.Method, ev.Route, status)
	}
	if session := getSession(app, r); session != nil {
		ev.UserID = session.UserID
		ev.UserEmail = session.Email
	}
	reportError(app, ev)
}

func recordRequestFrames(r *http.Request) {
	if slot := requestLogSlotFor(r); slot != nil {
		slot.mu.Lock()
		defer slot.mu.Unlock()
		if len(slot.pcs) == 0 {
			pcs := make([]uintptr, 64)
			n := runtime.Callers(3, pcs)
			// Omit the funnel itself so grouping points at the failing handler.
			for len(pcs[:n]) > 0 {
				f, _ := runtime.CallersFrames(pcs[:n]).Next()
				if !strings.HasPrefix(f.Function, "main.serverError") && f.Function != "main.noteServerError" {
					break
				}
				pcs = pcs[1:]
				n--
			}
			slot.pcs = pcs[:n]
		}
	}
}
