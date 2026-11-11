//go:build !cli

package main

import (
	"fmt"
	"log"
	"net/http"
	"path/filepath"
	"runtime"
)

// Both a plain ServeMux and the recording runtime mux implement this seam.
// Failed registrations never enter the inventory.
type appRouteRegistrar interface {
	HandleFunc(string, func(http.ResponseWriter, *http.Request))
}

type appRouteMux struct {
	*http.ServeMux
	patterns []string
	sources  map[string]string
	flows    map[string]string
	// authoredFrom indexes patterns: those before it are framework-owned,
	// the rest are the app's flows and pages (beginAuthoredRoutes).
	authoredFrom int
	// flowCollisions are the http flows RegisterFlows skipped.
	flowCollisions []flowRouteCollision
	// preflight is a route-only build (no handler is served): RegisterFlows
	// records collisions without logging them as load errors.
	preflight bool
	// initErr is startup work the served build could not finish and must
	// not serve without (buildAppMuxChecked returns it), such as a hipaa
	// app's append-only audit triggers.
	initErr error
}

func (mux *appRouteMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	// Without a ServeMux the patterns are only recorded (tableRoutePatterns):
	// a ServeMux would panic on the collision that caller is looking for.
	if mux.ServeMux != nil {
		mux.ServeMux.HandleFunc(pattern, handler)
	}
	mux.patterns = append(mux.patterns, pattern)
	if mux.sources == nil {
		mux.sources = make(map[string]string)
	}
	if _, file, line, ok := runtime.Caller(1); ok {
		mux.sources[pattern] = fmt.Sprintf("%s:%d", filepath.Base(file), line)
	}
}

// Candidate route construction reads staged environment without publishing it.
func appRouteEnv(app *App, key string) string {
	if app.routeEnv != nil {
		return app.routeEnv[key]
	}
	return GetAppEnv(app.Dir, key)
}

// Match the transport's supported methods without conflicting with the app's
// method-specific root fallbacks. The SDK handler replaces the placeholder later.
func registerAppMCPRouteReservation(mux appRouteRegistrar) {
	for _, method := range []string{"GET", "POST", "DELETE"} {
		mux.HandleFunc(method+" /api/_mcp", http.NotFound)
	}
	// Placeholders for registerAppMCPOperationRoutes (review/approve).
	mux.HandleFunc("GET "+appMCPOperationRoute+"{id}", http.NotFound)
	mux.HandleFunc("POST "+appMCPOperationRoute+"{id}/approve", http.NotFound)
	mux.HandleFunc("GET "+appMCPBatchRoute, http.NotFound)
	mux.HandleFunc("POST "+appMCPBatchRoute+"/approve", http.NotFound)
	mux.HandleFunc("GET "+appMCPGrantsRoute, http.NotFound)
	mux.HandleFunc("DELETE "+appMCPGrantsRoute+"/{id}", http.NotFound)
}

// routeInfof logs a route group's registration, except in a route-only
// preflight build (the write gate, `benmore check`, connector review), which
// registers nothing that serves.
func routeInfof(mux appRouteRegistrar, format string, args ...any) {
	if recorder, ok := mux.(*appRouteMux); ok && recorder.preflight {
		return
	}
	log.Printf(format, args...)
}
