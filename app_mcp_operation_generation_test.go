//go:build !cli

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"runtime/pprof"
	"strings"
	"testing"
)

func TestAppMCPOperationLimitersKeepHandlerGeneration(t *testing.T) {
	for _, cluster := range []string{"false", "true"} {
		t.Run("cluster="+cluster, func(t *testing.T) {
			t.Setenv("BENMORE_CLUSTER", cluster)
			for _, route := range []struct{ method, path string }{
				{http.MethodGet, appMCPOperationRoute + strings.Repeat("a", 32)},
				{http.MethodPost, appMCPOperationRoute + strings.Repeat("a", 32) + "/approve"},
				{http.MethodGet, appMCPBatchRoute},
				{http.MethodPost, appMCPBatchRoute + "/approve"},
			} {
				t.Run(route.method+route.path, func(t *testing.T) {
					app, cleanup := newTestApp(t)
					defer cleanup()
					// Open the fixture DB before labeling startup, so the SQL
					// pool's process-lifetime opener is not counted as a worker.
					if err := app.DB.Ping(); err != nil {
						t.Fatal(err)
					}
					app.Stop = make(chan struct{})
					old := app.Stop
					retired := http.NewServeMux()
					registration := t.Name() + "/registration"
					pprof.Do(context.Background(), pprof.Labels("worker-generation", registration), func(context.Context) {
						registerAppMCPOperationRoutes(retired, app, "https://fixture.example.com/api/_mcp")
					})
					waitGenerationWorker(t, registration, false)
					app.mu.Lock()
					close(old)
					app.Stop = make(chan struct{})
					app.mu.Unlock()
					retiredLabel, currentLabel := t.Name()+"/retired", t.Name()+"/current"
					defer func() {
						app.mu.Lock()
						close(app.Stop)
						app.mu.Unlock()
						waitGenerationWorker(t, retiredLabel, false)
						waitGenerationWorker(t, currentLabel, false)
					}()
					request := func(mux http.Handler, label string) {
						t.Helper()
						rec := httptest.NewRecorder()
						pprof.Do(context.Background(), pprof.Labels("worker-generation", label), func(context.Context) {
							mux.ServeHTTP(rec, httptest.NewRequest(route.method, "https://fixture.example.com"+route.path, nil))
						})
						if rec.Code != http.StatusNotFound {
							t.Fatalf("missing connector status=%d, want404", rec.Code)
						}
					}
					// First request on the old, already-retired real handler:
					// lazy cleanup must not attach to its replacement generation.
					request(retired, retiredLabel)
					waitGenerationWorker(t, retiredLabel, false)
					// Positive control: a fresh real handler remains lazy until
					// requested, then its workers live until that generation stops.
					current := http.NewServeMux()
					registerAppMCPOperationRoutes(current, app, "https://fixture.example.com/api/_mcp")
					request(current, currentLabel)
					waitGenerationWorker(t, currentLabel, true)
				})
			}
		})
	}
}

func TestAppMCPOperationRouteInventoryRemainsLazyWithNilStop(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	label := t.Name()
	pprof.Do(context.Background(), pprof.Labels("worker-generation", label), func(context.Context) {
		registerAppMCPOperationRoutes(http.NewServeMux(), app, "https://fixture.example.com/api/_mcp")
	})
	if app.Stop != nil {
		t.Fatal("route inventory initialized a worker generation")
	}
	waitGenerationWorker(t, label, false)
}
