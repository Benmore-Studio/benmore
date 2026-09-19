//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRuntimeHealthReceiptAndSuccessfulReload(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	app.Stop = make(chan struct{})
	defer app.Shutdown()
	previous := hostedHotHandler
	hostedHotHandler = &hotHandler{}
	hostedHotHandler.swap(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(202) }))
	defer func() { hostedHotHandler = previous }()
	readHealth := func(handler http.Handler) map[string]any {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, httptest.NewRequest("GET", "/health", nil))
		if rec.Code != 200 || rec.Header().Get("Cache-Control") != "no-store" {
			t.Fatalf("health status=%d headers=%v body=%s", rec.Code, rec.Header(), rec.Body.String())
		}
		var health map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &health); err != nil {
			t.Fatal(err)
		}
		if health["checks"] != nil || health["uptime"] != nil {
			t.Fatal("anonymous health exposed private diagnostics")
		}
		return health
	}
	before := readHealth(healthHandler(app))
	if before["instance_id"] == "" || before["instance_id"] == nil {
		t.Fatal("health missing process receipt")
	}
	writeTestFile(t, app.Dir, "app.yaml", "theme: default\n")
	if err := hotReloadApp(app, false); err != nil {
		t.Fatal(err)
	}
	after := readHealth(hostedHotHandler)
	if before["instance_id"] != after["instance_id"] || after["reload_generation"] != float64(1) {
		t.Fatalf("before=%v after=%v", before, after)
	}
}
