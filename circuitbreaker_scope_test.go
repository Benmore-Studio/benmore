//go:build !cli

package main

import (
	"strings"
	"testing"
)

func resetCircuitsForTest(t *testing.T) {
	t.Helper()
	globalBreaker.mu.Lock()
	saved := globalBreaker.circuits
	globalBreaker.circuits = map[string]*circuit{}
	globalBreaker.mu.Unlock()
	t.Cleanup(func() {
		globalBreaker.mu.Lock()
		globalBreaker.circuits = saved
		globalBreaker.mu.Unlock()
	})
}

// One `benmore host` process serves many apps. A tenant whose calls to a
// shared host fail (or that times them out on purpose) must open the
// circuit only for itself, and an app's health report lists only its own
// circuits.
func TestCircuitBreakerIsScopedToTheCallingApp(t *testing.T) {
	resetCircuitsForTest(t)
	a := &App{Dir: t.TempDir()}
	b := &App{Dir: t.TempDir()}
	const shared = "https://api.shared.example/v1/charge"
	for range cbFailureThreshold {
		RecordFailure(circuitKey(a, shared))
	}
	if err := CheckCircuit(circuitKey(a, shared)); err == nil {
		t.Fatal("failing app's circuit did not open")
	}
	if err := CheckCircuit(circuitKey(b, shared)); err != nil {
		t.Fatalf("another app's calls to the same host were blocked: %v", err)
	}
	if stats := CircuitBreakerStats(b); len(stats) != 0 {
		t.Fatalf("app B's health report shows app A's circuits: %v", stats)
	}
	if stats := CircuitBreakerStats(a); stats["api.shared.example"] == nil {
		t.Fatalf("app A's report = %v; want its host", stats)
	}
}

// URL credentials never become part of a circuit key (keys are logged and
// shown in the admin health report).
func TestCircuitKeyDropsURLCredentials(t *testing.T) {
	resetCircuitsForTest(t)
	app := &App{Dir: t.TempDir()}
	for _, raw := range []string{
		"https://svc-user:s3cr3t-token@API.Example.com:8443/hook?x=1",
		"https://svc-user:s3cr3t-token@API.Example.com:8443?x=1",
	} {
		if got := extractHost(raw); got != "api.example.com:8443" {
			t.Fatalf("extractHost(%q) = %q", raw, got)
		}
	}
	RecordFailure(circuitKey(app, "https://svc-user:s3cr3t-token@api.example.com/hook"))
	for host := range CircuitBreakerStats(app) {
		if strings.Contains(host, "s3cr3t") || strings.Contains(host, "svc-user") {
			t.Fatalf("circuit report exposes URL credentials: %q", host)
		}
	}
}
