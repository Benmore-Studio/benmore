//go:build !cli

package main

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync"
	"time"
)

// Circuit breaker: protects against dead external endpoints.
// Tracks failure rates per host. After consecutive failures, stops
// trying for a cooldown period. Prevents dead webhooks from
// starving the job queue.
//
// States: closed (normal) → open (blocking) → half-open (test one) → closed or open.
// No developer config needed - the runtime protects automatically.

const (
	cbStateClosed   = "closed"
	cbStateOpen     = "open"
	cbStateHalfOpen = "half-open"

	cbFailureThreshold = 5                // consecutive failures to trip
	cbCooldown         = 60 * time.Second // how long to stay open
)

type circuitBreaker struct {
	mu       sync.Mutex
	circuits map[string]*circuit // host → circuit state
}

type circuit struct {
	state       string
	failures    int
	lastFailure time.Time
	lastAttempt time.Time
}

var globalBreaker = &circuitBreaker{
	circuits: make(map[string]*circuit),
}

// CheckCircuit returns an error if the circuit for this host is open.
// If half-open, allows one request through (test probe).
func CheckCircuit(host string) error {
	globalBreaker.mu.Lock()
	defer globalBreaker.mu.Unlock()

	c, exists := globalBreaker.circuits[host]
	if !exists {
		return nil // no circuit = closed = allow
	}

	switch c.state {
	case cbStateClosed:
		return nil
	case cbStateOpen:
		// Check if cooldown has elapsed
		if time.Since(c.lastFailure) > cbCooldown {
			c.state = cbStateHalfOpen
			c.lastAttempt = time.Now()
			return nil // allow one probe request
		}
		return fmt.Errorf("circuit open for %s (%d consecutive failures, cooldown %s remaining)",
			circuitHost(host), c.failures, (cbCooldown - time.Since(c.lastFailure)).Round(time.Second))
	case cbStateHalfOpen:
		// Only one request allowed in half-open - block others
		if time.Since(c.lastAttempt) < 5*time.Second {
			return fmt.Errorf("circuit half-open for %s (probe in progress)", circuitHost(host))
		}
		c.lastAttempt = time.Now()
		return nil // allow another probe
	}
	return nil
}

// RecordSuccess resets the circuit to closed.
func RecordSuccess(host string) {
	globalBreaker.mu.Lock()
	defer globalBreaker.mu.Unlock()

	c, exists := globalBreaker.circuits[host]
	if !exists {
		return
	}
	if c.state != cbStateClosed {
		log.Printf("CIRCUIT BREAKER: %s recovered (was %s after %d failures)", circuitHost(host), c.state, c.failures)
	}
	c.state = cbStateClosed
	c.failures = 0
}

// RecordFailure increments the failure count and may trip the circuit.
func RecordFailure(host string) {
	globalBreaker.mu.Lock()
	defer globalBreaker.mu.Unlock()

	c, exists := globalBreaker.circuits[host]
	if !exists {
		c = &circuit{state: cbStateClosed}
		globalBreaker.circuits[host] = c
	}

	c.failures++
	c.lastFailure = time.Now()

	if c.state == cbStateHalfOpen {
		// Probe failed - back to open
		c.state = cbStateOpen
		log.Printf("CIRCUIT BREAKER: %s probe failed, staying open (%d failures)", circuitHost(host), c.failures)
		return
	}

	if c.failures >= cbFailureThreshold && c.state == cbStateClosed {
		c.state = cbStateOpen
		log.Printf("CIRCUIT BREAKER: %s tripped open after %d consecutive failures (cooldown %s)", circuitHost(host), c.failures, cbCooldown)
	}
}

// extractHost pulls the host from a URL for circuit breaker keying:
// lowercased, port kept, credentials dropped. A URL's userinfo (a user name
// and password before the @ in the authority) must never become part of the
// key, which is logged and shown in the admin health report.
func extractHost(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil && u.Host != "" {
		return strings.ToLower(u.Host)
	}
	rest := rawURL
	if idx := strings.Index(rest, "://"); idx >= 0 {
		rest = rest[idx+3:]
	}
	if end := strings.IndexAny(rest, "/?#"); end >= 0 {
		rest = rest[:end]
	}
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		rest = rest[at+1:]
	}
	return strings.ToLower(rest)
}

// circuitKey scopes a breaker to the app making the call as well as the
// host. The breaker state is process-wide, and one `benmore host` process
// serves many apps: keyed by host alone, one tenant's failing (or
// deliberately timed-out) calls to a shared host opened the circuit for
// every tenant calling it, and each app's health report listed the hosts
// every other app calls.
func circuitKey(app *App, rawURL string) string {
	host := extractHost(rawURL)
	if app == nil || app.Dir == "" {
		return host
	}
	return realtimeAppID(app.Dir) + circuitKeySep + host
}

const circuitKeySep = "|"

// circuitHost is the host part of a circuit key, for logs and reports.
func circuitHost(key string) string {
	if i := strings.LastIndex(key, circuitKeySep); i >= 0 {
		return key[i+len(circuitKeySep):]
	}
	return key
}

// CircuitBreakerStats returns the current state of app's circuits (for
// health checks / debugging), keyed by host.
func CircuitBreakerStats(app *App) map[string]any {
	globalBreaker.mu.Lock()
	defer globalBreaker.mu.Unlock()

	prefix := ""
	if app != nil && app.Dir != "" {
		prefix = realtimeAppID(app.Dir) + circuitKeySep
	}
	stats := make(map[string]any)
	for key, c := range globalBreaker.circuits {
		if !strings.HasPrefix(key, prefix) || (prefix == "" && strings.Contains(key, circuitKeySep)) {
			continue
		}
		stats[circuitHost(key)] = map[string]any{
			"state":        c.state,
			"failures":     c.failures,
			"last_failure": c.lastFailure,
		}
	}
	return stats
}
