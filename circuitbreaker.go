//go:build !cli

package main

import (
	"fmt"
	"log"
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
			host, c.failures, (cbCooldown - time.Since(c.lastFailure)).Round(time.Second))
	case cbStateHalfOpen:
		// Only one request allowed in half-open - block others
		if time.Since(c.lastAttempt) < 5*time.Second {
			return fmt.Errorf("circuit half-open for %s (probe in progress)", host)
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
		log.Printf("CIRCUIT BREAKER: %s recovered (was %s after %d failures)", host, c.state, c.failures)
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
		log.Printf("CIRCUIT BREAKER: %s probe failed, staying open (%d failures)", host, c.failures)
		return
	}

	if c.failures >= cbFailureThreshold && c.state == cbStateClosed {
		c.state = cbStateOpen
		log.Printf("CIRCUIT BREAKER: %s tripped open after %d consecutive failures (cooldown %s)", host, c.failures, cbCooldown)
	}
}

// extractHost pulls the host from a URL for circuit breaker keying.
func extractHost(rawURL string) string {
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rest := rawURL[idx+3:]
		if slashIdx := strings.Index(rest, "/"); slashIdx >= 0 {
			return rest[:slashIdx]
		}
		return rest
	}
	return rawURL
}

// CircuitBreakerStats returns current state of all circuits (for health checks / debugging).
func CircuitBreakerStats() map[string]any {
	globalBreaker.mu.Lock()
	defer globalBreaker.mu.Unlock()

	stats := make(map[string]any)
	for host, c := range globalBreaker.circuits {
		stats[host] = map[string]any{
			"state":        c.state,
			"failures":     c.failures,
			"last_failure": c.lastFailure,
		}
	}
	return stats
}
