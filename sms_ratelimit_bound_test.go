//go:build !cli

package main

import (
	"fmt"
	"testing"
	"time"
)

// Entries for numbers that are never messaged again used to stay in the
// per-phone limiter for the life of the process.
func TestSMSRateLimitSweepsExpiredNumbers(t *testing.T) {
	smsRateLimit.mu.Lock()
	old := smsRateLimit.sends
	smsRateLimit.sends = map[string][]time.Time{}
	stale := time.Now().Add(-time.Hour)
	for i := 0; i < smsRateLimitSweepAt+500; i++ {
		smsRateLimit.sends[fmt.Sprintf("+1415%07d", i)] = []time.Time{stale}
	}
	smsRateLimit.sends["+14155559999"] = []time.Time{time.Now()}
	smsRateLimit.mu.Unlock()
	t.Cleanup(func() {
		smsRateLimit.mu.Lock()
		smsRateLimit.sends = old
		smsRateLimit.mu.Unlock()
	})

	if err := checkSMSRateLimit("+14155550001"); err != nil {
		t.Fatal(err)
	}
	smsRateLimit.mu.Lock()
	n, live := len(smsRateLimit.sends), len(smsRateLimit.sends["+14155559999"])
	smsRateLimit.mu.Unlock()
	if n != 2 {
		t.Fatalf("limiter holds %d numbers after the sweep, want the 2 live ones", n)
	}
	if live != 1 {
		t.Fatal("the sweep dropped a number still inside its window")
	}
}
