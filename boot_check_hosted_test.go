//go:build !cli

package main

import "testing"

// Hosted apps skip the startup source check: the write gate already ran it,
// and under a dev unit's limits it kept a large app from ever starting.
func TestBootCheckSkippedInHostedProcesses(t *testing.T) {
	t.Setenv("BENMORE_BIND_LOOPBACK", "1")
	if bootCheckApplies() {
		t.Fatal("a hosted app process ran the startup source check")
	}
	t.Setenv("BENMORE_BIND_LOOPBACK", "")
	if !bootCheckApplies() {
		t.Fatal("local serve must keep the startup source check")
	}
}
