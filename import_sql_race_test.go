//go:build !cli && race

package main

// raceEnabled lets TestGuardRestoreStatementAllocationBudget skip itself
// under `go test -race`: the race detector's shadow-memory instrumentation
// legitimately inflates every allocation (measured ~19 KB/call under
// -race vs ~500 B/call without it - still two orders of magnitude below
// the ~2 MiB/call the budget exists to catch, just not within a budget
// tight enough to be a meaningful non-race regression guard).
const raceEnabled = true
