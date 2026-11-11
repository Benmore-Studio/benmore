//go:build !cli

package main

import (
	"fmt"
	"math"
	"time"
)

// auth.session_duration is how long a sign-in lasts. The runtime's reader
// (ParseSessionDuration) falls back to the 30-day default on anything it
// cannot read, and a zero or negative lifetime becomes 30 days when the
// session is created, so `session_duration: "1w"`, `12` or `0` all meant 30
// days with nothing said. This file is the one place that decides what a
// value means and whether it is an accepted form.

// minSessionDuration is the shortest accepted auth.session_duration. "1s" or
// "1ns" is a typo, not a lifetime: every session would expire as it was
// created (and the cookie get no Max-Age), so no one could stay signed in.
const minSessionDuration = 5 * time.Minute

// readSessionDuration reads the accepted forms of auth.session_duration: a
// Go duration of at least minSessionDuration ("12h", "90m", "1h30m") or
// whole days ("7d", "30d"). Every value it accepts is read the same way by
// ParseSessionDuration.
func readSessionDuration(s string) (time.Duration, bool) {
	if d, err := time.ParseDuration(s); err == nil {
		return d, d >= minSessionDuration
	}
	var n int
	if _, err := fmt.Sscanf(s, "%dd", &n); err != nil || n <= 0 || fmt.Sprintf("%dd", n) != s {
		return 0, false
	}
	if int64(n) > math.MaxInt64/int64(24*time.Hour) {
		return 0, false
	}
	return time.Duration(n) * 24 * time.Hour, true
}

// sessionDurationSetting is the one check of an auth.session_duration value,
// shared by the write gate and `benmore check` (sessionDurationAppYAMLProblem
// in validateAppYAML), the loader (RegisterAuthRoutes) and the security scan.
// applied is the lifetime the runtime gives sessions for it; problem is empty
// for an unset value (the default) and for an accepted form.
//
// A value that is not an accepted form keeps the lifetime it has always had,
// because apps carrying one are running: the 30-day default for what the
// reader cannot read and for zero or negative values, and the reader's own
// result for the loose spellings it happens to take ("7days" is 7 days).
// The loader warns; only a write and `benmore check` refuse.
func sessionDurationSetting(value string) (applied time.Duration, problem string) {
	if value == "" {
		return defaultSessionDuration, ""
	}
	if d, ok := readSessionDuration(value); ok {
		return d, ""
	}
	applied = ParseSessionDuration(value)
	if applied <= 0 {
		applied = defaultSessionDuration
	}
	return applied, fmt.Sprintf("auth.session_duration = %q is not an accepted session lifetime; the runtime gives sessions %s for it. Use a Go duration of at least 5m (\"12h\", \"90m\", \"1h30m\") or whole days (\"7d\", \"30d\"). A number needs a unit, there is no week, month or year unit, and \"0\" or a negative value does not turn expiry off (remove the key for the 30-day default; auth.idle_timeout ends inactive sessions sooner).", value, sessionDurationText(applied))
}

// sessionDurationAppYAMLProblem applies sessionDurationSetting to a parsed
// app.yaml, in the shape of idleTimeoutAppYAMLProblem. A missing or empty key
// is the default and no problem.
func sessionDurationAppYAMLProblem(doc map[string]any) string {
	auth, _ := doc["auth"].(map[string]any)
	if _, problem := sessionDurationSetting(anyToString(auth["session_duration"])); problem != "" {
		return "app.yaml: " + problem
	}
	return ""
}

// sessionDurationText prints a lifetime for a message: whole days as days
// ("30 days"), anything else as Go prints a duration.
func sessionDurationText(d time.Duration) string {
	day := 24 * time.Hour
	switch {
	case d == day:
		return "1 day"
	case d > 0 && d%day == 0:
		return fmt.Sprintf("%d days", d/day)
	}
	return d.String()
}
