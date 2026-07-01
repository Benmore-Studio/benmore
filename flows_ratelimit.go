//go:build !cli

package main

import (
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Declarative per-flow rate limiting. A flow opts in with `rate_limit:` on its
// `on.request` block - e.g. `rate_limit: "5/hour per ip"` - and the runtime
// rejects over-limit requests with 429 + Retry-After BEFORE any step runs.
// Closes the abuse vectors on public mint/self-serve endpoints (signup, invite
// redemption, free-trial bootstrap) that previously had NO general limit, only
// the auth lockout. Opt-in, so a flow without the key behaves exactly as before.

// FlowRateLimit is the parsed `rate_limit:` config for a flow.
type FlowRateLimit struct {
	Rate   int           // allowed requests per window
	Window time.Duration // the window
	Scope  string        // "ip" | "user" | "email" | "group"
	Raw    string        // original string (cache key + diagnostics)
}

// parseRateLimit parses forms like "5/hour per ip", "100/min per user",
// "10/h" (scope defaults to ip), "30/30s". Returns nil (and logs) on an
// unparseable value so a typo fails OPEN rather than blocking all traffic -
// the write-time validator is where a malformed value should be caught loudly.
func parseRateLimit(s string) *FlowRateLimit {
	raw := strings.TrimSpace(s)
	if raw == "" {
		return nil
	}
	body := raw
	scope := "ip"
	if i := strings.Index(strings.ToLower(body), " per "); i >= 0 {
		scope = strings.TrimSpace(strings.ToLower(body[i+len(" per "):]))
		body = strings.TrimSpace(body[:i])
	}
	scope = strings.TrimPrefix(scope, "per_")
	switch scope {
	case "ip", "user", "email", "group":
	default:
		log.Printf("flows: rate_limit scope %q not recognized (use ip|user|email|group); defaulting to ip", scope)
		scope = "ip"
	}
	parts := strings.SplitN(body, "/", 2)
	if len(parts) != 2 {
		log.Printf("flows: rate_limit %q malformed - want N/window (e.g. \"5/hour\")", raw)
		return nil
	}
	rate, err := strconv.Atoi(strings.TrimSpace(parts[0]))
	if err != nil || rate <= 0 {
		log.Printf("flows: rate_limit %q has a bad count - want a positive integer before the slash", raw)
		return nil
	}
	win := parseRateWindow(strings.TrimSpace(parts[1]))
	if win <= 0 {
		log.Printf("flows: rate_limit %q has an unrecognized window - use s/sec, m/min, h/hour, d/day, or a Go duration like 30s", raw)
		return nil
	}
	return &FlowRateLimit{Rate: rate, Window: win, Scope: scope, Raw: raw}
}

func parseRateWindow(w string) time.Duration {
	switch strings.ToLower(strings.TrimSpace(w)) {
	case "s", "sec", "secs", "second", "seconds":
		return time.Second
	case "m", "min", "mins", "minute", "minutes":
		return time.Minute
	case "h", "hr", "hour", "hours":
		return time.Hour
	case "d", "day", "days":
		return 24 * time.Hour
	}
	if d, err := time.ParseDuration(strings.TrimSpace(w)); err == nil && d > 0 {
		return d
	}
	return 0
}

// flowRateLimiters holds one limiter per (app instance, flow, config). Keyed by
// app.Dir so the bucket survives an app reload (a reload mustn't reset the
// count and let an attacker burst again). Per-instance buckets: in a multi-
// instance cluster the effective limit is rate × instances - acceptable for
// abuse prevention (still bounded), and noted in the api(at:'flows') docs.
var flowRateLimiters sync.Map // key string -> *RateLimiter

func flowLimiterFor(app *App, flow *Flow) *RateLimiter {
	rl := flow.RateLimit
	key := app.Dir + "\x00" + flow.Name + "\x00" + rl.Raw
	if v, ok := flowRateLimiters.Load(key); ok {
		return v.(*RateLimiter)
	}
	lim := NewRateLimiter(rl.Rate, rl.Window)
	actual, _ := flowRateLimiters.LoadOrStore(key, lim)
	return actual.(*RateLimiter)
}

// rateLimitKey derives the bucket key for a request under the given scope.
// per-user/email/group fall back to the IP when the request carries no such
// identity (an anon caller hitting a per-user limit is bucketed by IP, so the
// limit still applies rather than being silently skipped).
func rateLimitKey(app *App, scope string, r *http.Request) string {
	switch scope {
	case "user", "email", "group":
		if s := getSession(app, r); s != nil {
			switch scope {
			case "user":
				if s.UserID != 0 {
					return "u:" + strconv.FormatInt(s.UserID, 10)
				}
			case "email":
				if s.Email != "" {
					return "e:" + strings.ToLower(s.Email)
				}
			case "group":
				if g := s.EffectiveGroupID(); g != "" && g != "0" {
					return "g:" + g
				}
			}
		}
	}
	return "ip:" + clientIP(r)
}
