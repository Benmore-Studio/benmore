//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"strings"
	"time"
)

const (
	// minIdleTimeout keeps the timeout above the activity-touch granularity.
	minIdleTimeout = 2 * time.Minute
	// idleTouchInterval bounds the write rate: a session row is touched at
	// most once per interval, so the effective timeout is never longer than
	// configured and at most one interval shorter.
	idleTouchInterval = time.Minute
)

// parseIdleTimeout reads auth.idle_timeout ("15m", "1h", "1d"; "0" = off).
// Unlike ParseSessionDuration it never falls back to a default on garbage.
func parseIdleTimeout(s string) (time.Duration, bool) {
	s = strings.TrimSpace(s)
	d, err := time.ParseDuration(s)
	if err != nil {
		var n int
		if _, e := fmt.Sscanf(s, "%dd", &n); e != nil || n <= 0 || fmt.Sprintf("%dd", n) != s {
			return 0, false
		}
		d = time.Duration(n) * 24 * time.Hour
	}
	return d, d == 0 || d >= minIdleTimeout
}

// idleTimeoutAppYAMLProblem is the one check of auth.idle_timeout's shape,
// shared by the write gate and `benmore check` (validateAppYAML) and the
// loader (stageRuntimeConfig), for every app: a value that does not parse, or
// is below minIdleTimeout, is refused instead of being read as "off".
func idleTimeoutAppYAMLProblem(doc map[string]any) string {
	auth, _ := doc["auth"].(map[string]any)
	v, present := auth["idle_timeout"]
	if !present {
		return ""
	}
	if _, ok := parseIdleTimeout(anyToString(v)); !ok {
		return fmt.Sprintf("app.yaml: auth.idle_timeout = %v is not a duration of at least %s. Use e.g. \"15m\" or \"1h\" (\"0\" turns it off): a session with no counted request for that long ends and its holder signs in again.", v, idleTimeoutText(minIdleTimeout))
	}
	return ""
}

// idleTimeoutText prints a duration the way auth.idle_timeout is written
// ("2m", "15m", "1h30m"); time.Duration prints "2m0s", which a message about a
// config value should not show.
func idleTimeoutText(d time.Duration) string {
	s := d.String()
	if strings.HasSuffix(s, "m0s") {
		s = strings.TrimSuffix(s, "0s")
	}
	if strings.HasSuffix(s, "h0m") {
		s = strings.TrimSuffix(s, "0m")
	}
	return s
}

// idleTimeoutFor is the app's idle timeout (0 = none): auth.idle_timeout, else
// 15m under `compliance: hipaa`. Resolved here, not written into Design.Auth,
// because the presence of auth keys means "auth is configured" elsewhere
// (NeedsAuth). Read from the live Design on each call so a hot reload takes
// effect. The loader and the write gate refuse a value that does not parse for every
// app (idleTimeoutAppYAMLProblem); should one get here it is ignored, and under
// hipaa it falls back to the 15m ceiling.
func idleTimeoutFor(app *App) time.Duration {
	design := app.designConfig()
	if design == nil {
		return 0
	}
	if v, set := design.Auth["idle_timeout"]; set {
		if d, ok := parseIdleTimeout(v); ok && (!app.hipaa() || (d > 0 && d <= hipaaMaxIdleTimeout)) {
			return d
		}
	}
	if app.hipaa() {
		return hipaaMaxIdleTimeout
	}
	return 0
}

// backgroundRequestHeader marks a request a client sends on its own (a live
// query's refetch after a realtime event, a presence or broadcast heartbeat,
// a refresh when the tab becomes visible): bm.js sets it, and an app's own
// polling should too. Such a request is authenticated as usual but is not
// activity for auth.idle_timeout. A client can only shorten its own session
// by sending it, so it needs no proof.
const backgroundRequestHeader = "X-Benmore-Background"

// requestIsBackground reports whether r must not count as activity: a
// long-lived stream's re-check (SSE, WebSocket), an SDK timer the framework
// recognizes by route (requestIsBackgroundPoll), or a request marked with
// backgroundRequestHeader.
func requestIsBackground(r *http.Request) bool {
	if r == nil {
		return false
	}
	return requestIsLongLivedStream(r) || requestIsBackgroundPoll(r) || r.Header.Get(backgroundRequestHeader) == "1"
}

// getAppSession is GetSessionFromDB plus the app's idle timeout. Every
// credential-to-session lookup that has an app and a request goes through it.
func getAppSession(app *App, r *http.Request, token string) *Session {
	s := GetSessionFromDB(app.DB, token)
	if !sessionWithinIdle(app, r, s) {
		return nil
	}
	return s
}

// sessionIdleLast reads the unix time of a session row's last counted
// request (last_seen_at, or created_at for a row never touched). table is the
// session table, "_benmore_sessions" or "main._benmore_sessions".
func sessionIdleLast(q interface {
	QueryRow(string, ...any) *sql.Row
}, table, id string) (int64, error) {
	var last int64
	err := q.QueryRow(`SELECT COALESCE(NULLIF(last_seen_at, 0), CAST(strftime('%s', created_at) AS INTEGER), 0)
		FROM `+table+` WHERE id = ?`, id).Scan(&last)
	return last, err
}

// sessionWithinIdle enforces auth.idle_timeout on a stored session row:
// one primary-key read decides, an idle session is deleted, and an active one
// is touched at most once per idleTouchInterval. Streams (SSE, WebSocket)
// re-check on a timer, and SDK timers or requests marked as background
// (requestIsBackground) call the API with nobody at the tab, so those enforce
// the timeout but never count as activity. A row whose last activity cannot be
// read is treated as idle (fail closed). API tokens have their own expiry and
// are not subject to it.
func sessionWithinIdle(app *App, r *http.Request, s *Session) bool {
	timeout := idleTimeoutFor(app)
	if s == nil || timeout <= 0 || strings.HasPrefix(s.ID, "apitoken:") {
		return s != nil
	}
	now := time.Now().Unix()
	last, err := sessionIdleLast(app.DB, "_benmore_sessions", s.ID)
	if err != nil {
		return false
	}
	if now-last > int64(timeout.Seconds()) {
		app.DB.Exec("DELETE FROM _benmore_sessions WHERE id = ?", s.ID)
		return false
	}
	if now-last >= int64(idleTouchInterval.Seconds()) && !requestIsBackground(r) {
		app.DB.Exec("UPDATE _benmore_sessions SET last_seen_at = ? WHERE id = ? AND last_seen_at < ?", now, s.ID, now)
	}
	return true
}
