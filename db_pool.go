//go:build !cli

package main

// Connection-pool and page-cache sizing for an app's own data.db pool.
//
// Every SQLite connection carries its own page cache. The app DSN used to set
// _cache_size=-64000 (64 MB per connection) with up to 25 open and 10 idle
// connections that never expired - sized for a dedicated server, not for a
// hosted tenant unit capped at MemoryHigh=512M (and 96M on the dev tier),
// where a busy minute could grow 25 caches toward 1.6 GB of anonymous memory
// and push the unit into the cgroup reclaim throttle described in
// docs/incidents/2026-08-01-memoryhigh-outage.md (a soft cap does not kill,
// it freezes). SQLite allows one writer at a time and WAL readers do not
// block each other, so a tenant gains little from more than a handful of
// connections.
//
// Hosted tenant processes (hostedTenantProcess) therefore default to 10 open,
// 2 idle, a 2 minute idle lifetime and a 16 MB cache per connection: at most
// ~160 MB of cache, released when traffic stops. Ten (not fewer) keeps
// headroom for writers queued in BEGIN IMMEDIATE, each of which holds a
// connection while it waits on the busy timeout. Self-hosted processes keep
// the previous 25/10/64 MB defaults. Every value can be overridden through
// the process environment:
//
//	BENMORE_DB_MAX_OPEN        max open connections   (hosted 10, else 25)
//	BENMORE_DB_MAX_IDLE        max idle connections   (hosted 2,  else 10)
//	BENMORE_DB_IDLE_TIMEOUT    idle lifetime, Go duration; 0 = keep forever
//	                           (hosted 2m, else 0)
//	BENMORE_DB_CACHE_KIB       page cache per connection in KiB
//	                           (hosted 16000, else 64000)
//	BENMORE_DB_MAX_LIFETIME    longest a connection is reused, Go duration;
//	                           0 = forever (default 30m)
//
// A connection is also recycled after 30 minutes however busy it is. Every
// RegisterAuthorizer call (each hook `when:`, each read-only SQL tool call,
// each connector read) leaves a callback the driver frees only when the
// connection closes, so a pool that stays busy never released them and the
// process grew for as long as it ran. Reopening costs a ConnectHook run.

import (
	"database/sql"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// appDBConnMaxLifetime is the default for BENMORE_DB_MAX_LIFETIME.
const appDBConnMaxLifetime = 30 * time.Minute

type appDBPoolLimits struct {
	maxOpen     int
	maxIdle     int
	idleTimeout time.Duration
	maxLifetime time.Duration
	cacheKiB    int
}

func defaultAppDBPoolLimits(hosted bool) appDBPoolLimits {
	if hosted {
		return appDBPoolLimits{maxOpen: 10, maxIdle: 2, idleTimeout: 2 * time.Minute, maxLifetime: appDBConnMaxLifetime, cacheKiB: 16000}
	}
	return appDBPoolLimits{maxOpen: 25, maxIdle: 10, idleTimeout: 0, maxLifetime: appDBConnMaxLifetime, cacheKiB: 64000}
}

// resolveAppDBPoolLimits applies the BENMORE_DB_* overrides from getenv to the
// defaults for this process kind. Malformed values are ignored with a log
// line rather than failing the open.
func resolveAppDBPoolLimits(hosted bool, getenv func(string) string) appDBPoolLimits {
	l := defaultAppDBPoolLimits(hosted)
	posInt := func(key string, dst *int) {
		raw := strings.TrimSpace(getenv(key))
		if raw == "" {
			return
		}
		n, err := strconv.Atoi(raw)
		if err != nil || n < 1 || n > 1000000 {
			log.Printf("db: ignoring %s=%q (want a positive integer)", key, raw)
			return
		}
		*dst = n
	}
	posInt("BENMORE_DB_MAX_OPEN", &l.maxOpen)
	posInt("BENMORE_DB_MAX_IDLE", &l.maxIdle)
	posInt("BENMORE_DB_CACHE_KIB", &l.cacheKiB)
	if raw := strings.TrimSpace(getenv("BENMORE_DB_IDLE_TIMEOUT")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d >= 0 {
			l.idleTimeout = d
		} else {
			log.Printf("db: ignoring BENMORE_DB_IDLE_TIMEOUT=%q (want a Go duration such as 2m)", raw)
		}
	}
	if raw := strings.TrimSpace(getenv("BENMORE_DB_MAX_LIFETIME")); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d >= 0 {
			l.maxLifetime = d
		} else {
			log.Printf("db: ignoring BENMORE_DB_MAX_LIFETIME=%q (want a Go duration such as 30m)", raw)
		}
	}
	if l.maxIdle > l.maxOpen {
		l.maxIdle = l.maxOpen
	}
	return l
}

func currentAppDBPoolLimits() appDBPoolLimits {
	return resolveAppDBPoolLimits(hostedTenantProcess(), os.Getenv)
}

func applyAppDBPoolLimits(db *sql.DB, l appDBPoolLimits) {
	db.SetMaxOpenConns(l.maxOpen)
	db.SetMaxIdleConns(l.maxIdle)
	db.SetConnMaxIdleTime(l.idleTimeout)
	db.SetConnMaxLifetime(l.maxLifetime)
}

// sqliteAppCacheSizeParam is the DSN _cache_size value (negative = KiB).
func sqliteAppCacheSizeParam() string {
	return "-" + strconv.Itoa(currentAppDBPoolLimits().cacheKiB)
}
