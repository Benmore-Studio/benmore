//go:build !cli

package main

// Default statement deadline for the shared read helpers (QueryRows and
// friends on a *sql.DB). User-shaped queries - auto-CRUD list filters and
// ?sort= on unindexed columns, deep offsets, LIKE fallbacks, flow SQL -
// previously had no deadline at all, so one slow statement held a pool
// connection (and its page cache) for as long as it ran.
//
// BENMORE_QUERY_TIMEOUT overrides the 10s default: a Go duration ("30s",
// "2m") or a bare number of seconds; "0" disables the deadline. It is read
// from the process environment once.

import (
	"context"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const defaultQueryDeadline = 10 * time.Second

var (
	queryDeadlineOnce  sync.Once
	queryDeadlineValue time.Duration
)

func parseQueryDeadline(raw string) (time.Duration, bool) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return defaultQueryDeadline, true
	}
	if n, err := strconv.Atoi(raw); err == nil && n >= 0 {
		return time.Duration(n) * time.Second, true
	}
	if d, err := time.ParseDuration(raw); err == nil && d >= 0 {
		return d, true
	}
	return defaultQueryDeadline, false
}

// queryDeadline returns the configured statement deadline; 0 means none.
func queryDeadline() time.Duration {
	queryDeadlineOnce.Do(func() {
		raw := os.Getenv("BENMORE_QUERY_TIMEOUT")
		d, ok := parseQueryDeadline(raw)
		if !ok {
			log.Printf("db: ignoring BENMORE_QUERY_TIMEOUT=%q (want a duration such as 30s, or 0 to disable); using %s", raw, defaultQueryDeadline)
		}
		queryDeadlineValue = d
	})
	return queryDeadlineValue
}

// firstStepContext carries a cancellable context into database/sql and the
// driver, but stops exposing its Done channel once the first row has
// arrived (disarm).
//
// Why: up to v1.14.50 mattn/go-sqlite3 ran every rows.Next() on a fresh
// goroutine when the query's context had a Done channel, so it could call
// sqlite3_interrupt. That doubled the cost of scanning a list response
// (measured 103µs -> 242µs for 50 rows; BenchmarkScanRows50). Hiding the
// channel after the first row put the later steps on that driver's
// synchronous path, where the deadline could only act between steps.
//
// The driver in go.mod (v1.14.51 and later) reads Done once, at the first
// step, registers one callback for the whole result set (context.AfterFunc)
// and keeps every later step interruptible with no goroutine per row. disarm
// changes nothing for it (BenchmarkScanRows50Request measures the same with
// and without the wrapper). The wrapper stays so that building against an
// older driver does not bring the per-row goroutine back.
//
// What a caller gets with the current driver: the running statement is
// interrupted when the deadline passes or the client goes away, in the first
// step (the sort or aggregate over a large table) and in any later one (a
// filtered scan that finds one match early and the next one millions of rows
// later). The scan stops with the rows read so far AND the deadline error
// (scanRowsLimitHook returns both); a caller must treat that as a failed
// read, never as the complete result.
//
// This deliberately breaks context's "successive Done calls return the same
// value" rule after disarm; the value is only ever handed to one query.
type firstStepContext struct {
	context.Context
	disarmed atomic.Bool
}

func newFirstStepContext(ctx context.Context) *firstStepContext {
	return &firstStepContext{Context: ctx}
}

func (c *firstStepContext) Done() <-chan struct{} {
	if c.disarmed.Load() {
		return nil
	}
	return c.Context.Done()
}

// disarm hides the Done channel from later row steps (see firstStepContext
// for what that does on which driver). Safe on a nil receiver (no context was
// attached).
func (c *firstStepContext) disarm() {
	if c != nil {
		c.disarmed.Store(true)
	}
}

// withQueryDeadline derives a context carrying the default deadline unless
// ctx already ends sooner (or the deadline is disabled).
func withQueryDeadline(ctx context.Context) (context.Context, context.CancelFunc) {
	d := queryDeadline()
	if d <= 0 {
		return ctx, func() {}
	}
	if dl, ok := ctx.Deadline(); ok && time.Until(dl) <= d {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}
