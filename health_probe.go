//go:build !cli

package main

// /health readiness: a bounded database probe and the cgroup's memory
// pressure, for monitors that must see what users see.
//
// Why. On 2026-10-29 apps throttled at their unit's memory.high froze
// (blank screens, stalled requests) while /health kept answering 200
// "healthy", so every monitor stayed green. Its database check is `SELECT
// 1`, which SQLite answers without opening a read transaction or reading a
// page of data.db, its other counts ignore errors, and nothing in it is
// bounded in time or looks at memory.
//
// What. healthReadinessCache.read takes one snapshot and caches it for
// healthReadinessTTL, with at most one measurement in flight per app
// (callers wait for it), so a monitor polling every second, or anyone
// hammering the public endpoint, costs one probe per window. Only deep checks
// and admin sessions take one; a plain anonymous /health never does:
//
//   - db_probe: one plain autocommit read of the schema table's first page
//     on the app's own pool (`SELECT count(*) FROM (SELECT 1 FROM
//     sqlite_master LIMIT 1)`), under healthDBProbeTimeout. It waits for a
//     pool connection, opens a WAL read snapshot and reads a page, which is
//     what every request does first. It is never a transaction: the app DSN
//     begins transactions with BEGIN IMMEDIATE (_txlock=immediate), which
//     would queue the probe behind writers on the busy timeout; a plain read
//     under WAL succeeds while a writer holds the write lock, so the probe
//     neither takes that lock nor waits on it (a probe that began a
//     transaction under a held writer sat out the whole busy timeout: the
//     driver does not interrupt SQLite's busy handler). The deadline covers
//     the wait for a connection (database/sql) and the running statement
//     (the driver interrupts SQLite); because a busy-handler sleep is not
//     interruptible, every caller also stops waiting at its own deadline and
//     the measurement finishes in the background, still the only one in
//     flight.
//   - memory (cgroup v2, Linux): memory.current against the cgroup's limit
//     (cgroup_v2.go: the lowest memory.high, or memory.max, on its path) and
//     memory.pressure's avg10 values; plus the Go memory limit in force.
//     "full avg10" is the share of the last ten seconds in which every task
//     of the unit was stalled on memory at once: what a throttled unit
//     looks like from inside. memory.current alone is not a signal; it
//     includes reclaimable page cache and sits near the limit on any app
//     with a large database.
//
// Plain GET /health keeps its contract: the restart verification
// (platform_runtime_verify.go), `benmore deploy`/`promote`, the router's
// db_file sweep, scripts/release-fleet.py, scripts/fleet-impact.py (which
// requires status "healthy" exactly) and the ops scripts wait for 200 with
// status/version/instance_id/reload_generation, so neither result changes
// its status or HTTP code: an app that started under memory pressure has
// still started. Admin sessions see both results under checks.db_probe and
// checks.memory. GET /health?deep=1 is the readiness check for external
// monitors: 503 {"status":"unhealthy","ready":false,"reason":...} when the
// probe timed out (database_timeout) or failed (database_error), or full
// avg10 is at least healthMemoryPressureSevere (memory_pressure), and 200
// with "ready":true otherwise. The 503 answers before any unbounded query
// and before the session lookup (both wait on the same stalled database),
// so anonymous and admin callers get the same body; deep mode bounds the
// rest of the handler by healthDeepBudget. A change of readiness is logged
// once ("health: not ready: ..." / "health: ready again").

import (
	"bytes"
	"context"
	"database/sql"
	"log"
	"math"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	// healthDBProbeTimeout bounds the probe; under a second leaves a deep
	// check room to answer inside the 2 s that HTTP monitors such as
	// Route 53 allow. Variables so tests can shorten them.
	healthDBProbeTimeout = time.Second
	// healthReadinessTTL is how long one snapshot answers every caller.
	healthReadinessTTL = 5 * time.Second
	// healthCgroupFS is where memory is read from; tests point it at a
	// directory laid out like a host.
	healthCgroupFS = hostCgroupFS
)

const (
	// healthDBProbeSlow marks a probe that answered but took this long.
	healthDBProbeSlow = 250 * time.Millisecond
	// healthMemoryPressureSevere is the memory.pressure "full avg10"
	// percentage at which a deep check answers 503: a fifth of the last ten
	// seconds with every task of the unit stalled on memory reclaim at the
	// same time, which users see as stalled requests. A unit that is not
	// short of memory reads 0.00.
	healthMemoryPressureSevere = 20.0
	// healthDeepBudget bounds a deep check's handler, the probe included.
	healthDeepBudget = 1500 * time.Millisecond

	healthProbeOK      = "ok"
	healthProbeSlow    = "slow"
	healthProbeTimeout = "timeout"
	healthProbeError   = "error"
)

// healthDBProbe is checks.db_probe.
type healthDBProbe struct {
	Status    string    `json:"status"` // ok | slow | timeout | error
	Latency   string    `json:"latency"`
	CheckedAt time.Time `json:"checked_at"`
	err       error     // for the log line only; never in an answer
}

// healthMemoryReport is checks.memory. Absent fields could not be read.
type healthMemoryReport struct {
	Status            string   `json:"status"` // ok | pressure
	CurrentBytes      *int64   `json:"current_bytes,omitempty"`
	LimitBytes        int64    `json:"limit_bytes,omitempty"`
	LimitFile         string   `json:"limit_file,omitempty"` // memory.high | memory.max
	UsedPercent       *float64 `json:"used_percent,omitempty"`
	PressureSomeAvg10 *float64 `json:"pressure_some_avg10,omitempty"`
	PressureFullAvg10 *float64 `json:"pressure_full_avg10,omitempty"`
	GoMemoryLimit     int64    `json:"go_memory_limit_bytes,omitempty"`
}

// healthReadiness is one snapshot.
type healthReadiness struct {
	DB     healthDBProbe
	Memory *healthMemoryReport // nil without a readable cgroup
	at     time.Time
}

// notReadyReason is why a deep check answers 503, "" when it does not.
func (h healthReadiness) notReadyReason() string {
	switch h.DB.Status {
	case healthProbeTimeout:
		return "database_timeout"
	case healthProbeError:
		return "database_error"
	}
	if h.Memory != nil && h.Memory.PressureFullAvg10 != nil && *h.Memory.PressureFullAvg10 >= healthMemoryPressureSevere {
		return "memory_pressure"
	}
	return ""
}

// healthReadinessCache holds an app's last snapshot (App.healthReadiness).
type healthReadinessCache struct {
	mu       sync.Mutex
	last     healthReadiness
	inflight chan struct{}
	reported string // the not-ready reason last logged, "" while ready
	// measure takes a snapshot; nil means measureHealthReadiness (tests
	// replace it).
	measure func(*sql.DB) healthReadiness
}

// read returns a snapshot no older than healthReadinessTTL, starting a
// measurement if none is fresh or in flight. Every caller, the one that
// started it included, waits for it or for its own ctx, whichever ends
// first; a caller that gives up gets a timeout result and the measurement
// finishes on its own, still the only one in flight.
func (c *healthReadinessCache) read(ctx context.Context, db *sql.DB) healthReadiness {
	c.mu.Lock()
	if !c.last.at.IsZero() && time.Since(c.last.at) < healthReadinessTTL {
		last := c.last
		c.mu.Unlock()
		return last
	}
	wait := c.inflight
	if wait == nil {
		wait = make(chan struct{})
		c.inflight = wait
		measure := c.measure
		if measure == nil {
			measure = measureHealthReadiness
		}
		go c.complete(measure, db, wait)
	}
	c.mu.Unlock()
	select {
	case <-wait:
		c.mu.Lock()
		defer c.mu.Unlock()
		return c.last
	case <-ctx.Done():
		return healthReadiness{DB: healthDBProbe{Status: healthProbeTimeout, CheckedAt: time.Now().UTC()}}
	}
}

// complete runs one measurement, stores it and logs a change of readiness.
func (c *healthReadinessCache) complete(measure func(*sql.DB) healthReadiness, db *sql.DB, done chan struct{}) {
	snap := measure(db)
	if snap.at.IsZero() {
		snap.at = time.Now()
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.last, c.inflight = snap, nil
	close(done)
	reason := snap.notReadyReason()
	if reason == c.reported {
		return
	}
	c.reported = reason
	if reason == "" {
		log.Printf("health: ready again (db probe %s %s%s)", snap.DB.Status, snap.DB.Latency, snap.Memory.pressureText())
		return
	}
	detail := ""
	if snap.DB.err != nil {
		detail = ": " + snap.DB.err.Error()
	}
	log.Printf("health: not ready: %s (db probe %s %s%s%s)", reason, snap.DB.Status, snap.DB.Latency, detail, snap.Memory.pressureText())
}

func (m *healthMemoryReport) pressureText() string {
	if m == nil || m.PressureFullAvg10 == nil {
		return ""
	}
	return ", memory pressure full avg10 " + strconv.FormatFloat(*m.PressureFullAvg10, 'f', 2, 64) + "%"
}

// measureHealthReadiness takes one snapshot: the database probe and memory.
func measureHealthReadiness(db *sql.DB) healthReadiness {
	return healthReadiness{DB: probeHealthDB(db), Memory: readHealthMemory(), at: time.Now()}
}

// healthDBProbeQuery reads the schema table's first page in a plain
// autocommit statement (never BeginTx: see the header).
const healthDBProbeQuery = "SELECT count(*) FROM (SELECT 1 FROM sqlite_master LIMIT 1)"

// probeHealthDB runs the probe on the app's pool under healthDBProbeTimeout.
// Its context is its own: a caller that gives up does not cancel the
// measurement others are waiting for.
func probeHealthDB(db *sql.DB) healthDBProbe {
	ctx, cancel := context.WithTimeout(context.Background(), healthDBProbeTimeout)
	defer cancel()
	start := time.Now()
	var n int
	err := db.QueryRowContext(ctx, healthDBProbeQuery).Scan(&n)
	took := time.Since(start)
	p := healthDBProbe{Status: healthProbeOK, Latency: took.String(), CheckedAt: start.UTC(), err: err}
	switch {
	case err != nil && (ctx.Err() != nil || took >= healthDBProbeTimeout):
		p.Status = healthProbeTimeout
	case err != nil:
		p.Status = healthProbeError
	case took >= healthDBProbeSlow:
		p.Status = healthProbeSlow
	}
	return p
}

// readHealthMemory reads this process's cgroup memory; nil when nothing is
// readable (off Linux, no cgroup v2).
func readHealthMemory() *healthMemoryReport {
	cgroups, ok := healthCgroupFS()
	if !ok {
		return nil
	}
	cg, err := cgroups.selfPath()
	if err != nil {
		return nil
	}
	r := &healthMemoryReport{Status: "ok"}
	found := false
	if cur, err := cgroups.readInt(cg, "memory.current"); err == nil {
		r.CurrentBytes, found = &cur, true
		if limit, ok, err := cgroups.memoryLimit(cg); err == nil && ok && limit.Bytes > 0 {
			r.LimitBytes, r.LimitFile = limit.Bytes, limit.File
			used := math.Round(float64(cur)/float64(limit.Bytes)*1000) / 10
			r.UsedPercent = &used
		}
	}
	if data, err := cgroups.readFile(cgroupFile(cg, "memory.pressure")); err == nil {
		psi := parseMemoryPressure(data)
		r.PressureSomeAvg10, r.PressureFullAvg10 = psi.some, psi.full
		found = found || psi.some != nil || psi.full != nil
	}
	if !found {
		return nil
	}
	if r.PressureFullAvg10 != nil && *r.PressureFullAvg10 >= healthMemoryPressureSevere {
		r.Status = "pressure"
	}
	if limit := debug.SetMemoryLimit(-1); limit != math.MaxInt64 {
		r.GoMemoryLimit = limit
	}
	return r
}

// memoryPressureAvg10 holds memory.pressure's avg10 values; nil when the
// line is missing or malformed (the root cgroup has no "full" line on older
// kernels).
type memoryPressureAvg10 struct{ some, full *float64 }

// parseMemoryPressure reads the PSI format:
//
//	some avg10=0.00 avg60=0.00 avg300=0.00 total=0
//	full avg10=0.00 avg60=0.00 avg300=0.00 total=0
func parseMemoryPressure(data []byte) memoryPressureAvg10 {
	var out memoryPressureAvg10
	for _, line := range bytes.Split(data, []byte("\n")) {
		fields := strings.Fields(string(line))
		if len(fields) < 2 || (fields[0] != "some" && fields[0] != "full") {
			continue
		}
		for _, f := range fields[1:] {
			v, ok := strings.CutPrefix(f, "avg10=")
			if !ok {
				continue
			}
			n, err := strconv.ParseFloat(v, 64)
			if err != nil || n < 0 || n > 100 || math.IsNaN(n) {
				break
			}
			if fields[0] == "some" {
				out.some = &n
			} else {
				out.full = &n
			}
			break
		}
	}
	return out
}

// healthDeepRequested reports a readiness check (?deep=1 or ?deep=true).
func healthDeepRequested(r *http.Request) bool {
	v := r.URL.Query().Get("deep")
	return v == "1" || strings.EqualFold(v, "true")
}
