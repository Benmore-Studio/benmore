//go:build !cli

package main

// The Go soft memory limit follows the process's cgroup.
//
// Why. Hosted units cap memory with MemoryHigh (the kernel throttles the
// whole cgroup into synchronous reclaim above it; it freezes rather than
// dies, docs/incidents/2026-08-01-memoryhigh-outage.md) and told the Go
// garbage collector about that cap only through Environment=GOMEMLIMIT. The
// two drifted: systemd applies drop-ins sorted by file name across
// directories, so per-instance overrides that raised MemoryHigh lost their
// GOMEMLIMIT to the template's gomemlimit.conf. On 2026-10-29 five dev apps
// ran with an 85MiB Go limit against a 384M cap and collected garbage
// nearly continuously. The cgroup is the policy the kernel
// enforces, so the runtime now reads it.
//
// What. At start and every goMemoryLimitInterval (so `systemctl
// set-property ... MemoryHigh=` applies without a restart) the runtime reads
// the lowest memory.high, or memory.max where memory.high is "max", on its
// cgroup's path (cgroup_v2.go) and calls debug.SetMemoryLimit with the unit's
// percentage of it (BENMORE_GO_MEMORY_LIMIT_PERCENT, below), never less than
// goMemoryLimitFloor. It logs the limit once at start and again whenever it
// changes. When the cgroup stops setting a limit, the limit the process
// started with comes back. Off Linux, outside cgroup v2, or with no limit on
// the path, nothing changes.
//
// The ratio. BENMORE_GO_MEMORY_LIMIT_PERCENT, read once at start, is the
// percentage of the cgroup's limit (50 to 95; anything else is logged as a
// WARNING and 90 is used; unset is 90). The owner's decision (2026-11):
// production app units set 70 in benmore-app@.service, dev units and the
// router keep 90. Go's limit counts only memory the Go runtime maps. The
// cgroup also charges SQLite's page caches (C heap: up to 10 connections x
// 16 MB in a hosted tenant, db_pool.go), other cgo allocations, child
// processes (ffmpeg, the PDF helpers) and the file pages the app reads (its
// binary, data.db through the 256 MiB mmap window, the WAL). A production
// app carries real data and real traffic, so its pools fill: 70% of the
// template's 512M leaves about 154 MiB for those, nearly the pools' whole
// 160 MB. A dev app's caches stay small (reads of data.db go through the
// mmap window, a connection's cache fills only with pages read inside write
// transactions or from the WAL, and hosted pools close all but 2
// connections after 2 idle minutes), and there a lower ratio costs more than
// it saves: a limit under the live heap makes the GC run nearly
// continuously (the runtime lets it take up to half the CPU it sees, and a
// unit gets half a core), which is the 2026-10-29 failure. 90% reproduces
// what operators tuned by hand for those units: the router's 2750MiB under
// MemoryHigh=3G (89.5%) and the 340MiB dev overrides under 384M (88.5%). The
// key is platform-reserved (processControlEnvKey), so an app's env file
// cannot change its own unit's ratio.
//
// The floor. A tiny MemoryHigh would give a Go limit the heap of any app
// exceeds, and the GC would run nonstop; the derived limit is never set below
// goMemoryLimitFloor, and the log says when the floor applies.
//
// GOMEMLIMIT. Who wins depends on who owns the memory policy. In a hosted
// tenant process (hostedTenantProcess) and the platform's router and host,
// the platform does: where the cgroup sets a limit, the derived value applies
// whatever GOMEMLIMIT says, and an explicit GOMEMLIMIT more than
// goMemoryLimitEnvTolerance percent away is logged as a WARNING naming both
// values. Lower: a stale drop-in value is exactly the 2026-10-29 failure,
// and MemoryHigh is the setting operators change (live, with set-property).
// Higher: a soft limit above the throttle point lets the heap reach the
// reclaim throttle before the GC works harder, the 2026-08-01 outage; no
// workload gains from a Go limit past the point where the kernel throttles.
// Everywhere else (self-hosted `benmore serve`, the open-source framework
// edition, a container) the operator owns it: an explicit GOMEMLIMIT wins
// and the cgroup is read only when GOMEMLIMIT is unset. Either way the log
// says which applied. GOMEMLIMIT still governs until the first read and
// wherever no cgroup limit is readable (bare metal, macOS, cgroup v1). It
// stays a platform-reserved key an app cannot set (processControlEnvKey).
//
// Started by `benmore serve` (every hosted app) and by the platform's
// `benmore host` and `benmore router`; never by tests, validation loads, the
// tenant helper or the PDF helper re-exec (which sets its own limit).

import (
	"errors"
	"fmt"
	"io/fs"
	"log"
	"math"
	"os"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// goMemoryLimitPercentEnv names the unit's percentage of its cgroup
	// limit; goMemoryLimitPercentDefault applies when it is unset or out of
	// [goMemoryLimitPercentMin, goMemoryLimitPercentMax].
	goMemoryLimitPercentEnv     = "BENMORE_GO_MEMORY_LIMIT_PERCENT"
	goMemoryLimitPercentDefault = 90
	// goMemoryLimitPercentProdUnit is the default for a production app unit
	// (benmore-app@<app>.service) when the variable is unset: the binary
	// ships before a host's unit templates are reinstalled, and a prod unit
	// still on the old template must not get the 90% default.
	goMemoryLimitPercentProdUnit = 70
	goMemoryLimitPercentMin      = 50
	goMemoryLimitPercentMax      = 95
	// goMemoryLimitFloor is the lowest limit derived from a cgroup.
	goMemoryLimitFloor = 64 << 20
	// goMemoryLimitInterval spaces the re-reads of the cgroup's limit.
	goMemoryLimitInterval = 60 * time.Second
	// goMemoryLimitEnvTolerance (percent of the derived limit) is how far an
	// explicit GOMEMLIMIT may sit from it without a warning: the templates'
	// values are within it.
	goMemoryLimitEnvTolerance = 5
)

// goMemoryLimitPercentFrom parses BENMORE_GO_MEMORY_LIMIT_PERCENT. It
// returns the percentage to use and, for a value it cannot use, the warning
// to log.
func goMemoryLimitPercentFrom(value string) (int, string) {
	if value == "" {
		return goMemoryLimitPercentDefault, ""
	}
	n, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil || n < goMemoryLimitPercentMin || n > goMemoryLimitPercentMax {
		return goMemoryLimitPercentDefault, fmt.Sprintf("memory: WARNING %s=%q is not a whole number from %d to %d; using %d",
			goMemoryLimitPercentEnv, value, goMemoryLimitPercentMin, goMemoryLimitPercentMax, goMemoryLimitPercentDefault)
	}
	return n, ""
}

// goMemoryLimitFor is percent of limit, without overflow.
func goMemoryLimitFor(limit int64, percent int) int64 {
	p := int64(percent)
	return limit/100*p + limit%100*p/100
}

// goMemoryMiB formats a Go memory limit for the log.
func goMemoryMiB(n int64) string {
	if n == math.MaxInt64 {
		return "none"
	}
	return fmt.Sprintf("%.1f MiB", float64(n)/(1<<20))
}

// goMemoryPolicy is how a process derives its Go limit from its cgroup.
type goMemoryPolicy struct {
	percent int // of the cgroup's limit
	// platformOwned: the hosted platform sets the memory policy (a tenant
	// process, the router, the host), so the cgroup-derived limit applies
	// even over an explicit GOMEMLIMIT. Otherwise an explicit GOMEMLIMIT wins.
	platformOwned bool
}

type goMemoryLimiter struct {
	cgroups  cgroupFS
	policy   goMemoryPolicy
	setLimit func(int64) int64 // debug.SetMemoryLimit
	logf     func(format string, args ...any)
	// envSet records that GOMEMLIMIT was in the environment; initial is the
	// limit the runtime started with (its value, or MaxInt64 for none/off).
	envSet  bool
	initial int64

	mu      sync.Mutex
	applied int64  // the limit this limiter last set; 0 while initial is in force
	warned  string // the GOMEMLIMIT/derived pair last warned about
	readErr string // the read failure last logged
	logged  bool   // the "no cgroup limit" (or "GOMEMLIMIT wins") state was logged
}

func newGoMemoryLimiter(cgroups cgroupFS, envSet bool, policy goMemoryPolicy, setLimit func(int64) int64, logf func(string, ...any)) *goMemoryLimiter {
	// A negative argument reads the limit without changing it.
	return &goMemoryLimiter{cgroups: cgroups, policy: policy, setLimit: setLimit, logf: logf, envSet: envSet, initial: setLimit(-1)}
}

// envWins reports that an explicit GOMEMLIMIT decides the limit: outside the
// hosted platform the operator, not the cgroup, owns the policy.
func (l *goMemoryLimiter) envWins() bool {
	return l.envSet && !l.policy.platformOwned
}

// startingLimit describes the limit the process started with.
func (l *goMemoryLimiter) startingLimit() string {
	if !l.envSet {
		return "unset (no GOMEMLIMIT)"
	}
	if l.initial == math.MaxInt64 {
		return "GOMEMLIMIT=off"
	}
	return "GOMEMLIMIT " + goMemoryMiB(l.initial)
}

// derive is the Go limit for a cgroup limit: the policy's percentage of it,
// raised to goMemoryLimitFloor. how says where it came from, for the log.
func (l *goMemoryLimiter) derive(limit cgroupMemoryLimit) (want int64, how string) {
	want = goMemoryLimitFor(limit.Bytes, l.policy.percent)
	how = fmt.Sprintf("%d%% of %s %s on cgroup %s", l.policy.percent, limit.File, goMemoryMiB(limit.Bytes), limit.Cgroup)
	if want < goMemoryLimitFloor {
		how = fmt.Sprintf("the %s floor: %s is %s, and a lower limit would keep the garbage collector running nonstop", goMemoryMiB(goMemoryLimitFloor), how, goMemoryMiB(want))
		want = goMemoryLimitFloor
	}
	return want, how
}

// readLimit reads the cgroup's limit; ok is false when nothing on the path
// sets one, err when a file could not be read.
func (l *goMemoryLimiter) readLimit() (limit cgroupMemoryLimit, ok bool, err error) {
	cg, err := l.cgroups.selfPath()
	if err == nil {
		return l.cgroups.memoryLimit(cg)
	}
	if errors.Is(err, fs.ErrNotExist) || errors.Is(err, errNoCgroupV2) {
		return cgroupMemoryLimit{}, false, nil // no cgroup v2 membership: no limit
	}
	return cgroupMemoryLimit{}, false, err
}

// check reads the cgroup's limit and applies the derived Go limit if it
// changed.
func (l *goMemoryLimiter) check() {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.envWins() && l.logged {
		return // GOMEMLIMIT decides; said once
	}
	limit, ok, err := l.readLimit()
	if l.envWins() {
		l.logged = true
		cgroup := "no cgroup memory limit was found"
		if err != nil {
			cgroup = fmt.Sprintf("the cgroup memory limit could not be read: %v", err)
		} else if ok {
			want, how := l.derive(limit)
			cgroup = fmt.Sprintf("the cgroup would give %s (%s)", goMemoryMiB(want), how)
		}
		l.logf("memory: Go memory limit stays %s: outside the hosted platform an explicit GOMEMLIMIT wins over the cgroup (%s)", l.startingLimit(), cgroup)
		return
	}
	if err != nil {
		// A read that failed says nothing about the policy: keep the limit
		// in force rather than drop it until the next read.
		if err.Error() != l.readErr {
			l.readErr = err.Error()
			in := l.startingLimit()
			if l.applied != 0 {
				in = goMemoryMiB(l.applied)
			}
			l.logf("memory: cannot read the cgroup memory limit (%v); Go memory limit stays %s", err, in)
		}
		return
	}
	l.readErr = ""
	if !ok {
		if l.applied != 0 {
			l.setLimit(l.initial)
			l.logf("memory: the cgroup no longer sets a memory limit; Go memory limit back to %s (was %s)", l.startingLimit(), goMemoryMiB(l.applied))
			l.applied = 0
		} else if !l.logged {
			l.logf("memory: no cgroup memory limit found; Go memory limit stays %s", l.startingLimit())
		}
		l.logged = true
		return
	}
	want, how := l.derive(limit)
	if want == l.applied {
		return
	}
	was := ""
	if l.applied != 0 {
		was = "; was " + goMemoryMiB(l.applied)
	}
	l.setLimit(want)
	l.applied, l.logged = want, true
	l.logf("memory: Go memory limit %s (%s%s)", goMemoryMiB(want), how, was)
	l.warnExplicitLimit(want)
}

// warnExplicitLimit logs once per value pair when GOMEMLIMIT disagrees with
// the derived limit by more than goMemoryLimitEnvTolerance.
func (l *goMemoryLimiter) warnExplicitLimit(want int64) {
	if !l.envSet {
		return
	}
	diff := l.initial - want
	if diff < 0 {
		diff = -diff
	}
	if diff <= want/100*goMemoryLimitEnvTolerance {
		return
	}
	key := fmt.Sprint(l.initial, "/", want)
	if key == l.warned {
		return
	}
	l.warned = key
	side, why := "below", "the garbage collector would run far more often than the cgroup needs (a drop-in that sorts later may have left it stale)"
	if l.initial > want {
		side, why = "above", "the heap could reach the cgroup's reclaim throttle before the garbage collector works harder"
	}
	l.logf("memory: WARNING %s is %s the cgroup-derived %s and is not used: %s. Set MemoryHigh to change the limit", l.startingLimit(), side, goMemoryMiB(want), why)
}

var goMemoryLimiterStart sync.Once

// startGoMemoryLimitFromCgroup applies the cgroup-derived Go memory limit now
// and re-reads it every goMemoryLimitInterval for the life of the process.
// platformOwned is true where the hosted platform sets the memory policy (a
// hosted tenant process, the router, the host); elsewhere an explicit
// GOMEMLIMIT wins. A no-op off Linux.
func startGoMemoryLimitFromCgroup(platformOwned bool) {
	cgroups, ok := hostCgroupFS()
	if !ok {
		return
	}
	goMemoryLimiterStart.Do(func() {
		percent, warning := goMemoryLimitPercentFrom(os.Getenv(goMemoryLimitPercentEnv))
		if warning != "" {
			log.Print(warning)
		}
		if os.Getenv(goMemoryLimitPercentEnv) == "" && platformOwned && cgroups.inProdAppUnit() {
			percent = goMemoryLimitPercentProdUnit
		}
		policy := goMemoryPolicy{percent: percent, platformOwned: platformOwned}
		l := newGoMemoryLimiter(cgroups, os.Getenv("GOMEMLIMIT") != "", policy, debug.SetMemoryLimit, log.Printf)
		l.check()
		if l.envWins() {
			return // GOMEMLIMIT decides for the life of the process
		}
		go func() {
			t := time.NewTicker(goMemoryLimitInterval)
			defer t.Stop()
			for range t.C {
				l.check()
			}
		}()
	})
}
