//go:build !cli

package main

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"runtime/debug"
	"strconv"
	"strings"
	"testing"
)

// fakeGoMemoryLimit stands in for debug.SetMemoryLimit.
type fakeGoMemoryLimit struct {
	limit int64
	sets  []int64
	logs  []string
}

func (f *fakeGoMemoryLimit) set(n int64) int64 {
	prev := f.limit
	if n >= 0 {
		f.limit = n
		f.sets = append(f.sets, n)
	}
	return prev
}

func (f *fakeGoMemoryLimit) logf(format string, args ...any) {
	f.logs = append(f.logs, fmt.Sprintf(format, args...))
}

// take returns and clears the logged lines.
func (f *fakeGoMemoryLimit) take() []string {
	logs := f.logs
	f.logs = nil
	return logs
}

const mebibyte = int64(1 << 20)

// hostedGoMemoryPolicy is a dev unit's or the router's: 90%, the platform's
// policy over GOMEMLIMIT.
var hostedGoMemoryPolicy = goMemoryPolicy{percent: 90, platformOwned: true}

// newTestGoMemoryLimiter is a limiter with hostedGoMemoryPolicy over a fake
// cgroup root whose process sits in testDevUnitCgroup with the given
// memory.high and memory.max.
func newTestGoMemoryLimiter(t *testing.T, envLimit int64, high, max string) (*goMemoryLimiter, *fakeGoMemoryLimit, string) {
	t.Helper()
	return newTestGoMemoryLimiterWith(t, hostedGoMemoryPolicy, envLimit, high, max)
}

func newTestGoMemoryLimiterWith(t *testing.T, policy goMemoryPolicy, envLimit int64, high, max string) (*goMemoryLimiter, *fakeGoMemoryLimit, string) {
	t.Helper()
	root := t.TempDir()
	writeProcSelfCgroup(t, root, "0::"+testDevUnitCgroup+"\n")
	writeCgroupFiles(t, root, testDevUnitCgroup, map[string]string{"memory.high": high + "\n", "memory.max": max + "\n"})
	fake := &fakeGoMemoryLimit{limit: math.MaxInt64}
	envSet := envLimit != 0
	if envSet {
		fake.limit = envLimit
	}
	return newGoMemoryLimiter(cgroupFS{root: root}, envSet, policy, fake.set, fake.logf), fake, root
}

func setTestMemoryHigh(t *testing.T, root, high, max string) {
	t.Helper()
	writeCgroupFiles(t, root, testDevUnitCgroup, map[string]string{"memory.high": high + "\n", "memory.max": max + "\n"})
}

func TestGoMemoryLimitForIsThePercentage(t *testing.T) {
	for _, tc := range []struct {
		in      int64
		percent int
		want    int64
	}{
		{384 * mebibyte, 90, 362387865}, // 345.6 MiB: dev units
		{96 * mebibyte, 90, 90596966},   // 86.4 MiB
		{3 << 30, 90, 2899102924},       // 2764.8 MiB: the router
		{512 * mebibyte, 70, 375809638}, // 358.4 MiB: prod units
		{100, 90, 90}, {99, 90, 89}, {0, 90, 0}, {99, 70, 69},
		{math.MaxInt64, 90, 8301034833169298226}, // no overflow
		{math.MaxInt64, 95, 8762203435012037016},
	} {
		if got := goMemoryLimitFor(tc.in, tc.percent); got != tc.want {
			t.Errorf("goMemoryLimitFor(%d, %d) = %d, want %d", tc.in, tc.percent, got, tc.want)
		}
	}
}

// BENMORE_GO_MEMORY_LIMIT_PERCENT: 50 to 95, else a warning and 90.
func TestGoMemoryLimitPercentFromTheEnvironment(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  int
		warns bool
	}{
		{"", 90, false}, {"70", 70, false}, {"50", 50, false}, {"95", 95, false}, {" 70 ", 70, false},
		{"49", 90, true}, {"96", 90, true}, {"100", 90, true}, {"0", 90, true}, {"-70", 90, true},
		{"70.5", 90, true}, {"70%", 90, true}, {"seventy", 90, true},
	} {
		got, warning := goMemoryLimitPercentFrom(tc.value)
		if got != tc.want || (warning != "") != tc.warns {
			t.Errorf("goMemoryLimitPercentFrom(%q) = %d, %q; want %d (warning %v)", tc.value, got, warning, tc.want, tc.warns)
		}
		if tc.warns && !strings.Contains(warning, "memory: WARNING BENMORE_GO_MEMORY_LIMIT_PERCENT=") || tc.warns && !strings.Contains(warning, "using 90") {
			t.Errorf("warning for %q: %q", tc.value, warning)
		}
	}
}

// A prod unit (BENMORE_GO_MEMORY_LIMIT_PERCENT=70 under MemoryHigh=512M) gets
// 358.4 MiB, and the template's GOMEMLIMIT=358MiB draws no warning.
func TestGoMemoryLimitProdUnitIsSeventyPercent(t *testing.T) {
	l, fake, _ := newTestGoMemoryLimiterWith(t, goMemoryPolicy{percent: 70, platformOwned: true}, 358*mebibyte, "536870912", "805306368")
	l.check()
	if want := goMemoryLimitFor(512*mebibyte, 70); fake.limit != want {
		t.Fatalf("limit %d, want %d", fake.limit, want)
	}
	if logs := fake.take(); len(logs) != 1 || !strings.Contains(logs[0], "Go memory limit 358.4 MiB (70% of memory.high 512.0 MiB on cgroup "+testDevUnitCgroup+")") {
		t.Fatalf("logs %q", logs)
	}
	// The old template's 225MiB is the stale value the warning is for.
	l, fake, _ = newTestGoMemoryLimiterWith(t, goMemoryPolicy{percent: 70, platformOwned: true}, 225*mebibyte, "536870912", "805306368")
	l.check()
	if logs := fake.take(); len(logs) != 2 || !strings.Contains(logs[1], "WARNING GOMEMLIMIT 225.0 MiB is below the cgroup-derived 358.4 MiB") {
		t.Fatalf("logs %q", logs)
	}
}

// Outside the hosted platform (self-hosted serve, the framework edition, a
// container) an explicit GOMEMLIMIT wins; the cgroup counts only without one.
func TestGoMemoryLimitExplicitGOMEMLIMITWinsOutsideThePlatform(t *testing.T) {
	selfHosted := goMemoryPolicy{percent: 90, platformOwned: false}
	l, fake, root := newTestGoMemoryLimiterWith(t, selfHosted, 300*mebibyte, "536870912", "805306368")
	l.check()
	if len(fake.sets) != 0 || fake.limit != 300*mebibyte {
		t.Fatalf("an explicit GOMEMLIMIT was overridden: sets %v, limit %d", fake.sets, fake.limit)
	}
	logs := fake.take()
	if len(logs) != 1 || !strings.Contains(logs[0], "Go memory limit stays GOMEMLIMIT 300.0 MiB: outside the hosted platform an explicit GOMEMLIMIT wins over the cgroup (the cgroup would give 460.8 MiB (90% of memory.high 512.0 MiB") {
		t.Fatalf("logs %q", logs)
	}
	setTestMemoryHigh(t, root, "268435456", "536870912")
	l.check()
	if len(fake.sets) != 0 || len(fake.take()) != 0 {
		t.Fatalf("a later read changed or logged something: sets %v", fake.sets)
	}
	// GOMEMLIMIT=off is explicit too.
	off, fakeOff, _ := newTestGoMemoryLimiterWith(t, selfHosted, 0, "536870912", "805306368")
	off.envSet = true
	off.check()
	if logs := fakeOff.take(); len(fakeOff.sets) != 0 || len(logs) != 1 || !strings.Contains(logs[0], "stays GOMEMLIMIT=off: outside the hosted platform") {
		t.Fatalf("GOMEMLIMIT=off: sets %v, logs %q", fakeOff.sets, logs)
	}

	// Without GOMEMLIMIT the cgroup applies, as on the platform.
	unset, fakeUnset, _ := newTestGoMemoryLimiterWith(t, selfHosted, 0, "536870912", "805306368")
	unset.check()
	if want := goMemoryLimitFor(512*mebibyte, 90); fakeUnset.limit != want {
		t.Fatalf("limit %d, want %d", fakeUnset.limit, want)
	}
	if logs := fakeUnset.take(); len(logs) != 1 || !strings.Contains(logs[0], "Go memory limit 460.8 MiB (90% of memory.high 512.0 MiB") {
		t.Fatalf("logs %q", logs)
	}
}

// A tiny MemoryHigh never gives a limit under 64 MiB, where the garbage
// collector would run nonstop.
func TestGoMemoryLimitHasAFloor(t *testing.T) {
	l, fake, root := newTestGoMemoryLimiterWith(t, goMemoryPolicy{percent: 70, platformOwned: true}, 0, "67108864", "134217728")
	l.check()
	if fake.limit != goMemoryLimitFloor {
		t.Fatalf("limit %d, want the %d floor", fake.limit, int64(goMemoryLimitFloor))
	}
	if logs := fake.take(); len(logs) != 1 || !strings.Contains(logs[0], "Go memory limit 64.0 MiB (the 64.0 MiB floor: 70% of memory.high 64.0 MiB on cgroup "+testDevUnitCgroup+" is 44.8 MiB") {
		t.Fatalf("logs %q", logs)
	}
	// Exactly at the floor: no floor note.
	setTestMemoryHigh(t, root, strconv.FormatInt(goMemoryLimitFloor*100/70+1, 10), "134217728")
	l.check()
	if logs := fake.take(); len(logs) != 0 || fake.limit != goMemoryLimitFloor {
		t.Fatalf("limit %d, logs %q", fake.limit, logs)
	}
	setTestMemoryHigh(t, root, "536870912", "805306368")
	l.check()
	if logs := fake.take(); len(logs) != 1 || strings.Contains(logs[0], "floor") || !strings.Contains(logs[0], "Go memory limit 358.4 MiB (70% of memory.high 512.0 MiB") || !strings.Contains(logs[0], "was 64.0 MiB") {
		t.Fatalf("logs %q", logs)
	}
}

// The 2026-10-29 shape: MemoryHigh raised to 384M by a per-instance drop-in,
// GOMEMLIMIT left at the template's 85MiB by a later-sorting one.
func TestGoMemoryLimitFollowsMemoryHighOverAStaleGOMEMLIMIT(t *testing.T) {
	l, fake, root := newTestGoMemoryLimiter(t, 85*mebibyte, "402653184", "536870912")
	l.check()
	if want := goMemoryLimitFor(384*mebibyte, 90); fake.limit != want || len(fake.sets) != 1 {
		t.Fatalf("limit %d after sets %v, want %d", fake.limit, fake.sets, want)
	}
	logs := fake.take()
	if len(logs) != 2 || !strings.Contains(logs[0], "Go memory limit 345.6 MiB (90% of memory.high 384.0 MiB on cgroup "+testDevUnitCgroup+")") {
		t.Fatalf("logs %q", logs)
	}
	if !strings.Contains(logs[1], "WARNING GOMEMLIMIT 85.0 MiB is below the cgroup-derived 345.6 MiB") {
		t.Fatalf("no warning about the stale GOMEMLIMIT: %q", logs)
	}

	// Unchanged cgroup: nothing set, nothing logged.
	l.check()
	if len(fake.sets) != 1 || len(fake.take()) != 0 {
		t.Fatalf("an unchanged cgroup set %v", fake.sets)
	}

	// A live `systemctl set-property MemoryHigh=256M` applies on the next read.
	setTestMemoryHigh(t, root, "268435456", "536870912")
	l.check()
	if want := goMemoryLimitFor(256*mebibyte, 90); fake.limit != want {
		t.Fatalf("limit %d, want %d", fake.limit, want)
	}
	logs = fake.take()
	if len(logs) != 2 || !strings.Contains(logs[0], "Go memory limit 230.4 MiB (90% of memory.high 256.0 MiB") || !strings.Contains(logs[0], "was 345.6 MiB") {
		t.Fatalf("change logs %q", logs)
	}

	// MemoryHigh=infinity: memory.max takes over.
	setTestMemoryHigh(t, root, "max", "536870912")
	l.check()
	if want := goMemoryLimitFor(512*mebibyte, 90); fake.limit != want {
		t.Fatalf("limit %d, want %d (memory.max)", fake.limit, want)
	}
	if logs = fake.take(); len(logs) == 0 || !strings.Contains(logs[0], "of memory.max 512.0 MiB") {
		t.Fatalf("memory.max logs %q", logs)
	}

	// No limit at all: the starting limit comes back.
	setTestMemoryHigh(t, root, "max", "max")
	l.check()
	if fake.limit != 85*mebibyte {
		t.Fatalf("limit %d, want the starting GOMEMLIMIT back", fake.limit)
	}
	if logs = fake.take(); len(logs) != 1 || !strings.Contains(logs[0], "no longer sets a memory limit; Go memory limit back to GOMEMLIMIT 85.0 MiB (was 460.8 MiB)") {
		t.Fatalf("restore logs %q", logs)
	}
	l.check()
	if len(fake.take()) != 0 {
		t.Fatal("the unlimited state was logged twice")
	}
}

func TestGoMemoryLimitWarnsAboutAGOMEMLIMITAboveTheCgroup(t *testing.T) {
	l, fake, _ := newTestGoMemoryLimiter(t, 2750*mebibyte, "536870912", "805306368")
	l.check()
	if want := goMemoryLimitFor(512*mebibyte, 90); fake.limit != want {
		t.Fatalf("limit %d, want %d: a GOMEMLIMIT above the throttle point must not win", fake.limit, want)
	}
	logs := fake.take()
	if len(logs) != 2 || !strings.Contains(logs[1], "WARNING GOMEMLIMIT 2750.0 MiB is above the cgroup-derived 460.8 MiB") {
		t.Fatalf("logs %q", logs)
	}

	off, fakeOff, _ := newTestGoMemoryLimiter(t, 0, "536870912", "805306368")
	off.envSet = true // GOMEMLIMIT=off: the runtime reports MaxInt64
	off.check()
	if logs := fakeOff.take(); len(logs) != 2 || !strings.Contains(logs[1], "WARNING GOMEMLIMIT=off is above") {
		t.Fatalf("GOMEMLIMIT=off logs %q", logs)
	}
}

func TestGoMemoryLimitNoWarningWithinTolerance(t *testing.T) {
	// The dev template: 85MiB under MemoryHigh=96M (derived 86.4 MiB).
	l, fake, _ := newTestGoMemoryLimiter(t, 85*mebibyte, "100663296", "134217728")
	l.check()
	if logs := fake.take(); len(logs) != 1 || strings.Contains(logs[0], "WARNING") {
		t.Fatalf("logs %q", logs)
	}
	// No GOMEMLIMIT at all: no warning either.
	l, fake, _ = newTestGoMemoryLimiter(t, 0, "536870912", "805306368")
	l.check()
	if logs := fake.take(); len(logs) != 1 || strings.Contains(logs[0], "WARNING") {
		t.Fatalf("logs %q", logs)
	}
}

func TestGoMemoryLimitNoOpWithoutACgroupLimit(t *testing.T) {
	cases := map[string]func(t *testing.T, root string){
		"no /proc/self/cgroup": func(*testing.T, string) {},
		"cgroup v1 only": func(t *testing.T, root string) {
			writeProcSelfCgroup(t, root, "9:memory:/system.slice/x.service\n")
		},
		"host root cgroup": func(t *testing.T, root string) {
			writeProcSelfCgroup(t, root, "0::/\n")
			writeCgroupFiles(t, root, "/", map[string]string{"memory.current": "1\n"})
		},
		"unlimited unit": func(t *testing.T, root string) {
			writeProcSelfCgroup(t, root, "0::/system.slice/x.service\n")
			writeCgroupFiles(t, root, "/system.slice/x.service", map[string]string{"memory.high": "max\n", "memory.max": "max\n"})
		},
	}
	for name, setup := range cases {
		t.Run(name, func(t *testing.T) {
			root := t.TempDir()
			setup(t, root)
			fake := &fakeGoMemoryLimit{limit: 225 * mebibyte}
			l := newGoMemoryLimiter(cgroupFS{root: root}, true, hostedGoMemoryPolicy, fake.set, fake.logf)
			l.check()
			l.check()
			if len(fake.sets) != 0 || fake.limit != 225*mebibyte {
				t.Fatalf("sets %v, limit %d", fake.sets, fake.limit)
			}
			if logs := fake.take(); len(logs) != 1 || !strings.Contains(logs[0], "no cgroup memory limit found; Go memory limit stays GOMEMLIMIT 225.0 MiB") {
				t.Fatalf("logs %q", logs)
			}
		})
	}
}

// A cgroup file that cannot be read keeps the limit in force; it does not
// drop the process back to its starting limit until the next read.
func TestGoMemoryLimitKeepsItsLimitWhenTheCgroupIsUnreadable(t *testing.T) {
	l, fake, root := newTestGoMemoryLimiter(t, 0, "402653184", "536870912")
	l.check()
	applied := fake.limit
	fake.take()
	high := filepath.Join(root, "sys", "fs", "cgroup", filepath.FromSlash(testDevUnitCgroup), "memory.high")
	if err := os.Remove(high); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(high, 0o755); err != nil {
		t.Fatal(err)
	}
	l.check()
	l.check()
	if fake.limit != applied || len(fake.sets) != 1 {
		t.Fatalf("limit %d (sets %v), want %d kept", fake.limit, fake.sets, applied)
	}
	if logs := fake.take(); len(logs) != 1 || !strings.Contains(logs[0], "cannot read the cgroup memory limit") || !strings.Contains(logs[0], "stays 345.6 MiB") {
		t.Fatalf("logs %q", logs)
	}
}

func TestStartGoMemoryLimitIsANoOpOffLinux(t *testing.T) {
	if _, ok := hostCgroupFS(); ok {
		t.Skip("Linux: the start path reads the real cgroup")
	}
	before := debug.SetMemoryLimit(-1)
	startGoMemoryLimitFromCgroup(true)
	if after := debug.SetMemoryLimit(-1); after != before {
		t.Fatalf("Go memory limit changed off Linux: %d -> %d", before, after)
	}
}
