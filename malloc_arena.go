//go:build !cli

package main

// glibc's malloc arenas are capped at two.
//
// Why. SQLite (mattn/go-sqlite3, the sqlite3_benmore driver) allocates from
// the C heap, and glibc gives each thread its own arena on its first malloc,
// up to 8 per CPU (32 on the 4-vCPU host). An arena keeps the memory it
// reached: freed chunks stay mapped for the next allocation on that arena. A
// Go process runs cgo calls on many OS threads, so every thread that ran a
// heavy query keeps an arena at that query's high-water mark. On 2026-11-05 a dev app under a heavy recursive-CTE metrics endpoint
// (~45 calls/min, 2-15 s each) reached 383 MiB anonymous memory 40 s after
// start while the Go runtime held 70 MiB (heap 17 MiB); ~302 MiB sat in ~11
// anonymous 45-62 MiB mappings, glibc arenas of 17 threads. The Go memory
// limit (memory_limit_cgroup.go) neither sees nor returns that memory, so
// units reached their cgroup's MemoryHigh, were throttled and swapped
// (earlier: 328 MiB resident plus 299 MiB swap under MemoryHigh 384M). The
// same unit with MALLOC_ARENA_MAX=2 held 61 MiB at comparable load 3 minutes
// after start and 138 MiB after 20 minutes.
//
// What. A C constructor in this file calls mallopt(M_ARENA_MAX, 2) when the
// binary loads: before the Go runtime starts its threads and before any
// SQLite connection, so no thread ever gets a third arena. Every later thread
// is given one of the two (one no other thread holds at that moment) and
// waits for its lock while another thread allocates from it. Go's own heap
// does not use malloc and is unaffected. Two cases are left alone:
//
//   - The process environment sets MALLOC_ARENA_MAX (non-empty), or
//     GLIBC_TUNABLES names glibc.malloc.arena_max: the operator chose, and
//     glibc has already applied it. Hosted apps cannot set either from their
//     env (processControlEnvKey reserves MALLOC_* and GLIBC_TUNABLES), so in a
//     hosted unit such a value comes from the unit itself.
//   - The C library is not glibc (musl, macOS): there is no M_ARENA_MAX, and
//     nothing is called.
//
// The constructor runs in every invocation of the binary (CLI commands, the
// tenant and PDF helpers too); a served process (`benmore serve`, `benmore
// host`, `benmore router`) logs the outcome once at start, next to the Go
// memory limit line: `memory: malloc arenas capped at 2 (glibc)`, or `memory:
// malloc arenas left to MALLOC_ARENA_MAX=<n> from the environment`. Child
// processes (ffmpeg, the PDF tools) are separate programs and keep glibc's
// defaults.
//
// If the constructor did not run (a build that skips the C start-up code;
// this package's cgo builds are always externally linked, where it runs),
// package initialization applies the cap instead, later, and the log line
// says so: arenas made before then stay.

/*
#include <stdlib.h>
#include <string.h>
#if defined(__GLIBC__)
#include <malloc.h>
#include <stdio.h>
#endif

#define BENMORE_MALLOC_ARENA_CAP 2

// What the cap did (mallocArenaState).
#define BENMORE_ARENA_UNSET 0
#define BENMORE_ARENA_CAPPED 1
#define BENMORE_ARENA_FROM_ENV 2
#define BENMORE_ARENA_REFUSED 3
#define BENMORE_ARENA_NOT_GLIBC 4

static int benmore_arena_state = BENMORE_ARENA_UNSET;
static int benmore_arena_late = 0;

// benmore_env_sets_arena_max reports whether the environment chose the arena
// limit: MALLOC_ARENA_MAX with a value, or a glibc.malloc.arena_max entry with
// a value in GLIBC_TUNABLES (name=value pairs separated by ':'). Either
// argument may be NULL (unset). An empty value is no choice: glibc ignores it.
static int benmore_env_sets_arena_max(const char *arena_max, const char *tunables) {
	static const char name[] = "glibc.malloc.arena_max=";
	const char *p = tunables;
	if (arena_max != NULL && arena_max[0] != '\0') {
		return 1;
	}
	while (p != NULL && *p != '\0') {
		if (strncmp(p, name, sizeof name - 1) == 0) {
			char next = p[sizeof name - 1];
			if (next != '\0' && next != ':') {
				return 1;
			}
		}
		p = strchr(p, ':');
		if (p != NULL) {
			p++;
		}
	}
	return 0;
}

// benmore_cap_malloc_arenas applies the cap once; late is 1 when package
// initialization, not the constructor, got here first.
static void benmore_cap_malloc_arenas(int late) {
	if (benmore_arena_state != BENMORE_ARENA_UNSET) {
		return;
	}
	benmore_arena_late = late;
#if defined(__GLIBC__) && defined(M_ARENA_MAX)
	if (benmore_env_sets_arena_max(getenv("MALLOC_ARENA_MAX"), getenv("GLIBC_TUNABLES"))) {
		benmore_arena_state = BENMORE_ARENA_FROM_ENV;
	} else if (mallopt(M_ARENA_MAX, BENMORE_MALLOC_ARENA_CAP) == 1) {
		benmore_arena_state = BENMORE_ARENA_CAPPED;
	} else {
		benmore_arena_state = BENMORE_ARENA_REFUSED;
	}
#else
	benmore_arena_state = BENMORE_ARENA_NOT_GLIBC;
#endif
}

__attribute__((constructor, used)) static void benmore_cap_malloc_arenas_at_load(void) {
	benmore_cap_malloc_arenas(0);
}

static int benmore_malloc_arena_state(void) {
	return benmore_arena_state;
}

static int benmore_malloc_arena_late(void) {
	return benmore_arena_late;
}

// benmore_malloc_info returns malloc_info's XML report (one <heap> per
// arena) in a buffer the caller frees, or NULL off glibc. For the tests.
static char *benmore_malloc_info(void) {
#if defined(__GLIBC__)
	char *buf = NULL;
	size_t len = 0;
	FILE *f = open_memstream(&buf, &len);
	if (f == NULL) {
		return NULL;
	}
	int rc = malloc_info(0, f);
	fclose(f);
	if (rc != 0) {
		free(buf);
		return NULL;
	}
	return buf;
#else
	return NULL;
#endif
}
*/
import "C"

import (
	"fmt"
	"log"
	"os"
	"runtime"
	"strings"
	"sync"
	"unsafe"
)

// mallocArenaCap is the number of glibc malloc arenas a process may use.
const mallocArenaCap = C.BENMORE_MALLOC_ARENA_CAP

// mallocArenaState is what the cap did in this process.
type mallocArenaState int

const (
	mallocArenaUnset    = mallocArenaState(C.BENMORE_ARENA_UNSET)
	mallocArenaCapped   = mallocArenaState(C.BENMORE_ARENA_CAPPED)
	mallocArenaFromEnv  = mallocArenaState(C.BENMORE_ARENA_FROM_ENV)
	mallocArenaRefused  = mallocArenaState(C.BENMORE_ARENA_REFUSED)
	mallocArenaNotGlibc = mallocArenaState(C.BENMORE_ARENA_NOT_GLIBC)
)

func (s mallocArenaState) String() string {
	switch s {
	case mallocArenaCapped:
		return "capped"
	case mallocArenaFromEnv:
		return "environment"
	case mallocArenaRefused:
		return "refused"
	case mallocArenaNotGlibc:
		return "not-glibc"
	}
	return "unset"
}

func init() {
	// A no-op once the constructor has run.
	C.benmore_cap_malloc_arenas(1)
}

// mallocArenaStatus reports what the cap did; late is true when package
// initialization applied it because the constructor had not run.
func mallocArenaStatus() (state mallocArenaState, late bool) {
	return mallocArenaState(C.benmore_malloc_arena_state()), C.benmore_malloc_arena_late() != 0
}

// mallocArenaEnvChooses is the constructor's test of the environment, for the
// tests: MALLOC_ARENA_MAX's and GLIBC_TUNABLES' values ("" for unset).
func mallocArenaEnvChooses(arenaMax, tunables string) bool {
	a, t := C.CString(arenaMax), C.CString(tunables)
	defer C.free(unsafe.Pointer(a))
	defer C.free(unsafe.Pointer(t))
	return C.benmore_env_sets_arena_max(a, t) != 0
}

// mallocInfoXML is glibc's malloc_info report, "" off glibc. For the tests.
func mallocInfoXML() string {
	buf := C.benmore_malloc_info()
	if buf == nil {
		return ""
	}
	defer C.free(unsafe.Pointer(buf))
	return C.GoString(buf)
}

// mallocFromThreads calls malloc on n distinct OS threads, all holding their
// threads at once, so each thread that had no arena asks glibc for one. For
// the tests.
func mallocFromThreads(n int) {
	var ready, done sync.WaitGroup
	release := make(chan struct{})
	ready.Add(n)
	done.Add(n)
	for i := 0; i < n; i++ {
		go func() {
			defer done.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			p := C.malloc(64)
			ready.Done()
			<-release
			C.free(p)
		}()
	}
	ready.Wait()
	close(release)
	done.Wait()
}

// tunablesArenaEntry is the glibc.malloc.arena_max entry of a GLIBC_TUNABLES
// value, "" when it has none.
func tunablesArenaEntry(tunables string) string {
	for _, entry := range strings.Split(tunables, ":") {
		if strings.HasPrefix(entry, "glibc.malloc.arena_max=") {
			return entry
		}
	}
	return ""
}

// mallocArenaLogLine is the start-up log line for the cap, "" when there is
// nothing to say (off Linux). arenaMax and tunables are the environment's
// MALLOC_ARENA_MAX and GLIBC_TUNABLES.
func mallocArenaLogLine(state mallocArenaState, late bool, goos, arenaMax, tunables string) string {
	switch state {
	case mallocArenaCapped:
		if late {
			return fmt.Sprintf("memory: malloc arenas capped at %d (glibc) during package initialization: the C start-up hook did not run, so arenas made before then remain", mallocArenaCap)
		}
		return fmt.Sprintf("memory: malloc arenas capped at %d (glibc)", mallocArenaCap)
	case mallocArenaFromEnv:
		if arenaMax != "" {
			return fmt.Sprintf("memory: malloc arenas left to MALLOC_ARENA_MAX=%s from the environment", arenaMax)
		}
		if entry := tunablesArenaEntry(tunables); entry != "" {
			return fmt.Sprintf("memory: malloc arenas left to GLIBC_TUNABLES %s from the environment", entry)
		}
		return "memory: malloc arenas left to the environment's setting"
	case mallocArenaRefused:
		return fmt.Sprintf("memory: WARNING glibc refused mallopt(M_ARENA_MAX, %d); malloc arenas stay at glibc's default of 8 per CPU", mallocArenaCap)
	case mallocArenaNotGlibc:
		if goos == "linux" {
			return "memory: malloc arenas not capped: the C library is not glibc"
		}
		return ""
	}
	return "memory: WARNING the malloc arena cap never ran; malloc arenas stay at glibc's default of 8 per CPU"
}

var mallocArenaLogOnce sync.Once

// logMallocArenaCap logs once what the cap did in this process.
func logMallocArenaCap() {
	mallocArenaLogOnce.Do(func() {
		state, late := mallocArenaStatus()
		if line := mallocArenaLogLine(state, late, runtime.GOOS, os.Getenv("MALLOC_ARENA_MAX"), os.Getenv("GLIBC_TUNABLES")); line != "" {
			log.Print(line)
		}
	})
}
