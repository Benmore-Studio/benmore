//go:build !cli

package main

import (
	"encoding/xml"
	"os"
	"runtime"
	"strings"
	"testing"
)

// The constructor leaves the arena limit to the environment only when it
// names one: a MALLOC_ARENA_MAX value, or a glibc.malloc.arena_max entry with
// a value in GLIBC_TUNABLES. glibc ignores empty values, so they are no
// choice and the cap applies.
func TestMallocArenaEnvironmentDecides(t *testing.T) {
	for _, tc := range []struct {
		arenaMax, tunables string
		want               bool
	}{
		{"", "", false},
		{"8", "", true},
		{"1", "", true},
		{"", "glibc.malloc.arena_max=4", true},
		{"", "glibc.malloc.tcache_count=0:glibc.malloc.arena_max=4", true},
		{"", "glibc.malloc.arena_max=4:glibc.malloc.tcache_count=0", true},
		{"", "glibc.malloc.tcache_count=0", false},
		{"", "glibc.malloc.arena_max=", false},
		{"", "glibc.malloc.arena_max=:glibc.malloc.tcache_count=0", false},
		{"", "glibc.malloc.arena_test=4", false},
		{"", "xglibc.malloc.arena_max=4", false},
		{"", "glibc.malloc.arena_maximum=4", false},
	} {
		if got := mallocArenaEnvChooses(tc.arenaMax, tc.tunables); got != tc.want {
			t.Errorf("MALLOC_ARENA_MAX=%q GLIBC_TUNABLES=%q: environment chooses = %v, want %v", tc.arenaMax, tc.tunables, got, tc.want)
		}
	}
}

// The constructor ran before package initialization (not late), on glibc it
// capped the arenas unless this process's environment chose, and off glibc it
// called nothing.
func TestMallocArenaCapAppliedAtLoad(t *testing.T) {
	state, late := mallocArenaStatus()
	if late {
		t.Fatalf("the cap was applied during package initialization (state %s): the C constructor did not run", state)
	}
	switch {
	case runtime.GOOS != "linux":
		if state != mallocArenaNotGlibc {
			t.Fatalf("state on %s = %s, want not-glibc", runtime.GOOS, state)
		}
	case state == mallocArenaNotGlibc:
		t.Skip("the C library is not glibc")
	case mallocArenaEnvChooses(os.Getenv("MALLOC_ARENA_MAX"), os.Getenv("GLIBC_TUNABLES")):
		if state != mallocArenaFromEnv {
			t.Fatalf("state = %s with the arena limit in the environment, want environment", state)
		}
	default:
		if state != mallocArenaCapped {
			t.Fatalf("state = %s, want capped", state)
		}
	}
}

func TestMallocArenaLogLine(t *testing.T) {
	for _, tc := range []struct {
		state              mallocArenaState
		late               bool
		goos               string
		arenaMax, tunables string
		want               string
	}{
		{mallocArenaCapped, false, "linux", "", "", "memory: malloc arenas capped at 2 (glibc)"},
		{mallocArenaCapped, true, "linux", "", "", "memory: malloc arenas capped at 2 (glibc) during package initialization: the C start-up hook did not run, so arenas made before then remain"},
		{mallocArenaFromEnv, false, "linux", "8", "", "memory: malloc arenas left to MALLOC_ARENA_MAX=8 from the environment"},
		{mallocArenaFromEnv, false, "linux", "", "glibc.malloc.tcache_count=0:glibc.malloc.arena_max=4", "memory: malloc arenas left to GLIBC_TUNABLES glibc.malloc.arena_max=4 from the environment"},
		{mallocArenaFromEnv, false, "linux", "", "", "memory: malloc arenas left to the environment's setting"},
		{mallocArenaRefused, false, "linux", "", "", "memory: WARNING glibc refused mallopt(M_ARENA_MAX, 2); malloc arenas stay at glibc's default of 8 per CPU"},
		{mallocArenaNotGlibc, false, "linux", "", "", "memory: malloc arenas not capped: the C library is not glibc"},
		{mallocArenaNotGlibc, false, "darwin", "", "", ""},
		{mallocArenaUnset, false, "linux", "", "", "memory: WARNING the malloc arena cap never ran; malloc arenas stay at glibc's default of 8 per CPU"},
	} {
		if got := mallocArenaLogLine(tc.state, tc.late, tc.goos, tc.arenaMax, tc.tunables); got != tc.want {
			t.Errorf("mallocArenaLogLine(%s, late=%v, %s, %q, %q) =\n  %q\nwant\n  %q", tc.state, tc.late, tc.goos, tc.arenaMax, tc.tunables, got, tc.want)
		}
	}
}

// mallocInfoSummary is what the tests read from glibc's malloc_info report.
type mallocInfoSummary struct {
	arenas    int
	heldBytes int64 // obtained from the system: arenas' memory plus mmapped chunks
	freeBytes int64 // free chunks the arenas keep (fastbins and the other bins)
}

// parseMallocInfo reads malloc_info's XML: one <heap> per arena, then the
// process totals as direct children of <malloc>.
func parseMallocInfo(report string) (mallocInfoSummary, error) {
	type sized struct {
		Type string `xml:"type,attr"`
		Size int64  `xml:"size,attr"`
	}
	var doc struct {
		Heaps   []struct{} `xml:"heap"`
		Totals  []sized    `xml:"total"`
		Systems []sized    `xml:"system"`
	}
	if err := xml.NewDecoder(strings.NewReader(report)).Decode(&doc); err != nil {
		return mallocInfoSummary{}, err
	}
	s := mallocInfoSummary{arenas: len(doc.Heaps)}
	for _, total := range doc.Totals {
		switch total.Type {
		case "fast", "rest":
			s.freeBytes += total.Size
		case "mmap":
			s.heldBytes += total.Size
		}
	}
	for _, system := range doc.Systems {
		if system.Type == "current" {
			s.heldBytes += system.Size
		}
	}
	return s, nil
}

// A malloc_info report as glibc 2.35 writes it, two arenas.
func TestParseMallocInfo(t *testing.T) {
	report := `<malloc version="1">
<heap nr="0">
<sizes>
  <size from="17" to="32" total="64" count="2"/>
  <unsorted from="1" to="1" total="2" count="1"/>
</sizes>
<total type="fast" count="2" size="64"/>
<total type="rest" count="1" size="2048"/>
<system type="current" size="135168"/>
<system type="max" size="135168"/>
<aspace type="total" size="135168"/>
<aspace type="mprotect" size="135168"/>
</heap>
<heap nr="1">
<sizes>
</sizes>
<total type="fast" count="0" size="0"/>
<total type="rest" count="3" size="4096"/>
<system type="current" size="65536"/>
<system type="max" size="65536"/>
<aspace type="total" size="65536"/>
<aspace type="mprotect" size="65536"/>
<aspace type="subheaps" size="1"/>
</heap>
<total type="fast" count="2" size="64"/>
<total type="rest" count="4" size="6144"/>
<total type="mmap" count="1" size="200704"/>
<system type="current" size="200704"/>
<system type="max" size="200704"/>
<aspace type="total" size="200704"/>
<aspace type="mprotect" size="200704"/>
</malloc>
`
	got, err := parseMallocInfo(report)
	if err != nil {
		t.Fatal(err)
	}
	want := mallocInfoSummary{arenas: 2, heldBytes: 200704 + 200704, freeBytes: 64 + 6144}
	if got != want {
		t.Fatalf("parseMallocInfo = %+v, want %+v", got, want)
	}
	if _, err := parseMallocInfo("not xml"); err == nil {
		t.Fatal("parseMallocInfo accepted text that is not a report")
	}
}
