//go:build !cli

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// writeProcSelfCgroup writes root/proc/self/cgroup.
func writeProcSelfCgroup(t *testing.T, root, content string) {
	t.Helper()
	dir := filepath.Join(root, "proc", "self")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "cgroup"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeCgroupFiles writes files into cgroup cg under root/sys/fs/cgroup.
func writeCgroupFiles(t *testing.T, root, cg string, files map[string]string) {
	t.Helper()
	dir := filepath.Join(root, "sys", "fs", "cgroup", filepath.FromSlash(cg))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

const testDevUnitCgroup = `/system.slice/system-benmore\x2ddev.slice/benmore-dev@shop.service`

func TestCgroupSelfPathReadsTheUnifiedEntry(t *testing.T) {
	cases := []struct {
		name, content, want string
		err                 bool
	}{
		{name: "v2 only", content: "0::" + testDevUnitCgroup + "\n", want: testDevUnitCgroup},
		{name: "hybrid", content: "12:memory:/system.slice/x.service\n1:name=systemd:/system.slice/x.service\n0::/system.slice/x.service\n", want: "/system.slice/x.service"},
		{name: "container namespace root", content: "0::/\n", want: "/"},
		{name: "dot segments stay under the mount", content: "0::/../../etc\n", want: "/etc"},
		{name: "v1 only", content: "12:memory:/system.slice/x.service\n", err: true},
		{name: "relative path", content: "0::system.slice\n", err: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeProcSelfCgroup(t, root, tc.content)
			got, err := cgroupFS{root: root}.selfPath()
			if tc.err {
				if err == nil {
					t.Fatalf("selfPath = %q, want an error", got)
				}
				return
			}
			if err != nil || got != tc.want {
				t.Fatalf("selfPath = %q, %v; want %q", got, err, tc.want)
			}
		})
	}
	if _, err := (cgroupFS{root: t.TempDir()}).selfPath(); err == nil || errors.Is(err, errNoCgroupV2) {
		t.Fatalf("missing /proc/self/cgroup: %v, want a read error", err)
	}
}

func TestCgroupMemoryLimitPicksTheLowestOnThePath(t *testing.T) {
	const (
		slice = `/system.slice/system-benmore\x2ddev.slice`
		mib   = int64(1 << 20)
	)
	cases := []struct {
		name   string
		leaf   map[string]string
		parent map[string]string
		want   cgroupMemoryLimit
		ok     bool
	}{
		{name: "memory.high", leaf: map[string]string{"memory.high": "402653184\n", "memory.max": "536870912\n"},
			want: cgroupMemoryLimit{Bytes: 384 * mib, File: "memory.high", Cgroup: testDevUnitCgroup}, ok: true},
		{name: "high is max, falls back to memory.max", leaf: map[string]string{"memory.high": "max\n", "memory.max": "536870912\n"},
			want: cgroupMemoryLimit{Bytes: 512 * mib, File: "memory.max", Cgroup: testDevUnitCgroup}, ok: true},
		{name: "max below high", leaf: map[string]string{"memory.high": "536870912\n", "memory.max": "402653184\n"},
			want: cgroupMemoryLimit{Bytes: 384 * mib, File: "memory.max", Cgroup: testDevUnitCgroup}, ok: true},
		{name: "equal values name memory.high", leaf: map[string]string{"memory.high": "402653184\n", "memory.max": "402653184\n"},
			want: cgroupMemoryLimit{Bytes: 384 * mib, File: "memory.high", Cgroup: testDevUnitCgroup}, ok: true},
		{name: "ancestor binds", leaf: map[string]string{"memory.high": "402653184\n", "memory.max": "max\n"},
			parent: map[string]string{"memory.high": "268435456\n", "memory.max": "max\n"},
			want:   cgroupMemoryLimit{Bytes: 256 * mib, File: "memory.high", Cgroup: slice}, ok: true},
		{name: "no limit anywhere", leaf: map[string]string{"memory.high": "max\n", "memory.max": "max\n"},
			parent: map[string]string{"memory.high": "max\n", "memory.max": "max\n"}},
		{name: "unparseable values are absent", leaf: map[string]string{"memory.high": "lots\n", "memory.max": "-1\n"}},
		{name: "no files", leaf: map[string]string{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			writeCgroupFiles(t, root, testDevUnitCgroup, tc.leaf)
			if tc.parent != nil {
				writeCgroupFiles(t, root, slice, tc.parent)
			}
			got, ok, err := cgroupFS{root: root}.memoryLimit(testDevUnitCgroup)
			if err != nil || ok != tc.ok || got != tc.want {
				t.Fatalf("memoryLimit = %+v, %v, %v; want %+v, %v", got, ok, err, tc.want, tc.ok)
			}
		})
	}
}

// A file that exists but cannot be read is not "no limit": the caller must
// not act on it (memory_limit_cgroup.go keeps the limit it has).
func TestCgroupMemoryLimitReportsReadFailures(t *testing.T) {
	root := t.TempDir()
	writeCgroupFiles(t, root, testDevUnitCgroup, map[string]string{"memory.max": "536870912\n"})
	// A directory where the file should be: opening works, reading fails.
	if err := os.Mkdir(filepath.Join(root, "sys", "fs", "cgroup", filepath.FromSlash(testDevUnitCgroup), "memory.high"), 0o755); err != nil {
		t.Fatal(err)
	}
	if got, ok, err := (cgroupFS{root: root}).memoryLimit(testDevUnitCgroup); err == nil || ok {
		t.Fatalf("memoryLimit = %+v, %v, %v; want a read error", got, ok, err)
	}
}

func TestCgroupReadIntRejectsGarbage(t *testing.T) {
	root := t.TempDir()
	writeCgroupFiles(t, root, "/a.service", map[string]string{"memory.current": "123456\n", "memory.bad": "12 MB\n"})
	fs := cgroupFS{root: root}
	if n, err := fs.readInt("/a.service", "memory.current"); err != nil || n != 123456 {
		t.Fatalf("memory.current = %d, %v", n, err)
	}
	if _, err := fs.readInt("/a.service", "memory.bad"); !errors.Is(err, errCgroupValue) {
		t.Fatalf("a value with a unit: %v, want errCgroupValue", err)
	}
}

// A production app unit is told apart from a dev unit by its own cgroup, so
// its 70% default does not depend on the host's unit template being
// reinstalled with the new variable.
func TestCgroupInProdAppUnit(t *testing.T) {
	for path, want := range map[string]bool{
		`/system.slice/system-benmore\x2dapp.slice/benmore-app@shop.service`:      true,
		`/system.slice/system-benmore\x2dapp.slice/benmore-app@_platform.service`: true,
		`/system.slice/system-benmore\x2ddev.slice/benmore-dev@shop.service`:      false,
		`/system.slice/benmore-router.service`:                                    false,
		`/user.slice/user-501.slice/session-1.scope`:                              false,
		`/`: false,
	} {
		root := t.TempDir()
		writeProcSelfCgroup(t, root, "0::"+path+"\n")
		if got := (cgroupFS{root: root}).inProdAppUnit(); got != want {
			t.Errorf("%s: inProdAppUnit %v, want %v", path, got, want)
		}
	}
	if (cgroupFS{root: t.TempDir()}).inProdAppUnit() {
		t.Error("an unreadable cgroup counted as a prod app unit")
	}
}
