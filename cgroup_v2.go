//go:build !cli

package main

// Reading this process's own cgroup v2 memory accounting.
//
// Hosted apps and the router run as systemd units whose memory policy lives
// in their cgroup: MemoryHigh/MemoryMax from the unit file and its drop-ins,
// or a live `systemctl set-property`. Those files are what the kernel
// enforces, so they are what the runtime reads, never a copy of the policy in
// an environment variable that a drop-in ordering can leave stale.
//
// Only the unified hierarchy is read: the "0::<path>" line of
// /proc/self/cgroup, files under /sys/fs/cgroup/<path>. A cgroup v1 host, a
// hybrid host whose memory controller is not in the unified tree, the host's
// root cgroup (it has no limit files) and every OS but Linux read as "no
// limit". Reads are bounded, and a value that does not parse is treated as
// absent, never as zero. The unit hardening (ProtectControlGroups=true,
// ProcSubset=pid) leaves both files readable.

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

// cgroupFS reads cgroup files beneath root: "/" on a Linux host, a directory
// laid out the same way in tests.
type cgroupFS struct{ root string }

// hostCgroupFS is the real filesystem on Linux; cgroups exist nowhere else.
func hostCgroupFS() (cgroupFS, bool) {
	if runtime.GOOS != "linux" {
		return cgroupFS{}, false
	}
	return cgroupFS{root: "/"}, true
}

// cgroupFileMaxBytes bounds every read; the files read here are a few lines.
const cgroupFileMaxBytes = 64 << 10

var (
	errNoCgroupV2 = errors.New("no cgroup v2 entry in /proc/self/cgroup")
	// errCgroupValue marks a file that was read but holds no usable value.
	errCgroupValue = errors.New("unexpected value")
)

func (c cgroupFS) readFile(rel string) ([]byte, error) {
	f, err := os.Open(filepath.Join(c.root, filepath.FromSlash(rel)))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, cgroupFileMaxBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > cgroupFileMaxBytes {
		return nil, fmt.Errorf("%s is larger than %d bytes", rel, cgroupFileMaxBytes)
	}
	return data, nil
}

// selfPath is this process's cgroup v2 path, such as
// "/system.slice/system-benmore\x2dapp.slice/benmore-app@shop.service"
// (systemd's \x2d escape is part of the directory name).
func (c cgroupFS) selfPath() (string, error) {
	data, err := c.readFile("proc/self/cgroup")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(data), "\n") {
		p, ok := strings.CutPrefix(line, "0::")
		if !ok {
			continue
		}
		if !strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) {
			return "", fmt.Errorf("unexpected cgroup v2 path %q", p)
		}
		// Clean on a rooted path drops every "..", so the path stays under
		// the cgroup mount.
		return path.Clean(p), nil
	}
	return "", errNoCgroupV2
}

// inProdAppUnit reports whether this process runs in a production app unit,
// benmore-app@<app>.service (its cgroup's last element); dev units are
// benmore-dev@<app>.service. An unreadable cgroup is not one.
func (c cgroupFS) inProdAppUnit() bool {
	p, err := c.selfPath()
	if err != nil {
		return false
	}
	unit := path.Base(p)
	return strings.HasPrefix(unit, "benmore-app@") && strings.HasSuffix(unit, ".service")
}

// cgroupFile is the path, relative to the root, of one file of cgroup cg.
func cgroupFile(cg, name string) string {
	return path.Join("sys/fs/cgroup", cg, name)
}

// readInt reads a file holding one non-negative integer (memory.current).
func (c cgroupFS) readInt(cg, name string) (int64, error) {
	data, err := c.readFile(cgroupFile(cg, name))
	if err != nil {
		return 0, err
	}
	n, err := strconv.ParseInt(strings.TrimSpace(string(data)), 10, 64)
	if err != nil || n < 0 {
		return 0, fmt.Errorf("%s: %w: not a byte count", name, errCgroupValue)
	}
	return n, nil
}

// readLimit reads a memory.high or memory.max file: a byte count, or "max"
// for none (limited false).
func (c cgroupFS) readLimit(cg, name string) (bytes int64, limited bool, err error) {
	data, err := c.readFile(cgroupFile(cg, name))
	if err != nil {
		return 0, false, err
	}
	v := strings.TrimSpace(string(data))
	if v == "max" {
		return 0, false, nil
	}
	n, err := strconv.ParseInt(v, 10, 64)
	if err != nil || n < 0 {
		return 0, false, fmt.Errorf("%s: %w: not a byte count or max", name, errCgroupValue)
	}
	return n, true, nil
}

// cgroupMemoryLimit is the memory limit that binds a cgroup.
type cgroupMemoryLimit struct {
	Bytes  int64
	File   string // "memory.high" (the reclaim throttle) or "memory.max" (the kill)
	Cgroup string // the cgroup whose file sets it: cg itself or an ancestor
}

// memoryLimit is the lowest memory.high or memory.max on the path from cg up
// to the root. memory.high is where the kernel starts throttling the cgroup
// into synchronous reclaim (it freezes; docs/incidents/2026-08-01), memory.max
// where it kills; "max" in memory.high falls back to memory.max, and an
// ancestor's limit binds its descendants too (a container's limit sits on its
// namespace root, above the process's own cgroup). On a tie memory.high is
// named, since it is reached first. ok is false when nothing on the path sets
// a limit. A missing file, or one holding no usable value, sets none; any
// other read failure is returned, since it says nothing about the policy.
func (c cgroupFS) memoryLimit(cg string) (limit cgroupMemoryLimit, ok bool, err error) {
	for p := cg; ; p = path.Dir(p) {
		for _, name := range []string{"memory.high", "memory.max"} {
			n, limited, rerr := c.readLimit(p, name)
			switch {
			case rerr == nil:
			case errors.Is(rerr, fs.ErrNotExist), errors.Is(rerr, errCgroupValue):
				continue
			default:
				return cgroupMemoryLimit{}, false, rerr
			}
			if limited && (!ok || n < limit.Bytes) {
				limit, ok = cgroupMemoryLimit{Bytes: n, File: name, Cgroup: p}, true
			}
		}
		if p == "/" || p == "." || p == "" {
			return limit, ok, nil
		}
	}
}
