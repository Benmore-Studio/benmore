//go:build !windows

package main

// Unix implementations of the file-ownership helpers used by the
// encryption key persistence path (encryption.go) and the pre-migrate
// backup preflight (migrate.go). Split out per-GOOS because
// syscall.Stat_t does not exist on Windows - see fileowner_windows.go
// for the stubs.

import (
	"os"
	"path/filepath"
	"syscall"
)

// chownToDirOwner best-effort aligns a file's owner with its containing
// app directory's owner. On the platform host, app dirs are owned by
// per-tenant users while some writers (router, MCP post-write hooks,
// promote) run as a different user - a root-owned 0600 env.yaml is
// UNREADABLE by the app process, which then falls back to generating a
// fresh ephemeral ENCRYPTION_KEY on every boot (the "prod key didn't
// survive a restart → unrecoverable ciphertext" failure). Chown only
// succeeds when the writer is root or already the owner; failures are
// ignored (local dev, macOS, same-user case - all fine as-is).
func chownToDirOwner(path, dir string) {
	st, err := os.Stat(dir)
	if err != nil {
		return
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return
	}
	_ = os.Chown(path, int(sys.Uid), int(sys.Gid))
}

// writableByOwningUser reports whether `path` (or its nearest existing
// ancestor) is owned by a DIFFERENT uid than the current process AND
// carries the owner-write bit. That combination means the actual writer -
// the per-app process running as that owner - can create the backup even
// though this process's probe can't. Same-uid ownership returns false:
// then the probe's own failure is authoritative.
func writableByOwningUser(path string) bool {
	for p := path; ; {
		st, err := os.Stat(p)
		if err != nil {
			parent := filepath.Dir(p)
			if os.IsNotExist(err) && parent != p {
				p = parent
				continue
			}
			return false
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok {
			return false
		}
		return int(sys.Uid) != os.Geteuid() && st.Mode().Perm()&0200 != 0
	}
}
