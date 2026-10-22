//go:build !windows

package main

// Unix implementations of the file-ownership helpers used by the
// encryption key persistence path (encryption.go) and the pre-migrate
// backup preflight (migrate.go). Split out per-GOOS because
// syscall.Stat_t does not exist on Windows - see fileowner_windows.go
// for the stubs.

import (
	"errors"
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

// fileOwnedByProcess checks authority metadata's actual owner, including root services.
// fileOwnerUID returns the owning uid recorded in info.
func fileOwnerUID(info os.FileInfo) (uint32, bool) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, false
	}
	return stat.Uid, true
}

func fileOwnedByProcess(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int(stat.Uid) == os.Geteuid()
}

var errAuthorityLockBusy = errors.New("connector authority lock is busy")

func tryLockAuthorityFile(file *os.File) error {
	err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
	if errors.Is(err, syscall.EWOULDBLOCK) || errors.Is(err, syscall.EAGAIN) {
		return errAuthorityLockBusy
	}
	return err
}

func lockAuthorityFile(file *os.File) error { return syscall.Flock(int(file.Fd()), syscall.LOCK_EX) }
func unlockAuthorityFile(file *os.File)     { _ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN) }
