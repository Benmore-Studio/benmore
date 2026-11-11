//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
)

// Windows stubs for the Unix file-ownership helpers (fileowner_unix.go).
// The per-tenant-user ownership seam these exist for is a Linux platform-
// host concern; on Windows there is no uid-based split, so:
//   - chownToDirOwner is a no-op (chown semantics don't apply), and
//   - writableByOwningUser returns false (the caller's own write probe
//     is authoritative - never bypass it here).

func chownToDirOwner(path, dir string) {}

// openNoFollow and chmodNoFollow: Windows has no hosted tenant tree; plain
// file operations (fileowner_unix.go has the no-follow versions).
func openNoFollow(path string, flag int, perm os.FileMode) (*os.File, error) {
	return os.OpenFile(path, flag, perm)
}

func chmodNoFollow(path string, mode os.FileMode) error { return os.Chmod(path, mode) }

func writableByOwningUser(path string) bool { return false }

// Connector authority fails closed without Unix ownership/locking guarantees.
func fileOwnedByProcess(info os.FileInfo) bool { return false }

func fileOwnerUID(info os.FileInfo) (uint32, bool) { return 0, false }

func fileLinkCount(info os.FileInfo) (uint64, bool) { return 0, false }

var errAuthorityLockBusy = errors.New("connector authority lock is busy")

func tryLockAuthorityFile(file *os.File) error {
	return fmt.Errorf("connector authority is unsupported on this platform")
}

func lockAuthorityFile(file *os.File) error {
	return fmt.Errorf("connector authority is unsupported on this platform")
}
func unlockAuthorityFile(file *os.File) {}
