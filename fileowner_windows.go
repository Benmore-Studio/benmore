//go:build windows

package main

// Windows stubs for the Unix file-ownership helpers (fileowner_unix.go).
// The per-tenant-user ownership seam these exist for is a Linux platform-
// host concern; on Windows there is no uid-based split, so:
//   - chownToDirOwner is a no-op (chown semantics don't apply), and
//   - writableByOwningUser returns false (the caller's own write probe
//     is authoritative - never bypass it here).

func chownToDirOwner(path, dir string) {}

func writableByOwningUser(path string) bool { return false }
