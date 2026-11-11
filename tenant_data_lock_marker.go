//go:build !cli

package main

// The host side of the router tenant-data lock (router_tenant_data_lock.go,
// scripts/benmore-appctl, release runbook "Router tenant-data lock").
//
// While the operator's marker exists, an app instance's database files,
// uploads and backups belong to the app's own account alone, and every writer
// keeps them so: benmore-appctl on each own/provision, and the app process
// itself, which used to widen data.db to 0660 and its snapshots to 0640 for
// the router's group on every start. The app process reads the same marker
// (it is visible, read-only, in the unit's view of /etc), so the first
// restart after the lock goes on does not reopen the database to the router.
// Only the platform edition (the binary hosted app units run) knows the
// marker's host path (router_tenant_data_lock.go sets tenantDataLockOn); the
// framework and cloud editions, like a self-hosted app, never have the lock
// and keep their modes as before.

import (
	"os"
	"path/filepath"
)

// tenantDataLockOn reports whether this host has the tenant-data lock: a
// variable so the platform edition can install the marker check and tests can
// switch it.
var tenantDataLockOn = func() bool { return false }

// tenantDataLockExempt names the one instance directory the lock never
// covers: the dashboard's (_platform), whose database the router reads
// itself. The platform edition sets it; benmore-appctl and the router's
// openers exempt the same instance.
var tenantDataLockExempt = ""

// tenantDataLockedFor reports whether the lock covers the app instance whose
// directory is instanceDir: the host has the lock and the instance is not
// the dashboard. The app process's own writers (its database open, its
// snapshots) ask this, so the dashboard keeps the modes the router reads.
func tenantDataLockedFor(instanceDir string) bool {
	if tenantDataLockExempt != "" && filepath.Base(filepath.Clean(instanceDir)) == tenantDataLockExempt {
		return false
	}
	return tenantDataLockOn()
}

// tenantDataLockMarkerTrusted reports whether path is the operator's marker:
// a regular file (not a link) owned by rootUID, in a directory owned by
// rootUID that no group or other account can write. Anything else is not the
// lock, so a file another account could plant never changes what is written.
// The directory must also be searchable by every account: the app processes
// check the marker as their own accounts, and a root-run reader (the helper,
// `tenant-data-lock status`) that trusted a marker they cannot see would
// close the data while each app's next start reopened it.
func tenantDataLockMarkerTrusted(path string, rootUID uint32) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	if uid, ok := fileOwnerUID(info); !ok || uid != rootUID {
		return false
	}
	dir, err := os.Lstat(filepath.Dir(path))
	if err != nil || !dir.IsDir() || dir.Mode().Perm()&0o022 != 0 || dir.Mode().Perm()&0o001 == 0 {
		return false
	}
	uid, ok := fileOwnerUID(dir)
	return ok && uid == rootUID
}

// appDataFileMode is the mode an app gives its own data file (database,
// snapshot) when it was cur and the writer wanted want. Under the lock it is
// cur with the group and other bits cleared: a mode is only ever narrowed,
// never widened, and an owner-only file is left as it is.
func appDataFileMode(cur, want os.FileMode, locked bool) os.FileMode {
	if locked {
		return cur.Perm() &^ 0o077
	}
	return want
}

// tightenAppDataFile applies appDataFileMode to path (a file in the instance
// directory's root), skipping the chmod
// when nothing changes (systemd's RestrictSUIDSGID refuses even a no-op
// chmod that carries a set-id bit).
func tightenAppDataFile(path string, want os.FileMode, chmod func(string, os.FileMode) error) error {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return err
	}
	locked := tenantDataLockedFor(filepath.Dir(path))
	mode := appDataFileMode(info.Mode(), want, locked)
	if info.Mode().Perm() == mode && info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0 {
		return nil
	}
	return chmod(path, mode)
}
