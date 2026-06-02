//go:build !cli

package main

// On-disk paths for apps. Every app is live — one directory per subdomain
// at apps/{subdomain}. There are no draft, prod, or named branch
// directories; every write is an edit to the live app.

import (
	"os"
	"path/filepath"
)

// appDir returns the on-disk directory for an app.
func appDir(appsDir, subdomain string) string {
	return filepath.Join(appsDir, subdomain)
}

// ensureAppDir creates the app directory if it doesn't exist yet.
//
// Mode 0700: only the owner (the user the host runs as) can read or
// traverse the dir. In multi-tenant deployments where every per-app
// systemd unit runs as a distinct dynamic UID, this is the kernel-level
// fence that stops tenant A's process from cat-ing tenant B's data.db.
// In single-user dev mode (`benmore serve`) it's still correct — the dev
// owns the process and the directory.
func ensureAppDir(appsDir, subdomain string) error {
	return os.MkdirAll(filepath.Join(appsDir, subdomain), 0700)
}
