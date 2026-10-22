//go:build !cli && !linux && !darwin

package main

import "io/fs"

// Without unix stat identity the digest cache is skipped: every check re-hashes.
func appMCPDigestFileStamp(fs.FileInfo) (appMCPDigestStamp, bool) { return appMCPDigestStamp{}, false }
