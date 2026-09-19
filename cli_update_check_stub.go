//go:build !cloud

package main

// The CLI update check only ships in the cloud user CLI - the platform
// binary is deployed by the operator (its version is the deploy), and
// the OSS framework build is versioned by its own repo's releases.
func maybeWarnNewerCLI() {}
