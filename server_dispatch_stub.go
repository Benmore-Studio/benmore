//go:build !cli && !platform

package main

// dispatchPlatformServer is the open-source framework stub. The multi-tenant
// fleet commands (host / router / migrate-media) are platform-only, so in the
// framework build they don't exist and this always returns false - leaving
// `serve` (one app, one port) as the sole server command.
func dispatchPlatformServer(cmd string) bool { return false }
