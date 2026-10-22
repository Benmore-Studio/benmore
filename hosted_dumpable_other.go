//go:build !linux && !cli

package main

// markProcessNonDumpable is a Linux control (hosted_dumpable_linux.go).
func markProcessNonDumpable() {}
