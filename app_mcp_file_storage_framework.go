//go:build !cli && !platform

package main

func appMCPCheckFileSnapshotDBCap(_ *App, _ int64) error { return nil }
