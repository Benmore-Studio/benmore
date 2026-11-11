package main

// runtimeServing reports whether a /health status means the runtime is up
// and serving: "healthy", or "degraded" (serving with a problem a person must
// look at, such as a database file replaced under it, db_file_watch.go).
// Runtime-change checks (reload, restart, deploy, restore, refresh, push)
// accept both: a degraded app that looked like a failed push would invite the
// restart that discards what its running process still holds.
func runtimeServing(status string) bool {
	return status == "healthy" || status == "degraded"
}
