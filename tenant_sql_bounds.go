//go:build !cli

package main

import "time"

// Tenant-authored SQL run on an operator's behalf (sql write:true, the
// reset_and_seed seeds.sql) runs under a deadline. A statement with none -
// `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c) DELETE ...
// WHERE id IN (SELECT x FROM c)` never returns and burns a core (and one of
// the pool's few connections) until the process restarts. SQLite is
// interrupted and the statement (or reset transaction) rolls back. The write
// now runs in the app's own process (data channel exec, app_data_ops_sql.go);
// the bound still protects that process and the router waiting on it.
const (
	tenantWriteTimeout = 60 * time.Second
	appResetTimeout    = 2 * time.Minute
)

// tenantWriteDeadline and appResetDeadline are variables so tests can shrink them.
var (
	tenantWriteDeadline = tenantWriteTimeout
	appResetDeadline    = appResetTimeout
)
