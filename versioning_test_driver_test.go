//go:build !cli

package main

import (
	"database/sql"
	"time"

	sqlite3 "github.com/mattn/go-sqlite3"
)

const sqliteHistoryTestDriver = "sqlite3_history_fixture"

func init() {
	// These fixtures deliberately retain bare SQLite behavior so security
	// tests can create hostile attached/TEMP schemas before invoking the
	// relevant storage guard. Register only the functions retained history
	// triggers need; production always uses its separately hardened driver.
	sql.Register(sqliteHistoryTestDriver, &sqlite3.SQLiteDriver{
		ConnectHook: func(conn *sqlite3.SQLiteConn) error {
			return registerVersionHistoryClock(conn, time.Now)
		},
	})
}
