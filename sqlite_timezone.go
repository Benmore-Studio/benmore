//go:build !cli

package main

import (
	"fmt"
	"strings"
	"time"
	_ "time/tzdata"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// registerBenmoreToday exposes the server's current calendar date in an
// explicitly selected IANA time zone to app SQL.
func registerBenmoreToday(conn *sqlite3.SQLiteConn, now func() time.Time) error {
	return conn.RegisterFunc("benmore_today", func(timezone string) (string, error) {
		zone := strings.TrimSpace(timezone)
		if zone == "" || zone == "Local" {
			return "", fmt.Errorf("benmore_today requires an IANA time zone")
		}
		location, err := time.LoadLocation(zone)
		if err != nil {
			return "", fmt.Errorf("benmore_today invalid time zone %q", zone)
		}
		return now().In(location).Format("2006-01-02"), nil
	}, false)
}
