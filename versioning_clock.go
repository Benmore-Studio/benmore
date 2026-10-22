//go:build !cli

package main

import (
	"time"

	"github.com/mattn/go-sqlite3"
)

const versionTimestampLayout = "2006-01-02 15:04:05.999999999"

// Retained boundaries and source timestamps are evidence, not repair targets.
// A later boundary wins over a regressed source timestamp or incomplete history.
func versionLatestInstant(values ...any) (time.Time, bool) {
	var latest time.Time
	for _, value := range values {
		if versionedValueIsNull(value) {
			continue
		}
		instant, ok := parseUpdateTimestamp(stringifyForCrypto(value))
		if ok && (latest.IsZero() || instant.After(latest)) {
			latest = instant
		}
	}
	return latest, !latest.IsZero()
}

func registerVersionHistoryClock(conn *sqlite3.SQLiteConn, now func() time.Time) error {
	if err := conn.RegisterFunc("benmore_history_start", func(previousFrom, previousTo, updated, created any) string {
		start, known := versionLatestInstant(previousFrom, previousTo, updated, created)
		if !known {
			// No timestamp proves an earlier state; capture only the observed
			// pre-mutation instant instead of inventing an earlier lifetime.
			start = now().UTC()
		}
		return start.UTC().Format(versionTimestampLayout)
	}, false); err != nil {
		return err
	}
	return conn.RegisterFunc("benmore_history_end", func(startValue, candidate any) string {
		start, _ := versionLatestInstant(startValue)
		end, valid := versionLatestInstant(candidate)
		if !valid || !end.After(start) {
			end = now().UTC()
			if !end.After(start) {
				end = start.Add(time.Nanosecond)
			}
		}
		return end.UTC().Format(versionTimestampLayout)
	}, false)
}
