//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"strings"
	"time"

	"github.com/mattn/go-sqlite3"
)

// prepareUpdateTimestamp runs only after the row has been authorized, in the
// same transaction as its update. API reads normalize DATETIME values to UTC,
// while SQLite defaults store a space-separated timestamp. Compare instants
// without losing fractions, then retain the exact stored value for the SQL CAS.
// The new version must advance even if two writes share a clock tick or this
// server's clock is behind the previous writer's.
func prepareUpdateTimestamp(tx mutationQuerier, table, id, expected string) (next, stored string, err error) {
	var current sql.NullString
	if err := tx.QueryRow(fmt.Sprintf("SELECT CAST(updated_at AS TEXT) FROM main.%s WHERE id = ?", quoteIdent(table)), id).Scan(&current); err != nil {
		return "", "", updateInternalError(err)
	}
	currentTime, currentOK := parseUpdateTimestamp(current.String)
	if expected != "" {
		expectedTime, expectedOK := parseUpdateTimestamp(expected)
		if !current.Valid || (expected != current.String && (!currentOK || !expectedOK || !currentTime.Equal(expectedTime))) {
			return "", "", errUpdateConflict
		}
	}
	now := time.Now().UTC()
	if currentOK && !now.After(currentTime) {
		now = currentTime.Add(time.Nanosecond)
	}
	// Keep SQLite's UTC storage convention, adding only the precision needed
	// for distinct versions. DATETIME readback preserves it as RFC3339Nano.
	return now.Format("2006-01-02 15:04:05.999999999"), current.String, nil
}

func parseUpdateTimestamp(value string) (time.Time, bool) {
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed.UTC(), true
	}
	for _, layout := range sqlite3.SQLiteTimestampFormats {
		// Match the SQLite driver's handling of a trailing UTC marker even
		// when a timestamp uses a space instead of RFC3339's T separator.
		if parsed, err := time.ParseInLocation(layout, strings.TrimSuffix(value, "Z"), time.UTC); err == nil {
			return parsed.UTC(), true
		}
	}
	return time.Time{}, false
}
