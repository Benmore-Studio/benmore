//go:build !cli

package main

import (
	"testing"
	"time"
)

// validators.yaml `<`/`>`/`<=`/`>=` compare whole operands. Before the fix a
// numeric PREFIX was parsed (fmt.Sscanf %f), so an ISO date read as its
// year: `end_date >= start_date` accepted an earlier end in the same year
// (fail open) and the documented `end_date > start_date` refused every valid
// same-year range; "12abc" read as 12 and "10:30" as 10.
func TestCrossFieldComparesWholeOperands(t *testing.T) {
	for _, c := range []struct {
		rule string
		data map[string]any
		want bool
	}{
		// Dates and date-times compare as instants.
		{"end_date >= start_date", map[string]any{"start_date": "2024-03-05", "end_date": "2024-01-10"}, false},
		{"end_date > start_date", map[string]any{"start_date": "2024-01-10", "end_date": "2024-03-05"}, true},
		{"end_date > start_date", map[string]any{"start_date": "2024-03-05", "end_date": "2024-03-05"}, false},
		{"end_date <= start_date", map[string]any{"start_date": "2024-01-10", "end_date": "2024-03-05"}, false},
		{"ends_at > starts_at", map[string]any{"starts_at": "2024-03-05 09:00:00", "ends_at": "2024-03-05T10:00:00Z"}, true},
		{"ends_at > starts_at", map[string]any{"starts_at": "2024-03-05T10:00", "ends_at": "2024-03-05T09:30"}, false},
		{"end_date > '2024-01-01'", map[string]any{"end_date": "2024-06-01"}, true},
		{"end_date > start_date", map[string]any{"start_date": "2023-12-31", "end_date": "2024-01-01"}, true},
		{"end_date >= start_date", map[string]any{"start_date": time.Date(2024, 3, 5, 0, 0, 0, 0, time.UTC), "end_date": "2024-01-10"}, false},
		// Numbers compare numerically only when the whole operand is one.
		{"qty <= 12", map[string]any{"qty": "12abc"}, false},
		{"closes > opens", map[string]any{"opens": "10:15", "closes": "10:30"}, true},
		{"qty < 10", map[string]any{"qty": "9"}, true},
		{"qty >= 0", map[string]any{"qty": " 5 "}, true},
		{"qty >= 0", map[string]any{"qty": "-5"}, false},
		{"value >= 0", map[string]any{"value": 2.5}, true},
		{"qty < 10", map[string]any{"qty": "nan"}, false},
	} {
		if got := evaluateCrossFieldExpr(c.rule, c.data); got != c.want {
			t.Errorf("%s with %v = %v, want %v", c.rule, c.data, got, c.want)
		}
	}
}
