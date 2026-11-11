//go:build !cli

package main

import (
	"net/http"
	"testing"
)

// A cross-field rule with a NULL or omitted column operand passes, as a SQL
// CHECK does. The evaluator used to compare such an operand as its own column
// NAME: `end_date >= start_date` let a row with only start_date through
// ("end_date" sorts after a date) and refused one with only end_date
// ("2026-11-05" >= "start_date" is false as text).
func TestCrossFieldRuleNullOperandPasses(t *testing.T) {
	for _, mode := range []string{"single", "batch", "transaction", "ingest"} {
		t.Run(mode, func(t *testing.T) {
			app := newGateApp(t, `CREATE TABLE items(id INTEGER PRIMARY KEY, user_id INTEGER, name TEXT, start_date DATETIME, end_date DATETIME)`)
			EnsureJobsTable(app.DB)
			EnsureWebhooksTable(app.DB)
			_, sid := gateUser(t, app, "null-operand@example.test")
			app.Validators = &ValidatorConfig{Rules: map[string][]ValidatorRule{"items": {
				{Rule: "end_date >= start_date", Error: "end before start"},
				{Rule: "name != banned", Error: "banned name"},
			}}}
			mux := http.NewServeMux()
			RegisterCRUD(mux, app)
			count := 0
			for _, tc := range []struct {
				fields map[string]any
				ok     bool
			}{
				{map[string]any{"name": "a", "start_date": "2026-11-01"}, true},
				{map[string]any{"name": "b", "end_date": "2026-11-05"}, true},
				{map[string]any{"name": "c", "start_date": "2026-11-01", "end_date": nil}, true},
				{map[string]any{"name": "d", "start_date": nil, "end_date": "2026-11-05"}, true},
				{map[string]any{"name": "e", "start_date": "2026-11-01", "end_date": "2026-11-05"}, true},
				{map[string]any{"name": "f", "start_date": "2026-11-05", "end_date": "2026-11-01"}, false},
				// A bare word that is not a column stays a literal.
				{map[string]any{"name": "banned"}, false},
			} {
				w := inventorySchemaRequest(mux, sid, mode, tc.fields)
				if tc.ok {
					count++
				}
				got := gateScalar(t, app, "SELECT COUNT(*) FROM items")
				if want := itoa(count); got != want {
					t.Fatalf("%v: rows=%s want %s (status %d %s)", tc.fields, got, want, w.Code, w.Body.String())
				}
				if mode != "ingest" && !tc.ok && w.Code != 422 {
					t.Fatalf("%v: status %d, want 422", tc.fields, w.Code)
				}
			}
		})
	}
}
