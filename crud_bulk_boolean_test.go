//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func bulkBooleanCreate(app *App, mode, body, sid string) *httptest.ResponseRecorder {
	switch mode {
	case "batch":
		return gateCall(app, handleBatchCreate, "flags", http.MethodPost, "/api/flags/batch", "application/json", "["+body+"]", sid)
	case "ingest":
		return gateCall(app, handleStreamingIngest, "flags", http.MethodPost, "/api/flags/ingest", "application/x-ndjson", body+"\n", sid)
	default:
		return gateCall(app, handleCreate, "flags", http.MethodPost, "/api/flags", "application/json", body, sid)
	}
}

// Prisma Boolean fields use BOOLEAN affinity, while older app schemas also
// use INTEGER. Both need numeric storage so filters, SQL conditions and JSON
// round-trips agree, whichever create endpoint supplied the JSON boolean.
func TestBulkCreateBooleansMatchSingleCreate(t *testing.T) {
	for _, columnType := range []string{"BOOLEAN", "INTEGER"} {
		for _, mode := range []string{"single", "batch", "ingest"} {
			t.Run(columnType+"/"+mode, func(t *testing.T) {
				app := newGateApp(t, "CREATE TABLE flags (id INTEGER PRIMARY KEY, user_id INTEGER, label TEXT, enabled "+columnType+" NOT NULL DEFAULT 1, optional "+columnType+")")
				_, sid := gateUser(t, app, "boolean@example.com")
				for _, body := range []string{
					`{"label":"on","enabled":true,"optional":true}`,
					`{"label":"off","enabled":false,"optional":false}`,
					`{"label":"omitted"}`,
					`{"label":"null","enabled":null,"optional":null}`,
				} {
					w := bulkBooleanCreate(app, mode, body, sid)
					if w.Code != http.StatusOK {
						t.Fatalf("create %s: %d %s", body, w.Code, w.Body.String())
					}
				}
				for label, want := range map[string]int{"on": 1, "off": 0, "omitted": 1, "null": 1} {
					var value int
					var storage string
					if err := app.DB.QueryRow("SELECT CAST(enabled AS INTEGER), typeof(enabled) FROM flags WHERE label = ?", label).Scan(&value, &storage); err != nil {
						t.Fatal(err)
					}
					if value != want || storage != "integer" {
						t.Errorf("%s enabled = %d (%s), want %d (integer)", label, value, storage, want)
					}
				}
				if got := gateScalar(t, app, "SELECT COUNT(*) FROM flags WHERE label IN ('omitted','null') AND optional IS NULL"); got != "2" {
					t.Errorf("omitted/null optional values: got %s NULL rows, want 2", got)
				}
				for value, want := range map[int]int{0: 1, 1: 3} {
					w := gateCall(app, handleList, "flags", http.MethodGet, fmt.Sprintf("/api/flags?enabled=%d", value), "application/json", "", sid)
					var rows []map[string]any
					if err := json.Unmarshal(w.Body.Bytes(), &rows); err != nil || w.Code != http.StatusOK {
						t.Fatalf("filtered list: %d %s (%v)", w.Code, w.Body.String(), err)
					}
					if len(rows) != want {
						t.Errorf("enabled=%d returned %d rows, want %d", value, len(rows), want)
					}
					if columnType == "BOOLEAN" {
						for _, row := range rows {
							if got, ok := row["enabled"].(bool); !ok || got != (value == 1) {
								t.Errorf("BOOLEAN JSON value = %#v, want %v", row["enabled"], value == 1)
							}
						}
					}
				}
			})
		}
	}
}

// Validators and before-hooks must see the same normalized input as single
// create, before SQLite applies column affinity.
func TestBulkCreateBooleanValidationAndHooks(t *testing.T) {
	for _, mode := range []string{"single", "batch", "ingest"} {
		for _, gate := range []string{"validator", "hook"} {
			t.Run(mode+"/"+gate, func(t *testing.T) {
				app := newGateApp(t, "CREATE TABLE flags (id INTEGER PRIMARY KEY, user_id INTEGER, enabled BOOLEAN NOT NULL)")
				_, sid := gateUser(t, app, "boolean@example.com")
				if gate == "validator" {
					app.Validators = &ValidatorConfig{Rules: map[string][]ValidatorRule{
						"flags": {{Rule: "enabled = 1", Error: "enabled required"}},
					}}
				} else {
					app.Hooks = &HookConfig{BeforeInsert: map[string][]Hook{
						"flags": {{When: "enabled = 0", SQL: "SELECT 'enabled required' AS error"}},
					}}
				}
				accepted := bulkBooleanCreate(app, mode, `{"enabled":true}`, sid)
				if accepted.Code != http.StatusOK {
					t.Fatalf("true refused: %d %s", accepted.Code, accepted.Body.String())
				}
				refused := bulkBooleanCreate(app, mode, `{"enabled":false}`, sid)
				if mode == "ingest" {
					if refused.Code != http.StatusBadRequest || !strings.Contains(refused.Body.String(), `"errors":1`) {
						t.Fatalf("false must count as a refused row: %d %s", refused.Code, refused.Body.String())
					}
				} else if refused.Code != http.StatusUnprocessableEntity || !strings.Contains(refused.Body.String(), "enabled required") {
					t.Fatalf("false accepted: %d %s", refused.Code, refused.Body.String())
				}
				if got := gateScalar(t, app, "SELECT COUNT(*) FROM flags WHERE enabled = 1"); got != "1" {
					t.Errorf("valid true rows = %s, want 1", got)
				}
				if got := gateScalar(t, app, "SELECT COUNT(*) FROM flags"); got != "1" {
					t.Errorf("persisted rows = %s, want only the valid true row", got)
				}
			})
		}
	}
}
