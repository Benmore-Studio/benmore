//go:build !cli

package main

// Shared CRUD request parsing, field conversion, and HTTP responses.

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// appendHXTrigger appends an event to the HX-Trigger response header,
// preserving anything already set. HTMX parses comma-separated names.
// We use this so every CRUD mutation can fire "benmore:changed" - the
// auto-refresh shim in layout.go listens for that event and soft-reloads
// the page, which keeps <query> stat cards in sync with the table they
// read from. Without this, agents end up reinventing JS reload hacks on
// every page (and burning a dozen turns doing it).
func appendHXTrigger(w http.ResponseWriter, event string) {
	existing := w.Header().Get("HX-Trigger")
	if existing == "" {
		w.Header().Set("HX-Trigger", event)
		return
	}
	w.Header().Set("HX-Trigger", existing+", "+event)
}

// isTruthyQuery reports whether the named query-string parameter is
// present and looks like "yes" - `1`, `true`, `yes`, or just present
// without a value. Used by the auto-CRUD `?count=true` short-circuit
// so any of these forms work:
//
//	?count
//	?count=1
//	?count=true
//	?count_only=true
func isTruthyQuery(r *http.Request, key string) bool {
	if !r.URL.Query().Has(key) {
		return false
	}
	v := strings.ToLower(strings.TrimSpace(r.URL.Query().Get(key)))
	switch v {
	case "", "1", "true", "yes", "on":
		return true
	}
	return false
}

func extractID(path, table string) string {
	prefix := fmt.Sprintf("/api/%s/", table)
	if strings.HasPrefix(path, prefix) {
		return strings.TrimPrefix(path, prefix)
	}
	return ""
}

func getUpdateFields(r *http.Request) map[string]string {
	fields := make(map[string]string)

	// Try JSON body first
	if r.Header.Get("Content-Type") == "application/json" {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err == nil {
			for k, v := range body {
				fields[k] = jsonToFormValue(v)
			}
			return fields
		}
	}

	// Fall back to form values. Coerce boolean-like strings ("true"/
	// "false") to "1"/"0" so they line up with SQLite INTEGER columns
	// - otherwise the checkbox-via-hx-vals pattern writes the literal
	// string "true" into a boolean column and downstream queries
	// (`CASE WHEN x THEN ... END`) treat it as falsy.
	for k, v := range r.Form {
		if len(v) > 0 {
			fields[k] = coerceBoolString(v[0])
		}
	}

	// Also check hx-vals (JSON in query param)
	if hxVals := r.URL.Query().Get("hx-vals"); hxVals != "" {
		var vals map[string]string
		if err := json.Unmarshal([]byte(hxVals), &vals); err == nil {
			for k, v := range vals {
				fields[k] = v
			}
		}
	}

	return fields
}

// jsonToFormValue converts a JSON-decoded value into the string shape
// the form-encoded handlers expect. Booleans become "1" or "0" (not
// "true"/"false") so they line up with SQLite INTEGER columns. Without
// this, an HTMX checkbox using `hx-vals='js:{completed: event.target.checked}'`
// - the canonical pattern in the build docs - writes the literal string
// "true" into the column. SQLite stores it (loose typing), but
// downstream `CASE WHEN completed THEN 1 ELSE 0 END` queries treat the
// string as 0, and `{{if .completed}}` in templates treats it as truthy
// (non-empty string), giving the user a checkbox that says "checked"
// but a stat card that says "0 done".
func jsonToFormValue(v any) string {
	switch x := v.(type) {
	case bool:
		if x {
			return "1"
		}
		return "0"
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

// coerceBoolString turns literal "true"/"false" form values into
// "1"/"0". Form-encoded submissions from `hx-vals='js:{...:bool}'`
// arrive as strings, so this is the last-mile catch for the same
// issue jsonToFormValue handles for the JSON body case.
func coerceBoolString(s string) string {
	switch strings.ToLower(s) {
	case "true":
		return "1"
	case "false":
		return "0"
	}
	return s
}

func hasColumn(app *App, table, column string) bool {
	for _, t := range app.Tables {
		if t.Name == table {
			for _, c := range t.Columns {
				if c.Name == column {
					return true
				}
			}
		}
	}
	return false
}

func isHTMX(r *http.Request) bool {
	return r.Header.Get("HX-Request") == "true"
}

func queryInt(r *http.Request, key string, defaultVal int) int {
	v := r.URL.Query().Get(key)
	if v == "" {
		return defaultVal
	}
	var n int
	if _, err := fmt.Sscanf(v, "%d", &n); err != nil {
		return defaultVal
	}
	if n < 1 {
		return defaultVal
	}
	return n
}

func httpError(w http.ResponseWriter, msg string, code int) {
	http.Error(w, msg, code)
}
