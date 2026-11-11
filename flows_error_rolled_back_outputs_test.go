//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"strings"
	"testing"
)

// A transactional flow rolls back before its on_error handler runs, but the
// handler still read `steps.<id>.outputs` of the writes the rollback undid:
// an INSERT ... RETURNING id answered an id that no longer existed and that
// the handler's own insert then reused (round 2026-11-05 logic finding 11).
// The outputs of those writes are removed before the handler starts; reads
// keep theirs, and a flow without a transaction keeps every output.
func TestErrorHandlerDoesNotSeeRolledBackWriteOutputs(t *testing.T) {
	for _, transactional := range []bool{true, false} {
		app := errorJournalApp(t)
		mustExec(t, app.DB, `CREATE TABLE orders (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT)`)
		tx := ""
		if transactional {
			tx = ", transaction: true"
		}
		flows, err := parseGHAFlowFile("flows/tx-lab.yaml", []byte(`on:
  request: {method: POST, path: /api/tx-lab`+tx+`}
jobs:
  main:
    steps:
      - id: look
        query: "SELECT available FROM stock WHERE id = 1"
      - id: w1
        query: "INSERT INTO orders (title) VALUES ('main') RETURNING id"
      - id: bump
        query: "UPDATE stock SET available = available - 1 WHERE id = 1"
      - id: boom
        query: "INSERT INTO missing_table VALUES (1)"
        on_error:
          - id: own
            query: "INSERT INTO orders (title) VALUES ('handler') RETURNING id"
          - run: respond
            with:
              status: 409
              json:
                main_row: "${{ steps.w1.outputs.id || 'rolled back' }}"
                bumped: "${{ steps.bump.outputs.rows_affected || 'rolled back' }}"
                available: "${{ steps.look.outputs.available }}"
                own_row: "${{ steps.own.outputs.id }}"
`))
		if err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest("POST", "/api/tx-lab", strings.NewReader(`{}`))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		if err := executeFlowHTTP(app, &flows[0], w, r); err == nil || !strings.Contains(err.Error(), "missing_table") || w.Code != 409 {
			t.Fatalf("transaction=%v: %v %d %s", transactional, err, w.Code, w.Body.String())
		}
		var got map[string]any
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
			t.Fatalf("transaction=%v: %s", transactional, w.Body.String())
		}
		var handlerRow float64
		if err := app.DB.QueryRow("SELECT id FROM orders WHERE title = 'handler'").Scan(&handlerRow); err != nil {
			t.Fatal(err)
		}
		if got["own_row"] != handlerRow || got["available"] != float64(10) {
			t.Fatalf("transaction=%v: handler's own output or the read was lost: %v", transactional, got)
		}
		if transactional {
			// Row 1 was rolled back and reused by the handler's insert.
			if got["main_row"] != "rolled back" || got["bumped"] != "rolled back" || handlerRow != 1 {
				t.Fatalf("handler saw rolled-back writes: %v (handler row %v)", got, handlerRow)
			}
			continue
		}
		// A `||` result is written as text.
		if fmt.Sprint(got["main_row"]) != "1" || fmt.Sprint(got["bumped"]) != "1" || handlerRow != 2 {
			t.Fatalf("committed writes lost their outputs: %v (handler row %v)", got, handlerRow)
		}
	}
}
