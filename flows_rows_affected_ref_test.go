//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

// `.outputs.rows` is the alias for "the result set" only as a whole path
// segment. Cut as a prefix, it turned `steps.x.outputs.rows_affected` into
// `x_affected`, which never resolved: the documented count of a write could
// not be read, and an `if:` on it was always false.
func TestGHAOutputsRowsAliasIsAWholeSegment(t *testing.T) {
	for in, want := range map[string]string{
		"${{ steps.x.outputs.rows }}":               "{{x}}",
		"${{ steps.x.outputs.rows[0].id }}":         "{{x.0.id}}",
		"${{ steps.x.outputs.rows.0.id }}":          "{{x.0.id}}",
		"${{ steps.x.outputs.rows | length }}":      "{{x | length}}",
		"${{ steps.x.outputs.rows|length }}":        "{{x|length}}",
		"${{ steps.x.outputs.rows || 'none' }}":     "{{x || 'none'}}",
		"${{ steps.x.outputs.rows_affected }}":      "{{x.rows_affected}}",
		"${{ steps.x.outputs.rows_affected == 0 }}": "{{x.rows_affected == 0}}",
		"${{ steps.x.outputs.rows_total }}":         "{{x.rows_total}}",
		"${{ steps.x.outputs.rowsLeft }}":           "{{x.rowsLeft}}",
		"${{ steps.x.outputs.first.rows_seen }}":    "{{x.0.rows_seen}}",
	} {
		if got := normalizeGHARefs(in); got != want {
			t.Errorf("normalizeGHARefs(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFlowReadsRowsAffected(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT)`)
	mustExec(t, app.DB, `CREATE TABLE log (id INTEGER PRIMARY KEY, note TEXT)`)
	mustExec(t, app.DB, `INSERT INTO items (name) VALUES ('a'), ('b')`)
	flows, err := parseGHAFlowFile(filepath.Join(app.Dir, "flows", "probe.yaml"), []byte(`on:
  request:
    method: POST
    path: /api/probe
jobs:
  probe:
    steps:
      - id: upd
        run: sql
        with:
          query: "UPDATE items SET name = name || '!'"
      - id: none
        run: sql
        with:
          query: "UPDATE items SET name = 'x' WHERE id = 99"
      - if: ${{ steps.upd.outputs.rows_affected }}
        steps:
          - run: sql
            with: { query: "INSERT INTO log (note) VALUES ('changed')" }
      - if: ${{ steps.none.outputs.rows_affected }}
        steps:
          - run: sql
            with: { query: "INSERT INTO log (note) VALUES ('wrong')" }
      - run: respond
        with:
          status: 200
          body: { n: "${{ steps.upd.outputs.rows_affected }}" }
`))
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/probe", strings.NewReader(`{}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	if err := executeFlowHTTP(app, &flows[0], rr, req); err != nil || rr.Code != http.StatusOK {
		t.Fatalf("flow failed: %d %v %s", rr.Code, err, rr.Body.String())
	}
	if body := strings.TrimSpace(rr.Body.String()); body != `{"n":2}` {
		t.Fatalf("rows_affected read as %s, want {\"n\":2}", body)
	}
	var notes string
	if err := app.DB.QueryRow(`SELECT COALESCE(group_concat(note), '') FROM log`).Scan(&notes); err != nil || notes != "changed" {
		t.Fatalf("if: on rows_affected ran %q, want only the branch of the write that changed rows (%v)", notes, err)
	}
}
