//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"strings"
	"testing"
)

// Every ?include= entry runs its own batched query (plus one per nested
// level), and the entries were neither de-duplicated nor counted: a single
// anonymous GET on a public table with `?include=notes,notes,...` thousands
// of times ran thousands of queries over up to 500 parents each. Duplicates
// (after trimming each dotted segment) now resolve once, and more than
// maxIncludeSpecs distinct entries is a 400.
func TestIncludeSpecIsDeduplicatedAndCapped(t *testing.T) {
	got, err := normalizeIncludeSpec(" notes ,notes, notes . records ,notes.records,,")
	if err != nil || got != "notes,notes.records" {
		t.Fatalf("normalizeIncludeSpec = %q, %v", got, err)
	}

	app, mux := newAccessScopeFixture(t,
		map[string]map[AccessOp]string{"records": {"all": "anon"}, "notes": {"all": "anon"}},
		`CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, record_id INTEGER REFERENCES records(id), body TEXT)`,
		`INSERT INTO records (title) VALUES ('r')`,
		`INSERT INTO notes (record_id, body) VALUES (1, 'n')`,
	)
	cols, err := GetTableColumns(app.DB, "notes")
	if err != nil {
		t.Fatal(err)
	}
	app.Tables = append(app.Tables, Table{Name: "notes", Columns: cols})
	app.JoinMap = BuildJoinMap(app.DB)
	mux = buildAppMux(app, true, "http://localhost")

	repeated := strings.TrimSuffix(strings.Repeat("notes,", 200), ",")
	for _, path := range []string{"/api/records?include=" + repeated, "/api/records/1?include=" + repeated} {
		rec := crudScopeRequest(t, mux, http.MethodGet, path, "", nil)
		if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"notes":[`) {
			t.Fatalf("repeated include entries should collapse to one: %d %s", rec.Code, rec.Body.String())
		}
	}
	var distinct []string
	for i := 0; i <= maxIncludeSpecs; i++ {
		distinct = append(distinct, fmt.Sprintf("notes.x%d", i))
	}
	for _, path := range []string{"/api/records?include=", "/api/records/1?include=", "/api/records?cursor=0&include="} {
		if rec := crudScopeRequest(t, mux, http.MethodGet, path+strings.Join(distinct, ","), "", nil); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s with %d include entries: %d %s", path, len(distinct), rec.Code, rec.Body.String())
		}
	}
}
