//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"strings"
	"testing"
)

func upsertFlowSource(query string) string {
	return "on:\n  request: {method: POST, path: /api/report, auth: required, mode: async, transaction: true}\njobs:\n  report:\n    steps:\n      - run: sql\n        with:\n          query: " + fmt.Sprintf("%q", query) + "\n"
}

func TestReportUpsertExistingWhereExecutesAndValidates(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`CREATE TABLE report_entries(id INTEGER PRIMARY KEY, amount_cents INTEGER NOT NULL,user_id INTEGER NOT NULL)`,
		`CREATE TABLE report_runs(id INTEGER PRIMARY KEY,request_key TEXT,title TEXT,minimum INTEGER,row_count INTEGER,total_cents INTEGER,user_id INTEGER,UNIQUE(user_id,request_key))`,
		`INSERT INTO report_entries(amount_cents,user_id) VALUES(100,1),(250,1),(9999,2)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	query := `INSERT INTO report_runs (request_key,title,minimum,row_count,total_cents,user_id)
SELECT :request_key,:title,:minimum,COUNT(*),COALESCE(SUM(amount_cents),0),:user_id
FROM report_entries WHERE user_id=:user_id AND amount_cents>=:minimum
ON CONFLICT(user_id,request_key) DO NOTHING`
	for i := 0; i < 2; i++ {
		if _, err := db.Exec(query, sql.Named("request_key", "same"), sql.Named("title", "Report"), sql.Named("minimum", 0), sql.Named("user_id", 1)); err != nil {
			t.Fatal(err)
		}
	}
	var count, rows, total int
	if err := db.QueryRow(`SELECT COUNT(*),row_count,total_cents FROM report_runs`).Scan(&count, &rows, &total); err != nil {
		t.Fatal(err)
	}
	if count != 1 || rows != 2 || total != 350 {
		t.Fatalf("persisted count=%d rows=%d total=%d", count, rows, total)
	}
	if msg := ValidateOnWrite("flows/build-report.yaml", upsertFlowSource(query)); msg != "" {
		t.Fatalf("valid owner-filtered upsert refused: %s", msg)
	}
}

func TestUpsertWhereValidationUsesOuterSQLClauses(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE src(id INTEGER, "WHERE true" TEXT); CREATE TABLE dest(id INTEGER PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name, query string
		reject      bool
	}{
		{"ordinary predicate", `INSERT INTO dest(id) SELECT id FROM src WHERE id>0 ON CONFLICT(id) DO NOTHING`, false},
		{"comment separated keywords", `INSERT INTO dest(id) SELECT id FROM src WHERE /* filter */ id>0 ON /* upsert */ CONFLICT(id) DO NOTHING`, false},
		{"compound final predicate", `INSERT INTO dest(id) SELECT id FROM src UNION SELECT id FROM src WHERE id>0 ON CONFLICT(id) DO NOTHING`, false},
		{"values subquery", `INSERT INTO dest(id) VALUES ((SELECT id FROM src LIMIT 1)) ON CONFLICT(id) DO NOTHING`, false},
		{"CTE outer predicate", `WITH source AS (SELECT id FROM src) INSERT INTO dest(id) SELECT id FROM source WHERE id>0 ON CONFLICT(id) DO NOTHING`, false},
		{"ordered SELECT", `INSERT INTO dest(id) SELECT id FROM src ORDER BY id ON CONFLICT(id) DO NOTHING`, false},
		{"limited SELECT", `INSERT INTO dest(id) SELECT id FROM src LIMIT 1 ON CONFLICT(id) DO NOTHING`, false},
		{"missing predicate", `INSERT INTO dest(id) SELECT id FROM src ON CONFLICT(id) DO NOTHING`, true},
		{"comment not predicate", `INSERT INTO dest(id) SELECT id FROM src /* WHERE true */ ON CONFLICT(id) DO NOTHING`, true},
		{"literal not predicate", `INSERT INTO dest(id) SELECT 'WHERE true' FROM src ON CONFLICT(id) DO NOTHING`, true},
		{"quoted identifier not predicate", `INSERT INTO dest(id) SELECT "WHERE true" FROM src ON CONFLICT(id) DO NOTHING`, true},
		{"nested predicate not outer", `INSERT INTO dest(id) SELECT id FROM (SELECT id FROM src WHERE true) ON CONFLICT(id) DO NOTHING`, true},
		{"earlier compound predicate", `INSERT INTO dest(id) SELECT id FROM src WHERE true UNION SELECT id FROM src ON CONFLICT(id) DO NOTHING`, true},
		{"bind not predicate", `INSERT INTO dest(id) SELECT :where FROM src ON CONFLICT(id) DO NOTHING`, true},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			statement, err := db.Prepare(tt.query)
			if err == nil {
				statement.Close()
			}
			if (err != nil) != tt.reject {
				t.Fatalf("SQLite prepare error=%v, expected ambiguous=%v", err, tt.reject)
			}
			source := upsertFlowSource(tt.query)
			if !tt.reject {
				fixed, applied := AutoFixOnWrite("flows/build-report.yaml", source)
				if fixed != source || len(applied) != 0 {
					t.Fatalf("valid SQL was changed by autofix: %v\n%s", applied, fixed)
				}
			}
			msg := ValidateOnWrite("flows/build-report.yaml", source)
			if got := strings.Contains(msg, "WHERE"); got != tt.reject {
				t.Fatalf("reject=%v want%v: %s", got, tt.reject, msg)
			}
		})
	}
}

func TestUpsertWhereAutoFixStillRepairsAmbiguousOuterSelect(t *testing.T) {
	const query = `INSERT INTO dest(id) SELECT id FROM src ON CONFLICT(id) DO NOTHING`
	count, fixed := autoFixMissingWhereTrue(query)
	if count != 1 || fixed == query || upsertSelectNeedsWhere(fixed) {
		t.Fatalf("autofix count=%d query=%s", count, fixed)
	}
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE src(id INTEGER); CREATE TABLE dest(id INTEGER PRIMARY KEY); INSERT INTO src VALUES(7)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(fixed); err != nil {
		t.Fatal(err)
	}
	var id int
	if err := db.QueryRow(`SELECT id FROM dest`).Scan(&id); err != nil || id != 7 {
		t.Fatalf("repaired SQL effect id=%d err=%v", id, err)
	}
}
