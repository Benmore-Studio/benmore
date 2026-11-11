//go:build !cli && !windows

package main

import (
	"database/sql"
	"net/http"
	"strings"
	"testing"
)

// An aggregate is a read-only value. Its SQL ran on an ordinary connection,
// so `INSERT ... RETURNING` wrote a row at every start, reload, timer tick and
// manual refresh.

var aggregateWriteStatements = map[string]string{
	"insert returning":  `INSERT INTO notes (title) VALUES ('written by an aggregate') RETURNING id`,
	"update returning":  `UPDATE notes SET title = 'rewritten' RETURNING id`,
	"delete returning":  `DELETE FROM notes RETURNING id`,
	"with insert":       `WITH n AS (SELECT 'cte') INSERT INTO notes (title) SELECT * FROM n RETURNING id`,
	"replace":           `REPLACE INTO notes (id, title) VALUES (1, 'replaced') RETURNING id`,
	"second statement":  `DELETE FROM notes; SELECT 1`,
	"select then write": `SELECT 1; DELETE FROM notes`,
	"framework table":   `DELETE FROM _benmore_aggregates RETURNING name`,
	"ddl":               `CREATE TABLE made_by_an_aggregate (id INTEGER)`,
	"pragma":            `PRAGMA user_version = 7`,
}

func notesSnapshot(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`SELECT id || ':' || title FROM notes ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatal(err)
		}
		out = append(out, s)
	}
	return strings.Join(out, ",")
}

// A refresh of an aggregate whose SQL writes is refused and writes nothing,
// whatever put the statement in front of the refresher.
func TestAggregateRefreshRefusesSQLThatWrites(t *testing.T) {
	for name, statement := range aggregateWriteStatements {
		t.Run(name, func(t *testing.T) {
			app, _, _ := aggregateServeFixture(t, aggregatesAppYAML(aggregateEntry("note_count", "SELECT COUNT(*) FROM notes")))
			before := notesSnapshot(t, app.DB)
			err := refreshAggregate(app.DB, AggregateConfig{Name: "sneaky", SQL: statement})
			if err == nil {
				t.Errorf("the refresh must fail for %q", statement)
			}
			if after := notesSnapshot(t, app.DB); after != before {
				t.Errorf("the aggregate wrote: notes were %q, now %q", before, after)
			}
			var tables, version, stored int
			if err := app.DB.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE name = 'made_by_an_aggregate'`).Scan(&tables); err != nil || tables != 0 {
				t.Errorf("the aggregate created a table (%d, %v)", tables, err)
			}
			if err := app.DB.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version == 7 {
				t.Errorf("the aggregate set a pragma (%d, %v)", version, err)
			}
			if err := app.DB.QueryRow(`SELECT COUNT(*) FROM _benmore_aggregates WHERE name = 'note_count'`).Scan(&stored); err != nil || stored != 1 {
				t.Errorf("the aggregate deleted a stored value (%d, %v)", stored, err)
			}
			// The connection that ran it goes back to the pool able to write.
			mustExec(t, app.DB, `INSERT INTO notes (title) VALUES ('ordinary write')`)
			mustExec(t, app.DB, `DELETE FROM notes WHERE title = 'ordinary write'`)
		})
	}
}

// The same through a served app: the aggregate is listed as failed and stale,
// the others keep refreshing, and no row is written at start or on refresh.
func TestServedAggregateThatWritesIsRefusedAndWritesNothing(t *testing.T) {
	app, handler, sid := aggregateServeFixture(t, aggregatesAppYAML(
		aggregateEntry("note_count", "SELECT COUNT(*) FROM notes"),
		aggregateEntry("sneaky", "INSERT INTO notes (title) VALUES ('written by an aggregate') RETURNING id"),
	))
	rec := aggregateRequest(t, handler, http.MethodPost, sid)
	if body := rec.Body.String(); !strings.Contains(body, `"failed":["sneaky"]`) || !strings.Contains(body, `"refreshed":["note_count"]`) {
		t.Fatalf("refresh answer: %s", body)
	}
	if got := notesSnapshot(t, app.DB); got != "1:a,2:b,3:c" {
		t.Fatalf("the aggregate wrote rows: %s", got)
	}
	list := servedAggregateList(t, handler, sid)
	if list["note_count"]["value"] != float64(3) || list["note_count"]["stale"] != false {
		t.Errorf("the read-only aggregate must keep working: %v", list["note_count"])
	}
	sneaky := list["sneaky"]
	if sneaky == nil || sneaky["stale"] != true || sneaky["value"] != nil {
		t.Fatalf("the writing aggregate must be listed stale with no value: %v", sneaky)
	}
	if msg, _ := sneaky["error"].(string); !strings.Contains(msg, "read-only") {
		t.Errorf("its error must say an aggregate is read-only, got %q", msg)
	}
}

// Reads an aggregate has always been able to make still work on the
// read-only connection: joins, CTEs (recursive too), the framework's own
// tables, SQL functions, a literal or function that only looks like a write.
func TestAggregateReadsStillWork(t *testing.T) {
	app, _, _ := aggregateServeFixture(t, aggregatesAppYAML(aggregateEntry("note_count", "SELECT COUNT(*) FROM notes")))
	for statement, want := range map[string]string{
		`SELECT COUNT(*) FROM notes`:                                                                       "3",
		`SELECT COUNT(*) FROM notes WHERE title != 'delete'`:                                               "3",
		`SELECT replace(group_concat(title, ''), 'b', 'B') FROM notes`:                                     "aBc",
		`WITH t AS (SELECT title FROM notes) SELECT MAX(title) FROM t`:                                     "c",
		`WITH RECURSIVE n(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM n WHERE x < 5) SELECT SUM(x) FROM n`: "15",
		`SELECT COUNT(*) FROM _benmore_aggregates WHERE name = 'note_count'`:                               "1",
		`SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'notes'`:                       "1",
		`SELECT COUNT(*) FROM notes; -- trailing note`:                                                     "3",
		`VALUES (42)`: "42",
	} {
		if err := refreshAggregate(app.DB, AggregateConfig{Name: "probe", SQL: statement}); err != nil {
			t.Errorf("%s: %v", statement, err)
			continue
		}
		var got sql.NullString
		if err := app.DB.QueryRow(`SELECT value FROM _benmore_aggregates WHERE name = 'probe'`).Scan(&got); err != nil || got.String != want {
			t.Errorf("%s: stored %q (%v), want %q", statement, got.String, err, want)
		}
	}
}

func aggregateGateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.prisma", "model Note {\n  id    Int    @id @default(autoincrement())\n  title String\n}\n")
	return dir
}

// The write gate refuses an aggregate that is not one read-only SELECT. It
// accepted every one of these.
func TestAggregateWriteGateRefusesSQLThatWrites(t *testing.T) {
	dir := aggregateGateDir(t)
	for name, statement := range aggregateWriteStatements {
		doc := "aggregates:\n  sneaky:\n    sql: \"" + strings.ReplaceAll(statement, `"`, `\"`) + "\"\n    refresh: 5m\n"
		msg := ValidateOnWriteIn(dir, "app.yaml", doc)
		if !strings.Contains(msg, "sneaky") || !strings.Contains(msg, "read-only") {
			t.Errorf("%s: the gate must refuse %q naming the aggregate, got %q", name, statement, msg)
		}
	}
	for _, statement := range []string{
		`SELECT COUNT(*) FROM notes`,
		`SELECT COUNT(*) FROM notes WHERE title != 'delete'`,
		`SELECT replace(MAX(title), 'a', 'b') FROM notes`,
		`WITH t AS (SELECT title FROM notes) SELECT MAX(title) FROM t`,
		`SELECT COUNT(*) FROM notes;`,
		`VALUES (42)`,
	} {
		doc := "aggregates:\n  fine:\n    sql: \"" + statement + "\"\n    refresh: 5m\n"
		if msg := ValidateOnWriteIn(dir, "app.yaml", doc); msg != "" {
			t.Errorf("a read-only aggregate must pass (%s), got %q", statement, msg)
		}
	}
}

// Declarations the load drops with only a log line are refused by the gate,
// with the load's own reason: an aggregate that is never refreshed has no
// value anywhere and nothing says so.
func TestAggregateGateRefusesWhatTheLoadDrops(t *testing.T) {
	dir := aggregateGateDir(t)
	cases := map[string]struct{ entry, want string }{
		"no refresh":        {"    sql: SELECT 1\n", "refresh"},
		"refresh a number":  {"    sql: SELECT 1\n    refresh: 60\n", "refresh"},
		"refresh in days":   {"    sql: SELECT 1\n    refresh: 1d\n", "1d"},
		"refresh empty":     {"    sql: SELECT 1\n    refresh: \"\"\n", "refresh"},
		"no sql":            {"    refresh: 5m\n", "sql"},
		"query for sql":     {"    query: SELECT 1\n    refresh: 5m\n", `"query"`},
		"every for refresh": {"    sql: SELECT 1\n    every: 5m\n", `"every"`},
		"extra key":         {"    sql: SELECT 1\n    refresh: 5m\n    cache: true\n", `"cache"`},
		"only a comment":    {"    sql: \"-- nothing\"\n    refresh: 5m\n", "no SQL statement"},
	}
	for name, tc := range cases {
		doc := "aggregates:\n  total:\n" + tc.entry
		msg := ValidateOnWriteIn(dir, "app.yaml", doc)
		if !strings.Contains(msg, "total") || !strings.Contains(msg, tc.want) {
			t.Errorf("%s: the gate must refuse it naming the aggregate and %s, got %q", name, tc.want, msg)
		}
		// Gate and load agree: whatever the load would not run, the gate refuses.
		if configs := parseAggregateConfig([]byte(doc)); len(configs) != 0 && name != "extra key" && name != "only a comment" {
			t.Errorf("%s: the load is expected to drop it, got %+v", name, configs)
		}
	}
	if msg := ValidateOnWriteIn(dir, "app.yaml", "aggregates:\n  total: SELECT 1\n"); !strings.Contains(msg, "total") {
		t.Errorf("an aggregate that is not a mapping must be refused, got %q", msg)
	}
	// What the load runs, the gate accepts: the 1m and 24h bounds are clamps.
	for _, refresh := range []string{"1m", "5m", "1h", "24h", "90s", "30s", "48h"} {
		doc := "aggregates:\n  total:\n    sql: SELECT 1\n    refresh: " + refresh + "\n"
		if msg := ValidateOnWriteIn(dir, "app.yaml", doc); msg != "" {
			t.Errorf("refresh %s must pass, got %q", refresh, msg)
		}
		if configs := parseAggregateConfig([]byte(doc)); len(configs) != 1 {
			t.Errorf("refresh %s must load, got %+v", refresh, configs)
		}
	}
}
