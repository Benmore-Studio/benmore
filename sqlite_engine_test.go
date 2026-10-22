//go:build !cli

package main

// What the bundled SQLite engine and its driver (github.com/mattn/go-sqlite3)
// do in places the framework and app SQL depend on. Each test pins a behavior
// that differed in an earlier driver or engine release, so a dependency change
// that brings the old behavior back fails here and not in production. They run
// on the production driver name and DSN.

import (
	"database/sql"
	"path/filepath"
	"reflect"
	"testing"
)

func newEngineTestDB(t *testing.T) *sql.DB {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func engineInts(t *testing.T, db *sql.DB, query string) []int64 {
	t.Helper()
	rows, err := db.Query(query)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer rows.Close()
	out := []int64{}
	for rows.Next() {
		var v int64
		if err := rows.Scan(&v); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		out = append(out, v)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return out
}

func engineText(t *testing.T, db *sql.DB, query string) string {
	t.Helper()
	var v string
	if err := db.QueryRow(query).Scan(&v); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return v
}

// The driver's Query path on its own, without sqlRunnableText in front of it.
// Up to go-sqlite3 v1.14.42 each of these texts killed the process (it called
// sqlite3_clear_bindings on no statement). The driver now answers with an
// empty result that has no columns - and still does not run the statement
// before an empty trailing one. Both are why sqlRunnableText stays in front of
// every text the framework did not write (sql_scan.go).
func TestSQLiteDriverAnswersEmptyStatementWithEmptyResult(t *testing.T) {
	db := newEngineTestDB(t)
	mustExec(t, db, "CREATE TABLE t (id INTEGER PRIMARY KEY, name TEXT)")
	for _, q := range []string{
		"SELECT 1 AS n; -- note", "SELECT 1 AS n; /* x */", "SELECT 1 AS n;;",
		"-- only a comment", "/* only a comment */", "", "   ", ";", ";;",
	} {
		rows, err := db.Query(q)
		if err != nil {
			t.Fatalf("Query(%q): %v", q, err)
		}
		cols, err := rows.Columns()
		if err != nil || len(cols) != 0 || rows.Next() || rows.Err() != nil {
			t.Fatalf("Query(%q): columns %v (%v), a row or an error (%v); want an empty result without columns", q, cols, err, rows.Err())
		}
		rows.Close()
	}
	// An empty statement between two statements is skipped: the last one runs.
	if got := engineInts(t, db, "SELECT 1 AS n;; SELECT 2 AS n"); !reflect.DeepEqual(got, []int64{2}) {
		t.Fatalf("statement after an empty one answered %v, want [2]", got)
	}
	// A write followed by an empty statement is compiled and dropped by Query.
	rows, err := db.Query("INSERT INTO t (name) VALUES ('x') RETURNING id; -- note")
	if err != nil {
		t.Fatal(err)
	}
	if rows.Next() {
		t.Fatal("Query answered a row for a write followed by an empty statement")
	}
	rows.Close()
	if n := engineInts(t, db, "SELECT count(*) FROM t"); n[0] != 0 {
		t.Fatalf("Query ran the write before an empty trailing statement (%d rows); the sqlRunnableText comments say it does not", n[0])
	}
	// Exec skips the empty part and runs the write.
	mustExec(t, db, "INSERT INTO t (name) VALUES ('x'); -- note")
	if n := engineInts(t, db, "SELECT count(*) FROM t"); n[0] != 1 {
		t.Fatalf("Exec left %d rows, want 1", n[0])
	}
}

// SQLite 3.51 (the engine up to go-sqlite3 v1.14.43) turned a top-level EXISTS
// into a join and then counted OFFSET against the joined rows. When the
// subquery matched several rows for one outer row, a page began too early and a
// page past the end still held rows. Fixed upstream in 3.53.1.
func TestSQLiteEngineExistsWithOffsetSkipsResultRows(t *testing.T) {
	db := newEngineTestDB(t)
	mustExec(t, db, `CREATE TABLE orders (id INTEGER PRIMARY KEY, org_id INTEGER, status TEXT)`)
	mustExec(t, db, `CREATE TABLE items (id INTEGER PRIMARY KEY, order_id INTEGER, sku TEXT)`)
	mustExec(t, db, `CREATE INDEX idx_items_order ON items(order_id)`)
	mustExec(t, db, `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 20)
		INSERT INTO orders (id, org_id, status) SELECT x, 1 + (x % 4), 'new' FROM c`)
	// Orders 1..10 have three items each, the others none.
	mustExec(t, db, `WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c WHERE x < 30)
		INSERT INTO items (order_id, sku) SELECT 1 + (x % 10), 'S' || x FROM c`)

	const exists = `EXISTS (SELECT 1 FROM items i WHERE i.order_id = o.id)`
	for _, c := range []struct {
		name, query string
		want        []int64
	}{
		{"second page", `SELECT id FROM orders o WHERE ` + exists + ` ORDER BY id LIMIT 3 OFFSET 3`, []int64{4, 5, 6}},
		{"offset one", `SELECT id FROM orders o WHERE ` + exists + ` ORDER BY id LIMIT 1 OFFSET 1`, []int64{2}},
		{"descending", `SELECT id FROM orders o WHERE ` + exists + ` ORDER BY id DESC LIMIT 2 OFFSET 2`, []int64{8, 7}},
		{"with another filter", `SELECT id FROM orders o WHERE o.status = 'new' AND ` + exists + ` ORDER BY id LIMIT 2 OFFSET 8`, []int64{9, 10}},
		{"page past the end", `SELECT id FROM orders o WHERE ` + exists + ` ORDER BY id LIMIT 5 OFFSET 10`, []int64{}},
		{"no order by", `SELECT count(*) FROM (SELECT id FROM orders o WHERE ` + exists + ` LIMIT 50 OFFSET 4)`, []int64{6}},
	} {
		if got := engineInts(t, db, c.query); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v\n%s", c.name, got, c.want, c.query)
		}
	}
}

// SQLite 3.51 could answer "no row" for an EXISTS whose subquery filters on an
// OR of two indexed terms plus another condition: the rewritten join left at
// the first OR branch that failed the other condition. Fixed upstream in
// 3.53.1. The shapes are the upstream regression cases.
func TestSQLiteEngineExistsOverIndexedOr(t *testing.T) {
	db := newEngineTestDB(t)
	mustExec(t, db, `CREATE TABLE t (n INTEGER, parent INTEGER)`)
	mustExec(t, db, `CREATE INDEX idx_t_parent ON t(parent)`)
	mustExec(t, db, `INSERT INTO t VALUES (1, NULL), (10, NULL)`)
	mustExec(t, db, `CREATE TABLE t1 (a, b)`)
	mustExec(t, db, `INSERT INTO t1 VALUES (20, 20)`)
	mustExec(t, db, `CREATE TABLE t2 (c, d)`)
	mustExec(t, db, `CREATE INDEX t2c ON t2(c)`)
	mustExec(t, db, `CREATE INDEX t2d ON t2(d)`)
	mustExec(t, db, `INSERT INTO t2 VALUES (20, -1), (20, 0)`)

	if got := engineInts(t, db, `SELECT 1 WHERE EXISTS (SELECT 1 FROM t b WHERE (b.parent IS NULL OR b.parent = 99) AND 5 <= +b.n)`); !reflect.DeepEqual(got, []int64{1}) {
		t.Errorf("EXISTS over (IS NULL OR =) found %v, want one row", got)
	}
	if got := engineInts(t, db, `SELECT a FROM t1 WHERE EXISTS (SELECT 1 FROM t2 WHERE (c = a OR d = a) AND (d + 1) > 0)`); !reflect.DeepEqual(got, []int64{20}) {
		t.Errorf("EXISTS over (c = a OR d = a) found %v, want [20]", got)
	}
}

// How SQLite writes a double as text. Up to 3.51 it always kept 15 significant
// digits; since 3.53 it keeps 15 when that text reads back as the same double
// and 17 when it does not. A value stored as it was entered, a rounded value
// and printf with a precision are written as before. What changes is a double
// that carries arithmetic (a product, a SUM or AVG of REAL values) turned into
// text inside SQL: json_object()/json_array(), CAST(.. AS TEXT), `||`,
// printf('%s'). (A double read by Go was never rounded: 4.35*100 arrives as
// 434.99999999999994 either way.)
func TestSQLiteEngineWritesDoublesSoTheyReadBack(t *testing.T) {
	db := newEngineTestDB(t)
	for _, c := range []struct{ expr, want string }{
		// no shorter text reads back as the same double
		{`CAST(0.1 + 0.2 AS TEXT)`, "0.30000000000000004"},
		{`CAST(4.35 * 100 AS TEXT)`, "434.99999999999994"},
		{`(1.1 + 2.2) || ''`, "3.3000000000000003"},
		{`printf('%s', 0.1 + 0.7)`, "0.79999999999999993"},
		{`json_object('total', 4.35 * 100)`, `{"total":434.99999999999994}`},
		{`json_array(0.1 + 0.2, 1.0 / 3)`, "[0.30000000000000004,0.33333333333333332]"},
		{`(SELECT CAST(sum(v) AS TEXT) FROM (SELECT 19.99 AS v UNION ALL SELECT 5.01 UNION ALL SELECT 0.1))`, "25.099999999999998"},
		// 15 digits read back exactly: as before
		{`CAST(19.99 AS TEXT)`, "19.99"},
		{`CAST(19.99 * 3 AS TEXT)`, "59.97"},
		{`CAST(0.1 AS TEXT)`, "0.1"},
		{`json_object('price', 47.49)`, `{"price":47.49}`},
		// rounding and a printf precision decide the digits themselves
		{`CAST(round(4.35 * 100, 2) AS TEXT)`, "435.0"},
		{`printf('%.2f', 0.1 + 0.2)`, "0.30"},
		{`json_object('total', round(4.35 * 100, 2))`, `{"total":435.0}`},
	} {
		if got := engineText(t, db, "SELECT "+c.expr); got != c.want {
			t.Errorf("%s = %q, want %q", c.expr, got, c.want)
		}
	}
	// The text is the double: it reads back as the value it was written from.
	if got := engineInts(t, db, `SELECT CAST(CAST(0.1 + 0.2 AS TEXT) AS REAL) = 0.1 + 0.2`); got[0] != 1 {
		t.Error("the text of 0.1 + 0.2 does not read back as the same double")
	}
}
