//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
)

// readOnlySealedFixture is an app with encrypted columns (text with a blind
// index, an integer), a versioned table, a table with no encrypted column and
// one encrypted column whose rows are still plaintext at rest.
func readOnlySealedFixture(t *testing.T) *App {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model Patient {
 id Int @id @default(autoincrement())
 name String
 ssn String?
 salary Int?
 updated_at DateTime @default(now()) @updatedAt
 @@map("patients")
}
model Visit {
 id Int @id @default(autoincrement())
 patient_id Int
 note String
 @@map("visits")
}
model Legacy {
 id Int @id @default(autoincrement())
 body String?
 @@map("legacy_notes")
}`)
	writeTestFile(t, dir, "app.yaml", `auth: {identifier: email}
access:
 patients: admin
 visits: admin
 legacy_notes: admin
versioned: [patients]
`)
	writeTestFile(t, dir, "encrypted.yaml", `tables:
 patients:
  fields: [ssn, salary]
  blind_index: [ssn]
 legacy_notes:
  fields: [body]
`)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	mustExec(t, app.DB, `INSERT INTO patients(id, name, ssn, salary) VALUES (1, 'Ada', '123-45-6789', 50000)`)
	mustExec(t, app.DB, `INSERT INTO patients(id, name, ssn, salary) VALUES (2, 'Grace', NULL, NULL)`)
	// One edit, so patients_history holds a sealed snapshot of row 1.
	mustExec(t, app.DB, `UPDATE patients SET name = 'Ada L' WHERE id = 1`)
	mustExec(t, app.DB, `INSERT INTO visits(id, patient_id, note) VALUES (1, 1, 'Annual check')`)
	// A row written before the column was encrypted: plaintext at rest.
	triggers, err := app.DB.Query(`SELECT name FROM sqlite_master WHERE type = 'trigger' AND tbl_name = 'legacy_notes'`)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for triggers.Next() {
		var name string
		if err := triggers.Scan(&name); err != nil {
			t.Fatal(err)
		}
		names = append(names, name)
	}
	triggers.Close()
	for _, name := range names {
		mustExec(t, app.DB, `DROP TRIGGER `+quoteIdent(name))
	}
	mustExec(t, app.DB, `INSERT INTO legacy_notes(id, body) VALUES (1, 'written before encryption')`)
	return app
}

// readOnlySealedViews adds views over the encrypted column: one that computes
// on it and one whose text hides a compound from the statement that reads it.
func readOnlySealedViews(t *testing.T, app *App) {
	t.Helper()
	mustExec(t, app.DB, `CREATE VIEW patient_pieces AS SELECT id, name, ssn AS whole, substr(ssn, 2) AS piece FROM patients`)
	mustExec(t, app.DB, `CREATE VIEW patient_mix AS SELECT name AS v FROM patients WHERE 0 UNION ALL SELECT substr(ssn, 2) FROM patients`)
	// SQLite types a view's column by the last arm: here the plain one.
	mustExec(t, app.DB, `CREATE VIEW patient_mix_reversed AS SELECT substr(ssn, 2) AS v FROM patients UNION ALL SELECT name FROM patients WHERE id < 0`)
}

func readOnlySealedStored(t *testing.T, app *App) (ssn, salary, blind string) {
	t.Helper()
	if err := app.DB.QueryRow(`SELECT ssn, salary, ssn_blind FROM patients WHERE id = 1`).Scan(&ssn, &salary, &blind); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ssn, "enc:") || !strings.HasPrefix(salary, "enc:") || blind == "" {
		t.Fatalf("fixture is not encrypted at rest: ssn=%q salary=%q blind=%q", ssn, salary, blind)
	}
	return ssn, salary, blind
}

func readOnlySealedQuery(t *testing.T, app *App, gate, statement string) []map[string]any {
	t.Helper()
	args, _ := json.Marshal(appDataQueryArgs{SQL: statement, Gate: gate})
	out, err := appDataQuery(context.Background(), &appDataOpCall{App: app, Actor: appDataTestEditor, Args: args, RequestID: "sealed"})
	if err != nil {
		t.Fatalf("%s: %v", statement, err)
	}
	res, ok := out.(appDataRowsResult)
	if !ok {
		t.Fatalf("%s: result is %T", statement, out)
	}
	return res.Rows
}

// readOnlySealedLeak reports a result value that carries a piece of a stored
// ciphertext, in clear, in hex or as character codes.
func readOnlySealedLeak(value any, stored ...string) string {
	text := strings.ToLower(fmt.Sprint(value))
	for _, s := range stored {
		body := strings.ToLower(s[strings.LastIndexByte(s, ':')+1:])
		for i := 0; i+12 <= len(body); i += 4 {
			piece := body[i : i+12]
			if strings.Contains(text, piece) || strings.Contains(text, fmt.Sprintf("%x", piece)) {
				return piece
			}
		}
	}
	return ""
}

// Rule 26c: read-only SQL (query_db, `benmore sql`, the dashboard console)
// never hands back ciphertext. A value computed from an encrypted column does
// not start with `enc:`, so what a value looks like cannot decide it; where the
// result column comes from does.
func TestReadOnlySQLMasksValuesDerivedFromEncryptedColumns(t *testing.T) {
	app := readOnlySealedFixture(t)
	ssn, salary, _ := readOnlySealedStored(t, app)
	var history string
	if err := app.DB.QueryRow(`SELECT ssn FROM patients_history LIMIT 1`).Scan(&history); err != nil || !strings.HasPrefix(history, "enc:") {
		t.Fatalf("history snapshot is not sealed: %q %v", history, err)
	}
	type sealedCase struct{ name, statement string }
	cases := []sealedCase{
		{"substr", `SELECT substr(ssn, 2) AS v FROM patients WHERE id = 1`},
		{"substr aliased as the column", `SELECT substr(ssn, 2) AS ssn FROM patients WHERE id = 1`},
		{"concat", `SELECT ssn || '' AS v FROM patients WHERE id = 1`},
		{"concat prefix", `SELECT 'x' || ssn AS v FROM patients WHERE id = 1`},
		{"hex", `SELECT hex(ssn) AS v FROM patients WHERE id = 1`},
		{"lower", `SELECT lower(ssn) AS v FROM patients WHERE id = 1`},
		{"upper", `SELECT upper(ssn) AS v FROM patients WHERE id = 1`},
		{"trim", `SELECT ltrim(ssn, 'enc:v') AS v FROM patients WHERE id = 1`},
		{"quote", `SELECT quote(ssn) AS v FROM patients WHERE id = 1`},
		{"printf", `SELECT printf('%s', ssn) AS v FROM patients WHERE id = 1`},
		{"cast", `SELECT CAST(ssn AS BLOB) AS v FROM patients WHERE id = 1`},
		{"case whole", `SELECT CASE WHEN id = 1 THEN ssn END AS v FROM patients WHERE id = 1`},
		{"case piece", `SELECT CASE WHEN ssn LIKE 'enc:%' THEN substr(ssn, 5) ELSE name END AS v FROM patients WHERE id = 1`},
		{"coalesce", `SELECT coalesce(ssn, name) AS v FROM patients WHERE id = 1`},
		{"character codes", `SELECT unicode(substr(ssn, 9, 1)) AS v FROM patients WHERE id = 1`},
		{"length", `SELECT length(ssn) AS v FROM patients WHERE id = 1`},
		{"comparison", `SELECT ssn > 'enc:v2:5' AS v FROM patients WHERE id = 1`},
		{"null test", `SELECT ssn IS NOT NULL AS v FROM patients WHERE id = 1`},
		{"count of the column", `SELECT COUNT(ssn) AS v FROM patients`},
		{"count filtered by the column", `SELECT COUNT(*) AS v FROM patients WHERE ssn IS NOT NULL`},
		{"max", `SELECT max(ssn) AS v FROM patients`},
		{"group_concat", `SELECT group_concat(ssn) AS v FROM patients`},
		{"window", `SELECT first_value(ssn) OVER (ORDER BY id) AS v FROM patients WHERE id = 1`},
		{"numeric arithmetic", `SELECT salary + 1 AS v FROM patients WHERE id = 1`},
		{"numeric piece", `SELECT substr(salary, 3) AS v FROM patients WHERE id = 1`},
		{"scalar subquery", `SELECT (SELECT substr(p2.ssn, 2) FROM patients p2 WHERE p2.id = p.id) AS v FROM patients p WHERE p.id = 1`},
		{"from subquery", `SELECT v FROM (SELECT substr(ssn, 2) AS v FROM patients WHERE id = 1)`},
		{"from subquery kept apart", `SELECT v FROM (SELECT substr(ssn, 2) AS v FROM patients WHERE id = 1 LIMIT 5)`},
		{"cte", `WITH c AS (SELECT substr(ssn, 2) AS v FROM patients WHERE id = 1) SELECT v FROM c`},
		{"cte materialized", `WITH c AS MATERIALIZED (SELECT substr(ssn, 2) AS v FROM patients WHERE id = 1) SELECT v FROM c`},
		{"cte re-selected twice", `WITH c AS (SELECT ssn AS s FROM patients WHERE id = 1), d AS (SELECT substr(s, 2) AS v FROM c) SELECT v FROM d`},
		{"union behind a plain column", `SELECT name AS v FROM patients WHERE 0 UNION ALL SELECT substr(ssn, 2) FROM patients WHERE id = 1`},
		{"union distinct", `SELECT name AS v FROM patients WHERE 0 UNION SELECT substr(ssn, 2) FROM patients WHERE id = 1`},
		{"except", `SELECT substr(ssn, 2) AS v FROM patients WHERE id = 1 EXCEPT SELECT name FROM patients`},
		{"union in a subquery", `SELECT v FROM (SELECT name AS v FROM patients WHERE 0 UNION ALL SELECT substr(ssn, 2) FROM patients WHERE id = 1)`},
		{"union in a cte", `WITH c AS (SELECT name AS v FROM patients WHERE 0 UNION ALL SELECT substr(ssn, 2) FROM patients WHERE id = 1) SELECT v FROM c`},
		{"union in a subquery reversed", `SELECT v FROM (SELECT substr(ssn, 2) AS v FROM patients WHERE id = 1 UNION ALL SELECT name FROM patients WHERE id < 0)`},
		{"union in a cte reversed", `WITH c AS (SELECT substr(ssn, 2) AS v FROM patients WHERE id = 1 UNION SELECT name FROM patients WHERE id < 0) SELECT v FROM c`},
		{"intersect in a subquery", `SELECT v FROM (SELECT substr(ssn, 2) AS v FROM patients WHERE id = 1 INTERSECT SELECT substr(ssn, 2) FROM patients)`},
		{"union in a scalar subquery reversed", `SELECT (SELECT substr(ssn, 2) FROM patients WHERE id = 1 UNION ALL SELECT name FROM patients WHERE id < 0) AS v`},
		{"union in a scalar subquery", `SELECT (SELECT name FROM patients WHERE 0 UNION ALL SELECT substr(ssn, 2) FROM patients WHERE id = 1) AS v`},
		{"union with values", `SELECT name AS v FROM patients WHERE 0 UNION ALL VALUES ((SELECT substr(ssn, 2) FROM patients WHERE id = 1))`},
		{"values rows", `SELECT column1 AS v FROM (VALUES ((SELECT name FROM patients WHERE id = 1)), ((SELECT substr(ssn, 2) FROM patients WHERE id = 1))) WHERE column1 <> 'Ada L'`},
		{"values rows reversed", `SELECT column1 AS v FROM (VALUES ((SELECT substr(ssn, 2) FROM patients WHERE id = 1)), ((SELECT name FROM patients WHERE id = 1))) WHERE column1 <> 'Ada L'`},
		{"correlated values", `SELECT (WITH x(c) AS (VALUES (name), (substr(ssn, 2))) SELECT c FROM x LIMIT 1 OFFSET 1) AS v FROM patients WHERE id = 1`},
		{"correlated values reversed", `SELECT (WITH x(c) AS (VALUES (substr(ssn, 2)), (name)) SELECT c FROM x LIMIT 1) AS v FROM patients WHERE id = 1`},
		{"full join using", `SELECT substr(ssn, 2) AS v FROM patients a FULL JOIN patients b USING (ssn) WHERE ssn IS NOT NULL`},
		{"full outer join using", `SELECT hex(ssn) AS v FROM patients a FULL OUTER JOIN patients_history b USING (ssn) WHERE ssn IS NOT NULL`},
		{"natural full join", `SELECT substr(ssn, 2) AS v FROM patients a NATURAL FULL JOIN patients b WHERE ssn IS NOT NULL`},
		{"natural full join split", "SELECT substr(ssn, 2) AS v FROM patients a NATURAL/**/FULL\n\tOUTER JOIN patients b WHERE ssn IS NOT NULL"},
		{"full join using in a subquery", `SELECT v FROM (SELECT substr(ssn, 2) AS v FROM patients a FULL JOIN patients b USING (ssn) WHERE ssn IS NOT NULL)`},
		{"right join using", `SELECT substr(ssn, 2) AS v FROM patients a RIGHT JOIN patients b USING (ssn) WHERE ssn IS NOT NULL`},
		{"join using", `SELECT substr(ssn, 2) AS v FROM patients a JOIN patients b USING (ssn)`},
		{"json table function", `SELECT j.value AS v FROM patients, json_each(json_array(ssn)) AS j WHERE patients.id = 1`},
		{"history", `SELECT substr(ssn, 2) AS v FROM patients_history`},
		{"history hex", `SELECT hex(ssn) AS v FROM patients_history`},
		{"mixed case", `SELECT SUBSTR("SSN", 2) AS v FROM "PATIENTS" WHERE id = 1`},
	}
	check := func(stage string, cases []sealedCase) {
		t.Helper()
		for _, c := range cases {
			for _, gate := range []string{"query_db", "console"} {
				rows := readOnlySealedQuery(t, app, gate, c.statement)
				if len(rows) == 0 {
					t.Errorf("%s, %s (%s): no rows", stage, c.name, gate)
					continue
				}
				for _, row := range rows {
					for column, value := range row {
						if value != encryptedFieldMask {
							t.Errorf("%s, %s (%s): %s = %#v, want the mask", stage, c.name, gate, column, value)
						}
						if piece := readOnlySealedLeak(value, ssn, salary, history); piece != "" {
							t.Errorf("%s, %s (%s): %s carries ciphertext %q", stage, c.name, gate, column, piece)
						}
					}
				}
			}
		}
	}
	check("no views", cases)
	// A view's text is not in the statement that reads it, so a database with
	// views takes the stricter rule; every case holds under it too.
	readOnlySealedViews(t, app)
	check("with views", append(cases,
		sealedCase{"view expression", `SELECT piece AS v FROM patient_pieces WHERE id = 1`},
		sealedCase{"view union", `SELECT v FROM patient_mix WHERE v IS NOT NULL`},
		sealedCase{"view union reversed", `SELECT v FROM patient_mix_reversed WHERE v IS NOT NULL`},
		sealedCase{"view union in a subquery", `SELECT v FROM (SELECT v FROM patient_mix WHERE v IS NOT NULL)`},
		sealedCase{"view union reversed in a subquery", `SELECT v FROM (SELECT v FROM patient_mix_reversed WHERE v IS NOT NULL LIMIT 5)`},
		sealedCase{"view union reversed in a cte", `WITH c AS (SELECT v FROM patient_mix_reversed) SELECT v FROM c WHERE v IS NOT NULL`},
	))
	// Two result columns with one name: the plain one must not vouch for the
	// computed one.
	rows := readOnlySealedQuery(t, app, "query_db", `SELECT name, substr(ssn, 2) AS name FROM patients WHERE id = 1`)
	if len(rows) != 1 || rows[0]["name"] != encryptedFieldMask {
		t.Errorf("duplicate result name = %#v, want the mask", rows)
	}
	// NULL stays NULL, as it does under the field mask.
	rows = readOnlySealedQuery(t, app, "query_db", `SELECT substr(ssn, 2) AS v FROM patients WHERE id = 2`)
	if len(rows) != 1 || rows[0]["v"] != nil {
		t.Errorf("computed NULL = %#v, want NULL", rows)
	}
	// The same statement again on the same pool: the decision is made for every
	// run, not only the first time the statement is compiled.
	for i := 0; i < 3; i++ {
		rows = readOnlySealedQuery(t, app, "query_db", `SELECT substr(ssn, 2) AS v FROM patients WHERE id = 1`)
		if len(rows) != 1 || rows[0]["v"] != encryptedFieldMask {
			t.Errorf("run %d = %#v, want the mask", i, rows)
		}
	}
}

// A column selected by name keeps reading as before: the decrypted value, a
// number for an encrypted numeric column, and another table's columns in a
// join.
func TestReadOnlySQLKeepsPlainColumnsOfEncryptedTables(t *testing.T) {
	app := readOnlySealedFixture(t)
	ssn, salary, blind := readOnlySealedStored(t, app)
	one := func(statement string) map[string]any {
		t.Helper()
		rows := readOnlySealedQuery(t, app, "query_db", statement)
		if len(rows) != 1 {
			t.Fatalf("%s: %d rows", statement, len(rows))
		}
		for column, value := range rows[0] {
			if piece := readOnlySealedLeak(value, ssn, salary); piece != "" {
				t.Errorf("%s: %s carries ciphertext %q", statement, column, piece)
			}
		}
		return rows[0]
	}
	row := one(`SELECT id, name, ssn, salary FROM patients WHERE id = 1`)
	if row["id"] != int64(1) || row["name"] != "Ada L" || row["ssn"] != "123-45-6789" || row["salary"] != int64(50000) {
		t.Errorf("plain projection = %#v", row)
	}
	row = one(`SELECT * FROM patients WHERE id = 1`)
	if row["name"] != "Ada L" || row["ssn"] != "123-45-6789" || row["salary"] != int64(50000) || row["ssn_blind"] != blind {
		t.Errorf("star projection = %#v", row)
	}
	row = one(`SELECT p.ssn AS social, p."salary" AS pay FROM patients AS p WHERE p.id = 1 ORDER BY p.ssn`)
	if row["social"] != "123-45-6789" || row["pay"] != int64(50000) {
		t.Errorf("aliased projection = %#v", row)
	}
	// A join: the other table's column stays readable next to the decrypted
	// column and next to a masked expression.
	row = one(`SELECT v.note, p.name, p.ssn FROM visits v JOIN patients p ON p.id = v.patient_id`)
	if row["note"] != "Annual check" || row["name"] != "Ada L" || row["ssn"] != "123-45-6789" {
		t.Errorf("join = %#v", row)
	}
	row = one(`SELECT v.note, v.id, substr(p.ssn, 2) AS piece, upper(v.note) AS loud FROM visits v JOIN patients p ON p.id = v.patient_id`)
	if row["note"] != "Annual check" || row["id"] != int64(1) || row["piece"] != encryptedFieldMask || row["loud"] != encryptedFieldMask {
		t.Errorf("join with an expression = %#v", row)
	}
	// The blind-index sibling is an HMAC, not ciphertext: shown as stored, by
	// itself, in an expression, and next to the encrypted column.
	row = one(`SELECT ssn_blind, substr(ssn_blind, 1, 8) AS head, count(*) AS n FROM patients WHERE ssn_blind IS NOT NULL`)
	if row["ssn_blind"] != blind || row["head"] != blind[:8] || row["n"] != int64(1) {
		t.Errorf("blind sibling alone = %#v", row)
	}
	row = one(`SELECT ssn, ssn_blind, substr(ssn_blind, 1, 8) AS head FROM patients WHERE id = 1`)
	if row["ssn"] != "123-45-6789" || row["ssn_blind"] != blind || row["head"] != encryptedFieldMask {
		t.Errorf("blind sibling with its column = %#v", row)
	}
	// A filter on the column does not mask the plain columns it returns, which
	// is how `benmore encrypt-backfill` finds rows still in plaintext.
	row = one(`SELECT id, body AS val FROM legacy_notes WHERE body IS NOT NULL AND body NOT LIKE 'enc:%' AND body != ''`)
	if row["id"] != int64(1) || row["val"] != "written before encryption" {
		t.Errorf("backfill scan = %#v", row)
	}
	row = one(`SELECT id, name FROM patients WHERE ssn IS NOT NULL`)
	if row["id"] != int64(1) || row["name"] != "Ada L" {
		t.Errorf("filtered plain columns = %#v", row)
	}
	// The version history holds the same sealed value and reads the same way.
	row = one(`SELECT ssn, salary FROM patients_history LIMIT 1`)
	if row["ssn"] != "123-45-6789" || row["salary"] != int64(50000) {
		t.Errorf("history projection = %#v", row)
	}
	// A subquery or CTE that hands the column on as it is keeps it plain: with
	// no compound in the statement and no view in the database, each result
	// column has one expression behind it.
	passing := []string{
		`WITH c AS (SELECT id, name, ssn FROM patients WHERE id = 1) SELECT id, name, ssn FROM c`,
		`WITH c AS MATERIALIZED (SELECT id, name, ssn AS s FROM patients WHERE id = 1) SELECT id, name, s AS ssn FROM c`,
		`SELECT id, name, ssn FROM (SELECT * FROM patients WHERE id = 1 LIMIT 5)`,
		`SELECT id, name, ssn FROM patients WHERE id IN (SELECT patient_id FROM visits)`,
		`SELECT id, name, (SELECT p2.ssn FROM patients p2 WHERE p2.id = p.id) AS ssn FROM patients p WHERE p.id = 1`,
	}
	for _, statement := range passing {
		row = one(statement)
		if row["id"] != int64(1) || row["name"] != "Ada L" || row["ssn"] != "123-45-6789" {
			t.Errorf("%s = %#v", statement, row)
		}
	}
	// With a view in the database, a statement SQLite compiles as more than
	// one SELECT and that reads an encrypted column is masked whole: a view's
	// compound could stand behind any of its columns.
	readOnlySealedViews(t, app)
	for _, statement := range append(passing, `SELECT id, name, whole AS ssn FROM patient_pieces WHERE id = 1`) {
		row = one(statement)
		if row["id"] != encryptedFieldMask || row["name"] != encryptedFieldMask || row["ssn"] != encryptedFieldMask {
			t.Errorf("with views, %s = %#v, want the mask", statement, row)
		}
	}
	// One plain SELECT is not affected by the views.
	row = one(`SELECT v.note, p.name, p.ssn FROM visits v JOIN patients p ON p.id = v.patient_id`)
	if row["note"] != "Annual check" || row["name"] != "Ada L" || row["ssn"] != "123-45-6789" {
		t.Errorf("join with views in the database = %#v", row)
	}
	// Leaving the encrypted column out of such a statement leaves it alone.
	row = one(`SELECT id, upper(name) AS loud FROM patients WHERE id IN (SELECT patient_id FROM visits)`)
	if row["id"] != int64(1) || row["loud"] != "ADA L" {
		t.Errorf("subquery without the encrypted column = %#v", row)
	}
}

// A statement that reads no encrypted column is not looked at twice: computed
// columns of other tables, and of an encrypted table's other columns, read as
// they always did.
func TestReadOnlySQLLeavesOtherStatementsAlone(t *testing.T) {
	app := readOnlySealedFixture(t)
	rows := readOnlySealedQuery(t, app, "query_db", `SELECT upper(note) AS loud, length(note) AS n, (SELECT count(*) FROM visits) AS total FROM visits UNION ALL SELECT 'x', 1, 2`)
	if len(rows) != 2 || rows[0]["loud"] != "ANNUAL CHECK" || rows[0]["n"] != int64(12) || rows[0]["total"] != int64(1) {
		t.Errorf("table without encrypted columns = %#v", rows)
	}
	rows = readOnlySealedQuery(t, app, "console", `SELECT upper(name) AS loud, count(*) AS n FROM patients WHERE id = 1`)
	if len(rows) != 1 || rows[0]["loud"] != "ADA L" || rows[0]["n"] != int64(1) {
		t.Errorf("other columns of an encrypted table = %#v", rows)
	}
	rows = readOnlySealedQuery(t, app, "query_db", `SELECT count(*) AS n FROM patients`)
	if len(rows) != 1 || rows[0]["n"] != int64(2) {
		t.Errorf("row count of an encrypted table = %#v", rows)
	}
	if got := readOnlySealedColumns(app); !got["patients\x00ssn"] || !got["patients\x00salary"] || !got["patients_history\x00ssn"] || !got["legacy_notes\x00body"] || got["patients\x00ssn_blind"] || got["patients\x00name"] {
		t.Errorf("sealed columns = %v", got)
	}
	// A statement the authorizer never saw compiled is treated as one that
	// read an encrypted column, and nothing in it is taken as proven.
	unseen := &readOnlySealedReads{sealed: readOnlySealedColumns(app)}
	answer := []map[string]any{{"id": int64(1), "name": "Ada L", "gone": nil}}
	if !unseen.derived(`SELECT 1`) {
		t.Error("a statement never seen compiled must be masked")
	}
	readOnlyMaskDerived(answer, []string{"id", "name", "gone"}, []bool{true, true, true}, false)
	if answer[0]["id"] != encryptedFieldMask || answer[0]["name"] != encryptedFieldMask || answer[0]["gone"] != nil {
		t.Errorf("unproven answer = %#v", answer)
	}
	// No encrypted.yaml: nothing is recorded and no statement is inspected.
	plain := appDataTestApp(t)
	if got := readOnlySealedColumns(plain); got != nil {
		t.Errorf("sealed columns of an app without encrypted fields = %v", got)
	}
	rows = readOnlySealedQuery(t, plain, "query_db", `SELECT substr(title, 2) AS v FROM notes WHERE id = 1`)
	if len(rows) != 1 || rows[0]["v"] != "irst" {
		t.Errorf("app without encrypted fields = %#v", rows)
	}
}

// A join by column name (USING, NATURAL) reads its columns without the
// authorizer being asked, so the NULL a credential column reads as did not
// hold there: a FULL join returned the column and any such join compared it.
// Read-only SQL refuses the join on a framework table.
func TestReadOnlySQLRefusesNamedJoinsOnFrameworkTables(t *testing.T) {
	app := appDataTestApp(t)
	mustExec(t, app.DB, `CREATE TABLE _benmore_otp (email TEXT, code TEXT, attempts INTEGER DEFAULT 0, expires_at DATETIME);
		INSERT INTO _benmore_otp(email, code) VALUES ('a@example.test', '123456')`)
	run := func(gate, statement string) ([]map[string]any, error) {
		args, _ := json.Marshal(appDataQueryArgs{SQL: statement, Gate: gate})
		out, err := appDataQuery(context.Background(), &appDataOpCall{App: app, Actor: appDataTestEditor, Args: args, RequestID: "join"})
		res, _ := out.(appDataRowsResult)
		return res.Rows, err
	}
	for _, statement := range []string{
		`SELECT code FROM _benmore_otp a FULL JOIN _benmore_otp b USING (code)`,
		`SELECT * FROM _benmore_otp a NATURAL FULL JOIN _benmore_otp b`,
		`SELECT id FROM _benmore_sessions a FULL OUTER JOIN _benmore_sessions b USING (id)`,
		"select id from \"_BENMORE_SESSIONS\" a full\njoin [_benmore_sessions] b using(id)",
		// The join condition alone tells a guessed value from a wrong one.
		`SELECT g.code FROM _benmore_otp a JOIN (SELECT '123456' AS code) g USING (code)`,
		`SELECT g.code FROM (SELECT '123456' AS code) g NATURAL JOIN _benmore_otp`,
		`SELECT n.title FROM notes n LEFT JOIN _benmore_sessions s USING (id)`,
	} {
		for _, gate := range []string{"query_db", "console"} {
			rows, err := run(gate, statement)
			var de *appDataError
			if !errors.As(err, &de) || de.Code != "rejected" || de.Message != readOnlyNamedJoinRefusal {
				t.Errorf("%s (%s): rows=%v err=%v, want the join refused", statement, gate, rows, err)
			}
			for _, row := range rows {
				for column, value := range row {
					if text, _ := value.(string); strings.Contains(text, "123456") || strings.Contains(text, "live-session") {
						t.Errorf("%s (%s): %s = %q", statement, gate, column, text)
					}
				}
			}
		}
	}
	// The same joins written with ON are answered, credentials as NULL.
	rows, err := run("query_db", `SELECT a.email, a.code, b.code AS other FROM _benmore_otp a FULL JOIN _benmore_otp b ON a.code = b.code`)
	if err != nil || len(rows) == 0 {
		t.Fatalf("join with ON: rows=%v err=%v", rows, err)
	}
	for _, row := range rows {
		if row["code"] != nil || row["other"] != nil {
			t.Errorf("join with ON = %#v, want NULL codes", row)
		}
	}
	// App tables join by name as before, and a column that only contains the
	// word is not a join.
	mustExec(t, app.DB, `CREATE TABLE housing(id INTEGER PRIMARY KEY, natural_light TEXT, full_name TEXT); INSERT INTO housing VALUES(1, 'south', 'First Flat')`)
	rows, err = run("console", `SELECT title, full_name FROM notes NATURAL JOIN housing`)
	if err != nil || len(rows) != 1 || rows[0]["title"] != "first" || rows[0]["full_name"] != "First Flat" {
		t.Errorf("app tables joined by name: rows=%v err=%v", rows, err)
	}
	rows, err = run("query_db", `SELECT h.natural_light, s.user_id FROM housing h JOIN _benmore_sessions s ON s.user_id = h.id`)
	if err != nil || len(rows) != 1 || rows[0]["natural_light"] != "south" {
		t.Errorf("framework table joined with ON: rows=%v err=%v", rows, err)
	}
}
