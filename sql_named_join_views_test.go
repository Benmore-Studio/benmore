//go:build !cli

package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"html"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mattn/go-sqlite3"
)

// The engine fact behind the view rule: SQLite compiles a view's text when a
// statement reads the view, and a join by column name in that text reads its
// columns without asking the authorizer, exactly as one written in the
// statement does. The statement that reads the view holds no join to find. A
// view that reads the table by name is reported, also when the statement
// joins the view by column name: only the text that holds the join matters.
func TestNamedJoinInsideAViewIsNotReportedToTheAuthorizer(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustExec(t, db, `CREATE TABLE denied_rows(id INTEGER PRIMARY KEY, secret TEXT);
		INSERT INTO denied_rows VALUES (1, 'kept-from-the-caller');
		CREATE VIEW joined_view AS SELECT secret FROM (SELECT NULL AS secret WHERE 0) g FULL JOIN denied_rows USING (secret);
		CREATE VIEW outer_view AS SELECT secret FROM joined_view;
		CREATE VIEW plain_view AS SELECT secret FROM denied_rows`)
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	asked := 0
	if err := conn.Raw(func(raw any) error {
		mustSQLiteConn(raw).RegisterAuthorizer(func(action int, table, _, _ string) int {
			if action == sqlite3.SQLITE_READ && table == "denied_rows" {
				asked++
				return sqlite3.SQLITE_DENY
			}
			return sqlite3.SQLITE_OK
		})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	defer conn.Raw(func(raw any) error { restoreConnAuthorizer(mustSQLiteConn(raw)); return nil })
	read := func(statement string) (string, error) {
		var value sql.NullString
		err := conn.QueryRowContext(ctx, statement).Scan(&value)
		return value.String, err
	}
	for name, statement := range map[string]string{
		"a view that holds the join":         `SELECT secret FROM joined_view`,
		"a view that reads that view":        `SELECT secret FROM outer_view`,
		"an expression over the view":        `SELECT substr(secret, 1) FROM joined_view`,
		"the view under another name (CTE)":  `WITH c AS (SELECT secret AS s FROM outer_view) SELECT s FROM c`,
		"the view in a scalar subquery":      `SELECT (SELECT secret FROM joined_view)`,
		"the view named with its schema":     `SELECT secret FROM main."JOINED_VIEW"`,
		"the view named as a string literal": `SELECT secret FROM 'joined_view'`,
	} {
		value, err := read(statement)
		if err != nil || value != "kept-from-the-caller" || asked != 0 {
			t.Errorf("%s: value=%q err=%v asked=%d; SQLite now reports this read, revisit sql_named_join.go", name, value, err, asked)
		}
	}
	// A view that reads the table by name is compiled like a subquery: the
	// authorizer is asked, whatever the statement around it does.
	for name, statement := range map[string]string{
		"a plain view":                      `SELECT secret FROM plain_view`,
		"a plain view joined by column":     `SELECT g.secret FROM (SELECT 'kept-from-the-caller' AS secret) g JOIN plain_view USING (secret)`,
		"a plain view in a FULL named join": `SELECT secret FROM (SELECT NULL AS secret WHERE 0) g FULL JOIN plain_view USING (secret)`,
	} {
		asked = 0
		if value, err := read(statement); err == nil || asked == 0 {
			t.Errorf("%s: value=%q err=%v asked=%d, want the read denied", name, value, err, asked)
		}
	}
}

func TestSQLNamedJoinTouchesThroughViews(t *testing.T) {
	views := map[string][]string{
		"otp_codes":   {`CREATE VIEW otp_codes AS SELECT code FROM (SELECT NULL AS code WHERE 0) g FULL JOIN _benmore_otp USING (code)`},
		"codes_again": {`CREATE VIEW codes_again AS SELECT code FROM "OTP_CODES"`},
		"pairs":       {`CREATE VIEW pairs AS SELECT a.id FROM notes a NATURAL JOIN tags b`},
		"sessions_on": {`CREATE VIEW sessions_on AS SELECT s.user_id FROM notes n JOIN _benmore_sessions s ON s.user_id = n.id`},
		"loop_a":      {`CREATE VIEW loop_a AS SELECT * FROM loop_b`},
		"loop_b":      {`CREATE VIEW loop_b AS SELECT * FROM loop_a`},
		// Two views of one name (main and temp): either may be the one read.
		"shadowed": {`CREATE VIEW shadowed AS SELECT 1 AS n`, `CREATE VIEW shadowed AS SELECT id FROM _benmore_users NATURAL JOIN notes`},
	}
	for statement, want := range map[string]string{
		`SELECT code FROM otp_codes`:                                    "_benmore_otp",
		`SELECT code FROM "Otp_Codes"`:                                  "_benmore_otp",
		`SELECT code FROM [otp_codes]`:                                  "_benmore_otp",
		`SELECT code FROM 'otp_codes'`:                                  "_benmore_otp",
		`SELECT code FROM main.otp_codes AS c`:                          "_benmore_otp",
		`WITH c AS (SELECT code AS x FROM codes_again) SELECT x FROM c`: "_benmore_otp",
		`SELECT n FROM shadowed`:                                        "_benmore_users",
		`SELECT id FROM pairs`:                                          "",
		`SELECT user_id FROM sessions_on`:                               "",
		`SELECT * FROM loop_a`:                                          "",
		`SELECT title FROM notes`:                                       "",
		// The statement's own join, as before.
		`SELECT code FROM _benmore_otp a FULL JOIN _benmore_otp b USING (code)`: "_benmore_otp",
		// A join in the statement does not make a view's reported reads a
		// refusal: the view text that names the table holds no such join.
		`SELECT n.id FROM notes n JOIN sessions_on USING (id)`: "",
	} {
		if got, _ := sqlNamedJoinTouchesIn(sqlTextsRead(statement, views), sqlNamesFrameworkTable); got != want {
			t.Errorf("%s: touches %q, want %q", statement, got, want)
		}
	}
	for statement, want := range map[string]bool{
		`SELECT code FROM otp_codes`:   true,
		`SELECT code FROM codes_again`: true,
		`SELECT id FROM pairs`:         false,
		`SELECT title FROM notes`:      false,
	} {
		if got := sqlNamedFullJoinIn(sqlTextsRead(statement, views)); got != want {
			t.Errorf("%s: full named join = %t, want %t", statement, got, want)
		}
	}
}

// Read-only SQL: a view whose text joins a framework table by column name
// returned the credential column that reads as NULL everywhere else, and a
// view that computes on an encrypted column through such a join returned
// pieces of ciphertext. The statement that reads the view names neither.
func TestReadOnlySQLRefusesViewsThatJoinFrameworkTablesByName(t *testing.T) {
	app := appDataTestApp(t)
	mustExec(t, app.DB, `CREATE TABLE _benmore_otp (email TEXT, code TEXT, attempts INTEGER DEFAULT 0, expires_at DATETIME);
		INSERT INTO _benmore_otp(email, code) VALUES ('a@example.test', '123456');
		CREATE VIEW otp_codes AS SELECT code FROM (SELECT NULL AS code WHERE 0) g FULL JOIN _benmore_otp USING (code);
		CREATE VIEW otp_again AS SELECT code AS c FROM otp_codes;
		CREATE VIEW otp_guess AS SELECT g.code FROM (SELECT '123456' AS code) g NATURAL JOIN _benmore_otp;
		CREATE VIEW live_sessions AS SELECT id FROM (SELECT NULL AS id WHERE 0) g FULL JOIN _benmore_sessions USING (id);
		CREATE VIEW otp_on AS SELECT o.email, o.code FROM notes n JOIN _benmore_otp o ON o.attempts = n.id - 1;
		CREATE TABLE tags(id INTEGER PRIMARY KEY, label TEXT); INSERT INTO tags VALUES (1, 'red');
		CREATE VIEW tagged AS SELECT title, label FROM notes NATURAL JOIN tags`)
	run := func(gate, statement string) ([]map[string]any, error) {
		args, _ := json.Marshal(appDataQueryArgs{SQL: statement, Gate: gate})
		out, err := appDataQuery(context.Background(), &appDataOpCall{App: app, Actor: appDataTestEditor, Args: args, RequestID: "view"})
		res, _ := out.(appDataRowsResult)
		return res.Rows, err
	}
	leaked := func(label string, rows []map[string]any) {
		t.Helper()
		for _, row := range rows {
			for column, value := range row {
				if text, _ := value.(string); strings.Contains(text, "123456") || strings.Contains(text, "live-session") {
					t.Errorf("%s: %s = %q", label, column, text)
				}
			}
		}
	}
	for _, statement := range []string{
		`SELECT code FROM otp_codes`,
		`SELECT * FROM "OTP_CODES"`,
		`SELECT substr(code, 1) AS v FROM otp_codes`,
		`SELECT c FROM otp_again`,
		`WITH w AS (SELECT c AS x FROM otp_again) SELECT x FROM w`,
		`SELECT code FROM otp_guess`,
		`SELECT id FROM live_sessions`,
		`SELECT (SELECT id FROM live_sessions) AS v`,
	} {
		for _, gate := range []string{"query_db", "console"} {
			rows, err := run(gate, statement)
			leaked(statement+" ("+gate+")", rows)
			var de *appDataError
			if !errors.As(err, &de) || de.Code != "rejected" || !strings.Contains(de.Message, "USING") || !strings.Contains(de.Message, "view") {
				t.Errorf("%s (%s): rows=%v err=%v, want the view refused", statement, gate, rows, err)
			}
		}
	}
	// The table browser reads a view by its name.
	args, _ := json.Marshal(map[string]any{"table": "otp_codes", "limit": 10})
	out, err := appDataTableRows(context.Background(), &appDataOpCall{App: app, Actor: appDataTestEditor, Args: args, RequestID: "view"})
	if res, _ := out.(appDataRowsResult); err == nil || len(res.Rows) != 0 {
		leaked("table browser", res.Rows)
		t.Errorf("table browser on the view: rows=%v err=%v, want it refused", res.Rows, err)
	}
	// A view that reads the framework table with ON is answered, credentials
	// as NULL; a view that joins app tables by name is untouched.
	rows, err := run("query_db", `SELECT email, code FROM otp_on`)
	if err != nil || len(rows) != 1 || rows[0]["email"] != "a@example.test" || rows[0]["code"] != nil {
		t.Errorf("view with ON: rows=%v err=%v", rows, err)
	}
	rows, err = run("console", `SELECT title, label FROM tagged`)
	if err != nil || len(rows) != 1 || rows[0]["title"] != "first" || rows[0]["label"] != "red" {
		t.Errorf("view over app tables: rows=%v err=%v", rows, err)
	}
}

func TestReadOnlySQLMasksEncryptedColumnsReadThroughAViewJoin(t *testing.T) {
	app := readOnlySealedFixture(t)
	ssn, salary, _ := readOnlySealedStored(t, app)
	mustExec(t, app.DB, `CREATE VIEW ssn_pieces AS SELECT substr(ssn, 2) AS piece, hex(ssn) AS hexed, ssn AS whole FROM (SELECT NULL AS ssn WHERE 0) g FULL JOIN patients USING (ssn);
		CREATE VIEW ssn_renamed AS SELECT id, ssn AS s, salary AS pay FROM patients;
		CREATE VIEW ssn_pieces_again AS SELECT piece AS p FROM ssn_pieces`)
	for _, statement := range []string{
		`SELECT piece FROM ssn_pieces WHERE piece IS NOT NULL`,
		`SELECT hexed FROM ssn_pieces WHERE hexed IS NOT NULL`,
		`SELECT p FROM ssn_pieces_again WHERE p IS NOT NULL`,
		`SELECT substr(whole, 3) AS v FROM ssn_pieces WHERE whole IS NOT NULL`,
		`WITH c AS (SELECT piece AS x FROM ssn_pieces) SELECT x FROM c WHERE x IS NOT NULL`,
		// A view, subquery or CTE that only renames the column: the value
		// computed from it is masked whatever the column is called by then.
		`SELECT substr(s, 2) AS v FROM ssn_renamed WHERE id = 1`,
		`SELECT s || '' AS v FROM ssn_renamed WHERE id = 1`,
		`SELECT pay + 1 AS v FROM ssn_renamed WHERE id = 1`,
		`SELECT substr(x, 2) AS v FROM (SELECT s AS x FROM ssn_renamed WHERE id = 1)`,
		`WITH c(y) AS (SELECT s FROM ssn_renamed WHERE id = 1), d AS (SELECT y AS z FROM c) SELECT hex(z) AS v FROM d`,
		`SELECT substr(z, 2) AS v FROM (SELECT ssn AS z FROM patients WHERE id = 1)`,
	} {
		for _, gate := range []string{"query_db", "console"} {
			rows := readOnlySealedQuery(t, app, gate, statement)
			if len(rows) == 0 {
				t.Errorf("%s (%s): no rows", statement, gate)
			}
			for _, row := range rows {
				for column, value := range row {
					if value != encryptedFieldMask {
						t.Errorf("%s (%s): %s = %#v, want the mask", statement, gate, column, value)
					}
					if piece := readOnlySealedLeak(value, ssn, salary); piece != "" {
						t.Errorf("%s (%s): %s carries ciphertext %q", statement, gate, column, piece)
					}
				}
			}
		}
	}
	// The table's own column selected as it is still reads decrypted.
	rows := readOnlySealedQuery(t, app, "query_db", `SELECT ssn FROM patients WHERE id = 1`)
	if len(rows) != 1 || rows[0]["ssn"] != "123-45-6789" {
		t.Errorf("column selected as it is = %#v", rows)
	}
}

// A page's authored SQL: the hidden column, the read audit and the field
// masks follow what the statement read, and a view whose text joins by
// column name reads without being reported.
func TestPageQueryRefusesViewsThatJoinProtectedTablesByName(t *testing.T) {
	pages := map[string]string{
		"hidden.html":  legacyQueryPage("", "SELECT api_key FROM company_keys"),
		"renamed.html": legacyQueryPage("", "SELECT k AS shown FROM company_keys_again"),
		"audit.html":   legacyQueryPage("", "SELECT label FROM project_probe"),
		"plain.html":   legacyQueryPage("", "SELECT label FROM region_labels"),
		"on.html":      legacyQueryPage("", "SELECT name FROM project_names ORDER BY name"),
	}
	app := legacyQueryApp(t, pages)
	crudScopeMustExec(t, app.DB, "ALTER TABLE companies ADD COLUMN api_key TEXT")
	crudScopeMustExec(t, app.DB, "UPDATE companies SET api_key='must-stay-hidden'")
	crudScopeMustExec(t, app.DB, "CREATE TABLE regions(id INTEGER PRIMARY KEY, label TEXT); INSERT INTO regions VALUES (1, 'north')")
	crudScopeMustExec(t, app.DB, "CREATE TABLE region_notes(id INTEGER PRIMARY KEY, note TEXT); INSERT INTO region_notes VALUES (1, 'n')")
	crudScopeMustExec(t, app.DB, `CREATE VIEW company_keys AS SELECT api_key FROM (SELECT NULL AS api_key WHERE 0) g FULL JOIN companies USING (api_key)`)
	crudScopeMustExec(t, app.DB, `CREATE VIEW company_keys_again AS SELECT api_key AS k FROM company_keys`)
	crudScopeMustExec(t, app.DB, `CREATE VIEW project_probe AS SELECT g.label FROM (SELECT 1 AS company_id, 'a project of company one exists' AS label) g JOIN projects USING (company_id)`)
	crudScopeMustExec(t, app.DB, `CREATE VIEW region_labels AS SELECT r.label FROM regions r JOIN region_notes USING (id)`)
	crudScopeMustExec(t, app.DB, `CREATE VIEW project_names AS SELECT p.name FROM projects p JOIN companies c ON c.id = p.company_id`)
	for i := range app.Tables {
		if app.Tables[i].Name == "companies" {
			var err error
			if app.Tables[i].Columns, err = GetTableColumns(app.DB, "companies"); err != nil {
				t.Fatal(err)
			}
		}
	}
	app.Design = &DesignConfig{Auth: map[string]string{"read_audit": "projects"}}
	InitReadAudit(app, false)
	mux := buildAppMux(app, false, legacyQueryBaseURL)
	viewer, uid := tenantMember(t, app, "viewer@example.com", "user", 1, "viewer")
	audited := func() int {
		t.Helper()
		FlushReadAudit(app)
		var n int
		if err := app.DB.QueryRow("SELECT count(*) FROM _benmore_read_audit WHERE table_name='projects' AND user_id=? AND query_type='page_query'", uid).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	for _, name := range []string{"hidden", "renamed", "audit"} {
		before := audited()
		w := ssrGet(mux, "/"+name, viewer)
		body := html.UnescapeString(w.Body.String())
		for _, secret := range []string{"must-stay-hidden", "a project of company one exists"} {
			if strings.Contains(body, secret) {
				t.Errorf("%s: answered %q: %d %s", name, secret, w.Code, body)
			}
		}
		if w.Code != http.StatusInternalServerError {
			t.Errorf("%s: status %d, want the query refused: %s", name, w.Code, body)
		}
		if after := audited(); after != before {
			t.Errorf("%s: a refused query wrote %d read-audit row(s)", name, after-before)
		}
	}
	_, _, err := runPageQuery(context.Background(), app, nil, nil, newPageQueryPolicy(app, nil, nil, false), "SELECT label FROM project_probe")
	if err == nil || !strings.Contains(err.Error(), "write the join with ON") || !strings.Contains(err.Error(), "projects") || !strings.Contains(err.Error(), "view") {
		t.Errorf("refusal = %v", err)
	}
	// A view over tables nothing applies to, and a view that joins a
	// protected table with ON (reported, so audited), are answered.
	if rows := legacyQueryRows(t, mux, "/plain", viewer); len(rows) != 1 || rows[0]["label"] != "north" {
		t.Errorf("view over unprotected tables: %v", rows)
	}
	before := audited()
	if rows := legacyQueryRows(t, mux, "/on", viewer); len(rows) != 2 {
		t.Errorf("view with ON: %v", rows)
	}
	if after := audited(); after != before+1 {
		t.Errorf("view with ON wrote %d read-audit row(s), want 1", after-before)
	}
}
