//go:build !cli

package main

import (
	"context"
	"database/sql"
	"html"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/mattn/go-sqlite3"
)

// The engine fact every guard below answers to: a join by column name reads a
// table with no authorizer callback for it. If a later SQLite asks, this test
// says so and the refusals can be reconsidered.
func TestNamedJoinReadsATableWithoutAskingTheAuthorizer(t *testing.T) {
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	mustExec(t, db, `CREATE TABLE open_rows(id INTEGER PRIMARY KEY, secret TEXT);
		CREATE TABLE denied_rows(id INTEGER PRIMARY KEY, secret TEXT);
		INSERT INTO denied_rows VALUES (1, 'kept-from-the-caller')`)
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
		var args []any
		if strings.Contains(statement, "?1") {
			args = append(args, 0)
		}
		err := conn.QueryRowContext(ctx, statement, args...).Scan(&value)
		return value.String, err
	}
	// Written with ON, the authorizer is asked and the read is denied.
	if _, err := read(`SELECT d.secret FROM open_rows o FULL JOIN denied_rows d ON d.secret = o.secret`); err == nil || asked == 0 {
		t.Fatalf("join with ON: err=%v asked=%d, want the read denied", err, asked)
	}
	asked = 0
	for name, statement := range map[string]string{
		"value through a FULL join":   `SELECT secret FROM (SELECT NULL AS secret WHERE 0) g FULL JOIN denied_rows USING (secret)`,
		"value through NATURAL FULL":  `SELECT secret FROM (SELECT NULL AS secret WHERE 0) g NATURAL FULL JOIN denied_rows`,
		"guess through the condition": `SELECT g.secret FROM (SELECT 'kept-from-the-caller' AS secret) g JOIN denied_rows USING (secret)`,
		"after a numbered parameter":  `SELECT g.secret FROM (SELECT 'kept-from-the-caller' AS secret) g LEFT JOIN (SELECT 1 AS n) o ON o.n=?1natural join denied_rows`,
	} {
		value, err := read(statement)
		if err != nil || value != "kept-from-the-caller" || asked != 0 {
			t.Errorf("%s: value=%q err=%v asked=%d; SQLite now reports this read, revisit sql_named_join.go", name, value, err, asked)
		}
	}
}

func TestSQLNamedJoinTouches(t *testing.T) {
	framework := sqlNamesFrameworkTable
	for statement, want := range map[string]string{
		`SELECT code FROM _benmore_otp a FULL JOIN _benmore_otp b USING (code)`:                   "_benmore_otp",
		"select 1 from notes natural\n\tjoin \"_BENMORE_SESSIONS\"":                               "_BENMORE_SESSIONS",
		`SELECT 1 FROM notes n NATURAL JOIN [_benmore_sessions]`:                                  "_benmore_sessions",
		"SELECT 1 FROM notes n NATURAL JOIN `_benmore_sessions`":                                  "_benmore_sessions",
		`SELECT 1 FROM notes n NATURAL JOIN '_benmore_sessions'`:                                  "_benmore_sessions",
		`SELECT 1 FROM notes n JOIN main._benmore_sessions/**/using(id)`:                          "_benmore_sessions",
		`SELECT 1 FROM g LEFT JOIN notes n ON n.id=?1natural join _benmore_otp`:                   "_benmore_otp",
		`SELECT 1 FROM g LEFT JOIN notes n ON n.id=?12NATURAL JOIN _benmore_otp`:                  "_benmore_otp",
		`SELECT 1 FROM notes n JOIN _benmore_sessions s ON s.user_id = n.id`:                      "",
		`SELECT 1 FROM notes NATURAL JOIN housing`:                                                "",
		`SELECT natural_light, 'using' FROM _benmore_sessions -- natural join`:                    "",
		`SELECT "using", [natural] FROM _benmore_sessions /* using */ WHERE note = 'natural'`:     "",
		`SELECT 1 FROM notes n JOIN tags USING (id) WHERE n.title = 'about _benmore_sessions'`:    "about _benmore_sessions",
		`SELECT 1 FROM notes n JOIN tags USING (id) WHERE n.title = 'plain' -- _benmore_sessions`: "",
	} {
		if got := sqlNamedJoinTouches(statement, framework); got != want {
			t.Errorf("%s: touches %q, want %q", statement, got, want)
		}
	}
	for statement, want := range map[string]bool{
		`SELECT 1 FROM a FULL JOIN b USING (x)`:                     true,
		"SELECT 1 FROM a NATURAL/**/FULL\n\tOUTER JOIN b":           true,
		`SELECT 1 FROM a LEFT JOIN c ON c.x=?1full join b using(x)`: true,
		`SELECT 1 FROM a FULL JOIN b ON a.x = b.x`:                  false,
		`SELECT full_name FROM a JOIN b USING (x)`:                  false,
		`SELECT 'full' FROM a JOIN b USING (x)`:                     false,
	} {
		if got := sqlNamedFullJoin(statement); got != want {
			t.Errorf("%s: full named join = %t, want %t", statement, got, want)
		}
	}
}

// The authorizers that are NOT given the named-join check protect no read: each
// answers OK to a read of a credential column, so a join that is not reported
// steps around nothing. One that starts to deny or record reads needs the check
// (sql_named_join.go).
func TestAuthorizersWithoutNamedJoinCheckProtectNoRead(t *testing.T) {
	// The migration dry run (platform edition) answers with the migration
	// scope and the storage ceiling, both listed here.
	hipaa := &appSQLScope{hipaa: true}
	migration := &appSQLScope{migration: true, hipaa: true}
	for name, authorize := range map[string]func(action int, arg1, arg2, database string) int{
		"hook when: and aggregates":  authorizeWhenQuery,
		"reset and seeds":            authorizeAppReset,
		"storage ceiling":            authorizeStorageCeiling,
		"flow, hook and page SQL":    (&appSQLScope{}).authorize,
		"flow SQL, compliance hipaa": hipaa.authorize,
		"migration file":             migration.authorize,
	} {
		for _, read := range [][2]string{{"_benmore_sessions", "id"}, {"_benmore_users", "password_hash"}, {"_benmore_mcp_credentials", "token_hash"}, {"_benmore_audit_log", ""}} {
			if got := authorize(sqlite3.SQLITE_READ, read[0], read[1], "main"); got != sqlite3.SQLITE_OK {
				t.Errorf("%s: read of %s.%s = %d; an authorizer that protects a read must ask sqlNamedJoinTouches", name, read[0], read[1], got)
			}
		}
	}
	if hipaa.refused != "" || migration.refused != "" {
		t.Errorf("a read was refused: %q %q", hipaa.refused, migration.refused)
	}
}

// Every place that installs an authorizer is known to sql_named_join.go. A new
// one fails here until it is decided whether authored SQL reaches it and
// whether it protects reads.
func TestEveryAuthorizerInstallIsReviewedForNamedJoins(t *testing.T) {
	reviewed := map[string]bool{
		"app_mcp_command_sql_functions.go": true, // records function calls of command SQL, never a read
		"app_mcp_dispatch.go":              true, // fixed framework text
		"app_mcp_flows.go":                 true, // connector read flow: checked in flows_sql.go
		"app_mcp_grants.go":                true, // fixed framework text
		"app_mcp_oauth.go":                 true, // fixed framework text
		"app_reset.go":                     true, // admits every read
		"app_sql_guard.go":                 true, // schema changes and audit rewrites only
		"flows_command_runtime.go":         true, // command SQL: table inventory; hook SQL: checked in app_mcp_command_hooks.go
		"hook_when.go":                     true, // admits every read
		"mcp_query_readonly.go":            true, // read-only SQL: checked in app_data_ops_sql.go
		"migration_dry_run.go":             true, // admits every read
		"page_query_reads.go":              true, // checked in runPageQuery
		"storage_limit.go":                 true, // pragmas only
		"validators_encrypted_compute.go":  true, // checked in encryptedComputeProblems
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		source, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(source), ".RegisterAuthorizer(") && !reviewed[file] {
			t.Errorf("%s installs a SQLite authorizer: decide whether authored SQL reaches it and whether it denies, masks or records a read (then it needs sqlNamedJoinTouches), and list it here and in sql_named_join.go", file)
		}
	}
}

// A page's authored SQL: what the statement read decides the read audit, the
// hidden columns and the field masks, and a join by column name is not
// reported. Such a query on a table any of those apply to is refused.
func TestPageQueryRefusesNamedJoinsOnProtectedTables(t *testing.T) {
	leaks := map[string]string{
		// benmore_decrypt(...) AS <field> is masked for a viewer by the field's
		// name, when the query is known to have read the field.
		"decrypt": "SELECT benmore_decrypt(private_note) AS private_note FROM (SELECT NULL AS private_note WHERE 0) g FULL JOIN projects USING (private_note)",
		// A hidden column is stripped from the tables the query read.
		"hidden":  "SELECT api_key FROM (SELECT NULL AS api_key WHERE 0) g FULL JOIN companies USING (api_key)",
		"natural": "SELECT * FROM (SELECT NULL AS api_key WHERE 0) g NATURAL FULL JOIN companies",
		// A read of an audited table writes a read-audit row.
		"audit":     "SELECT g.label FROM (SELECT 1 AS company_id, 'a project of company one exists' AS label) g JOIN projects USING (company_id)",
		"framework": "SELECT g.label FROM (SELECT 1 AS id, 'user one exists' AS label) g JOIN _benmore_users USING (id)",
	}
	pages := map[string]string{
		"on.html":    legacyQueryPage("", "SELECT p.name, c.name AS company FROM projects p JOIN companies c ON c.id = p.company_id ORDER BY p.id"),
		"plain.html": legacyQueryPage("", "SELECT r.label FROM regions r NATURAL JOIN (SELECT 1 AS id) g JOIN region_notes USING (id)"),
		"word.html":  legacyQueryPage("", "SELECT name, 'natural' AS using_note FROM projects ORDER BY id"),
	}
	for name, query := range leaks {
		pages[name+".html"] = legacyQueryPage("", query)
	}
	app := legacyQueryApp(t, pages)
	crudScopeMustExec(t, app.DB, "ALTER TABLE companies ADD COLUMN api_key TEXT")
	crudScopeMustExec(t, app.DB, "UPDATE companies SET api_key='must-stay-hidden'")
	crudScopeMustExec(t, app.DB, "CREATE TABLE regions(id INTEGER PRIMARY KEY, label TEXT); INSERT INTO regions VALUES (1, 'north')")
	crudScopeMustExec(t, app.DB, "CREATE TABLE region_notes(id INTEGER PRIMARY KEY, note TEXT); INSERT INTO region_notes VALUES (1, 'n')")
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
	for name := range leaks {
		before := audited()
		w := ssrGet(mux, "/"+name, viewer)
		body := html.UnescapeString(w.Body.String())
		for _, secret := range []string{"acme-private-note", "globex-private-note", "must-stay-hidden", "a project of company one exists", "user one exists"} {
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
	// The refusal says what to write instead.
	_, _, err := runPageQuery(context.Background(), app, nil, nil, newPageQueryPolicy(app, nil, nil, false), leaks["audit"])
	if err == nil || !strings.Contains(err.Error(), "write the join with ON") || !strings.Contains(err.Error(), "projects") {
		t.Errorf("refusal = %v", err)
	}
	// The same join with ON is answered and audited; a join by name between
	// tables nothing applies to, and the bare words as values, are untouched.
	before := audited()
	if rows := legacyQueryRows(t, mux, "/on", viewer); len(rows) != 2 {
		t.Errorf("join with ON: %v", rows)
	}
	if after := audited(); after != before+1 {
		t.Errorf("join with ON wrote %d read-audit row(s), want 1", after-before)
	}
	if rows := legacyQueryRows(t, mux, "/plain", viewer); len(rows) != 1 || rows[0]["label"] != "north" {
		t.Errorf("join by name between unprotected tables: %v", rows)
	}
	if rows := legacyQueryRows(t, mux, "/word", viewer); len(rows) != 2 || rows[0]["using_note"] != "natural" {
		t.Errorf("the words as values: %v", rows)
	}
}

// Computed fields and aggregates: which encrypted column one reads is the
// authorizer's answer, so a join by column name on an encrypted table is
// refused at write time like the read it hides.
func TestComputedAndAggregatesRefuseNamedJoinsOnEncryptedTables(t *testing.T) {
	dir := writeApp(t, map[string]string{"schema.prisma": encComputeSchema, "encrypted.yaml": encComputeEncrypted, "app.yaml": encComputeApp})
	refused := []struct{ name, file, content, want string }{
		{"aggregate full join using", "app.yaml", encComputeAggregate("salary_sum", "SELECT SUM(salary) FROM (SELECT NULL AS salary WHERE 0) g FULL JOIN patients USING (salary)"), "app.yaml: aggregate salary_sum joins by column name (USING or NATURAL) in a statement that names patients, which encrypted.yaml encrypts"},
		{"aggregate natural", "app.yaml", encComputeAggregate("dx", "SELECT COUNT(*) FROM (SELECT 'flu' AS diagnosis) g NATURAL JOIN patients"), "aggregate dx joins by column name"},
		{"sql using", "computed.yaml", encComputeSQL("SELECT SUM(amount) FROM (SELECT NULL AS amount WHERE 0) g FULL JOIN case_notes USING (amount) WHERE patient_id = ?"), "computed.yaml: patients.note_total (sql) joins by column name (USING or NATURAL) in a statement that names case_notes, which encrypted.yaml encrypts"},
		{"expr subquery", "computed.yaml", encComputeExpr("ssn_last4", "(SELECT substr(ssn, -4) FROM (SELECT NULL AS ssn WHERE 0) g FULL JOIN patients USING (ssn) LIMIT 1)"), "patients.ssn_last4 (expr) joins by column name"},
	}
	for _, tc := range refused {
		t.Run("refused/"+tc.name, func(t *testing.T) {
			msg := ValidateOnWriteIn(dir, tc.file, tc.content)
			if !strings.Contains(msg, encComputeTag) || !strings.Contains(msg, tc.want) || !strings.Contains(msg, "write the join with ON") {
				t.Fatalf("%s write must be refused naming %q, got:\n%s", tc.file, tc.want, msg)
			}
		})
	}
	accepted := []struct{ name, file, content string }{
		{"aggregate using between plain tables", "app.yaml", encComputeAggregate("pairs", "SELECT COUNT(*) FROM contractors a JOIN contractors b USING (id)")},
		{"aggregate on with an encrypted table", "app.yaml", encComputeAggregate("paid", "SELECT SUM(c.salary) FROM contractors c JOIN patients p ON p.id = c.patient_id")},
		{"sql the word as a value", "computed.yaml", encComputeSQL("SELECT COUNT(*) FROM case_notes WHERE patient_id = ? AND title = 'natural'")},
	}
	for _, tc := range accepted {
		t.Run("accepted/"+tc.name, func(t *testing.T) {
			if msg := ValidateOnWriteIn(dir, tc.file, tc.content); msg != "" {
				t.Fatalf("%s write must be accepted, got:\n%s", tc.file, msg)
			}
		})
	}
}
