//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

const encComputeSchema = `model Patient {
  id        Int     @id @default(autoincrement())
  fullName  String  @map("full_name")
  ssn       String?
  salary    Int?
  diagnosis String?
  status    String  @default("open")
  riskScore Int     @default(0) @map("risk_score")
  label     String?
  ssnLast4  String? @map("ssn_last4")
  hasSsn    Int?    @map("has_ssn")
  noteTotal Int?    @map("note_total")
  userId    Int?    @map("user_id")
  @@map("patients")
}

model CaseNote {
  id        Int     @id @default(autoincrement())
  patientId Int     @map("patient_id")
  amount    Int?
  title     String?
  @@map("case_notes")
}

model Contractor {
  id        Int  @id @default(autoincrement())
  patientId Int? @map("patient_id")
  salary    Int?
  @@map("contractors")
}
`

const encComputeEncrypted = "tables:\n  patients:\n    fields: [ssn, salary, diagnosis]\n    unmask_roles: [self]\n  case_notes:\n    fields: [amount]\n"

const encComputeApp = "auth:\n  signup: false\n"

const encComputeTag = "computed-encrypted-column"

func encComputeExpr(column, expr string) string {
	return "patients:\n  " + column + ":\n    expr: \"" + expr + "\"\n"
}

func encComputeSQL(query string) string {
	return "patients:\n  note_total:\n    sql: \"" + query + "\"\n    triggers:\n      - table: case_notes\n        on: [insert, update, delete]\n        fk: patient_id\n"
}

func encComputeAggregate(name, query string) string {
	return encComputeApp + "aggregates:\n  " + name + ":\n    sql: \"" + query + "\"\n    refresh: 1m\n"
}

// Round 2026-11-05 finding 6: a computed field or aggregate that reads an
// encrypted column computes on its ciphertext (substr(ssn,-4) gave hex,
// SUM(salary) a silent 0) while push and `benmore check` stayed clean. Which
// column a field reads is resolved by SQLite, so qualified names, aliases and
// joins count, a same-named column of an unencrypted table does not, and a
// null test or COUNT(col) - which work on ciphertext - stay allowed.
func TestComputedAndAggregatesOverEncryptedColumnsRefused(t *testing.T) {
	dir := writeApp(t, map[string]string{"schema.prisma": encComputeSchema, "encrypted.yaml": encComputeEncrypted, "app.yaml": encComputeApp})

	refused := []struct{ name, file, content, want string }{
		{"expr substr", "computed.yaml", encComputeExpr("ssn_last4", "substr(ssn,-4)"), "computed.yaml: patients.ssn_last4 (expr) reads patients.ssn, which encrypted.yaml encrypts."},
		{"expr table-qualified", "computed.yaml", encComputeExpr("ssn_last4", "substr(patients.ssn, -4)"), "patients.ssn_last4 (expr) reads patients.ssn"},
		{"expr NEW-qualified", "computed.yaml", encComputeExpr("ssn_last4", "substr(NEW.\\\"ssn\\\", -4)"), "patients.ssn_last4 (expr) reads patients.ssn"},
		{"expr length", "computed.yaml", encComputeExpr("ssn_last4", "length(ssn)"), "patients.ssn_last4 (expr) reads patients.ssn"},
		{"expr explicit decrypt", "computed.yaml", encComputeExpr("ssn_last4", "substr(benmore_decrypt(ssn),-4)"), "patients.ssn_last4 (expr) reads patients.ssn"},
		{"expr null test beside a value use", "computed.yaml", encComputeExpr("label", "CASE WHEN ssn IS NULL THEN 'none' ELSE diagnosis END"), "patients.label (expr) reads patients.diagnosis"},
		{"sql sum", "computed.yaml", encComputeSQL("SELECT SUM(amount) FROM case_notes WHERE patient_id = ?"), "computed.yaml: patients.note_total (sql) reads case_notes.amount, which encrypted.yaml encrypts."},
		{"sql alias", "computed.yaml", encComputeSQL("SELECT SUM(n.amount) FROM case_notes AS n WHERE n.patient_id = ?"), "patients.note_total (sql) reads case_notes.amount"},
		{"sql count distinct", "computed.yaml", encComputeSQL("SELECT COUNT(DISTINCT amount) FROM case_notes WHERE patient_id = ?"), "patients.note_total (sql) reads case_notes.amount"},
		{"aggregate sum", "app.yaml", encComputeAggregate("salary_sum", "SELECT SUM(salary) FROM patients"), "app.yaml: aggregate salary_sum reads patients.salary, which encrypted.yaml encrypts."},
		{"aggregate join", "app.yaml", encComputeAggregate("paid", "SELECT SUM(p.salary) FROM contractors c JOIN patients p ON p.id = c.patient_id"), "aggregate paid reads patients.salary"},
		{"aggregate subquery", "app.yaml", encComputeAggregate("dx", "SELECT COUNT(*) FROM (SELECT diagnosis FROM patients WHERE diagnosis = 'flu')"), "aggregate dx reads patients.diagnosis"},
	}
	for _, tc := range refused {
		t.Run("refused/"+tc.name, func(t *testing.T) {
			msg := ValidateOnWriteIn(dir, tc.file, tc.content)
			if !strings.Contains(msg, encComputeTag) || !strings.Contains(msg, tc.want) {
				t.Fatalf("%s write must be refused naming %q, got:\n%s", tc.file, tc.want, msg)
			}
			if !strings.Contains(msg, "its own plain column") {
				t.Fatalf("refusal must say what to do instead, got:\n%s", msg)
			}
		})
	}
	// The null test on ssn is not a read of ssn; diagnosis is.
	if msg := ValidateOnWriteIn(dir, "computed.yaml", refused[5].content); strings.Contains(msg, "reads patients.ssn") {
		t.Fatalf("a null test of ssn was reported as a read:\n%s", msg)
	}

	accepted := []struct{ name, file, content string }{
		{"expr plain columns", "computed.yaml", encComputeExpr("label", "upper(full_name)||' ['||status||']'")},
		{"expr is not null", "computed.yaml", encComputeExpr("has_ssn", "ssn IS NOT NULL")},
		{"expr qualified null test", "computed.yaml", encComputeExpr("has_ssn", "CASE WHEN patients.ssn IS NULL THEN 0 ELSE 1 END")},
		{"expr notnull", "computed.yaml", encComputeExpr("has_ssn", "ssn NOTNULL")},
		{"sql count col", "computed.yaml", encComputeSQL("SELECT COUNT(amount) FROM case_notes WHERE patient_id = ?")},
		{"sql null filter", "computed.yaml", encComputeSQL("SELECT COUNT(*) FROM case_notes WHERE patient_id = ? AND amount IS NOT NULL")},
		{"aggregate same name, unencrypted table", "app.yaml", encComputeAggregate("paid", "SELECT SUM(c.salary) FROM contractors c JOIN patients p ON p.id = c.patient_id")},
		{"aggregate plain column", "app.yaml", encComputeAggregate("max_risk_closed", "SELECT MAX(risk_score) FROM patients WHERE status = 'closed'")},
		{"aggregate null filter", "app.yaml", encComputeAggregate("with_ssn", "SELECT COUNT(*) FROM patients WHERE ssn IS NOT NULL")},
	}
	for _, tc := range accepted {
		t.Run("accepted/"+tc.name, func(t *testing.T) {
			if msg := ValidateOnWriteIn(dir, tc.file, tc.content); msg != "" {
				t.Fatalf("%s write must be accepted, got:\n%s", tc.file, msg)
			}
		})
	}
}

// A write that makes an existing computed field read an encrypted column is
// refused too (encrypted.yaml, or app.yaml's legacy encrypted: section),
// unless the same batch writes the computed file next.
func TestComputedOverEncryptedColumnRefusedFromEncryptionSide(t *testing.T) {
	computed := encComputeExpr("ssn_last4", "substr(ssn,-4)")
	dir := writeApp(t, map[string]string{"schema.prisma": encComputeSchema, "app.yaml": encComputeApp, "computed.yaml": computed,
		"encrypted.yaml": "tables:\n  patients:\n    fields: [diagnosis]\n"})

	msg := ValidateOnWriteIn(dir, "encrypted.yaml", encComputeEncrypted)
	if !strings.Contains(msg, "encrypted.yaml not written: with it, computed.yaml would compute on encrypted columns") ||
		!strings.Contains(msg, "computed.yaml: patients.ssn_last4 (expr) reads patients.ssn") {
		t.Fatalf("encrypted.yaml write must be refused naming the computed field, got:\n%s", msg)
	}
	if msg, _ := ValidateOnWriteInPending(dir, "encrypted.yaml", encComputeEncrypted, []string{"computed.yaml"}); msg != "" {
		t.Fatalf("a batch that writes computed.yaml next must be accepted, got:\n%s", msg)
	}
	// Encrypting a column no field reads is fine.
	if msg := ValidateOnWriteIn(dir, "encrypted.yaml", "tables:\n  patients:\n    fields: [diagnosis, salary]\n"); msg != "" {
		t.Fatalf("encrypting an unread column must be accepted, got:\n%s", msg)
	}

	legacy := writeApp(t, map[string]string{"schema.prisma": encComputeSchema, "app.yaml": encComputeApp, "computed.yaml": computed})
	msg = ValidateOnWriteIn(legacy, "app.yaml", encComputeApp+"encrypted:\n  patients: [ssn]\n")
	if !strings.Contains(msg, "app.yaml not written") || !strings.Contains(msg, "reads patients.ssn, which app.yaml (encrypted:) encrypts.") {
		t.Fatalf("app.yaml encrypted: write must be refused naming the computed field, got:\n%s", msg)
	}
}

// `benmore check` reports the problem as an error on the file that holds the
// field, and the app still loads and computes as before: the refusal is for
// writes and check only, never for a deployed app's start.
func TestComputedOverEncryptedColumnCheckErrorButAppLoads(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", encComputeSchema)
	writeTestFile(t, dir, "encrypted.yaml", encComputeEncrypted)
	writeTestFile(t, dir, "computed.yaml", encComputeExpr("ssn_last4", "substr(ssn,-4)"))
	writeTestFile(t, dir, "app.yaml", encComputeAggregate("salary_sum", "SELECT SUM(salary) FROM patients"))
	writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: "+strings.Repeat("cd", 32)+"\n")

	files := map[string]bool{}
	for _, f := range RunSourceCheck(dir, "").Findings {
		if f.Severity == "error" && strings.Contains(f.Message, encComputeTag) {
			files[f.File] = true
		}
	}
	if !files["computed.yaml"] || !files["app.yaml"] || len(files) != 2 {
		t.Fatalf("check must report the field on computed.yaml and the aggregate on app.yaml (and nothing on encrypted.yaml), got %v", files)
	}

	app, err := loadAppWithOptions(dir, appLoadOptions{startup: true})
	if err != nil {
		t.Fatalf("an app with such a field must still load: %v", err)
	}
	defer dbCryptoRegistry.Delete(canonicalDBPath(filepath.Join(dir, "data.db")))
	defer app.Shutdown()
	mustExec(t, app.DB, `INSERT INTO patients (full_name, ssn) VALUES ('A', '123-45-6789')`)
	var last4 sql.NullString
	if err := app.DB.QueryRow(`SELECT ssn_last4 FROM patients`).Scan(&last4); err != nil || !last4.Valid {
		t.Fatalf("the computed field still runs at load: %v %v", last4, err)
	}
}

// Round 2026-11-05 finding 8: an aggregate whose SQL yields NULL (MAX over no
// rows) failed every refresh ("converting NULL to string is unsupported"), was
// missing from /api/_aggregates, and one that had a value before kept serving
// that old value as current.
func TestAggregateNullResultStoredAndServed(t *testing.T) {
	app := ssrTestApp(t)
	EnsureAggregatesTable(app.DB)
	maxNote := AggregateConfig{Name: "max_note", SQL: "SELECT MAX(id) FROM notes"}
	firstTitle := AggregateConfig{Name: "first_title", SQL: "SELECT title FROM notes ORDER BY id LIMIT 1"}

	stored := func(name string) (sql.NullString, bool) {
		t.Helper()
		var v sql.NullString
		err := app.DB.QueryRow(`SELECT value FROM _benmore_aggregates WHERE name = ?`, name).Scan(&v)
		if err == sql.ErrNoRows {
			return v, false
		}
		if err != nil {
			t.Fatal(err)
		}
		return v, true
	}
	sess := seedAdminSession(t, app)
	mux := http.NewServeMux()
	RegisterAggregateRoutes(mux, app)
	served := func() map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, authedRequest(http.MethodGet, "/api/_aggregates", "", sess))
		if rec.Code != http.StatusOK {
			t.Fatalf("GET /api/_aggregates: %d %s", rec.Code, rec.Body.String())
		}
		var body struct {
			Aggregates []map[string]any `json:"aggregates"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
			t.Fatal(err)
		}
		out := map[string]any{}
		for _, a := range body.Aggregates {
			out[a["name"].(string)] = a["value"]
		}
		return out
	}

	// NULL from the start, and no row at all: stored as NULL, served as null.
	for _, c := range []AggregateConfig{maxNote, firstTitle} {
		if err := refreshAggregate(app.DB, c); err != nil {
			t.Fatalf("%s over no rows must refresh: %v", c.Name, err)
		}
		if v, ok := stored(c.Name); !ok || v.Valid {
			t.Fatalf("%s must be stored as NULL, got %v (row %v)", c.Name, v, ok)
		}
	}
	if got := served(); len(got) != 2 || got["max_note"] != nil || got["first_title"] != nil {
		t.Fatalf("NULL aggregates must be listed with value null, got %v", got)
	}

	crudScopeMustExec(t, app.DB, `INSERT INTO notes (user_id, title) VALUES (1, 'a'), (1, 'b'), (1, 'c')`)
	if err := refreshAggregate(app.DB, maxNote); err != nil {
		t.Fatal(err)
	}
	if got := served(); got["max_note"] != float64(3) {
		t.Fatalf("max_note after inserts: %v", got)
	}

	// The value turns NULL again: the old 3 must not stay current.
	crudScopeMustExec(t, app.DB, `DELETE FROM notes`)
	if err := refreshAggregate(app.DB, maxNote); err != nil {
		t.Fatalf("refresh to NULL: %v", err)
	}
	if v, _ := stored("max_note"); v.Valid {
		t.Fatalf("max_note must be NULL once no rows match, still stored %q", v.String)
	}
	if got := served(); got["max_note"] != nil {
		t.Fatalf("max_note must be served as null, got %v", got["max_note"])
	}
	values := LoadAggregateValues(app.DB)
	if v, ok := values["max_note"]; !ok || v != nil {
		t.Fatalf("template values must hold max_note as nil, got %v (present %v)", v, ok)
	}
	ctx := &RenderContext{Data: map[string]any{}, App: app}
	InjectAggregateData(ctx)
	out := ssrRender(t, app, &Page{Route: "/stats", RawHTML: `<p>n=[{{aggregate.max_note}}]</p>`}, nil, ctx.Data)
	if !strings.Contains(out, "n=[]") {
		t.Fatalf("a NULL aggregate must render empty, got: %s", out)
	}
}

// Apps created before NULL aggregates have value declared NOT NULL; the table
// is rebuilt with a nullable value, keeping the stored values.
func TestAggregatesTableUpgradeKeepsValues(t *testing.T) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	mustExec(t, db, `CREATE TABLE _benmore_aggregates (name TEXT PRIMARY KEY, value TEXT NOT NULL DEFAULT '', updated_at DATETIME DEFAULT CURRENT_TIMESTAMP)`)
	mustExec(t, db, `INSERT INTO _benmore_aggregates (name, value) VALUES ('kept', '7')`)
	EnsureAggregatesTable(db)
	EnsureAggregatesTable(db) // idempotent
	var notNull int
	if err := db.QueryRow(`SELECT "notnull" FROM pragma_table_info('_benmore_aggregates') WHERE name = 'value'`).Scan(&notNull); err != nil || notNull != 0 {
		t.Fatalf("value must be nullable after the upgrade: notnull=%d err=%v", notNull, err)
	}
	if got := LoadAggregateValues(db)["kept"]; got != int64(7) {
		t.Fatalf("stored value lost in the upgrade: %v", got)
	}
	mustExec(t, db, `CREATE TABLE t (x INTEGER)`)
	if err := refreshAggregate(db, AggregateConfig{Name: "none", SQL: "SELECT MAX(x) FROM t"}); err != nil {
		t.Fatalf("NULL refresh after the upgrade: %v", err)
	}
}

// The accepted cases above pass because their reads were compiled and found
// clean, not because the analysis gave up: the compiler resolves the reads,
// and the rewrite touches only null tests and COUNT(col).
func TestEncryptedComputeReadAnalysis(t *testing.T) {
	got := encryptedComputeAnalysisSQL(`x IS NOT NULL AND (a+b) IS NULL AND COUNT("t".y) > 0 AND COUNT(DISTINCT z) > 0 AND w NOTNULL AND 'v IS NULL' = s AND f(u) IS NULL`)
	want := `NULL IS NOT NULL AND (a+b) IS NULL AND COUNT(NULL) > 0 AND COUNT(DISTINCT z) > 0 AND NULL NOTNULL AND 'v IS NULL' = s AND f(u) IS NULL`
	if got != want {
		t.Fatalf("rewrite:\n got %s\nwant %s", got, want)
	}

	models, err := ParsePrismaSchema(encComputeSchema)
	if err != nil {
		t.Fatal(err)
	}
	c, err := newSQLReadCompiler(EmitSQL(models))
	if err != nil {
		t.Fatal(err)
	}
	defer c.close()
	reads := c.statementReads(encryptedComputeAnalysisSQL("SELECT SUM(c.salary) FROM contractors c JOIN patients p ON p.id = c.patient_id WHERE p.ssn IS NOT NULL"))
	if reads == nil || !reads.readColumn("contractors", "salary") || !reads.readColumn("patients", "id") || reads.readColumn("patients", "salary") || reads.readColumn("patients", "ssn") {
		t.Fatalf("join reads: %+v", reads)
	}
	reads = c.exprReads("patients", "has_ssn", encryptedComputeAnalysisSQL("CASE WHEN patients.ssn IS NULL THEN 0 ELSE length(full_name) END"))
	if reads == nil || !reads.readColumn("patients", "full_name") || reads.readColumn("patients", "ssn") {
		t.Fatalf("expr reads: %+v", reads)
	}
	// The analysis trigger is dropped again, so the next field compiles alone.
	if reads = c.exprReads("patients", "has_ssn", "status"); reads == nil || reads.readColumn("patients", "full_name") {
		t.Fatalf("second expr on the same column: %+v", reads)
	}
	if c.exprReads("patients", "label", "nope(") != nil || c.statementReads("SELECT missing FROM patients") != nil {
		t.Fatal("a field that does not compile must not be judged")
	}
}
