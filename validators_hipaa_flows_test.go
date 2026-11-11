//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// hipaaFlowCheckFindings is the compliance layer's part of a check report.
func hipaaFlowCheckFindings(rpt CheckReport) []CheckFinding {
	var out []CheckFinding
	for _, f := range rpt.Findings {
		if f.Source == "compliance" {
			out = append(out, f)
		}
	}
	return out
}

// The fixture holds one flow of each kind: a write with no audit row and a
// `SELECT *` row in a response are warned about, the same write with its own
// audit insert and a response of named columns are not. Nothing is refused.
func TestHIPAAFlowChecksWarnOnTheFixture(t *testing.T) {
	dir := configGapFixtureDir(t, "hipaa-flow-checks")
	rpt := RunSourceCheck(dir, "")
	for _, f := range rpt.Findings {
		if f.Severity == "error" {
			t.Errorf("the write gate refuses %s: %s", f.File, f.Message)
		}
	}
	got := map[string]CheckFinding{}
	for _, f := range hipaaFlowCheckFindings(rpt) {
		if f.Severity != "warning" {
			t.Errorf("%s: severity %q, want warning: %s", f.File, f.Severity, f.Message)
		}
		if _, twice := got[f.File]; twice {
			t.Errorf("%s is reported twice", f.File)
		}
		got[f.File] = f
	}
	want := map[string]struct{ docs, has string }{
		"flows/note-unaudited.yaml": {"audit.flow_writes", `job "note_unaudited" writes visit_notes with its own SQL and inserts no row into _benmore_audit_log`},
		"flows/patient-row.yaml":    {"encryption.flow_results", "responds with whole rows of step \"p\", whose query selects `*` from patients"},
	}
	for file, w := range want {
		f, ok := got[file]
		if !ok {
			t.Errorf("no compliance warning for %s; got %v", file, got)
			continue
		}
		if !strings.Contains(f.Message, w.has) {
			t.Errorf("%s: message %q does not contain %q", file, f.Message, w.has)
		}
		if f.Docs != w.docs {
			t.Errorf("%s: docs %q, want %q", file, f.Docs, w.docs)
		}
	}
	if msg := got["flows/patient-row.yaml"].Message; !strings.Contains(msg, "ssn") || !strings.Contains(msg, "ssn_blind") {
		t.Errorf("the whole-row warning does not name the encrypted column and its blind index: %q", msg)
	}
	for _, silent := range []string{"flows/sign-note.yaml", "flows/patient-card.yaml"} {
		if f, ok := got[silent]; ok {
			t.Errorf("%s is warned about: %s", silent, f.Message)
		}
	}
	if len(got) != len(want) {
		t.Errorf("%d compliance warnings, want %d: %v", len(got), len(want), got)
	}
}

// The same files without `compliance: hipaa` raise nothing.
func TestHIPAAFlowChecksAreSilentWithoutHIPAA(t *testing.T) {
	dir := configGapFixtureDir(t, "hipaa-flow-checks")
	appYAML, err := os.ReadFile(filepath.Join(dir, "app.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	plain := strings.Replace(string(appYAML), "compliance: hipaa\n", "", 1)
	if plain == string(appYAML) {
		t.Fatal("the fixture's app.yaml does not set compliance: hipaa")
	}
	writeTestFile(t, dir, "app.yaml", plain)
	if got := hipaaFlowCheckFindings(RunSourceCheck(dir, "")); len(got) != 0 {
		t.Fatalf("an app without compliance: hipaa is warned: %v", got)
	}
	if got := hipaaFlowCheckFindings(RunSourceCheck(dir, "flows/note-unaudited.yaml")); len(got) != 0 {
		t.Fatalf("a flow write of an app without compliance: hipaa is warned: %v", got)
	}
}

// The check that follows a write reports the written file's warning (and only
// that file's); a write of app.yaml, which is where hipaa is switched on,
// reports every flow's.
func TestHIPAAFlowChecksFollowAWrite(t *testing.T) {
	dir := configGapFixtureDir(t, "hipaa-flow-checks")
	files := func(written string) []string {
		var out []string
		for _, f := range hipaaFlowCheckFindings(RunSourceCheck(dir, written)) {
			out = append(out, f.File)
		}
		return out
	}
	if got := files("flows/note-unaudited.yaml"); len(got) != 1 || got[0] != "flows/note-unaudited.yaml" {
		t.Errorf("after writing flows/note-unaudited.yaml: %v", got)
	}
	if got := files("flows/patient-row.yaml"); len(got) != 1 || got[0] != "flows/patient-row.yaml" {
		t.Errorf("after writing flows/patient-row.yaml: %v", got)
	}
	if got := files("flows/sign-note.yaml"); len(got) != 0 {
		t.Errorf("after writing flows/sign-note.yaml: %v", got)
	}
	if got := files("app.yaml"); len(got) != 2 {
		t.Errorf("after writing app.yaml: %v, want both flows", got)
	}
	if got := files("static/app.tsx"); len(got) != 0 {
		t.Errorf("after writing a script: %v", got)
	}
}

func decodeHIPAAFlow(t *testing.T, src string) FlowFileGHA {
	t.Helper()
	var file FlowFileGHA
	if err := decodeConfigYAML([]byte(src), &file); err != nil {
		t.Fatalf("decode: %v\n%s", err, src)
	}
	return file
}

// A job is named when any of its SQL steps writes a table of the app and none
// inserts into _benmore_audit_log, wherever the steps sit.
func TestHIPAAUnauditedFlowWrites(t *testing.T) {
	const head = "on:\n  request: { method: POST, path: /x, auth: required }\njobs:\n  j:\n    steps:\n"
	const audit = "      - run: sql\n        with: { query: \"INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, user_email) VALUES ('update', 'notes', :id, :user_id, :user_email)\" }\n"
	cases := map[string]struct {
		steps  string
		tables string // "" when the job is not named
	}{
		"insert":                      {"      - run: sql\n        with: { query: \"INSERT INTO notes (body) VALUES (:b)\" }\n", "notes"},
		"shorthand update":            {"      - query: UPDATE notes SET body = :b WHERE id = :id\n", "notes"},
		"delete":                      {"      - query: DELETE FROM notes WHERE id = :id\n", "notes"},
		"quoted and qualified":        {"      - query: 'UPDATE main.\"Notes\" SET body = :b'\n", "Notes"},
		"cte write":                   {"      - query: WITH old AS (SELECT id FROM notes) DELETE FROM labs WHERE id IN (SELECT id FROM old)\n", "labs"},
		"sql_dynamic":                 {"      - run: sql_dynamic\n        with: { query: \"UPDATE notes SET body = 'x' WHERE id = 1\" }\n", "notes"},
		"two tables, two statements":  {"      - query: INSERT INTO notes (body) VALUES (:b); UPDATE labs SET n = n + 1\n", "notes, labs"},
		"same table twice":            {"      - query: INSERT INTO notes (body) VALUES (:b)\n      - query: UPDATE notes SET body = :b\n", "notes"},
		"in if":                       {"      - if: \"1 == 1\"\n        steps:\n          - query: UPDATE notes SET body = :b\n", "notes"},
		"in else":                     {"      - if: \"1 == 1\"\n        steps:\n          - query: SELECT 1\n        else:\n          - query: UPDATE notes SET body = :b\n", "notes"},
		"in for_each":                 {"      - id: rows\n        query: SELECT 1 AS id\n      - for_each: ${{ steps.rows.outputs.rows }}\n        as: r\n        steps:\n          - query: UPDATE notes SET body = :b\n", "notes"},
		"in on_error":                 {"      - query: SELECT 1\n        on_error:\n          - query: UPDATE notes SET failed = 1\n", "notes"},
		"with its audit insert":       {"      - query: UPDATE notes SET body = :b WHERE id = :id\n" + audit, ""},
		"audit insert first":          {audit + "      - query: UPDATE notes SET body = :b WHERE id = :id\n", ""},
		"audit insert in a branch":    {"      - query: UPDATE notes SET body = :b\n      - if: \"1 == 1\"\n        steps:\n" + strings.ReplaceAll(audit, "      ", "          "), ""},
		"audit row updated, not kept": {"      - query: UPDATE notes SET body = :b\n      - query: UPDATE _benmore_audit_log SET action = 'x'\n", "notes"},
		"read only":                   {"      - id: n\n        query: SELECT id, body FROM notes WHERE user_id = :user_id\n", ""},
		"a word that looks like one":  {"      - query: SELECT replace(body, 'update', 'delete') AS update_count FROM notes\n", ""},
		"framework table only":        {"      - query: UPDATE _benmore_users SET first_name = :n WHERE id = :user_id\n", ""},
		"audit row only":              {audit, ""},
		"not a sql step":              {"      - run: set\n        with: { query: \"UPDATE notes SET body = 1\" }\n", ""},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			problems := hipaaUnauditedWriteProblems(decodeHIPAAFlow(t, head+c.steps))
			if c.tables == "" {
				if len(problems) != 0 {
					t.Fatalf("named: %q\n%s", problems, c.steps)
				}
				return
			}
			if len(problems) != 1 || !strings.Contains(problems[0], `job "j" writes `+c.tables+" with its own SQL") {
				t.Fatalf("got %q, want one problem naming %q\n%s", problems, c.tables, c.steps)
			}
		})
	}

	// Each job is judged by its own steps.
	two := "on:\n  request: { method: POST, path: /x, auth: required }\njobs:\n  a:\n    steps:\n      - query: UPDATE notes SET body = :b\n  b:\n    steps:\n      - query: UPDATE labs SET n = 1\n" + audit
	problems := hipaaUnauditedWriteProblems(decodeHIPAAFlow(t, two))
	if len(problems) != 1 || !strings.Contains(problems[0], `job "a" writes notes`) {
		t.Fatalf("got %q, want only job a", problems)
	}
}

// A respond step is named when it returns a step's rows whole and that step's
// query selects `*` from a table with encrypted columns.
func TestHIPAAWholeRowFlowResponses(t *testing.T) {
	enc := parseEncryptedFieldsConfig([]byte("tables:\n  patients:\n    fields: [ssn, balance]\n    blind_index: [ssn]\n    unmask_roles: [admin]\n"), nil)
	if enc == nil {
		t.Fatal("no encrypted fields parsed")
	}
	const head = "on:\n  request: { method: GET, path: /x, auth: required }\njobs:\n  j:\n    steps:\n"
	query := func(q string) string {
		return "      - id: p\n        run: sql\n        with:\n          query: \"" + q + "\"\n"
	}
	respond := func(ref string) string {
		return "      - run: respond\n        with: { json: { patient: \"${{ " + ref + " }}\" } }\n"
	}
	cases := map[string]struct {
		steps string
		named bool
	}{
		"star, first":                 {query("SELECT * FROM patients WHERE id = :id") + respond("steps.p.outputs.first"), true},
		"star, rows":                  {query("SELECT * FROM patients") + respond("steps.p.outputs.rows"), true},
		"star, one row by index":      {query("SELECT * FROM patients") + respond("steps.p.outputs.rows[0]"), true},
		"star, whole outputs":         {query("SELECT * FROM patients") + respond("steps.p.outputs"), true},
		"star, with a pipe":           {query("SELECT * FROM patients") + respond("steps.p.outputs.rows | json"), true},
		"alias star":                  {query("SELECT p.* FROM patients p JOIN visits v ON v.patient_id = p.id") + respond("steps.p.outputs.first"), true},
		"alias star with AS":          {query("SELECT p.*, v.at FROM visits v JOIN patients AS p ON v.patient_id = p.id") + respond("steps.p.outputs.first"), true},
		"quoted table":                {query("SELECT * FROM main.[patients]") + respond("steps.p.outputs.first"), true},
		"star of a join":              {query("SELECT * FROM visits v JOIN patients p ON v.patient_id = p.id") + respond("steps.p.outputs.rows"), true},
		"second select of a union":    {query("SELECT id, name FROM archived UNION ALL SELECT * FROM patients") + respond("steps.p.outputs.rows"), true},
		"star through a cte":          {query("WITH mine AS (SELECT * FROM patients WHERE user_id = :user_id) SELECT * FROM mine") + respond("steps.p.outputs.first"), true},
		"returning star":              {query("UPDATE patients SET name = :n WHERE id = :id RETURNING *") + respond("steps.p.outputs.first"), true},
		"respond text body":           {query("SELECT * FROM patients") + "      - run: respond\n        with: { body: \"${{ steps.p.outputs.rows | json }}\" }\n", true},
		"respond inside a branch":     {query("SELECT * FROM patients") + "      - if: \"1 == 1\"\n        steps:\n          - run: respond\n            with: { json: \"${{ steps.p.outputs.first }}\" }\n", true},
		"one column of the row":       {query("SELECT * FROM patients") + respond("steps.p.outputs.first.name"), false},
		"one column, short form":      {query("SELECT * FROM patients") + respond("steps.p.outputs.name"), false},
		"one column by index":         {query("SELECT * FROM patients") + respond("steps.p.outputs.rows[0].name"), false},
		"named columns":               {query("SELECT id, name FROM patients") + respond("steps.p.outputs.first"), false},
		"count star":                  {query("SELECT COUNT(*) AS n FROM patients") + respond("steps.p.outputs.first"), false},
		"multiplication":              {query("SELECT id, visits * 2 AS doubled FROM patients") + respond("steps.p.outputs.first"), false},
		"star of the other table":     {query("SELECT v.* FROM visits v JOIN patients p ON v.patient_id = p.id") + respond("steps.p.outputs.first"), false},
		"star inside a subquery only": {query("SELECT name FROM (SELECT * FROM patients) AS t") + respond("steps.p.outputs.first"), false},
		"table without encryption":    {query("SELECT * FROM visits") + respond("steps.p.outputs.rows"), false},
		"returning named columns":     {query("UPDATE patients SET name = :n WHERE id = :id RETURNING id, name") + respond("steps.p.outputs.first"), false},
		"not returned":                {query("SELECT * FROM patients") + "      - run: respond\n        with: { json: { ok: true } }\n", false},
		"used by a later query only":  {query("SELECT * FROM patients") + "      - query: UPDATE visits SET seen = 1 WHERE patient_id = :pid\n        params: { pid: \"${{ steps.p.outputs.first.id }}\" }\n      - run: respond\n        with: { json: { ok: true } }\n", false},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			problems := hipaaWholeRowResponseProblems(decodeHIPAAFlow(t, head+c.steps), enc)
			if !c.named {
				if len(problems) != 0 {
					t.Fatalf("named: %q\n%s", problems, c.steps)
				}
				return
			}
			if len(problems) != 1 {
				t.Fatalf("got %q, want one problem\n%s", problems, c.steps)
			}
			for _, has := range []string{`job "j"`, `step "p"`, "from patients", "balance, ssn", "ssn_blind"} {
				if !strings.Contains(problems[0], has) {
					t.Errorf("%q does not contain %q", problems[0], has)
				}
			}
		})
	}
	if problems := hipaaWholeRowResponseProblems(decodeHIPAAFlow(t, head+query("SELECT * FROM patients")+respond("steps.p.outputs.first")), nil); len(problems) != 0 {
		t.Fatalf("an app with no encrypted fields is named: %q", problems)
	}
}

// hooks.yaml: a hook whose SQL writes a table is named unless a hook of the
// same event and table inserts the audit row.
func TestHIPAAUnauditedHookWrites(t *testing.T) {
	const appYAML = "site_name: hooks\ncompliance: hipaa\nauth:\n  identifier: email\n"
	const schema = "model Note {\n  id Int @id @default(autoincrement())\n  body String\n  seen Int @default(0)\n  userId Int @map(\"user_id\")\n  @@map(\"notes\")\n}\n\nmodel Tally {\n  id Int @id @default(autoincrement())\n  n Int @default(0)\n  @@map(\"tallies\")\n}\n"
	const hooks = `on_insert:
  notes:
    - sql: "UPDATE tallies SET n = n + 1"
before_update:
  notes:
    - sql: "SELECT 'locked' AS error WHERE {{seen}} = 1"
on_update:
  notes:
    - sql: "UPDATE tallies SET n = n + 1"
    - sql: "INSERT INTO _benmore_audit_log (action, table_name, row_id, user_id, user_email) VALUES ('update', 'tallies', '1', {{user_id}}, {{user_email}})"
on_delete:
  notes:
    - webhook: "https://example.com/hook"
`
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", appYAML)
	writeTestFile(t, dir, "schema.prisma", schema)
	writeTestFile(t, dir, "hooks.yaml", hooks)

	for _, written := range []string{"", "hooks.yaml", "app.yaml"} {
		rpt := RunSourceCheck(dir, written)
		for _, f := range rpt.Findings {
			if f.Severity == "error" {
				t.Fatalf("written %q: the write gate refuses %s: %s", written, f.File, f.Message)
			}
		}
		got := hipaaFlowCheckFindings(rpt)
		if len(got) != 1 {
			t.Fatalf("written %q: %d compliance warnings, want 1: %v", written, len(got), got)
		}
		f := got[0]
		if f.File != "hooks.yaml" || f.Severity != "warning" || f.Docs != "audit.flow_writes" ||
			!strings.Contains(f.Message, "hooks.yaml: on_insert hook on notes writes tallies with its own SQL and inserts no row into _benmore_audit_log") {
			t.Fatalf("written %q: %+v", written, f)
		}
	}

	writeTestFile(t, dir, "app.yaml", strings.Replace(appYAML, "compliance: hipaa\n", "", 1))
	if got := hipaaFlowCheckFindings(RunSourceCheck(dir, "")); len(got) != 0 {
		t.Fatalf("an app without compliance: hipaa is warned: %v", got)
	}
}

// The reference's example of a flow that writes its own audit row is the
// fixture's flow file, which the fixture's tests run.
func TestAuditFlowWritesExampleIsTheFixtureFlow(t *testing.T) {
	example, err := os.ReadFile(filepath.Join("docs", "reference", "audit", "flow_writes_example.txt"))
	if err != nil {
		t.Fatal(err)
	}
	flow, err := os.ReadFile(filepath.Join("testdata", "hipaa-flow-checks", "flows", "sign-note.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(example) != string(flow) {
		t.Fatalf("api(at:\"audit.flow_writes_example\") and testdata/hipaa-flow-checks/flows/sign-note.yaml differ:\n%s\n---\n%s", example, flow)
	}
	if problems := hipaaUnauditedWriteProblems(decodeHIPAAFlow(t, string(flow))); len(problems) != 0 {
		t.Fatalf("the documented example is itself warned about: %q", problems)
	}
}
