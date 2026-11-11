//go:build !cli

package main

import (
	"slices"
	"strings"
	"testing"
)

func TestSQLStepOutputNames(t *testing.T) {
	for query, want := range map[string]string{
		"SELECT member_role FROM company_members WHERE user_id = :user_id": "member_role",
		"SELECT COUNT(*) AS n FROM t":                                      "n",
		"select count(*) n, t.id from t":                                   "n,id",
		"SELECT DISTINCT name FROM t ORDER BY name":                        "name",
		"WITH x AS (SELECT 1 AS q) SELECT q, 'lit' AS label FROM x":        "q,label",
		"SELECT (SELECT COUNT(*) FROM u WHERE u.a = t.a) AS c FROM t":      "c",
		"SELECT CASE WHEN a THEN 1 ELSE 0 END AS flag FROM t":              "flag",
		"SELECT json_object('a', 1) obj":                                   "obj",
		`SELECT "Weird Name" FROM t`:                                       "Weird Name",
		"INSERT INTO t (a) VALUES (:a)":                                    "rows_affected",
		"UPDATE t SET a = 1 WHERE id = :id":                                "rows_affected",
		"INSERT INTO t (a) VALUES (:a) RETURNING id, a":                    "id,a",
		"SELECT * FROM t":                                                  "",
		"SELECT t.* FROM t":                                                "",
		"SELECT a + b FROM t":                                              "",
		"SELECT CASE WHEN a THEN 1 ELSE 0 END FROM t":                      "",
		"UPDATE t SET a = 1 RETURNING *":                                   "",
		"SELECT 1; SELECT 2":                                               "",
	} {
		names, ok := sqlStepOutputNames(FlowStepGHA{Run: "sql", With: map[string]any{"query": query}})
		got := strings.Join(names, ",")
		if !ok {
			got = ""
		}
		if got != want {
			t.Errorf("%q = %q (ok=%v), want %q", query, strings.Join(names, ","), ok, want)
		}
	}
	if _, ok := sqlStepOutputNames(FlowStepGHA{Run: "sql_dynamic", With: map[string]any{"query": "SELECT a FROM t"}}); ok {
		t.Error("sql_dynamic text is rendered at run time; it must stay unchecked")
	}
}

// The owner check of a probe app's invite flow read an output its query did
// not return, so it never matched and every member could invite.
func TestWriteGateRefusesGuardOnMissingStepOutput(t *testing.T) {
	flow := func(selectList, ref string) string {
		return `on:
  request:
    method: POST
    path: /api/invite
    auth: required
jobs:
  main:
    steps:
      - id: me
        run: sql
        with:
          query: "SELECT ` + selectList + ` FROM company_members WHERE user_id = :user_id AND member_role = 'owner'"
      - if: "` + ref + `"
        run: respond
        with:
          status: 403
          body: '{"error":"owners only"}'
      - run: respond
        with:
          body: '{"status":"ok"}'
`
	}
	dir := t.TempDir()
	msg := ValidateOnWriteIn(dir, "flows/invite.yaml", flow("member_role", "${{ steps.me.outputs.count }} == 0"))
	if !strings.Contains(msg, "steps.me.outputs.count") || !strings.Contains(msg, "member_role") || !strings.Contains(msg, "does not guard") {
		t.Fatalf("guard on a missing output = %q", msg)
	}
	// The loader keeps loading such a flow: refusing it would take a live
	// app down at its next restart.
	if flows, err := parseGHAFlowFile("flows/invite.yaml", []byte(flow("member_role", "${{ steps.me.outputs.count }} == 0"))); err != nil || len(flows) != 1 {
		t.Fatalf("loader refused a flow the write gate only rejects: %v", err)
	}
	for _, ok := range []string{
		flow("COUNT(*) AS n", "${{ steps.me.outputs.n }} == 0"),
		flow("member_role", "${{ !steps.me.outputs.rows }}"),
		flow("member_role", "${{ steps.me.outputs.first.member_role }} != 'owner'"),
		flow("*", "${{ steps.me.outputs.count }} == 0"), // columns unknown: unchecked
	} {
		if msg := ValidateOnWriteIn(dir, "flows/invite.yaml", ok); strings.Contains(msg, "outputs.") && strings.Contains(msg, "does not guard") {
			t.Errorf("valid reference refused: %s", msg)
		}
	}
	// Outside a guard the same mistake is a warning.
	writeTestFile(t, dir, "flows/echo.yaml", `on:
  request:
    method: GET
    path: /api/echo
jobs:
  main:
    steps:
      - id: add
        run: sql
        with:
          query: "INSERT INTO notes (title) VALUES ('x')"
      - run: respond
        with:
          body: '{"id": "${{ steps.add.outputs.id }}"}'
`)
	warnings := stepOutputRefWarnings(dir, "flows/echo.yaml")
	if len(warnings) != 1 || !strings.Contains(warnings[0].Message, "rows_affected") {
		t.Fatalf("non-guard reference warnings = %+v", warnings)
	}
	if !slices.ContainsFunc(warnings, func(f CheckFinding) bool { return f.Severity == "warning" }) {
		t.Fatal("a non-guard reference must stay a warning")
	}
}
