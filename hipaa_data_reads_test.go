//go:build !cli

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

// H7: a compliance: hipaa app answers a workforce row read (query_db, sql,
// the SQL console) only to its owner with a reason, and audits it before any
// row leaves. Data-channel operations are not reachable from `benmore test`.
func TestHIPAAWorkforceReadsAreOwnerOnlyAndAudited(t *testing.T) {
	app := appDataTestApp(t)
	run := func(actor appDataActor, reason string) (any, error) {
		args, _ := json.Marshal(appDataQueryArgs{SQL: "SELECT title FROM notes", Gate: "console", Reason: reason})
		return appDataQuery(context.Background(), &appDataOpCall{App: app, Actor: actor, Args: args, RequestID: "r1"})
	}
	owner := appDataActor{PlatformUserID: 9, Email: "owner@test.com", Role: "owner", Surface: "dashboard"}

	// Not hipaa: unchanged (an editor reads, no reason, no read audit row).
	if _, err := run(appDataTestEditor, ""); err != nil {
		t.Fatalf("non-hipaa editor read: %v", err)
	}
	app.Design = &DesignConfig{Compliance: complianceHIPAA}
	var de *appDataError
	if _, err := run(appDataTestEditor, "debugging"); !errors.As(err, &de) || de.Code != "forbidden" {
		t.Fatalf("hipaa editor read: %v", err)
	}
	if _, err := run(owner, "  "); !errors.As(err, &de) || de.Code != "bad_request" {
		t.Fatalf("hipaa owner read without a reason: %v", err)
	}
	out, err := run(owner, "ticket 42: wrong totals")
	if err != nil {
		t.Fatalf("hipaa owner read with a reason: %v", err)
	}
	if res, _ := out.(appDataRowsResult); len(res.Rows) != 3 {
		t.Fatalf("rows = %+v", out)
	}
	var action, values string
	if err := app.DB.QueryRow(`SELECT action, new_values FROM _benmore_audit_log WHERE action = 'data_sql_read'`).Scan(&action, &values); err != nil {
		t.Fatalf("audit row: %v", err)
	}
	if !strings.Contains(values, "ticket 42") || !strings.Contains(values, "statement_sha256") || strings.Contains(values, "SELECT title") || !strings.Contains(values, `"row_count":3`) {
		t.Fatalf("audit values = %s", values)
	}
	// No audit row, no rows.
	mustExec(t, app.DB, `CREATE TRIGGER audit_down BEFORE INSERT ON _benmore_audit_log BEGIN SELECT RAISE(ABORT, 'down'); END`)
	if out, err := run(owner, "again"); err == nil {
		t.Fatalf("read answered without its audit row: %+v", out)
	}
	// table_rows has no reason to carry, so it is closed under hipaa.
	args, _ := json.Marshal(appDataTableRowsArgs{Table: "notes"})
	if _, err := appDataTableRows(context.Background(), &appDataOpCall{App: app, Actor: owner, Args: args}); !errors.As(err, &de) || de.Code != "forbidden" {
		t.Fatalf("table_rows under hipaa: %v", err)
	}
}

// A-F13: the write gate counts rows a workflows.yaml change would strand, and
// check_live names rows already in an undeclared state.
func TestWorkflowStateRemovalCountsStrandedRows(t *testing.T) {
	app := appDataTestApp(t)
	mustExec(t, app.DB, `CREATE TABLE orders(id INTEGER PRIMARY KEY, status TEXT, deleted_at TEXT);
		INSERT INTO orders VALUES(1,'draft',NULL),(2,'review',NULL),(3,'review',NULL),(4,'legacy',NULL),(5,'gone','2026-01-01');`)
	current, err := parseWorkflowsYAML([]byte("order:\n  table: orders\n  field: status\n  states: [draft, review, done, gone]\n  transitions:\n    draft: {review: {}}\n    review: {done: {}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	app.Workflows = current
	stranded := func(content string) []workflowStuckState {
		t.Helper()
		args, _ := json.Marshal(appDataWorkflowStateArgs{Content: content})
		out, err := appDataWorkflowStateRows(context.Background(), &appDataOpCall{App: app, Actor: appDataTestEditor, Args: args})
		if err != nil {
			t.Fatal(err)
		}
		return out.(map[string]any)["stuck"].([]workflowStuckState)
	}
	// Renaming review -> in_review strands the two live review rows; the
	// pre-existing "legacy" row and the soft-deleted "gone" row are not this
	// write's doing.
	got := stranded("order:\n  table: orders\n  field: status\n  states: [draft, in_review, done]\n  transitions:\n    draft: {in_review: {}}\n    in_review: {done: {}}\n")
	if len(got) != 1 || got[0].State != "review" || got[0].Rows != 2 {
		t.Fatalf("stranded = %+v", got)
	}
	// Removing an unused state, or the whole workflow, strands nothing.
	if got := stranded("order:\n  table: orders\n  field: status\n  states: [draft, review]\n  transitions:\n    draft: {review: {}}\n"); len(got) != 0 {
		t.Fatalf("unused state removal refused: %+v", got)
	}
	if got := stranded("other:\n  table: notes\n  field: title\n  states: [first, second, third]\n"); len(got) != 0 {
		t.Fatalf("workflow removal refused: %+v", got)
	}

	// check_live: every live row in an undeclared state, however it got there.
	writeTestFile(t, app.Dir, "workflows.yaml", "order:\n  table: orders\n  field: status\n  states: [draft, review, done]\n  transitions:\n    draft: {review: {}}\n")
	findings := workflowStuckFindings(app.Dir, app.DB)
	if len(findings) != 1 || findings[0].Severity != "error" || !strings.Contains(findings[0].Message, `"legacy" (1 rows`) || strings.Contains(findings[0].Message, `"gone"`) {
		t.Fatalf("findings = %+v", findings)
	}
}
