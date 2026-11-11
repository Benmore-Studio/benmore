//go:build !cli

package main

import (
	"context"
	"database/sql"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Rows in a workflow state that workflows.yaml no longer declares have no
// transition out, no timeout, and generic PATCH refuses the state column, so
// only raw SQL could move them (A-F13). Design: refuse the change, never
// migrate. A config-declared `migrate_states:` mapping would be a bulk UPDATE
// at load with no audit, hooks, versioning or webhooks (the guarantees a
// transition gives), so it was not added. Instead:
//   - the hosted write gate refuses a workflows.yaml that removes or renames a
//     state live rows still hold, counting them in the app's own process (data
//     channel op workflow_state_rows; workflow_state_guard.go), and
//   - `benmore check` (check_live) names rows already stuck in an undeclared
//     state, however they got there (flow SQL, an older file, an import).
// To retire a state: keep it declared with a transition to its replacement,
// move the rows through the transition API (audited, hooks fire), then remove
// it.

// workflowStuckState is one undeclared state value and its live row count.
type workflowStuckState struct {
	Workflow string `json:"workflow"`
	Table    string `json:"table"`
	Field    string `json:"field"`
	State    string `json:"state"`
	Rows     int64  `json:"rows"`
}

// workflowUndeclaredStates counts live rows (not soft-deleted) of each
// workflow in next whose non-NULL state is not one of next's states. With
// prior set, only states prior declares for the same table and field count:
// the states a change from prior to next would strand. A table that does not
// exist yet, and an encrypted state column (equality on ciphertext proves
// nothing), are skipped.
func workflowUndeclaredStates(ctx context.Context, db *sql.DB, next, prior *WorkflowConfig, enc *EncryptedFieldConfig) ([]workflowStuckState, error) {
	if next == nil || db == nil {
		return nil, nil
	}
	var out []workflowStuckState
	for _, name := range sortedWhenKeys(next.Workflows) {
		wf := next.Workflows[name]
		if wf.Table == "" || wf.Field == "" || workflowStateEncrypted(enc, wf.Table, wf.Field) {
			continue
		}
		declared := map[string]bool{}
		for _, s := range wf.States {
			declared[s] = true
		}
		var before map[string]bool
		if prior != nil {
			before = workflowStatesFor(prior, wf.Table, wf.Field)
			if before == nil {
				continue // a new workflow strands nothing it did not declare
			}
		}
		cols, err := GetTableColumns(db, wf.Table)
		if err != nil || len(cols) == 0 || !hasColumnFold(cols, wf.Field) {
			continue
		}
		q := fmt.Sprintf("SELECT CAST(%s AS TEXT), COUNT(*) FROM %s WHERE %s IS NOT NULL",
			quoteIdent(wf.Field), quoteIdent(wf.Table), quoteIdent(wf.Field))
		if hasColumnFold(cols, "deleted_at") {
			q += " AND deleted_at IS NULL"
		}
		rows, err := db.QueryContext(ctx, q+" GROUP BY 1 ORDER BY 1")
		if err != nil {
			return nil, fmt.Errorf("count %s.%s states: %w", wf.Table, wf.Field, err)
		}
		for rows.Next() {
			var state string
			var n int64
			if err := rows.Scan(&state, &n); err != nil {
				rows.Close()
				return nil, err
			}
			if declared[state] || (prior != nil && !before[state]) {
				continue
			}
			out = append(out, workflowStuckState{Workflow: name, Table: wf.Table, Field: wf.Field, State: state, Rows: n})
		}
		if err := rows.Close(); err != nil {
			return nil, err
		}
		if err := rows.Err(); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func workflowStatesFor(cfg *WorkflowConfig, table, field string) map[string]bool {
	for _, wf := range cfg.Workflows {
		if identIs(wf.Table, table) && identIs(wf.Field, field) {
			set := map[string]bool{}
			for _, s := range wf.States {
				set[s] = true
			}
			return set
		}
	}
	return nil
}

func hasColumnFold(cols []Column, name string) bool {
	for _, c := range cols {
		if sqliteIdentifierFold(c.Name) == sqliteIdentifierFold(name) {
			return true
		}
	}
	return false
}

func workflowStateEncrypted(enc *EncryptedFieldConfig, table, field string) bool {
	if enc == nil {
		return false
	}
	for t, defs := range enc.Fields {
		if !identIs(t, table) {
			continue
		}
		for _, d := range defs {
			if identIs(d.Column, field) {
				return true
			}
		}
	}
	return false
}

// workflowStuckSummary is the shared wording of a list of stuck states.
func workflowStuckSummary(stuck []workflowStuckState) string {
	parts := make([]string, 0, len(stuck))
	for _, s := range stuck {
		parts = append(parts, fmt.Sprintf("%s.%s = %q (%d rows, workflow %s)", s.Table, s.Field, s.State, s.Rows, s.Workflow))
	}
	sort.Strings(parts)
	return strings.Join(parts, "; ")
}

// workflowStuckFindings is the check_live layer: rows already in a state the
// app's workflows.yaml does not declare. It runs only in the serving process,
// on its own pool (db); elsewhere there is no database to count.
func workflowStuckFindings(dir string, db *sql.DB) []CheckFinding {
	if db == nil {
		return nil
	}
	data, err := readOptionalConfig(dir, "workflows.yaml")
	if err != nil || len(data) == 0 {
		return nil
	}
	cfg, err := parseWorkflowsYAML(data)
	if err != nil {
		return nil // the per-file check reports the parse error
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	stuck, err := workflowUndeclaredStates(ctx, db, cfg, nil, LoadEncryptedFieldsConfig(dir))
	if err != nil {
		return []CheckFinding{{Severity: "warning", Source: "workflow_states", Message: "workflow states could not be counted: " + err.Error()}}
	}
	if len(stuck) == 0 {
		return nil
	}
	return []CheckFinding{{
		Severity: "error",
		Source:   "workflow_states",
		Message:  "rows are in a workflow state workflows.yaml does not declare, so no transition or timeout can move them and PATCH refuses the column: " + workflowStuckSummary(stuck) + ". Declare the state again with a transition to where the rows belong and move them through the transition API.",
	}}
}

func init() {
	registerAppDataOp("workflow_state_rows", appDataOp{MinRole: "editor", Timeout: 30 * time.Second, Run: appDataWorkflowStateRows})
}

type appDataWorkflowStateArgs struct {
	// Content is the workflows.yaml about to be written.
	Content string `json:"content"`
}

// appDataWorkflowStateRows answers the write gate: the states the candidate
// workflows.yaml removes (relative to the workflows this process serves) that
// live rows still hold.
func appDataWorkflowStateRows(ctx context.Context, c *appDataOpCall) (any, error) {
	var args appDataWorkflowStateArgs
	if err := c.decodeArgs(&args); err != nil {
		return nil, err
	}
	if len(args.Content) > appDataQueryMaxSQLBytes {
		return nil, appDataFail("too_large", "workflows.yaml is too large")
	}
	next, err := parseWorkflowsYAML([]byte(args.Content))
	if err != nil {
		return nil, appDataFail("bad_request", "%s", err.Error())
	}
	prior := c.App.Workflows
	if prior == nil {
		return map[string]any{"stuck": []workflowStuckState{}}, nil
	}
	if next == nil {
		next = &WorkflowConfig{}
	}
	stuck, err := workflowUndeclaredStates(ctx, c.App.DB, next, prior, c.App.Encrypted)
	if err != nil {
		return nil, appDataQueryError(ctx, err)
	}
	if stuck == nil {
		stuck = []workflowStuckState{}
	}
	return map[string]any{"stuck": stuck}, nil
}
