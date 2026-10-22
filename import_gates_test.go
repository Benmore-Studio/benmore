//go:build !cli

package main

import (
	"strings"
	"testing"
)

// Mode A import strips the columns auto-CRUD create never accepts from a
// client (soft-delete marker, computed and workflow-state columns), keeps
// the tenant key (an admin create honours an explicit tenant), and owns the
// rows by the importing admin instead of leaving user_id NULL.
func TestImportColumnsAndOwnerMatchAutoCRUDCreate(t *testing.T) {
	app, cleanup := newImportTestApp(t)
	defer cleanup()
	mustExec(t, app.DB, `CREATE TABLE ledger (
		id INTEGER PRIMARY KEY AUTOINCREMENT,
		sku TEXT,
		org_id TEXT,
		deleted_at DATETIME,
		total INTEGER,
		status TEXT,
		USER_ID INTEGER
	)`)
	app.Group = &GroupConfig{Table: "members", Key: "org_id"}
	app.Computed = &ComputedFieldConfig{Fields: map[string]map[string]*ComputedField{
		"ledger": {"total": {Table: "ledger", Column: "total", Expr: "1"}},
	}}
	app.Workflows = &WorkflowConfig{Workflows: map[string]*Workflow{
		"ledger_flow": {Name: "ledger_flow", Table: "ledger", Field: "status", Initial: "draft"},
	}}

	cols, err := importableColumns(app.DB, "ledger", app)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, c := range cols {
		names = append(names, c.Name)
	}
	if got := strings.Join(names, ","); got != "sku,org_id" {
		t.Fatalf("importable columns = %s, want sku,org_id", got)
	}

	content := "sku,org_id\nA,acme\nB,acme\n"
	sum := stageString(t, app, "gate0001", content)
	sess := &importSession{
		ID: "gate0001", TableName: "ledger", Format: "csv",
		BytesTotal: int64(len(content)), SHA256: sum, CreatedBy: 7,
	}
	insertSession(t, app, sess)
	if err := runImport(app, sess); err != nil {
		t.Fatalf("runImport: %v", err)
	}
	var owned, tenanted int
	app.DB.QueryRow("SELECT COUNT(*) FROM ledger WHERE USER_ID = 7").Scan(&owned)
	app.DB.QueryRow("SELECT COUNT(*) FROM ledger WHERE org_id = 'acme'").Scan(&tenanted)
	if owned != 2 || tenanted != 2 {
		t.Fatalf("imported rows must carry the importer as owner and the file's tenant: owned=%d tenanted=%d", owned, tenanted)
	}

	// A file naming a stripped column is refused, as for user_id.
	bad := "sku,deleted_at\nC,2026-01-01\n"
	sum = stageString(t, app, "gate0002", bad)
	sess = &importSession{ID: "gate0002", TableName: "ledger", Format: "csv", BytesTotal: int64(len(bad)), SHA256: sum, CreatedBy: 7}
	insertSession(t, app, sess)
	if err := runImport(app, sess); err == nil {
		t.Fatal("a file setting deleted_at must be rejected")
	}
}
