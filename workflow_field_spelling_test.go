package main

import "testing"

// A workflows.yaml table/field with surrounding whitespace passed the
// identifier check (which trims) but was stored as written, so every exact
// comparison against the column missed and the create/PATCH guard opened.
func TestWorkflowFieldWithWhitespaceIsTrimmed(t *testing.T) {
	cfg, err := parseWorkflowsYAML([]byte("order:\n  table: \" orders \"\n  field: \"status \"\n  initial: draft\n  transitions:\n    draft:\n      approve: { to: approved }\n"))
	if err != nil {
		t.Fatal(err)
	}
	wf := cfg.Workflows["order"]
	if wf == nil || wf.Table != "orders" || wf.Field != "status" {
		t.Fatalf("workflow = %+v, want table orders field status", wf)
	}
}

// Connector route validation registers transition routes under the
// workflow's table; it must use the schema's spelling, as the runtime does.
func TestWorkflowTableNamesCanonicalizedForRouteValidation(t *testing.T) {
	cfg := &WorkflowConfig{Workflows: map[string]*Workflow{"o": {Table: "Orders", Field: "status"}, "nil": nil}}
	canonicalizeWorkflowTableNames(cfg, []string{"customers", "orders"})
	if got := cfg.Workflows["o"]; got.Table != "orders" || got.ConfiguredTable != "Orders" {
		t.Fatalf("table = %q configured %q, want orders / Orders", got.Table, got.ConfiguredTable)
	}
}
