//go:build !cli

package main

import (
	"strings"
	"testing"
)

// Pins the SSR variable the docs name for materialized aggregates: servePage
// injects them as {{aggregate.<name>}} (not {{agg.<name>}}), app-wide values
// the author's SQL computed across every user and tenant.
func TestAggregateTemplateVariable(t *testing.T) {
	app := ssrTestApp(t)
	EnsureAggregatesTable(app.DB)
	crudScopeMustExec(t, app.DB, `INSERT INTO notes (user_id, title) VALUES (1, 'a'), (2, 'b'), (3, 'c')`)
	if err := refreshAggregate(app.DB, AggregateConfig{Name: "note_count", SQL: "SELECT COUNT(*) FROM notes"}); err != nil {
		t.Fatal(err)
	}
	ctx := &RenderContext{Data: map[string]any{}, App: app}
	InjectAggregateData(ctx)
	out := ssrRender(t, app, &Page{Route: "/stats", RawHTML: `<p>n={{aggregate.note_count}}</p><p>old={{agg.note_count}}</p>`}, nil, ctx.Data)
	if !strings.Contains(out, "n=3") {
		t.Fatalf("{{aggregate.note_count}} did not render: %s", out)
	}
	if strings.Contains(out, "old=3") {
		t.Fatalf("{{agg.*}} rendered; update the docs to name it: %s", out)
	}
}
