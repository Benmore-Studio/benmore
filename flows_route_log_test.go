//go:build !cli

package main

import (
	"bytes"
	"log"
	"net/http"
	"strings"
	"testing"
)

// Every hot reload re-registers an app's flows. The per-route lines are
// printed once per process; later registrations print a one-line count, so a
// 400-flow app no longer writes ~430 journal lines per reload.
func TestRegisterFlowsListsRoutesOnceThenCounts(t *testing.T) {
	var buf bytes.Buffer
	oldOut, oldFlags := log.Writer(), log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() { log.SetOutput(oldOut); log.SetFlags(oldFlags) })

	app := &App{}
	flows := []Flow{
		{Name: "list_items", Trigger: FlowTrigger{Type: "http", Method: "GET", Path: "/api/items-list"}},
		{Name: "make_item", Trigger: FlowTrigger{Type: "http", Method: "POST", Path: "/api/items-make"}},
	}
	RegisterFlows(http.NewServeMux(), app, flows)
	first := buf.String()
	if !strings.Contains(first, "flow: GET /api/items-list → list_items") || !strings.Contains(first, "flow: POST /api/items-make → make_item") {
		t.Fatalf("first registration did not list the routes:\n%s", first)
	}

	buf.Reset()
	RegisterFlows(http.NewServeMux(), app, flows)
	second := buf.String()
	if strings.Contains(second, "flow: GET") || strings.Contains(second, "flow: POST") {
		t.Fatalf("reload listed every route again:\n%s", second)
	}
	if !strings.Contains(second, "flows: 2 HTTP routes and 0 cron flows registered") {
		t.Fatalf("reload did not log the route count:\n%s", second)
	}
}
