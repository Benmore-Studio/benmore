//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestQueryAggregateAliasesAreDerivedOutputs(t *testing.T) {
	app, mux := newTenantEncryptionFixture(t)
	reviewer, _ := tenantMember(t, app, "alias-reviewer@example.test", "user", 1, "company_admin")
	viewer, _ := tenantMember(t, app, "alias-viewer@example.test", "user", 1, "viewer")
	for _, sid := range []string{reviewer, viewer} {
		for _, alias := range []string{"private_note", "private_note_blind", "password_hash"} {
			w := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", sid, map[string]any{
				"table": "companies", "aggregates": []map[string]string{{"fn": "count", "as": alias}},
				"order_by": []map[string]string{{"col": alias}},
			})
			var body struct {
				Rows []map[string]any `json:"rows"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != 200 || len(body.Rows) != 1 || body.Rows[0][alias] != float64(2) {
				t.Errorf("row count alias %s: %d %s", alias, w.Code, w.Body.String())
			}
		}
	}
	// Source authorization remains attached to the real aggregate operand.
	for _, sid := range []string{reviewer, viewer} {
		w := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", sid, map[string]any{
			"table": "companies", "aggregates": []map[string]string{{"fn": "count", "col": "private_note", "as": "private_note"}},
		})
		if sid == viewer {
			if w.Code != 400 {
				t.Errorf("unauthorized encrypted count: %d %s", w.Code, w.Body.String())
			}
		} else if w.Code != 200 || !strings.Contains(w.Body.String(), `"private_note":1`) {
			t.Errorf("authorized tenant encrypted count: %d %s", w.Code, w.Body.String())
		}
	}
	// Ordinary projected source fields still have their normal field masks.
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", viewer, map[string]any{
		"table": "companies", "select": []string{"id", "private_note"},
	})
	if w.Code != 200 || strings.Contains(w.Body.String(), "acme-private-note") || !strings.Contains(w.Body.String(), "****") {
		t.Errorf("ordinary source masking: %d %s", w.Code, w.Body.String())
	}
}
