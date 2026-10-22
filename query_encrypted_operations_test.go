//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestQueryEncryptedOperationsRefuseCiphertextResults(t *testing.T) {
	app, mux := newTenantEncryptionFixture(t)
	crudScopeMustExec(t, app.DB, "ALTER TABLE companies ADD COLUMN private_amount INTEGER")
	app.Encrypted.Fields["companies"] = append(app.Encrypted.Fields["companies"], EncryptedFieldDef{Column: "private_amount", Roles: []string{"company_admin"}})
	if err := InstallEncryptionTriggers(app.DB, app.Encrypted); err != nil {
		t.Fatal(err)
	}
	crudScopeMustExec(t, app.DB, "UPDATE companies SET private_amount=10101 WHERE id=1")
	for i := range app.Tables {
		if app.Tables[i].Name == "companies" {
			var err error
			app.Tables[i].Columns, err = GetTableColumns(app.DB, "companies")
			if err != nil {
				t.Fatal(err)
			}
		}
	}
	for _, actor := range []struct{ name, primary, membership string }{
		{"admin", "admin", "viewer"},
		{"tenant_reviewer", "user", "company_admin"},
	} {
		t.Run(actor.name, func(t *testing.T) {
			sid, _ := tenantMember(t, app, actor.name+"@example.test", actor.primary, 1, actor.membership)
			for _, spec := range []map[string]any{
				{"aggregates": []map[string]string{{"fn": "sum", "col": "private_amount", "as": "total"}}},
				{"aggregates": []map[string]string{{"fn": "avg", "col": "private_amount", "as": "total"}}},
				{"aggregates": []map[string]string{{"fn": "min", "col": "private_amount", "as": "total"}}},
				{"aggregates": []map[string]string{{"fn": "max", "col": "private_amount", "as": "total"}}},
				{"group_by": []string{"private_note"}},
				{"order_by": []map[string]string{{"col": "private_amount"}}},
				{"where": map[string]any{"private_note": "acme-private-note"}},
				{"where": map[string]any{"private_note": map[string]any{"in": []string{"acme-private-note"}}}},
				{"where": map[string]any{"private_amount": map[string]any{"gt": 0}}},
			} {
				spec["table"] = "companies"
				w := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", sid, spec)
				if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "encrypted column") {
					t.Errorf("unsupported encrypted operation returned %d %s for %v", w.Code, w.Body.String(), spec)
				}
			}
			// Counting non-NULL encrypted cells remains meaningful and retains
			// the existing field/tenant permission gate, including output aliases.
			for _, alias := range []string{"total", "count_amount"} {
				w := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", sid, map[string]any{"table": "companies", "aggregates": []map[string]string{{"fn": "count", "col": "private_amount", "as": alias}}, "order_by": []map[string]string{{"col": alias}}})
				var body struct {
					Rows []map[string]any `json:"rows"`
				}
				if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil || w.Code != http.StatusOK || len(body.Rows) != 1 || body.Rows[0][alias] != float64(1) {
					t.Errorf("encrypted cell count %d %s", w.Code, w.Body.String())
				}
			}
			// NULL tests do not compare ciphertext and ordinary projections
			// still decrypt under the caller's existing unmask policy.
			w := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", sid, map[string]any{"table": "companies", "select": []string{"id", "private_amount"}, "where": map[string]any{"private_amount": map[string]any{"ne": nil}}})
			if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"private_amount":10101`) {
				t.Errorf("non-NULL projection %d %s", w.Code, w.Body.String())
			}
		})
	}
}
