//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

// `self` scopes rows by user_id and `group` by the tenant key. On a table
// that has neither column, rowScopeClause has nothing to scope by, so the
// mode silently meant "every signed-in user, every row" - including through
// access.default, where `all: self` reads like a safe default. Such a table
// now answers 404 for these modes (admins keep access).
func TestSelfOrGroupOnTableWithoutScopeColumnsFailsClosed(t *testing.T) {
	for _, mode := range []string{"self", "group"} {
		t.Run(mode, func(t *testing.T) {
			app, mux := newAccessScopeFixture(t,
				map[string]map[AccessOp]string{"default": {"all": mode}},
				`CREATE TABLE price_overrides (id INTEGER PRIMARY KEY AUTOINCREMENT, sku TEXT, price REAL)`,
				`INSERT INTO price_overrides (sku, price) VALUES ('widget', 10)`,
			)
			cols, err := GetTableColumns(app.DB, "price_overrides")
			if err != nil {
				t.Fatal(err)
			}
			app.Tables = append(app.Tables, Table{Name: "price_overrides", Columns: cols})
			mux = buildAppMux(app, true, "http://localhost")
			bob := createCrudScopeSession(t, app, "bob@example.com", "user", "org-b", "")

			if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/price_overrides", bob, nil); rec.Code == http.StatusOK && strings.Contains(rec.Body.String(), "widget") {
				t.Fatalf("%s on a table with no owner/tenant column read every row: %s", mode, rec.Body.String())
			}
			crudScopeRequest(t, mux, http.MethodPatch, "/api/price_overrides/1", bob, map[string]any{"price": 0.01})
			var price float64
			if err := app.DB.QueryRow("SELECT price FROM price_overrides WHERE id = 1").Scan(&price); err != nil || price != 10 {
				t.Fatalf("%s on a table with no owner/tenant column let any user update: price=%v err=%v", mode, price, err)
			}
			// The table's real scope columns still work: records has both.
			alice := createCrudScopeSession(t, app, "alice@example.com", "user", "org-a", "")
			assertStatus(t, mux, http.MethodPost, "/api/records", alice, map[string]any{"title": "mine"}, http.StatusOK)
		})
	}
}
