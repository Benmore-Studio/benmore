//go:build !cli && !windows

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"
)

// The admin panel's create and edit forms kept a short list of their own of
// columns to leave out (the primary key, user_id, the timestamps, a
// command-owned column). They offered an input for every other column, also
// the ones a create or an update never takes from a request: a computed
// column, a workflow's state column, the tenant key on an edit, deleted_at on
// an edit, a membership row's role. A browser submits every input, so each
// save sent values the write path dropped (X-Stripped-Fields) and the admin
// saw a field they had typed into come back unchanged.
//
// This submits each form the way a browser does, with every offered input
// filled in, and checks that the write stored every one of them.
func TestAdminFormsOfferOnlyWhatTheirSubmitStores(t *testing.T) {
	app, mux := schemaWritableFixture(t)
	admin := createCrudScopeSession(t, app, "boss@example.com", "admin", "", "")
	// The same admin stepped into tenant 7: a create then takes the tenant
	// from the session, never from the request.
	steppedIn := createCrudScopeSession(t, app, "support@example.com", "admin", "", "7")
	mustExec(t, app.DB, `INSERT INTO orders (id, user_id, title) VALUES (900, 1, 'parent order')`)

	seq := 0
	// probe is a value for column that no default, trigger or session stores.
	probe := func(table string, col Column) string {
		seq++
		if table == "order_items" && col.Name == "order_id" {
			return "900" // a foreign key names a row that exists
		}
		typ := strings.ToUpper(col.Type)
		switch {
		case strings.Contains(col.Name, "email"):
			return fmt.Sprintf("probe-%d@example.com", seq)
		case strings.Contains(typ, "INT"):
			return fmt.Sprint(4000 + seq)
		case strings.Contains(typ, "REAL"), strings.Contains(typ, "FLOA"), strings.Contains(typ, "DOUB"):
			return fmt.Sprintf("%d.5", 4000+seq)
		}
		return fmt.Sprintf("probe %d", seq)
	}
	stored := func(table, id, col string) string {
		t.Helper()
		var v sql.NullString
		if err := app.DB.QueryRow("SELECT CAST("+quoteIdent(col)+" AS TEXT) FROM "+quoteIdent(table)+" WHERE id = ?", id).Scan(&v); err != nil {
			t.Fatalf("read %s.%s of row %s: %v", table, col, id, err)
		}
		return v.String
	}
	// submit fills every input the form offers and posts it; it fails the
	// test unless the write stored each value and dropped none.
	submit := func(token, table, formPage, action string, cols []Column) (offered []string, id string) {
		t.Helper()
		fields := adminFormFields(t, formPage, action)
		sent := map[string]string{}
		for _, col := range cols {
			if _, ok := fields[col.Name]; ok {
				sent[col.Name] = probe(table, col)
				fields.Set(col.Name, sent[col.Name])
				offered = append(offered, col.Name)
			}
		}
		for name := range fields {
			if _, ok := sent[name]; !ok && name != "_csrf" {
				t.Errorf("%s: the form has an input %q that is no column of %s", action, name, table)
			}
		}
		rec := rawOwnedRequest(mux, http.MethodPost, action, token, "application/x-www-form-urlencoded", fields.Encode())
		if rec.Code != http.StatusOK {
			t.Fatalf("POST %s with the form's own fields %v: %d %s", action, offered, rec.Code, rec.Body.String())
		}
		if dropped := rec.Header().Get("X-Stripped-Fields"); dropped != "" {
			t.Errorf("POST %s: the form offers inputs its own submit drops: %s", action, dropped)
		}
		var row map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &row)
		id = action[strings.LastIndex(action, "/")+1:]
		if strings.HasSuffix(action, "/create") {
			if row["id"] == nil {
				t.Fatalf("POST %s: no id in %s", action, rec.Body.String())
			}
			id = fmt.Sprint(row["id"])
		}
		for name, want := range sent {
			got := stored(table, id, name)
			if strings.HasPrefix(got, "enc:") {
				continue // an encrypted column holds the ciphertext of what was sent
			}
			if got != want {
				t.Errorf("POST %s: the form offers %s, sent %q, and the row holds %q", action, name, want, got)
			}
		}
		sort.Strings(offered)
		return offered, id
	}

	cases := []struct {
		table  string
		create []string // inputs the create form offers a platform admin
		edit   []string // inputs the edit form offers
		shown  []string // not editable, still shown on the record page
	}{
		// line_total and item_count are computed, status is a workflow's
		// state, tax_id_blind a blind index; the rest are filled in by the
		// framework.
		{"orders", []string{"note", "qty", "tax_id", "title", "unit_price"}, []string{"note", "qty", "tax_id", "title", "unit_price"},
			[]string{"Line total", "Item count", "Status", "Deleted at", "User id", "Created at"}},
		{"order_items", []string{"label", "order_id"}, []string{"label", "order_id"}, []string{"User id"}},
		// The tenant key: a platform admin's create names it; no update moves a row to another tenant.
		{"projects", []string{"name", "org_id"}, []string{"name"}, []string{"Org id", "User id"}},
		// The membership table: the role column is never client-written, and
		// an update re-points neither the member nor the tenant.
		{"org_members", []string{"email", "org_id"}, nil, []string{"Org id", "Email", "Member role"}},
	}
	for _, c := range cases {
		cols, err := GetTableColumns(app.DB, c.table)
		if err != nil {
			t.Fatal(err)
		}
		createAction := "/_admin/api/" + c.table + "/create"
		offered, id := submit(admin, c.table, adminPage(t, mux, admin, "/_admin/"+c.table), createAction, cols)
		if fmt.Sprint(offered) != fmt.Sprint(c.create) {
			t.Errorf("%s create form offers %v, want %v", c.table, offered, c.create)
		}

		record := adminPage(t, mux, admin, "/_admin/"+c.table+"/"+id)
		for _, label := range c.shown {
			if !strings.Contains(record, ">"+label+"</label>") {
				t.Errorf("%s record page no longer shows %q", c.table, label)
			}
		}
		updateAction := "/_admin/api/" + c.table + "/update/" + id
		if len(c.edit) == 0 {
			// Nothing on this row is an update's to change: the page shows
			// it and has no form to save.
			if strings.Contains(record, `action="`+updateAction+`"`) || strings.Contains(record, "Save Changes") {
				t.Errorf("%s record page has a save form though no column of it can be edited", c.table)
			}
			continue
		}
		offered, _ = submit(admin, c.table, record, updateAction, cols)
		if fmt.Sprint(offered) != fmt.Sprint(c.edit) {
			t.Errorf("%s edit form offers %v, want %v", c.table, offered, c.edit)
		}
	}

	// Stepped into a tenant, the create form has no tenant input: the row
	// takes the tenant the admin is in.
	fields := adminFormFields(t, adminPage(t, mux, steppedIn, "/_admin/projects"), "/_admin/api/projects/create")
	if _, offered := fields["org_id"]; offered {
		t.Error("an admin stepped into a tenant is offered a tenant input on create; the create takes the session's tenant")
	}
	fields.Set("name", "made while stepped in")
	rec := rawOwnedRequest(mux, http.MethodPost, "/_admin/api/projects/create", steppedIn, "application/x-www-form-urlencoded", fields.Encode())
	if rec.Code != http.StatusOK || rec.Header().Get("X-Stripped-Fields") != "" {
		t.Fatalf("create while stepped in: %d stripped %q %s", rec.Code, rec.Header().Get("X-Stripped-Fields"), rec.Body.String())
	}
	var org string
	if err := app.DB.QueryRow(`SELECT CAST(org_id AS TEXT) FROM projects WHERE name = 'made while stepped in'`).Scan(&org); err != nil || org != "7" {
		t.Fatalf("row created while stepped into tenant 7 holds tenant %q (%v)", org, err)
	}

	// The gate is unchanged: a request that names such a column anyway is
	// answered as before, the value dropped and named.
	rec = rawOwnedRequest(mux, http.MethodPost, "/_admin/api/orders/create", admin, "application/x-www-form-urlencoded",
		url.Values{"title": {"typed by hand"}, "line_total": {"999"}, "status": {"approved"}}.Encode())
	if dropped := rec.Header().Get("X-Stripped-Fields"); rec.Code != http.StatusOK || !strings.Contains(dropped, "line_total") || !strings.Contains(dropped, "status") {
		t.Fatalf("a create naming a computed and a state column: %d, X-Stripped-Fields %q", rec.Code, dropped)
	}
}
