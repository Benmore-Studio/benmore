//go:build !cli

package main

import (
	"encoding/json"
	"testing"
)

// /api/_schema told a caller about tables and operations their RBAC scopes
// refuse: a role scoped to `notes:read` still got the `payroll` table with
// every column and relation, and `notes` came back writable. The other docs
// surfaces gate on access mode AND scope (SessionCanAccessTable); the schema
// descriptor now does too.
func TestRichSchemaHonorsScopes(t *testing.T) {
	app := authzApp(t)
	authzTable(t, app, "notes", "CREATE TABLE notes (id INTEGER PRIMARY KEY, user_id INTEGER, title TEXT)")
	authzTable(t, app, "payroll", "CREATE TABLE payroll (id INTEGER PRIMARY KEY, user_id INTEGER, salary INTEGER)")
	app.Access = accessFromYAML(t, "access:\n  notes: self\n  payroll: self\n")

	type desc struct {
		Ops    map[string]bool `json:"ops"`
		Fields []struct {
			Name     string `json:"name"`
			Writable bool   `json:"writable"`
		} `json:"fields"`
	}
	schemaFor := func(s *Session) map[string]desc {
		raw, _ := json.Marshal(generateRichSchema(app, s))
		var out struct {
			Tables map[string]desc `json:"tables"`
		}
		if err := json.Unmarshal(raw, &out); err != nil {
			t.Fatal(err)
		}
		return out.Tables
	}

	scoped := schemaFor(&Session{UserID: 2, Role: "viewer", Scopes: "notes:read"})
	if _, ok := scoped["payroll"]; ok {
		t.Errorf("a notes:read caller is told about payroll: %+v", scoped["payroll"])
	}
	notes, ok := scoped["notes"]
	if !ok || !notes.Ops["read"] || notes.Ops["write"] || notes.Ops["update"] || notes.Ops["delete"] {
		t.Errorf("notes ops for a notes:read caller = %+v (present %v), want read only", notes.Ops, ok)
	}
	for _, f := range notes.Fields {
		if f.Writable {
			t.Errorf("notes.%s writable for a read-only scope", f.Name)
		}
	}
	// Write implies read; delete is its own scope.
	if w := schemaFor(&Session{UserID: 2, Role: "viewer", Scopes: "notes:write"})["notes"]; !w.Ops["read"] || !w.Ops["write"] || !w.Ops["update"] || w.Ops["delete"] {
		t.Errorf("notes ops for notes:write = %+v", w.Ops)
	}

	// Unscoped sessions (cookie sessions without roles: scopes) are unchanged.
	full := schemaFor(&Session{UserID: 2, Role: "user"})
	for _, table := range []string{"notes", "payroll"} {
		d, ok := full[table]
		if !ok || !d.Ops["read"] || !d.Ops["write"] || !d.Ops["update"] || !d.Ops["delete"] {
			t.Errorf("unscoped caller lost %s: %+v", table, d.Ops)
		}
	}
	if all := schemaFor(&Session{UserID: 2, Role: "user", Scopes: "*"}); len(all) != 2 {
		t.Errorf("a * scope lost tables: %v", all)
	}
}
