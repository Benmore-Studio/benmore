package main

import (
	"strings"
	"testing"
)

// a capability-only roles: block shuts auto-CRUD for
// everyone unless `table_scopes: access` hands table access to access:.
func TestRolesTableScopesFromAccess(t *testing.T) {
	tables := []Table{{Name: "notes"}, {Name: "leads"}}
	yaml := "roles:\n  user: {scopes: \"app:read\"}\n  manager: {scopes: \"notes:approve\"}\n"
	session := func(rc *RolesConfig, role, cred string) *Session {
		s := &Session{Scopes: rc.ResolveScopesForRoles([]string{role}), CredentialScopes: cred, accessTables: rc.accessTables}
		if cred != "" {
			s.Scopes = intersectScopes(cred, s.Scopes)
		}
		s.Permissions = strings.Fields(s.Scopes) // as applySessionRoleScopesWith does
		return s
	}

	plain := parseRolesConfig([]byte(yaml))
	bindRoleTableScopes(plain, tables)
	if checkScope(session(plain, "user", ""), "notes", "read") == nil {
		t.Fatal("without the opt-in roles must keep gating auto-CRUD")
	}

	rc := parseRolesConfig([]byte("table_scopes: access\n" + yaml))
	bindRoleTableScopes(rc, tables)
	user := session(rc, "user", "")
	for _, action := range []string{"read", "write", "delete"} {
		if err := checkScope(user, "notes", action); err != nil {
			t.Fatalf("auto-CRUD notes:%s refused: %v", action, err)
		}
	}
	if checkScope(user, "files", "read") == nil {
		t.Fatal("a non-schema resource must not be opened")
	}
	// Review of #407: perm: modes, flow permissions and connector tools read
	// session scopes, which must NOT gain table scopes.
	if HasPermission(user, "notes:approve") || scopesWithin(user.Scopes, "notes:write") || strings.Contains(user.Scopes, "notes") {
		t.Fatalf("table scopes leaked into session scopes: %q", user.Scopes)
	}
	if mgr := session(rc, "manager", ""); !HasPermission(mgr, "notes:approve") {
		t.Fatal("a role's own capability must still hold")
	}
	// An undeclared role keeps the deny sentinel for capabilities.
	if s := rc.ResolveScopesForRoles([]string{"ghost"}); s != "" {
		t.Fatalf("undeclared role resolved scopes: %q", s)
	}
	// A credential's own scopes still narrow auto-CRUD.
	token := session(rc, "user", "notes:read")
	if checkScope(token, "notes", "read") != nil || checkScope(token, "leads", "read") == nil || checkScope(token, "notes", "write") == nil {
		t.Fatal("token scopes must still narrow auto-CRUD")
	}
}

func TestRolesWithoutTableScopesWarning(t *testing.T) {
	models := []PrismaModel{{Name: "Note", Table: "notes"}}
	cases := map[string]string{
		"roles:\n  user: {scopes: \"app:read\"}\n":                       "names no table",
		"roles:\n  admin: {scopes: \"notes:read\"}\n":                    "does not declare `user`",
		"roles:\n  user: {scopes: \"notes:read\"}\n":                     "",
		"table_scopes: access\nroles:\n  user: {scopes: \"app:read\"}\n": "",
		"roles:\n  user: {scopes: \"*\"}\n":                              "",
	}
	for doc, want := range cases {
		got := rolesWithoutTableScopesWarning(parseRolesConfig([]byte(doc)), models)
		if (want == "") != (got == "") || !strings.Contains(got, want) {
			t.Errorf("%q: got %q, want %q", doc, got, want)
		}
	}
}
