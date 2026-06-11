//go:build !cli

package main

import (
	"strings"
	"testing"
)

// rowScopeClause is the consolidated per-row scope policy. The critical
// property: act-as awareness - IsAdminBypass (a STEPPED-IN admin does NOT
// bypass) + EffectiveGroupID (the acted-as tenant). Pre-consolidation the
// per-site copies used IsAdmin + native group, an act-as escape.
func TestRowScopeClause_ActAsAware(t *testing.T) {
	app := &App{
		Group:  &GroupConfig{Key: "org_id"},
		Tables: []Table{{Name: "docs", Columns: []Column{{Name: "id"}, {Name: "org_id"}, {Name: "user_id"}}}},
	}
	ownerApp := &App{Tables: []Table{{Name: "notes", Columns: []Column{{Name: "id"}, {Name: "user_id"}}}}}

	admin := &Session{Role: "admin", UserID: 1, Email: "a@x"}
	steppedAdmin := &Session{Role: "admin", ActingAsGroup: "7", UserID: 1, Email: "a@x"}
	groupUser := &Session{Role: "user", GroupID: "5", UserID: 2, Email: "g@x"}
	ownerUser := &Session{Role: "user", UserID: 3, Email: "o@x"}

	// Admin NOT stepped in → bypass.
	if _, _, bypass := rowScopeClause(app, "docs", admin, "view"); !bypass {
		t.Error("admin (not stepped in) should bypass row scoping")
	}
	// Stepped-in admin → must NOT bypass; scopes to the ACTED-AS group (7).
	pred, args, bypass := rowScopeClause(app, "docs", steppedAdmin, "view")
	if bypass {
		t.Fatal("stepped-in admin must NOT bypass - that was the act-as escape")
	}
	if !strings.Contains(pred, "org_id = ?") || args[0] != "7" {
		t.Errorf("stepped-in admin should scope to acted-as group 7: pred=%q args=%v", pred, args)
	}
	// Group user → effective group = native GroupID (5).
	pred, args, _ = rowScopeClause(app, "docs", groupUser, "view")
	if !strings.Contains(pred, "org_id = ?") || args[0] != "5" {
		t.Errorf("group user should scope to group 5: pred=%q args=%v", pred, args)
	}
	// Owner-only table → user_id clause.
	pred, args, _ = rowScopeClause(ownerApp, "notes", ownerUser, "view")
	if !strings.Contains(pred, "user_id = ?") || args[0] != int64(3) {
		t.Errorf("owner user should scope to user_id 3: pred=%q args=%v", pred, args)
	}
	// nil session → no predicate, no bypass.
	if pred, _, bypass := rowScopeClause(app, "docs", nil, "view"); pred != "" || bypass {
		t.Errorf("nil session → empty pred + no bypass; got pred=%q bypass=%v", pred, bypass)
	}
	// ACL action threads through to aclFilter (edit → edit/admin grants).
	pred, _, _ = rowScopeClause(app, "docs", groupUser, "edit")
	if !strings.Contains(pred, "_benmore_permissions") {
		t.Errorf("scope clause should include the ACL grant subquery: %q", pred)
	}
}
