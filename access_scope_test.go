//go:build !cli

package main

import (
	"os"
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

func TestRowScopeClause_DeleteMemberOf(t *testing.T) {
	app := &App{
		Tables: []Table{
			{Name: "rooms", Columns: []Column{{Name: "id"}}},
			{Name: "room_members", Columns: []Column{{Name: "room_id"}, {Name: "member_id"}}},
		},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"rooms": {"delete": "member-of:room_members(room_id, member_id)"},
		}},
	}
	user := &Session{Role: "user", UserID: 42, Email: "u@example.com"}

	pred, args, bypass := rowScopeClause(app, "rooms", user, "delete")
	if bypass {
		t.Fatal("member-of delete must not bypass row scoping")
	}
	if !strings.Contains(pred, "EXISTS (SELECT 1 FROM room_members WHERE room_members.room_id = rooms.id AND room_members.member_id = ?)") {
		t.Fatalf("delete member-of should use membership predicate, got %q", pred)
	}
	if len(args) != 3 || args[0] != int64(42) || args[1] != "rooms" || args[2] != "u@example.com" {
		t.Fatalf("delete member-of args = %v, want [42 rooms u@example.com]", args)
	}
	if !strings.Contains(pred, "permission IN ('delete','admin')") {
		t.Fatalf("delete member-of should thread delete ACL semantics, got %q", pred)
	}
}

func TestCrudScopesUseRowScopeClause(t *testing.T) {
	srcBytes, err := os.ReadFile("crud.go")
	if err != nil {
		t.Fatal(err)
	}
	src := string(srcBytes)
	expected := map[string]int{
		"handleList":        1,
		"handleRead":        1,
		"handleUpdate":      2,
		"handleDelete":      1,
		"handleBatchUpdate": 1,
		"handleBatchDelete": 1,
		"txUpdate":          1,
		"txDelete":          1,
	}
	for name, want := range expected {
		block := functionBlock(t, src, name)
		if got := strings.Count(block, "rowScopeClause("); got != want {
			t.Fatalf("%s should call rowScopeClause %d time(s), got %d", name, want, got)
		}
		if strings.Contains(block, "memberOfFor(app, table") || strings.Contains(block, "aclFilter(table,") {
			t.Fatalf("%s still contains a hand-rolled scope cascade", name)
		}
	}
}

func functionBlock(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "func "+name+"(")
	if start < 0 {
		t.Fatalf("function %s not found", name)
	}
	open := strings.Index(src[start:], "{")
	if open < 0 {
		t.Fatalf("function %s has no opening brace", name)
	}
	i := start + open
	depth := 0
	for ; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[start : i+1]
			}
		}
	}
	t.Fatalf("function %s has no closing brace", name)
	return ""
}
