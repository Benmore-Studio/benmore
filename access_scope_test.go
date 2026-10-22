//go:build !cli

package main

import (
	"os"
	"path/filepath"
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
	groupUser := &Session{Role: "user", GroupID: "5", UserID: 2, Email: "g@x", Verified: true}
	ownerUser := &Session{Role: "user", UserID: 3, Email: "o@x", Verified: true}

	// Admin NOT stepped in → bypass.
	if _, _, bypass := rowScopeClause(app, "docs", admin, "view"); !bypass {
		t.Error("admin (not stepped in) should bypass row scoping")
	}
	// Stepped-in admin → must NOT bypass; scopes to the ACTED-AS group (7).
	pred, args, bypass := rowScopeClause(app, "docs", steppedAdmin, "view")
	if bypass {
		t.Fatal("stepped-in admin must NOT bypass - that was the act-as escape")
	}
	if !strings.Contains(pred, `"org_id" = ?`) || args[0] != "7" {
		t.Errorf("stepped-in admin should scope to acted-as group 7: pred=%q args=%v", pred, args)
	}
	// Group user → effective group = native GroupID (5).
	pred, args, _ = rowScopeClause(app, "docs", groupUser, "view")
	if !strings.Contains(pred, `"org_id" = ?`) || args[0] != "5" {
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
	pred, _, _ = rowScopeClause(ownerApp, "notes", ownerUser, "edit")
	if !strings.Contains(pred, "_benmore_permissions") || !strings.Contains(pred, "permission IN ('edit','admin')") {
		t.Errorf("scope clause should include the ACL grant subquery: %q", pred)
	}
	// Group mode never ORs a grant next to the tenant clause - that let a
	// share from another tenant through.
	pred, _, _ = rowScopeClause(app, "docs", groupUser, "edit")
	if strings.Contains(pred, "_benmore_permissions") {
		t.Errorf("group scope must not OR an unguarded ACL grant: %q", pred)
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
	user := &Session{Role: "user", UserID: 42, Email: "u@example.com", Verified: true}

	pred, args, bypass := rowScopeClause(app, "rooms", user, "delete")
	if bypass {
		t.Fatal("member-of delete must not bypass row scoping")
	}
	if !strings.Contains(pred, `EXISTS (SELECT 1 FROM main."room_members" WHERE main."room_members"."room_id" = main."rooms"."id" AND main."room_members"."member_id" = ?)`) {
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
	// Follow the CRUD source family so splitting a handler into its own file
	// cannot remove it from this security guard.
	files, err := filepath.Glob("crud*.go")
	if err != nil {
		t.Fatal(err)
	}
	var source strings.Builder
	for _, file := range files {
		if strings.HasSuffix(file, "_test.go") {
			continue
		}
		contents, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		source.Write(contents)
		source.WriteByte('\n')
	}
	if source.Len() == 0 {
		t.Fatal("no CRUD source files found")
	}
	src := source.String()
	expected := map[string]int{
		"handleList":   1,
		"handleRead":   1,
		"handleDelete": 1,
		"txUpdateMode": 1,
		"txDeleteRow":  1,
	}
	// The batch handlers route every row through the canonical one-row
	// pipelines (which carry the scope) instead of their own WHERE.
	for name, helper := range map[string]string{
		"handleBatchUpdate": "applyCanonicalUpdateTx(",
		"handleBatchDelete": "txDeleteRow(",
		"txDelete":          "txDeleteRow(",
		"txUpdate":          "txUpdateMode(",
		"txAuthorizedRow":   "txAuthorizedRowMode(",
	} {
		block := functionBlock(t, src, name)
		if got := strings.Count(block, helper); got != 1 {
			t.Fatalf("%s should delegate once to %s, got %d", name, helper, got)
		}
		if strings.Contains(block, "rowScopeClause(") || strings.Contains(block, "memberOfFor(app, table") || strings.Contains(block, "aclFilter(table,") {
			t.Fatalf("%s still contains a hand-rolled scope cascade", name)
		}
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

	// The update handler delegates to the canonical transaction pipeline. Keep
	// checking the real scoped read and write helpers instead of pinning scope
	// calls to the HTTP handler's implementation details.
	handler := functionBlock(t, src, "handleUpdate")
	if got := strings.Count(handler, "applyCanonicalUpdateTx("); got != 1 {
		t.Fatalf("handleUpdate should delegate once to applyCanonicalUpdateTx, got %d", got)
	}
	if strings.Contains(handler, "memberOfFor(app, table") || strings.Contains(handler, "aclFilter(table,") {
		t.Fatal("handleUpdate still contains a hand-rolled scope cascade")
	}
	update := functionBlock(t, src, "applyCanonicalUpdateTx")
	if got := strings.Count(update, "applyCanonicalUpdateTxContext("); got != 1 {
		t.Fatalf("applyCanonicalUpdateTx must delegate once to context wrapper, got %d", got)
	}
	ordinary := functionBlock(t, src, "applyCanonicalUpdateTxContext")
	if got := strings.Count(ordinary, "applyCanonicalUpdateTxContextMode("); got != 1 || !strings.Contains(ordinary, "expectedUpdatedAt, false, false)") {
		t.Fatalf("ordinary context wrapper must delegate once in ordinary mode, got %d", got)
	}
	private := functionBlock(t, src, "applyCanonicalUpdateTxContextPrivate")
	if got := strings.Count(private, "applyCanonicalUpdateTxContextMode("); got != 1 || !strings.Contains(private, "expectedUpdatedAt, true, false)") {
		t.Fatalf("private context wrapper must delegate once in private mode, got %d", got)
	}
	updateMode := functionBlock(t, src, "applyCanonicalUpdateTxContextMode")
	if got := strings.Count(updateMode, "txAuthorizedRowMode("); got != 2 {
		t.Fatalf("canonical update mode must authorize before-edit and restore before-view exactly twice, got %d", got)
	}
	if got := strings.Count(updateMode, "txAuthorizedRow("); got != 1 {
		t.Fatalf("canonical update mode must authorize the final live view exactly once, got %d", got)
	}
	// Restore may select a deleted row for its before-edit and before-view
	// guards only. The final response must still pass the ordinary live-row
	// view guard before its caller can commit the transaction.
	previous := -1
	for _, call := range []string{
		`txAuthorizedRowMode(q, app, table, id, actor, "edit", restore)`,
		`txAuthorizedRowMode(q, app, table, id, actor, "view", true)`,
		`txUpdateMode(q, app, table, id, values, actor, expectedUpdatedAt, restore)`,
		`txAuthorizedRow(q, app, table, id, actor, "view")`,
	} {
		index := strings.Index(updateMode, call)
		if index <= previous {
			t.Fatalf("canonical update must retain ordered edit, restore pre-view, mutation and live readback guards; missing or reordered %s", call)
		}
		previous = index
	}
	if got := strings.Count(updateMode, "txUpdateMode("); got != 1 {
		t.Fatalf("canonical update mode must call txUpdateMode exactly once, got %d", got)
	}
	for _, gate := range []string{`SessionCanAccessTable(app, table, OpUpdate, actor)`, `SessionCanAccessTable(app, table, OpRead, actor)`, `checkScope(actor, table, "read")`} {
		index := strings.Index(updateMode, gate)
		if index < 0 || index > strings.Index(updateMode, `txUpdateMode(`) {
			t.Fatalf("restore must retain the pre-mutation authorization gate %s", gate)
		}
	}
	if !strings.Contains(functionBlock(t, src, "txUpdate"), "expectedUpdatedAt, false)") || !strings.Contains(functionBlock(t, src, "txAuthorizedRow"), "session, action, false)") {
		t.Fatal("ordinary mutation/read wrappers must keep deleted-row restoration disabled")
	}
	restore := functionBlock(t, src, "handleRestore")
	if strings.Count(restore, "applyCanonicalUpdateTxContextMode(") != 1 || !strings.Contains(restore, `table, id, nil, "", false, true)`) {
		t.Fatal("restore handler must delegate once to non-private canonical restore mode")
	}
	for _, op := range []string{"OpRead", "OpUpdate"} {
		gate := "EnforceCRUDAccess(w, r, app, table, " + op + ", 0)"
		index := strings.Index(restore, gate)
		if index < 0 || index > strings.Index(restore, "BeginTx(") {
			t.Fatalf("restore handler must enforce %s before opening its transaction", op)
		}
	}
	for _, name := range []string{"txAuthorizedRowMode", "txUpdateMode"} {
		block := functionBlock(t, src, name)
		if got := strings.Count(block, "rowScopeClause("); got != 1 {
			t.Fatalf("%s should apply rowScopeClause once, got %d", name, got)
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
