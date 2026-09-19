//go:build !cli

package main

import (
	"strings"
	"testing"
)

// member-of:<table>(<join>,<user>) - membership-scoped access (v2.7.164).
// The critical properties: the EXISTS predicate replaces owner/group
// scoping for the governed op, joins on the table's own column when
// present (child) or id (parent), never widens across tenants (group
// clause AND'd when the table is group-keyed), and malformed
// declarations fail closed.

func memberOfTestApp() *App {
	return &App{
		Tables: []Table{
			{Name: "rooms", Columns: []Column{{Name: "id"}, {Name: "name"}}},
			{Name: "messages", Columns: []Column{{Name: "id"}, {Name: "room_id"}, {Name: "body"}, {Name: "user_id"}}},
			{Name: "tenant_msgs", Columns: []Column{{Name: "id"}, {Name: "room_id"}, {Name: "company_id"}}},
			{Name: "room_members", Columns: []Column{{Name: "id"}, {Name: "room_id"}, {Name: "member_id"}}},
		},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"rooms":       {"all": "member-of:room_members(room_id, member_id)"},
			"messages":    {"all": "member-of:room_members(room_id, member_id)"},
			"tenant_msgs": {"all": "member-of:room_members(room_id, member_id)"},
		}},
	}
}

func TestParseMemberOf(t *testing.T) {
	r := parseMemberOf("member-of:room_members(room_id, member_id)")
	if r == nil || r.Table != "room_members" || r.JoinCol != "room_id" || r.UserCol != "member_id" {
		t.Fatalf("well-formed rule should parse: %+v", r)
	}
	for _, bad := range []string{
		"member-of:",
		"member-of:room_members",
		"member-of:room_members()",
		"member-of:room_members(room_id)",
		"member-of:room_members(room_id, member_id); DROP TABLE x",
		"member-of:room members(room_id, member_id)",
		"member-of:room_members(room-id, member_id)",
	} {
		if parseMemberOf(bad) != nil {
			t.Errorf("malformed rule must not parse: %q", bad)
		}
	}
}

func TestAllowed_MemberOf(t *testing.T) {
	app := memberOfTestApp()
	user := &Session{Role: "user", UserID: 2, Email: "u@x"}
	if app.Access.Allowed("member-of:room_members(room_id, member_id)", nil, 0) {
		t.Error("member-of must require authentication")
	}
	if !app.Access.Allowed("member-of:room_members(room_id, member_id)", user, 0) {
		t.Error("member-of should pass the coarse gate for any authed user (EXISTS filters rows)")
	}
	// Malformed declaration fails closed - a typo halts traffic rather
	// than widening the policy.
	if app.Access.Allowed("member-of:room_members(room_id", user, 0) {
		t.Error("malformed member-of must fail closed")
	}
}

func TestRowScopeClause_MemberOf(t *testing.T) {
	app := memberOfTestApp()
	user := &Session{Role: "user", UserID: 2, Email: "u@x"}

	// Child table: joins on its own room_id column.
	pred, args, bypass := rowScopeClause(app, "messages", user, "view")
	if bypass {
		t.Fatal("member-of user must not bypass")
	}
	if !strings.Contains(pred, "EXISTS (SELECT 1 FROM room_members WHERE room_members.room_id = messages.room_id AND room_members.member_id = ?)") {
		t.Errorf("child table should join on its room_id column: %q", pred)
	}
	if len(args) == 0 || args[0] != int64(2) {
		t.Errorf("member arg should be the session user id: %v", args)
	}
	// member-of REPLACES owner scoping - messages has user_id but the
	// predicate must NOT restrict to the caller's own rows.
	if strings.Contains(pred, "user_id = ?") {
		t.Errorf("member-of must replace owner scoping, not compose with it: %q", pred)
	}

	// Parent table: no room_id column → joins on id.
	pred, _, _ = rowScopeClause(app, "rooms", user, "view")
	if !strings.Contains(pred, "room_members.room_id = rooms.id") {
		t.Errorf("parent table should join on id: %q", pred)
	}

	// Admin (not stepped in) still bypasses.
	admin := &Session{Role: "admin", UserID: 1, Email: "a@x"}
	if _, _, bypass := rowScopeClause(app, "messages", admin, "view"); !bypass {
		t.Error("admin (not stepped in) should bypass member-of scoping")
	}
}

func TestMemberOf_TenantClauseANDed(t *testing.T) {
	app := memberOfTestApp()
	app.Group = &GroupConfig{Table: "company_members", Key: "company_id", UserField: "email"}
	groupUser := &Session{Role: "user", UserID: 2, Email: "u@x", GroupID: "5"}

	pred, args, _ := rowScopeClause(app, "tenant_msgs", groupUser, "view")
	if !strings.Contains(pred, "company_id = ? AND") {
		t.Errorf("group-keyed member-of table must AND the tenant clause (membership widens within a tenant, never across): %q", pred)
	}
	if args[0] != "5" || args[1] != int64(2) {
		t.Errorf("args should be [groupID, userID, ...]: %v", args)
	}

	// Stepped-in admin scopes to the ACTED-AS tenant.
	stepped := &Session{Role: "admin", ActingAsGroup: "7", UserID: 1, Email: "a@x"}
	pred, args, bypass := rowScopeClause(app, "tenant_msgs", stepped, "view")
	if bypass {
		t.Fatal("stepped-in admin must not bypass member-of scoping")
	}
	if !strings.Contains(pred, "company_id = ?") || args[0] != "7" {
		t.Errorf("stepped-in admin should scope to acted-as tenant 7: pred=%q args=%v", pred, args)
	}
}

func TestMatchWSRoomPattern(t *testing.T) {
	cases := []struct {
		pattern, room, val string
		ok                 bool
	}{
		{"room-:id", "room-42", "42", true},
		{"room-:id", "room-", "", false},
		{"room-:id", "lobby", "", false},
		{"teamup-room-:id", "teamup-room-a1b2", "a1b2", true},
		{"chat/:slug/feed", "chat/general/feed", "general", true},
		{"chat/:slug/feed", "chat/general", "", false},
		{"lobby", "lobby", "", true},
		{"lobby", "lobby2", "", false},
	}
	for _, c := range cases {
		val, ok := matchWSRoomPattern(c.pattern, c.room)
		if ok != c.ok || val != c.val {
			t.Errorf("matchWSRoomPattern(%q, %q) = (%q, %v), want (%q, %v)", c.pattern, c.room, val, ok, c.val, c.ok)
		}
	}
}

func TestMemberOf_EmailUserCol(t *testing.T) {
	app := &App{
		Tables: []Table{
			{Name: "channels", Columns: []Column{{Name: "id"}}},
			{Name: "channel_members", Columns: []Column{{Name: "channel_id"}, {Name: "email"}}},
		},
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"channels": {"all": "member-of:channel_members(channel_id, email)"},
		}},
	}
	user := &Session{Role: "user", UserID: 2, Email: "u@x"}
	_, args, _ := rowScopeClause(app, "channels", user, "view")
	if args[0] != "u@x" {
		t.Errorf("a user column containing \"email\" should compare against the session email: %v", args)
	}
}
