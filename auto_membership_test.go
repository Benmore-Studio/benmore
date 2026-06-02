//go:build !cli

package main

import (
	"strings"
	"testing"
)

// Defaults: parent → <parent>_members, FK → <parent_singular>_id,
// user_field → user_id, members → all_users.
func TestFillMembershipDefaults(t *testing.T) {
	got := fillMembershipDefaults("channels", AutoMembershipConfig{})
	if got.Table != "channels_members" {
		t.Errorf("table default: got %q want channels_members", got.Table)
	}
	if got.Parent != "channel_id" {
		t.Errorf("parent default: got %q want channel_id", got.Parent)
	}
	if got.UserField != "user_id" {
		t.Errorf("user_field default: got %q want user_id", got.UserField)
	}
	if got.Members != "all_users" {
		t.Errorf("members default: got %q want all_users", got.Members)
	}
}

// Singular table names fall back to <name>_id.
func TestFillMembershipDefaults_NonPluralizedTable(t *testing.T) {
	got := fillMembershipDefaults("workspace", AutoMembershipConfig{})
	if got.Parent != "workspace_id" {
		t.Errorf("parent on singular: got %q want workspace_id", got.Parent)
	}
}

// Explicit values override the defaults.
func TestFillMembershipDefaults_ExplicitWins(t *testing.T) {
	cfg := AutoMembershipConfig{
		Table:     "rooms_with_people_in_them",
		Parent:    "the_room_id",
		UserField: "member_user_id",
		Members:   "role = 'employee'",
	}
	got := fillMembershipDefaults("rooms", cfg)
	if got.Table != "rooms_with_people_in_them" ||
		got.Parent != "the_room_id" ||
		got.UserField != "member_user_id" ||
		got.Members != "role = 'employee'" {
		t.Errorf("explicit overrides clobbered: %+v", got)
	}
}

// Synthesized SQL hits the right shapes for the common case.
func TestBuildAutoMembershipHook_DefaultShape(t *testing.T) {
	h := buildAutoMembershipHook("channels", AutoMembershipConfig{})
	if h.SQL == "" {
		t.Fatal("empty SQL — config rejected unexpectedly")
	}
	for _, want := range []string{
		"INSERT INTO channels_members",
		"(user_id, channel_id)",
		"SELECT id, {{id}} FROM _benmore_users",
		"WHERE deactivated_at IS NULL OR deactivated_at = ''",
		"ON CONFLICT DO NOTHING",
		"/*auto_membership:channels*/",
	} {
		if !strings.Contains(h.SQL, want) {
			t.Errorf("synthesized SQL missing %q\nfull: %s", want, h.SQL)
		}
	}
}

// Custom members WHERE fragment lands in the SQL.
func TestBuildAutoMembershipHook_CustomMembers(t *testing.T) {
	h := buildAutoMembershipHook("channels", AutoMembershipConfig{
		Members: "role = 'employee' AND verified = 1",
	})
	if !strings.Contains(h.SQL, "WHERE role = 'employee' AND verified = 1") {
		t.Errorf("custom members fragment not in SQL: %s", h.SQL)
	}
}

// synthesizeAutoMembershipHooks is idempotent — calling it twice
// (e.g. across hot-reloads) doesn't accumulate duplicate hooks.
func TestSynthesizeAutoMembershipHooks_Idempotent(t *testing.T) {
	app := &App{
		Design: &DesignConfig{
			AutoMemberships: map[string]AutoMembershipConfig{
				"channels": {},
			},
		},
		Hooks: &HookConfig{OnInsert: map[string][]Hook{}},
	}
	synthesizeAutoMembershipHooks(app)
	first := len(app.Hooks.OnInsert["channels"])
	if first != 1 {
		t.Fatalf("first run: got %d hooks, want 1", first)
	}
	synthesizeAutoMembershipHooks(app)
	second := len(app.Hooks.OnInsert["channels"])
	if second != 1 {
		t.Errorf("second run accumulated hooks: %d", second)
	}
}
