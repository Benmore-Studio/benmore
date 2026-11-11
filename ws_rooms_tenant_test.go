//go:build !cli

package main

import (
	"testing"
)

// A ws_rooms membership table that carries the groups: tenant key follows
// the member-of tenant rule: a membership row admits a join only inside the
// caller's own tenant, and a caller with no tenant gains nothing from one.
// Before, a tenant member could create a membership row (stamped with their
// own tenant) naming a user of another tenant, or a user with no tenant, and
// that user's join was admitted.
func TestWSRoomJoinAppliesMembershipTenantRule(t *testing.T) {
	app, _ := memberOfTenantApp(t)
	app.WSRooms = []WSRoomRule{
		{Pattern: "project-:id", Rule: &memberOfRule{Table: "project_members", JoinCol: "project_id", UserCol: "member_id"}},
		{Pattern: "lobby", Rule: &memberOfRule{Table: "project_members", JoinCol: "project_id", UserCol: "member_id"}},
	}
	session := func(email, role, group string) *Session {
		t.Helper()
		s := GetSessionFromDB(app.DB, createCrudScopeSession(t, app, email, role, group, ""))
		if s == nil {
			t.Fatal("session did not resolve")
		}
		return s
	}
	alice := session("alice@example.com", "user", "1") // tenant 1
	carol := session("carol@example.com", "user", "2") // tenant 2
	dave := session("dave@example.com", "user", "")    // no tenant
	admin := session("boss@example.com", "admin", "")
	a, c, d := itoaInt(alice.UserID), itoaInt(carol.UserID), itoaInt(dave.UserID)
	for _, stmt := range []string{
		"INSERT INTO company_members (company_id, member_id) VALUES (1, " + a + "), (2, " + c + ")",
		// Rows alice's tenant wrote: alice herself, and carol and dave invited
		// into tenant 1's project.
		"INSERT INTO project_members (company_id, project_id, member_id) VALUES (1, 1, " + a + "), (1, 1, " + c + "), (1, 1, " + d + ")",
	} {
		mustExec(t, app.DB, stmt)
	}
	join := func(s *Session, room string) bool {
		return roomMembershipAllowed(app, s, s.UserID, room)
	}

	if !join(alice, "project-1") || !join(alice, "lobby") {
		t.Fatal("a member's own-tenant membership row must admit the join")
	}
	for name, s := range map[string]*Session{"another tenant's user": carol, "a user with no tenant": dave} {
		if join(s, "project-1") {
			t.Errorf("%s joined project-1 through a membership row stamped with tenant 1", name)
		}
		if join(s, "lobby") {
			t.Errorf("%s joined the literal room through a tenant-1 membership row", name)
		}
	}
	if !join(admin, "project-1") {
		t.Fatal("admins bypass ws_rooms membership")
	}

	// Carol's own tenant's membership admits her.
	mustExec(t, app.DB, "INSERT INTO project_members (company_id, project_id, member_id) VALUES (2, 5, "+c+")")
	if !join(carol, "project-5") || !join(carol, "lobby") {
		t.Fatal("a membership row in the caller's own tenant must admit the join")
	}
	if join(carol, "project-1") {
		t.Fatal("an own-tenant row for another room widened carol's access to project-1")
	}
}

// A membership table without the tenant key keeps the plain membership
// check: nothing on the row says which tenant it belongs to.
func TestWSRoomJoinWithoutTenantKeyUnchanged(t *testing.T) {
	app, _ := auditApp(t)
	app.WSRooms = []WSRoomRule{{Pattern: "room-:id", Rule: &memberOfRule{Table: "room_members", JoinCol: "room_id", UserCol: "member_id"}}}
	s := GetSessionFromDB(app.DB, createCrudScopeSession(t, app, "solo@example.com", "user", "", ""))
	mustExec(t, app.DB, "INSERT INTO room_members (room_id, member_id) VALUES (1, "+itoaInt(s.UserID)+")")
	if !roomMembershipAllowed(app, s, s.UserID, "room-1") {
		t.Fatal("membership in an un-keyed room table must still admit a tenantless member")
	}
	if roomMembershipAllowed(app, s, s.UserID, "room-2") {
		t.Fatal("membership in room 1 admitted room 2")
	}
}
