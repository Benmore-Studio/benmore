//go:build !cli

package main

import (
	"net/http"
	"strings"
	"testing"
)

const memberOfRefSchema = `model Room {
  id    Int    @id @default(autoincrement())
  title String
}
model RoomMember {
  id       Int @id @default(autoincrement())
  roomId   Int
  memberId Int
}
model Message {
  id     Int    @id @default(autoincrement())
  roomId Int
  body   String
}
model Note {
  id     Int    @id @default(autoincrement())
  roomId Int
  body   String
}
`

// A member-of rule in access: that names a membership table or column the
// app does not have loads, and every request it gates fails. The write gate
// accepts the file (the table may arrive with the next schema write); the
// post-write check and `benmore check` name each such rule once.
func TestMemberOfRuleUnknownTableOrColumnIsWarned(t *testing.T) {
	const appYAML = `site_name: rooms
access:
  rooms: member-of:room_members(room_id, member_id)
  messages:
    read: member-of:nosuchtable(room_id, member_id)
    update: member-of:nosuchtable(room_id, member_id)
    delete: member-of:room_members(room_id, nosuchuser)
  notes: member-of:room_members(nosuchjoin=id, member_id)
`
	dir := t.TempDir()
	if msg := ValidateOnWriteIn(dir, "app.yaml", appYAML); msg != "" {
		t.Fatalf("the write gate refuses the file: %s", msg)
	}
	writeTestFile(t, dir, "app.yaml", appYAML)
	writeTestFile(t, dir, "schema.prisma", memberOfRefSchema)
	var got []string
	for _, f := range RunSourceCheck(dir, "app.yaml").Findings {
		if !strings.Contains(f.Message, "member-of:") || !strings.Contains(f.Message, " names ") {
			continue
		}
		if f.Severity != "warning" || f.Docs != "access.member_of" {
			t.Errorf("finding is %s with docs %q, want a warning at access.member_of: %s", f.Severity, f.Docs, f.Message)
		}
		got = append(got, f.Message)
	}
	all := strings.Join(got, "\n")
	if len(got) != 3 {
		t.Errorf("%d warnings, want 3 (one per broken rule of a table):\n%s", len(got), all)
	}
	for _, want := range []string{
		"access.messages (read, update) = member-of:nosuchtable(room_id, member_id) names membership table nosuchtable, which the app does not have",
		"messages, notes, room_members, rooms",
		"access.messages (delete) = member-of:room_members(room_id, nosuchuser) names room_members.nosuchuser, which the table does not have",
		"access.notes = member-of:room_members(nosuchjoin=id, member_id) names room_members.nosuchjoin",
		"id, member_id, room_id",
		"fails",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("the warnings lack %q:\n%s", want, all)
		}
	}
	if strings.Contains(all, "access.rooms") {
		t.Errorf("a working rule is warned about:\n%s", all)
	}

	// What the warning says happens: with the rule in force a member's
	// request is not answered with rows, while the working rule answers.
	app, mux := auditApp(t)
	sid := createCrudScopeSession(t, app, "member@example.com", "user", "", "")
	member := GetSessionFromDB(app.DB, sid)
	mustExec(t, app.DB, "INSERT INTO room_members (room_id, member_id) VALUES (1, "+itoaInt(member.UserID)+")")
	if rec := crudScopeRequest(t, mux, "GET", "/api/rooms", sid, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "private-room") {
		t.Fatalf("control: a member does not read the room under the working rule: %d %s", rec.Code, rec.Body.String())
	}
	for _, mode := range []string{"member-of:nosuchtable(room_id, member_id)", "member-of:room_members(room_id, nosuchuser)", "member-of:room_members(nosuchjoin=id, member_id)"} {
		app.Access.rules["rooms"] = map[AccessOp]string{"all": mode}
		rec := crudScopeRequest(t, mux, "GET", "/api/rooms", sid, nil)
		if rec.Code < 400 || strings.Contains(rec.Body.String(), "private-room") {
			t.Errorf("%s: the member's read was answered %d %s, want a failure", mode, rec.Code, rec.Body.String())
		}
	}
}

// A table or view a migration creates is not the sources' to judge: a rule
// naming one draws no warning.
func TestMemberOfRuleOnMigrationCreatedTableIsNotWarned(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "site_name: rooms\naccess:\n  messages: member-of:live_members(room_id, member_id)\n")
	writeTestFile(t, dir, "schema.prisma", memberOfRefSchema)
	writeTestFile(t, dir, "migrations/20260101000000_view.sql", "CREATE VIEW live_members AS SELECT room_id, member_id FROM room_members;\n")
	for _, f := range RunSourceCheck(dir, "app.yaml").Findings {
		if strings.Contains(f.Message, "member-of:") && strings.Contains(f.Message, " names ") {
			t.Errorf("a rule on a migration-created view is warned about: %s", f.Message)
		}
	}
}
