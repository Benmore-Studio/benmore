//go:build !cli

package main

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const wsRoomCheckSchema = `model Room {
  id    Int    @id @default(autoincrement())
  title String
}
model RoomMember {
  id       Int @id @default(autoincrement())
  roomId   Int
  memberId Int
}
`

// wsRoomCheckWarnings writes an app holding the given ws_rooms block and
// returns what `benmore check` and the post-write check warn about it. The
// file must also pass the write gate: a deployed app.yaml keeps pushing.
func wsRoomCheckWarnings(t *testing.T, wsRooms string) []string {
	t.Helper()
	dir := t.TempDir()
	appYAML := "site_name: rooms\nws_rooms:\n" + wsRooms
	if msg := ValidateOnWriteIn(dir, "app.yaml", appYAML); msg != "" {
		t.Fatalf("the write gate refuses the file:\n%s\n%s", appYAML, msg)
	}
	for name, content := range map[string]string{"app.yaml": appYAML, "schema.prisma": wsRoomCheckSchema} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	report := RunSourceCheck(dir, "app.yaml")
	var out []string
	for _, f := range report.Findings {
		if !strings.Contains(f.Message, "ws_rooms") {
			continue
		}
		if f.Severity != "warning" {
			t.Errorf("a ws_rooms finding is %s, want a warning: %s", f.Severity, f.Message)
		}
		if f.Docs != "websocket.room_authorization" {
			t.Errorf("the finding points at %q, want websocket.room_authorization: %s", f.Docs, f.Message)
		}
		out = append(out, f.Message)
	}
	return out
}

// Every pattern shape a builder writes with `-`, `.` or `:` around the
// placeholder reads as written and draws no warning: the placeholder's value
// is the text between the pattern's literal parts.
func TestWSRoomPatternShapesReadAsWritten(t *testing.T) {
	for _, tc := range []struct{ pattern, room, value string }{
		{"board-:id", "board-42", "42"},
		{"chat::id", "chat:42", "42"},
		{"team-:id-lobby", "team-42-lobby", "42"},
		{"board-:id-notes", "board-42-notes", "42"},
		{":id-room", "42-room", "42"},
		{"doc.:id", "doc.42", "42"},
		{"u-:user", "u-42", "42"},
		{"lounge", "lounge", ""},
		// `_` before the placeholder is room-name text.
		{"a_:id", "a_42", "42"},
		// A placeholder may carry a column-like name: `_` is part of it.
		{"room-:room_id", "room-42", "42"},
		{"thread-:thread_id", "thread-42", "42"},
	} {
		if val, ok := matchWSRoomPattern(tc.pattern, tc.room); !ok || val != tc.value {
			t.Errorf("%q: room %s reads as (%q, %v), want (%q, true)", tc.pattern, tc.room, val, ok, tc.value)
		}
		if got := wsRoomCheckWarnings(t, "  \""+tc.pattern+"\": room_members(room_id, member_id)\n"); len(got) != 0 {
			t.Errorf("%q draws a warning: %v", tc.pattern, got)
		}
	}
}

// A `_` directly after the placeholder's name continues the name: "a_:id_b"
// is the placeholder :id_b, so it restricts rooms a_<value> and a room named
// a_42_b is checked with the join value "42_b". That reading is kept (a
// deployed pattern keeps guarding the rooms it guards today); the check says
// how the pattern is read and names the pattern for rooms a_<value>-b, and
// that pattern gates those rooms.
func TestWSRoomPatternUnderscoreAfterPlaceholderIsWarned(t *testing.T) {
	resetWSHub(t)
	app, _ := auditApp(t)
	member := wsRoomTestSession(t, app, "member@example.com", "user")
	outsider := wsRoomTestSession(t, app, "outsider@example.com", "user")
	mustExec(t, app.DB, "INSERT INTO room_members (room_id, member_id) VALUES (42, "+itoaInt(member.UserID)+")")

	// The reading at run time: the room the author meant refuses its member.
	app.WSRooms = parseWSRooms([]byte("ws_rooms:\n  \"a_:id_b\": room_members(room_id, member_id)\n"))
	if refusal, joined := wsJoinOverSocket(t, app, member, "a_42_b"); joined || !strings.Contains(refusal, "not a member of this room") {
		t.Fatalf("a_:id_b admitted a member of 42 to a_42_b (%q, joined=%v): the pattern's reading changed", refusal, joined)
	}
	if refusal, joined := wsJoinOverSocket(t, app, member, "a_42"); refusal != "" || !joined {
		t.Fatalf("a_:id_b no longer admits a member of 42 to a_42 (%q, joined=%v)", refusal, joined)
	}
	if _, joined := wsJoinOverSocket(t, app, outsider, "a_42"); joined {
		t.Fatal("a_:id_b admits a non-member to a_42")
	}

	for _, tc := range []struct {
		pattern, fixed, fixedRoom string
		want                      []string
	}{
		{"a_:id_b", "a_:id-b", "a_42-b", []string{`"a_:id_b"`, ":id_b", "a_42_b", `"a_:id-b"`, `"a_:id.b"`, "a_42-b", "name it :id or :room_id and"}},
		{"team_:id_lobby", "team_:id-lobby", "team_42-lobby", []string{`"team_:id_lobby"`, ":id_lobby", `"team_:id-lobby"`}},
		{":id_room", ":id-room", "42-room", []string{`":id_room"`, ":id_room", `":id-room"`}},
		// Named after the join column, then more text: the split is after the column's name.
		{"r-:room_id_chat", "r-:room_id-chat", "r-42-chat", []string{`"r-:room_id_chat"`, `"r-:room_id-chat"`, "name it :room_id and"}},
	} {
		got := wsRoomCheckWarnings(t, "  \""+tc.pattern+"\": room_members(room_id, member_id)\n")
		if len(got) != 1 {
			t.Errorf("%q: %d warnings, want 1: %v", tc.pattern, len(got), got)
			continue
		}
		for _, want := range tc.want {
			if !strings.Contains(got[0], want) {
				t.Errorf("%q: the warning lacks %q:\n%s", tc.pattern, want, got[0])
			}
		}
		// The pattern the warning names draws none and gates its rooms.
		if again := wsRoomCheckWarnings(t, "  \""+tc.fixed+"\": room_members(room_id, member_id)\n"); len(again) != 0 {
			t.Errorf("%q, the pattern the warning names, is warned about: %v", tc.fixed, again)
		}
		app.WSRooms = parseWSRooms([]byte("ws_rooms:\n  \"" + tc.fixed + "\": room_members(room_id, member_id)\n"))
		if refusal, joined := wsJoinOverSocket(t, app, member, tc.fixedRoom); refusal != "" || !joined {
			t.Errorf("%q: a member's join of %s answered %q (joined=%v)", tc.fixed, tc.fixedRoom, refusal, joined)
		}
		if refusal, joined := wsJoinOverSocket(t, app, outsider, tc.fixedRoom); joined || !strings.Contains(refusal, "not a member of this room") {
			t.Errorf("%q: a non-member's join of %s answered %q (joined=%v)", tc.fixed, tc.fixedRoom, refusal, joined)
		}
	}

	// The refusal for an unusable pattern no longer offers `_` as a separator
	// after the placeholder.
	msg := wsRoomPatternRefusal("a-:x-:y")
	if strings.Contains(msg, "Use `-`, `.` or `_` for any other separator") {
		t.Errorf("the refusal still offers `_` as a separator anywhere in the room name:\n%s", msg)
	}
	if !strings.Contains(msg, "part of the placeholder's name") {
		t.Errorf("the refusal does not say how `_` after a placeholder is read:\n%s", msg)
	}
}

// A rule that names a table or column the app does not have refuses every
// join of its rooms. The file still pushes; the check names the rule, what is
// missing and what happens, and the load logs the same.
func TestWSRoomRuleUnknownTableOrColumnIsWarned(t *testing.T) {
	got := wsRoomCheckWarnings(t, `  "good-:id": room_members(room_id, member_id)
  "bad-:id": nosuchtable(room_id, member_id)
  "bad2-:id": room_members(nosuchcol, member_id)
  "bad3-:id": room_members(room_id, nosuchuser)
  "lobby": room_members(unused_for_a_literal, member_id)
`)
	all := strings.Join(got, "\n")
	if len(got) != 3 {
		t.Errorf("%d warnings, want 3 (one per broken rule):\n%s", len(got), all)
	}
	for _, want := range []string{
		`ws_rooms."bad-:id"`, "nosuchtable", "room_members, rooms",
		`ws_rooms."bad2-:id"`, "room_members.nosuchcol",
		`ws_rooms."bad3-:id"`, "room_members.nosuchuser", "id, member_id, room_id",
		"refused",
	} {
		if !strings.Contains(all, want) {
			t.Errorf("the warnings lack %q:\n%s", want, all)
		}
	}
	for _, not := range []string{`"good-:id"`, `"lobby"`} {
		if strings.Contains(all, not) {
			t.Errorf("a working rule %s is warned about:\n%s", not, all)
		}
	}

	// At run time the broken rules refuse a member and a working one admits.
	resetWSHub(t)
	app, _ := auditApp(t)
	member := wsRoomTestSession(t, app, "member@example.com", "user")
	mustExec(t, app.DB, "INSERT INTO room_members (room_id, member_id) VALUES (42, "+itoaInt(member.UserID)+")")
	rules := parseWSRooms([]byte(`ws_rooms:
  "good-:id": room_members(room_id, member_id)
  "bad-:id": nosuchtable(room_id, member_id)
  "bad2-:id": room_members(nosuchcol, member_id)
  "bad3-:id": room_members(room_id, nosuchuser)
`))
	app.WSRooms = rules
	for room, want := range map[string]bool{"good-42": true, "bad-42": false, "bad2-42": false, "bad3-42": false} {
		if _, joined := wsJoinOverSocket(t, app, member, room); joined != want {
			t.Errorf("join of %s: joined=%v, want %v", room, joined, want)
		}
	}

	// The load says so, once per broken rule, from the live database.
	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	logWSRoomRuleReferences(app.DB, rules)
	log.SetOutput(os.Stderr)
	logged := logs.String()
	if n := strings.Count(logged, "app.yaml: ws_rooms."); n != 3 {
		t.Errorf("%d log lines, want 3:\n%s", n, logged)
	}
	for _, want := range []string{`ws_rooms."bad-:id"`, "nosuchtable", "room_members.nosuchcol", "room_members.nosuchuser"} {
		if !strings.Contains(logged, want) {
			t.Errorf("the load log lacks %q:\n%s", want, logged)
		}
	}
	if strings.Contains(logged, `"good-:id"`) {
		t.Errorf("the load logs a working rule:\n%s", logged)
	}
}

// The groups membership table left to its default takes a tenant admin to
// write (membershipManageGated), so the check does not tell its author that
// "any user can insert a membership row". The warning stays for a table the
// app opened itself and for every other membership table.
func TestMemberOfSelfJoinWarningKnowsTheGroupsTable(t *testing.T) {
	const schema = `model Team {
  id   Int    @id @default(autoincrement())
  name String
}
model TeamMember {
  id     Int @id @default(autoincrement())
  teamId Int
  userId Int
}
model Board {
  id     Int @id @default(autoincrement())
  teamId Int
}
model BoardMember {
  id       Int @id @default(autoincrement())
  boardId  Int
  userId   Int
}
`
	models, err := ParsePrismaSchema(schema)
	if err != nil {
		t.Fatal(err)
	}
	const groups = `groups:
  table: team_members
  key: team_id
  user_field: user_id
  role_field: member_role
  bootstrap:
    org_table: teams
    founding_role: team_admin
`
	for _, tc := range []struct {
		name, access string
		warned       map[string]bool // membership table -> warned
	}{
		{"groups table on its default", `access:
  teams:
    read: member-of:team_members(team_id, user_id)
  team_members:
    read: group
  boards:
    all: member-of:board_members(board_id, user_id)
`, map[string]bool{"team_members": false, "board_members": true}},
		{"a default: block is not a rule on the groups table", `access:
  default:
    write: everyone
  teams:
    read: member-of:team_members(team_id, user_id)
`, map[string]bool{"team_members": false}},
		{"groups table opened by its own rule", `access:
  teams:
    read: member-of:team_members(team_id, user_id)
  team_members:
    write: self
`, map[string]bool{"team_members": true}},
	} {
		appYAML := []byte(groups + tc.access)
		access, err := parseAccessConfig(appYAML)
		if err != nil {
			t.Fatal(err)
		}
		group := parseGroupConfig(appYAML)
		msgs := strings.Join(memberOfSelfJoinWarnings(access, group, models), "\n")
		for table, want := range tc.warned {
			if got := strings.Contains(msgs, table+" is a member-of membership table"); got != want {
				t.Errorf("%s: warning for %s = %v, want %v:\n%s", tc.name, table, got, want, msgs)
			}
			// The runtime's own decision: a gated write needs a tenant admin.
			gated := membershipManageGated(&App{Group: group, Access: access}, table, OpWrite)
			if gated && strings.Contains(msgs, table+" is a member-of membership table") {
				t.Errorf("%s: %s creates take a tenant admin at run time, and the check says any user can insert", tc.name, table)
			}
		}
	}
}
