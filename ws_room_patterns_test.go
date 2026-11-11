//go:build !cli

package main

import (
	"bufio"
	"encoding/json"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"
)

var wsRoomTestRule = &memberOfRule{Table: "room_members", JoinCol: "room_id", UserCol: "member_id"}

func wsRoomTestSession(t *testing.T, app *App, email, role string) *Session {
	t.Helper()
	s := GetSessionFromDB(app.DB, createCrudScopeSession(t, app, email, role, "", ""))
	if s == nil {
		t.Fatal("session did not resolve")
	}
	return s
}

// wsJoinOverSocket sends one join frame through the connection's read loop,
// as a browser does, and returns the error frame the server answered ("" for
// an accepted join) and whether the connection now holds the room.
func wsJoinOverSocket(t *testing.T, app *App, session *Session, room string) (refusal string, joined bool) {
	t.Helper()
	srv, cli := net.Pipe()
	client := &wsClient{ws: &wsConn{conn: srv, br: bufio.NewReader(srv)}, send: make(chan []byte, 8),
		appID: "rooms", userID: session.UserID, subscriptions: map[string]bool{}, rooms: map[string]bool{},
		principal: realtimePrincipal{app: app, session: session}}
	go io.Copy(io.Discard, cli)
	done := make(chan struct{})
	go func() { wsReadLoop(client, app); close(done) }()
	msg, _ := json.Marshal(wsClientMsg{Type: "join", Room: room})
	if _, err := cli.Write(wsTestTextFrame(string(msg))); err != nil {
		t.Fatal(err)
	}
	cli.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the read loop did not end")
	}
	select {
	case frame := <-client.send:
		refusal = string(frame)
	default:
	}
	client.subMu.RLock()
	defer client.subMu.RUnlock()
	return refusal, client.rooms[scopedRoomID(client, room)]
}

// Every accepted pattern shape gates the room it names, over the socket: a
// member's join is taken, a non-member's is answered with the error frame and
// the connection does not hold the room. `chat::id` is the shape for rooms
// named chat:<id>, which the first ':' of a pattern used to make unreachable.
func TestWSRoomPatternShapesGateTheirRooms(t *testing.T) {
	resetWSHub(t)
	app, _ := auditApp(t)
	member := wsRoomTestSession(t, app, "member@example.com", "user")
	outsider := wsRoomTestSession(t, app, "outsider@example.com", "user")
	mustExec(t, app.DB, "INSERT INTO room_members (room_id, member_id) VALUES (42, "+itoaInt(member.UserID)+")")

	for _, tc := range []struct{ pattern, room, otherRoom string }{
		{"room-:id", "room-42", "room-43"},
		{"project-:id-chat", "project-42-chat", "project-43-chat"},
		{"chat::id", "chat:42", "chat:43"},
		{"team.:id", "team.42", "team.43"},
		{":id", "42", "43"},
		{"lobby", "lobby", ""}, // a literal room: membership in any row
	} {
		yaml := "ws_rooms:\n  \"" + tc.pattern + "\": room_members(room_id, member_id)\n"
		if msg := ValidateOnWriteIn(t.TempDir(), "app.yaml", yaml); msg != "" {
			t.Errorf("%q is refused at write time: %s", tc.pattern, msg)
		}
		app.WSRooms = parseWSRooms([]byte(yaml))
		if len(app.WSRooms) != 1 {
			t.Fatalf("%q did not load as one rule: %+v", tc.pattern, app.WSRooms)
		}
		if refusal, joined := wsJoinOverSocket(t, app, member, tc.room); refusal != "" || !joined {
			t.Errorf("%q: a member's join of %s answered %q (joined=%v)", tc.pattern, tc.room, refusal, joined)
		}
		refusal, joined := wsJoinOverSocket(t, app, outsider, tc.room)
		if joined || !strings.Contains(refusal, `"type":"error"`) || !strings.Contains(refusal, "not a member of this room") {
			t.Errorf("%q: a non-member's join of %s answered %q (joined=%v), want the error frame", tc.pattern, tc.room, refusal, joined)
		}
		if tc.otherRoom != "" {
			if refusal, joined := wsJoinOverSocket(t, app, member, tc.otherRoom); joined || refusal == "" {
				t.Errorf("%q: membership in room 42 admitted %s", tc.pattern, tc.otherRoom)
			}
		}
	}
}

// A pattern that can't mean what it says is refused when app.yaml is written
// and by `benmore check` (the same validator), with the pattern named and,
// where one exists, the working pattern for the rooms it was written for.
func TestUnusableWSRoomPatternsAreRefusedAtWriteTime(t *testing.T) {
	for _, tc := range []struct {
		pattern string
		want    []string // each must appear in the message
	}{
		{"chat:*", []string{`"chat:*"`, "not a wildcard", `"chat::id"`, "chat:42"}},
		{"room-*", []string{`"room-*"`, "not a wildcard", `"room-:id"`, "room-42"}},
		{"team-*-chat", []string{`"team-*-chat"`, `"team-:id-chat"`, "team-42-chat"}},
		{"*", []string{`"*"`, "not a wildcard"}},
		{"room-:id-*", []string{`"room-:id-*"`, "not a wildcard"}},
		{"a-:x-:y", []string{`"a-:x-:y"`, "one `:name` placeholder"}},
		{"chat:room-:id", []string{`"chat:room-:id"`, "one `:name` placeholder"}},
		{"chat:::id", []string{`"chat:::id"`, "one `:name` placeholder"}},
	} {
		yaml := "site_name: rooms\nws_rooms:\n  \"" + tc.pattern + "\": room_members(room_id, member_id)\n"
		dir := t.TempDir()
		msg := ValidateOnWriteIn(dir, "app.yaml", yaml)
		if msg == "" {
			t.Errorf("%q passes the write gate", tc.pattern)
			continue
		}
		for _, want := range append(tc.want, "ws_rooms") {
			if !strings.Contains(msg, want) {
				t.Errorf("%q: write-gate message lacks %q:\n%s", tc.pattern, want, msg)
			}
		}
		// benmore check reads the file from the app directory.
		if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(yaml), 0o644); err != nil {
			t.Fatal(err)
		}
		found := false
		for _, f := range RunSourceCheck(dir, "").Findings {
			if f.Severity == "error" && strings.Contains(f.Message, "ws_rooms") && strings.Contains(f.Message, `"`+tc.pattern+`"`) {
				found = true
			}
		}
		if !found {
			t.Errorf("%q: benmore check reports no error for the pattern: %+v", tc.pattern, RunSourceCheck(dir, "").Findings)
		}
	}
}

// A deployed app.yaml that already holds such a pattern still loads, and the
// rooms the pattern was written for are closed instead of open: a join to a
// room whose name starts with the text before the pattern's first ':' or '*'
// is refused for everyone but an admin. Rooms a usable pattern matches keep
// following that pattern, and unrelated rooms stay as they were.
func TestUnusableWSRoomPatternClosesItsRooms(t *testing.T) {
	resetWSHub(t)
	app, _ := auditApp(t)
	member := wsRoomTestSession(t, app, "member@example.com", "user")
	outsider := wsRoomTestSession(t, app, "outsider@example.com", "user")
	admin := wsRoomTestSession(t, app, "boss@example.com", "admin")
	mustExec(t, app.DB, "INSERT INTO room_members (room_id, member_id) VALUES (5, "+itoaInt(member.UserID)+")")

	appYAML := "site_name: rooms\nws_rooms:\n" +
		"  \"chat:*\": room_members(room_id, member_id)\n" +
		"  \"deal-:a-:b\": room_members(room_id, member_id)\n" +
		"  \"room-*-notes\": room_members(room_id, member_id)\n" +
		"  \"room-:id\": room_members(room_id, member_id)\n"
	// The loader takes the file: the app keeps serving.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(appYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	var loaded *runtimeConfig
	logged := captureLog(t, func() {
		var err error
		if loaded, err = loadServedRuntimeConfig(dir); err != nil {
			t.Fatalf("an app.yaml holding an unusable ws_rooms pattern does not load: %v", err)
		}
	})
	for _, pattern := range []string{`"chat:*"`, `"deal-:a-:b"`, `"room-*-notes"`} {
		if !strings.Contains(logged, "ws_rooms") || !strings.Contains(logged, pattern) {
			t.Errorf("loading logged nothing about %s:\n%s", pattern, logged)
		}
	}
	if n := strings.Count(logged, "ws_rooms pattern "); n != 3 {
		t.Errorf("loading logged %d patterns, want the 3 unusable ones and not the usable \"room-:id\":\n%s", n, logged)
	}
	app.WSRooms = loaded.wsRooms

	join := func(s *Session, room string) bool { return roomMembershipAllowed(app, s, s.UserID, room) }
	for _, room := range []string{"chat:5", "chat:6", "chat5", "chat-lobby", "deal-5-9", "deal-x"} {
		for name, s := range map[string]*Session{"a member": member, "a non-member": outsider} {
			if join(s, room) {
				t.Errorf("%s joined %s, a room an unusable pattern was written for", name, room)
			}
			if refusal, joined := wsJoinOverSocket(t, app, s, room); joined || !strings.Contains(refusal, "not a member of this room") {
				t.Errorf("%s joined %s over the socket (%q)", name, room, refusal)
			}
		}
		if roomMembershipAllowed(app, nil, 0, room) {
			t.Errorf("an anonymous caller joined %s", room)
		}
		if !join(admin, room) {
			t.Errorf("an admin was refused %s; admins bypass room rules", room)
		}
	}
	// "room-:id" is usable and decides its rooms, though the unusable
	// "room-*-notes" shares its lead.
	if !join(member, "room-5") {
		t.Error("a member was refused room-5, which a usable pattern gates")
	}
	if join(outsider, "room-5") {
		t.Error("a non-member joined room-5")
	}
	// No pattern names these rooms.
	for _, room := range []string{"lobby", "cha", "dea", "announcements"} {
		if !join(outsider, room) {
			t.Errorf("%s is closed, though no pattern is written for it", room)
		}
	}
}

var wsRoomsExampleRe = regexp.MustCompile(`ws_rooms: (\{[^}]*\})`)

// The check's advice for per-row rooms used with no rule must itself work:
// the pattern it tells the author to write is read out of the message,
// passes the write gate, and keeps a non-member out of the room a
// `chat:${id}` name produces. (It used to advise "chat:*", which gates
// nothing.)
func TestDynamicRoomWarningAdvisesAPatternThatGates(t *testing.T) {
	resetWSHub(t)
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "static"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "static", "app.tsx"), []byte("const r = bm.room(`chat:${id}`);\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	msg := dynamicWSRoomWarning(dir, nil)
	m := wsRoomsExampleRe.FindStringSubmatch(msg)
	if m == nil {
		t.Fatalf("the warning carries no ws_rooms example: %q", msg)
	}
	appYAML := "site_name: rooms\nws_rooms: " + m[1] + "\n"
	if refused := ValidateOnWriteIn(t.TempDir(), "app.yaml", appYAML); refused != "" {
		t.Fatalf("the warning's own example is refused at write time: %s", refused)
	}
	rules := parseWSRooms([]byte(appYAML))
	if len(rules) != 1 {
		t.Fatalf("the warning's example loads as %d rules, want 1: %s", len(rules), m[1])
	}
	if got := dynamicWSRoomWarning(dir, rules); got != "" {
		t.Errorf("the warning stays after its own advice is followed: %q", got)
	}

	// The membership table the example names, as the example names it.
	rule := rules[0].Rule
	app, _ := auditApp(t)
	mustExec(t, app.DB, "DROP TABLE room_members")
	mustExec(t, app.DB, "CREATE TABLE "+rule.Table+" (id INTEGER PRIMARY KEY, "+rule.JoinCol+" INTEGER, "+rule.UserCol+" INTEGER)")
	app.WSRooms = rules
	member := wsRoomTestSession(t, app, "member@example.com", "user")
	outsider := wsRoomTestSession(t, app, "outsider@example.com", "user")
	mustExec(t, app.DB, "INSERT INTO "+rule.Table+" ("+rule.JoinCol+", "+rule.UserCol+") VALUES (42, "+itoaInt(member.UserID)+")")
	if refusal, joined := wsJoinOverSocket(t, app, member, "chat:42"); refusal != "" || !joined {
		t.Errorf("a member's join of chat:42 answered %q (joined=%v)", refusal, joined)
	}
	if refusal, joined := wsJoinOverSocket(t, app, outsider, "chat:42"); joined || !strings.Contains(refusal, "not a member of this room") {
		t.Errorf("a non-member joined chat:42 under the advised pattern (%q, joined=%v)", refusal, joined)
	}
}
