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

// A migration file that creates what ws_rooms rules name: a view, a table,
// a schema-qualified quoted view, and text that only looks like DDL (a
// comment, a string literal, a temporary view that no other connection sees).
const wsRoomMigrationSQL = `-- CREATE VIEW commented_out AS SELECT 1 AS room_id, 1 AS member_id;
CREATE VIEW IF NOT EXISTS lobby_members AS
  SELECT room_id, member_id FROM room_members;
CREATE TABLE guest_passes (id INTEGER PRIMARY KEY, room_id INTEGER, member_id INTEGER);
CREATE VIEW main."door_list" AS SELECT room_id, member_id FROM room_members;
CREATE TEMP VIEW scratch_members AS SELECT room_id, member_id FROM room_members;
INSERT INTO guest_passes (room_id, member_id) SELECT 0, 0 WHERE 'CREATE VIEW in_a_string AS SELECT 1' = '';
ALTER TABLE guest_passes RENAME TO day_passes;
`

func wsRoomMigrationApp(t *testing.T, wsRooms string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "migrations"), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"app.yaml":                  "site_name: rooms\nws_rooms:\n" + wsRooms,
		"schema.prisma":             wsRoomCheckSchema,
		"migrations/0002_rooms.sql": wsRoomMigrationSQL,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func wsRoomFindings(findings []CheckFinding) []string {
	var out []string
	for _, f := range findings {
		if strings.Contains(f.Message, "app.yaml: ws_rooms.") {
			out = append(out, f.Message)
		}
	}
	return out
}

// A rule may name a view or a table that only a migrations/ file creates: the
// database will hold it, so the source check does not say the app lacks it,
// and it does not guess at such a relation's columns. A name that appears
// nowhere, or only in a comment, a string or a temporary view, is still
// warned about.
func TestWSRoomRuleOnMigrationCreatedRelationIsNotWarned(t *testing.T) {
	dir := wsRoomMigrationApp(t, `  "lob_:token": lobby_members(room_id, member_id)
  "pass-:id": day_passes(room_id, member_id)
  "old-:id": guest_passes(room_id, member_id)
  "door-:id": door_list(room_id, member_id)
  "view-col-:id": lobby_members(not_in_the_view, member_id)
  "gone-:id": nosuchtable(room_id, member_id)
  "note-:id": commented_out(room_id, member_id)
  "text-:id": in_a_string(room_id, member_id)
  "temp-:id": scratch_members(room_id, member_id)
`)
	got := wsRoomFindings(RunSourceCheck(dir, "app.yaml").Findings)
	all := strings.Join(got, "\n")
	for _, silent := range []string{`"lob_:token"`, `"pass-:id"`, `"old-:id"`, `"door-:id"`, `"view-col-:id"`} {
		if strings.Contains(all, "ws_rooms."+silent) {
			t.Errorf("the rule %s names what a migration creates and is warned about:\n%s", silent, all)
		}
	}
	for _, warned := range []string{`"gone-:id"`, `"note-:id"`, `"text-:id"`, `"temp-:id"`} {
		if !strings.Contains(all, "ws_rooms."+warned) {
			t.Errorf("the rule %s names nothing the database will hold and draws no warning:\n%s", warned, all)
		}
	}
	if len(got) != 4 {
		t.Errorf("%d warnings, want 4:\n%s", len(got), all)
	}
}

// With the app's database at hand (the hosted check asks the serving process)
// the check reads it: a view's rule is judged by the view's real columns, a
// rule the source check already named is reported once, and the load's log
// line agrees.
func TestWSRoomRuleIsJudgedAgainstTheLiveDatabase(t *testing.T) {
	resetWSHub(t)
	app, _ := auditApp(t)
	mustExec(t, app.DB, "CREATE VIEW lobby_members AS SELECT room_id, member_id FROM room_members")
	member := wsRoomTestSession(t, app, "member@example.com", "user")
	mustExec(t, app.DB, "INSERT INTO room_members (room_id, member_id) VALUES (42, "+itoaInt(member.UserID)+")")

	const wsRooms = `  "lob_:token": lobby_members(room_id, member_id)
  "view-col-:id": lobby_members(not_in_the_view, member_id)
  "gone-:id": nosuchtable(room_id, member_id)
`
	dir := wsRoomMigrationApp(t, wsRooms)
	rules := parseWSRooms([]byte("ws_rooms:\n" + wsRooms))
	app.WSRooms = rules

	// The rooms themselves: the view admits its member, the broken rules refuse.
	for room, want := range map[string]bool{"lob_42": true, "view-col-42": false, "gone-42": false} {
		if _, joined := wsJoinOverSocket(t, app, member, room); joined != want {
			t.Errorf("join of %s: joined=%v, want %v", room, joined, want)
		}
	}

	live := wsRoomFindings(wsRoomLiveFindings(dir, app.DB))
	all := strings.Join(live, "\n")
	if len(live) != 2 || strings.Contains(all, `"lob_:token"`) ||
		!strings.Contains(all, "lobby_members.not_in_the_view") || !strings.Contains(all, "nosuchtable") {
		t.Errorf("the live check reports:\n%s\nwant the missing view column and the missing table only", all)
	}
	if got := wsRoomLiveFindings(dir, nil); len(got) != 0 {
		t.Errorf("with no database the live check reports %v", got)
	}

	// One report: the source layers and the live layer name each rule once.
	report := runCheckWithLive(dir, "", true, func(dir string) []CheckFinding { return wsRoomLiveFindings(dir, app.DB) })
	merged := wsRoomFindings(report.Findings)
	if len(merged) != 2 {
		t.Errorf("%d ws_rooms findings in one report, want 2 (each rule once):\n%s", len(merged), strings.Join(merged, "\n"))
	}
	for _, f := range report.Findings {
		if strings.Contains(f.Message, "app.yaml: ws_rooms.") && (f.Severity != "warning" || f.Docs != "websocket.room_authorization") {
			t.Errorf("finding is %s with docs %q, want a warning at websocket.room_authorization: %s", f.Severity, f.Docs, f.Message)
		}
	}

	var logs bytes.Buffer
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(os.Stderr) })
	logWSRoomRuleReferences(app.DB, rules)
	log.SetOutput(os.Stderr)
	if logged := logs.String(); strings.Contains(logged, `"lob_:token"`) || strings.Count(logged, "app.yaml: ws_rooms.") != 2 {
		t.Errorf("the load log should name the two broken rules and not the view's:\n%s", logged)
	}
}
