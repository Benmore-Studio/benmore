//go:build !cli

package main

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// newMemberOfShapeFixture: rooms is the member-of parent of room_members;
// posts declares the same rule but has no room_id column (its column is
// channel_id), and tasks is scoped by the groups membership table without
// carrying the tenant key.
func newMemberOfShapeFixture(t *testing.T, access string) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	if err := EnsureUserRolesTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	for _, stmt := range []string{
		`CREATE TABLE rooms (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT)`,
		`CREATE TABLE room_members (id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER, member_id INTEGER, UNIQUE(room_id, member_id))`,
		`CREATE TABLE posts (id INTEGER PRIMARY KEY AUTOINCREMENT, channel_id INTEGER, body TEXT)`,
		`CREATE TABLE spaces (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT)`,
		`CREATE TABLE space_members (id INTEGER PRIMARY KEY AUTOINCREMENT, area_id INTEGER REFERENCES spaces(id), member_id INTEGER, UNIQUE(area_id, member_id))`,
		`CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, body TEXT)`,
		`CREATE TABLE note_readers (id INTEGER PRIMARY KEY AUTOINCREMENT, ref INTEGER, member_id INTEGER)`,
		`CREATE TABLE members (id INTEGER PRIMARY KEY AUTOINCREMENT, org_id INTEGER, email TEXT)`,
		`CREATE TABLE tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, organization_id INTEGER, title TEXT)`,
		`INSERT INTO rooms (id, title) VALUES (1, 'private-room')`,
		`INSERT INTO posts (id, channel_id, body) VALUES (1, 7, 'someone-elses-post')`,
	} {
		crudScopeMustExec(t, db, stmt)
	}
	app := &App{
		Dir: dir, DB: db, SessionDuration: time.Hour, Stop: make(chan struct{}),
		Group:  &GroupConfig{Table: "members", Key: "org_id", UserField: "email"},
		Access: accessFromYAML(t, access),
	}
	for _, name := range []string{"rooms", "room_members", "posts", "spaces", "space_members", "notes", "note_readers", "members", "tasks"} {
		cols, err := GetTableColumns(db, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	app.JoinMap = BuildJoinMap(db)
	t.Cleanup(app.Shutdown)
	return app, buildAppMux(app, true, "http://localhost")
}

func memberOfCount(t *testing.T, app *App, q string, args ...any) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow(q, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// A member-of rule on a table that lacks the rule's join column was read as
// "this table is the parent": rows matched membership by their own id, anyone
// could create one, and the create auto-joined the creator into the
// membership whose join value equals the new row's id - an arbitrary room,
// or an arbitrary tenant when the membership table is the groups table. A
// table is the parent only when the membership join column points at it.
func TestMemberOfMisdeclaredChildFailsClosed(t *testing.T) {
	app, mux := newMemberOfShapeFixture(t, `access:
  rooms: member-of:room_members(room_id, member_id)
  posts: member-of:room_members(room_id, member_id)
  tasks: member-of:members(org_id, email)
`)
	sid := createCrudScopeSession(t, app, "mallory@example.com", "user", "", "")
	var uid int64
	if err := app.DB.QueryRow("SELECT id FROM _benmore_users WHERE email = 'mallory@example.com'").Scan(&uid); err != nil {
		t.Fatal(err)
	}

	// Creating rows in the misdeclared tables must not mint memberships.
	for _, path := range []string{"/api/posts", "/api/tasks"} {
		crudScopeRequest(t, mux, http.MethodPost, path, sid, map[string]any{"body": "x", "title": "x"})
		crudScopeRequest(t, mux, http.MethodPost, path+"/batch", sid, []any{map[string]any{"body": "x", "title": "x"}})
		table := strings.TrimPrefix(path, "/api/")
		crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", sid, map[string]any{"operations": []any{map[string]any{"table": table, "action": "insert", "data": map[string]any{"body": "x", "title": "x"}}}})
	}
	if n := memberOfCount(t, app, "SELECT COUNT(*) FROM room_members WHERE member_id = ?", uid); n != 0 {
		t.Fatalf("creating a post joined the creator into %d room(s)", n)
	}
	if n := memberOfCount(t, app, "SELECT COUNT(*) FROM members WHERE email = 'mallory@example.com'"); n != 0 {
		t.Fatalf("creating a task joined the creator into %d tenant(s)", n)
	}
	if n := memberOfCount(t, app, "SELECT COUNT(*) FROM posts") + memberOfCount(t, app, "SELECT COUNT(*) FROM tasks"); n != 1 {
		t.Fatalf("rows were created in misdeclared member-of tables (%d rows)", n)
	}
	// Membership in room 1 is not access to post 1.
	crudScopeMustExec(t, app.DB, fmt.Sprintf("INSERT INTO room_members (room_id, member_id) VALUES (1, %d)", uid))
	for _, path := range []string{"/api/posts", "/api/posts/1"} {
		if rec := crudScopeRequest(t, mux, http.MethodGet, path, sid, nil); strings.Contains(rec.Body.String(), "someone-elses-post") {
			t.Fatalf("GET %s matched a post by a room id: %s", path, rec.Body.String())
		}
	}
	crudScopeRequest(t, mux, http.MethodPatch, "/api/posts/1", sid, map[string]any{"body": "overwritten"})
	crudScopeRequest(t, mux, http.MethodDelete, "/api/posts/1", sid, nil)
	if n := memberOfCount(t, app, "SELECT COUNT(*) FROM posts WHERE body = 'someone-elses-post'"); n != 1 {
		t.Fatal("a room member edited or deleted a post matched by id")
	}
	// The real parent keeps working: read through the membership, create
	// with the founder auto-join.
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/rooms", sid, nil); !strings.Contains(rec.Body.String(), "private-room") {
		t.Fatalf("parent read through membership: %d %s", rec.Code, rec.Body.String())
	}
	assertStatus(t, mux, http.MethodPost, "/api/rooms", sid, map[string]any{"title": "mine"}, http.StatusOK)
	if n := memberOfCount(t, app, "SELECT COUNT(*) FROM room_members WHERE member_id = ? AND room_id <> 1", uid); n != 1 {
		t.Fatalf("parent create should auto-join its creator once, got %d", n)
	}
}

// What makes a table the parent: a foreign key from the membership join
// column, the groups tenant root, the conventional <singular>_id name, or
// an explicit `<join>=id`.
func TestMemberOfParentRecognition(t *testing.T) {
	app, mux := newMemberOfShapeFixture(t, `access:
  spaces: member-of:space_members(area_id, member_id)
  notes: member-of:note_readers(ref=id, member_id)
  posts: member-of:space_members(area_id, member_id)
`)
	sid := createCrudScopeSession(t, app, "ann@example.com", "user", "", "")
	// spaces: the foreign key says area_id points at it.
	assertStatus(t, mux, http.MethodPost, "/api/spaces", sid, map[string]any{"title": "s"}, http.StatusOK)
	// notes: declared the parent explicitly.
	assertStatus(t, mux, http.MethodPost, "/api/notes", sid, map[string]any{"body": "n"}, http.StatusOK)
	if n := memberOfCount(t, app, "SELECT COUNT(*) FROM space_members") + memberOfCount(t, app, "SELECT COUNT(*) FROM note_readers"); n != 2 {
		t.Fatalf("founder auto-join rows = %d, want 2", n)
	}
	// Without the explicit form, notes is not what note_readers.ref names.
	// Successful creates queued realtime delivery using the current policy.
	// Finish that delivery before this fixture replaces the policy in place.
	realtimeFlush()
	app.Access = accessFromYAML(t, "access:\n  notes: member-of:note_readers(ref, member_id)\n")
	if rec := crudScopeRequest(t, mux, http.MethodPost, "/api/notes", sid, map[string]any{"body": "n2"}); rec.Code == http.StatusOK {
		t.Fatalf("an unprovable parent was accepted: %s", rec.Body.String())
	}
	realtimeFlush()
	app.Access = accessFromYAML(t, "access:\n  posts: member-of:space_members(area_id, member_id)\n")
	// posts: the foreign key points elsewhere, so it is not the parent.
	if rec := crudScopeRequest(t, mux, http.MethodPost, "/api/posts", sid, map[string]any{"body": "p"}); rec.Code == http.StatusOK {
		t.Fatalf("a table the join column does not reference was treated as the parent: %s", rec.Body.String())
	}

	for rule, table := range map[string]string{"company_id": "companies", "room_id": "rooms", "box_id": "boxes", "org_id": "orgs"} {
		if !memberOfJoinNamesTable(rule, table) {
			t.Errorf("%s should name %s", rule, table)
		}
	}
	for rule, table := range map[string]string{"room_id": "messages", "org_id": "tasks", "room": "rooms", "_id": "s"} {
		if memberOfJoinNamesTable(rule, table) {
			t.Errorf("%s should not name %s", rule, table)
		}
	}
}

// The same decision is made before the file lands: writing app.yaml (or a
// schema.prisma that drops the join column) is refused, and `benmore check`
// reports it, since both run ValidateOnWriteIn.
func TestMemberOfShapeRefusedAtWriteTime(t *testing.T) {
	dir := t.TempDir()
	schema := `model Room {
  id    Int    @id @default(autoincrement())
  title String
}

model RoomMember {
  id       Int  @id @default(autoincrement())
  roomId   Int
  room     Room @relation(fields: [roomId], references: [id])
  memberId Int
}

model Message {
  id        Int    @id @default(autoincrement())
  roomId    Int
  body      String
}

model Post {
  id        Int    @id @default(autoincrement())
  channelId Int
  body      String
}
`
	good := "site_name: demo\naccess:\n  rooms: member-of:room_members(room_id, member_id)\n  messages: member-of:room_members(room_id, member_id)\n"
	bad := good + "  posts: member-of:room_members(room_id, member_id)\n"
	explicit := good + "  posts: member-of:room_members(room_id=id, member_id)\n"
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("schema.prisma", schema)
	write("app.yaml", good)

	if msg := ValidateOnWriteIn(dir, "app.yaml", good); msg != "" {
		t.Fatalf("a child with the join column and the related parent must be accepted: %s", msg)
	}
	if msg := ValidateOnWriteIn(dir, "app.yaml", explicit); msg != "" {
		t.Fatalf("an explicit parent must be accepted: %s", msg)
	}
	msg := ValidateOnWriteIn(dir, "app.yaml", bad)
	if !strings.Contains(msg, "access.posts") || !strings.Contains(msg, "room_id") {
		t.Fatalf("a member-of table with no join column that the relation does not point at must be refused, got %q", msg)
	}
	// The schema side: dropping messages.room_id leaves the rule misdeclared.
	if msg := ValidateOnWriteIn(dir, "schema.prisma", strings.Replace(schema, "  roomId    Int\n  body      String", "  body      String", 1)); !strings.Contains(msg, "access.messages") {
		t.Fatalf("a schema edit that removes the join column must be refused, got %q", msg)
	}
	// benmore check reports the same error.
	write("app.yaml", bad)
	report := RunSourceCheck(dir, "")
	found := false
	for _, f := range report.Findings {
		if f.Severity == "error" && strings.Contains(f.Message, "access.posts") {
			found = true
		}
	}
	if !found {
		t.Fatalf("benmore check did not report the misdeclared member-of table: %+v", report.Findings)
	}
}
