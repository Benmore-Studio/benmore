//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A membership table scoped by its own membership (the documented roster
// rule, room_members: member-of:room_members(room_id, member_id)) must show a
// caller only the rosters of rooms they belong to. The EXISTS once named the
// membership table on both sides, so SQLite read both sides from the inner
// row and any membership anywhere admitted every roster row: a user who made
// their own room could list every room's members and repoint another room's
// membership row at themselves, then read that room's messages.
func memberOfSelfScopeApp(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open(sqliteHistoryTestDriver, filepath.Join(dir, "data.db")+"?_journal_mode=WAL&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, stmt := range []string{
		`CREATE TABLE rooms (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, user_id INTEGER)`,
		`CREATE TABLE room_members (id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER, member_id INTEGER, user_id INTEGER)`,
		`CREATE TABLE messages (id INTEGER PRIMARY KEY AUTOINCREMENT, room_id INTEGER, body TEXT, user_id INTEGER)`,
	} {
		mustExec(t, db, stmt)
	}
	if err := EnsureUsersTable(db); err != nil {
		t.Fatal(err)
	}
	EnsureSessionsTable(db)
	EnsureAPITokensTable(db)
	EnsurePermissionsTable(db)
	EnsureAuditLogTable(db)
	EnsureIdempotencyTable(db)
	EnsureNotificationsTable(db)
	EnsureWebhooksTable(db)
	rule := "member-of:room_members(room_id, member_id)"
	app := &App{Dir: dir, DB: db, Stop: make(chan struct{}), SessionDuration: time.Hour,
		Access: &AccessConfig{rules: map[string]map[AccessOp]string{
			"rooms":        {"read": rule, "write": "everyone"},
			"room_members": {"all": rule},
			"messages":     {"all": rule},
		}},
	}
	t.Cleanup(app.Shutdown)
	names, err := GetTableNames(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		cols, err := GetTableColumns(db, name)
		if err != nil {
			t.Fatal(err)
		}
		app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
	}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	return app, mux
}

func TestMemberOfSelfScopedMembershipTableStaysInRoom(t *testing.T) {
	app, mux := memberOfSelfScopeApp(t)
	owner := createCrudScopeSession(t, app, "owner@example.com", "user", "", "")
	victim := createCrudScopeSession(t, app, "victim@example.com", "user", "", "")
	attacker := createCrudScopeSession(t, app, "attacker@example.com", "user", "", "")
	// Users 1-3. Room 1: owner + victim, with a private message. Room 2:
	// the attacker's own room, so the attacker holds one live membership.
	for _, stmt := range []string{
		`INSERT INTO rooms (id, name, user_id) VALUES (1, 'private-room', 1), (2, 'my-room', 3)`,
		`INSERT INTO room_members (id, room_id, member_id, user_id) VALUES (1, 1, 1, 1), (2, 1, 2, 1), (3, 2, 3, 3)`,
		`INSERT INTO messages (id, room_id, body, user_id) VALUES (1, 1, 'launch code 1234', 1)`,
	} {
		mustExec(t, app.DB, stmt)
	}

	assertListIDs(t, mux, attacker, "/api/room_members", []float64{3})
	assertListIDs(t, mux, owner, "/api/room_members", []float64{2, 1})
	for _, path := range []string{"/api/room_members/1", "/api/room_members/2"} {
		if rec := crudScopeRequest(t, mux, "GET", path, attacker, nil); rec.Code != http.StatusNotFound {
			t.Errorf("attacker read %s outside their rooms: HTTP %d %s", path, rec.Code, rec.Body.String())
		}
	}

	repoint := crudScopeRequest(t, mux, "PATCH", "/api/room_members/2", attacker, map[string]any{"member_id": 3})
	if repoint.Code != http.StatusNotFound {
		t.Errorf("attacker repointed room 1's membership row: HTTP %d %s", repoint.Code, repoint.Body.String())
	}
	var member int64
	if err := app.DB.QueryRow(`SELECT member_id FROM room_members WHERE id = 2`).Scan(&member); err != nil || member != 2 {
		t.Fatalf("room 1's membership row changed: member_id=%d err=%v", member, err)
	}
	if rec := crudScopeRequest(t, mux, "DELETE", "/api/room_members/1", attacker, nil); rec.Code != http.StatusNotFound {
		t.Errorf("attacker deleted room 1's owner membership: HTTP %d %s", rec.Code, rec.Body.String())
	}
	if rec := crudScopeRequest(t, mux, "GET", "/api/messages", attacker, nil); strings.Contains(rec.Body.String(), "launch code") {
		t.Errorf("attacker read room 1's messages: %s", rec.Body.String())
	}

	// A member of room 1 keeps the roster rights the rule grants.
	if rec := crudScopeRequest(t, mux, "PATCH", "/api/room_members/2", victim, map[string]any{"member_id": 2}); rec.Code != http.StatusOK {
		t.Errorf("room 1 member could not update room 1's roster: HTTP %d %s", rec.Code, rec.Body.String())
	}
}

func TestMemberOfPredicateAliasesTheMembershipTable(t *testing.T) {
	app := memberOfTestApp()
	app.Tables = append(app.Tables, Table{Name: "room_members", Columns: []Column{{Name: "id"}, {Name: "room_id"}, {Name: "member_id"}, {Name: "deleted_at"}}})
	app.Access.rules["room_members"] = map[AccessOp]string{"all": "member-of:room_members(room_id, member_id)"}
	user := &Session{Role: "user", UserID: 2, Email: "u@x", Verified: true}
	pred, _, _ := rowScopeClause(app, "room_members", user, "view")
	if !strings.Contains(pred, `main."room_members"."room_id"`) {
		t.Fatalf("the outer row must be referenced by its table: %q", pred)
	}
	inner := pred[strings.Index(pred, "EXISTS"):]
	inner = inner[:strings.Index(inner, ") OR")]
	if strings.Count(inner, `main."room_members"`) != 2 {
		t.Errorf("the membership table must be aliased inside the EXISTS (FROM + one outer reference): %q", inner)
	}
}
