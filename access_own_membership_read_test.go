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

// A member whose membership is switched off (groups.active_field), and who is
// in no other tenant, reads the membership rows that name them: the list a
// "your access was switched off" screen shows. Before, they read such a row
// only when the row's user_id was also theirs, which a roster keyed by its
// own member column (member_id, an address) never is.
//
// The read is all it gives. These tests pin that it changes and deletes
// nothing, reaches no other member's row and no tenant row, confers no tenant
// and no tenant role, and leaves live members, admins and stepped-in admins
// exactly where they were.

// ownMembershipApp serves a workspace app whose roster names its members in
// userField ("member_id", or "member_email" for an address-keyed roster) and
// has no user_id column. sites, docs and reports carry the tenant key; the
// roster points at a site and at its workspace (the tenant root).
func ownMembershipApp(t *testing.T, userField string, rules map[string]map[AccessOp]string) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("versioned: [workspace_members]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, stmt := range []string{
		`CREATE TABLE workspaces (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, name TEXT)`,
		`CREATE TABLE sites (id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id INTEGER, name TEXT)`,
		`CREATE TABLE workspace_members (id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id INTEGER REFERENCES workspaces(id), site_id INTEGER REFERENCES sites(id), member_id INTEGER, member_email TEXT, member_role TEXT, active INTEGER DEFAULT 1, note TEXT, deleted_at TEXT)`,
		`CREATE TABLE docs (id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id INTEGER, user_id INTEGER, title TEXT)`,
		`CREATE TABLE reports (id INTEGER PRIMARY KEY AUTOINCREMENT, workspace_id INTEGER, title TEXT)`,
	} {
		crudScopeMustExec(t, db, stmt)
	}
	if rules == nil {
		rules = map[string]map[AccessOp]string{}
	}
	if _, ok := rules["reports"]; !ok {
		rules["reports"] = map[AccessOp]string{"all": "role:manager"}
	}
	app := &App{
		Dir:             dir,
		DB:              db,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Group: &GroupConfig{
			Table: "workspace_members", Key: "workspace_id", UserField: userField, RoleField: "member_role", ActiveField: "active",
			Bootstrap: &GroupBootstrapConfig{OrgTable: "workspaces", FoundingRole: "owner"},
		},
		Access: &AccessConfig{rules: rules},
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
	if err := InstallVersioningTriggers(db, &VersionedConfig{Tables: []string{"workspace_members"}}); err != nil {
		t.Fatal(err)
	}
	app.JoinMap = BuildJoinMap(db)
	return app, buildAppMux(app, true, "http://localhost")
}

// seedOwnMembershipRoster signs four accounts in and writes two workspaces:
//
//	abe (1) founded workspace 1 and is a live manager of it
//	sam (2) is switched off in workspace 1 and in workspace 2: no live membership
//	kim (3) is switched off in workspace 1, and nothing else
//	lee (4) is live in workspace 2 and switched off in workspace 1
//
// Roster rows: 1 abe/ws1, 2 sam/ws1 (off), 3 kim/ws1 (off), 4 lee/ws2,
// 5 lee/ws1 (off), 6 sam/ws2 (off), 7 sam/ws1 (off, soft-deleted).
func seedOwnMembershipRoster(t *testing.T, app *App) (abe, sam, kim, lee string) {
	t.Helper()
	abe = createCrudScopeSession(t, app, "abe@example.com", "user", "", "")
	sam = createCrudScopeSession(t, app, "sam@example.com", "user", "", "")
	kim = createCrudScopeSession(t, app, "kim@example.com", "user", "", "")
	lee = createCrudScopeSession(t, app, "lee@example.com", "user", "", "")
	for _, stmt := range []string{
		`INSERT INTO workspaces (id, user_id, name) VALUES (1, 1, 'ws-one-name'), (2, 9, 'ws-two-name')`,
		`INSERT INTO sites (id, workspace_id, name) VALUES (1, 1, 'site-one-name'), (2, 2, 'site-two-name')`,
		`INSERT INTO workspace_members (id, workspace_id, site_id, member_id, member_email, member_role, active, note, deleted_at) VALUES
			(1, 1, 1, 1, 'abe@example.com', 'manager', 1, 'abe-first-note', NULL),
			(2, 1, 1, 2, 'sam@example.com', 'manager', 0, 'sam-first-note', NULL),
			(3, 1, 1, 3, 'kim@example.com', 'manager', 0, 'kim-note', NULL),
			(4, 2, 2, 4, 'lee@example.com', 'manager', 1, 'lee-note', NULL),
			(5, 1, 1, 4, 'lee@example.com', 'manager', 0, 'lee-off-note', NULL),
			(6, 2, 2, 2, 'sam@example.com', 'owner', 0, 'sam-two-note', NULL),
			(7, 1, 1, 2, 'sam@example.com', 'manager', 0, 'sam-gone-note', '2026-01-01')`,
		`INSERT INTO docs (id, workspace_id, user_id, title) VALUES (1, 1, 2, 'sam-made-doc'), (2, 1, 1, 'abe-made-doc')`,
		`INSERT INTO reports (id, workspace_id, title) VALUES (1, 1, 'ws-one-report')`,
		// Rows 1 and 2 have a version to read and to revert to.
		`UPDATE workspace_members SET note = 'abe-note' WHERE id = 1`,
		`UPDATE workspace_members SET note = 'sam-note' WHERE id = 2`,
	} {
		crudScopeMustExec(t, app.DB, stmt)
	}
	if n := tenantlessCount(t, app, `SELECT COUNT(*) FROM workspace_members_history WHERE id IN (1, 2)`); n < 2 {
		t.Fatalf("fixture rows have no version: %d history rows", n)
	}
	return abe, sam, kim, lee
}

// ownMembershipShapes are the rosters and read rules under which a live
// member reads the roster through the tenant, so a switched-off member reads
// the rows that name them.
var ownMembershipShapes = []struct {
	name, userField, rosterRead string
}{
	{"member id, no rule", "member_id", ""},
	{"member id, group", "member_id", "group"},
	{"member id, member-of the roster", "member_id", "member-of:workspace_members(workspace_id, member_id)"},
	{"address, no rule", "member_email", ""},
	{"address, group", "member_email", "group"},
}

func ownMembershipRules(rosterRead string) map[string]map[AccessOp]string {
	rules := map[string]map[AccessOp]string{}
	if rosterRead != "" {
		rules["workspace_members"] = map[AccessOp]string{"read": rosterRead}
	}
	return rules
}

func TestSwitchedOffMemberReadsOwnMembershipRows(t *testing.T) {
	for _, shape := range ownMembershipShapes {
		t.Run(shape.name, func(t *testing.T) {
			app, mux := ownMembershipApp(t, shape.userField, ownMembershipRules(shape.rosterRead))
			_, sam, kim, _ := seedOwnMembershipRoster(t, app)

			// Exactly the rows that name her, in whichever workspace, live
			// or not; never the soft-deleted one, never another member's.
			assertListedIDs(t, mux, sam, "/api/workspace_members", []int{2, 6})
			assertListedIDs(t, mux, kim, "/api/workspace_members", []int{3})
			for id, want := range map[int]int{1: 404, 2: 200, 3: 404, 4: 404, 5: 404, 6: 200, 7: 404} {
				assertStatus(t, mux, http.MethodGet, fmt.Sprintf("/api/workspace_members/%d", id), sam, nil, want)
			}
			query := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", sam, map[string]any{"table": "workspace_members"})
			if ids := listedIDs(t, query); fmt.Sprint(ids) != "[2 6]" {
				t.Errorf("/api/_query workspace_members rows %v, want [2 6]: %s", ids, query.Body.String())
			}
			count := crudScopeRequest(t, mux, http.MethodGet, "/api/workspace_members?count=true", sam, nil)
			if !strings.Contains(count.Body.String(), `"count":2`) {
				t.Errorf("?count=true: HTTP %d %s", count.Code, count.Body.String())
			}
			// A filter cannot reach past the scope.
			assertListedIDs(t, mux, sam, "/api/workspace_members?workspace_id=1", []int{2})
			assertListedIDs(t, mux, sam, "/api/workspace_members?note=kim-note", []int{})
			for _, path := range []string{"/api/workspace_members", "/api/workspace_members?q=note", "/api/_my-data"} {
				body := crudScopeRequest(t, mux, http.MethodGet, path, sam, nil).Body.String()
				for _, other := range []string{"abe-note", "kim-note", "lee-note", "lee-off-note", "sam-gone-note"} {
					if strings.Contains(body, other) {
						t.Errorf("GET %s answers with another row (%s): %s", path, other, body)
					}
				}
			}
		})
	}
}

// The read changes nothing: she may not switch herself back on, edit, delete,
// lock or share the row, through any write route.
func TestSwitchedOffMemberCannotChangeOwnMembershipRow(t *testing.T) {
	for _, shape := range ownMembershipShapes {
		t.Run(shape.name, func(t *testing.T) {
			app, mux := ownMembershipApp(t, shape.userField, ownMembershipRules(shape.rosterRead))
			_, sam, _, _ := seedOwnMembershipRoster(t, app)
			assertStatus(t, mux, http.MethodGet, "/api/workspace_members/2", sam, nil, http.StatusOK)
			for _, call := range []struct {
				method, path string
				body         any
			}{
				{http.MethodPatch, "/api/workspace_members/2", map[string]any{"active": 1}},
				{http.MethodPatch, "/api/workspace_members/2", map[string]any{"note": "changed"}},
				{http.MethodPatch, "/api/workspace_members/2", map[string]any{"member_role": "owner"}},
				{http.MethodDelete, "/api/workspace_members/2", nil},
				{http.MethodPost, "/api/workspace_members/2/lock", nil},
				{http.MethodPost, "/api/workspace_members/2/share", map[string]any{"email": "kim@example.com", "permission": "view"}},
				{http.MethodPost, "/api/workspace_members/2/revert/1", nil},
				{http.MethodPost, "/api/workspace_members/batch", map[string]any{"update": []map[string]any{{"id": 2, "active": 1}}}},
				{http.MethodPost, "/api/workspace_members/batch", map[string]any{"delete": []int{2}}},
				{http.MethodPost, "/api/_transaction", map[string]any{"operations": []map[string]any{{"action": "update", "table": "workspace_members", "id": 2, "data": map[string]any{"active": 1}}}}},
				{http.MethodPost, "/api/_transaction", map[string]any{"operations": []map[string]any{{"action": "delete", "table": "workspace_members", "id": 2}}}},
			} {
				rec := crudScopeRequest(t, mux, call.method, call.path, sam, call.body)
				if rec.Code >= 200 && rec.Code < 300 && !strings.Contains(rec.Body.String(), `"error"`) && !strings.Contains(rec.Body.String(), `"failed":1`) {
					t.Errorf("switched-off member, %s %s %v: HTTP %d %s", call.method, call.path, call.body, rec.Code, rec.Body.String())
				}
			}
			if n := tenantlessCount(t, app, `SELECT COUNT(*) FROM workspace_members WHERE id = 2 AND active = 0 AND note = 'sam-note' AND member_role = 'manager' AND deleted_at IS NULL`); n != 1 {
				t.Fatal("the switched-off member changed or deleted her membership row")
			}
			if n := tenantlessCount(t, app, `SELECT COUNT(*) FROM _benmore_permissions WHERE resource_type = 'workspace_members'`); n != 0 {
				t.Fatal("the switched-off member shared her membership row")
			}
			if locked, _ := CheckLock(app.DB, "workspace_members", "2", 0); locked {
				t.Fatal("the switched-off member locked her membership row")
			}
		})
	}
}

// A switched-off membership confers no tenant and no tenant role, and the
// row she reads opens no tenant row: not through a list, a read, an include,
// a signed URL or a change event.
func TestSwitchedOffMembershipConfersNoTenantAndNoRole(t *testing.T) {
	for _, shape := range ownMembershipShapes {
		t.Run(shape.name, func(t *testing.T) {
			app, mux := ownMembershipApp(t, shape.userField, ownMembershipRules(shape.rosterRead))
			abe, sam, _, _ := seedOwnMembershipRoster(t, app)
			assertListedIDs(t, mux, sam, "/api/workspace_members", []int{2, 6})

			session := getSession(app, tenantlessBearerRequest(sam))
			if session == nil {
				t.Fatal("no session")
			}
			if session.HasGroup() || session.EffectiveHasGroup() {
				t.Fatalf("a switched-off membership gave the session tenant %q", session.EffectiveGroupID())
			}
			if HasAnyRole(session, []string{"manager"}) || HasAnyRole(session, []string{"owner"}) {
				t.Fatalf("a switched-off membership gave the session a tenant role: %v", session.Roles)
			}

			// No tenant row, her own doc included; the role-gated table
			// answers like a route that does not exist.
			assertListedIDs(t, mux, sam, "/api/docs", []int{})
			assertListedIDs(t, mux, sam, "/api/sites", []int{})
			assertListedIDs(t, mux, sam, "/api/workspaces", []int{})
			for _, path := range []string{"/api/docs/1", "/api/docs/2", "/api/sites/1", "/api/sites/2", "/api/workspaces/1", "/api/workspaces/2", "/api/reports", "/api/reports/1"} {
				assertStatus(t, mux, http.MethodGet, path, sam, nil, http.StatusNotFound)
			}
			// Nor may she create one in the workspace her row names.
			for _, call := range []struct {
				path string
				body map[string]any
			}{
				{"/api/reports", map[string]any{"workspace_id": 1, "title": "hers"}},
				{"/api/sites", map[string]any{"workspace_id": 1, "name": "hers"}},
				{"/api/workspace_members", map[string]any{"workspace_id": 1, "member_id": 2, "member_email": "sam@example.com", "active": 1}},
			} {
				if rec := crudScopeRequest(t, mux, http.MethodPost, call.path, sam, call.body); rec.Code < 400 {
					t.Errorf("switched-off member, POST %s: HTTP %d %s", call.path, rec.Code, rec.Body.String())
				}
			}
			if n := tenantlessCount(t, app, `SELECT (SELECT COUNT(*) FROM reports WHERE workspace_id = 1) + (SELECT COUNT(*) FROM sites WHERE workspace_id = 1) + (SELECT COUNT(*) FROM workspace_members WHERE workspace_id = 1)`); n != 1+1+5 {
				t.Fatalf("a switched-off member wrote into the workspace: %d rows, want 7", n)
			}

			// ?include= expands neither the workspace nor the site (a live
			// member gets both).
			live := crudScopeRequest(t, mux, http.MethodGet, "/api/workspace_members/1?include=workspace,site", abe, nil).Body.String()
			if !strings.Contains(live, "ws-one-name") || !strings.Contains(live, "site-one-name") {
				t.Fatalf("a live member's include expands nothing: %s", live)
			}
			for _, path := range []string{
				"/api/workspace_members?include=workspace,site", "/api/workspace_members/2?include=workspace,site",
				"/api/workspace_members?include=workspace", "/api/workspace_members?include=site",
			} {
				rec := crudScopeRequest(t, mux, http.MethodGet, path, sam, nil)
				if body := rec.Body.String(); strings.Contains(body, "ws-one-name") || strings.Contains(body, "ws-two-name") || strings.Contains(body, "site-one-name") || strings.Contains(body, "site-two-name") {
					t.Errorf("GET %s expands a tenant row: HTTP %d %s", path, rec.Code, body)
				}
			}
			if authorizeRecordReadForSigning(tenantlessBearerRequest(sam), app, "docs", "1") || authorizeRecordReadForSigning(tenantlessBearerRequest(sam), app, "sites", "1") {
				t.Error("a switched-off member may sign a file of a tenant row")
			}

			// The roster's change events still skip a client with no tenant,
			// her own row's included.
			if skip, _ := realtimeAudienceFor(app, "workspace_members", "1", 0).classify(false, session.EffectiveGroupID(), session.UserID); !skip {
				t.Error("a switched-off member is in the realtime audience of the workspace roster")
			}
			if skip, _ := realtimeAudienceFor(app, "docs", "1", session.UserID).classify(false, session.EffectiveGroupID(), session.UserID); !skip {
				t.Error("a switched-off member is in the realtime audience of a workspace row")
			}
		})
	}
}

// Live members, admins and stepped-in admins read what they read before: the
// roster of the tenant they are in, and no row of another one, their own
// switched-off row there included.
func TestOwnMembershipReadLeavesOtherCallersUnchanged(t *testing.T) {
	for _, shape := range ownMembershipShapes {
		t.Run(shape.name, func(t *testing.T) {
			app, mux := ownMembershipApp(t, shape.userField, ownMembershipRules(shape.rosterRead))
			abe, _, _, lee := seedOwnMembershipRoster(t, app)
			admin := createCrudScopeSession(t, app, "root@example.com", "admin", "", "")    // user 5
			stepped := createCrudScopeSession(t, app, "step@example.com", "admin", "", "2") // user 6, stepped into workspace 2
			crudScopeMustExec(t, app.DB, `INSERT INTO workspace_members (id, workspace_id, site_id, member_id, member_email, member_role, active, note) VALUES
				(8, 1, 1, 5, 'root@example.com', 'manager', 0, 'root-off-note'),
				(9, 1, 1, 6, 'step@example.com', 'manager', 0, 'step-off-note')`)

			// A live member: the roster of the workspace they are in (the
			// soft-deleted row never lists).
			assertListedIDs(t, mux, abe, "/api/workspace_members", []int{1, 2, 3, 5, 8, 9})
			// Live in workspace 2, switched off in workspace 1: workspace 2
			// only. Her switched-off row is not added to it.
			assertListedIDs(t, mux, lee, "/api/workspace_members", []int{4, 6})
			assertStatus(t, mux, http.MethodGet, "/api/workspace_members/5", lee, nil, http.StatusNotFound)
			assertStatus(t, mux, http.MethodGet, "/api/workspace_members/4", lee, nil, http.StatusOK)
			// An admin reads every row.
			assertListedIDs(t, mux, admin, "/api/workspace_members", []int{1, 2, 3, 4, 5, 6, 8, 9})
			// Stepped into workspace 2, an admin reads workspace 2: not the
			// switched-off row that names them in workspace 1.
			// (A roster scoped by its own membership admits members only.)
			steppedSees := []int{4, 6}
			if strings.HasPrefix(shape.rosterRead, "member-of:") {
				steppedSees = []int{}
			}
			assertListedIDs(t, mux, stepped, "/api/workspace_members", steppedSees)
			assertStatus(t, mux, http.MethodGet, "/api/workspace_members/9", stepped, nil, http.StatusNotFound)
			assertStatus(t, mux, http.MethodGet, "/api/workspace_members/1", stepped, nil, http.StatusNotFound)
		})
	}
}

// An address-keyed roster names the member by address: only an account that
// has proven the address reads the row, and never by a column other than
// groups.user_field.
func TestOwnMembershipReadNeedsTheProvenMemberValue(t *testing.T) {
	app, mux := ownMembershipApp(t, "member_email", nil)
	_, sam, kim, _ := seedOwnMembershipRoster(t, app)
	crudScopeMustExec(t, app.DB, `UPDATE _benmore_users SET verified = 0, email_grandfathered = 0 WHERE email = 'kim@example.com'`)
	// The row carries kim's user id in member_id, which is not the member
	// column here, and sam's address in a row that names kim.
	crudScopeMustExec(t, app.DB, `UPDATE workspace_members SET member_id = 2 WHERE id = 3`)
	assertListedIDs(t, mux, kim, "/api/workspace_members", []int{})
	assertStatus(t, mux, http.MethodGet, "/api/workspace_members/3", kim, nil, http.StatusNotFound)
	assertListedIDs(t, mux, sam, "/api/workspace_members", []int{2, 6})
	assertStatus(t, mux, http.MethodGet, "/api/workspace_members/3", sam, nil, http.StatusNotFound)
}

// Where the roster's read rule is the builder's own owner rule (`self`,
// `owner_or_role:`), or closes the table to the caller (`admin`, `off`, a
// role they do not hold), that rule decides, as for a live member: a
// switched-off member never reads more than a live one would.
func TestOwnMembershipReadFollowsTheRosterRule(t *testing.T) {
	for _, tc := range []struct {
		mode string
		want int // the status of the list
	}{
		{"admin", http.StatusNotFound},
		{"off", http.StatusNotFound},
		{"role:manager", http.StatusNotFound},
		{"owner_or_role:manager", http.StatusOK},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			app, mux := ownMembershipApp(t, "member_id", ownMembershipRules(tc.mode))
			_, sam, _, _ := seedOwnMembershipRoster(t, app)
			rec := crudScopeRequest(t, mux, http.MethodGet, "/api/workspace_members", sam, nil)
			if rec.Code != tc.want {
				t.Fatalf("list: HTTP %d %s, want %d", rec.Code, rec.Body.String(), tc.want)
			}
			if ids := listedIDs(t, rec); len(ids) != 0 {
				t.Fatalf("list answers %v, want no row", ids)
			}
			assertStatus(t, mux, http.MethodGet, "/api/workspace_members/2", sam, nil, http.StatusNotFound)
		})
	}
	// A `role:` gate the caller passes (a role held globally; a switched-off
	// membership gives none) is a roster a live holder reads tenant-wide: the
	// switched-off holder reads the row that names them, and only that.
	app, mux := ownMembershipApp(t, "member_id", ownMembershipRules("role:manager"))
	seedOwnMembershipRoster(t, app)
	maxToken := createCrudScopeSession(t, app, "max@example.com", "manager", "", "") // user 5
	crudScopeMustExec(t, app.DB, `INSERT INTO workspace_members (id, workspace_id, site_id, member_id, member_email, member_role, active, note) VALUES (10, 1, 1, 5, 'max@example.com', 'member', 0, 'max-note')`)
	assertListedIDs(t, mux, maxToken, "/api/workspace_members", []int{10})
	assertStatus(t, mux, http.MethodGet, "/api/workspace_members/2", maxToken, nil, http.StatusNotFound)
	assertListedIDs(t, mux, maxToken, "/api/docs", []int{})
}

// describe states the read, on the roster and nowhere else.
func TestDescribeStatesTheOwnMembershipRead(t *testing.T) {
	const want = "the membership rows that name them"
	for _, shape := range ownMembershipShapes {
		app, _ := ownMembershipApp(t, shape.userField, ownMembershipRules(shape.rosterRead))
		access := describeTableAccess(app, "workspace_members")
		if effect, _ := access["read"]["effect"].(string); !strings.Contains(effect, want) {
			t.Errorf("%s: read effect %q does not say %q", shape.name, effect, want)
		}
		for _, op := range []string{"update", "delete"} {
			if effect, _ := access[op]["effect"].(string); strings.Contains(effect, want) {
				t.Errorf("%s: %s effect %q claims the read", shape.name, op, effect)
			}
		}
		for _, table := range []string{"docs", "sites", "reports"} {
			if effect, _ := describeTableAccess(app, table)["read"]["effect"].(string); strings.Contains(effect, want) {
				t.Errorf("%s: %s read effect %q claims the read", shape.name, table, effect)
			}
		}
	}
	// Not under the roster rules that leave it to the owner tier or close
	// the table (team_members has a user_id column, so `self` is the owner
	// rule there).
	for _, mode := range []string{"self", "owner_or_role:manager", "admin", "off"} {
		app, _ := tenantlessOwnerAppWithRules(t, map[string]map[AccessOp]string{"team_members": {"all": mode}})
		if effect, _ := describeTableAccess(app, "team_members")["read"]["effect"].(string); strings.Contains(effect, want) {
			t.Errorf("read: %s: effect %q claims the read", mode, effect)
		}
	}
}

// With the roster's writes open to every signed-in user (declared rules, so
// only the row scope stands between her and the row), the row she reads is
// still not hers to change or delete: the read is the view scope alone.
func TestOwnMembershipReadIsNotAWriteScope(t *testing.T) {
	for _, userField := range []string{"member_id", "member_email"} {
		t.Run(userField, func(t *testing.T) {
			app, mux := ownMembershipApp(t, userField, map[string]map[AccessOp]string{
				"workspace_members": {"read": "group", "update": "everyone", "delete": "everyone"},
			})
			_, sam, _, _ := seedOwnMembershipRoster(t, app)
			assertListedIDs(t, mux, sam, "/api/workspace_members", []int{2, 6})
			assertStatus(t, mux, http.MethodPatch, "/api/workspace_members/2", sam, map[string]any{"note": "changed"}, http.StatusNotFound)
			assertStatus(t, mux, http.MethodPatch, "/api/workspace_members/2", sam, map[string]any{"active": 1}, http.StatusNotFound)
			assertStatus(t, mux, http.MethodDelete, "/api/workspace_members/2", sam, nil, http.StatusNotFound)
			for _, body := range []map[string]any{
				{"update": []map[string]any{{"id": 2, "note": "changed"}}},
				{"delete": []int{2}},
			} {
				crudScopeRequest(t, mux, http.MethodPost, "/api/workspace_members/batch", sam, body)
			}
			for _, op := range []map[string]any{
				{"action": "update", "table": "workspace_members", "id": 2, "data": map[string]any{"note": "changed"}},
				{"action": "delete", "table": "workspace_members", "id": 2},
			} {
				if rec := crudScopeRequest(t, mux, http.MethodPost, "/api/_transaction", sam, map[string]any{"operations": []map[string]any{op}}); rec.Code == http.StatusOK {
					t.Errorf("/api/_transaction %v: HTTP %d %s", op, rec.Code, rec.Body.String())
				}
			}
			assertStatus(t, mux, http.MethodPost, "/api/workspace_members/2/revert/1", sam, nil, http.StatusNotFound)
			for path, body := range map[string]any{
				"/api/workspace_members/2/lock":  nil,
				"/api/workspace_members/2/share": map[string]any{"email": "kim@example.com", "permission": "view"},
			} {
				if rec := crudScopeRequest(t, mux, http.MethodPost, path, sam, body); rec.Code < 400 {
					t.Errorf("POST %s: HTTP %d %s", path, rec.Code, rec.Body.String())
				}
			}
			if n := tenantlessCount(t, app, `SELECT COUNT(*) FROM _benmore_permissions WHERE resource_type = 'workspace_members'`); n != 0 {
				t.Fatal("the switched-off member shared her membership row")
			}
			if n := tenantlessCount(t, app, `SELECT COUNT(*) FROM workspace_members WHERE id = 2 AND active = 0 AND note = 'sam-note' AND deleted_at IS NULL`); n != 1 {
				t.Fatal("the switched-off member changed or deleted her membership row")
			}
			if locked, _ := CheckLock(app.DB, "workspace_members", "2", 0); locked {
				t.Fatal("the switched-off member locked her membership row")
			}
		})
	}
}

// The side read routes of a row (its versions, its lock state, a signed file
// URL) keep their own table gate: under `group` a caller with no tenant is
// refused there before any row is looked at, and where the gate lets them
// call (a roster scoped by its own membership) they answer for the caller's
// own row and no other.
func TestOwnMembershipReadOnSideRoutes(t *testing.T) {
	for _, shape := range ownMembershipShapes {
		t.Run(shape.name, func(t *testing.T) {
			app, mux := ownMembershipApp(t, shape.userField, ownMembershipRules(shape.rosterRead))
			_, sam, _, _ := seedOwnMembershipRoster(t, app)
			own := http.StatusNotFound
			if strings.HasPrefix(shape.rosterRead, "member-of:") {
				own = http.StatusOK
			}
			for _, suffix := range []string{"/versions", "/versions/1", "/lock"} {
				assertStatus(t, mux, http.MethodGet, "/api/workspace_members/2"+suffix, sam, nil, own)
				assertStatus(t, mux, http.MethodGet, "/api/workspace_members/1"+suffix, sam, nil, http.StatusNotFound)
			}
			if got := authorizeRecordReadForSigning(tenantlessBearerRequest(sam), app, "workspace_members", "2"); got != (own == http.StatusOK) {
				t.Errorf("signing a file of her own row: %v", got)
			}
			if authorizeRecordReadForSigning(tenantlessBearerRequest(sam), app, "workspace_members", "1") {
				t.Error("she may sign a file of another member's row")
			}
			// Reverting is a write, whatever she reads.
			if rec := crudScopeRequest(t, mux, http.MethodPost, "/api/workspace_members/2/revert/1", sam, nil); rec.Code < 400 {
				t.Errorf("revert: HTTP %d %s", rec.Code, rec.Body.String())
			}
			if n := tenantlessCount(t, app, `SELECT COUNT(*) FROM workspace_members WHERE id = 2 AND note = 'sam-note'`); n != 1 {
				t.Fatal("she reverted her membership row")
			}
		})
	}
}
