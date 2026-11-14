//go:build !cli

package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

// A row of a tenant table belongs to its tenant. A caller with no tenant
// (removed from the team, or never in one) used to keep reading - and, under
// the owner-scoped modes, editing, deleting and sharing - every tenant row
// whose user_id was theirs, with the other members' later edits in it: the
// owner tier of rowScopeClause ran without the tenant clause whenever the
// caller had no tenant to compare. These tests walk the builder's sequence on
// every per-row surface and pin what is kept: rows explicitly shared with a
// tenant-less user, the global admin bypass, un-grouped tables, and the
// caller's own rows that carry no tenant.

// tenantlessOwnerApp serves a team app: team_members is the groups table
// (a member is live while `active` is on), docs carries the tenant key and
// user_id, bookmarks is an un-grouped owner table pointing at docs. docsRules
// are the access rules of docs.
func tenantlessOwnerApp(t *testing.T, docsRules map[AccessOp]string) (*App, *http.ServeMux) {
	t.Helper()
	rules := map[string]map[AccessOp]string{}
	if docsRules != nil {
		rules["docs"] = docsRules
	}
	return tenantlessOwnerAppWithRules(t, rules)
}

func tenantlessOwnerAppWithRules(t *testing.T, rules map[string]map[AccessOp]string) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte("versioned: [docs]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The only way to file a request to join a team: a signed-in user asks
	// for a team they are not in. The row carries that team's key and the
	// requester's user_id.
	if err := os.MkdirAll(filepath.Join(dir, "flows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flows", "join-request.yaml"), []byte(`on:
  request:
    method: POST
    path: /api/join-request
    auth: required
jobs:
  go:
    steps:
      - id: ins
        run: sql
        with:
          query: "INSERT INTO join_requests (team_id, user_id, status) VALUES (:team, :uid, 'pending') RETURNING id"
          params: { team: "${{ params.team_id }}", uid: "${{ user.id }}" }
      - run: respond
        with:
          status: 200
          json: { id: "${{ steps.ins.outputs.id }}" }
`), 0o644); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, stmt := range []string{
		`CREATE TABLE team_members (id INTEGER PRIMARY KEY AUTOINCREMENT, team_id INTEGER, user_id INTEGER, active INTEGER DEFAULT 1, note TEXT)`,
		`CREATE TABLE docs (id INTEGER PRIMARY KEY AUTOINCREMENT, team_id INTEGER, user_id INTEGER, title TEXT, body TEXT)`,
		`CREATE TABLE doc_members (id INTEGER PRIMARY KEY AUTOINCREMENT, team_id INTEGER, doc_id INTEGER, member_id INTEGER)`,
		`CREATE TABLE bookmarks (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, doc_id INTEGER REFERENCES docs(id), label TEXT)`,
		`CREATE TABLE join_requests (id INTEGER PRIMARY KEY AUTOINCREMENT, team_id INTEGER, user_id INTEGER, status TEXT)`,
	} {
		crudScopeMustExec(t, db, stmt)
	}
	app := &App{
		Dir:             dir,
		DB:              db,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Group:           &GroupConfig{Table: "team_members", Key: "team_id", UserField: "user_id", ActiveField: "active"},
		Access:          &AccessConfig{rules: rules},
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
	if err := InstallVersioningTriggers(db, &VersionedConfig{Tables: []string{"docs"}}); err != nil {
		t.Fatal(err)
	}
	app.JoinMap = BuildJoinMap(db)
	app.Flows = LoadFlowsGHA(dir)
	if len(app.Flows) != 1 {
		t.Fatalf("fixture flow did not load: %d flows", len(app.Flows))
	}
	return app, buildAppMux(app, true, "http://localhost")
}

// listedIDs returns the ids a list-shaped response carries (a JSON array, or
// the `rows` of a /api/_query answer), sorted; nil when the call was refused.
func listedIDs(t *testing.T, rec *httptest.ResponseRecorder) []int {
	t.Helper()
	if rec.Code != http.StatusOK {
		return nil
	}
	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		var wrapped struct {
			Rows []map[string]any `json:"rows"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &wrapped); err != nil {
			t.Fatalf("decode %q: %v", rec.Body.String(), err)
		}
		rows = wrapped.Rows
	}
	ids := []int{}
	for _, row := range rows {
		if id, ok := row["id"].(float64); ok {
			ids = append(ids, int(id))
		}
	}
	sort.Ints(ids)
	return ids
}

// assertListedIDs compares the ids a list answers with, in id order.
func assertListedIDs(t *testing.T, mux *http.ServeMux, token, path string, want []int) {
	t.Helper()
	rec := crudScopeRequest(t, mux, http.MethodGet, path, token, nil)
	if got := listedIDs(t, rec); got == nil || fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("GET %s lists %v, want %v: HTTP %d %s", path, got, want, rec.Code, rec.Body.String())
	}
}

// docsRulesFor is the access block of docs for one mode ("" = no rule: the
// implicit default of a table with user_id and the tenant key).
func docsRulesFor(mode string) map[AccessOp]string {
	if mode == "" {
		return nil
	}
	return map[AccessOp]string{"all": mode}
}

// The modes where the tenant decides: a caller with no tenant reaches, through
// user_id, only rows that carry no tenant. A rule declared `self` is the
// builder's own "the owner reaches their row" and is not among them.
var tenantlessOwnerModes = []string{"", "group", "owner_or_role:manager", "role:user"}

func tenantlessBearerRequest(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/api/_signed_url", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}

func tenantlessCount(t *testing.T, app *App, query string, args ...any) int {
	t.Helper()
	var n int
	if err := app.DB.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// The builder's sequence: a member creates a team row, another member edits
// it, the creator is removed from the team. On their next request no per-row
// surface answers with the row; re-adding the member restores access.
func TestRemovedMemberLosesTenantRowsOnEverySurface(t *testing.T) {
	for _, mode := range tenantlessOwnerModes {
		t.Run("mode="+mode, func(t *testing.T) {
			app, mux := tenantlessOwnerApp(t, docsRulesFor(mode))
			abe := createCrudScopeSession(t, app, "abe@example.com", "user", "1", "") // user 1
			ann := createCrudScopeSession(t, app, "ann@example.com", "user", "1", "") // user 2
			crudScopeMustExec(t, app.DB, `INSERT INTO team_members (team_id, user_id) VALUES (1, 1), (1, 2)`)

			created := crudScopeRequest(t, mux, http.MethodPost, "/api/docs", ann, map[string]any{"title": "ann-doc", "body": "ann v1"})
			if created.Code != http.StatusOK {
				t.Fatalf("member create: %d %s", created.Code, created.Body.String())
			}
			if n := tenantlessCount(t, app, `SELECT COUNT(*) FROM docs WHERE id = 1 AND team_id = 1 AND user_id = 2`); n != 1 {
				t.Fatalf("created row is not ann's row in team 1 (matches %d)", n)
			}
			// Another member's later edit. The owner-only modes refuse abe on
			// the API; there the edit stands for a manager's or a flow's.
			if rec := crudScopeRequest(t, mux, http.MethodPatch, "/api/docs/1", abe, map[string]any{"body": "abe-secret plans"}); rec.Code != http.StatusOK {
				crudScopeMustExec(t, app.DB, `UPDATE docs SET body = 'abe-secret plans' WHERE id = 1`)
			}
			assertStatus(t, mux, http.MethodPost, "/api/bookmarks", ann, map[string]any{"doc_id": 1, "label": "kept"}, http.StatusOK)

			// While she is a member everything answers.
			assertListIDs(t, mux, ann, "/api/docs", []float64{1})
			if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/docs/1", ann, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "abe-secret") {
				t.Fatalf("member read: %d %s", rec.Code, rec.Body.String())
			}
			if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/bookmarks?include=doc", ann, nil); !strings.Contains(rec.Body.String(), "abe-secret") {
				t.Fatalf("member include: %d %s", rec.Code, rec.Body.String())
			}
			assertStatus(t, mux, http.MethodGet, "/api/docs/1/versions", ann, nil, http.StatusOK)
			if !authorizeRecordReadForSigning(tenantlessBearerRequest(ann), app, "docs", "1") {
				t.Fatal("member may not sign a file of her own team row")
			}

			// Removed from the team: her next request has no tenant.
			crudScopeMustExec(t, app.DB, `DELETE FROM team_members WHERE user_id = 2`)

			for _, path := range []string{
				"/api/docs", "/api/docs/1", "/api/docs?q=secret", "/api/docs?title=ann-doc", "/api/docs?count=true",
				"/api/bookmarks?include=doc", "/api/bookmarks/1?include=doc", "/api/_my-data",
				"/api/docs/1/versions", "/api/docs/1/versions/1", "/api/docs/1/lock", "/api/docs/1?as_of=2999-01-01T00:00:00Z",
			} {
				rec := crudScopeRequest(t, mux, http.MethodGet, path, ann, nil)
				if body := rec.Body.String(); strings.Contains(body, "abe-secret") || strings.Contains(body, "ann-doc") || strings.Contains(body, `"count":1`) {
					t.Errorf("removed member, GET %s: HTTP %d %s", path, rec.Code, body)
				}
			}
			if ids := listedIDs(t, crudScopeRequest(t, mux, http.MethodGet, "/api/docs", ann, nil)); ids == nil || len(ids) != 0 {
				t.Errorf("removed member lists docs %v, want an empty page", ids)
			}
			assertStatus(t, mux, http.MethodGet, "/api/docs/1", ann, nil, http.StatusNotFound)
			assertStatus(t, mux, http.MethodGet, "/api/docs/1/versions", ann, nil, http.StatusNotFound)
			query := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", ann, map[string]any{"table": "docs"})
			if ids := listedIDs(t, query); ids == nil || len(ids) != 0 {
				t.Errorf("removed member, /api/_query: HTTP %d %s", query.Code, query.Body.String())
			}
			agg := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", ann, map[string]any{"table": "docs", "aggregates": []map[string]any{{"fn": "count", "as": "n"}}})
			if agg.Code != http.StatusOK || !strings.Contains(agg.Body.String(), `"n":0`) {
				t.Errorf("removed member, /api/_query count: HTTP %d %s", agg.Code, agg.Body.String())
			}
			if authorizeRecordReadForSigning(tenantlessBearerRequest(ann), app, "docs", "1") {
				t.Error("removed member may still sign a file of the team row")
			}
			// The team's change events skip a client with no tenant.
			if skip, _ := realtimeAudienceFor(app, "docs", "1", 2).classify(false, "", 2); !skip {
				t.Error("removed member is in the realtime audience of the team row")
			}
			// Nor may she lock, share, change or delete it.
			for _, call := range []struct {
				method, path string
				body         any
			}{
				{http.MethodPost, "/api/docs/1/lock", nil},
				{http.MethodPost, "/api/docs/1/share", map[string]any{"email": "ann@example.com", "permission": "admin"}},
				{http.MethodPatch, "/api/docs/1", map[string]any{"title": "changed"}},
				{http.MethodPatch, "/api/docs/batch", map[string]any{"ids": []any{1}, "fields": map[string]any{"title": "changed"}}},
				{http.MethodPost, "/api/docs/1/revert/1", nil},
				{http.MethodDelete, "/api/docs/1", nil},
			} {
				rec := crudScopeRequest(t, mux, call.method, call.path, ann, call.body)
				if rec.Code == http.StatusOK && call.path != "/api/docs/batch" {
					t.Errorf("removed member, %s %s: HTTP %d %s", call.method, call.path, rec.Code, rec.Body.String())
				}
			}
			if n := tenantlessCount(t, app, `SELECT COUNT(*) FROM docs WHERE id = 1 AND title = 'ann-doc' AND body = 'abe-secret plans'`); n != 1 {
				t.Error("the removed member changed or deleted the team row")
			}
			if n := tenantlessCount(t, app, `SELECT COUNT(*) FROM _benmore_permissions WHERE resource_type = 'docs'`); n != 0 {
				t.Errorf("the removed member created %d grant(s) on the team row", n)
			}
			if n := tenantlessCount(t, app, `SELECT COUNT(*) FROM _benmore_locks WHERE table_name = 'docs'`); n != 0 {
				t.Errorf("the removed member holds %d lock(s) on the team row", n)
			}

			// Back in the team: the row is hers to read and edit again.
			crudScopeMustExec(t, app.DB, `INSERT INTO team_members (team_id, user_id) VALUES (1, 2)`)
			assertListIDs(t, mux, ann, "/api/docs", []float64{1})
			if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/docs/1", ann, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "abe-secret") {
				t.Fatalf("re-added member read: %d %s", rec.Code, rec.Body.String())
			}
			assertStatus(t, mux, http.MethodPatch, "/api/docs/1", ann, map[string]any{"title": "ann-doc v2"}, http.StatusOK)
		})
	}
}

// What a caller with no tenant keeps on a tenant table: a row explicitly
// shared with them, and their own rows that carry no tenant (created before
// they joined or founded one).
func TestTenantlessCallerKeepsSharedAndTenantlessOwnRows(t *testing.T) {
	for _, mode := range tenantlessOwnerModes {
		t.Run("mode="+mode, func(t *testing.T) {
			app, mux := tenantlessOwnerApp(t, docsRulesFor(mode))
			_ = createCrudScopeSession(t, app, "abe@example.com", "user", "1", "")     // user 1, team 1
			nora := createCrudScopeSession(t, app, "nora@example.com", "user", "", "") // user 2, never in a team
			_ = createCrudScopeSession(t, app, "olaf@example.com", "user", "", "")     // user 3, never in a team
			for _, stmt := range []string{
				`INSERT INTO team_members (team_id, user_id) VALUES (1, 1)`,
				`INSERT INTO docs (id, team_id, user_id, title, body) VALUES
					(1, 1, 1, 'team-shared', 'shared with nora'),
					(2, 1, 1, 'team-private', 'not shared'),
					(3, 1, 2, 'team-row-nora-made', 'a team row whose user_id is nora'),
					(4, NULL, 2, 'nora-personal', 'no tenant'),
					(5, 0, 2, 'nora-personal-zero', 'tenant key 0 is no tenant'),
					(6, NULL, 3, 'olaf-personal', 'another user, no tenant')`,
				`INSERT INTO _benmore_permissions (resource_type, resource_id, grant_type, grantee_id, permission)
					VALUES ('docs', '1', 'user', 'nora@example.com', 'view')`,
			} {
				crudScopeMustExec(t, app.DB, stmt)
			}
			// (a) the shared row and (d) her rows without a tenant; not the
			// team row that only carries her user_id, not another user's.
			assertListedIDs(t, mux, nora, "/api/docs", []int{1, 4, 5})
			for id, want := range map[int]int{1: 200, 2: 404, 3: 404, 4: 200, 5: 200, 6: 404} {
				assertStatus(t, mux, http.MethodGet, fmt.Sprintf("/api/docs/%d", id), nora, nil, want)
			}
			query := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", nora, map[string]any{"table": "docs"})
			if ids := listedIDs(t, query); fmt.Sprint(ids) != "[1 4 5]" {
				t.Errorf("/api/_query rows %v, want [1 4 5]: %s", ids, query.Body.String())
			}
			// A view share does not let her edit; her own tenant-less row does.
			assertStatus(t, mux, http.MethodPatch, "/api/docs/3", nora, map[string]any{"title": "x"}, map[bool]int{true: 403, false: 404}[mode == "group"])
			if mode == "group" {
				// `group` writes need a tenant: unchanged.
				assertStatus(t, mux, http.MethodPost, "/api/docs", nora, map[string]any{"title": "new"}, http.StatusForbidden)
				return
			}
			assertStatus(t, mux, http.MethodPatch, "/api/docs/4", nora, map[string]any{"title": "nora-personal v2"}, http.StatusOK)
			created := crudScopeRequest(t, mux, http.MethodPost, "/api/docs", nora, map[string]any{"title": "nora-new"})
			if created.Code != http.StatusOK {
				t.Fatalf("tenant-less create: %d %s", created.Code, created.Body.String())
			}
			if n := tenantlessCount(t, app, `SELECT COUNT(*) FROM docs WHERE id = 7 AND team_id IS NULL AND user_id = 2`); n != 1 {
				t.Fatal("a tenant-less caller's new row should carry no tenant and her user_id")
			}
			assertListedIDs(t, mux, nora, "/api/docs", []int{1, 4, 5, 7})
			assertStatus(t, mux, http.MethodGet, "/api/docs/7", nora, nil, http.StatusOK)
			assertStatus(t, mux, http.MethodDelete, "/api/docs/7", nora, nil, http.StatusOK)

			// Once she joins team 1 the tenant clause bounds everything: the
			// team row she made is hers again, the rows without a tenant are
			// outside her tenant.
			crudScopeMustExec(t, app.DB, `INSERT INTO team_members (team_id, user_id) VALUES (1, 2)`)
			for id, want := range map[int]int{1: 200, 3: 200, 4: 404, 5: 404, 6: 404} {
				assertStatus(t, mux, http.MethodGet, fmt.Sprintf("/api/docs/%d", id), nora, nil, want)
			}
		})
	}
}

// Unchanged around the fix: an admin who bypasses row scope reads every row,
// an un-grouped table is owner-scoped for everyone, and a table declared
// `everyone` keeps its broad read (the owner tier still bounds its writes).
func TestTenantlessCallerUnchangedCases(t *testing.T) {
	seed := func(t *testing.T, app *App) {
		t.Helper()
		for _, stmt := range []string{
			`INSERT INTO team_members (team_id, user_id) VALUES (1, 1)`,
			`INSERT INTO docs (id, team_id, user_id, title, body) VALUES (1, 1, 1, 'abe-doc', 'x'), (2, 1, 2, 'team-row-ann-made', 'y'), (3, 2, 9, 'other-team', 'z')`,
			`INSERT INTO bookmarks (id, user_id, doc_id, label) VALUES (1, 1, 1, 'abe-mark'), (2, 2, 1, 'ann-mark')`,
		} {
			crudScopeMustExec(t, app.DB, stmt)
		}
	}
	t.Run("global admin bypass", func(t *testing.T) {
		app, mux := tenantlessOwnerApp(t, docsRulesFor("group"))
		_ = createCrudScopeSession(t, app, "abe@example.com", "user", "1", "")
		_ = createCrudScopeSession(t, app, "ann@example.com", "user", "", "")
		root := createCrudScopeSession(t, app, "root@example.com", "admin", "", "")
		seed(t, app)
		assertListedIDs(t, mux, root, "/api/docs", []int{1, 2, 3})
		assertStatus(t, mux, http.MethodGet, "/api/docs/3", root, nil, http.StatusOK)
	})
	t.Run("un-grouped table", func(t *testing.T) {
		app, mux := tenantlessOwnerApp(t, docsRulesFor("group"))
		_ = createCrudScopeSession(t, app, "abe@example.com", "user", "1", "")
		ann := createCrudScopeSession(t, app, "ann@example.com", "user", "", "")
		seed(t, app)
		assertListedIDs(t, mux, ann, "/api/bookmarks", []int{2})
		assertStatus(t, mux, http.MethodGet, "/api/bookmarks/2", ann, nil, http.StatusOK)
		assertStatus(t, mux, http.MethodGet, "/api/bookmarks/1", ann, nil, http.StatusNotFound)
		assertStatus(t, mux, http.MethodPatch, "/api/bookmarks/2", ann, map[string]any{"label": "renamed"}, http.StatusOK)
	})
	t.Run("everyone", func(t *testing.T) {
		app, mux := tenantlessOwnerApp(t, map[AccessOp]string{"read": "everyone", "write": "everyone", "update": "everyone", "delete": "everyone"})
		_ = createCrudScopeSession(t, app, "abe@example.com", "user", "1", "")
		ann := createCrudScopeSession(t, app, "ann@example.com", "user", "", "")
		seed(t, app)
		// The app declared every row readable by every signed-in user.
		assertListedIDs(t, mux, ann, "/api/docs", []int{1, 2, 3})
		// Writes stay row-scoped: no tenant, so not the team row she made.
		assertStatus(t, mux, http.MethodPatch, "/api/docs/2", ann, map[string]any{"title": "changed"}, http.StatusNotFound)
		assertStatus(t, mux, http.MethodDelete, "/api/docs/2", ann, nil, http.StatusNotFound)
	})
	t.Run("member-of", func(t *testing.T) {
		app, mux := tenantlessOwnerApp(t, docsRulesFor("member-of:doc_members(doc_id, member_id)"))
		_ = createCrudScopeSession(t, app, "abe@example.com", "user", "1", "")
		ann := createCrudScopeSession(t, app, "ann@example.com", "user", "", "")
		seed(t, app)
		crudScopeMustExec(t, app.DB, `INSERT INTO doc_members (team_id, doc_id, member_id) VALUES (1, 2, 2)`)
		// Membership counts only inside the caller's tenant.
		assertListedIDs(t, mux, ann, "/api/docs", []int{})
		assertStatus(t, mux, http.MethodGet, "/api/docs/2", ann, nil, http.StatusNotFound)
	})
}

// The groups membership table carries the tenant key too. A member whose
// membership is switched off has no tenant, and still reaches the one row
// that names them (a pending-invitation or "your access was switched off"
// screen lists it): nothing else of that table, and no other tenant table. A
// removed member has no row and reads nothing. What the switched-off member
// may change on their row is the membership gates' decision, as before: they
// may leave, and may not switch themselves back on.
func TestTenantlessMemberReachesOnlyOwnMembershipRow(t *testing.T) {
	for _, mode := range []string{"", "group", "self"} {
		t.Run("mode="+mode, func(t *testing.T) {
			rules := map[string]map[AccessOp]string{"docs": {"all": "group"}}
			if mode != "" {
				rules["team_members"] = map[AccessOp]string{"all": mode}
			}
			app, mux := tenantlessOwnerAppWithRules(t, rules)
			abe := createCrudScopeSession(t, app, "abe@example.com", "user", "1", "") // user 1, live member
			sam := createCrudScopeSession(t, app, "sam@example.com", "user", "1", "") // user 2, switched off
			rex := createCrudScopeSession(t, app, "rex@example.com", "user", "1", "") // user 3, removed
			for _, stmt := range []string{
				`INSERT INTO team_members (id, team_id, user_id, active) VALUES (1, 1, 1, 1), (2, 1, 2, 0), (3, 2, 9, 1)`,
				`INSERT INTO docs (id, team_id, user_id, title, body) VALUES (1, 1, 2, 'sam-made', 'team-secret'), (2, 1, 3, 'rex-made', 'team-secret')`,
			} {
				crudScopeMustExec(t, app.DB, stmt)
			}
			// A live member: the team's roster (their own row under `self`).
			roster := []int{1, 2}
			if mode == "self" {
				roster = []int{1}
			}
			assertListedIDs(t, mux, abe, "/api/team_members", roster)

			// Switched off: her own membership row, and only that.
			assertListedIDs(t, mux, sam, "/api/team_members", []int{2})
			assertStatus(t, mux, http.MethodGet, "/api/team_members/2", sam, nil, http.StatusOK)
			assertStatus(t, mux, http.MethodGet, "/api/team_members/1", sam, nil, http.StatusNotFound)
			assertStatus(t, mux, http.MethodGet, "/api/team_members/3", sam, nil, http.StatusNotFound)
			query := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", sam, map[string]any{"table": "team_members"})
			if ids := listedIDs(t, query); fmt.Sprint(ids) != "[2]" {
				t.Errorf("/api/_query team_members rows %v, want [2]: %s", ids, query.Body.String())
			}
			// Removed: no row names him.
			assertListedIDs(t, mux, rex, "/api/team_members", []int{})
			for _, id := range []int{1, 2, 3} {
				assertStatus(t, mux, http.MethodGet, fmt.Sprintf("/api/team_members/%d", id), rex, nil, http.StatusNotFound)
			}
			// Neither reads the team's other tables, their own rows included.
			for _, token := range []string{sam, rex} {
				assertListedIDs(t, mux, token, "/api/docs", []int{})
				assertStatus(t, mux, http.MethodGet, "/api/docs/1", token, nil, http.StatusNotFound)
				assertStatus(t, mux, http.MethodGet, "/api/docs/2", token, nil, http.StatusNotFound)
			}

			// She may not change another member's row or switch herself on.
			for _, call := range []struct {
				method, path string
				body         any
			}{
				{http.MethodPatch, "/api/team_members/2", map[string]any{"active": 1}},
				{http.MethodPatch, "/api/team_members/1", map[string]any{"active": 0}},
				{http.MethodDelete, "/api/team_members/1", nil},
			} {
				if rec := crudScopeRequest(t, mux, call.method, call.path, sam, call.body); rec.Code == http.StatusOK {
					t.Errorf("switched-off member, %s %s: HTTP %d %s", call.method, call.path, rec.Code, rec.Body.String())
				}
			}
			if n := tenantlessCount(t, app, `SELECT COUNT(*) FROM team_members WHERE (id = 1 AND active = 1) OR (id = 2 AND active = 0)`); n != 2 {
				t.Fatal("the switched-off member changed a membership row")
			}
			assertListedIDs(t, mux, sam, "/api/docs", []int{})
			// Leaving (deleting her own row) is the membership gate's call:
			// allowed unless the table's delete rule needs a tenant.
			wantLeave := map[string]int{"": http.StatusOK, "self": http.StatusOK, "group": http.StatusForbidden}[mode]
			assertStatus(t, mux, http.MethodDelete, "/api/team_members/2", sam, nil, wantLeave)
		})
	}
}

// An email-keyed membership table names the member by address, and its
// user_id (when it has one) is whoever created the row. A caller with no
// tenant reads the rows that name them, compared the way membership
// resolution compares: a proven address. Rows they created about other
// members stay with the tenant.
func TestTenantlessMemberOwnMembershipRowEmailKeyed(t *testing.T) {
	app, mux := tenantlessOwnerAppWithRules(t, map[string]map[AccessOp]string{})
	crudScopeMustExec(t, app.DB, `ALTER TABLE team_members ADD COLUMN email TEXT`)
	refreshTableColumns(t, app, "team_members")
	mux = rebuildTestMux(t, app, true, "http://localhost", func() {
		app.Group.UserField = "email"
	})
	_ = createCrudScopeSession(t, app, "abe@example.com", "user", "1", "")    // user 1
	sam := createCrudScopeSession(t, app, "sam@example.com", "user", "1", "") // user 2
	uma := createCrudScopeSession(t, app, "uma@example.com", "user", "1", "") // user 3, address not proven
	for _, stmt := range []string{
		`UPDATE _benmore_users SET verified = 0, email_grandfathered = 0 WHERE email = 'uma@example.com'`,
		`INSERT INTO team_members (id, team_id, email, user_id, active) VALUES
			(1, 1, 'abe@example.com', 1, 1),
			(2, 1, 'sam@example.com', 2, 0),
			(3, 1, 'kim@example.com', 2, 1),
			(4, 2, 'sam@example.com', 1, 0),
			(5, 1, 'uma@example.com', 3, 0)`,
	} {
		crudScopeMustExec(t, app.DB, stmt)
	}
	// Rows 2 and 4 name her (row 4 was written by another user, in another
	// team). Row 3 she created about someone else.
	assertListedIDs(t, mux, sam, "/api/team_members", []int{2, 4})
	for id, want := range map[int]int{1: 404, 2: 200, 3: 404, 4: 200, 5: 404} {
		assertStatus(t, mux, http.MethodGet, fmt.Sprintf("/api/team_members/%d", id), sam, nil, want)
	}
	assertStatus(t, mux, http.MethodGet, "/api/team_members/4/lock", sam, nil, http.StatusOK)
	// Reading row 4 is all she may do with it: its user_id is not hers.
	assertStatus(t, mux, http.MethodPatch, "/api/team_members/4", sam, map[string]any{"note": "changed"}, http.StatusNotFound)
	assertStatus(t, mux, http.MethodDelete, "/api/team_members/4", sam, nil, http.StatusNotFound)
	if n := tenantlessCount(t, app, `SELECT COUNT(*) FROM team_members WHERE id = 4 AND note IS NULL`); n != 1 {
		t.Fatal("she changed a membership row another user wrote")
	}
	// An address the account has not proven names nobody.
	assertListedIDs(t, mux, uma, "/api/team_members", []int{})
	assertStatus(t, mux, http.MethodGet, "/api/team_members/5", uma, nil, http.StatusNotFound)

	// A read rule declared `self` on the membership table is the builder's
	// own owner rule: every row whose user_id is theirs, as before.
	mux = rebuildTestMux(t, app, true, "http://localhost", func() {
		app.Access = &AccessConfig{rules: map[string]map[AccessOp]string{"team_members": {"read": "self"}}}
	})
	assertListedIDs(t, mux, sam, "/api/team_members", []int{2, 3})
}

// A rule declared `self` on a tenant-keyed table is the builder saying "the
// owner reaches their own row", whatever tenant the row names. The shape a
// production app uses it for: someone who is in no team asks to join one. The
// request carries that team's key and the requester's user_id; the requester
// tracks it (read: self) and may withdraw it (delete: self).
func TestDeclaredSelfKeepsOwnerRowsForCallerWithNoTenant_JoinRequest(t *testing.T) {
	app, mux := tenantlessOwnerAppWithRules(t, map[string]map[AccessOp]string{
		"join_requests": {"read": "self", "write": "off", "update": "off", "delete": "self"},
		"docs":          {"all": "group"},
	})
	_ = createCrudScopeSession(t, app, "abe@example.com", "user", "1", "")     // user 1, team 1
	nora := createCrudScopeSession(t, app, "nora@example.com", "user", "", "") // user 2, in no team
	olaf := createCrudScopeSession(t, app, "olaf@example.com", "user", "", "") // user 3, in no team
	for _, stmt := range []string{
		`INSERT INTO team_members (team_id, user_id) VALUES (1, 1)`,
		`INSERT INTO docs (id, team_id, user_id, title, body) VALUES (1, 1, 1, 'team-doc', 'team-secret')`,
		`INSERT INTO join_requests (id, team_id, user_id, status) VALUES (1, 1, 3, 'pending')`, // olaf's
	} {
		crudScopeMustExec(t, app.DB, stmt)
	}
	// Filed through the flow, the only write path.
	assertStatus(t, mux, http.MethodPost, "/api/join_requests", nora, map[string]any{"team_id": 1}, http.StatusNotFound)
	filed := crudScopeRequest(t, mux, http.MethodPost, "/api/join-request", nora, map[string]any{"team_id": 1})
	if filed.Code != http.StatusOK {
		t.Fatalf("join-request flow: %d %s", filed.Code, filed.Body.String())
	}
	if n := tenantlessCount(t, app, `SELECT COUNT(*) FROM join_requests WHERE id = 2 AND team_id = 1 AND user_id = 2`); n != 1 {
		t.Fatal("the flow did not file a request carrying team 1 and the requester's user_id")
	}
	// She lists and reads her request, not the other requester's, and no
	// other table of that team.
	assertListedIDs(t, mux, nora, "/api/join_requests", []int{2})
	assertListedIDs(t, mux, nora, "/api/join_requests?status=pending", []int{2})
	assertStatus(t, mux, http.MethodGet, "/api/join_requests/2", nora, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodGet, "/api/join_requests/1", nora, nil, http.StatusNotFound)
	assertListedIDs(t, mux, nora, "/api/docs", []int{})
	assertStatus(t, mux, http.MethodGet, "/api/docs/1", nora, nil, http.StatusNotFound)
	// update is off: the decision is not hers to write.
	if rec := crudScopeRequest(t, mux, http.MethodPatch, "/api/join_requests/2", nora, map[string]any{"status": "accepted"}); rec.Code == http.StatusOK {
		t.Fatalf("requester changed her own request: %d %s", rec.Code, rec.Body.String())
	}
	// She withdraws hers, and only hers.
	assertStatus(t, mux, http.MethodDelete, "/api/join_requests/1", nora, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodDelete, "/api/join_requests/2", nora, nil, http.StatusOK)
	if n := tenantlessCount(t, app, `SELECT COUNT(*) FROM join_requests`); n != 1 {
		t.Fatalf("join_requests holds %d rows after the withdrawal, want olaf's one", n)
	}
	assertListedIDs(t, mux, olaf, "/api/join_requests", []int{1})
}

// Under `self` a removed member keeps exactly the rows whose user_id is
// theirs, on every read surface, and nothing else of the team.
func TestDeclaredSelfRemovedMemberKeepsOnlyOwnRows(t *testing.T) {
	app, mux := tenantlessOwnerApp(t, docsRulesFor("self"))
	_ = createCrudScopeSession(t, app, "abe@example.com", "user", "1", "")    // user 1
	ann := createCrudScopeSession(t, app, "ann@example.com", "user", "1", "") // user 2
	crudScopeMustExec(t, app.DB, `INSERT INTO team_members (team_id, user_id) VALUES (1, 1), (1, 2)`)
	assertStatus(t, mux, http.MethodPost, "/api/docs", ann, map[string]any{"title": "ann-doc", "body": "ann-own"}, http.StatusOK)
	for _, stmt := range []string{
		`INSERT INTO docs (id, team_id, user_id, title, body) VALUES (2, 1, 1, 'abe-doc', 'abe-secret')`,
		`UPDATE docs SET body = 'abe-secret v2' WHERE id = 2`,
		`INSERT INTO bookmarks (id, user_id, doc_id, label) VALUES (1, 2, 1, 'own'), (2, 2, 2, 'abes')`,
		`DELETE FROM team_members WHERE user_id = 2`,
	} {
		crudScopeMustExec(t, app.DB, stmt)
	}
	assertListedIDs(t, mux, ann, "/api/docs", []int{1})
	assertStatus(t, mux, http.MethodGet, "/api/docs/1", ann, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodGet, "/api/docs/2", ann, nil, http.StatusNotFound)
	query := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", ann, map[string]any{"table": "docs"})
	if ids := listedIDs(t, query); fmt.Sprint(ids) != "[1]" {
		t.Errorf("/api/_query rows %v, want [1]: %s", ids, query.Body.String())
	}
	assertStatus(t, mux, http.MethodGet, "/api/docs/1/versions", ann, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodGet, "/api/docs/2/versions", ann, nil, http.StatusNotFound)
	assertStatus(t, mux, http.MethodPatch, "/api/docs/1", ann, map[string]any{"title": "ann-doc v2"}, http.StatusOK)
	assertStatus(t, mux, http.MethodPatch, "/api/docs/2", ann, map[string]any{"title": "taken"}, http.StatusNotFound)
	for _, path := range []string{
		"/api/docs", "/api/docs?q=secret", "/api/docs?count=true", "/api/bookmarks?include=doc", "/api/bookmarks/2?include=doc",
		"/api/_my-data", "/api/docs/2/versions/1", "/api/docs/2?as_of=2999-01-01T00:00:00Z",
	} {
		rec := crudScopeRequest(t, mux, http.MethodGet, path, ann, nil)
		if body := rec.Body.String(); strings.Contains(body, "abe-secret") || strings.Contains(body, "abe-doc") || strings.Contains(body, `"count":2`) {
			t.Errorf("removed member under self, GET %s: HTTP %d %s", path, rec.Code, body)
		}
	}
	// Her own row still expands through an include.
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/bookmarks/1?include=doc", ann, nil); !strings.Contains(rec.Body.String(), "ann-own") {
		t.Errorf("her own doc did not expand: %d %s", rec.Code, rec.Body.String())
	}
}

// What a member removed from the team (no tenant) reaches of a team row
// whose user_id is theirs, per rule. reads/edits are what this version
// answers; before the fix every mode but member-of answered reads=true, and
// every mode but member-of and `group` (whose table gate needs a tenant for
// writes) answered edits=true. The first version of the fix also bounded
// declared `self`.
//
//	rule on the table            before the fix    first version    this version
//	(none: implicit default)     read + edit       nothing          nothing
//	all: group                   read              nothing          nothing
//	all: self                    read + edit       nothing          read + edit
//	read: self, update: group    read              nothing          read
//	all: owner_or_role:manager   read + edit       nothing          nothing
//	all: role:user               read + edit       nothing          nothing
//	all: everyone                all rows + edit   all rows         all rows
//	all: member-of:...           nothing           nothing          nothing
func TestRemovedMemberOwnTenantRowPerRule(t *testing.T) {
	for _, c := range []struct {
		name         string
		rules        map[AccessOp]string
		reads, edits bool
	}{
		{"implicit default", nil, false, false},
		{"all group", map[AccessOp]string{"all": "group"}, false, false},
		{"all self", map[AccessOp]string{"all": "self"}, true, true},
		{"read self update group", map[AccessOp]string{"read": "self", "write": "group", "update": "group", "delete": "group"}, true, false},
		{"owner_or_role", map[AccessOp]string{"all": "owner_or_role:manager"}, false, false},
		{"role", map[AccessOp]string{"all": "role:user"}, false, false},
		{"everyone", map[AccessOp]string{"all": "everyone"}, true, false},
		{"member-of", map[AccessOp]string{"all": "member-of:doc_members(doc_id, member_id)"}, false, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			app, mux := tenantlessOwnerApp(t, c.rules)
			_ = createCrudScopeSession(t, app, "abe@example.com", "user", "1", "")   // user 1, member
			ann := createCrudScopeSession(t, app, "ann@example.com", "user", "", "") // user 2, removed
			for _, stmt := range []string{
				`INSERT INTO team_members (team_id, user_id) VALUES (1, 1)`,
				`INSERT INTO docs (id, team_id, user_id, title, body) VALUES (1, 1, 2, 'ann-made', 'team-secret')`,
				`INSERT INTO doc_members (team_id, doc_id, member_id) VALUES (1, 1, 2)`,
			} {
				crudScopeMustExec(t, app.DB, stmt)
			}
			read := crudScopeRequest(t, mux, http.MethodGet, "/api/docs/1", ann, nil)
			if got := read.Code == http.StatusOK; got != c.reads {
				t.Errorf("read by id: HTTP %d, want reads=%v", read.Code, c.reads)
			}
			if listed := strings.Contains(crudScopeRequest(t, mux, http.MethodGet, "/api/docs", ann, nil).Body.String(), "team-secret"); listed != c.reads {
				t.Errorf("list shows the row: %v, want %v", listed, c.reads)
			}
			edit := crudScopeRequest(t, mux, http.MethodPatch, "/api/docs/1", ann, map[string]any{"title": "changed"})
			if got := edit.Code == http.StatusOK; got != c.edits {
				t.Errorf("edit: HTTP %d %s, want edits=%v", edit.Code, edit.Body.String(), c.edits)
			}
			if changed := tenantlessCount(t, app, `SELECT COUNT(*) FROM docs WHERE id = 1 AND title = 'changed'`) == 1; changed != c.edits {
				t.Errorf("row changed: %v, want %v", changed, c.edits)
			}
		})
	}
}

// describe states what rowScopeClause does for a caller with no tenant: the
// owner tier reaches only owned rows that carry no tenant, plus, on the
// membership table, the caller's own membership rows.
func TestDescribeStatesTheTenantlessOwnerBound(t *testing.T) {
	for _, tc := range []struct {
		table, mode, want string
	}{
		{"docs", "", "a caller with no tenant reaches only rows they own (user_id) that carry no tenant"},
		{"docs", "owner_or_role:manager", "rows the caller owns (user_id) in their tenant (with no tenant, only owned rows that carry no tenant)"},
		{"team_members", "", "carry no tenant, and the membership rows that name them (user_id), active or not"},
	} {
		rules := map[string]map[AccessOp]string{}
		if tc.mode != "" {
			rules[tc.table] = docsRulesFor(tc.mode)
		}
		app, _ := tenantlessOwnerAppWithRules(t, rules)
		effect, _ := describeTableAccess(app, tc.table)["read"]["effect"].(string)
		if !strings.Contains(effect, tc.want) {
			t.Errorf("%s %q: effect %q does not say %q", tc.table, tc.mode, effect, tc.want)
		}
	}
}
