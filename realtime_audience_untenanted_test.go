//go:build !cli

package main

import (
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
)

const realtimeGenericWS = `{"type":"change","action":"refresh"}`

func realtimeAddTable(t *testing.T, app *App, ddl, name string) {
	t.Helper()
	mustExec(t, app.DB, ddl)
	cols, err := GetTableColumns(app.DB, name)
	if err != nil {
		t.Fatal(err)
	}
	app.Tables = append(app.Tables, Table{Name: name, Columns: cols})
}

func realtimeFullEvent(table, action string) (sse, ws string) {
	return fmt.Sprintf(`{"table":"%s","action":"%s"}`, table, action),
		fmt.Sprintf(`{"type":"change","table":"%s","action":"%s"}`, table, action)
}

func realtimeExpect(t *testing.T, label string, sub *flowRealtimeSubscriber, wantSSE, wantWS []string) {
	t.Helper()
	sse, ws := sub.drain()
	if !reflect.DeepEqual(sse, wantSSE) || !reflect.DeepEqual(ws, wantWS) {
		t.Errorf("%s: got sse=%q ws=%q, want sse=%q ws=%q", label, sse, ws, wantSSE, wantWS)
	}
}

// A table without the tenant key (here `tags`, readable by role:user, and a
// groups.shared catalog) has rows that carry no tenant: a reader in another
// tenant lists the same rows. Its change event used to stay in the writer's
// tenant, so that reader's live view never refreshed. It now reaches every
// reader of the table in full, whichever tenant wrote. A tenant-keyed table
// stays in the writer's tenant, and a user who cannot read the table hears
// nothing.
func TestRealtimeUntenantedTableReachesReadersInEveryTenant(t *testing.T) {
	app := realtimeTasksApp(t)
	realtimeAddTable(t, app, `CREATE TABLE tags (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)`, "tags")
	realtimeAddTable(t, app, `CREATE TABLE catalog (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT)`, "catalog")
	app.Group.Shared = []string{"catalog"}
	app.Access.rules["tags"] = map[AccessOp]string{"all": "role:user"}
	app.Access.rules["catalog"] = map[AccessOp]string{"all": "role:user"}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)

	sidA1 := createCrudScopeSession(t, app, "a1@example.com", "user", "tenant-a", "")
	sidB := createCrudScopeSession(t, app, "b@example.com", "user", "tenant-b", "")
	mustExec(t, app.DB, "INSERT INTO members (org_id, email) VALUES ('tenant-b', 'guest@example.com')")
	sidGuest := createCrudScopeSession(t, app, "guest@example.com", "guest", "tenant-b", "")
	a1 := subscribeFlowRealtime(t, app, sidA1)
	a2 := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "a2@example.com", "user", "tenant-a", ""))
	b := subscribeFlowRealtime(t, app, sidB)
	guest := subscribeFlowRealtime(t, app, sidGuest)
	writerA := GetSessionFromDB(app.DB, sidA1)
	writerB := GetSessionFromDB(app.DB, sidB)

	for _, table := range []string{"tags", "catalog"} {
		// The row is readable across tenants: tenant B lists tenant A's row.
		if rr := crudScopeRequest(t, mux, http.MethodPost, "/api/"+table, sidA1, map[string]any{"name": "urgent"}); rr.Code != http.StatusOK {
			t.Fatalf("%s: tenant A create=%d %s", table, rr.Code, rr.Body.String())
		}
		if rr := crudScopeRequest(t, mux, http.MethodGet, "/api/"+table, sidB, nil); rr.Code != http.StatusOK || !strings.Contains(rr.Body.String(), "urgent") {
			t.Fatalf("%s: tenant B cannot list tenant A's row: %d %s", table, rr.Code, rr.Body.String())
		}
		if rr := crudScopeRequest(t, mux, http.MethodGet, "/api/"+table, sidGuest, nil); rr.Code == http.StatusOK {
			t.Fatalf("%s: control: guest read the table: %s", table, rr.Body.String())
		}
		sse, ws := realtimeFullEvent(table, "insert")
		for _, s := range []*flowRealtimeSubscriber{a1, a2, b} {
			realtimeExpect(t, table+" create by tenant A: "+s.sse.groupID, s, []string{sse}, []string{ws})
		}
		realtimeExpect(t, table+" create by tenant A: guest", guest, nil, nil)

		// The other direction: tenant B writes, tenant A readers hear it.
		Broadcast(app, table, "update", writerB)
		sse, ws = realtimeFullEvent(table, "update")
		for _, s := range []*flowRealtimeSubscriber{a1, a2, b} {
			realtimeExpect(t, table+" update by tenant B: "+s.sse.groupID, s, []string{sse}, []string{ws})
		}
		realtimeExpect(t, table+" update by tenant B: guest", guest, nil, nil)
	}

	// A tenant-keyed table still stays in the writer's tenant.
	Broadcast(app, "orgdocs", "update", writerA)
	sse, ws := realtimeFullEvent("orgdocs", "update")
	realtimeExpect(t, "orgdocs: writer", a1, []string{sse}, []string{ws})
	realtimeExpect(t, "orgdocs: tenant colleague", a2, []string{sse}, []string{ws})
	realtimeExpect(t, "orgdocs: other tenant", b, nil, nil)
}

// An owner row (notes: user_id, explicit self, no tenant key) shared through
// a record grant is readable by the grantee in another tenant. The grantee
// used to hear nothing about changes to it while a same-tenant user who
// cannot read it got the generic refresh. Any reader of the table, the
// grantee included, now gets the generic refresh (a refetch hint with no
// table name; per-row grants can't be resolved without the row), the owner
// and admins the full event, and a credential that cannot read the table
// nothing.
func TestRealtimeSharedOwnerRowReachesGrantee(t *testing.T) {
	app, mux := auditApp(t)
	mustExec(t, app.DB, "INSERT INTO members (org_id, email) VALUES ('tenant-a', 'a1@example.com'), ('tenant-a', 'a2@example.com'), ('tenant-b', 'b@example.com'), ('tenant-c', 'c@example.com')")
	sidOwner := createCrudScopeSession(t, app, "a1@example.com", "user", "tenant-a", "")
	sidGrantee := createCrudScopeSession(t, app, "b@example.com", "user", "tenant-b", "")
	sidColleague := createCrudScopeSession(t, app, "a2@example.com", "user", "tenant-a", "")
	sidStranger := createCrudScopeSession(t, app, "c@example.com", "user", "tenant-c", "")
	sidAdmin := createCrudScopeSession(t, app, "boss@example.com", "admin", "", "")
	owner := GetSessionFromDB(app.DB, sidOwner)
	mustExec(t, app.DB, fmt.Sprintf("INSERT INTO notes (id, user_id, title) VALUES (1, %d, 'shared note')", owner.UserID))
	mustExec(t, app.DB, `INSERT INTO _benmore_permissions (resource_type, resource_id, grant_type, grantee_id, permission)
		VALUES ('notes', '1', 'user', 'b@example.com', 'view')`)

	// The grant really is a read: the grantee in tenant B reads the row, the
	// stranger in tenant C and the colleague in tenant A do not.
	if rr := crudScopeRequest(t, mux, http.MethodGet, "/api/notes/1", sidGrantee, nil); rr.Code != http.StatusOK {
		t.Fatalf("grantee read=%d %s", rr.Code, rr.Body.String())
	}
	for _, sid := range []string{sidColleague, sidStranger} {
		if rr := crudScopeRequest(t, mux, http.MethodGet, "/api/notes/1", sid, nil); rr.Code != http.StatusNotFound {
			t.Fatalf("control: non-grantee read=%d", rr.Code)
		}
	}

	ownerSub := subscribeFlowRealtime(t, app, sidOwner)
	grantee := subscribeFlowRealtime(t, app, sidGrantee)
	colleague := subscribeFlowRealtime(t, app, sidColleague)
	stranger := subscribeFlowRealtime(t, app, sidStranger)
	admin := subscribeFlowRealtime(t, app, sidAdmin)
	noNotesScope := subscribeFlowRealtime(t, app, auditToken(t, app, sidGrantee, "orgdocs:read"))

	if rr := crudScopeRequest(t, mux, http.MethodPatch, "/api/notes/1", sidOwner, map[string]any{"title": "edited"}); rr.Code != http.StatusOK {
		t.Fatalf("owner update=%d %s", rr.Code, rr.Body.String())
	}
	sse, ws := realtimeFullEvent("notes", "update")
	realtimeExpect(t, "owner", ownerSub, []string{sse}, []string{ws})
	realtimeExpect(t, "admin", admin, []string{sse}, []string{ws})
	realtimeExpect(t, "grantee in another tenant", grantee, []string{realtimeGenericSSE}, []string{realtimeGenericWS})
	realtimeExpect(t, "tenant colleague", colleague, []string{realtimeGenericSSE}, []string{realtimeGenericWS})
	realtimeExpect(t, "stranger", stranger, []string{realtimeGenericSSE}, []string{realtimeGenericWS})
	realtimeExpect(t, "token without notes:read", noNotesScope, nil, nil)
}

// A hook job (on_insert, on_delete, or any hook with a non-SQL action) runs
// with no session. Its SQL writes used to go out unscoped: every tenant's
// readers of the written table got the generic refresh. They now take their
// audience from the triggering row, as a data-event flow's writes do: its
// tenant key for a tenant table (none: admins only) and its user_id for an
// owner table.
func TestHookJobSQLRefreshFollowsTriggeringRow(t *testing.T) {
	app := realtimeTasksApp(t)
	sidA1 := createCrudScopeSession(t, app, "a1@example.com", "user", "tenant-a", "")
	a1 := subscribeFlowRealtime(t, app, sidA1)
	a2 := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "a2@example.com", "user", "tenant-a", ""))
	b := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "b@example.com", "user", "tenant-b", ""))
	admin := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "boss@example.com", "admin", "", ""))
	uid := GetSessionFromDB(app.DB, sidA1).UserID

	orgdocsSSE, orgdocsWS := realtimeFullEvent("orgdocs", "refresh")
	notesSSE, notesWS := realtimeFullEvent("notes", "refresh")
	for _, c := range []struct {
		name                string
		sql                 string
		row                 map[string]any
		a1, a2, b, adminGot []string
		a1WS, a2WS, bWS     []string
	}{
		{
			name: "tenant table, triggering row in tenant A",
			sql:  "INSERT INTO orgdocs (org_id, title) VALUES ({{org_id}}, 'log ' || {{id}})",
			row:  map[string]any{"id": 7, "org_id": "tenant-a", "user_id": uid, "title": "task"},
			a1:   []string{orgdocsSSE}, a1WS: []string{orgdocsWS},
			a2: []string{orgdocsSSE}, a2WS: []string{orgdocsWS},
			adminGot: []string{orgdocsSSE},
		},
		{
			name:     "tenant table, triggering row names no tenant",
			sql:      "INSERT INTO orgdocs (org_id, title) VALUES ('tenant-b', 'from an untenanted row')",
			row:      map[string]any{"id": 8, "user_id": uid},
			adminGot: []string{orgdocsSSE},
		},
		{
			name: "owner table: the triggering row's user in full, other readers the generic refresh",
			sql:  "INSERT INTO notes (user_id, title) VALUES ({{user_id}}, 'note from hook')",
			row:  map[string]any{"id": 9, "org_id": "tenant-a", "user_id": uid},
			a1:   []string{notesSSE}, a1WS: []string{notesWS},
			a2: []string{realtimeGenericSSE}, a2WS: []string{realtimeGenericWS},
			b: []string{realtimeGenericSSE}, bWS: []string{realtimeGenericWS},
			adminGot: []string{notesSSE},
		},
	} {
		if err := roundTripHookJob(t, app, hookJobPayload(Hook{SQL: c.sql}, "tasks", c.row)); err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		realtimeExpect(t, c.name+": a1", a1, c.a1, c.a1WS)
		realtimeExpect(t, c.name+": a2", a2, c.a2, c.a2WS)
		realtimeExpect(t, c.name+": b", b, c.b, c.bWS)
		if sse, _ := admin.drain(); !reflect.DeepEqual(sse, c.adminGot) {
			t.Errorf("%s: admin got %q, want %q", c.name, sse, c.adminGot)
		}
	}
}

// A SQL-only update hook runs in the write's transaction. Its writes are
// announced after commit scoped by the writing session, like the update's own
// event: the session's tenant hears about the tenant table it wrote, another
// tenant hears nothing (it used to get the generic refresh).
func TestTransactionalHookRefreshFollowsWritingSession(t *testing.T) {
	app := realtimeTasksApp(t)
	app.Hooks = &HookConfig{OnUpdate: map[string][]Hook{
		"tasks": {{SQL: "UPDATE orgdocs SET title = 'touched by ' || {{id}} WHERE org_id = {{org_id}}"}},
	}}
	mux := http.NewServeMux()
	RegisterCRUD(mux, app)
	sidA1 := createCrudScopeSession(t, app, "a1@example.com", "user", "tenant-a", "")
	uid := GetSessionFromDB(app.DB, sidA1).UserID
	mustExec(t, app.DB, fmt.Sprintf("INSERT INTO tasks (id, user_id, org_id, title) VALUES (1, %d, 'tenant-a', 'task')", uid))
	a1 := subscribeFlowRealtime(t, app, sidA1)
	a2 := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "a2@example.com", "user", "tenant-a", ""))
	b := subscribeFlowRealtime(t, app, createCrudScopeSession(t, app, "b@example.com", "user", "tenant-b", ""))

	if rr := crudScopeRequest(t, mux, http.MethodPatch, "/api/tasks/1", sidA1, map[string]any{"title": "renamed"}); rr.Code != http.StatusOK {
		t.Fatalf("update=%d %s", rr.Code, rr.Body.String())
	}
	var title string
	if err := app.DB.QueryRow("SELECT title FROM orgdocs WHERE org_id = 'tenant-a'").Scan(&title); err != nil || title != "touched by 1" {
		t.Fatalf("hook did not run: title=%q err=%v", title, err)
	}
	tasksSSE, tasksWS := realtimeFullEvent("tasks", "update")
	docsSSE, docsWS := realtimeFullEvent("orgdocs", "refresh")
	realtimeExpect(t, "writer", a1, []string{tasksSSE, docsSSE}, []string{tasksWS, docsWS})
	realtimeExpect(t, "tenant colleague", a2, []string{tasksSSE, docsSSE}, []string{tasksWS, docsWS})
	realtimeExpect(t, "other tenant", b, nil, nil)
}
