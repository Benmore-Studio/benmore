//go:build !cli

package main

import (
	"database/sql"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Record sharing can be turned off: app-wide with `features.sharing: false`,
// per table with `access.<table>.share: off`. While it is off the share
// endpoint refuses, and the grants already stored give no access on any
// per-row surface; turning it back on restores them.

// sharingSwitchApp serves a team app from the app.yaml it is given: docs
// carries the tenant key and user_id (declared `self`, versioned), notes is a
// tenant table on the implicit default, tasks is an un-grouped owner table,
// bookmarks points at docs.
func sharingSwitchApp(t *testing.T, appYAML string) (*App, *http.ServeMux) {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, stmt := range []string{
		`CREATE TABLE team_members (id INTEGER PRIMARY KEY AUTOINCREMENT, team_id INTEGER, user_id INTEGER, active INTEGER DEFAULT 1)`,
		`CREATE TABLE docs (id INTEGER PRIMARY KEY AUTOINCREMENT, team_id INTEGER, user_id INTEGER, title TEXT, body TEXT)`,
		`CREATE TABLE notes (id INTEGER PRIMARY KEY AUTOINCREMENT, team_id INTEGER, user_id INTEGER, title TEXT)`,
		`CREATE TABLE tasks (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, title TEXT)`,
		`CREATE TABLE bookmarks (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, doc_id INTEGER REFERENCES docs(id), label TEXT)`,
	} {
		crudScopeMustExec(t, db, stmt)
	}
	app := &App{
		Dir:             dir,
		DB:              db,
		SessionDuration: time.Hour,
		Stop:            make(chan struct{}),
		Group:           &GroupConfig{Table: "team_members", Key: "team_id", UserField: "user_id", ActiveField: "active"},
	}
	t.Cleanup(app.Shutdown)
	sharingSwitchConfig(t, app, appYAML)
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
	return app, buildAppMux(app, true, "http://localhost")
}

// sharingSwitchBase is the app.yaml every case starts from; a case appends
// its features: section or replaces the docs rule.
const sharingSwitchBase = "versioned: [docs]\n"

const sharingSwitchDocsSelf = "access:\n  docs:\n    all: self\n"

// sharingSwitchConfig puts appYAML in force the way a reload does: the write
// gate accepts it, the checked loader parses it, and the app's access and
// features come from that file.
func sharingSwitchConfig(t *testing.T, app *App, appYAML string) {
	t.Helper()
	if msg := validateAppYAML(appYAML); msg != "" {
		t.Fatalf("the write gate refuses the app.yaml under test: %s\n%s", msg, appYAML)
	}
	if err := os.WriteFile(filepath.Join(app.Dir, "app.yaml"), []byte(appYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	raw, _, err := parseAppConfigDocument([]byte(appYAML))
	if err != nil {
		t.Fatalf("the loader refuses the app.yaml under test: %v\n%s", err, appYAML)
	}
	access, err := loadAccessChecked(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	realtimeFlush() // no queued event reads the config while it is replaced
	app.Access, app.Design = access, designFromAppYAML(raw)
}

type sharingSwitchUsers struct{ owner, peer, outsider string }

// sharingSwitchSeed makes the rows and the grants while sharing is on: the
// owner (team 1) shares doc 1 and task 1 with an account outside the team
// (edit), and gives a team-mate an admin grant on note 1.
func sharingSwitchSeed(t *testing.T, app *App, mux *http.ServeMux) sharingSwitchUsers {
	t.Helper()
	u := sharingSwitchUsers{
		owner:    createCrudScopeSession(t, app, "owner@example.com", "user", "1", ""),
		peer:     createCrudScopeSession(t, app, "peer@example.com", "user", "1", ""),
		outsider: createCrudScopeSession(t, app, "outsider@example.com", "user", "", ""),
	}
	crudScopeMustExec(t, app.DB, `INSERT INTO team_members (team_id, user_id) VALUES (1, 1), (1, 2)`)
	assertStatus(t, mux, http.MethodPost, "/api/docs", u.owner, map[string]any{"title": "plan", "body": "first draft"}, http.StatusOK)
	assertStatus(t, mux, http.MethodPatch, "/api/docs/1", u.owner, map[string]any{"body": "owner-secret"}, http.StatusOK)
	assertStatus(t, mux, http.MethodPost, "/api/notes", u.owner, map[string]any{"title": "team note"}, http.StatusOK)
	assertStatus(t, mux, http.MethodPost, "/api/tasks", u.owner, map[string]any{"title": "owner-task"}, http.StatusOK)
	share := func(path, email, permission string) {
		t.Helper()
		assertStatus(t, mux, http.MethodPost, path, u.owner, map[string]any{"email": email, "permission": permission}, http.StatusOK)
	}
	share("/api/docs/1/share", "outsider@example.com", "edit")
	share("/api/tasks/1/share", "outsider@example.com", "edit")
	share("/api/notes/1/share", "peer@example.com", "admin")
	// The grantee reaches all of it, the version history included.
	assertStatus(t, mux, http.MethodGet, "/api/docs/1", u.outsider, nil, http.StatusOK)
	assertListIDs(t, mux, u.outsider, "/api/docs", []float64{1})
	assertStatus(t, mux, http.MethodGet, "/api/docs/1/versions", u.outsider, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodPatch, "/api/docs/1", u.outsider, map[string]any{"title": "plan v2"}, http.StatusOK)
	assertStatus(t, mux, http.MethodGet, "/api/tasks/1", u.outsider, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodPost, "/api/bookmarks", u.outsider, map[string]any{"doc_id": 1, "label": "kept"}, http.StatusOK)
	if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/bookmarks?include=doc", u.outsider, nil); !strings.Contains(rec.Body.String(), "owner-secret") {
		t.Fatalf("grantee include while sharing is on: %d %s", rec.Code, rec.Body.String())
	}
	assertStatus(t, mux, http.MethodGet, "/api/notes/1/permissions", u.peer, nil, http.StatusOK)
	return u
}

func sharingSwitchGrant(t *testing.T, app *App, table, grantee string) string {
	t.Helper()
	var permission string
	err := app.DB.QueryRow(`SELECT permission FROM _benmore_permissions WHERE resource_type = ? AND resource_id = '1' AND grantee_id = ?`, table, grantee).Scan(&permission)
	if err != nil && err != sql.ErrNoRows {
		t.Fatal(err)
	}
	return permission
}

// assertSharingRefused checks the stable refusal of a share on path, and that
// it stored nothing.
func assertSharingRefused(t *testing.T, app *App, mux *http.ServeMux, token, path string, body map[string]any) {
	t.Helper()
	before := tenantlessCount(t, app, `SELECT COUNT(*) FROM _benmore_permissions`)
	rec := crudScopeRequest(t, mux, http.MethodPost, path, token, body)
	var got map[string]any
	mustDecodeBody(t, rec, &got)
	if rec.Code != http.StatusForbidden || got["error"] != sharingDisabledCode || got["docs"] != "permissions.sharing_switch" {
		t.Fatalf("POST %s with sharing off: %d %s, want 403 %s with docs permissions.sharing_switch", path, rec.Code, rec.Body.String(), sharingDisabledCode)
	}
	if after := tenantlessCount(t, app, `SELECT COUNT(*) FROM _benmore_permissions`); after != before {
		t.Fatalf("POST %s with sharing off changed the grants: %d rows, were %d", path, after, before)
	}
}

func TestRecordSharingOffRefusesGrantsAndIgnoresExistingOnes(t *testing.T) {
	for name, off := range map[string]string{
		"features.sharing false": sharingSwitchBase + sharingSwitchDocsSelf + "features:\n  sharing: false\n",
		"features.sharing no":    sharingSwitchBase + sharingSwitchDocsSelf + "features:\n  sharing: no\n",
		"access.default.share":   sharingSwitchBase + "access:\n  docs:\n    all: self\n  default:\n    share: off\n",
	} {
		t.Run(name, func(t *testing.T) {
			on := sharingSwitchBase + sharingSwitchDocsSelf
			app, mux := sharingSwitchApp(t, on)
			u := sharingSwitchSeed(t, app, mux)

			mux = rebuildTestMux(t, app, true, "http://localhost", func() {
				sharingSwitchConfig(t, app, off)
			})

			// (1) No grant is created or changed, on any table.
			assertSharingRefused(t, app, mux, u.owner, "/api/docs/1/share", map[string]any{"email": "new@example.com", "permission": "view"})
			assertSharingRefused(t, app, mux, u.owner, "/api/docs/1/share", map[string]any{"email": "outsider@example.com", "permission": "admin"})
			assertSharingRefused(t, app, mux, u.owner, "/api/tasks/1/share", map[string]any{"email": "new@example.com", "permission": "view"})
			if got := sharingSwitchGrant(t, app, "docs", "outsider@example.com"); got != "edit" {
				t.Fatalf("the stored grant changed while sharing was off: %q", got)
			}

			// (2) The stored grant gives nothing on any per-row surface.
			for _, path := range []string{
				"/api/docs", "/api/docs/1", "/api/docs?q=secret", "/api/docs?count=true",
				"/api/bookmarks?include=doc", "/api/bookmarks/1?include=doc",
				"/api/docs/1/versions", "/api/docs/1/versions/1", "/api/docs/1/lock", "/api/docs/1?as_of=2999-01-01T00:00:00Z",
				"/api/tasks", "/api/tasks/1",
			} {
				rec := crudScopeRequest(t, mux, http.MethodGet, path, u.outsider, nil)
				if body := rec.Body.String(); strings.Contains(body, "owner-secret") || strings.Contains(body, "plan v2") || strings.Contains(body, "owner-task") || strings.Contains(body, `"count":1`) {
					t.Errorf("sharing off, grantee GET %s: HTTP %d %s", path, rec.Code, body)
				}
			}
			if ids := listedIDs(t, crudScopeRequest(t, mux, http.MethodGet, "/api/docs", u.outsider, nil)); ids == nil || len(ids) != 0 {
				t.Errorf("sharing off, grantee lists docs %v, want an empty page", ids)
			}
			assertStatus(t, mux, http.MethodGet, "/api/docs/1", u.outsider, nil, http.StatusNotFound)
			assertStatus(t, mux, http.MethodGet, "/api/docs/1/versions", u.outsider, nil, http.StatusNotFound)
			assertStatus(t, mux, http.MethodGet, "/api/tasks/1", u.outsider, nil, http.StatusNotFound)
			assertStatus(t, mux, http.MethodPatch, "/api/docs/1", u.outsider, map[string]any{"title": "taken"}, http.StatusNotFound)
			assertStatus(t, mux, http.MethodDelete, "/api/docs/1", u.outsider, nil, http.StatusNotFound)
			if rec := crudScopeRequest(t, mux, http.MethodPost, "/api/docs/1/lock", u.outsider, nil); rec.Code == http.StatusOK {
				t.Errorf("sharing off, grantee locked the row: %s", rec.Body.String())
			}
			if authorizeRecordReadForSigning(tenantlessBearerRequest(u.outsider), app, "docs", "1") {
				t.Error("sharing off, grantee may still sign a file of the shared row")
			}
			if got := gateScalar(t, app, `SELECT title FROM docs WHERE id = 1`); got != "plan v2" {
				t.Fatalf("sharing off, the grantee's write went through: title %q", got)
			}
			// An admin grant is a grant: it no longer manages the row's shares.
			assertStatus(t, mux, http.MethodGet, "/api/notes/1/permissions", u.peer, nil, http.StatusForbidden)
			assertStatus(t, mux, http.MethodDelete, "/api/notes/1/permissions/"+url.PathEscape("peer@example.com"), u.peer, nil, http.StatusForbidden)

			// The owner is untouched, sees the grants marked inactive, and
			// may revoke one.
			assertStatus(t, mux, http.MethodGet, "/api/docs/1", u.owner, nil, http.StatusOK)
			var listed struct {
				Sharing     string           `json:"sharing"`
				Permissions []map[string]any `json:"permissions"`
			}
			mustDecodeBody(t, crudScopeRequest(t, mux, http.MethodGet, "/api/docs/1/permissions", u.owner, nil), &listed)
			if listed.Sharing != "off" || len(listed.Permissions) != 1 || listed.Permissions[0]["active"] != false || listed.Permissions[0]["grantee_id"] != "outsider@example.com" {
				t.Fatalf("sharing off, the owner's grant list: %+v", listed)
			}
			assertStatus(t, mux, http.MethodDelete, "/api/tasks/1/permissions/"+url.PathEscape("outsider@example.com"), u.owner, nil, http.StatusOK)

			// Turning it back on restores the grants that are still stored.
			mux = rebuildTestMux(t, app, true, "http://localhost", func() {
				sharingSwitchConfig(t, app, on)
			})
			if rec := crudScopeRequest(t, mux, http.MethodGet, "/api/docs/1", u.outsider, nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "owner-secret") {
				t.Fatalf("sharing back on, grantee read: %d %s", rec.Code, rec.Body.String())
			}
			assertStatus(t, mux, http.MethodGet, "/api/docs/1/versions", u.outsider, nil, http.StatusOK)
			assertStatus(t, mux, http.MethodPatch, "/api/docs/1", u.outsider, map[string]any{"title": "plan v3"}, http.StatusOK)
			assertStatus(t, mux, http.MethodGet, "/api/notes/1/permissions", u.peer, nil, http.StatusOK)
			assertStatus(t, mux, http.MethodGet, "/api/tasks/1", u.outsider, nil, http.StatusNotFound) // revoked while off
			rec := crudScopeRequest(t, mux, http.MethodGet, "/api/docs/1/permissions", u.owner, nil)
			if body := rec.Body.String(); strings.Contains(body, `"sharing"`) || strings.Contains(body, `"active"`) {
				t.Fatalf("sharing on, the grant list carries the off markers: %s", body)
			}
			assertStatus(t, mux, http.MethodPost, "/api/docs/1/share", u.owner, map[string]any{"email": "new@example.com", "permission": "view"}, http.StatusOK)
		})
	}
}

// The table's own switch decides for that table and leaves the others alone;
// it also wins over the app-wide switch.
func TestRecordSharingSwitchPerTable(t *testing.T) {
	app, mux := sharingSwitchApp(t, sharingSwitchBase+sharingSwitchDocsSelf)
	u := sharingSwitchSeed(t, app, mux)

	for _, spelling := range []string{"off", "false", "no", "OFF"} {
		mux = rebuildTestMux(t, app, true, "http://localhost", func() {
			sharingSwitchConfig(t, app, sharingSwitchBase+"access:\n  docs:\n    all: self\n    share: "+spelling+"\n")
		})
		assertStatus(t, mux, http.MethodGet, "/api/docs/1", u.outsider, nil, http.StatusNotFound)
		assertStatus(t, mux, http.MethodGet, "/api/docs/1/versions", u.outsider, nil, http.StatusNotFound)
		assertSharingRefused(t, app, mux, u.owner, "/api/docs/1/share", map[string]any{"email": "new@example.com", "permission": "view"})
		// tasks and notes are still shared.
		assertStatus(t, mux, http.MethodGet, "/api/tasks/1", u.outsider, nil, http.StatusOK)
		assertStatus(t, mux, http.MethodPatch, "/api/tasks/1", u.outsider, map[string]any{"title": "owner-task"}, http.StatusOK)
		assertStatus(t, mux, http.MethodGet, "/api/notes/1/permissions", u.peer, nil, http.StatusOK)
		assertStatus(t, mux, http.MethodPost, "/api/tasks/1/share", u.owner, map[string]any{"email": "peer@example.com", "permission": "view"}, http.StatusOK)
	}

	// Off for the app, on for docs.
	mux = rebuildTestMux(t, app, true, "http://localhost", func() {
		sharingSwitchConfig(t, app, sharingSwitchBase+"features:\n  sharing: off\naccess:\n  docs:\n    all: self\n    share: on\n")
	})
	assertStatus(t, mux, http.MethodGet, "/api/docs/1", u.outsider, nil, http.StatusOK)
	assertStatus(t, mux, http.MethodGet, "/api/tasks/1", u.outsider, nil, http.StatusNotFound)
	assertSharingRefused(t, app, mux, u.owner, "/api/tasks/1/share", map[string]any{"email": "new@example.com", "permission": "view"})
	assertStatus(t, mux, http.MethodPost, "/api/docs/1/share", u.owner, map[string]any{"email": "new@example.com", "permission": "view"}, http.StatusOK)

	// A caller who may not read the table learns nothing from the refusal.
	mux = rebuildTestMux(t, app, true, "http://localhost", func() {
		sharingSwitchConfig(t, app, sharingSwitchBase+"access:\n  docs:\n    all: admin\n    share: off\n")
	})
	rec := crudScopeRequest(t, mux, http.MethodPost, "/api/docs/1/share", u.outsider, map[string]any{"email": "new@example.com", "permission": "view"})
	if rec.Code != http.StatusNotFound || rec.Body.String() != unmatchedAPINotFoundBody {
		t.Fatalf("share on an unreadable table with sharing off: %d %s, want the unmatched-path answer", rec.Code, rec.Body.String())
	}
}

// With sharing off the canonical row scope carries no grant branch under any
// access mode; with it on, each mode's predicate has one.
func TestRecordSharingOffRemovesTheGrantBranchOfEveryMode(t *testing.T) {
	member := &Session{UserID: 7, Email: "member@example.com", Verified: true, GroupID: "1"}
	tenantless := &Session{UserID: 8, Email: "outsider@example.com", Verified: true}
	for name, tc := range map[string]struct {
		rule    string
		table   string
		session *Session
	}{
		"declared self":             {"docs:\n    all: self\n", "docs", member},
		"declared self, no tenant":  {"docs:\n    all: self\n", "docs", tenantless},
		"owner_or_role":             {"docs:\n    all: owner_or_role:manager\n", "docs", member},
		"member-of":                 {"docs:\n    all: member-of:doc_members(doc_id,member_id)\n", "docs", member},
		"member-of, no tenant":      {"docs:\n    all: member-of:doc_members(doc_id,member_id)\n", "docs", tenantless},
		"implicit owner":            {"docs:\n    read: self\n", "tasks", member},
		"implicit group, no tenant": {"docs:\n    read: self\n", "notes", tenantless},
		"tenant key only":           {"docs:\n    read: self\n", "doc_members", tenantless},
	} {
		t.Run(name, func(t *testing.T) {
			app := &App{Group: &GroupConfig{Table: "team_members", Key: "team_id", UserField: "user_id"}, Tables: []Table{
				{Name: "team_members", Columns: []Column{{Name: "id"}, {Name: "team_id"}, {Name: "user_id"}}},
				{Name: "docs", Columns: []Column{{Name: "id"}, {Name: "team_id"}, {Name: "user_id"}, {Name: "title"}}},
				{Name: "notes", Columns: []Column{{Name: "id"}, {Name: "team_id"}, {Name: "user_id"}, {Name: "title"}}},
				{Name: "tasks", Columns: []Column{{Name: "id"}, {Name: "user_id"}, {Name: "title"}}},
				{Name: "doc_members", Columns: []Column{{Name: "id"}, {Name: "team_id"}, {Name: "doc_id"}, {Name: "member_id"}}},
			}}
			for _, action := range []string{"view", "edit", "delete"} {
				app.Access = accessFromYAML(t, "access:\n  "+tc.rule)
				pred, _, _ := rowScopeClause(app, tc.table, tc.session, action)
				if !strings.Contains(pred, "_benmore_permissions") {
					t.Fatalf("%s: sharing on, the scope has no grant branch (the case tests nothing): %s", action, pred)
				}
				app.Access = accessFromYAML(t, "access:\n  "+tc.rule+"  default:\n    share: off\n")
				pred, args, bypass := rowScopeClause(app, tc.table, tc.session, action)
				if bypass || pred == "" || strings.Contains(pred, "_benmore_permissions") {
					t.Fatalf("%s: sharing off, the scope still reads grants or stopped scoping: bypass=%v %q", action, bypass, pred)
				}
				if got := strings.Count(pred, "?"); got != len(args) {
					t.Fatalf("%s: sharing off, %d placeholders and %d arguments: %s", action, got, len(args), pred)
				}
			}
		})
	}
}

// A misspelled switch is refused when it is written, never read as "on".
func TestRecordSharingSwitchSpellingIsCheckedAtWriteTime(t *testing.T) {
	for name, tc := range map[string]struct{ yaml, want string }{
		"features typo":         {"features:\n  sharng: false\n", "features.sharng is not a feature switch"},
		"features plural":       {"features:\n  shares: false\n", "features.shares is not a feature switch"},
		"features not a switch": {"features:\n  sharing: admins\n", "features.sharing"},
		"access typo":           {"access:\n  docs:\n    shar: off\n", "access.docs.shar is not an access operation"},
		"access sharing":        {"access:\n  docs:\n    sharing: off\n", "access.docs.sharing is not an access operation"},
		"access mode as value":  {"access:\n  docs:\n    share: admin\n", "access.docs.share takes on or off"},
		"access mapping":        {"access:\n  docs:\n    share:\n      enabled: false\n", "access.docs.share takes on or off"},
		"access empty":          {"access:\n  docs:\n    share:\n", "access.docs.share is empty"},
	} {
		t.Run(name, func(t *testing.T) {
			if msg := validateAppYAML(tc.yaml); !strings.Contains(msg, tc.want) {
				t.Fatalf("write gate answered %q, want it to name %q", msg, tc.want)
			}
		})
	}
	for _, accepted := range []string{
		"features:\n  sharing: false\n", "features:\n  sharing: off\n", "features:\n  sharing: yes\n",
		"access:\n  docs:\n    read: self\n    share: off\n", "access:\n  docs:\n    share: false\n", "access:\n  docs:\n    share: On\n",
		"access:\n  default:\n    share: 0\n",
	} {
		if msg := validateAppYAML(accepted); msg != "" {
			t.Errorf("write gate refuses %q: %s", accepted, msg)
		}
		if _, _, err := parseAppConfigDocument([]byte(accepted)); err != nil {
			t.Errorf("loader refuses %q: %v", accepted, err)
		}
	}
	// What the loader does with a value the write gate would have refused:
	// the narrower reading, off.
	for value, want := range map[string]bool{"admin": false, "{enabled: true}": false, "on": true, "1": true, "off": false} {
		app := &App{Access: accessFromYAML(t, "access:\n  docs:\n    share: "+value+"\n")}
		if got := recordSharingEnabled(app, "docs"); got != want {
			t.Errorf("share: %s reads as sharing %v, want %v", value, got, want)
		}
		if !recordSharingEnabled(app, "tasks") {
			t.Errorf("share: %s on docs turned sharing off for tasks", value)
		}
	}
	if !recordSharingEnabled(&App{}, "docs") || !recordSharingEnabled(nil, "docs") {
		t.Error("with nothing declared record sharing is on")
	}
}
