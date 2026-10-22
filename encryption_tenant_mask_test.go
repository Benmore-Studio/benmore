//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func newTenantEncryptionFixture(t *testing.T) (*App, *http.ServeMux) {
	t.Helper()
	app, mux := newTenantRoleFixture(t, "access:\n  companies: {read: everyone}\n  projects: {read: everyone}\n  brokers: {read: everyone}\n")
	key := testKeyBytes(0x35)
	path := filepath.Join(app.Dir, "data.db")
	RegisterDBEncryptionKey(path, key)
	t.Cleanup(func() { dbCryptoRegistry.Delete(canonicalDBPath(path)) })
	app.Encrypted = &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{}}
	for _, table := range []string{"companies", "projects", "brokers"} {
		crudScopeMustExec(t, app.DB, "ALTER TABLE "+table+" ADD COLUMN private_note TEXT")
		app.Encrypted.Fields[table] = []EncryptedFieldDef{{Column: "private_note", Roles: []string{"company_admin"}, BlindIndex: true}}
	}
	crudScopeMustExec(t, app.DB, "ALTER TABLE projects ADD COLUMN user_id INTEGER")
	EnsureBlindColumns(app.DB, app.Encrypted)
	InstallEncryptionTriggers(app.DB, app.Encrypted)
	InstallBlindIndexTriggers(app.DB, app.Encrypted)
	for i := range app.Tables {
		name := app.Tables[i].Name
		if _, ok := app.Encrypted.Fields[name]; ok {
			crudScopeMustExec(t, app.DB, "UPDATE "+name+" SET private_note = CASE id WHEN 1 THEN 'acme-private-note' ELSE 'globex-private-note' END")
		}
		var err error
		app.Tables[i].Columns, err = GetTableColumns(app.DB, name)
		if err != nil {
			t.Fatal(err)
		}
	}
	return app, mux
}

func assertTenantEncryptedRead(t *testing.T, mux *http.ServeMux, sid, path string, wantPlain bool, value string) {
	t.Helper()
	w := crudScopeRequest(t, mux, http.MethodGet, path, sid, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: status=%d body=%s", path, w.Code, w.Body.String())
	}
	if gotPlain := strings.Contains(w.Body.String(), value); gotPlain != wantPlain {
		t.Fatalf("%s: plaintext=%t want=%t body=%s", path, gotPlain, wantPlain, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "private_note_blind") {
		t.Fatalf("blind index appeared in response: %s", w.Body.String())
	}
}

func TestEncryptedUnmaskTenantRoleBoundToRow(t *testing.T) {
	app, mux := newTenantEncryptionFixture(t)
	sid, uid := tenantMember(t, app, "member@example.com", "user", 1, "company_admin")
	if _, err := app.DB.Exec("INSERT INTO company_members (company_id,email,member_role) VALUES (2,?,'viewer')", "member@example.com"); err != nil {
		t.Fatal(err)
	}
	for _, table := range []string{"companies", "projects"} {
		assertTenantEncryptedRead(t, mux, sid, "/api/"+table+"/1", true, "acme-private-note")
		assertTenantEncryptedRead(t, mux, sid, "/api/"+table+"/2", false, "globex-private-note")
		assertTenantEncryptedRead(t, mux, sid, "/api/"+table, true, "acme-private-note")
		assertTenantEncryptedRead(t, mux, sid, "/api/"+table, false, "globex-private-note")
	}
	// A second membership does not import the first tenant's role into it.
	otherSID := CreateSession(app.DB, uid, "member@example.com", "2", time.Hour)
	assertTenantEncryptedRead(t, mux, otherSID, "/api/companies/2", false, "globex-private-note")
	// A role separately granted in both tenants applies only to the active
	// tenant, including when the grant's spelling matches the first one.
	if _, err := app.DB.Exec("INSERT INTO _benmore_user_roles (user_id,role,group_id) VALUES (?,'company_admin','2')", uid); err != nil {
		t.Fatal(err)
	}
	assertTenantEncryptedRead(t, mux, otherSID, "/api/companies/2", true, "globex-private-note")
	assertTenantEncryptedRead(t, mux, otherSID, "/api/companies/1", false, "acme-private-note")
	assertTenantEncryptedRead(t, mux, sid, "/api/companies/2", false, "globex-private-note")
	// No tenant metadata means no tenant-derived unmask, including public
	// ungrouped tables. An explicit shared catalog retains its role contract.
	assertTenantEncryptedRead(t, mux, sid, "/api/brokers/1", false, "acme-private-note")
	app.Group.Shared = []string{"brokers"}
	assertTenantEncryptedRead(t, mux, sid, "/api/brokers/1", true, "acme-private-note")
}

func TestEncryptedUnmaskGlobalRolesAndBoundAdmin(t *testing.T) {
	app, mux := newTenantEncryptionFixture(t)
	for _, primary := range []string{"company_admin", "admin"} {
		sid, _ := tenantMember(t, app, primary+"@example.com", primary, 1, "viewer")
		assertTenantEncryptedRead(t, mux, sid, "/api/companies/2", true, "globex-private-note")
	}
	sid, uid := tenantMember(t, app, "global@example.com", "user", 1, "viewer")
	if _, err := app.DB.Exec("INSERT INTO _benmore_user_roles (user_id,role) VALUES (?,'company_admin')", uid); err != nil {
		t.Fatal(err)
	}
	assertTenantEncryptedRead(t, mux, sid, "/api/companies/2", true, "globex-private-note")
	if _, err := app.DB.Exec("UPDATE _benmore_user_roles SET expires_at='2000-01-01' WHERE user_id=?", uid); err != nil {
		t.Fatal(err)
	}
	assertTenantEncryptedRead(t, mux, sid, "/api/companies/2", false, "globex-private-note")

	for name, actor := range map[string]*Session{
		"act-as":    {UserID: uid, Role: "admin", GroupID: "2", ActingAsGroup: "1"},
		"connector": {UserID: uid, Role: "admin", GroupID: "1", connectorGrant: true},
	} {
		t.Run(name, func(t *testing.T) {
			rows := []map[string]any{{"id": int64(1), "private_note": "acme-private-note"}, {"id": int64(2), "private_note": "globex-private-note"}}
			MaskEncryptedFields(app, "companies", rows, actor)
			if rows[0]["private_note"] != "acme-private-note" || rows[1]["private_note"] == "globex-private-note" {
				t.Fatalf("bound admin masking: %+v", rows)
			}
		})
	}
}

func TestEncryptedUnmaskMissingTenantAndHistoricalRow(t *testing.T) {
	app, mux := newTenantEncryptionFixture(t)
	sid, _ := tenantMember(t, app, "member@example.com", "user", 1, "company_admin")
	assertTenantEncryptedRead(t, mux, sid, "/api/companies?fields=private_note", true, "acme-private-note")
	assertTenantEncryptedRead(t, mux, sid, "/api/companies/1?fields=private_note", true, "acme-private-note")
	assertTenantEncryptedRead(t, mux, sid, "/api/companies?fields=private_note&cursor=0", false, "globex-private-note")
	w := crudScopeRequest(t, mux, http.MethodPost, "/api/_query", sid, map[string]any{"table": "companies", "select": []string{"private_note"}})
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "acme-private-note") || strings.Contains(w.Body.String(), "globex-private-note") {
		t.Fatalf("query projection should use internal row tenant: %d %s", w.Code, w.Body.String())
	}
	actor := getSession(app, authzReq("GET", "/", sid, ""))
	unknown := []map[string]any{{"private_note": "unknown-tenant-secret"}}
	MaskEncryptedFields(app, "companies", unknown, actor)
	if unknown[0]["private_note"] == "unknown-tenant-secret" {
		t.Fatal("unknown tenant projection must stay masked")
	}
	// A historical snapshot must keep its own tenant identity even if the
	// current row with the same id is now in the viewer's tenant.
	rows := []map[string]any{{"id": int64(1), "company_id": int64(2), "private_note": "historical-other-tenant"}}
	sanitizeResponseRows(app, "projects", rows, actor)
	if rows[0]["private_note"] == "historical-other-tenant" {
		t.Fatal("historical row was unmasked using current-row scope")
	}
	// Includes must apply the related table's identity, not the parent row.
	for _, rows := range [][]map[string]any{
		batchFetchByIDs(app, "companies", map[string]bool{"1": true, "2": true}, actor),
		batchFetchByFK(app, "projects", "company_id", map[string]bool{"1": true, "2": true}, actor),
	} {
		if len(rows) == 0 {
			t.Fatalf("include fixture returned no authorized rows: %+v", rows)
		}
		for _, row := range rows {
			if fmt.Sprint(row["id"]) == "2" && row["private_note"] == "globex-private-note" {
				t.Fatal("related tenant row was unmasked")
			}
		}
	}
}

func TestEncryptedTenantBlindFiltersAndQueryScope(t *testing.T) {
	app, mux := newTenantEncryptionFixture(t)
	sid, uid := tenantMember(t, app, "member@example.com", "user", 1, "company_admin")
	for _, table := range []string{"companies", "projects"} {
		assertListIDs(t, mux, sid, "/api/"+table+"?private_note=acme-private-note", []float64{1})
		assertListIDs(t, mux, sid, "/api/"+table+"?private_note=globex-private-note", []float64{})
		w := crudScopeRequest(t, mux, http.MethodGet, "/api/"+table+"?count=true&private_note=globex-private-note", sid, nil)
		if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), `"count":0`) {
			t.Fatalf("cross-tenant count: %d %s", w.Code, w.Body.String())
		}
		w = crudScopeRequest(t, mux, http.MethodPost, "/api/_query", sid, map[string]any{"table": table, "aggregates": []map[string]string{{"fn": "count", "col": "private_note", "as": "total"}}})
		var got struct {
			Rows []map[string]any `json:"rows"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || w.Code != http.StatusOK || len(got.Rows) != 1 || got.Rows[0]["total"] != float64(1) {
			t.Fatalf("tenant aggregate: %d %s err=%v", w.Code, w.Body.String(), err)
		}
	}
	// Mixed owner + tenant grants are a union: outside-tenant owner rows
	// remain searchable exactly where explicit self unmask authorizes them.
	def := app.Encrypted.Fields["projects"][0]
	def.Roles = append(def.Roles, "self")
	app.Encrypted.Fields["projects"][0] = def
	if _, err := app.DB.Exec("UPDATE projects SET user_id=? WHERE id=2", uid); err != nil {
		t.Fatal(err)
	}
	assertListIDs(t, mux, sid, "/api/projects?private_note=globex-private-note", []float64{2})
	assertTenantEncryptedRead(t, mux, sid, "/api/projects/2", true, "globex-private-note")
}

func TestEncryptedUnmaskMissingDBFailsClosed(t *testing.T) {
	app := &App{
		Group:  &GroupConfig{Key: "company_id"},
		Tables: []Table{{Name: "projects", Columns: []Column{{Name: "company_id"}}}},
		Encrypted: &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
			"projects": {{Column: "private_note", Roles: []string{"company_admin"}}},
		}},
	}
	actor := &Session{UserID: 1, Role: "user", Roles: []string{"company_admin"}, GroupID: "1"}
	rows := []map[string]any{{"company_id": int64(2), "private_note": "other-tenant-secret"}}
	MaskEncryptedFields(app, "projects", rows, actor)
	if rows[0]["private_note"] == "other-tenant-secret" {
		t.Fatal("missing role database must not imply a global grant")
	}
	if got := blindFilterAccessFor(app, "projects", "private_note", actor); got != blindFilterTenantRows {
		t.Fatalf("missing DB should retain only known tenant authority, got %v", got)
	}
}

func TestEncryptedUnmaskGlobalGrantOnTransactionAndUngroupedConnector(t *testing.T) {
	app, _ := newTenantEncryptionFixture(t)
	sid, uid := tenantMember(t, app, "global@example.com", "user", 1, "viewer")
	if _, err := app.DB.Exec("INSERT INTO _benmore_user_roles (user_id,role) VALUES (?,'company_admin')", uid); err != nil {
		t.Fatal(err)
	}
	actor := getSession(app, authzReq("GET", "/", sid, ""))
	app.DB.SetMaxOpenConns(1)
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	rows := []map[string]any{{"id": int64(2), "private_note": "globex-private-note"}}
	maskEncryptedFieldsWith(app, tx, "companies", rows, actor)
	if rows[0]["private_note"] != "globex-private-note" {
		t.Fatal("global grant should resolve through the transaction")
	}
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}

	// A malformed connector missing the tenant required by groups config
	// fails closed even when the account itself is an administrator.
	missingTenant := []map[string]any{{"id": int64(1), "private_note": "acme-private-note"}}
	MaskEncryptedFields(app, "companies", missingTenant, &Session{UserID: uid, Role: "admin", connectorGrant: true})
	if missingTenant[0]["private_note"] == "acme-private-note" {
		t.Fatal("grouped connector without required tenant regained admin bypass")
	}

	// A connector with no tenant boundary keeps the same global-role
	// authority as a normal credential on an ungrouped application.
	app.Group = nil
	for _, role := range []string{"company_admin", "admin"} {
		actor := &Session{UserID: uid, Role: role, connectorGrant: true}
		rows := []map[string]any{{"private_note": "ungrouped-global-secret"}}
		MaskEncryptedFields(app, "brokers", rows, actor)
		if rows[0]["private_note"] != "ungrouped-global-secret" {
			t.Fatalf("non-tenant connector role %s lost global unmask", role)
		}
	}
}
