//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
)

// Build-first Casework reproduction: UUID + full-text + encrypted/versioned
// evidence is valid app source but its first native insert failed with a
// datatype mismatch because FTS tried to use the public text id as its rowid.
func TestFTSUUIDNativeCRUDWithEncryptedHistory(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model CaseRecord {
 id String @id @default(uuid())
 userId Int @map("user_id")
 title String
 narrative String
 shareToken String @default("") @map("share_token")
 createdAt DateTime @default(now()) @map("created_at")
 updatedAt DateTime @default(now()) @updatedAt @map("updated_at")
 @@fulltext([title,shareToken])
}`)
	writeTestFile(t, dir, "app.yaml", "auth: {identifier: email}\naccess: {case_records: self}\nversioned: [case_records]\n")
	writeTestFile(t, dir, "encrypted.yaml", "tables:\n  case_records:\n    fields: [narrative]\n    unmask_roles: [self]\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "https://audit.example.invalid")
	owner := createCrudScopeSession(t, app, "owner@example.test", "user", "", "")
	peer := createCrudScopeSession(t, app, "peer@example.test", "user", "", "")
	r := crudScopeRequest(t, mux, http.MethodPost, "/api/case_records", owner, map[string]any{"title": "Harbor inspection", "narrative": "private evidence", "share_token": "hidden-canary"})
	if r.Code != http.StatusOK && r.Code != http.StatusCreated {
		t.Fatalf("create searchable UUID record: %d %s", r.Code, r.Body.String())
	}
	var row map[string]any
	if err := json.Unmarshal(r.Body.Bytes(), &row); err != nil {
		t.Fatal(err)
	}
	id, ok := row["id"].(string)
	if !ok || len(id) != 36 || row["narrative"] != "private evidence" {
		t.Fatalf("created row: %v", row)
	}
	for _, tc := range []struct {
		token, q string
		want     int
	}{{owner, "harbor", 1}, {owner, "ha", 1}, {peer, "harbor", 0}, {owner, "hidden-canary", 0}} {
		r := crudScopeRequest(t, mux, http.MethodGet, "/api/case_records?q="+url.QueryEscape(tc.q), tc.token, nil)
		var rows []map[string]any
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &rows) != nil || len(rows) != tc.want {
			t.Fatalf("search %q want %d: %d %s", tc.q, tc.want, r.Code, r.Body.String())
		}
	}
	r = crudScopeRequest(t, mux, http.MethodPatch, "/api/case_records/"+id, owner, map[string]any{"title": "Meadow inspection", "narrative": "revised private evidence"})
	if r.Code != 200 {
		t.Fatalf("update: %d %s", r.Code, r.Body.String())
	}
	for _, tc := range []struct {
		q    string
		want int
	}{{"harbor", 0}, {"meadow", 1}} {
		r = crudScopeRequest(t, mux, http.MethodGet, "/api/case_records?q="+tc.q, owner, nil)
		var rows []map[string]any
		if r.Code != 200 || json.Unmarshal(r.Body.Bytes(), &rows) != nil || len(rows) != tc.want {
			t.Fatalf("updated search %q: %d %s", tc.q, r.Code, r.Body.String())
		}
	}
	r = crudScopeRequest(t, mux, http.MethodGet, "/api/case_records/"+id+"/versions/1", owner, nil)
	if r.Code != 200 || !strings.Contains(r.Body.String(), "private evidence") || strings.Contains(r.Body.String(), "hidden-canary") {
		t.Fatalf("history: %d %s", r.Code, r.Body.String())
	}
	r = crudScopeRequest(t, mux, http.MethodDelete, "/api/case_records/"+id, owner, nil)
	if r.Code != 200 {
		t.Fatalf("delete: %d %s", r.Code, r.Body.String())
	}
	r = crudScopeRequest(t, mux, http.MethodGet, "/api/case_records?q=meadow", owner, nil)
	if r.Code != 200 || strings.TrimSpace(r.Body.String()) != "[]" {
		t.Fatalf("deleted search: %d %s", r.Code, r.Body.String())
	}
}

func TestFTSTextPrimaryKeyExistingRowsAndKeyChanges(t *testing.T) {
	db := openFTSTestDB(t)
	defer db.Close()
	mustExec(t, db, "CREATE TABLE projects(id TEXT PRIMARY KEY,title TEXT)")
	mustExec(t, db, "INSERT INTO projects(id,title) VALUES('a','Harbor existing'),('b','Meadow existing')")
	tables := []Table{{Name: "projects", FullText: [][]string{{"title"}}}}
	if err := EnsureFTSTables(db, tables); err != nil {
		t.Fatalf("index existing UUID/text records: %v", err)
	}
	assertMatch := func(term string, want int) {
		t.Helper()
		var got int
		if err := db.QueryRow("SELECT count(*) FROM projects_fts WHERE projects_fts MATCH ?", term).Scan(&got); err != nil || got != want {
			t.Fatalf("match %s = %d, want %d: %v", term, got, want, err)
		}
	}
	assertMatch("harbor", 1)
	mustExec(t, db, "UPDATE projects SET id='changed' WHERE id='a'")
	assertMatch("harbor", 1)
	mustExec(t, db, "UPDATE projects SET title='Lakeside updated' WHERE id='changed'")
	assertMatch("harbor", 0)
	assertMatch("lakeside", 1)
	if err := EnsureFTSTables(db, tables); err != nil {
		t.Fatal(err)
	}
	assertMatch("lakeside", 1)
	mustExec(t, db, "DELETE FROM projects WHERE id='changed'")
	assertMatch("lakeside", 0)
	assertMatch("meadow", 1)
	mustExec(t, db, "VACUUM")
	assertMatch("meadow", 1)
	var publicID string
	if err := db.QueryRow("SELECT p.id FROM projects p JOIN projects_fts f ON p._rowid_=f.rowid WHERE projects_fts MATCH 'meadow'").Scan(&publicID); err != nil || publicID != "b" {
		t.Fatalf("vacuum changed search/public-id mapping: %q %v", publicID, err)
	}
}

func TestFTSTextKeyUpgradesLegacyIndex(t *testing.T) {
	db := openFTSTestDB(t)
	defer db.Close()
	mustExec(t, db, "CREATE TABLE projects(id TEXT PRIMARY KEY,title TEXT)")
	mustExec(t, db, "INSERT INTO projects(id,title) VALUES('900','Existing harbor')")
	legacy, err := makeFTSDefinition("projects", []string{"title"})
	if err != nil {
		t.Fatal(err)
	}
	mustExec(t, db, legacy.create)
	for _, trigger := range legacy.triggers {
		mustExec(t, db, trigger.sql)
	}
	mustExec(t, db, "INSERT INTO projects_fts(projects_fts) VALUES('rebuild')")
	if err := EnsureFTSTables(db, []Table{{Name: "projects", FullText: [][]string{{"title"}}}}); err != nil {
		t.Fatal(err)
	}
	var id string
	if err := db.QueryRow("SELECT p.id FROM projects p JOIN projects_fts f ON p._rowid_=f.rowid WHERE projects_fts MATCH 'harbor'").Scan(&id); err != nil || id != "900" {
		t.Fatalf("upgraded existing row = %q: %v", id, err)
	}
	mustExec(t, db, "INSERT INTO projects(id,title) VALUES('uuid-public-id','New harbor')")
	var count int
	if err := db.QueryRow("SELECT count(*) FROM projects_fts WHERE projects_fts MATCH 'harbor'").Scan(&count); err != nil || count != 2 {
		t.Fatalf("upgrade match count %d: %v", count, err)
	}
}

func TestFTSTextKeyUsesUnshadowedRowIDAndRejectsMissingIdentity(t *testing.T) {
	for _, tc := range []struct {
		name, extra, suffix string
		wantOK              bool
	}{
		{"plain", "", "", true},
		{"one_shadow", ", _rowid_ TEXT", "", true},
		{"two_shadows", ", _rowid_ TEXT, rowid TEXT", "", true},
		{"all_shadowed", ", _rowid_ TEXT, rowid TEXT, oid TEXT", "", false},
		{"without_rowid", "", " WITHOUT ROWID", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := openFTSTestDB(t)
			defer db.Close()
			mustExec(t, db, "CREATE TABLE projects(id TEXT PRIMARY KEY,title TEXT"+tc.extra+")"+tc.suffix)
			err := EnsureFTSTables(db, []Table{{Name: "projects", FullText: [][]string{{"title"}}}})
			if !tc.wantOK {
				if err == nil {
					t.Fatal("accepted source without an integer search identity")
				}
				var n int
				if err := db.QueryRow("SELECT count(*) FROM sqlite_master WHERE name='projects_fts'").Scan(&n); err != nil || n != 0 {
					t.Fatalf("refusal mutated index: %d %v", n, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			mustExec(t, db, "INSERT INTO projects(id,title) VALUES('public-text-id','Harbor')")
			var n int
			if err := db.QueryRow("SELECT count(*) FROM projects_fts WHERE projects_fts MATCH 'harbor'").Scan(&n); err != nil || n != 1 {
				t.Fatalf("shadow-safe search: %d %v", n, err)
			}
		})
	}
}

func TestFTSUUIDCapturedTriggerClosure(t *testing.T) {
	db := openFTSTestDB(t)
	defer db.Close()
	mustExec(t, db, "CREATE TABLE projects(id TEXT PRIMARY KEY,title TEXT)")
	if err := EnsureFTSTables(db, []Table{{Name: "projects", FullText: [][]string{{"title"}}}}); err != nil {
		t.Fatal(err)
	}
	generation := &appMCPRuntimeGeneration{view: &App{}, sourceFiles: map[string][]byte{"schema.prisma": []byte(`model Project {
 id String @id @default(uuid())
 headline String @map("title")
 @@fulltext([headline])
}`)}}
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	if err := verifyAppMCPDeclaredTriggerClosure(tx, generation, []string{"projects"}, false); err != nil {
		t.Fatalf("valid mapped UUID FTS closure refused: %v", err)
	}
	if _, err := tx.Exec("DROP TRIGGER projects_fts_au"); err != nil {
		t.Fatal(err)
	}
	if err := verifyAppMCPDeclaredTriggerClosure(tx, generation, []string{"projects"}, false); err == nil {
		t.Fatal("missing UUID FTS trigger was accepted")
	}
}
