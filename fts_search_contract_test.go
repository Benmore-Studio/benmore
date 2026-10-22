//go:build !cli

package main

import (
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func searchContractApp(t *testing.T, customFlow bool) (*App, *http.ServeMux, string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model Document {
  id Int @id @default(autoincrement())
  title String
  bodyText String
  @@fulltext([title, bodyText])
  @@map("articles")
}
model TextRecord {
  id String @id @default(cuid())
  title String
  @@map("text_records")
}
`)
	writeTestFile(t, dir, "app.yaml", "auth: {identifier: email}\naccess: {articles: everyone, text_records: everyone}\n")
	if customFlow {
		writeTestFile(t, dir, "flows/custom-search.yaml", "on:\n  request: {method: GET, path: /api/articles/search}\njobs:\n  reply:\n    steps:\n      - run: respond\n        with: {json: {custom_search: true}}\n")
	}
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "https://audit.example.invalid")
	sid := createCrudScopeSession(t, app, "reader@example.com", "admin", "", "")
	crudScopeMustExec(t, app.DB, "INSERT INTO articles(id,title,body_text) VALUES (1,'chosen','needle in mapped body'),(2,'other','irrelevant')")
	crudScopeMustExec(t, app.DB, "INSERT INTO text_records(id,title) VALUES ('search','literal record id')")
	return app, mux, sid
}

func TestSearchListUsesMappedPrismaTableMetadata(t *testing.T) {
	app, mux, sid := searchContractApp(t, false)
	table, cols := FTSTableFor(app.Tables, "articles")
	if table != "articles_fts" || !reflect.DeepEqual(cols, []string{"title", "body_text"}) {
		t.Fatalf("mapped schema lost FTS metadata: %q %v", table, cols)
	}
	assertListIDs(t, mux, sid, "/api/articles?q=needle", []float64{1})
	assertListIDs(t, mux, sid, "/api/articles?q=absent", []float64{})
}

func TestSearchPathRetainsAuthoredFlowAndTextRecord(t *testing.T) {
	app, mux, sid := searchContractApp(t, true)
	if len(app.Flows) != 1 {
		t.Fatal("custom search flow not loaded")
	}
	custom := crudScopeRequest(t, mux, http.MethodGet, "/api/articles/search?q=needle", sid, nil)
	if custom.Code != http.StatusOK || !strings.Contains(custom.Body.String(), `"custom_search":true`) {
		t.Fatalf("framework search replaced app flow: %d %s", custom.Code, custom.Body.String())
	}
	row := crudScopeRequest(t, mux, http.MethodGet, "/api/text_records/search", sid, nil)
	if row.Code != http.StatusOK || !strings.Contains(row.Body.String(), `"id":"search"`) {
		t.Fatalf("framework search replaced text id: %d %s", row.Code, row.Body.String())
	}
}
