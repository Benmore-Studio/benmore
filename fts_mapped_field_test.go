//go:build !cli

package main

import (
	"net/http"
	"path/filepath"
	"strings"
	"testing"
)

func TestSearchMappedFulltextField(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "schema.prisma", `model Document {
  id Int @id @default(autoincrement())
  headline String @map("title")
  @@fulltext([headline])
  @@map("articles")
}
`)
	writeTestFile(t, dir, "app.yaml", "auth: {identifier: email}\naccess: {articles: everyone}\n")
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("valid mapped fulltext field could not load: %v", err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, true, "https://audit.example.invalid")
	sid := createCrudScopeSession(t, app, "reader@example.com", "admin", "", "")
	created := crudScopeRequest(t, mux, http.MethodPost, "/api/articles", sid, map[string]any{"title": "needle"})
	if created.Code != http.StatusOK && created.Code != http.StatusCreated {
		t.Fatalf("mapped record create failed: %d %s", created.Code, created.Body.String())
	}
	assertListIDs(t, mux, sid, "/api/articles?q=needle", []float64{1})
	assertListIDs(t, mux, sid, "/api/articles?q=absent", []float64{})
}

func TestSearchMappedFulltextFieldRejectsEncryptedColumn(t *testing.T) {
	schema := `model Document {
  id Int @id @default(autoincrement())
  privateBody String @map("body")
  @@fulltext([privateBody])
  @@map("articles")
}
`
	enc := &EncryptedFieldConfig{Fields: map[string][]EncryptedFieldDef{
		"articles": {{Column: "body"}},
	}}
	if got := validateFulltextEncryptedConflict(schema, enc, nil); !strings.Contains(got, "fulltext-encrypted-column") {
		t.Fatalf("mapped encrypted/fulltext overlap passed validation: %q", got)
	}
	const encrypted = "tables:\n  articles:\n    fields: [body]\n"
	dir := writeApp(t, map[string]string{"schema.prisma": schema, "encrypted.yaml": encrypted})
	inlineDir := writeApp(t, map[string]string{"schema.prisma": schema})
	for name, content := range map[string]string{
		"schema.prisma":  schema,
		"encrypted.yaml": encrypted,
		"app.yaml":       "encrypted: {articles: [body]}\n",
	} {
		target := dir
		if name == "app.yaml" {
			target = inlineDir // encrypted.yaml otherwise owns this table's policy.
		}
		if got := ValidateOnWriteIn(target, name, content); !strings.Contains(got, "fulltext-encrypted-column") {
			t.Errorf("%s write admitted mapped encrypted/fulltext overlap: %q", name, got)
		}
	}
	if report := RunCompleteCheck(dir, ""); report.Clean() || !strings.Contains(FormatReport(report), "fulltext-encrypted-column") {
		t.Errorf("app check admitted mapped encrypted/fulltext overlap: %+v", report)
	}
	enc.Fields["articles"][0].Column = "another_column"
	if got := validateFulltextEncryptedConflict(schema, enc, nil); got != "" {
		t.Fatalf("unrelated encrypted column refused: %s", got)
	}
}
