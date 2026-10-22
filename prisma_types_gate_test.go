//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Reproduced by building a quiz app: Json options/correct/answers deployed
// successfully, but no corresponding columns were created. These are authoring
// refusals, not a new Json implementation or a loader compatibility change.
func TestSchemaPrismaWriteGateRefusesDroppedFieldTypes(t *testing.T) {
	for name, field := range map[string]string{
		"JSON":                       "options Json",
		"nullable JSON":              "answers Json?",
		"capitalized typo":           "title Strng",
		"undefined relation":         "owner Missing @relation(fields: [ownerId], references: [id])",
		"undefined reverse relation": "children Missing[]",
		"scalar list":                "labels String[]",
		"optional scalar list":       "counts Int?[]",
		"enum":                       "status State",
	} {
		t.Run(name, func(t *testing.T) {
			src := "model Quiz {\n id Int @id\n ownerId Int\n " + field + "\n}\nenum State { OPEN CLOSED }\n"
			if _, err := ParsePrismaSchema(src); err != nil {
				t.Fatalf("deployed loading compatibility changed: %v", err)
			}
			msg := ValidateOnWrite("schema.prisma", src)
			if !strings.Contains(msg, "model Quiz") || !strings.Contains(msg, "field "+strings.Fields(field)[0]) || !strings.Contains(msg, "line 4") {
				t.Fatalf("want actionable dropped-field refusal, got %q", msg)
			}
			if !strings.Contains(msg, "column") {
				t.Fatalf("missing persistence consequence: %q", msg)
			}
		})
	}
}

func TestSchemaPrismaWriteGatePreservesSupportedFieldTypes(t *testing.T) {
	src := `model Article {
 id Int @id
 ownerId Int
 owner Account @relation(fields: [ownerId], references: [id])
 reverse Profile?
 tags Tag[] @relation("ArticleTags")
 userId Int
 user User @relation(fields: [userId], references: [id])
 session Session?
 audits AuditLog[]
 s String?
 n BigInt
 f Float
 d Decimal
 b Boolean
 at DateTime
 bytes Bytes
}
model Account { id Int @id articles Article[] }
model Profile { id Int @id articleId Int article Article @relation(fields: [articleId], references: [id]) }
model Tag { id Int @id }
`
	if msg := ValidateOnWrite("schema.prisma", src); msg != "" {
		t.Fatalf("supported scalar/forward/reverse/reserved relations refused: %s", msg)
	}
	// Json may be a real app model name. Do not ban it by spelling alone.
	src = "model Document { id Int @id value Json? values Json[] }\nmodel Json { id Int @id text String }"
	if msg := ValidateOnWrite("schema.prisma", src); msg != "" {
		t.Fatalf("declared model reference refused: %s", msg)
	}
}

func TestSchemaPrismaCheckRefusesDroppedFieldTypes(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	src := "model Quiz {\n id Int @id\n answers Json?\n @@map(\"quiz_checks\")\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(src), 0600); err != nil {
		t.Fatal(err)
	}
	for _, check := range []func(string, string) CheckReport{RunSourceCheck, RunCompleteCheck} {
		report := check(dir, "schema.prisma")
		found := false
		for _, issue := range report.Findings {
			if issue.Severity == "error" && issue.File == "schema.prisma" && strings.Contains(issue.Message, "field answers") {
				found = true
			}
		}
		if !found {
			t.Fatalf("check did not expose omitted Json field: %#v", report)
		}
		if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
			t.Fatalf("refused schema check opened or migrated the live database: %v", err)
		}
	}
	// A previously deployed file still loads through the runtime parser. Only
	// authoring/check behavior changes; the omitted value is not recovered.
	app, err := loadApp(dir)
	if err != nil {
		t.Fatalf("existing deployed schema no longer loads: %v", err)
	}
	defer app.Shutdown()
	columns, err := GetTableColumns(app.DB, "quiz_checks")
	if err != nil {
		t.Fatal(err)
	}
	if len(columns) != 1 || columns[0].Name != "id" {
		t.Fatalf("loader changed persistence for unsupported Json: %#v", columns)
	}

}
