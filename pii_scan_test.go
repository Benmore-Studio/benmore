//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPIIExposureWarnings(t *testing.T) {
	dir := t.TempDir()
	schema := `
model Customer {
  id           Int    @id @default(autoincrement())
  user_email   String
  phone_number String
  home_address String
  note         String
}
model Widget {
  id    Int    @id
  color String
}
model Member {
  id    Int    @id
  email String
}
`
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(schema), 0644); err != nil {
		t.Fatal(err)
	}
	models, err := ParsePrismaSchema(schema)
	if err != nil || len(models) != 3 {
		t.Fatalf("parse schema: %v (got %d models)", err, len(models))
	}
	table := map[string]string{} // model name -> table name (naming-rule independent)
	for _, m := range models {
		table[m.Name] = m.Table
	}

	// customer: read everyone + PII  -> flagged
	// widget:   read everyone, no PII -> not flagged
	// member:   read owner + PII     -> not flagged (scoped)
	appYaml := "access:\n" +
		"  " + table["Customer"] + ": { read: everyone }\n" +
		"  " + table["Widget"] + ": { read: everyone }\n" +
		"  " + table["Member"] + ": { read: owner }\n"
	if err := os.WriteFile(filepath.Join(dir, "app.yaml"), []byte(appYaml), 0644); err != nil {
		t.Fatal(err)
	}

	findings := piiExposureWarnings(dir)
	if len(findings) != 1 {
		t.Fatalf("expected exactly 1 PII finding, got %d: %+v", len(findings), findings)
	}
	f := findings[0]
	if f.Severity != "warning" {
		t.Errorf("severity = %q, want warning", f.Severity)
	}
	// snake_case PII columns must be caught (the `\b` regex missed these because
	// Go treats `_` as a word char - the exact bug this fix closes).
	if !strings.Contains(f.Message, table["Customer"]) || !strings.Contains(f.Message, "user_email") {
		t.Errorf("finding should name the customer table + the snake_case user_email column: %s", f.Message)
	}
	if strings.Contains(f.Message, table["Widget"]) {
		t.Errorf("widget (no PII) should not be flagged: %s", f.Message)
	}
}
