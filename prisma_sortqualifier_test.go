//go:build !cli

package main

// Regression tests for the v2.7.167 migration-defect batch (field
// report: a Prisma sort qualifier emitted invalid SQLite, the broken
// migration retried on every boot appending a new .failed file each
// time - 391 in 8 days - and promote's rsync died on the app-owned
// .failed files).

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPrismaIndexSortQualifier(t *testing.T) {
	src := `
model LeadTouchpoint {
  id         Int      @id @default(autoincrement())
  projectId  Int
  occurredAt DateTime @default(now())

  @@index([projectId, occurredAt(sort: Desc)])
}
`
	models, err := ParsePrismaSchema(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	sql := EmitSQL(models)
	if strings.Contains(sql, "(sort:") || strings.Contains(sql, "_desc") {
		t.Fatalf("sort qualifier leaked into SQL:\n%s", sql)
	}
	if !strings.Contains(sql, "occurred_at DESC") {
		t.Errorf("expected `occurred_at DESC` in index columns, got:\n%s", sql)
	}
	if !strings.Contains(sql, "idx_lead_touchpoints_project_id_occurred_at") {
		t.Errorf("index name should use clean column names, got:\n%s", sql)
	}
}

func TestParsePrismaColumnListSorts(t *testing.T) {
	cols, sorts := parsePrismaColumnListSorts("@@index([projectId, occurredAt(sort: Desc), name(length: 10)])")
	wantCols := []string{"project_id", "occurred_at", "name"}
	wantSorts := []string{"", "DESC", ""}
	if len(cols) != 3 {
		t.Fatalf("cols = %v", cols)
	}
	for i := range wantCols {
		if cols[i] != wantCols[i] || sorts[i] != wantSorts[i] {
			t.Errorf("entry %d = (%q, %q), want (%q, %q)", i, cols[i], sorts[i], wantCols[i], wantSorts[i])
		}
	}
	// Qualifier with a comma inside must not split the entry.
	cols2, _ := parsePrismaColumnListSorts("@@index([a(sort: Desc, length: 5), b])")
	if len(cols2) != 2 || cols2[0] != "a" || cols2[1] != "b" {
		t.Errorf("paren-aware split broken: %v", cols2)
	}
}

func TestFailedMigrationDedup(t *testing.T) {
	dir := t.TempDir()
	// Same diff emitted twice with different timestamps/names - the
	// bodies match once comments are stripped.
	first := EmitMigrationSQL(MigrationDiff{TablesAdded: []PrismaModel{{Name: "Note", Table: "notes"}}}, "add_1_tables", "20260611T010101Z")
	second := EmitMigrationSQL(MigrationDiff{TablesAdded: []PrismaModel{{Name: "Note", Table: "notes"}}}, "add_1_tables", "20260611T020202Z")
	if first == second {
		t.Fatal("test premise: emissions should differ (timestamp header)")
	}
	if migrationBodyHash(first) != migrationBodyHash(second) {
		t.Fatal("body hash should ignore comment headers")
	}

	if err := os.WriteFile(filepath.Join(dir, "0001_x.sql.failed"), []byte(first), 0644); err != nil {
		t.Fatal(err)
	}
	if dup := findExistingFailedDup(dir, second); dup != "0001_x.sql.failed" {
		t.Errorf("expected dedup hit, got %q", dup)
	}
	// A genuinely different migration is NOT a dup.
	other := EmitMigrationSQL(MigrationDiff{TablesAdded: []PrismaModel{{Name: "Task", Table: "tasks"}}}, "add_1_tables", "20260611T030303Z")
	if dup := findExistingFailedDup(dir, other); dup != "" {
		t.Errorf("different migration deduped against %q", dup)
	}
}

