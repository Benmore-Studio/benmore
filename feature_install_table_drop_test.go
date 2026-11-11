//go:build !cli

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The plan's part of the table-drop consent, with the instance's answer
// supplied: which pack files are judged, what the plan lists, and what blocks
// it. The check itself (the write gate's) is exercised with a real database
// in feature_install_table_drop_platform_test.go.
func TestFeatureInstallPlanListsDataDropsAndBlocksWithoutConsent(t *testing.T) {
	const existing = "model Note {\n  id Int @id @default(autoincrement())\n}\n\nmodel Tag {\n  id Int @id @default(autoincrement())\n}\n"
	const replacement = "model Note {\n  id Int @id @default(autoincrement())\n}\n"
	newTarget := func(t *testing.T) string {
		dir := t.TempDir()
		writeTestFile(t, dir, "schema.prisma", existing)
		writeTestFile(t, dir, "migrations/0001_seen.sql", "CREATE TABLE seen (id INTEGER PRIMARY KEY);\n")
		return dir
	}
	packOf := func(files map[string]string) (FeaturePack, map[string][]byte) {
		pack := FeaturePack{Name: "Pack", Slug: "pack"}
		bodies := map[string][]byte{}
		for p, body := range files {
			bodies[p] = []byte(body)
			pack.Files = append(pack.Files, FeaturePackFile{Path: p, SHA256: hashBytesSHA256([]byte(body)), Size: int64(len(body))})
		}
		return pack, bodies
	}
	// The instance's answer: the schema drops tags, one migration drops a column.
	var asked []string
	answer := func(rel, content string) []string {
		asked = append(asked, rel)
		switch rel {
		case "schema.prisma":
			if !strings.Contains(content, "model Tag") {
				return []string{"tags (2 rows)"}
			}
		case "migrations/0003_drop.sql":
			return []string{"DROP COLUMN notes.body (4 rows with a value)"}
		}
		return nil
	}
	packFiles := map[string]string{
		"schema.prisma":            replacement,
		"migrations/0001_seen.sql": "CREATE TABLE seen (id INTEGER PRIMARY KEY);\n", // the target holds it unchanged
		"migrations/0002_add.sql":  "CREATE TABLE more (id INTEGER PRIMARY KEY);\n",
		"migrations/0003_drop.sql": "ALTER TABLE notes DROP COLUMN body;\n",
		"migrations/note.txt":      "not a migration",
		"docs/schema.prisma":       replacement, // not the app's schema
		"static/page.tsx":          "export default () => null",
	}
	wantDrops := []string{"migrations/0003_drop.sql: DROP COLUMN notes.body (4 rows with a value)", "schema.prisma: tags (2 rows)"}

	t.Run("blocked without consent, nothing written", func(t *testing.T) {
		dir := newTarget(t)
		asked = nil
		pack, files := packOf(packFiles)
		plan, err := ApplyFeaturePackToDirWithOptions(dir, pack, files, FeatureInstallOptions{Replace: true, DataDrops: answer})
		if err == nil || !plan.Blocked || !reflect.DeepEqual(plan.TableDrops, wantDrops) {
			t.Fatalf("plan must be blocked and list the loss: blocked=%v table_drops=%q err=%v", plan.Blocked, plan.TableDrops, err)
		}
		// Only the files a load's schema step reads, and only when the
		// install changes them.
		if want := []string{"migrations/0002_add.sql", "migrations/0003_drop.sql", "schema.prisma"}; !reflect.DeepEqual(asked, want) {
			t.Fatalf("the instance was asked about %q, want %q", asked, want)
		}
		joined := strings.Join(plan.Collisions, "\n")
		for _, want := range []string{
			"schema.prisma: the pack's schema.prisma removes the model of a table that still holds data",
			"tags (2 rows). Nothing is installed.",
			"migrations/0003_drop.sql: it drops data this app still holds",
			"allow_table_drop (`--allow-table-drop`)",
		} {
			if !strings.Contains(joined, want) {
				t.Fatalf("collisions do not say %q: %q", want, plan.Collisions)
			}
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "schema.prisma")); string(b) != existing {
			t.Fatalf("a refused install replaced schema.prisma: %q", b)
		}
		if _, err := os.Stat(filepath.Join(dir, "migrations", "0003_drop.sql")); !os.IsNotExist(err) {
			t.Fatalf("a refused install wrote a migration: %v", err)
		}
	})
	t.Run("consent lists the loss and installs", func(t *testing.T) {
		dir := newTarget(t)
		pack, files := packOf(packFiles)
		plan, err := ApplyFeaturePackToDirWithOptions(dir, pack, files, FeatureInstallOptions{Replace: true, AllowTableDrop: true, DataDrops: answer})
		if err != nil || plan.Blocked || !plan.AllowTableDrop || !reflect.DeepEqual(plan.TableDrops, wantDrops) {
			t.Fatalf("plan with allow_table_drop: blocked=%v collisions=%q table_drops=%q err=%v", plan.Blocked, plan.Collisions, plan.TableDrops, err)
		}
		if b, _ := os.ReadFile(filepath.Join(dir, "schema.prisma")); string(b) != replacement {
			t.Fatalf("schema.prisma not replaced: %q", b)
		}
	})
	t.Run("a file the plan does not write is not judged", func(t *testing.T) {
		// Without replace the pack's schema.prisma is a "file exists"
		// collision: the install would not write it.
		dir := newTarget(t)
		asked = nil
		pack, files := packOf(map[string]string{"schema.prisma": replacement})
		plan, err := PlanFeatureInstallWithOptions(dir, pack, files, FeatureInstallOptions{DryRun: true, DataDrops: answer})
		if err != nil || !plan.Blocked || len(plan.TableDrops) != 0 || len(asked) != 0 {
			t.Fatalf("plan=%+v asked=%q err=%v", plan, asked, err)
		}
	})
	t.Run("more migration files than one install checks", func(t *testing.T) {
		// Each check is a dry run on the instance: past the limit none runs,
		// and the plan asks for the consent on that ground.
		dir := newTarget(t)
		many := map[string]string{"schema.prisma": replacement}
		for i := 0; i <= featureInstallMigrationCheckLimit; i++ {
			many[fmt.Sprintf("migrations/1%03d_step.sql", i)] = fmt.Sprintf("CREATE TABLE step_%d (id INTEGER PRIMARY KEY);\n", i)
		}
		note := fmt.Sprintf("migrations/: %d migration files not checked for data loss (an install checks at most %d)", featureInstallMigrationCheckLimit+1, featureInstallMigrationCheckLimit)
		asked = nil
		pack, files := packOf(many)
		plan, err := PlanFeatureInstallWithOptions(dir, pack, files, FeatureInstallOptions{DryRun: true, Replace: true, DataDrops: answer})
		if err != nil || !plan.Blocked || !reflect.DeepEqual(plan.TableDrops, []string{note, "schema.prisma: tags (2 rows)"}) {
			t.Fatalf("blocked=%v table_drops=%q err=%v", plan.Blocked, plan.TableDrops, err)
		}
		if !reflect.DeepEqual(asked, []string{"schema.prisma"}) {
			t.Fatalf("past the limit only schema.prisma is judged, asked %q", asked)
		}
		if joined := strings.Join(plan.Collisions, "\n"); !strings.Contains(joined, "migrations/: the pack adds or changes") || !strings.Contains(joined, "benmore push migrations/<file>") {
			t.Fatalf("collisions do not explain the unchecked files: %q", plan.Collisions)
		}
		plan, err = PlanFeatureInstallWithOptions(dir, pack, files, FeatureInstallOptions{DryRun: true, Replace: true, AllowTableDrop: true, DataDrops: answer})
		if err != nil || plan.Blocked || len(plan.TableDrops) != 2 {
			t.Fatalf("with allow_table_drop: blocked=%v collisions=%q table_drops=%q err=%v", plan.Blocked, plan.Collisions, plan.TableDrops, err)
		}
		// At the limit every file is judged.
		delete(many, fmt.Sprintf("migrations/1%03d_step.sql", featureInstallMigrationCheckLimit))
		asked = nil
		pack, files = packOf(many)
		if _, err := PlanFeatureInstallWithOptions(dir, pack, files, FeatureInstallOptions{DryRun: true, Replace: true, DataDrops: answer}); err != nil || len(asked) != featureInstallMigrationCheckLimit+1 {
			t.Fatalf("at the limit %d files must be judged, asked %d (%v)", featureInstallMigrationCheckLimit+1, len(asked), err)
		}
	})
	t.Run("models appended to schema.prisma remove nothing", func(t *testing.T) {
		dir := newTarget(t)
		asked = nil
		pack := FeaturePack{Name: "Pack", Slug: "pack", SchemaModels: []FeaturePackModel{curatedModel("Extra", "model Extra {\n  id Int @id @default(autoincrement())\n}")}}
		plan, err := PlanFeatureInstallWithOptions(dir, pack, nil, FeatureInstallOptions{DryRun: true, DataDrops: answer})
		if err != nil || plan.Blocked || len(asked) != 0 {
			t.Fatalf("plan=%+v asked=%q err=%v", plan, asked, err)
		}
	})
}
