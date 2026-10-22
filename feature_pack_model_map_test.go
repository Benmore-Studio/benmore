//go:build !cli

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// The fixture is the synthetic two-model module used in hosted build-first
// testing. Its source, authenticated completion flow and browser CRUD caller
// are exported and installed through the real feature-pack paths here.
func handoffModelMapPack(t *testing.T) (FeaturePack, map[string][]byte) {
	t.Helper()
	pack, files, err := ExportFeaturePackFromDir("testdata/feature-pack-handoffs", FeaturePack{Name: "Handoff model mapping"}, []string{"static/shift-desk.html", "docs/handoff-module.md"}, []string{"Handoff", "HandoffItem"}, []string{"complete-handoff"})
	if err != nil {
		t.Fatal(err)
	}
	// Exercise both model and table references, including ordinary CRUD URLs.
	refs := []byte(`const parent = 'Handoff'; const child = 'HandoffItem'; const parents = '/api/handoffs'; const children = '/api/handoff_items'; const sql = 'SELECT * FROM handoffs JOIN handoff_items'; const unrelated = 'HandoffItems handoffs_extra';`)
	files["static/references.ts"] = refs
	pack.Files = append(pack.Files, FeaturePackFile{Path: "static/references.ts", SHA256: hashBytesSHA256(refs), Size: int64(len(refs))})
	return pack, files
}

func TestFeatureModelMapsInstallDistinctModelsAndAllReferences(t *testing.T) {
	for _, tc := range []struct {
		name, parent, child, parentTable, childTable string
		opts                                         FeatureInstallOptions
	}{
		{"chained map", "Task", "Handoff", "tasks", "handoffs", FeatureInstallOptions{ModelMap: map[string]string{"Handoff": "Task", "HandoffItem": "Handoff"}}},
		{"swapped names", "HandoffItem", "Handoff", "handoff_items", "handoffs", FeatureInstallOptions{ModelMap: map[string]string{"Handoff": "HandoffItem", "HandoffItem": "Handoff"}}},
		{"partial parent map", "Task", "HandoffItem", "tasks", "handoff_items", FeatureInstallOptions{ModelMap: map[string]string{"Handoff": "Task"}}},
		{"partial child map", "Handoff", "Task", "handoffs", "tasks", FeatureInstallOptions{ModelMap: map[string]string{"HandoffItem": "Task"}}},
		{"disjoint names", "Transfer", "ChecklistItem", "transfers", "checklist_items", FeatureInstallOptions{ModelMap: map[string]string{"Handoff": "Transfer", "HandoffItem": "ChecklistItem"}}},
		{"prefix and exact map", "Task", "OpsHandoffItem", "tasks", "ops_handoff_items", FeatureInstallOptions{ModelPrefix: "Ops", ModelMap: map[string]string{"Handoff": "Task"}}},
		{"identity map", "Handoff", "HandoffItem", "handoffs", "handoff_items", FeatureInstallOptions{ModelMap: map[string]string{"Handoff": "Handoff"}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pack, files := handoffModelMapPack(t)
			beforePack, _ := json.Marshal(pack)
			beforeFiles, _ := json.Marshal(files)
			dir := t.TempDir()
			originalSchema := "model ExistingNote {\n id Int @id\n text String\n}\n"
			writeTestFile(t, dir, "schema.prisma", originalSchema)
			preview, err := PlanFeatureInstallWithOptions(dir, pack, files, tc.opts)
			if err != nil || preview.Blocked {
				t.Fatalf("preview refused valid mapping: %#v, %v", preview, err)
			}
			plan, err := ApplyFeaturePackToDirWithOptions(dir, pack, files, tc.opts)
			if err != nil || plan.Blocked || !reflect.DeepEqual(plan.SchemaAdds, preview.SchemaAdds) {
				t.Fatalf("apply disagrees with preview: %#v, %v", plan, err)
			}
			src, err := os.ReadFile(filepath.Join(dir, "schema.prisma"))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.HasPrefix(string(src), originalSchema) {
				t.Fatal("install changed the existing model")
			}
			models, err := ParsePrismaSchema(string(src))
			if err != nil {
				t.Fatalf("installed schema is invalid: %v", err)
			}
			byName := map[string]PrismaModel{}
			for _, model := range models {
				if _, exists := byName[model.Name]; exists {
					t.Fatalf("preview advertised %v but installed duplicate model %s", preview.SchemaAdds, model.Name)
				}
				byName[model.Name] = model
			}
			if len(byName) != 3 || byName[tc.parent].Table != tc.parentTable || byName[tc.child].Table != tc.childTable {
				t.Fatalf("installed names/tables disagree with mapping: %#v", byName)
			}
			if !strings.Contains(string(src), "items "+tc.child+"[]") || !strings.Contains(string(src), "handoff "+tc.parent+" @relation") {
				t.Fatalf("references in mapped/unmapped models did not follow the mapping:\n%s", src)
			}
			var parentRef string
			for _, field := range byName[tc.child].Fields {
				if field.Column == "handoff_id" {
					parentRef = field.FKTable
				}
			}
			if parentRef != tc.parentTable {
				t.Fatalf("child foreign key points to %q, want %q", parentRef, tc.parentTable)
			}
			flows := LoadFlowsGHA(dir)
			if len(flows) != 1 || flows[0].Trigger.Path != "/api/handoffs/:id/complete" || flows[0].Auth != "required" || !flows[0].Transaction || !strings.Contains(flows[0].Steps[0].SQL, "UPDATE "+tc.parentTable+" SET") || !strings.Contains(flows[0].Steps[0].SQL, "user_id=:user_id") {
				t.Fatal("installed custom route, authorization, transaction or SQL target changed incorrectly")
			}
			page, err := os.ReadFile(filepath.Join(dir, "static/shift-desk.html"))
			if err != nil || !strings.Contains(string(page), "'/api/"+tc.parentTable+"?limit=100'") {
				t.Fatalf("browser CRUD target was not renamed: %v", err)
			}
			refs, err := os.ReadFile(filepath.Join(dir, "static/references.ts"))
			wantRefs := "const parent = '" + tc.parent + "'; const child = '" + tc.child + "'; const parents = '/api/" + tc.parentTable + "'; const children = '/api/" + tc.childTable + "'; const sql = 'SELECT * FROM " + tc.parentTable + " JOIN " + tc.childTable + "'; const unrelated = 'HandoffItems handoffs_extra';"
			if err != nil || string(refs) != wantRefs {
				t.Fatalf("model/table references cascaded or lost boundaries:\n got %s\nwant %s\nerr %v", refs, wantRefs, err)
			}
			afterPack, _ := json.Marshal(pack)
			afterFiles, _ := json.Marshal(files)
			if string(beforePack) != string(afterPack) || string(beforeFiles) != string(afterFiles) {
				t.Fatal("preview/apply mutated the original pack or payload")
			}
		})
	}
}

func TestFeatureModelMapsRefuseCollisionsWithoutTargetChanges(t *testing.T) {
	for _, mapping := range []map[string]string{
		{"Handoff": "Task", "HandoffItem": "Task"}, // two explicit targets
		{"HandoffItem": "Handoff"},                 // collision with an unmapped model
	} {
		pack, files := handoffModelMapPack(t)
		dir := t.TempDir()
		original := "model ExistingNote {\n id Int @id\n}\n"
		writeTestFile(t, dir, "schema.prisma", original)
		opts := FeatureInstallOptions{ModelMap: mapping}
		preview, err := PlanFeatureInstallWithOptions(dir, pack, files, opts)
		if err != nil || !preview.Blocked {
			t.Fatalf("colliding map accepted: %#v, %v", preview, err)
		}
		if _, err := ApplyFeaturePackToDirWithOptions(dir, pack, files, opts); err == nil {
			t.Fatal("colliding map applied")
		}
		got, err := os.ReadFile(filepath.Join(dir, "schema.prisma"))
		if err != nil || string(got) != original {
			t.Fatal("refused install changed existing schema")
		}
		if _, err := os.Stat(filepath.Join(dir, "static")); !os.IsNotExist(err) {
			t.Fatal("refused install created payload files")
		}
	}
}
