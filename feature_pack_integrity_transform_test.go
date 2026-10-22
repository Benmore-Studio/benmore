package main

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestFeatureInstallValidatesOriginalHashBeforeTransforms(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts FeatureInstallOptions
	}{
		{"model prefix", FeatureInstallOptions{ModelPrefix: "Ops"}},
		{"route prefix", FeatureInstallOptions{RoutePrefix: "ops"}},
		{"combined prefix", FeatureInstallOptions{ModelPrefix: "Ops", RoutePrefix: "ops"}},
		{"explicit maps", FeatureInstallOptions{ModelMap: map[string]string{"Handoff": "Transfer"}, RouteMap: map[string]string{"/handoff": "/transfer"}}},
	} {
		for _, altered := range []bool{false, true} {
			name := tc.name + "/valid"
			if altered {
				name = tc.name + "/altered"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				writeTestFile(t, dir, "schema.prisma", "model Existing {\n id Int @id\n}\n")
				writeTestFile(t, dir, "static/index.html", "existing host page")
				writeTestFile(t, dir, "data.db", "synthetic retained data marker")
				body := []byte(`<a href="/handoff">Handoff uses handoffs</a>`)
				pack := FeaturePack{
					Name: "Handoff", Slug: "handoff",
					Routes:       []string{"/handoff"},
					Files:        []FeaturePackFile{{Path: "static/handoff.html", SHA256: hashBytesSHA256(body), Size: int64(len(body))}},
					SchemaModels: []FeaturePackModel{curatedModel("Handoff", "model Handoff {\n id Int @id\n title String\n}\n")},
				}
				files := map[string][]byte{"static/handoff.html": append([]byte(nil), body...)}
				if altered {
					files["static/handoff.html"] = append(files["static/handoff.html"], []byte("<p>altered after export</p>")...)
				}
				originalBody := string(files["static/handoff.html"])
				originalHash := pack.Files[0].SHA256
				before := featureIntegrityTree(t, dir)
				opts := tc.opts
				opts.DryRun = true
				plan, err := PlanFeatureInstallWithOptions(dir, pack, files, opts)
				if err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(before, featureIntegrityTree(t, dir)) {
					t.Fatal("preview changed target source or retained data")
				}
				if plan.Blocked != altered {
					t.Errorf("preview blocked=%v, altered=%v: %+v", plan.Blocked, altered, plan)
				}
				if altered && !strings.Contains(strings.Join(plan.Collisions, "\n"), "static/handoff.html: sha256 mismatch") {
					t.Error("preview did not report the original file checksum mismatch")
				}
				applied, err := ApplyFeaturePackToDirWithOptions(dir, pack, files, opts)
				if altered {
					if err == nil || !applied.Blocked {
						t.Errorf("altered archive was applied: %v, %+v", err, applied)
					}
					if !reflect.DeepEqual(before, featureIntegrityTree(t, dir)) {
						t.Fatal("refused apply changed target source or retained data")
					}
				} else {
					if err != nil || applied.Blocked || len(applied.FileAdds) != 1 {
						t.Fatalf("valid transformed archive refused: %v, %+v", err, applied)
					}
					installed, err := os.ReadFile(filepath.Join(dir, applied.FileAdds[0]))
					if err != nil || string(installed) == string(body) || strings.Contains(string(installed), "altered after export") {
						t.Fatalf("valid payload was not transformed correctly: %s, %v", installed, err)
					}
					if got, _ := os.ReadFile(filepath.Join(dir, "data.db")); string(got) != before["data.db"] {
						t.Fatal("valid source install changed retained data")
					}
				}
				if pack.Files[0].SHA256 != originalHash || string(files["static/handoff.html"]) != originalBody {
					t.Fatal("planning/apply rewrote the original input integrity evidence")
				}
			})
		}
	}
}

func featureIntegrityTree(t *testing.T, dir string) map[string]string {
	t.Helper()
	files := map[string]string{}
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, err error) error {
		if err != nil || entry.IsDir() {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		files[filepath.ToSlash(rel)] = string(body)
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	return files
}
