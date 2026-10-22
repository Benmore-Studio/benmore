//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// featurePackPathProtected judged the raw path, so a trailing "/." hid the
// protected basename while the join still landed on the file: a viewer's
// feature_export returned data.db or env.yaml, and an editor's install
// overwrote them.
func TestFeaturePackTrailingDotCannotReachProtectedFiles(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "name: fixture\n")
	writeTestFile(t, dir, "data.db", "SQLITE-DATABASE-BYTES")
	writeTestFile(t, dir, "env.yaml", "ENCRYPTION_KEY: fixture-secret\n")
	for _, p := range []string{"data.db/.", "env.yaml/.", "./env.yaml/.", "static/../env.yaml"} {
		_, files, _ := ExportFeaturePackFromDir(dir, FeaturePack{Name: "Fixture"}, []string{p}, nil, nil)
		for k, b := range files {
			if strings.Contains(string(b), "SQLITE-DATABASE-BYTES") || strings.Contains(string(b), "fixture-secret") {
				t.Fatalf("export of %q carried protected bytes as %q", p, k)
			}
		}
		_, files, _ = ExportFeaturePackFromDir(dir, FeaturePack{Name: "Fixture"}, nil, nil, []string{p})
		for k, b := range files {
			if strings.Contains(string(b), "SQLITE-DATABASE-BYTES") || strings.Contains(string(b), "fixture-secret") {
				t.Fatalf("flow export of %q carried protected bytes as %q", p, k)
			}
		}
	}
	for _, p := range []string{"env.yaml/.", "data.db/.", "."} {
		if !featurePackPathProtected(p) {
			t.Errorf("featurePackPathProtected(%q) = false", p)
		}
	}
	body := []byte("ENCRYPTION_KEY: replaced\n")
	pack := FeaturePack{APIVersion: featurePackAPIVersion, Kind: "FeaturePack", Name: "p", Slug: "p", Version: "1.0.0",
		Files: []FeaturePackFile{{Path: "env.yaml/.", SHA256: hashBytesSHA256(body), Size: int64(len(body))}}}
	files := map[string][]byte{"env.yaml/.": body}
	if plan, err := PlanFeatureInstallWithOptions(dir, pack, files, FeatureInstallOptions{DryRun: true, Replace: true}); err == nil && !plan.Blocked {
		_, _ = ApplyFeaturePackToDirWithOptions(dir, pack, files, FeatureInstallOptions{Replace: true})
	}
	if got, _ := os.ReadFile(filepath.Join(dir, "env.yaml")); strings.Contains(string(got), "replaced") {
		t.Fatal("feature install overwrote env.yaml through \"env.yaml/.\"")
	}
}
