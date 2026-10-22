package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFeatureExportRefusesProtectedDirectoryAlias(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, ".benmore/private-marker.txt", "fixture-only protected bytes")
	if err := os.MkdirAll(filepath.Join(dir, "static"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join("..", ".benmore"), filepath.Join(dir, "static", "assets")); err != nil {
		t.Fatal(err)
	}
	_, files, err := ExportFeaturePackFromDir(dir, FeaturePack{Name: "Boundary"}, []string{"static/assets/private-marker.txt"}, nil, nil)
	if err == nil {
		t.Fatalf("export accepted a protected directory alias: %q", files["static/assets/private-marker.txt"])
	}
	if len(files) != 0 {
		t.Fatalf("failed export returned file bodies: %v", files)
	}
}

func TestFeatureExportRefusesSymlinkedModelSource(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, ".benmore/models.prisma", "model Fixture {\n  id Int @id\n}\n")
	if err := os.Symlink(filepath.Join(".benmore", "models.prisma"), filepath.Join(dir, "schema.prisma")); err != nil {
		t.Fatal(err)
	}
	if pack, _, err := ExportFeaturePackFromDir(dir, FeaturePack{Name: "Boundary"}, nil, []string{"Fixture"}, nil); err == nil {
		t.Fatalf("model export accepted a protected source alias: %#v", pack.SchemaModels)
	}
}

func TestFeatureExportAcceptsRegularFilesAndModels(t *testing.T) {
	dir := t.TempDir()
	body := "export const Page = () => null"
	writeTestFile(t, dir, "static/page.tsx", body)
	writeTestFile(t, dir, "schema.prisma", "model Fixture {\n  id Int @id\n}\n")
	pack, files, err := ExportFeaturePackFromDir(dir, FeaturePack{Name: "Regular"}, []string{"static/page.tsx"}, []string{"Fixture"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(files["static/page.tsx"]) != body || len(pack.SchemaModels) != 1 || pack.SchemaModels[0].Name != "Fixture" {
		t.Fatalf("regular source/model export changed: files=%v models=%v", files, pack.SchemaModels)
	}
}

func TestFeatureExportNeverReadsSwappedProtectedAliases(t *testing.T) {
	for _, kind := range []string{"file", "parent", "model"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			const protectedMarker = "fixture-protected-marker"
			const publicBody = "fixture public source"
			writeTestFile(t, dir, "static/source.txt", publicBody)
			writeTestFile(t, dir, ".benmore/source.txt", protectedMarker)
			writeTestFile(t, dir, "schema.prisma", "model Fixture {\n  id Int @id\n}\n")
			writeTestFile(t, dir, ".benmore/models.prisma", "model Fixture {\n  id Int @id\n  marker String @default(\""+protectedMarker+"\")\n}\n")
			previous := featurePackBeforeRead
			t.Cleanup(func() { featurePackBeforeRead = previous })
			swapped := false
			featurePackBeforeRead = func(rel string) {
				if swapped {
					t.Fatal("unexpected repeated source read")
				}
				swapped = true
				path := filepath.Join(dir, filepath.FromSlash(rel))
				switch kind {
				case "file":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(filepath.Join("..", ".benmore", "source.txt"), path); err != nil {
						t.Fatal(err)
					}
				case "parent":
					if err := os.Rename(filepath.Join(dir, "static"), filepath.Join(dir, "original-static")); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(".benmore", filepath.Join(dir, "static")); err != nil {
						t.Fatal(err)
					}
				case "model":
					if err := os.Remove(path); err != nil {
						t.Fatal(err)
					}
					if err := os.Symlink(filepath.Join(".benmore", "models.prisma"), path); err != nil {
						t.Fatal(err)
					}
				}
			}
			paths, models := []string{"static/source.txt"}, []string(nil)
			if kind == "model" {
				paths, models = nil, []string{"Fixture"}
			}
			pack, files, err := ExportFeaturePackFromDir(dir, FeaturePack{Name: "Swap"}, paths, models, nil)
			if !swapped {
				t.Fatal("source swap boundary was not exercised")
			}
			for name, body := range files {
				if strings.Contains(string(body), protectedMarker) {
					t.Fatalf("export read protected bytes through swapped %s: %s", kind, name)
				}
			}
			for _, model := range pack.SchemaModels {
				if strings.Contains(model.Source, protectedMarker) {
					t.Fatal("model export read protected bytes through swapped source")
				}
			}
			if kind == "parent" {
				if err != nil || string(files["static/source.txt"]) != publicBody {
					t.Fatalf("export did not retain the opened source directory: %q, %v", files["static/source.txt"], err)
				}
			} else if err == nil {
				t.Fatalf("export accepted swapped %s symlink", kind)
			}
		})
	}
}
