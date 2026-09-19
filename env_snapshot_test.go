//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestEnvSnapshotRejectsMalformedFilesWithoutReplacingValues(t *testing.T) {
	for _, kind := range []string{"yaml", "environment", "unreadable"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			SetAppEnv(dir, "EXISTING", "keep")
			switch kind {
			case "yaml":
				if err := os.WriteFile(filepath.Join(dir, "env.yaml"), []byte("API_KEY: [invalid]\n"), 0600); err != nil {
					t.Fatal(err)
				}
			case "environment":
				if err := os.Mkdir(filepath.Join(dir, ".benmore"), 0700); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(filepath.Join(dir, ".benmore", "env"), []byte("API_KEY=\"unclosed"), 0600); err != nil {
					t.Fatal(err)
				}
			case "unreadable":
				if err := os.Mkdir(filepath.Join(dir, "env.yaml"), 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := LoadEnv(dir); err == nil {
				t.Fatal("invalid snapshot accepted")
			}
			if GetAppEnv(dir, "EXISTING") != "keep" {
				t.Fatal("last good snapshot lost")
			}
			if app, err := loadApp(dir); err == nil {
				app.Shutdown()
				t.Fatal("startup accepted invalid environment")
			}
			if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
				t.Fatal("startup opened a database before validating env")
			}
		})
	}
}
func TestEnvSnapshotQuotedValuesRoundTrip(t *testing.T) {
	for _, value := range []string{"", " plain value ", "line one\nline two", `slashes\\and\"quotes`, "$VALUE`command`", "unicode λ"} {
		vars, err := parseAppEnvironmentFile("FIXTURE=" + quoteAppEnvValue(value) + "\nNEXT=plain\n")
		if err != nil || vars["FIXTURE"] != value || vars["NEXT"] != "plain" {
			t.Fatalf("quoted value did not round-trip: %v", err)
		}
	}
}

func TestEnvSnapshotRejectsValuesSystemdCannotLoad(t *testing.T) {
	for _, value := range []string{"nul\x00", "invalid\xff", "bom\uFEFF", "noncharacter\uFDD0", "plane\U0001FFFF"} {
		if _, err := parseAppEnvironmentFile("FIXTURE=" + quoteAppEnvValue(value) + "\n"); err == nil {
			t.Fatal("accepted a value systemd cannot load")
		}
	}
}
