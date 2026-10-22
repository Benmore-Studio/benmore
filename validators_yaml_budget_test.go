//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateOnWriteYAMLResourceLimits(t *testing.T) {
	// Just above the existing mapping budget; no changes to its limits.
	wide := flatYAML(20_001)
	for _, tc := range []struct {
		name, path, content, want string
	}{
		{"app", "app.yaml", wide, "too many keys"},
		{"flow", "flows/a.yaml", wide, "too many keys"},
		{"generic yml", "translations.YML", wide, "too many keys"},
		{"later document", "settings.yaml", "small: true\n---\n" + wide, "too many keys"},
		{"bytes", "env.yaml", "#" + strings.Repeat("x", yamlMaxBytes), "the limit is"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			msg := ValidateOnWriteIn(t.TempDir(), tc.path, tc.content)
			if !strings.HasPrefix(msg, "yaml resource limit in "+tc.path+": ") ||
				!strings.Contains(msg, tc.want) || !strings.HasSuffix(msg, writeRejectionFooter) {
				t.Fatalf("missing early resource refusal: %q", msg)
			}
		})
	}
}

func TestValidateOnWriteYAMLResourceGuardPreservesOtherChecks(t *testing.T) {
	dir := t.TempDir()
	if msg := ValidateOnWriteIn(dir, "settings.yml", "small: [1, 2]\n"); msg != "" {
		t.Fatalf("ordinary YAML refused: %s", msg)
	}
	if msg := ValidateOnWriteIn(dir, "settings.yaml", "small: [unclosed"); !strings.Contains(msg, "yaml syntax") {
		t.Fatalf("syntax error lost: %q", msg)
	}
	// A fabricated credential-shaped value, never a real credential.
	secret := "key: ghp_" + strings.Repeat("a", 36) + "\n"
	if msg := ValidateOnWriteIn(dir, "settings.yml", secret); !strings.Contains(msg, "[secrets]") {
		t.Fatalf("credential check lost: %q", msg)
	}
	if msg := ValidateOnWriteIn(dir, "pnpm-lock.yaml", flatYAML(20_001)); msg != validateForbiddenPath("pnpm-lock.yaml") {
		t.Fatalf("forbidden path no longer takes precedence: %q", msg)
	}
	if msg := ValidateOnWriteIn(dir, "notes.txt", flatYAML(20_001)); msg != "" {
		t.Fatalf("YAML guard applied to ordinary text: %q", msg)
	}
}

func TestYAMLResourceRefusalSharedBySourceAndCompleteChecks(t *testing.T) {
	dir := t.TempDir()
	path := "computed.yaml"
	content := flatYAML(20_001)
	if err := os.WriteFile(filepath.Join(dir, path), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	want := ValidateOnWriteIn(dir, path, content)
	if !strings.Contains(want, "too many keys") {
		t.Fatalf("write accepted over-budget content: %q", want)
	}
	for name, check := range map[string]func(string, string) CheckReport{
		"source": RunSourceCheck, "complete": RunCompleteCheck,
	} {
		t.Run(name, func(t *testing.T) {
			report := check(dir, path)
			for _, f := range report.Findings {
				if f.File == path && f.Severity == "error" && f.Source == "syntax" && f.Message == want {
					return
				}
			}
			t.Fatalf("check lost the write refusal: %+v", report)
		})
	}
	if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
		t.Fatalf("refused source check opened a live database: %v", err)
	}
}
