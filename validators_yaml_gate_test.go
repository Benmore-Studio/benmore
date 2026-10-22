//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func validatorsGateApp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	schema := "model Deal {\n  id Int @id @default(autoincrement())\n  value Float\n  stage String\n  startDate DateTime @map(\"start_date\")\n  endDate DateTime @map(\"end_date\")\n  closed Boolean @default(false)\n}\n"
	if err := os.WriteFile(filepath.Join(dir, "schema.prisma"), []byte(schema), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// validators.yaml rules that the evaluator would silently skip or always
// pass (a dropped key, a misspelled column, an operator it doesn't parse, a
// table that doesn't exist) are refused at write time and by `benmore check`.
// The loader is unchanged.
func TestValidatorsYAMLWriteGate(t *testing.T) {
	dir := validatorsGateApp(t)
	refused := map[string]string{
		"dropped key":        "deals:\n  - rule: \"value >= 0\"\n    message: \"no negatives\"\n",
		"no rule":            "deals:\n  - expr: \"value >= 0\"\n",
		"unknown table":      "deal:\n  - rule: \"value >= 0\"\n",
		"misspelled column":  "deals:\n  - rule: \"valeu >= 0\"\n",
		"no spaces":          "deals:\n  - rule: \"value>=0\"\n",
		"double equals":      "deals:\n  - rule: \"stage == 'won'\"\n",
		"and":                "deals:\n  - rule: \"value >= 0 AND value <= 100\"\n",
		"unquoted date":      "deals:\n  - rule: \"end_date > 2024-01-01\"\n",
		"constant truthy":    "deals:\n  - rule: \"true\"\n",
		"not a list":         "deals:\n  rule: \"value >= 0\"\n",
		"function call":      "deals:\n  - rule: \"end_date > date('now')\"\n",
		"non-column truthy":  "deals:\n  - rule: \"is_open\"\n",
		"two literals":       "deals:\n  - rule: \"'a' = 'a'\"\n",
		"empty rule":         "deals:\n  - rule: \"\"\n    error: \"x\"\n",
		"rule not a string":  "deals:\n  - rule: [value]\n",
		"entry not a map":    "deals:\n  - \"value >= 0\"\n",
		"yaml syntax":        "deals:\n  - rule: \"value >= 0\n",
		"multiple documents": "deals:\n  - rule: \"value >= 0\"\n---\nother: []\n",
	}
	for name, content := range refused {
		if msg := ValidateOnWriteIn(dir, "validators.yaml", content); msg == "" || !strings.Contains(msg, "validators.yaml") {
			t.Errorf("%s: want a validators.yaml refusal, got %q", name, msg)
		}
	}
	accepted := []string{
		"deals:\n  - rule: \"value >= 0\"\n    error: \"Deal value cannot be negative\"\n  - rule: \"end_date > start_date\"\n  - rule: \"stage != 'lost'\"\n  - rule: \"stage != draft\"\n  - rule: \"closed\"\n  - rule: \"value < 1e6\"\n  - rule: \"stage != 'on hold'\"\n",
		"",
		"# no rules yet\n",
	}
	for _, content := range accepted {
		if msg := ValidateOnWriteIn(dir, "validators.yaml", content); msg != "" {
			t.Errorf("valid validators.yaml refused:\n%s\n%s", content, msg)
		}
	}
	// Without a schema the table and column checks are skipped; the shape
	// checks still apply.
	bare := t.TempDir()
	if msg := ValidateOnWriteIn(bare, "validators.yaml", "anything:\n  - rule: \"x >= 0\"\n"); msg != "" {
		t.Errorf("schema-less app: %s", msg)
	}
	if msg := ValidateOnWriteIn(bare, "validators.yaml", "anything:\n  - rule: \"x>=0\"\n"); msg == "" {
		t.Error("schema-less app: an unparseable rule was accepted")
	}

	// `benmore check` reports the same file.
	if err := os.WriteFile(filepath.Join(dir, "validators.yaml"), []byte(refused["misspelled column"]), 0o644); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range RunSourceCheck(dir, "").Findings {
		if f.File == "validators.yaml" && f.Severity == "error" {
			found = true
		}
	}
	if !found {
		t.Fatal("benmore check did not report validators.yaml")
	}
	// The runtime still loads it.
	if cfg := parseValidatorsYAML([]byte(refused["misspelled column"])); cfg == nil || len(cfg.Rules["deals"]) != 1 {
		t.Fatalf("loader changed: %+v", cfg)
	}
}
