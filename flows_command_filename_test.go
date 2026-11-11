//go:build !cli

package main

import (
	"strings"
	"testing"
)

// A command flow saved as flows/receive-stock.yaml was refused with
// "command filename must be flows/<safe-name>.yaml", which does not say what
// a safe name is or that the hyphen is the problem.
func TestCommandFileNameRefusalStatesTheRule(t *testing.T) {
	tables := map[string]bool{"work_items": true}
	if _, err := parseFlowCommandFile("flows/complete_item.yaml", []byte(commandFixtureForManifest), tables); err != nil {
		t.Fatalf("the fixture command must load under an allowed name: %v", err)
	}
	for name, rename := range map[string]string{
		"complete-item": "flows/complete_item.yaml",
		"CompleteItem":  "flows/completeitem.yaml",
		"complete.item": "flows/complete_item.yaml",
		"1st_item":      "", // no allowed name is one substitution away
	} {
		_, err := parseFlowCommandFile("flows/"+name+".yaml", []byte(commandFixtureForManifest), tables)
		if err == nil {
			t.Fatalf("flows/%s.yaml loaded as a command", name)
		}
		msg := err.Error()
		for _, want := range []string{`"` + name + `"`, "lowercase letters, digits and underscores", "no hyphen"} {
			if !strings.Contains(msg, want) {
				t.Errorf("flows/%s.yaml: refusal lacks %q: %s", name, want, msg)
			}
		}
		if rename != "" && !strings.Contains(msg, "rename it to "+rename) {
			t.Errorf("flows/%s.yaml: refusal does not offer %s: %s", name, rename, msg)
		}
		if rename == "" && strings.Contains(msg, "rename it to") {
			t.Errorf("flows/%s.yaml: refusal offers a name that is not allowed: %s", name, msg)
		}
	}

	// The push write gate says the same thing.
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE work_items (id INTEGER PRIMARY KEY, title TEXT NOT NULL, status TEXT NOT NULL);\n")
	gate := ValidateOnWriteIn(dir, "flows/complete-item.yaml", commandFixtureForManifest)
	if !strings.Contains(gate, "no hyphen") || !strings.Contains(gate, "rename it to flows/complete_item.yaml") {
		t.Errorf("write gate refusal does not state the rule: %s", gate)
	}
}
