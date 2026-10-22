//go:build !cli && !windows

package main

import (
	"os"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestConnectorGuideExamplesParse(t *testing.T) {
	data, err := os.ReadFile("docs/agent/connector.md")
	if err != nil {
		t.Fatal(err)
	}
	var examples []string
	for rest := string(data); ; {
		start := strings.Index(rest, "```yaml\n")
		if start < 0 {
			break
		}
		rest = rest[start+len("```yaml\n"):]
		end := strings.Index(rest, "\n```")
		if end < 0 {
			t.Fatal("unclosed YAML example")
		}
		example := rest[:end]
		var value any
		if err := yaml.Unmarshal([]byte(example), &value); err != nil {
			t.Fatalf("YAML example %d: %v", len(examples)+1, err)
		}
		examples = append(examples, example)
		rest = rest[end+len("\n```"):]
	}
	if len(examples) < 6 {
		t.Fatalf("expected the complete manifest and authoring examples, got %d", len(examples))
	}
	manifest, err := parseAppMCPManifestForReview([]byte(examples[0]))
	if err != nil || len(manifest.Tools) != 1 || manifest.Tools[0].Handler.Operation != "table.list" {
		t.Fatalf("complete Notes manifest does not pass review parsing: manifest=%+v err=%v", manifest, err)
	}
	if _, err := parseGHAFlowFile("flows/read_note.yaml", []byte(examples[2])); err != nil {
		t.Fatalf("read-flow example: %v", err)
	}
	if _, err := parseFlowCommandFile("flows/complete_task.yaml", []byte(examples[4]), map[string]bool{"tasks": true}); err != nil {
		t.Fatalf("command example: %v", err)
	}
}
