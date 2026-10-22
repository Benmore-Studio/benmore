//go:build !cli && !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// A runtime upgrade that tightens command rules (for example a templated
// mid-prepare refusal, accepted at compile time before) must disable only the
// connector: a deployed app that no longer compiles one command flow keeps
// loading, while the strict loaders behind check, review and the write gate
// still refuse it. The fleet check caught an app that otherwise failed to load.
func TestAppMCPCommandCompileErrorWithholdsConnectorOnly(t *testing.T) {
	app, _, _ := newCommandProviderTaskFixtureWithPolicies(t, hookTaskFlow, "")
	dir := app.Dir
	const anchor = "  prepare:\n    steps:\n"
	if !strings.Contains(hookTaskFlow, anchor) {
		t.Fatal("fixture prepare anchor moved")
	}
	invalid := strings.Replace(hookTaskFlow, anchor, anchor+
		"      - if: '${{ params.arguments.id }} == 0'\n        steps:\n          - run: respond\n            with: {status: 409, json: {error: '${{ params.arguments.id }}'}}\n", 1)
	writeTestFile(t, dir, "flows/complete_item.yaml", invalid)
	// Re-seal so the review itself is current: only the runtime rule refuses.
	raw, err := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseAppMCPManifest(raw)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ContractDigest, manifest.ExecutionDigest, err = appMCPDigests(dir, manifest); err != nil {
		t.Fatal(err)
	}
	sealed, _ := yaml.Marshal(manifest)
	writeTestFile(t, dir, "mcp.yaml", string(sealed))

	if _, err := loadRuntimeConfig(dir); err == nil || !strings.Contains(err.Error(), "command response") {
		t.Fatalf("strict load must refuse the invalid command: %v", err)
	}
	c, err := loadServedRuntimeConfig(dir)
	if err != nil {
		t.Fatalf("served load must keep the app up: %v", err)
	}
	if c.mcp != nil || !strings.Contains(c.mcpWithheld, "command response") {
		t.Fatalf("connector must be withheld with the reason: mcp=%v withheld=%q", c.mcp != nil, c.mcpWithheld)
	}
	for _, flow := range c.flows {
		if flow.Name == "complete_item" {
			t.Fatal("the invalid command flow was loaded")
		}
	}
}
