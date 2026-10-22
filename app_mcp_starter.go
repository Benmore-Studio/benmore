//go:build !cli

package main

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// Only the trusted Notes starter is bound automatically. Existing app edits
// require explicit review; this does not enable owner-controlled exposure.
func writeAppMCPStarter(dir string) error {
	manifest, err := parseAppMCPManifest([]byte(`version: 1
connector: {id: notes-starter, name: Notes, version: '1'}
contract_digest: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
execution_digest: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
tools:
  - name: list_notes
    description: Read your notes
    handler: {kind: native, operation: table.list, table: notes}
    input_schema:
      type: object
      additionalProperties: false
      properties:
        page: {type: integer, minimum: 1}
        per_page: {type: integer, minimum: 1, maximum: 500}
    output_schema:
      type: object
      additionalProperties: false
      properties:
        id: {type: integer}
        title: {type: string}
        body: {type: string}
    permissions: [notes:read]
    effect: read
    approval: none
    idempotency: none
    reconciliation: none
    output: {include: [id, title, body]}
    component: none
resources: []
connections: []
`))
	if err != nil {
		return fmt.Errorf("MCP starter: %w", err)
	}
	manifest.ExecutionSources = appMCPExecutionSourcesRuntime
	manifest.ContractDigest, manifest.ExecutionDigest, err = appMCPDigests(dir, manifest)
	if err != nil {
		return err
	}
	data, err := yaml.Marshal(manifest)
	if err != nil {
		return fmt.Errorf("MCP starter: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, "mcp.yaml"), data, 0o644)
}
