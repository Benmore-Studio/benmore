//go:build !cli

package main

import (
	"fmt"
	"os"
	"path/filepath"
)

// Only the trusted Notes starter is bound automatically. Existing app edits
// require explicit review; this does not enable owner-controlled exposure.
func writeAppMCPStarter(dir string) error {
	source := []byte(`version: 1
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
`)
	manifest, err := parseAppMCPManifest(source)
	if err != nil {
		return fmt.Errorf("MCP starter: %w", err)
	}
	manifest.ExecutionSources = appMCPExecutionSourcesRuntime
	contract, execution, err := appMCPDigests(dir, manifest)
	if err != nil {
		return err
	}
	// Written like a review: the two-space source above with only the review
	// keys set, so the app's first edit can follow the file's own style.
	data, err := appMCPReviewedManifestBytes(source, contract, execution)
	if err != nil {
		return fmt.Errorf("MCP starter: %w", err)
	}
	return os.WriteFile(filepath.Join(dir, "mcp.yaml"), data, 0o644)
}
