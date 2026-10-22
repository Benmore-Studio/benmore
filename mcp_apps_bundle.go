//go:build !cli

package main

// mcp_apps_bundle - the vendored MCP Apps browser bundle
// (@modelcontextprotocol/ext-apps 2.0.3, the package's own self-contained
// `app-with-deps.js` ES module). It is embedded here only; nothing serves it
// yet. Provenance, registry integrity, per-file sha256 and the licenses live in
// embedded/mcp-apps/VENDOR.json and are re-verified by mcp_apps_bundle_test.go.
// `!cli` keeps the ~410 KB bundle out of the cloud CLI binary.

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
)

const mcpAppsBundleName = "app-with-deps.js"

//go:embed embedded/mcp-apps
var mcpAppsFS embed.FS

// mcpAppsBundle returns the vendored browser bundle and its hex sha256.
func mcpAppsBundle() ([]byte, string) {
	b, err := mcpAppsFS.ReadFile("embedded/mcp-apps/" + mcpAppsBundleName)
	if err != nil {
		panic("mcp-apps: embedded bundle missing: " + err.Error())
	}
	sum := sha256.Sum256(b)
	return b, hex.EncodeToString(sum[:])
}
