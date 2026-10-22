//go:build !cli

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
)

// appMCPConnectorWithheldNotice explains a connector the app is about to turn
// off. Once mcp.yaml's review no longer binds the app's source (any changed
// file, a static image included), startup and reload load the app from disk
// with the connector withheld (loadServedRuntimeConfig) until the source is
// reviewed again. Returns "" when there is no mcp.yaml or the review matches.
func appMCPConnectorWithheldNotice(dir string) string {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return ""
	}
	data, err := root.ReadFile("mcp.yaml")
	root.Close()
	if errors.Is(err, fs.ErrNotExist) {
		return ""
	}
	if err != nil {
		return ""
	}
	manifest, err := parseAppMCPManifest(data)
	if err != nil || manifest == nil {
		return "" // malformed manifests are refused by the write gate and the loader
	}
	if err := validateAppMCPDigests(dir, manifest); err == nil {
		return ""
	}
	return "The change is live, but this app's MCP connector is off: mcp.yaml's review no longer matches the source. " +
		"If the app serves an MCP connector, review the change, run `benmore mcp review <appdir> --reviewed`, then push mcp.yaml. " +
		"If it doesn't, delete mcp.yaml (`benmore delete-file mcp.yaml`)." + appMCPUnpulledSourcesNote(dir, manifest)
}

// appMCPUnpulledSourcesNote names the reviewed source files a pulled
// workspace never holds, so a review made there can't match the server.
func appMCPUnpulledSourcesNote(dir string, m *AppMCPManifest) string {
	paths, more := appMCPUnpulledSources(dir, m, 8)
	if len(paths) == 0 {
		return ""
	}
	list := strings.Join(paths, ", ")
	if more > 0 {
		list += fmt.Sprintf(" and %d more", more)
	}
	note := " The review digest covers server files that `benmore pull` never writes (" + list + "), so a review made in a pulled workspace cannot match: " +
		"delete them on the server (`benmore delete-file <path>`) or review in a workspace that holds the same files."
	if m == nil || m.ExecutionSources == "" {
		note += " This review binds the whole tree; reviewing again binds only the files the runtime reads, which leaves most of these out."
	}
	return note
}

// noteAppMCPConnectorWithheld adds that warning to a write response. The write
// still succeeded, so ok is left alone.
func noteAppMCPConnectorWithheld(resp map[string]any, dir string) {
	if notice := appMCPConnectorWithheldNotice(dir); notice != "" {
		resp["mcp_connector_withheld"] = notice
	}
}
