//go:build !cli

package main

import (
	"bytes"
	"fmt"
	"io"
	"strings"
)

// Approved MCP commands keep their prepared operations, approvals and attempt
// history sealed under the app's ENCRYPTION_KEY, so a load whose mcp.yaml
// binds a command flow refuses to start without a durable key
// (appMCPConfiguredLifecycleKey). Encrypted fields have the same need and get
// a key pinned by the hosted restart that enables them; these helpers let
// command flows share that path and let checks say what is missing before a
// reload is refused.

// appMCPCommandKeyMessage explains the requirement to app builders. It names
// both the hosted recovery (a restart pins a key) and the self-hosted one.
const appMCPCommandKeyMessage = "approved MCP commands store sealed approvals under the app's ENCRYPTION_KEY, and this environment does not set one: every load of this source refuses with `operation lifecycle requires configured ENCRYPTION_KEY`. Hosted: the reload after a push that adds commands restarts the app instead, and the restart pins a key in the instance's environment (`benmore restart <app> --env <env>` does the same). Self-hosted or `benmore serve`: set ENCRYPTION_KEY (`openssl rand -hex 32`) in env.yaml or the process environment before starting, and keep it: it cannot be changed without the key-rotation workflow once commands have run."

// appSourceDeclaresMCPCommands reports that dir holds an mcp.yaml and at least
// one flows/<name>.yaml with a top-level command declaration: the source
// shape whose load needs a durable ENCRYPTION_KEY. The router runs it over a
// tenant's directory, so every level is read by handle (treeDir) and a link,
// FIFO or device is skipped rather than followed. Anything unreadable or
// malformed counts as no command: the caller then keeps its earlier behaviour
// and the app load reports the real error.
func appSourceDeclaresMCPCommands(dir string) bool {
	root, err := openTreeDir(dir)
	if err != nil {
		return false
	}
	defer root.Close()
	if info, err := root.lstat("mcp.yaml"); err != nil || !info.Mode().IsRegular() {
		return false
	}
	flows, err := root.openDir("flows")
	if err != nil {
		return false
	}
	defer flows.Close()
	names, err := flows.names()
	if err != nil {
		return false
	}
	for _, name := range names {
		if !strings.HasSuffix(name, ".yaml") {
			continue
		}
		data, err := readTreeRegularCapped(flows, name, maxForeignConfigBytes)
		if err != nil || !bytes.Contains(data, []byte("command")) {
			continue
		}
		var shape map[string]any
		if decodeConfigYAML(data, &shape) != nil {
			continue
		}
		if _, ok := shape["command"]; ok {
			return true
		}
	}
	return false
}

// readTreeRegularCapped reads the regular file name in d, refusing one larger
// than limit bytes.
func readTreeRegularCapped(d *treeDir, name string, limit int64) ([]byte, error) {
	f, _, err := d.openRegular(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("%s: larger than %d bytes", name, limit)
	}
	return data, nil
}

// appEnvironmentHasEncryptionKey reports whether the environment the app at
// dir loads with (env.yaml, the materialized .benmore/env, else the process
// environment: readAppEnv) sets ENCRYPTION_KEY. known is false when that
// environment cannot be read, so a check stays silent instead of guessing.
func appEnvironmentHasEncryptionKey(dir string) (has, known bool) {
	vars, err := readAppEnv(dir)
	if err != nil {
		return false, false
	}
	return vars["ENCRYPTION_KEY"] != "", true
}

// appMCPCommandKeyFindings warns, in benmore check / check_app and after a
// write of mcp.yaml or a flow, that the source declares commands the current
// environment cannot load. Source and upload checks pass such an app, so
// before this the first sign was a reload refused after the deploy reported
// success.
func appMCPCommandKeyFindings(dir, writtenPath string, liveDB bool) []CheckFinding {
	if !liveDB && writtenPath != "" && !writeAffectsOtherFiles(writtenPath) && !isFlowsSubdirFile(writtenPath) {
		return nil
	}
	if !appSourceDeclaresMCPCommands(dir) {
		return nil
	}
	if has, known := appEnvironmentHasEncryptionKey(dir); has || !known {
		return nil
	}
	return []CheckFinding{{Severity: "warning", Source: "mcp_connector", Message: appMCPCommandKeyMessage}}
}
