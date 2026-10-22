//go:build !cli

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func loadFlowsChecked(dir string, allowLegacy bool) ([]Flow, error) {
	return loadFlowsCheckedFromSources(dir, allowLegacy, nil)
}

// appMCPCommandCompileError is a command flow file the current runtime cannot
// compile. Strict loaders (check, review, the write gate) refuse it; a served
// app loads with its connector withheld instead (loadServedRuntimeConfig), so
// a framework upgrade that tightens command rules never takes an app down.
type appMCPCommandCompileError struct{ err error }

func (e *appMCPCommandCompileError) Error() string { return e.err.Error() }
func (e *appMCPCommandCompileError) Unwrap() error { return e.err }

func loadFlowsCheckedFromSources(dir string, allowLegacy bool, captured map[string][]byte) ([]Flow, error) {
	return loadFlowsCheckedFromSourcesSkipping(dir, allowLegacy, captured, false)
}

// loadFlowsCheckedFromSourcesSkipping with skipInvalidCommands leaves out (and
// logs) command flow files that do not compile, for a connector-withheld load.
func loadFlowsCheckedFromSourcesSkipping(dir string, allowLegacy bool, captured map[string][]byte, skipInvalidCommands bool) ([]Flow, error) {
	paths := []string{"flows.yaml"}
	if captured == nil {
		entries, err := os.ReadDir(filepath.Join(dir, "flows"))
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("read flows: %w", err)
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
				paths = append(paths, filepath.Join("flows", entry.Name()))
			}
		}
	} else {
		var flowPaths []string
		for path := range captured {
			if strings.HasPrefix(path, "flows/") && strings.Count(path, "/") == 1 && strings.HasSuffix(path, ".yaml") {
				flowPaths = append(flowPaths, path)
			}
		}
		sort.Strings(flowPaths)
		paths = append(paths, flowPaths...)
	}
	var out []Flow
	names := map[string]bool{}
	var commandTables map[string]bool
	var commandColumns map[string]map[string]string
	commandTablesLoaded := false
	for _, path := range paths {
		var data []byte
		var err error
		if captured == nil {
			data, err = readOptionalConfig(dir, path)
			if err != nil {
				return nil, err
			}
		} else {
			data = captured[path]
			if data == nil {
				if path != "flows.yaml" {
					return nil, fmt.Errorf("%s: missing captured flow bytes", path)
				}
				continue
			}
		}
		var shape map[string]any
		if err := decodeConfigYAML(data, &shape); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		if _, commandPresent := shape["command"]; commandPresent {
			if path == "flows.yaml" {
				return nil, fmt.Errorf("%s: command declarations are only allowed in flows/<name>.yaml", path)
			}
			if !commandTablesLoaded {
				var definitions []crudTableDefinition
				var tableErr error
				if captured == nil {
					definitions, tableErr = appMCPSchemaTableDefinitions(dir)
				} else {
					definitions, tableErr = appMCPSchemaTableDefinitionsWithReader(func(name string) ([]byte, error) {
						if b, ok := captured[name]; ok {
							return b, nil
						}
						return nil, os.ErrNotExist
					})
				}
				if tableErr != nil {
					return nil, fmt.Errorf("command table inventory: %w", tableErr)
				}
				commandTables = eligibleCRUDTables(definitions)
				commandColumns = commandColumnInventory(definitions)
				commandTablesLoaded = true
			}
			flow, err := parseFlowCommandFileColumns(filepath.ToSlash(path), data, commandTables, commandColumns)
			if err != nil {
				if skipInvalidCommands {
					log.Printf("  MCP command flow %s left out (connector withheld): %v", path, err)
					continue
				}
				return nil, &appMCPCommandCompileError{fmt.Errorf("%s: %w", path, err)}
			}
			flow.Source = filepath.ToSlash(path)
			flow.sourceHash = hashBytesSHA256(data)
			if names[flow.Name] {
				return nil, fmt.Errorf("%s: duplicate flow name %q", path, flow.Name)
			}
			names[flow.Name] = true
			out = append(out, flow)
			continue
		}
		if len(shape) == 0 {
			continue
		}
		var flows []Flow
		_, on := shape["on"]
		_, jobs := shape["jobs"]
		if on || jobs {
			flows, err = parseGHAFlowFile(path, data)
		} else if path == "flows.yaml" {
			if !allowLegacy {
				continue
			}
			flows, err = parseLegacyFlowsYAML(data)
		} else {
			err = fmt.Errorf("expected file-level on and jobs")
		}
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		for _, flow := range flows {
			if names[flow.Name] {
				return nil, fmt.Errorf("%s: duplicate flow name %q", path, flow.Name)
			}
			names[flow.Name] = true
			flow.Source = filepath.ToSlash(path)
			flow.sourceHash = hashBytesSHA256(data)
			out = append(out, flow)
		}
	}
	return out, nil
}

// Legacy root maps remain a runtime compatibility format, not an error fallback.
func parseLegacyFlowsYAML(data []byte) ([]Flow, error) {
	if err := rejectLegacyHandledStatuses(data); err != nil {
		return nil, err
	}
	var raw map[string]FlowYAML
	if err := decodeConfigYAML(data, &raw); err != nil {
		return nil, err
	}
	var names []string
	for name := range raw {
		names = append(names, name)
	}
	sort.Strings(names)
	var flows []Flow
	for _, name := range names {
		f := raw[name]
		if strings.TrimSpace(f.Trigger) == "" || len(f.Steps) == 0 {
			return nil, fmt.Errorf("legacy flow %q requires trigger and steps", name)
		}
		if err := validateFlowPermissions(f.Permissions); err != nil {
			return nil, fmt.Errorf("flow %s: %w", name, err)
		}
		steps := convertSteps(f.Steps)
		if err := checkConvertedSteps(steps); err != nil {
			return nil, fmt.Errorf("flow %s: %w", name, err)
		}
		flows = append(flows, Flow{Name: name, Trigger: parseTrigger(f.Trigger), Verify: f.Verify, Secret: f.Secret, Transaction: f.Transaction, Auth: normalizeFlowAuth(f.Auth, name), Role: f.Role, Permissions: f.Permissions, Steps: steps})
	}
	return flows, nil
}

// rejectLegacyHandledStatuses prevents the new GHA-only API option from being
// silently discarded by the legacy line-shaped parser.
func rejectLegacyHandledStatuses(data []byte) error {
	var root any
	if err := decodeConfigYAML(data, &root); err != nil {
		return nil
	}
	var hasHandledStatus func(any) bool
	hasHandledStatus = func(steps any) bool {
		items, ok := steps.([]any)
		if !ok {
			return false
		}
		for _, item := range items {
			step, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if api, ok := step["api"].(map[string]any); ok {
				if _, declared := api["handled_statuses"]; declared {
					return true
				}
			}
			for _, branch := range []string{"steps", "else", "on_error"} {
				if hasHandledStatus(step[branch]) {
					return true
				}
			}
		}
		return false
	}
	rootFlows, ok := root.(map[string]any)
	if ok {
		for _, flow := range rootFlows {
			if flowMap, ok := flow.(map[string]any); ok && hasHandledStatus(flowMap["steps"]) {
				return fmt.Errorf("legacy `api:` steps do not support handled_statuses; use GHA `run: api` with `with.handled_statuses`")
			}
		}
	}
	return nil
}

func checkConvertedSteps(steps []FlowStep) error {
	for i, step := range steps {
		if step.Type == "" {
			return fmt.Errorf("step %d has no recognized action", i+1)
		}
		if err := checkConvertedSteps(step.Steps); err != nil {
			return err
		}
		if err := checkConvertedSteps(step.ElseSteps); err != nil {
			return err
		}
	}
	return nil
}
