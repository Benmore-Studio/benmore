//go:build !cli

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

func loadFlowsChecked(dir string, allowLegacy bool) ([]Flow, error) {
	paths := []string{"flows.yaml"}
	entries, err := os.ReadDir(filepath.Join(dir, "flows"))
	if err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("read flows: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".yaml") {
			paths = append(paths, filepath.Join("flows", entry.Name()))
		}
	}
	var out []Flow
	names := map[string]bool{}
	for _, path := range paths {
		data, err := readOptionalConfig(dir, path)
		if err != nil {
			return nil, err
		}
		var shape map[string]any
		if err := decodeConfigYAML(data, &shape); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
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
			out = append(out, flow)
		}
	}
	return out, nil
}

// Legacy root maps remain a runtime compatibility format, not an error fallback.
func parseLegacyFlowsYAML(data []byte) ([]Flow, error) {
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
		steps := convertSteps(f.Steps)
		if err := checkConvertedSteps(steps); err != nil {
			return nil, fmt.Errorf("flow %s: %w", name, err)
		}
		flows = append(flows, Flow{Name: name, Trigger: parseTrigger(f.Trigger), Verify: f.Verify, Secret: f.Secret, Transaction: f.Transaction, Auth: f.Auth, Role: f.Role, Steps: steps})
	}
	return flows, nil
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
