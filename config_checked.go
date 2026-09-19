//go:build !cli

package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Missing optional files disable a feature. Unreadable files and malformed
// replacements must never be mistaken for intentional removal.
func readOptionalConfig(dir, name string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(dir, name))
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read %s: %w", name, err)
	}
	return data, nil
}

func decodeConfigYAML(data []byte, target any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(target); err != nil {
		if err == io.EOF {
			return nil
		}
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("expected one YAML document")
	}
	return nil
}

func parseAppConfigDocument(data []byte) (map[string]any, *BackupConfig, error) {
	var raw map[string]any
	if err := decodeConfigYAML(data, &raw); err != nil {
		return nil, nil, fmt.Errorf("app.yaml: %w", err)
	}
	// All these sections are maps in the actual loaders. A list or scalar
	// otherwise silently discards auth, access, scoping, or worker settings.
	for _, key := range strings.Fields("colors typography spacing nav seo auth csp pwa recording table database features auto_memberships groups scopes access ws_rooms roles backup retention aggregates encrypted") {
		if value := raw[key]; value != nil {
			if _, ok := value.(map[string]any); !ok {
				return nil, nil, fmt.Errorf("app.yaml: %s must be a mapping", key)
			}
		}
	}
	for _, key := range strings.Fields("auth csp ws_rooms") {
		values, _ := raw[key].(map[string]any)
		for name, value := range values {
			switch value.(type) {
			case string, bool, int, float64:
			default:
				return nil, nil, fmt.Errorf("app.yaml: %s.%s must be a scalar", key, name)
			}
			if key == "ws_rooms" {
				s, ok := value.(string)
				if !ok || parseMemberOf("member-of:"+strings.ToLower(strings.TrimSpace(s))) == nil {
					return nil, nil, fmt.Errorf("app.yaml: ws_rooms.%s must be a membership rule", name)
				}
			}
		}
	}
	if groups, ok := raw["groups"].(map[string]any); ok && len(groups) > 0 {
		for _, key := range []string{"table", "key", "user_field"} {
			if s, ok := groups[key].(string); !ok || strings.TrimSpace(s) == "" {
				return nil, nil, fmt.Errorf("app.yaml: groups.%s must be a nonempty string", key)
			}
		}
	}
	access, _ := raw["access"].(map[string]any)
	for table, value := range access {
		switch rule := value.(type) {
		case string:
		case map[string]any:
			for op, mode := range rule {
				if _, ok := mode.(string); !ok {
					return nil, nil, fmt.Errorf("app.yaml: access.%s.%s must be a string", table, op)
				}
			}
		default:
			return nil, nil, fmt.Errorf("app.yaml: access.%s must be a string or mapping", table)
		}
	}
	roles, _ := raw["roles"].(map[string]any)
	for name, value := range roles {
		values := []any{value}
		if mapping, ok := value.(map[string]any); ok {
			values = nil
			for _, key := range []string{"scopes", "inherits"} {
				if v, exists := mapping[key]; exists {
					values = append(values, v)
				}
			}
		}
		for _, v := range values {
			switch v := v.(type) {
			case string:
			case []any:
				for _, entry := range v {
					if _, ok := entry.(string); !ok {
						return nil, nil, fmt.Errorf("app.yaml: roles.%s lists must contain strings", name)
					}
				}
			default:
				return nil, nil, fmt.Errorf("app.yaml: roles.%s scopes/inherits must be strings or lists", name)
			}
		}
	}
	var typed struct {
		Scopes    map[string]ScopeConfig             `yaml:"scopes"`
		Encrypted map[string][]EncryptedFieldDefYAML `yaml:"encrypted"`
	}
	if err := decodeConfigYAML(data, &typed); err != nil {
		return nil, nil, fmt.Errorf("app.yaml: %w", err)
	}
	for table, fields := range typed.Encrypted {
		for _, field := range fields {
			if strings.TrimSpace(field.Column) == "" {
				return nil, nil, fmt.Errorf("app.yaml: encrypted.%s requires column names", table)
			}
		}
	}
	backup, err := parseBackupConfig(raw)
	return raw, backup, err
}

func parseBackupConfig(raw map[string]any) (*BackupConfig, error) {
	value := raw["backup"]
	if value == nil {
		return nil, nil
	}
	m, ok := value.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("app.yaml: backup must be a mapping")
	}
	for key := range m {
		if key != "interval" && key != "keep" {
			return nil, fmt.Errorf("app.yaml: unknown backup key %q", key)
		}
	}
	interval, ok := m["interval"].(string)
	duration, err := time.ParseDuration(interval)
	if !ok || err != nil || duration < time.Minute {
		return nil, fmt.Errorf("app.yaml: backup.interval must be a duration of at least 1m")
	}
	config := &BackupConfig{Interval: duration, Keep: 20}
	if value, exists := m["keep"]; exists {
		keep, ok := value.(int)
		if !ok || keep < 1 {
			return nil, fmt.Errorf("app.yaml: backup.keep must be a positive integer")
		}
		config.Keep = keep
	}
	return config, nil
}

type runtimeConfig struct {
	design    *DesignConfig
	backup    *BackupConfig
	hooks     *HookConfig
	flows     []Flow
	workflows *WorkflowConfig
	cron      *CronConfig
}

// Stage fallible configuration before opening/migrating a DB or retiring the
// previous worker generation. Returned values, including deliberate nils, are
// the ones published by startup/reload.
func loadRuntimeConfig(dir string) (*runtimeConfig, error) {
	c := &runtimeConfig{}
	data, err := readOptionalConfig(dir, "app.yaml")
	if err != nil {
		return nil, err
	}
	raw, backup, err := parseAppConfigDocument(data)
	if err != nil {
		return nil, err
	}
	if raw != nil {
		c.design = designFromAppYAML(raw)
	}
	c.backup = backup
	data, err = readOptionalConfig(dir, "hooks.yaml")
	if err != nil {
		return nil, err
	}
	c.hooks, err = parseHooksYAML(data)
	if err != nil {
		return nil, err
	}
	c.flows, err = loadFlowsChecked(dir, true)
	if err != nil {
		return nil, err
	}
	c.workflows, err = loadWorkflowsYAMLChecked(dir)
	if err != nil {
		return nil, err
	}
	data, err = readOptionalConfig(dir, "cron.yaml")
	if err != nil {
		return nil, err
	}
	c.cron, err = parseCronYAML(data)
	if err != nil {
		return nil, err
	}
	data, err = readOptionalConfig(dir, "encrypted.yaml")
	if err != nil {
		return nil, err
	}
	if msg := validateEncryptedYAML(string(data)); msg != "" {
		return nil, fmt.Errorf("%s", msg)
	}
	return c, nil
}
