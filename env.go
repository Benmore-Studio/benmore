//go:build !cli

package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
)

// contextKey is an unexported type for context keys to prevent collisions.
type contextKey string

const appDirContextKey contextKey = "appDir"

// WithAppDir returns a new context with the app directory set.
func WithAppDir(ctx context.Context, dir string) context.Context {
	return context.WithValue(ctx, appDirContextKey, dir)
}

// AppDirFromContext extracts the app directory from a request context.
func AppDirFromContext(ctx context.Context) string {
	if dir, ok := ctx.Value(appDirContextKey).(string); ok {
		return dir
	}
	return ""
}

// AppDirFromRequest extracts the app directory from an HTTP request context.
func AppDirFromRequest(r *http.Request) string {
	return AppDirFromContext(r.Context())
}

// AppEnvStore holds per-app environment variables. Each app gets its own isolated map.
type AppEnvStore struct {
	mu   sync.RWMutex
	apps map[string]map[string]string // appDir → key → value
}

var appEnvStore = &AppEnvStore{
	apps: make(map[string]map[string]string),
}

// Platform processes must never import their own credentials into tenant apps.
// Set before loading any tenant by RegisterPlatformAPI.
var isolateAppEnvironment atomic.Bool

// LoadEnv snapshots this app's env.yaml and authoritative .benmore/env.
// Only dedicated app processes may import process env or systemd credentials.
// Missing keys never fall back to another app or to stale process values.
func LoadEnv(dir string) error {
	vars, err := readAppEnv(dir)
	if err != nil {
		return err
	}
	storeAppEnv(dir, vars)
	return nil
}

func readAppEnv(dir string) (map[string]string, error) {
	data, err := readOptionalConfig(dir, "env.yaml")
	if err != nil {
		return nil, fmt.Errorf("read env.yaml: %w", err)
	}
	return readAppEnvFromSource(dir, data)
}

// Runtime loads privately stage env.yaml once for both merged credentials and
// the YAML-only Go-template helper. Source-only inspection never calls this.
func (c *runtimeConfig) stageEnvironment(dir string) (map[string]string, error) {
	data, err := readOptionalConfig(dir, "env.yaml")
	if err != nil {
		return nil, err
	}
	vars, err := readAppEnvFromSource(dir, data)
	if err != nil {
		return nil, err
	}
	c.templateEnvSource = data
	return appVisibleEnvironment(vars), nil
}

func readAppEnvFromSource(dir string, data []byte) (map[string]string, error) {
	vars := make(map[string]string)
	if len(data) > 0 {
		if err := decodeConfigYAML(data, &vars); err != nil {
			return nil, fmt.Errorf("invalid env.yaml; expected a mapping of environment keys to string values")
		}
	}
	if vars == nil {
		vars = make(map[string]string)
	}
	for key, value := range vars {
		if !validAppEnvKey(key) || !validAppEnvValue(value) {
			return nil, fmt.Errorf("invalid environment entry in env.yaml")
		}
	}
	systemdFilePresent := false
	data, err := readOptionalConfig(dir, ".benmore/env")
	if err != nil {
		return nil, fmt.Errorf("read environment file: %w", err)
	}
	if data != nil {
		systemdFilePresent = true
		generated, err := parseAppEnvironmentFile(string(data))
		if err != nil {
			return nil, err
		}
		for key, value := range generated {
			vars[key] = value
		}
	}

	if !systemdFilePresent && !isolateAppEnvironment.Load() {
		for _, env := range os.Environ() {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				vars[parts[0]] = parts[1]
			}
		}
	}
	// Dedicated app processes may receive systemd credentials. Snapshot them
	// during load; a missing app key must never trigger a process-wide lookup.
	if !isolateAppEnvironment.Load() {
		if credDir := os.Getenv("CREDENTIALS_DIRECTORY"); credDir != "" {
			if entries, err := os.ReadDir(credDir); err == nil {
				for _, entry := range entries {
					key := strings.ToUpper(entry.Name())
					if !entry.IsDir() && validEnvCredentialName(key) && vars[key] == "" {
						vars[key] = processCredential(key)
					}
				}
			}
		}
	}

	// Shared hosts must load the owning vault before encryption and other
	// consumers initialize. A reload replaces the snapshot, including removals.
	vault, err := platformAppEnv(dir)
	if err != nil {
		return nil, err
	}
	for key, value := range vault {
		if !validAppEnvKey(key) || !validAppEnvValue(value) {
			return nil, fmt.Errorf("invalid stored environment entry")
		}
		vars[key] = value
	}
	return appVisibleEnvironment(vars), nil
}

// These credentials authenticate the runtime/operator, never app-authored
// templates or flows. ENCRYPTION_KEY and app provider keys remain app settings.
func runtimePrivateEnvKey(key string) bool {
	switch strings.ToUpper(key) {
	case "BENMORE_SERVER_SECRET", "BENMORE_MASTER_KEY", "BENMORE_PPROF_TOKEN", "BENMORE_METRICS_TOKEN",
		"BENMORE_AUDIT_WEBHOOK_SECRET", "BENMORE_AUDIT_WEBHOOK_TOKEN",
		"BENMORE_UPLOADS_S3_KEY", "BENMORE_UPLOADS_S3_SECRET",
		"BENMORE_MEDIA_S3_KEY", "BENMORE_MEDIA_S3_SECRET",
		"BENMORE_BUILDER_UPLOADS_KEY", "BENMORE_BUILDER_UPLOADS_SECRET":
		return true
	}
	return strings.HasPrefix(strings.ToUpper(key), "BENMORE_PLATFORM_") || strings.HasPrefix(strings.ToUpper(key), "BACKUP_S3_")
}

func appVisibleEnvironment(values map[string]string) map[string]string {
	visible := make(map[string]string, len(values))
	for key, value := range values {
		if !runtimePrivateEnvKey(key) {
			visible[key] = value
		}
	}
	return visible
}

func storeAppEnv(dir string, vars map[string]string) {
	absDir, _ := filepath.Abs(dir)
	appEnvStore.mu.Lock()
	appEnvStore.apps[absDir] = appVisibleEnvironment(vars)
	appEnvStore.mu.Unlock()
}

// SetAppEnv sets a single env var for a specific app.
func SetAppEnv(dir, key, value string) {
	if runtimePrivateEnvKey(key) {
		return
	}
	absDir, _ := filepath.Abs(dir)
	appEnvStore.mu.Lock()
	defer appEnvStore.mu.Unlock()
	if appEnvStore.apps[absDir] == nil {
		appEnvStore.apps[absDir] = make(map[string]string)
	}
	appEnvStore.apps[absDir][key] = value
}

// GetEnv resolves app keys only from that app's snapshot. An empty appDir
// is reserved for platform/operator configuration in the process environment.
func GetEnv(appDir, key string) string {
	if appDir != "" {
		return GetAppEnv(appDir, key)
	}
	if val := os.Getenv(key); val != "" {
		return val
	}
	return processCredential(key)
}

func validEnvCredentialName(key string) bool {
	if key == "" {
		return false
	}
	for _, c := range key {
		if c != '_' && (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') {
			return false
		}
	}
	return true
}

func processCredential(key string) string {
	if !validEnvCredentialName(key) {
		return ""
	}

	// systemd LoadCredential fallback. CREDENTIALS_DIRECTORY is set by
	// systemd to the per-unit private path containing files named after
	// each LoadCredential= entry. We use the lower-cased key as the
	// credential name to match standard convention.
	if credDir := os.Getenv("CREDENTIALS_DIRECTORY"); credDir != "" {
		root, err := os.OpenRoot(credDir)
		if err != nil {
			return ""
		}
		defer root.Close()
		if data, err := root.ReadFile(strings.ToLower(key)); err == nil {
			return strings.TrimRight(string(data), "\n")
		}
	}
	return ""
}

// AppEnvSnapshot returns a copy so callers never iterate a concurrently edited map.
func AppEnvSnapshot(dir string) map[string]string {
	return appEnvSnapshot(dir, nil)
}

// Caller holds app.mu when passing its bound generation. Cold replacement
// may replace the directory store while the older App is still serving.
func appEnvSnapshot(dir string, generation map[string]string) map[string]string {
	appEnvStore.mu.RLock()
	defer appEnvStore.mu.RUnlock()
	if generation == nil {
		absDir, _ := filepath.Abs(dir)
		generation = appEnvStore.apps[absDir]
	}
	return appVisibleEnvironment(generation)
}

// GetAppEnv returns an env var for a specific app directory.
func GetAppEnv(dir, key string) string {
	if runtimePrivateEnvKey(key) {
		return ""
	}
	absDir, _ := filepath.Abs(dir)
	appEnvStore.mu.RLock()
	defer appEnvStore.mu.RUnlock()
	if vars, ok := appEnvStore.apps[absDir]; ok {
		if val, ok := vars[key]; ok {
			return val
		}
	}
	return ""
}

// InterpolateEnv replaces compact env references using only the caller's app.
func InterpolateEnv(s string, appDir string) string {
	return interpolateEnvValues(s, AppEnvSnapshot(appDir))
}

func interpolateEnvForApp(s string, app *App) string {
	if app == nil {
		return s
	}
	app.mu.RLock()
	env := app.environment
	app.mu.RUnlock()
	if env != nil {
		return interpolateEnvValues(s, env)
	}
	return InterpolateEnv(s, app.Dir)
}

func interpolateEnvValues(s string, values map[string]string) string {
	for key, val := range values {
		if runtimePrivateEnvKey(key) {
			continue
		}
		s = strings.ReplaceAll(s, "{{env."+key+"}}", val)
	}
	return s
}
