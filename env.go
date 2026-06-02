//go:build !cli

package main

import (
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

// Global fallback for single-app mode (benmore serve)
var EnvVars = make(map[string]string)

// LoadEnv refreshes the per-app env store from disk. Reads three
// sources in priority order (later wins):
//
//  1. <dir>/env.yaml — app source file (legacy, mostly empty in
//     cloud deployments; secrets aren't checked into git anyway).
//  2. os.Environ() — set by systemd's EnvironmentFile= at process
//     start. FROZEN once the process starts; systemd does not
//     refresh it on SIGHUP, only on full restart. So this source
//     is stale-but-not-wrong: it has the values the unit started
//     with, never anything newer.
//  3. <dir>/.benmore/env — the SAME file systemd reads as its
//     EnvironmentFile, but we read it directly. THIS is what
//     gets rewritten. Reading it here on every
//     LoadEnv() call (i.e. every SIGHUP) means an env edit followed
//     by hot reload picks up the new values without a real
//     restart. Previously the process had to be restarted
//     after env.yaml edits because SIGHUP
//     alone was a no-op for env vars — the source-of-truth file
//     just wasn't on LoadEnv's read path.
//
// Each source overrides earlier ones, so a `.benmore/env` write
// wins over both a stale os.Environ() entry AND any env.yaml
// value. That's the intent: tools that write env vars should
// see their write reflected in the running process within one
// SIGHUP cycle (a few hundred ms via the reload debouncer).
func LoadEnv(dir string) {
	vars := make(map[string]string)

	// Layer 1: env.yaml (legacy app source file).
	path := filepath.Join(dir, "env.yaml")
	data, err := os.ReadFile(path)
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				val := strings.TrimSpace(parts[1])
				val = strings.Trim(val, `"'`)
				vars[key] = val
			}
		}
	}

	// Layer 2: .benmore/env when it exists — the live systemd
	// EnvironmentFile, rewritten on env.yaml edits.
	// When this file is present we treat it as the AUTHORITATIVE
	// source for app-level env vars and SKIP the os.Environ() merge
	// below.
	//
	// Why authoritative-not-merged (v2.7.7+): systemd reads
	// .benmore/env once at unit start, snapshots into os.Environ(),
	// and never re-reads it. So os.Environ() is forever frozen at
	// the start-time snapshot. If the file later removes a key
	// (because a var was removed from env.yaml), a naive layered merge would
	// keep the stale os.Environ() value alive — defeating the whole
	// point of hot-reloading env vars without a restart. By making
	// the file authoritative when present, the per-app store
	// reflects exactly the current file contents, including
	// removals.
	//
	// Edge case: in dev mode (`benmore serve`) the file doesn't exist
	// and we fall through to os.Environ() like the legacy path. The
	// GetEnv function also has a final fallback to os.Getenv for any
	// key not in the per-app store, so system vars (PATH, HOME, etc)
	// that an agent might reference via `{{env.HOME}}` still resolve
	// even though we don't merge them into the per-app store.
	//
	// Format mirrors writeAppEnvFile() in deploy_systemd.go: one
	// `KEY="value"` per line, quotes optional, internal double-
	// quotes escaped as `\"`. We parse permissively — strip
	// optional surrounding double or single quotes, skip blank
	// and `#`-commented lines.
	systemdEnvPath := filepath.Join(dir, ".benmore", "env")
	systemdFilePresent := false
	if data, err := os.ReadFile(systemdEnvPath); err == nil {
		systemdFilePresent = true
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			eq := strings.IndexByte(trimmed, '=')
			if eq <= 0 {
				continue
			}
			key := strings.TrimSpace(trimmed[:eq])
			val := strings.TrimSpace(trimmed[eq+1:])
			// Strip a single layer of surrounding quotes if present.
			if len(val) >= 2 {
				if (val[0] == '"' && val[len(val)-1] == '"') ||
					(val[0] == '\'' && val[len(val)-1] == '\'') {
					val = val[1 : len(val)-1]
				}
			}
			// Un-escape `\"` → `"` (matches writeAppEnvFile's escape).
			val = strings.ReplaceAll(val, `\"`, `"`)
			vars[key] = val
		}
	}

	// Layer 3 (fallback only): os.Environ() — used in `benmore serve`
	// where no .benmore/env file exists, OR to catch system vars
	// (PATH/HOME/USER/etc.) for the host-mode single-process path.
	// In router mode the per-app process should never reach this
	// branch for app-level vars — they all come from the file.
	if !systemdFilePresent {
		for _, env := range os.Environ() {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) == 2 {
				vars[parts[0]] = parts[1]
			}
		}
	}

	// Store per-app
	absDir, _ := filepath.Abs(dir)
	appEnvStore.mu.Lock()
	appEnvStore.apps[absDir] = vars
	appEnvStore.mu.Unlock()

	// Also set global for single-app mode (benmore serve)
	EnvVars = vars
}

// SetAppEnv sets a single env var for a specific app.
func SetAppEnv(dir, key, value string) {
	absDir, _ := filepath.Abs(dir)
	appEnvStore.mu.Lock()
	defer appEnvStore.mu.Unlock()
	if appEnvStore.apps[absDir] == nil {
		appEnvStore.apps[absDir] = make(map[string]string)
	}
	appEnvStore.apps[absDir][key] = value
}

// GetEnv returns an environment variable for a specific app.
// appDir must be provided — no global state, no races.
//
// Lookup order:
//  1. Per-app env store (app's env.yaml + InjectPlatformEnv)
//  2. Global EnvVars map (single-app mode)
//  3. Process env (os.Getenv) — what systemd's Environment= injects
//  4. Systemd credentials directory ($CREDENTIALS_DIRECTORY/<key>) —
//     where LoadCredential= drops secrets so they DON'T show up via
//     `systemctl show --property=Environment`. The credentials file
//     content is the secret value (single-line, no trailing newline).
//
// The credentials fallback is what makes Stripe/Resend/etc secrets
// systemd-dbus-private. See the platform service unit for the
// LoadCredential= declarations.
func GetEnv(appDir, key string) string {
	if appDir != "" {
		absDir, _ := filepath.Abs(appDir)
		appEnvStore.mu.RLock()
		if vars, ok := appEnvStore.apps[absDir]; ok {
			if val, ok := vars[key]; ok {
				appEnvStore.mu.RUnlock()
				return val
			}
		}
		appEnvStore.mu.RUnlock()
	}

	// Fall back to global (single-app mode)
	if val, ok := EnvVars[key]; ok {
		return val
	}

	if val := os.Getenv(key); val != "" {
		return val
	}

	// systemd LoadCredential fallback. CREDENTIALS_DIRECTORY is set by
	// systemd to the per-unit private path containing files named after
	// each LoadCredential= entry. We use the lower-cased key as the
	// credential name to match standard convention.
	if credDir := os.Getenv("CREDENTIALS_DIRECTORY"); credDir != "" {
		credPath := filepath.Join(credDir, strings.ToLower(key))
		if data, err := os.ReadFile(credPath); err == nil {
			return strings.TrimRight(string(data), "\n")
		}
	}
	return ""
}

// GetAppEnv returns an env var for a specific app directory.
func GetAppEnv(dir, key string) string {
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

// InterpolateEnv replaces {{env.VAR}} in a string with env values for a specific app.
// Per-app values take precedence; global values fill in anything still unresolved.
// Previously this early-returned after consulting the per-app map, which meant keys
// only present in the global map (e.g. platform_env injected via InjectPlatformEnv)
// never got applied in multi-tenant host mode once the per-app map existed.
func InterpolateEnv(s string, appDir string) string {
	if appDir != "" {
		absDir, _ := filepath.Abs(appDir)
		appEnvStore.mu.RLock()
		if vars, ok := appEnvStore.apps[absDir]; ok {
			for key, val := range vars {
				s = strings.ReplaceAll(s, "{{env."+key+"}}", val)
			}
		}
		appEnvStore.mu.RUnlock()
	}

	// Fill in anything still unresolved from the global fallback. ReplaceAll is a
	// no-op if per-app already replaced the token, so per-app wins on conflict.
	for key, val := range EnvVars {
		s = strings.ReplaceAll(s, "{{env."+key+"}}", val)
	}
	return s
}
