package main

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadEnv_ReadsBenmoreEnvFile pins the fix where SIGHUP-driven
// LoadEnv refreshes env vars from .benmore/env without a full process
// restart. Pre-fix, the process had to be restarted after every env.yaml
// edit because LoadEnv only read env.yaml + os.Environ() (both frozen at
// process start), so SIGHUP was a no-op for env vars.
func TestLoadEnv_ReadsBenmoreEnvFile(t *testing.T) {
	dir := t.TempDir()
	benmoreDir := filepath.Join(dir, ".benmore")
	if err := os.MkdirAll(benmoreDir, 0700); err != nil {
		t.Fatalf("mkdir .benmore: %v", err)
	}

	// Simulate what writeAppEnvFile produces: KEY="value" per line.
	envFile := filepath.Join(benmoreDir, "env")
	contents := `BENMORE_PORT=18042
ALPACA_KEY_ID="PKABCDEFGHIJK"
STRIPE_SECRET="sk_test_xyz"
HAS_QUOTE="value with \"escaped\" quotes"
# this is a comment

UNQUOTED_VAL=plain
`
	if err := os.WriteFile(envFile, []byte(contents), 0600); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	LoadEnv(dir)

	absDir, _ := filepath.Abs(dir)
	cases := map[string]string{
		"BENMORE_PORT":  "18042",
		"ALPACA_KEY_ID": "PKABCDEFGHIJK",
		"STRIPE_SECRET": "sk_test_xyz",
		"HAS_QUOTE":     `value with "escaped" quotes`,
		"UNQUOTED_VAL":  "plain",
	}
	for k, want := range cases {
		if got := GetEnv(absDir, k); got != want {
			t.Errorf("GetEnv(%q) = %q, want %q", k, got, want)
		}
	}
}

// TestLoadEnv_BenmoreEnvOverridesOsEnviron verifies the layering:
// .benmore/env wins over a stale os.Environ() entry. This is the
// crux of the fix — after an env.yaml edit, the systemd
// EnvironmentFile holds the new value but os.Environ() still has the
// old one (frozen at process start). The third-layer read must win.
func TestLoadEnv_BenmoreEnvOverridesOsEnviron(t *testing.T) {
	const key = "BENMORE_TEST_LAYERED_VAR"
	t.Setenv(key, "from-os-environ-at-start")

	dir := t.TempDir()
	benmoreDir := filepath.Join(dir, ".benmore")
	if err := os.MkdirAll(benmoreDir, 0700); err != nil {
		t.Fatalf("mkdir .benmore: %v", err)
	}
	envFile := filepath.Join(benmoreDir, "env")
	if err := os.WriteFile(envFile, []byte(key+"=\"freshly-set-via-benmore-env\"\n"), 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	LoadEnv(dir)

	absDir, _ := filepath.Abs(dir)
	got := GetEnv(absDir, key)
	want := "freshly-set-via-benmore-env"
	if got != want {
		t.Errorf("GetEnv(%q) = %q, want %q. The .benmore/env file should override os.Environ on LoadEnv. Pre-v2.7.7 the os.Environ stale value would have won.", key, got, want)
	}
}

// TestLoadEnv_UnsetVarRemovedFromStore pins the v2.7.7 fix where
// removing a var from env.yaml followed by SIGHUP-driven LoadEnv MUST
// remove X from the per-app store — not just leave the stale value
// behind because os.Environ() (frozen at process start) still has
// it. The whole point of hot-reloading env without restart breaks
// if unset doesn't actually unset in-process.
func TestLoadEnv_UnsetVarRemovedFromStore(t *testing.T) {
	const key = "BENMORE_TEST_UNSET_VAR"
	// Pre-seed os.Environ() with the var, simulating the start-time
	// systemd snapshot that contains the now-unset value.
	t.Setenv(key, "stale-from-process-start")

	dir := t.TempDir()
	benmoreDir := filepath.Join(dir, ".benmore")
	if err := os.MkdirAll(benmoreDir, 0700); err != nil {
		t.Fatalf("mkdir .benmore: %v", err)
	}
	envFile := filepath.Join(benmoreDir, "env")
	// File EXISTS but does NOT contain the var — the "after unset" state.
	if err := os.WriteFile(envFile, []byte("OTHER_VAR=\"still-here\"\n"), 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	LoadEnv(dir)

	absDir, _ := filepath.Abs(dir)
	if got := GetEnv(absDir, key); got != "" {
		// Note: GetEnv has a final fallback to os.Getenv (line ~134 of env.go)
		// so the os.Environ() value MIGHT still surface. The key test is the
		// per-app store specifically — that should NOT have it.
		appEnvStore.mu.RLock()
		storeVal, present := appEnvStore.apps[absDir][key]
		appEnvStore.mu.RUnlock()
		if present {
			t.Errorf("per-app store still has %s = %q after unset. The file is authoritative now; the os.Environ stale snapshot should not bleed into the store.", key, storeVal)
		}
	}

	// Sanity: vars actually in the file are still in the store.
	if got := GetEnv(absDir, "OTHER_VAR"); got != "still-here" {
		t.Errorf("OTHER_VAR should still be %q (it's in the file), got %q", "still-here", got)
	}
}

// TestFlatDataForCtx_EnvOverlay_ResolvesPipeForm pins the v2.7.7 fix
// for env vars accessed via pipe-form references. Pre-v2.7.7,
// `{{env.X | default:'fallback'}}` would always resolve to the
// fallback even when env.X was set — InterpolateEnv only handles
// the literal `{{env.X}}` form, so pipe-form refs survived past
// it, hit the main scanner, found nothing in flatData (env vars
// weren't surfaced there), and triggered the v2.7.6 default-pipe
// short-circuit. The result: every agent who wrote
// `${{ env.STRIPE_KEY | default:'' }}` got the empty default
// instead of the actual key — silently misconfiguring outbound
// auth.
func TestFlatDataForCtx_EnvOverlay_ResolvesPipeForm(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "FOO_KEY", "real-key-value")
	ctx := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}

	flat := flatDataForCtx(ctx)
	if got := flat["env.FOO_KEY"]; got != "real-key-value" {
		t.Errorf("flat[env.FOO_KEY] = %v, want \"real-key-value\". env overlay is the v2.7.7 mechanism that makes pipe-form refs resolve.", got)
	}

	// Round-trip through resolveBindExpr to confirm pipe-form works.
	val, ok := resolveBindExpr("env.FOO_KEY | default:'fallback'", flat)
	if !ok || val != "real-key-value" {
		t.Errorf("pipe-form resolve: got (%v, %v), want (\"real-key-value\", true). The default should be ignored because env.FOO_KEY resolves.", val, ok)
	}

	// Missing env + default: should hit the default short-circuit.
	val2, ok2 := resolveBindExpr("env.MISSING_KEY | default:'fallback'", flat)
	if !ok2 || val2 != "fallback" {
		t.Errorf("missing env + default: got (%v, %v), want (\"fallback\", true)", val2, ok2)
	}
}

// TestLoadEnv_MissingBenmoreEnvIsFine — a fresh app without a
// .benmore/env file shouldn't error or fail. LoadEnv falls back to
// env.yaml + os.Environ() like before. This covers the dev path and
// any app that hasn't had an env.yaml edit called yet.
func TestLoadEnv_MissingBenmoreEnvIsFine(t *testing.T) {
	dir := t.TempDir()
	// Write env.yaml so layer 1 has something.
	envYaml := filepath.Join(dir, "env.yaml")
	if err := os.WriteFile(envYaml, []byte("LEGACY_KEY: legacy-value\n"), 0644); err != nil {
		t.Fatalf("write env.yaml: %v", err)
	}

	LoadEnv(dir)

	absDir, _ := filepath.Abs(dir)
	if got := GetEnv(absDir, "LEGACY_KEY"); got != "legacy-value" {
		t.Errorf("env.yaml fallback broken: GetEnv(LEGACY_KEY) = %q, want %q", got, "legacy-value")
	}
}
