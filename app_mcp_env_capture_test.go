//go:build !cli

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
)

func TestAppMCPCapturedEnvRendersReviewedGeneration(t *testing.T) {
	app, _ := auditApp(t)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);")
	writeTestFile(t, app.Dir, "index.html", "---\nengine: gotmpl\nauth: none\nlayout: none\n---\n<p>{{env \"OVERRIDE\"}}|{{env \"NUM\"}}|{{env \"GENERATED_ONLY\"}}</p>")
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, app.Dir)
	writeTestFile(t, app.Dir, "env.yaml", "OVERRIDE: approved-yaml\nNUM: 1.00\n")
	writeTestFile(t, app.Dir, ".benmore/env", "OVERRIDE=generated-override\nGENERATED_ONLY=generated-only\n")

	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	nextEnv, err := config.stageEnvironment(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if nextEnv["OVERRIDE"] != "generated-override" || nextEnv["GENERATED_ONLY"] != "generated-only" {
		t.Fatalf("merged environment = %#v", nextEnv)
	}
	app.mu.Lock()
	app.MCP, app.templateEnvSource = config.mcp, config.templateEnvSource
	app.mu.Unlock()
	helper := gotmplHelpers(app, nil)["env"].(func(string) string)

	if err := os.Remove(filepath.Join(app.Dir, "env.yaml")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "env.yaml", "OVERRIDE: changed-on-disk\nNUM: 99.0\nGENERATED_ONLY: changed-generated-only\n")
	if err := reloadAppConfigStaged(app, config, nextEnv); err != nil {
		t.Fatal(err)
	}
	if got := helper("OVERRIDE") + "|" + helper("NUM") + "|" + helper("GENERATED_ONLY"); got != "approved-yaml|1|" {
		t.Fatalf("saved helper changed generation: %q", got)
	}

	mux := http.NewServeMux()
	registerAppPageRoutes(mux, app, false)
	rec := httptest.NewRecorder()
	mux.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "approved-yaml|1|") || strings.Contains(rec.Body.String(), "changed-on-disk") || strings.Contains(rec.Body.String(), "generated-only") {
		t.Fatalf("reviewed page: HTTP %d %s", rec.Code, rec.Body.String())
	}

	// A saved helper remains bound to its render even after a new private
	// environment generation is successfully published.
	nextEnv, err = config.stageEnvironment(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := reloadAppConfigStaged(app, config, nextEnv); err != nil {
		t.Fatal(err)
	}
	if helper("OVERRIDE") != "approved-yaml" || gotmplHelpers(app, nil)["env"].(func(string) string)("OVERRIDE") != "changed-on-disk" {
		t.Fatal("helper did not retain its own generation across publication")
	}
}

func TestAppMCPCapturedAbsentEnvIgnoresLateFile(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, dir)
	config, err := loadRuntimeConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.stageEnvironment(dir); err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: dir}
	app.mu.Lock()
	app.MCP, app.templateEnvSource = config.mcp, config.templateEnvSource
	app.mu.Unlock()
	helper := gotmplHelpers(app, nil)["env"].(func(string) string)
	writeTestFile(t, dir, "env.yaml", "LATE_CAPTURE_KEY: late-value\n")
	if got := helper("LATE_CAPTURE_KEY"); got != "" {
		t.Fatalf("reviewed helper read late file: %q", got)
	}
	if got := EnvLookup(dir, "LATE_CAPTURE_KEY"); got != "late-value" {
		t.Fatalf("ordinary disk lookup = %q", got)
	}
}

func TestAppMCPEnvExcludedFromSourceCaptureAndFailedStage(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, dir)
	writeTestFile(t, dir, "env.yaml", "APPROVED: first\n")
	config, err := loadRuntimeConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.stageEnvironment(dir); err != nil {
		t.Fatal(err)
	}
	SetAppEnv(dir, "EXISTING", "keep")
	firstSource := append([]byte(nil), config.templateEnvSource...)
	firstFiles := config.sourceFiles
	firstHashes := config.mcp.sourceHashes
	firstContract, firstExecution := config.mcp.ContractDigest, config.mcp.ExecutionDigest

	writeTestFile(t, dir, "env.yaml", "APPROVED: second\n")
	reloaded, err := loadRuntimeConfig(dir)
	if err != nil {
		t.Fatal(err)
	}
	if reloaded.mcp.ContractDigest != firstContract || reloaded.mcp.ExecutionDigest != firstExecution || !reflect.DeepEqual(reloaded.sourceFiles, firstFiles) || !reflect.DeepEqual(reloaded.mcp.sourceHashes, firstHashes) {
		t.Fatal("env.yaml changed reviewed digests or captured source inventory")
	}
	if GetAppEnv(dir, "EXISTING") != "keep" {
		t.Fatal("source-only load published environment values")
	}

	writeTestFile(t, dir, "env.yaml", "APPROVED: [unterminated\n")
	if _, err := loadRuntimeConfig(dir); err != nil {
		t.Fatalf("source-only load read malformed env.yaml: %v", err)
	}
	if _, err := inspectAppMCPSource(dir); err != nil {
		t.Fatalf("source-only CLI inspection read malformed environment: %v", err)
	}
	if _, err := config.stageEnvironment(dir); err == nil {
		t.Fatal("explicit environment stage accepted malformed env.yaml")
	}
	if !bytes.Equal(config.templateEnvSource, firstSource) || GetAppEnv(dir, "EXISTING") != "keep" {
		t.Fatal("failed environment stage replaced prior capture or stored snapshot")
	}
}

func TestGotmplEnvHelpersObserveLockedImmutablePublication(t *testing.T) {
	app := &App{Dir: t.TempDir(), MCP: &AppMCPManifest{}, templateEnvSource: []byte("LEFT: a\nRIGHT: a\n")}
	var wg sync.WaitGroup
	start := make(chan struct{})
	for n := 0; n < 4; n++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 500; i++ {
				helper := gotmplHelpers(app, nil)["env"].(func(string) string)
				left, right := helper("LEFT"), helper("RIGHT")
				if left != right || left != "a" && left != "b" {
					t.Errorf("helper mixed environment generations: LEFT=%q RIGHT=%q", left, right)
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		for i := 0; i < 500; i++ {
			value := "a"
			if i%2 != 0 {
				value = "b"
			}
			manifest := &AppMCPManifest{}
			source := []byte("LEFT: " + value + "\nRIGHT: " + value + "\n")
			app.mu.Lock()
			app.MCP, app.templateEnvSource = manifest, source
			app.mu.Unlock()
		}
	}()
	close(start)
	wg.Wait()
}

func TestAppMCPEnvStartupAndFailedReloadPreservePrivateGeneration(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);")
	writeTestFile(t, dir, "index.html", "---\nengine: gotmpl\nauth: none\nlayout: none\n---\n<p>{{env \"PRIVATE_CAPTURE\"}}</p>")
	writeTestFile(t, dir, "env.yaml", "PRIVATE_CAPTURE: startup-value\n")
	writeTestFile(t, dir, ".benmore/env", "PRIVATE_CAPTURE=merged-value\n")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, dir)
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer app.Shutdown()
	if got := gotmplHelpers(app, nil)["env"].(func(string) string)("PRIVATE_CAPTURE"); got != "startup-value" {
		t.Fatalf("startup helper = %q", got)
	}
	if GetAppEnv(dir, "PRIVATE_CAPTURE") != "merged-value" {
		t.Fatal("startup did not publish canonical merged environment")
	}
	oldManifest := app.MCP
	writeTestFile(t, dir, "env.yaml", "PRIVATE_CAPTURE: [unterminated\n")
	if err := reloadAppConfig(app); err == nil {
		t.Fatal("reload accepted malformed private environment")
	}
	if app.MCP != oldManifest || GetAppEnv(dir, "PRIVATE_CAPTURE") != "merged-value" || gotmplHelpers(app, nil)["env"].(func(string) string)("PRIVATE_CAPTURE") != "startup-value" {
		t.Fatal("failed reload replaced the last good private generation")
	}
}
