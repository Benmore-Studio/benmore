//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

const (
	appMCPWorkerHooksFixture = `on_update:
  notes:
    - sql: SELECT 1
      when: "status = 'reviewed'"
`
	appMCPWorkerWorkflowsFixture = `review:
  table: notes
  field: status
  initial: draft
  transitions:
    draft:
      reviewed: {role: editor, when: "title != ''"}
  on_transition:
    reviewed:
      - sql: SELECT 1
  timeout:
    draft: {after: 2h, to: reviewed}
`
	appMCPWorkerCronFixture = `jobs:
  - id: harmless
    schedule: "0 0 * * *"
    run:
      - sql: SELECT 1
`
)

var appMCPWorkerSources = map[string]string{
	"hooks.yaml":     appMCPWorkerHooksFixture,
	"workflows.yaml": appMCPWorkerWorkflowsFixture,
	"cron.yaml":      appMCPWorkerCronFixture,
}

func TestAppMCPWorkerConfigUsesReviewedCapturedBytesOnStagedReload(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(*testing.T, *App)
		check func(*testing.T, *runtimeConfig)
	}{
		{
			name: "replacements",
			setup: func(t *testing.T, app *App) {
				writeTestFile(t, app.Dir, "hooks.yaml", "on_update:\n  notes:\n    - sql: SELECT 'replacement'\n")
				writeTestFile(t, app.Dir, "workflows.yaml", "replacement:\n  table: notes\n  field: status\n  initial: replacement\n")
				writeTestFile(t, app.Dir, "cron.yaml", "jobs:\n  - id: replacement\n    schedule: '@daily'\n    run: [{sql: SELECT 2}]\n")
			},
			check: assertAppMCPWorkerConfig,
		},
		{
			name: "removals",
			setup: func(t *testing.T, app *App) {
				for name := range appMCPWorkerSources {
					if err := os.Remove(filepath.Join(app.Dir, name)); err != nil {
						t.Fatal(err)
					}
				}
			},
			check: assertAppMCPWorkerConfig,
		},
		{
			name: "late files after reviewed absence",
			setup: func(t *testing.T, app *App) {
				for name := range appMCPWorkerSources {
					writeTestFile(t, app.Dir, name, appMCPWorkerSources[name])
				}
			},
			check: func(t *testing.T, config *runtimeConfig) {
				if config.hooks != nil || config.workflows != nil || config.cron != nil {
					t.Fatalf("late files entered absent staged config: hooks=%#v workflows=%#v cron=%#v", config.hooks, config.workflows, config.cron)
				}
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, _ := auditApp(t)
			writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT, status TEXT);\n")
			if tc.name != "late files after reviewed absence" {
				for name, body := range appMCPWorkerSources {
					writeTestFile(t, app.Dir, name, body)
				}
			}
			writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
			reviewAppMCPFixture(t, app.Dir)

			captured := map[string][]byte{"hooks.yaml": nil, "workflows.yaml": nil, "cron.yaml": nil}
			if _, _, _, err := appMCPSourceDigests(app.Dir, mustParseAppMCPManifest(t, app.Dir), captured); err != nil {
				t.Fatal(err)
			}
			for name, want := range appMCPWorkerSources {
				if tc.name == "late files after reviewed absence" {
					if captured[name] != nil {
						t.Errorf("captured absent %s = %q, want nil", name, captured[name])
					}
				} else if string(captured[name]) != want {
					t.Errorf("captured %s = %q, want exact reviewed bytes %q", name, captured[name], want)
				}
			}

			config, err := loadRuntimeConfig(app.Dir)
			if err != nil {
				t.Fatal(err)
			}
			if tc.name == "late files after reviewed absence" {
				if config.hooks != nil || config.workflows != nil || config.cron != nil {
					t.Fatalf("absent reviewed inputs parsed as hooks=%#v workflows=%#v cron=%#v", config.hooks, config.workflows, config.cron)
				}
			} else {
				assertAppMCPWorkerConfig(t, config)
			}
			tc.setup(t, app)
			if err := reloadAppConfigStaged(app, config, nil); err != nil {
				t.Fatalf("staged reload: %v", err)
			}
			tc.check(t, &runtimeConfig{hooks: app.Hooks, workflows: app.Workflows, cron: app.Cron})
		})
	}
}

func mustParseAppMCPManifest(t *testing.T, dir string) *AppMCPManifest {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseAppMCPManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	return manifest
}

func assertAppMCPWorkerConfig(t *testing.T, config *runtimeConfig) {
	t.Helper()
	wantHooks, err := parseHooksYAML([]byte(appMCPWorkerHooksFixture))
	if err != nil {
		t.Fatal(err)
	}
	wantWorkflows, err := parseWorkflowsYAML([]byte(appMCPWorkerWorkflowsFixture))
	if err != nil {
		t.Fatal(err)
	}
	wantCron, err := parseCronYAML([]byte(appMCPWorkerCronFixture))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(config.hooks, wantHooks) {
		t.Errorf("hooks config = %#v, want parsed reviewed bytes %#v", config.hooks, wantHooks)
	}
	if !reflect.DeepEqual(config.workflows, wantWorkflows) {
		// Workflow state slices are built from maps, so compare their named
		// fields and transitions without depending on slice iteration order.
		var got *Workflow
		if config.workflows != nil {
			got = config.workflows.Workflows["review"]
		}
		want := wantWorkflows.Workflows["review"]
		if got == nil || got.Name != want.Name || got.Table != want.Table || got.Field != want.Field || got.Initial != want.Initial ||
			!reflect.DeepEqual(got.Transitions, want.Transitions) || !reflect.DeepEqual(got.OnTransition, want.OnTransition) || !reflect.DeepEqual(got.Timeouts, want.Timeouts) {
			t.Errorf("workflow config = %#v, want parsed reviewed bytes %#v", config.workflows, wantWorkflows)
		}
	}
	if !reflect.DeepEqual(config.cron, wantCron) {
		t.Errorf("cron config = %#v, want parsed reviewed bytes %#v", config.cron, wantCron)
	}
}

func TestAppMCPMalformedWorkerConfigRejectsReloadBeforeEffects(t *testing.T) {
	for name, source := range map[string]string{
		"hooks.yaml":     "on_insert: {notes: false}\n",
		"workflows.yaml": "review: {transitions: false}\n",
		"cron.yaml":      "jobs: false\n",
	} {
		t.Run(name, func(t *testing.T) {
			app, _ := auditApp(t)
			previousHooks := &HookConfig{OnInsert: map[string][]Hook{"notes": {{SQL: "SELECT 1"}}}}
			previousWorkflows := &WorkflowConfig{Workflows: map[string]*Workflow{"previous": {Name: "previous"}}}
			previousCron := &CronConfig{Jobs: []CronJob{{ID: "previous"}}}
			app.Hooks, app.Workflows, app.Cron = previousHooks, previousWorkflows, previousCron
			writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY); CREATE TABLE staged_only (id INTEGER PRIMARY KEY);\n")
			writeTestFile(t, app.Dir, name, source)
			writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
			reviewAppMCPFixture(t, app.Dir)
			if err := reloadAppConfig(app); err == nil {
				t.Fatal("reload accepted malformed reviewed worker config")
			}
			if app.Hooks != previousHooks || app.Workflows != previousWorkflows || app.Cron != previousCron {
				t.Fatal("malformed config replaced published worker settings")
			}
			select {
			case <-app.Stop:
				t.Fatal("malformed config stopped the current worker generation")
			default:
			}
			var exists int
			if err := app.DB.QueryRow("SELECT count(*) FROM sqlite_master WHERE type='table' AND name='staged_only'").Scan(&exists); err != nil || exists != 0 {
				t.Fatalf("malformed config reached schema effects: exists=%d err=%v", exists, err)
			}
		})
	}
}

func TestAppMCPReservedConfigDirectoriesRejectBeforeStartupEffects(t *testing.T) {
	for _, name := range []string{"app.yaml", "encrypted.yaml", "hooks.yaml", "workflows.yaml", "cron.yaml", "schema.prisma", "schema.sql"} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if name == "schema.sql" {
				writeTestFile(t, dir, "schema.prisma", "model Note {\n id Int @id\n title String?\n}\n")
			} else {
				writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);\n")
			}
			writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
			reviewAppMCPFixture(t, dir)
			if _, err := loadRuntimeConfig(dir); err != nil {
				t.Fatalf("valid reviewed baseline: %v", err)
			}
			if err := os.Mkdir(filepath.Join(dir, name), 0o755); err != nil {
				t.Fatal(err)
			}
			if app, err := loadApp(dir); err == nil {
				if app != nil {
					app.DB.Close()
				}
				t.Fatal("empty directory was accepted as an absent reviewed configuration file")
			}
			if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
				t.Fatalf("directory rejection reached database opening: %v", err)
			}
		})
	}
}
