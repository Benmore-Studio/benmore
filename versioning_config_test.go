//go:build !cli

package main

import (
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestVersionedConfigSupportedYAMLLayouts(t *testing.T) {
	for name, content := range map[string]string{
		"block":          "versioned:\n  - documents\n  - notes\n",
		"flow":           "versioned: [documents, notes]\n",
		"quoted":         "'versioned':\n  - \"documents\"\n  - 'notes'\n",
		"comments":       "versioned: # record history\n  - documents # first table\n\n  # second table\n  - notes\n",
		"indentless":     "versioned:\n- documents\n- notes\n",
		"other sections": "site_name: Audit\nversioned: [documents, notes]\ntheme: zinc\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got := ValidateOnWrite("app.yaml", content); got != "" {
				t.Errorf("supported record history rejected at write: %s", got)
			}
			dir := t.TempDir()
			writeTestFile(t, dir, "app.yaml", content)
			writeTestFile(t, dir, "schema.sql", "CREATE TABLE documents (\n id INTEGER PRIMARY KEY\n);\nCREATE TABLE notes (\n id INTEGER PRIMARY KEY\n);\n")
			if report := RunCompleteCheck(dir, "app.yaml"); !report.Clean() {
				t.Errorf("supported record history rejected by app check: %+v", report)
			}
			if _, _, err := parseAppConfigDocument([]byte(content)); err != nil {
				t.Errorf("supported record history rejected at load: %v", err)
			}
			got := parseVersionedConfig([]byte(content))
			if got == nil || !reflect.DeepEqual(got.Tables, []string{"documents", "notes"}) {
				t.Errorf("history tables = %+v", got)
			}
		})
	}
}

func TestVersionedConfigMalformedRefused(t *testing.T) {
	for name, content := range map[string]string{
		"scalar":        "versioned: documents\n",
		"mapping":       "versioned: {documents: true}\n",
		"boolean":       "versioned: false\n",
		"number":        "versioned: [12]\n",
		"nested":        "versioned: [[documents]]\n",
		"null item":     "versioned: [documents, null]\n",
		"empty item":    "versioned: [documents, '']\n",
		"invalid name":  "versioned: [documents, 'bad-name']\n",
		"padded name":   "versioned: [' documents ']\n",
		"duplicate":     "versioned: [documents, documents]\n",
		"case variant":  "versioned: [Documents, documents]\n",
		"duplicate key": "versioned: [documents]\nversioned: [notes]\n",
	} {
		t.Run(name, func(t *testing.T) {
			if got := ValidateOnWrite("app.yaml", content); got == "" || !strings.Contains(got, "versioned") {
				t.Errorf("write did not explain invalid versioned configuration: %q", got)
			}
			if _, _, err := parseAppConfigDocument([]byte(content)); err == nil || !strings.Contains(err.Error(), "versioned") {
				t.Errorf("load did not explain invalid versioned configuration: %v", err)
			}
			dir := t.TempDir()
			writeTestFile(t, dir, "app.yaml", content)
			if report := RunCompleteCheck(dir, "app.yaml"); report.Clean() {
				t.Error("app check admitted invalid versioned configuration")
			}
			if got := parseVersionedConfig([]byte(content)); got != nil {
				t.Errorf("ordinary parser admitted partial invalid history: %+v", got)
			}
		})
	}
}

func TestVersionedConfigDisabled(t *testing.T) {
	for _, content := range []string{"", "site_name: Audit\n", "versioned:\n", "versioned: null\n", "versioned: []\n"} {
		if got := ValidateOnWrite("app.yaml", content); got != "" {
			t.Errorf("disabled history rejected: %q: %s", content, got)
		}
		if _, _, err := parseAppConfigDocument([]byte(content)); err != nil {
			t.Errorf("disabled history rejected at load: %q: %v", content, err)
		}
		if got := parseVersionedConfig([]byte(content)); got != nil {
			t.Errorf("disabled history loaded: %q: %+v", content, got)
		}
	}
}

func TestVersionedConfigActivatesHistoryThroughHTTP(t *testing.T) {
	for name, config := range map[string]string{
		"block": "versioned:\n  - documents\n",
		"flow":  "versioned: [documents]\n",
		"yaml":  "'versioned': # record history\n  - 'documents' # quoted table\n",
	} {
		t.Run(name, func(t *testing.T) {
			dir, err := filepath.EvalSymlinks(t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, dir, "schema.sql", "CREATE TABLE documents (\n id INTEGER PRIMARY KEY,\n title TEXT\n);\n")
			writeTestFile(t, dir, "app.yaml", "auth: {identifier: email}\naccess: {documents: everyone}\n"+config)
			app, err := loadApp(dir)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(app.Shutdown)
			mux := buildAppMux(app, true, "https://audit.example.invalid")
			sid := createCrudScopeSession(t, app, "historian@example.com", "admin", "", "")
			crudScopeMustExec(t, app.DB, "INSERT INTO documents(id, title) VALUES (1,'original')")
			updated := crudScopeRequest(t, mux, http.MethodPatch, "/api/documents/1", sid, map[string]any{"title": "revised"})
			if updated.Code != http.StatusOK {
				t.Fatalf("record update: %d %s", updated.Code, updated.Body.String())
			}
			history := crudScopeRequest(t, mux, http.MethodGet, "/api/documents/1/versions/1", sid, nil)
			var snapshot map[string]any
			if err := json.Unmarshal(history.Body.Bytes(), &snapshot); err != nil || history.Code != http.StatusOK || snapshot["title"] != "original" {
				t.Fatalf("history endpoint did not return pre-update value: %d %s (%v)", history.Code, history.Body.String(), err)
			}
			current := crudScopeRequest(t, mux, http.MethodGet, "/api/documents/1", sid, nil)
			var row map[string]any
			if err := json.Unmarshal(current.Body.Bytes(), &row); err != nil || current.Code != http.StatusOK || row["title"] != "revised" {
				t.Fatalf("history changed live record: %d %s (%v)", current.Code, current.Body.String(), err)
			}
		})
	}
}

func TestVersionedConfigMalformedBeforeStartupOrReloadEffects(t *testing.T) {
	dir := t.TempDir()
	bad := "versioned: {documents: true}\n"
	writeTestFile(t, dir, "app.yaml", bad)
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE documents (\n id INTEGER PRIMARY KEY\n);\n")
	if app, err := loadApp(dir); err == nil {
		app.Shutdown()
		t.Error("startup accepted malformed history configuration")
	}
	if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
		t.Errorf("malformed history reached database creation: %v", err)
	}
	app, cleanup := newTestApp(t)
	defer cleanup()
	oldDesign := &DesignConfig{CSS: "existing"}
	app.Design = oldDesign
	writeTestFile(t, app.Dir, "app.yaml", bad)
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE should_not_exist (\n id INTEGER PRIMARY KEY\n);\n")
	if err := reloadAppConfig(app); err == nil {
		t.Error("reload accepted malformed history configuration")
	}
	if app.Design != oldDesign {
		t.Error("rejected history configuration replaced the active generation")
	}
	var count int
	if err := app.DB.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE name='should_not_exist'").Scan(&count); err != nil || count != 0 {
		t.Errorf("malformed history reached migration: %d %v", count, err)
	}
}

func TestVersionedConfigCapturedYAMLSource(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "app.yaml", "versioned: [unreviewed]\n")
	app := &App{Dir: dir, MCP: &AppMCPManifest{}, sourceFiles: map[string][]byte{"app.yaml": []byte("versioned: ['documents'] # captured\n")}}
	got := app.versionedConfig()
	if got == nil || !reflect.DeepEqual(got.Tables, []string{"documents"}) {
		t.Fatalf("captured versioned YAML not used: %+v", got)
	}
	app.sourceFiles = map[string][]byte{}
	if got := app.versionedConfig(); got != nil {
		t.Fatalf("empty capture admitted late disk config: %+v", got)
	}
}
