//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func capturedFlowFixture(route, value string) string {
	return fmt.Sprintf(`on:
  request: {method: GET, path: %s, permissions: [notes:read]}
jobs:
  read:
    steps:
      - id: value
        query: SELECT '%s' AS generation
      - run: respond
        with:
          body: ${{ steps.value.outputs.rows[0] }}
`, route, value)
}

func TestAppMCPCapturedFlowSourcesPreserveMembershipAndCanonicalHTTP(t *testing.T) {
	app, _ := auditApp(t)
	sid := seedMemberSession(t, app)
	sources := map[string]string{
		"flows.yaml":   "root_read:\n  trigger: GET /api/captured-root\n  permissions: [notes:read]\n  steps:\n    - sql: SELECT 1\n    - respond: {json: {generation: approved-root}}\n",
		"flows/a.yaml": capturedFlowFixture("/api/captured-a", "approved-a"),
		"flows/z.yaml": capturedFlowFixture("/api/captured-z", "approved-z"),
	}
	writeTestFile(t, app.Dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY, title TEXT);\n")
	for path, source := range sources {
		writeTestFile(t, app.Dir, path, source)
	}
	writeTestFile(t, app.Dir, "flows/nested/ignored.yaml", "malformed: [")
	writeTestFile(t, app.Dir, "flows/ignored.txt", "malformed: [")
	writeTestFile(t, app.Dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, app.Dir)
	config, err := loadRuntimeConfig(app.Dir)
	if err != nil {
		t.Fatal(err)
	}
	captured := map[string][]byte{"flows.yaml": nil, "flows/": nil}
	if _, _, _, err := appMCPSourceDigests(app.Dir, config.mcp, captured); err != nil {
		t.Fatal(err)
	}
	for path, source := range sources {
		if string(captured[path]) != source {
			t.Fatalf("capture for %s differs from reviewed bytes", path)
		}
	}
	writeTestFile(t, app.Dir, "flows.yaml", "malformed: [")
	writeTestFile(t, app.Dir, "flows/a.yaml", capturedFlowFixture("/api/captured-a", "replacement"))
	if err := os.Remove(filepath.Join(app.Dir, "flows/z.yaml")); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, app.Dir, "flows/late.yaml", capturedFlowFixture("/api/late", "late"))
	// Exercise the shared parser after the captured generation's files change.
	config.flows, err = loadFlowsCheckedFromSources(app.Dir, true, captured)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"flows.yaml", "flows/a.yaml", "flows/z.yaml"}
	if len(config.flows) != len(want) {
		t.Fatalf("captured membership = %d flows, want %d", len(config.flows), len(want))
	}
	for i, path := range want {
		flow := config.flows[i]
		if flow.Source != path || flow.sourceHash != hashBytesSHA256([]byte(sources[path])) || flow.sourceHash != config.mcp.sourceHashes[path] {
			t.Fatalf("flow %d source/hash differs from reviewed generation: %q", i, flow.Source)
		}
	}
	if err := reloadAppConfigStaged(app, config, nil); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, app.Flows)
	for route, want := range map[string]string{"/api/captured-root": "approved-root", "/api/captured-a": "approved-a", "/api/captured-z": "approved-z"} {
		request := httptest.NewRequest(http.MethodGet, route, nil)
		request.Header.Set("Authorization", "Bearer "+sid)
		recorder := httptest.NewRecorder()
		mux.ServeHTTP(recorder, request)
		var got map[string]any
		if err := json.Unmarshal(recorder.Body.Bytes(), &got); err != nil || recorder.Code != http.StatusOK || got["generation"] != want {
			t.Fatalf("captured canonical HTTP %s: %d %s (%v)", route, recorder.Code, recorder.Body.String(), err)
		}
	}
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/late", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("late flow registered: %d", recorder.Code)
	}
}

func TestAppMCPCapturedEmptyFlowSetDoesNotFallBackToDisk(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "flows.yaml", "root_read:\n  trigger: GET /api/root\n  steps: [{sql: SELECT 1}]\n")
	writeTestFile(t, dir, "flows/a.yaml", capturedFlowFixture("/api/a", "late"))
	captured, err := loadFlowsCheckedFromSources(dir, true, map[string][]byte{})
	if err != nil || len(captured) != 0 {
		t.Fatalf("empty captured set loaded disk: %+v %v", captured, err)
	}
	ordinary, err := loadFlowsChecked(dir, true)
	if err != nil || len(ordinary) != 2 {
		t.Fatalf("ordinary loader changed: %+v %v", ordinary, err)
	}
}

func TestAppMCPCapturedFlowSourcesKeepCanonicalValidation(t *testing.T) {
	gha := []byte(capturedFlowFixture("/api/a", "reviewed"))
	legacy := []byte("a:\n  trigger: GET /api/root\n  steps: [{sql: SELECT 1}]\n")
	for name, sources := range map[string]map[string][]byte{
		"duplicate":     {"flows.yaml": legacy, "flows/a.yaml": gha},
		"malformed":     {"flows/a.yaml": []byte("on: [invalid]\n")},
		"missing bytes": {"flows/a.yaml": nil},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadFlowsCheckedFromSources(t.TempDir(), true, sources); err == nil {
				t.Fatal("invalid captured flow accepted")
			}
		})
	}
	flows, err := loadFlowsCheckedFromSources(t.TempDir(), false, map[string][]byte{"flows.yaml": legacy, "flows/a.yaml": gha})
	if err != nil || len(flows) != 1 || flows[0].Source != "flows/a.yaml" {
		t.Fatalf("legacy opt-out changed: %+v %v", flows, err)
	}
}

func TestAppMCPFlowSourceKindsRejectBeforeDatabaseEffects(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);\n")
	writeTestFile(t, dir, "mcp.yaml", appMCPManifestFixture())
	reviewAppMCPFixture(t, dir)
	if err := os.Mkdir(filepath.Join(dir, "flows.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := loadApp(dir); err == nil {
		t.Fatal("flows.yaml directory accepted as absence")
	}
	if _, err := os.Stat(filepath.Join(dir, "data.db")); !os.IsNotExist(err) {
		t.Fatalf("invalid source reached database: %v", err)
	}
	other := t.TempDir()
	writeTestFile(t, other, "flows", "not a directory")
	manifest, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := appMCPDigests(other, manifest); err == nil {
		t.Fatal("non-directory flows source accepted")
	}
}
