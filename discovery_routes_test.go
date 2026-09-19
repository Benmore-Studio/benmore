//go:build !cli

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestContext7ManifestTargetsPublicBuilderAndSDKDocs(t *testing.T) {
	data, err := os.ReadFile("context7.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Schema         string   `json:"$schema"`
		Folders        []string `json:"folders"`
		ExcludeFolders []string `json:"excludeFolders"`
		ExcludeFiles   []string `json:"excludeFiles"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatalf("invalid context7.json: %v", err)
	}
	if manifest.Schema != "https://context7.com/schema/context7.json" {
		t.Fatalf("schema = %q", manifest.Schema)
	}
	if !reflect.DeepEqual(manifest.Folders, []string{"docs/agent", "embedded"}) {
		t.Fatalf("folders = %v, want only public builder and SDK docs", manifest.Folders)
	}
	if !discoveryContainsString(manifest.ExcludeFolders, "docs/superpowers") {
		t.Fatalf("excludeFolders = %v, want internal plans excluded", manifest.ExcludeFolders)
	}
	if !discoveryContainsString(manifest.ExcludeFiles, "AGENTS.md") {
		t.Fatalf("excludeFiles = %v, want platform agent contract excluded", manifest.ExcludeFiles)
	}
	if !discoveryContainsString(manifest.ExcludeFiles, "deploy.md") {
		t.Fatalf("excludeFiles = %v, want hosted-platform deploy guide excluded", manifest.ExcludeFiles)
	}
}

func discoveryContainsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestOpenAPIAliasesMatchCanonical(t *testing.T) {
	for _, visibility := range []string{"public", "auth"} {
		t.Run(visibility, func(t *testing.T) {
			app := &App{
				Design: &DesignConfig{Features: &FeaturesConfig{DocsVisibility: visibility}},
				Tables: []Table{{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true}}}},
			}
			mux := http.NewServeMux()
			RegisterAPIDocsRoutes(mux, app)

			want := recordDiscoveryRoute(mux, "/api/_openapi")
			for _, path := range []string{"/openapi.json", "/api/openapi.json"} {
				assertSameDiscoveryResponse(t, recordDiscoveryRoute(mux, path), want)
			}
		})
	}
}

func TestOpenAPIAliasesAreReservedAcrossValidationSurfaces(t *testing.T) {
	for _, path := range []string{"/openapi.json", "/api/openapi.json"} {
		t.Run(path, func(t *testing.T) {
			flow := fmt.Sprintf(`on:
  request:
    method: GET
    path: %s
jobs:
  respond:
    steps:
      - run: respond
        with: { status: 200 }
`, path)

			if msg := ValidateOnWrite("flows.yaml", flow); !strings.Contains(msg, "reserved") {
				t.Fatalf("write-time validation accepted reserved path %q: %s", path, msg)
			}

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(flow), 0o644); err != nil {
				t.Fatal(err)
			}
			report := RunCompleteCheck(dir, "flows.yaml")
			if report.Clean() || len(report.Findings) != 1 || report.Findings[0].File != "flows.yaml" ||
				!strings.Contains(report.Findings[0].Message, "reserved") {
				t.Fatalf("complete check accepted reserved path %q:\n%s", path, FormatReport(report))
			}
		})
	}
}

func TestLLMsWellKnownAliasMatchesCanonical(t *testing.T) {
	app, mux := newCrudScopeTestApp(t)
	if err := os.MkdirAll(filepath.Join(app.Dir, "static"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.Dir, "static", "llms.txt"), []byte("# exact override\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	for _, visibility := range []string{"public", "auth"} {
		t.Run(visibility, func(t *testing.T) {
			app.Design = &DesignConfig{Features: &FeaturesConfig{DocsVisibility: visibility}}
			want := recordDiscoveryRoute(mux, "/llms.txt")
			got := recordDiscoveryRoute(mux, "/.well-known/llms.txt")
			assertSameDiscoveryResponse(t, got, want)
		})
	}
}

func recordDiscoveryRoute(handler http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

func assertSameDiscoveryResponse(t *testing.T, got, want *httptest.ResponseRecorder) {
	t.Helper()
	if got.Code != want.Code {
		t.Fatalf("status = %d, want %d; body=%q", got.Code, want.Code, got.Body.String())
	}
	if !reflect.DeepEqual(got.Header(), want.Header()) {
		t.Fatalf("headers = %#v, want %#v", got.Header(), want.Header())
	}
	if !bytes.Equal(got.Body.Bytes(), want.Body.Bytes()) {
		t.Fatalf("body = %q, want exact bytes %q", got.Body.Bytes(), want.Body.Bytes())
	}
}
