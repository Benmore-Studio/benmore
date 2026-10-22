//go:build !cli && !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func runtimeFormManifest(t *testing.T) *AppMCPManifest {
	t.Helper()
	manifest, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	manifest.ExecutionSources = appMCPExecutionSourcesRuntime
	return manifest
}

func runtimeSourceBase(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER);")
	writeTestFile(t, dir, "flows/read.yaml", "SELECT 1")
	writeTestFile(t, dir, "static/app.js", "export const value = 1")
	return dir
}

// Files no loader reads must not move a runtime-form digest: hosted instances
// accumulate docs, a root README and pull-denied hidden directories.
func TestAppMCPRuntimeFormIgnoresFilesTheRuntimeNeverReads(t *testing.T) {
	dir := runtimeSourceBase(t)
	manifest := runtimeFormManifest(t)
	contract, execution, err := appMCPDigests(dir, manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifest.ContractDigest, manifest.ExecutionDigest = contract, execution
	for rel, body := range map[string]string{
		"docs/guide.md":                "notes",
		"docs/x/.verify/sweep.json":    "{}",
		"README.md":                    "readme",
		"AGENTS.md":                    "agents",
		".sdd/plan.md":                 "plan",
		"tests/journeys/home.yaml":     "journey",
		"src/view.tsx":                 "export {}",
		"scripts/seed.py":              "print(1)",
		"partials/.sdd/scratch.html":   "scratch",
		"layouts/.verify/state.json":   "{}",
		"Dockerfile":                   "FROM scratch",
		"unrelated.sql":                "SELECT 2",
		"docs/openapi.yaml":            "openapi: 3.0.3",
		"notes.html.bak":               "backup",
		"schema.sql.orig":              "CREATE TABLE copy (id INTEGER);",
		"migrations/.verify/sweep.sql": "SELECT 3",
	} {
		writeTestFile(t, dir, rel, body)
	}
	if err := validateAppMCPDigests(dir, manifest); err != nil {
		t.Fatalf("a file the runtime never reads moved the digest: %v", err)
	}
}

// Everything a loader reads, executes or serves still moves the digest.
func TestAppMCPRuntimeFormBindsEveryRuntimeRead(t *testing.T) {
	manifest := runtimeFormManifest(t)
	base := runtimeSourceBase(t)
	_, want, err := appMCPDigests(base, manifest)
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{
		"app.yaml", "encrypted.yaml", "schema.prisma", "schema.yaml", "hooks.yaml", "workflows.yaml", "cron.yaml", "flows.yaml",
		"validators.yaml", "admin.yaml", "computed.yaml", "retention.yaml", "head.html", "theme.css", "seeds.sql",
		"favicon.ico", "favicon.png", "tsconfig.json", "package.json", "index.html", "dashboard.html",
		"static/index.html", "static/.hidden/asset.js", "static/lib/dep.ts", "flows/.drafts/x.yaml", "flows/other.yaml",
		"partials/header.html", "layouts/main.html", "i18n/en.yaml", "migrations/001_add.sql",
		"emails/welcome.html", "emails/sub/dir.html", "emails/.hidden/t.html", "templates/invoice.html",
	} {
		dir := runtimeSourceBase(t)
		writeTestFile(t, dir, rel, "runtime input")
		_, got, err := appMCPDigests(dir, manifest)
		if err != nil {
			t.Fatalf("%s: %v", rel, err)
		}
		if got == want {
			t.Errorf("%s changed without moving the runtime-form digest", rel)
		}
	}
}

// The two forms never hash alike, so a manifest cannot be read in the wrong
// form, and a digest made over the whole tree still validates as the old form.
func TestAppMCPLegacyFormKeepsTheWholeTreeWalk(t *testing.T) {
	dir := runtimeSourceBase(t)
	legacy, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	runtime := runtimeFormManifest(t)
	lc, le, err := appMCPDigests(dir, legacy)
	if err != nil {
		t.Fatal(err)
	}
	rc, re, err := appMCPDigests(dir, runtime)
	if err != nil {
		t.Fatal(err)
	}
	if le == re {
		t.Fatal("legacy and runtime forms produced the same execution digest")
	}
	if lc == rc {
		t.Fatal("the form is not part of the reviewed contract")
	}
	legacy.ContractDigest, legacy.ExecutionDigest = lc, le
	if err := validateAppMCPDigests(dir, legacy); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, dir, "docs/guide.md", "binds a legacy review")
	if err := validateAppMCPDigests(dir, legacy); err == nil {
		t.Fatal("legacy form stopped binding the whole tree")
	}
	// An unchanged contract keeps the contract digest of manifests that omit the field.
	again, err := parseAppMCPManifest([]byte(appMCPManifestFixture()))
	if err != nil {
		t.Fatal(err)
	}
	if c, err := appMCPContractDigest(again); err != nil || c != lc {
		t.Fatalf("contract digest of a manifest without execution_sources moved: %v", err)
	}
	// Only the two spellings are accepted.
	if err := validateAppMCPManifestGated(runtime, true); err != nil {
		t.Fatalf("runtime form refused: %v", err)
	}
	runtime.ExecutionSources = "everything"
	if err := validateAppMCPManifestGated(runtime, true); err == nil {
		t.Fatal("unknown execution_sources accepted")
	}
}

// A case variant or wrong-kind entry named like a runtime source is refused
// rather than skipped: a case-insensitive file system hands it to the runtime.
func TestAppMCPRuntimeFormRefusesAmbiguousSourceNames(t *testing.T) {
	manifest := runtimeFormManifest(t)
	for name, build := range map[string]func(dir string){
		"config case variant":   func(dir string) { writeTestFile(t, dir, "App.yaml", "x") },
		"seeds case variant":    func(dir string) { writeTestFile(t, dir, "Seeds.sql", "x") },
		"tree case variant":     func(dir string) { writeTestFile(t, dir, "Partials/a.html", "x") },
		"emails case variant":   func(dir string) { writeTestFile(t, dir, "EMAILS/a.html", "x") },
		"config named as a dir": func(dir string) { writeTestFile(t, dir, "seeds.sql/inner", "x") },
		"tree named as a file":  func(dir string) { writeTestFile(t, dir, "emails", "x") },
	} {
		dir := runtimeSourceBase(t)
		build(dir)
		if _, _, err := appMCPDigests(dir, manifest); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestAppMCPSourceCoversRuntimeForm(t *testing.T) {
	m := runtimeFormManifest(t)
	for path, want := range map[string]bool{
		"app.yaml":                  true,
		"seeds.sql":                 true,
		"index.html":                true,
		"static/.claude/x.js":       true,
		"flows/.drafts/x.yaml":      true,
		"emails/.hidden/t.html":     true,
		"docs/guide.md":             false,
		"docs/x/.verify/sweep.json": false,
		"README.md":                 false,
		".sdd/plan.md":              false,
		"partials/.sdd/x.html":      false,
		"partials/header.html":      true,
		"mcp.yaml":                  false,
		"env.yaml":                  false,
	} {
		if got := appMCPSourceCovers(path, m); got != want {
			t.Errorf("appMCPSourceCovers(%q) = %v, want %v", path, got, want)
		}
	}
	// The same paths in the whole-tree form.
	if !appMCPSourceCovers("docs/x/.verify/sweep.json", nil) || !appMCPSourceCovers("README.md", nil) {
		t.Error("whole-tree form must keep covering docs and root files")
	}
}

// A pinned OpenAPI document is runtime input wherever it lives; its siblings
// are what a relative reference can load. Neither pulls in the rest of docs/.
func TestAppMCPRuntimeFormBindsDeclaredOpenAPIDocuments(t *testing.T) {
	m := runtimeFormManifest(t)
	m.Connections = []AppMCPConnection{
		{Name: "rates", OpenAPI: "openapi/rates.yaml"},
		{Name: "docs", OpenAPI: "docs/api/billing.json"},
		{Name: "root", OpenAPI: "root.yaml"},
		{Name: "bad", OpenAPI: "../escape.yaml"},
	}
	for path, want := range map[string]bool{
		"openapi/rates.yaml":           true,
		"openapi/schemas/pet.yaml":     true,
		"openapi/readme.md":            false,
		"docs/api/billing.json":        true,
		"docs/api/models.yaml":         true,
		"docs/api/notes.md":            false,
		"docs/api/.verify/x.json":      false,
		"docs/guide.md":                false,
		"root.yaml":                    true,
		"other.yaml":                   true, // beside a root-level document
		"schemas/a.json":               true,
		"schemas/.verify/a.json":       false,
		"notes.md":                     false,
		"openapi/.verify/sweep.json":   false,
		"openapi/schemas/.git/config":  false,
		"openapi/schemas/diagram.png":  false,
		"openapi/schemas/readme.md":    false,
		"openapi/schemas/nested/a.yml": true,
	} {
		if got := appMCPSourceCovers(path, m); got != want {
			t.Errorf("appMCPSourceCovers(%q) = %v, want %v", path, got, want)
		}
	}
}

// Review writes the runtime form, an old-form manifest keeps loading until
// then, and a docs/ edit afterwards no longer takes the connector down.
func TestAppMCPReviewUpgradesLegacyManifestWithoutLosingTheConnector(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := WriteHTMLScaffoldFiles(dir, "Notes fixture"); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := parseAppMCPManifest(data)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.ExecutionSources != appMCPExecutionSourcesRuntime {
		t.Fatalf("starter did not write the runtime form: %q", manifest.ExecutionSources)
	}

	// An app reviewed before the field existed.
	manifest.ExecutionSources = ""
	manifest.ContractDigest, manifest.ExecutionDigest, err = appMCPDigests(dir, manifest)
	if err != nil {
		t.Fatal(err)
	}
	legacy, err := yaml.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(legacy), "execution_sources") {
		t.Fatalf("legacy manifest spells the new field:\n%s", legacy)
	}
	writeTestFile(t, dir, "mcp.yaml", string(legacy))
	config, err := loadRuntimeConfig(dir)
	if err != nil || config.mcp == nil {
		t.Fatalf("old-form review stopped validating after the upgrade: %v", err)
	}
	if notice := appMCPConnectorWithheldNotice(dir); notice != "" {
		t.Fatalf("old-form review reported stale: %s", notice)
	}

	// A docs file makes an old-form review stale: it still binds the whole tree.
	writeTestFile(t, dir, "docs/guide.md", "hosted notes")
	var stale *appMCPReviewStaleError
	if _, err := loadRuntimeConfig(dir); !errors.As(err, &stale) {
		t.Fatalf("old-form review ignored a docs file: %v", err)
	}

	// Review writes the runtime form; docs, README and hidden files no longer matter.
	if _, err := reviewAppMCPSource(dir); err != nil {
		t.Fatal(err)
	}
	reviewed, err := os.ReadFile(filepath.Join(dir, "mcp.yaml"))
	if err != nil || !strings.Contains(string(reviewed), "execution_sources: runtime") {
		t.Fatalf("review did not write the runtime form: %v\n%s", err, reviewed)
	}
	for rel, body := range map[string]string{
		"docs/guide.md":             "edited",
		"docs/x/.verify/sweep.json": "{}",
		"README.md":                 "readme",
		".sdd/plan.md":              "plan",
	} {
		writeTestFile(t, dir, rel, body)
	}
	config, err = loadRuntimeConfig(dir)
	if err != nil || config.mcp == nil {
		t.Fatalf("docs and hidden files took the reviewed connector down: %v", err)
	}
	if notice := appMCPConnectorWithheldNotice(dir); notice != "" {
		t.Fatalf("runtime-form review reported stale: %s", notice)
	}
	// Runtime input still does.
	writeTestFile(t, dir, "static/hero.png", "\x89PNG-hero")
	if _, err := loadRuntimeConfig(dir); !errors.As(err, &stale) {
		t.Fatalf("runtime-form review ignored a static file: %v", err)
	}
}

// A hook's email template stays under emails/: ../ must not reach a file the
// runtime-form digest leaves out.
func TestHookEmailTemplateCannotClimbOutOfEmails(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "docs/note.html", "<p>LEAK</p>")
	writeTestFile(t, dir, "emails/ok.html", "<p>fine</p>")
	if got := hookEmailBody(&EmailHook{Template: "ok"}, map[string]any{}, dir); !strings.Contains(got, "fine") {
		t.Fatalf("emails/ok.html not read: %q", got)
	}
	if got := hookEmailBody(&EmailHook{Template: "../docs/note"}, map[string]any{}, dir); strings.Contains(got, "LEAK") {
		t.Fatalf("template climbed out of emails/: %q", got)
	}
}

// A reviewed app's flow email template is read from the captured bytes, so a
// file outside the digest (docs/) is not found.
func TestFlowEmailTemplateReadsCapturedSourceOfReviewedApp(t *testing.T) {
	dir := t.TempDir()
	writeTestFile(t, dir, "docs/note.html", "<p>OUTSIDE</p>")
	writeTestFile(t, dir, "emails/in.html", "<p>ON DISK</p>")
	app := &App{Dir: dir, MCP: &AppMCPManifest{}, sourceFiles: map[string][]byte{"emails/in.html": []byte("<p>CAPTURED</p>")}}
	ctx := &FlowContext{App: app, Data: map[string]any{}}
	html, _, err := resolveEmailBody(ctx, &FlowEmail{Template: "in"})
	if err != nil || !strings.Contains(html, "CAPTURED") || strings.Contains(html, "ON DISK") {
		t.Fatalf("reviewed app did not read captured bytes: %q %v", html, err)
	}
	if _, _, err := resolveEmailBody(ctx, &FlowEmail{Template: "docs/note.html"}); err == nil {
		t.Fatal("reviewed app read a template outside its digested source")
	}
}

// A pinned document at the app root loads its sibling $refs from the same
// digest-bound set as one in a subdirectory: reviewing it must work.
func TestAppMCPRuntimeFormBindsRootLevelOpenAPIRefs(t *testing.T) {
	const body = "type: object\nadditionalProperties: false\nrequired: [term]\nproperties: {term: {type: string}}\n"
	spec := strings.Replace(externalRuntimeOpenAPI,
		"schema: {type: object, additionalProperties: false, required: [term], properties: {term: {type: string}}}",
		"schema: {$ref: 'body.yaml'}", 1)
	if spec == externalRuntimeOpenAPI {
		t.Fatal("fixture no longer carries the search request schema")
	}
	for _, layout := range []struct{ doc, ref string }{
		{"openapi/items.yaml", "openapi/body.yaml"},
		{"openapi.yaml", "body.yaml"},
		{"openapi.yaml", "schemas/body.yaml"},
	} {
		t.Run(layout.doc+"+"+layout.ref, func(t *testing.T) {
			dir := t.TempDir()
			writeTestFile(t, dir, "schema.sql", "CREATE TABLE notes (id INTEGER PRIMARY KEY);")
			rel, err := filepath.Rel(filepath.Dir(layout.doc), layout.ref)
			if err != nil {
				t.Fatal(err)
			}
			doc := strings.Replace(spec, "'body.yaml'", "'"+filepath.ToSlash(rel)+"'", 1)
			writeTestFile(t, dir, layout.doc, doc)
			writeTestFile(t, dir, layout.ref, body)
			manifest := strings.ReplaceAll(externalRuntimeManifest, "openapi/items.yaml", layout.doc)
			manifest = strings.Replace(manifest, "connections:", "execution_sources: runtime\nconnections:", 1)
			writeTestFile(t, dir, "mcp.yaml", manifest)
			reviewAppMCPFixture(t, dir)
			if _, err := loadRuntimeConfig(dir); err != nil {
				t.Fatalf("reviewed pinned document with a sibling $ref did not load: %v", err)
			}
			// Editing the referenced file is a runtime change: the review goes stale.
			writeTestFile(t, dir, layout.ref, body+"description: changed\n")
			var stale *appMCPReviewStaleError
			if _, err := loadRuntimeConfig(dir); !errors.As(err, &stale) {
				t.Fatalf("referenced document edit did not stale the review: %v", err)
			}
		})
	}
}
