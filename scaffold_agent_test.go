//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestScaffoldSharedAgentContractMatchesEdition(t *testing.T) {
	dir := t.TempDir()
	if err := WriteBareScaffoldFiles(dir, "Fixture"); err != nil {
		t.Fatal(err)
	}
	shared, err := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	claude, err := os.ReadFile(filepath.Join(dir, "CLAUDE.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(claude), "@AGENTS.md") {
		t.Fatal("Claude does not import the shared contract")
	}
	hosted := editionName == "cloud" || editionName == "platform"
	for _, command := range []string{"benmore push", "benmore api", "benmore skill install --agent codex"} {
		if strings.Contains(string(shared), command) != hosted {
			t.Errorf("%s scaffold has wrong availability for %q", editionName, command)
		}
	}
	if strings.Contains(string(shared), "benmore dev") || strings.Contains(string(shared), "init-workspace") {
		t.Fatal("removed command in scaffold")
	}
}

func TestHTMLScaffoldCarriesQASelectorsAndStarterJourney(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHTMLScaffoldFiles(dir, "QA App"); err != nil {
		t.Fatal(err)
	}
	for file, ids := range map[string][]string{
		"static/index.html":  {`data-testid="note-form"`, `data-testid="note-add"`, `data-testid="signout"`, `data-testid="nav-login"`},
		"static/login.html":  {`data-testid="login-email"`, `data-testid="login-submit"`},
		"static/signup.html": {`data-testid="signup-email"`, `data-testid="signup-submit"`},
	} {
		b, err := os.ReadFile(filepath.Join(dir, file))
		if err != nil {
			t.Fatal(err)
		}
		for _, id := range ids {
			if !strings.Contains(string(b), id) {
				t.Errorf("%s missing %s", file, id)
			}
		}
	}
	journey, err := os.ReadFile(filepath.Join(dir, "tests", "journeys", "home.yaml"))
	if err != nil {
		t.Fatalf("starter journey missing: %v", err)
	}
	for _, want := range []string{"name: home", "tags: [smoke]", "path: /", "assertions:", `{visible: "main"}`} {
		if !strings.Contains(string(journey), want) {
			t.Errorf("starter journey missing %q:\n%s", want, journey)
		}
	}
	guide, err := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	// The hosted editions point at the QA reference and tools; the framework
	// edition has neither and points at its own test runner.
	runner := "benmore test <appdir>"
	if editionName == "cloud" || editionName == "platform" {
		runner = `api(at:"qa")`
	}
	if !strings.Contains(string(guide), "data-testid") || !strings.Contains(string(guide), runner) {
		t.Fatalf("scaffolded AGENTS.md must teach the QA selector convention and name %q:\n%s", runner, guide)
	}
}

// A new app's files are the first thing its agent reads, so they may name only
// what the edition that wrote them can run. The framework edition has no
// platform MCP tools and no hosted CLI commands; it said to run `benmore qa
// draft`, `benmore types` and `benmore publish`, all of which answer "Unknown
// command" there. It does carry the reference: an api(at:"<topic>.<key>")
// address, as a refusal prints one, is read with `benmore docs`, so the
// notation may appear only where the file says so.
func TestFrameworkScaffoldNamesOnlyItsOwnCommands(t *testing.T) {
	if editionName != "framework" {
		t.Skip("the hosted editions have these commands and tools")
	}
	dir := t.TempDir()
	if err := WriteHTMLScaffoldFiles(dir, "Edition"); err != nil {
		t.Fatal(err)
	}
	hostedOnly := []string{
		"qa_inventory", "browser_batch", "benmore qa", "benmore types", "benmore publish",
		"benmore push", "benmore deploy", "benmore check", "benmore sync-status", "benmore promote",
		"benmore skill", "benmore hooks", "benmore api",
	}
	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return err
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, _ := filepath.Rel(dir, path)
		for _, name := range hostedOnly {
			if strings.Contains(string(body), name) {
				t.Errorf("%s names %q, which the framework edition does not have", rel, name)
			}
		}
		// `benmore verify` may be named only as the hosted runner this
		// edition lacks, and an api(at:) address only as what a refusal
		// prints (there is no `api` tool here to call).
		for _, line := range strings.Split(string(body), "\n") {
			if strings.Contains(line, "benmore verify") && !strings.Contains(line, "hosted") {
				t.Errorf("%s presents benmore verify as available: %q", rel, line)
			}
			if strings.Contains(line, "api(at:") && !strings.Contains(line, "docs: api(at:") {
				t.Errorf("%s presents the api tool as available: %q", rel, line)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// The placeholder src/bm.d.ts stands in until the first types refresh, so it
// must agree with the generated file on what the runtime answers and export
// what the starter's own files import. It typed update() as the row and a
// change event as carrying one, and had no Note export for views/notes.tsx.
func TestScaffoldTypesPlaceholderMatchesTheRuntime(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHTMLScaffoldFiles(dir, "Types"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "src", "bm.d.ts"))
	if err != nil {
		t.Fatal(err)
	}
	placeholder := string(raw)
	generated := GenerateBMTypes(&App{Tables: []Table{{Name: "notes", Columns: []Column{{Name: "id", Type: "INTEGER", PK: true, NotNull: true}}}}})
	for _, want := range []string{
		"update(id: number | string, body: Partial<Row>): Promise<UpdateReceipt>;",
		"| { action: 'insert' | 'update' | 'delete'; table: string }",
		"| { action: 'refresh'; table: '' };",
	} {
		if !strings.Contains(generated, want) {
			t.Fatalf("generated types no longer declare %q; update the placeholder to match", want)
		}
		if !strings.Contains(placeholder, want) {
			t.Errorf("placeholder does not declare %q as the generated types do", want)
		}
	}
	if strings.Contains(placeholder, "row: T") || strings.Contains(placeholder, "Promise<Row>;\n  delete") {
		t.Errorf("placeholder types a change event or update() as carrying the row:\n%s", placeholder)
	}
	// Every type the starter imports from 'bm' is exported by the placeholder.
	importRe := regexp.MustCompile(`import bm, \{([^}]*)\} from 'bm'`)
	checked := 0
	err = filepath.Walk(filepath.Join(dir, "static"), func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !(strings.HasSuffix(path, ".ts") || strings.HasSuffix(path, ".tsx")) {
			return err
		}
		body, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, m := range importRe.FindAllStringSubmatch(string(body), -1) {
			for _, name := range strings.Split(m[1], ",") {
				name = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), "type "))
				if name == "" {
					continue
				}
				checked++
				if !strings.Contains(placeholder, "export interface "+name+" ") && !strings.Contains(placeholder, "export type "+name+" ") {
					t.Errorf("%s imports %s from 'bm'; the placeholder does not export it", filepath.Base(path), name)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("found no named imports from 'bm' in the starter; the check no longer reads them")
	}
	// The bare scaffold has no notes table and so no Note type.
	bare := t.TempDir()
	if err := WriteBareScaffoldFiles(bare, "Bare"); err != nil {
		t.Fatal(err)
	}
	rawBare, err := os.ReadFile(filepath.Join(bare, "src", "bm.d.ts"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(rawBare), "Note") {
		t.Errorf("bare placeholder declares the demo's Note type:\n%s", rawBare)
	}
}

// The generated AGENTS.md says how to find a contract with what the edition
// that wrote it can run. The hosted editions have the addressed reference:
// search, then the topic's index, then the key. The framework edition has no
// `api` command, so it names the bundled guides, command help and the running
// app's own description, each of which answers there.
func TestScaffoldAgentContractSaysHowToFindAContract(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHTMLScaffoldFiles(dir, "Lookup"); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	guide := strings.Join(strings.Fields(string(raw)), " ")
	if editionName == "cloud" || editionName == "platform" {
		for _, want := range []string{
			"**Contract, not guesses.**",
			"`benmore api <app> --search \"<words>\"`",
			"`benmore api <app> <topic>`",
			"`benmore api <app> index`",
			"`benmore api <app> <topic>.<key>`",
			"when an answer names a documentation address, fetch it",
		} {
			if !strings.Contains(guide, want) {
				t.Errorf("the hosted AGENTS.md does not say %q", want)
			}
		}
		return
	}
	for _, want := range []string{
		"Do not guess a contract",
		"The reference is in the binary and needs no network",
		"`benmore docs --search \"<words>\"`",
		"`benmore docs <topic>.<key>`",
		"`benmore docs <topic>`",
		"`benmore docs index`",
		"`docs: api(at:\"<topic>.<key>\")`",
		"`benmore help <command>`",
		"`/api/_schema` and `/api/_openapi` (signed in)",
	} {
		if !strings.Contains(guide, want) {
			t.Errorf("the framework AGENTS.md does not say %q", want)
		}
	}
	// What it names answers in this edition: each form of `benmore docs`
	// reads the reference from the binary, an address pasted from a refusal
	// included, and both routes exist and ask for a sign-in.
	for _, args := range [][]string{{"--search", "rate limit"}, {"csrf.how_to_send"}, {"flows"}, {"index"}, {`api(at:"csrf.how_to_send")`}} {
		if code, guideName, stdout, stderr := docsForTest(t, args...); code != 0 || guideName != "" || !strings.HasPrefix(stdout, "{") {
			t.Errorf("benmore docs %q does not answer from the reference: exit %d, guide %q\n%s", args, code, guideName, stderr)
		}
	}
	app, err := loadApp(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Shutdown)
	mux := buildAppMux(app, false, "https://lookup.example.com")
	for _, path := range []string{"/api/_schema", "/api/_openapi"} {
		r := httptest.NewRequest(http.MethodGet, "https://lookup.example.com"+path, nil)
		rr := httptest.NewRecorder()
		mux.ServeHTTP(rr, r)
		if rr.Code != http.StatusUnauthorized {
			t.Errorf("GET %s without a sign-in answered %d, want 401", path, rr.Code)
		}
	}
}
