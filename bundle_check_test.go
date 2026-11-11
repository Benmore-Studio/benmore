//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// bundleCheckApp is a freshly scaffolded app: static/app.tsx imports
// ./lib/auth and ./views/notes, which imports ../components/ui and ../lib/dom.
func bundleCheckApp(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := WriteHTMLScaffoldFiles(dir, "Bundle check"); err != nil {
		t.Fatal(err)
	}
	return dir
}

func findingFor(report CheckReport, file, needle string) *CheckFinding {
	for i, f := range report.Findings {
		if f.Severity == "error" && f.File == file && strings.Contains(f.Message, needle) {
			return &report.Findings[i]
		}
	}
	return nil
}

// Every script and page a new app is scaffolded with must pass the new
// checks, at write time and in `benmore check`.
func TestBundleCheckAcceptsScaffold(t *testing.T) {
	dir := bundleCheckApp(t)
	for _, rel := range []string{"static/app.tsx", "static/lib/auth.ts", "static/lib/dom.ts", "static/views/notes.tsx", "static/components/ui.tsx", "static/styles.css", "static/index.html", "static/login.html"} {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
		if err != nil {
			t.Fatal(err)
		}
		if msg := ValidateOnWriteIn(dir, rel, string(data)); msg != "" {
			t.Errorf("scaffold %s refused: %s", rel, msg)
		}
	}
	for _, f := range runCheck(dir, "", false).Findings {
		if f.Source == "bundle" || f.Source == "include" {
			t.Errorf("scaffold check finding: %+v", f)
		}
	}
}

// Finding 8: an import outside static/ passed push and check and served a
// module that throws. It is refused at write time with esbuild's message and
// location, also inside a batch (no later file can move app.yaml into static/).
func TestWriteGateRefusesBundleImportOutsideStatic(t *testing.T) {
	dir := bundleCheckApp(t)
	leak := "// reads the app config\nimport cfg from '../app.yaml' with { type: 'text' };\nconsole.log(cfg);\n"
	for name, msg := range map[string]string{
		"single write": ValidateOnWriteIn(dir, "static/leak.tsx", leak),
		"batch write":  func() string { m, _ := ValidateOnWriteInBatch(dir, "static/leak.tsx", leak, true, nil); return m }(),
	} {
		if !strings.Contains(msg, "static/leak.tsx:2:") || !strings.Contains(msg, "refusing to read a file outside static/") || !strings.Contains(msg, "/static/leak.js") {
			t.Errorf("%s: write gate = %q, want the containment refusal located at static/leak.tsx:2", name, msg)
		}
	}
	// The containment message never quotes the outside file.
	appYAML, _ := os.ReadFile(filepath.Join(dir, "app.yaml"))
	if msg := ValidateOnWriteIn(dir, "static/leak.tsx", leak); len(appYAML) > 20 && strings.Contains(msg, strings.TrimSpace(string(appYAML))[:20]) {
		t.Errorf("refusal quotes app.yaml: %s", msg)
	}
}

// A file symlinked into static/ from outside is refused by its real path,
// and the refusal does not carry the file's bytes.
func TestWriteGateRefusesImportOfSymlinkLeavingStatic(t *testing.T) {
	appDir, static := bundleContainmentApp(t)
	writeBundleFile(t, filepath.Join(static, "app.tsx"), "export const ok = 1;\n")
	if err := os.Symlink(filepath.Join(appDir, ".benmore", "server-secret"), filepath.Join(static, "secret.txt")); err != nil {
		t.Fatal(err)
	}
	msg := ValidateOnWriteIn(appDir, "static/app.tsx", "import s from './secret.txt' with { type: 'text' };\nconsole.log(s);\n")
	if !strings.Contains(msg, "outside static/") {
		t.Fatalf("write gate = %q, want a containment refusal", msg)
	}
	if strings.Contains(msg, "synthetic-server-secret") {
		t.Fatalf("refusal leaked the linked file: %s", msg)
	}
}

// Finding 8: an import that resolves to nothing, and a named import its
// module does not export, are refused for a single write. In a batch that
// defers its reload a later file may supply them, so the write is accepted
// and the post-write check reports them.
func TestWriteGateRefusesUnresolvableImports(t *testing.T) {
	dir := bundleCheckApp(t)
	cases := map[string]string{
		"missing module": "import { nope } from './lib/does-not-exist';\nconsole.log(nope);\n",
		"missing export": "import { nope } from './lib/dom';\nconsole.log(nope);\n",
	}
	wants := map[string]string{"missing module": `Could not resolve "./lib/does-not-exist"`, "missing export": `No matching export`}
	for name, src := range cases {
		msg := ValidateOnWriteIn(dir, "static/probe.tsx", src)
		if !strings.Contains(msg, "static/probe.tsx:1:") || !strings.Contains(msg, wants[name]) {
			t.Errorf("%s: write gate = %q, want %q at static/probe.tsx:1", name, msg, wants[name])
		}
		if msg, _ := ValidateOnWriteInBatch(dir, "static/probe.tsx", src, true, nil); msg != "" {
			t.Errorf("%s: deferred batch write refused: %s", name, msg)
		}
		writeAppFile(t, dir, "static/probe.tsx", src)
		if f := findingFor(RunSourceCheck(dir, "static/probe.tsx"), "static/probe.tsx", wants[name]); f == nil || f.Source != "bundle" {
			t.Errorf("%s: post-write check did not report it: %+v", name, RunSourceCheck(dir, "static/probe.tsx").Findings)
		}
	}
}

// A module that imports a broken one is part of the same bundle: a write of
// the importer is judged with the whole graph (here views/notes.tsx imports
// lib/dom.ts, which app.tsx reaches through it).
func TestWriteGateBuildsTheWrittenModulesImporters(t *testing.T) {
	dir := bundleCheckApp(t)
	t.Run("errors in another file are reported, not refused", func(t *testing.T) {
		// lib/dom.ts loses the export views/notes.tsx imports: the error is
		// in notes.tsx, so the write is saved (refusing would deadlock an
		// export renamed together with its import) and the check reports it.
		dom, err := os.ReadFile(filepath.Join(dir, "static", "lib", "dom.ts"))
		if err != nil {
			t.Fatal(err)
		}
		renamed := strings.ReplaceAll(string(dom), "export function reconcileList", "export function reconcileRows")
		if renamed == string(dom) {
			t.Fatal("scaffold lib/dom.ts no longer exports reconcileList")
		}
		if msg := ValidateOnWriteIn(dir, "static/lib/dom.ts", renamed); msg != "" {
			t.Fatalf("write of lib/dom.ts refused for its importer's error: %s", msg)
		}
		writeAppFile(t, dir, "static/lib/dom.ts", renamed)
		report := RunSourceCheck(dir, "static/lib/dom.ts")
		if f := findingFor(report, "static/views/notes.tsx", `No matching export in "lib/dom.ts" for import "reconcileList"`); f == nil {
			t.Fatalf("post-write check did not report the importer: %+v", report.Findings)
		}
		writeAppFile(t, dir, "static/lib/dom.ts", string(dom))
	})
	t.Run("only affected entries are built", func(t *testing.T) {
		writeAppFile(t, dir, "static/standalone.tsx", "export const standalone = 1;\n")
		tree, ok := loadBundleTree(dir)
		if !ok || !tree.readContents() {
			t.Fatal("tree not loaded")
		}
		var got []string
		for _, e := range tree.affectedEntries("static/lib/dom.ts") {
			got = append(got, tree.rel(e))
		}
		joined := strings.Join(got, ",")
		for _, want := range []string{"static/app.tsx", "static/views/notes.tsx", "static/lib/dom.ts"} {
			if !strings.Contains(joined, want) {
				t.Errorf("affected entries %v miss %s", got, want)
			}
		}
		if strings.Contains(joined, "standalone") || strings.Contains(joined, "components/ui.tsx") {
			t.Errorf("affected entries %v include files that do not import lib/dom.ts", got)
		}
	})
	t.Run("the post-write check reuses the gate's build", func(t *testing.T) {
		src := "import { reconcileList } from './lib/dom';\nexport const r = reconcileList;\n"
		before := bundleCheckBuilds.Load()
		if msg := ValidateOnWriteIn(dir, "static/reuse.tsx", src); msg != "" {
			t.Fatalf("refused: %s", msg)
		}
		writeAppFile(t, dir, "static/reuse.tsx", src)
		RunSourceCheck(dir, "static/reuse.tsx")
		if n := bundleCheckBuilds.Load() - before; n != 1 {
			t.Fatalf("gate + post-write check ran %d builds, want 1", n)
		}
	})
}

// Finding 8, the real-world case: deleting views/notes.tsx while app.tsx
// still imports it broke the login and signup scripts. The delete is
// refused naming the importer; once the import is gone it goes through.
func TestBundleDeleteRefusalNamesImporters(t *testing.T) {
	dir := bundleCheckApp(t)
	msg := bundleDeleteRefusal(dir, "static/views/notes.tsx")
	if !strings.Contains(msg, "refusing to delete static/views/notes.tsx") || !strings.Contains(msg, "static/app.tsx:") || !strings.Contains(msg, `Could not resolve "./views/notes"`) {
		t.Fatalf("delete refusal = %q, want it to name static/app.tsx's import", msg)
	}
	// A file nothing imports, and a module whose importer already fails for
	// another reason, are not refused for the delete.
	writeAppFile(t, dir, "static/lib/unused.ts", "export const unused = 1;\n")
	if msg := bundleDeleteRefusal(dir, "static/lib/unused.ts"); msg != "" {
		t.Fatalf("delete of an unimported module refused: %s", msg)
	}
	app, err := os.ReadFile(filepath.Join(dir, "static", "app.tsx"))
	if err != nil {
		t.Fatal(err)
	}
	var kept []string
	for _, line := range strings.Split(string(app), "\n") {
		if strings.Contains(line, "./views/notes") {
			continue
		}
		kept = append(kept, strings.ReplaceAll(line, "initNotes(", "void ("))
	}
	writeAppFile(t, dir, "static/app.tsx", strings.Join(kept, "\n"))
	if msg := bundleDeleteRefusal(dir, "static/views/notes.tsx"); msg != "" {
		t.Fatalf("delete refused after the import was removed: %s", msg)
	}
}

// `benmore check` builds every entry: a deployed app whose module was
// deleted under its importer reports the importer.
func TestCheckReportsBrokenBundle(t *testing.T) {
	dir := bundleCheckApp(t)
	if err := os.Remove(filepath.Join(dir, "static", "views", "notes.tsx")); err != nil {
		t.Fatal(err)
	}
	writeAppFile(t, dir, "static/leak.tsx", "import cfg from '../app.yaml' with { type: 'text' };\nconsole.log(cfg);\n")
	report := runCheck(dir, "", false)
	if f := findingFor(report, "static/app.tsx", `Could not resolve "./views/notes"`); f == nil || f.Source != "bundle" {
		t.Errorf("check did not report app.tsx's missing module: %+v", report.Findings)
	}
	if f := findingFor(report, "static/leak.tsx", "outside static/"); f == nil {
		t.Errorf("check did not report the import outside static/: %+v", report.Findings)
	}
}

// A tree the check cannot copy faithfully (a directory link) is not judged,
// rather than refused for files the copy would miss.
func TestBundleCheckSkipsTreeWithDirectoryLink(t *testing.T) {
	dir := bundleCheckApp(t)
	if err := os.Symlink("lib", filepath.Join(dir, "static", "shared")); err != nil {
		t.Fatal(err)
	}
	if msg := ValidateOnWriteIn(dir, "static/probe.tsx", "import { nope } from './lib/does-not-exist';\n"); strings.Contains(msg, "Could not resolve") {
		t.Fatalf("tree with a directory link was judged: %s", msg)
	}
}

// Measured on the fleet snapshot before shipping: files that are no page's
// script are not reported. A connector widget component imports the MCP Apps
// module the widget build supplies, tests kept in static/ import their
// runner's modules, and a vendored bundle over 1 MiB is not read (any name
// imported from it is accepted).
func TestBundleCheckLeavesWidgetsTestsAndVendoredBundles(t *testing.T) {
	dir := bundleCheckApp(t)
	writeAppFile(t, dir, "static/widgets/kit.ts", "import { App } from '@modelcontextprotocol/ext-apps';\nimport { reconcileList } from '../lib/dom';\nexport const app = new App({ name: 'kit', version: '1' });\nexport const r = reconcileList;\n")
	writeAppFile(t, dir, "static/server/rules.ts", "export function rules() { return 1; }\n")
	writeAppFile(t, dir, "static/server/__tests__/rules.test.ts", "import { expect, test } from 'bun:test';\nimport { rules } from '../rules';\ntest('r', () => expect(rules()).toBe(1));\n")
	writeAppFile(t, dir, "static/server/rules.spec.ts", "import { test } from 'vitest';\ntest('r', () => {});\n")
	writeAppFile(t, dir, "static/vendor/big.js", "export const big = 1;\n/*"+strings.Repeat("x", bundleCheckStubBytes)+"*/\n")
	writeAppFile(t, dir, "static/uses-big.tsx", "import { big, other } from './vendor/big.js';\nconsole.log(big, other);\n")
	for _, f := range runCheck(dir, "", false).Findings {
		if f.Source == "bundle" {
			t.Errorf("unexpected bundle finding: %+v", f)
		}
	}
	// A write of the module the tests import does not report them either.
	if msg := ValidateOnWriteIn(dir, "static/server/rules.ts", "export function rules() { return 2; }\n"); msg != "" {
		t.Errorf("write refused: %s", msg)
	}
	// A page script importing an unknown package is still reported.
	writeAppFile(t, dir, "static/chart.tsx", "import { Chart } from 'chart.js';\nconsole.log(Chart);\n")
	if f := findingFor(runCheck(dir, "", false), "static/chart.tsx", `Could not resolve "chart.js"`); f == nil {
		t.Error("check did not report the unresolvable package import")
	}
}
