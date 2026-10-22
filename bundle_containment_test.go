//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	esbuild "github.com/benmore-studio/benmore/third_party/esbuild/pkg/api"
)

// A synthetic, recognisable stand-in for the app server secret.
var bundleContainmentSecret = strings.Repeat("synthetic-server-secret-", 3)

// bundleContainmentApp lays out <app>/.benmore/server-secret and an empty
// <app>/static, the shape of a hosted app directory.
func bundleContainmentApp(t *testing.T) (appDir, static string) {
	t.Helper()
	appDir = t.TempDir()
	static = filepath.Join(appDir, "static")
	for _, dir := range []string{static, filepath.Join(appDir, ".benmore")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(appDir, ".benmore", "server-secret"), []byte(bundleContainmentSecret), 0o600); err != nil {
		t.Fatal(err)
	}
	return appDir, static
}

func writeBundleFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// A failed browser build is served publicly as a module that throws
// esbuild's messages. Importing a file outside static/ as JSON used to fail
// with a parse error that quoted the file - here the app's server secret -
// because containment was only checked after a successful build.
func TestTSXBuildNeverReadsFilesOutsideStatic(t *testing.T) {
	resetTSXCache()
	appDir, static := bundleContainmentApp(t)
	cases := map[string]string{
		"json import":      "import s from '../.benmore/server-secret' with { type: 'json' };\nconsole.log(s);\n",
		"text import":      "import s from '../.benmore/server-secret' with { type: 'text' };\nconsole.log(s);\n",
		"absolute import":  "import s from '" + filepath.Join(appDir, ".benmore", "server-secret") + "' with { type: 'text' };\nconsole.log(s);\n",
		"css import":       "import './sheet.css';\n",
		"symlinked import": "import s from './linked/server-secret' with { type: 'text' };\nconsole.log(s);\n",
	}
	writeBundleFile(t, filepath.Join(static, "sheet.css"), "@import '../.benmore/server-secret';\n")
	if err := os.Symlink(filepath.Join(appDir, ".benmore"), filepath.Join(static, "linked")); err != nil {
		t.Fatal(err)
	}
	for name, src := range cases {
		entry := filepath.Join(static, strings.ReplaceAll(name, " ", "-")+".ts")
		writeBundleFile(t, entry, src)
		out, err := compileTSXOrTS(entry, static)
		if err != nil {
			t.Fatalf("%s: compile: %v", name, err)
		}
		if strings.Contains(string(out), bundleContainmentSecret[:24]) {
			t.Fatalf("%s: public bundle carries the server secret:\n%s", name, out)
		}
		if !strings.Contains(string(out), "outside static/") {
			t.Fatalf("%s: expected an outside-static refusal, got:\n%s", name, out)
		}
	}
}

// A package resolved from a node_modules directory above static/ is refused
// when esbuild would load it.
func TestTSXBuildRefusesPackagesOutsideStatic(t *testing.T) {
	resetTSXCache()
	appDir, static := bundleContainmentApp(t)
	writeBundleFile(t, filepath.Join(appDir, "node_modules", "leakpkg", "index.js"), "export const v = 'OUTSIDE-PACKAGE-BODY';\n")
	entry := filepath.Join(static, "app.ts")
	writeBundleFile(t, entry, "import { v } from 'leakpkg';\nconsole.log(v);\n")
	out, err := compileTSXOrTS(entry, static)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "OUTSIDE-PACKAGE-BODY") || !strings.Contains(string(out), "outside static/") {
		t.Fatalf("a package outside static/ must be refused:\n%s", out)
	}
}

// esbuild still reads tsconfig.json files while resolving. An error located
// in a file outside static/ must not publish that file's text.
func TestTSXBuildErrorOutsideStaticIsRedacted(t *testing.T) {
	resetTSXCache()
	_, static := bundleContainmentApp(t)
	writeBundleFile(t, filepath.Join(static, "tsconfig.json"), `{"extends": "../.benmore/server-secret"}`)
	entry := filepath.Join(static, "app.ts")
	writeBundleFile(t, entry, "const x: number = ;\n")
	out, err := compileTSXOrTS(entry, static)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), bundleContainmentSecret[:24]) {
		t.Fatalf("public bundle carries the server secret:\n%s", out)
	}
	if !strings.Contains(string(out), "[bm-tsx-compile]") {
		t.Fatalf("expected the in-static syntax error to still be reported:\n%s", out)
	}
}

// Messages located outside static/ lose their text and location; messages
// inside keep both.
func TestRedactOutsideBuildMessages(t *testing.T) {
	appDir, static := bundleContainmentApp(t)
	msgs := []esbuild.Message{
		{Text: "Unexpected \"" + bundleContainmentSecret + "\"", Location: &esbuild.Location{File: "../.benmore/server-secret", Line: 1, LineText: bundleContainmentSecret}},
		{Text: "Unexpected \"" + bundleContainmentSecret + "\"", Location: &esbuild.Location{File: filepath.Join(appDir, ".benmore", "server-secret"), Line: 1}},
		{Text: "Expected expression", Location: &esbuild.Location{File: "app.ts", Line: 3, LineText: "const x = ;"}},
		{Text: "no location"},
	}
	got := redactOutsideBuildMessages(msgs, static, static)
	for i := 0; i < 2; i++ {
		if got[i].Location != nil || strings.Contains(got[i].Text, bundleContainmentSecret) || !strings.Contains(got[i].Text, "outside static/") {
			t.Fatalf("message %d located outside static/ was not redacted: %+v", i, got[i])
		}
	}
	if got[2].Location == nil || got[2].Location.Line != 3 || got[2].Text != "Expected expression" {
		t.Fatalf("message inside static/ was changed: %+v", got[2])
	}
	if got[3].Text != "no location" {
		t.Fatalf("message without a location was changed: %+v", got[3])
	}
}

// A compute module's compile errors reach flow logs and step errors; an
// import outside static/ is refused before its bytes are read.
func TestComputeBuildNeverReadsFilesOutsideStatic(t *testing.T) {
	appDir, static := bundleContainmentApp(t)
	writeBundleFile(t, filepath.Join(static, "leak.ts"),
		"import s from '../.benmore/server-secret' with { type: 'json' };\nexport function f(): string { return String(s); }\n")
	_, err := RunCompute(&App{Dir: appDir}, "leak", "f", nil, 0)
	if err == nil {
		t.Fatal("expected the import outside static/ to be refused")
	}
	if strings.Contains(err.Error(), bundleContainmentSecret[:24]) || !strings.Contains(err.Error(), "outside static/") {
		t.Fatalf("compute error must refuse without quoting the file: %v", err)
	}
}
