//go:build !cli

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateScriptSyntaxRefusesUnparsableScripts(t *testing.T) {
	for _, tc := range []struct {
		path, content, want string
	}{
		// The reported case: a compute module with a duplicate declaration.
		{"static/compute/unfurl.ts", "export function unfurl(u: string) {\n  const id = 1;\n  const id = 2;\n  return id;\n}\n", `"id" has already been declared`},
		{"static/app.tsx", "export function App() {\n  return <div>{items.map((i) => <p>{i}</p>}</div>;\n}\n", "static/app.tsx:2:"},
		{"static/lib/util.js", "export function f( {\n", "static/lib/util.js:2:"},
		{"src/views/x.jsx", "const a = <div>;\n", "src/views/x.jsx:2:"},
	} {
		msg := ValidateOnWriteIn(t.TempDir(), tc.path, tc.content)
		if !strings.Contains(msg, "does not parse") || !strings.Contains(msg, tc.want) {
			t.Errorf("%s: write gate = %q, want a parse refusal naming %q", tc.path, msg, tc.want)
		}
	}
}

func TestValidateScriptSyntaxAcceptsValidScripts(t *testing.T) {
	for _, tc := range []struct{ path, content string }{
		{"static/app.tsx", "import bm, { type User } from 'bm';\nimport { notes } from './views/notes';\nexport function App(props: { user?: User }) {\n  return <main>{props.user?.email ?? 'guest'}</main>;\n}\n"},
		{"static/compute/payload.ts", "export function build(name: string) {\n  return { text: `hello ${name}`, n: 2 } as const;\n}\n"},
		// Sloppy-mode scripts served as written (vendored libraries).
		{"static/vendor/legacy.js", "var o = {a: 1};\nwith (o) { a = 2; }\nvar n = 010;\n"},
		{"static/styles.css", "body { color: red"},
		// Outside static/ and src/ nothing is parsed.
		{"tests/fixture.js", "this is not javascript {"},
	} {
		if msg := validateScriptSyntax(tc.path, tc.content); msg != "" {
			t.Errorf("%s: refused valid content: %s", tc.path, msg)
		}
	}
}

// Every script a new app is scaffolded with must pass the gate.
func TestValidateScriptSyntaxAcceptsScaffold(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHTMLScaffoldFiles(dir, "Syntax fixture"); err != nil {
		t.Fatal(err)
	}
	checked := 0
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, _ := filepath.Rel(dir, path)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if _, ok := scriptSyntaxLoaders[strings.ToLower(filepath.Ext(rel))]; ok {
			checked++
		}
		if msg := validateScriptSyntax(rel, string(data)); msg != "" {
			t.Errorf("scaffold file refused: %s", msg)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if checked == 0 {
		t.Fatal("scaffold has no scripts to check")
	}
}

// benmore check walks static/ scripts, so one already deployed is reported.
func TestCheckReportsUnparsableStaticScript(t *testing.T) {
	dir := t.TempDir()
	if err := WriteHTMLScaffoldFiles(dir, "Syntax fixture"); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "static", "compute"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "static", "compute", "unfurl.ts"), []byte("const a = 1;\nconst a = 2;\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	report := runCheck(dir, "", false)
	for _, f := range report.Findings {
		if f.File == "static/compute/unfurl.ts" && f.Severity == "error" && strings.Contains(f.Message, "does not parse") {
			return
		}
	}
	t.Fatalf("check did not report the unparsable compute module: %+v", report.Findings)
}
