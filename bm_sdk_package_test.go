package main

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
)

func TestStageBMSDKPackageUsesCanonicalRuntime(t *testing.T) {
	out := t.TempDir()
	cmd := exec.Command("bash", "scripts/stage-bm-package.sh", out)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("stage package: %v\n%s", err, output)
	}

	wantRuntime, err := os.ReadFile("embedded/bm.js")
	if err != nil {
		t.Fatal(err)
	}
	gotRuntime, err := os.ReadFile(filepath.Join(out, "index.js"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(gotRuntime, wantRuntime) {
		t.Fatal("staged index.js differs from canonical embedded/bm.js")
	}

	entries, err := os.ReadDir(out)
	if err != nil {
		t.Fatal(err)
	}
	gotFiles := make([]string, 0, len(entries))
	for _, entry := range entries {
		gotFiles = append(gotFiles, entry.Name())
	}
	sort.Strings(gotFiles)
	wantFiles := []string{"README.md", "index.d.ts", "index.js", "package.json"}
	if !reflect.DeepEqual(gotFiles, wantFiles) {
		t.Fatalf("staged files = %v, want %v", gotFiles, wantFiles)
	}
}

func TestBMSDKPackageExportsESMWithGenericTypes(t *testing.T) {
	raw, err := os.ReadFile("packages/bm/package.json")
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Name         string            `json:"name"`
		Version      string            `json:"version"`
		Type         string            `json:"type"`
		Exports      map[string]string `json:"exports"`
		Types        string            `json:"types"`
		Dependencies map[string]any    `json:"dependencies"`
		Scripts      map[string]any    `json:"scripts"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Name != "@benmore/bm" || manifest.Version != version || manifest.Type != "module" {
		t.Fatalf("unexpected package identity: %+v", manifest)
	}
	if manifest.Exports["import"] != "./index.js" || manifest.Exports["types"] != "./index.d.ts" || manifest.Types != "./index.d.ts" {
		t.Fatalf("unexpected package exports: %+v", manifest)
	}
	if len(manifest.Dependencies) != 0 || len(manifest.Scripts) != 0 {
		t.Fatalf("SDK package must have no dependencies or build scripts: %+v", manifest)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		t.Fatal(err)
	}
	if _, ok := fields["sideEffects"]; ok {
		t.Fatal("SDK installs window/global error handlers; package.json must not claim sideEffects:false")
	}

	types, err := os.ReadFile("packages/bm/index.d.ts")
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"export interface TableClient<Row", "export function table<Row", "export const api:",
		"export const auth:", "export function live(", "export function room(", "export default bm",
		"export function aggregate<", "export function upload(", "export function signedUrl(",
	} {
		if !strings.Contains(string(types), want) {
			t.Errorf("generic declarations missing %q", want)
		}
	}
}

func TestBMSDKDeclarationsCoverCanonicalRuntime(t *testing.T) {
	jsBytes, err := os.ReadFile("embedded/bm.js")
	if err != nil {
		t.Fatal(err)
	}
	dtsBytes, err := os.ReadFile("packages/bm/index.d.ts")
	if err != nil {
		t.Fatal(err)
	}
	js, dts := string(jsBytes), string(dtsBytes)

	// Every actual named JS export must remain a named declaration. This list is
	// source-derived so adding a runtime export without types fails immediately.
	named := regexp.MustCompile(`(?m)^export\s+(?:async\s+)?(?:const|function)\s+([A-Za-z_$][\w$]*)`).FindAllStringSubmatch(js, -1)
	for _, match := range named {
		name := regexp.QuoteMeta(match[1])
		if !regexp.MustCompile(`(?m)^export\s+(?:const|function)\s+` + name + `\b`).MatchString(dts) {
			t.Errorf("named runtime export %q has no named declaration", match[1])
		}
	}

	// The default object intentionally includes private (non-named) functions
	// such as markdown/presence/cache. Derive its keys from the canonical object
	// literal and require an exact default-declaration property for every key.
	defaultMatch := regexp.MustCompile(`(?s)const bm = \{(.*?)\};\s*export default bm;`).FindStringSubmatch(js)
	declareMatch := regexp.MustCompile(`(?s)declare const bm: \{(.*?)\n\};`).FindStringSubmatch(dts)
	if len(defaultMatch) != 2 || len(declareMatch) != 2 {
		t.Fatal("could not locate canonical or declared default bm object")
	}
	declared := map[string]bool{}
	for _, match := range regexp.MustCompile(`(?m)^\s+([A-Za-z_$][\w$]*):`).FindAllStringSubmatch(declareMatch[1], -1) {
		declared[match[1]] = true
	}
	for _, name := range regexp.MustCompile(`[A-Za-z_$][\w$]*`).FindAllString(defaultMatch[1], -1) {
		if !declared[name] {
			t.Errorf("default runtime member %q has no declaration", name)
		}
	}

	// Attached/nested behavior is public API too. Each row proves the runtime
	// marker exists first, then requires the declaration that models it.
	contracts := []struct{ runtime, declaration string }{
		{"raw: {", "raw: {"}, {"optimistic({ apply", "optimistic<T"},
		{"async function signUp(fields)", "signUp(fields: { email: string; password: string;"},
		{"name: t,", "readonly name: string"}, {"restore:  (id)", "restore(id:"},
		{"versions: (id)", "versions(id:"}, {"revertTo: (id, version)", "revertTo(id:"},
		{"table.before = function", "function before("}, {"table.clearHooks = function", "function clearHooks()"},
		{"live.scoped = function", "function scoped("}, {"onAny(fn)", "onAny(fn:"},
		{"raw: ws", "readonly raw: WebSocket"}, {"reset(nextState)", "reset(nextState?:"},
		{"subscribe(selector, listener", "subscribe<Slice>("},
		{"async function markdownBatch(items)", "markdownBatch: typeof markdownBatch"},
		{"function presence(slug)", "presence: typeof presence"}, {"const cache = {", "cache: typeof cache"},
	}
	for _, contract := range contracts {
		if !strings.Contains(js, contract.runtime) {
			t.Fatalf("test contract is stale; runtime marker missing: %q", contract.runtime)
		}
		if !strings.Contains(dts, contract.declaration) {
			t.Errorf("runtime %q missing declaration %q", contract.runtime, contract.declaration)
		}
	}
}
