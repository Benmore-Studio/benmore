//go:build !cli

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestInlineSourceMap(t *testing.T) {
	prefix := "//# sourceMappingURL=data:application/json;base64,"
	data := []byte(`{"version":3,"sources":[],"mappings":""}`)
	bundle := []byte(prefix + "bad\nconsole.log(1);\n" + prefix + base64.StdEncoding.EncodeToString(data) + "\n")
	got, ok := inlineSourceMap(bundle)
	if !ok || !bytes.Equal(got, data) {
		t.Fatalf("inline map: %q, %v", got, ok)
	}
	for _, bad := range [][]byte{[]byte(prefix + "%%%"), bytes.Repeat([]byte("x"), (16<<20)+1), []byte("none")} {
		if _, ok := inlineSourceMap(bad); ok {
			t.Fatal("accepted invalid map")
		}
	}
}

func errorMapFixture(t *testing.T) (*App, string, *tsxCacheEntry, int, int) {
	t.Helper()
	dir := t.TempDir()
	root := filepath.Join(dir, "static")
	if err := os.MkdirAll(root, 0755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"app.tsx":  "import { crash } from './crash';\ncrash();\n",
		"crash.ts": "export function crash() {\n  throw new Error('mapping-marker');\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(root, name), []byte(content), 0644); err != nil {
			t.Fatal(err)
		}
	}
	entryPath := resolveTSXSource(dir, "app.js")
	entry, err := compileTSXEntry(context.Background(), entryPath, root, true, "")
	if err != nil {
		t.Fatal(err)
	}
	if entry.treeVersion == "" {
		t.Fatal("real served bundle has no tree version")
	}
	for line, text := range strings.Split(string(entry.body), "\n") {
		if col := strings.Index(text, "throw new Error"); col >= 0 {
			return &App{Dir: dir}, entryPath, entry, line + 1, col + 1
		}
	}
	t.Fatal("fixture throw missing from compiled output")
	return nil, "", nil, 0, 0
}

func TestSymbolicateCachedTSX(t *testing.T) {
	app, entryPath, entry, line, col := errorMapFixture(t)
	data, ok := inlineSourceMap(entry.body)
	if !ok {
		t.Fatal("real esbuild output has no inline source map")
	}
	var sm rawSourceMap
	if err := json.Unmarshal(data, &sm); err != nil {
		t.Fatal(err)
	}
	if len(sm.SourcesContent) == 0 {
		t.Fatal("U1: esbuild omitted sourcesContent")
	}
	before := tsxCompileRuns.Load()
	frames := []errorFrame{{Filename: "/static/app.js", AbsPath: "https://app.example/static/app.js", Line: line, Col: col, InApp: true, Version: entry.treeVersion}}
	got, stale := symbolicateFrames(app, frames)
	if stale || len(got) != 1 || !strings.HasSuffix(got[0].Filename, "crash.ts") || got[0].Line != 2 || !strings.Contains(got[0].ContextLine, "mapping-marker") {
		t.Fatalf("resolved: %+v, stale=%v", got, stale)
	}
	frames[0].Version = "old"
	got, stale = symbolicateFrames(app, frames)
	if !stale || got[0].Filename != "/static/app.js" {
		t.Fatalf("stale: %+v %v", got, stale)
	}
	tsxCacheMu.Lock()
	delete(tsxCache, entryPath)
	tsxCacheMu.Unlock()
	frames[0].Version = entry.treeVersion
	got, _ = symbolicateFrames(app, frames)
	if got[0].Filename != "/static/app.js" || tsxCompileRuns.Load() != before {
		t.Fatal("cold cache compiled or resolved a bundle")
	}
}

func TestSourceMapColumnsAndUnmappedSegments(t *testing.T) {
	sm := &rawSourceMap{Version: 3, Sources: []string{"a.ts"}, Names: []string{"a"}, Mappings: "AAAAA,KACA,K"}
	data, err := json.Marshal(sm)
	if err != nil {
		t.Fatal(err)
	}
	source, line, col, name, err := decodeSourceMapPos(data, 1, 6)
	if err != nil || source != "a.ts" || line != 2 || col != 1 || name != "" {
		t.Fatalf("shared decoder boundary: %s:%d:%d %q %v", source, line, col, name, err)
	}
	loc, ok := lookupSourceMap(sm, 1, 5)
	if !ok || loc.Line != 1 {
		t.Fatalf("one-based boundary: %+v", loc)
	}
	loc, ok = lookupSourceMap(sm, 1, 6)
	if !ok || loc.Line != 2 || loc.Name != "" {
		t.Fatalf("second segment: %+v", loc)
	}
	if _, ok = lookupSourceMap(sm, 1, 11); ok {
		t.Fatal("unmapped segment retained earlier location")
	}
}
