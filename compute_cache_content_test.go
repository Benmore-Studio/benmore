//go:build !cli

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestComputeCacheInvalidatesWhenContentChangesWithRestoredMtime(t *testing.T) {
	staticDir := filepath.Join(t.TempDir(), "static")
	if err := os.MkdirAll(staticDir, 0o755); err != nil {
		t.Fatal(err)
	}
	entry := filepath.Join(staticDir, "main.ts")
	dependency := filepath.Join(staticDir, "factor.ts")
	write := func(path, content string) {
		t.Helper()
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(dependency, "export const factor = 2;\n")
	write(entry, `import { factor } from './factor';
export function calculate(value: number): number { return value * factor; }
`)

	dependencyInfo, err := os.Stat(dependency)
	if err != nil {
		t.Fatal(err)
	}
	entryInfo, err := os.Stat(entry)
	if err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: filepath.Dir(staticDir)}
	got, err := RunCompute(app, "main", "calculate", 3, 0)
	if err != nil || got != int64(6) {
		t.Fatalf("initial RunCompute = %v, %v; want 6, nil", got, err)
	}

	write(dependency, "export const factor = 3;\n")
	if err := os.Chtimes(dependency, dependencyInfo.ModTime(), dependencyInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	got, err = RunCompute(app, "main", "calculate", 3, 0)
	if err != nil || got != int64(9) {
		t.Fatalf("import-only same-mtime edit = %v, %v; want 9", got, err)
	}
	write(entry, `import { factor } from './factor';
export function calculate(value: number): number { return value * factor + 1; }
`)
	if err := os.Chtimes(dependency, dependencyInfo.ModTime(), dependencyInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(entry, entryInfo.ModTime(), entryInfo.ModTime()); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{entry, dependency} {
		want := entryInfo.ModTime()
		if path == dependency {
			want = dependencyInfo.ModTime()
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if !info.ModTime().Equal(want) {
			t.Fatalf("could not restore mtime for %s: got %v, want %v", filepath.Base(path), info.ModTime(), want)
		}
	}

	got, err = RunCompute(app, "main", "calculate", 3, 0)
	if err != nil || got != int64(10) {
		t.Fatalf("RunCompute after same-mtime edits = %v, %v; want 10, nil", got, err)
	}
}

func TestComputeCacheInvalidatesEntrySymlinkRetarget(t *testing.T) {
	static := filepath.Join(t.TempDir(), "static")
	if err := os.MkdirAll(static, 0700); err != nil {
		t.Fatal(err)
	}
	a, b, entry := filepath.Join(static, "a.ts"), filepath.Join(static, "b.ts"), filepath.Join(static, "main.ts")
	if err := os.WriteFile(a, []byte("export function calculate() { return 1; }"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("export function calculate() { return 2; }"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("a.ts", entry); err != nil {
		t.Fatal(err)
	}
	app := &App{Dir: filepath.Dir(static)}
	if got, err := RunCompute(app, "main", "calculate", nil, 0); err != nil || got != int64(1) {
		t.Fatalf("first target %v %v", got, err)
	}
	if err := os.Remove(entry); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("b.ts", entry); err != nil {
		t.Fatal(err)
	}
	if got, err := RunCompute(app, "main", "calculate", nil, 0); err != nil || got != int64(2) {
		t.Fatalf("retarget %v %v", got, err)
	}
}
