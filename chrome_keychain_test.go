//go:build !cli

package main

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

// Every Chrome the framework starts carries the keychain-free flags, so a
// private profile can't send macOS SecurityAgent looking for a keychain.
func TestChromeLaunchesCarryKeychainFreeFlags(t *testing.T) {
	args := pdfChromeArgs("127.0.0.1:1", "http://127.0.0.1:1/doc", "/tmp/out.pdf", "/tmp/profile")
	for _, flag := range chromeKeychainFreeArgs {
		if !slices.Contains(args, flag) {
			t.Errorf("PDF render args lack %s: %v", flag, args)
		}
	}
	home := slices.ContainsFunc(browserChromeEnv("/tmp/profile"), func(e string) bool { return strings.HasPrefix(e, "HOME=") })
	if home == chromeKeepsHome() {
		t.Errorf("browser env HOME override=%v on %s", home, runtime.GOOS)
	}
}

// A fake browser that records how it was started: on macOS the version comes
// from the bundle and the executable never runs; elsewhere it runs with the
// keychain-free flags.
func TestChromeVersionProbeNeverPromptsForKeychain(t *testing.T) {
	bundle := filepath.Join(t.TempDir(), "Fake Browser.app", "Contents")
	if err := os.MkdirAll(filepath.Join(bundle, "MacOS"), 0o755); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(t.TempDir(), "ran")
	exe := filepath.Join(bundle, "MacOS", "Fake Browser")
	script := "#!/bin/sh\necho \"$@\" > '" + marker + "'\necho 'Fake Browser 1.2.3'\n"
	if err := os.WriteFile(exe, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	plist := `<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0"><dict>
<key>CFBundleName</key><string>Fake</string>
<key>CFBundleDisplayName</key><string>Fake Browser</string>
<key>Nested</key><dict><key>CFBundleShortVersionString</key><string>9.9.9</string></dict>
<key>CFBundleShortVersionString</key><string>1.2.3</string>
</dict></plist>`
	if err := os.WriteFile(filepath.Join(bundle, "Info.plist"), []byte(plist), 0o644); err != nil {
		t.Fatal(err)
	}
	version, err := appMCPProbeArtifactChromeVersion(context.Background(), exe)
	if err != nil || version != "Fake Browser 1.2.3" {
		t.Fatalf("version = %q, %v", version, err)
	}
	ran, err := os.ReadFile(marker)
	if chromeKeepsHome() {
		if err == nil {
			t.Fatalf("macOS probe started the browser: %q", ran)
		}
		return
	}
	for _, flag := range append([]string{"--version"}, chromeKeychainFreeArgs...) {
		if !strings.Contains(string(ran), flag) {
			t.Errorf("probe ran without %s: %q", flag, ran)
		}
	}
}

// Tests start Chrome too, and a test run on a developer Mac is where the
// keychain reset was seen. Every exec of a Chrome binary in this package,
// tests included, passes the keychain-free flags (directly or through
// pdfChromeArgs).
func TestEveryChromeExecCarriesKeychainFreeFlags(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	checked := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			src, err := os.ReadFile(name)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				if pkgIdent, isIdent := sel.X.(*ast.Ident); !isIdent || pkgIdent.Name != "exec" || (sel.Sel.Name != "Command" && sel.Sel.Name != "CommandContext") {
					return true
				}
				program := 0
				if sel.Sel.Name == "CommandContext" {
					program = 1
				}
				if len(call.Args) <= program {
					return true
				}
				if ident, ok := call.Args[program].(*ast.Ident); !ok || !strings.Contains(strings.ToLower(ident.Name), "chrome") {
					return true
				}
				checked++
				args := string(src[fset.Position(call.Args[program].End()).Offset:fset.Position(call.End()).Offset])
				if !strings.Contains(args, "chromeKeychainFreeArgs") && !strings.Contains(args, "pdfChromeArgs(") {
					// A slice built earlier names the flags where it is built.
					if ident, ok := call.Args[len(call.Args)-1].(*ast.Ident); !ok || call.Ellipsis == token.NoPos || !chromeArgsSliceCarriesFlags(file, src, fset, ident.Name) {
						t.Errorf("%s: Chrome started without chromeKeychainFreeArgs", fset.Position(call.Pos()))
					}
				}
				return true
			})
		}
	}
	if checked == 0 {
		t.Fatal("found no Chrome exec to check")
	}
}

// chromeArgsSliceCarriesFlags reports whether name is assigned in file from an
// expression that names chromeKeychainFreeArgs or pdfChromeArgs.
func chromeArgsSliceCarriesFlags(file *ast.File, src []byte, fset *token.FileSet, name string) bool {
	found := false
	ast.Inspect(file, func(n ast.Node) bool {
		assign, ok := n.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != len(assign.Rhs) {
			return true
		}
		for i, lhs := range assign.Lhs {
			if ident, ok := lhs.(*ast.Ident); ok && ident.Name == name {
				rhs := string(src[fset.Position(assign.Rhs[i].Pos()).Offset:fset.Position(assign.Rhs[i].End()).Offset])
				if strings.Contains(rhs, "chromeKeychainFreeArgs") || strings.Contains(rhs, "pdfChromeArgs(") {
					found = true
				}
			}
		}
		return true
	})
	return found
}
