//go:build !cli

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	esbuild "github.com/benmore-studio/benmore/third_party/esbuild/pkg/api"
)

// maxScriptSyntaxCheckBytes bounds the write-time parse. Larger files (a
// generated or vendored bundle: Expo builds run 1-2 MB per file) are left to
// the compiler; transforming hundreds of them made a full check slow and
// memory-hungry.
const maxScriptSyntaxCheckBytes = 1 << 20

var scriptSyntaxLoaders = map[string]esbuild.Loader{
	".ts":  esbuild.LoaderTS,
	".mts": esbuild.LoaderTS,
	".cts": esbuild.LoaderTS,
	".tsx": esbuild.LoaderTSX,
	".jsx": esbuild.LoaderJSX,
	".js":  esbuild.LoaderJS,
	".mjs": esbuild.LoaderJS,
	".cjs": esbuild.LoaderJS,
}

// validateScriptSyntax parses a script under static/ or src/ - the files the
// framework compiles for the browser (/static/*.js) and for `run: compute` -
// and refuses one esbuild cannot parse. A push used to accept them: a syntax
// error (a duplicate `const`, an unclosed brace) surfaced only when the page
// loaded or a flow ran the compute step. Parse only: imports are not
// resolved and no file is read, so it is safe in the router.
func validateScriptSyntax(path, content string) string {
	clean := filepath.ToSlash(path)
	if !strings.HasPrefix(clean, "static/") && !strings.HasPrefix(clean, "src/") {
		return ""
	}
	// Type declarations (src/bm.d.ts) are read by editors, never compiled.
	if lower := strings.ToLower(clean); strings.HasSuffix(lower, ".d.ts") || strings.HasSuffix(lower, ".d.mts") || strings.HasSuffix(lower, ".d.cts") {
		return ""
	}
	loader, ok := scriptSyntaxLoaders[strings.ToLower(filepath.Ext(clean))]
	if !ok || len(content) > maxScriptSyntaxCheckBytes {
		return ""
	}
	result := esbuild.Transform(content, esbuild.TransformOptions{
		Loader:     loader,
		Sourcefile: clean,
		LogLevel:   esbuild.LogLevelSilent,
	})
	if len(result.Errors) == 0 {
		return ""
	}
	var lines []string
	for i, msg := range result.Errors {
		if i == 5 {
			lines = append(lines, fmt.Sprintf("  ... and %d more", len(result.Errors)-i))
			break
		}
		where := clean
		if msg.Location != nil {
			where = fmt.Sprintf("%s:%d:%d", clean, msg.Location.Line, msg.Location.Column+1)
		}
		lines = append(lines, fmt.Sprintf("  %s: %s", where, msg.Text))
	}
	return fmt.Sprintf("%s does not parse, so it would fail when the page loads or the compute step runs:\n%s\nFix the syntax and write it again.", clean, strings.Join(lines, "\n"))
}
