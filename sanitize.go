//go:build !cli

package main

import (
	"strings"
	"sync"

	"github.com/microcosm-cc/bluemonday"
)

// HTML sanitizer for {{{raw}}} output.
//
// Backed by bluemonday's UGCPolicy — the standard Go HTML sanitizer used
// in production by web stacks across the ecosystem. It's a real
// DOM-aware parser rather than a regex stack, so the bypass classes we
// patched in the previous regex implementation (nested-tag reformation,
// `<img/onerror=...>` slash separators, HTML-entity-encoded
// `java&Tab;script:` URLs, etc.) are not reachable.
//
// For truly raw output, use {{{{raw}}}} (quadruple braces) which skips
// this function entirely — that's the explicit opt-in for cases where
// the developer has already validated the content themselves.

var (
	htmlSanitizer     *bluemonday.Policy
	htmlSanitizerOnce sync.Once
)

func getHTMLSanitizer() *bluemonday.Policy {
	htmlSanitizerOnce.Do(func() {
		p := bluemonday.UGCPolicy()
		// UGCPolicy already covers the common safe tags + attributes
		// (anchors, headings, code, lists, tables, blockquotes, images,
		// etc.) and strips scripts, iframes, event handlers, javascript:
		// URLs, data: URIs in src, CSS expressions, and so on. The
		// adjustments below pull a few attributes UGC normally drops
		// that the framework's templates rely on.
		p.AllowAttrs("class", "id", "style").Globally()
		// Common formatting tags some UGC policies omit by default.
		p.AllowElements("section", "article", "aside", "header", "footer", "main", "nav", "figure", "figcaption")
		// Image attributes — UGC allows <img> but not all the responsive-image
		// attributes some apps include in their markdown output.
		p.AllowAttrs("loading", "decoding", "srcset", "sizes").OnElements("img")
		// Anchor target/rel — UGCPolicy auto-adds rel="nofollow" on links,
		// which is the right default for user-supplied content.
		p.AllowAttrs("target").OnElements("a")
		htmlSanitizer = p
	})
	return htmlSanitizer
}

// SanitizeHTML strips dangerous elements from HTML while preserving safe
// formatting. Used for {{{ triple brace }}} output in the SSR/gotmpl
// template engine. Pass user-supplied HTML through this when you want
// to allow formatting but not script execution.
func SanitizeHTML(input string) string {
	return getHTMLSanitizer().Sanitize(input)
}

// IsUnsafeRaw checks if content contains patterns that would be dangerous
// even after sanitization. Used by the audit command to flag potential
// issues — kept as a fast pre-flight heuristic for static analysis,
// distinct from the runtime sanitization above.
func IsUnsafeRaw(content string) bool {
	lower := strings.ToLower(content)
	return strings.Contains(lower, "<script") ||
		strings.Contains(lower, "<svg") ||
		strings.Contains(lower, "<math") ||
		strings.Contains(lower, "javascript:") ||
		strings.Contains(lower, "onerror=") ||
		strings.Contains(lower, "onload=")
}
