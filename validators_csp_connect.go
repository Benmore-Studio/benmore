//go:build !cli

package main

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// A ws:// or wss:// URL with a literal host in app source. A computed host
// (`wss://${location.host}/ws`, "wss://" + host) has no literal and is not
// matched; neither is a single-label name such as localhost.
var webSocketLiteralRe = regexp.MustCompile(`\b(wss?)://([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)(?::[0-9]{1,5})?`)

// connectSrcWebSocketWarnings flags a WebSocket URL in static/ whose host the
// page's connect-src does not allow. The default policy allows the app's own
// origin only (it used to allow `wss: ws:`, any host), so such a socket is
// blocked in the browser while every server-side check passes. Each finding
// names the file and line, the host and the app.yaml line that allows it.
func connectSrcWebSocketWarnings(dir string) []CheckFinding {
	var declared []string
	if design := LoadAppConfigYAML(dir); design != nil {
		for _, v := range []string{design.CSP["connect_src"], design.SEO["connect_src"]} {
			declared = append(declared, strings.Fields(v)...)
		}
	}
	type hit struct {
		file, origin string
		line         int
	}
	var hits []hit
	seen := map[string]bool{}
	root := filepath.Join(dir, "static")
	_ = filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if d.Name() == "node_modules" || strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".ts", ".tsx", ".js", ".jsx", ".mjs", ".html":
		default:
			return nil
		}
		if info, err := d.Info(); err != nil || info.Size() > 2<<20 {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(dir, path)
		rel = filepath.ToSlash(rel)
		for i, line := range bytes.Split(data, []byte("\n")) {
			for _, m := range webSocketLiteralRe.FindAllSubmatch(line, -1) {
				origin := strings.ToLower(string(m[1]) + "://" + string(m[2]))
				if seen[rel+" "+origin] || connectSrcAllowsWebSocket(declared, string(m[1]), strings.ToLower(string(m[2]))) {
					continue
				}
				seen[rel+" "+origin] = true
				hits = append(hits, hit{rel, origin, i + 1})
			}
		}
		return nil
	})
	if len(hits) == 0 {
		return nil
	}
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].file != hits[j].file {
			return hits[i].file < hits[j].file
		}
		return hits[i].line < hits[j].line
	})
	// One app.yaml line allows every origin found, kept with what is declared.
	value := strings.Join(declared, " ")
	added := map[string]bool{}
	for _, h := range hits {
		if !added[h.origin] {
			added[h.origin] = true
			value = strings.TrimSpace(value + " " + h.origin)
		}
	}
	var findings []CheckFinding
	for i, h := range hits {
		if i == 10 {
			break
		}
		findings = append(findings, CheckFinding{Severity: "warning", Source: "security", File: h.file,
			Message: fmt.Sprintf("%s:%d opens a WebSocket to %s, which the page's Content-Security-Policy blocks: connect-src allows the app's own origin and csp.connect_src only. If the app needs it, add to app.yaml:\n  csp:\n    connect_src: %q",
				h.file, h.line, h.origin, value)})
	}
	return findings
}

// connectSrcAllowsWebSocket reports whether a declared connect-src source
// list allows a WebSocket to scheme://host, by CSP Level 3 scheme matching: a
// `wss:` source allows wss, a `ws:` source allows ws and wss, and a host
// source needs a ws or wss scheme by the same rule and a matching host (`*.x`
// covers subdomains of x). An https:// or scheme-less source does not allow a
// WebSocket from an HTTPS page, so it does not count.
func connectSrcAllowsWebSocket(declared []string, scheme, host string) bool {
	schemeAllows := func(src string) bool { return src == scheme || (src == "ws" && scheme == "wss") }
	for _, src := range declared {
		src = strings.ToLower(strings.Trim(src, "'\""))
		if strings.HasSuffix(src, ":") && !strings.Contains(src, "/") {
			if schemeAllows(strings.TrimSuffix(src, ":")) {
				return true
			}
			continue
		}
		srcScheme, rest, ok := strings.Cut(src, "://")
		if !ok || !schemeAllows(srcScheme) {
			continue
		}
		if i := strings.IndexAny(rest, "/:"); i >= 0 {
			rest = rest[:i]
		}
		if rest == host || (strings.HasPrefix(rest, "*.") && strings.HasSuffix(host, rest[1:])) {
			return true
		}
	}
	return false
}
