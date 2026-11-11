//go:build !cli

package main

// Write-time and check-time checks of <include> tags.
//
// The runtime expands `<include src="..." />` (includeTagRe, template.go) in
// HTML-stack pages under static/ (relative to static/), in root mustache
// pages, layouts/ and partials/kit.html (relative to the app). A tag whose
// target was missing passed push and `benmore check` and rendered, at view
// time, a visitor-visible `Include error: ... not found`; a tag written any
// other way (no `/>`, single quotes, another attribute) was left in the page
// unexpanded, with no error anywhere (round 2026-11-05).
//
// The write gate and `benmore check` now refuse, in a file whose includes the
// runtime expands: a tag of another shape, a src that leaves its directory,
// and a target that does not exist. A batch write that defers its reload
// (deploy, a multi-file push) can be followed by the partial it names, so
// there a missing target is left to the post-write check and the CLI's check
// when the batch ends. delete_file refuses removing a partial a page still
// includes. Pages are not changed: an existing tag renders as before.
//
// Measured before shipping (fleet snapshot 2026-11-05, 289 instances): 2,022
// include tags in 234 instances, every one in the self-closing double-quoted
// form and every target present.

import (
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

var (
	// includeAnyTagRe finds every <include> start tag, whatever its shape.
	includeAnyTagRe = regexp.MustCompile(`(?i)<include\b[^>]*>`)
	// includeSrcAttrRe reads a src attribute in either quote style, for the
	// corrected tag a refusal suggests.
	includeSrcAttrRe = regexp.MustCompile(`(?i)\bsrc\s*=\s*(?:"([^"]*)"|'([^']*)'|([^\s>/]+))`)
	includeCommentRe = regexp.MustCompile(`(?s)<!--.*?-->`)
)

// includeBase reports whether the runtime expands <include> tags in rel and
// the app-relative directory their src resolves in ("static" or "").
func includeBase(rel, content string) (base string, expands bool) {
	rel = filepath.ToSlash(filepath.Clean(rel))
	if !strings.EqualFold(path.Ext(rel), ".html") || pathHasMetadataSidecar(rel) {
		return "", false
	}
	switch {
	case strings.HasPrefix(rel, "static/"):
		return "static", true
	case rel == "partials/kit.html" || strings.HasPrefix(rel, "layouts/"):
		return "", true
	case !strings.Contains(rel, "/") && strings.HasSuffix(rel, ".html") && rel != "head.html":
		// gotmpl and raw pages render their body without the include pass.
		if fm, _, err := ExtractFrontmatter(content); err == nil && fm != nil && (fm.Engine == "gotmpl" || fm.Engine == "raw") {
			return "", false
		}
		return "", true
	}
	return "", false
}

// includeProblems are rel's <include> tags the runtime would not expand as
// written. shape: tags it does not expand at all, or whose src leaves the
// directory; missing: tags naming a file that is not there (gone, when set,
// is an app-relative file counted as absent).
func includeProblems(appDir, rel, content, gone string) (shape, missing []string) {
	base, expands := includeBase(rel, content)
	if !expands {
		return nil, nil
	}
	body := includeCommentRe.ReplaceAllString(content, "")
	var root *os.Root
	if appDir != "" {
		if r, err := os.OpenRoot(appDir); err == nil {
			root = r
			defer root.Close()
		}
	}
	for _, tag := range includeAnyTagRe.FindAllString(body, -1) {
		m := includeTagRe.FindStringSubmatch(tag)
		if m == nil || m[0] != tag {
			fix := `<include src="..." />`
			if a := includeSrcAttrRe.FindStringSubmatch(tag); a != nil {
				fix = `<include src="` + a[1] + a[2] + a[3] + `" />`
			}
			shape = append(shape, fmt.Sprintf("%s is not expanded (the tag must be exactly %s: self-closing, src in double quotes, no other attributes)", tag, fix))
			continue
		}
		src := m[1]
		if strings.HasPrefix(src, "/") || strings.Contains(src, `\`) {
			shape = append(shape, fmt.Sprintf("%s: src must be a relative path with / separators, such as partials/nav.html", tag))
			continue
		}
		target := path.Clean(path.Join(base, src))
		if target == ".." || strings.HasPrefix(target, "../") || base != "" && target != base && !strings.HasPrefix(target, base+"/") {
			dir := base + "/"
			if base == "" {
				dir = "the app directory"
			}
			shape = append(shape, fmt.Sprintf("%s names a file outside %s, which is never included", tag, dir))
			continue
		}
		if root != nil && !includeTargetExists(root, base, src, gone) {
			what := target + " does not exist"
			if base == "static" && includeRootPartial(src) {
				what = "neither " + target + " nor " + src + " exists"
			}
			missing = append(missing, fmt.Sprintf("%s: %s, so the page would show \"Include error: %s not found\"", tag, what, src))
		}
	}
	return shape, missing
}

// includeRootPartial reports whether src names a partial the app loads at
// start (partials/<name>.html), which every include context checks first.
func includeRootPartial(src string) bool {
	name, ok := strings.CutPrefix(src, "partials/")
	return ok && !strings.Contains(name, "/") && strings.HasSuffix(name, ".html") && !isMetadataSidecar(name)
}

// includeTargetExists resolves src as the runtime does: a loaded root
// partial first, then the file under base, read through the app's root.
func includeTargetExists(root *os.Root, base, src, gone string) bool {
	regular := func(rel string) bool {
		if rel == gone {
			return false
		}
		info, err := root.Stat(filepath.FromSlash(rel))
		return err == nil && info.Mode().IsRegular()
	}
	if includeRootPartial(src) && regular(src) {
		return true
	}
	return regular(path.Clean(path.Join(base, src)))
}

// includeWriteRefusal is the write gate's <include> check of a write of
// content to rel. deferred: the write defers its reload to later files of
// its batch, one of which may be the missing partial.
func includeWriteRefusal(appDir, rel, content string, deferred bool) string {
	shape, missing := includeProblems(appDir, rel, content, "")
	if deferred {
		missing = nil
	}
	problems := append(shape, missing...)
	if len(problems) == 0 {
		return ""
	}
	rel = filepath.ToSlash(rel)
	var b strings.Builder
	fmt.Fprintf(&b, "%s has <include> tags the server would not expand:\n", rel)
	for _, p := range problems {
		fmt.Fprintf(&b, "  %s\n", p)
	}
	if len(missing) > 0 {
		b.WriteString("Push the partial first, then this file. ")
	}
	b.WriteString("Fix the tags and write the file again.")
	return b.String()
}

// includeContextFiles lists the app-relative HTML files whose includes the
// runtime expands: static/**.html, root pages, layouts/**.html and
// partials/kit.html.
func includeContextFiles(appDir string) []string {
	root, err := os.OpenRoot(appDir)
	if err != nil {
		return nil
	}
	defer root.Close()
	var out []string
	if entries, err := fs.ReadDir(root.FS(), "."); err == nil {
		for _, e := range entries {
			if e.Type().IsRegular() && strings.HasSuffix(e.Name(), ".html") {
				out = append(out, e.Name())
			}
		}
	}
	if info, err := root.Lstat(filepath.Join("partials", "kit.html")); err == nil && info.Mode().IsRegular() {
		out = append(out, "partials/kit.html")
	}
	for _, dir := range []string{"static", "layouts"} {
		_ = fs.WalkDir(root.FS(), dir, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if p == dir {
					return fs.SkipAll
				}
				return nil
			}
			if d.Type().IsRegular() && strings.EqualFold(path.Ext(p), ".html") {
				out = append(out, p)
			}
			return nil
		})
	}
	sort.Strings(out)
	return out
}

// readIncludeContextFile reads an app-relative HTML file for the check.
func readIncludeContextFile(appDir, rel string) (string, bool) {
	root, err := os.OpenRoot(appDir)
	if err != nil {
		return "", false
	}
	defer root.Close()
	data, err := readBundleSource(root, rel, 4<<20)
	if err != nil {
		return "", false
	}
	return string(data), true
}

// includeCheckFindings reports <include> problems as errors: in every file
// whose includes the runtime expands (writtenPath "", a full check), or in
// the written file.
func includeCheckFindings(dir, writtenPath string) []CheckFinding {
	var files []string
	if writtenPath == "" {
		files = includeContextFiles(dir)
	} else if _, expands := includeBase(writtenPath, ""); expands {
		files = []string{filepath.ToSlash(filepath.Clean(writtenPath))}
	}
	var findings []CheckFinding
	for _, rel := range files {
		content, ok := readIncludeContextFile(dir, rel)
		if !ok {
			continue
		}
		shape, missing := includeProblems(dir, rel, content, "")
		problems := append(shape, missing...)
		if len(problems) == 0 {
			continue
		}
		findings = append(findings, CheckFinding{Severity: "error", Source: "include", File: rel,
			Message: "<include> tags the server would not expand:\n  " + strings.Join(problems, "\n  ")})
	}
	return findings
}

// includeDeleteRefusal refuses removing rel while a page still includes it
// and no other file would take its place.
func includeDeleteRefusal(appDir, rel string) string {
	rel = filepath.ToSlash(filepath.Clean(rel))
	if appDir == "" || !strings.EqualFold(path.Ext(rel), ".html") {
		return ""
	}
	var broken []string
	for _, page := range includeContextFiles(appDir) {
		if page == rel {
			continue
		}
		content, ok := readIncludeContextFile(appDir, page)
		if !ok || !strings.Contains(content, "<include") {
			continue
		}
		_, before := includeProblems(appDir, page, content, "")
		_, after := includeProblems(appDir, page, content, rel)
		if len(after) > len(before) {
			broken = append(broken, page)
		}
	}
	if len(broken) == 0 {
		return ""
	}
	return fmt.Sprintf("refusing to delete %s: %s still include it, and would show \"Include error: ... not found\" to visitors. Remove those <include> tags first (push the pages), then delete it.", rel, strings.Join(broken, ", "))
}
