package main

// A .gitignore matcher for an app workspace, written here because the CLI
// cannot rely on git being installed. gitignoreMatcher is ONE parsed
// .gitignore and answers "would git leave this path out?" for slash paths
// relative to the directory that holds it; workspaceGitignores (below) puts
// the root file and the nested ones together the way git does.
//
// Understood: blank lines, `#` comments, `*`, `?`, `**` as a whole path
// segment (`**/x`, `x/**`, `a/**/b`), a leading `/` (and any other inner `/`)
// anchoring the pattern to the root, a trailing `/` for directories only, `!`
// negation, last matching line wins, and git's rule that nothing below an
// excluded directory can be re-included.
//
// Not understood: a pattern holding a backslash escape or a `[...]` character
// class, or an empty path segment (`a//b`). Such a line never excludes
// anything; when it is a negation it re-includes everything, because the paths
// it would have re-included are unknown. Either way the matcher errs towards
// "not ignored", so a caller that warns about ignored files never warns
// because of a line it could not read. Matching is case-sensitive and works on
// bytes, as git's does by default.

import (
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
)

// workspaceGitignoreMaxBytes bounds the .gitignore loadWorkspaceGitignore
// reads; a larger file is treated as absent.
const workspaceGitignoreMaxBytes = 1 << 20

// loadWorkspaceGitignore parses the .gitignore at the root of a workspace. It
// returns nil when there is none, or when it is not a regular file, cannot be
// read or is larger than workspaceGitignoreMaxBytes. A nil matcher ignores
// nothing.
func loadWorkspaceGitignore(root string) *gitignoreMatcher {
	name := filepath.Join(root, ".gitignore")
	info, err := os.Lstat(name)
	if err != nil || !info.Mode().IsRegular() {
		return nil
	}
	f, err := os.Open(name)
	if err != nil {
		return nil
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, workspaceGitignoreMaxBytes+1))
	if err != nil || len(data) > workspaceGitignoreMaxBytes {
		return nil
	}
	return parseGitignore(string(data))
}

// gitignoreRule is one pattern line of a .gitignore.
type gitignoreRule struct {
	Line    int    // 1-based line number in the file
	Pattern string // the line as written, without trailing spaces
	Negate  bool   // a `!` line: re-includes what it matches

	dirOnly     bool     // trailing `/`: matches directories only
	anchored    bool     // holds a `/` before its end: matched from the root
	segs        []string // the pattern split on `/`; "**" spans directories
	unsupported bool
}

// gitignoreMatcher is a parsed .gitignore.
type gitignoreMatcher struct {
	rules []gitignoreRule
}

// parseGitignore parses the content of a .gitignore. It never fails: a line it
// does not understand is kept as an unsupported rule (see the file comment).
func parseGitignore(content string) *gitignoreMatcher {
	m := &gitignoreMatcher{}
	content = strings.TrimPrefix(content, "\ufeff")
	for i, line := range strings.Split(content, "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rule := gitignoreRule{Line: i + 1}
		if strings.ContainsAny(line, `\[`) {
			rule.Pattern = line
			rule.Negate = strings.HasPrefix(line, "!")
			rule.unsupported = true
			m.rules = append(m.rules, rule)
			continue
		}
		line = strings.TrimRight(line, " ")
		rule.Pattern = line
		if strings.HasPrefix(line, "!") {
			rule.Negate = true
			line = line[1:]
		}
		if strings.HasSuffix(line, "/") {
			rule.dirOnly = true
			line = line[:len(line)-1]
		}
		rule.anchored = strings.Contains(line, "/")
		line = strings.TrimPrefix(line, "/")
		if line == "" {
			continue
		}
		for _, seg := range strings.Split(line, "/") {
			if seg == "" {
				rule.unsupported = true
				break
			}
			if seg == "**" && rule.anchored {
				// Two spans in a row match what one does.
				if n := len(rule.segs); n > 0 && rule.segs[n-1] == "**" {
					continue
				}
				rule.segs = append(rule.segs, seg)
				continue
			}
			// Asterisks that are not a whole segment of an anchored pattern
			// are ordinary ones.
			for strings.Contains(seg, "**") {
				seg = strings.ReplaceAll(seg, "**", "*")
			}
			rule.segs = append(rule.segs, seg)
		}
		m.rules = append(m.rules, rule)
	}
	return m
}

// Ignored reports whether git would leave rel out: a slash path relative to
// the directory holding the .gitignore, a directory when isDir.
func (m *gitignoreMatcher) Ignored(rel string, isDir bool) bool {
	return m.Match(rel, isDir) != nil
}

// Match returns the rule that excludes rel, or nil when rel is not ignored.
// For a path below an excluded directory it is the rule excluding that
// directory.
func (m *gitignoreMatcher) Match(rel string, isDir bool) *gitignoreRule {
	if m == nil || len(m.rules) == 0 {
		return nil
	}
	rel = strings.Trim(strings.TrimPrefix(rel, "./"), "/")
	if rel == "" || rel == "." {
		return nil
	}
	segs := strings.Split(rel, "/")
	for i := 1; i <= len(segs); i++ {
		dir := isDir || i < len(segs)
		rule := m.decide(segs[:i], dir)
		if rule != nil && !rule.Negate {
			return rule
		}
	}
	return nil
}

// decide returns the last rule matching the path, whichever way it decides.
func (m *gitignoreMatcher) decide(segs []string, isDir bool) *gitignoreRule {
	for i := len(m.rules) - 1; i >= 0; i-- {
		rule := &m.rules[i]
		if rule.unsupported {
			if rule.Negate {
				return rule
			}
			continue
		}
		if rule.dirOnly && !isDir {
			continue
		}
		if !rule.anchored {
			if gitignoreGlob(rule.segs[0], segs[len(segs)-1]) {
				return rule
			}
			continue
		}
		if gitignoreSegsMatch(rule.segs, segs) {
			return rule
		}
	}
	return nil
}

// gitignoreSegsMatch matches an anchored pattern, segment by segment. "**"
// spans zero or more directories, except as the last segment, where it stands
// for everything inside (at least one name).
func gitignoreSegsMatch(pat, segs []string) bool {
	// next[j] is "pat[i+1:] matches segs[j:]", cur[j] the same for pat[i:].
	next := make([]bool, len(segs)+1)
	cur := make([]bool, len(segs)+1)
	next[len(segs)] = true
	for i := len(pat) - 1; i >= 0; i-- {
		for j := len(segs); j >= 0; j-- {
			switch {
			case pat[i] == "**" && i == len(pat)-1:
				cur[j] = j < len(segs)
			case pat[i] == "**":
				cur[j] = next[j] || j < len(segs) && cur[j+1]
			default:
				cur[j] = j < len(segs) && next[j+1] && gitignoreGlob(pat[i], segs[j])
			}
		}
		next, cur = cur, next
	}
	return next[0]
}

// gitignoreGlob matches one path segment against a pattern segment: `*` is
// any run of bytes (also none), `?` any one byte.
func gitignoreGlob(pattern, name string) bool {
	p, n := 0, 0
	star, mark := -1, 0
	for n < len(name) {
		switch {
		case p < len(pattern) && pattern[p] == '*':
			star, mark = p, n
			p++
		case p < len(pattern) && (pattern[p] == '?' || pattern[p] == name[n]):
			p++
			n++
		case star >= 0:
			mark++
			p, n = star+1, mark
		default:
			return false
		}
	}
	for p < len(pattern) && pattern[p] == '*' {
		p++
	}
	return p == len(pattern)
}

// workspaceGitignores answers "would git leave this path out?" for a whole
// workspace: the root .gitignore and the .gitignore of every directory on the
// way down to the path, as git reads them. A deeper file decides before a
// shallower one, its patterns are relative to its own directory, and nothing
// below an excluded directory is consulted (git does not read a .gitignore
// there, so it cannot re-include anything). Files are read on first use.
//
// Not read: .git/info/exclude, a global excludes file, and a .gitignore below
// a symbolic link (git does not follow one).
type workspaceGitignores struct {
	root  string
	byDir map[string]*gitignoreMatcher // by slash path from root, "" for the root; nil when there is none
	plain map[string]bool              // whether a directory is one all the way down from the root (no link)
}

func newWorkspaceGitignores(root string) *workspaceGitignores {
	return &workspaceGitignores{root: root, byDir: map[string]*gitignoreMatcher{}, plain: map[string]bool{}}
}

// matcher returns the parsed .gitignore of dir, or nil when dir has none or
// is reached through a symbolic link.
func (w *workspaceGitignores) matcher(dir string) *gitignoreMatcher {
	if m, seen := w.byDir[dir]; seen {
		return m
	}
	var m *gitignoreMatcher
	if w.plainDir(dir) {
		m = loadWorkspaceGitignore(filepath.Join(w.root, filepath.FromSlash(dir)))
	}
	w.byDir[dir] = m
	return m
}

// plainDir reports whether dir and every directory above it, up to the root,
// is a directory and not a link to one.
func (w *workspaceGitignores) plainDir(dir string) bool {
	if dir == "" || dir == "." {
		return true
	}
	if plain, seen := w.plain[dir]; seen {
		return plain
	}
	plain := w.plainDir(path.Dir(dir))
	if plain {
		info, err := os.Lstat(filepath.Join(w.root, filepath.FromSlash(dir)))
		plain = err == nil && info.IsDir()
	}
	w.plain[dir] = plain
	return plain
}

// Ignored reports whether git would leave rel out: a slash path relative to
// the workspace root, a directory when isDir.
func (w *workspaceGitignores) Ignored(rel string, isDir bool) bool {
	rel = strings.Trim(strings.TrimPrefix(rel, "./"), "/")
	if rel == "" || rel == "." {
		return false
	}
	segs := strings.Split(rel, "/")
	// Each directory on the way down, then the path itself: the first one
	// that is excluded excludes everything below it.
	for i := 1; i <= len(segs); i++ {
		dir := isDir || i < len(segs)
		// The .gitignore next to this entry first, then each one above it;
		// the first file with a matching line decides.
		for d := i - 1; d >= 0; d-- {
			m := w.matcher(strings.Join(segs[:d], "/"))
			if m == nil || len(m.rules) == 0 {
				continue
			}
			rule := m.decide(segs[d:i], dir)
			if rule == nil {
				continue
			}
			if !rule.Negate {
				return true
			}
			break
		}
	}
	return false
}

// workspaceIgnoredFiles returns, sorted, the files among rels (slash paths
// relative to root) that the workspace's .gitignore files exclude.
func workspaceIgnoredFiles(root string, rels []string) []string {
	ignores := newWorkspaceGitignores(root)
	var ignored []string
	for _, rel := range rels {
		if ignores.Ignored(rel, false) {
			ignored = append(ignored, rel)
		}
	}
	sort.Strings(ignored)
	return ignored
}
