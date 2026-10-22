package main

// Paths `benmore pull` never writes into a developer's workspace. Shared by
// the CLI (pull, sync-status), the platform (pull archive, manifest) and the
// MCP review digest, so every side agrees on the same set.

import (
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// pullDeniedSegments are directory names whose contents are workspace
// auto-exec configuration (editor tasks, agent hooks, MCP servers, git hooks).
// Any file a collaborator could plant there would run on the puller's machine
// the next time they open the workspace.
var pullDeniedSegments = map[string]bool{
	".vscode": true, ".idea": true, ".claude": true, ".codex": true, ".agents": true, ".git": true,
	".cursor": true, ".gemini": true, ".zed": true, ".devcontainer": true,
}

// pullAllowedDotDirs are the only hidden directories pull writes outside
// static/: served /.well-known content and repository CI config, neither of
// which runs on the puller's machine. Every other hidden directory is refused,
// because each new editor or agent keeps its auto-run project config (hooks,
// MCP servers, plugins, language-server commands) in one, and a fixed list
// always lags. Hidden directories below static/ are served app content, so
// they still pull (the named config directories above are refused there too).
var pullAllowedDotDirs = map[string]bool{".well-known": true, ".github": true}

// pullDeniedFiles are auto-exec config files that live outside a hidden
// directory: project MCP servers, direnv/mise environments, a root
// devcontainer (initializeCommand runs on the host), agent and editor
// project config that starts commands.
var pullDeniedFiles = map[string]bool{
	".mcp.json": true, ".envrc": true, ".devcontainer.json": true,
	"opencode.json": true, "opencode.jsonc": true, "crush.json": true, ".crush.json": true,
	".aider.conf.yml": true, ".nvim.lua": true, ".nvimrc": true, ".exrc": true, ".lazy.lua": true,
	"mise.toml": true, ".mise.toml": true, "mise.local.toml": true, ".mise.local.toml": true,
}

// pullDeniedPath reports whether an archive path is workspace auto-exec config
// at any depth (case-insensitive: macOS and Windows checkouts fold case).
var pullShortNameRe = regexp.MustCompile(`~[0-9]+$`)

// pullFoldName canonicalizes an archive path the way the developer's file
// system may compare names: case-folded with Unicode folding (APFS treats
// U+017F LONG S as "s" and the Kelvin sign as "k") and without the code
// points HFS+ ignores (zero-width joiners, direction marks, BOM), so
// ".mcp.j<U+200C>son" cannot reach .mcp.json.
func pullFoldName(name string) string {
	var b strings.Builder
	for _, r := range strings.ReplaceAll(filepath.ToSlash(name), "\\", "/") {
		switch {
		case r >= 0x200c && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x206a && r <= 0x206f, r == 0xfeff:
			continue
		}
		folded := unicode.ToLower(r)
		for f := unicode.SimpleFold(r); f != r; f = unicode.SimpleFold(f) {
			if f < utf8.RuneSelf {
				folded = unicode.ToLower(f)
				break
			}
		}
		b.WriteRune(folded)
	}
	return b.String()
}

func pullDeniedPath(name string) bool {
	norm := pullFoldName(name)
	// Judge the path as written and as it resolves: "mise.toml/." names
	// mise.toml, and "static/../.sdd/x" leaves the served tree.
	return pullDeniedFolded(norm, true) || pullDeniedFolded(cleanFoldedPath(norm), true)
}

// workspaceAutoRunPath reports whether rel (a file, or a directory when
// isDir) is editor/agent auto-run configuration outside static/: a directory
// or file pull refuses by name (.vscode/, .claude/, .mcp.json, .envrc,
// *.code-workspace, ...) or a Windows alias for one. Unlike pullDeniedPath it
// does not cover other hidden directories, which hosted apps keep accepting
// (agent working directories such as .sdd/). Hosted write tools refuse these
// paths, and the MCP execution digest leaves them out.
func workspaceAutoRunPath(rel string, isDir bool) bool {
	norm := pullFoldName(rel)
	if isDir {
		norm += "/x"
	}
	for _, p := range []string{norm, cleanFoldedPath(norm)} {
		segs := strings.Split(strings.TrimPrefix(p, "./"), "/")
		if len(segs) > 1 && segs[0] == "static" {
			continue
		}
		if pullDeniedFolded(p, false) {
			return true
		}
	}
	return false
}

// cleanFoldedPath removes dot segments from a folded slash path, the way a
// file system resolves it.
func cleanFoldedPath(norm string) string {
	return strings.TrimPrefix(path.Clean("/"+norm), "/")
}

// pullDeniedFolded applies the deny-list to an already folded path. hiddenDirs
// adds the rule refusing every other hidden directory outside static/.
func pullDeniedFolded(norm string, hiddenDirs bool) bool {
	segs := strings.Split(strings.TrimPrefix(norm, "./"), "/")
	servedTree := len(segs) > 1 && segs[0] == "static"
	for i, seg := range segs {
		// Windows resolves a trailing dot or space, an NTFS stream suffix
		// (".claude::$INDEX_ALLOCATION") and an 8.3 short name ("CLAUDE~1") to
		// the same directory, so those spellings must not slip past the list.
		if c := strings.IndexByte(seg, ':'); c >= 0 {
			seg = seg[:c]
		}
		seg = strings.TrimRight(seg, ". ")
		if i < len(segs)-1 && pullShortNameRe.MatchString(seg) {
			return true
		}
		if pullDeniedSegments[seg] {
			return true
		}
		if hiddenDirs && i < len(segs)-1 && strings.HasPrefix(seg, ".") && !pullAllowedDotDirs[seg] && !servedTree {
			return true
		}
		if i == len(segs)-1 && (pullDeniedFiles[seg] || strings.HasSuffix(seg, ".code-workspace")) {
			return true
		}
	}
	return false
}
