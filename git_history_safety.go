//go:build !cli

package main

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// Ignore files are a convenience, not the staging boundary: deeper ignore files
// can negate a root rule, and tracked files bypass ignores entirely.
func gitProtectedPath(path string) bool {
	parts := strings.Split(filepath.ToSlash(path), "/")
	if len(parts) > 0 && parts[0] == "Benmore" {
		return true
	}
	for _, part := range parts {
		switch part {
		case "data.db", "data.db-wal", "data.db-shm", ".benmore", "uploads", "env.yaml", "secrets.yaml", ".env", ".git":
			return true
		}
		if strings.HasSuffix(part, ".pem") {
			return true
		}
		if strings.HasPrefix(part, ".env.") || strings.HasSuffix(part, ".key") || strings.HasSuffix(part, ".log") {
			return true
		}
	}
	return false
}

// Require a repo owned by this app directory, not a parent repo, worktree file,
// symlink or core.worktree redirect. Callers hold gitDirLock for mutations.
func gitAppRepoExists(dir string) (bool, error) {
	info, err := os.Lstat(filepath.Join(dir, ".git"))
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	if !info.IsDir() {
		return false, fmt.Errorf("app git metadata must be a directory")
	}
	want, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return false, err
	}
	want, err = filepath.Abs(want)
	if err != nil {
		return false, err
	}
	for _, check := range []struct{ flag, want string }{
		{"--show-toplevel", want}, {"--absolute-git-dir", filepath.Join(want, ".git")},
	} {
		out, err := gitRun(dir, "rev-parse", check.flag)
		if err != nil {
			return false, err
		}
		actual, err := filepath.EvalSymlinks(strings.TrimSpace(out))
		if err != nil || actual != check.want {
			return false, fmt.Errorf("git repository is outside the app directory")
		}
	}
	return true, nil
}

func gitRejectProtectedPaths(paths string) error {
	for _, path := range strings.Split(paths, "\x00") {
		if path != "" && gitProtectedPath(path) {
			// Do not print paths: file names can themselves contain private data.
			return fmt.Errorf("app history already tracks runtime data or secret files; operator cleanup is required before history operations")
		}
	}
	return nil
}

func gitCheckIndex(dir string) error {
	paths, err := gitRun(dir, "ls-files", "-z")
	if err != nil {
		return err
	}
	return gitRejectProtectedPaths(paths)
}

func gitSafeCommit(dir, revision string) (string, error) {
	sha, err := gitRun(dir, "rev-parse", "--verify", "--end-of-options", revision+"^{commit}")
	if err != nil {
		return "", err
	}
	sha = strings.TrimSpace(sha)
	paths, err := gitRun(dir, "ls-tree", "-r", "--name-only", "-z", sha)
	if err != nil {
		return "", err
	}
	return sha, gitRejectProtectedPaths(paths)
}

func gitCheckCurrentTree(dir string) error {
	if err := gitCheckIndex(dir); err != nil {
		return err
	}
	// Reference inspection distinguishes an unborn repo from a broken HEAD. A repo
	// initialized by Benmore always has a symbolic HEAD, including before init's
	// first commit; rev-parse alone would hide corruption as "no commits yet".
	refs, err := gitRun(dir, "rev-parse", "--verify", "--quiet", "HEAD")
	if err != nil {
		ref, refErr := gitRun(dir, "symbolic-ref", "-q", "HEAD")
		if refErr != nil {
			return err
		}
		// An absent loose ref is not sufficient: it may be packed.
		all, listErr := gitRun(dir, "for-each-ref", "--format=%(refname)", strings.TrimSpace(ref))
		if listErr != nil || strings.TrimSpace(all) != "" {
			return fmt.Errorf("cannot read app history HEAD: %w", err)
		}
		return nil
	}
	_, err = gitSafeCommit(dir, strings.TrimSpace(refs))
	return err
}

// Mandatory rules are appended after app rules and restored after source mirrors.
// Atomic replacement also rejects symlinked .gitignore files.
func gitProtectHistory(dir string) error {
	exists, err := gitAppRepoExists(dir)
	if err != nil {
		return err
	}
	if exists {
		if err := gitCheckCurrentTree(dir); err != nil {
			return err
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	if info, err := root.Lstat(".gitignore"); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("app gitignore must be a regular file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	data, err := root.ReadFile(".gitignore")
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if strings.HasSuffix(string(data), gitignoreContents) {
		return nil
	}
	data = append(data, []byte("\n"+gitignoreContents)...)
	name := ".history-ignore-" + generateToken(12)
	f, err := root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer root.Remove(name)
	_, err = f.Write(data)
	if err = errors.Join(err, f.Sync(), f.Close()); err != nil {
		return err
	}
	return root.Rename(name, ".gitignore")
}

func gitSourcePaths(dir string, args ...string) (string, error) {
	paths, err := gitRun(dir, append([]string{"ls-files", "-z"}, args...)...)
	if err != nil {
		return "", err
	}
	var source strings.Builder
	for _, path := range strings.Split(paths, "\x00") {
		if path != "" && !gitProtectedPath(path) {
			// Literal pathspecs prevent wildcard/colon/newline filenames from
			// selecting other files. stdin avoids command-line length limits.
			source.WriteString(":(literal)" + path + "\x00")
		}
	}
	return source.String(), nil
}

func gitStageSource(dir string) error {
	// A tracked file may have become a directory. Passing its old name to
	// `git add` would recursively stage the new contents, bypassing the filter.
	// Remove deleted/type-changed entries from the index before enumerating new
	// files. update-index only changes the index, never the filesystem.
	cached, err := gitRun(dir, "ls-files", "-z", "--cached")
	if err != nil {
		return err
	}
	var removed strings.Builder
	for _, path := range strings.Split(cached, "\x00") {
		if path == "" {
			continue
		}
		info, err := os.Lstat(filepath.Join(dir, filepath.FromSlash(path)))
		if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) || (err == nil && info.IsDir()) {
			removed.WriteString(path + "\x00")
		} else if err != nil {
			return err
		}
	}
	if removed.Len() > 0 {
		if _, err := gitRunInput(dir, removed.String(), "update-index", "--force-remove", "-z", "--stdin"); err != nil {
			return err
		}
	}
	paths, err := gitSourcePaths(dir, "--cached", "--others", "--exclude-standard")
	if err != nil {
		return err
	}
	if paths != "" {
		if _, err := gitRunInput(dir, paths, "add", "--all", "--pathspec-from-file=-", "--pathspec-file-nul"); err != nil {
			return err
		}
	}
	return gitCheckIndex(dir)
}

// A safe target file can still replace a directory containing ignored runtime
// files. reset --hard removes such obstructions; reject before it touches them.
func gitCheckRestoreObstructions(dir, sha string) error {
	paths, err := gitRun(dir, "ls-tree", "-r", "--name-only", "-z", sha)
	if err != nil {
		return err
	}
	for _, path := range strings.Split(paths, "\x00") {
		if path == "" {
			continue
		}
		full := filepath.Join(dir, filepath.FromSlash(path))
		info, err := os.Lstat(full)
		if os.IsNotExist(err) || errors.Is(err, syscall.ENOTDIR) {
			continue
		}
		if err != nil {
			return err
		}
		if !info.IsDir() {
			continue
		}
		if err := filepath.WalkDir(full, func(p string, _ fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			rel, err := filepath.Rel(dir, p)
			if err != nil {
				return err
			}
			if gitProtectedPath(rel) {
				return fmt.Errorf("restore would replace a directory containing runtime data or secrets")
			}
			return nil
		}); err != nil {
			return err
		}
	}
	return nil
}

// Audit all reachable history before exporting it, including deleted files and
// every merge parent. Checking only HEAD would allow an older secret to leak.
func gitPublishHead(dir string) (string, error) {
	if exists, err := gitAppRepoExists(dir); err != nil {
		return "", err
	} else if !exists {
		return "", fmt.Errorf("app has no git repository")
	}
	sha, err := gitSafeCommit(dir, "HEAD")
	if err != nil {
		return "", err
	}
	paths, err := gitRun(dir, "log", "--format=", "--name-only", "-z", "--no-renames", "--root", "-m", sha, "--")
	if err != nil {
		return "", err
	}
	return sha, gitRejectProtectedPaths(paths)
}
