package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// gitignoreCases is one table for two checks: the matcher's own answers, and
// (where git is installed) git's answers for the same files.
var gitignoreCases = []struct {
	name      string
	gitignore string
	files     []string // files of the workspace
	ignored   []string // the files the matcher must report, sorted
	// partial marks a .gitignore with a line the matcher does not read: git
	// may ignore more than the matcher reports, never less.
	partial bool
}{
	{
		name:      "comments and blank lines are not patterns",
		gitignore: "# notes.txt\n\n   \n#\n",
		files:     []string{"notes.txt", "#", "a/# notes.txt"},
	},
	{
		name:      "a plain name matches at any depth",
		gitignore: "notes.txt\n",
		files:     []string{"notes.txt", "docs/notes.txt", "docs/deep/notes.txt", "notes.txt.bak", "my-notes.txt"},
		ignored:   []string{"docs/deep/notes.txt", "docs/notes.txt", "notes.txt"},
	},
	{
		name:      "a plain name also excludes a directory and all below it",
		gitignore: "build\n",
		files:     []string{"build/out.js", "build/deep/a.js", "src/build/x.js", "src/builder.js", "rebuild/x.js"},
		ignored:   []string{"build/deep/a.js", "build/out.js", "src/build/x.js"},
	},
	{
		name:      "star stays inside one path segment",
		gitignore: "*.tmp\ndraft-*\nsrc/*.gen.ts\n",
		files:     []string{"a.tmp", "x/b.tmp", ".tmp", "a.tmpx", "draft-1.md", "x/draft-", "src/a.gen.ts", "src/deep/b.gen.ts", "other/a.gen.ts"},
		ignored:   []string{".tmp", "a.tmp", "draft-1.md", "src/a.gen.ts", "x/b.tmp", "x/draft-"},
	},
	{
		name:      "question mark is exactly one character",
		gitignore: "v?.json\n",
		files:     []string{"v1.json", "v.json", "v12.json", "data/v2.json"},
		ignored:   []string{"data/v2.json", "v1.json"},
	},
	{
		name:      "a leading slash anchors to the root",
		gitignore: "/todo.md\n/dist\n",
		files:     []string{"todo.md", "docs/todo.md", "dist/a.js", "static/dist/a.js"},
		ignored:   []string{"dist/a.js", "todo.md"},
	},
	{
		name:      "a slash in the middle anchors too",
		gitignore: "docs/internal.md\nfixtures/*.sql\n",
		files:     []string{"docs/internal.md", "x/docs/internal.md", "fixtures/a.sql", "fixtures/deep/b.sql", "tests/fixtures/c.sql"},
		ignored:   []string{"docs/internal.md", "fixtures/a.sql"},
	},
	{
		name:      "a trailing slash matches directories only",
		gitignore: "cache/\n/out/\nnotes/\n",
		files:     []string{"cache/a", "static/cache/b", "cache.txt", "out/x", "static/out/x", "notes"},
		ignored:   []string{"cache/a", "out/x", "static/cache/b"},
	},
	{
		name:      "leading double star matches in every directory",
		gitignore: "**/secret.txt\n**/tmp/*.json\n",
		files:     []string{"secret.txt", "a/secret.txt", "a/b/secret.txt", "tmp/a.json", "x/tmp/b.json", "x/tmp/deep/c.json"},
		ignored:   []string{"a/b/secret.txt", "a/secret.txt", "secret.txt", "tmp/a.json", "x/tmp/b.json"},
	},
	{
		name:      "trailing double star matches everything inside",
		gitignore: "scratch/**\n",
		files:     []string{"scratch/a", "scratch/b/c", "scratch.md", "x/scratch/d"},
		ignored:   []string{"scratch/a", "scratch/b/c"},
	},
	{
		name:      "double star between slashes spans zero or more directories",
		gitignore: "a/**/z.txt\n",
		files:     []string{"a/z.txt", "a/b/z.txt", "a/b/c/z.txt", "z.txt", "b/a/z.txt", "a/b/zz.txt"},
		ignored:   []string{"a/b/c/z.txt", "a/b/z.txt", "a/z.txt"},
	},
	{
		name:      "asterisks that are not a whole segment are ordinary ones",
		gitignore: "a**b.txt\nlib/x**\n",
		files:     []string{"ab.txt", "a123b.txt", "a/b.txt", "lib/x", "lib/xyz", "lib/xdir/deep", "lib/y"},
		ignored:   []string{"a123b.txt", "ab.txt", "lib/x", "lib/xdir/deep", "lib/xyz"},
	},
	{
		name:      "negation re-includes and the last matching line wins",
		gitignore: "*.md\n!README.md\nREADME.md\n!/README.md\n",
		files:     []string{"a.md", "README.md", "docs/README.md"},
		ignored:   []string{"a.md", "docs/README.md"},
	},
	{
		name:      "nothing below an excluded directory is re-included",
		gitignore: "private/\n!private/keep.txt\n",
		files:     []string{"private/keep.txt", "private/other.txt"},
		ignored:   []string{"private/keep.txt", "private/other.txt"},
	},
	{
		name:      "a directory's contents can be re-included one by one",
		gitignore: "private/*\n!private/keep.txt\n",
		files:     []string{"private/keep.txt", "private/other.txt", "private/sub/x"},
		ignored:   []string{"private/other.txt", "private/sub/x"},
	},
	{
		name:      "trailing spaces, CRLF line ends and a byte order mark are dropped",
		gitignore: "\ufeffone.txt\r\ntwo.txt   \r\nthree.txt",
		files:     []string{"one.txt", "two.txt", "three.txt", "four.txt"},
		ignored:   []string{"one.txt", "three.txt", "two.txt"},
	},
	{
		name:      "matching is case-sensitive and a star matches a leading dot",
		gitignore: "Notes.txt\n*rc\n",
		files:     []string{"a/notes.txt", "b/Notes.txt", ".toolrc", "lib/.rc"},
		ignored:   []string{".toolrc", "b/Notes.txt", "lib/.rc"},
	},
	{
		name:      "a character class or an escape is not read and excludes nothing",
		gitignore: "data[0-9].csv\n\\#literal\nfile\\ name\nplain.csv\n",
		files:     []string{"data1.csv", "#literal", "file name", "plain.csv"},
		ignored:   []string{"plain.csv"},
		partial:   true,
	},
	{
		name:      "a negation that is not read re-includes everything before it",
		gitignore: "*.csv\nold/\n![k]eep.csv\nlater.txt\n",
		files:     []string{"a.csv", "keep.csv", "old/x", "later.txt"},
		ignored:   []string{"later.txt"},
		partial:   true,
	},
	{
		name:      "an empty path segment is not read",
		gitignore: "a//b\nc.txt\n",
		files:     []string{"a/b", "c.txt"},
		ignored:   []string{"c.txt"},
	},
	{
		name:      "lines that hold no pattern",
		gitignore: "/\n!\n!/\n",
		files:     []string{"a", "b/c"},
	},
}

func TestGitignoreMatcher(t *testing.T) {
	for _, tc := range gitignoreCases {
		t.Run(tc.name, func(t *testing.T) {
			matcher := parseGitignore(tc.gitignore)
			var got []string
			for _, file := range tc.files {
				if matcher.Ignored(file, false) {
					got = append(got, file)
				}
			}
			sort.Strings(got)
			if !reflect.DeepEqual(got, tc.ignored) {
				t.Fatalf(".gitignore %q\n ignored %q\n    want %q", tc.gitignore, got, tc.ignored)
			}
		})
	}
}

// The table's expectations are git's own: every case is replayed through
// `git check-ignore`. For a .gitignore the matcher reads in full the answers
// are equal; for one with a line it does not read, git may ignore more.
func TestGitignoreMatcherAgreesWithGit(t *testing.T) {
	git, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git is not installed")
	}
	for _, tc := range gitignoreCases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			home := t.TempDir()
			// No setting of the machine or of a calling git process may reach
			// the comparison (a global excludes file, GIT_DIR from a hook).
			var env []string
			for _, kv := range os.Environ() {
				if !strings.HasPrefix(kv, "GIT_") {
					env = append(env, kv)
				}
			}
			env = append(env, "HOME="+home, "XDG_CONFIG_HOME="+home, "GIT_CONFIG_GLOBAL="+os.DevNull, "GIT_CONFIG_NOSYSTEM=1")
			run := func(stdin string, args ...string) (string, error) {
				cmd := exec.Command(git, args...)
				cmd.Dir = dir
				cmd.Env = env
				cmd.Stdin = strings.NewReader(stdin)
				var stderr strings.Builder
				cmd.Stderr = &stderr
				out, err := cmd.Output()
				if err != nil && stderr.Len() > 0 {
					t.Logf("git %s: %s", args[0], stderr.String())
				}
				return string(out), err
			}
			if _, err := run("", "init", "-q"); err != nil {
				t.Skipf("git init: %v", err)
			}
			if _, err := run("", "config", "core.ignorecase", "false"); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte(tc.gitignore), 0o644); err != nil {
				t.Fatal(err)
			}
			for _, file := range tc.files {
				full := filepath.Join(dir, filepath.FromSlash(file))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			// Exit status 1 with no output means "none of them is ignored".
			out, err := run(strings.Join(tc.files, "\x00")+"\x00", "check-ignore", "--stdin", "-z")
			if exit, ok := err.(*exec.ExitError); err != nil && (!ok || exit.ExitCode() != 1) {
				t.Fatalf("git check-ignore: %v", err)
			}
			byGit := map[string]bool{}
			var gitIgnored []string
			for _, file := range strings.Split(out, "\x00") {
				if file != "" {
					byGit[file] = true
					gitIgnored = append(gitIgnored, file)
				}
			}
			sort.Strings(gitIgnored)
			for _, file := range tc.ignored {
				if !byGit[file] {
					t.Errorf("the matcher ignores %q, git does not (git ignores %q)", file, gitIgnored)
				}
			}
			if !tc.partial && !reflect.DeepEqual(gitIgnored, tc.ignored) {
				t.Errorf(".gitignore %q\n git ignores %q\n the matcher %q", tc.gitignore, gitIgnored, tc.ignored)
			}
			if tc.partial && len(gitIgnored) == len(tc.ignored) {
				t.Errorf("case is marked partial, but git and the matcher agree on %q", gitIgnored)
			}
		})
	}
}

func TestGitignoreMatcherDirectoriesAndRules(t *testing.T) {
	matcher := parseGitignore("# header\ncache/\n*.tmp\n!keep.tmp\n")
	for _, tc := range []struct {
		rel   string
		isDir bool
		want  bool
	}{
		{"cache", true, true},
		{"cache", false, false},
		{"static/cache", true, true},
		{"static/cache/a/b", true, true},
		{"./cache/a", false, true},
		{"a.tmp", false, true},
		{"keep.tmp", false, false},
		{"", false, false},
		{".", true, false},
	} {
		if got := matcher.Ignored(tc.rel, tc.isDir); got != tc.want {
			t.Errorf("Ignored(%q, dir=%v) = %v, want %v", tc.rel, tc.isDir, got, tc.want)
		}
	}
	rule := matcher.Match("static/cache/a.txt", false)
	if rule == nil || rule.Line != 2 || rule.Pattern != "cache/" {
		t.Fatalf("Match names the rule that excludes the directory, got %+v", rule)
	}
	if rule := matcher.Match("keep.tmp", false); rule != nil {
		t.Fatalf("a re-included file has no excluding rule, got %+v", rule)
	}
	var none *gitignoreMatcher
	if none.Ignored("a.tmp", false) {
		t.Fatal("a missing .gitignore ignores nothing")
	}
}

func TestLoadWorkspaceGitignore(t *testing.T) {
	dir := t.TempDir()
	if loadWorkspaceGitignore(dir) != nil {
		t.Fatal("no .gitignore must give no matcher")
	}
	if err := os.WriteFile(filepath.Join(dir, ".gitignore"), []byte("*.tmp\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if matcher := loadWorkspaceGitignore(dir); !matcher.Ignored("a.tmp", false) {
		t.Fatal("the root .gitignore was not read")
	}
	big := t.TempDir()
	if err := os.WriteFile(filepath.Join(big, ".gitignore"), []byte(strings.Repeat("*.tmp\n", workspaceGitignoreMaxBytes/6+1)), 0o644); err != nil {
		t.Fatal(err)
	}
	if loadWorkspaceGitignore(big) != nil {
		t.Fatal("an oversized .gitignore must be treated as absent")
	}
	linked := t.TempDir()
	if err := os.Symlink(filepath.Join(dir, ".gitignore"), filepath.Join(linked, ".gitignore")); err != nil {
		t.Skip("symlinks are not available")
	}
	if loadWorkspaceGitignore(linked) != nil {
		t.Fatal("a symlinked .gitignore must not be followed")
	}
}
