//go:build !cli

package main

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A scaffold must already satisfy every write-time auto-fix. The push and the
// write_file tool both rewrite a file the auto-fixes would change, and in an
// app with a reviewed mcp.yaml (every connector-bearing scaffold) they refuse
// the rewrite instead, so a scaffold the auto-fixes disagree with could not be
// pushed back unchanged after a pull. Run every file a scaffold writes through
// both entry points; adding an auto-fix or a scaffold file keeps them in sync.
func assertScaffoldNeedsNoAutoFix(t *testing.T, dir string, wantFiles ...string) {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	checked := map[string]bool{}
	err = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		data, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		content := string(data)
		checked[rel] = true
		if fixed, applied := AutoFixOnWrite(rel, content); len(applied) > 0 || fixed != content {
			t.Errorf("push would rewrite scaffold file %s (%s):\n%s", rel, strings.Join(applied, "; "), autoFixAddedLines(content, fixed))
		}
		if fixed, applied, refusal := autoFixOrRefuse(root, rel, content); refusal != "" || len(applied) > 0 || fixed != content {
			t.Errorf("write_file would rewrite or refuse scaffold file %s: applied=%v refusal=%q", rel, applied, refusal)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, rel := range wantFiles {
		if !checked[rel] {
			t.Errorf("scaffold did not write %s; checked %d files", rel, len(checked))
		}
	}
}

// autoFixAddedLines lists the lines an auto-fix would add, for the failure
// message.
func autoFixAddedLines(before, after string) string {
	have := map[string]int{}
	for _, l := range strings.Split(before, "\n") {
		have[l]++
	}
	var out []string
	for _, l := range strings.Split(after, "\n") {
		if have[l] > 0 {
			have[l]--
		} else {
			out = append(out, "+ "+strings.TrimSpace(l))
		}
	}
	return strings.Join(out, "\n")
}

var htmlScaffoldPages = []string{"static/index.html", "static/login.html", "static/signup.html", "app.yaml", "AGENTS.md", "tests/journeys/home.yaml"}

func TestScaffoldFilesNeedNoWriteTimeAutoFix(t *testing.T) {
	cases := []struct {
		name  string
		write func(dir string) error
		want  []string
	}{
		// `benmore new` in the framework edition binds the starter connector.
		{"benmore new with connector", func(dir string) error { return writeHTMLScaffoldFiles(dir, "", true) }, append([]string{"mcp.yaml"}, htmlScaffoldPages...)},
		// `benmore new` in the cloud edition leaves the connector to after the first deploy.
		{"benmore new without connector", func(dir string) error { return writeHTMLScaffoldFiles(dir, "", false) }, htmlScaffoldPages},
		// The hosted create_app starter (and its title) binds the connector too.
		{"create_app starter", func(dir string) error { return WriteHTMLScaffoldFiles(dir, "Fixture App") }, append([]string{"mcp.yaml"}, htmlScaffoldPages...)},
		{"create_app bare", func(dir string) error { return WriteBareScaffoldFiles(dir, "Fixture App") }, []string{"app.yaml"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "fixture-app")
			if err := tc.write(dir); err != nil {
				t.Fatal(err)
			}
			assertScaffoldNeedsNoAutoFix(t, dir, tc.want...)
		})
	}
}

// The auth pages carry method="POST" themselves: without the page script a
// browser submits a form with no method as GET, putting the password in the
// URL, and with it the auto-fix has nothing to add.
func TestScaffoldAuthFormsDeclarePOST(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "fixture-app")
	if err := writeHTMLScaffoldFiles(dir, "", false); err != nil {
		t.Fatal(err)
	}
	for _, page := range []string{"static/login.html", "static/signup.html"} {
		data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(page)))
		if err != nil {
			t.Fatal(err)
		}
		forms := formBlockRe.FindAllStringSubmatch(string(data), -1)
		if len(forms) != 1 || !passwordInputRe.MatchString(forms[0][2]) {
			t.Fatalf("%s: want one password form, got %d", page, len(forms))
		}
		m := formMethodAttrRe.FindStringSubmatch(forms[0][1])
		if len(m) < 2 || !strings.EqualFold(m[1], "POST") {
			t.Fatalf("%s: password form declares no POST method: <form%s>", page, forms[0][1])
		}
	}
}
