//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/net/html"
)

// The scaffold's app.yaml says `mode: dark` and every page pairs its light
// classes with `dark:` ones, yet a new app rendered light: the Tailwind the
// binary serves uses class-based dark mode (tailwindDarkModeClass), whose
// `dark:` variant is `&:is(.dark *)`, and no served page carried the class.
// `mode:` reaches server-rendered pages only (wrapLayoutAt); pages under
// static/ are served as written, so the scaffold has to carry the class.
//
// This reads the bytes the binary serves. Tailwind builds its CSS in the
// browser, so what the pages look like is not checked here.
func TestScaffoldDarkStylingReachesEveryPage(t *testing.T) {
	// withConnector true: create_app and the framework edition's `benmore
	// new`; false: the hosted CLI's `benmore new`. One writer, both shapes.
	for _, withConnector := range []bool{true, false} {
		dir := filepath.Join(t.TempDir(), "darkapp")
		if err := writeHTMLScaffoldFiles(dir, "Dark fixture", withConnector); err != nil {
			t.Fatal(err)
		}
		conf, err := os.ReadFile(filepath.Join(dir, "app.yaml"))
		if err != nil || !strings.Contains(string(conf), "\nmode: dark") {
			t.Fatalf("scaffold app.yaml no longer says mode: dark (%v):\n%s", err, conf)
		}
		app, err := loadAppForServerTests(dir)
		if err != nil {
			t.Fatal(err)
		}
		mux := buildAppMux(app, false, "https://dark.example.com")
		get := func(path string) (int, string) {
			w := httptest.NewRecorder()
			mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "https://dark.example.com"+path, nil))
			return w.Code, w.Body.String()
		}

		// The served Tailwind: class strategy, default selector ".dark", and
		// a variant that matches descendants of the marked element only.
		code, tailwind := get("/_internal/tailwind.js")
		if code != http.StatusOK {
			t.Fatalf("/_internal/tailwind.js answered %d", code)
		}
		if !strings.HasSuffix(strings.TrimSpace(tailwind), "{darkMode:'class'}));}catch(e){}") {
			t.Fatal("the served Tailwind does not end by setting darkMode:'class'")
		}
		for _, want := range []string{
			`[r,i=".dark"]=[].concat(t("darkMode","media"))`, // selector defaults to .dark
			"r===\"class\"&&e(\"dark\",`&:is(${i} *)`)",      // class strategy: descendants of .dark
		} {
			if !strings.Contains(tailwind, want) {
				t.Fatalf("the served Tailwind's dark variant changed (no %q); re-derive what this test asserts", want)
			}
		}

		pages, err := filepath.Glob(filepath.Join(dir, "static", "*.html"))
		if err != nil || len(pages) < 8 {
			t.Fatalf("scaffold wrote %d pages (%v)", len(pages), err)
		}
		for _, file := range pages {
			name := filepath.Base(file)
			path := "/" + name
			if name == "index.html" {
				path = "/"
			}
			code, body := get(path)
			if code != http.StatusOK {
				t.Errorf("%s answered %d", path, code)
				continue
			}
			doc, err := html.Parse(strings.NewReader(body))
			if err != nil {
				t.Fatal(err)
			}
			var darkUses, controls int
			var rootMarked bool
			// inMain: the scaffold's own markup. What the framework appends to
			// a served page (the feedback widget's textarea) styles itself.
			var walk func(n *html.Node, underDark, inMain bool)
			walk = func(n *html.Node, underDark, inMain bool) {
				marksDark := false
				if n.Type == html.ElementNode {
					inMain = inMain || n.Data == "main"
					classes := strings.Fields(htmlAttr(n, "class"))
					for _, c := range classes {
						if c == "dark" {
							marksDark = true
							if n.Data == "html" {
								rootMarked = true
							}
						}
					}
					for _, c := range classes {
						if !strings.HasPrefix(c, "dark:") && !strings.Contains(c, ":dark:") {
							continue
						}
						darkUses++
						if !underDark {
							t.Errorf("%s: <%s class=%q>: %s can never apply, the element is not inside one with class \"dark\"", name, n.Data, htmlAttr(n, "class"), c)
						}
					}
					if inMain && scaffoldTypedControl(n) {
						controls++
						for _, prefix := range []string{"bg-", "dark:bg-", "text-zinc-", "dark:text-zinc-", "placeholder-", "dark:placeholder-"} {
							if !hasClassPrefix(classes, prefix) {
								t.Errorf("%s: <%s name=%q> sets no %s* class (%q): its text or placeholder colour is inherited", name, n.Data, htmlAttr(n, "name"), prefix, htmlAttr(n, "class"))
							}
						}
					}
					if n.Data == "body" {
						for _, prefix := range []string{"bg-", "dark:bg-", "text-", "dark:text-"} {
							if !hasClassPrefix(classes, prefix) {
								t.Errorf("%s: <body class=%q> sets no %s* class", name, htmlAttr(n, "class"), prefix)
							}
						}
					}
				}
				for c := n.FirstChild; c != nil; c = c.NextSibling {
					walk(c, underDark || marksDark, inMain)
				}
			}
			walk(doc, false, false)
			if !rootMarked {
				t.Errorf("%s: served <html> has no class \"dark\", so none of its %d dark: classes apply", name, darkUses)
			}
			if darkUses == 0 {
				t.Errorf("%s: no dark: classes; the page no longer pairs light and dark styling", name)
			}
			if controls == 0 {
				t.Errorf("%s: found no input to check", name)
			}
		}
		app.Shutdown()
	}
}

func htmlAttr(n *html.Node, key string) string {
	for _, a := range n.Attr {
		if a.Key == key {
			return a.Val
		}
	}
	return ""
}

func hasClassPrefix(classes []string, prefix string) bool {
	for _, c := range classes {
		if strings.HasPrefix(c, prefix) {
			return true
		}
	}
	return false
}

// scaffoldTypedControl reports an element a person types into.
func scaffoldTypedControl(n *html.Node) bool {
	switch n.Data {
	case "textarea", "select":
		return true
	case "input":
		switch htmlAttr(n, "type") {
		case "hidden", "checkbox", "radio", "submit", "button", "file":
			return false
		}
		return true
	}
	return false
}
