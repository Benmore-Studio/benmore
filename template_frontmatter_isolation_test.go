//go:build !cli

package main

import (
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestRenderTemplateKeepsSharedFrontmatterPageImmutable(t *testing.T) {
	for _, engine := range []string{"mustache", "gotmpl", "raw"} {
		t.Run(engine, func(t *testing.T) {
			app := ssrTestApp(t)
			if err := os.Mkdir(filepath.Join(app.Dir, "layouts"), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(app.Dir, "layouts", "frame.html"), []byte("<main>layout-start{{content}}layout-end</main>"), 0o644); err != nil {
				t.Fatal(err)
			}
			body := "<p>{{message}}</p>"
			if engine == "gotmpl" {
				body = "<p>{{.message}}</p>"
			} else if engine == "raw" {
				body = "<p>rendered-content</p>"
			}
			page := &Page{Route: "/report", File: "report.html", RawHTML: fmt.Sprintf("---\nengine: %s\nlayout: frame\ntitle: Report\nscope: owner\n---\n%s", engine, body)}
			before := *page
			ctx := &RenderContext{App: app, Page: page, Data: map[string]any{"message": "rendered-content"}, Request: httptest.NewRequest("GET", "/report", nil)}
			out, err := RenderTemplate(app, page, ctx)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(out, "layout-start<p>rendered-content</p>layout-end") {
				t.Fatalf("frontmatter layout/body were not applied: %q", out)
			}
			if *page != before || ctx.Page != page {
				t.Fatal("render changed the shared page or left a replacement in its caller's context")
			}
		})
	}
}

func TestFrontmatterRenderConcurrentWithContextGraph(t *testing.T) {
	app := ssrTestApp(t)
	ssrLoadPages(t, app, map[string]string{
		"report.html": "---\nengine: gotmpl\nlayout: none\n---\n<p>{{.message}}</p>",
	})
	page := app.Pages["/report"]
	before := *page
	start := make(chan struct{})
	var readers sync.WaitGroup
	readers.Add(1)
	go func() {
		defer readers.Done()
		<-start
		for i := 0; i < 20; i++ {
			RebuildContextGraph(app)
		}
	}()
	close(start)
	for i := 0; i < 40; i++ {
		ctx := &RenderContext{App: app, Page: page, Data: map[string]any{"message": "shared-report"}}
		out, err := RenderTemplate(app, page, ctx)
		if err != nil || !strings.Contains(out, "<p>shared-report</p>") {
			t.Errorf("render %d: output=%q error=%v", i, out, err)
		}
	}
	readers.Wait()
	if *page != before {
		t.Fatal("render changed loaded page metadata")
	}
}

func TestFrontmatterRenderLocalOwnerScope(t *testing.T) {
	for _, engine := range []string{"mustache", "gotmpl"} {
		t.Run(engine, func(t *testing.T) {
			app := ssrTestApp(t)
			crudScopeMustExec(t, app.DB, `INSERT INTO notes(user_id,title) VALUES(1,'owned-note'),(2,'foreign-note')`)
			raw := "---\nscope: owner\nlayout: none\n---\n" + `<query sql="SELECT title FROM notes ORDER BY id" as="rows">{{#rows}}<p>{{title}}</p>{{/rows}}</query>`
			if engine == "gotmpl" {
				raw = "---\nengine: gotmpl\nscope: owner\nlayout: none\nqueries:\n  rows: SELECT title FROM notes ORDER BY id\n---\n<p>{{range .rows}}{{.title}}{{end}}</p>"
			}
			page := &Page{Route: "/notes", File: "notes.html", RawHTML: raw}
			before := *page
			for _, user := range []*Session{{UserID: 1}, nil} {
				ctx := &RenderContext{App: app, Page: page, User: user, Data: map[string]any{}}
				out, err := RenderTemplate(app, page, ctx)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(out, "foreign-note") || strings.Contains(out, "owned-note") != (user != nil) {
					t.Fatalf("owner scope was lost (signed in=%t): %s", user != nil, out)
				}
				if *page != before || ctx.Page != page {
					t.Fatal("scoped render changed shared page/context")
				}
			}
		})
	}
}

func TestFrontmatterRenderErrorRestoresPageContext(t *testing.T) {
	app := ssrTestApp(t)
	page := &Page{RawHTML: "---\nengine: gotmpl\nlayout: none\n---\n{{if}}"}
	before := *page
	ctx := &RenderContext{App: app, Page: page, Data: map[string]any{}}
	if _, err := RenderTemplate(app, page, ctx); err == nil {
		t.Fatal("invalid template unexpectedly rendered")
	}
	if *page != before || ctx.Page != page {
		t.Fatal("failed render changed shared page/context")
	}
}
