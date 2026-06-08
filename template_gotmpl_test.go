//go:build !cli

package main

// Tests for the html/template rendering path. Two layers:
//
//   - Frontmatter parser: shape recognition, attribute mapping, body
//     extraction. The model is told to write a `---`-fenced YAML block;
//     the parser has to handle a few small variants (trailing newline
//     or not, CRLF, missing optional fields).
//   - End-to-end render: a representative gotmpl page renders against
//     a stub RenderContext and produces the expected HTML.

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExtractFrontmatter_BasicShape(t *testing.T) {
	raw := "---\ntitle: Notes\nauth: required\nengine: gotmpl\n---\n<h1>{{.user.email}}</h1>\n"
	fm, body, err := ExtractFrontmatter(raw)
	if err != nil {
		t.Fatalf("unexpected err: %s", err)
	}
	if fm == nil {
		t.Fatalf("expected frontmatter, got nil")
	}
	if fm.Title != "Notes" || fm.Auth != "required" || fm.Engine != "gotmpl" {
		t.Fatalf("frontmatter fields wrong: %+v", fm)
	}
	if !strings.HasPrefix(body, "<h1>") {
		t.Fatalf("body should start with <h1>, got: %q", body)
	}
}

func TestExtractFrontmatter_NoFrontmatter(t *testing.T) {
	raw := "<page auth=\"required\"><h1>Old shape</h1></page>"
	fm, body, err := ExtractFrontmatter(raw)
	if err != nil {
		t.Fatalf("unexpected err: %s", err)
	}
	if fm != nil {
		t.Fatalf("expected nil frontmatter on legacy file")
	}
	if body != raw {
		t.Fatalf("body should pass through unchanged when no frontmatter")
	}
}

func TestExtractFrontmatter_CRLF(t *testing.T) {
	// Windows-style line endings shouldn't break the parser.
	raw := "---\r\ntitle: x\r\nengine: gotmpl\r\n---\r\n<p>hi</p>"
	fm, body, err := ExtractFrontmatter(raw)
	if err != nil {
		t.Fatalf("unexpected err: %s", err)
	}
	if fm == nil || fm.Engine != "gotmpl" {
		t.Fatalf("CRLF frontmatter not parsed: %+v", fm)
	}
	if !strings.HasPrefix(body, "<p>") {
		t.Fatalf("CRLF body should start with <p>, got: %q", body)
	}
}

func TestExtractFrontmatter_QueriesMap(t *testing.T) {
	raw := `---
title: Contacts
engine: gotmpl
queries:
  contacts: SELECT * FROM contacts WHERE user_id = :user_id
  stats: SELECT COUNT(*) AS n FROM contacts
---
body`
	fm, _, err := ExtractFrontmatter(raw)
	if err != nil {
		t.Fatalf("unexpected err: %s", err)
	}
	if len(fm.Queries) != 2 {
		t.Fatalf("expected 2 queries, got %d", len(fm.Queries))
	}
	if !strings.Contains(fm.Queries["contacts"], ":user_id") {
		t.Fatalf("queries.contacts should preserve :user_id bind, got %q", fm.Queries["contacts"])
	}
}

func TestApplyFrontmatterToPage_DoesNotOverwrite(t *testing.T) {
	// The <page> tag wins over frontmatter so a mixed file stays
	// self-consistent. This is the rule that makes the migration safe.
	p := &Page{Auth: "required", Title: "From Page Tag"}
	fm := &Frontmatter{Auth: "none", Title: "From Frontmatter", Layout: "dashboard"}
	ApplyFrontmatterToPage(p, fm)
	if p.Auth != "required" {
		t.Fatalf("auth should not have been overwritten: got %q", p.Auth)
	}
	if p.Title != "From Page Tag" {
		t.Fatalf("title should not have been overwritten: got %q", p.Title)
	}
	if p.Layout != "dashboard" {
		t.Fatalf("layout (unset on page) should have been filled from frontmatter, got %q", p.Layout)
	}
}

func TestRenderGoTemplate_RangeAndUserContext(t *testing.T) {
	// Smoke test the renderer end to end with a representative page.
	// No DB queries here — that path is exercised by the example app
	// + integration tests; this verifies the template engine plumbing.
	body := `<h1>Hi {{.user.email}}</h1>
{{range .items}}<p>{{.name}}</p>{{else}}<p>none</p>{{end}}`

	app := &App{Dir: t.TempDir()}
	page := &Page{Route: "/", File: "index.html"}
	ctx := &RenderContext{
		Data: map[string]any{
			"user": map[string]any{"email": "alice@example.com"},
			"items": []map[string]any{
				{"name": "first"},
				{"name": "second"},
			},
		},
		Request: httptest.NewRequest("GET", "/", nil),
	}

	out, err := renderGoTemplate(app, page, ctx, &Frontmatter{}, body)
	if err != nil {
		t.Fatalf("render error: %s", err)
	}
	for _, want := range []string{"Hi alice@example.com", "<p>first</p>", "<p>second</p>"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q\n--- got ---\n%s", want, out)
		}
	}
	if strings.Contains(out, "<p>none</p>") {
		t.Errorf("else branch should not have rendered when items present")
	}
}

func TestRenderGoTemplate_ElseEmptyBranch(t *testing.T) {
	body := `{{range .items}}x{{else}}EMPTY{{end}}`
	app := &App{Dir: t.TempDir()}
	page := &Page{Route: "/"}
	ctx := &RenderContext{
		Data:    map[string]any{"items": []map[string]any{}},
		Request: httptest.NewRequest("GET", "/", nil),
	}
	out, err := renderGoTemplate(app, page, ctx, &Frontmatter{}, body)
	if err != nil {
		t.Fatalf("render error: %s", err)
	}
	if !strings.Contains(out, "EMPTY") {
		t.Errorf("expected else branch to render on empty slice, got %q", out)
	}
}

func TestRenderGoTemplate_CSRFHelper(t *testing.T) {
	// The csrf helper emits a hidden input + a meta tag so any form
	// passes CSRF middleware and HTMX requests pick up the token.
	body := `{{csrf}}`
	app := &App{Dir: t.TempDir()}
	page := &Page{Route: "/"}
	ctx := &RenderContext{
		Data:    map[string]any{},
		Request: httptest.NewRequest("GET", "/", nil),
	}
	out, err := renderGoTemplate(app, page, ctx, &Frontmatter{}, body)
	if err != nil {
		t.Fatalf("render error: %s", err)
	}
	if !strings.Contains(out, `name="_csrf"`) {
		t.Errorf("csrf helper missing hidden input: %s", out)
	}
	if !strings.Contains(out, `name="csrf-token"`) {
		t.Errorf("csrf helper missing meta tag: %s", out)
	}
}

func TestGotmplHelpers_SprigMathAvailable(t *testing.T) {
	// Sprig math (add/sub/mul/div/mod) drove a Haiku session into a
	// dead end last time — `{{sub a b}}` returned "function not
	// defined". Now Sprig's full FuncMap is registered.
	cases := map[string]string{
		`{{add 2 3}}`:                "5",
		`{{sub 10 4}}`:               "6",
		`{{mul 3 7}}`:                "21",
		`{{div 10 2}}`:               "5",
		`{{mod 10 3}}`:               "1",
		`{{max 5 8}}`:                "8",
		`{{min 5 8}}`:                "5",
		`{{add (add 1 2) (add 3 4)}}`: "10",
	}
	for tmpl, want := range cases {
		body := tmpl
		app := &App{Dir: t.TempDir()}
		page := &Page{Route: "/"}
		ctx := &RenderContext{Data: map[string]any{}}
		got, err := renderGoTemplate(app, page, ctx, &Frontmatter{}, body)
		if err != nil {
			t.Errorf("render %q error: %s", tmpl, err)
			continue
		}
		if got != want {
			t.Errorf("render %q = %q, want %q", tmpl, got, want)
		}
	}
}

func TestGotmplHelpers_SprigStringsAvailable(t *testing.T) {
	cases := map[string]string{
		`{{upper "hi"}}`:                                "HI",
		`{{lower "HELLO"}}`:                             "hello",
		`{{title "hello world"}}`:                       "Hello World",
		`{{trim "  spaces  "}}`:                         "spaces",
		`{{replace "x" "y" "axb"}}`:                     "ayb",
		`{{contains "ell" "hello"}}`:                    "true",
		`{{hasPrefix "he" "hello"}}`:                    "true",
		`{{hasSuffix "lo" "hello"}}`:                    "true",
		`{{default "fallback" ""}}`:                     "fallback",
		`{{default "fallback" "actual"}}`:               "actual",
		`{{repeat 3 "ab"}}`:                             "ababab",
		`{{join ", " (list "a" "b" "c")}}`:              "a, b, c",
	}
	for tmpl, want := range cases {
		body := tmpl
		app := &App{Dir: t.TempDir()}
		page := &Page{Route: "/"}
		ctx := &RenderContext{Data: map[string]any{}}
		got, err := renderGoTemplate(app, page, ctx, &Frontmatter{}, body)
		if err != nil {
			t.Errorf("render %q error: %s", tmpl, err)
			continue
		}
		if got != want {
			t.Errorf("render %q = %q, want %q", tmpl, got, want)
		}
	}
}

func TestGotmplHelpers_SprigCollections(t *testing.T) {
	body := `{{$xs := list 1 2 3}}{{len $xs}}-{{first $xs}}-{{last $xs}}`
	app := &App{Dir: t.TempDir()}
	page := &Page{Route: "/"}
	ctx := &RenderContext{Data: map[string]any{}}
	got, err := renderGoTemplate(app, page, ctx, &Frontmatter{}, body)
	if err != nil {
		t.Fatalf("render error: %s", err)
	}
	if got != "3-1-3" {
		t.Errorf("got %q, want %q", got, "3-1-3")
	}
}

func TestGotmplHelpers_FrameworkOverridesEnv(t *testing.T) {
	// Sprig's `env` reads from OS environment. Our override reads
	// from per-app env.yaml — that's the framework convention and
	// the agent's intuition.
	dir := t.TempDir()
	envPath := filepath.Join(dir, "env.yaml")
	if err := os.WriteFile(envPath, []byte("MY_KEY: hello-world\n"), 0644); err != nil {
		t.Fatal(err)
	}
	body := `{{env "MY_KEY"}}`
	app := &App{Dir: dir}
	page := &Page{Route: "/"}
	ctx := &RenderContext{Data: map[string]any{}}
	got, err := renderGoTemplate(app, page, ctx, &Frontmatter{}, body)
	if err != nil {
		t.Fatalf("render error: %s", err)
	}
	if got != "hello-world" {
		t.Errorf("got %q, want hello-world — framework env override didn't take", got)
	}
}

func TestIsSingleRowQuery(t *testing.T) {
	cases := map[string]bool{
		"SELECT * FROM users WHERE id = 1 LIMIT 1":     true,
		"SELECT * FROM users WHERE id = 1 LIMIT 1;":    true,
		"select * from users limit 1":                  true,
		"SELECT * FROM users LIMIT  1":                 true, // multiple spaces
		"SELECT * FROM users":                          false,
		"SELECT * FROM users LIMIT 10":                 false,
		"SELECT * FROM users LIMIT 1 OFFSET 5":         false, // not a bare LIMIT 1
		"SELECT * FROM users WHERE name = 'limit 1'":   false, // string literal
	}
	for sql, want := range cases {
		if got := isSingleRowQuery(sql); got != want {
			t.Errorf("isSingleRowQuery(%q) = %v, want %v", sql, got, want)
		}
	}
}

func TestRenderGoTemplate_SingleRowQueryReturnsMap(t *testing.T) {
	// Simulates the scenario Haiku hit: a singleton profile query
	// that returns 0 rows. With the LIMIT 1 contract, .profile is
	// an empty map and .profile.bio resolves silently to "" via
	// missingkey=zero — no template crash.
	body := `bio: [{{.profile.bio}}], theme: [{{.profile.theme}}]`
	app := &App{Dir: t.TempDir()}
	page := &Page{Route: "/"}
	// Hand-set the data shape the renderer would produce for a
	// zero-row LIMIT 1 query. This test doesn't exercise the SQL
	// path; runFrontmatterQuery is tested via the example app.
	ctx := &RenderContext{Data: map[string]any{
		"profile": map[string]any{}, // empty map, NOT nil, NOT a slice
	}}
	got, err := renderGoTemplate(app, page, ctx, &Frontmatter{}, body)
	if err != nil {
		t.Fatalf("empty map should render cleanly, got: %s", err)
	}
	if got != "bio: [], theme: []" {
		t.Errorf("got %q", got)
	}
}

func TestRenderGoTemplate_SingleRowQueryPopulated(t *testing.T) {
	body := `bio: [{{.profile.bio}}], theme: [{{.profile.theme}}]`
	app := &App{Dir: t.TempDir()}
	page := &Page{Route: "/"}
	ctx := &RenderContext{Data: map[string]any{
		"profile": map[string]any{
			"bio":   "hello",
			"theme": "dark",
		},
	}}
	got, err := renderGoTemplate(app, page, ctx, &Frontmatter{}, body)
	if err != nil {
		t.Fatalf("populated map should render cleanly, got: %s", err)
	}
	if got != "bio: [hello], theme: [dark]" {
		t.Errorf("got %q", got)
	}
}

func TestResolveBind_KnownNames(t *testing.T) {
	ctx := &RenderContext{
		User: &Session{UserID: 42, Email: "x@y.z", Role: "admin", GroupID: "7"},
	}
	if v, ok := resolveBind(ctx, "user_id"); !ok || v != int64(42) {
		t.Errorf("user_id bind: got %v ok=%v", v, ok)
	}
	if v, ok := resolveBind(ctx, "user_email"); !ok || v != "x@y.z" {
		t.Errorf("user_email bind: got %v ok=%v", v, ok)
	}
	if _, ok := resolveBind(ctx, "totally_made_up"); ok {
		t.Errorf("unknown bind should return ok=false so the SQL error stays honest")
	}
}
