//go:build !cli

package main

import (
	"errors"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	ttemplate "text/template"
	"time"
)

const gotmplTestSecret = "gotmpl-router-secret-7f3a"

func renderGotmplForTest(t *testing.T, body string) (string, error) {
	t.Helper()
	app := &App{Dir: t.TempDir()}
	return renderGoTemplate(app, &Page{Route: "/t"}, &RenderContext{Data: map[string]any{}}, &Frontmatter{Engine: "gotmpl"}, body)
}

func gotmplPage(body string) string {
	return "---\nengine: gotmpl\n---\n" + body
}

// expandenv / getHostByName / key generation are gone from the render map,
// so a page using them fails to parse instead of reading the process
// environment or resolving DNS.
func TestGotmplHelpersExcludeNonHermeticSprig(t *testing.T) {
	fm := gotmplHelpers(nil, nil)
	for _, name := range gotmplRemovedSprigFuncs {
		if name == "env" {
			continue // replaced by the framework's env.yaml lookup
		}
		if _, ok := fm[name]; ok {
			t.Errorf("gotmpl helper %q must not be available", name)
		}
	}
	t.Setenv("GOTMPL_TEST_SECRET", gotmplTestSecret)
	for _, body := range []string{
		`{{expandenv "$GOTMPL_TEST_SECRET"}}`,
		`{{getHostByName "example.com"}}`,
		`{{genPrivateKey "rsa"}}`,
	} {
		out, err := renderGotmplForTest(t, body)
		if err == nil || !strings.Contains(err.Error(), "not defined") {
			t.Errorf("render %s: want undefined-function error, got out=%q err=%v", body, out, err)
		}
	}
	// The framework `env` reads env.yaml, never the process environment.
	out, err := renderGotmplForTest(t, `[{{env "GOTMPL_TEST_SECRET"}}]`)
	if err != nil || out != "[]" {
		t.Fatalf("env must not read the process environment: out=%q err=%v", out, err)
	}
}

func TestGotmplValidationNeverSeesProcessEnv(t *testing.T) {
	t.Setenv("GOTMPL_TEST_SECRET", gotmplTestSecret)
	for _, body := range []string{
		`{{ fail (expandenv "$GOTMPL_TEST_SECRET") }}`,
		`{{ fail (env "GOTMPL_TEST_SECRET") }}`,
		`{{ getHostByName "example.com" }}`,
	} {
		msg := validateGotmplParseIn(t.TempDir(), "index.html", gotmplPage(body))
		if strings.Contains(msg, gotmplTestSecret) {
			t.Fatalf("validation of %s leaked the process environment: %s", body, msg)
		}
		if strings.Contains(body, "expandenv") || strings.Contains(body, "getHostByName") {
			if !strings.Contains(msg, "not defined") {
				t.Errorf("validation of %s: want undefined-function error, got %q", body, msg)
			}
		}
	}
}

func TestGotmplCapsRefuseHugeAllocations(t *testing.T) {
	for _, body := range []string{
		`{{range until 1000000000}}x{{end}}`,
		`{{range untilStep 0 2000000000 1}}x{{end}}`,
		`{{seq 1000000000}}`,
		`{{repeat 1000000000 "abc"}}`,
		`{{indent 100000000 "a\nb"}}`,
		`{{replace "" (repeat 4000 "x") (repeat 4000 "y")}}`,
		`{{randAlpha 1000000000}}`,
		`{{regexReplaceAll "" (repeat 4000 "a") (repeat 4000 "b")}}`,
	} {
		start := time.Now()
		_, err := renderGotmplForTest(t, body)
		if err == nil || !strings.Contains(err.Error(), "limit") {
			t.Errorf("render %s: want size-limit error, got %v", body, err)
		}
		if time.Since(start) > 2*time.Second {
			t.Errorf("render %s took %s", body, time.Since(start))
		}
	}
	// In-bounds calls behave exactly like Sprig.
	out, err := renderGotmplForTest(t, `{{range until 3}}{{.}}{{end}}|{{seq 3}}|{{repeat 2 "ab"}}|{{indent 2 "a\nb"}}|{{replace "a" "b" "aa"}}`)
	if err != nil || out != "012|1 2 3|abab|  a\n  b|bb" {
		t.Fatalf("in-bounds helpers: out=%q err=%v", out, err)
	}
}

func TestGotmplRegexReplaceMatchesStdlib(t *testing.T) {
	fm := gotmplSprigFuncs()
	expand := fm["regexReplaceAll"].(func(string, string, string) (string, error))
	literal := fm["regexReplaceAllLiteral"].(func(string, string, string) (string, error))
	cases := []struct{ re, s, repl string }{
		{`a(x*)b`, "-ab-axxb-", "${1}W"},
		{`a*`, "baaac", "X"},
		{``, "abc", "-"},
		{`(\w+)@(\w+)`, "me@here you@there", "$2.$1"},
	}
	for _, c := range cases {
		re := regexp.MustCompile(c.re)
		if got, err := expand(c.re, c.s, c.repl); err != nil || got != re.ReplaceAllString(c.s, c.repl) {
			t.Errorf("regexReplaceAll(%q,%q,%q) = %q, %v; want %q", c.re, c.s, c.repl, got, err, re.ReplaceAllString(c.s, c.repl))
		}
		if got, err := literal(c.re, c.s, c.repl); err != nil || got != re.ReplaceAllLiteralString(c.s, c.repl) {
			t.Errorf("regexReplaceAllLiteral(%q,%q,%q) = %q, %v", c.re, c.s, c.repl, got, err)
		}
	}
}

// Write-time validation runs in the router: loops, recursion and doubling
// must stop within the budget instead of stalling the process.
func TestGotmplValidationIsBounded(t *testing.T) {
	for _, body := range []string{
		`{{range 2000000000}}{{range 2000000000}}{{end}}{{end}}`,
		`{{range until 100000}}{{range until 100000}}{{end}}{{end}}`,
		`{{define "a"}}{{if lt (len .) 60}}{{template "a" (printf "%sx" .)}}{{template "a" (printf "%sx" .)}}{{end}}{{end}}{{template "a" "x"}}`,
		`{{define "b"}}{{if lt (len .) 60}}{{template "b" (cat . "x")}}{{template "b" (cat . "x")}}{{end}}{{end}}{{template "b" "x"}}`,
		`{{define "c"}}{{if lt (len .) 1000000000}}{{template "c" (cat . .)}}{{end}}{{end}}{{template "c" "x"}}`,
		`{{range until 100000}}{{bcrypt "x"}}{{end}}`,
		`{{range until 100000}}{{repeat 1000 "x"}}{{end}}`,
		`{{printf (repeat 4000 "%999999d") 1}}`,
	} {
		start := time.Now()
		msg := validateGotmplParseIn(t.TempDir(), "index.html", gotmplPage(body))
		if took := time.Since(start); took > gotmplValidateTimeout+3*time.Second {
			t.Errorf("validation of %s took %s", body, took)
		}
		if msg != "" {
			t.Errorf("budget exhaustion must not be reported as a template error for %s: %s", body, msg)
		}
	}
}

// The bounded pass still reports template-intrinsic execute errors and
// html/template escaping errors.
func TestGotmplValidationStillReportsErrors(t *testing.T) {
	for body, want := range map[string]string{
		`{{$x := dict "only_one_arg"}}{{$x}}`:                   "even number",
		`{{env "A" "B"}}`:                                       "wrong number of args",
		`{{range until 3}}{{dict "odd"}}{{end}}`:                "even number",
		`<a href="{{if .x}}/a{{else}}/b?q={{end}}{{.y}}">x</a>`: "ambiguous",
	} {
		msg := validateGotmplParseIn(t.TempDir(), "index.html", gotmplPage(body))
		if !strings.Contains(msg, want) {
			t.Errorf("validation of %s: want %q in message, got %q", body, want, msg)
		}
	}
}

func TestGotmplPartialsDoNotFollowSymlinksOutOfApp(t *testing.T) {
	base := t.TempDir()
	outside := filepath.Join(base, "outside.html")
	if err := os.WriteFile(outside, []byte(`{{define "leak"}}`+gotmplTestSecret+`{{end}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	appDir := filepath.Join(base, "app")
	if err := os.MkdirAll(filepath.Join(appDir, "partials"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(appDir, "shared.html"), []byte(`{{define "ok"}}inside{{end}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(appDir, "partials", "leak.html")); err != nil {
		t.Skip("symlinks unavailable:", err)
	}
	if err := os.Symlink(filepath.Join("..", "shared.html"), filepath.Join(appDir, "partials", "ok.html")); err != nil {
		t.Fatal(err)
	}
	got := readGotmplPartials(appDir)
	if _, ok := got["leak.html"]; ok {
		t.Fatal("a partial symlinked outside the app must not be read")
	}
	if !strings.Contains(got["ok.html"], "inside") {
		t.Fatalf("a symlink that stays inside the app should still be read: %v", got)
	}

	// Render: the escaping partial is not registered, the in-app one is.
	app := &App{Dir: appDir}
	out, err := renderGoTemplate(app, &Page{Route: "/t"}, &RenderContext{Data: map[string]any{}}, &Frontmatter{Engine: "gotmpl"}, `{{template "ok"}}`)
	if err != nil || out != "inside" {
		t.Fatalf("in-app partial render: out=%q err=%v", out, err)
	}
	if out, err := renderGoTemplate(app, &Page{Route: "/t"}, &RenderContext{Data: map[string]any{}}, &Frontmatter{Engine: "gotmpl"}, `{{template "leak"}}`); err == nil || strings.Contains(out, gotmplTestSecret) {
		t.Fatalf("outside partial rendered: out=%q err=%v", out, err)
	}

	// A partials/ directory that is itself a symlink out of the app is not read.
	app2 := filepath.Join(base, "app2")
	if err := os.MkdirAll(app2, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(base, filepath.Join(app2, "partials")); err != nil {
		t.Fatal(err)
	}
	if got := readGotmplPartials(app2); len(got) != 0 {
		t.Fatalf("symlinked partials/ dir must not be read: %v", got)
	}
}

func TestGotmplRenderOutputIsBounded(t *testing.T) {
	w := &gotmplLimitWriter{limit: 10}
	if _, err := w.Write(make([]byte, 8)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, 8)); err != errGotmplOutputLimit {
		t.Fatalf("want output limit error, got %v", err)
	}
	_ = template.HTML("")
}

// text/template's builtin escapers (html, js, urlquery) format all their
// arguments into one string before escaping it. In the router's validation
// pass they must be charged and size-checked like every other helper, or a
// single call over many references to one in-cap string allocates any
// multiple of the cap.
func TestGotmplValidationBoundsBuiltinEscapers(t *testing.T) {
	for _, fn := range []string{"html", "js", "urlquery"} {
		b := &gotmplValidateBudget{deadline: time.Now().Add(time.Minute)}
		tmpl, err := ttemplate.New("p").Funcs(gotmplValidationFuncs(b)).Parse(`{{$x := repeat 4000000 "a"}}{{` + fn + ` $x $x}}`)
		if err != nil {
			t.Fatal(err)
		}
		if err := tmpl.Execute(io.Discard, nil); !errors.Is(err, errGotmplLimit) {
			t.Errorf("%s over 8 MB of arguments: want the size limit, got %v", fn, err)
		}
	}
	b := &gotmplValidateBudget{deadline: time.Now().Add(time.Minute)}
	tmpl, err := ttemplate.New("p").Funcs(gotmplValidationFuncs(b)).Parse(`{{html "<a>"}}|{{js "'"}}|{{urlquery "a b"}}`)
	if err != nil {
		t.Fatal(err)
	}
	var out strings.Builder
	if err := tmpl.Execute(&out, nil); err != nil || out.String() != `&lt;a&gt;|\'|a+b` {
		t.Fatalf("in-bounds escapers: out=%q err=%v", out.String(), err)
	}
	if msg := validateGotmplParseIn(t.TempDir(), "index.html", gotmplPage(`<p>{{.x | html}}</p><a href="/s?q={{.y | urlquery}}">s</a>`)); msg != "" {
		t.Fatalf("escapers over runtime data must still validate: %s", msg)
	}
}
