//go:build !cli

package main

import (
	"encoding/json"
	"html"
	"regexp"
	"strings"
	"testing"
)

// TestMustacheURLAttributesNeutralizeScriptSchemes pins item 24 (URL half):
// `{{var}}` was HTML-escaped only, so a stored `javascript:` value in href/src
// ran when the link was followed.
func TestMustacheURLAttributesNeutralizeScriptSchemes(t *testing.T) {
	blocked := []struct{ tmpl, val string }{
		{`<a href="{{u}}">x</a>`, "javascript:alert(1)"},
		{`<a href="{{u}}">x</a>`, "JaVaScRiPt:alert(1)"},
		{`<a href="{{u}}">x</a>`, " \tjava\nscript:alert(1)"},
		{`<a href='{{u}}'>x</a>`, "vbscript:msgbox(1)"},
		{`<iframe src="{{u}}"></iframe>`, "data:text/html,<script>alert(1)</script>"},
		{`<a href={{u}}>x</a>`, "javascript:alert(1)"},
		{`<form action="{{u}}"></form>`, "javascript:alert(1)"},
		{`<button formaction="{{u}}">x</button>`, "javascript:alert(1)"},
		{`<video poster="{{u}}"></video>`, "javascript:alert(1)"},
		{`<svg><a xlink:href="{{u}}">x</a></svg>`, "javascript:alert(1)"},
		{`<img srcset="{{u}}">`, "/ok.png 1x, javascript:alert(1) 2x"},
		{`<a href="java{{u}}">x</a>`, "script:alert(1)"},
		{`<a class="c" HREF = "{{u}}">x</a>`, "javascript:alert(1)"},
	}
	for _, c := range blocked {
		out := RenderMustache(c.tmpl, map[string]any{"u": c.val})
		if strings.Contains(strings.ToLower(out), "script:") && !strings.Contains(out, "<script>alert") || strings.Contains(out, "alert(1)") && !strings.Contains(out, blockedURL) {
			t.Errorf("%s with %q: script-capable URL survived: %s", c.tmpl, c.val, out)
		}
		if !strings.Contains(out, blockedURL) {
			t.Errorf("%s with %q: want %s marker, got %s", c.tmpl, c.val, blockedURL, out)
		}
	}

	kept := []struct{ tmpl, val, want string }{
		{`<a href="{{u}}">x</a>`, "https://example.com/a?b=1&c=2", `<a href="https://example.com/a?b=1&amp;c=2">x</a>`},
		{`<a href="{{u}}">x</a>`, "/relative/path", `<a href="/relative/path">x</a>`},
		{`<a href="/search?q={{u}}">x</a>`, "javascript:alert(1)", `<a href="/search?q=javascript:alert(1)">x</a>`},
		{`<a href="{{u}}">x</a>`, "mailto:a@example.com", `<a href="mailto:a@example.com">x</a>`},
		{`<img src="{{u}}">`, "data:image/png;base64,iVBORw0KGgo=", `<img src="data:image/png;base64,iVBORw0KGgo=">`},
		{`<a title="{{u}}">x</a>`, "javascript:alert(1)", `<a title="javascript:alert(1)">x</a>`},
	}
	for _, c := range kept {
		if out := RenderMustache(c.tmpl, map[string]any{"u": c.val}); out != c.want {
			t.Errorf("%s with %q:\n got %s\nwant %s", c.tmpl, c.val, out, c.want)
		}
	}
}

// TestMustacheScriptBlocksEncodeValues pins item 24 (script half): inside
// <script>, html.EscapeString does nothing useful, so a value in expression
// position was code and a quote-free payload walked out of a string.
func TestMustacheScriptBlocksEncodeValues(t *testing.T) {
	cases := []struct {
		name, tmpl string
		data       map[string]any
		want       string
	}{
		{"expr string", `<script>var n = {{n}};</script>`, map[string]any{"n": "1;alert(1)"}, `<script>var n = "1;alert(1)";</script>`},
		{"expr number", `<script>var n = {{n}};</script>`, map[string]any{"n": int64(5)}, `<script>var n = 5;</script>`},
		{"expr bool", `<script>var b = {{b}};</script>`, map[string]any{"b": true}, `<script>var b = true;</script>`},
		{"double-quoted string", `<script>var s = "{{s}}";</script>`, map[string]any{"s": `";alert(1);//`}, `<script>var s = "\u0022;alert(1);\u002f\u002f";</script>`},
		{"single-quoted string", `<script>var s = '{{s}}';</script>`, map[string]any{"s": `';alert(1);'`}, `<script>var s = '\u0027;alert(1);\u0027';</script>`},
		{"template literal", "<script>var s = `{{s}}`;</script>", map[string]any{"s": "${alert(1)}`"}, "<script>var s = `\\u0024\\u007balert(1)\\u007d\\u0060`;</script>"},
		{"close script in string", `<script>var s = "{{s}}";</script>`, map[string]any{"s": `</script><script>alert(1)</script>`}, `<script>var s = "\u003c\u002fscript\u003e\u003cscript\u003ealert(1)\u003c\u002fscript\u003e";</script>`},
		{"regex literal", `<script>var r = /{{x}}/;</script>`, map[string]any{"x": `/;alert(1);/`}, `<script>var r = /\u002f;alert(1);\u002f/;</script>`},
		{"division is expression", `<script>var h = total / {{n}};</script>`, map[string]any{"n": "2;alert(1)"}, `<script>var h = total / "2;alert(1)";</script>`},
		{"line comment", "<script>// {{x}}\nok();</script>", map[string]any{"x": "\nalert(1)"}, "<script>// \\u000aalert(1)\nok();</script>"},
		{"json pipe object", `<script>var cfg = {{cfg | json}};</script>`, map[string]any{"cfg": map[string]any{"a": "</script>"}}, `<script>var cfg = {"a":"\u003c\u002fscript\u003e"};</script>`},
		{"section in array", `<script>var ids = [{{#items}}{{id}},{{/items}}];</script>`, map[string]any{"items": []map[string]any{{"id": "a"}, {"id": "b];alert(1);//"}}}, `<script>var ids = ["a","b];alert(1);\u002f\u002f",];</script>`},
		{"module script", `<script type="module">let x = {{x}};</script>`, map[string]any{"x": "1;alert(1)"}, `<script type="module">let x = "1;alert(1)";</script>`},
		{"after script ends", `<script>var a = 1;</script><p>{{x}}</p>`, map[string]any{"x": "<b>"}, `<script>var a = 1;</script><p>&lt;b&gt;</p>`},
		{"triple mustache in script", `<script>var h = {{{h}}};</script>`, map[string]any{"h": "1;alert(1)"}, `<script>var h = "1;alert(1)";</script>`},
	}
	for _, c := range cases {
		if out := RenderMustache(c.tmpl, c.data); out != c.want {
			t.Errorf("%s:\n got %s\nwant %s", c.name, out, c.want)
		}
	}

	// JSON-LD stays valid JSON with a hostile value.
	ld := RenderMustache(`<script type="application/ld+json">{"name": "{{t}}", "n": {{n}}}</script>`,
		map[string]any{"t": `x", "evil": "</script>`, "n": int64(3)})
	body := strings.TrimSuffix(strings.TrimPrefix(ld, `<script type="application/ld+json">`), `</script>`)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil || parsed["name"] != `x", "evil": "</script>` || parsed["n"] != float64(3) || len(parsed) != 2 {
		t.Fatalf("ld+json must stay one valid object, got %s (err %v)", body, err)
	}

	// Event handlers are JavaScript after entity decoding.
	out := RenderMustache(`<button onclick="go('{{n}}', {{n}})">x</button>`, map[string]any{"n": `');alert(1);//`})
	m := regexp.MustCompile(`onclick="([^"]*)"`).FindStringSubmatch(out)
	if m == nil || html.UnescapeString(m[1]) != `go('\u0027);alert(1);\u002f\u002f', "\u0027);alert(1);\u002f\u002f")` {
		t.Fatalf("onclick handler not JS-escaped: %s", out)
	}
}

// TestMustacheBodyRenderingUnchanged: body text, ordinary attributes, inert
// script types and raw-text elements keep html.EscapeString output exactly.
func TestMustacheBodyRenderingUnchanged(t *testing.T) {
	v := `<b>"it's" & {{x}}</b>`
	esc := neutralizeReparse(html.EscapeString(v))
	data := map[string]any{"v": v, "h": "<em>hi</em><script>x()</script>"}
	cases := map[string]string{
		`<p>{{v}}</p>`: `<p>` + esc + `</p>`,
		`<div class="{{v}}" data-x='{{v}}'>{{v}}</div>`: `<div class="` + esc + `" data-x='` + esc + `'>` + esc + `</div>`,
		`<p>{{{h}}}</p>`: `<p>` + neutralizeReparse(SanitizeHTML(data["h"].(string))) + `</p>`,
		`<textarea>{{v}}</textarea><style>{{v}}</style>`: `<textarea>` + esc + `</textarea><style>` + esc + `</style>`,
		`<script type="text/template">{{v}}</script>`:    `<script type="text/template">` + esc + `</script>`,
		`<!-- {{v}} --><p>{{v}}</p>`:                     `<!-- ` + esc + ` --><p>` + esc + `</p>`,
		`{{#items}}<li>{{v}}</li>{{/items}}`:             `<li>` + esc + `</li>`,
		`a < b and {{v}}`:                                `a < b and ` + esc,
		`<input value={{w}}>`:                            `<input value=a&#32;onfocus&#61;alert(1)>`,
	}
	data["items"] = []map[string]any{{}}
	data["w"] = "a onfocus=alert(1)"
	for tmpl, want := range cases {
		if got := RenderMustache(tmpl, data); got != want {
			t.Errorf("%s:\n got %s\nwant %s", tmpl, got, want)
		}
	}

	// <query> bodies are rendered in the context of their position.
	frag := newFragmentRenderer(`<script>var rows = [`)
	if got := frag.render(`{{v}},`, map[string]any{"v": "1;alert(1)"}); got != `"1;alert(1)",` {
		t.Fatalf("query body inside <script> must be JS-encoded, got %s", got)
	}

	// The HTML/TSX stack's include pass does not evaluate mustache at all.
	src := `<script>var x = {{x}};</script><include src="p.html" />`
	if got := ProcessIncludes(src, map[string]string{"p.html": `<a href="{{u}}">`}, t.TempDir()); got != `<script>var x = {{x}};</script><a href="{{u}}">` {
		t.Fatalf("ProcessIncludes changed template text: %s", got)
	}
}
