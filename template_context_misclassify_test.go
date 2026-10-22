//go:build !cli

package main

import (
	"html"
	"strings"
	"testing"
)

// Places where the context tokenizer disagreed with the browser, so a
// {{var}} got weaker escaping than the context it really landed in:
//
//   - comments the browser closes early (`<!-->`, `<!--->`, `--!>`), after
//     which the tokenizer still thought it was inside the comment;
//   - <script> types browsers run as JavaScript but the tokenizer treated
//     as inert (text/jscript, text/javascript1.5, ...);
//   - `a++ / {{v}}`, where the tokenizer read the division as a regex;
//   - srcdoc, whose value is decoded once and then parsed as a document.
func TestMustacheContextMatchesBrowserParsing(t *testing.T) {
	for _, tmpl := range []string{
		`<!--><a href="{{u}}">x</a>`,
		`<!---><a href="{{u}}">x</a>`,
		`<!-- note --!><a href="{{u}}">x</a>`,
	} {
		out := RenderMustache(tmpl, map[string]any{"u": "javascript:alert(1)"})
		if strings.Contains(out, "javascript:") {
			t.Errorf("%s -> %s: script URL kept after a comment the browser has closed", tmpl, out)
		}
	}
	// A comment that is still open keeps plain escaping.
	if out := RenderMustache(`<!-- {{u}} -->`, map[string]any{"u": "a<b"}); out != `<!-- a&lt;b -->` {
		t.Errorf("open comment rendering changed: %s", out)
	}

	for _, typ := range []string{"text/jscript", "text/livescript", "text/javascript1.5", "application/x-ecmascript", "text/x-ecmascript"} {
		tmpl := `<script type="` + typ + `">var n = {{v}};</script>`
		out := RenderMustache(tmpl, map[string]any{"v": "1;alert(1)"})
		if !strings.Contains(out, `var n = "1;alert(1)";`) {
			t.Errorf("type %s: value not encoded as a JS string: %s", typ, out)
		}
	}
	// The browser uses a tag's first type attribute.
	if out := RenderMustache(`<script type="module" type="text/x-template">var n = {{v}};</script>`, map[string]any{"v": "1;alert(1)"}); !strings.Contains(out, `var n = "1;alert(1)";`) {
		t.Errorf("duplicate type: value not encoded as a JS string: %s", out)
	}
	// Types the browser does not execute keep HTML escaping.
	if out := RenderMustache(`<script type="text/x-template"><b>{{v}}</b></script>`, map[string]any{"v": "a<b"}); !strings.Contains(out, "<b>a&lt;b</b>") {
		t.Errorf("inert template script changed: %s", out)
	}

	for _, tmpl := range []string{`<script>var r = a++ / {{v}};</script>`, `<script>var r = a-- / {{v}};</script>`} {
		out := RenderMustache(tmpl, map[string]any{"v": "1;alert(1)"})
		if !strings.Contains(out, `/ "1;alert(1)";`) {
			t.Errorf("%s -> %s: division operand not encoded as an expression", tmpl, out)
		}
	}
	// A regex after a prefix/infix operator is still a regex.
	if out := RenderMustache(`<script>var r = x + /{{v}}/;</script>`, map[string]any{"v": "a'b"}); !strings.Contains(out, "+ /a\\u0027b/;") {
		t.Errorf("regex after + lost its regex escaping: %s", out)
	}

	out := RenderMustache(`<iframe srcdoc="{{h}}"></iframe>`, map[string]any{"h": `<script>alert(1)</script>`})
	start := strings.Index(out, `srcdoc="`) + len(`srcdoc="`)
	value := out[start : start+strings.Index(out[start:], `"`)]
	if doc := html.UnescapeString(value); strings.Contains(doc, "<script") {
		t.Errorf("srcdoc value decodes to markup: %s", doc)
	}
}
