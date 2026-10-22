//go:build !cli

package main

// HTML-aware rendering for author templates that become an HTML email: a
// hook's `email:` body (inline `body:` or emails/<template>.html) and a
// `run: email` step's inline `html:`. Row values and request fields were
// substituted verbatim, so a submitted name of
// `<a href="https://evil.example">Reset your password</a>` became a real
// link in mail the app sends from its own domain, and a legitimate `&` or
// `<` produced broken markup.
//
// A `{{ref}}` value (and, in a flow, a `:param`) is now escaped for the HTML
// context it lands in, with the page renderer's own rules (template_context.go):
// text and attribute values are entity-escaped, a URL attribute also loses a
// script-capable scheme. Markup has to be asked for, as in page and email
// templates:
//
//	{{{ref}}}    HTML, sanitized (scripts and event handlers removed)
//	{{{{ref}}}}  the value exactly as it is
//
// The author also decides where else markup may come from a value:
//
//   - a body that is exactly one reference (`html: "{{ steps.render.outputs.html }}"`,
//     a hook `body: "{{html}}"`) is that value as it is: the value IS the
//     document, built by the app;
//   - an env value is the app's own configuration (`{{env.FOOTER_HTML}}`);
//   - in a flow, a reference whose last pipe is `raw` (a marker that changes
//     nothing anywhere else, so the same template renders alike on a runtime
//     without this file) or a markdown pipe (already sanitized HTML) is
//     written as is, and `| nl2br` escapes the value and then turns its
//     newlines into <br>.
//
// A flow email's `text:` body and every subject, recipient and header are
// plain text and keep verbatim substitution (SendEmailOpts strips CR/LF from
// headers). Values are written once and never scanned again.

import (
	"fmt"
	"strings"
)

// htmlPlaceholderAt parses a `{{…}}`, `{{{…}}}` or `{{{{…}}}}` placeholder
// starting at template[i]: its inner text, brace count and total length.
func htmlPlaceholderAt(template string, i int) (inner string, braces, n int, ok bool) {
	if i+1 >= len(template) || template[i] != '{' || template[i+1] != '{' {
		return "", 0, 0, false
	}
	for _, b := range []int{4, 3, 2} {
		if !strings.HasPrefix(template[i:], "{{{{"[:b]) {
			continue
		}
		if end := strings.Index(template[i+b:], "}}}}"[:b]); end >= 0 {
			return template[i+b : i+b+end], b, end + 2*b, true
		}
	}
	return "", 0, 0, false
}

// htmlPlaceholderValue renders one resolved value for the context c is in.
func htmlPlaceholderValue(c *htmlCtx, val any, s string, braces int, rawPipe bool) string {
	switch {
	case braces == 4:
		return s
	case rawPipe && c.writesHTML():
		return s
	case braces == 3 && c.writesHTML():
		return SanitizeHTML(s)
	}
	return escapeMustacheValue(c, val, s, false)
}

// htmlLastPipe splits a `{{ }}` expression at its last single `|` (a pipe,
// not the `||` fallback operator) outside quotes: the expression before it
// and the pipe's name. ok is false when the expression has no pipe.
func htmlLastPipe(expr string) (head, pipe string, ok bool) {
	quote := byte(0)
	last := -1
	for i := 0; i < len(expr); i++ {
		c := expr[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '|':
			if i+1 < len(expr) && expr[i+1] == '|' {
				i++
				continue
			}
			last = i
		}
	}
	if last < 0 {
		return expr, "", false
	}
	name, _, _ := splitPipeNameArg(expr[last+1:])
	return strings.TrimSpace(expr[:last]), name, true
}

// soleRowRef reports a hook body that is exactly one `{{column}}`.
func soleRowRef(template string) bool {
	t := strings.TrimSpace(template)
	return strings.HasPrefix(t, "{{") && strings.HasSuffix(t, "}}") && !strings.HasPrefix(t, "{{{") &&
		strings.Count(t, "{{") == 1 && strings.Count(t, "}}") == 1
}

// interpolateRowHTML is interpolateRow for a hook email body.
func interpolateRowHTML(template string, row map[string]any, appDir string) string {
	if !strings.Contains(template, "{{") {
		return template
	}
	if soleRowRef(template) {
		// The value is the whole document.
		return interpolateRow(template, row, appDir)
	}
	var env map[string]string
	var b strings.Builder
	c := &htmlCtx{}
	write := func(s string) {
		b.WriteString(s)
		c.feedString(s)
	}
	i := 0
	for i < len(template) {
		if inner, braces, n, ok := htmlPlaceholderAt(template, i); ok {
			name := inner
			if braces > 2 {
				name = strings.TrimSpace(inner)
			}
			if val, found := row[name]; found {
				write(htmlPlaceholderValue(c, val, fmt.Sprintf("%v", val), braces, false))
				i += n
				continue
			}
			if key, isEnv := strings.CutPrefix(name, "env."); isEnv && braces == 2 {
				if env == nil {
					env = AppEnvSnapshot(appDir)
				}
				if val, found := env[key]; found {
					write(val)
					i += n
					continue
				}
			}
		}
		b.WriteByte(template[i])
		c.feed(template[i])
		i++
	}
	return b.String()
}

// interpolateCtxHTML is interpolateCtx for a flow email's inline `html:`.
func interpolateCtxHTML(template string, ctx *FlowContext) string {
	if _, sole := soleFlowExpr(template); sole && !strings.HasPrefix(strings.TrimSpace(template), "{{{") {
		// The value is the whole document.
		return interpolateCtx(template, ctx)
	}
	flatData := flatDataForCtx(ctx)
	var b strings.Builder
	c := &htmlCtx{}
	write := func(s string) {
		b.WriteString(s)
		c.feedString(s)
	}
	i := 0
	for i < len(template) {
		if n, val, ok := colonParamAt(template, i, ctx.Params); ok {
			write(escapeMustacheValue(c, val, val, false))
			i += n
			continue
		}
		if inner, braces, n, ok := htmlPlaceholderAt(template, i); ok {
			expr := strings.TrimSpace(inner)
			head, pipe, piped := htmlLastPipe(expr)
			// `| nl2br` adds markup of its own: resolve what is before
			// it, escape that, then add the <br>s.
			breaks := piped && pipe == "nl2br" && braces == 2
			resolve := expr
			if breaks {
				resolve = head
			}
			if val, resolved := resolveBindExpr(resolve, flatData); resolved {
				if val != nil {
					text := fmt.Sprintf("%v", val)
					switch {
					case breaks:
						text = escapeMustacheValue(c, val, text, false)
						if c.writesHTML() {
							text = strings.ReplaceAll(text, "\n", "<br>")
						}
						write(text)
					case flowExprIsEnvOnly(expr) && c.writesHTML():
						write(text)
					default:
						rawPipe := piped && (pipe == "raw" || isRawHTMLPipe(pipe))
						write(htmlPlaceholderValue(c, val, text, braces, rawPipe))
					}
				}
				i += n
				continue
			}
			if braces == 2 {
				// Unresolved: recorded so the step halts, as in interpolateCtx.
				ctx.noteMissingRef(expr)
			}
		}
		b.WriteByte(template[i])
		c.feed(template[i])
		i++
	}
	return b.String()
}
