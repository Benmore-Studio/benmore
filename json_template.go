//go:build !cli

package main

// JSON-aware rendering for author templates that become a JSON document:
// a hook's `body:` and `ws:` `payload:`, a legacy `ws:` step's payload and
// a `run: webhook` `body:`. Verbatim substitution let a value holding a
// quote close its string and add or override keys of the outbound body, or
// of the message every room member receives; a legitimate quote, backslash
// or newline made the JSON invalid.
//
// The decision is made on the author's template alone: it is a JSON document
// when it starts with `{`, `[` or `"` and stays valid JSON with every
// `{{...}}` placeholder replaced by a neutral value (nothing inside a string,
// `0` elsewhere). Then a placeholder inside a JSON string literal is written
// JSON-string-escaped, and one in a value position is written as one JSON
// value: its text when that is already exactly one JSON value (a number,
// true/false, JSON text such as a json_group_array() column), null for no
// value, a JSON array/object for a list or map, otherwise a JSON string. A
// `:param` is substituted only inside a string literal (escaped); outside one,
// `:` is the key separator. Any other template (plain text, a single
// placeholder, a fragment that splices raw JSON) renders verbatim exactly as
// before. Values are written once and never scanned again (single-pass, see
// interpolateCtx).

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

// jsonTemplatePart is one piece of an author's template: a literal run, a
// `{{...}}` placeholder (ref holds its inner text) or a `:param` placeholder
// inside a string literal.
type jsonTemplatePart struct {
	text     string
	ref      string
	isRef    bool
	colon    bool
	inString bool
}

// jsonTemplateParts splits template into parts and reports whether it is a
// JSON document. colonAt, when set, returns the length of a `:param` token
// at template[i] (0 for none); it is consulted only inside string literals.
func jsonTemplateParts(template string, colonAt func(string, int) int) ([]jsonTemplatePart, bool) {
	trimmed := strings.TrimLeft(template, " \t\r\n")
	if trimmed == "" || strings.HasPrefix(trimmed, "{{") || !strings.ContainsRune("{[\"", rune(trimmed[0])) {
		return nil, false
	}
	var parts []jsonTemplatePart
	var skeleton strings.Builder
	inString := false
	lit := 0
	flush := func(end int) {
		if end > lit {
			parts = append(parts, jsonTemplatePart{text: template[lit:end]})
			skeleton.WriteString(template[lit:end])
		}
	}
	i := 0
	for i < len(template) {
		if i+2 < len(template) && template[i] == '{' && template[i+1] == '{' {
			if end := strings.Index(template[i+2:], "}}"); end >= 0 {
				flush(i)
				n := end + 4
				parts = append(parts, jsonTemplatePart{text: template[i : i+n], ref: template[i+2 : i+2+end], isRef: true, inString: inString})
				if !inString {
					skeleton.WriteString("0")
				}
				i += n
				lit = i
				continue
			}
		}
		c := template[i]
		if inString {
			if colonAt != nil && c == ':' {
				if n := colonAt(template, i); n > 0 {
					flush(i)
					parts = append(parts, jsonTemplatePart{text: template[i : i+n], colon: true, inString: true})
					i += n
					lit = i
					continue
				}
			}
			switch c {
			case '\\':
				i += 2
				continue
			case '"':
				inString = false
			}
		} else if c == '"' {
			inString = true
		}
		i++
	}
	if i > len(template) {
		i = len(template)
	}
	flush(i)
	return parts, json.Valid([]byte(skeleton.String()))
}

// writeJSONStringContent writes s as the inside of a JSON string literal.
func writeJSONStringContent(b *strings.Builder, s string) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if enc.Encode(s) != nil {
		return
	}
	out := bytes.TrimSuffix(buf.Bytes(), []byte("\n"))
	if len(out) >= 2 {
		b.Write(out[1 : len(out)-1])
	}
}

// writeJSONValue writes one JSON value for a placeholder in a value position.
// raw is the text verbatim substitution produced.
func writeJSONValue(b *strings.Builder, val any, raw string) {
	if val == nil {
		b.WriteString("null")
		return
	}
	switch reflect.ValueOf(val).Kind() {
	case reflect.Map, reflect.Slice, reflect.Array:
		if _, isBytes := val.([]byte); !isBytes {
			var buf bytes.Buffer
			enc := json.NewEncoder(&buf)
			enc.SetEscapeHTML(false)
			if enc.Encode(val) == nil {
				b.Write(bytes.TrimSuffix(buf.Bytes(), []byte("\n")))
				return
			}
		}
	}
	if json.Valid([]byte(raw)) {
		b.WriteString(raw)
		return
	}
	b.WriteByte('"')
	writeJSONStringContent(b, raw)
	b.WriteByte('"')
}

// writeJSONPlaceholder writes a resolved placeholder in its slot.
func writeJSONPlaceholder(b *strings.Builder, p jsonTemplatePart, val any, raw string) {
	if p.inString {
		writeJSONStringContent(b, raw)
		return
	}
	writeJSONValue(b, val, raw)
}

// writeJSONUnresolved keeps an unresolved placeholder's text, as verbatim
// substitution does, without letting it end a string literal.
func writeJSONUnresolved(b *strings.Builder, p jsonTemplatePart) {
	if p.inString {
		writeJSONStringContent(b, p.text)
		return
	}
	b.WriteString(p.text)
}

// interpolateCtxJSON is interpolateCtx for a template whose output is a
// JSON body or message.
func interpolateCtxJSON(template string, ctx *FlowContext) string {
	parts, isJSON := jsonTemplateParts(template, func(t string, i int) int {
		n, _, ok := colonParamAt(t, i, ctx.Params)
		if !ok {
			return 0
		}
		return n
	})
	if !isJSON {
		return interpolateCtx(template, ctx)
	}
	flatData := flatDataForCtx(ctx)
	var b strings.Builder
	for _, p := range parts {
		switch {
		case p.colon:
			_, val, _ := colonParamAt(p.text, 0, ctx.Params)
			writeJSONStringContent(&b, val)
		case p.isRef:
			expr := strings.TrimSpace(p.ref)
			val, ok := resolveBindExpr(expr, flatData)
			if !ok {
				ctx.noteMissingRef(expr)
				writeJSONUnresolved(&b, p)
				continue
			}
			raw := ""
			if val != nil {
				raw = fmt.Sprintf("%v", val)
			}
			writeJSONPlaceholder(&b, p, val, raw)
		default:
			b.WriteString(p.text)
		}
	}
	return b.String()
}

// interpolateRowJSONWithEnv is interpolateRowWithEnv for a template whose
// output is a JSON body or message.
func interpolateRowJSONWithEnv(template string, row map[string]any, env map[string]string, appDir string) string {
	parts, isJSON := jsonTemplateParts(template, nil)
	if !isJSON {
		return interpolateRowWithEnv(template, row, env, appDir)
	}
	var b strings.Builder
	for _, p := range parts {
		if !p.isRef {
			b.WriteString(p.text)
			continue
		}
		if val, ok := row[p.ref]; ok {
			writeJSONPlaceholder(&b, p, val, fmt.Sprintf("%v", val))
			continue
		}
		if key, ok := strings.CutPrefix(p.ref, "env."); ok {
			if env == nil {
				env = AppEnvSnapshot(appDir)
			}
			if val, ok := env[key]; ok {
				writeJSONPlaceholder(&b, p, val, val)
				continue
			}
		}
		writeJSONUnresolved(&b, p)
	}
	return b.String()
}

// interpolateRowJSONForApp is interpolateRowForApp for a JSON template.
func interpolateRowJSONForApp(template string, row map[string]any, app *App) string {
	if app == nil {
		return interpolateRowJSONWithEnv(template, row, map[string]string{}, "")
	}
	app.mu.RLock()
	env := app.environment
	app.mu.RUnlock()
	if env != nil {
		return interpolateRowJSONWithEnv(template, row, env, "")
	}
	return interpolateRowJSONWithEnv(template, row, nil, app.Dir)
}
