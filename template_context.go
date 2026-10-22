//go:build !cli

package main

// Context-aware escaping for the mustache renderer (template.go).
//
// html.EscapeString is correct for HTML body text and ordinary quoted
// attributes, and that output stays byte-identical. It is NOT enough in two
// places, where the browser interprets the escaped text as something other
// than HTML:
//
//   - URL-bearing attributes (href, src, action, formaction, srcset, ...):
//     `javascript:alert(1)` contains nothing html.EscapeString touches and
//     runs when the link is followed.
//   - <script> blocks (and on* event-handler attributes): script text is not
//     entity-decoded, so a value in a non-string position (`var n = {{n}};`
//     with n = `1;alert(1)`) is code.
//
// htmlCtx is a small incremental HTML tokenizer fed with the renderer's
// output as it is produced, so each `{{var}}` is escaped for the context it
// actually lands in. Inside script it runs a JS lexer to tell string/
// template/regex/comment positions (escaped as JS string content, no quotes
// added) from expression positions (JSON-encoded value). The gotmpl engine
// uses html/template, which is already context-aware, and is not involved.

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html"
	"strings"
	"unicode/utf8"
)

type htmlState uint8

const (
	hsText htmlState = iota
	hsLt
	hsEndTagOpen
	hsTagName
	hsBeforeAttr
	hsAttrName
	hsAfterAttrName
	hsBeforeAttrValue
	hsAttrValue
	hsSelfClosing
	hsBang
	hsComment
	hsBogusComment
	hsRawText // <script>/<style>/<textarea>/<title>... body until its end tag
)

// scriptKind classifies a <script> body.
type scriptKind uint8

const (
	scriptInert scriptKind = iota // unknown type (client templates etc.) - HTML escaping kept
	scriptJS                      // classic or module JavaScript
	scriptJSON                    // JSON data block (ld+json, importmap, ...)
)

type htmlCtx struct {
	state      htmlState
	tag        []byte // current tag name (lowercase)
	isEnd      bool
	attr       []byte // current attribute name (lowercase)
	quote      byte   // attribute value quote, 0 = unquoted
	attrVal    []byte // attribute value text so far (raw, entity-encoded)
	scriptType string
	typeSet    bool   // the tag's first type attribute was seen (the browser uses the first)
	rawEnd     string // end tag that closes the raw-text element
	script     scriptKind
	endMatch   int // progress matching "</" + rawEnd inside raw text
	bangDash   bool
	dashes     int
	// Comment close tracking: a comment ends at "-->", at "--!>", and at a
	// ">" directly after "<!--" or "<!---" (the browser's abrupt close).
	commentText bool // something other than dashes followed "<!--"
	commentBang bool // "--!" was just seen
	js          jsLexer
}

func (c *htmlCtx) clone() *htmlCtx {
	if c == nil {
		return &htmlCtx{}
	}
	n := *c
	n.tag = append([]byte(nil), c.tag...)
	n.attr = append([]byte(nil), c.attr...)
	n.attrVal = append([]byte(nil), c.attrVal...)
	n.js.tmpl = append([]int(nil), c.js.tmpl...)
	n.js.word = append([]byte(nil), c.js.word...)
	return &n
}

// inScript reports a position inside a JavaScript or JSON <script> body.
func (c *htmlCtx) inScript() bool { return c.state == hsRawText && c.script != scriptInert }

// writesHTML reports a position where markup is being written (body text,
// comments, inert raw text), as opposed to an attribute value or a script.
func (c *htmlCtx) writesHTML() bool {
	return !c.inScript() && c.state != hsAttrValue && c.state != hsBeforeAttrValue
}

func (c *htmlCtx) feedString(s string) {
	for i := 0; i < len(s); i++ {
		c.feed(s[i])
	}
}

func isASCIILetter(b byte) bool { return (b|0x20) >= 'a' && (b|0x20) <= 'z' }

func isHTMLSpace(b byte) bool { return b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f' }

func lowerByte(b byte) byte {
	if b >= 'A' && b <= 'Z' {
		return b + 32
	}
	return b
}

func (c *htmlCtx) feed(b byte) {
	switch c.state {
	case hsText:
		if b == '<' {
			c.state = hsLt
		}
	case hsLt:
		switch {
		case isASCIILetter(b):
			c.tag = append(c.tag[:0], lowerByte(b))
			c.isEnd = false
			c.scriptType, c.typeSet = "", false
			c.state = hsTagName
		case b == '/':
			c.state = hsEndTagOpen
		case b == '!':
			c.bangDash = false
			c.state = hsBang
		case b == '?':
			c.state = hsBogusComment
		case b == '<':
			// stay
		default:
			c.state = hsText
		}
	case hsEndTagOpen:
		switch {
		case isASCIILetter(b):
			c.tag = append(c.tag[:0], lowerByte(b))
			c.isEnd = true
			c.state = hsTagName
		case b == '>':
			c.state = hsText
		default:
			c.state = hsBogusComment
		}
	case hsTagName:
		switch {
		case isHTMLSpace(b):
			c.state = hsBeforeAttr
		case b == '/':
			c.state = hsSelfClosing
		case b == '>':
			c.tagEnd()
		default:
			c.tag = append(c.tag, lowerByte(b))
		}
	case hsBeforeAttr, hsAfterAttrName:
		switch {
		case isHTMLSpace(b):
		case b == '/':
			c.state = hsSelfClosing
		case b == '>':
			c.tagEnd()
		case b == '=' && c.state == hsAfterAttrName:
			c.attrVal = c.attrVal[:0]
			c.state = hsBeforeAttrValue
		default:
			c.attr = append(c.attr[:0], lowerByte(b))
			c.state = hsAttrName
		}
	case hsAttrName:
		switch {
		case isHTMLSpace(b):
			c.state = hsAfterAttrName
		case b == '/':
			c.state = hsSelfClosing
		case b == '=':
			c.attrVal = c.attrVal[:0]
			c.state = hsBeforeAttrValue
		case b == '>':
			c.tagEnd()
		default:
			c.attr = append(c.attr, lowerByte(b))
		}
	case hsBeforeAttrValue:
		switch {
		case isHTMLSpace(b):
		case b == '"' || b == '\'':
			c.quote = b
			c.attrVal = c.attrVal[:0]
			c.state = hsAttrValue
		case b == '>':
			c.tagEnd()
		default:
			c.quote = 0
			c.attrVal = append(c.attrVal[:0], b)
			c.state = hsAttrValue
		}
	case hsAttrValue:
		if c.quote != 0 {
			if b == c.quote {
				c.attrDone()
				c.state = hsBeforeAttr
			} else {
				c.attrVal = append(c.attrVal, b)
			}
			return
		}
		switch {
		case isHTMLSpace(b):
			c.attrDone()
			c.state = hsBeforeAttr
		case b == '>':
			c.attrDone()
			c.tagEnd()
		default:
			c.attrVal = append(c.attrVal, b)
		}
	case hsSelfClosing:
		if b == '>' {
			// HTML ignores the self-closing flag on non-void elements, so
			// `<script/>` still opens a script body.
			c.tagEnd()
			return
		}
		c.state = hsBeforeAttr
		c.feed(b)
	case hsBang:
		if b == '-' {
			if c.bangDash {
				c.dashes = 0
				c.commentText, c.commentBang = false, false
				c.state = hsComment
			} else {
				c.bangDash = true
			}
			return
		}
		if b == '>' {
			c.state = hsText
			return
		}
		c.state = hsBogusComment
	case hsComment:
		switch {
		case b == '>' && (!c.commentText || c.dashes >= 2 || c.commentBang):
			c.state = hsText
		case b == '-':
			if c.commentBang {
				c.dashes = 1 // "--!-" is back to one pending dash
			} else {
				c.dashes++
			}
			c.commentBang = false
		case b == '!' && c.dashes >= 2 && !c.commentBang:
			c.commentBang = true
			c.commentText = true
		default:
			c.dashes = 0
			c.commentBang = false
			c.commentText = true
		}
	case hsBogusComment:
		if b == '>' {
			c.state = hsText
		}
	case hsRawText:
		if c.script != scriptInert {
			c.js.feed(b)
		}
		c.matchRawEnd(b)
	}
}

// matchRawEnd recognises the end tag of a raw-text element regardless of
// what the element's content looks like (the HTML tokenizer does the same:
// `</script` ends a script even inside a JS string).
func (c *htmlCtx) matchRawEnd(b byte) {
	switch {
	case c.endMatch == 0:
		if b == '<' {
			c.endMatch = 1
		}
	case c.endMatch == 1:
		if b == '/' {
			c.endMatch = 2
		} else if b != '<' {
			c.endMatch = 0
		}
	case c.endMatch-2 < len(c.rawEnd):
		if lowerByte(b) == c.rawEnd[c.endMatch-2] {
			c.endMatch++
		} else if b == '<' {
			c.endMatch = 1
		} else {
			c.endMatch = 0
		}
	default:
		if isHTMLSpace(b) || b == '/' || b == '>' {
			c.tag = append(c.tag[:0], c.rawEnd...)
			c.isEnd = true
			c.endMatch = 0
			c.script = scriptInert
			if b == '>' {
				c.state = hsText
			} else {
				c.state = hsBeforeAttr
			}
			return
		}
		c.endMatch = 0
		if b == '<' {
			c.endMatch = 1
		}
	}
}

func (c *htmlCtx) attrDone() {
	if !c.isEnd && string(c.tag) == "script" && string(c.attr) == "type" && !c.typeSet {
		c.scriptType = html.UnescapeString(string(c.attrVal))
		c.typeSet = true
	}
}

func (c *htmlCtx) tagEnd() {
	c.state = hsText
	if c.isEnd {
		return
	}
	switch name := string(c.tag); name {
	case "script":
		c.state = hsRawText
		c.rawEnd = name
		c.endMatch = 0
		c.script = classifyScriptType(c.scriptType)
		c.js = jsLexer{}
	case "style", "textarea", "title", "xmp", "iframe", "noembed", "noframes", "plaintext":
		c.state = hsRawText
		c.rawEnd = name
		c.endMatch = 0
		c.script = scriptInert
	}
}

func classifyScriptType(t string) scriptKind {
	t = strings.ToLower(strings.TrimSpace(t))
	if i := strings.IndexByte(t, ';'); i >= 0 {
		t = strings.TrimSpace(t[:i])
	}
	switch t {
	// Every JavaScript MIME type the HTML standard runs as a classic script,
	// plus module and the in-browser JSX transpilers' types.
	case "", "text/javascript", "application/javascript", "module", "text/ecmascript",
		"application/ecmascript", "application/x-javascript", "text/x-javascript",
		"application/x-ecmascript", "text/x-ecmascript", "text/jscript", "text/livescript",
		"text/javascript1.0", "text/javascript1.1", "text/javascript1.2", "text/javascript1.3",
		"text/javascript1.4", "text/javascript1.5",
		"text/jsx", "text/babel":
		return scriptJS
	case "application/json", "importmap", "speculationrules":
		return scriptJSON
	}
	if strings.HasSuffix(t, "+json") || strings.HasSuffix(t, "/json") {
		return scriptJSON
	}
	return scriptInert
}

// urlAttrs are attributes whose value the browser resolves as a URL.
var urlAttrs = map[string]bool{
	"href": true, "src": true, "action": true, "formaction": true, "poster": true,
	"xlink:href": true, "srcset": true, "imagesrcset": true, "cite": true,
	"background": true, "data": true, "codebase": true, "longdesc": true,
	"manifest": true, "ping": true, "icon": true, "lowsrc": true, "dynsrc": true,
	"profile": true, "usemap": true, "classid": true, "archive": true,
}

// escapeMustacheValue escapes one rendered value for the context c is in.
// raw is the native value (used for JSON encoding in script expressions); s
// is its rendered string (after pipes). jsonPipe marks a `| json` pipe, whose
// intent is the value's JSON form. The HTML-body/ordinary-attribute branch
// is exactly html.EscapeString, so body output is unchanged.
func escapeMustacheValue(c *htmlCtx, raw any, s string, jsonPipe bool) string {
	if c == nil {
		return html.EscapeString(s)
	}
	switch c.state {
	case hsRawText:
		if c.script == scriptInert {
			return html.EscapeString(s)
		}
		return jsEscapeForState(&c.js, raw, s, jsonPipe)
	case hsBeforeAttrValue, hsAttrValue:
		name := string(c.attr)
		quote := c.quote
		if c.state == hsBeforeAttrValue {
			quote = 0
		}
		var out string
		switch {
		case name == "srcdoc":
			// The browser decodes the attribute once and parses the result
			// as a whole document, so the value is escaped for that
			// document and again for the attribute.
			out = html.EscapeString(html.EscapeString(s))
		case urlAttrs[name]:
			prefix := ""
			if c.state == hsAttrValue {
				prefix = html.UnescapeString(string(c.attrVal))
			}
			if unsafeURLValue(name, prefix, s) {
				s = blockedURL
			}
			out = html.EscapeString(s)
		case strings.HasPrefix(name, "on") && len(name) > 2:
			// Event handler: the decoded attribute value is JavaScript.
			var lx jsLexer
			if c.state == hsAttrValue {
				lx.feedString(html.UnescapeString(string(c.attrVal)))
			}
			out = html.EscapeString(jsEscapeForState(&lx, raw, s, jsonPipe))
		default:
			out = html.EscapeString(s)
		}
		if quote == 0 {
			out = escapeUnquotedAttr(out)
		}
		return out
	}
	return html.EscapeString(s)
}

// blockedURL replaces a URL value whose scheme can run script.
const blockedURL = "#blocked-unsafe-url"

// unsafeURLValue reports whether the attribute value prefix+s would carry
// a script-capable scheme (javascript:, vbscript:, or data: other than a
// raster image). srcset-style lists check every candidate.
func unsafeURLValue(attr, prefix, s string) bool {
	full := prefix + s
	if attr == "srcset" || attr == "imagesrcset" {
		for _, cand := range strings.Split(full, ",") {
			f := strings.Fields(cand)
			if len(f) > 0 && dangerousURL(f[0]) {
				return true
			}
		}
		return false
	}
	return dangerousURL(full)
}

func dangerousURL(u string) bool {
	// Browsers strip leading C0/space and remove tab/CR/LF anywhere before
	// parsing, so `java\tscript:` and ` javascript:` are still scripts.
	u = strings.TrimLeftFunc(u, func(r rune) bool { return r <= 0x20 })
	u = strings.Map(func(r rune) rune {
		if r == '\t' || r == '\n' || r == '\r' {
			return -1
		}
		return r
	}, u)
	end := strings.IndexAny(u, ":/?#")
	if end <= 0 || u[end] != ':' {
		return false
	}
	scheme := strings.ToLower(u[:end])
	switch scheme {
	case "javascript", "vbscript", "livescript":
		return true
	case "data":
		rest := strings.ToLower(strings.TrimLeft(u[end+1:], " "))
		for _, img := range []string{"image/png", "image/gif", "image/jpeg", "image/jpg", "image/webp", "image/avif", "image/bmp", "image/x-icon", "image/vnd.microsoft.icon"} {
			if strings.HasPrefix(rest, img) && len(rest) > len(img) && (rest[len(img)] == ';' || rest[len(img)] == ',') {
				return false
			}
		}
		return true
	}
	return false
}

// escapeUnquotedAttr additionally escapes the bytes that end or split an
// unquoted attribute value, so `class={{x}}` cannot grow new attributes.
func escapeUnquotedAttr(s string) string {
	if !strings.ContainsAny(s, " \t\n\r\f=`") {
		return s
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case ' ':
			b.WriteString("&#32;")
		case '\t':
			b.WriteString("&#9;")
		case '\n':
			b.WriteString("&#10;")
		case '\r':
			b.WriteString("&#13;")
		case '\f':
			b.WriteString("&#12;")
		case '=':
			b.WriteString("&#61;")
		case '`':
			b.WriteString("&#96;")
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// jsEscapeForState escapes a value at the lexer's current position: JS
// string content inside strings, template literals, regexes and comments;
// a JSON value (valid JS expression) in expression position.
func jsEscapeForState(lx *jsLexer, raw any, s string, jsonPipe bool) string {
	lx.resolvePending()
	if lx.state != jsExpr {
		return jsStringEscape(s)
	}
	var v any = s
	if raw != nil {
		switch raw.(type) {
		case string:
		default:
			// Numbers, booleans, maps and slices keep their JSON shape; a
			// pipe that rewrote the value keeps its string result.
			if jsonPipe || s == fmt.Sprintf("%v", raw) {
				v = raw
			}
		}
	}
	if jsonPipe {
		if str, ok := raw.(string); ok {
			v = str
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(true)
	if err := enc.Encode(v); err != nil {
		return `"` + jsStringEscape(s) + `"`
	}
	return jsonScriptSafe(strings.TrimSuffix(buf.String(), "\n"))
}

// jsonScriptSafe rewrites braces and slashes inside JSON string literals to
// \u escapes, so the output can neither re-enter mustache (`{{`) nor end a
// regex/comment, while structural JSON is untouched. json.Encoder already
// escapes <, >, &, U+2028 and U+2029.
func jsonScriptSafe(j string) string {
	if !strings.ContainsAny(j, "{}/'`") {
		return j
	}
	var b strings.Builder
	inStr, esc := false, false
	for i := 0; i < len(j); i++ {
		ch := j[i]
		if inStr {
			switch {
			case esc:
				esc = false
			case ch == '\\':
				esc = true
			case ch == '"':
				inStr = false
			case ch == '{' || ch == '}' || ch == '/' || ch == '\'' || ch == '`':
				fmt.Fprintf(&b, "\\u%04x", ch)
				continue
			}
		} else if ch == '"' {
			inStr = true
		}
		b.WriteByte(ch)
	}
	return b.String()
}

// jsStringEscape renders s as JS (and JSON) string-literal content: every
// quote, backslash, template/regex delimiter, HTML-significant byte, brace
// and line terminator becomes an escape, so the value cannot close the
// string it sits in, start `${}` interpolation, end a regex or comment, or
// close the <script> element.
func jsStringEscape(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		i += size
		switch {
		case r == '\\':
			b.WriteString(`\\`)
		case r == '\'' || r == '"' || r == '`' || r == '<' || r == '>' || r == '&' ||
			r == '{' || r == '}' || r == '$' || r == '/':
			fmt.Fprintf(&b, `\u%04x`, r)
		case r < 0x20 || r == 0x7f || r == 0x2028 || r == 0x2029:
			fmt.Fprintf(&b, `\u%04x`, r)
		case r == utf8.RuneError && size == 1:
			b.WriteString("\\ufffd")
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// jsLexer tracks enough JavaScript lexical state to tell whether the next
// byte is inside a string, template literal, regex or comment, or in
// expression position. Regex-vs-division uses the previous significant
// token, the same heuristic html/template uses.
type jsState uint8

const (
	jsExpr jsState = iota
	jsSQ
	jsDQ
	jsTmpl
	jsRegex
	jsRegexClass
	jsLineComment
	jsBlockComment
)

type jsLexer struct {
	state        jsState
	escaped      bool
	pendingSlash bool
	pendingDollr bool
	prevStar     bool
	lastSig      byte
	word         []byte // last identifier in expression position
	wordOpen     bool   // the previous expression byte was part of word
	braces       int
	tmpl         []int // brace depth at each `${` inside template literals
	// opRun counts adjacent '+' or '-' ending at lastSig, so `a++ / b` is
	// division and `a + /re/` a regex; opGap marks whitespace since then.
	opRun int
	opGap bool
}

func (lx *jsLexer) feedString(s string) {
	for i := 0; i < len(s); i++ {
		lx.feed(s[i])
	}
}

var jsRegexKeywords = map[string]bool{
	"return": true, "typeof": true, "instanceof": true, "in": true, "of": true,
	"new": true, "delete": true, "void": true, "throw": true, "case": true,
	"do": true, "else": true, "yield": true, "await": true,
}

func isJSIdent(b byte) bool {
	return b == '_' || b == '$' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b >= 0x80
}

// regexAllowed reports whether a `/` after the last significant token
// starts a regex literal (true) or is division (false).
func (lx *jsLexer) regexAllowed() bool {
	switch {
	case lx.lastSig == 0:
		return true
	case isJSIdent(lx.lastSig):
		return jsRegexKeywords[string(lx.word)]
	case lx.lastSig == ')' || lx.lastSig == ']':
		return false
	case lx.lastSig == '+' || lx.lastSig == '-':
		// `++`/`--` end an operand; a lone (or odd run of) + or - is an
		// operator that an expression, so a regex, follows.
		return lx.opRun%2 == 1
	}
	return true
}

// resolvePending settles a `/` whose meaning depended on the next byte.
func (lx *jsLexer) resolvePending() {
	if !lx.pendingSlash {
		return
	}
	lx.pendingSlash = false
	if lx.regexAllowed() {
		lx.state = jsRegex
		lx.escaped = false
	} else {
		lx.sig('/')
	}
}

func (lx *jsLexer) sig(b byte) {
	if b == '+' || b == '-' {
		if lx.lastSig == b && !lx.opGap {
			lx.opRun++
		} else {
			lx.opRun = 1
		}
	} else {
		lx.opRun = 0
	}
	lx.opGap = false
	lx.lastSig = b
	if isJSIdent(b) {
		if !lx.wordOpen {
			lx.word = lx.word[:0]
		}
		if len(lx.word) < 16 {
			lx.word = append(lx.word, b)
		}
		lx.wordOpen = true
		return
	}
	lx.word = lx.word[:0]
	lx.wordOpen = false
}

func (lx *jsLexer) feed(b byte) {
	if lx.pendingSlash {
		lx.pendingSlash = false
		switch b {
		case '/':
			lx.state = jsLineComment
			return
		case '*':
			lx.state = jsBlockComment
			lx.prevStar = false
			return
		}
		if lx.regexAllowed() {
			lx.state = jsRegex
			lx.escaped = false
		} else {
			lx.sig('/')
		}
	}
	if lx.pendingDollr && lx.state == jsTmpl {
		lx.pendingDollr = false
		if b == '{' {
			lx.tmpl = append(lx.tmpl, lx.braces)
			lx.state = jsExpr
			lx.lastSig, lx.word, lx.wordOpen = '{', lx.word[:0], false
			return
		}
	}
	switch lx.state {
	case jsExpr:
		switch {
		case b == '\'':
			lx.state, lx.escaped = jsSQ, false
		case b == '"':
			lx.state, lx.escaped = jsDQ, false
		case b == '`':
			lx.state, lx.escaped = jsTmpl, false
		case b == '/':
			lx.pendingSlash = true
		case b == '{':
			lx.braces++
			lx.sig(b)
		case b == '}':
			if n := len(lx.tmpl); n > 0 && lx.tmpl[n-1] == lx.braces {
				lx.tmpl = lx.tmpl[:n-1]
				lx.state, lx.escaped = jsTmpl, false
				return
			}
			if lx.braces > 0 {
				lx.braces--
			}
			lx.sig(b)
		case b == ' ' || b == '\t' || b == '\n' || b == '\r' || b == '\f':
			// Whitespace ends the current word but keeps lastSig/word, so
			// `return /re/` still sees the keyword.
			lx.wordOpen = false
			lx.opGap = true
		default:
			lx.sig(b)
		}
	case jsSQ, jsDQ:
		switch {
		case lx.escaped:
			lx.escaped = false
		case b == '\\':
			lx.escaped = true
		case (b == '\'' && lx.state == jsSQ) || (b == '"' && lx.state == jsDQ):
			lx.state = jsExpr
			lx.lastSig, lx.word, lx.wordOpen = ')', lx.word[:0], false
		}
	case jsTmpl:
		switch {
		case lx.escaped:
			lx.escaped = false
		case b == '\\':
			lx.escaped = true
		case b == '`':
			lx.state = jsExpr
			lx.lastSig, lx.word, lx.wordOpen = ')', lx.word[:0], false
		case b == '$':
			lx.pendingDollr = true
		}
	case jsRegex:
		switch {
		case lx.escaped:
			lx.escaped = false
		case b == '\\':
			lx.escaped = true
		case b == '[':
			lx.state = jsRegexClass
		case b == '/':
			lx.state = jsExpr
			lx.lastSig, lx.word, lx.wordOpen = ')', lx.word[:0], false
		}
	case jsRegexClass:
		switch {
		case lx.escaped:
			lx.escaped = false
		case b == '\\':
			lx.escaped = true
		case b == ']':
			lx.state = jsRegex
		}
	case jsLineComment:
		if b == '\n' || b == '\r' {
			lx.state = jsExpr
		}
	case jsBlockComment:
		if lx.prevStar && b == '/' {
			lx.state = jsExpr
			lx.prevStar = false
			return
		}
		lx.prevStar = b == '*'
	}
}
