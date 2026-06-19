//go:build !cli

package main

import (
	"fmt"
	"regexp"
	"strings"

	"golang.org/x/net/html"
)

// ASTNode represents a universal UI primitive in the abstract syntax tree.
type ASTNode struct {
	Type     string            `json:"type"`               // box, text, image, input, scroll, list, pressable, form, table, chart, select
	Class    string            `json:"class,omitempty"`    // Tailwind / custom CSS classes
	Style    map[string]string `json:"style,omitempty"`    // inline styles
	Value    string            `json:"value,omitempty"`    // static text content
	Bind     string            `json:"bind,omitempty"`     // mustache binding (e.g. "name", "st_spend.total | currency")
	Attrs    map[string]string `json:"attrs,omitempty"`    // other attributes (name, placeholder, type, href, src, etc.)
	Children []*ASTNode        `json:"children,omitempty"` // child nodes
	Events   []*ASTEvent       `json:"events,omitempty"`   // event handlers
	Each     string            `json:"each,omitempty"`     // loop variable (from {{#list}}...{{/list}})
	Empty    []*ASTNode        `json:"empty,omitempty"`    // empty state (from {{^list}}...{{/list}})
}

// ASTEvent represents a user interaction binding.
type ASTEvent struct {
	Type  string `json:"type"`            // create, delete, patch, navigate, toggle
	Table string `json:"table,omitempty"` // for CRUD events
	URL   string `json:"url,omitempty"`   // for navigation
	Set   string `json:"set,omitempty"`   // for :patch :set="field=value"
}

// ASTQuery represents a data dependency extracted from <query> tags.
type ASTQuery struct {
	Name string `json:"name"`           // variable name (as="...")
	SQL  string `json:"sql"`            // SQL query text
	From string `json:"from,omitempty"` // shorthand table name
}

// ASTPage represents the full AST for a single page/screen.
type ASTPage struct {
	Route   string     `json:"route"`
	Title   string     `json:"title,omitempty"`
	Auth    string     `json:"auth,omitempty"`
	Scope   string     `json:"scope,omitempty"`
	Role    string     `json:"role,omitempty"`
	Layout  string     `json:"layout,omitempty"`
	Data    []ASTQuery `json:"data"`
	Tree    *ASTNode   `json:"tree"`
	Scripts []string   `json:"scripts,omitempty"`
}

// BuildPageAST parses a raw page HTML into a platform-independent AST.
func BuildPageAST(page *Page) (*ASTPage, error) {
	rawHTML := page.RawHTML

	// Extract page attributes
	auth, scope, title, layout := ParsePageAttrs(rawHTML)
	role := ""
	if m := pageAttrRe.FindStringSubmatch(rawHTML); m != nil {
		attrs := parseAttrs(m[1])
		role = attrs["role"]
	}

	// Extract queries as data dependencies
	queries := ExtractQueries(rawHTML)
	var astQueries []ASTQuery
	for _, q := range queries {
		aq := ASTQuery{
			Name: q.As,
			SQL:  q.SQL,
			From: q.From,
		}
		// If shorthand mode (from="table"), note it
		if aq.SQL == "" && q.From != "" {
			aq.SQL = fmt.Sprintf("SELECT * FROM %s", q.From)
		}
		astQueries = append(astQueries, aq)
	}

	// Strip <page> wrapper and <query> tags from the body for HTML parsing
	body := stripPageTag(rawHTML)
	body = stripQueryTags(body)

	// Extract and strip <script> blocks
	scripts := extractScripts(body)
	body = stripScripts(body)

	// Strip {{#if ...}}...{{/if}} conditional blocks from body - these can't be converted
	// to AST nodes easily. Keep only the {{else}} (default) branch content.
	body = stripIfBlocks(body)

	// Clean mustache section syntax from HTML attribute values before marker conversion.
	// Mustache like {{#done}}bg-violet{{/done}} inside class="..." corrupts the HTML parser
	// when mustacheToMarkers converts them to <ast-each> tags inside attributes.
	body = cleanMustacheInAttrs(body)

	// Pre-process mustache sections into HTML-parseable markers
	body = mustacheToMarkers(body)

	// Parse HTML into AST
	tree, err := parseHTMLToAST(body)
	if err != nil {
		return nil, fmt.Errorf("HTML parse: %w", err)
	}

	return &ASTPage{
		Route:   page.Route,
		Title:   title,
		Auth:    auth,
		Scope:   scope,
		Role:    role,
		Layout:  layout,
		Data:    astQueries,
		Tree:    tree,
		Scripts: scripts,
	}, nil
}

// stripQueryTags removes <query> and </query> tags but KEEPS the inner content.
// This preserves the page body for AST parsing while removing the query wrappers.
func stripQueryTags(content string) string {
	// Self-closing: <query ... /> - remove entirely (no inner content)
	selfClose := regexp.MustCompile(`<query\s+[^>]*/>\s*`)
	content = selfClose.ReplaceAllString(content, "")

	// Opening tags: <query ...> - remove the tag, keep what follows
	openTag := regexp.MustCompile(`<query\s+[^>]*>\s*`)
	content = openTag.ReplaceAllString(content, "")

	// Closing tags: </query> - remove
	content = strings.ReplaceAll(content, "</query>", "")

	return content
}

var scriptBlockRe = regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`)
var styleBlockRe = regexp.MustCompile(`(?s)<style[^>]*>(.*?)</style>`)

// extractScripts pulls out <script> block contents.
func extractScripts(content string) []string {
	matches := scriptBlockRe.FindAllStringSubmatch(content, -1)
	var scripts []string
	for _, m := range matches {
		s := strings.TrimSpace(m[1])
		if s != "" {
			scripts = append(scripts, s)
		}
	}
	return scripts
}

// stripScripts removes <script> blocks from content.
func stripScripts(content string) string {
	content = scriptBlockRe.ReplaceAllString(content, "")
	content = styleBlockRe.ReplaceAllString(content, "")
	return content
}

// mustacheToMarkers converts {{#section}}/{{^section}}/{{/section}} into
// HTML-parseable <ast-each>/<ast-empty> markers so the HTML parser can handle them.
var (
	mustacheSectionRe  = regexp.MustCompile(`\{\{#(\w[\w.]*)\}\}`)
	mustacheInvertedRe = regexp.MustCompile(`\{\{\^(\w[\w.]*)\}\}`)
	mustacheEndRe      = regexp.MustCompile(`\{\{/(\w[\w.]*)\}\}`)
)

// stripIfBlocks removes {{#if ...}}...{{else}}...{{/if}} blocks from body HTML.
// Keeps only the {{else}} (default) branch content since conditionals can't be
// statically resolved for native compilation. If no else, keeps the first branch.
func stripIfBlocks(content string) string {
	// Match {{#if ...}}, {{else if ...}}, {{else}}, {{/if}}
	ifOpenRe := regexp.MustCompile(`\{\{#if\s[^}]*\}\}`)
	elseIfRe := regexp.MustCompile(`\{\{else\s+if\s[^}]*\}\}`)
	elseRe := regexp.MustCompile(`\{\{else\}\}`)
	ifCloseRe := regexp.MustCompile(`\{\{/if\}\}`)

	// Process iteratively - handle innermost blocks first
	for {
		// Find the first {{#if that has a matching {{/if}} without nested {{#if}} between them
		openLocs := ifOpenRe.FindAllStringIndex(content, -1)
		if len(openLocs) == 0 {
			break
		}

		replaced := false
		for _, openLoc := range openLocs {
			start := openLoc[0]
			rest := content[openLoc[1]:]

			// Find matching {{/if}} - track nesting
			depth := 1
			pos := 0
			closeEnd := -1
			for pos < len(rest) {
				nextOpen := ifOpenRe.FindStringIndex(rest[pos:])
				nextClose := ifCloseRe.FindStringIndex(rest[pos:])

				if nextClose == nil {
					break // unmatched - bail
				}

				// Determine which comes first
				closeAbs := pos + nextClose[0]
				openAbs := -1
				if nextOpen != nil {
					openAbs = pos + nextOpen[0]
				}

				if openAbs >= 0 && openAbs < closeAbs {
					depth++
					pos = pos + nextOpen[1]
				} else {
					depth--
					if depth == 0 {
						closeEnd = openLoc[1] + pos + nextClose[1]
						break
					}
					pos = pos + nextClose[1]
				}
			}

			if closeEnd < 0 {
				continue // unmatched block, skip
			}

			block := content[openLoc[1]:closeEnd]
			block = strings.TrimSuffix(block, ifCloseRe.FindString(block))
			// Remove the {{/if}} at the end
			if loc := ifCloseRe.FindStringIndex(content[start:closeEnd]); loc != nil {
				block = content[openLoc[1] : start+loc[0]]
			}

			// Split on {{else}} to find branches
			// Find the outermost {{else}} (not inside nested if blocks)
			elseBranch := ""
			firstBranch := block
			if loc := findOuterElse(block, elseRe, elseIfRe, ifOpenRe, ifCloseRe); loc >= 0 {
				firstBranch = block[:loc]
				// Find where the else marker ends
				remaining := block[loc:]
				if m := elseRe.FindStringIndex(remaining); m != nil && m[0] == 0 {
					elseBranch = remaining[m[1]:]
				} else if m := elseIfRe.FindStringIndex(remaining); m != nil && m[0] == 0 {
					// else if - treat remaining as another conditional, just take it as-is
					elseBranch = remaining[m[1]:]
				}
			}

			// Prefer else branch (default state), fall back to first branch
			replacement := elseBranch
			if strings.TrimSpace(replacement) == "" {
				replacement = firstBranch
			}

			content = content[:start] + replacement + content[closeEnd:]
			replaced = true
			break // restart since indices shifted
		}

		if !replaced {
			break
		}
	}

	return content
}

// findOuterElse finds the position of the first {{else}} that's not inside a nested {{#if}}.
func findOuterElse(block string, elseRe, elseIfRe, ifOpenRe, ifCloseRe *regexp.Regexp) int {
	depth := 0
	pos := 0
	for pos < len(block) {
		rest := block[pos:]

		nextOpen := ifOpenRe.FindStringIndex(rest)
		nextClose := ifCloseRe.FindStringIndex(rest)
		nextElse := elseRe.FindStringIndex(rest)
		nextElseIf := elseIfRe.FindStringIndex(rest)

		// Find the earliest match
		type match struct {
			kind string
			pos  int
			end  int
		}
		var candidates []match
		if nextOpen != nil {
			candidates = append(candidates, match{"open", nextOpen[0], nextOpen[1]})
		}
		if nextClose != nil {
			candidates = append(candidates, match{"close", nextClose[0], nextClose[1]})
		}
		if nextElseIf != nil {
			candidates = append(candidates, match{"elseif", nextElseIf[0], nextElseIf[1]})
		}
		if nextElse != nil {
			candidates = append(candidates, match{"else", nextElse[0], nextElse[1]})
		}

		if len(candidates) == 0 {
			break
		}

		// Sort by position
		earliest := candidates[0]
		for _, c := range candidates[1:] {
			if c.pos < earliest.pos {
				earliest = c
			}
		}

		switch earliest.kind {
		case "open":
			depth++
			pos += earliest.end
		case "close":
			depth--
			pos += earliest.end
		case "else", "elseif":
			if depth == 0 {
				return pos + earliest.pos
			}
			pos += earliest.end
		}
	}
	return -1
}

// cleanMustacheInAttrs strips mustache section syntax ({{#var}}, {{^var}}, {{/var}})
// from inside HTML attribute values to prevent corrupting the HTML parser.
// For :set toggle patterns, encodes as field=__toggle__ for the compiler.
// For class attrs, keeps the conditional classes as static (can't be dynamic in RN anyway).
func cleanMustacheInAttrs(content string) string {
	// Handle :set toggle pattern first: :set="done={{#done}}0{{/done}}{{^done}}1{{/done}}"
	setToggleRe := regexp.MustCompile(`:set="(\w+)=\{\{#\w+\}\}[^"]*\{\{/\w+\}\}"`)
	content = setToggleRe.ReplaceAllStringFunc(content, func(m string) string {
		parts := setToggleRe.FindStringSubmatch(m)
		return fmt.Sprintf(`:set="%s=__toggle__"`, parts[1])
	})

	// Strip remaining mustache sections from all attribute values
	attrWithSectionRe := regexp.MustCompile(`="([^"]*\{\{[#^/][^}]*\}\}[^"]*)"`)
	content = attrWithSectionRe.ReplaceAllStringFunc(content, func(m string) string {
		val := m[2 : len(m)-1] // strip =" and trailing "
		val = mustacheSectionRe.ReplaceAllString(val, "")
		val = mustacheInvertedRe.ReplaceAllString(val, "")
		val = mustacheEndRe.ReplaceAllString(val, "")
		val = strings.Join(strings.Fields(val), " ")
		return `="` + val + `"`
	})

	return content
}

func mustacheToMarkers(content string) string {
	content = mustacheSectionRe.ReplaceAllString(content, `<ast-each data-each="$1">`)
	content = mustacheInvertedRe.ReplaceAllString(content, `<ast-empty data-when="$1">`)
	content = mustacheEndRe.ReplaceAllString(content, `</ast-each>`)
	return content
}

// parseHTMLToAST parses an HTML string into an ASTNode tree.
func parseHTMLToAST(htmlStr string) (*ASTNode, error) {
	// Wrap in a root div so the parser has a single root
	wrapped := "<div>" + htmlStr + "</div>"
	doc, err := html.Parse(strings.NewReader(wrapped))
	if err != nil {
		return nil, err
	}

	// Navigate to the body content (html > head > body > div)
	root := findBodyContent(doc)
	if root == nil {
		return &ASTNode{Type: "box"}, nil
	}

	node := walkNode(root)
	return node, nil
}

// findBodyContent finds the first meaningful content node in the parsed HTML tree.
func findBodyContent(n *html.Node) *html.Node {
	if n.Type == html.ElementNode && n.Data == "body" {
		// Return the wrapper div inside body
		for c := n.FirstChild; c != nil; c = c.NextSibling {
			if c.Type == html.ElementNode && c.Data == "div" {
				return c
			}
		}
		return n
	}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if found := findBodyContent(c); found != nil {
			return found
		}
	}
	return nil
}

// walkNode recursively converts an html.Node into an ASTNode.
func walkNode(n *html.Node) *ASTNode {
	if n == nil {
		return nil
	}

	switch n.Type {
	case html.TextNode:
		text := strings.TrimSpace(n.Data)
		if text == "" {
			return nil
		}
		return textOrBind(text)

	case html.ElementNode:
		return elementToAST(n)
	}

	// For document/fragment nodes, wrap children
	root := &ASTNode{Type: "box"}
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		child := walkNode(c)
		if child != nil {
			root.Children = append(root.Children, child)
		}
	}
	if len(root.Children) == 1 {
		return root.Children[0]
	}
	return root
}

var mustacheVarRe = regexp.MustCompile(`\{\{+([^}]+)\}\}+`)

// textOrBind creates a text ASTNode, detecting mustache bindings.
func textOrBind(text string) *ASTNode {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}

	// Pure binding: entire text is a single {{var}} or {{var | pipe}}
	if mustacheVarRe.MatchString(text) {
		pure := mustacheVarRe.FindString(text)
		if strings.TrimSpace(pure) == strings.TrimSpace(text) {
			inner := mustacheVarRe.FindStringSubmatch(text)[1]
			return &ASTNode{Type: "text", Bind: strings.TrimSpace(inner)}
		}
	}

	// Mixed content: "Hello {{name}}, welcome!"
	if strings.Contains(text, "{{") {
		return &ASTNode{Type: "text", Value: text}
	}

	// Pure static text
	return &ASTNode{Type: "text", Value: text}
}

// elementToAST converts an HTML element node to an ASTNode.
func elementToAST(n *html.Node) *ASTNode {
	tag := strings.ToLower(n.Data)

	// Handle our mustache markers
	if tag == "ast-each" {
		return handleEachMarker(n)
	}
	if tag == "ast-empty" {
		return handleEmptyMarker(n)
	}

	node := &ASTNode{}

	// Map HTML elements to AST types
	switch tag {
	case "div", "section", "article", "main", "header", "footer", "nav", "aside", "li", "ul", "ol":
		node.Type = "box"
	case "span", "p", "h1", "h2", "h3", "h4", "h5", "h6", "label", "th", "td", "small", "strong", "em":
		node.Type = "text"
		if tag == "h1" || tag == "h2" || tag == "h3" || tag == "h4" || tag == "h5" || tag == "h6" {
			if node.Attrs == nil {
				node.Attrs = make(map[string]string)
			}
			node.Attrs["tag"] = tag
		}
	case "img":
		node.Type = "image"
	case "input", "textarea":
		node.Type = "input"
	case "select":
		node.Type = "select"
	case "button":
		node.Type = "pressable"
	case "a":
		node.Type = "pressable"
	case "form":
		node.Type = "form"
	case "table":
		node.Type = "table"
	case "thead":
		node.Type = "table-head"
	case "tbody":
		node.Type = "table-body"
	case "tr":
		node.Type = "table-row"
	case "canvas":
		node.Type = "chart"
	case "svg":
		node.Type = "icon"
		// Don't recurse into SVG internals
		return node
	case "option":
		node.Type = "option"
	case "br":
		return nil // skip
	default:
		node.Type = "box"
	}

	// Extract attributes
	extractAttrs(n, node)

	// Extract directives as events
	extractDirectives(n, node)

	// Recurse into children
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		child := walkNode(c)
		if child != nil {
			node.Children = append(node.Children, child)
		}
	}

	// For text-type nodes with a single text child, flatten
	if isTextType(node.Type) && len(node.Children) == 1 && node.Children[0].Type == "text" {
		child := node.Children[0]
		node.Value = child.Value
		node.Bind = child.Bind
		node.Children = nil
	}

	// For text-type nodes with no children and no value, check for direct text
	if isTextType(node.Type) && len(node.Children) == 0 && node.Value == "" && node.Bind == "" {
		text := extractDirectText(n)
		if text != "" {
			tn := textOrBind(text)
			if tn != nil {
				node.Value = tn.Value
				node.Bind = tn.Bind
			}
		}
	}

	return node
}

func isTextType(t string) bool {
	return t == "text" || t == "option"
}

// extractDirectText gets the concatenated text content of an HTML node.
func extractDirectText(n *html.Node) string {
	var sb strings.Builder
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		if c.Type == html.TextNode {
			sb.WriteString(c.Data)
		}
	}
	return strings.TrimSpace(sb.String())
}

// extractAttrs reads HTML attributes into an ASTNode.
func extractAttrs(n *html.Node, node *ASTNode) {
	for _, attr := range n.Attr {
		key := attr.Key
		val := attr.Val

		switch {
		case key == "class":
			node.Class = val
		case key == "style":
			node.Style = parseInlineStyle(val)
		case key == "src" && node.Type == "image":
			if node.Attrs == nil {
				node.Attrs = make(map[string]string)
			}
			node.Attrs["src"] = val
		case key == "href":
			if node.Attrs == nil {
				node.Attrs = make(map[string]string)
			}
			node.Attrs["href"] = val
		case key == "id":
			if node.Attrs == nil {
				node.Attrs = make(map[string]string)
			}
			node.Attrs["id"] = val
		case key == "name":
			if node.Attrs == nil {
				node.Attrs = make(map[string]string)
			}
			node.Attrs["name"] = val
		case key == "type":
			if node.Attrs == nil {
				node.Attrs = make(map[string]string)
			}
			node.Attrs["type"] = val
		case key == "value":
			if node.Type == "option" || node.Type == "select" {
				// For option/select elements, value is the form value (not display text)
				if node.Attrs == nil {
					node.Attrs = make(map[string]string)
				}
				node.Attrs["value"] = val
			} else if strings.Contains(val, "{{") {
				node.Bind = mustacheVarRe.FindStringSubmatch(val)[1]
			} else {
				node.Value = val
			}
		case key == "placeholder":
			if node.Attrs == nil {
				node.Attrs = make(map[string]string)
			}
			node.Attrs["placeholder"] = val
		case key == "rows":
			if node.Attrs == nil {
				node.Attrs = make(map[string]string)
			}
			node.Attrs["rows"] = val
		case key == "action":
			if node.Attrs == nil {
				node.Attrs = make(map[string]string)
			}
			node.Attrs["action"] = val
		case key == "data-start" || key == "data-end" || key == "data-obj" || key == "data-cost" || key == "data-id" ||
			key == "data-label" || key == "data-value" || key == "data-count" || key == "data-each" || key == "data-when" ||
			key == "data-lucide":
			if node.Attrs == nil {
				node.Attrs = make(map[string]string)
			}
			node.Attrs[key] = val
		// Capture onclick for modal/visibility toggling (getElementById patterns)
		case key == "onclick":
			if strings.Contains(val, "getElementById") || strings.Contains(val, "style.display") {
				if node.Attrs == nil {
					node.Attrs = make(map[string]string)
				}
				node.Attrs["onclick"] = val
			}
			continue
		// Skip other event handler attributes
		case strings.HasPrefix(key, "on"):
			continue
		// Alpine.js attributes - capture for RN compilation
		case key == "x-data" || key == "x-show" || strings.HasPrefix(key, "@"):
			if node.Attrs == nil {
				node.Attrs = make(map[string]string)
			}
			node.Attrs[key] = val
		case key == ":id":
			if node.Attrs == nil {
				node.Attrs = make(map[string]string)
			}
			node.Attrs[":id"] = val
		}
	}
}

var directiveCreateRe = regexp.MustCompile(`:create`)
var directiveDeleteRe = regexp.MustCompile(`:delete`)
var directivePatchRe = regexp.MustCompile(`:patch`)

// extractDirectives looks for :create, :delete, :patch directives on an element.
func extractDirectives(n *html.Node, node *ASTNode) {
	for _, attr := range n.Attr {
		switch {
		case attr.Key == ":create":
			node.Events = append(node.Events, &ASTEvent{
				Type:  "create",
				Table: attr.Val,
			})
		case attr.Key == ":delete":
			evt := &ASTEvent{
				Type:  "delete",
				Table: attr.Val,
			}
			// Look for :id attribute
			for _, a2 := range n.Attr {
				if a2.Key == ":id" {
					evt.Set = a2.Val // reuse Set field to carry the ID expression
				}
			}
			node.Events = append(node.Events, evt)
		case attr.Key == ":patch":
			evt := &ASTEvent{
				Type: "patch",
				URL:  attr.Val,
			}
			// Look for :set attribute
			for _, a2 := range n.Attr {
				if a2.Key == ":set" {
					evt.Set = a2.Val
				}
			}
			node.Events = append(node.Events, evt)
		case attr.Key == ":validate":
			if node.Attrs == nil {
				node.Attrs = make(map[string]string)
			}
			node.Attrs["validate"] = attr.Val
		}
	}
}

// handleEachMarker converts <ast-each data-each="list"> into an ASTNode with Each set.
func handleEachMarker(n *html.Node) *ASTNode {
	eachVar := ""
	for _, attr := range n.Attr {
		if attr.Key == "data-each" {
			eachVar = attr.Val
		}
	}

	node := &ASTNode{
		Type: "box",
		Each: eachVar,
	}

	// Check if there's a following ast-empty for the same variable
	for c := n.FirstChild; c != nil; c = c.NextSibling {
		child := walkNode(c)
		if child != nil {
			node.Children = append(node.Children, child)
		}
	}

	// Look for sibling <ast-empty> (rendered as </ast-each> swallows it, so check inside)
	// The empty state is handled separately if it's a sibling in the parent

	return node
}

// handleEmptyMarker converts <ast-empty data-when="list"> into children for an empty state.
func handleEmptyMarker(n *html.Node) *ASTNode {
	whenVar := ""
	for _, attr := range n.Attr {
		if attr.Key == "data-when" {
			whenVar = attr.Val
		}
	}

	node := &ASTNode{
		Type: "box",
		Attrs: map[string]string{
			"empty-when": whenVar,
		},
	}

	for c := n.FirstChild; c != nil; c = c.NextSibling {
		child := walkNode(c)
		if child != nil {
			node.Children = append(node.Children, child)
		}
	}

	return node
}

// parseInlineStyle parses a CSS style string into a map.
func parseInlineStyle(style string) map[string]string {
	m := make(map[string]string)
	parts := strings.Split(style, ";")
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		idx := strings.Index(part, ":")
		if idx < 0 {
			continue
		}
		key := strings.TrimSpace(part[:idx])
		val := strings.TrimSpace(part[idx+1:])
		m[key] = val
	}
	return m
}
