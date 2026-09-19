//go:build !cli

package main

// Go html/template rendering path. This is the "new shape" - agent-facing
// surface is shaped like idioms the model already knows cold:
//
//   - Frontmatter (Astro/MDX style) at the top of every page declares
//     auth/title/layout/queries - no <page> wrapper required.
//   - Body is Go's stdlib html/template: {{range .Items}}, {{if eq .X "y"}},
//     {{else}}, {{.field}}. The model has seen this thousands of times.
//   - Interactivity is raw HTMX attrs (hx-post, hx-target, hx-swap) - no
//     custom :create / :patch / :delete directives.
//   - Queries declared as a map under `queries:` in frontmatter, results
//     surface as .queryName in the template.
//
// This file is purely ADDITIVE. Pages without frontmatter, or with
// frontmatter that omits `engine: gotmpl`, continue down the existing
// mustache pipeline. No behavior change for existing apps.

import (
	"bytes"
	"fmt"
	"html/template"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/Masterminds/sprig/v3"
	"gopkg.in/yaml.v3"
)

// Frontmatter is the parsed YAML block from the top of a page file.
// Mirrors the Page struct's fields plus engine/queries.
type Frontmatter struct {
	// Page metadata - same semantics as <page> tag attrs.
	Title       string `yaml:"title"`
	Auth        string `yaml:"auth"`
	Scope       string `yaml:"scope"`
	Role        string `yaml:"role"`
	Layout      string `yaml:"layout"`
	Type        string `yaml:"type"`
	Require     string `yaml:"require"`
	Redirect    string `yaml:"redirect"`
	Description string `yaml:"description"`
	Image       string `yaml:"image"`
	Robots      string `yaml:"robots"`

	// Renderer selector. Empty or "mustache" → legacy mustache path.
	// "gotmpl" → Go html/template path (this file).
	Engine string `yaml:"engine"`

	// Named SQL queries. Results bind to .{name} in the template.
	// Bind params: :user_id, :user_email, :user_role, :user_group_id,
	// :param_<name> (URL query string). All injected from the session.
	Queries map[string]string `yaml:"queries"`
}

// frontmatterRe matches a YAML block at the start of a file fenced by
// `---` lines. The body after the closing fence is everything else.
var frontmatterRe = regexp.MustCompile(`(?s)\A---\r?\n(.*?)\r?\n---\r?\n?`)

// ExtractFrontmatter splits a page file into (frontmatter, body). If the
// file doesn't start with `---`, returns (nil, original) - frontmatter is
// optional. Errors only on malformed YAML inside a valid fence.
func ExtractFrontmatter(raw string) (*Frontmatter, string, error) {
	m := frontmatterRe.FindStringSubmatchIndex(raw)
	if m == nil {
		return nil, raw, nil
	}
	yamlText := raw[m[2]:m[3]]
	body := raw[m[1]:]
	var fm Frontmatter
	if err := yaml.Unmarshal([]byte(yamlText), &fm); err != nil {
		return nil, raw, fmt.Errorf("frontmatter yaml: %w", err)
	}
	return &fm, body, nil
}

// ApplyFrontmatterToPage merges frontmatter values into a Page struct.
// Existing values (from a <page> tag) are not overwritten - the <page>
// tag wins if both are present, so a mixed file stays self-consistent
// during migration.
func ApplyFrontmatterToPage(p *Page, fm *Frontmatter) {
	if fm == nil {
		return
	}
	if p.Title == "" {
		p.Title = fm.Title
	}
	if p.Auth == "" {
		p.Auth = fm.Auth
	}
	if p.Scope == "" {
		p.Scope = fm.Scope
	}
	if p.Layout == "" {
		p.Layout = fm.Layout
	}
	if p.Type == "" {
		p.Type = fm.Type
	}
	if p.Require == "" {
		p.Require = fm.Require
	}
	if p.Redirect == "" {
		p.Redirect = fm.Redirect
	}
	if p.Engine == "" {
		p.Engine = fm.Engine
	}
	if p.Description == "" {
		p.Description = fm.Description
	}
	if p.Image == "" {
		p.Image = fm.Image
	}
	if p.Robots == "" {
		p.Robots = fm.Robots
	}
}

// renderGoTemplate is the entry point for engine: gotmpl pages.
// Mirrors RenderTemplate's contract: (final HTML, error). Runs the queries
// declared in frontmatter, builds the template data context, executes the
// template, then defers to the existing pipeline for layout wrapping +
// image opts + N+1 detection - those stages don't care which engine
// produced the body content.
func renderGoTemplate(app *App, page *Page, ctx *RenderContext, fm *Frontmatter, body string) (string, error) {
	// 1. Execute named queries from frontmatter.
	//
	// Shape rule: if the SQL ends in `LIMIT 1`, the result is stored
	// in ctx.Data as a SINGLE map (or empty map when zero rows),
	// NOT a slice. Templates then write `.profile.bio` directly
	// instead of the dangerous `(index .profile 0).bio` pattern
	// (which panics on empty results). With missingkey=zero, an
	// empty map's `.bio` resolves to "" silently - exactly the
	// "use default" behavior agents want for singleton queries.
	//
	// Multi-row queries (no LIMIT 1) keep the slice shape they've
	// always had, so {{range .todos}} works unchanged.
	for name, sql := range fm.Queries {
		rows, err := runFrontmatterQuery(app, ctx, sql)
		if err != nil {
			if app.DevMode {
				return "", fmt.Errorf("query %q: %w", name, err)
			}
			log.Printf("gotmpl query %q failed: %s", name, err)
			if isSingleRowQuery(sql) {
				ctx.Data[name] = map[string]any{}
			} else {
				ctx.Data[name] = []map[string]any{}
			}
			continue
		}
		if isSingleRowQuery(sql) {
			if len(rows) > 0 {
				ctx.Data[name] = rows[0]
			} else {
				ctx.Data[name] = map[string]any{}
			}
		} else {
			ctx.Data[name] = rows
		}
		ctx.QueryCount++
	}

	// 2. Compile the template with the standard helper funcs registered.
	tmplName := page.Route
	if tmplName == "" {
		tmplName = page.File
	}
	tmpl := template.New(tmplName).Funcs(gotmplHelpers(app, ctx))

	// 2a. Parse partials/ as named templates so {{template "name" .}} works
	// for shared snippets. Best-effort - failure to parse one partial
	// shouldn't kill the page render.
	partialsDir := filepath.Join(app.Dir, "partials")
	if entries, err := os.ReadDir(partialsDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".html") {
				continue
			}
			pData, err := os.ReadFile(filepath.Join(partialsDir, e.Name()))
			if err != nil {
				continue
			}
			pName := strings.TrimSuffix(e.Name(), ".html")
			if _, err := tmpl.New(pName).Parse(string(pData)); err != nil {
				log.Printf("gotmpl partial %q parse: %s", pName, err)
			}
		}
	}

	// 2b. Parse the page body.
	parsed, err := tmpl.Parse(body)
	if err != nil {
		return "", fmt.Errorf("template parse: %w", err)
	}

	// 3. Execute against ctx.Data.
	var buf bytes.Buffer
	if err := parsed.Execute(&buf, ctx.Data); err != nil {
		return "", fmt.Errorf("template execute: %w", err)
	}
	return buf.String(), nil
}

// gotmplHelpers returns the FuncMap registered on every page template.
// Kept tight - the model knows the helpers because they're tiny and
// uniform across every page; less to memorize than the 26-pipe mustache
// dialect, and each helper is a real Go function with a real signature.
// gotmplHelpers returns the FuncMap every gotmpl page renders with.
// The base is Sprig's HtmlFuncMap (~200 funcs: math add/sub/mul/div/
// mod, strings upper/lower/title/trim/replace/split/join/regex,
// dates now/dateFormat, lists, dicts, defaults, type coercion,
// crypto/encoding, etc.) - same surface Helm/kubectl expose, which
// is what the agent's training prior reaches for first.
//
// On top of Sprig we layer the framework-specific helpers (csrf,
// env, t, dict - yes, sprig's `dict` is overridden to keep the
// framework signature stable). Framework helpers take precedence.
//
// All helpers are nil-safe: env / t / dict don't deref `app` or
// `ctx` when they're nil, so the write-time validator's stub-execute
// pass against nil data doesn't crash on a real template.
func gotmplHelpers(app *App, ctx *RenderContext) template.FuncMap {
	fm := sprig.HtmlFuncMap()

	// ----- Framework helpers (override Sprig where names collide) -----

	// csrf emits the hidden input + meta tag so forms and HTMX both
	// pass CSRF validation. Sprig has no equivalent - this is ours.
	fm["csrf"] = func() template.HTML {
		tok := generateCSRFToken()
		return template.HTML(fmt.Sprintf(
			`<input type="hidden" name="_csrf" value="%s"><meta name="csrf-token" content="%s">`,
			template.HTMLEscapeString(tok), template.HTMLEscapeString(tok),
		))
	}
	// env reads an env.yaml key. Sprig's `env` reads OS environment
	// variables; we override to read the per-app env.yaml - that's
	// the framework convention. Returns "" when missing or app=nil
	// (nil-app comes from the write-time validator's stub-execute).
	fm["env"] = func(key string) string {
		if app == nil {
			return ""
		}
		return EnvLookup(app.Dir, key)
	}
	// t looks up an i18n key for the current request's language.
	// Sprig has no equivalent.
	fm["t"] = func(key string) string {
		lang := "en"
		if ctx != nil && ctx.Request != nil {
			if q := ctx.Request.URL.Query().Get("lang"); q != "" {
				lang = q
			} else if c, err := ctx.Request.Cookie("lang"); err == nil && c.Value != "" {
				lang = c.Value
			}
		}
		return T(key, lang)
	}
	// dict - Sprig has this too with the same signature. Keeping our
	// version pinned for backwards compat in case Sprig changes.
	fm["dict"] = func(pairs ...any) (map[string]any, error) {
		if len(pairs)%2 != 0 {
			return nil, fmt.Errorf("dict requires even number of args")
		}
		out := make(map[string]any, len(pairs)/2)
		for i := 0; i < len(pairs); i += 2 {
			k, ok := pairs[i].(string)
			if !ok {
				return nil, fmt.Errorf("dict key %d not a string", i)
			}
			out[k] = pairs[i+1]
		}
		return out, nil
	}

	return fm
}

// isSingleRowQuery returns true when a frontmatter query is shaped to
// produce at most one row. Two triggers:
//
//  1. Trailing `LIMIT 1` (case-insensitive, whitespace-tolerant, may
//     have a trailing semicolon). Covers per-user profile, app config,
//     latest thing.
//  2. Pure-aggregate SELECT with no GROUP BY - every projected column
//     is wrapped in an aggregate function (COUNT/SUM/AVG/MAX/MIN/TOTAL)
//     or is a constant. SQL guarantees this returns exactly one row.
//     Covers the stat-card / dashboard query shape:
//     SELECT COUNT(*) AS total, SUM(amount) AS revenue FROM orders
//     The agent shouldn't have to remember LIMIT 1 to make `.stats.total`
//     work - the query shape already promises it.
//
// When true, the renderer stores the row as a map directly. Templates
// write `.stats.total` and missing/zero-row cases resolve cleanly via
// missingkey=zero - no `(index .x 0)` indexing.
var singleRowQueryRe = regexp.MustCompile(`(?i)\blimit\s+1\s*;?\s*$`)

// aggregateSelectRe matches a SELECT statement whose every output column
// is an aggregate (or constant) AND has no GROUP BY. The shape we recognize:
//
//	SELECT <aggregate-expr>[, <aggregate-expr>]* FROM ... [WHERE ...] [;]
//
// where each aggregate-expr starts with COUNT|SUM|AVG|MIN|MAX|TOTAL.
// We can't fully parse SQL with a regex, so we accept false negatives
// (complex projections) but want zero false positives (no GROUP BY).
func isAggregateOnlyQuery(sql string) bool {
	s := strings.ToLower(strings.TrimSpace(sql))
	s = strings.TrimSuffix(s, ";")
	s = strings.TrimSpace(s)
	if !strings.HasPrefix(s, "select ") {
		return false
	}
	// Any GROUP BY anywhere disqualifies - those produce multiple rows.
	if strings.Contains(s, " group by ") {
		return false
	}
	// Extract the projection (between SELECT and FROM).
	rest := s[len("select "):]
	fromIdx := strings.Index(rest, " from ")
	if fromIdx == -1 {
		return false
	}
	projection := rest[:fromIdx]
	// Split on top-level commas. SQL aggregate functions can contain
	// commas inside parens, so depth-track.
	cols := splitTopLevel(projection, ',')
	if len(cols) == 0 {
		return false
	}
	for _, col := range cols {
		col = strings.TrimSpace(col)
		if !columnIsAggregate(col) {
			return false
		}
	}
	return true
}

// splitTopLevel splits a string on `sep`, ignoring instances inside parens.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth := 0
	start := 0
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		case sep:
			if depth == 0 {
				out = append(out, s[start:i])
				start = i + 1
			}
		}
	}
	out = append(out, s[start:])
	return out
}

// columnIsAggregate reports whether a projection column is an aggregate
// function call. Matches an identifier from the aggregate set followed
// by `(`, ignoring leading whitespace.
var aggregateFuncs = []string{"count", "sum", "avg", "min", "max", "total"}

func columnIsAggregate(col string) bool {
	col = strings.TrimSpace(strings.ToLower(col))
	for _, fn := range aggregateFuncs {
		if strings.HasPrefix(col, fn+"(") || strings.HasPrefix(col, fn+" (") {
			return true
		}
	}
	return false
}

func isSingleRowQuery(sql string) bool {
	trimmed := strings.TrimSpace(sql)
	if singleRowQueryRe.MatchString(trimmed) {
		return true
	}
	return isAggregateOnlyQuery(trimmed)
}

// runFrontmatterQuery executes a SQL string with the standard set of bind
// parameters (:user_id, :user_email, :user_role, :user_group_id, and
// :param_<name> from URL query string) substituted in. Returns the rows
// as []map[string]any so they're directly usable from html/template.
func runFrontmatterQuery(app *App, ctx *RenderContext, sqlText string) ([]map[string]any, error) {
	// Substitute :name placeholders with ? and collect args in order.
	// Supports the same set the rest of the framework supports.
	bindRe := regexp.MustCompile(`:([a-zA-Z_][a-zA-Z0-9_]*)`)
	var args []any
	resolved := bindRe.ReplaceAllStringFunc(sqlText, func(m string) string {
		name := strings.TrimPrefix(m, ":")
		val, ok := resolveBind(ctx, name)
		if !ok {
			// Unknown bind - leave the placeholder so the SQL parser
			// gives a useful error rather than silently substituting NULL.
			return m
		}
		args = append(args, val)
		return "?"
	})
	rows, err := QueryRows(app.DB, resolved, args...)
	if err != nil {
		return nil, err
	}
	return rows, nil
}

// resolveBind maps a :name placeholder to its runtime value from the
// session/request context. Returns ok=false if the name isn't a
// recognized bind - the caller leaves it in place so the SQL error is
// honest.
func resolveBind(ctx *RenderContext, name string) (any, bool) {
	switch name {
	case "user_id":
		if ctx.User != nil {
			return ctx.User.UserID, true
		}
		return nil, false
	case "user_email":
		if ctx.User != nil {
			return ctx.User.Email, true
		}
		return nil, false
	case "user_role":
		if ctx.User != nil {
			return ctx.User.Role, true
		}
		return nil, false
	case "user_group_id":
		if ctx.User != nil && ctx.User.HasGroup() {
			return ctx.User.GroupID, true
		}
		return nil, false
	}
	// param_<name> binds to a URL query string value.
	if strings.HasPrefix(name, "param_") && ctx.Request != nil {
		key := strings.TrimPrefix(name, "param_")
		if v := ctx.Request.URL.Query().Get(key); v != "" {
			return v, true
		}
	}
	// Path param fallback - net/http's PathValue is populated for mux
	// patterns like /sheet/{id}.
	if ctx.Request != nil {
		if v := ctx.Request.PathValue(name); v != "" {
			return v, true
		}
	}
	return nil, false
}

// EnvLookup reads a single key from env.yaml. Returns "" if the file
// is missing or the key isn't set. Best-effort; no caching here - the
// env.yaml is small and loads on demand.
func EnvLookup(appDir, key string) string {
	data, err := os.ReadFile(filepath.Join(appDir, "env.yaml"))
	if err != nil {
		return ""
	}
	var env map[string]any
	if err := yaml.Unmarshal(data, &env); err != nil {
		return ""
	}
	if v, ok := env[key]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}
