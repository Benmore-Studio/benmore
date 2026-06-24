//go:build !cli

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"html"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// queryCache provides a simple in-memory cache for <query cache="5m"> tags.
// Keyed on SHA256(sql + args), entries expire based on the cache duration.
var queryCache = struct {
	mu      sync.RWMutex
	entries map[string]*queryCacheEntry
}{entries: make(map[string]*queryCacheEntry)}

type queryCacheEntry struct {
	rows      []map[string]any
	expiresAt time.Time
	table     string // which table this query reads from (for per-table invalidation)
}

func queryCacheKey(sql string, args []any) string {
	h := sha256.New()
	h.Write([]byte(sql))
	for _, a := range args {
		h.Write([]byte(fmt.Sprintf("%v", a)))
	}
	return hex.EncodeToString(h.Sum(nil))
}

func queryCacheGet(key string) ([]map[string]any, bool) {
	queryCache.mu.RLock()
	defer queryCache.mu.RUnlock()
	entry, ok := queryCache.entries[key]
	if !ok || time.Now().After(entry.expiresAt) {
		return nil, false
	}
	return entry.rows, true
}

func queryCacheSet(key string, rows []map[string]any, ttl time.Duration, table string) {
	queryCache.mu.Lock()
	defer queryCache.mu.Unlock()
	queryCache.entries[key] = &queryCacheEntry{rows: rows, expiresAt: time.Now().Add(ttl), table: table}
}

// InvalidateQueryCacheForTable clears cached queries that read from the given table.
// Only the mutated table's caches are cleared - other tables stay warm.
func InvalidateQueryCacheForTable(table string) {
	queryCache.mu.Lock()
	defer queryCache.mu.Unlock()
	for key, entry := range queryCache.entries {
		if entry.table == table {
			delete(queryCache.entries, key)
		}
	}
}

var (
	queryTagRe = regexp.MustCompile(`(?s)<query\s+([^>]*)>(.*?)</query>`)
	// Self-closing required: <include src="..." />. Docs (pages.md,
	// templates.md, docs-templates.html) all show this form.
	includeTagRe = regexp.MustCompile(`<include\s+src="([^"]+)"\s*/>`)
	pageAttrRe   = regexp.MustCompile(`<page\s+([^>]*)>`)
	schemaTagRe  = regexp.MustCompile(`(?s)<schema>(.*?)</schema>`)
	seedTagRe    = regexp.MustCompile(`(?s)<seed>(.*?)</seed>`)
	pageBlockRe  = regexp.MustCompile(`(?s)<page\s+([^>]*)>(.*?)</page>`)
	attrRe       = regexp.MustCompile(`(\w+)="([^"]*)"`)
)

// ParsePageAttrs extracts auth, scope, title, layout, and require attributes from a page's HTML.
func ParsePageAttrs(rawHTML string) (auth, scope, title, layout string) {
	if m := pageAttrRe.FindStringSubmatch(rawHTML); m != nil {
		attrs := parseAttrs(m[1])
		auth = attrs["auth"]
		scope = attrs["scope"]
		title = attrs["title"]
		layout = attrs["layout"]
	}
	return
}

// ExtractPageRequire extracts the require="..." attribute for generic user field gating.
func ExtractPageRequire(rawHTML string) string {
	if m := pageAttrRe.FindStringSubmatch(rawHTML); m != nil {
		attrs := parseAttrs(m[1])
		return attrs["require"]
	}
	return ""
}

// ExtractPageType extracts the type="..." attribute for auth page discovery.
func ExtractPageType(rawHTML string) string {
	if m := pageAttrRe.FindStringSubmatch(rawHTML); m != nil {
		attrs := parseAttrs(m[1])
		return attrs["type"]
	}
	return ""
}

// ExtractPageRedirect extracts the redirect="..." attribute for role-based routing.
// Format: redirect="admin:/admin,user:/dashboard,*:/home"
// The * wildcard matches any authenticated user. Checked in order, first match wins.
func ExtractPageRedirect(rawHTML string) string {
	if m := pageAttrRe.FindStringSubmatch(rawHTML); m != nil {
		attrs := parseAttrs(m[1])
		return attrs["redirect"]
	}
	return ""
}

// ParsePageSEO extracts SEO attributes from a page's HTML.
func ParsePageSEO(rawHTML string) (description, image, robots string) {
	if m := pageAttrRe.FindStringSubmatch(rawHTML); m != nil {
		attrs := parseAttrs(m[1])
		description = attrs["description"]
		image = attrs["image"]
		robots = attrs["robots"]
	}
	return
}

// ProcessIncludes expands <include src="..."/> tags with partial content.
// `src` is normally a developer-authored template path; we still validate
// it stays inside `dir` so that a CMS-style flow rendering DB-controlled
// HTML through this pipeline can't escape via `../../`.
func ProcessIncludes(content string, partials map[string]string, dir string) string {
	return includeTagRe.ReplaceAllStringFunc(content, func(match string) string {
		m := includeTagRe.FindStringSubmatch(match)
		if m == nil {
			return match
		}
		src := m[1]

		// Check in-memory partials first
		if partial, ok := partials[src]; ok {
			return partial
		}

		// Read from disk, after confirming the resolved path is inside `dir`.
		absRoot, _ := filepath.Abs(dir)
		path, err := filepath.Abs(filepath.Join(dir, src))
		if err != nil || (path != absRoot && !strings.HasPrefix(path, absRoot+string(filepath.Separator))) {
			return fmt.Sprintf(`<div class="benmore-error">Include error: %s blocked</div>`, html.EscapeString(src))
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Sprintf(`<div class="benmore-error">Include error: %s not found</div>`, html.EscapeString(src))
		}
		return string(data)
	})
}

// ExtractQueries finds all <query> tags and returns them with positions.
// Handles nested <query> tags correctly by tracking depth.
func ExtractQueries(content string) []QueryTag {
	var queries []QueryTag
	// Match <query ...> - must handle > inside quoted attribute values (e.g. sql="... > 0")
	// Uses a non-greedy match that finds the last > after accounting for quoted strings
	openTagRe := regexp.MustCompile(`<query\s+((?:[^>"]*"[^"]*")*[^>]*)>`)
	i := 0
	for i < len(content) {
		// Find next <query ...>
		loc := openTagRe.FindStringIndex(content[i:])
		if loc == nil {
			break
		}
		tagStart := i + loc[0]
		tagEnd := i + loc[1]
		attrStr := openTagRe.FindStringSubmatch(content[i:])[1]

		// Check for self-closing: </query> immediately after (possibly with whitespace)
		rest := content[tagEnd:]
		closeIdx := strings.Index(rest, "</query>")
		if closeIdx == -1 {
			// No closing tag - treat as self-closing, no inner content
			queries = append(queries, QueryTag{
				SQL:   parseAttrs(attrStr)["sql"],
				As:    parseAttrs(attrStr)["as"],
				From:  parseAttrs(attrStr)["from"],
				Attrs: parseAttrs(attrStr),
				Start: tagStart,
				End:   tagEnd,
				Inner: "",
			})
			i = tagEnd
			continue
		}

		// Find the matching </query> by tracking depth
		depth := 1
		searchPos := tagEnd
		matchEnd := -1
		for searchPos < len(content) {
			nextOpen := strings.Index(content[searchPos:], "<query ")
			nextClose := strings.Index(content[searchPos:], "</query>")

			if nextClose == -1 {
				break // no more closing tags
			}

			// If there's another <query before this </query>, increase depth
			if nextOpen != -1 && nextOpen < nextClose {
				depth++
				searchPos = searchPos + nextOpen + 7 // skip past "<query "
				continue
			}

			// Found a </query>
			depth--
			if depth == 0 {
				matchEnd = searchPos + nextClose + 8 // include "</query>"
				break
			}
			searchPos = searchPos + nextClose + 8
		}

		if matchEnd == -1 {
			// Unmatched - treat as self-closing
			queries = append(queries, QueryTag{
				SQL:   parseAttrs(attrStr)["sql"],
				As:    parseAttrs(attrStr)["as"],
				From:  parseAttrs(attrStr)["from"],
				Attrs: parseAttrs(attrStr),
				Start: tagStart,
				End:   tagEnd,
				Inner: "",
			})
			i = tagEnd
			continue
		}

		inner := content[tagEnd : matchEnd-8] // exclude "</query>"
		attrs := parseAttrs(attrStr)
		queries = append(queries, QueryTag{
			SQL:   attrs["sql"],
			As:    attrs["as"],
			From:  attrs["from"],
			Attrs: attrs,
			Start: tagStart,
			End:   matchEnd,
			Inner: inner,
		})
		i = tagEnd // continue searching inside (for nested queries)
	}
	return queries
}

// RenderTemplate processes a full page: includes, queries, mustache, directives.
func RenderTemplate(app *App, page *Page, ctx *RenderContext) (string, error) {
	content := page.RawHTML

	// 0. Frontmatter dispatch. If the file starts with `---` and declares
	// `engine: gotmpl`, route through the html/template path. Pages without
	// frontmatter, or with `engine:` set to anything else (or omitted),
	// fall through to the existing mustache pipeline below - no behavior
	// change for legacy apps.
	fm, body, fmErr := ExtractFrontmatter(content)
	if fmErr != nil {
		return "", fmErr
	}
	if fm != nil {
		// Merge frontmatter into Page so auth/scope/layout work even on a
		// fresh load that hasn't been through the page loader yet.
		ApplyFrontmatterToPage(page, fm)
		content = body
		if fm.Engine == "gotmpl" {
			rendered, err := renderGoTemplate(app, page, ctx, fm, body)
			if err != nil {
				return "", err
			}
			// Defer to the existing layout + image-opts + N+1 stages so
			// gotmpl pages get the same downstream treatment as mustache.
			return finalizeRender(app, page, ctx, rendered), nil
		}
		if fm.Engine == "raw" {
			// `engine: raw` = serve the page body verbatim, no template
			// pass at all. For SPAs / bring-your-own-frontend where the
			// HTML/JS shouldn't be scanned for {{x}} or :directive
			// patterns (a React bundle's {{ would be a false hit).
			//
			// The framework still wants its essentials on the page -
			// CSRF meta, auto-refresh shim, the badge, security headers
			// - but those come from the layout pipeline downstream
			// (finalizeRender), not from string-rewriting the body.
			//
			// The user opts into this by writing:
			//   ---
			//   engine: raw
			//   layout: none   # optional; recommended for SPAs
			//   ---
			//   <!doctype html><html>…my JS bundle…</html>
			//
			// Same origin as the backend - cookies, CSRF, /api/* all
			// just work. Edges live at a different origin; raw pages do
			// not.
			return finalizeRender(app, page, ctx, body), nil
		}
	}

	// 1. Strip <page> wrapper if present
	content = stripPageTag(content)

	// 2. Expand includes
	content = ProcessIncludes(content, app.Partials, app.Dir)

	// 2b. Resolve {{env.X}} variables from env.yaml
	content = InterpolateEnv(content, app.Dir)

	// 2c. Resolve {{t "key"}} i18n translations
	// Precedence: ?lang= query param → lang cookie → Accept-Language header → default
	lang := "en"
	if ctx.Request != nil {
		if q := ctx.Request.URL.Query().Get("lang"); q != "" {
			lang = q
		} else if c, err := ctx.Request.Cookie("lang"); err == nil && c.Value != "" {
			lang = c.Value
		} else if detected := GetLangFromRequest(ctx.Request.Header.Get("Accept-Language")); detected != "" {
			lang = detected
		}
	}
	content = TranslateTemplate(content, lang)

	// 3. Execute <query> tags
	content, err := executeQueries(content, app, ctx)
	if err != nil {
		return "", err
	}

	// 3a. Expand mustache loops/sections FIRST, but protect <fetch> inner
	// content by temporarily swapping {{ with a safe marker inside fetch blocks.
	// This lets {{#sites}}...<fetch>...{{/sites}} expand the loop (duplicating
	// the fetch tag per site with correct URL vars) while preserving
	// {{wx.current.*}} inside the fetch for later rendering.
	content = expandMustacheWithProtectedFetch(content, ctx.Data)

	// 3b. Execute <fetch> tags - async with loading skeletons
	// Page renders instantly, data loads via HTMX and fills in
	content = ExpandFetchTagsAsync(content, app, ctx)

	// 3c. Expand <transitions> tags - render workflow transition buttons
	if app.Workflows != nil {
		content = expandTransitionTags(content, app, ctx)
	}

	// 4. Compile directives to HTMX
	content = CompileDirectives(content)

	// 6. Second mustache pass - render any vars from fetch results
	content = RenderMustache(content, ctx.Data)

	return finalizeRender(app, page, ctx, content), nil
}

// finalizeRender runs the engine-agnostic tail of the render pipeline:
// layout wrapping, kit auto-inject, image optimizations, N+1 detection.
// Both the mustache and gotmpl paths route through here so a switch in
// engine doesn't change the final HTML's outer shell.
func finalizeRender(app *App, page *Page, ctx *RenderContext, content string) string {
	if ctx.Page != nil && ctx.Page.Layout != "" && ctx.Page.Layout != "none" {
		layoutPath := fmt.Sprintf("layouts/%s.html", ctx.Page.Layout)
		if layoutData, err := os.ReadFile(filepath.Join(app.Dir, layoutPath)); err == nil {
			layoutHTML := string(layoutData)
			layoutHTML = ProcessIncludes(layoutHTML, app.Partials, app.Dir)
			layoutHTML = strings.Replace(layoutHTML, "{{content}}", content, 1)
			content = RenderMustache(layoutHTML, ctx.Data)
		}
	} else if ctx.Page != nil {
		// layout="none" or "" - no layout wrapping. Auto-inject partials/kit.html
		// if it exists so marketing/landing/auth pages that skip the layout
		// still get the app's design-system styling (CSS variables, component
		// classes, fonts) without boilerplate in every file.
		if kitData, err := os.ReadFile(filepath.Join(app.Dir, "partials", "kit.html")); err == nil {
			kitHTML := ProcessIncludes(string(kitData), app.Partials, app.Dir)
			content = kitHTML + "\n" + content
		}
	}

	// Auto-add loading="lazy" and decoding="async" to <img> tags that don't have them
	content = addImageOptimizations(content)

	// N+1 detection: warn and inject HTML comment in dev mode
	if ctx.QueryCount > 10 && app.DevMode {
		pageName := ""
		if ctx.Page != nil {
			pageName = ctx.Page.Route
		}
		log.Printf("N+1 WARNING: page %s executed %d queries (threshold: 10)", pageName, ctx.QueryCount)
	}
	if app.DevMode && ctx.QueryCount > 0 {
		content += fmt.Sprintf("\n<!-- N+1: %d queries -->", ctx.QueryCount)
	}

	return content
}

// injectRawPageEssentials was the React-SPA head/body injector for
// `engine: raw` pages - CSRF meta, /_internal/* React + bm.js scripts,
// theme block, analytics, recorder, testing banner, "Built with"
// badge. Removed when the SPA stack was stripped (v2.4.0). Raw pages
// now get just the CSRF meta tag via injectCSRFMeta(static_html.go).

// addImageOptimizations adds loading="lazy" and decoding="async" to img tags.
func addImageOptimizations(content string) string {
	imgRe := regexp.MustCompile(`<img\s([^>]*?)>`)
	return imgRe.ReplaceAllStringFunc(content, func(match string) string {
		if strings.Contains(match, `loading=`) {
			return match // already has loading attribute
		}
		// Don't lazy-load likely LCP images (first image, logo, hero)
		if strings.Contains(match, `logo`) || strings.Contains(match, `hero`) || strings.Contains(match, `fetchpriority`) {
			return match
		}
		// Insert before closing >
		return strings.Replace(match, ">", ` loading="lazy" decoding="async">`, 1)
	})
}

func executeQueries(content string, app *App, ctx *RenderContext) (string, error) {
	// Process queries innermost-first. Re-extract after each pass since positions shift.
	for pass := 0; pass < 50; pass++ {
		queries := ExtractQueries(content)
		if len(queries) == 0 {
			break
		}

		// Collect leaf queries (no nested <query> in their Inner) - process from last to first
		var leaves []int
		for i, q := range queries {
			if !strings.Contains(q.Inner, "<query ") {
				leaves = append(leaves, i)
			}
		}
		if len(leaves) == 0 {
			break // safety: no leaf queries found
		}

		// Process leaves from last to first (preserves earlier positions)
		for li := len(leaves) - 1; li >= 0; li-- {
			q := queries[leaves[li]]

			var sql string
			var args []any

			if q.From != "" {
				// Shorthand mode: expand from/pick/where/owned/sort into SQL.
				// Pre-resolve mustache vars in attribute values so authors can
				// write where="id = {{param_id}}" the same as raw <query sql>.
				// Issue #7. Vars resolve to escaped string values inline since
				// shorthand builds WHERE via concatenation (not ? placeholders).
				resolvedAttrs := make(map[string]string, len(q.Attrs))
				for k, v := range q.Attrs {
					resolvedAttrs[k] = resolveShorthandVars(v, ctx.Data)
				}
				var userID int64
				if ctx.User != nil {
					userID = ctx.User.UserID
				}
				sql, args = ExpandShorthand(app, q.From, resolvedAttrs, userID)
			} else if q.SQL != "" {
				// Raw SQL mode - resolve mustache vars (e.g. {{param_id}}) as parameterized args
				sql, args = resolveQueryParams(q.SQL, ctx.Data, args)
			} else {
				continue
			}

			// Replace :current_user with session user ID
			if ctx.User != nil && strings.Contains(sql, ":current_user") {
				sql = strings.ReplaceAll(sql, ":current_user", "?")
				args = append(args, ctx.User.UserID)
			}

			// Handle scope="owner" - inject WHERE clause
			if ctx.Page != nil && ctx.Page.Scope == "owner" && ctx.User != nil {
				sql = injectOwnerScope(sql, ctx.User.UserID)
			}

			// Query cache: <query cache="5m" ...> caches results for the given duration
			var cacheTTL time.Duration
			if cacheStr := q.Attrs["cache"]; cacheStr != "" {
				cacheTTL, _ = time.ParseDuration(cacheStr)
			}
			var cacheKey string
			if cacheTTL > 0 {
				cacheKey = queryCacheKey(sql, args)
				if cachedRows, ok := queryCacheGet(cacheKey); ok {
					if q.As != "" {
						ctx.Data[q.As] = cachedRows
						if len(cachedRows) == 1 {
							for k, v := range cachedRows[0] {
								ctx.Data[q.As+"."+k] = v
							}
						}
					}
					if q.Inner != "" {
						var rendered strings.Builder
						if q.As != "" && len(cachedRows) > 0 {
							sectionTag := "{{#" + q.As + "}}"
							hasSectionLoop := strings.Contains(q.Inner, sectionTag)
							if hasSectionLoop {
								innerProtected := protectFetchInner(q.Inner)
								expanded := RenderMustache(innerProtected, ctx.Data)
								rendered.WriteString(restoreFetchInner(expanded))
							} else {
								for _, row := range cachedRows {
									rowData := mergeData(ctx.Data, row)
									innerProtected := protectFetchInner(q.Inner)
									expanded := RenderMustache(innerProtected, rowData)
									rendered.WriteString(restoreFetchInner(expanded))
								}
							}
						} else {
							rendered.WriteString(RenderMustache(q.Inner, ctx.Data))
						}
						content = content[:q.Start] + rendered.String() + content[q.End:]
					} else {
						content = content[:q.Start] + content[q.End:]
					}
					continue
				}
			}

			// Mock query mode: <query mock="5" ...> generates fake rows without hitting DB.
			// Used in prototype phase - pages render with realistic dummy data before schema exists.
			var rows []map[string]any
			var err error

			if mockStr := q.Attrs["mock"]; mockStr != "" {
				mockCount := 3 // default
				// Accept 0 explicitly to render the empty-state branch
				// (inverted mustache section).
				if n, e := strconv.Atoi(mockStr); e == nil && n >= 0 {
					mockCount = n
				}
				rows = generateMockRows(app, q, mockCount)
			} else {
				rows, err = QueryRows(app.DB, sql, args...)
			}

			// N+1 detection: track query count and log SQL
			ctx.QueryCount++
			if app.DevMode {
				logSQL := sql
				if len(logSQL) > 200 {
					logSQL = logSQL[:200] + "..."
				}
				ctx.QueryLog = append(ctx.QueryLog, logSQL)
			}

			if err != nil {
				var errHTML string
				if app.DevMode {
					// Dev mode: show full error with SQL for debugging
					errHTML = fmt.Sprintf(`<div class="benmore-error"><strong>SQL Error</strong><pre>%s</pre><p>%s</p></div>`,
						html.EscapeString(q.SQL), html.EscapeString(err.Error()))
				} else {
					// Production: generic error, log details to stderr
					log.Printf("ERROR [query] %s: %s", q.SQL, err.Error())
					errHTML = `<div class="benmore-error">An error occurred loading this content.</div>`
				}
				content = content[:q.Start] + errHTML + content[q.End:]
				continue
			}

			// Cache results if cache attribute was set
			if cacheKey != "" && cacheTTL > 0 {
				// Determine table name for per-table cache invalidation
				cacheTable := q.From
				if cacheTable == "" {
					cacheTable = extractTableFromSQL(sql)
				}
				queryCacheSet(cacheKey, rows, cacheTTL, cacheTable)
			}

			// Store results in context
			if q.As != "" {
				// Always store as array (enables {{#var}} iteration and {{var.0.field}} access)
				ctx.Data[q.As] = rows
				if len(rows) == 1 {
					// Single row: also flatten fields for direct access: {{var.field}}
					for k, v := range rows[0] {
						ctx.Data[q.As+"."+k] = v
					}
				}
			}

			// Render the inner template with query results
			if q.Inner != "" {
				var rendered strings.Builder
				if q.As != "" && len(rows) > 0 {
					// Check if inner content contains a {{#as}}...{{/as}} section matching
					// the query's as name. If so, let mustache handle iteration (render once).
					// Otherwise, render per-row (backward compat for templates without sections).
					sectionTag := "{{#" + q.As + "}}"
					hasSectionLoop := strings.Contains(q.Inner, sectionTag)
					if hasSectionLoop {
						// Render once - mustache {{#as}} section handles row iteration
						innerProtected := protectFetchInner(q.Inner)
						expanded := RenderMustache(innerProtected, ctx.Data)
						rendered.WriteString(restoreFetchInner(expanded))
					} else {
						// No section wrapper - render per-row (each row's fields available directly)
						for _, row := range rows {
							rowData := mergeData(ctx.Data, row)
							innerProtected := protectFetchInner(q.Inner)
							expanded := RenderMustache(innerProtected, rowData)
							rendered.WriteString(restoreFetchInner(expanded))
						}
					}
				} else if len(rows) == 0 {
					// Empty state - render {{^as}}...{{/as}} blocks
					rendered.WriteString(RenderMustache(q.Inner, ctx.Data))
				}
				content = content[:q.Start] + rendered.String() + content[q.End:]
			} else {
				// No inner content - just remove the tag
				content = content[:q.Start] + content[q.End:]
			}
		} // end leaf iteration
	} // end pass loop

	return content, nil
}

// protectFetchInner replaces {{ }} inside <fetch> inner content with safe markers.
func protectFetchInner(content string) string {
	return fetchTagRe.ReplaceAllStringFunc(content, func(match string) string {
		m := fetchTagRe.FindStringSubmatch(match)
		if m == nil {
			return match
		}
		inner := m[2]
		protectedInner := strings.ReplaceAll(inner, "{{", "\x00MO\x00")
		protectedInner = strings.ReplaceAll(protectedInner, "}}", "\x00MC\x00")
		return "<fetch " + m[1] + ">" + protectedInner + "</fetch>"
	})
}

// restoreFetchInner restores protected markers back to mustache syntax.
func restoreFetchInner(content string) string {
	content = strings.ReplaceAll(content, "\x00MO\x00", "{{")
	content = strings.ReplaceAll(content, "\x00MC\x00", "}}")
	return content
}

// expandMustacheWithProtectedFetch runs mustache rendering but protects <fetch>
// inner content from being consumed. This allows {{#sites}}<fetch url="{{lat}}">
// {{wx.temp}}</fetch>{{/sites}} to work: the loop expands (duplicating the fetch
// per site with correct URL vars) while {{wx.temp}} survives for the fetch handler.
func expandMustacheWithProtectedFetch(content string, data map[string]any) string {
	// Replace {{ and }} inside <fetch>...</fetch> inner content with safe markers
	const openMarker = "\x00OPEN\x00"
	const closeMarker = "\x00CLOSE\x00"

	protected := fetchTagRe.ReplaceAllStringFunc(content, func(match string) string {
		m := fetchTagRe.FindStringSubmatch(match)
		if m == nil {
			return match
		}
		attrStr := m[1]
		inner := m[2]

		// Protect inner content mustache vars but NOT the URL attribute vars
		protectedInner := strings.ReplaceAll(inner, "{{", openMarker)
		protectedInner = strings.ReplaceAll(protectedInner, "}}", closeMarker)

		return "<fetch " + attrStr + ">" + protectedInner + "</fetch>"
	})

	// Run mustache - loops expand, URL vars resolve, inner content is protected
	rendered := RenderMustache(protected, data)

	// Restore protected markers back to mustache syntax
	rendered = strings.ReplaceAll(rendered, openMarker, "{{")
	rendered = strings.ReplaceAll(rendered, closeMarker, "}}")

	return rendered
}

// injectOwnerScope appends a user_id filter. userID is always from the server-side
// session (int64), never from user input, so fmt.Sprintf is safe here.
func injectOwnerScope(sql string, userID int64) string {
	upper := strings.ToUpper(sql)
	// Extract primary table alias to qualify user_id (avoids ambiguity in JOINs)
	qualifier := extractPrimaryAlias(upper, sql)
	col := "user_id"
	if qualifier != "" {
		col = qualifier + ".user_id"
	}
	hasTopLevelWhere := indexTopLevel(upper, "WHERE ") >= 0
	clause := fmt.Sprintf(" AND %s = %d", col, userID)
	if !hasTopLevelWhere {
		clause = fmt.Sprintf(" WHERE %s = %d", col, userID)
	}
	// Find insertion point: before top-level GROUP BY, ORDER BY, or LIMIT
	// (skip keywords inside parentheses like OVER(ORDER BY ...) or subqueries)
	for _, keyword := range []string{"GROUP BY", "ORDER BY", "LIMIT"} {
		if idx := indexTopLevel(upper, keyword); idx >= 0 {
			return sql[:idx] + clause + " " + sql[idx:]
		}
	}
	return sql + clause
}

// extractPrimaryAlias returns the alias (or table name) of the primary FROM table.
// Uses indexTopLevel to skip FROM inside subqueries.
// e.g. "SELECT ..., (SELECT ... FROM x) FROM players p LEFT JOIN teams t" → "p"
//
//	"FROM teams ORDER BY" → "teams"
func extractPrimaryAlias(upper, original string) string {
	idx := indexTopLevel(upper, "FROM ")
	if idx < 0 {
		return ""
	}
	rest := original[idx+5:] // after "FROM "
	rest = strings.TrimSpace(rest)
	fields := strings.Fields(rest)
	if len(fields) == 0 {
		return ""
	}
	table := fields[0]
	if len(fields) > 1 {
		next := strings.ToUpper(fields[1])
		if next != "WHERE" && next != "ORDER" && next != "GROUP" && next != "LIMIT" &&
			next != "LEFT" && next != "RIGHT" && next != "INNER" && next != "OUTER" &&
			next != "JOIN" && next != "CROSS" && next != "ON" && next != "NATURAL" {
			return fields[1] // alias
		}
	}
	return table
}

// indexTopLevel finds the first occurrence of keyword at parenthesis depth 0.
func indexTopLevel(upper, keyword string) int {
	depth := 0
	klen := len(keyword)
	for i := 0; i < len(upper)-klen+1; i++ {
		switch upper[i] {
		case '(':
			depth++
		case ')':
			if depth > 0 {
				depth--
			}
		default:
			if depth == 0 && upper[i:i+klen] == keyword {
				// Ensure it's a word boundary (not mid-identifier)
				if i > 0 && upper[i-1] != ' ' && upper[i-1] != ')' && upper[i-1] != '\n' && upper[i-1] != '\t' {
					continue
				}
				return i
			}
		}
	}
	return -1
}

// neutralizeReparse defuses mustache delimiters that appear INSIDE a resolved
// data value, so a later render pass can't re-interpret stored data as
// template syntax. The pipeline runs two full mustache passes (loops/sections,
// then fetch-result vars), and html.EscapeString doesn't touch `{`/`}` - so a
// stored field value like `{{user.email}}` would otherwise be re-evaluated
// against the VIEWING user's context (cross-user data disclosure / stored
// template injection). Replacing the delimiter pairs with HTML entities is
// display-identical (`&#123;` renders as `{`) but no longer matches the `{{`
// scanner. Resolved values are DATA, never template - only `<fetch>` inner
// content is intentionally re-rendered, and that has its own marker-based
// protection (protectFetchInner).
func neutralizeReparse(s string) string {
	if !strings.Contains(s, "{{") && !strings.Contains(s, "}}") {
		return s
	}
	s = strings.ReplaceAll(s, "{{", "{&#123;")
	s = strings.ReplaceAll(s, "}}", "&#125;}")
	return s
}

// RenderMustache performs simple mustache-like template rendering.
func RenderMustache(template string, data map[string]any) string {
	var result strings.Builder
	i := 0
	for i < len(template) {
		// Check for {{{{ truly raw }}}} (no sanitization - explicit dangerous opt-in)
		if i+4 <= len(template) && template[i:i+4] == "{{{{" {
			end := strings.Index(template[i+4:], "}}}}")
			if end >= 0 {
				key := strings.TrimSpace(template[i+4 : i+4+end])
				val := lookupValue(data, key)
				result.WriteString(neutralizeReparse(fmt.Sprintf("%v", val)))
				i = i + 4 + end + 4
				continue
			}
		}

		// Check for {{{ sanitized raw }}} - HTML sanitized (strips scripts, event handlers)
		if i+3 < len(template) && template[i:i+3] == "{{{" {
			end := strings.Index(template[i+3:], "}}}")
			if end >= 0 {
				key := strings.TrimSpace(template[i+3 : i+3+end])
				val := lookupValue(data, key)
				result.WriteString(neutralizeReparse(SanitizeHTML(fmt.Sprintf("%v", val))))
				i = i + 3 + end + 3
				continue
			}
		}

		// Check for {{ var }} or {{# section }} or {{^ inverted }} or {{/ close }}
		if i+2 < len(template) && template[i:i+2] == "{{" {
			end := strings.Index(template[i+2:], "}}")
			if end >= 0 {
				tag := strings.TrimSpace(template[i+2 : i+2+end])
				nextI := i + 2 + end + 2

				if strings.HasPrefix(tag, "#") {
					name := strings.TrimSpace(tag[1:])

					// Role section: {{#role "admin"}}...{{/role}} - server-side role check.
					// `requiredRole` may now be a comma-separated list of roles
					// (`{{#role "editor,reviewer"}}`); the section renders if the
					// caller holds ANY of them. This mirrors the access mode
					// `role:editor,reviewer` so SSR-gated UI and CRUD-layer auth
					// share one semantic.
					if strings.HasPrefix(name, `role "`) || strings.HasPrefix(name, `role '`) {
						requiredRole := strings.Trim(name[5:], `"' `)
						closeTag := "{{/role}}"
						closeIdx := strings.Index(template[nextI:], closeTag)
						if closeIdx >= 0 {
							inner := template[nextI : nextI+closeIdx]
							userRole, _ := data["user_role"].(string)
							appRole, _ := data["user_app_role"].(string)
							rolesAll, _ := data["user_roles"].(string)
							held := map[string]bool{}
							if userRole != "" {
								held[userRole] = true
							}
							if appRole != "" {
								held[appRole] = true
							}
							for _, r := range strings.Split(rolesAll, ",") {
								if t := strings.TrimSpace(r); t != "" {
									held[t] = true
								}
							}
							match := false
							for _, want := range strings.Split(requiredRole, ",") {
								want = strings.TrimSpace(want)
								if want == "" {
									continue
								}
								if held[want] || held["admin"] {
									match = true
									break
								}
							}
							if match {
								result.WriteString(RenderMustache(inner, data))
							}
							i = nextI + closeIdx + len(closeTag)
							continue
						}
					}

					// Conditional: {{#if expr}}...{{else}}...{{/if}}
					if strings.HasPrefix(name, "if ") {
						expr := strings.TrimSpace(name[3:])
						closeTag := "{{/if}}"
						openTag := "{{#if "
						// Find matching {{/if}} accounting for nested {{#if}} blocks
						closeIdx := findMatchingClose(template[nextI:], openTag, closeTag)
						if closeIdx >= 0 {
							body := template[nextI : nextI+closeIdx]
							// Split on {{else}} at depth 0 (not inside nested ifs)
							truePart, falsePart := body, ""
							elseIdx := findElseAtDepth0(body)
							if elseIdx >= 0 {
								truePart = body[:elseIdx]
								falsePart = body[elseIdx+8:]
							}
							if evaluateIfExpr(expr, data) {
								result.WriteString(RenderMustache(truePart, data))
							} else {
								result.WriteString(RenderMustache(falsePart, data))
							}
							i = nextI + closeIdx + len(closeTag)
							continue
						}
					}

					// Switch: {{#switch field}}{{#case "val1"}}...{{#case "val2"}}...{{#default}}...{{/switch}}
					if strings.HasPrefix(name, "switch ") {
						field := strings.TrimSpace(name[7:])
						closeTag := "{{/switch}}"
						openTag := "{{#switch "
						closeIdx := findMatchingClose(template[nextI:], openTag, closeTag)
						if closeIdx >= 0 {
							body := template[nextI : nextI+closeIdx]
							fieldVal := fmt.Sprintf("%v", lookupValue(data, field))
							result.WriteString(evaluateSwitch(body, fieldVal, data))
							i = nextI + closeIdx + len(closeTag)
							continue
						}
					}

					// Section: {{#name}}...{{/name}}
					closeTag := "{{/" + name + "}}"
					closeIdx := strings.Index(template[nextI:], closeTag)
					if closeIdx >= 0 {
						inner := template[nextI : nextI+closeIdx]
						val := lookupValue(data, name)
						result.WriteString(renderSection(inner, val, data))
						i = nextI + closeIdx + len(closeTag)
						continue
					}
				} else if strings.HasPrefix(tag, "^") {
					// Inverted section: {{^name}}...{{/name}}
					name := strings.TrimSpace(tag[1:])
					closeTag := "{{/" + name + "}}"
					closeIdx := strings.Index(template[nextI:], closeTag)
					if closeIdx >= 0 {
						inner := template[nextI : nextI+closeIdx]
						val := lookupValue(data, name)
						if isEmpty(val) {
							result.WriteString(RenderMustache(inner, data))
						}
						i = nextI + closeIdx + len(closeTag)
						continue
					}
				} else if strings.HasPrefix(tag, "/") {
					// Close tag (shouldn't reach here in well-formed templates)
					i = nextI
					continue
				} else {
					// Variable: {{name}} or {{name | pipe}} - HTML escaped
					key := tag
					pipe := ""
					if pipeIdx := strings.Index(tag, " | "); pipeIdx >= 0 {
						key = strings.TrimSpace(tag[:pipeIdx])
						pipe = strings.TrimSpace(tag[pipeIdx+3:])
					}
					val := lookupValue(data, key)
					s := fmt.Sprintf("%v", val)
					if pipe != "" {
						s = ApplyPipe(val, pipe)
					}
					result.WriteString(neutralizeReparse(html.EscapeString(s)))
					i = nextI
					continue
				}
			}
		}

		result.WriteByte(template[i])
		i++
	}
	return result.String()
}

// findMatchingClose finds the index of the closing tag that matches the nesting depth.
// Returns -1 if not found.
func findMatchingClose(s, openTag, closeTag string) int {
	depth := 0
	i := 0
	for i < len(s) {
		if i+len(openTag) <= len(s) && s[i:i+len(openTag)] == openTag {
			depth++
			i += len(openTag)
			continue
		}
		if i+len(closeTag) <= len(s) && s[i:i+len(closeTag)] == closeTag {
			if depth == 0 {
				return i
			}
			depth--
			i += len(closeTag)
			continue
		}
		i++
	}
	return -1
}

// findElseAtDepth0 finds {{else}} that is not inside a nested {{#if}}...{{/if}}.
func findElseAtDepth0(s string) int {
	depth := 0
	elseTag := "{{else}}"
	openTag := "{{#if "
	closeTag := "{{/if}}"
	i := 0
	for i < len(s) {
		if i+len(openTag) <= len(s) && s[i:i+len(openTag)] == openTag {
			depth++
			i += len(openTag)
			continue
		}
		if i+len(closeTag) <= len(s) && s[i:i+len(closeTag)] == closeTag {
			depth--
			i += len(closeTag)
			continue
		}
		if depth == 0 && i+len(elseTag) <= len(s) && s[i:i+len(elseTag)] == elseTag {
			return i
		}
		i++
	}
	return -1
}

func renderSection(inner string, val any, parentData map[string]any) string {
	if val == nil {
		return ""
	}

	switch v := val.(type) {
	case []map[string]any:
		var sb strings.Builder
		for _, item := range v {
			merged := mergeData(parentData, item)
			sb.WriteString(RenderMustache(inner, merged))
		}
		return sb.String()
	case map[string]any:
		merged := mergeData(parentData, v)
		return RenderMustache(inner, merged)
	case bool:
		if v {
			return RenderMustache(inner, parentData)
		}
		return ""
	case string:
		if v != "" {
			return RenderMustache(inner, parentData)
		}
		return ""
	case int64:
		if v != 0 {
			return RenderMustache(inner, parentData)
		}
		return ""
	default:
		return RenderMustache(inner, parentData)
	}
}

// resolveQueryParams replaces {{var}} placeholders in SQL with parameterized ? args.
// Unquoted vars become ? params (safe from injection). Vars inside SQL string quotes
// ('{{var}}') are replaced inline since SQLite doesn't bind params inside quotes.
// Inline values are sanitized to prevent SQL injection.
// resolveShorthandVars replaces {{var}} references in a shorthand attribute
// value (where/sort/limit/offset) with the resolved value from template
// context. Single quotes in the value are escaped to prevent SQL injection
// via interpolation. Used by the shorthand query path which builds WHERE
// clauses by concatenation rather than parameterised queries. Issue #7.
func resolveShorthandVars(s string, data map[string]any) string {
	if !strings.Contains(s, "{{") {
		return s
	}
	varRe := regexp.MustCompile(`\{\{(\w[\w.]*)\}\}`)
	return varRe.ReplaceAllStringFunc(s, func(match string) string {
		key := strings.TrimSpace(match[2 : len(match)-2])
		val := lookupValue(data, key)
		valStr := fmt.Sprintf("%v", val)
		// Escape single quotes - protects against an injection vector if a
		// developer accidentally references a user-controlled var.
		return strings.ReplaceAll(valStr, "'", "''")
	})
}

func resolveQueryParams(sqlStr string, data map[string]any, args []any) (string, []any) {
	varRe := regexp.MustCompile(`\{\{(\w[\w.]*)\}\}`)
	// Find all matches and their positions to determine if inside quotes
	result := varRe.ReplaceAllStringFunc(sqlStr, func(match string) string {
		key := strings.TrimSpace(match[2 : len(match)-2])
		val := lookupValue(data, key)
		s := fmt.Sprintf("%v", val)

		// Check if this var is inside SQL string quotes by counting quotes before it
		idx := strings.Index(sqlStr, match)
		before := sqlStr[:idx]
		singleQuotes := strings.Count(before, "'") - strings.Count(before, "\\'")
		insideQuotes := singleQuotes%2 == 1

		if insideQuotes {
			// Inside SQL quotes - inline the value (escape single quotes to prevent injection)
			return strings.ReplaceAll(s, "'", "''")
		}
		if s == "" {
			// Empty unquoted param - use NULL to avoid SQL syntax errors
			return "NULL"
		}
		args = append(args, s)
		return "?"
	})
	return result, args
}

func lookupValue(data map[string]any, key string) any {
	if data == nil {
		return ""
	}

	// Check exact key first (handles flattened dot-notation keys like "staff_avg.rating")
	if val, ok := data[key]; ok {
		if val == nil {
			return ""
		}
		return val
	}

	// Dot notation: row.name - traverse nested maps and arrays
	parts := strings.SplitN(key, ".", 2)
	if len(parts) == 2 {
		if nested, ok := data[parts[0]]; ok {
			switch v := nested.(type) {
			case map[string]any:
				return lookupValue(v, parts[1])
			case []map[string]any:
				// Array index access: results.0.field
				idxParts := strings.SplitN(parts[1], ".", 2)
				if idx, err := strconv.Atoi(idxParts[0]); err == nil && idx >= 0 && idx < len(v) {
					if len(idxParts) == 2 {
						return lookupValue(v[idx], idxParts[1])
					}
					return v[idx]
				}
			}
		}
	}

	return ""
}

func isEmpty(val any) bool {
	if val == nil {
		return true
	}
	switch v := val.(type) {
	case bool:
		return !v
	case string:
		return v == ""
	case int64:
		return v == 0
	case float64:
		return v == 0
	case []map[string]any:
		return len(v) == 0
	}
	return false
}

// evaluateSwitch processes {{#switch field}} body to find the matching {{#case "value"}} block.
// Falls back to {{#default}} if no case matches.
// Syntax: {{#switch status}}{{#case "active"}}...{{#case "pending"}}...{{#default}}...{{/switch}}
func evaluateSwitch(body, fieldVal string, data map[string]any) string {
	type block struct {
		value   string // empty for default
		content string
		isDef   bool
	}

	caseTag := "{{#case "
	defaultTag := "{{#default}}"

	// Find all marker positions ({{#case "..."}} and {{#default}})
	type marker struct {
		pos   int
		end   int // position after the closing }}
		value string
		isDef bool
	}
	var markers []marker

	for i := 0; i < len(body); {
		if i+len(caseTag) <= len(body) && body[i:i+len(caseTag)] == caseTag {
			closeIdx := strings.Index(body[i+len(caseTag):], "}}")
			if closeIdx >= 0 {
				val := strings.TrimSpace(body[i+len(caseTag) : i+len(caseTag)+closeIdx])
				val = strings.Trim(val, `"'`)
				markers = append(markers, marker{pos: i, end: i + len(caseTag) + closeIdx + 2, value: val})
				i = i + len(caseTag) + closeIdx + 2
				continue
			}
		}
		if i+len(defaultTag) <= len(body) && body[i:i+len(defaultTag)] == defaultTag {
			markers = append(markers, marker{pos: i, end: i + len(defaultTag), isDef: true})
			i += len(defaultTag)
			continue
		}
		i++
	}

	// Build blocks: each marker's content runs until the next marker (or end of body)
	var blocks []block
	for idx, m := range markers {
		contentEnd := len(body)
		if idx+1 < len(markers) {
			contentEnd = markers[idx+1].pos
		}
		blocks = append(blocks, block{
			value:   m.value,
			content: strings.TrimSpace(body[m.end:contentEnd]),
			isDef:   m.isDef,
		})
	}

	// Find matching case
	for _, b := range blocks {
		if !b.isDef && b.value == fieldVal {
			return RenderMustache(b.content, data)
		}
	}
	// Fallback to default
	for _, b := range blocks {
		if b.isDef {
			return RenderMustache(b.content, data)
		}
	}
	return ""
}

// evaluateIfExpr evaluates a simple comparison expression against template data.
// Supports: {{#if status = "active"}}, {{#if amount > 100}}, {{#if name != ""}}
// Operators: =, !=, >, <, >=, <=
func evaluateIfExpr(expr string, data map[string]any) bool {
	// Try each operator (longest first to match >= before >)
	for _, op := range []string{"!=", ">=", "<=", "=", ">", "<"} {
		idx := strings.Index(expr, op)
		if idx < 0 {
			continue
		}
		left := strings.TrimSpace(expr[:idx])
		right := strings.TrimSpace(expr[idx+len(op):])

		// Strip quotes from right side
		right = strings.Trim(right, `"'`)

		// Resolve left side from data
		leftVal := fmt.Sprintf("%v", lookupValue(data, left))

		switch op {
		case "=":
			return leftVal == right
		case "!=":
			return leftVal != right
		case ">", ">=", "<", "<=":
			// Try numeric comparison
			var lf, rf float64
			_, lErr := fmt.Sscanf(leftVal, "%f", &lf)
			_, rErr := fmt.Sscanf(right, "%f", &rf)
			if lErr == nil && rErr == nil {
				switch op {
				case ">":
					return lf > rf
				case ">=":
					return lf >= rf
				case "<":
					return lf < rf
				case "<=":
					return lf <= rf
				}
			}
			// Fall back to string comparison
			switch op {
			case ">":
				return leftVal > right
			case ">=":
				return leftVal >= right
			case "<":
				return leftVal < right
			case "<=":
				return leftVal <= right
			}
		}
		return false
	}

	// No operator found - treat as truthy check
	val := lookupValue(data, strings.TrimSpace(expr))
	return !isEmpty(val)
}

func mergeData(base, overlay map[string]any) map[string]any {
	merged := make(map[string]any, len(base)+len(overlay))
	for k, v := range base {
		merged[k] = v
	}
	for k, v := range overlay {
		merged[k] = v
	}
	return merged
}

func parseAttrs(s string) map[string]string {
	attrs := make(map[string]string)
	for _, m := range attrRe.FindAllStringSubmatch(s, -1) {
		attrs[m[1]] = m[2]
	}
	return attrs
}

func stripPageTag(content string) string {
	// Remove <page ...> and </page> wrapper if present
	if m := pageBlockRe.FindStringSubmatchIndex(content); m != nil {
		return content[m[4]:m[5]]
	}
	content = pageAttrRe.ReplaceAllString(content, "")
	content = strings.ReplaceAll(content, "</page>", "")
	return content
}

// ParseSingleFile handles single-file mode with <schema>, <seed>, <page> blocks.
func ParseSingleFile(content string) (schema, seed string, pages map[string]*Page) {
	pages = make(map[string]*Page)

	// Extract <schema>
	if m := schemaTagRe.FindStringSubmatch(content); m != nil {
		schema = strings.TrimSpace(m[1])
	}

	// Extract <seed>
	if m := seedTagRe.FindStringSubmatch(content); m != nil {
		seed = strings.TrimSpace(m[1])
	}

	// Extract <page> blocks
	matches := pageBlockRe.FindAllStringSubmatch(content, -1)
	for _, m := range matches {
		attrs := parseAttrs(m[1])
		route := attrs["route"]
		if route == "" {
			route = "/"
		}
		pages[route] = &Page{
			Route:   route,
			RawHTML: m[2],
			Auth:    attrs["auth"],
			Scope:   attrs["scope"],
			Title:   attrs["title"],
		}
	}

	return
}

// LoadPages discovers and parses all .html files in the app directory.
func LoadPages(dir string) (map[string]*Page, map[string]string, error) {
	pages := make(map[string]*Page)
	partials := make(map[string]string)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			// Check partials directory
			if entry.Name() == "partials" {
				partialDir := filepath.Join(dir, "partials")
				partialEntries, err := os.ReadDir(partialDir)
				if err == nil {
					for _, pe := range partialEntries {
						if strings.HasSuffix(pe.Name(), ".html") {
							data, err := os.ReadFile(filepath.Join(partialDir, pe.Name()))
							if err == nil {
								partials["partials/"+pe.Name()] = string(data)
							}
						}
					}
				}
			}
			continue
		}

		if !strings.HasSuffix(entry.Name(), ".html") {
			continue
		}
		// Skip special files that aren't pages
		if entry.Name() == "head.html" {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, nil, fmt.Errorf("read %s: %w", entry.Name(), err)
		}

		content := string(data)

		// Determine route from filename
		name := strings.TrimSuffix(entry.Name(), ".html")
		route := "/" + name
		if name == "index" {
			route = "/"
		}

		auth, scope, title, layout := ParsePageAttrs(content)
		description, image, robots := ParsePageSEO(content)

		page := &Page{
			Route:       route,
			File:        entry.Name(),
			RawHTML:     content,
			Description: description,
			Image:       image,
			Robots:      robots,
			Auth:        auth,
			Scope:       scope,
			Title:       title,
			Layout:      layout,
			Require:     ExtractPageRequire(content),
			Type:        ExtractPageType(content),
			Redirect:    ExtractPageRedirect(content),
		}
		// Frontmatter takes effect when the legacy <page> tag is absent -
		// otherwise the <page> tag wins so a mixed file stays self-consistent.
		if fm, _, fmErr := ExtractFrontmatter(content); fmErr == nil && fm != nil {
			ApplyFrontmatterToPage(page, fm)
		}
		pages[route] = page
	}

	return pages, partials, nil
}

// expandTransitionTags replaces <transitions table="X" id="Y"> with rendered
// workflow transition buttons based on the current state and user's role.
// Reads from workflows.yaml config - no API call needed at render time.
func expandTransitionTags(content string, app *App, ctx *RenderContext) string {
	re := regexp.MustCompile(`<transitions\s+([^>]*?)/?>`)
	return re.ReplaceAllStringFunc(content, func(match string) string {
		m := re.FindStringSubmatch(match)
		if m == nil {
			return match
		}
		attrs := parseAttrs(m[1])
		table := attrs["table"]
		id := attrs["id"]
		if table == "" || id == "" {
			return `<!-- transitions: table and id required -->`
		}

		// Find the workflow for this table
		var wf *Workflow
		for _, w := range app.Workflows.Workflows {
			if w.Table == table {
				wf = w
				break
			}
		}
		if wf == nil {
			return fmt.Sprintf(`<!-- transitions: no workflow for table %s -->`, table)
		}

		// Fetch the current state
		row, err := QueryRows(app.DB, fmt.Sprintf("SELECT %s FROM %s WHERE id = ?", wf.Field, table), id)
		if err != nil || len(row) == 0 {
			return `<!-- transitions: record not found -->`
		}
		currentState := fmt.Sprintf("%v", row[0][wf.Field])

		// Get available transitions for the current user
		targets := wf.Transitions[currentState]
		if len(targets) == 0 {
			return "" // no transitions available from this state
		}

		session := ctx.User
		var sb strings.Builder
		sb.WriteString(`<div class="flex flex-wrap gap-2" data-transitions>`)
		for to, t := range targets {
			// Check role
			if t.Role != "" && (session == nil || !hasWorkflowRole(app, session, t.Role)) {
				continue
			}
			label := strings.Title(strings.ReplaceAll(to, "_", " "))
			// Use HTMX to POST the transition
			sb.WriteString(fmt.Sprintf(`<button hx-post="/api/%s/%s/transition" hx-vals='{"to":"%s"}' hx-swap="outerHTML" hx-target="closest [data-transitions]" hx-confirm="Transition to %s?" class="inline-flex items-center px-3 py-1.5 text-sm font-medium rounded-md border border-border bg-secondary text-secondary-foreground hover:bg-accent transition-colors">%s</button>`,
				table, id, to, label, label))
		}
		sb.WriteString(`</div>`)
		return sb.String()
	})
}

// generateMockRows creates fake rows for <query mock="N"> prototyping mode.
// Column discovery priority:
//  1. Live schema (app.Tables) - for apps with real migrations.
//  2. `pick=` attribute on the <query> tag - for shorthand usage.
//  3. SELECT clause parsing - for raw SQL queries.
//  4. Generic fallback (id/name/status/created_at).
func generateMockRows(app *App, q QueryTag, count int) []map[string]any {
	// Determine column names from the query
	var columns []Column

	if q.From != "" {
		// Shorthand mode: use the table's actual columns
		for _, t := range app.Tables {
			if t.Name == q.From {
				columns = t.Columns
				break
			}
		}
		// If table doesn't exist yet (prototype phase), infer from pick attribute
		if len(columns) == 0 {
			if pick := q.Attrs["pick"]; pick != "" {
				for _, name := range strings.Split(pick, ",") {
					name = strings.TrimSpace(name)
					if name != "" {
						columns = append(columns, Column{Name: name, Type: "TEXT"})
					}
				}
			}
		}
	} else if q.SQL != "" {
		// SQL mode: parse column names from SELECT clause
		columns = inferColumnsFromSQL(q.SQL)
	}

	// Fallback: if we still have no columns, generate generic ones
	if len(columns) == 0 {
		columns = []Column{
			{Name: "id", Type: "INTEGER"},
			{Name: "name", Type: "TEXT"},
			{Name: "status", Type: "TEXT"},
			{Name: "created_at", Type: "DATETIME"},
		}
	}

	// Detect name-pair entities once so we can inject a virtual `initials`
	// field - avatar components generally want 2 letters, not the full name.
	hasFirstName, hasLastName := false, false
	for _, col := range columns {
		switch col.Name {
		case "first_name":
			hasFirstName = true
		case "last_name":
			hasLastName = true
		}
	}

	// Generate rows
	rows := make([]map[string]any, count)
	for i := 0; i < count; i++ {
		row := make(map[string]any)
		for _, col := range columns {
			if col.Name == "id" {
				row["id"] = int64(i + 1)
				continue
			}
			row[col.Name] = mockValue(col.Name, col.Type, i)
		}
		// Virtual `initials` derived from first_name + last_name if both exist.
		// Partials can reference {{initials}} without needing a real DB column.
		if hasFirstName && hasLastName {
			fn, _ := row["first_name"].(string)
			ln, _ := row["last_name"].(string)
			if len(fn) > 0 && len(ln) > 0 {
				row["initials"] = strings.ToUpper(string(fn[0]) + string(ln[0]))
			}
		}
		rows[i] = row
	}
	return rows
}

// inferColumnsFromSQL extracts column names from a SELECT statement.
func inferColumnsFromSQL(sql string) []Column {
	upper := strings.ToUpper(strings.TrimSpace(sql))
	if !strings.HasPrefix(upper, "SELECT") {
		return nil
	}

	// Find text between SELECT and FROM
	fromIdx := strings.Index(upper, " FROM ")
	if fromIdx == -1 {
		return nil
	}
	selectPart := strings.TrimSpace(sql[6:fromIdx]) // skip "SELECT"

	if selectPart == "*" {
		return nil // can't infer columns from *
	}

	var columns []Column
	for _, part := range strings.Split(selectPart, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		// Handle "expr AS alias" - use the alias
		upperPart := strings.ToUpper(part)
		if asIdx := strings.Index(upperPart, " AS "); asIdx != -1 {
			alias := strings.TrimSpace(part[asIdx+4:])
			colType := "TEXT"
			if strings.Contains(upperPart, "COUNT") || strings.Contains(upperPart, "SUM") {
				colType = "INTEGER"
			}
			columns = append(columns, Column{Name: alias, Type: colType})
		} else {
			// Simple column reference: "table.col" or "col"
			name := part
			if dotIdx := strings.LastIndex(name, "."); dotIdx != -1 {
				name = name[dotIdx+1:]
			}
			columns = append(columns, Column{Name: strings.TrimSpace(name), Type: "TEXT"})
		}
	}
	return columns
}

// mockValue generates a realistic fake value based on column name and type.
func mockValue(name, colType string, rowIndex int) any {
	lower := strings.ToLower(name)
	upper := strings.ToUpper(colType)

	// Type-based defaults
	if strings.Contains(upper, "BOOL") {
		if rowIndex%3 == 0 {
			return "1"
		}
		return "0"
	}
	if strings.Contains(upper, "INT") && lower != "id" {
		return int64(rowIndex*7 + 42)
	}
	if strings.Contains(upper, "REAL") || strings.Contains(upper, "FLOAT") {
		return fmt.Sprintf("%.2f", float64(rowIndex)*29.99+9.99)
	}
	if strings.Contains(upper, "DATE") {
		return fmt.Sprintf("2026-01-%02d", (rowIndex%28)+1)
	}

	// Name-based smart values (with variation per row)
	names := []string{"Alice Chen", "Bob Smith", "Carol Davis", "Dan Wilson", "Eva Martinez", "Frank Lee", "Grace Kim", "Henry Patel"}
	emails := []string{"alice@company.com", "bob@company.com", "carol@company.com", "dan@company.com", "eva@company.com"}
	titles := []string{"Design system tokens", "API authentication flow", "Mobile navigation", "Database schema review", "Onboarding redesign", "Search performance", "Email templates", "Billing integration"}
	statuses := []string{"active", "pending", "in_progress", "completed", "todo"}
	priorities := []string{"urgent", "high", "medium", "low", "none"}

	switch {
	case lower == "email" || strings.HasSuffix(lower, "_email"):
		return emails[rowIndex%len(emails)]
	case lower == "phone" || strings.HasSuffix(lower, "_phone"):
		return fmt.Sprintf("555-01%02d", rowIndex+10)
	case lower == "assignee" || lower == "owner" || lower == "initials":
		// Return initials - most avatar components want 2 letters.
		parts := strings.Split(names[rowIndex%len(names)], " ")
		if len(parts) >= 2 {
			return string(parts[0][0]) + string(parts[1][0])
		}
		return strings.ToUpper(string(parts[0][0]))
	case lower == "first_name":
		return strings.Split(names[rowIndex%len(names)], " ")[0]
	case lower == "last_name":
		parts := strings.Split(names[rowIndex%len(names)], " ")
		return parts[len(parts)-1]
	case lower == "name" || strings.HasSuffix(lower, "_name") || lower == "full_name":
		return names[rowIndex%len(names)]
	case lower == "title" || lower == "subject":
		return titles[rowIndex%len(titles)]
	case lower == "description" || lower == "notes" || lower == "body" || lower == "content":
		return "Sample description for this item. Edit to customize."
	case lower == "status" || lower == "state":
		return statuses[rowIndex%len(statuses)]
	case lower == "priority":
		return priorities[rowIndex%len(priorities)]
	case lower == "company" || lower == "organization":
		companies := []string{"Acme Corp", "TechStart", "DataFlow", "CloudBase", "NetPrime"}
		return companies[rowIndex%len(companies)]
	case lower == "url" || lower == "website" || strings.HasSuffix(lower, "_url"):
		return "https://example.com"
	case lower == "color" || lower == "hex":
		colors := []string{"#6366f1", "#ef4444", "#f59e0b", "#22c55e", "#8b5cf6"}
		return colors[rowIndex%len(colors)]
	case lower == "icon":
		icons := []string{"📋", "⚙️", "📱", "🚀", "💡"}
		return icons[rowIndex%len(icons)]
	case lower == "slug":
		slugs := []string{"design-system", "api-auth", "mobile-nav", "schema-review", "onboarding"}
		return slugs[rowIndex%len(slugs)]
	case lower == "identifier":
		return fmt.Sprintf("TF-%d", rowIndex+1)
	case lower == "assignee":
		return names[rowIndex%len(names)]
	case lower == "label_name" || lower == "tag":
		labels := []string{"Bug", "Feature", "Improvement", "Documentation", "Design"}
		return labels[rowIndex%len(labels)]
	case lower == "label_color":
		colors := []string{"#ef4444", "#6366f1", "#f59e0b", "#6b7280", "#8b5cf6"}
		return colors[rowIndex%len(colors)]
	case strings.Contains(lower, "amount") || strings.Contains(lower, "price") || strings.Contains(lower, "value") || strings.Contains(lower, "cost") || strings.Contains(lower, "revenue"):
		return fmt.Sprintf("%.2f", float64(rowIndex)*249.99+49.99)
	case strings.Contains(lower, "count") || strings.Contains(lower, "total") || strings.Contains(lower, "quantity"):
		return int64(rowIndex*3 + 1)
	case lower == "role":
		roles := []string{"admin", "editor", "viewer", "user", "manager"}
		return roles[rowIndex%len(roles)]
	case lower == "created_at" || lower == "updated_at" || strings.HasSuffix(lower, "_at") || strings.HasSuffix(lower, "_date"):
		return fmt.Sprintf("2026-04-%02d 09:%02d:00", (rowIndex%28)+1, rowIndex*7%60)
	case lower == "user_id" || strings.HasSuffix(lower, "_id"):
		return int64(rowIndex + 1)
	}

	// Default: generic text
	return fmt.Sprintf("Sample %s %d", strings.ReplaceAll(name, "_", " "), rowIndex+1)
}
