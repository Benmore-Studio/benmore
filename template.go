//go:build !cli

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"sort"
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

// queryCacheKey identifies one app's query and arguments. The cache is
// process-wide, so the key carries the app directory (a `benmore host`
// process serves many apps, and two apps can run the same SQL text), and
// the parts are JSON-encoded so ("1","23") and ("12","3") differ. An
// argument JSON can't encode yields "" and the query is not cached.
func queryCacheKey(appDir, sql string, args []any) string {
	enc, err := json.Marshal([]any{appDir, sql, args})
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(enc)
	return hex.EncodeToString(sum[:])
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

// The key carries request-derived arguments, so a visitor can mint entries at
// will. Bound the cache: expired entries are dropped when it fills, then the
// entry closest to expiry is evicted, and result sets too large to hold are
// simply not cached (the query still runs).
const (
	queryCacheMaxEntries = 1024
	queryCacheMaxRows    = 2000
)

func queryCacheSet(key string, rows []map[string]any, ttl time.Duration, table string) {
	if len(rows) > queryCacheMaxRows {
		return
	}
	queryCache.mu.Lock()
	defer queryCache.mu.Unlock()
	now := time.Now()
	if _, exists := queryCache.entries[key]; !exists && len(queryCache.entries) >= queryCacheMaxEntries {
		var soonestKey string
		var soonest time.Time
		for k, e := range queryCache.entries {
			if now.After(e.expiresAt) {
				delete(queryCache.entries, k)
				continue
			}
			if soonestKey == "" || e.expiresAt.Before(soonest) {
				soonestKey, soonest = k, e.expiresAt
			}
		}
		if len(queryCache.entries) >= queryCacheMaxEntries && soonestKey != "" {
			delete(queryCache.entries, soonestKey)
		}
	}
	queryCache.entries[key] = &queryCacheEntry{rows: rows, expiresAt: now.Add(ttl), table: table}
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

	// queryOpenTagRe matches <query ...>, allowing > inside quoted
	// attribute values (e.g. sql="... > 0").
	queryOpenTagRe   = regexp.MustCompile(`<query\s+((?:[^>"]*"[^"]*")*[^>]*)>`)
	imgTagRe         = regexp.MustCompile(`<img\s([^>]*?)>`)
	transitionsTagRe = regexp.MustCompile(`<transitions\s+([^>]*?)/?>`)
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
	return processIncludesWithReader(content, partials, dir, func(name string) ([]byte, error) {
		return readFileInRoot(dir, name)
	})
}

func processIncludesWithReader(content string, partials map[string]string, dir string, readSource func(string) ([]byte, error)) string {
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
		data, err := readSource(src)
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
	i := 0
	for i < len(content) {
		// Find next <query ...>
		loc := queryOpenTagRe.FindStringIndex(content[i:])
		if loc == nil {
			break
		}
		tagStart := i + loc[0]
		tagEnd := i + loc[1]
		attrStr := queryOpenTagRe.FindStringSubmatch(content[i:])[1]

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
		// Pages are shared with other requests and the context graph. Apply
		// fallback metadata to this render only, including the Page used by
		// query scoping and layout selection in the request context.
		originalPage := page
		renderPage := *page
		page = &renderPage
		if ctx.Page == originalPage {
			ctx.Page = page
			defer func() { ctx.Page = originalPage }()
		}
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
			return string(injectI18nBootstrap([]byte(finalizeRender(app, page, ctx, body)), app)), nil
		}
	}

	// 1. Strip <page> wrapper if present
	content = stripPageTag(content)

	// 2. Expand includes
	content = processIncludesWithReader(content, app.Partials, app.Dir, app.readAppInclude)

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
	content = app.i18nConfig().TranslateTemplate(content, lang)

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
		if layoutData, err := app.readSourceFile(layoutPath); err == nil {
			layoutHTML := string(layoutData)
			layoutHTML = processIncludesWithReader(layoutHTML, app.Partials, app.Dir, app.readAppInclude)
			layoutHTML = strings.Replace(layoutHTML, "{{content}}", content, 1)
			content = RenderMustache(layoutHTML, ctx.Data)
		}
	} else if ctx.Page != nil {
		// layout="none" or "" - no layout wrapping. Auto-inject partials/kit.html
		// if it exists so marketing/landing/auth pages that skip the layout
		// still get the app's design-system styling (CSS variables, component
		// classes, fonts) without boilerplate in every file.
		if kitData, err := app.readSourceFile("partials/kit.html"); err == nil {
			kitHTML := processIncludesWithReader(string(kitData), app.Partials, app.Dir, app.readAppInclude)
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
	return imgTagRe.ReplaceAllStringFunc(content, func(match string) string {
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
				// Authors can write where="id = {{param_id}}" the same as raw
				// <query sql> (issue #7): the value is bound as a ? argument.
				// Other attributes are validated against the schema or parsed
				// as numbers by ExpandShorthand.
				where, whereArgs, bindErr := bindTemplateSQL(q.Attrs["where"], ctx.Data, ctx.User)
				if bindErr != nil {
					content = content[:q.Start] + queryErrorHTML(app, q, bindErr) + content[q.End:]
					continue
				}
				resolvedAttrs := make(map[string]string, len(q.Attrs))
				for k, v := range q.Attrs {
					resolvedAttrs[k] = resolveAttrVars(v, ctx.Data)
				}
				resolvedAttrs["where"] = where
				var userID int64
				if ctx.User != nil {
					userID = ctx.User.UserID
				}
				var expandErr error
				sql, args, expandErr = ExpandShorthand(app, q.From, resolvedAttrs, userID, whereArgs)
				if expandErr != nil {
					content = content[:q.Start] + queryErrorHTML(app, q, expandErr) + content[q.End:]
					continue
				}
			} else if q.SQL != "" {
				// Raw SQL mode - {{vars}} and :current_user bind as ? args in
				// statement order (bindTemplateSQL).
				var bindErr error
				sql, args, bindErr = bindTemplateSQL(q.SQL, ctx.Data, ctx.User)
				if bindErr != nil {
					content = content[:q.Start] + queryErrorHTML(app, q, bindErr) + content[q.End:]
					continue
				}
			} else {
				continue
			}

			// Handle scope="owner" - inject WHERE clause. Without a session
			// the page gets no rows rather than every owner's rows.
			if ctx.Page != nil && ctx.Page.Scope == "owner" {
				var uid int64
				if ctx.User != nil {
					uid = ctx.User.UserID
				}
				scoped, scopeErr := injectOwnerScope(sql, uid, ctx.User != nil)
				if scopeErr != nil {
					content = content[:q.Start] + queryErrorHTML(app, q, scopeErr) + content[q.End:]
					continue
				}
				sql = scoped
			}

			// Query cache: <query cache="5m" ...> caches results for the given duration
			var cacheTTL time.Duration
			if cacheStr := q.Attrs["cache"]; cacheStr != "" {
				cacheTTL, _ = time.ParseDuration(cacheStr)
			}
			var cacheKey string
			if cacheTTL > 0 {
				cacheKey = queryCacheKey(app.Dir, sql, args)
			}
			if cacheKey != "" {
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
						frag := newFragmentRenderer(content[:q.Start])
						if q.As != "" && len(cachedRows) > 0 {
							sectionTag := "{{#" + q.As + "}}"
							hasSectionLoop := strings.Contains(q.Inner, sectionTag)
							if hasSectionLoop {
								innerProtected := protectFetchInner(q.Inner)
								expanded := frag.render(innerProtected, ctx.Data)
								rendered.WriteString(restoreFetchInner(expanded))
							} else {
								for _, row := range cachedRows {
									rowData := mergeData(ctx.Data, row)
									innerProtected := protectFetchInner(q.Inner)
									expanded := frag.render(innerProtected, rowData)
									rendered.WriteString(restoreFetchInner(expanded))
								}
							}
						} else {
							rendered.WriteString(frag.render(q.Inner, ctx.Data))
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
				content = content[:q.Start] + queryErrorHTML(app, q, err) + content[q.End:]
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
				frag := newFragmentRenderer(content[:q.Start])
				if q.As != "" && len(rows) > 0 {
					// Check if inner content contains a {{#as}}...{{/as}} section matching
					// the query's as name. If so, let mustache handle iteration (render once).
					// Otherwise, render per-row (backward compat for templates without sections).
					sectionTag := "{{#" + q.As + "}}"
					hasSectionLoop := strings.Contains(q.Inner, sectionTag)
					if hasSectionLoop {
						// Render once - mustache {{#as}} section handles row iteration
						innerProtected := protectFetchInner(q.Inner)
						expanded := frag.render(innerProtected, ctx.Data)
						rendered.WriteString(restoreFetchInner(expanded))
					} else {
						// No section wrapper - render per-row (each row's fields available directly)
						for _, row := range rows {
							rowData := mergeData(ctx.Data, row)
							innerProtected := protectFetchInner(q.Inner)
							expanded := frag.render(innerProtected, rowData)
							rendered.WriteString(restoreFetchInner(expanded))
						}
					}
				} else if len(rows) == 0 {
					// Empty state - render {{^as}}...{{/as}} blocks
					rendered.WriteString(frag.render(q.Inner, ctx.Data))
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
//
// A resolved value must also never carry the NUL byte that delimits the
// fetch-protection markers (`\x00MO\x00`, `\x00OPEN\x00`): restoreFetchInner
// and expandMustacheWithProtectedFetch turn those markers back into `{{`/`}}`
// with a global replace over output that already holds the value, so a stored
// value containing the marker bytes would otherwise become a live tag on the
// next pass. NUL never legitimately appears in rendered HTML, so it is
// replaced with the Unicode replacement character.
//
// The same holds for the framework's server-side tags. A <query> block's
// rendered rows are spliced into the page before the next extraction pass,
// and <fetch> / <transitions> expand after the mustache pass, so a raw
// ({{{{x}}}}) value holding `<query sql="...">` ran that SQL on the app's
// database handle, outside every access rule. The opener's `<` becomes
// `&lt;` (the tag scanners match `<name` + whitespace); the value renders as
// text instead of an unknown element.
func neutralizeReparse(s string) string {
	if strings.IndexByte(s, 0) >= 0 {
		s = strings.ReplaceAll(s, "\x00", "�")
	}
	s = neutralizeFrameworkTags(s)
	if !strings.Contains(s, "{{") && !strings.Contains(s, "}}") {
		return s
	}
	s = strings.ReplaceAll(s, "{{", "{&#123;")
	s = strings.ReplaceAll(s, "}}", "&#125;}")
	return s
}

// frameworkTagNames are the tags the renderer executes after values are in
// the page (queryOpenTagRe, fetchTagRe, transitionsTagRe).
var frameworkTagNames = []string{"query", "fetch", "transitions"}

// neutralizeFrameworkTags escapes the `<` of every `<query`, `<fetch` or
// `<transitions` followed by whitespace (RE2 \s, what the tag patterns
// require), so a rendered value can never open one of those tags.
func neutralizeFrameworkTags(s string) string {
	if !strings.Contains(s, "<") {
		return s
	}
	var b strings.Builder
	last := 0
	for i := 0; i < len(s); i++ {
		if s[i] != '<' {
			continue
		}
		for _, name := range frameworkTagNames {
			end := i + 1 + len(name)
			if end < len(s) && s[i+1:end] == name && strings.IndexByte(" \t\n\f\r", s[end]) >= 0 {
				b.WriteString(s[last:i])
				b.WriteString("&lt;")
				last = i + 1
				break
			}
		}
	}
	if last == 0 {
		return s
	}
	b.WriteString(s[last:])
	return b.String()
}

// RenderMustache performs simple mustache-like template rendering. Values
// are escaped for the HTML context they land in (template_context.go):
// body text and ordinary attributes get html.EscapeString, URL attributes
// also neutralize script-capable schemes, and <script> blocks / on* handlers
// get JS-string or JSON encoding.
func RenderMustache(template string, data map[string]any) string {
	return renderMustacheCtx(template, data, &htmlCtx{})
}

// fragmentRenderer renders fragments that are spliced into a document right
// after `before` (a <query> body inside its page), so their values are
// escaped for the context at the splice point. Successive renders (one per
// row) continue in the context the previous one left.
type fragmentRenderer struct{ c *htmlCtx }

func newFragmentRenderer(before string) *fragmentRenderer {
	c := &htmlCtx{}
	c.feedString(before)
	return &fragmentRenderer{c: c}
}

func (f *fragmentRenderer) render(template string, data map[string]any) string {
	out := renderMustacheCtx(template, data, f.c.clone())
	f.c.feedString(out)
	return out
}

// renderValue escapes one resolved `{{ }}` / `{{{ }}}` value for c's
// context. sanitized selects the `{{{ }}}` / raw-pipe output, which keeps
// its unescaped HTML only where HTML is being written (body text, comments,
// non-script raw text); in attributes and scripts it is escaped like `{{ }}`.
func renderValue(c *htmlCtx, raw any, s string, rawHTML, jsonPipe bool) string {
	if rawHTML && c.writesHTML() {
		return neutralizeReparse(s)
	}
	out := escapeMustacheValue(c, raw, s, jsonPipe)
	if c.inScript() {
		// JS/JSON escaping already turns braces inside strings into \u
		// escapes; neutralizeReparse's HTML entities would corrupt script.
		return out
	}
	return neutralizeReparse(out)
}

func renderMustacheCtx(template string, data map[string]any, c *htmlCtx) string {
	var result strings.Builder
	write := func(s string) {
		result.WriteString(s)
		c.feedString(s)
	}
	i := 0
	for i < len(template) {
		// Check for {{{{ truly raw }}}} (no sanitization - explicit dangerous opt-in)
		if i+4 <= len(template) && template[i:i+4] == "{{{{" {
			end := strings.Index(template[i+4:], "}}}}")
			if end >= 0 {
				key := strings.TrimSpace(template[i+4 : i+4+end])
				val := lookupValue(data, key)
				write(neutralizeReparse(fmt.Sprintf("%v", val)))
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
				s := fmt.Sprintf("%v", val)
				// Sanitized HTML is only meaningful where HTML is being
				// written; in attributes and scripts escape it like {{ }}.
				if c.writesHTML() {
					write(neutralizeReparse(SanitizeHTML(s)))
				} else {
					write(renderValue(c, val, s, false, false))
				}
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
								write(renderMustacheCtx(inner, data, c.clone()))
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
								write(renderMustacheCtx(truePart, data, c.clone()))
							} else {
								write(renderMustacheCtx(falsePart, data, c.clone()))
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
							write(evaluateSwitch(body, fieldVal, data, c))
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
						write(renderSection(inner, val, data, c))
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
							write(renderMustacheCtx(inner, data, c.clone()))
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
					rawHTML, jsonPipe := false, false
					if pipe != "" {
						s = ApplyPipe(val, pipe)
						// benmark output is already sanitized; emitted raw
						// where HTML is being written.
						rawHTML = isRawHTMLPipe(pipe)
						jsonPipe = strings.TrimSpace(strings.SplitN(pipe, ":", 2)[0]) == "json"
					}
					write(renderValue(c, val, s, rawHTML, jsonPipe))
					i = nextI
					continue
				}
			}
		}

		result.WriteByte(template[i])
		c.feed(template[i])
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

// renderSection renders a {{#name}} section starting in context c (the
// caller's escaping context at the section; c itself is not modified).
func renderSection(inner string, val any, parentData map[string]any, c *htmlCtx) string {
	if val == nil {
		return ""
	}
	render := func(data map[string]any) string {
		return renderMustacheCtx(inner, data, c.clone())
	}

	switch v := val.(type) {
	case []map[string]any:
		// Each iteration continues in the context the previous one left.
		var sb strings.Builder
		cc := c.clone()
		for _, item := range v {
			merged := mergeData(parentData, item)
			out := renderMustacheCtx(inner, merged, cc.clone())
			cc.feedString(out)
			sb.WriteString(out)
		}
		return sb.String()
	case map[string]any:
		merged := mergeData(parentData, v)
		return render(merged)
	case bool:
		if v {
			return render(parentData)
		}
		return ""
	case string:
		if v != "" {
			return render(parentData)
		}
		return ""
	case int64:
		if v != 0 {
			return render(parentData)
		}
		return ""
	default:
		return render(parentData)
	}
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
func evaluateSwitch(body, fieldVal string, data map[string]any, c *htmlCtx) string {
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
			return renderMustacheCtx(b.content, data, c.clone())
		}
	}
	// Fallback to default
	for _, b := range blocks {
		if b.isDef {
			return renderMustacheCtx(b.content, data, c.clone())
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
	return loadPagesFromSources(dir, nil)
}

func loadPagesFromSources(dir string, captured map[string][]byte) (map[string]*Page, map[string]string, error) {
	pages := make(map[string]*Page)
	partials := make(map[string]string)
	pageSources := make(map[string][]byte)

	if captured == nil {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, nil, err
		}
		for _, entry := range entries {
			if entry.IsDir() {
				if entry.Name() == "partials" {
					// Read through an os.Root at the app dir: a partial
					// symlinked outside the app is skipped, not inlined
					// into every page that includes it.
					for name, data := range readGotmplPartials(dir) {
						if strings.HasSuffix(name, ".html") && !isMetadataSidecar(name) {
							partials["partials/"+name] = data
						}
					}
				}
				continue
			}
			if !strings.HasSuffix(entry.Name(), ".html") || entry.Name() == "head.html" || isMetadataSidecar(entry.Name()) {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				return nil, nil, fmt.Errorf("read %s: %w", entry.Name(), err)
			}
			pageSources[entry.Name()] = data
		}
	} else {
		keys := make([]string, 0, len(captured))
		for name := range captured {
			keys = append(keys, name)
		}
		sort.Strings(keys)
		for _, name := range keys {
			if strings.HasPrefix(name, "partials/") {
				partial := strings.TrimPrefix(name, "partials/")
				if strings.Contains(partial, "/") || !strings.HasSuffix(partial, ".html") || isMetadataSidecar(partial) {
					continue
				}
				if data := captured[name]; data != nil {
					partials[name] = string(data)
				}
				continue
			}
			if strings.Contains(name, "/") || !strings.HasSuffix(name, ".html") || name == "head.html" || isMetadataSidecar(name) {
				continue
			}
			pageSources[name] = captured[name]
		}
	}

	pageNames := make([]string, 0, len(pageSources))
	for name := range pageSources {
		pageNames = append(pageNames, name)
	}
	sort.Strings(pageNames)
	for _, name := range pageNames {
		data := pageSources[name]
		if captured != nil && data == nil {
			return nil, nil, fmt.Errorf("read %s: %w", name, os.ErrNotExist)
		}
		content := string(data)

		// Determine route from filename
		pageName := strings.TrimSuffix(name, ".html")
		route := "/" + pageName
		if pageName == "index" {
			route = "/"
		}

		page := &Page{Route: route, File: name}
		setPageAttrsFromSource(page, content)
		pages[route] = page
	}

	return pages, partials, nil
}

// setPageAttrsFromSource derives a page's gates and metadata from its source:
// the <page> tag first, then frontmatter for anything the tag leaves empty
// (the tag wins so a mixed file stays self-consistent). The page loader and
// the dev-mode re-read both use it, so neither can drop a frontmatter gate.
func setPageAttrsFromSource(page *Page, content string) {
	page.RawHTML = content
	page.Auth, page.Scope, page.Title, page.Layout = ParsePageAttrs(content)
	page.Description, page.Image, page.Robots = ParsePageSEO(content)
	page.Require = ExtractPageRequire(content)
	page.Type = ExtractPageType(content)
	page.Redirect = ExtractPageRedirect(content)
	page.Role = extractPageRole(content)
	page.Engine = ""
	if fm, _, fmErr := ExtractFrontmatter(content); fmErr == nil && fm != nil {
		ApplyFrontmatterToPage(page, fm)
	}
	page.Auth = normalizePageAuth(page.Auth, page.File)
}

// normalizePageAuth maps a page's auth value onto the two the router knows:
// "required" or open ("" / "none"). Route registration gated only the exact
// string "required", so auth="true", `auth: yes` or a typo registered the page
// with no sign-in check. Anything that isn't an explicit opt-out now requires
// sign-in.
func normalizePageAuth(auth, file string) string {
	norm, known := canonicalAuthValue(auth)
	if !known {
		log.Printf("WARNING page %s: unknown auth=%q; treating it as auth=\"required\"", file, auth)
	}
	return norm
}

// canonicalAuthValue maps a page or flow `auth` value onto "" (unset),
// "none" (explicit opt-out) or "required". known is false for a value that
// is not one of the recognized spellings; it still maps to "required", so an
// unrecognized value fails closed.
func canonicalAuthValue(auth string) (norm string, known bool) {
	switch strings.ToLower(strings.TrimSpace(auth)) {
	case "":
		return "", true
	case "none", "public", "false", "no", "off":
		return "none", true
	case "required", "true", "yes", "on":
		return "required", true
	default:
		return "required", false
	}
}

// expandTransitionTags replaces <transitions table="X" id="Y"> with rendered
// workflow transition buttons based on the current state and user's role.
// Reads from workflows.yaml config - no API call needed at render time.
func expandTransitionTags(content string, app *App, ctx *RenderContext) string {
	return transitionsTagRe.ReplaceAllStringFunc(content, func(match string) string {
		m := transitionsTagRe.FindStringSubmatch(match)
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

		// Fetch the current state through the same gates as
		// GET /api/<table>/{id}/transitions: the table's read mode and the
		// canonical row scope. Another tenant's (or owner's) record is "not
		// found" rather than a view of its state.
		session := ctx.User
		if session == nil || !SessionCanAccessTable(app, table, OpRead, session) {
			return `<!-- transitions: record not found -->`
		}
		readSQL := "SELECT " + quoteColumn(table, wf.Field) + " FROM " + quoteIdent(table) + " WHERE id = ?"
		readArgs := []any{id}
		if hasColumn(app, table, "deleted_at") {
			readSQL += " AND deleted_at IS NULL"
		}
		if pred, pargs, bypass := rowScopeClause(app, table, session, "view"); !bypass && pred != "" {
			readSQL += " AND " + pred
			readArgs = append(readArgs, pargs...)
		}
		row, err := queryNativeRowsWith(app.DB, app, table, readSQL, readArgs...)
		if err != nil || len(row) == 0 {
			return `<!-- transitions: record not found -->`
		}
		currentState := fmt.Sprintf("%v", row[0][wf.Field])

		// Get available transitions for the current user
		targets := wf.Transitions[currentState]
		if len(targets) == 0 {
			return "" // no transitions available from this state
		}

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
