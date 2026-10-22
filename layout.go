//go:build !cli

package main

import (
	"encoding/json"
	"fmt"
	"html"
	"net/http"
	"strings"
)

const tailwindPath = "/_internal/tailwind.js"
const alpinePath = "/_internal/alpine.js"
const htmxPath = "/_internal/htmx.js"
const chartjsPath = "/_internal/chart.js"
const lucidePath = "/_internal/lucide.js"

// htmxInitScript wires four framework essentials onto every HTMX request:
//
//  1. X-CSRF-Token header - reads the token from <meta name="csrf-token">.
//     Without this, any :patch/:delete directive fires a 403 because the
//     framework's CSRF validator checks both form field AND header.
//  2. Initial Lucide icon render on DOMContentLoaded.
//  3. Lucide re-render after HTMX swaps content, so icons in fragments
//     rendered via hx-swap actually get replaced.
//  4. benmore:changed listener - every successful CRUD mutation emits the
//     HX-Trigger "benmore:changed" header. This shim catches it and does
//     a soft refresh (re-fetch + body-swap) so <query> stat cards stay in
//     sync with the table they read from. Without this, agents reinvent
//     a different ad-hoc reload hack on every page.
const htmxInitScript = `<script>document.addEventListener('DOMContentLoaded',function(){if(typeof lucide!=='undefined')lucide.createIcons();document.body.addEventListener('htmx:configRequest',function(e){var m=document.querySelector('meta[name="csrf-token"]');if(m)e.detail.headers['X-CSRF-Token']=m.content});document.body.addEventListener('htmx:afterSwap',function(){if(typeof lucide!=='undefined')lucide.createIcons()});document.body.addEventListener('benmore:changed',function(){if(window.__bmReloading)return;window.__bmReloading=true;setTimeout(function(){window.location.reload()},50)})});</script>`

// WrapLayout wraps page content in the full HTML shell.
func WrapLayout(content, title string, app *App, session *Session) string {
	return WrapLayoutWithPage(content, title, app, session, nil)
}

// WrapLayoutWithPage wraps page content with full SEO support.
func WrapLayoutWithPage(content, title string, app *App, session *Session, page *Page) string {
	if title == "" {
		title = "Benmore App"
	}

	// Resolve theme
	themeName := "zinc"
	themeMode := "dark"
	brand := ""
	customFont := ""
	if app != nil && app.Design != nil {
		if app.Design.Nav["theme"] != "" {
			themeName = app.Design.Nav["theme"]
		}
		if t, ok := app.Design.Colors["_theme"]; ok {
			themeName = t
		}
		if m, ok := app.Design.Colors["_mode"]; ok {
			themeMode = m
		}
		if f, ok := app.Design.Colors["_font"]; ok {
			customFont = f
		}
		if b, ok := app.Design.Colors["_brand"]; ok {
			brand = b
		}
	}

	// Load custom theme.css overrides
	customCSS := loadThemeCSS(app)

	// Detect if page uses charts
	needsChartJS := strings.Contains(content, "chart-container")

	// CSS mode: "tailwind" (default) - Tailwind + Alpine, no theme variables
	//           "themed" - Tailwind + Alpine + shadcn CSS variables from theme/mode/brand
	//           "none" - nothing loaded, app brings its own CSS
	// Legacy: "default" and "both" treated as "themed" for backwards compat
	cssMode := "tailwind"
	if app != nil && app.Design != nil && app.Design.CSS != "" {
		cssMode = app.Design.CSS
		// Backwards compat: old "default" and "both" modes → "themed"
		if cssMode == "default" || cssMode == "both" {
			cssMode = "themed"
		}
	}

	var sb strings.Builder
	lang := getLang(app)
	sb.WriteString(fmt.Sprintf(`<!DOCTYPE html>
<html lang="%s">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>`, lang))
	sb.WriteString(title)
	sb.WriteString(`</title>`)

	// SEO meta tags
	seo := buildSEOTags(app, page, title)
	sb.WriteString(seo)

	// Favicon
	if app != nil && app.Design != nil {
		if favicon, ok := app.Design.SEO["favicon"]; ok {
			sb.WriteString(fmt.Sprintf(`<link rel="icon" href="%s">`, favicon))
		}
	}

	// Feed discovery + alternate formats
	sb.WriteString(`<link rel="alternate" type="application/atom+xml" title="Feed" href="/feed.xml">`)

	// PWA meta tags + service worker registration
	if app != nil {
		sb.WriteString(PWAMetaTags(app))
		if IsPWAEnabled(app) {
			sb.WriteString(`<script>if('serviceWorker' in navigator){navigator.serviceWorker.register('/sw.js')}</script>`)
		}
	}

	// head.html - custom scripts (analytics, pixels, etc.) - always loaded regardless of CSS mode
	if app != nil {
		if headHTML, err := app.readSourceFile("head.html"); err == nil {
			sb.WriteString(InterpolateEnv(string(headHTML), app.Dir))
		}
	}

	// CSRF meta tag for JS fetch() calls: document.querySelector('meta[name=csrf-token]').content
	sb.WriteString(fmt.Sprintf(`<meta name="csrf-token" content="%s">`, generateCSRFToken()))

	if cssMode != "none" {
		// Tailwind (embedded in binary) + config
		sb.WriteString(fmt.Sprintf(`<script src="%s"></script>`, tailwindPath))
		sb.WriteString(`<script>`)
		sb.WriteString(TailwindConfig)
		sb.WriteString(`</script>`)

		// Alpine.js (embedded in binary) - declarative JS behaviors
		sb.WriteString(fmt.Sprintf(`<script defer src="%s"></script>`, alpinePath))
	}

	if cssMode == "themed" {
		// shadcn CSS variables + base styles (only in "themed" mode)
		sb.WriteString(`<style>`)
		sb.WriteString(BuildCSS(themeName, themeMode, brand))
		sb.WriteString(`</style>`)
	}

	// Custom font: use font_url from app.yaml if set, otherwise Google Fonts
	if customFont != "" {
		fontURL := ""
		if app != nil && app.Design != nil {
			fontURL = app.Design.Typography["font_url"]
		}
		if fontURL != "" {
			// Custom font URL (self-hosted or any CDN)
			sb.WriteString(fmt.Sprintf(`<link href="%s" rel="stylesheet">`, fontURL))
		} else {
			// Default: Google Fonts
			fontParam := strings.ReplaceAll(customFont, " ", "+")
			sb.WriteString(`<link rel="preconnect" href="https://fonts.googleapis.com">`)
			sb.WriteString(`<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>`)
			sb.WriteString(fmt.Sprintf(`<link href="https://fonts.googleapis.com/css2?family=%s:wght@400;500;600;700&display=swap" rel="stylesheet">`, fontParam))
		}
		sb.WriteString(fmt.Sprintf(`<style>:root { --font-sans: '%s', ui-sans-serif, system-ui, sans-serif; }</style>`, customFont))
	}

	// Custom theme.css overrides - always loaded regardless of CSS mode
	if customCSS != "" {
		sb.WriteString(`<style>`)
		sb.WriteString(customCSS)
		sb.WriteString(`</style>`)
	}

	// HTMX + Lucide icons - always loaded (functional, not design)
	sb.WriteString(fmt.Sprintf(`<script src="%s"></script>`, htmxPath))
	sb.WriteString(fmt.Sprintf(`<script src="%s"></script>`, lucidePath))
	sb.WriteString(htmxInitScript)

	// Chart.js (only if needed)
	if needsChartJS {
		sb.WriteString(fmt.Sprintf(`<script src="%s"></script>`, chartjsPath))
	}

	groupAttr := ""
	if session != nil && session.HasGroup() {
		groupAttr = fmt.Sprintf(` data-group-id="%s"`, session.GroupID)
	}
	if cssMode == "none" {
		sb.WriteString(fmt.Sprintf(`</head><body%s>`, groupAttr))
	} else {
		sb.WriteString(fmt.Sprintf(`</head><body%s>`, groupAttr))
	}
	sb.WriteString(content)

	if cssMode != "none" {
		sb.WriteString(`<script>`)
		sb.WriteString(DefaultJS)
		sb.WriteString(SSEClientScript)
		if devReloadClientEnabled(app) {
			sb.WriteString(DevReloadClientScript)
		}
		sb.WriteString(`</script>`)
	} else {
		// In "none" mode, still inject SSE for live updates but skip DefaultJS (switchTab, toggleAccordion, etc.)
		sb.WriteString(`<script>`)
		sb.WriteString(SSEClientScript)
		if devReloadClientEnabled(app) {
			sb.WriteString(DevReloadClientScript)
		}
		sb.WriteString(`</script>`)
	}
	if app != nil {
		sb.WriteString(RecorderScript(app, app.DevMode))
		// Testing mode shows the feedback flag (below); there is no banner.
		// features.feedback keeps the flag on a published prod app.
		if app.FeedbackWidgetEnabled() {
			sb.WriteString(FeedbackWidgetHTML(app.FeatureEnabled("testing")))
		}
		// "Built with Benmore" attribution badge. Renders only for the hosted
		// platform's free tier; a no-op for self-hosted apps (see
		// BuiltWithBadgeHTML).
		sb.WriteString(BuiltWithBadgeHTML(app))
	}
	// Analytics beacon - auto-injected when features.analytics is enabled (default: true)
	if app.FeatureEnabled("analytics") {
		sb.WriteString(AnalyticsBeaconJS())
		sb.WriteString(AnalyticsCookieNotice(app))
	}
	// Form control styling handled by @tailwindcss/forms plugin (embedded in tailwind.min.js)
	sb.WriteString(`</body></html>`)

	return sb.String()
}

// loadNamedLayout reads a layout file from the app's layouts/ directory.
func loadNamedLayout(app *App, name string) string {
	path := fmt.Sprintf("layouts/%s.html", name)
	data, err := app.readSourceFile(path)
	if err != nil {
		return ""
	}
	return string(data)
}

// wrapHTMLShell wraps content in the HTML head/body shell (Tailwind, theme, fonts, scripts)
// without the sidebar nav. Used by named layouts and layout="none".
func wrapHTMLShell(content, title string, app *App, session *Session, page *Page, themeName, themeMode, brand, customFont, customCSS string) string {
	var sb strings.Builder
	lang := getLang(app)
	sb.WriteString(fmt.Sprintf(`<!DOCTYPE html>
<html lang="%s">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>`, lang))
	sb.WriteString(title)
	sb.WriteString(`</title>`)

	seo := buildSEOTags(app, page, title)
	sb.WriteString(seo)

	if app != nil && app.Design != nil {
		if favicon, ok := app.Design.SEO["favicon"]; ok {
			sb.WriteString(fmt.Sprintf(`<link rel="icon" href="%s">`, favicon))
		}
	}
	if app != nil {
		if headHTML, err := app.readSourceFile("head.html"); err == nil {
			sb.WriteString(InterpolateEnv(string(headHTML), app.Dir))
		}
	}

	// CSRF meta tag for JS fetch() calls: document.querySelector('meta[name=csrf-token]').content
	sb.WriteString(fmt.Sprintf(`<meta name="csrf-token" content="%s">`, generateCSRFToken()))

	// CSS mode (same logic as WrapLayoutWithPage)
	cssMode := "tailwind"
	if app != nil && app.Design != nil && app.Design.CSS != "" {
		cssMode = app.Design.CSS
		if cssMode == "default" || cssMode == "both" {
			cssMode = "themed"
		}
	}

	if cssMode != "none" {
		sb.WriteString(fmt.Sprintf(`<script src="%s"></script>`, tailwindPath))
		sb.WriteString(`<script>`)
		sb.WriteString(TailwindConfig)
		sb.WriteString(`</script>`)
		sb.WriteString(fmt.Sprintf(`<script defer src="%s"></script>`, alpinePath))
	}

	if cssMode == "themed" {
		sb.WriteString(`<style>`)
		sb.WriteString(BuildCSS(themeName, themeMode, brand))
		sb.WriteString(`</style>`)
	}

	if customFont != "" {
		fontParam := strings.ReplaceAll(customFont, " ", "+")
		sb.WriteString(`<link rel="preconnect" href="https://fonts.googleapis.com">`)
		sb.WriteString(`<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>`)
		sb.WriteString(fmt.Sprintf(`<link href="https://fonts.googleapis.com/css2?family=%s:wght@400;500;600;700&display=swap" rel="stylesheet">`, fontParam))
		sb.WriteString(fmt.Sprintf(`<style>:root { --font-sans: '%s', ui-sans-serif, system-ui, sans-serif; }</style>`, customFont))
	}
	if customCSS != "" {
		sb.WriteString(`<style>`)
		sb.WriteString(customCSS)
		sb.WriteString(`</style>`)
	}

	// HTMX + Lucide - always loaded (functional, not design)
	sb.WriteString(fmt.Sprintf(`<script src="%s"></script>`, htmxPath))
	sb.WriteString(fmt.Sprintf(`<script src="%s"></script>`, lucidePath))
	sb.WriteString(htmxInitScript)
	if strings.Contains(content, "chart-container") {
		sb.WriteString(fmt.Sprintf(`<script src="%s"></script>`, chartjsPath))
	}

	shellGroupAttr := ""
	if session != nil && session.HasGroup() {
		shellGroupAttr = fmt.Sprintf(` data-group-id="%s"`, session.GroupID)
	}
	sb.WriteString(fmt.Sprintf(`</head><body%s>`, shellGroupAttr))
	sb.WriteString(content)
	if cssMode != "none" {
		sb.WriteString(`<script>`)
		sb.WriteString(DefaultJS)
		sb.WriteString(SSEClientScript)
		if devReloadClientEnabled(app) {
			sb.WriteString(DevReloadClientScript)
		}
		sb.WriteString(`</script>`)
	} else {
		sb.WriteString(`<script>`)
		sb.WriteString(SSEClientScript)
		if devReloadClientEnabled(app) {
			sb.WriteString(DevReloadClientScript)
		}
		sb.WriteString(`</script>`)
	}
	if app != nil {
		sb.WriteString(RecorderScript(app, app.DevMode))
		// Testing mode shows the feedback flag (below); there is no banner.
		if app.FeedbackWidgetEnabled() {
			sb.WriteString(FeedbackWidgetHTML(app.FeatureEnabled("testing")))
		}
	}
	// Form control styling handled by @tailwindcss/forms plugin (embedded in tailwind.min.js)
	sb.WriteString(`</body></html>`)
	return sb.String()
}

func loadThemeCSS(app *App) string {
	if app == nil {
		return ""
	}
	data, err := app.readSourceFile("theme.css")
	if err != nil {
		return ""
	}
	return string(data)
}

func readFile(dir, name string) ([]byte, error) {
	return readFileFromDir(dir, name)
}

// buildSEOTags generates comprehensive meta tags: SEO, Open Graph, Twitter, JSON-LD, AI discoverability.
func buildSEOTags(app *App, page *Page, title string) string {
	var sb strings.Builder

	siteName := ""
	siteDesc := ""
	siteImage := ""
	siteURL := ""
	brand := ""
	if app != nil && app.Design != nil {
		siteName = app.Design.SEO["site_name"]
		siteDesc = app.Design.SEO["description"]
		siteImage = app.Design.SEO["image"]
		siteURL = app.Design.SEO["url"]
		brand = app.Design.Colors["_brand"]
	}

	desc := siteDesc
	image := siteImage
	robots := "index, follow"
	if page != nil {
		if page.Description != "" {
			desc = page.Description
		}
		if page.Image != "" {
			image = page.Image
		}
		if page.Robots != "" {
			robots = page.Robots
		}
	}

	// Standard meta (escape all user-controlled values for XSS protection)
	if desc != "" {
		sb.WriteString(fmt.Sprintf(`<meta name="description" content="%s">`, html.EscapeString(desc)))
	}
	sb.WriteString(fmt.Sprintf(`<meta name="robots" content="%s">`, html.EscapeString(robots)))

	// Theme color (for browser UI)
	themeColor := "#09090b"
	if brand != "" {
		themeColor = brand
	}
	sb.WriteString(fmt.Sprintf(`<meta name="theme-color" content="%s">`, themeColor))
	// Respect the app's theme mode for color-scheme. Default to "light" so
	// form controls (checkboxes, radios) don't render with dark-mode styling
	// on users' systems. Only apps that explicitly set mode: dark get "dark".
	colorScheme := "light"
	initialBg := "#ffffff"
	initialFg := "#0a0a0a"
	if app != nil && app.Design != nil && app.Design.Colors["_mode"] == "dark" {
		colorScheme = "dark light"
		initialBg = "#09090b"
		initialFg = "#e4e4e7"
	}
	sb.WriteString(fmt.Sprintf(`<meta name="color-scheme" content="%s">`, colorScheme))
	// Inline the initial bg/fg before external CSS loads to kill the white
	// flash-of-unstyled-content between page transitions. Without this, the
	// browser paints default white for the ~50ms before Tailwind/themed CSS
	// applies, which is jarring inside the builder iframe as users click tabs.
	sb.WriteString(fmt.Sprintf(`<style>html,body{background:%s;color:%s}</style>`, initialBg, initialFg))

	// Apple touch icon
	if app != nil && app.Design != nil {
		if favicon := app.Design.SEO["favicon"]; favicon != "" {
			sb.WriteString(fmt.Sprintf(`<link rel="apple-touch-icon" href="%s">`, favicon))
		}
	}

	// Open Graph (escape all user-controlled values)
	sb.WriteString(fmt.Sprintf(`<meta property="og:title" content="%s">`, html.EscapeString(title)))
	if desc != "" {
		sb.WriteString(fmt.Sprintf(`<meta property="og:description" content="%s">`, html.EscapeString(desc)))
	}
	sb.WriteString(`<meta property="og:type" content="website">`)
	if siteName != "" {
		sb.WriteString(fmt.Sprintf(`<meta property="og:site_name" content="%s">`, html.EscapeString(siteName)))
	}
	if image != "" {
		sb.WriteString(fmt.Sprintf(`<meta property="og:image" content="%s">`, html.EscapeString(image)))
	}
	if siteURL != "" && page != nil {
		sb.WriteString(fmt.Sprintf(`<meta property="og:url" content="%s%s">`, siteURL, page.Route))
		sb.WriteString(fmt.Sprintf(`<link rel="canonical" href="%s%s">`, siteURL, page.Route))
	} else if siteURL != "" {
		sb.WriteString(fmt.Sprintf(`<meta property="og:url" content="%s">`, siteURL))
	}
	sb.WriteString(`<meta property="og:locale" content="en_US">`)

	// Twitter Card (escape all user-controlled values)
	sb.WriteString(`<meta name="twitter:card" content="summary_large_image">`)
	sb.WriteString(fmt.Sprintf(`<meta name="twitter:title" content="%s">`, html.EscapeString(title)))
	if desc != "" {
		sb.WriteString(fmt.Sprintf(`<meta name="twitter:description" content="%s">`, html.EscapeString(desc)))
	}
	if image != "" {
		sb.WriteString(fmt.Sprintf(`<meta name="twitter:image" content="%s">`, html.EscapeString(image)))
	}

	// JSON-LD: WebSite schema (homepage only). Structured values are built
	// as maps and serialized with encoding/json, so a quote in a site name or
	// description cannot produce invalid JSON, and `<` is escaped so a value
	// cannot terminate the <script> element.
	route := ""
	if page != nil {
		route = page.Route
	}
	if siteURL != "" && siteName != "" && route == "/" {
		website := map[string]any{
			"@context": "https://schema.org",
			"@type":    "WebSite",
			"name":     siteName,
			"url":      siteURL,
		}
		if desc != "" {
			website["description"] = desc
		}
		// Sitelinks search box: only advertise a SearchAction when the app
		// actually has a search page, or declares one under seo.search_url.
		// Google flags a SearchAction whose target 404s.
		if searchURL := siteSearchURL(app, siteURL); searchURL != "" {
			website["potentialAction"] = map[string]any{
				"@type": "SearchAction",
				"target": map[string]any{
					"@type":       "EntryPoint",
					"urlTemplate": searchURL,
				},
				"query-input": "required name=search_term_string",
			}
		}
		writeJSONLD(&sb, website)

		// Organization schema
		org := app.Design.SEO["org"]
		if org == "" {
			org = siteName
		}
		organization := map[string]any{
			"@context": "https://schema.org",
			"@type":    "Organization",
			"name":     org,
			"url":      siteURL,
		}
		if favicon := app.Design.SEO["favicon"]; favicon != "" {
			organization["logo"] = siteURL + favicon
		}
		writeJSONLD(&sb, organization)
	}

	// JSON-LD: WebPage schema (every page)
	if siteURL != "" && route != "" {
		webpage := map[string]any{
			"@context": "https://schema.org",
			"@type":    "WebPage",
			"name":     title,
			"url":      siteURL + route,
		}
		if desc != "" {
			webpage["description"] = desc
		}
		writeJSONLD(&sb, webpage)
	}

	// JSON-LD: BreadcrumbList (auto-generated from URL path)
	if siteURL != "" && route != "" && route != "/" {
		parts := strings.Split(strings.Trim(route, "/"), "/")
		items := []map[string]any{{
			"@type":    "ListItem",
			"position": 1,
			"name":     "Home",
			"item":     siteURL + "/",
		}}
		path := ""
		for i, part := range parts {
			path += "/" + part
			items = append(items, map[string]any{
				"@type":    "ListItem",
				"position": i + 2,
				"name":     strings.Title(strings.ReplaceAll(part, "-", " ")),
				"item":     siteURL + path,
			})
		}
		writeJSONLD(&sb, map[string]any{
			"@context":        "https://schema.org",
			"@type":           "BreadcrumbList",
			"itemListElement": items,
		})
	}

	return sb.String()
}

// siteSearchURL returns the SearchAction URL template for an app, or "" when
// the app has nothing to search. An explicit `seo.search_url` wins (it must
// contain the `{search_term_string}` placeholder); otherwise a page routed at
// /search enables the framework default. Apps without either emit no
// SearchAction, since advertising a search box that 404s is a structured-data
// error, not an SEO feature.
func siteSearchURL(app *App, siteURL string) string {
	if app == nil || app.Design == nil {
		return ""
	}
	if custom := strings.TrimSpace(app.Design.SEO["search_url"]); custom != "" {
		if !strings.Contains(custom, "{search_term_string}") {
			return ""
		}
		if strings.HasPrefix(custom, "/") {
			return siteURL + custom
		}
		return custom
	}
	if _, ok := app.Pages["/search"]; ok {
		return siteURL + "/search?q={search_term_string}"
	}
	return ""
}

// writeJSONLD serializes v into a <script type="application/ld+json"> element.
// encoding/json escapes <, > and & as < etc., so no value can close the
// script element early. A marshal failure (impossible for the map/string/int
// shapes used here) emits nothing rather than a half-written element.
func writeJSONLD(sb *strings.Builder, v any) {
	data, err := json.Marshal(v)
	if err != nil {
		return
	}
	sb.WriteString(`<script type="application/ld+json">`)
	sb.Write(data)
	sb.WriteString(`</script>`)
}

// GenerateSitemap creates a sitemap.xml from truly public routes only.
// Excludes: auth-required pages, typed pages (login/signup), require-gated pages,
// and pages with robots="noindex". Only publicly accessible pages appear.
// pagePubliclyListable reports whether a page may appear in a public discovery
// surface (sitemap, llms.txt, feed). It excludes every page an anonymous
// crawler can't fully reach - auth, require, role, a redirect spec, a typed
// auth page - and any page marked noindex. One predicate keeps the three
// generators from drifting apart (a role- or require-gated page had been
// listed with its title and description).
func pagePubliclyListable(page *Page) bool {
	if page == nil {
		return false
	}
	if page.Auth == "required" || page.Type != "" || page.Require != "" ||
		pageRole(page) != "" || page.Redirect != "" {
		return false
	}
	return page.Robots != "noindex"
}

func GenerateSitemap(app *App, baseURL string) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)

	for route, page := range app.Pages {
		if !pagePubliclyListable(page) {
			continue
		}
		priority := "0.5"
		changefreq := "weekly"
		if route == "/" {
			priority = "1.0"
			changefreq = "daily"
		} else if strings.HasPrefix(route, "/docs") {
			priority = "0.8"
		}
		sb.WriteString(`<url>`)
		sb.WriteString(fmt.Sprintf(`<loc>%s%s</loc>`, baseURL, route))
		sb.WriteString(fmt.Sprintf(`<changefreq>%s</changefreq>`, changefreq))
		sb.WriteString(fmt.Sprintf(`<priority>%s</priority>`, priority))
		sb.WriteString(`</url>`)
	}

	sb.WriteString(`</urlset>`)
	return sb.String()
}

// seoBaseURL is the public origin the discovery files (sitemap, robots.txt,
// llms.txt, feed, security.txt) put in absolute links: the configured
// seo.url or public origin, else the request's own host where something
// trustworthy vetted it (dev mode, or the platform router, which serves only
// hosts it matched to this app), else fallback. Hosted apps run behind the
// router on a loopback port, so the old fallback alone (http://localhost:N)
// told crawlers the sitemap was on localhost.
func seoBaseURL(app *App, r *http.Request, fallback string) string {
	if app.Design != nil {
		if u := app.Design.SEO["url"]; u != "" {
			return strings.TrimRight(u, "/")
		}
	}
	if origin := uploadsCanonicalOrigin(app); origin != "" {
		return strings.TrimRight(origin, "/")
	}
	if r != nil && (app.DevMode || routerVettedHost(r)) {
		return protoOf(r) + "://" + r.Host
	}
	return fallback
}

// GenerateRobots creates robots.txt with AI crawler directives.
func GenerateRobots(baseURL string) string {
	return fmt.Sprintf(`User-agent: *
Allow: /
Sitemap: %s/sitemap.xml

# AI Crawlers
User-agent: GPTBot
Allow: /

User-agent: Google-Extended
Allow: /

User-agent: ClaudeBot
Allow: /

User-agent: PerplexityBot
Allow: /

User-agent: Applebot-Extended
Allow: /
`, baseURL)
}

// GenerateLLMsTxt creates an llms.txt file for AI discoverability.
// See https://llmstxt.org for the specification.
func GenerateLLMsTxt(app *App, baseURL string) string {
	siteName := "App"
	siteDesc := ""
	if app != nil && app.Design != nil {
		if n := app.Design.SEO["site_name"]; n != "" {
			siteName = n
		}
		siteDesc = app.Design.SEO["description"]
	}

	var sb strings.Builder
	sb.WriteString(fmt.Sprintf("# %s\n\n", siteName))
	if siteDesc != "" {
		sb.WriteString(fmt.Sprintf("> %s\n\n", siteDesc))
	}

	// List truly public pages only - same filter as sitemap
	sb.WriteString("## Pages\n\n")
	for route, page := range app.Pages {
		if !pagePubliclyListable(page) {
			continue
		}
		title := page.Title
		if title == "" {
			title = strings.TrimPrefix(route, "/")
			if title == "" {
				title = "Home"
			}
		}
		desc := page.Description
		if desc == "" {
			desc = title
		}
		sb.WriteString(fmt.Sprintf("- [%s](%s%s): %s\n", title, baseURL, route, desc))
	}

	return sb.String()
}

// GenerateSecurityTxt creates a /.well-known/security.txt file.
func GenerateSecurityTxt(app *App, baseURL string) string {
	contact := ""
	if app != nil && app.Design != nil {
		if c := app.Design.SEO["security_contact"]; c != "" {
			contact = c
		}
	}
	return fmt.Sprintf("Contact: mailto:%s\nPreferred-Languages: en\nCanonical: %s/.well-known/security.txt\n", contact, baseURL)
}

// GenerateAtomFeed creates an Atom feed of public pages.
func GenerateAtomFeed(app *App, baseURL string) string {
	siteName := "App"
	if app != nil && app.Design != nil {
		if n := app.Design.SEO["site_name"]; n != "" {
			siteName = n
		}
	}

	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(fmt.Sprintf(`<feed xmlns="http://www.w3.org/2005/Atom"><title>%s</title><link href="%s"/>`, html.EscapeString(siteName), html.EscapeString(baseURL)))
	sb.WriteString(fmt.Sprintf(`<link rel="self" href="%s/feed.xml"/>`, html.EscapeString(baseURL)))
	sb.WriteString(fmt.Sprintf(`<id>%s/</id>`, html.EscapeString(baseURL)))

	for route, page := range app.Pages {
		if !pagePubliclyListable(page) {
			continue
		}
		title := page.Title
		if title == "" {
			title = strings.TrimPrefix(route, "/")
			if title == "" {
				title = "Home"
			}
		}
		desc := page.Description
		sb.WriteString(`<entry>`)
		sb.WriteString(fmt.Sprintf(`<title>%s</title>`, html.EscapeString(title)))
		sb.WriteString(fmt.Sprintf(`<link href="%s%s"/>`, html.EscapeString(baseURL), html.EscapeString(route)))
		sb.WriteString(fmt.Sprintf(`<id>%s%s</id>`, html.EscapeString(baseURL), html.EscapeString(route)))
		if desc != "" {
			sb.WriteString(fmt.Sprintf(`<summary>%s</summary>`, html.EscapeString(desc)))
		}
		sb.WriteString(`</entry>`)
	}

	sb.WriteString(`</feed>`)
	return sb.String()
}

// getLang returns the language code from app.yaml or "en" as default.
func getLang(app *App) string {
	if app != nil && app.Design != nil {
		if l := app.Design.SEO["lang"]; l != "" {
			return l
		}
	}
	return "en"
}
