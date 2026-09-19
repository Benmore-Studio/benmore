//go:build !cli

package main

import (
	"fmt"
	"html"
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
		if headHTML, err := readFileFromDir(app.Dir, "head.html"); err == nil {
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
		// Testing mode: the amber preview banner. Shown on every page
		// (including pre-auth /login, /signup) when features.testing
		// is opted in - the whole point is to make every view obviously
		// non-production for anyone who lands on the app. The feedback
		// widget is gated separately (below) so features.feedback can
		// run it on a published prod app WITHOUT this banner.
		if app.FeatureEnabled("testing") {
			sb.WriteString(TestingBannerHTML(session, app))
		}
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
		sb.WriteString(AnalyticsCookieNotice())
	}
	// Form control styling handled by @tailwindcss/forms plugin (embedded in tailwind.min.js)
	sb.WriteString(`</body></html>`)

	return sb.String()
}

// loadNamedLayout reads a layout file from the app's layouts/ directory.
func loadNamedLayout(app *App, name string) string {
	path := fmt.Sprintf("layouts/%s.html", name)
	data, err := readFileFromDir(app.Dir, path)
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
		if headHTML, err := readFileFromDir(app.Dir, "head.html"); err == nil {
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
		// Testing mode: the amber preview banner (testing-only). The
		// feedback widget is gated separately so features.feedback can
		// run it on a published prod app without the banner.
		if app.FeatureEnabled("testing") {
			sb.WriteString(TestingBannerHTML(session, app))
		}
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
	data, err := readFile(app.Dir, "theme.css")
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

	// JSON-LD: WebSite schema (homepage only)
	route := ""
	if page != nil {
		route = page.Route
	}
	if siteURL != "" && siteName != "" && route == "/" {
		sb.WriteString(fmt.Sprintf(`<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebSite","name":"%s","url":"%s"`, siteName, siteURL))
		if desc != "" {
			sb.WriteString(fmt.Sprintf(`,"description":"%s"`, desc))
		}
		// SearchAction for sitelinks search box
		sb.WriteString(fmt.Sprintf(`,"potentialAction":{"@type":"SearchAction","target":{"@type":"EntryPoint","urlTemplate":"%s/search?q={search_term_string}"},"query-input":"required name=search_term_string"}`, siteURL))
		sb.WriteString(`}</script>`)

		// Organization schema
		org := app.Design.SEO["org"]
		if org == "" {
			org = siteName
		}
		sb.WriteString(fmt.Sprintf(`<script type="application/ld+json">{"@context":"https://schema.org","@type":"Organization","name":"%s","url":"%s"`, org, siteURL))
		if favicon := app.Design.SEO["favicon"]; favicon != "" {
			sb.WriteString(fmt.Sprintf(`,"logo":"%s%s"`, siteURL, favicon))
		}
		sb.WriteString(`}</script>`)
	}

	// JSON-LD: WebPage schema (every page)
	if siteURL != "" && route != "" {
		sb.WriteString(fmt.Sprintf(`<script type="application/ld+json">{"@context":"https://schema.org","@type":"WebPage","name":"%s","url":"%s%s"`, title, siteURL, route))
		if desc != "" {
			sb.WriteString(fmt.Sprintf(`,"description":"%s"`, desc))
		}
		sb.WriteString(`}</script>`)
	}

	// JSON-LD: BreadcrumbList (auto-generated from URL path)
	if siteURL != "" && route != "" && route != "/" {
		parts := strings.Split(strings.Trim(route, "/"), "/")
		sb.WriteString(`<script type="application/ld+json">{"@context":"https://schema.org","@type":"BreadcrumbList","itemListElement":[`)
		sb.WriteString(fmt.Sprintf(`{"@type":"ListItem","position":1,"name":"Home","item":"%s/"}`, siteURL))
		path := ""
		for i, part := range parts {
			path += "/" + part
			name := strings.Title(strings.ReplaceAll(part, "-", " "))
			sb.WriteString(fmt.Sprintf(`,{"@type":"ListItem","position":%d,"name":"%s","item":"%s%s"}`, i+2, name, siteURL, path))
		}
		sb.WriteString(`]}</script>`)
	}

	return sb.String()
}

// GenerateSitemap creates a sitemap.xml from truly public routes only.
// Excludes: auth-required pages, typed pages (login/signup), require-gated pages,
// and pages with robots="noindex". Only publicly accessible pages appear.
func GenerateSitemap(app *App, baseURL string) string {
	var sb strings.Builder
	sb.WriteString(`<?xml version="1.0" encoding="UTF-8"?>`)
	sb.WriteString(`<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">`)

	for route, page := range app.Pages {
		if page.Auth == "required" || page.Type != "" || page.Require != "" {
			continue
		}
		if page.Robots == "noindex" {
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
		if page.Auth == "required" || page.Type != "" || page.Require != "" {
			continue
		}
		if page.Robots == "noindex" {
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
		if page.Auth == "required" || page.Type != "" {
			continue
		}
		if page.Robots == "noindex" {
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
