//go:build !cli

package main

// Static-HTML routing + CSRF meta injection for the vanilla HTML stack.
//
// When an HTML-stack app puts its frontend in `static/*.html`, the
// framework rewrites clean URLs to file paths and auto-injects the
// CSRF token into the served HTML. The goal is that an agent can
// write plain `<form action="/login" method="POST">` + plain `fetch()`
// calls and have CSRF "just work" without ever importing a helper
// library.
//
// Routing rules (GET only - POST/PATCH/DELETE still 404 here):
//   /                         → static/index.html
//   /contacts                 → static/contacts.html
//   /contacts/                → static/contacts/index.html  (or static/contacts.html)
//   /settings/profile         → static/settings/profile.html
//
// If none of those exist AND the request looks like a browser
// navigation (Accept: text/html), fall back to static/index.html so
// client-side routers can take over. Asset-like requests (anything
// with a recognizable extension we don't own) get a real 404.

import (
	"bytes"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// serveStaticHTML attempts to serve a request from the app's static/
// directory with clean-URL routing. Returns true if a response was
// written (success OR a fatal traversal block); false if no matching
// file was found and the caller should fall through to its own 404.
func serveStaticHTML(w http.ResponseWriter, r *http.Request, app *App) bool {
	if app == nil || app.Dir == "" {
		return false
	}
	staticRoot := filepath.Join(app.Dir, "static")
	if st, err := os.Stat(staticRoot); err != nil || !st.IsDir() {
		return false
	}

	clean := filepath.Clean("/" + strings.TrimPrefix(r.URL.Path, "/"))
	// filepath.Clean preserves "/" - but on the wire "/" should resolve
	// to index.html, not "" or ".".
	if clean == "/" || clean == "." || clean == "" {
		return tryServeHTMLFile(w, r, app, filepath.Join(staticRoot, "index.html"))
	}

	// Strip the leading slash for joining.
	rel := strings.TrimPrefix(clean, "/")

	// Reject any traversal attempts up front - filepath.Clean shouldn't
	// produce ".." for absolute paths, but defense-in-depth.
	if strings.Contains(rel, "..") {
		return false
	}

	// Candidate resolution order:
	//   1. static/<rel>.html              (clean URL → file)
	//   2. static/<rel>/index.html        (directory-style)
	//   3. static/<rel>                   (literal - useful for /login.html etc.)
	candidates := []string{
		filepath.Join(staticRoot, rel+".html"),
		filepath.Join(staticRoot, rel, "index.html"),
		filepath.Join(staticRoot, rel),
	}
	for _, candidate := range candidates {
		// Defense-in-depth: verify the resolved path stays inside static/.
		// filepath.Clean has already removed `..`, but an absolute symlink
		// could still escape - Stat follows symlinks, so a check on the
		// resolved path catches that case.
		if !strings.HasPrefix(candidate, staticRoot+string(filepath.Separator)) &&
			candidate != staticRoot {
			continue
		}
		st, err := os.Stat(candidate)
		if err != nil || st.IsDir() {
			continue
		}
		// Only inject CSRF on actual .html files. Other extensions
		// (.js, .css, .png) fall through to the /static/ handler
		// when the agent uses absolute paths - but if someone serves
		// them via clean URL routing too, just stream them as-is.
		if strings.HasSuffix(strings.ToLower(candidate), ".html") {
			return tryServeHTMLFile(w, r, app, candidate)
		}
		http.ServeFile(w, r, candidate)
		return true
	}

	// SPA-style fallback: any unmatched GET that looks like a browser
	// navigation gets `index.html` so a client-side router can pick it
	// up. Asset-looking paths (with extensions like .js, .css, .png)
	// don't fall through - those should return a real 404 so missing
	// assets are obvious.
	if looksLikeAssetPath(rel) {
		return false
	}
	// Never SPA-fall-back for obvious vulnerability-scanner probes - dotfiles
	// (.env/.git/.aws/.ssh/.netrc), CMS/scanner markers (wp-*, xmlrpc,
	// phpinfo, cgi-bin), and sensitive config extensions (.php/.sql/.ini/
	// .tfstate/.key/…). Serving index.html (200) for these doesn't leak the
	// file - the app has no such file - but a 200 misleads scanners and
	// floods the request log. A real 404 is the correct, quiet answer.
	if isScannerProbe(rel) {
		return false
	}
	if !acceptsHTML(r) {
		return false
	}
	return tryServeHTMLFile(w, r, app, filepath.Join(staticRoot, "index.html"))
}

// tryServeHTMLFile reads `path`, injects the CSRF meta tag (and the
// analytics beacon when the app has analytics enabled), and writes it
// to `w`. Returns true if the file existed and was served; false if
// the read failed (in which case the caller falls through to 404 - no
// response has been written yet).
func tryServeHTMLFile(w http.ResponseWriter, r *http.Request, app *App, path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	// Defensive: an older agent may have written a YAML frontmatter
	// block at the top of a static file (the pre-v2.5.6 page-contract
	// validator wrongly told them to add `engine: raw`). The frontmatter
	// would otherwise render as literal text in the browser. Strip
	// anything between leading `---\n` ... `\n---\n` (or `---\r\n`).
	data = stripLeadingFrontmatter(data)
	// Expand <include src="partials/head.html" /> for HTML-stack pages.
	// The HTML stack previously had NO partial/layout mechanism - only the
	// gotmpl renderer ran ProcessIncludes - so multi-page HTML/TSX apps had
	// to copy-paste shared chrome (notably <head>) into every page (a real app:
	// 35 duplicate heads). Run it FIRST so included content also gets the
	// CSRF-meta, asset-versioning, and SDUI-import injection below. Partials
	// resolve relative to static/ (so `partials/head.html` → static/partials/
	// head.html); ProcessIncludes' own path-containment keeps the include
	// inside static/. No-op when a page has no <include> tags, so existing
	// pages are unaffected.
	if app != nil {
		staticRoot := filepath.Join(app.Dir, "static")
		data = []byte(ProcessIncludes(string(data), app.Partials, staticRoot))
	}
	injected := injectCSRFMeta(data)
	// Auto-fill hidden _csrf inputs on native POST forms. The token
	// reuses the same generator (HMAC + timestamp), so the form's
	// value passes the same validator as the meta tag's value.
	injected = injectCSRFFormFields(injected, "")
	if app != nil {
		// Built-with-Benmore badge - always inject; the helper itself
		// decides whether to render based on app type (_platform skips),
		// owner plan (paid tiers hide), and testing mode (force-show even
		// when paid). HTML-stack apps used to bypass this because the
		// badge lived in the gotmpl layout wrapper; layout wrapping isn't
		// in this code path, so the badge needs explicit injection here.
		injected = injectBuiltWithBadge(injected, app)
		// Testing/QA feedback widget (element-select, screenshot, comment).
		// Like the badge above, this used to ride in the gotmpl layout
		// wrapper (layout.go) - which never runs on the TSX-default serving
		// path - so HTML-stack apps in testing mode silently lost the
		// widget. Inject it explicitly here, gated on features.testing.
		if app.FeatureEnabled("testing") {
			injected = injectFeedbackWidget(injected)
		}
		if app.FeatureEnabled("analytics") {
			// Cookie banner sits with the analytics beacon - the beacon
			// is what the consent gates, so they belong together. Banner
			// goes in first so it's visible before the beacon JS fires.
			injected = injectCookieBanner(injected)
			injected = injectAnalyticsBeacon(injected)
		}
		if devReloadClientEnabled(app) {
			injected = injectDevReloadClient(injected)
		}
	}
	injected = versionStaticAssets(injected, app)
	// Guarantee the bm import map exists BEFORE versioning/sdui run (they only
	// rewrite an existing map). Without this, any page that loads ES modules
	// but lacks the map throws "Failed to resolve module specifier bm" and the
	// whole module dies - the exact reason agent-rewritten login/signup pages
	// silently broke.
	injected = injectBmImportmap(injected)
	injected = versionBmInternal(injected)
	injected = injectSDUIImport(injected)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Don't long-cache HTML - the CSRF token rotates per request, and
	// stale HTML with a stale token would CSRF-fail on first mutation.
	w.Header().Set("Cache-Control", "no-store")
	w.Write(injected)
	return true
}

// injectDevReloadClient inserts the browser-side hot reload listener
// before </body>. It is gated by the caller to dev/testing surfaces.
func injectDevReloadClient(html []byte) []byte {
	if bytes.Contains(html, []byte(`id="bm-dev-reload-client"`)) {
		return html
	}
	chunk := []byte("\n<script id=\"bm-dev-reload-client\">" + DevReloadClientScript + "</script>\n")
	lower := bytes.ToLower(html)
	if i := bytes.LastIndex(lower, []byte("</body>")); i >= 0 {
		out := make([]byte, 0, len(html)+len(chunk))
		out = append(out, html[:i]...)
		out = append(out, chunk...)
		out = append(out, html[i:]...)
		return out
	}
	return append(html, chunk...)
}

// injectAnalyticsBeacon adds the framework's per-page-view beacon
// before </body>. Picks up pageviews + custom events for the dashboard
// analytics tab; without it, HTML-stack apps show as silent in the
// platform UI. The beacon is the same one gotmpl pages get via the
// SSR injection path - keeping it consistent across stacks means
// the dashboard query (count distinct visitors per app per day) works
// identically.
//
// Idempotent: if the document already declares the beacon (`bm:analytics`
// marker class), no-op.
func injectAnalyticsBeacon(html []byte) []byte {
	// Idempotency marker: the beacon's POST target is unique enough.
	if bytes.Contains(html, []byte(`/api/_analytics`)) {
		return html
	}
	beacon := []byte("\n" + AnalyticsBeaconJS() + "\n")
	lower := bytes.ToLower(html)
	if i := bytes.LastIndex(lower, []byte("</body>")); i >= 0 {
		out := make([]byte, 0, len(html)+len(beacon))
		out = append(out, html[:i]...)
		out = append(out, beacon...)
		out = append(out, html[i:]...)
		return out
	}
	return append(html, beacon...)
}

// injectBuiltWithBadge inserts the Built-with-Benmore badge before
// </body>. The badge HTML is generated by BuiltWithBadgeHTML(app),
// which short-circuits to "" for the _platform app or for paid-tier
// owners not in testing mode - so this is a no-op for apps that
// shouldn't show it.
//
// Idempotency: bails when the bm-bb-badge marker class is already
// present in the document, so static HTML that already hand-rolls a
// Benmore badge isn't double-injected.
func injectBuiltWithBadge(html []byte, app *App) []byte {
	badge := BuiltWithBadgeHTML(app)
	if badge == "" {
		return html
	}
	if bytes.Contains(html, []byte(`bm-bb-badge`)) {
		return html
	}
	chunk := []byte("\n" + badge + "\n")
	lower := bytes.ToLower(html)
	if i := bytes.LastIndex(lower, []byte("</body>")); i >= 0 {
		out := make([]byte, 0, len(html)+len(chunk))
		out = append(out, html[:i]...)
		out = append(out, chunk...)
		out = append(out, html[i:]...)
		return out
	}
	return append(html, chunk...)
}

// injectFeedbackWidget inserts the testing/QA feedback widget (the
// floating "Feedback" tab + element-picker + screenshot + comment box)
// before </body>. FeedbackWidgetHTML() carries its own styles and JS;
// the backend tables + submit/list API are registered separately in
// buildAppMux when features.testing is enabled, so the widget has a
// place to write to. Caller gates on features.testing.
//
// Idempotency: bails when the widget's root id is already present, so a
// page that hand-rolls the widget isn't double-injected.
func injectFeedbackWidget(html []byte) []byte {
	if bytes.Contains(html, []byte(`id="bm-feedback-btn"`)) {
		return html
	}
	chunk := []byte("\n" + FeedbackWidgetHTML() + "\n")
	lower := bytes.ToLower(html)
	if i := bytes.LastIndex(lower, []byte("</body>")); i >= 0 {
		out := make([]byte, 0, len(html)+len(chunk))
		out = append(out, html[:i]...)
		out = append(out, chunk...)
		out = append(out, html[i:]...)
		return out
	}
	return append(html, chunk...)
}

// injectCookieBanner inserts the consent banner before </body>. The
// banner gates the analytics beacon's _bm_vid cookie - without an
// explicit "Accept" click, the server-side handler at
// /api/_analytics returns 204 without setting a tracking cookie. See
// AnalyticsCookieNotice and cookieConsentGiven for the runtime side.
//
// Idempotency: bails when the bm-cookie id is already in the document.
func injectCookieBanner(html []byte) []byte {
	if bytes.Contains(html, []byte(`id="bm-cookie"`)) {
		return html
	}
	chunk := []byte("\n" + AnalyticsCookieNotice() + "\n")
	lower := bytes.ToLower(html)
	if i := bytes.LastIndex(lower, []byte("</body>")); i >= 0 {
		out := make([]byte, 0, len(html)+len(chunk))
		out = append(out, html[:i]...)
		out = append(out, chunk...)
		out = append(out, html[i:]...)
		return out
	}
	return append(html, chunk...)
}

// staticAssetRefRe matches `href="/static/foo.css"` and
// `src="/static/foo.js"` patterns, optionally followed by a `?v=<digits>`
// query string that the framework manages itself. We accept and discard
// the existing `?v=N` so subsequent passes re-version with the current
// mtime - pre-2.7.31 the regex required the closing quote to follow the
// extension immediately, so any URL the agent had bumped by hand (or that
// we'd written ourselves on a prior render) became a permanent dead zone
// and never picked up a fresh mtime. An earlier app build manually
// walked `?v=2→3→5→6→7` across nine HTML files for this exact reason.
//
// Other query strings (`?hash=abc`, `?ver=foo`, `?v=abc`) are author
// intent and left untouched. Only the numeric `?v=` shape is claimed
// by the framework.
//
// Capture groups (used by versionStaticAssets):
//
//	$1 = attribute name (href | src)
//	$2 = opening quote
//	$3 = URL path without query string (e.g. /static/app.js)
//	$4 = optional framework-owned `?v=<digits>` - discarded
//	$5 = closing quote
//
// Supported extensions are the cacheable static-asset shapes the
// framework serves with `immutable` cache-control. The set extends
// well beyond CSS/JS because EVERY file the static handler serves
// with `max-age=31536000, immutable` is unbustable from the client
// side once cached. Pre-v2.7.63 this regex only covered .css|.js;
// agents replacing a logo/png/font would push the new bytes, but
// browsers + Cloudflare would still serve the old cached copy
// (sometimes for the full year). The fix is to extend the same
// `?v=<mtime>` rewrite to every cacheable shape.
//
// Covered now:
//
//	css   js   mjs   cjs           - stylesheets + scripts
//	png   jpg  jpeg  gif  webp     - raster images
//	svg   avif ico                 - vector / modern raster / favicons
//	woff  woff2 ttf  otf  eot      - web fonts
//
// Not covered (deliberate): URLs in CSS `background-image: url(...)`
// or `<source srcset="...">`. Those don't appear in href/src so the
// regex doesn't see them. Agents who hit cache-staleness on CSS
// `url()` references should bump the *.css file itself - its
// versioned link picks up the same `?v=<mtime>` and triggers a CF
// revalidate; the inner url() is fetched as part of that.
var staticAssetRefRe = regexp.MustCompile(
	`(?i)(href|src)=("|')(/static/[^"'?]+?\.(?:css|js|mjs|cjs|png|jpg|jpeg|gif|webp|svg|avif|ico|woff2|woff|ttf|otf|eot))(\?v=[0-9]+)?("|')`)

// versionStaticAssets rewrites `href="/static/foo.css"` and
// `src="/static/foo.js"` references in served HTML to include a
// `?v=<mtime>` query string. This invalidates Cloudflare's immutable
// cache (which the static handler sets to max-age=1y) the moment a
// file on disk changes - no agent has to remember to bump a version
// in their HTML, and no `?v=N`-thrash debugging loops.
//
// Idempotent: URLs that already carry a query string (the author chose
// their own version) are left untouched. Files that don't exist on
// disk are also left untouched so a real 404 surfaces normally.
//
// Only rewrites `/static/*` - `/_internal/*` libraries are tied to the
// framework binary version and don't need per-app busting.
func versionStaticAssets(html []byte, app *App) []byte {
	if app == nil || app.Dir == "" {
		return html
	}
	staticRoot := filepath.Join(app.Dir, "static")
	return staticAssetRefRe.ReplaceAllFunc(html, func(match []byte) []byte {
		groups := staticAssetRefRe.FindSubmatch(match)
		if len(groups) < 6 {
			return match
		}
		// groups[4] is the optional existing `?v=<digits>` - discarded.
		attr, quote, urlPath, closeQuote := groups[1], groups[2], groups[3], groups[5]
		rel := strings.TrimPrefix(string(urlPath), "/static/")
		mtime, ok := assetMtime(staticRoot, rel)
		if !ok {
			return match
		}
		ver := strconv.FormatInt(mtime.Unix(), 10)
		out := make([]byte, 0, len(match)+16)
		out = append(out, attr...)
		out = append(out, '=')
		out = append(out, quote...)
		out = append(out, urlPath...)
		out = append(out, '?', 'v', '=')
		out = append(out, ver...)
		out = append(out, closeQuote...)
		return out
	})
}

// versionBmInternal rewrites every "/_internal/bm.js" reference in the
// served HTML (whether in a <script src=> attribute or inside an
// importmap JSON body) to include a `?v=<bm-content-hash>` query
// suffix. Two callers:
//
//   - <script type="importmap">{"imports":{"bm":"/_internal/bm.js"}}</script>
//     The framework's own TSX scaffold + every app served by the framework.
//
//   - <script src="/_internal/bm.js"></script>
//     Plain-script usage when an agent doesn't go through the import map.
//
// Without this rewrite, CF caches the bare /_internal/bm.js URL for up
// to a day after a framework deploy - agents push new code, browsers
// run old SDK, "bm.broadcast is undefined" symptoms surface. The
// version hash changes whenever the binary's embedded bm.js changes,
// so the cached URL becomes a different URL the moment we deploy.
// Idempotent: if "?v=" is already present we skip - preserves explicit
// versions an app author wrote by hand.
func versionBmInternal(html []byte) []byte {
	const target = "/_internal/bm.js"
	if !bytes.Contains(html, []byte(target)) {
		return html
	}
	ver := bmJSETag()
	// Strip the quotes from the ETag - we want just the hex digest as
	// the version. ETag includes quotes per RFC 7232 ("X"); the query
	// suffix should be raw hex.
	ver = strings.Trim(ver, `"`)
	versioned := target + "?v=" + ver
	// Use bytes.ReplaceAll but skip occurrences that already carry a ?v=
	// suffix. The simplest predicate: any occurrence followed by `?` or
	// has `?v=` immediately after is left alone.
	out := make([]byte, 0, len(html)+64)
	cursor := 0
	for {
		idx := bytes.Index(html[cursor:], []byte(target))
		if idx < 0 {
			out = append(out, html[cursor:]...)
			break
		}
		abs := cursor + idx
		out = append(out, html[cursor:abs]...)
		out = append(out, []byte(target)...)
		next := abs + len(target)
		// Already carries a query string? Leave it.
		if next < len(html) && html[next] == '?' {
			cursor = next
			continue
		}
		out = append(out, []byte("?v="+ver)...)
		cursor = next
	}
	_ = versioned // referenced in comment for grep-ability
	return out
}

// injectBmImportmap guarantees the bm import map is present on any served HTML
// that uses ES modules. The bm SDK is imported as the bare specifier
// `import bm from 'bm'`, which ONLY resolves if the document carries
//
//	<script type="importmap">{"imports":{"bm":"/_internal/bm.js"}}</script>
//
// The scaffold ships it, but agents (the in-browser builder AND MCP clients
// like Claude Code) routinely rewrite a page - login/signup, extra pages - and
// drop it. The browser then throws "Failed to resolve module specifier bm" and
// the entire module fails to evaluate, so auth forms / app bootstraps silently
// do nothing. Injecting it in the framework's serve path makes
// `import bm from 'bm'` work no matter what any author wrote - one consistent
// fix for every app and every agent.
//
// An import map MUST appear before the first module script that uses it, so we
// insert it immediately before the first <script type="module">. Runs before
// versionBmInternal + injectSDUIImport so they version the bm.js URL and add
// the sdui entry to the freshly-injected map. No-op when the page declares no
// module scripts or already has an import map.
func injectBmImportmap(html []byte) []byte {
	lower := bytes.ToLower(html)
	if bytes.Contains(lower, []byte(`type="importmap"`)) || bytes.Contains(lower, []byte(`type='importmap'`)) {
		return html // author/scaffold already provided one
	}
	idx := bytes.Index(lower, []byte(`<script type="module"`))
	if i := bytes.Index(lower, []byte(`<script type='module'`)); i >= 0 && (idx < 0 || i < idx) {
		idx = i
	}
	if idx < 0 {
		return html // no ES modules on this page - nothing to resolve
	}
	tag := []byte(`<script type="importmap">{"imports":{"bm":"/_internal/bm.js"}}</script>` + "\n")
	out := make([]byte, 0, len(html)+len(tag))
	out = append(out, html[:idx]...)
	out = append(out, tag...)
	out = append(out, html[idx:]...)
	return out
}

// injectSDUIImport ensures the import map maps `sdui` →
// /_internal/sdui.js (versioned by content hash, like bm.js) so apps
// can `import { DataTable } from 'sdui'` without declaring it. Only acts
// when an import map with an "imports" object is present and sdui isn't
// already mapped - idempotent, and a no-op for gotmpl apps with no map.
func injectSDUIImport(html []byte) []byte {
	marker := []byte(`"imports":{`)
	if !bytes.Contains(html, marker) || bytes.Contains(html, []byte(`"sdui"`)) {
		return html
	}
	ver := strings.Trim(sduiJSETag(), `"`)
	entry := []byte(`"imports":{"sdui":"/_internal/sdui.js?v=` + ver + `",`)
	return bytes.Replace(html, marker, entry, 1)
}

// assetMtime resolves the freshness timestamp for a /static/<rel>
// reference. For non-JS files (app.css, /img/logo.png) it's just the
// file's mtime. For .js - whether plain on-disk or JIT-compiled from
// a sibling .tsx/.ts/.jsx - we return the MAX of (.js own mtime,
// every .tsx/.ts/.jsx mtime under static/). The framework's embedded
// esbuild writes the compiled .js back to disk so subsequent serves
// can fast-path it; that means `os.Stat(app.js)` succeeds but returns
// the time of the LAST COMPILATION, not the latest source edit.
// Pre-2.7.31 we returned that stale .js mtime even when a non-entry
// import (an earlier app build's `notes.tsx`, an earlier app build's
// `golive.tsx`, an earlier app build's `huddle.tsx`) had been edited
// since - agents had to manually `touch app.tsx` to force a bump.
//
// Walking the entire static/ tree for max mtime is bounded (apps
// have dozens of files, not thousands) and only runs on HTML serve,
// which is itself cached at the CDN layer.
//
// Tests: see static_html_test.go.
func assetMtime(staticRoot, rel string) (time.Time, bool) {
	full := filepath.Join(staticRoot, rel)
	onDiskMtime, onDiskOK := time.Time{}, false
	if st, err := os.Stat(full); err == nil {
		onDiskMtime, onDiskOK = st.ModTime(), true
	}
	// For .js (whether plain on-disk or JIT-compiled), also consider
	// every static source file's mtime. The compiled output's mtime
	// trails the source edit by however long it takes the next
	// request to trigger a recompile, which is exactly the cache-bust
	// stale-window we want to avoid.
	if strings.HasSuffix(rel, ".js") {
		if sourceMtime, ok := maxStaticSourceMtime(staticRoot); ok {
			if !onDiskOK || sourceMtime.After(onDiskMtime) {
				return sourceMtime, true
			}
		}
	}
	if onDiskOK {
		return onDiskMtime, true
	}
	return time.Time{}, false
}

// maxStaticSourceMtime walks staticRoot recursively and returns the
// most-recent mtime across every .tsx/.ts/.jsx file it finds. This is
// the right cache-bust key for JIT-compiled bundles: editing any
// imported module changes the compiled output, so the URL version
// should change too.
//
// Bounded work - typical app has <50 source files. Errors from walk
// (permission, disappeared file) are ignored: we return whatever we
// found, or (zero, false) if nothing matched.
func maxStaticSourceMtime(staticRoot string) (time.Time, bool) {
	var newest time.Time
	found := false
	_ = filepath.Walk(staticRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() {
			return nil
		}
		name := info.Name()
		switch {
		case strings.HasSuffix(name, ".tsx"),
			strings.HasSuffix(name, ".ts"),
			strings.HasSuffix(name, ".jsx"):
			if mt := info.ModTime(); mt.After(newest) {
				newest = mt
				found = true
			}
		}
		return nil
	})
	return newest, found
}

// injectCSRFMeta inserts a `<meta name="csrf-token" content="...">` tag
// into the served HTML so JS code can read it without a separate fetch.
//
// Idempotent: if the document already declares a REAL csrf-token meta
// tag, the bytes are returned untouched. The marker is anchored on
// `<meta name="csrf-token"` (with the opening `<meta` tag) so it
// doesn't false-match HTML comments or stringified docs that mention
// the meta tag's name without actually declaring it.
//
// Insertion points, in order of preference:
//  1. Immediately before `</head>`
//  2. Immediately after `<head>` (or `<head ...>`) when no closing tag
//  3. At the very top of the document
func injectCSRFMeta(html []byte) []byte {
	if indexFoldBytes(html, []byte(`<meta name="csrf-token"`)) >= 0 ||
		indexFoldBytes(html, []byte(`<meta name='csrf-token'`)) >= 0 {
		return html
	}
	token := generateCSRFToken()
	meta := []byte("<meta name=\"csrf-token\" content=\"" + token + "\">\n")

	// Try </head> (case-insensitive).
	if idx := indexFoldBytes(html, []byte("</head>")); idx >= 0 {
		out := make([]byte, 0, len(html)+len(meta))
		out = append(out, html[:idx]...)
		out = append(out, meta...)
		out = append(out, html[idx:]...)
		return out
	}

	// Try <head ...>.
	if idx := indexFoldBytes(html, []byte("<head")); idx >= 0 {
		// Find the closing '>' that ends the <head> tag.
		closeIdx := bytes.IndexByte(html[idx:], '>')
		if closeIdx >= 0 {
			insertAt := idx + closeIdx + 1
			out := make([]byte, 0, len(html)+len(meta))
			out = append(out, html[:insertAt]...)
			out = append(out, '\n')
			out = append(out, meta...)
			out = append(out, html[insertAt:]...)
			return out
		}
	}

	// No head section at all - prepend.
	out := make([]byte, 0, len(html)+len(meta))
	out = append(out, meta...)
	out = append(out, html...)
	return out
}

// injectCSRFFormFields walks every `<form>` in `html` and, when the form
// uses method="POST" (case-insensitive) AND doesn't already include an
// `<input name="_csrf">`, inserts a hidden CSRF input right after the
// opening form tag. Mirrors the agent-friendly behavior of
// injectCSRFMeta - vanilla-HTML developers who write a native form-POST
// (no JS) get CSRF protection automatically, same as JS callers who
// already read the meta tag.
//
// Pre-v2.7.13 agents writing chat / signup / login / contact forms in
// pure HTML routinely hit "Invalid request" because the framework's
// CSRF validator requires either the X-CSRF-Token header (JS-driven)
// OR a `_csrf` form field (native submit). The scaffold's app.js
// covered the case via fetch(), but as soon as the developer
// overwrote app.js they lost it. This injector closes that gap.
//
// Idempotent: forms that already declare `name="_csrf"` are skipped.
// GET forms are skipped. The token re-used per page-render so the
// meta tag and form field carry the same value.
func injectCSRFFormFields(html []byte, token string) []byte {
	if len(html) == 0 {
		return html
	}
	if token == "" {
		token = generateCSRFToken()
	}
	inputTag := []byte(`<input type="hidden" name="_csrf" value="` + token + `">`)

	out := make([]byte, 0, len(html)+128)
	cursor := 0
	for cursor < len(html) {
		// Find the next opening <form ... > tag (case-insensitive).
		formStart := indexFoldBytes(html[cursor:], []byte("<form"))
		if formStart < 0 {
			out = append(out, html[cursor:]...)
			break
		}
		formStart += cursor
		// Find the end of THIS opening tag.
		tagEnd := bytes.IndexByte(html[formStart:], '>')
		if tagEnd < 0 {
			// Malformed (unclosed <form). Stop touching the document.
			out = append(out, html[cursor:]...)
			break
		}
		tagEnd += formStart // absolute index of the '>'

		openingTag := html[formStart : tagEnd+1]
		// Find the </form> for THIS form so we can scan its body for an
		// existing _csrf input. Nesting isn't valid HTML; first match wins.
		bodyEnd := indexFoldBytes(html[tagEnd+1:], []byte("</form>"))
		var bodyAbsEnd int
		if bodyEnd < 0 {
			bodyAbsEnd = len(html) // no closer; scan to EOF
		} else {
			bodyAbsEnd = tagEnd + 1 + bodyEnd
		}

		// Copy everything up to and including the opening tag.
		out = append(out, html[cursor:tagEnd+1]...)

		// Only inject when this is a POST form and doesn't already have _csrf.
		isPost := bytes.Contains(bytes.ToLower(openingTag), []byte(`method="post"`)) ||
			bytes.Contains(bytes.ToLower(openingTag), []byte(`method='post'`)) ||
			bytes.Contains(bytes.ToLower(openingTag), []byte(`method=post`))
		alreadyHas := indexFoldBytes(html[tagEnd+1:bodyAbsEnd], []byte(`name="_csrf"`)) >= 0 ||
			indexFoldBytes(html[tagEnd+1:bodyAbsEnd], []byte(`name='_csrf'`)) >= 0
		if isPost && !alreadyHas {
			out = append(out, inputTag...)
		}
		cursor = tagEnd + 1
	}
	return out
}

// indexFoldBytes does a case-insensitive substring search. Tiny helper
// - `bytes` doesn't ship one, and the inputs here are short enough
// that the naive scan is fine.
func indexFoldBytes(haystack, needle []byte) int {
	if len(needle) == 0 {
		return 0
	}
	if len(needle) > len(haystack) {
		return -1
	}
	for i := 0; i <= len(haystack)-len(needle); i++ {
		match := true
		for j := 0; j < len(needle); j++ {
			a := haystack[i+j]
			b := needle[j]
			if a >= 'A' && a <= 'Z' {
				a += 'a' - 'A'
			}
			if b >= 'A' && b <= 'Z' {
				b += 'a' - 'A'
			}
			if a != b {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}

// looksLikeAssetPath returns true for paths whose last segment has a
// non-HTML file extension we recognize as an asset. Used to decide
// whether to fall back to index.html (SPA) vs return a real 404.
//
// Why explicit allowlist? An agent might define a clean URL like
// `/notes/2026-04` that contains a dot but isn't an asset. The
// allowlist below is the set of extensions where "user is asking
// for a literal file" is the obvious intent.
func looksLikeAssetPath(rel string) bool {
	base := filepath.Base(rel)
	dot := strings.LastIndexByte(base, '.')
	if dot < 0 || dot == len(base)-1 {
		return false
	}
	ext := strings.ToLower(base[dot:])
	switch ext {
	case ".js", ".mjs", ".cjs", ".css", ".map",
		".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico", ".avif",
		".woff", ".woff2", ".ttf", ".otf", ".eot",
		".pdf", ".zip", ".tar", ".gz",
		".mp3", ".mp4", ".webm", ".ogg", ".wav",
		".json", ".xml", ".txt", ".csv", ".rss":
		return true
	}
	return false
}

// sensitiveProbeExts are file extensions that are never a Benmore app's
// client-side route - requests for them are credential/secret/config
// harvesting by scanners. Matched on the last path segment.
var sensitiveProbeExts = map[string]bool{
	"env": true, "php": true, "sql": true, "ini": true, "yaml": true, "yml": true,
	"toml": true, "tfstate": true, "tfvars": true, "key": true, "secret": true,
	"pem": true, "bak": true, "log": true, "cgi": true, "properties": true,
	"netrc": true, "cfg": true, "conf": true, "config": true, "sh": true,
	"py": true, "asp": true, "aspx": true, "jsp": true, "htaccess": true,
	"htpasswd": true, "dockercfg": true, "npmrc": true, "ts": true, "tsx": true,
	"jsx": true, "rb": true, "phar": true,
}

// scannerProbeMarkers are substrings that mark a request as automated
// CMS/exploit scanning (WordPress, PHP, CGI), not a real visitor.
var scannerProbeMarkers = []string{
	"wp-includes", "wp-content", "wp-admin", "wp-json", "xmlrpc",
	"wlwmanifest", "phpinfo", "cgi-bin", "/.git/", "/.svn/", "/.hg/",
}

// isScannerProbe reports whether an unmatched GET is an obvious scanner
// probe that must hard-404 rather than fall through to the SPA index.html.
// Three signals: a dot-prefixed path SEGMENT (.env/.aws/.git/.ssh - never a
// legit client route, dot-prefixed never appears in app routing), a known
// CMS/exploit marker, or a sensitive config extension on the last segment.
// /.well-known/ is exempt (legit: security.txt, ACME, etc.).
func isScannerProbe(rel string) bool {
	if rel == ".well-known" || strings.HasPrefix(rel, ".well-known/") {
		return false
	}
	lower := strings.ToLower(rel)
	for _, seg := range strings.Split(rel, "/") {
		if len(seg) > 1 && seg[0] == '.' { // .env, .aws, .git, .ssh, .netrc …
			return true
		}
	}
	for _, m := range scannerProbeMarkers {
		if strings.Contains(lower, m) {
			return true
		}
	}
	base := lower
	if i := strings.LastIndexByte(base, '/'); i >= 0 {
		base = base[i+1:]
	}
	if dot := strings.LastIndexByte(base, '.'); dot >= 0 && dot < len(base)-1 {
		if sensitiveProbeExts[base[dot+1:]] {
			return true
		}
	}
	return false
}

// stripLeadingFrontmatter removes a YAML frontmatter block from the
// start of an HTML file - `---\n…\n---\n` (or CRLF). Returns the rest
// untouched. Files that don't start with `---` are returned as-is.
//
// This exists for one reason: the pre-v2.5.6 page-contract validator
// erroneously told agents to add `engine: raw` frontmatter to static
// files, and a lot of in-the-wild apps now have that artifact at the
// top of `static/index.html` etc. The framework's static serve path
// is supposed to deliver the file verbatim, but verbatim would mean
// rendering the YAML as on-page text. Strip it on the way out so
// existing apps don't visibly leak the legacy validator's mistake.
func stripLeadingFrontmatter(data []byte) []byte {
	if len(data) < 7 || !bytes.HasPrefix(data, []byte("---")) {
		return data
	}
	// Find the closing `---` on its own line.
	rest := data[3:]
	// Allow a newline immediately after the opening `---`.
	if len(rest) > 0 && (rest[0] == '\n' || rest[0] == '\r') {
		if rest[0] == '\r' && len(rest) > 1 && rest[1] == '\n' {
			rest = rest[2:]
		} else {
			rest = rest[1:]
		}
	}
	for _, marker := range [][]byte{[]byte("\n---\n"), []byte("\n---\r\n"), []byte("\r\n---\r\n"), []byte("\r\n---\n")} {
		if idx := bytes.Index(rest, marker); idx >= 0 {
			return rest[idx+len(marker):]
		}
	}
	// Closer not found; assume the file isn't really frontmatter-prefixed.
	return data
}

// acceptsHTML returns true if the client signals it'll render HTML -
// used to gate the SPA-style index.html fallback. Treats requests with
// no Accept header (curl, fetch with default headers) as "yes" so they
// get the same surface as a browser would.
func acceptsHTML(r *http.Request) bool {
	accept := r.Header.Get("Accept")
	if accept == "" {
		return true
	}
	return strings.Contains(accept, "text/html") || strings.Contains(accept, "*/*")
}
