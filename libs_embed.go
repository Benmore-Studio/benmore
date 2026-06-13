//go:build !cli

package main

// Embedded JS libraries served at /_internal/* paths. Zero external CDN
// dependencies - everything ships in the binary. The HTML stack is
// vanilla-first but agents who want a small library (Chart.js for
// graphs, Alpine.js for reactive sprinkles, HTMX for declarative HTTP,
// Lucide for icons) can pull them from /_internal/ instead of taking a
// CDN dependency.
//
// bm.js (the Benmore frontend SDK) IS served here - it's the
// canonical agent-facing way to talk to the backend (auth, table
// CRUD, live SSE, WS rooms). Tiny vanilla ES module, no React
// shipped. v2.7.14+.

import (
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"net/http"
	"strings"
)

// bmJSETag derives a strong ETag from the embedded bm.js content hash.
// Stable across processes that share the same binary (so a rolling
// restart doesn't invalidate every browser cache), changes the instant
// the binary updates (so a new deploy reaches every client on the
// next If-None-Match round trip).
func bmJSETag() string {
	sum := sha256.Sum256(bmSDKJS)
	return `"` + hex.EncodeToString(sum[:8]) + `"`
}

//go:embed embedded/chart.min.js
var chartJS []byte

//go:embed embedded/mermaid.min.js
var mermaidJS []byte

//go:embed embedded/alpine.min.js
var alpineJS []byte

//go:embed embedded/htmx.min.js
var htmxJS []byte

//go:embed embedded/lucide.min.js
var lucideJS []byte

// rrweb (record) is injected into the headless browser during browser_check to
// capture an agent-test session; rrweb-player replays it in the builder UI.
//
//go:embed embedded/rrweb.min.js
var rrwebJS []byte

// PLAYER PROVENANCE: @amplitude/rrweb-player@2.1.1
// (dist/rrweb-player.umd.min.cjs + dist/style.css). The UPSTREAM
// rrweb-player@2.0.1 npm dist is BROKEN - every build (umd/min/esm) ships
// an empty onMount and no replayer core, so the Svelte shell renders but
// getReplayer() stays undefined and the replay iframe is never created
// (verified in a headless harness 2026-06-11; the source's Player.svelte
// is fine, the published artifact lost the body to tree-shaking). The
// Amplitude fork is the same 2.x player built correctly. If you upgrade,
// run the smoke test: new rrwebPlayer.default({target,props:{events}})
// then assert getReplayer() returns an object and an iframe exists.
//
//go:embed embedded/rrweb-player.js
var rrwebPlayerJS []byte

//go:embed embedded/rrweb-player.css
var rrwebPlayerCSS []byte

//go:embed embedded/libavoid.js
var libavoidJS []byte

//go:embed embedded/libavoid.wasm
var libavoidWASM []byte

//go:embed embedded/bm.js
var bmSDKJS []byte

//go:embed embedded/sdui.js
var sduiJS []byte

// sduiJSETag mirrors bmJSETag for the schema-driven component library.
func sduiJSETag() string {
	sum := sha256.Sum256(sduiJS)
	return `"` + hex.EncodeToString(sum[:8]) + `"`
}

//go:embed embedded/markdown.js
var markdownJS []byte

// RegisterLibRoutes serves embedded JS libraries from /_internal/ paths.
// Available libs (drop-in CDN replacements):
//   /_internal/chart.js     - Chart.js for line/bar/pie charts
//   /_internal/mermaid.js   - Mermaid for diagrams
//   /_internal/alpine.js    - Alpine.js for reactive sprinkles
//   /_internal/htmx.js      - HTMX for declarative HTTP
//   /_internal/lucide.js    - Lucide icon set
//   /_internal/libavoid.js  - Libavoid for graph routing
//   /_internal/libavoid.wasm - Libavoid WASM module
//   /_internal/bm.js        - Benmore frontend SDK (special handling)
func RegisterLibRoutes(mux *http.ServeMux) {
	serve := func(path string, data []byte) {
		mux.HandleFunc("GET "+path, func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/javascript")
			w.Header().Set("Cache-Control", "public, max-age=86400")
			w.Write(data)
		})
	}
	serve("/_internal/chart.js", chartJS)
	serve("/_internal/mermaid.js", mermaidJS)
	serve("/_internal/alpine.js", alpineJS)
	serve("/_internal/htmx.js", htmxJS)
	serve("/_internal/lucide.js", lucideJS)
	serve("/_internal/libavoid.js", libavoidJS)
	// markdown.js - tiny safe-by-default Markdown→HTML renderer. Pulled
	// out as a shared lib after an earlier app build hand-rolled the same
	// regex twice in different modules. See bm.markdown() in bm.js for
	// the SDK wrapper.
	serve("/_internal/markdown.js", markdownJS)
	// rrweb session-replay player (builder "watch the agent test" view).
	serve("/_internal/rrweb-player.js", rrwebPlayerJS)
	mux.HandleFunc("GET /_internal/rrweb-player.css", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/css")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(rrwebPlayerCSS)
	})

	// bm.js gets DIFFERENT cache headers from the other libs above.
	// The other libs are pinned-version third-party JS and change only
	// with a framework release - 24h CDN cache is fine. bm.js is the
	// framework's own SDK and changes every framework deploy. With the
	// 24h cache, CF would happily serve a stale bm.js for a day after
	// every deploy - agents push new code, browsers run old SDK,
	// `bm.broadcast is undefined` symptoms surface. Same trick we use
	// for TSX-compiled output: strong ETag + CDN-Cache-Control: no-store
	// so CF goes back to origin on every request, browser revalidates
	// against the ETag (304 ~50 bytes when unchanged).
	bmETag := bmJSETag()
	mux.HandleFunc("GET /_internal/bm.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("ETag", bmETag)
		w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
		w.Header().Set("CDN-Cache-Control", "no-store")
		w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store")
		if match := r.Header.Get("If-None-Match"); match != "" {
			for _, candidate := range strings.Split(match, ",") {
				c := strings.TrimSpace(candidate)
				if c == bmETag || c == "W/"+bmETag {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
		}
		w.Write(bmSDKJS)
	})

	// sdui.js - schema-driven component library. Same no-store + ETag
	// treatment as bm.js (it's framework-own code that changes every
	// deploy, so CF must revalidate or agents get a stale component layer).
	sduiETag := sduiJSETag()
	mux.HandleFunc("GET /_internal/sdui.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript; charset=utf-8")
		w.Header().Set("ETag", sduiETag)
		w.Header().Set("Cache-Control", "private, no-cache, no-store, must-revalidate")
		w.Header().Set("CDN-Cache-Control", "no-store")
		w.Header().Set("Cloudflare-CDN-Cache-Control", "no-store")
		if match := r.Header.Get("If-None-Match"); match != "" {
			for _, candidate := range strings.Split(match, ",") {
				c := strings.TrimSpace(candidate)
				if c == sduiETag || c == "W/"+sduiETag {
					w.WriteHeader(http.StatusNotModified)
					return
				}
			}
		}
		w.Write(sduiJS)
	})

	// WASM needs application/wasm Content-Type or the browser's streaming
	// compiler (WebAssembly.instantiateStreaming) refuses it.
	mux.HandleFunc("GET /_internal/libavoid.wasm", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/wasm")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(libavoidWASM)
	})
}
