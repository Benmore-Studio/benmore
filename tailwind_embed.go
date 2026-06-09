//go:build !cli

package main

import (
	_ "embed"
	"net/http"
)

//go:embed embedded/tailwind.min.js
var tailwindJS []byte

// RegisterTailwindRoute serves the embedded Tailwind JS from
// /_internal/tailwind.js. Available to any app that wants utility-CSS
// without taking a CDN dependency - drop
// `<script src="/_internal/tailwind.js"></script>` into your HTML.
// tailwindDarkModeClass forces CLASS-based dark mode on the Play CDN.
// Without it the CDN defaults to `darkMode: 'media'`, so every `dark:`
// utility (e.g. the sdui skin's `dark:bg-zinc-900` inputs) fires on the
// VISITOR'S OS dark-mode setting - turning inputs/cards black on a
// light page. The framework's theming is class/[data-theme]-driven
// (see TailwindConfig + the scaffold's dark CSS vars), so `dark:` must
// key off a page-controlled `.dark` ancestor, never the OS. Appended to
// the served file so it runs right after the CDN initializes; a page
// that sets its own tailwind.config later (gotmpl layout) still wins.
var tailwindDarkModeClass = []byte("\n;try{window.tailwind&&(window.tailwind.config=Object.assign({},window.tailwind.config,{darkMode:'class'}));}catch(e){}\n")

func RegisterTailwindRoute(mux *http.ServeMux) {
	mux.HandleFunc("GET /_internal/tailwind.js", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("Cache-Control", "public, max-age=86400")
		w.Write(tailwindJS)
		w.Write(tailwindDarkModeClass)
	})
}
