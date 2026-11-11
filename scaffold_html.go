//go:build !cli

package main

// HTML scaffold for `benmore new <name> --html`. The default direction
// going forward - vanilla HTML + CSS + JS hitting the framework's REST
// + SSE + WS surface. No bm.js, no React, no esbuild. The agent writes
// whatever frontend it wants; the framework just serves files and APIs.
//
// Layout:
//
//   <name>/
//     app.yaml         - auth + theme + features
//     schema.prisma    - example Note model
//     tsconfig.json    - paths: { "bm": ["./src/bm.d.ts"] }, strict
//     src/bm.d.ts      - AUTO-REGEN per-app TypeScript types
//     static/          - agent's frontend lives here
//       index.html     - home page (auto-injected <script type="importmap">)
//       login.html     - login UI
//       signup.html    - signup UI
//       verify-mfa.html, mfa-setup.html, verify-otp.html,
//       forgot-password.html, reset-password.html - sign-in step pages
//       app.tsx        - thin entry, compiled on the fly to /static/app.js
//       lib/auth.ts    - logic helpers (lib/)
//       components/ui.tsx - shared UI primitives (components/)
//       views/notes.tsx   - example feature (views/, one per feature)
//       styles.css     - opt-in custom CSS (Tailwind is primary, served from binary)
//     AGENTS.md        - shared app contract; CLAUDE.md imports it
//
// What the framework adds at serve time:
//   - <meta name="csrf-token"> auto-injected into every .html in static/
//   - GET /api/_csrf endpoint returning the same token (fetch fallback)
//   - Clean URL routing: `/contacts` → `static/contacts.html`,
//     `/` → `static/index.html`, SPA-style fallback to index.html
//   - Everything else (auth, CRUD, SSE, WS, flows, hooks…) unchanged.

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ScaffoldNewHTML creates a vanilla HTML+JS app. Counterpart to
// ScaffoldNewReact (legacy) and ScaffoldNew (gotmpl). This is the
// direction we want everyone going.
func ScaffoldNewHTML(name string) {
	title := strings.Title(name)
	if err := WriteHTMLScaffoldFiles(name, title); err != nil {
		fmt.Printf("Error scaffolding %s: %s\n", name, err)
		os.Exit(1)
	}

	fmt.Printf("Created %s/ (TSX-by-default; auto-compiled by embedded esbuild)\n", name)
	fmt.Printf("  app.yaml          - auth + theme\n")
	fmt.Printf("  schema.prisma     - example Note model\n")
	fmt.Printf("  mcp.yaml          - reviewed read-only Notes connector (owner opt-in)\n")
	fmt.Printf("  static/index.html - home page\n")
	fmt.Printf("  static/login.html - login UI\n")
	fmt.Printf("  static/signup.html - signup UI\n")
	fmt.Printf("  static/verify-mfa.html, mfa-setup.html, verify-otp.html,\n")
	fmt.Printf("    forgot-password.html, reset-password.html - sign-in step pages\n")
	fmt.Printf("  static/app.tsx           - thin entry (orchestration only)\n")
	fmt.Printf("  static/lib/auth.ts       - auth state + sign-out (logic → lib/)\n")
	fmt.Printf("  static/components/ui.tsx - shared UI primitives (Button, Input, Field, Card, Badge, EmptyState)\n")
	fmt.Printf("  static/views/notes.tsx   - example feature (one file per feature → views/)\n")
	fmt.Printf("  static/styles.css        - opt-in custom CSS (Tailwind is the primary styling engine; served from binary)\n")
	fmt.Printf("  tsconfig.json     - paths { bm: src/bm.d.ts }\n")
	fmt.Printf("  src/bm.d.ts       - per-app TS types (auto-regen on push)\n")
	fmt.Printf("  AGENTS.md         - shared app contract (Codex + Claude)\n\n")
	fmt.Printf("Edit static/*.tsx; the framework auto-compiles to /static/*.js\n")
	fmt.Printf("on every request via embedded esbuild. Add features as\n")
	fmt.Printf("static/views/<name>.tsx + import from app.tsx (keep app.tsx thin).\n")
}

// WriteHTMLScaffoldFiles writes the HTML+JS starter into `dir`. Shared
// between the CLI scaffold (`benmore new --html`) and the MCP
// `create_app` tool (once it learns about the HTML stack).
func WriteHTMLScaffoldFiles(dir, title string) error {
	return writeHTMLScaffoldFiles(dir, title, true)
}

// An unlinked hosted workspace cannot yet attest server-contributed source.
// Keep its first deploy usable; author/review a connector after pulling the
// deployed source. Server-created and self-hosted starters can bind it now.
func writeHTMLScaffoldFiles(dir, title string, withConnector bool) error {
	name := filepath.Base(dir)
	if title == "" {
		title = strings.Title(name)
	}

	if err := os.MkdirAll(filepath.Join(dir, "static"), 0o755); err != nil {
		return fmt.Errorf("mkdir static: %w", err)
	}

	write := func(rel, content string) error {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(rel), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", rel, err)
		}
		return nil
	}

	if err := write("app.yaml", fmt.Sprintf(`site_name: %q
theme: zinc
mode: dark         # pages the server renders; static/ pages are dark through class="dark" on their html element

auth:
  identifier: email
  session_duration: "30d"
  signup_fields: "first_name"

features:
  testing: true   # %s
`, title, scaffoldTestingFlagNote)); err != nil {
		return err
	}

	if err := write("schema.prisma", `model Note {
  id        Int      @id @default(autoincrement())
  title     String
  body      String   @default("")
  userId    Int      @map("user_id")
  createdAt DateTime @default(now()) @map("created_at")
  updatedAt DateTime @default(now()) @updatedAt @map("updated_at")

  @@index([userId, updatedAt])
}
`); err != nil {
		return err
	}

	// Shared <head> partial. The HTML stack supports <include src="..." />
	// (v2.7.147+), so chrome that's identical across pages - meta, Tailwind,
	// stylesheet - lives in ONE file instead of being copy-pasted into every
	// page. This is the pattern to reach for the moment you have more than one
	// page: add it here, include it everywhere, edit it once.
	if err := write("static/partials/head.html", `<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<!-- Tailwind is the primary styling engine for this scaffold.
     It is served from the framework binary at
     /_internal/tailwind.js - no CDN, no build step, every utility
     class works out of the box. Agents: prefer Tailwind utility
     classes for everything. The styles.css below is a thin opt-in
     stub for the rare custom rule Tailwind can't express; almost
     all real styling work belongs in the markup as utility classes. -->
<script src="/_internal/tailwind.js"></script>
<link rel="stylesheet" href="/static/styles.css">
`+scaffoldFaviconNote+`
<link rel="icon" href="/static/favicon.svg" type="image/svg+xml">
`); err != nil {
		return err
	}

	if err := write("static/favicon.svg", htmlScaffoldFaviconSVG); err != nil {
		return err
	}

	if err := write("static/index.html", `<!doctype html>
<html lang="en" class="dark h-full">
<head>
  <!-- class="dark" on the html element above is what makes this page dark:
       a dark: utility applies only inside an element with class "dark",
       never from the visitor's system setting, so keep dark: classes on
       body and below. For a light app remove "dark" from each page's html
       element. -->
  <!-- Shared chrome (meta, Tailwind, stylesheet) lives in one place.
       Edit static/partials/head.html once; every page picks it up.
       <include> resolves relative to static/ on the HTML stack. -->
  <include src="partials/head.html" />
  <title>`+title+`</title>
</head>
<body class="h-full bg-white dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 antialiased">
  <main class="mx-auto max-w-3xl px-6 py-10" data-route="home">
    <header class="flex items-center justify-between mb-8">
      <h1 class="text-2xl font-semibold tracking-tight">`+title+`</h1>
      <div class="who flex items-center gap-3" hidden>
        <span class="who-name text-sm text-zinc-600 dark:text-zinc-400"></span>
        <button type="button" data-action="signout" data-testid="signout" class="text-sm px-3 py-1.5 rounded-md border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-800">Sign out</button>
      </div>
    </header>

    <!-- Anonymous view -->
    <section class="anon space-y-2" hidden>
      <p class="text-zinc-600 dark:text-zinc-400">You're not signed in.</p>
      <p class="text-sm">
        <a href="/login.html" data-testid="nav-login" class="text-blue-600 dark:text-blue-400 hover:underline">Log in</a>
        <span class="text-zinc-400">&middot;</span>
        <a href="/signup.html" data-testid="nav-signup" class="text-blue-600 dark:text-blue-400 hover:underline">Sign up</a>
      </p>
    </section>

    <!-- Authenticated view -->
    <section class="app space-y-4" hidden>
      `+scaffoldTestidNote+`
      <form id="new-note" data-testid="note-form" class="flex gap-2">
        <input name="title" data-testid="note-title" placeholder="What needs writing down?" autocomplete="off" required
               class="flex-1 px-3 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500">
        <button type="submit" data-testid="note-add" class="px-4 py-2 rounded-md bg-blue-600 text-white font-medium hover:bg-blue-500">Add</button>
      </form>
      <ul id="notes" data-testid="note-list" class="divide-y divide-zinc-200 dark:divide-zinc-800 rounded-md border border-zinc-200 dark:border-zinc-800"></ul>
      <p class="empty text-sm text-zinc-500" data-testid="note-empty" hidden>No notes yet. Add one above.</p>
    </section>
  </main>

  <!-- Resolve the bare 'bm' specifier to the framework's SDK module.
       Agents writing TSX/TS use: import bm from 'bm' -->
  <script type="importmap">{"imports":{"bm":"/_internal/bm.js"}}</script>
  <!-- /static/app.js is compiled on-the-fly from static/app.tsx
       (embedded esbuild; no node, no build step). `+scaffoldEditTSXNote+` -->
  <script type="module" src="/static/app.js"></script>
</body>
</html>
`); err != nil {
		return err
	}

	if err := write("static/login.html", `<!doctype html>
<html lang="en" class="dark h-full">
<head>
  <include src="partials/head.html" />
  <title>Log in &middot; `+title+`</title>
</head>
<body class="h-full bg-white dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 antialiased">
  <main class="min-h-full flex items-center justify-center px-6 py-10" data-auth-page>
    <form id="login-form" method="POST" data-testid="login-form" autocomplete="on" class="w-full max-w-sm space-y-4 p-6 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm">
      <h1 class="text-2xl font-semibold tracking-tight">Log in</h1>
      <p class="text-sm text-zinc-600 dark:text-zinc-400">Welcome back to `+title+`.</p>
      <div class="error text-sm text-red-600 dark:text-red-400" role="alert" hidden></div>
      <div class="success text-sm text-green-700 dark:text-green-400" role="status" hidden></div>
      <label class="block space-y-1">
        <span class="text-sm font-medium">Email</span>
        <input type="email" name="email" data-testid="login-email" required autocomplete="email"
               class="block w-full px-3 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500">
      </label>
      <label class="block space-y-1">
        <span class="text-sm font-medium">Password</span>
        <input type="password" name="password" data-testid="login-password" required autocomplete="current-password"
               class="block w-full px-3 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500">
      </label>
      <button type="submit" data-testid="login-submit" class="w-full px-4 py-2 rounded-md bg-blue-600 text-white font-medium hover:bg-blue-500">Log in</button>
      <button type="button" id="login-passkey" data-testid="login-passkey" hidden class="w-full px-4 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 font-medium hover:bg-zinc-50 dark:hover:bg-zinc-900">Sign in with a passkey</button>
      <p class="text-sm text-zinc-600 dark:text-zinc-400"><a href="/forgot-password" data-testid="login-forgot" class="text-blue-600 dark:text-blue-400 hover:underline">Forgot your password?</a></p>
      <p class="text-sm text-zinc-600 dark:text-zinc-400">No account? <a href="/signup.html" class="text-blue-600 dark:text-blue-400 hover:underline">Sign up</a></p>
    </form>
  </main>
  <!-- Resolve the bare 'bm' specifier to the framework's SDK module.
       Agents writing TSX/TS use: import bm from 'bm' -->
  <script type="importmap">{"imports":{"bm":"/_internal/bm.js"}}</script>
  <!-- /static/app.js is compiled on-the-fly from static/app.tsx
       (embedded esbuild; no node, no build step). `+scaffoldEditTSXNote+` -->
  <script type="module" src="/static/app.js"></script>
</body>
</html>
`); err != nil {
		return err
	}

	if err := write("static/signup.html", `<!doctype html>
<html lang="en" class="dark h-full">
<head>
  <include src="partials/head.html" />
  <title>Sign up &middot; `+title+`</title>
</head>
<body class="h-full bg-white dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 antialiased">
  <main class="min-h-full flex items-center justify-center px-6 py-10" data-auth-page>
    <form id="signup-form" method="POST" data-testid="signup-form" autocomplete="on" class="w-full max-w-sm space-y-4 p-6 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm">
      <h1 class="text-2xl font-semibold tracking-tight">Create an account</h1>
      <p class="text-sm text-zinc-600 dark:text-zinc-400">Start using `+title+`.</p>
      <div class="error text-sm text-red-600 dark:text-red-400" role="alert" hidden></div>
      <label class="block space-y-1">
        <span class="text-sm font-medium">First name</span>
        <input type="text" name="first_name" data-testid="signup-first-name" required autocomplete="given-name"
               class="block w-full px-3 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500">
      </label>
      <label class="block space-y-1">
        <span class="text-sm font-medium">Email</span>
        <input type="email" name="email" data-testid="signup-email" required autocomplete="email"
               class="block w-full px-3 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500">
      </label>
      <label class="block space-y-1">
        <span class="text-sm font-medium">Password</span>
        <input type="password" name="password" data-testid="signup-password" required autocomplete="new-password" minlength="8"
               class="block w-full px-3 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500">
      </label>
      <button type="submit" data-testid="signup-submit" class="w-full px-4 py-2 rounded-md bg-blue-600 text-white font-medium hover:bg-blue-500">Sign up</button>
      <p class="text-sm text-zinc-600 dark:text-zinc-400">Already have an account? <a href="/login.html" class="text-blue-600 dark:text-blue-400 hover:underline">Log in</a></p>
    </form>
  </main>
  <!-- Resolve the bare 'bm' specifier to the framework's SDK module.
       Agents writing TSX/TS use: import bm from 'bm' -->
  <script type="importmap">{"imports":{"bm":"/_internal/bm.js"}}</script>
  <!-- /static/app.js is compiled on-the-fly from static/app.tsx
       (embedded esbuild; no node, no build step). `+scaffoldEditTSXNote+` -->
  <script type="module" src="/static/app.js"></script>
</body>
</html>
`); err != nil {
		return err
	}

	// Sign-in step pages. The framework's sign-in handlers send a person to
	// these paths mid sign-in (an authenticator code, enrolling one, an
	// emailed code, a reset link) and serve no page there, so the app ships
	// them; without them the step 404s or the SPA fallback shows the home
	// page signed out. One file per path (clean URLs: /verify-mfa →
	// static/verify-mfa.html).
	for _, page := range htmlScaffoldAuthStepPages(title) {
		if err := write(page.rel, page.html); err != nil {
			return err
		}
	}

	// v2.7.21+: TSX-by-default scaffold. v2.7.25+: split into 3 files
	// to model the canonical multi-file pattern. Agents shouldn't ever
	// be forced into a god-file; seeing the split at scaffold time is
	// what teaches them where the seams go.
	//
	//   static/app.tsx           - entry; ~25 lines, just orchestration
	//   static/lib/auth.ts       - auth state + sign-out wiring (logic → lib/)
	//   static/components/ui.tsx - shared UI primitives (components/)
	//   static/views/notes.tsx   - example feature (the scaffolded `notes` table)
	//
	// This folder convention (lib/ for logic, components/ for shared UI,
	// views/ for features) IS the structure agents should follow as the app
	// grows - the scaffold models it from the start so a build never devolves
	// into one giant app.tsx. esbuild bundles the whole import graph from the
	// entry, so /static/app.js stays a single request no matter how many files.
	if err := write("static/app.tsx", htmlScaffoldAppTSX); err != nil {
		return err
	}
	if err := write("static/lib/auth.ts", htmlScaffoldAuthTSX); err != nil {
		return err
	}
	// Keyed list rendering helper - the flicker-free way to re-render a list on
	// live SSE updates (vs the innerHTML-wipe antipattern). Used by views/notes.tsx.
	if err := write("static/lib/dom.ts", htmlScaffoldDomTS); err != nil {
		return err
	}
	if err := write("static/views/notes.tsx", htmlScaffoldNotesTSX); err != nil {
		return err
	}
	// Canonical UI primitives (v2.7.62+). Ships in every scaffold so
	// agents have something to reach for instead of hand-rolling
	// Button / Input / Card markup in each feature file. Used by
	// views/notes.tsx already; extend with app-specific primitives here.
	if err := write("static/components/ui.tsx", htmlScaffoldComponentsTSX); err != nil {
		return err
	}

	if err := write("static/styles.css", htmlScaffoldStylesCSS); err != nil {
		return err
	}
	// A first browser journey so `benmore verify` has something real to run
	// on day one. qa_inventory drafts more of these from the rendered app.
	if err := write("tests/journeys/home.yaml", htmlScaffoldHomeJourneyYAML); err != nil {
		return err
	}

	// TypeScript project config - points the `bm` bare specifier at
	// src/bm.d.ts (regenerated on every push). With this in place,
	// `import * as bm from 'bm'` autocompletes in the agent's editor
	// using the per-app schema types.
	if err := write("tsconfig.json", htmlScaffoldTSConfig); err != nil {
		return err
	}

	// Initial bm.d.ts - placeholder pointing at the live endpoint. The
	// real types regenerate when the app rebuilds after changes to the
	// schema. Workspace copy keeps `import 'bm'` resolving locally for
	// the editor even when offline.
	if err := write("src/bm.d.ts", htmlScaffoldBMDTSPlaceholder); err != nil {
		return err
	}

	if err := write("CLAUDE.md", scaffoldClaudeMD(title, name)); err != nil {
		return err
	}
	if err := write("AGENTS.md", scaffoldAgentsGuide(title, name)); err != nil {
		return err
	}
	// Hosted create_app initializes git next; include its protected ignore
	// rules now so that setup does not change the reviewed source digest.
	if err := write(".gitignore", gitignoreContents); err != nil {
		return err
	}

	if withConnector {
		return writeAppMCPStarter(dir)
	}
	return nil
}

// WriteBareScaffoldFiles writes only the infrastructure files an app
// needs to exist on the platform - NO demo content. Used by `benmore
// deploy` when it creates an app for an EXISTING local directory: the
// deploy is about to push the real app.yaml/schema.prisma/static/*, so
// scaffolding the Notes demo first would leave every demo file the
// local dir doesn't happen to shadow (views/notes.tsx, app.tsx, the
// notes index.html, …) live in the deployed app - a scaffold/app
// chimera that 404s on /api/notes and serves the wrong front page.
//
// What still ships:
//   - app.yaml: minimal, so the app boots even before the first push
//     lands (overwritten by the deploy when the dir has its own).
//   - tsconfig.json + src/bm.d.ts: editor infra for the typed SDK,
//     regenerated/refreshed on push - not app content.
//   - CLAUDE.md: the agent guide; kept if the dir doesn't ship one.
func WriteBareScaffoldFiles(dir, title string) error {
	name := filepath.Base(dir)
	if title == "" {
		title = strings.Title(name)
	}
	write := func(rel, content string) error {
		full := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return fmt.Errorf("mkdir %s: %w", filepath.Dir(rel), err)
		}
		if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
			return fmt.Errorf("write %s: %w", rel, err)
		}
		return nil
	}
	if err := write("app.yaml", fmt.Sprintf(`site_name: %q
`, title)); err != nil {
		return err
	}
	if err := write("tsconfig.json", htmlScaffoldTSConfig); err != nil {
		return err
	}
	if err := write("src/bm.d.ts", bareScaffoldBMDTSPlaceholder); err != nil {
		return err
	}
	if err := write("CLAUDE.md", scaffoldClaudeMD(title, name)); err != nil {
		return err
	}
	if err := write("AGENTS.md", scaffoldAgentsGuide(title, name)); err != nil {
		return err
	}
	return nil
}

// Class strings shared by the scaffold's sign-in step pages (the login and
// signup pages above spell the same ones out).
const (
	scaffoldAuthCard   = `w-full max-w-sm space-y-4 p-6 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm`
	scaffoldAuthInput  = `block w-full px-3 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500`
	scaffoldAuthButton = `w-full px-4 py-2 rounded-md bg-blue-600 text-white font-medium hover:bg-blue-500`
	scaffoldAuthNote   = `text-sm text-zinc-600 dark:text-zinc-400`
	scaffoldAuthLink   = `text-blue-600 dark:text-blue-400 hover:underline`
	scaffoldAuthError  = `<div class="error text-sm text-red-600 dark:text-red-400" role="alert" hidden></div>`
	// /login, the path the framework's own sign-in redirects use.
	scaffoldAuthBack = `<p class="` + scaffoldAuthNote + `"><a href="/login" class="` + scaffoldAuthLink + `">Back to log in</a></p>`
)

type scaffoldPage struct{ rel, html string }

// htmlScaffoldAuthStepPages are the pages the framework's sign-in handlers
// send a person to between the password and a session, plus password
// recovery. Each form posts to the framework's handler for its path and works
// without script; lib/auth.ts initAuthPage shows ?error=/?success= and fills
// the hidden next/token fields. mfa-setup is the one page that needs script.
func htmlScaffoldAuthStepPages(title string) []scaffoldPage {
	page := func(heading, body string) string {
		return `<!doctype html>
<html lang="en" class="dark h-full">
<head>
  <include src="partials/head.html" />
  <title>` + heading + ` &middot; ` + title + `</title>
</head>
<body class="h-full bg-white dark:bg-zinc-950 text-zinc-900 dark:text-zinc-100 antialiased">
  <main class="min-h-full flex items-center justify-center px-6 py-10" data-auth-page>
` + body + `  </main>
  <script type="importmap">{"imports":{"bm":"/_internal/bm.js"}}</script>
  <script type="module" src="/static/app.js"></script>
</body>
</html>
`
	}
	codeField := func(name, testid string) string {
		return `      <label class="block space-y-1">
        <span class="text-sm font-medium">Code</span>
        <input type="text" name="` + name + `" data-testid="` + testid + `" required autofocus autocomplete="one-time-code" autocapitalize="off" spellcheck="false" maxlength="32"
               class="` + scaffoldAuthInput + `">
      </label>
`
	}
	return []scaffoldPage{
		{"static/verify-mfa.html", page("Two-factor code", `    <!-- Second sign-in step for an account with an authenticator app (MFA).
         POST /login sends the person here after the password; this form
         posts the code to /verify-mfa, which signs them in and goes on to
         ?next= (or comes back here with ?error=). -->
    <form id="verify-mfa-form" method="POST" action="/verify-mfa" data-testid="verify-mfa-form" class="`+scaffoldAuthCard+`">
      <h1 class="text-2xl font-semibold tracking-tight">Two-factor code</h1>
      <p class="`+scaffoldAuthNote+`">Enter the 6-digit code from your authenticator app, or one of your backup codes.</p>
      `+scaffoldAuthError+`
      <input type="hidden" name="next" value="">
`+codeField("mfa_code", "verify-mfa-code")+`      <button type="submit" data-testid="verify-mfa-submit" class="`+scaffoldAuthButton+`">Verify</button>
      `+scaffoldAuthBack+`
    </form>
`)},
		{"static/mfa-setup.html", page("Set up two-factor sign-in", `    <!-- Enrollment step for a role listed in auth.require_mfa_for_roles. A
         sign-in or sign-up sends the person here with a short-lived setup
         cookie instead of a session: lib/auth.ts initMFASetup asks
         bm.mfa.enroll() for a key, shows it, and bm.mfa.verify(code) turns
         the factor on and signs the person in. A person who was already
         signed in when the rule began to apply to them lands here too; the
         server then wants their current password first, so the script shows
         the password form below, calls bm.mfa.enroll(password), and offers
         sign-out. -->
    <section id="mfa-setup" data-testid="mfa-setup" class="`+scaffoldAuthCard+`">
      <h1 class="text-2xl font-semibold tracking-tight">Set up two-factor sign-in</h1>
      <p class="`+scaffoldAuthNote+`">Your account needs a second step at sign-in. Add this key to an authenticator app (1Password, Google Authenticator, Authy), then enter the 6-digit code it shows.</p>
      `+scaffoldAuthError+`
      <form id="mfa-setup-password-form" method="POST" class="space-y-4" data-testid="mfa-setup-password-form" hidden>
        <p class="`+scaffoldAuthNote+`">Enter your password to begin. If you sign in without one (Google, a passkey), sign out and sign in again instead.</p>
        <label class="block space-y-1">
          <span class="text-sm font-medium">Password</span>
          <input type="password" name="password" data-testid="mfa-setup-password" required autocomplete="current-password"
                 class="`+scaffoldAuthInput+`">
        </label>
        <button type="submit" data-testid="mfa-setup-password-submit" class="`+scaffoldAuthButton+`">Continue</button>
      </form>
      <div class="mfa-key space-y-2" hidden>
        <code class="mfa-secret block p-2 rounded bg-zinc-100 dark:bg-zinc-800 text-sm break-all" data-testid="mfa-setup-secret"></code>
        <a class="mfa-link text-sm `+scaffoldAuthLink+`" data-testid="mfa-setup-link" hidden>Open in an authenticator app on this device</a>
        <p class="`+scaffoldAuthNote+`">Backup codes: each signs you in once if you lose your authenticator. Save them now; they are not shown again.</p>
        <pre class="mfa-backup-codes p-2 rounded bg-zinc-100 dark:bg-zinc-800 text-sm" data-testid="mfa-setup-backup-codes"></pre>
      </div>
      <form id="mfa-setup-form" method="POST" class="space-y-4" data-testid="mfa-setup-form" hidden>
`+codeField("code", "mfa-setup-code")+`        <button type="submit" data-testid="mfa-setup-submit" class="`+scaffoldAuthButton+`">Turn on and continue</button>
      </form>
      `+scaffoldAuthBack+`
      <p class="mfa-signout `+scaffoldAuthNote+`" hidden>You are signed in. <button type="button" data-action="signout" data-testid="mfa-setup-signout" class="`+scaffoldAuthLink+`">Sign out</button></p>
    </section>
`)},
		{"static/verify-otp.html", page("Enter your code", `    <!-- Emailed or texted sign-in code (auth.otp: true). The sign-in sends
         the person here once the code is sent; this form posts it to
         /verify-otp, which signs them in and goes on to ?next=. -->
    <form id="verify-otp-form" method="POST" action="/verify-otp" data-testid="verify-otp-form" class="`+scaffoldAuthCard+`">
      <h1 class="text-2xl font-semibold tracking-tight">Enter your code</h1>
      <p class="`+scaffoldAuthNote+`">We sent you a 6-digit code. It expires in 10 minutes.</p>
      `+scaffoldAuthError+`
      <input type="hidden" name="next" value="">
`+codeField("code", "verify-otp-code")+`      <button type="submit" data-testid="verify-otp-submit" class="`+scaffoldAuthButton+`">Verify</button>
      `+scaffoldAuthBack+`
    </form>
`)},
		{"static/forgot-password.html", page("Reset your password", `    <!-- Password recovery, step 1. POST /forgot-password emails a one-hour
         link to /reset-password (when the address has an account) and comes
         back here with ?success=. auth.password_reset: false turns this off. -->
    <form id="forgot-password-form" method="POST" action="/forgot-password" data-testid="forgot-password-form" class="`+scaffoldAuthCard+`">
      <h1 class="text-2xl font-semibold tracking-tight">Reset your password</h1>
      <p class="`+scaffoldAuthNote+`">Enter your account's email and we'll send you a link to choose a new password.</p>
      `+scaffoldAuthError+`
      <div class="success text-sm text-green-700 dark:text-green-400" role="status" hidden></div>
      <label class="block space-y-1">
        <span class="text-sm font-medium">Email</span>
        <input type="email" name="email" data-testid="forgot-password-email" required autocomplete="email"
               class="`+scaffoldAuthInput+`">
      </label>
      <button type="submit" data-testid="forgot-password-submit" class="`+scaffoldAuthButton+`">Send reset link</button>
      `+scaffoldAuthBack+`
    </form>
`)},
		{"static/reset-password.html", page("Choose a new password", `    <!-- Password recovery, step 2: the emailed link opens
         /reset-password?token=...; the token goes back with the form. On
         success POST /reset-password signs every session out and sends the
         person to log in with ?success=. -->
    <form id="reset-password-form" method="POST" action="/reset-password" data-testid="reset-password-form" class="`+scaffoldAuthCard+`">
      <h1 class="text-2xl font-semibold tracking-tight">Choose a new password</h1>
      `+scaffoldAuthError+`
      <input type="hidden" name="token" value="">
      <label class="block space-y-1">
        <span class="text-sm font-medium">New password</span>
        <input type="password" name="password" data-testid="reset-password-password" required autocomplete="new-password" minlength="8"
               class="`+scaffoldAuthInput+`">
      </label>
      <label class="block space-y-1">
        <span class="text-sm font-medium">Confirm new password</span>
        <input type="password" name="confirm" data-testid="reset-password-confirm" required autocomplete="new-password" minlength="8"
               class="`+scaffoldAuthInput+`">
      </label>
      <button type="submit" data-testid="reset-password-submit" class="`+scaffoldAuthButton+`">Set new password</button>
      `+scaffoldAuthBack+`
    </form>
`)},
	}
}

// Scaffold models the canonical folder split (lib/ logic · components/ shared
// UI · views/ features). htmlScaffoldAppTSX is the LEAN entry - orchestration
// only; real logic lives in static/lib/auth.ts + static/views/notes.tsx. Adding
// a feature means a new static/views/<name>.tsx imported here.
const htmlScaffoldAppTSX = `// app.tsx - thin entry. Orchestration only; feature code lives under lib/ + components/ + views/.
//
// This file is compiled on-the-fly by the framework's embedded esbuild
// (Go API, no Node) into /static/app.js. esbuild bundles every file
// imported from here into one ES module.
//
// Keep this file THIN - it just wires modules together. Real code lives in:
//   lib/        - logic + data helpers (e.g. lib/auth.ts)
//   components/ - shared UI primitives (e.g. components/ui.tsx)
//   views/      - one file per feature/screen (e.g. views/notes.tsx)
// Add a feature by creating static/views/<feature>.tsx exporting an init fn,
// then import + call it below. esbuild bundles the whole graph into app.js;
// relative imports resolve .ts/.tsx so the extension is optional.
// The SDK's import map ('bm' → /_internal/bm.js) is set in index.html.

import { initAuth, initAuthPage } from './lib/auth';
import { initNotes } from './views/notes';

async function boot() {
  // The sign-in pages (login, signup and the step pages such as
  // verify-mfa.html) load this same bundle and mark <main data-auth-page>.
  // Wire the page's form and stop: the app view below is for signed-in pages.
  if (document.querySelector('[data-auth-page]')) { await initAuthPage(); return; }

  const me = await initAuth();
  if (!me) return; // anon view shown by initAuth
  await initNotes(me);
}

boot().catch(err => {
  console.error('boot:', err);
  document.body.insertAdjacentHTML(
    'afterbegin',
    '<pre style="color:red;padding:1em">' + String(err) + '</pre>'
  );
});
`

// lib/auth.ts - auth helpers showing the canonical module shape:
// import bm + types, export an initFn the entry calls.
const htmlScaffoldAuthTSX = `// lib/auth.ts - auth state + sign-out wiring (logic, no JSX → lib/).
//
// Pattern: each feature module exports an init function that takes
// whatever data it needs and returns whatever the entry needs from it.
// Keeps the entry (app.tsx) tiny and the boundaries clear.

import bm, { type User } from 'bm';

const $ = (sel: string) => document.querySelector(sel) as HTMLElement | null;

export async function initAuth(): Promise<User | null> {
  const me: User | null = await bm.auth.me();
  if (!me) {
    const anon = $('.anon');
    if (anon) anon.hidden = false;
    return null;
  }

  // Reveal the authenticated UI.
  const app = $('.app');     if (app)  app.hidden  = false;
  const who = $('.who');     if (who)  who.hidden  = false;
  const name = $('.who-name');
  if (name) name.textContent = me.first_name || me.email;

  $('[data-action="signout"]')?.addEventListener('click', async () => {
    await bm.auth.signOut();
    location.reload();
  });

  return me;
}

// initAuthPage - every sign-in page (login, signup and the step pages
// verify-mfa, verify-otp, mfa-setup, forgot-password, reset-password) runs
// this. The step pages are plain forms that POST to the framework and work
// without this script: the framework answers with a redirect, back to the
// page with ?error= or ?success=, or on into the app. This shows those
// messages, copies ?next= and ?token= into the form's hidden fields, and
// wires the pages that need script (login, signup, mfa-setup).
export async function initAuthPage() {
  const params = new URLSearchParams(location.search);
  for (const [sel, key] of [['.error', 'error'], ['.success', 'success']]) {
    const el = $(sel);
    const text = params.get(key);
    if (el && text) { el.textContent = text; el.hidden = false; }
  }
  document.querySelectorAll<HTMLInputElement>('input[type="hidden"][name="next"], input[type="hidden"][name="token"]')
    .forEach((input) => { input.value = params.get(input.name) || ''; });
  initLogin();
  initSignup();
  await initMFASetup();
}

// initLogin - wire the login form on login.html: preventDefault + POST
// via the typed SDK; redirect home on success, show the error inline on
// failure. The form keeps method="POST" so that, if this script never
// loads, a native submit still never puts ?email=...&password=... into
// the URL (and the write-time auto-fix has nothing to add to the page).
export function initLogin() {
  const form = document.getElementById('login-form') as HTMLFormElement | null;
  if (!form) return;
  const err = form.querySelector('.error') as HTMLElement | null;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (err) err.hidden = true;
    const fd = new FormData(form);
    try {
      await bm.auth.signIn(String(fd.get('email') || ''), String(fd.get('password') || ''));
      location.href = '/';
    } catch (ex: any) {
      if (err) { err.textContent = ex?.message || 'Sign-in failed'; err.hidden = false; }
    }
  });
  // Passkeys (Face ID, Touch ID, Windows Hello, a phone): shown only where the
  // browser supports them. Users add one while signed in with
  // bm.auth.passkey.register().
  const passkeyBtn = document.getElementById('login-passkey') as HTMLButtonElement | null;
  if (passkeyBtn && bm.auth.passkey.supported()) {
    passkeyBtn.hidden = false;
    passkeyBtn.addEventListener('click', async () => {
      if (err) err.hidden = true;
      try {
        await bm.auth.passkey.signIn();
        location.href = '/';
      } catch (ex: any) {
        if (ex?.name === 'NotAllowedError') return; // the person dismissed the prompt
        if (err) { err.textContent = ex?.message || 'Passkey sign-in failed'; err.hidden = false; }
      }
    });
  }
}

// initSignup - same for signup.html. Object.fromEntries forwards every
// field (first_name, email, password, plus any auth.signup_fields).
export function initSignup() {
  const form = document.getElementById('signup-form') as HTMLFormElement | null;
  if (!form) return;
  const err = form.querySelector('.error') as HTMLElement | null;
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (err) err.hidden = true;
    const fd = new FormData(form);
    try {
      await bm.auth.signUp(Object.fromEntries(fd.entries()) as any);
      location.href = '/';
    } catch (ex: any) {
      if (err) { err.textContent = ex?.message || 'Sign-up failed'; err.hidden = false; }
    }
  });
}

// initMFASetup - mfa-setup.html, the enrollment step for a role listed in
// auth.require_mfa_for_roles. Two kinds of visitor land here:
//   - from a sign-in or sign-up, with a short-lived setup cookie instead of
//     a session: bm.mfa.enroll() needs no password (the cookie is the proof)
//     and bm.mfa.verify(code) turns the authenticator on and signs them in;
//   - already signed in (the rule began to apply to their account, or they
//     turned their authenticator off): the server answers enroll() with 400
//     until it gets the current password, so the page asks for it, calls
//     bm.mfa.enroll(password), and offers sign-out. Once verify succeeds the
//     session they hold works again.
export async function initMFASetup() {
  const root = document.getElementById('mfa-setup');
  const form = document.getElementById('mfa-setup-form') as HTMLFormElement | null;
  if (!root || !form) return;
  const passwordForm = document.getElementById('mfa-setup-password-form') as HTMLFormElement | null;
  const signout = root.querySelector('.mfa-signout') as HTMLElement | null;
  const err = root.querySelector('.error') as HTMLElement | null;
  const fail = (message: string) => { if (err) { err.textContent = message; err.hidden = false; } };

  // start asks the server for a key and shows it, or shows the password form
  // when the server wants the password first.
  const start = async (password?: string) => {
    if (err) err.hidden = true;
    let setup;
    try {
      setup = await bm.mfa.enroll(password);
    } catch (ex: any) {
      if (ex?.status === 400 && !password && passwordForm) {
        passwordForm.hidden = false;
        if (signout) signout.hidden = false;
        return;
      }
      fail(ex?.status === 401 ? 'This sign-in step expired. Log in again to set up two-factor sign-in.' : ex?.message || 'Could not start two-factor setup.');
      return;
    }
    if (passwordForm) passwordForm.hidden = true;
    const secret = root.querySelector('.mfa-secret');
    if (secret) secret.textContent = setup.secret;
    const link = root.querySelector('.mfa-link') as HTMLAnchorElement | null;
    if (link && setup.otpauth_uri) { link.href = setup.otpauth_uri; link.hidden = false; }
    const codes = root.querySelector('.mfa-backup-codes');
    if (codes) codes.textContent = (setup.backup_codes || []).join('\n');
    const key = root.querySelector('.mfa-key') as HTMLElement | null;
    if (key) key.hidden = false;
    form.hidden = false;
  };

  if (passwordForm) {
    passwordForm.addEventListener('submit', async (e) => {
      e.preventDefault();
      const password = String(new FormData(passwordForm).get('password') || '');
      if (!password) { fail('Enter your password.'); return; }
      await start(password);
    });
  }
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    if (err) err.hidden = true;
    try {
      await bm.mfa.verify(String(new FormData(form).get('code') || '').trim());
      location.href = safeNext();
    } catch (ex: any) {
      fail(ex?.message || 'That code did not match. Enter the code your app shows now.');
    }
  });
  root.querySelector('[data-action="signout"]')?.addEventListener('click', async () => {
    try { await bm.auth.signOut(); } catch { /* the session may already have ended */ }
    location.href = '/login';
  });

  await start();
}

// safeNext - the page's ?next= when it is a path on this site, else '/'.
function safeNext(): string {
  const next = new URLSearchParams(location.search).get('next') || '';
  return next.startsWith('/') && !next.startsWith('//') && !next.startsWith('/\\') ? next : '/';
}
`

// views/notes.tsx - the example feature module the scaffold ships. Replace
// or delete when you swap the Note model for your real domain.
// htmlScaffoldComponentsTSX - canonical UI primitives at components/ui.tsx.
// The scaffold's view files (views/notes.tsx, etc.) import from here. Agents
// EXTENDING the app should follow the same pattern: when the same
// `class="..."` string appears twice, extract a primitive HERE rather
// than copying markup across feature files. Drift comes from each
// feature reinventing button/input/card styling slightly differently;
// the fix is structural - one component file, one canonical shape.
const htmlScaffoldComponentsTSX = `// components/ui.tsx - canonical UI primitives.
//
// AGENT RULE: when you'd write the same Tailwind class string twice,
// add it here as a function instead. The third copy of a class="…"
// string is a drift signal - extract on the SECOND use.
//
// All primitives return HTML strings (no React, no JSX). Compose them
// in feature modules via template literals + innerHTML, matching the
// pattern in views/notes.tsx.

const escapeHtml = (s: unknown): string => String(s ?? '').replace(/[&<>"']/g, c => ({
  '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
} as Record<string, string>)[c]);

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger';
export type ButtonSize = 'sm' | 'md';

export function Button(opts: {
  label: string;
  type?: 'submit' | 'button' | 'reset';
  variant?: ButtonVariant;
  size?: ButtonSize;
  /** QA selector hook: rendered as data-testid (see tests/journeys/). */
  testid?: string;
  attrs?: string;
  extraClass?: string;
}): string {
  const variant = {
    primary: 'bg-blue-600 text-white hover:bg-blue-500',
    secondary: 'border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-800',
    ghost: 'hover:bg-zinc-100 dark:hover:bg-zinc-800 text-zinc-600 dark:text-zinc-400',
    danger: 'bg-red-600 text-white hover:bg-red-500',
  }[opts.variant ?? 'primary'];
  const size = opts.size === 'sm' ? 'px-3 py-1.5 text-sm' : 'px-4 py-2';
  const testid = opts.testid ? ` + "`data-testid=\"${escapeHtml(opts.testid)}\"`" + ` : '';
  return ` + "`<button type=\"${opts.type ?? 'button'}\" class=\"rounded-md font-medium ${size} ${variant} ${opts.extraClass ?? ''}\" ${testid} ${opts.attrs ?? ''}>${escapeHtml(opts.label)}</button>`" + `;
}

export function Input(opts: {
  name: string;
  type?: string;
  placeholder?: string;
  value?: string;
  required?: boolean;
  /** QA selector hook: rendered as data-testid (see tests/journeys/). */
  testid?: string;
  attrs?: string;
}): string {
  // ALWAYS set an explicit text + bg + placeholder color paired by light/dark -
  // a bg without a matching text color is the #1 cause of invisible
  // white-on-white inputs. Never ship an input that relies on inherited color.
  const testid = opts.testid ? ` + "`data-testid=\"${escapeHtml(opts.testid)}\"`" + ` : '';
  return ` + "`<input name=\"${opts.name}\" type=\"${opts.type ?? 'text'}\" ${testid} ${opts.required ? 'required' : ''} ${opts.placeholder ? `placeholder=\"${escapeHtml(opts.placeholder)}\"` : ''} ${opts.value !== undefined ? `value=\"${escapeHtml(opts.value)}\"` : ''} class=\"block w-full px-3 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 text-zinc-900 dark:text-zinc-100 placeholder-zinc-400 dark:placeholder-zinc-500 focus:outline-none focus:ring-2 focus:ring-blue-500\" ${opts.attrs ?? ''}>`" + `;
}

export function Field(opts: { label: string; input: string; hint?: string }): string {
  return ` + "`<label class=\"block space-y-1\">\n    <span class=\"text-sm font-medium\">${escapeHtml(opts.label)}</span>\n    ${opts.input}\n    ${opts.hint ? `<span class=\"text-xs text-zinc-500\">${escapeHtml(opts.hint)}</span>` : ''}\n  </label>`" + `;
}

export function Card(opts: { title?: string; body: string; extraClass?: string }): string {
  return ` + "`<section class=\"rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 p-5 ${opts.extraClass ?? ''}\">\n    ${opts.title ? `<h2 class=\"text-base font-semibold mb-3\">${escapeHtml(opts.title)}</h2>` : ''}\n    ${opts.body}\n  </section>`" + `;
}

export type BadgeVariant = 'default' | 'success' | 'warning' | 'danger';

export function Badge(opts: { label: string; variant?: BadgeVariant }): string {
  const cls = {
    default: 'bg-zinc-100 text-zinc-700 dark:bg-zinc-800 dark:text-zinc-300',
    success: 'bg-green-100 text-green-700 dark:bg-green-900/30 dark:text-green-300',
    warning: 'bg-amber-100 text-amber-700 dark:bg-amber-900/30 dark:text-amber-300',
    danger:  'bg-red-100 text-red-700 dark:bg-red-900/30 dark:text-red-300',
  }[opts.variant ?? 'default'];
  return ` + "`<span class=\"inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium ${cls}\">${escapeHtml(opts.label)}</span>`" + `;
}

export function EmptyState(opts: { message: string; cta?: string }): string {
  return ` + "`<div class=\"text-center py-12 text-zinc-500\">\n    <p class=\"text-sm\">${escapeHtml(opts.message)}</p>\n    ${opts.cta ? `<div class=\"mt-4\">${opts.cta}</div>` : ''}\n  </div>`" + `;
}

// Add app-specific primitives below as patterns repeat. Examples:
//
//   export function PriceTag(opts: { cents: number }): string {
//     return ` + "`<span class=\"font-mono tabular-nums\">$${(opts.cents / 100).toFixed(2)}</span>`" + `;
//   }
//
//   export function UserAvatar(opts: { name: string; email: string }): string { ... }
//
// Rule of thumb: any styled element that appears in two feature files
// belongs here. The third instance is wasted work + drift waiting to
// happen.
`

// htmlScaffoldDomTS - keyed list rendering. THE fix for the #1 live-update bug:
// re-rendering with ul.innerHTML = rows.map(...).join(”) rebuilds EVERY row on
// every update, so an SSE refresh (e.g. toggling one item complete) flashes the
// whole list, drops input focus, and re-initialises icons. reconcileList reuses
// unchanged rows and only touches what changed.
const htmlScaffoldDomTS = `// lib/dom.ts - keyed list rendering without the flicker.
//
// Use reconcileList instead of "container.innerHTML = rows.map(...).join('')"
// whenever a list re-renders on live data (bm.live). The innerHTML approach
// rebuilds every row each time, so an SSE refresh flashes the whole list, inputs
// lose focus, and icons re-initialise. reconcileList keeps unchanged rows exactly
// as they are and only adds / removes / replaces what actually changed.

export function reconcileList<T>(
  container: HTMLElement,
  rows: T[],
  idOf: (row: T) => string | number,
  rowHTML: (row: T) => string,
): void {
  const toEl = (html: string): HTMLElement => {
    const t = document.createElement('template');
    t.innerHTML = html.trim();
    return t.content.firstElementChild as HTMLElement;
  };
  const prev = new Map<string, HTMLElement>();
  Array.from(container.children).forEach(el => {
    const k = (el as HTMLElement).dataset.key;
    if (k != null) prev.set(k, el as HTMLElement);
  });
  // Reuse any row whose key + rendered HTML are unchanged (never touched → no flicker).
  const next = rows.map(row => {
    const key = String(idOf(row));
    const html = rowHTML(row).trim();
    const old = prev.get(key);
    if (old && old.dataset.h === html) return old;
    const el = toEl(html);
    el.dataset.key = key;
    el.dataset.h = html;
    return el;
  });
  const keep = new Set(next);
  Array.from(container.children).forEach(el => { if (!keep.has(el as HTMLElement)) el.remove(); });
  next.forEach((node, i) => {
    const cur = container.children[i];
    if (cur !== node) container.insertBefore(node, cur || null);
  });
}
`

const htmlScaffoldNotesTSX = `// views/notes.tsx - example feature module.
//
// Use this as the template for your own features (one file per feature/screen
// under views/):
//   1. Import bm + the row type for your table.
//   2. Import UI primitives from '../components/ui' instead of writing
//      your own Button/Input/Card markup.
//   3. Export an init(me) that wires events + does the first render.
//   4. Use bm.live(table, cb) (or bm.live.scoped for noisy tables) to
//      refresh on remote mutations.

import bm, { type User, type Note } from 'bm';
import { Button } from '../components/ui';
import { reconcileList } from '../lib/dom';

const $ = (sel: string) => document.querySelector(sel) as HTMLElement | null;

function escapeHtml(s: string): string {
  return String(s ?? '').replace(/[&<>"']/g, c => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  } as Record<string, string>)[c]);
}

async function render() {
  const ul = $('#notes') as HTMLUListElement | null;
  const empty = $('.empty');
  if (!ul) return;
  const rows: Note[] = await bm.table('notes').list({ limit: 100 });
  if (empty) empty.hidden = rows.length > 0;
  // reconcileList (lib/dom) re-renders WITHOUT flicker: it reuses unchanged rows
  // and only touches what changed. So when bm.live fires on a mutation (e.g. you
  // toggle one item), the rest of the list stays put - no flash, no lost focus,
  // no re-initialised icons. NEVER do "ul.innerHTML = rows.map(...).join('')" on
  // a live list; that rebuilds every row every time.
  reconcileList(ul, rows, n => n.id, n => ` + "`<li class=\"px-4 py-3 hover:bg-zinc-50 dark:hover:bg-zinc-800/50 flex items-center justify-between gap-3\">\n      <span>${escapeHtml(n.title)}</span>\n      ${Button({ label: 'Delete', variant: 'ghost', size: 'sm', attrs: `data-id=\"${n.id}\" data-action=\"delete-note\" data-testid=\"note-delete-${n.id}\"` })}\n    </li>`" + `);
}

export async function initNotes(_me: User) {
  await render();
  // Live SSE - refreshes the list on every CRUD mutation across all tabs.
  // For high-traffic tables use bm.live.scoped(table, refresh, {debounce})
  // - it debounces and serializes refresh promises per subscription.
  ` + scaffoldLiveScopedNote + `
  bm.live('notes', () => render());

  $('#new-note')?.addEventListener('submit', async (e: Event) => {
    e.preventDefault();
    const form = e.target as HTMLFormElement;
    const title = (new FormData(form).get('title') as string | null) ?? '';
    if (!title.trim()) return;
    await bm.table('notes').create({ title });
    form.reset();
    // SSE will fire bm.live and re-render.
  });

  // Delegated delete handler - uses the data-action attribute the
  // Button() component sets on each row.
  document.addEventListener('click', async (e: Event) => {
    const btn = (e.target as HTMLElement | null)?.closest('[data-action="delete-note"]') as HTMLElement | null;
    if (!btn) return;
    const id = btn.getAttribute('data-id');
    if (!id) return;
    await bm.table('notes').delete(id);
    // SSE fires bm.live and re-renders.
  });
}
`

// htmlScaffoldTSConfig is dropped into the workspace root. The
// 'paths' mapping makes `import 'bm'` resolve to src/bm.d.ts so the
// agent's TypeScript editor sees the live per-app types.
const htmlScaffoldTSConfig = `{
  "compilerOptions": {
    "target": "ES2022",
    "module": "ESNext",
    "moduleResolution": "Bundler",
    "strict": true,
    "noEmit": true,
    "lib": ["ES2022", "DOM", "DOM.Iterable"],
    "jsx": "react-jsx",
    "esModuleInterop": true,
    "skipLibCheck": true,
    "isolatedModules": true,
    "allowImportingTsExtensions": true,
    "paths": {
      "bm": ["./src/bm.d.ts"]
    }
  },
  "include": ["static/**/*.ts", "static/**/*.tsx", "src/bm.d.ts"]
}
`

// The initial src/bm.d.ts of a new workspace. The running app generates the
// real file (every table, every flow, the whole SDK); until the first refresh
// this placeholder declares the calls the starter's own files make, with the
// shapes the runtime answers: update() resolves to {status: 'updated'} and a
// change event carries {table, action}, never the row. scaffoldBMDTSNote is
// the Notes starter's addition; the bare scaffold has no notes table.
const scaffoldBMDTSNote = `export interface Note { id: number; title: string; body: string; user_id: number; created_at: string; updated_at: string; }
`

const scaffoldBMDTSNotesTable = `export function table(name: 'notes'): TableClient<Note>;
`

// htmlScaffoldBMDTSPlaceholder is the starter's src/bm.d.ts (Notes demo);
// bareScaffoldBMDTSPlaceholder is the same file without the demo's table.
const (
	htmlScaffoldBMDTSPlaceholder = scaffoldBMDTSHead + scaffoldBMDTSNote + scaffoldBMDTSCalls + scaffoldBMDTSNotesTable + scaffoldBMDTSTail
	bareScaffoldBMDTSPlaceholder = scaffoldBMDTSHead + scaffoldBMDTSCalls + scaffoldBMDTSTail
)

const scaffoldBMDTSHead = `// PLACEHOLDER - the real per-app types are generated by the running app.
` + scaffoldTypesRefreshNote + `
//
// Until the first refresh this file declares only the SDK calls a new app's
// pages make. The generated file covers every table and flow and the whole SDK.

export interface User { id: number; email: string; first_name?: string | null; last_name?: string | null; role: string; verified: number; }
`

const scaffoldBMDTSCalls = `export interface ApiResult<T = unknown> { ok: boolean; status: number; data: T | null; }
// A change event names the table and the action, never the row: refetch.
export type ChangeEvent =
  | { action: 'insert' | 'update' | 'delete'; table: string }
  | { action: 'refresh'; table: '' };
export interface UpdateReceipt { status: 'updated'; }

export interface TableClient<Row = Record<string, unknown>> {
  list(opts?: { limit?: number; offset?: number; q?: string }): Promise<Row[]>;
  get(id: number | string): Promise<Row>;
  create(body: Partial<Row>): Promise<Row>;
  update(id: number | string, body: Partial<Row>): Promise<UpdateReceipt>;
  delete(id: number | string): Promise<void>;
}

export const api: {
  get<T = any>(path: string): Promise<T>;
  post<T = any>(path: string, body?: unknown): Promise<T>;
  patch<T = any>(path: string, body?: unknown): Promise<T>;
  delete(path: string): Promise<void>;
};
export const auth: {
  me(): Promise<User | null>;
  signIn(identifier: string, password: string): Promise<User | null>;
  signUp(fields: { email: string; password: string; [extraField: string]: unknown }): Promise<User | null>;
  signOut(): Promise<void>;
  refreshMe(): Promise<User | null>;
  passkey: {
    supported(): boolean;
    signIn(): Promise<User | null>;
  };
};
export const mfa: {
  enroll(password?: string): Promise<{ secret: string; otpauth_uri: string; backup_codes: string[] }>;
  verify(code: string): Promise<{ status: 'mfa_enabled'; token?: string; user_id?: number; email?: string }>;
};
export const users: {
  list(opts?: { limit?: number; offset?: number }): Promise<User[]>;
  get(id: number): Promise<User>;
};
`

const scaffoldBMDTSTail = `export function table<R = Record<string, unknown>>(name: string): TableClient<R>;
export function live(table: string, cb: (ev: ChangeEvent) => void): () => void;
export function room(name: string): {
  on(kind: string, fn: (payload: any, from: number | 'server') => void): any;
  send(payload: any): void;
  leave(): void;
};

declare const bm: {
  api: typeof api;
  auth: typeof auth;
  mfa: typeof mfa;
  users: typeof users;
  table: typeof table;
  live: typeof live;
  room: typeof room;
};
export default bm;
`

// htmlScaffoldStylesCSS - v2.7.62+: Tailwind-first scaffold. Tailwind
// is loaded from the framework binary at /_internal/tailwind.js, so
// every utility class works out of the box without a build step.
// This stylesheet exists ONLY as an opt-in for rules Tailwind can't
// express in markup - keep it small, keep it task-specific.
//
// Prior versions of the scaffold shipped ~160 lines of hand-rolled
// design tokens + component CSS here; agents predictably extended
// THAT file instead of using Tailwind for new components, ending up
// with apps that were 70% custom CSS and 30% Tailwind utility classes
// - the worst of both worlds. The new scaffold ships a stub instead,
// with explicit guidance pointing every agent at the utility-class
// path.
const htmlScaffoldStylesCSS = `/* styles.css - opt-in custom styles.

   Tailwind is the primary styling engine - drop utility classes
   directly in your HTML/JSX markup (and in className strings inside
   .tsx files). Look up utility names at tailwindcss.com/docs. Common
   patterns the scaffold already uses:

     Layout      flex, grid, gap-4, space-y-2, mx-auto, max-w-3xl
     Color       bg-zinc-900 dark:bg-zinc-50, text-zinc-100, ring-blue-500
     Type        text-2xl font-semibold tracking-tight
     Borders     rounded-md, border, divide-y
     Spacing     px-3 py-2, p-6, mt-4
     States      hover:bg-blue-500, focus:outline-none focus:ring-2
     Dark mode   prefix with "dark:" - applies inside an element with class "dark"

   Use this file ONLY for things Tailwind can't express in markup -
   keyframe animations, third-party widget overrides, custom font
   declarations, app-wide CSS variables. Don't recreate utility-class
   styles here; the agent that follows you will end up confused about
   which path is canonical.

   Examples of legitimate styles.css content:

     @keyframes pulse-once { 0%{opacity:.4} 100%{opacity:1} }
     .toast-enter { animation: pulse-once .2s ease-out; }

     @font-face { font-family: 'CompanyBrand'; src: url(...); }

   The scaffold leaves this file empty by default. Add what you need;
   don't add what you don't.
*/

/* The HTML "hidden" attribute must beat utility display classes. A node like
   <section class="... flex" hidden> otherwise stays display:flex - the .flex
   utility loads after the UA [hidden]{display:none} rule with equal
   specificity, so it wins and the element never actually hides. That breaks
   the common pattern of toggling the "hidden" attribute to switch between an
   anonymous view and the signed-in app. Keep this rule (or delete it only if
   you never use the hidden attribute alongside a display utility class). */
[hidden] { display: none !important; }
`

// htmlScaffoldHomeJourneyYAML is the scaffold's starter browser journey
// (tests/journeys/home.yaml). Journeys run in a real headless browser via
// browser_batch during `benmore verify`; selectors use the data-testid
// convention the scaffold pages follow.
// htmlScaffoldFaviconSVG is the starter's icon (static/favicon.svg, linked
// from static/partials/head.html). The scaffold shipped none, so the
// browser's own GET /favicon.ico answered 404 and the starter journey
// failed `benmore verify` on a fresh app (Round 2 B10). A neutral shape: the
// framework ships no branding into apps.
const htmlScaffoldFaviconSVG = `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 32 32"><rect width="32" height="32" rx="7" fill="#2563eb"/><path d="M10 11h12M10 16h12M10 21h7" stroke="#fff" stroke-width="2.5" stroke-linecap="round"/></svg>
`

const htmlScaffoldHomeJourneyYAML = scaffoldJourneyHeader + `
name: home
tags: [smoke]
path: /
assertions:
  - {visible: "main"}
  - {horizontal_overflow: false}
`
