//go:build !cli

package main

// HTML scaffold for `benmore new <name> --html`. The default direction
// going forward — vanilla HTML + CSS + JS hitting the framework's REST
// + SSE + WS surface. No bm.js, no React, no esbuild. The agent writes
// whatever frontend it wants; the framework just serves files and APIs.
//
// Layout:
//
//   <name>/
//     app.yaml         — auth + theme + features
//     schema.prisma    — example Note model
//     tsconfig.json    — paths: { "bm": ["./src/bm.d.ts"] }, strict
//     src/bm.d.ts      — AUTO-REGEN per-app TypeScript types
//     static/          — agent's frontend lives here
//       index.html     — home page (auto-injected <script type="importmap">)
//       login.html     — login UI
//       signup.html    — signup UI
//       app.tsx        — entry, compiled on the fly to /static/app.js
//       styles.css     — opt-in custom CSS (Tailwind is primary, served from binary)
//     CLAUDE.md        — agent guide
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
	fmt.Printf("  app.yaml          — auth + theme\n")
	fmt.Printf("  schema.prisma     — example Note model\n")
	fmt.Printf("  static/index.html — home page\n")
	fmt.Printf("  static/login.html — login UI\n")
	fmt.Printf("  static/signup.html — signup UI\n")
	fmt.Printf("  static/app.tsx    — entry (orchestration only)\n")
	fmt.Printf("  static/auth.tsx   — auth state + sign-out\n")
	fmt.Printf("  static/notes.tsx  — example feature module\n")
	fmt.Printf("  static/components.tsx — canonical UI primitives (Button, Input, Field, Card, Badge, EmptyState)\n")
	fmt.Printf("  static/styles.css — opt-in custom CSS (Tailwind is the primary styling engine; served from binary)\n")
	fmt.Printf("  tsconfig.json     — paths { bm: src/bm.d.ts }\n")
	fmt.Printf("  src/bm.d.ts       — per-app TS types (auto-regen on push)\n")
	fmt.Printf("  CLAUDE.md         — agent guide\n\n")
	fmt.Printf("Edit static/*.tsx; the framework auto-compiles to /static/*.js\n")
	fmt.Printf("on every request via embedded esbuild. Add features by\n")
	fmt.Printf("creating new static/<name>.tsx + importing from app.tsx.\n")
}

// WriteHTMLScaffoldFiles writes the HTML+JS starter into `dir`. Shared
// between the CLI scaffold (`benmore new --html`) and the MCP
// `create_app` tool (once it learns about the HTML stack).
func WriteHTMLScaffoldFiles(dir, title string) error {
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
mode: dark

auth:
  identifier: email
  session_duration: "30d"
  signup_fields: "first_name"

features:
  testing: true   # amber banner + feedback widget (turn off when this is no longer a prototype)

frontend:
  stack: html      # TSX in static/*.tsx; framework auto-compiles to /static/*.js
`, title)); err != nil {
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
	// (v2.7.147+), so chrome that's identical across pages — meta, Tailwind,
	// stylesheet — lives in ONE file instead of being copy-pasted into every
	// page. This is the pattern to reach for the moment you have more than one
	// page: add it here, include it everywhere, edit it once.
	if err := write("static/partials/head.html", `<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<!-- Tailwind is the primary styling engine for this scaffold.
     v2.7.62+: ships served from the framework binary at
     /_internal/tailwind.js — no CDN, no build step, every utility
     class works out of the box. Agents: prefer Tailwind utility
     classes for everything. The styles.css below is a thin opt-in
     stub for the rare custom rule Tailwind can't express; almost
     all real styling work belongs in the markup as utility classes. -->
<script src="/_internal/tailwind.js"></script>
<link rel="stylesheet" href="/static/styles.css">
`); err != nil {
		return err
	}

	if err := write("static/index.html", `<!doctype html>
<html lang="en" class="h-full bg-white dark:bg-zinc-950">
<head>
  <!-- Shared chrome (meta, Tailwind, stylesheet) lives in one place.
       Edit static/partials/head.html once; every page picks it up.
       <include> resolves relative to static/ on the HTML stack. -->
  <include src="partials/head.html" />
  <title>`+title+`</title>
</head>
<body class="h-full text-zinc-900 dark:text-zinc-100 antialiased">
  <main class="mx-auto max-w-3xl px-6 py-10" data-route="home">
    <header class="flex items-center justify-between mb-8">
      <h1 class="text-2xl font-semibold tracking-tight">`+title+`</h1>
      <div class="who flex items-center gap-3" hidden>
        <span class="who-name text-sm text-zinc-600 dark:text-zinc-400"></span>
        <button type="button" data-action="signout" class="text-sm px-3 py-1.5 rounded-md border border-zinc-300 dark:border-zinc-700 hover:bg-zinc-100 dark:hover:bg-zinc-800">Sign out</button>
      </div>
    </header>

    <!-- Anonymous view -->
    <section class="anon space-y-2" hidden>
      <p class="text-zinc-600 dark:text-zinc-400">You're not signed in.</p>
      <p class="text-sm">
        <a href="/login.html" class="text-blue-600 dark:text-blue-400 hover:underline">Log in</a>
        <span class="text-zinc-400">&middot;</span>
        <a href="/signup.html" class="text-blue-600 dark:text-blue-400 hover:underline">Sign up</a>
      </p>
    </section>

    <!-- Authenticated view -->
    <section class="app space-y-4" hidden>
      <form id="new-note" class="flex gap-2">
        <input name="title" placeholder="What needs writing down?" autocomplete="off" required
               class="flex-1 px-3 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 focus:outline-none focus:ring-2 focus:ring-blue-500">
        <button type="submit" class="px-4 py-2 rounded-md bg-blue-600 text-white font-medium hover:bg-blue-500">Add</button>
      </form>
      <ul id="notes" class="divide-y divide-zinc-200 dark:divide-zinc-800 rounded-md border border-zinc-200 dark:border-zinc-800"></ul>
      <p class="empty text-sm text-zinc-500" hidden>No notes yet. Add one above.</p>
    </section>
  </main>

  <!-- Resolve the bare 'bm' specifier to the framework's SDK module.
       Agents writing TSX/TS use: import bm from 'bm' -->
  <script type="importmap">{"imports":{"bm":"/_internal/bm.js"}}</script>
  <!-- /static/app.js is compiled on-the-fly from static/app.tsx
       (esbuild Go API; no node, no build step). Edit the .tsx file
       directly; saves auto-refresh. -->
  <script type="module" src="/static/app.js"></script>
</body>
</html>
`); err != nil {
		return err
	}

	if err := write("static/login.html", `<!doctype html>
<html lang="en" class="h-full bg-white dark:bg-zinc-950">
<head>
  <include src="partials/head.html" />
  <title>Log in &middot; `+title+`</title>
</head>
<body class="h-full text-zinc-900 dark:text-zinc-100 antialiased">
  <main class="min-h-full flex items-center justify-center px-6 py-10">
    <form id="login-form" autocomplete="on" class="w-full max-w-sm space-y-4 p-6 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm">
      <h1 class="text-2xl font-semibold tracking-tight">Log in</h1>
      <p class="text-sm text-zinc-600 dark:text-zinc-400">Welcome back to `+title+`.</p>
      <div class="error text-sm text-red-600 dark:text-red-400" hidden></div>
      <label class="block space-y-1">
        <span class="text-sm font-medium">Email</span>
        <input type="email" name="email" required autocomplete="email"
               class="block w-full px-3 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 focus:outline-none focus:ring-2 focus:ring-blue-500">
      </label>
      <label class="block space-y-1">
        <span class="text-sm font-medium">Password</span>
        <input type="password" name="password" required autocomplete="current-password"
               class="block w-full px-3 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 focus:outline-none focus:ring-2 focus:ring-blue-500">
      </label>
      <button type="submit" class="w-full px-4 py-2 rounded-md bg-blue-600 text-white font-medium hover:bg-blue-500">Log in</button>
      <p class="text-sm text-zinc-600 dark:text-zinc-400">No account? <a href="/signup.html" class="text-blue-600 dark:text-blue-400 hover:underline">Sign up</a></p>
    </form>
  </main>
  <!-- Resolve the bare 'bm' specifier to the framework's SDK module.
       Agents writing TSX/TS use: import bm from 'bm' -->
  <script type="importmap">{"imports":{"bm":"/_internal/bm.js"}}</script>
  <!-- /static/app.js is compiled on-the-fly from static/app.tsx
       (esbuild Go API; no node, no build step). Edit the .tsx file
       directly; saves auto-refresh. -->
  <script type="module" src="/static/app.js"></script>
</body>
</html>
`); err != nil {
		return err
	}

	if err := write("static/signup.html", `<!doctype html>
<html lang="en" class="h-full bg-white dark:bg-zinc-950">
<head>
  <include src="partials/head.html" />
  <title>Sign up &middot; `+title+`</title>
</head>
<body class="h-full text-zinc-900 dark:text-zinc-100 antialiased">
  <main class="min-h-full flex items-center justify-center px-6 py-10">
    <form id="signup-form" autocomplete="on" class="w-full max-w-sm space-y-4 p-6 rounded-lg border border-zinc-200 dark:border-zinc-800 bg-white dark:bg-zinc-900 shadow-sm">
      <h1 class="text-2xl font-semibold tracking-tight">Create an account</h1>
      <p class="text-sm text-zinc-600 dark:text-zinc-400">Start using `+title+`.</p>
      <div class="error text-sm text-red-600 dark:text-red-400" hidden></div>
      <label class="block space-y-1">
        <span class="text-sm font-medium">First name</span>
        <input type="text" name="first_name" required autocomplete="given-name"
               class="block w-full px-3 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 focus:outline-none focus:ring-2 focus:ring-blue-500">
      </label>
      <label class="block space-y-1">
        <span class="text-sm font-medium">Email</span>
        <input type="email" name="email" required autocomplete="email"
               class="block w-full px-3 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 focus:outline-none focus:ring-2 focus:ring-blue-500">
      </label>
      <label class="block space-y-1">
        <span class="text-sm font-medium">Password</span>
        <input type="password" name="password" required autocomplete="new-password" minlength="8"
               class="block w-full px-3 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-950 focus:outline-none focus:ring-2 focus:ring-blue-500">
      </label>
      <button type="submit" class="w-full px-4 py-2 rounded-md bg-blue-600 text-white font-medium hover:bg-blue-500">Sign up</button>
      <p class="text-sm text-zinc-600 dark:text-zinc-400">Already have an account? <a href="/login.html" class="text-blue-600 dark:text-blue-400 hover:underline">Log in</a></p>
    </form>
  </main>
  <!-- Resolve the bare 'bm' specifier to the framework's SDK module.
       Agents writing TSX/TS use: import bm from 'bm' -->
  <script type="importmap">{"imports":{"bm":"/_internal/bm.js"}}</script>
  <!-- /static/app.js is compiled on-the-fly from static/app.tsx
       (esbuild Go API; no node, no build step). Edit the .tsx file
       directly; saves auto-refresh. -->
  <script type="module" src="/static/app.js"></script>
</body>
</html>
`); err != nil {
		return err
	}

	// v2.7.21+: TSX-by-default scaffold. v2.7.25+: split into 3 files
	// to model the canonical multi-file pattern. Agents shouldn't ever
	// be forced into a god-file; seeing the split at scaffold time is
	// what teaches them where the seams go.
	//
	//   static/app.tsx    — entry; ~25 lines, just orchestration
	//   static/auth.tsx   — auth state + sign-out wiring
	//   static/notes.tsx  — example feature (the scaffolded `notes` table)
	//
	// esbuild bundles all imports from the entry, so /static/app.js
	// remains a single network request even with multiple source files.
	// The agent adds more features by adding more .tsx files under
	// static/ and importing them from app.tsx.
	if err := write("static/app.tsx", htmlScaffoldAppTSX); err != nil {
		return err
	}
	if err := write("static/auth.tsx", htmlScaffoldAuthTSX); err != nil {
		return err
	}
	if err := write("static/notes.tsx", htmlScaffoldNotesTSX); err != nil {
		return err
	}
	// Canonical UI primitives (v2.7.62+). Ships in every scaffold so
	// agents have something to reach for instead of hand-rolling
	// Button / Input / Card markup in each feature file. Used by
	// notes.tsx already; extend with app-specific primitives here.
	if err := write("static/components.tsx", htmlScaffoldComponentsTSX); err != nil {
		return err
	}

	if err := write("static/styles.css", htmlScaffoldStylesCSS); err != nil {
		return err
	}

	// TypeScript project config — points the `bm` bare specifier at
	// src/bm.d.ts (regenerated on every push). With this in place,
	// `import * as bm from 'bm'` autocompletes in the agent's editor
	// using the per-app schema types.
	if err := write("tsconfig.json", htmlScaffoldTSConfig); err != nil {
		return err
	}

	// Initial bm.d.ts — placeholder pointing at the live endpoint. The
	// real types regenerate when the app rebuilds after changes to the
	// schema. Workspace copy keeps `import 'bm'` resolving locally for
	// the editor even when offline.
	if err := write("src/bm.d.ts", htmlScaffoldBMDTSPlaceholder); err != nil {
		return err
	}

	if err := write("CLAUDE.md", scaffoldClaudeMD(title, name)); err != nil {
		return err
	}

	return nil
}

// v2.7.25+: 3-file scaffold modeling the canonical multi-file split.
// htmlScaffoldAppTSX is the LEAN entry — orchestration only. Real
// feature logic lives in static/auth.tsx + static/notes.tsx. Adding
// a new feature means adding a new .tsx file and importing it here.
const htmlScaffoldAppTSX = `// app.tsx — entry. Orchestration only; feature code lives in sibling .tsx files.
//
// This file is compiled on-the-fly by the framework's embedded esbuild
// (Go API, no Node) into /static/app.js. esbuild bundles every file
// imported from here into one ES module.
//
// Add a new feature by:
//   1. Create static/<feature>.tsx exporting an init function
//   2. Import + call it below
// The SDK's import map ('bm' → /_internal/bm.js) is set in index.html.

import { initAuth, initLogin, initSignup } from './auth.tsx';
import { initNotes } from './notes.tsx';

async function boot() {
  // login.html / signup.html load this same bundle. Wire their form
  // and stop — without this the form does a native GET and leaks
  // ?email=...&password=... into the URL.
  if (document.getElementById('login-form'))  { initLogin();  return; }
  if (document.getElementById('signup-form')) { initSignup(); return; }

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

// auth.tsx — a small example feature module showing the canonical
// shape: import bm + types, export an initFn the entry calls.
const htmlScaffoldAuthTSX = `// auth.tsx — auth state + sign-out wiring.
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

// initLogin — wire the login form on login.html. WITHOUT this, the
// form has no action/method and the browser does a native GET submit,
// dumping ?email=...&password=... into the URL. preventDefault + POST
// via the typed SDK instead; redirect home on success, show the error
// inline on failure.
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
}

// initSignup — same for signup.html. Object.fromEntries forwards every
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
`

// notes.tsx — the example feature module the scaffold ships. Replace
// or delete when you swap the Note model for your real domain.
// htmlScaffoldComponentsTSX — canonical UI primitives. The scaffold's
// other feature files (notes.tsx, etc.) import from here. Agents
// EXTENDING the app should follow the same pattern: when the same
// `class="..."` string appears twice, extract a primitive HERE rather
// than copying markup across feature files. Drift comes from each
// feature reinventing button/input/card styling slightly differently;
// the fix is structural — one component file, one canonical shape.
const htmlScaffoldComponentsTSX = `// components.tsx — canonical UI primitives.
//
// AGENT RULE: when you'd write the same Tailwind class string twice,
// add it here as a function instead. The third copy of a class="…"
// string is a drift signal — extract on the SECOND use.
//
// All primitives return HTML strings (no React, no JSX). Compose them
// in feature modules via template literals + innerHTML, matching the
// pattern in notes.tsx.

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
  return ` + "`<button type=\"${opts.type ?? 'button'}\" class=\"rounded-md font-medium ${size} ${variant} ${opts.extraClass ?? ''}\" ${opts.attrs ?? ''}>${escapeHtml(opts.label)}</button>`" + `;
}

export function Input(opts: {
  name: string;
  type?: string;
  placeholder?: string;
  value?: string;
  required?: boolean;
  attrs?: string;
}): string {
  return ` + "`<input name=\"${opts.name}\" type=\"${opts.type ?? 'text'}\" ${opts.required ? 'required' : ''} ${opts.placeholder ? `placeholder=\"${escapeHtml(opts.placeholder)}\"` : ''} ${opts.value !== undefined ? `value=\"${escapeHtml(opts.value)}\"` : ''} class=\"block w-full px-3 py-2 rounded-md border border-zinc-300 dark:border-zinc-700 bg-white dark:bg-zinc-900 focus:outline-none focus:ring-2 focus:ring-blue-500\" ${opts.attrs ?? ''}>`" + `;
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

const htmlScaffoldNotesTSX = `// notes.tsx — example feature module.
//
// Use this as the template for your own features:
//   1. Import bm + the row type for your table.
//   2. Import UI primitives from './components.tsx' instead of writing
//      your own Button/Input/Card markup.
//   3. Export an init(me) that wires events + does the first render.
//   4. Use bm.live(table, cb) (or bm.live.scoped for noisy tables) to
//      refresh on remote mutations.

import bm, { type User, type Note } from 'bm';
import { Button } from './components.tsx';

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
  if (!rows.length) {
    ul.innerHTML = '';
    if (empty) empty.hidden = false;
    return;
  }
  if (empty) empty.hidden = true;
  // Notice: we reach for Button() from components.tsx rather than
  // hand-rolling button markup here. When you'd write the same
  // class="..." twice across feature files, extract it into
  // components.tsx instead. That's the convention; UI drift is
  // structural debt that compounds fast otherwise.
  ul.innerHTML = rows
    .map(n => ` + "`<li class=\"px-4 py-3 hover:bg-zinc-50 dark:hover:bg-zinc-800/50 flex items-center justify-between gap-3\">\n      <span>${escapeHtml(n.title)}</span>\n      ${Button({ label: 'Delete', variant: 'ghost', size: 'sm', attrs: `data-id=\"${n.id}\" data-action=\"delete-note\"` })}\n    </li>`" + `)
    .join('');
}

export async function initNotes(_me: User) {
  await render();
  // Live SSE — refreshes the list on every CRUD mutation across all tabs.
  // For high-traffic tables use bm.live.scoped(table, refresh, {debounce})
  // — it debounces, dedupes concurrent fetches, and skips work when the
  // tab is hidden.
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

  // Delegated delete handler — uses the data-action attribute the
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
    "baseUrl": ".",
    "paths": {
      "bm": ["./src/bm.d.ts"]
    }
  },
  "include": ["static/**/*.ts", "static/**/*.tsx", "src/bm.d.ts"]
}
`

// htmlScaffoldBMDTSPlaceholder is the initial src/bm.d.ts dropped into
// every new workspace. It's a thin pointer to the live endpoint; the
// real types are regenerated on every push that touches schema.prisma
// or app.yaml. Until that runs, the placeholder gives the agent the
// SDK surface (auth/table/live/room/aggregate/workflow/etc) but no
// per-app types — the placeholder's interfaces are minimal.
const htmlScaffoldBMDTSPlaceholder = `// PLACEHOLDER — the real per-app types are generated by the running app.
// Pull the live types any time from your running server with:
//   curl http://localhost:8080/_internal/bm.d.ts > src/bm.d.ts

// SDK surface (matches /_internal/bm.js). Full per-app types land
// on first push.
export interface User { id: number; email: string; first_name?: string; last_name?: string; role: string; verified: number; }
export interface ApiResult<T = unknown> { ok: boolean; status: number; data: T | null; }
export type ChangeEvent<T = Record<string, unknown>> =
  | { action: 'insert' | 'update'; table: string; id: number; row: T }
  | { action: 'delete'; table: string; id: number }
  | { action: 'refresh'; table: '' };

export interface TableClient<Row = Record<string, unknown>> {
  list(opts?: { limit?: number; offset?: number; q?: string }): Promise<Row[]>;
  get(id: number | string): Promise<Row>;
  create(body: Partial<Row>): Promise<Row>;
  update(id: number | string, body: Partial<Row>): Promise<Row>;
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
  signOut(): Promise<void>;
  refreshMe(): Promise<User | null>;
};
export const users: {
  list(opts?: { limit?: number; offset?: number }): Promise<User[]>;
  get(id: number): Promise<User>;
};
export function table<R = Record<string, unknown>>(name: string): TableClient<R>;
export function live<T = Record<string, unknown>>(table: string, cb: (ev: ChangeEvent<T>) => void): () => void;
export function room(name: string): {
  on(kind: string, fn: (payload: any, from: number) => void): any;
  send(payload: any): void;
  leave(): void;
};

declare const bm: {
  api: typeof api;
  auth: typeof auth;
  users: typeof users;
  table: typeof table;
  live: typeof live;
  room: typeof room;
};
export default bm;
`

// htmlScaffoldStylesCSS — v2.7.62+: Tailwind-first scaffold. Tailwind
// is loaded from the framework binary at /_internal/tailwind.js, so
// every utility class works out of the box without a build step.
// This stylesheet exists ONLY as an opt-in for rules Tailwind can't
// express in markup — keep it small, keep it task-specific.
//
// Prior versions of the scaffold shipped ~160 lines of hand-rolled
// design tokens + component CSS here; agents predictably extended
// THAT file instead of using Tailwind for new components, ending up
// with apps that were 70% custom CSS and 30% Tailwind utility classes
// — the worst of both worlds. The new scaffold ships a stub instead,
// with explicit guidance pointing every agent at the utility-class
// path.
const htmlScaffoldStylesCSS = `/* styles.css — opt-in custom styles.

   Tailwind is the primary styling engine — drop utility classes
   directly in your HTML/JSX markup (and in className strings inside
   .tsx files). Look up utility names at tailwindcss.com/docs. Common
   patterns the scaffold already uses:

     Layout      flex, grid, gap-4, space-y-2, mx-auto, max-w-3xl
     Color       bg-zinc-900 dark:bg-zinc-50, text-zinc-100, ring-blue-500
     Type        text-2xl font-semibold tracking-tight
     Borders     rounded-md, border, divide-y
     Spacing     px-3 py-2, p-6, mt-4
     States      hover:bg-blue-500, focus:outline-none focus:ring-2
     Dark mode   prefix with "dark:" — automatic via prefers-color-scheme

   Use this file ONLY for things Tailwind can't express in markup —
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
   <section class="... flex" hidden> otherwise stays display:flex — the .flex
   utility loads after the UA [hidden]{display:none} rule with equal
   specificity, so it wins and the element never actually hides. That breaks
   the common pattern of toggling the "hidden" attribute to switch between an
   anonymous view and the signed-in app. Keep this rule (or delete it only if
   you never use the hidden attribute alongside a display utility class). */
[hidden] { display: none !important; }
`

