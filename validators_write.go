//go:build !cli

package main

// The write-time feedback loop. When the agent writes any file, every
// validator that can produce actionable feedback runs here BEFORE the
// file lands on disk. The agent then sees the full set of issues in
// the same tool result - no need to deploy, render, watch logs, and
// roll back. The framework teaches the migration on every mistake.
//
// Linter-in-the-loop pattern from Factory.ai: lint passing is a proxy
// for "conforms to architecture". The framework's job here is to
// catch the corpus-vs-DSL collisions instantly, with prescriptive
// migrations baked into each message.
//
// Validators called from write_file + edit_file:
//
//   *.html              page contract (no <!DOCTYPE>, etc.) + form
//                       security + cross-engine antipatterns +
//                       gotmpl leakage (if frontmatter declares it)
//                       + Go html/template parse (for gotmpl pages)
//
//   schema.prisma       ParsePrismaSchema - surface parse errors with
//                       the model name and the offending line
//
//   flows.yaml          LoadFlowsGHA (or legacy parser); reject empty
//                       jobs/triggers; reject step types we don't know
//
//   hooks.yaml          basic shape check
//
//   *.yaml              gets a fallback YAML syntax check so a missing
//                       colon doesn't silently break the app at boot
//
//   app.yaml            validateAppYAML (existing) - unknown top-level
//                       keys, unknown auth.* keys, etc.

import (
	"fmt"
	"html/template"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// ValidateOnWrite is the single entry point for write-time validation.
// Returns the empty string on clean content, or a single string
// (potentially multi-line) listing every issue found, formatted so the
// agent can act on each one without further questions.
//
// Convention: each issue line starts with the validator name in
// brackets so multi-issue messages stay legible. The first line is
// always a one-line summary the agent can echo back to the user.
func ValidateOnWrite(path, content string) string {
	return ValidateOnWriteIn("", path, content)
}

// AutoFixOnWrite applies deterministic, single-canonical-fix transforms
// to the content BEFORE validation runs. The point: for violations
// where there's only one sensible correction (a password form missing
// method=POST, an UPSERT missing WHERE true), don't reject the write -
// silently apply the fix and let the agent ship.
//
// Returns (fixedContent, fixesApplied). The caller writes fixedContent
// and logs/surfaces fixesApplied so the agent knows what happened.
// When no fixes apply, fixedContent == content (same string identity)
// and fixesApplied is nil. The transforms are intentionally conservative:
// only run when the violation pattern matches AND the fix is unambiguous.
func AutoFixOnWrite(path, content string) (string, []string) {
	out := content
	var applied []string
	if n, fixed := autoFixPasswordForms(out); n > 0 {
		out = fixed
		applied = append(applied, fmt.Sprintf("inserted method=\"POST\" on %d password form(s)", n))
	}
	if strings.HasSuffix(strings.ToLower(filepath.Base(path)), ".yaml") {
		if n, fixed := autoFixMissingWhereTrue(out); n > 0 {
			out = fixed
			applied = append(applied, fmt.Sprintf("inserted `WHERE true` before %d ON CONFLICT clause(s)", n))
		}
	}
	return out, applied
}

// autoFixPasswordForms injects method="POST" on any <form> containing
// a <input type="password"> that doesn't already have a method attr.
// Skips :create / :patch directive forms (those auto-POST via HTMX).
func autoFixPasswordForms(content string) (int, string) {
	count := 0
	out := formBlockRe.ReplaceAllStringFunc(content, func(block string) string {
		m := formBlockRe.FindStringSubmatch(block)
		if len(m) < 3 {
			return block
		}
		attrs, body := m[1], m[2]
		if !passwordInputRe.MatchString(body) {
			return block
		}
		if strings.Contains(attrs, ":create=") || strings.Contains(attrs, ":patch=") {
			return block
		}
		if mm := formMethodAttrRe.FindStringSubmatch(attrs); len(mm) >= 2 && strings.EqualFold(mm[1], "POST") {
			return block
		}
		// Insert method="POST" right after the opening <form tag.
		count++
		// `<form` is 5 chars; preserve the rest of the attrs as-is.
		idx := strings.Index(block, "<form")
		if idx < 0 {
			return block
		}
		return block[:idx+5] + ` method="POST"` + block[idx+5:]
	})
	return count, out
}

// autoFixMissingWhereTrue inserts `WHERE true` between FROM…<SELECT…>
// and ON CONFLICT for SQLite UPSERTs that otherwise fail with
// `near "DO": syntax error`. Conservative: only operates on
// `INSERT INTO … SELECT … FROM … ON CONFLICT …` shapes.
func autoFixMissingWhereTrue(content string) (int, string) {
	// Match a SELECT-clause INSERT followed by FROM … ON CONFLICT
	// where no WHERE clause appears between FROM and ON CONFLICT.
	re := regexp.MustCompile(`(?is)(INSERT\s+INTO\s+\w+[^;]*?SELECT\b[^;]*?FROM\s+[^;]*?)(\s+ON\s+CONFLICT\b)`)
	count := 0
	out := re.ReplaceAllStringFunc(content, func(m string) string {
		parts := re.FindStringSubmatch(m)
		if len(parts) < 3 {
			return m
		}
		head, tail := parts[1], parts[2]
		upperHead := strings.ToUpper(head)
		if strings.Contains(upperHead, "WHERE TRUE") || strings.Contains(upperHead, "WHERE 1") || strings.Contains(upperHead, " WHERE ") {
			return m
		}
		count++
		return head + "\nWHERE true" + tail
	})
	return count, out
}

// ValidateOnWriteIn is the appDir-aware variant. The MCP write_file
// path passes the absolute app directory so partial-loading + future
// cross-file checks resolve correctly even when the file's path is
// relative. The CLI's RunCompleteCheck passes the app dir likewise.
func ValidateOnWriteIn(appDir, path, content string) string {
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))

	// Path-based hard rejects. These fire BEFORE any content inspection
	// because the file's existence itself is the violation - there's
	// no "right" content for a package.json in a Benmore app.
	if msg := validateForbiddenPath(path); msg != "" {
		return msg
	}

	var issues []string

	// Hardcoded-credential gate (any file type): a committed secret leaks into
	// per-app git history. High-confidence shapes only, so a normal push is
	// never blocked by a false positive.
	if msg := validateNoCommittedSecrets(path, content); msg != "" {
		issues = append(issues, msg)
	}

	// React+TS source files (src/*.tsx, *.jsx, *.ts, *.js) get the SPA
	// antipattern sweep. Same detectFrameworkAntipatterns dispatcher
	// the .html branch uses, so cross-file antipatterns (CDN imports,
	// ReactDOM.createRoot, etc.) surface in the same shape.
	if isSPASourceFile(path) {
		if msg := detectFrameworkAntipatterns(path, content); msg != "" {
			issues = append(issues, msg)
		}
	}

	switch {
	case ext == ".html":
		if msg := validatePageContract(path, content); msg != "" {
			issues = append(issues, msg)
		}
		// gotmpl-specific: compile the body with html/template to
		// catch syntax errors before render. Strip frontmatter first
		// so YAML doesn't confuse the parser.
		if msg := validateGotmplParseIn(appDir, path, content); msg != "" {
			issues = append(issues, msg)
		}
		// engine-mode mixup: raw pages that contain {{ template syntax
		// or gotmpl pages that contain SPA-only constructs. Both
		// silently fail to render the way the agent intended.
		if msg := validateEngineMixup(path, content); msg != "" {
			issues = append(issues, msg)
		}
		// <video autoplay> without muted = the iOS / Chrome autoplay
		// block. Black screen until the user finds the hidden play
		// button on the element. Surfaces in livestream apps the agent writes.
		if msg := validateVideoAutoplay(path, content); msg != "" {
			issues = append(issues, msg)
		}

	case base == "schema.prisma":
		if msg := validateSchemaPrisma(content); msg != "" {
			issues = append(issues, msg)
		}

	case base == "flows.yaml" || isFlowsSubdirFile(path):
		// flows.yaml in the app root OR any *.yaml under flows/ -
		// agents commonly split flows across multiple files (one flow
		// per file under flows/) and those need the same validation.
		if msg := validateFlowsYAML(content); msg != "" {
			issues = append(issues, msg)
		}
		// Auto-CRUD route collision is a write-time HARD ERROR (not
		// a post-write warning) because shipping it crashes the app
		// at boot - http.ServeMux.HandleFunc panics on duplicate
		// registration, the per-app process dies, systemd restarts,
		// and the agent sees "connection refused" with no clue why.
		// The runtime now recovers the panic too (see RegisterFlows
		// in flows.go) but catching at write time gives the agent the
		// prescriptive fix immediately.
		if appDir != "" {
			tables := loadSchemaTableNames(appDir)
			if len(tables) > 0 {
				if msg := detectFlowCRUDConflictsInContent(content, tables); msg != "" {
					issues = append(issues, msg)
				}
			}
		}

	case base == "hooks.yaml":
		if msg := validateHooksYAML(content); msg != "" {
			issues = append(issues, msg)
		}

	case base == "app.yaml":
		if msg := validateAppYAML(content); msg != "" {
			issues = append(issues, msg)
		}

	case base == "encrypted.yaml":
		if msg := validateEncryptedYAML(content); msg != "" {
			issues = append(issues, msg)
		}

	case ext == ".yaml" || ext == ".yml":
		if msg := validateYAMLSyntax(content); msg != "" {
			issues = append(issues, fmt.Sprintf("yaml syntax in %s: %s", path, msg))
		}

	case base == "tsconfig.json":
		if msg := validateTSConfig(content); msg != "" {
			issues = append(issues, msg)
		}
	}

	if len(issues) == 0 {
		return ""
	}
	// Append a recovery footer: agents that hit a rejection often
	// fall back to Edit instead of re-Writing the corrected content,
	// which leaves the file partially-old (the rest of the intended
	// rewrite never lands). The fix is to re-Write with the correction.
	body := strings.Join(issues, "\n\n---\n\n")
	return body + "\n\n" + writeRejectionFooter
}

// committedSecretRes are high-confidence credential shapes (specific provider
// prefix + entropy length) so the write-time gate can reject a literal secret
// without false-positiving on ordinary code. Publishable keys (pk_*) are
// intentionally NOT matched - they're safe to ship. An `${{ env.X }}` reference
// never matches (it carries no literal key), so the correct pattern is allowed.
var committedSecretRes = []struct {
	name string
	re   *regexp.Regexp
}{
	{"Stripe secret/restricted key", regexp.MustCompile(`(?i)\b[rs]k_(live|test)_[0-9a-zA-Z]{20,}`)},
	{"AWS access key id", regexp.MustCompile(`\bAKIA[0-9A-Z]{16}\b`)},
	{"GitHub token", regexp.MustCompile(`\bgh[pousr]_[0-9A-Za-z]{36,}`)},
	{"Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_\-]{35}\b`)},
	{"Slack token", regexp.MustCompile(`\bxox[baprs]-[0-9A-Za-z-]{12,}`)},
	{"Resend API key", regexp.MustCompile(`\bre_[0-9A-Za-z]{30,}\b`)},
	// Anthropic: sk-ant-api03-... (the `ant-<kind><nn>-` infix gates the hyphenated tail).
	{"Anthropic API key", regexp.MustCompile(`\bsk-ant-(api|admin)[0-9]{2}-[0-9A-Za-z_\-]{20,}`)},
	// OpenAI: sk-proj-<...> OR classic sk-<32+ base62, NO hyphens> - so kebab-case CSS
	// classes like `sk-btn-primary-rounded-lg` (hyphens in the tail) never match.
	{"OpenAI API key", regexp.MustCompile(`\bsk-(proj-[0-9A-Za-z_\-]{20,}|[0-9A-Za-z]{32,})\b`)},
	{"Private key block", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----`)},
}

// validateNoCommittedSecrets rejects a write whose content embeds a literal
// credential, pointing the author at `benmore env`. Returns "" when clean.
func validateNoCommittedSecrets(path, content string) string {
	for _, p := range committedSecretRes {
		m := p.re.FindString(content)
		if m == "" {
			continue
		}
		// Redact: keep just enough of the prefix to be recognizable.
		red := m
		if len(red) > 10 {
			red = red[:8] + "…"
		}
		return fmt.Sprintf("[secrets] a %s appears to be hardcoded in %s (matched `%s`). Committed secrets leak into the per-app git history. Move it out: `benmore env <app> set KEY=VALUE` and reference it as ${{ env.KEY }} (flows/hooks) - never a literal key in a pushed file.",
			p.name, filepath.Base(path), red)
	}
	return ""
}

// writeRejectionFooter is appended to every validator rejection. Tells
// the agent how to recover correctly. Past sessions showed agents
// downgrading to Edit on rejection, which only mutates the targeted
// block - the rest of the intended rewrite never lands and the file
// stays partially-old.
const writeRejectionFooter = "Recovery: re-Write the entire file with the correction above. Do NOT fall back to Edit - Edit only modifies the block you reference, leaving the rest of the file at its pre-rejection content (often the scaffold default). The Write tool is idempotent; re-running with the fix is the right path."

// validateForbiddenPath rejects file paths that don't belong in a
// Benmore app. The framework is no-npm by design - package.json,
// node_modules, package-lock.json, etc. signal the agent has reverted
// to the standard Node toolchain and is about to fight the build.
// types/bm.d.ts is overwritten by the framework on every boot, so
// hand-editing it is silently undone - surface that as a warning.
// videoTagRe matches an opening <video ...> tag and captures the
// attributes. We scan for autoplay-without-muted, the canonical
// browser-autoplay-block footgun introduced when bm.broadcast.subscribe
// shipped (v2.7.29). RE2 has no negative lookahead, so we capture
// the attr string and inspect it directly.
var videoTagRe = regexp.MustCompile(`(?i)<video\b([^>]*)>`)

// validateVideoAutoplay rejects `<video autoplay>` tags missing
// `muted`. Browsers refuse to autoplay video-with-audio until the
// user has interacted with the origin, so the viewer sees a black
// element until they tap. Always start muted + surface a "Tap to
// unmute" overlay.
//
// Every agent building a livestream/viewer page hits this; catching it
// at write time is much cheaper than 'works in dev, breaks on iPhone'.
func validateVideoAutoplay(path, content string) string {
	matches := videoTagRe.FindAllStringSubmatch(content, -1)
	if len(matches) == 0 {
		return ""
	}
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		attrs := strings.ToLower(m[1])
		if !strings.Contains(attrs, "autoplay") {
			continue
		}
		// `muted` can appear as bare attr (`muted`) or boolean (`muted=""`,
		// `muted="muted"`, `muted='true'`). Word boundary check is enough.
		if regexp.MustCompile(`\bmuted\b`).MatchString(attrs) {
			continue
		}
		return "antipattern [video-autoplay-no-muted] in " + path + ": `<video autoplay>` without `muted` will be blocked by every modern browser. The viewer sees a black video element until they find the native play button - exactly the symptom 'video doesn't play on iPhone Safari'.\n\nFix:\n\n  <video autoplay playsinline muted></video>\n\nThen surface a 'Tap to unmute' overlay that flips muted off on user interaction:\n\n  const video = document.querySelector('video');\n  const unmute = document.querySelector('.tap-to-unmute');\n  video.muted = true;                       // before assigning srcObject\n  video.srcObject = sub.stream;\n  unmute.onclick = async () => {\n    video.muted = false;\n    try { await video.play(); } catch {}\n    unmute.hidden = true;\n  };\n\nThis is non-negotiable for any livestream / video-call UI on iOS. See api({at:'webrtc'}) → autoplay gotcha."
	}
	return ""
}

func validateForbiddenPath(path string) string {
	clean := filepath.ToSlash(strings.TrimLeft(path, "/"))
	base := strings.ToLower(filepath.Base(clean))

	// Hard rejects - these files actively break the framework's build.
	switch base {
	case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb":
		return "forbidden path: " + path + " doesn't belong in a Benmore app. There's no npm step - React, ReactDOM, Lucide, and bm.js are embedded in the framework binary and resolved by the compiler's globals plugin at build. If you wanted to add a dependency: imports of 'react', 'react-dom', 'lucide' / 'lucide-react', 'bm', 'bm/ui' all just work without any package.json. For anything else, write a flow in flows.yaml (calls run server-side) or copy the source into src/ and import it relatively."
	case ".npmrc", ".yarnrc", ".pnpmrc":
		return "forbidden path: " + path + " - Benmore has no npm step. Drop the file."
	case "webpack.config.js", "vite.config.js", "vite.config.ts", "rollup.config.js", "esbuild.config.js":
		return "forbidden path: " + path + " - Benmore runs esbuild internally with the right config for /static/<entry>.<hash>.js bundles. No custom build config is needed; don't try to override it."
	}
	if clean == "node_modules" || strings.HasPrefix(clean, "node_modules/") || strings.Contains(clean, "/node_modules/") {
		return "forbidden path: " + path + " - Benmore has no node_modules. Imports of 'react', 'react-dom', 'lucide', 'bm', 'bm/ui' resolve to embedded window globals at build time. Don't try to add packages this way."
	}
	if strings.HasPrefix(clean, "dist/") || strings.HasPrefix(clean, "build/") {
		return "forbidden path: " + path + " - Benmore emits content-hashed bundles into static/ automatically (e.g. static/app.<hash>.js). You don't write build artifacts by hand."
	}
	// Soft warnings - file is allowed to exist but agent's edit is futile.
	if clean == "types/bm.d.ts" {
		return "types/bm.d.ts is auto-overwritten on every `benmore dev` / `benmore serve` boot from the framework's embedded `bm.d.ts` source. Hand-edits are silently reverted. If you want different types: the d.ts the framework ships covers every bm.* hook and bm/ui component. If something's missing, ask for it in the framework, don't patch it locally."
	}
	return ""
}

// isSPASourceFile returns true if the path is a React/TS bundle entry
// or imported source file. Anything under src/ with a JS/TS/JSX/TSX
// extension qualifies - that's the surface esbuild compiles.
func isSPASourceFile(path string) bool {
	clean := filepath.ToSlash(path)
	if !strings.HasPrefix(clean, "src/") && !strings.Contains(clean, "/src/") {
		return false
	}
	ext := strings.ToLower(filepath.Ext(clean))
	return ext == ".tsx" || ext == ".jsx" || ext == ".ts" || ext == ".js"
}

// validateTSConfig surfaces tsconfig.json edits that break the
// framework's esbuild contract. The compiler expects React.createElement
// as the JSX factory (NOT the new automatic runtime, which would try
// to import 'react/jsx-runtime' from a module the globals plugin
// doesn't know about). Catch the most common drift.
func validateTSConfig(content string) string {
	if strings.TrimSpace(content) == "" {
		return ""
	}
	// v2.7.21+: the framework embeds esbuild and handles JSX natively.
	// `"jsx": "react-jsx"` (the modern automatic runtime) is now the
	// correct setting and the scaffold writes it. The old "use the
	// classic runtime with React.createElement" check fired against the
	// new scaffold's own tsconfig - removed.
	if strings.Contains(content, `"noEmit": false`) {
		return "tsconfig.json: `\"noEmit\": false` is wrong for Benmore. esbuild - not tsc - produces the output bundle. tsc is editor-only here; set `\"noEmit\": true`."
	}
	return ""
}

// validateGotmplParse is the legacy entry point - callers that don't
// know the app directory get partial loading via path heuristics.
// Prefer validateGotmplParseIn.
func validateGotmplParse(path, content string) string {
	return validateGotmplParseIn("", path, content)
}

// validateEngineMixup catches the most common engine-mode confusion:
// agents put mustache `{{var}}` syntax inside an `engine: raw` page
// expecting it to render server-side, but engine: raw means "ship the
// HTML untouched and let React mount into #root" - template tags are
// emitted as literal text. Similarly, putting JSX-only constructs
// (<script type="module" src="/static/app...">) into an engine: gotmpl
// page can produce confusing render-order bugs.
func validateEngineMixup(path, content string) string {
	fm, body, err := ExtractFrontmatter(content)
	if err != nil || fm == nil {
		return ""
	}
	engine := strings.ToLower(strings.TrimSpace(fm.Engine))
	// Strip the obvious framework-injected meta tags that DO use
	// mustache (e.g. <meta name="csrf-token" content="{{csrf}}">):
	// those are interpreted at injection time, not by the page engine.
	// Same with src/app.tsx JSX which lives in TSX, not in HTML.
	hasMustache := regexp.MustCompile(`\{\{[a-zA-Z_][a-zA-Z0-9_.]*\}\}`).MatchString(body)
	hasFrameworkMustache := strings.Contains(body, "{{csrf}}") || strings.Contains(body, "{{user_email}}")
	if engine == "raw" && hasMustache && !hasFrameworkMustache {
		return fmt.Sprintf(
			"%s: declares `engine: raw` but contains mustache `{{var}}` syntax. Raw pages do NOT process mustache - the template tags will render literally as text. Either:\n  (a) move dynamic data into src/*.tsx and use bm.useTable() / bm.useRecord() to fetch it client-side (the React idiom), or\n  (b) change frontmatter to `engine: gotmpl` if you need server-rendered HTML (typical for marketing/SEO pages, not for app UI).",
			path)
	}
	return ""
}

// validateGotmplParseIn runs the gotmpl body through html/template's
// parser to catch unbalanced {{ }}, unknown function names, wrong
// argument shapes, etc. before render time. Only applies if the file
// declared engine: gotmpl in frontmatter.
//
// Uses the SAME FuncMap shape the runtime registers (gotmplHelpers)
// so html/template's argument-arity checks match what'll actually
// run. We pass nil for app and ctx - none of the helpers dereference
// those at PARSE time (Parse only inspects signatures, not bodies),
// so the nils never panic. They would at execute time, which is why
// we never call Execute here.
func validateGotmplParseIn(appDir, path, content string) string {
	fm, body, err := ExtractFrontmatter(content)
	if err != nil {
		return fmt.Sprintf("frontmatter yaml in %s: %s\n\nFix the YAML at the top of the file (between the `---` fences). Common mistakes: missing `:`, indentation not in spaces, special characters in unquoted strings.", path, err)
	}
	if fm == nil || strings.ToLower(strings.TrimSpace(fm.Engine)) != "gotmpl" {
		return ""
	}
	tmpl := template.New(path).Funcs(gotmplHelpers(nil, nil)).Option("missingkey=zero")
	// Register partials/*.html so `{{template "name" .}}` references
	// resolve at parse + execute time. Without this, every page that
	// uses a partial trips a "no such template" false positive.
	// Caller's appDir takes precedence; fall back to the path-based
	// heuristic for older callers that don't pass an app dir.
	resolved := appDir
	if resolved == "" {
		resolved = guessAppDirForPath(path)
	}
	if resolved != "" {
		registerPartialsForValidation(tmpl, resolved)
	}
	parsed, err := tmpl.Parse(body)
	if err != nil {
		return formatGotmplError(path, err)
	}
	// Stub-execute against nil so wrong-arity and helper errors
	// (which html/template only surfaces at execute, not at parse)
	// also bubble up at write time. The "missingkey=zero" option
	// ensures `.notes` and friends silently resolve to the zero value
	// - those are data-dependent, not template-intrinsic, so they
	// shouldn't be false-positive errors here.
	if err := parsed.Execute(io.Discard, nil); err != nil {
		// Denylist: errors that depend on real runtime data, NOT on
		// the template itself. These are false positives at write
		// time because the runtime will supply real data when the
		// page actually renders.
		em := err.Error()
		dataDependent := []string{
			"can't evaluate field",
			"nil pointer evaluating",
			"invalid value; expected",
			"index out of range",
			"is not a method",
			"untyped nil",         // {{index .x 0}} when .x is nil
			"error calling index", // related - happens when index target is nil
			"error calling len",   // {{len .x}} when .x is nil
		}
		for _, pat := range dataDependent {
			if strings.Contains(em, pat) {
				return ""
			}
		}
		return formatGotmplError(path, err)
	}
	return ""
}

// guessAppDirForPath returns the directory containing the file
// being validated, IF it's an absolute path on disk. The MCP
// write_file path passes relative paths (the dir is implicit in
// the app context); for those we can't load partials and just
// accept the false-positive risk for partial-using pages. The
// CLI's RunCompleteCheck passes paths relative to the app dir
// AND has the app dir in cwd, so we resolve relative-to-cwd.
func guessAppDirForPath(path string) string {
	if filepath.IsAbs(path) {
		return filepath.Dir(path)
	}
	// Walk up from the file's directory looking for an app marker
	// (app.yaml). Bounded depth so we don't escape the workspace.
	dir := filepath.Dir(path)
	if dir == "" || dir == "." {
		dir = "."
	}
	for i := 0; i < 4; i++ {
		if _, err := os.Stat(filepath.Join(dir, "app.yaml")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	return ""
}

// registerPartialsForValidation reads partials/*.html and registers
// each as a named template under the parent. Best-effort: partials
// that fail to parse are skipped silently (their own validator pass
// will surface the error when that file is checked individually).
func registerPartialsForValidation(parent *template.Template, appDir string) {
	partialsDir := filepath.Join(appDir, "partials")
	entries, err := os.ReadDir(partialsDir)
	if err != nil {
		return
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".html") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(partialsDir, e.Name()))
		if err != nil {
			continue
		}
		name := strings.TrimSuffix(e.Name(), ".html")
		// Strip frontmatter from partials too - they may have it.
		_, body, _ := ExtractFrontmatter(string(data))
		_, _ = parent.New(name).Parse(body)
	}
}

// formatGotmplError wraps a template error with the migration cheat
// sheet so the message teaches the corpus mapping every time.
func formatGotmplError(path string, err error) string {
	msg := strings.TrimPrefix(err.Error(), fmt.Sprintf("template: %s:", path))
	msg = strings.TrimSpace(msg)
	return fmt.Sprintf(
		"gotmpl parse error in %s: %s\n\n"+
			"This is Go html/template syntax. Common fixes:\n"+
			"  - Iteration: `{{range .items}}<li>{{.name}}</li>{{else}}<p>none</p>{{end}}` - fields use a leading dot, empty-state in `{{else}}`.\n"+
			"  - Conditional: `{{if eq .x \"y\"}}yes{{else}}no{{end}}` - use `eq`/`ne`/`gt`/`lt`/`ge`/`le`, not `=`. Chained: `{{if ...}}…{{else if ...}}…{{else}}…{{end}}` is valid.\n"+
			"  - Every `{{range}}`, `{{if}}`, `{{with}}` must close with `{{end}}`.\n"+
			"  - Framework helpers: `{{csrf}}`, `{{env \"K\"}}`, `{{t \"key\"}}`, `{{dict \"k\" v}}`.\n"+
			"  - Sprig helpers (full library available, ~200 funcs): `{{add a b}}`, `{{sub a b}}`, `{{mul a b}}`, `{{div a b}}`, `{{mod a b}}`, `{{min}}`, `{{max}}`, `{{upper}}`, `{{lower}}`, `{{title}}`, `{{trim}}`, `{{replace old new s}}`, `{{default fallback value}}`, `{{join sep list}}`, `{{date \"2006-01-02\" .Time}}`, `{{now}}`, `{{len .x}}`, `{{first .xs}}`, `{{last .xs}}`, plus regex/crypto/encoding. Sprig docs: https://masterminds.github.io/sprig/\n"+
			"  - Field access uses `.field` (with the dot), not `field`.",
		path, msg)
}

// validateSchemaPrisma runs the parser and surfaces every error in
// one shot. Parse errors include the model name and offending line,
// so the agent can target the fix precisely.
func validateSchemaPrisma(content string) string {
	if strings.TrimSpace(content) == "" {
		return "schema.prisma is empty. Declare at least one `model X { id Int @id @default(autoincrement()) ... }` block."
	}
	if _, err := ParsePrismaSchema(content); err != nil {
		return fmt.Sprintf(
			"schema.prisma parse error: %s\n\n"+
				"Reference shape (do NOT declare `model User` - that's framework-reserved):\n"+
				"  model Note {\n"+
				"    id        Int      @id @default(autoincrement())\n"+
				"    title     String\n"+
				"    body      String   @default(\"\")\n"+
				"    userId    Int      @map(\"user_id\")\n"+
				"    createdAt DateTime @default(now()) @map(\"created_at\")\n"+
				"    @@index([userId, createdAt])\n"+
				"  }\n\n"+
				"Scalar types: Int, BigInt, String, Boolean, Float, DateTime, Bytes.\n"+
				"Use `?` for nullable, `[]` for reverse list relations.\n"+
				"For user_id: just `userId Int @map(\"user_id\")` - NO `@relation` (the framework manages users in `_benmore_users` and auto-injects user_id from the session).\n"+
				"FK shape between YOUR tables: declare `model Account { ... }`, then on the child `ownerId Int` + `owner Account @relation(fields: [ownerId], references: [id])`.",
			err)
	}
	return ""
}

// validateFlowsYAML accepts either the GHA shape (preferred) or the
// legacy line-shaped format. Empty content is OK (the file is
// optional). A file that parses as YAML but matches NEITHER shape is
// rejected with concrete next steps.
func validateFlowsYAML(content string) string {
	if strings.TrimSpace(content) == "" {
		return ""
	}
	// Generic YAML syntax check first - guarantees that "shape
	// detection" below doesn't silently accept malformed YAML.
	var probe any
	if err := yaml.Unmarshal([]byte(content), &probe); err != nil {
		return fmt.Sprintf(
			"flows.yaml YAML syntax: %s\n\n"+
				"Recommended shape (GitHub Actions style):\n"+
				"  on:\n"+
				"    request: { method: POST, path: /api/foo, auth: required }\n"+
				"  jobs:\n"+
				"    name:\n"+
				"      steps:\n"+
				"        - id: lookup\n"+
				"          query: SELECT * FROM foo WHERE id = :id\n"+
				"        - run: respond\n"+
				"          with: { status: 200, body: { ok: true } }",
			err)
	}
	// Probe into the GHA-shaped struct. The file is well-formed GHA when
	// `on:` and `jobs:` are TOP-LEVEL keys (not nested under a flow
	// name). Anything else gets a specific, fixable error.
	var ghaFile FlowFileGHA
	_ = yaml.Unmarshal([]byte(content), &ghaFile)
	if ghaFile.Jobs != nil && (ghaFile.On.Request != nil || ghaFile.On.Schedule != nil || ghaFile.On.Event != nil) {
		// First, catch the worst silent failure: GHA envelope with
		// legacy step shorthand (`- sql: ...`, `- respond: ...`). The
		// struct unmarshal accepts these by dropping the unknown keys,
		// so every step becomes a no-op without complaint.
		if msg := detectLegacyShorthandInGHASteps(content); msg != "" {
			return msg
		}
		if ghaFile.On.Request != nil {
			if msg := detectReservedPath(ghaFile.On.Request.Path); msg != "" {
				return msg
			}
			if msg := validateFlowInputs(ghaFile.On.Request.Inputs); msg != "" {
				return msg
			}
		}
		return validateGHAFlowsContents(ghaFile)
	}
	// Not valid GHA at the file level. Figure out what the agent
	// actually wrote and steer them back to GHA shape with a concrete
	// rewrite - every wrong shape goes through here and the response is
	// the single source of truth for "what does correct look like".
	return diagnoseFlowsShape(content)
}

// flowInputTypes is the control vocabulary an on.request.inputs: block
// may use - shared with the schema descriptor's control set.
var flowInputTypes = map[string]bool{
	"text": true, "textarea": true, "number": true, "bool": true,
	"date": true, "enum": true, "email": true,
}

// validateFlowInputs checks the optional on.request.inputs: block.
// Inputs are declarative (the runtime ignores them - params bind
// regardless), but a bad type or a misplaced values: list silently
// produces a wrong FlowForm, so catch it at write time.
func validateFlowInputs(inputs map[string]FlowInput) string {
	for name, in := range inputs {
		if in.Type == "" {
			return fmt.Sprintf("flows.yaml: input %q is missing a `type:`. Use one of: text, textarea, number, bool, date, enum, email.", name)
		}
		if !flowInputTypes[in.Type] {
			return fmt.Sprintf("flows.yaml: input %q has unknown type %q. Use one of: text, textarea, number, bool, date, enum, email.", name, in.Type)
		}
		if in.Type == "enum" && len(in.Values) == 0 {
			return fmt.Sprintf("flows.yaml: enum input %q needs a non-empty `values:` list.", name)
		}
		if in.Type != "enum" && len(in.Values) > 0 {
			return fmt.Sprintf("flows.yaml: input %q sets `values:` but its type is %q - `values:` only applies to `type: enum`.", name, in.Type)
		}
	}
	return ""
}

// diagnoseFlowsShape inspects a flows.yaml that didn't match the GHA
// shape and emits the most specific, fix-now error possible. The two
// patterns we catch by name (because they cost real time in live
// builds):
//
//  1. GHA-nested-under-flow-name - the agent put `on:` / `jobs:` inside
//     a `flow_name:` wrapper. yaml.v3 happily unmarshals that, the
//     top-level GHA probe sees nil `On.Request` and nil `Jobs`, and we
//     fall here. Without this branch the agent gets a useless "doesn't
//     match either shape" with no clue what they did wrong.
//
//  2. Pure legacy form (`flow_name:` + `trigger:` + `steps:`). Banned
//     for new writes - no apps on the platform use it, the runtime
//     parser stays for any historical files but the write gate ensures
//     all new flows are GHA.
//
// Anything else falls through to a generic "doesn't match" message that
// still shows the canonical shape.
func diagnoseFlowsShape(content string) string {
	// Probe as `map[string]any` so we can introspect what keys live
	// where without committing to either struct.
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(content), &raw); err != nil || len(raw) == 0 {
		return canonicalGHAShapeMessage("flows.yaml is empty or unparseable as a YAML map.")
	}

	// 1. GHA-nested-under-flow-name: every top-level value is a map
	//    that itself contains `on:` and/or `jobs:`.
	for name, v := range raw {
		m, ok := v.(map[string]any)
		if !ok {
			continue
		}
		_, hasOn := m["on"]
		_, hasJobs := m["jobs"]
		if hasOn || hasJobs {
			return fmt.Sprintf(
				"flows.yaml: `on:` and `jobs:` are nested under %q. In Benmore's GHA shape they're FILE-LEVEL keys - there is no flow-name wrapper. Move them to the top of the file and put the flow name on the `jobs:` map key:\n\n"+
					"WRONG (what you wrote):\n"+
					"  %s:\n"+
					"    on:\n"+
					"      request: { ... }\n"+
					"    jobs:\n"+
					"      ...:\n"+
					"        steps: [ ... ]\n\n"+
					"RIGHT (file-level):\n"+
					"  on:\n"+
					"    request:\n"+
					"      method: POST\n"+
					"      path: /api/your/path\n"+
					"  jobs:\n"+
					"    %s:\n"+
					"      steps:\n"+
					"        - id: lookup\n"+
					"          query: SELECT 1 AS ok\n"+
					"        - run: respond\n"+
					"          with: { status: 200, body: { ok: true } }",
				name, name, name)
		}
	}

	// 2. Pure legacy form. Detect by the legacy struct having a
	//    populated `trigger:` somewhere.
	var legacy map[string]FlowYAML
	if err := yaml.Unmarshal([]byte(content), &legacy); err == nil && len(legacy) > 0 {
		for name, fy := range legacy {
			if fy.Trigger != "" {
				return fmt.Sprintf(
					"flows.yaml: flow %q uses the legacy `trigger:` + `steps:` shape. That shape is no longer accepted at write time - every Benmore app on the platform uses the GHA shape, the legacy parser silently drops modern features (`sign:` recipes most notably), and keeping both alive forces every doc + example + diagnostic to disambiguate. Rewrite as:\n\n"+
						"  on:\n"+
						"    request:\n"+
						"      method: %s\n"+
						"      path: %s\n"+
						"  jobs:\n"+
						"    %s:\n"+
						"      steps:\n"+
						"        - id: example\n"+
						"          query: SELECT 1 AS ok\n"+
						"        - run: respond\n"+
						"          with: { status: 200, body: { ok: true } }\n\n"+
						"Legacy step shorthand (`- sql:`, `- api:`, `- respond:` at step root) also doesn't translate - GHA steps use `run: <type>` + `with: { ... }`. For SQL there's a shorthand: `query: SELECT ...` is the same as `run: sql` + `with: { query: ... }`. Variable references use `${{ steps.<id>.outputs.<field> }}` for step outputs and `${{ env.NAME }}` for env vars. See `help(topic: \"build\")` for the full flow reference.",
					name,
					legacyTriggerMethod(fy.Trigger),
					legacyTriggerPath(fy.Trigger),
					name)
			}
		}
	}

	// 3. Anything else - canonical shape with hints.
	return canonicalGHAShapeMessage("flows.yaml: file doesn't match the GHA shape.")
}

// legacyTriggerMethod / legacyTriggerPath split a "POST /api/foo"
// trigger string. Tolerant of an extra space or unusual whitespace.
func legacyTriggerMethod(t string) string {
	parts := strings.Fields(t)
	if len(parts) >= 1 {
		return strings.ToUpper(parts[0])
	}
	return "POST"
}

func legacyTriggerPath(t string) string {
	parts := strings.Fields(t)
	if len(parts) >= 2 {
		return parts[1]
	}
	return "/api/your/path"
}

// canonicalGHAShapeMessage is the fallback "here's what correct looks
// like" rendered any time we couldn't pin down a specific mistake.
func canonicalGHAShapeMessage(prefix string) string {
	return prefix + "\n\n" +
		"Canonical shape (GitHub Actions style, file-level `on:` and `jobs:`):\n\n" +
		"  on:\n" +
		"    request:\n" +
		"      method: POST\n" +
		"      path: /api/your/path\n" +
		"      # optional: auth: required, role: admin, transaction: true,\n" +
		"      #           verify: stripe (for inbound webhook signature checks)\n" +
		"  jobs:\n" +
		"    flow_name:\n" +
		"      steps:\n" +
		"        - id: lookup\n" +
		"          query: SELECT * FROM things WHERE id = :id\n" +
		"        - run: respond\n" +
		"          with:\n" +
		"            status: 200\n" +
		"            body:\n" +
		"              thing: ${{ steps.lookup.outputs.rows[0] }}\n\n" +
		"Bindings: `${{ steps.<id>.outputs.<field> }}` for step outputs, `${{ env.NAME }}` " +
		"for env vars, `${{ params.<name> }}` for path/query/body params, `${{ user.id }}` " +
		"/ `${{ user.email }}` for session. See `help(topic: \"build\")` for the full reference."
}

// isFlowsSubdirFile reports whether `path` lives under a `flows/`
// directory anywhere in the app and ends in `.yaml`/`.yml`. The
// framework loads every yaml file under flows/ as a flow definition;
// the validator needs to treat them identically to flows.yaml.
func isFlowsSubdirFile(path string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	ext := strings.ToLower(filepath.Ext(clean))
	if ext != ".yaml" && ext != ".yml" {
		return false
	}
	// match either "flows/<name>.yaml" at the app root or any
	// nested path like "subdir/flows/<name>.yaml". The framework only
	// loads the app-root flows/ today, but matching loosely is
	// future-proof and never false-positives against unrelated yaml.
	parts := strings.Split(clean, "/")
	for i, p := range parts {
		if p == "flows" && i < len(parts)-1 {
			return true
		}
	}
	return false
}

// validateLegacyFlowSteps walks the FlowStepYAML list and rejects any
// step that doesn't declare exactly one action key. The legacy parser
// silently skips unknown steps; this surfaces the typo upstream so the
// agent fixes it before the flow goes live.
//
// Legacy step shape: each step must set EXACTLY ONE of:
//
//	sql, api, email, webhook, redirect, respond, if, for_each, parse, set
//
// The most common agent mistake here is a typo'd key (`sqls:`,
// `query:`, `webhooks:`) that yaml.v3 parses as an unknown field and
// the runtime silently ignores.
func validateLegacyFlowSteps(flowName string, steps []FlowStepYAML) string {
	for i, s := range steps {
		actionSet := 0
		if s.SQL != "" {
			actionSet++
		}
		if s.API != nil {
			actionSet++
		}
		if s.Email != nil {
			actionSet++
		}
		if s.Webhook != "" {
			actionSet++
		}
		if s.Redirect != "" {
			actionSet++
		}
		if s.Respond != nil {
			actionSet++
		}
		if s.If != "" {
			actionSet++
		}
		if s.ForEach != "" {
			actionSet++
		}
		if s.Parse != "" {
			actionSet++
		}
		if s.Set != nil {
			actionSet++
		}
		if actionSet == 0 {
			return fmt.Sprintf(
				"flows.yaml: flow %q step %d has no recognized action. Each step must set exactly one of: sql, api, email, webhook, redirect, respond, if, for_each, parse, set.\n\n"+
					"Common typos that the YAML parser silently drops: `sqls:`, `query:` (use `sql:`), `webhooks:`, `then:` (use nested `steps:` under `if:`).\n\n"+
					"Recommended for new flows: switch to the GHA-shaped `on:` / `jobs:` shape - see `help(topic: \"flows\")`.",
				flowName, i)
		}
		if actionSet > 1 {
			return fmt.Sprintf(
				"flows.yaml: flow %q step %d sets multiple actions in the same step (%d action keys). Split into separate steps - one action per step.",
				flowName, i, actionSet)
		}
		// Recurse into if/for_each branches.
		if msg := validateLegacyFlowSteps(flowName+"/if", s.Steps); msg != "" {
			return msg
		}
		if msg := validateLegacyFlowSteps(flowName+"/else", s.Else); msg != "" {
			return msg
		}
	}
	return ""
}

// validateGHAFlowsContents reports issues within a successfully-shaped
// GHA flows file: jobs with no steps, steps with unknown `run:` types,
// and steps that mix legacy shorthand (`sql:`, `respond:`, etc. at step
// root) into the GHA envelope. The legacy-shorthand case is the
// dangerous one: yaml.v3 silently drops keys that don't exist on the
// target struct, so the GHA parser produced empty steps and the
// runtime fell through to its "{\"status\":\"ok\"}" default response.
// That made the flow look healthy when its steps were all no-ops.
func validateGHAFlowsContents(file FlowFileGHA) string {
	// Derive from flowRunTypes (flows_gha.go) - the SINGLE SOURCE the parser
	// switch also uses, so this validator can never drift behind a new step
	// type again. Empty `run:` is allowed (query:/if:/for_each: shorthand).
	knownRun := map[string]bool{"": true}
	for t := range flowRunTypes {
		knownRun[t] = true
	}
	// rate_limit on on.request must parse - a typo would otherwise fail OPEN
	// (no limit) at runtime, silently leaving a public endpoint unprotected.
	if file.On.Request != nil && strings.TrimSpace(file.On.Request.RateLimit) != "" {
		if parseRateLimit(file.On.Request.RateLimit) == nil {
			return fmt.Sprintf(
				"flows.yaml: rate_limit %q is malformed. Use `<count>/<window> [per <scope>]` - e.g. `5/hour per ip`, `100/min per user`, `10/h`. Windows: s/sec, m/min, h/hour, d/day (or a Go duration like 30s). Scopes: ip (default), user, email, group.",
				file.On.Request.RateLimit)
		}
	}
	for jobName, job := range file.Jobs {
		if len(job.Steps) == 0 {
			return fmt.Sprintf(
				"flows.yaml: job %q has no steps. Every job needs at least one step under `steps:`.",
				jobName)
		}
		// `when:` is not a flow-engine key (only `if:` is), so yaml.v3 drops it
		// and the guard never applies. Catch it on ANY step, including nested
		// if/for_each/else/on_error branches - an `on_error:` respond branch is
		// exactly where the "my guard keeps firing" footgun lives.
		if msg := ghaWhenViolation(jobName, job.Steps); msg != "" {
			return msg
		}
		for i, s := range job.Steps {
			if !knownRun[strings.ToLower(strings.TrimSpace(s.Run))] {
				return fmt.Sprintf(
					"flows.yaml: job %q step %d has `run: %s` which isn't a known step type.\n"+
						"Known: sql, sql_dynamic, api, email, webhook, redirect, respond, parse, set, parallel.\n"+
						"Shorthand: `query: SELECT ...` (auto-becomes `run: sql`), `if: ${{ ... }}` (conditional wrapper), `for_each: ${{ ... }}` (iteration wrapper).\n"+
						"`sql_dynamic` is the opt-in escape hatch for AI-generated queries (text-interpolated, not param-bound) - use only for SQL assembled by trusted internal callers.",
					jobName, i, s.Run)
			}
			if msg := validateStepSQLPatterns(jobName, i, s); msg != "" {
				return msg
			}
			if msg := validateSQLDynamicSafety(jobName, i, s); msg != "" {
				return msg
			}
		}
	}
	return ""
}

// ghaWhenViolation recursively finds a `when:` key on any flow step, including
// nested if/for_each/else/on_error branches.
func ghaWhenViolation(jobName string, steps []FlowStepGHA) string {
	for _, s := range steps {
		if strings.TrimSpace(s.When) != "" {
			return fmt.Sprintf(
				"flows.yaml: job %q has a step using `when:` - the flow engine has NO `when:` key, so it is silently ignored and the guarded branch ALWAYS runs. Use `if:` instead (e.g. `if: ${{ steps.x.outputs.rows }}`).",
				jobName)
		}
		if msg := ghaWhenViolation(jobName, s.Steps); msg != "" {
			return msg
		}
		if msg := ghaWhenViolation(jobName, s.Else); msg != "" {
			return msg
		}
		if msg := ghaWhenViolation(jobName, s.OnError); msg != "" {
			return msg
		}
	}
	return ""
}

// validateStepSQLPatterns catches SQLite-specific footguns that agents
// routinely hit during live builds. Returns "" if no issue.
//
// Caught patterns:
//
//  1. RAISE(ABORT, …) in flow SQL - only legal inside trigger programs.
//     The runtime returns "RAISE() may only be used within a trigger-
//     program" and the flow halts. Validator says: use an `if:` step
//     with a `respond` branch instead.
//
//  2. INSERT INTO … SELECT … ON CONFLICT … (no `WHERE true` between
//     them) - SQLite parser ambiguity at the SELECT/ON CONFLICT
//     boundary returns "near 'DO': syntax error". Validator says:
//     add `WHERE true` between FROM and ON CONFLICT.
//     See https://sqlite.org/lang_upsert.html#parsing_ambiguity.
//
// validateSQLDynamicSafety rejects a `run: sql_dynamic` step whose query
// text-interpolates a BARE (non-namespaced) reference - the request-input
// injection shape. sql_dynamic substitutes values as raw SQL text (NOT
// parameter-bound), so `WHERE name = '{{q}}'` or `= :id` fed from a request
// param/body/query is a direct SQL-injection primitive. Namespaced refs
// (`{{env.X}}`, `{{steps.x.y}}` - they contain a `.`) are server-controlled
// and allowed; the dangerous case is a bare single token, which is exactly how
// request params surface. Request input that must reach SQL belongs in a
// `run: sql` step, where `${{...}}` / `:param` are bound as ? placeholders.
func validateSQLDynamicSafety(jobName string, stepIdx int, s FlowStepGHA) string {
	if strings.ToLower(strings.TrimSpace(s.Run)) != "sql_dynamic" {
		return ""
	}
	sql := s.Query
	if sql == "" {
		if q, ok := s.With["query"].(string); ok {
			sql = q
		}
	}
	if sql == "" {
		return ""
	}
	// Scan {{ ... }} interpolations: a bare token with no `.` namespace is the
	// request-param shape.
	rest := sql
	for {
		open := strings.Index(rest, "{{")
		if open < 0 {
			break
		}
		close := strings.Index(rest[open+2:], "}}")
		if close < 0 {
			break
		}
		tok := strings.TrimSpace(rest[open+2 : open+2+close])
		// Strip a GHA `${{ }}` leading `$`-less form; tolerate a leading "${".
		tok = strings.TrimPrefix(tok, "$")
		if tok != "" && !strings.Contains(tok, ".") {
			return fmt.Sprintf(
				"flows.yaml: job %q step %d (`run: sql_dynamic`) interpolates a bare `{{%s}}` directly into the query.\n"+
					"sql_dynamic substitutes values as raw SQL TEXT, not bound parameters - a bare reference fed from request input is a SQL-injection hole.\n"+
					"For request input, use `run: sql` (or `query:`) where `${{ %s }}` / `:%s` bind as ? placeholders. Reserve sql_dynamic for SQL assembled from server-trusted values (`{{env.X}}`, `{{steps.<id>.<field>}}`).",
				jobName, stepIdx, tok, tok, tok)
		}
		rest = rest[open+2+close+2:]
	}
	// Scan `:name` bind-style placeholders outside quotes (the other request
	// shape). Conservative: only flag a colon directly followed by an
	// identifier and not part of `::` (cast) - matches the framework's :param
	// substitution that sql_dynamic does NOT bind.
	for i := 0; i < len(sql); i++ {
		if sql[i] != ':' {
			continue
		}
		if i+1 < len(sql) && sql[i+1] == ':' { // `::` cast - skip both
			i++
			continue
		}
		// Predecessor must be a bind position (start, whitespace, `(`, `,`,
		// `=`), not an identifier or quote - so `:word` inside a string
		// literal ('a:b') or a time literal ('12:30:00', digit predecessor)
		// isn't flagged.
		if i > 0 {
			p := sql[i-1]
			if !(p == ' ' || p == '\t' || p == '\n' || p == '\r' || p == '(' || p == ',' || p == '=') {
				continue
			}
		}
		// First char after `:` must start an identifier (letter/underscore),
		// excluding numeric time-literal fragments like `:30`.
		if i+1 >= len(sql) || !(sql[i+1] == '_' || (sql[i+1] >= 'a' && sql[i+1] <= 'z') || (sql[i+1] >= 'A' && sql[i+1] <= 'Z')) {
			continue
		}
		j := i + 1
		for j < len(sql) && (isIdentByte(sql[j])) {
			j++
		}
		if j > i+1 { // :identifier
			name := sql[i+1 : j]
			return fmt.Sprintf(
				"flows.yaml: job %q step %d (`run: sql_dynamic`) uses a `:%s` placeholder.\n"+
					"sql_dynamic does NOT bind `:params` - it text-substitutes them, so this is injectable from request input.\n"+
					"Use `run: sql` (or `query:`) where `:%s` binds as a ? placeholder.",
				jobName, stepIdx, name, name)
		}
	}
	return ""
}

func isIdentByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func validateStepSQLPatterns(jobName string, stepIdx int, s FlowStepGHA) string {
	sql := s.Query
	if sql == "" {
		if q, ok := s.With["query"].(string); ok {
			sql = q
		}
	}
	if sql == "" {
		return ""
	}
	upper := strings.ToUpper(sql)

	// (1) RAISE() in flow SQL.
	if strings.Contains(upper, "RAISE(") || strings.Contains(upper, "RAISE (") {
		return fmt.Sprintf(
			"flows.yaml: job %q step %d uses RAISE() in a flow SQL step. RAISE() only works inside SQLite trigger programs - flow SQL will fail at runtime with 'RAISE() may only be used within a trigger-program'.\n\n"+
				"Fix: use an `if:` step with a `respond` branch to short-circuit instead.\n\n"+
				"  - id: check\n"+
				"    query: SELECT 1 AS bad WHERE <your condition>\n"+
				"  - if: ${{ steps.check.outputs.bad }} = 1\n"+
				"    run: respond\n"+
				"    with: { status: 400, body: { error: \"your message\" } }",
			jobName, stepIdx)
	}

	// (2) INSERT INTO ... SELECT ... ON CONFLICT without WHERE true.
	if strings.Contains(upper, "INSERT") &&
		strings.Contains(upper, "SELECT") &&
		strings.Contains(upper, "ON CONFLICT") {
		// Look for a SELECT ... ON CONFLICT pattern (vs. INSERT INTO ... VALUES ... ON CONFLICT which is fine).
		// Heuristic: if a SELECT-clause precedes ON CONFLICT and there's no `WHERE true` between FROM and ON CONFLICT.
		selectIdx := strings.Index(upper, "SELECT")
		conflictIdx := strings.Index(upper, "ON CONFLICT")
		fromIdx := strings.Index(upper[selectIdx:], "FROM")
		if fromIdx >= 0 && selectIdx >= 0 && conflictIdx > selectIdx {
			between := upper[selectIdx+fromIdx : conflictIdx]
			if !strings.Contains(between, "WHERE TRUE") && !strings.Contains(between, "WHERE 1") {
				return fmt.Sprintf(
					"flows.yaml: job %q step %d uses INSERT INTO … SELECT … ON CONFLICT without a `WHERE true` separator. SQLite's parser can't tell where the SELECT ends and the ON CONFLICT begins - the request will fail at runtime with 'near \"DO\": syntax error'.\n\n"+
						"Fix: add `WHERE true` between the SELECT/FROM and the ON CONFLICT clause:\n\n"+
						"  INSERT INTO things (id, name)\n"+
						"  SELECT json_extract(value, '$.id'), json_extract(value, '$.name')\n"+
						"  FROM json_each(:rows)\n"+
						"  WHERE true                          ← add this line\n"+
						"  ON CONFLICT(id) DO UPDATE SET name = excluded.name\n\n"+
						"See https://sqlite.org/lang_upsert.html#parsing_ambiguity for why this exists.",
					jobName, stepIdx)
			}
		}
	}
	return ""
}

// reservedPathPrefixes lists framework-owned URL prefixes. Flows that
// register a `path:` falling under any of these would lose to the
// framework's own handler (mux ordering puts framework routes first
// in buildAppMux). Catching this at write time is a million times
// nicer than the agent watching their endpoint silently 404 or return
// the framework's default response.
var reservedPathPrefixes = []string{
	"/api/_",      // /api/_audit, /api/_auth, /api/_notifications, /api/_files, /api/_docs, etc.
	"/api/v1/",    // platform API
	"/_internal/", // embedded React/ReactDOM/bm.js
	"/_admin",     // admin panel
	"/login",      // auth path
	"/signup",     // auth path
	"/logout",     // auth path
	"/forgot-password",
	"/reset-password",
	"/verify-email",
	"/verify-otp",
	"/verify-mfa",
	"/settings",
	"/static/",
	"/uploads/",
	"/health",
	"/feed.xml",
	"/sitemap.xml",
	"/robots.txt",
	"/llms.txt",
	"/favicon.ico",
	"/manifest.json",
	"/sw.js",
	"/sse/",
	"/ws",
	"/pdf/",
	"/platform/", // benmore.ai platform endpoints
	"/.well-known/",
}

func detectReservedPath(path string) string {
	if path == "" {
		return ""
	}
	for _, prefix := range reservedPathPrefixes {
		if path == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(path, prefix) {
			return fmt.Sprintf(
				"flows.yaml: path %q collides with the framework's reserved prefix %q. The framework registers its handler first, so your flow would never receive these requests. Pick a path under /api/<your-name>/ that doesn't start with `_` - e.g. /api/explore, /api/checkout, /api/webhooks/stripe.",
				path, prefix)
		}
	}
	return ""
}

// detectLegacyShorthandInGHASteps re-parses the raw YAML into a generic
// map so we can SEE keys that the FlowStepGHA struct silently drops.
// If a step at GHA-envelope level has `sql:`, `respond:`, `email:`,
// `webhook:`, `api:`, `redirect:`, `parse:`, or `set:` as a root key
// (instead of `run: <type>` + `with: { ... }`), the file mixes two
// incompatible formats and EVERY step is silently a no-op at runtime.
//
// Returns the human-readable rewrite hint. Empty string = no problem.
func detectLegacyShorthandInGHASteps(content string) string {
	var raw struct {
		On   any                       `yaml:"on"`
		Jobs map[string]map[string]any `yaml:"jobs"`
	}
	if err := yaml.Unmarshal([]byte(content), &raw); err != nil || raw.Jobs == nil {
		return ""
	}
	legacyShorthand := map[string]bool{
		"sql": true, "respond": true, "email": true, "webhook": true,
		"api": true, "redirect": true, "parse": true, "set": true,
	}
	for jobName, job := range raw.Jobs {
		stepsAny, ok := job["steps"].([]any)
		if !ok {
			continue
		}
		for i, st := range stepsAny {
			stm, ok := st.(map[string]any)
			if !ok {
				continue
			}
			for k := range stm {
				if legacyShorthand[strings.ToLower(k)] {
					return fmt.Sprintf(
						"flows.yaml: job %q step %d uses legacy shorthand `%s:` at the step root, but the file uses the GitHub Actions envelope (`on:` + `jobs:`). yaml.v3 silently drops unrecognized keys, so this step becomes a no-op at runtime and the route returns `{\"status\":\"ok\"}` instead of executing.\n\n"+
							"Pick ONE format consistently:\n\n"+
							"  (a) GHA-style (recommended) - use `run:` + `with:` at every step:\n"+
							"      steps:\n"+
							"        - run: sql\n"+
							"          query: SELECT * FROM stories WHERE status = 'published'\n"+
							"          id: rows\n"+
							"        - run: respond\n"+
							"          with: { body: \"${{ steps.rows.outputs.* }}\" }\n\n"+
							"  (b) Legacy - drop the GHA envelope entirely:\n"+
							"      explore:\n"+
							"        trigger: GET /api/explore\n"+
							"        steps:\n"+
							"          - sql: SELECT ...\n"+
							"            name: rows\n"+
							"          - respond:\n"+
							"              json: \"{{rows}}\"",
						jobName, i, k)
				}
			}
		}
	}
	return ""
}

// validateHooksYAML checks hooks.yaml has a recognized top-level shape.
// Each top-level key must be one of on_insert / on_update / on_delete /
// before_insert / before_update / before_delete. Anything else is
// almost certainly a typo (`on_create:` is common; mapped to nothing).
func validateHooksYAML(content string) string {
	if strings.TrimSpace(content) == "" {
		return ""
	}
	var top map[string]any
	if err := yaml.Unmarshal([]byte(content), &top); err != nil {
		return fmt.Sprintf("hooks.yaml YAML syntax: %s", err)
	}
	known := map[string]bool{
		"on_insert": true, "on_update": true, "on_delete": true,
		"before_insert": true, "before_update": true, "before_delete": true,
	}
	for k := range top {
		if !known[k] {
			return fmt.Sprintf(
				"hooks.yaml: unknown top-level key %q.\n\n"+
					"Valid keys: on_insert, on_update, on_delete, before_insert, before_update, before_delete.\n"+
					"Common fabrications: `on_create` (use on_insert), `after_save` (use on_update or on_insert), `hooks:` wrapper around everything (the keys go at the top level - no wrapper).",
				k)
		}
	}
	return ""
}

// validateYAMLSyntax is the fallback for any .yaml file we don't have
// specific knowledge of. It just runs yaml.Unmarshal and surfaces the
// error position when parsing fails - the agent's YAML mistakes are
// usually indentation or missing colons, and the parser already
// pinpoints both.
func validateYAMLSyntax(content string) string {
	if strings.TrimSpace(content) == "" {
		return ""
	}
	var probe any
	if err := yaml.Unmarshal([]byte(content), &probe); err != nil {
		return err.Error()
	}
	return ""
}

// validateEncryptedYAML catches the common typos in encrypted.yaml that
// silently no-op at runtime. LoadEncryptedFieldsConfig accepts ONLY the
// shape:
//
//	tables:
//	  <name>:
//	    fields:       [a, b, c]
//	    unmask_roles: [admin, manager]
//
// Anything else (top-level `table:`, per-table `columns:` instead of
// `fields:`, per-table `roles:` instead of `unmask_roles:`, or a
// top-level map of tables without the `tables:` wrapper) parses cleanly
// but contributes nothing to config.Fields - so the encrypted.yaml file
// appears to deploy but the runtime installs ZERO triggers. The agent
// then sends a message and reads plaintext from the DB, and has no
// signal that anything went wrong.
func validateEncryptedYAML(content string) string {
	if strings.TrimSpace(content) == "" {
		return ""
	}
	if msg := validateYAMLSyntax(content); msg != "" {
		return fmt.Sprintf("encrypted.yaml: yaml syntax - %s", msg)
	}

	// Parse to the most permissive shape so we can inspect the keys.
	var raw map[string]any
	if err := yaml.Unmarshal([]byte(content), &raw); err != nil {
		return fmt.Sprintf("encrypted.yaml: yaml parse failed - %s", err)
	}

	// Top-level: must have `tables:` and nothing else (other top-level
	// keys are silently ignored at runtime).
	if _, ok := raw["tables"]; !ok {
		// Detect the two most common mistakes: singular `table:` and
		// putting table names at the top level (no wrapper).
		if _, hasSingular := raw["table"]; hasSingular {
			return "antipattern [unknown-encrypted-key] in encrypted.yaml: top-level key `table:` is not recognized - the framework expects PLURAL `tables:`. Real shape:\n\n  tables:\n    <name>:\n      fields:       [col_a, col_b]\n      unmask_roles: [admin, hr_admin]\n\nWithout the `tables:` wrapper, runtime parses zero fields and installs zero encryption triggers - the file appears to deploy but every write lands plaintext."
		}
		// Heuristic: if the top-level keys LOOK like table names (any
		// of them is itself a map with `fields:` inside), the developer
		// forgot the `tables:` wrapper.
		for k, v := range raw {
			if m, ok := v.(map[string]any); ok {
				if _, hasFields := m["fields"]; hasFields {
					return fmt.Sprintf("antipattern [missing-encrypted-wrapper] in encrypted.yaml: top-level key %q looks like a table definition (it has a `fields:` key), but the framework requires the `tables:` wrapper. Real shape:\n\n  tables:\n    %s:\n      fields:       [...]\n      unmask_roles: [...]\n\nWithout the wrapper, runtime parses zero fields and installs zero encryption triggers - the file appears to deploy but every write lands plaintext.", k, k)
				}
			}
		}
		return "antipattern [missing-encrypted-wrapper] in encrypted.yaml: file has no `tables:` key. Real shape:\n\n  tables:\n    <name>:\n      fields:       [col_a, col_b]\n      unmask_roles: [admin, hr_admin]"
	}

	// Per-table: must have `fields:` (list of strings); `unmask_roles:`
	// is optional but if present must be a list of strings.
	tables, ok := raw["tables"].(map[string]any)
	if !ok {
		return "antipattern [encrypted-yaml-shape] in encrypted.yaml: `tables:` must be a map of table name → spec, e.g. `tables: { contacts: { fields: [ssn] } }`."
	}
	for tableName, spec := range tables {
		specMap, ok := spec.(map[string]any)
		if !ok {
			return fmt.Sprintf("antipattern [encrypted-yaml-shape] in encrypted.yaml: `tables.%s` must be a map with `fields:` and optional `unmask_roles:`, got %T.", tableName, spec)
		}
		// Known sub-keys: fields, unmask_roles. Everything else is
		// silently ignored - flag it.
		for k := range specMap {
			switch k {
			case "fields", "unmask_roles", "blind_index":
				// ok
			case "columns", "column":
				return fmt.Sprintf("antipattern [unknown-encrypted-key] in encrypted.yaml: `tables.%s.%s` is not recognized - the framework expects `fields:`. Real shape:\n\n  tables:\n    %s:\n      fields:       [col_a, col_b]\n      unmask_roles: [admin]", tableName, k, tableName)
			case "roles", "unmask":
				return fmt.Sprintf("antipattern [unknown-encrypted-key] in encrypted.yaml: `tables.%s.%s` is not recognized - the framework expects `unmask_roles:` (the list of roles that read decrypted; everyone else sees masked). Real shape:\n\n  tables:\n    %s:\n      fields:       [col_a]\n      unmask_roles: [admin]", tableName, k, tableName)
			case "blind", "blind_indexes", "blind_indices", "searchable":
				return fmt.Sprintf("antipattern [unknown-encrypted-key] in encrypted.yaml: `tables.%s.%s` is not recognized - the framework expects `blind_index:` (singular, list of columns to equality-search-enable). Real shape:\n\n  tables:\n    %s:\n      fields:       [email, ssn]\n      blind_index:  [email]", tableName, k, tableName)
			default:
				return fmt.Sprintf("antipattern [unknown-encrypted-key] in encrypted.yaml: `tables.%s.%s` is not a recognized key. Real per-table keys: `fields` (list of column names to encrypt), `unmask_roles` (optional list of roles that read decrypted), `blind_index` (optional list of fields that get a deterministic HMAC sibling column for equality search).", tableName, k)
			}
		}
		// fields: required, must be a non-empty list of strings.
		fields, hasFields := specMap["fields"]
		if !hasFields {
			return fmt.Sprintf("antipattern [encrypted-yaml-shape] in encrypted.yaml: `tables.%s` is missing the `fields:` key. Without `fields:`, no columns are encrypted for this table - the entry is a no-op. Add at least one column:\n\n  tables:\n    %s:\n      fields: [<column_name>]", tableName, tableName)
		}
		fieldList, ok := fields.([]any)
		if !ok {
			return fmt.Sprintf("antipattern [encrypted-yaml-shape] in encrypted.yaml: `tables.%s.fields` must be a list of column names, got %T. Example: `fields: [body, notes]`.", tableName, fields)
		}
		for i, f := range fieldList {
			s, ok := f.(string)
			if !ok {
				return fmt.Sprintf("antipattern [encrypted-yaml-shape] in encrypted.yaml: `tables.%s.fields[%d]` is %T, expected a string column name.", tableName, i, f)
			}
			if strings.TrimSpace(s) == "" {
				return fmt.Sprintf("antipattern [encrypted-yaml-shape] in encrypted.yaml: `tables.%s.fields[%d]` is an empty string.", tableName, i)
			}
		}
		// unmask_roles: optional, must be a list of strings if present.
		if roles, hasRoles := specMap["unmask_roles"]; hasRoles {
			roleList, ok := roles.([]any)
			if !ok {
				return fmt.Sprintf("antipattern [encrypted-yaml-shape] in encrypted.yaml: `tables.%s.unmask_roles` must be a list of role names, got %T.", tableName, roles)
			}
			for i, r := range roleList {
				if _, ok := r.(string); !ok {
					return fmt.Sprintf("antipattern [encrypted-yaml-shape] in encrypted.yaml: `tables.%s.unmask_roles[%d]` is %T, expected a string role name.", tableName, i, r)
				}
			}
		}
		// blind_index: optional, must be a list of strings if present.
		// Each name must also appear in the table's `fields:` list - a
		// blind index without an encrypted source is a no-op, and almost
		// always a typo. v2.7.55+.
		if blind, hasBlind := specMap["blind_index"]; hasBlind {
			blindList, ok := blind.([]any)
			if !ok {
				return fmt.Sprintf("antipattern [encrypted-yaml-shape] in encrypted.yaml: `tables.%s.blind_index` must be a list of column names, got %T. Example: `blind_index: [email]`.", tableName, blind)
			}
			// Build a set of declared fields for cross-reference.
			fieldSet := map[string]bool{}
			if fieldsRaw, ok := specMap["fields"].([]any); ok {
				for _, f := range fieldsRaw {
					if s, ok := f.(string); ok {
						fieldSet[s] = true
					}
				}
			}
			for i, b := range blindList {
				s, ok := b.(string)
				if !ok {
					return fmt.Sprintf("antipattern [encrypted-yaml-shape] in encrypted.yaml: `tables.%s.blind_index[%d]` is %T, expected a string column name.", tableName, i, b)
				}
				if strings.TrimSpace(s) == "" {
					return fmt.Sprintf("antipattern [encrypted-yaml-shape] in encrypted.yaml: `tables.%s.blind_index[%d]` is an empty string.", tableName, i)
				}
				if !fieldSet[s] {
					return fmt.Sprintf("antipattern [blind-index-not-in-fields] in encrypted.yaml: `tables.%s.blind_index` contains %q, but %q is not in `tables.%s.fields`. A blind index only makes sense for an encrypted column - add %q to `fields:` first.", tableName, s, s, tableName, s)
				}
			}
		}
	}
	return ""
}
