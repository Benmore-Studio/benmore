//go:build !cli

package main

import (
	"fmt"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

// knownAppYAMLKeys is the canonical set of top-level keys the
// framework actually reads from app.yaml. Agents repeatedly invent
// keys like `database`, `routes`, `middleware`, `cors`, `cdn` that
// silently no-op. Flag unknown top-level keys at write time so the
// agent can fix them before debugging "why isn't my config doing
// anything."
var knownAppYAMLKeys = map[string]bool{
	"site_name":        true,
	"description":      true,
	"theme":            true,
	"mode":             true,
	"font":             true,
	"brand":            true,
	"css":              true,
	"radius":           true,
	"shadow":           true,
	"nav":              true,
	"seo":              true,
	"auth":             true,
	"roles":            true,
	"features":         true,
	"groups":           true,
	"pwa":              true,
	"recording":        true,
	"backup":           true,
	"aggregates":       true,
	"database":         true,
	"head":             true,
	"oauth":            true,
	"frontend":         true, // frontend.stack: html|react|gotmpl - picks the scaffold flavor
	"scopes":           true, // legacy per-table public_read_when overrides
	"access":           true, // v2.7.12 declarative per-table per-op access control
	"auto_memberships": true, // v2.7.35 shorthand: synthesize on_insert hooks for "every active user → parent's join table"
	"csp":              true, // per-directive CSP allowlist extensions: script_src, style_src, img_src, font_src, connect_src, frame_src
	"ws_rooms":         true, // v2.7.164 WS room-name patterns bound to membership tables (join-time authorization)
}

// knownCSPKeys is the set of directives accepted under `csp:` in
// app.yaml. Each value is a space-separated origin list appended to
// the framework's default CSP (it widens, never replaces).
var knownCSPKeys = map[string]bool{
	"script_src":  true,
	"style_src":   true,
	"img_src":     true,
	"font_src":    true,
	"connect_src": true,
	"frame_src":   true,
}

// knownAuthKeys is the canonical set of keys under `auth:` in app.yaml.
// Agents invent `auth.enabled`, `auth.providers`, `auth.signup_enabled`,
// `auth.redirect_unauthenticated_to`, etc. that don't exist.
var knownAuthKeys = map[string]bool{
	"identifier":            true,
	"session_duration":      true,
	"signup_fields":         true,
	"otp":                   true,
	"domain":                true,
	"redirect":              true,
	"require_verified":      true,
	"verify_email":          true,
	"oauth":                 true,
	"mfa":                   true,
	"require_mfa_for_roles": true, // comma-separated roles that must enroll MFA before a session is issued
	"mfa_setup_redirect":    true, // form-login redirect target when enrollment is required (default /mfa-setup)
	"read_audit_sync":       true,
}

// yamlTopLevelKeyRe captures top-level YAML keys (no leading whitespace).
var yamlTopLevelKeyRe = regexp.MustCompile(`(?m)^([a-zA-Z_][a-zA-Z0-9_]*)\s*:`)

// yamlNestedAuthKeyRe captures keys nested under `auth:` (two-space indent).
var yamlNestedAuthKeyRe = regexp.MustCompile(`(?m)^  ([a-zA-Z_][a-zA-Z0-9_]*)\s*:`)

// validateAppYAML scans app.yaml for fabricated top-level and auth.* keys
// that the framework doesn't recognize. Returns the first violation's
// error string, empty if clean.
func validateAppYAML(content string) string {
	for _, m := range yamlTopLevelKeyRe.FindAllStringSubmatch(content, -1) {
		if len(m) < 2 {
			continue
		}
		key := m[1]
		if knownAppYAMLKeys[key] {
			continue
		}
		return fmt.Sprintf("antipattern [unknown-app-yaml-key] in app.yaml: top-level key %q is not recognized by the framework. Known keys: %s. Common fabrications: `routes:`, `middleware:`, `pages:`, `database_url:`, `cdn:`, `theme.primary_color:` (the real `theme:` is just a string like \"zinc\"/\"blue\", plus `brand:` for the accent color). Read `help(topic: \"build\")` for the full app.yaml shape.", key, knownYAMLKeysList())
	}
	// Scope-format sanity check on roles. v2.5.10 widened the parser
	// to accept list shapes (`scopes: ["*"]`) - and joins entries with
	// spaces - but the framework still expects each entry to be a real
	// `resource:action` (or `*`) scope. `scopes: ["own"]` parses
	// cleanly but every CRUD call 403s
	// because "own" isn't a real scope. Catch it at write time.
	if strings.Contains(content, "\nroles:\n") || strings.HasPrefix(content, "roles:\n") {
		var parsed map[string]any
		if err := yaml.Unmarshal([]byte(content), &parsed); err == nil {
			if rolesRaw, ok := parsed["roles"].(map[string]any); ok {
				for roleName, v := range rolesRaw {
					var entries []string
					switch val := v.(type) {
					case map[string]any:
						switch s := val["scopes"].(type) {
						case string:
							entries = strings.Fields(s)
						case []any:
							for _, item := range s {
								if str, ok := item.(string); ok && str != "" {
									entries = append(entries, str)
								}
							}
						}
					case string:
						entries = strings.Fields(val)
					case []any:
						for _, item := range val {
							if str, ok := item.(string); ok && str != "" {
								entries = append(entries, str)
							}
						}
					}
					for _, e := range entries {
						if e == "*" {
							continue
						}
						parts := strings.SplitN(e, ":", 2)
						if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
							return fmt.Sprintf("app.yaml: role %q has invalid scope %q. Scopes must be \"*\" for full access, or \"resource:action\" pairs (e.g. \"customers:read\", \"shipments:write\"). The framework's CRUD gate checks every API call against this list, so a malformed scope means every call 403s with `scope denied: token does not have <table>:read permission`.\n\nFix:\n  roles:\n    %s:\n      scopes: [\"*\"]                     # full access (admins)\n  or\n  roles:\n    %s:\n      scopes: [\"customers:read\", \"shipments:read\", \"invites:read\"]\n\nNote: tenant scoping (each user only sees their own data) is automatic via the `groups:` config + ownership columns - scopes are about WHICH tables, not which rows.",
								roleName, e, roleName, roleName)
						}
						// `read`, `write`, `delete`, `*` are framework CRUD
						// verbs. Anything else is an app-defined custom verb
						// the developer uses in their own flows.yaml
						// (e.g. `reviews:approve`, `orders:approve`). Allow any
						// well-formed identifier - runtime hasScope() handles
						// exact-match against checkScope(session, t, action)
						// regardless of which set the verb came from. Pre-
						// 2.7.31 we rejected custom verbs here, which forced
						// agents to either invent fake `read/write` mappings
						// or fall back to admin-only - exactly the wrong
						// outcome for fine-grained app-defined RBAC.
						action := parts[1]
						if !isScopeIdentifier(action) {
							return fmt.Sprintf("app.yaml: role %q scope %q has invalid action %q. Action must be a non-empty identifier (a-z, A-Z, 0-9, _, *).", roleName, e, action)
						}
					}
				}
			}
		}
	}
	// access: block sanity - validates that each mode value is in the
	// known enum (anon / everyone / self / group / admin / role:<X> / off).
	// Typo'd modes (`read: anonn`, `read: everyone:read`, `read: pubic`)
	// parse as YAML strings cleanly and then crash the access enforcer
	// at runtime with `unknown access mode` - but only when the first
	// request to that table arrives, by which point the agent has
	// already moved on. Catch at write time.
	if strings.Contains(content, "\naccess:") || strings.HasPrefix(content, "access:") {
		var parsed map[string]any
		if err := yaml.Unmarshal([]byte(content), &parsed); err == nil {
			if accessRaw, ok := parsed["access"].(map[string]any); ok {
				for tableName, v := range accessRaw {
					// Two shapes: `posts: admin` (string applied to all
					// ops) or `posts: { read: anon, write: self, ... }` (per-op map).
					switch val := v.(type) {
					case string:
						if msg := validateAccessMode(tableName, "all", val); msg != "" {
							return msg
						}
					case map[string]any:
						for op, mode := range val {
							modeStr, ok := mode.(string)
							if !ok {
								return fmt.Sprintf("app.yaml: access.%s.%s must be a string mode name, got %T. Allowed: anon, everyone, self, group, admin, role:<name>, perm:<resource>.<action>, member-of:<table>(<join_col>,<user_col>), off.", tableName, op, mode)
							}
							if msg := validateAccessMode(tableName, op, modeStr); msg != "" {
								return msg
							}
						}
					}
				}
			}
		}
	}

	// ws_rooms: block sanity (v2.7.164) - each value must parse as a
	// membership rule. A typo'd rule is DROPPED at load time (the room
	// stays unprotected), so catch it at write time where the agent can
	// act on it.
	if strings.Contains(content, "\nws_rooms:") || strings.HasPrefix(content, "ws_rooms:") {
		var parsed map[string]any
		if err := yaml.Unmarshal([]byte(content), &parsed); err == nil {
			if wsRaw, ok := parsed["ws_rooms"].(map[string]any); ok {
				for pattern, v := range wsRaw {
					ruleStr, ok := v.(string)
					if !ok || parseMemberOf("member-of:"+strings.ToLower(strings.TrimSpace(ruleStr))) == nil {
						return fmt.Sprintf("app.yaml: ws_rooms.%q = %v is malformed. Syntax: `<membership_table>(<join_col>, <user_col>)`, e.g.\n\nws_rooms:\n  \"room-:id\": room_members(room_id, member_id)\n\nThe `:id` placeholder captures the room's numeric/uuid id from the WS room name and requires a membership row (join_col = captured id, user_col = session user id, or email when the column name contains \"email\") before `join` succeeds.", pattern, v)
					}
				}
			}
		}
	}

	// Auth sub-keys
	if strings.Contains(content, "\nauth:\n") || strings.HasPrefix(content, "auth:\n") {
		// Find the auth: block and scan its children
		idx := strings.Index(content, "auth:\n")
		if idx >= 0 {
			tail := content[idx:]
			// Read until next top-level key (line starting with non-space)
			end := len(tail)
			lines := strings.Split(tail, "\n")
			authBlock := ""
			for i, line := range lines {
				if i == 0 { // "auth:"
					authBlock += line + "\n"
					continue
				}
				// Empty line OR top-level key (no leading space) breaks the block
				if line == "" {
					authBlock += line + "\n"
					continue
				}
				if !strings.HasPrefix(line, " ") {
					break
				}
				authBlock += line + "\n"
				_ = end
			}
			for _, m := range yamlNestedAuthKeyRe.FindAllStringSubmatch(authBlock, -1) {
				if len(m) < 2 {
					continue
				}
				key := m[1]
				if knownAuthKeys[key] {
					continue
				}
				return fmt.Sprintf("antipattern [unknown-auth-key] in app.yaml: `auth.%s` is not recognized. Real auth keys: %s. Common fabrications: `auth.enabled: true` (the framework auto-enables auth when `auth:` is present), `auth.providers: [...]` (use `auth.oauth.<provider>:` for OAuth providers), `auth.signup_enabled: true` (always-on, no flag), `auth.redirect_unauthenticated_to:` (use `auth.redirect:` for post-login destination). Read `help(topic: \"auth\")` for the real schema.", key, knownAuthKeysList())
			}
		}
	}

	// CSP sub-keys - same shape, different known-set + error message.
	if strings.Contains(content, "\ncsp:\n") || strings.HasPrefix(content, "csp:\n") {
		idx := strings.Index(content, "csp:\n")
		if idx >= 0 {
			tail := content[idx:]
			cspBlock := ""
			for i, line := range strings.Split(tail, "\n") {
				if i == 0 {
					cspBlock += line + "\n"
					continue
				}
				if line == "" {
					cspBlock += line + "\n"
					continue
				}
				if !strings.HasPrefix(line, " ") {
					break
				}
				cspBlock += line + "\n"
			}
			for _, m := range yamlNestedAuthKeyRe.FindAllStringSubmatch(cspBlock, -1) {
				if len(m) < 2 {
					continue
				}
				key := m[1]
				if knownCSPKeys[key] {
					continue
				}
				return fmt.Sprintf("antipattern [unknown-csp-key] in app.yaml: `csp.%s` is not a recognised CSP directive. Real directives: script_src, style_src, img_src, font_src, connect_src, frame_src (each value is a space-separated origin list, appended to the framework defaults). Example: `csp:\\n  script_src: \"https://maps.googleapis.com\"\\n  img_src: \"https://*.tile.openstreetmap.org\"`. Read `help(topic: \"csp\")` for the full schema.", key)
			}
		}
	}

	return ""
}

// knownAccessModes mirrors the set Allowed() in access.go honors.
// Unknown modes fail-closed at runtime but the request that triggers
// the failure happens long after the agent's write - catching at
// write time means the agent gets the actionable error inline.
var knownAccessModes = map[string]bool{
	"anon":     true,
	"everyone": true,
	"self":     true,
	"group":    true,
	"admin":    true,
	"off":      true,
}

// validateAccessMode returns an error message when `mode` isn't a
// recognized access mode. Accepts the special-cased `role:<name>`,
// `perm:<resource>.<action>`, and `member-of:<table>(<join>,<user>)`
// prefixes for developer-defined gates.
func validateAccessMode(table, op, mode string) string {
	m := strings.ToLower(strings.TrimSpace(mode))
	if m == "" {
		return fmt.Sprintf("app.yaml: access.%s.%s is empty. Allowed modes: anon, everyone, self, group, admin, role:<name>, perm:<resource>.<action>, member-of:<table>(<join_col>,<user_col>), off.", table, op)
	}
	if strings.HasPrefix(m, "role:") {
		if strings.TrimSpace(strings.TrimPrefix(m, "role:")) == "" {
			return fmt.Sprintf("app.yaml: access.%s.%s = %q has empty role name. Use `role:<name>` where <name> matches an entry in your `roles:` block.", table, op, mode)
		}
		return ""
	}
	// owner_or_role:<roles> - tiered visibility (owner sees own, role-holders
	// see their group / all). A row is visible if you own it OR hold a listed
	// role; admins (platform) always see all.
	if strings.HasPrefix(m, "owner_or_role:") {
		if strings.TrimSpace(strings.TrimPrefix(m, "owner_or_role:")) == "" {
			return fmt.Sprintf("app.yaml: access.%s.%s = %q has an empty role list. Use `owner_or_role:<r1,r2>` where each role matches an entry in your `roles:` block (e.g. `owner_or_role:manager,admin`).", table, op, mode)
		}
		return ""
	}
	// perm:<resource>.<action> / perm:<resource>:<action> - granular
	// permission gates (v2.7.54). The validator predates them; without
	// this branch a perfectly valid perm: mode was rejected at write time.
	if strings.HasPrefix(m, "perm:") {
		want := strings.TrimSpace(strings.TrimPrefix(m, "perm:"))
		if want == "" || (!strings.Contains(want, ".") && !strings.Contains(want, ":")) {
			return fmt.Sprintf("app.yaml: access.%s.%s = %q is malformed. Use `perm:<resource>.<action>`, e.g. `perm:posts.publish`.", table, op, mode)
		}
		return ""
	}
	// member-of:<table>(<join_col>, <user_col>) - membership-scoped
	// access (v2.7.164). Malformed declarations fail closed at request
	// time, so catch the syntax here where the agent can act on it.
	if strings.HasPrefix(m, "member-of:") {
		if parseMemberOf(m) == nil {
			return fmt.Sprintf("app.yaml: access.%s.%s = %q is malformed. Syntax: `member-of:<membership_table>(<join_col>, <user_col>)`, e.g. `member-of:room_members(room_id, member_id)`. Rows become visible to users who have a row in the membership table; <join_col> matches the protected table's column of the same name (or its `id` when absent); <user_col> compares against the session user id (or email when the column name contains \"email\").", table, op, mode)
		}
		return ""
	}
	if knownAccessModes[m] {
		return ""
	}
	return fmt.Sprintf("app.yaml: access.%s.%s = %q is not a known access mode.\n\nAllowed modes:\n  anon      - no auth required (truly public)\n  everyone  - any authenticated user\n  self      - owner only (table needs user_id column)\n  group     - same-group only (table needs groups: config + group key column)\n  admin     - only role=admin\n  role:NAME - only users with that named role; admin bypasses\n  perm:RESOURCE.ACTION - users whose role scopes include the permission\n  member-of:TABLE(JOIN_COL, USER_COL) - members of the row's room/channel/project (membership table EXISTS)\n  off       - endpoint returns 404 to everyone\n\nMost common typos: `anonn` → `anon`, `every` → `everyone`, `own` → `self`, `groups` → `group`. For chat / public feeds set `read: anon` (anon viewers see history) + `write: everyone` (only authed users post) + `delete: self` (authors delete their own). For private rooms/channels use `member-of:` - it replaces hand-written EXISTS guards in flows.", table, op, mode)
}

func knownYAMLKeysList() string {
	var keys []string
	for k := range knownAppYAMLKeys {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}

func knownAuthKeysList() string {
	var keys []string
	for k := range knownAuthKeys {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}

func validatePageContract(path, content string) string {
	if !strings.HasSuffix(strings.ToLower(path), ".html") {
		return ""
	}
	// Static-stack files (v2.4.0+ HTML scaffold) live under `static/`
	// and are served verbatim by the framework's clean-URL routing.
	// They are FULL HTML documents and do NOT go through the template
	// engine - no frontmatter required, no `<page>` wrapper.
	normPath := strings.ReplaceAll(path, "\\", "/")
	if strings.Contains(normPath, "static/") {
		// Static assets only get the form-security + antipattern checks;
		// skip the engine: raw / <page> contract entirely.
		if msg := validateFormSecurity(content); msg != "" {
			return msg
		}
		return ""
	}
	// Email templates are legitimately FULL HTML documents (email
	// clients want a complete doctype + head + inline styles), and they
	// are server-side templates, not pages - the "pages belong in
	// static/" rule doesn't apply. Same carve-out for templates/.
	if strings.HasPrefix(normPath, "emails/") || strings.Contains(normPath, "/emails/") ||
		strings.HasPrefix(normPath, "templates/") || strings.Contains(normPath, "/templates/") {
		return ""
	}
	// `engine: raw` pages are entire HTML documents (SPA shells) and
	// SHOULD start with <!doctype html>. They opt out of the page
	// contract - see template.go's raw branch.
	if detectRawEngine(content) {
		return ""
	}
	trimmed := strings.TrimLeftFunc(content, func(r rune) bool {
		return r == ' ' || r == '\t' || r == '\n' || r == '\r'
	})
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(lower, "<!doctype") || strings.HasPrefix(lower, "<html") || strings.HasPrefix(lower, "<head") || strings.HasPrefix(lower, "<body") {
		return "page contract: " + path + " is a full HTML document but it's at the app root, not under `static/`.\n\nBenmore's default stack (v2.4.0+) is vanilla HTML - put full documents in `static/`. The framework serves them verbatim with clean-URL routing (`/contacts` → `static/contacts.html`) and auto-injects the CSRF meta tag + analytics beacon. No frontmatter, no `<page>` wrapper, no engine declaration.\n\nFix: move this file to `static/" + path + "` (the user-facing URL stays the same).\n\nThe SEO-marketing alternative (gotmpl) is opt-in and uses body-only `<page>` content - only reach for it when crawlers need server-rendered HTML at the request path. Do NOT add `engine: raw` frontmatter to make this validator pass; that's a legacy mode kept only for backwards-compat with React-stack apps and shouldn't be used in new code."
	}
	if msg := validateFormSecurity(content); msg != "" {
		return msg
	}
	if msg := detectFrameworkAntipatterns(path, content); msg != "" {
		return msg
	}
	if strings.HasSuffix(strings.ToLower(path), "app.yaml") {
		if msg := validateAppYAML(content); msg != "" {
			return msg
		}
	}
	return ""
}

// antipattern is one of the known agent-training-prior mistakes the
// write_file/edit_file path checks for. Each entry includes the
// regex that detects it, the file extensions it applies to (empty =
// any), and a description that gets surfaced to the agent.
//
// Goal: write_file rejects with a hyper-specific error so the agent
// learns the framework's actual contract at write time, instead of
// shipping broken pages and burning turns on debug spirals.
//
// Detection precision > coverage. Each pattern here is a near-zero-
// false-positive signature. If a pattern catches legitimate code we
// should narrow it, not loosen the check.
type antipattern struct {
	name        string         // short id used in the error message
	re          *regexp.Regexp // matches the wrong syntax
	exts        []string       // restrict to these extensions (".html", ".yaml", ...). Empty = any text file
	description string         // shown to the agent verbatim
	// mustacheOnly skips the check when the page is in gotmpl mode.
	// Some "antipatterns" are wrong in custom-mustache but correct
	// in Go html/template (e.g. {{else if}}, {{with}}). For those,
	// only fire when we're confident the file ISN'T gotmpl.
	mustacheOnly bool
}

var antipatterns = []antipattern{
	// ===== Templating from other frameworks =====
	{
		name:        "mustache-partial",
		re:          regexp.MustCompile(`\{\{\s*>\s*[\w./-]+\s*\}\}`),
		exts:        []string{".html"},
		description: "Mustache partial syntax `{{>name}}` is from Mustache/Handlebars. Benmore uses `<include src=\"partials/<name>.html\" />` - the file gets text-substituted into the page before mustache rendering. {{>...}} is silently dropped by the parser.",
	},
	{
		name:        "handlebars-each",
		re:          regexp.MustCompile(`\{\{\s*#\s*each\s+`),
		exts:        []string{".html"},
		description: "`{{#each items}}` is Handlebars syntax. Benmore uses mustache sections: `{{#items}}…{{/items}}`. Inside the section, fields reference the current row directly (e.g. `{{name}}`).",
	},
	{
		name:        "handlebars-unless",
		re:          regexp.MustCompile(`\{\{\s*#\s*unless\s+`),
		exts:        []string{".html"},
		description: "`{{#unless x}}` is Handlebars syntax. Benmore uses inverted mustache sections: `{{^x}}…{{/x}}` renders when x is empty/falsy.",
	},
	{
		name: "handlebars-elseif",
		re:   regexp.MustCompile(`\{\{\s*else\s+if\s+`),
		exts: []string{".html"},
		// In gotmpl, `{{else if}}` is the standard Go html/template
		// chained-conditional syntax - totally valid. Only flag in
		// mustache files where it's a Handlebars import that the
		// custom mustache engine doesn't grok.
		mustacheOnly: true,
		description:  "`{{else if}}` isn't supported in mustache. Use chained `{{#if x}}...{{/if}}{{#if y}}...{{/if}}` blocks. (In a gotmpl page - `engine: gotmpl` in frontmatter - `{{else if eq .x \"y\"}}` IS valid and works as expected.)",
	},
	{
		name: "handlebars-with",
		re:   regexp.MustCompile(`\{\{\s*#\s*with\s+`),
		exts: []string{".html"},
		// `{{with}}` is valid in Go html/template (`{{with .x}}...{{end}}`)
		// but uses the `{{#with}}` syntax only in Handlebars. We flag the
		// `{{#with}}` form, which is wrong in both engines. Gotmpl's
		// `{{with .x}}` (no `#`) isn't matched by the regex.
		description: "`{{#with obj}}` isn't supported. In mustache use dot notation directly: `{{user.email}}`, `{{stats.n}}`. In gotmpl use `{{with .user}}...{{.email}}...{{end}}` (no `#`).",
	},
	// ===== Vue.js patterns =====
	{
		name:        "vue-v-directive",
		re:          regexp.MustCompile(`\bv-(?:if|else|else-if|for|show|on|bind|model|html|text|cloak|once|pre|slot)\b`),
		exts:        []string{".html"},
		description: "Vue `v-*` directive detected. Benmore directives use a colon prefix: `:create=\"table\"`, `:patch=\"/api/x/{{id}}\"`, `:delete=\"table\"`, `:set=\"field=value\"`, `:validate=\"required,email\"`, `:confirm=\"…\"`. For conditionals use `{{#if}}` mustache; for loops use `{{#items}}…{{/items}}`.",
	},
	{
		name:        "vue-shorthand-event",
		re:          regexp.MustCompile(`\s@(?:click|input|change|submit|keydown|keyup|keypress|focus|blur|mouseover|mouseout)\s*=`),
		exts:        []string{".html"},
		description: "Vue `@event` shorthand detected. Benmore is server-rendered; use `:create`/`:patch`/`:delete` directives for form submission, plain `<a href>` for navigation, or a `<script>` block with `addEventListener` for custom client-side behavior.",
	},

	// ===== React / JSX patterns =====
	{
		name: "react-classname",
		// Match the JSX attribute form (`<div className="...">`) but NOT
		// the JavaScript DOM property form (`el.className = "..."`), which
		// is valid vanilla JS. The leading `[^.\w]` excludes a preceding
		// `.` (property access) and any word char (so `myClassName` and
		// `foo.className` don't trip). RE2 has no lookbehind, so we
		// consume one char as a guard - that's fine, the match still
		// identifies the offending `className=`.
		re:          regexp.MustCompile(`(?:^|[^.\w])className\s*=`),
		exts:        []string{".html"},
		description: "`className=` looks like React/JSX. In Benmore HTML it's `class=` (lowercase). If you're writing JavaScript (e.g. `element.className = 'foo'`), that's valid vanilla DOM and the linter should NOT have flagged it - the regex is dot-aware, so make sure the `.` before `className` isn't being stripped.",
	},
	{
		name:        "react-htmlfor",
		re:          regexp.MustCompile(`\bhtmlFor\s*=`),
		exts:        []string{".html"},
		description: "`htmlFor=` is React/JSX. In HTML it's `for=` (lowercase). Benmore renders server-side HTML.",
	},
	{
		name:        "react-camelCase-event",
		re:          regexp.MustCompile(`\b(?:onClick|onChange|onSubmit|onInput|onKeyDown|onKeyUp|onFocus|onBlur|onMouseOver|onMouseOut)\s*=`),
		exts:        []string{".html"},
		description: "React-style camelCase event handlers detected (e.g. `onClick=`). Benmore is server-rendered; use lowercase `onclick=` if you really need inline JS (CSP may block it), or `:create`/`:patch`/`:delete` directives for form submission, or `<script>` with `addEventListener`.",
	},

	// ===== Angular patterns =====
	{
		name:        "angular-directive",
		re:          regexp.MustCompile(`\b(?:ng-(?:if|for|repeat|model|click|show|hide|class|style|bind|src|href)|\[\([\w]+\)\]|\*ng[A-Z])`),
		exts:        []string{".html"},
		description: "Angular directive detected (e.g. `ng-if`, `*ngFor`, `[(ngModel)]`). Benmore uses mustache for templating and `:create`/`:patch`/`:delete` for form wiring.",
	},

	// ===== Fabricated routes =====
	{
		name:        "fabricated-auth-route",
		re:          regexp.MustCompile(`(?:href|action)\s*=\s*["']/auth/(?:login|signup|signin|signout|logout|register|forgot-password|reset-password)`),
		exts:        []string{".html"},
		description: "Fabricated auth route detected: Benmore's auth routes are FLAT - `/login`, `/signup`, `/logout`, `/forgot-password`, `/reset-password`, `/verify-email`, `/verify-mfa`, `/settings`. There is no `/auth/` prefix and never will be. Update the href/action to the flat path.",
	},
	{
		name:        "fabricated-api-auth",
		re:          regexp.MustCompile(`(?:href|action)\s*=\s*["']/api/(?:auth|users|v1|v2)/`),
		exts:        []string{".html"},
		description: "Fabricated API route detected. Benmore's API surface is `/api/<table>` for auto-CRUD and `/api/_*` for framework internals (`/api/_auth/*`, `/api/_notifications`, `/api/_audit`). There is no `/api/auth/...` or `/api/v1/...`. For login/signup/logout, POST to the flat `/login`/`/signup`/`/logout` paths (set up by the framework when `auth:` is configured in app.yaml).",
	},

	// ===== Wrong assets =====
	{
		name:        "external-css-cdn",
		re:          regexp.MustCompile(`<link[^>]+href\s*=\s*["']https?://(?:cdn\.tailwindcss\.com|unpkg\.com/tailwindcss|cdn\.jsdelivr\.net/npm/tailwindcss)`),
		exts:        []string{".html"},
		description: "Loading Tailwind from a CDN - Benmore bundles Tailwind internally and auto-injects it when `css: tailwind` is set in app.yaml. Remove the `<link>` tag; Tailwind is already there.",
	},

	// ===== Tag misuse =====
	{
		name:        "doctype-in-page",
		re:          regexp.MustCompile(`(?i)<!doctype\b`),
		exts:        []string{".html"},
		description: "`<!DOCTYPE html>` doesn't belong in a Benmore page file. The framework wraps your content in its own complete HTML document. Pages start with `<page title=\"…\">…</page>` containing ONLY the body content.",
	},
	{
		name:        "html-tag-in-page",
		re:          regexp.MustCompile(`(?i)<html\b|</html>|<body\b|</body>|<head\b|</head>`),
		exts:        []string{".html"},
		description: "`<html>`/`<body>`/`<head>` tags don't belong in a Benmore page file. The framework wraps your content in its own complete HTML document. Pages start with `<page title=\"…\">…</page>` containing ONLY the body content; put `<style>` blocks INSIDE the `<page>` tag.",
	},
	{
		name:        "nested-page",
		re:          regexp.MustCompile(`<page\b[^>]*>[\s\S]*?<page\b`),
		exts:        []string{".html"},
		description: "Nested `<page>` tags detected. There is exactly ONE `<page>` wrapper per page file. Layouts (`layouts/*.html`) use `{{body}}` to inject child page content.",
	},

	// ===== SPA antipatterns (React+TypeScript bundle source) =====
	// Fire on src/*.{tsx,jsx,ts,js} - the React entry points compiled
	// by esbuild at every app load. The framework auto-injects React,
	// ReactDOM, Lucide, and bm.js for engine: raw pages, so the LLM
	// doesn't need to reach for CDNs, manage CSRF manually, stash
	// tokens in localStorage, or wire up ReactDOM.createRoot.
	{
		name:        "jsx-cdn-react",
		re:          regexp.MustCompile(`(?:unpkg\.com|cdn\.jsdelivr\.net|esm\.sh|cdn\.skypack\.dev)/(?:react|react-dom|@babel/|lucide|bm)`),
		exts:        []string{".tsx", ".jsx", ".ts", ".js", ".html"},
		description: "Loading React/ReactDOM/Lucide/bm from a CDN - the framework embeds these and serves them at /_internal/react.js, /_internal/react-dom.js, /_internal/lucide.js, /_internal/bm.js, and auto-injects all four on every engine: raw page. The compiler also resolves named imports like `import { useState } from 'react'`, `import { useTable } from 'bm'`, `import { Button } from 'bm/ui'` to window globals automatically. Drop the CDN entirely; the globals (React, ReactDOM, lucide, bm) are already on window when your bundle runs.",
	},
	{
		name:        "spa-cdn-import",
		re:          regexp.MustCompile(`import\s+(?:[\w*\s,{}]+\s+from\s+)?["'](?:https?:|//)[^"']+["']`),
		exts:        []string{".tsx", ".jsx", ".ts", ".js"},
		description: "Importing from an absolute URL (CDN, ESM service, etc.) in a bundle file. esbuild can't fetch remote modules during the framework's build step - this will fail compilation. The framework provides everything you need without a CDN: `import { useState } from 'react'`, `import { useTable, useAuth } from 'bm'`, `import { Button, Card } from 'bm/ui'`. These resolve to embedded window globals at build time. For anything else, write a custom flow in flows.yaml or fetch via bm.api() at runtime.",
	},
	{
		name:        "spa-react-createroot",
		re:          regexp.MustCompile(`\b(?:ReactDOM\.)?(?:createRoot|hydrateRoot)\s*\(`),
		exts:        []string{".tsx", ".jsx", ".ts", ".js"},
		description: "Calling ReactDOM.createRoot() / hydrateRoot() directly. Use `bm.mount(target, <Root />)` instead - it picks createRoot vs hydrateRoot automatically based on whether the page was prerendered, so the same code works whether SSR is on or off. The shape is identical to createRoot:\n  bm.mount(document.getElementById('root')!, <Root />);",
	},
	{
		name:        "jsx-localstorage-auth",
		re:          regexp.MustCompile(`localStorage\.(?:setItem|getItem)\s*\(\s*['"](?:token|access_token|auth_token|jwt|csrf|csrf_token|session|user_id)['"]`),
		exts:        []string{".tsx", ".jsx", ".ts", ".js"},
		description: "Stashing auth/CSRF/session data in localStorage. Benmore uses HttpOnly session cookies - the browser attaches them automatically on same-origin fetches, and they're inaccessible to XSS. CSRF tokens are HMAC-derived and read from <meta name=\"csrf-token\"> (already in the document). bm.api() and bm.useAuth() handle all of this - don't roll your own.",
	},
	{
		name:        "jsx-mass-assign-userid",
		re:          regexp.MustCompile(`['"]user_?id['"]\s*:\s*(?:user\.id|me\.id|currentUser|session)`),
		exts:        []string{".tsx", ".jsx", ".ts", ".js"},
		description: "Putting `user_id` into a CRUD body. The framework REJECTS protected fields (user_id, role, password_hash, created_at) from client writes - handleCreate strips them before the INSERT. Owner scoping is automatic: a POST /api/<table> uses the session's user_id server-side, no client involvement needed. Just drop the field from the body.",
	},
	{
		name:        "jsx-window-reload",
		re:          regexp.MustCompile(`window\.location\.reload\s*\(`),
		exts:        []string{".tsx", ".jsx", ".ts", ".js"},
		description: "Calling window.location.reload() defeats the SPA. bm.useTable() and bm.useRecord() subscribe to the invalidation bus and refetch automatically after any mutation (local bm.api(), HX-Trigger benmore:changed events, or cross-tab SSE). If you need to force a refresh: call the hook's .refresh() method, or bm.invalidate('table_name').",
	},
	{
		name:        "jsx-bare-fetch-mutation",
		re:          regexp.MustCompile(`\bfetch\s*\(\s*['"]/api/[^'"]+['"]\s*,\s*\{\s*method\s*:\s*['"](?:POST|PATCH|PUT|DELETE)['"]`),
		exts:        []string{".tsx", ".jsx", ".ts", ".js"},
		description: "Raw fetch() with a mutation method against /api/. This works but you lose CSRF auto-attachment, error normalization, and the invalidation bus that powers bm.useTable refetches. Prefer: bm.useTable('<table>').create(...) / .update(id, ...) / .remove(id), or bm.api('POST', '/api/<custom>', body) for non-CRUD endpoints. CSRF and credentials are handled.",
	},
	{
		name:        "jsx-dangerously-set",
		re:          regexp.MustCompile(`dangerouslySetInnerHTML\s*=`),
		exts:        []string{".tsx", ".jsx", ".ts", ".js"},
		description: "dangerouslySetInnerHTML is an XSS vector - values are injected as raw HTML without escaping. React's default `{value}` interpolation handles ~all UI safely. If you genuinely need to render HTML (e.g. server-sanitized markdown), use the framework's bm/ui <Markdown> component (already sanitized) or sanitize externally with DOMPurify. Reach for this only when you've made a deliberate decision.",
	},

	// ===== v2.7.27-v2.7.30 SDK footguns =====
	//
	// Each pattern catches a near-zero-false-positive shape that
	// silently fails at runtime. The regex matches the wrong usage;
	// the description prescribes the right one.

	{
		// SSE events carry only { table, action } - no row data. Agents
		// who reach for `ev.row.body` / `event.row.title` etc. silently
		// get undefined and the UI looks broken. The correct pattern is
		// the cursor-based fetch - see docs/agent/build.md "Real-time".
		name:        "sse-row-access",
		re:          regexp.MustCompile(`\bev(?:ent)?\.row\.\w+`),
		exts:        []string{".tsx", ".ts", ".jsx", ".js"},
		description: "antipattern [sse-row-access]: SSE/bm.live events carry only { table, action } - there is NO `row` field. `ev.row.X` resolves to undefined. The correct pattern is the cursor-based fetch: keep a `lastId` cursor; on each event, fetch the latest rows from the table API and append any newer than lastId.\n\n  let lastId = 0;\n  const seen = new Set<number>();\n  async function refresh() {\n    const rows = await bm.api.get(`/api/messages?orderBy=id:asc&limit=200`);\n    for (const m of rows) {\n      if (seen.has(m.id) || m.id <= lastId) continue;\n      appendChat(m); seen.add(m.id); lastId = m.id;\n    }\n  }\n  await refresh();\n  bm.live('messages', () => refresh());\n\nSee docs/agent/build.md → Real-time, or api({at:'sse'}).",
	},

	{
		// Hardcoded STUN servers when bm.webrtc.iceServers() exists.
		// Apps that pin Google's STUN miss out on platform-provisioned
		// TURN (the v2.7.28 feature that makes cellular subscribers
		// actually connect). Pure regex - the literal URL is a strong
		// signal the agent didn't reach for the SDK.
		name:        "webrtc-hardcoded-stun",
		re:          regexp.MustCompile(`stun:stun\.l\.google\.com:19302`),
		exts:        []string{".tsx", ".ts", ".jsx", ".js"},
		description: "antipattern [webrtc-hardcoded-stun]: hardcoded Google STUN URL. The framework ships `bm.webrtc.iceServers()` (v2.7.28+) which returns STUN + platform-provisioned TURN - required for cellular subscribers to actually connect (most carriers run address-restricted-cone NAT that drops UDP without a TURN relay). Replace:\n\n  // ❌ doesn't work for cellular viewers\n  const pc = new RTCPeerConnection({\n    iceServers: [{ urls: 'stun:stun.l.google.com:19302' }],\n  });\n\n  // ✅ STUN + TURN, fleet-wide creds, time-limited tokens\n  const ice = await bm.webrtc.iceServers();\n  const pc = new RTCPeerConnection({ iceServers: ice });\n\nFor livestream specifically, use bm.broadcast.publish/subscribe instead of hand-rolling peer-mesh - it routes through Cloudflare's SFU and scales to hundreds of viewers. See api({at:'webrtc'}).",
	},

	{
		// Old peer-mesh signaling pattern for streams. If the agent
		// writes `bm.room('stream:XXX')` AND uses RTCPeerConnection +
		// getUserMedia, they're hand-rolling a livestream - which
		// chokes at 5 viewers. bm.broadcast is the right primitive.
		// Multi-line check: regex matches common stream room names.
		name:        "peer-mesh-stream-room",
		re:          regexp.MustCompile(`bm\.room\(\s*['"\x60](?:stream|broadcast|live):`),
		exts:        []string{".tsx", ".ts", ".jsx", ".js"},
		description: "antipattern [peer-mesh-stream-room]: `bm.room('stream:…')` paired with RTCPeerConnection is hand-rolled peer-mesh livestream. Peer-mesh chokes at ~5 viewers because the publisher uploads N copies through its own uplink. Use `bm.broadcast.{publish,subscribe}` instead - routes through Cloudflare's SFU, publisher uploads ONCE, scales to hundreds:\n\n  // Publisher\n  const stream = await navigator.mediaDevices.getUserMedia({video:true, audio:true});\n  const pub = await bm.broadcast.publish('my-slug', stream);\n\n  // Viewer\n  videoEl.muted = true;     // CRITICAL - browsers block autoplay-with-sound\n  const sub = await bm.broadcast.subscribe('my-slug');\n  videoEl.srcObject = sub.stream;\n\nIf this is genuinely a small (≤4-person) video CALL - not a livestream - keep bm.room signaling but rename the room from `stream:` to `call:` or similar so the validator doesn't fire. See api({at:'webrtc'}).",
	},
}

// detectFrameworkAntipatterns scans a write for known training-prior
// mistakes and returns the first violation's actionable error. Empty
// return means clean.
func detectFrameworkAntipatterns(path, content string) string {
	lowerPath := strings.ToLower(path)
	isHTML := strings.HasSuffix(lowerPath, ".html")
	isJSX := strings.HasSuffix(lowerPath, ".jsx")
	// `engine: raw` pages opt out of HTML-template validation. SPA
	// bundles can use JSX, mustache-looking braces, Vue syntax,
	// whatever - the framework serves the doc verbatim. JSX-specific
	// rules still fire on src/*.jsx files (see ext filter below).
	if isHTML && detectRawEngine(content) {
		return ""
	}
	isGotmpl := isHTML && detectGotmplEngine(content)
	_ = isJSX

	for _, ap := range antipatterns {
		if len(ap.exts) > 0 {
			ok := false
			for _, e := range ap.exts {
				if strings.HasSuffix(lowerPath, e) {
					ok = true
					break
				}
			}
			if !ok {
				continue
			}
		}
		// Skip mustache-only antipatterns when we know the file is
		// gotmpl - the same syntax is correct there.
		if ap.mustacheOnly && isGotmpl {
			continue
		}
		if m := ap.re.FindString(content); m != "" {
			return fmt.Sprintf("antipattern [%s] in %s: matched %q. %s", ap.name, path, strings.TrimSpace(m), ap.description)
		}
	}

	// gotmpl-specific antipatterns. These catch mustache / framework-directive
	// leakage into a file the agent declared as `engine: gotmpl`. The most
	// likely cause is the agent partway-migrated a page and left some old-shape
	// symbols behind - we want immediate feedback so it doesn't ship.
	if isGotmpl {
		if v := detectGotmplLeakage(path, content); v != "" {
			return v
		}
	}

	// Dead-form check (stateful - needs to inspect form bodies, not just regex)
	if isHTML {
		for _, m := range formBlockRe.FindAllStringSubmatch(content, -1) {
			if len(m) < 3 {
				continue
			}
			attrs, body := m[1], m[2]
			if !strings.Contains(body, "<input") && !strings.Contains(body, "<textarea") && !strings.Contains(body, "<select") {
				continue
			}
			if strings.Contains(attrs, ":create=") || strings.Contains(attrs, ":patch=") {
				continue
			}
			// HTMX wires the form: hx-post / hx-put / hx-patch on the <form>
			// element submits it. Correct in both engines, primary shape in
			// gotmpl. Don't flag as dead.
			if strings.Contains(attrs, "hx-post=") || strings.Contains(attrs, "hx-put=") || strings.Contains(attrs, "hx-patch=") {
				continue
			}
			methodMatch := formMethodAttrRe.FindStringSubmatch(attrs)
			if len(methodMatch) >= 2 && strings.ToUpper(methodMatch[1]) == "POST" {
				continue
			}
			if isGotmpl {
				return "antipattern [dead-form] in " + path + ": <form> in a gotmpl page needs explicit wiring. Either:\n\n  HTMX (preferred, server-rendered partial swap):\n    <form hx-post=\"/api/notes\" hx-target=\"#list\" hx-swap=\"afterbegin\">\n      <input name=\"title\" required>\n      <button>Add</button>\n    </form>\n\n  Plain POST (full-page navigation):\n    <form method=\"POST\" action=\"/some-route\">\n      <input name=\"title\" required>\n      <button>Add</button>\n    </form>\n\n  In gotmpl, do NOT use `:create=\"...\"` - that's a mustache-only directive."
			}
			return "antipattern [dead-form] in " + path + ": <form> contains input/textarea/select elements but has NO submission wiring - no `:create=`, no `:patch=`, no `method=\"POST\"`, no `hx-post=`. Browser default is GET, which sends values into the URL and does nothing useful. Wire it:\n\n  Preferred - `:create` posts to the framework's auto-CRUD endpoint with CSRF + HTMX swap:\n    <form :create=\"tasks\">\n      <input name=\"title\" required>\n      <button>Add</button>\n    </form>\n\n  Plain HTML - explicit POST to a route you handle yourself (in flows.yaml):\n    <form method=\"POST\" action=\"/some-route\">\n      <input type=\"hidden\" name=\"_csrf\" value=\"{{csrf}}\">\n      <input name=\"title\" required>\n      <button>Add</button>\n    </form>"
		}

		// Nested forms - HTML forbids them. Browsers silently drop the inner
		// <form>, so submit handlers never fire and CSRF tokens leak from the
		// wrong form. Agents reach for this when adding a "delete" button
		// inside a task <li>; the fix is hx-delete on the button, no form.
		if msg := detectNestedForms(path, content); msg != "" {
			return msg
		}

		// _method=DELETE / _method=PATCH override. Benmore doesn't translate
		// these - only Rails/Laravel do. Agents reach for this when the
		// framework rejects PATCH in a plain HTML form (forms only support
		// GET/POST). The fix is HTMX: hx-delete / hx-patch on a button.
		if methodOverrideRe.MatchString(content) {
			return "antipattern [method-override] in " + path + ": `<input name=\"_method\" value=\"DELETE\">` (or similar) doesn't work in Benmore - the framework doesn't translate `_method` overrides like Rails/Laravel. HTML forms only support GET/POST. To send a real PATCH/DELETE, use HTMX:\n  <button hx-delete=\"/api/tasks/{{id}}\" hx-confirm=\"Delete?\">×</button>\n  <input type=\"checkbox\" hx-patch=\"/api/tasks/{{id}}\" hx-vals='js:{completed: event.target.checked}'>\nCSRF auto-injects from the <meta name=\"csrf-token\"> tag on any HTMX request - no token needed in the body."
		}

		// <form> posting to /api/... must include CSRF in the body (since it's
		// a plain HTML form, not HTMX - HTMX gets CSRF from the meta tag).
		if msg := detectFormMissingCSRF(path, content); msg != "" {
			return msg
		}

		// :patch / hx-patch to /api/<table>/ (trailing slash + no ID) or to
		// /api/<table> with no ID resolution. The framework now supports
		// singleton upsert for tables with UNIQUE(user_id), but only those -
		// catch the common mistake of patching a list endpoint by accident.
		if msg := detectPatchMissingID(path, content); msg != "" {
			return msg
		}
	}

	return ""
}

// methodOverrideRe catches `<input name="_method" value="DELETE">` and the
// quote-flipped variant. Benmore doesn't honor method override - agents
// learn this pattern from Rails/Laravel and it silently fails.
var methodOverrideRe = regexp.MustCompile(`(?i)<input[^>]*name\s*=\s*["']_method["']`)

// detectNestedForms returns a fix-style error message when a <form> contains
// another <form>. HTML doesn't allow this; the inner form is dropped by the
// parser and its submit handler never runs. Agents hit this trying to put a
// "delete" form inside a list item that's already inside an outer form.
func detectNestedForms(path, content string) string {
	// Find each outer <form>'s span. Track the open tag positions via a
	// stack; any <form> opened while the stack is non-empty is nested.
	lower := strings.ToLower(content)
	depth := 0
	i := 0
	for i < len(lower) {
		openIdx := strings.Index(lower[i:], "<form")
		closeIdx := strings.Index(lower[i:], "</form")
		if openIdx == -1 && closeIdx == -1 {
			break
		}
		// pick whichever comes first
		next := openIdx
		isOpen := true
		if closeIdx != -1 && (openIdx == -1 || closeIdx < openIdx) {
			next = closeIdx
			isOpen = false
		}
		if isOpen {
			depth++
			if depth >= 2 {
				return "antipattern [nested-form] in " + path + ": HTML doesn't allow <form> inside another <form> - the browser silently drops the inner one, so its CSRF token and submit handler never fire. This is the #1 cause of \"Invalid CSRF token\" errors in tight loops. Replace the inner form with an HTMX button:\n  <button hx-delete=\"/api/tasks/{{id}}\" hx-target=\"closest li\" hx-swap=\"outerHTML\" hx-confirm=\"Delete?\">×</button>\n  <input type=\"checkbox\" hx-patch=\"/api/tasks/{{id}}\" hx-vals='js:{completed: event.target.checked}'>\nNo form needed - HTMX submits the request directly with CSRF auto-attached from the <meta name=\"csrf-token\"> tag."
			}
		} else {
			depth--
			if depth < 0 {
				depth = 0
			}
		}
		i += next + 5
	}
	return ""
}

// detectFormMissingCSRF flags a plain <form> that posts to /api/... but has
// no {{csrf}} reference or _csrf input. Such forms 403 with "Invalid CSRF
// token" - the agent's most-burned-turns failure mode. HTMX forms are fine
// (CSRF comes from the meta header), so we only check plain method=POST.
func detectFormMissingCSRF(path, content string) string {
	for _, m := range formBlockRe.FindAllStringSubmatch(content, -1) {
		if len(m) < 3 {
			continue
		}
		attrs, body := m[1], m[2]
		methodMatch := formMethodAttrRe.FindStringSubmatch(attrs)
		if len(methodMatch) < 2 || strings.ToUpper(methodMatch[1]) != "POST" {
			continue
		}
		// HTMX form: CSRF flows via header on submit, no body field needed.
		if strings.Contains(attrs, "hx-post=") || strings.Contains(attrs, "hx-put=") || strings.Contains(attrs, "hx-patch=") || strings.Contains(attrs, "hx-delete=") {
			continue
		}
		// Form posts to a real route - check action looks like /api/ or /flow/.
		actionMatch := formActionAttrRe.FindStringSubmatch(attrs)
		if len(actionMatch) < 2 {
			continue
		}
		action := actionMatch[1]
		if !strings.HasPrefix(action, "/api/") && !strings.HasPrefix(action, "/flow/") {
			continue
		}
		// Body must reference the CSRF token.
		if strings.Contains(body, "{{csrf}}") || strings.Contains(body, "{{.csrf}}") || strings.Contains(body, "{{ csrf ") || strings.Contains(body, "name=\"_csrf\"") || strings.Contains(body, "name='_csrf'") {
			continue
		}
		return "antipattern [form-missing-csrf] in " + path + ": <form method=\"POST\" action=\"" + action + "\"> has no CSRF token, so Benmore will reject it with 403 Invalid CSRF token. Two fixes:\n\n  Add the token to the form body (plain HTML):\n    <input type=\"hidden\" name=\"_csrf\" value=\"{{csrf}}\">  (mustache)\n    <input type=\"hidden\" name=\"_csrf\" value=\"{{.csrf}}\">  (gotmpl: use the csrf helper)\n\n  Or switch to HTMX (CSRF auto-attaches from <meta name=\"csrf-token\">):\n    <form hx-post=\"" + action + "\" hx-target=\"#list\" hx-swap=\"afterbegin\">"
	}
	return ""
}

// detectPatchMissingID catches `hx-patch=\"/api/tasks/\"` and similar - a
// PATCH against the list endpoint with no row ID. Returns 400 unless the
// table is a singleton (UNIQUE(user_id)). We can't know the table shape at
// lint time, so we warn with the two valid shapes and let the agent pick.
func detectPatchMissingID(path, content string) string {
	for _, m := range patchNoIDRe.FindAllStringSubmatch(content, -1) {
		if len(m) < 2 {
			continue
		}
		table := m[1]
		return "antipattern [patch-missing-id] in " + path + ": hx-patch / :patch targets `/api/" + table + "/` with no row ID. The framework returns \"Missing ID\" 400 unless the table is a per-user singleton (one row, UNIQUE(user_id) - e.g. settings, profile). Two valid shapes:\n\n  Update a specific row:\n    <input type=\"checkbox\" hx-patch=\"/api/" + table + "/{{id}}\" hx-vals='js:{completed: event.target.checked}'>\n\n  Singleton upsert (only if " + table + " has UNIQUE(user_id)):\n    <form hx-patch=\"/api/" + table + "\" hx-target=\"this\">  ← no trailing slash, no ID\n      <input name=\"bio\" value=\"{{profile.bio}}\">\n    </form>"
	}
	return ""
}

// patchNoIDRe matches hx-patch or :patch attributes pointing at /api/<table>/
// (trailing slash) with no ID after it. Captures the table name.
var patchNoIDRe = regexp.MustCompile(`(?:hx-patch|:patch)\s*=\s*["']/api/([a-z_][a-z0-9_]*)/["']`)

// formActionAttrRe extracts the action="..." value from a <form> tag's
// attribute string.
var formActionAttrRe = regexp.MustCompile(`(?i)\baction\s*=\s*["']([^"']+)["']`)

// detectGotmplEngine checks whether a page declared `engine: gotmpl` in
// its frontmatter. Cheap heuristic - looks for the literal string inside
// the leading `---`-fenced block. Avoids pulling in the yaml parser at
// detector time.
func detectGotmplEngine(content string) bool {
	if !strings.HasPrefix(content, "---") {
		return false
	}
	end := strings.Index(content[3:], "\n---")
	if end == -1 {
		return false
	}
	fm := content[3 : 3+end]
	return gotmplEngineRe.MatchString(fm)
}

// detectRawEngine checks whether a page declared `engine: raw`. Raw
// pages opt out of ALL template scanning - they're SPAs / static HTML
// bundles where double-braces and colon-prefixed attrs are real syntax
// (React's `${x}`, Vue's `:class`, etc.), not Benmore framework
// directives. Validators must skip them entirely.
func detectRawEngine(content string) bool {
	if !strings.HasPrefix(content, "---") {
		return false
	}
	end := strings.Index(content[3:], "\n---")
	if end == -1 {
		return false
	}
	fm := content[3 : 3+end]
	return rawEngineRe.MatchString(fm)
}

// isSPASource returns true if the (lowercased) path is a React/TS
// bundle source. Mirrors validators_write.go's isSPASourceFile.
var rawEngineRe = regexp.MustCompile(`(?m)^\s*engine\s*:\s*["']?raw["']?\s*$`)

var gotmplEngineRe = regexp.MustCompile(`(?m)^\s*engine\s*:\s*["']?gotmpl["']?\s*$`)

// detectGotmplLeakage catches the old-shape symbols the agent will most
// likely sprinkle into a gotmpl file mid-migration. Each match returns a
// concrete fix in the message - the linter teaches the model the
// translation, not just flags the symptom.
func detectGotmplLeakage(path, content string) string {
	// Strip the frontmatter block so the YAML's own `:` characters don't
	// trip the directive regexes. The body is what we're auditing.
	body := content
	if strings.HasPrefix(body, "---") {
		if idx := strings.Index(body[3:], "\n---"); idx != -1 {
			// Skip past the closing fence + its newline.
			body = body[3+idx+4:]
		}
	}

	type gotmplCheck struct {
		name string
		re   *regexp.Regexp
		desc string
	}
	checks := []gotmplCheck{
		{
			name: "mustache-section",
			re:   regexp.MustCompile(`\{\{\s*#\s*[\w.]+\s*\}\}`),
			desc: "Mustache section `{{#x}}…{{/x}}` is the legacy engine. In gotmpl, iterate with `{{range .x}}…{{else}}…{{end}}` and access fields as `{{.field}}` (note the leading dot). Empty-state goes in the `{{else}}` branch.",
		},
		{
			name: "mustache-inverted",
			re:   regexp.MustCompile(`\{\{\s*\^\s*[\w.]+\s*\}\}`),
			desc: "Mustache inverted section `{{^x}}` is the legacy engine. In gotmpl, use the `{{else}}` branch of a `{{range}}` or `{{if}}` block instead.",
		},
		{
			name: "mustache-if-comparison",
			re:   regexp.MustCompile(`\{\{\s*#\s*if\s+`),
			desc: "Mustache `{{#if x = \"y\"}}` is the legacy engine. In gotmpl, use `{{if eq .x \"y\"}}…{{else}}…{{end}}` (eq/ne/gt/lt/ge/le are the comparison functions). Fields use a leading dot.",
		},
		{
			name: "mustache-role-section",
			re:   regexp.MustCompile(`\{\{\s*#\s*role\s+`),
			desc: "`{{#role \"admin\"}}` is the legacy engine. In gotmpl, use `{{if eq .user.role \"admin\"}}…{{end}}`.",
		},
		{
			name: "mustache-pipe",
			re:   regexp.MustCompile(`\{\{[^}]*\|\s*(?:upper|lower|title|truncate|currency|cents|number|percent|date|ago|digits|count|md5|sha256|base64|urlencode|first|last|initials|default|pluralize|json|strip_html|nl2br|slug)\b`),
			desc: "Mustache pipe (`{{x | upper}}`) is the legacy engine. In gotmpl, use Go template's pipe to a real function - e.g. `{{.x | upper}}` works only if you register an `upper` func in the FuncMap. The framework's gotmpl FuncMap is intentionally small: `csrf`, `env`, `t`, `dict`. For formatting, do it in the frontmatter (real TypeScript-ish JavaScript… err, Go expressions) or use template helpers like `printf`.",
		},
		{
			name: "page-tag-in-gotmpl",
			re:   regexp.MustCompile(`(?i)<page\b`),
			desc: "`<page>` tag is the legacy engine's page-attribute carrier. In gotmpl the YAML frontmatter at the top already declares title/auth/scope/layout - delete the `<page>` tag.",
		},
		{
			name: "include-tag-in-gotmpl",
			re:   regexp.MustCompile(`(?i)<include\s+src=`),
			desc: "`<include src=\"...\" />` is the legacy engine's partial syntax. In gotmpl, files in `partials/` are auto-registered as named templates - invoke them with `{{template \"partial-name\" .}}`.",
		},
		{
			name: "create-directive-in-gotmpl",
			re:   regexp.MustCompile(`\s:create\s*=`),
			desc: "`:create=\"table\"` is a mustache-only directive. In gotmpl, write the HTMX attrs explicitly:\n  <form hx-post=\"/api/<table>\" hx-target=\"#list\" hx-swap=\"afterbegin\">\nThe framework still validates CSRF - it auto-injects the meta tag and the htmx:configRequest listener.",
		},
		{
			name: "patch-directive-in-gotmpl",
			re:   regexp.MustCompile(`\s:patch\s*=`),
			desc: "`:patch=\"/api/...\"` is a mustache-only directive. In gotmpl, use the raw HTMX attr:\n  <button hx-patch=\"/api/contacts/{{.id}}\" hx-vals='{\"archived\": 1}'>Archive</button>",
		},
		{
			name: "delete-directive-in-gotmpl",
			re:   regexp.MustCompile(`\s:delete\s*=`),
			desc: "`:delete=\"table\" :id=\"{{id}}\"` is a mustache-only directive. In gotmpl:\n  <button hx-delete=\"/api/<table>/{{.id}}\" hx-target=\"closest article\" hx-swap=\"outerHTML\" hx-confirm=\"Delete?\">×</button>",
		},
		{
			name: "validate-directive-in-gotmpl",
			re:   regexp.MustCompile(`\s:validate\s*=`),
			desc: "`:validate=\"required,email\"` is a mustache-only directive. In gotmpl, use the real HTML5 attributes (`required`, `type=\"email\"`, `minlength=\"8\"`, `pattern=\"...\"`). The framework's server-side validator reads those same attributes when the form posts.",
		},
		{
			name: "param-prefix-in-gotmpl",
			re:   regexp.MustCompile(`\{\{\s*param_[\w]+\s*\}\}`),
			desc: "`{{param_id}}` is the mustache URL-param convention. In gotmpl, URL params come through the template data - use `{{.param_id}}` (with leading dot). Inside frontmatter queries, `:param_id` still binds the URL value to a SQL placeholder.",
		},
	}
	for _, c := range checks {
		if m := c.re.FindString(body); m != "" {
			return fmt.Sprintf("antipattern [%s] in %s: matched %q in a gotmpl page. %s", c.name, path, strings.TrimSpace(m), c.desc)
		}
	}
	return ""
}

// formBlockRe captures every <form ...>…</form> block. Group 1 is the
// opening tag's attrs, group 2 is the body. RE2-compatible (no
// lookaround) - non-greedy match works fine since <form> doesn't nest
// in practice.
var formBlockRe = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
var passwordInputRe = regexp.MustCompile(`(?is)<input\b[^>]*\btype\s*=\s*["']?password\b`)
var formMethodAttrRe = regexp.MustCompile(`(?i)\bmethod\s*=\s*["']?(\w+)`)

// validateFormSecurity catches the most dangerous form mistake an LLM
// can make: a form with a password input but no method="POST". The
// browser default is GET - the password ends up in the URL, browser
// history, server logs, referer headers, Cloudflare logs. We reject
// these at write_file time so the leak never makes it onto disk.
func validateFormSecurity(content string) string {
	for _, m := range formBlockRe.FindAllStringSubmatch(content, -1) {
		if len(m) < 3 {
			continue
		}
		attrs, body := m[1], m[2]
		if !passwordInputRe.MatchString(body) {
			continue
		}
		// `:create="…"` and `:patch="…"` directives auto-add method=POST
		// at render time - treat those as already-correct.
		if strings.Contains(attrs, ":create=") || strings.Contains(attrs, ":patch=") {
			continue
		}
		methodMatch := formMethodAttrRe.FindStringSubmatch(attrs)
		if len(methodMatch) < 2 || strings.ToUpper(methodMatch[1]) != "POST" {
			return "security violation: this file contains a <form> with an <input type=\"password\"> that does NOT specify method=\"POST\". The browser default is GET - submitting will put the user's password in the URL bar, browser history, server access logs, and Cloudflare logs. ALWAYS write password forms one of these two ways:\n\n  Option 1 (recommended) - use the framework's :create directive, which auto-posts via HTMX and adds CSRF:\n    <form :create=\"_benmore_users\">\n      <input name=\"email\" type=\"email\" required>\n      <input name=\"password\" type=\"password\" required>\n      <button>Sign up</button>\n    </form>\n\n  Option 2 - plain HTML with explicit method:\n    <form method=\"POST\" action=\"/signup\">\n      <input type=\"hidden\" name=\"_csrf\" value=\"{{csrf}}\">\n      <input name=\"email\" type=\"email\" required>\n      <input name=\"password\" type=\"password\" required>\n      <button>Sign up</button>\n    </form>"
		}
	}
	return ""
}
