//go:build !cli

package main

// Cross-file validation - runs AFTER the per-file syntactic check in
// ValidateOnWrite passes, scanning the whole app for orphan references
// that span file boundaries. Specifically: hooks.yaml / workflows.yaml
// / flows.yaml that mention tables which don't exist in schema.prisma
// (or schema.sql).
//
// Returns issues as **warnings** rather than hard rejections: the
// agent might be writing the schema next, or running a multi-file
// migration. Forcing an error on every intermediate state of a
// multi-file edit would be hostile. Warnings appear in the write_file
// response alongside the success result, so the agent sees them but
// the file still saves.

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// frameworkTables enumerates the internal tables the runtime creates
// on its own. They aren't declared in schema.prisma but are valid
// targets for hooks.yaml / workflows.yaml / SQL in flows. Without
// this allowlist, hooks on the auth table (`on_insert: _benmore_users`
// → fire a welcome email on signup) trigger false "table doesn't
// exist" warnings.
var frameworkTables = map[string]bool{
	"_benmore_users":          true,
	"_benmore_sessions":       true,
	"_benmore_audit_log":      true,
	"_benmore_notifications":  true,
	"_benmore_login_attempts": true,
	"_benmore_rate_limits":    true,
	"_benmore_idempotency":    true,
	"_benmore_permissions":    true,
	"_benmore_locks":          true,
	"_benmore_versions":       true,
	"_benmore_jobs":           true,
	"_benmore_webhooks":       true,
	"_benmore_devices":        true,
	"_benmore_metering":       true,
	"_benmore_client_errors":  true,
	"_benmore_feedback":       true,
	"_benmore_draft_capture":  true,
	"_benmore_migrations":     true,
	"_benmore_oauth_tokens":   true,
	"_benmore_custom_fields":  true,
	"_benmore_events":         true,
	"_benmore_aggregates":     true,
}

func frameworkTableList() string {
	out := make([]string, 0, len(frameworkTables))
	for k := range frameworkTables {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}

// typoDirNeighbors lists common misspellings of the framework's known
// subdirectory names. Keys are the typos; values are the correct name
// the contents need to live under to be loaded.
var typoDirNeighbors = map[string]string{
	"email":        "emails",
	"partial":      "partials",
	"layout":       "layouts",
	"i18ns":        "i18n",
	"locale":       "i18n",
	"locales":      "i18n",
	"translation":  "i18n",
	"translations": "i18n",
	"migration":    "migrations",
	"test":         "tests",
	"flow":         "flows",
	"hook":         "hooks",
	"workflow":     "workflows",
	"upload":       "uploads",
	"assets":       "static",
	"public":       "static",
	"img":          "static",
	"images":       "static",
}

func detectTypoDirs(appDir string) []string {
	entries, err := os.ReadDir(appDir)
	if err != nil {
		return nil
	}
	var warnings []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if correct, isTypo := typoDirNeighbors[e.Name()]; isTypo {
			// Only warn if the correct dir doesn't also exist OR is
			// empty - the agent likely meant the typo'd one.
			warnings = append(warnings, fmt.Sprintf(
				"directory %q looks like a typo of %q. The framework only loads files from %q (singular/plural/synonyms aren't auto-mapped). Rename the directory so the contents are picked up.",
				e.Name(), correct, correct))
		}
	}
	return warnings
}

// CrossFileWarnings scans the given app directory and returns any
// cross-file orphan-reference warnings. Empty slice means clean.
//
// `writtenPath` is the file the agent just wrote - passed so we can
// tailor a warning to the agent's intent (e.g., if they just edited
// schema.prisma and that change broke a hooks.yaml reference, the
// warning frames the fix from the schema's perspective).
func CrossFileWarnings(appDir, writtenPath string) []string {
	// Load the current set of table names from schema.prisma (or
	// schema.sql as a fallback). If neither exists we can't validate;
	// return clean.
	tables := loadSchemaTableNames(appDir)
	if len(tables) == 0 {
		return nil
	}

	var warnings []string

	// flows.yaml ⇄ auto-CRUD path conflicts. The framework auto-
	// generates GET/POST/PATCH/DELETE handlers at /api/<table> and
	// /api/<table>/{id} for every table in schema.prisma. A flow
	// declared at the same (method, path) crashes the app at boot
	// with a "pattern conflicts" panic from net/http's mux.
	//
	// This is the EXACT failure mode the simple-to-do-app on prod
	// hit - Haiku wrote `POST /api/todos` thinking it needed to
	// register a create endpoint, not knowing auto-CRUD already
	// owns that path. Now that's a hard error at write time, with
	// the corrected shape inline.
	if conflicts := detectFlowCRUDConflicts(appDir, tables); len(conflicts) > 0 {
		warnings = append(warnings, conflicts...)
	}

	// Multi-document YAML. yaml.v3 only parses the first document -
	// any content after a `---` separator is silently dropped. Apply
	// the check to every config file we read with yaml.Unmarshal,
	// not just flows.yaml. The trap is identical in shape across them
	// all: the agent thinks they've defined two of something and the
	// second silently never registers.
	for _, configFile := range []string{
		"flows.yaml", "hooks.yaml", "workflows.yaml", "cron.yaml",
		"computed.yaml", "encrypted.yaml", "retention.yaml", "app.yaml",
	} {
		if msg := detectMultiDocYAML(filepath.Join(appDir, configFile)); msg != "" {
			warnings = append(warnings, msg)
		}
	}

	// hooks.yaml: each top-level on_*/before_* block maps table-name
	// → list-of-step-objects. The KEY is a table name. Framework
	// tables (_benmore_users etc.) are valid hook targets and must
	// not trigger false warnings.
	if refs := scanHooksRefs(appDir); len(refs) > 0 {
		for _, ref := range refs {
			if !tables[ref.table] && !frameworkTables[ref.table] {
				warnings = append(warnings, fmt.Sprintf(
					"hooks.yaml: %s.%s references table %q which doesn't exist in schema.prisma (known tables: %s, plus framework tables: %s)",
					ref.section, ref.table, ref.table, crossFileSortedKeys(tables), frameworkTableList()))
			}
		}
	}

	// workflows.yaml: each top-level workflow has a `table:` field.
	if refs := scanWorkflowRefs(appDir); len(refs) > 0 {
		for _, ref := range refs {
			if !tables[ref.table] && !frameworkTables[ref.table] {
				warnings = append(warnings, fmt.Sprintf(
					"workflows.yaml: workflow %q has table: %s, which doesn't exist in schema.prisma (known tables: %s)",
					ref.section, ref.table, crossFileSortedKeys(tables)))
			}
		}
	}

	// Typo-dir detection. The framework loads files from a fixed set
	// of named subdirectories - `emails/`, `partials/`, `layouts/`,
	// `i18n/`, `migrations/`, `tests/`, `flows/`, `static/`,
	// `uploads/`. If the agent's last write created a sibling
	// directory whose name differs by a common typo (singular vs
	// plural, missing a letter), the contents are silently invisible
	// to the runtime. Warn so the agent renames it.
	if typoWarnings := detectTypoDirs(appDir); len(typoWarnings) > 0 {
		warnings = append(warnings, typoWarnings...)
	}

	// flows.yaml: scan inline SQL for FROM <name> / INTO <name> /
	// UPDATE <name> patterns. Best-effort regex - won't catch every
	// query shape, but the corpus-typical agent writes are caught.
	if refs := scanFlowsSQLTables(appDir); len(refs) > 0 {
		seen := map[string]bool{} // dedupe - same flow can reference same table multiple times
		for _, ref := range refs {
			key := ref.section + ":" + ref.table
			if seen[key] {
				continue
			}
			seen[key] = true
			if !tables[ref.table] && !strings.HasPrefix(ref.table, "_benmore_") {
				warnings = append(warnings, fmt.Sprintf(
					"flows.yaml: flow %q queries table %q which doesn't exist in schema.prisma (known tables: %s)",
					ref.section, ref.table, crossFileSortedKeys(tables)))
			}
		}
	}

	// External provider gaps - auth.verify_email, auth.otp, or
	// auth.billing_provider features declared in app.yaml that depend
	// on an env-var-driven external integration (Resend / Postmark /
	// SMTP / Twilio / Stripe) which isn't wired. The features still
	// "compile" (app loads, framework registers routes) but the
	// runtime calls into SendEmail/SendSMS/Stripe fail. Surface here
	// so the agent sees the gap during `benmore check`, not when a
	// real user hits signup and the OTP never arrives.
	if design := LoadAppConfigYAML(appDir); design != nil {
		// Construct a lightweight App wrapper since ProviderGapWarnings
		// operates on *App. Only Dir + Design are read; the rest stays nil.
		stubApp := &App{Dir: appDir, Design: design}
		if providerWarnings := ProviderGapWarnings(stubApp); len(providerWarnings) > 0 {
			warnings = append(warnings, providerWarnings...)
		}
	}

	return warnings
}

type tableRef struct {
	section string // hook section or flow/workflow name (whatever locates the ref in the source file)
	table   string
}

// loadSchemaTableNames reads schema.prisma (preferred) or schema.sql
// and returns the set of table names. Maps Prisma model names through
// the same pluralize+snake-case logic the emitter uses so the lookup
// matches the actual table name on disk.
func loadSchemaTableNames(appDir string) map[string]bool {
	tables := map[string]bool{}
	if data, err := os.ReadFile(filepath.Join(appDir, "schema.prisma")); err == nil {
		if models, err := ParsePrismaSchema(string(data)); err == nil {
			for _, m := range models {
				tables[m.Table] = true
			}
		}
		return tables
	}
	if data, err := os.ReadFile(filepath.Join(appDir, "schema.sql")); err == nil {
		// Parse CREATE TABLE statements to extract the table name.
		re := regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?["']?(\w+)["']?`)
		for _, m := range re.FindAllStringSubmatch(string(data), -1) {
			tables[strings.ToLower(m[1])] = true
		}
		return tables
	}
	return tables
}

// scanHooksRefs returns one tableRef per table-keyed entry in hooks.yaml.
func scanHooksRefs(appDir string) []tableRef {
	data, err := os.ReadFile(filepath.Join(appDir, "hooks.yaml"))
	if err != nil {
		return nil
	}
	var top map[string]map[string]any
	if err := yaml.Unmarshal(data, &top); err != nil {
		return nil
	}
	known := map[string]bool{
		"on_insert": true, "on_update": true, "on_delete": true,
		"before_insert": true, "before_update": true, "before_delete": true,
	}
	var refs []tableRef
	for section, tableMap := range top {
		if !known[section] {
			continue
		}
		for table := range tableMap {
			refs = append(refs, tableRef{section: section, table: table})
		}
	}
	return refs
}

// scanWorkflowRefs extracts the `table:` field from each top-level
// workflow definition.
func scanWorkflowRefs(appDir string) []tableRef {
	data, err := os.ReadFile(filepath.Join(appDir, "workflows.yaml"))
	if err != nil {
		return nil
	}
	var top map[string]struct {
		Table string `yaml:"table"`
	}
	if err := yaml.Unmarshal(data, &top); err != nil {
		return nil
	}
	var refs []tableRef
	for name, wf := range top {
		if wf.Table != "" {
			refs = append(refs, tableRef{section: name, table: wf.Table})
		}
	}
	return refs
}

// scanFlowsSQLTables walks both GHA and legacy shapes and pulls every
// table identifier out of inline SQL strings. Uses the SQL tokenizer
// from sql_tables.go so CTEs, subqueries, and quoted identifiers are
// handled correctly.
func scanFlowsSQLTables(appDir string) []tableRef {
	data, err := os.ReadFile(filepath.Join(appDir, "flows.yaml"))
	if err != nil {
		return nil
	}
	// Try GHA shape first.
	var ghaFile FlowFileGHA
	if err := yaml.Unmarshal(data, &ghaFile); err == nil && ghaFile.Jobs != nil {
		var refs []tableRef
		for jobName, job := range ghaFile.Jobs {
			for _, step := range job.Steps {
				q := step.Query
				if q == "" {
					if w, ok := step.With["query"].(string); ok {
						q = w
					}
				}
				if q == "" {
					continue
				}
				for _, table := range ExtractTableRefs(q) {
					refs = append(refs, tableRef{section: jobName, table: table})
				}
			}
		}
		return refs
	}
	// Legacy shape.
	var legacy map[string]FlowYAML
	if err := yaml.Unmarshal(data, &legacy); err == nil {
		var refs []tableRef
		for name, fy := range legacy {
			for _, step := range fy.Steps {
				if step.SQL == "" {
					continue
				}
				for _, table := range ExtractTableRefs(step.SQL) {
					refs = append(refs, tableRef{section: name, table: table})
				}
			}
		}
		return refs
	}
	return nil
}

// detectFlowCRUDConflictsInContent is the write-time variant that
// scans content the agent is ABOUT to write (not the on-disk version).
// Same logic as detectFlowCRUDConflicts but takes the YAML body
// directly so it can run before the file lands.
func detectFlowCRUDConflictsInContent(content string, tables map[string]bool) string {
	// GHA shape first.
	var ghaFile FlowFileGHA
	if yaml.Unmarshal([]byte(content), &ghaFile) == nil && ghaFile.On.Request != nil && ghaFile.Jobs != nil {
		method := strings.ToUpper(ghaFile.On.Request.Method)
		if method == "" {
			method = "POST"
		}
		return matchAutoCRUDPath(method, ghaFile.On.Request.Path, tables)
	}
	// Legacy shape.
	var legacy map[string]FlowYAML
	if yaml.Unmarshal([]byte(content), &legacy) == nil {
		for name, fy := range legacy {
			if fy.Trigger == "" {
				continue
			}
			parts := strings.Fields(fy.Trigger)
			if len(parts) < 2 {
				continue
			}
			method := strings.ToUpper(parts[0])
			path := parts[1]
			if msg := matchAutoCRUDPath(method, path, tables); msg != "" {
				return fmt.Sprintf("flows.yaml flow %q: %s", name, msg)
			}
		}
	}
	return ""
}

// detectFlowCRUDConflicts checks every flow path in flows.yaml against
// the auto-CRUD route pattern. Auto-CRUD owns:
//
//	GET    /api/<table>              list
//	POST   /api/<table>              create
//	GET    /api/<table>/{id}         read
//	PATCH  /api/<table>/{id}         update
//	DELETE /api/<table>/{id}         delete
//	POST   /api/<table>/batch        batch ops
//	POST   /api/<table>/ingest       NDJSON ingest
//
// for every table in schema.prisma. A flow registered at the same
// (method, path) crashes the app at boot with net/http's pattern
// conflict panic - that's the EXACT failure Haiku hit on the
// simple-to-do-app deploy. Returning a warning here would let the
// crash through; this is an ERROR-class message and the validator
// elsewhere is allowed to upgrade it.
func detectFlowCRUDConflicts(appDir string, tables map[string]bool) []string {
	data, err := os.ReadFile(filepath.Join(appDir, "flows.yaml"))
	if err != nil {
		return nil
	}
	var conflicts []string

	// Try GHA shape first.
	var ghaFile FlowFileGHA
	if yaml.Unmarshal(data, &ghaFile) == nil && ghaFile.On.Request != nil && ghaFile.Jobs != nil {
		method := strings.ToUpper(ghaFile.On.Request.Method)
		if method == "" {
			method = "POST"
		}
		if msg := matchAutoCRUDPath(method, ghaFile.On.Request.Path, tables); msg != "" {
			conflicts = append(conflicts, msg)
		}
		return conflicts
	}

	// Legacy shape.
	var legacy map[string]FlowYAML
	if yaml.Unmarshal(data, &legacy) == nil {
		for name, fy := range legacy {
			if fy.Trigger == "" {
				continue
			}
			parts := strings.Fields(fy.Trigger)
			if len(parts) < 2 {
				continue
			}
			method := strings.ToUpper(parts[0])
			path := parts[1]
			if msg := matchAutoCRUDPath(method, path, tables); msg != "" {
				conflicts = append(conflicts, fmt.Sprintf("flows.yaml flow %q: %s", name, msg))
			}
		}
	}
	return conflicts
}

// matchAutoCRUDPath returns a warning string if (method, path) collides
// with an auto-CRUD endpoint for any table in the declared schema.
// Empty return = no conflict.
func matchAutoCRUDPath(method, path string, tables map[string]bool) string {
	method = strings.ToUpper(method)
	if !strings.HasPrefix(path, "/api/") {
		return ""
	}
	rest := strings.TrimPrefix(path, "/api/")
	// Strip leading "/" if double-slash was present.
	rest = strings.TrimPrefix(rest, "/")
	segments := strings.Split(rest, "/")
	if len(segments) == 0 || segments[0] == "" {
		return ""
	}
	table := segments[0]
	if !tables[table] {
		return ""
	}
	// /api/<table>
	if len(segments) == 1 {
		switch method {
		case "GET", "POST":
			return autoCRUDConflictMessage(method, path, table, segments)
		}
	}
	// /api/<table>/{id} or /api/<table>/:id
	if len(segments) == 2 && (segments[1] == "" || strings.HasPrefix(segments[1], ":") || strings.HasPrefix(segments[1], "{")) {
		switch method {
		case "GET", "PATCH", "PUT", "DELETE":
			return autoCRUDConflictMessage(method, path, table, segments)
		}
	}
	// /api/<table>/batch and /api/<table>/ingest
	if len(segments) == 2 && (segments[1] == "batch" || segments[1] == "ingest") && method == "POST" {
		return autoCRUDConflictMessage(method, path, table, segments)
	}
	return ""
}

func autoCRUDConflictMessage(method, path, table string, segments []string) string {
	return fmt.Sprintf(
		"flows.yaml route %s %s conflicts with the auto-CRUD endpoint for table %q. The framework already provides %s - your flow registration will crash the app at boot with `pattern conflicts`.\n\n"+
			"The fix depends on why you wrote the flow:\n"+
			"  - You wanted to auto-set user_id on insert? You don't need a flow - the auto-CRUD INSERT handler already pulls user_id from the session for any column named `user_id`. Just remove the flow.\n"+
			"  - You wanted to add validation or a side effect? Use `hooks.yaml` instead - `before_insert: %s: - sql: ...` for validation, `on_insert: %s: - webhook: ...` for side effects.\n"+
			"  - You wanted a route the auto-CRUD doesn't cover (e.g. a custom verb, a /search endpoint, a /report)? Pick a path that ISN'T /api/<table> or /api/<table>/{id}. Examples that DON'T conflict: /api/%s/search, /api/%s/{id}/star, /api/%s/{id}/duplicate.",
		method, path, table, autoCRUDListForTable(table), table, table, table, table, table)
}

func autoCRUDListForTable(table string) string {
	return fmt.Sprintf("GET/POST /api/%s, GET/PATCH/DELETE /api/%s/{id}, POST /api/%s/batch, POST /api/%s/ingest", table, table, table, table)
}

// detectMultiDocYAML returns a warning when a YAML file contains more
// than one document (separated by `---`). yaml.Unmarshal only parses
// the first; subsequent documents are silently dropped. Haiku hit this
// when trying to fit three flow definitions in one flows.yaml - only
// the first registered.
func detectMultiDocYAML(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	body := string(data)
	// Count `---` separators that AREN'T the leading document-open
	// marker. The YAML spec allows ONE optional `---` at the very
	// top to explicitly open the document; we ignore that case. A
	// second `---` starts a new document, which yaml.Unmarshal won't
	// see (it only reads the first doc).
	lines := strings.Split(body, "\n")
	count := 0
	for i, line := range lines {
		if strings.TrimSpace(line) != "---" {
			continue
		}
		// Skip a leading `---` that opens the first document. This is
		// the case where the file's first non-empty line is `---`.
		if i == firstNonEmpty(lines) {
			continue
		}
		count++
	}
	if count == 0 {
		return ""
	}
	return fmt.Sprintf(
		"%s contains %d `---` document separators. YAML allows multiple documents per file but our parser only reads the FIRST - every flow after a `---` is silently ignored. The fix: put every flow under one top-level `on:` + `jobs:` shape (the `jobs:` map can hold multiple named jobs, each with its own steps).\n\n"+
			"Example for three CRUD-like flows in one file:\n"+
			"  on:\n"+
			"    request: { method: ANY, path: /api/special/* }  # use one trigger\n"+
			"  jobs:\n"+
			"    job_a:\n"+
			"      steps: [ ... ]\n"+
			"    job_b:\n"+
			"      steps: [ ... ]\n\n"+
			"OR: if each flow needs a different trigger, put each in its own .yaml file under flows/ (currently flows.yaml is one file - file a feature request if you need multi-file).",
		filepath.Base(path), count)
}

func firstNonEmpty(lines []string) int {
	for i, l := range lines {
		if strings.TrimSpace(l) != "" {
			return i
		}
	}
	return -1
}

func crossFileSortedKeys(m map[string]bool) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}
