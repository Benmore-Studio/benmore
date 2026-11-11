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
//                       the model name and the offending line; a first
//                       model that would take the place of the app's
//                       schema.sql while leaving out tables it declares
//                       (schema_file_switch.go)
//
//   flows.yaml          LoadFlowsGHA (or legacy parser); reject empty
//                       jobs/triggers; reject step types we don't know
//
//   hooks.yaml          basic shape check; every `when:` prepared against
//                       the schema (validators_when.go)
//
//   workflows.yaml      parse; every transition / on_transition `when:`
//                       prepared against the schema
//
//   *.yaml              gets a fallback YAML syntax check so a missing
//                       colon doesn't silently break the app at boot
//
//   schema.yaml         shorthand that would replace a hand-written
//                       schema.sql while leaving out tables it declares
//                       (schema_file_switch.go)
//
//   app.yaml            validateAppYAML (existing) - unknown top-level
//                       keys, unknown auth.* keys, etc.
//
//   schema.prisma, schema.sql, app.yaml, encrypted.yaml, computed.yaml
//                       encrypted, versioned and computed tables/columns
//                       the load would not find, in the file or broken by
//                       it in another (validators_load_refs.go)
//
//   schema.prisma, app.yaml, encrypted.yaml, computed.yaml
//                       computed expr:/sql: and app.yaml aggregates: that
//                       read an encrypted column, which they would compute
//                       on as ciphertext (validators_encrypted_compute.go)

import (
	"errors"
	"fmt"
	"html/template"
	"maps"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
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

// autoFixOrRefuse is AutoFixOnWrite for server-side writes into an app dir
// (root = the instance directory). An app with a reviewed mcp.yaml has a sealed
// execution digest over its source bytes, so a rewrite after review would
// withhold the connector; the CLI push refuses the same case (cli_thin_clients.go).
// There it returns a non-empty refusal showing the lines the author must
// change locally and re-review; other apps get AutoFixOnWrite unchanged.
func autoFixOrRefuse(root *os.Root, path, content string) (string, []string, string) {
	fixed, applied := AutoFixOnWrite(path, content)
	if len(applied) == 0 || fixed == content {
		return fixed, applied, ""
	}
	reviewed := filepath.Base(path) == "mcp.yaml"
	why := "This app has a reviewed mcp.yaml"
	if !reviewed {
		// Only "does not exist" means no manifest. Any other stat failure
		// (permissions, I/O, a link loop) fails closed: rewriting source under
		// a manifest we could not see would withhold the connector.
		_, err := root.Stat("mcp.yaml")
		if errors.Is(err, os.ErrNotExist) {
			return fixed, applied, ""
		}
		if err != nil {
			why = "The server could not check for a reviewed mcp.yaml (" + err.Error() + ")"
		}
	}
	have := map[string]int{}
	for _, l := range strings.Split(content, "\n") {
		have[l]++
	}
	var lines []string
	for _, l := range strings.Split(fixed, "\n") {
		if have[l] > 0 {
			have[l]--
		} else if len(lines) < 10 {
			lines = append(lines, "+ "+l)
		}
	}
	return content, nil, fmt.Sprintf("%s needs normalization (%s). %s, so the server will not rewrite its source: apply these changes locally, review them, then write again:\n%s", path, strings.Join(applied, "; "), why, strings.Join(lines, "\n"))
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
		if !upsertSelectNeedsWhere(m) {
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
	return validateOnWriteIn(appDir, path, content, true)
}

// ValidateOnWriteInPending is ValidateOnWriteIn for a write that defers its
// reload to later writes of the same batch: pending names those files. A
// reference the app's load refuses that this write breaks in one of them is
// left to that file's own write (validators_load_refs.go); excused lists
// those files, for the write's answer.
func ValidateOnWriteInPending(appDir, path, content string, pending []string) (string, []string) {
	return ValidateOnWriteInBatch(appDir, path, content, true, pending)
}

// ValidateOnWriteInBatch is the write gate of write_file. deferred: the write
// defers its reload to later writes of its batch (reload:false), which may
// supply a module a bundle imports or a partial a page includes, so those
// are left to the post-write check (bundle_check.go, include_check.go);
// pending is as for ValidateOnWriteInPending.
func ValidateOnWriteInBatch(appDir, path, content string, deferred bool, pending []string) (string, []string) {
	var set map[string]bool
	if deferred {
		set = map[string]bool{}
		for _, p := range pending {
			set[filepath.ToSlash(filepath.Clean(p))] = true
		}
	}
	return validateOnWriteInPending(appDir, path, content, true, deferred, set)
}

// validateOnWriteIn is the dispatcher. gate runs the write gate's per-file
// preflights that `benmore check` runs app-wide instead: flow routes
// (flowRouteCollisionFindings), browser bundles (bundleCheckFindings) and
// <include> targets (includeCheckFindings), all in app_check.go.
func validateOnWriteIn(appDir, path, content string, gate bool) string {
	msg, _ := validateOnWriteInPending(appDir, path, content, gate, false, nil)
	return msg
}

// cleanWritePath is the path a write lands at (safeJoin cleans it), in slash
// form. The validators are chosen by the path's base name and extension, so
// they must judge this form: `flows.yaml/.` has base "." and skipped every
// typed validator while the file landed at flows.yaml.
func cleanWritePath(path string) string {
	if path == "" {
		return path
	}
	return filepath.ToSlash(filepath.Clean(path))
}

func validateOnWriteInPending(appDir, path, content string, gate, deferred bool, pending map[string]bool) (string, []string) {
	verdict, excused := writeGateVerdict(appDir, path, content, gate, deferred, pending)
	return verdict.Refusal, excused
}

// writeGateVerdict runs the validators on one file. Its verdict holds the
// refusal as the validators word it and, for the text a refused write
// answers, the same with the documentation address of each issue's rule
// (refusal_docs.go). Every issue is raised through add with its rule.
func writeGateVerdict(appDir, path, content string, gate, deferred bool, pending map[string]bool) (gateVerdict, []string) {
	path = cleanWritePath(path)
	base := strings.ToLower(filepath.Base(path))
	ext := strings.ToLower(filepath.Ext(path))

	var issues []string
	rules := map[int]gateRule{} // the rule behind issues[i]
	add := func(rule gateRule, msg string) {
		rules[len(issues)] = rule
		issues = append(issues, msg)
	}

	// Path-based hard rejects. These fire BEFORE any content inspection
	// because the file's existence itself is the violation - there's
	// no "right" content for a package.json in a Benmore app.
	if msg := validateForbiddenPath(path); msg != "" {
		add(gateForbiddenPath, msg)
		return newGateVerdict(issues, rules, nil, ""), nil
	}

	// Refuse over-budget YAML once before credential scans and the independent
	// validators below. Each parser keeps its own guard for other callers, but
	// repeatedly parsing a document that already exceeds the budget makes the
	// write gate itself expensive. Syntax errors still go to normal validators.
	if ext == ".yaml" || ext == ".yml" {
		if err := checkYAMLShape([]byte(content)); err != nil {
			add(gateYAMLLimit, fmt.Sprintf("yaml resource limit in %s: %v", path, err))
			return newGateVerdict(issues, rules, nil, writeRejectionFooter), nil
		}
	}

	// Hardcoded-credential gate (any file type): a committed secret leaks into
	// per-app git history. High-confidence shapes only, so a normal push is
	// never blocked by a false positive.
	if msg := validateNoCommittedSecrets(path, content); msg != "" {
		add(gateSecret, msg)
	}

	// TS/JS source files (src/*.tsx, *.jsx, *.ts, *.js) get the browser
	// antipattern sweep. Same detectFrameworkAntipatterns dispatcher
	// the .html branch uses, so cross-file antipatterns (CDN imports,
	// ReactDOM.createRoot, etc.) surface in the same shape.
	if isSPASourceFile(path) {
		if msg := detectFrameworkAntipatterns(path, content); msg != "" {
			add(gateBrowserSource, msg)
		}
	}
	if msg := hipaaUploadKindProblem(appDir, path, content); msg != "" { // compliance.go
		add(gateHIPAAUpload, msg)
	}
	if msg := validateScriptSyntax(path, content); msg != "" {
		add(gateScriptSyntax, msg)
	} else if gate {
		// The bundles this file is part of must build: every import inside
		// static/ and resolvable (bundle_check.go).
		if msg := bundleWriteRefusal(appDir, path, content, deferred); msg != "" {
			add(gateBundle, msg)
		}
	}

	switch {
	case ext == ".html":
		if msg := validatePageContract(path, content); msg != "" {
			add(gatePage, msg)
		}
		// A root page's filename is its route: a `:` must be a well-formed
		// path parameter that registers (page_path_params.go).
		if msg := validatePageRouteFile(appDir, path); msg != "" {
			add(gatePageRoute, msg)
		}
		// gotmpl-specific: compile the body with html/template to
		// catch syntax errors before render. Strip frontmatter first
		// so YAML doesn't confuse the parser.
		if msg := validateGotmplParseIn(appDir, path, content); msg != "" {
			add(gateGotmpl, msg)
		}
		// engine-mode mixup: raw pages that contain {{ template syntax
		// or gotmpl pages that contain SPA-only constructs. Both
		// silently fail to render the way the agent intended.
		if msg := validateEngineMixup(path, content); msg != "" {
			add(gatePageEngine, msg)
		}
		// <video autoplay> without muted = the iOS / Chrome autoplay
		// block. Black screen until the user finds the hidden play
		// button on the element. Surfaces in livestream apps the agent writes.
		if msg := validateVideoAutoplay(path, content); msg != "" {
			add(gateVideoAutoplay, msg)
		}
		// <include> tags the runtime would leave unexpanded or render as an
		// "Include error" (include_check.go).
		if gate {
			if msg := includeWriteRefusal(appDir, path, content, deferred); msg != "" {
				add(gateInclude, msg)
			}
		}

	case base == "schema.prisma":
		if msg := validateSchemaPrisma(content); msg != "" {
			add(gateSchemaPrisma, msg)
		}
		if appDir != "" {
			if msg := validateFulltextEncryptedConflict(content, LoadEncryptedFieldsConfig(appDir), nil); msg != "" {
				add(gateFulltextEnc, msg)
			}
			// A schema edit can turn a member-of child into a table the
			// rule no longer fits (validators_authz.go).
			if msg := validateMemberOfShape(readAppFileOrNil(appDir, "app.yaml"), []byte(content)); msg != "" {
				add(gateMemberOfShape, msg)
			}
			// The first model in the schema.prisma of an app whose schema
			// is schema.sql replaces that schema (schema_file_switch.go).
			if strings.EqualFold(appRelativeFile(appDir, path), "schema.prisma") {
				if msg := schemaPrismaSwitchRefusal(appDir, content); msg != "" {
					add(gateSchemaFile, msg)
				}
			}
		}

	case base == "flows.yaml" || isFlowsSubdirFile(path):
		if commandDeclarationPresent(content) {
			commandPath, pathErr := commandWritePath(appDir, path)
			if pathErr != nil {
				add(gateCommandFlow, pathErr.Error())
			} else {
				definitions, err := appMCPSchemaTableDefinitions(appDir)
				if err != nil {
					add(gateCommandFlow, fmt.Sprintf("command schema inventory: %v", err))
				} else if flow, err := parseFlowCommandFileColumns(commandPath, []byte(content), eligibleCRUDTables(definitions), commandColumnInventory(definitions)); err != nil {
					add(gateCommandFlow, fmt.Sprintf("command declaration: %v", err))
				} else if err := appMCPCheckCommandDependencyShapes(func(name string) ([]byte, error) { return readOptionalConfig(appDir, name) }, []Flow{flow}); err != nil {
					// A dependency that cannot return one id column would fail every prepare.
					add(gateCommandFlow, fmt.Sprintf("command declaration: %v", err))
				} else if err := appMCPCheckCommandSQLFunctions(func(name string) ([]byte, error) { return readOptionalConfig(appDir, name) }, []Flow{flow}, nil); err != nil {
					// A function the command authorizer refuses fails that statement on every run.
					add(gateCommandFlow, fmt.Sprintf("command declaration: %v", err))
				}
			}
			break
		}
		// flows.yaml in the app root OR any *.yaml under flows/ -
		// agents commonly split flows across multiple files (one flow
		// per file under flows/) and those need the same validation.
		if msg := validateFlowsYAML(content); msg != "" {
			add(gateFlows, msg)
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
					add(gateFlowRoutes, msg)
				}
			}
			// An event flow on a name that is no table of the app never
			// starts (validators_flow_ignored_values.go).
			if msg := flowEventTableViolation(appDir, content, pending); msg != "" {
				add(gateFlowEventTable, msg)
			}
			// Every other framework route (per-table share, permissions,
			// versions, lock, transition ...; framework paths), found by
			// running the app's real route registration from source
			// (route_collisions.go). Such a flow used to crash the app at
			// load when the framework route registered after it. `benmore
			// check` runs the app-wide form (flowRouteCollisionFindings).
			if gate {
				if msg := flowRouteCollisionViolation(appDir, path, content); msg != "" {
					add(gateFlowRoutes, msg)
				}
			}
		}

	case base == "hooks.yaml":
		if msg := validateHooksYAML(content); msg != "" {
			add(gateHooks, msg)
		} else if msg := hooksSubKeyViolation(content); msg != "" {
			// Write gate and `benmore check` only (validateHooksYAML also
			// runs in the loader; this must not refuse a file at boot).
			add(gateHooks, msg)
		} else if msg := validateWhenConditions(appDir, base, content); msg != "" {
			// Write gate and `benmore check` only: the loader never
			// refuses a file over a `when:` (warnWhenConditions logs).
			add(gateWhen, msg)
		} else if msg := hooksFrameworkDDLViolation(content); msg != "" {
			// Write gate and `benmore check` only: the runtime refuses the
			// statement when the hook runs (app_sql_guard.go).
			add(gateHooks, msg)
		}

	case base == "mcp.yaml":
		var err error
		if appDir != "" {
			// Stage the proposed manifest with the same captured-source snapshot
			// used by runtime loading. Command declarations can reference sealed
			// compute modules, so validating bindings against a bare parsed
			// manifest (with no sourceHashes) falsely reports those modules absent.
			_, err = loadRuntimeConfigWithManifest(appDir, []byte(content))
		} else {
			_, err = parseAppMCPManifest([]byte(content))
		}
		if err != nil {
			add(gateMCPManifest, err.Error())
		}

	case base == "cron.yaml":
		if cfg, err := parseCronYAML([]byte(content)); err != nil {
			add(gateCron, err.Error())
		} else if problems := cronShapeProblems(content); len(problems) > 0 {
			// Write gate and `benmore check` only: a deployed file with
			// ignored keys still loads (warnCronShape logs them).
			add(gateCron, strings.Join(problems, "\n"))
		} else if problems := cronFlowRefProblems(appDir, cfg); len(problems) > 0 {
			// Same: a deployed file naming a missing flow still loads
			// (warnCronFlowRefs logs it) and each run fails.
			add(gateCron, strings.Join(problems, "\n"))
		}

	case base == "workflows.yaml":
		if _, err := parseWorkflowsYAML([]byte(content)); err != nil {
			add(gateWorkflows, err.Error())
		} else {
			// Write gate and `benmore check` only: a deployed file with
			// these problems still loads (warnWorkflowShape logs them).
			if msg := validateWorkflowsShape(appDir, content); msg != "" {
				add(gateWorkflows, msg)
			}
			if msg := validateWhenConditions(appDir, base, content); msg != "" {
				add(gateWhen, msg)
			}
		}

	case base == "app.yaml":
		if msg := validateAppYAML(content); msg != "" {
			add(gateAppYAML, msg)
		}
		// versioned: and encrypted: take the app's own tables only
		// (config_framework_tables.go). The load ignores such an entry.
		if msg := frameworkTableConfigViolation("app.yaml", content); msg != "" {
			add(gateFrameworkTable, msg)
		}
		if msg := hipaaReadAuditTablesProblem(appDir, content); msg != "" {
			add(gateHIPAAReadAudit, msg)
		}
		if msg := workflowEncryptedStateIssue(appDir, readAppFileOrNil(appDir, "encrypted.yaml"), []byte(content)); msg != "" {
			add(gateWorkflowState, msg)
		}
		if msg := validateAuthzAppYAML(content); msg != "" { // validators_authz.go
			add(gateAuthz, msg)
		}
		if msg := validateSignupFields(content); msg != "" {
			add(gateSignupFields, msg)
		}
		if msg := complianceRemovalProblem(appDir, content); msg != "" { // compliance.go
			add(gateCompliance, msg)
		}
		// aggregates: the load's own reader, plus the read-only rule the
		// refresher applies (aggregates.go).
		if msg := aggregatesSectionViolation(content); msg != "" {
			add(gateAggregates, msg)
		}
		if appDir != "" {
			if msg := validateMemberOfShape([]byte(content), readAppFileOrNil(appDir, "schema.prisma")); msg != "" { // validators_authz.go
				add(gateMemberOfShape, msg)
			}
			// Only tables whose encryption comes from this app.yaml
			// (encrypted.yaml wins per table).
			diskEnc := readAppFileOrNil(appDir, "encrypted.yaml")
			fromEncFile := parseEncryptedFieldsConfig(diskEnc, nil)
			merged := parseEncryptedFieldsConfig(diskEnc, []byte(content))
			own := map[string]bool{}
			if merged != nil {
				for table := range merged.Fields {
					if fromEncFile == nil || fromEncFile.Fields[table] == nil {
						own[table] = true
					}
				}
			}
			if len(own) > 0 {
				if msg := validateFulltextEncryptedConflict(string(readAppFileOrNil(appDir, "schema.prisma")), merged, own); msg != "" {
					add(gateFulltextEnc, msg)
				}
			}
		}

	case base == "encrypted.yaml":
		if msg := validateEncryptedYAML(content); msg != "" {
			add(gateEncryptedYAML, msg)
		} else if msg := frameworkTableConfigViolation("encrypted.yaml", content); msg != "" {
			// The app's own tables only (config_framework_tables.go). The
			// load ignores such an entry.
			add(gateFrameworkTable, msg)
		}
		if msg := workflowEncryptedStateIssue(appDir, []byte(content), readAppFileOrNil(appDir, "app.yaml")); msg != "" {
			add(gateWorkflowState, msg)
		}
		if appDir != "" {
			if enc := parseEncryptedFieldsConfig([]byte(content), nil); enc != nil {
				if msg := validateFulltextEncryptedConflict(string(readAppFileOrNil(appDir, "schema.prisma")), enc, nil); msg != "" {
					add(gateFulltextEnc, msg)
				}
			}
		}

	case base == "validators.yaml":
		// Write gate and `benmore check` only: the loader keeps loading
		// rules this refuses (validators_crossfield.go).
		if msg := validatorsYAMLViolation(appDir, content); msg != "" {
			add(gateValidatorsYAML, msg)
		}

	case writesAppRootFile(appDir, path, "computed.yaml"):
		// The load's own checks (computed_document.go). A deployed file
		// whose fields install nothing still loads.
		if msg := computedYAMLViolation(appDir, content); msg != "" {
			add(gateComputedYAML, msg)
		}

	case writesAppRootFile(appDir, path, "retention.yaml"):
		// The load's own reader (retention_document.go), so the gate and
		// the load cannot disagree. A deployed file with a problem still
		// loads: the policy it concerns does not run.
		if msg := retentionYAMLViolation(appDir, content); msg != "" {
			add(gateRetentionYAML, msg)
		}

	case ext == ".yaml" || ext == ".yml":
		if msg := validateYAMLSyntax(content); msg != "" {
			add(gateYAMLSyntax, fmt.Sprintf("yaml syntax in %s: %s", path, msg))
		}
		// A schema.yaml beside a hand-written schema.sql makes the next
		// load overwrite that file (schema_file_switch.go).
		if appDir != "" && strings.EqualFold(appRelativeFile(appDir, path), "schema.yaml") {
			if msg := schemaYAMLWriteRefusal(appDir, content); msg != "" {
				add(gateSchemaFile, msg)
			}
		}

	case base == "tsconfig.json":
		if msg := validateTSConfig(content); msg != "" {
			add(gateTSConfig, msg)
		}
	}

	// A table named like a framework route (`_upload`, `_jobs`, ...): its
	// auto-CRUD routes cannot register next to the framework's, so the app
	// would not load (table_route_collisions.go). Write gate and `benmore
	// check` only.
	if msg := tableRouteCollisionViolation(appDir, path, content); msg != "" {
		add(gateTableRoute, msg)
	}

	// References the app's load refuses: an encrypted, versioned or computed
	// table or column the schema does not have, in this file or broken by it
	// in another (validators_load_refs.go).
	refusal, excused := loadRefWriteCheck(appDir, path, content, pending)
	if refusal != "" {
		add(gateLoadRefs, refusal)
	}
	// Computed fields and aggregates that read an encrypted column compute on
	// ciphertext (validators_encrypted_compute.go). Write gate and `benmore
	// check` only: the load keeps such a field.
	if msg := encryptedComputeWriteCheck(appDir, path, content, pending); msg != "" {
		add(gateEncryptedRead, msg)
	}

	if len(issues) == 0 {
		return gateVerdict{}, excused
	}
	// Append a recovery footer: agents that hit a rejection often
	// fall back to Edit instead of re-Writing the corrected content,
	// which leaves the file partially-old (the rest of the intended
	// rewrite never lands). The fix is to re-Write with the correction.
	var rename func(string) string
	if isFlowsSubdirFile(path) {
		label := flowFileLabel(appDir, path)
		rename = func(body string) string { return nameFlowFile(body, label) }
	}
	return newGateVerdict(issues, rules, rename, writeRejectionFooter), nil
}

// writesAppRootFile reports whether path is the app's own <name> at the app
// root, the file the load reads, and not one that only shares its name
// (tests/retention.yaml is a test file).
func writesAppRootFile(appDir, path, name string) bool {
	clean := filepath.ToSlash(filepath.Clean(path))
	if filepath.IsAbs(path) && appDir != "" {
		if rel, err := filepath.Rel(appDir, path); err == nil {
			clean = filepath.ToSlash(rel)
		}
	}
	return strings.EqualFold(clean, name)
}

// nameFlowFile puts the flow file's own path where a flow validator's message
// names the file. The flow validators serve flows.yaml and every
// flows/<name>.yaml alike and begin each message (and each line of a joined
// list) with "flows.yaml", so a refusal of flows/v1ping.yaml named a file the
// app may not even have. Only a leading file name is replaced; advice that
// mentions flows.yaml further on is left as written.
func nameFlowFile(msg, file string) string {
	if file == "" || file == "flows.yaml" {
		return msg
	}
	lines := strings.Split(msg, "\n")
	for i, line := range lines {
		if rest, ok := strings.CutPrefix(line, "flows.yaml"); ok && (rest == "" || rest[0] == ':' || rest[0] == ' ') {
			lines[i] = file + rest
		}
	}
	return strings.Join(lines, "\n")
}

// flowFileLabel is a flow file's path as the app names it: relative to the
// app directory (flows/<name>.yaml).
func flowFileLabel(appDir, path string) string {
	if filepath.IsAbs(path) && appDir != "" {
		if rel, err := filepath.Rel(appDir, path); err == nil && filepath.IsLocal(rel) {
			path = rel
		}
	}
	clean := filepath.ToSlash(filepath.Clean(path))
	if filepath.IsAbs(path) {
		if i := strings.LastIndex(clean, "/flows/"); i >= 0 {
			clean = clean[i+1:]
		}
	}
	return clean
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
	// Webhook signing secrets: Stripe's (whsec_ + 32 base62, or 64 hex from
	// the Stripe CLI) and Svix's (whsec_ + base64; Clerk, Resend and other
	// Svix senders). A `secret: "whsec_..."` beside `verify:` used to pass.
	{"webhook signing secret (whsec_)", regexp.MustCompile(`\bwhsec_[0-9A-Za-z+/]{24,}`)},
	// Shopify app secret (verifies Shopify webhooks) and access tokens.
	{"Shopify app secret or access token", regexp.MustCompile(`\bshp(ss|at|ca|pa)_[0-9a-fA-F]{32}\b`)},
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
	// The header alone is not a key: code and comments name the format
	// ("-----BEGIN PRIVATE KEY-----" when parsing one from env, or building
	// one around an env value). A key's base64 body follows the header
	// directly, after a newline or an escaped \n in a JSON or env string.
	{"Private key block", regexp.MustCompile(`-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----(?:\s|\\[nr])*[A-Za-z0-9+/]{32,}`)},
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

	// Desktop-metadata sidecars are never app content. The loader ignores
	// them, so writing one silently does nothing - refuse it instead.
	if pathHasMetadataSidecar(clean) {
		return "forbidden path: " + path + " is a desktop metadata sidecar (AppleDouble `._*`, .DS_Store, Thumbs.db), not app content. The runtime ignores these names so the write would have no effect. If this came from `tar` on macOS, rebuild the archive with COPYFILE_DISABLE=1 (or `--no-xattrs --no-mac-metadata`) and upload the real file."
	}

	// Hard rejects - these files actively break the framework's build.
	switch base {
	case "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb":
		return "forbidden path: " + path + " doesn't belong in a Benmore app. There's no npm step: the framework compiles browser modules with embedded esbuild and serves its own modules, 'bm' (/_internal/bm.js) and 'sdui' (/_internal/sdui.js), through the page's import map. It ships no React or other npm package, and a bare import of one (`import ... from 'react'`) fails to build. To use a library, copy its ES module files under static/ and import them relatively; for server-side work, write a flow in flows.yaml."
	case ".npmrc", ".yarnrc", ".pnpmrc":
		return "forbidden path: " + path + " - Benmore has no npm step. Drop the file."
	case "webpack.config.js", "vite.config.js", "vite.config.ts", "rollup.config.js", "esbuild.config.js":
		return "forbidden path: " + path + " - Benmore runs esbuild internally with the right config for /static/<entry>.<hash>.js bundles. No custom build config is needed; don't try to override it."
	}
	if clean == "node_modules" || strings.HasPrefix(clean, "node_modules/") || strings.Contains(clean, "/node_modules/") {
		return "forbidden path: " + path + " - Benmore has no node_modules. The framework serves 'bm' and 'sdui' as bare imports (the import map); copy any other library's ES module files under static/ and import them relatively, or map a bare name to such a file with a tsconfig.json `paths` entry."
	}
	if strings.HasPrefix(clean, "dist/") || strings.HasPrefix(clean, "build/") {
		return "forbidden path: " + path + " - Benmore emits content-hashed bundles into static/ automatically (e.g. static/app.<hash>.js). You don't write build artifacts by hand."
	}
	// Soft warnings - file is allowed to exist but agent's edit is futile.
	if clean == "types/bm.d.ts" {
		return "types/bm.d.ts is auto-overwritten on every `benmore dev` / `benmore serve` boot from the framework's embedded `bm.d.ts` source. Hand-edits are silently reverted. If you want different types: the d.ts the framework ships covers the whole bm SDK (bm.table, bm.auth, bm.live, bm.query, ...). If something's missing, ask for it in the framework, don't patch it locally."
	}
	return ""
}

// isSPASourceFile returns true if the path is a TS/JS browser module
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
// framework's esbuild contract (esbuild, not tsc, emits the bundle).
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
	// TypeScript 7 removed baseUrl (paths are relative to the project root).
	// Keeping it is a hard error under tsc 7 / editor TS 7.
	if strings.Contains(content, `"baseUrl"`) {
		return "tsconfig.json: `\"baseUrl\"` was removed in TypeScript 7. Drop it and keep `paths` entries relative to the project root (e.g. `\"bm\": [\"./src/bm.d.ts\"]`)."
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
// HTML untouched and let the page's own script render it" - template tags are
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
			"%s: declares `engine: raw` but contains mustache `{{var}}` syntax. Raw pages do NOT process mustache - the template tags will render literally as text. Either:\n  (a) fetch the data client-side in a TSX module with bm.table('<table>').list() / .get(id) and render it into the page, or\n  (b) change frontmatter to `engine: gotmpl` if you need server-rendered HTML (typical for marketing/SEO pages, not for app UI).",
			path)
	}
	return ""
}

// validateGotmplParseIn runs the gotmpl body through html/template's
// parser to catch unbalanced {{ }}, unknown function names, wrong
// argument shapes, etc. before render time. Only applies if the file
// declared engine: gotmpl in frontmatter.
//
// Uses the SAME FuncMap the runtime registers (gotmplHelpers, with
// app and ctx nil - every helper is nil-safe) so argument-arity
// checks match what will actually run.
//
// This runs in the router on MCP write_file/edit_file, and it DOES
// execute tenant template code: wrong-arity calls and helper errors
// (dict with an odd argument count) only surface at execute time.
// The execution is hermetic and bounded - see validateGotmplExecute
// (gotmpl_validate.go): no environment/DNS helpers, a step budget and
// deadline charged on every call, range iteration and template entry,
// per-call size limits, and a bounded output writer.
func validateGotmplParseIn(appDir, path, content string) string {
	fm, body, err := ExtractFrontmatter(content)
	if err != nil {
		return fmt.Sprintf("frontmatter yaml in %s: %s\n\nFix the YAML at the top of the file (between the `---` fences). Common mistakes: missing `:`, indentation not in spaces, special characters in unquoted strings.", path, err)
	}
	if fm == nil || strings.ToLower(strings.TrimSpace(fm.Engine)) != "gotmpl" {
		return ""
	}
	// Register partials/*.html so `{{template "name" .}}` references
	// resolve at parse + execute time. Without this, every page that
	// uses a partial trips a "no such template" false positive.
	// Caller's appDir takes precedence; fall back to the path-based
	// heuristic for older callers that don't pass an app dir.
	resolved := appDir
	if resolved == "" {
		resolved = guessAppDirForPath(path)
	}
	var partials map[string]string
	if resolved != "" {
		partials = partialsForValidation(resolved)
	}
	// Parse first so a syntax error is reported as such.
	if _, err := template.New(path).Funcs(gotmplHelpers(nil, nil)).Option("missingkey=zero").Parse(body); err != nil {
		return formatGotmplError(path, err)
	}
	// Stub-execute against nil so wrong-arity and helper errors
	// (which html/template only surfaces at execute, not at parse)
	// also bubble up at write time. The "missingkey=zero" option
	// ensures `.notes` and friends silently resolve to the zero value
	// - those are data-dependent, not template-intrinsic, so they
	// shouldn't be false-positive errors here.
	if err := validateGotmplExecute(path, body, partials); err != nil {
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

// partialsForValidation reads partials/*.html, keyed by template
// name. Reads go through an os.Root at appDir (readGotmplPartials),
// so a symlinked partial can't pull a file from outside the app into
// the router's validation pass. Best-effort: partials that fail to
// parse are skipped silently by the caller (their own validator pass
// will surface the error when that file is checked individually).
func partialsForValidation(appDir string) map[string]string {
	out := map[string]string{}
	for file, data := range readGotmplPartials(appDir) {
		// Strip frontmatter from partials too - they may have it.
		_, body, _ := ExtractFrontmatter(data)
		out[strings.TrimSuffix(file, ".html")] = body
	}
	return out
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
	models, err := ParsePrismaSchema(content)
	if err != nil {
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
	// Write gate and `benmore check` only: the parser skips these
	// declarations and a deployed schema keeps loading.
	if problems := prismaIgnoredSchemaProblems(content, models); len(problems) > 0 {
		return strings.Join(problems, "\n")
	}
	// The load refuses these (validators_load_refs.go).
	if problems := prismaFullTextProblems(models); len(problems) > 0 {
		return strings.Join(problems, "\n")
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
	if err := decodeConfigYAML([]byte(content), &probe); err != nil {
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
	// A role list would fail the typed decode below with the decoder's own
	// words (validators_flow_role_gate.go).
	if msg := flowRoleListViolation(probe); msg != "" {
		return msg
	}
	var ghaFile FlowFileGHA
	if err := yamlUnmarshal([]byte(content), &ghaFile); err != nil {
		return fmt.Sprintf("flows.yaml: invalid typed declaration: %v", err)
	}
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
		// Write gate and `benmore check` only (the loader keeps loading
		// these files and logs them): triggers it reads leniently, keys it
		// drops (in the file's structure and per step type), values it
		// can't honor, and conditions that can never be true (they log once
		// and are false).
		if problems := flowTriggerProblems(ghaFile); len(problems) > 0 {
			return strings.Join(problems, "\n")
		}
		if msg := validateGHAFlowsContents(ghaFile); msg != "" {
			return msg
		}
		// SQL in a parallel block of a transactional flow: the app does not
		// register the flow (validators_flow_ignored_values.go). Here and not
		// in validateGHAFlowsContents, which the loader shares: a deployed
		// file still loads its other jobs.
		if problems := flowParallelSQLInTransactionProblems(ghaFile); len(problems) > 0 {
			return strings.Join(problems, "\n")
		}
		// A guard reading an output its SQL step does not return never sees
		// it (validators_step_outputs.go). Write gate and check only: a live
		// app with such a guard keeps loading.
		if guards, _ := stepOutputRefProblems(ghaFile); len(guards) > 0 {
			return "flows.yaml: " + guards[0]
		}
		if msg := flowUnknownKeyViolation(content); msg != "" {
			return msg
		}
		if msg := flowTriggerValueViolation(ghaFile); msg != "" {
			return msg
		}
		if msg := expectRowsEmptyViolation(content); msg != "" {
			return msg
		}
		// A step key its step type does not read (validators_flow_step_keys.go).
		if refused, _ := flowStepKeyProblems(content, ghaFile); len(refused) > 0 {
			return strings.Join(refused, "\n")
		}
		// A step value that would not be sent as written
		// (validators_flow_step_values.go).
		if problems := flowStepValueProblems(ghaFile); len(problems) > 0 {
			return strings.Join(problems, "\n")
		}
		if msg := flowUnreachableResponseViolation(ghaFile); msg != "" {
			return msg
		}
		// A `${{ }}` value expression that doesn't parse never resolves
		// (flows_value_expr.go).
		if msg := ghaValueExpressionViolation(ghaFile); msg != "" {
			return msg
		}
		if msg := ghaDeadConditionViolation(ghaFile); msg != "" {
			return msg
		}
		// A `steps.<id>` naming no step in the flow reads as empty: a guard
		// on it never fires (validators_step_ids.go). Checked after the
		// file's structure, whose problems are named first. Write gate and
		// check only: a live app with such a reference keeps loading.
		if problems := unknownStepRefProblems(ghaFile); len(problems) > 0 {
			return strings.Join(problems, "\n")
		}
		return ""
	}
	if err := rejectLegacyHandledStatuses([]byte(content)); err != nil {
		return "flows.yaml: " + err.Error()
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
// Types are enforced before execution and also drive FlowForm controls.
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
		// A default is bound when the caller omits the input
		// (bindFlowInputDefaults), so it must be a value the caller could
		// have sent.
		if in.Default != nil {
			check := map[string]FlowInput{name: {Type: in.Type, Values: in.Values, Min: in.Min, Max: in.Max}}
			if err := validateFlowInputValues(check, map[string]any{name: flowInputDefaultValue(in.Default)}); err != nil {
				return fmt.Sprintf("flows.yaml: input %q has `default: %v`, which is not a valid %s value: %v. The default is bound when a caller omits the input, so it must pass the same check a sent value does.", name, in.Default, in.Type, err)
			}
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
	if err := yamlUnmarshal([]byte(content), &raw); err != nil || len(raw) == 0 {
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
	if err := yamlUnmarshal([]byte(content), &legacy); err == nil && len(legacy) > 0 {
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

// commandDeclarationPresent recognizes the command discriminator without
// treating arbitrary YAML syntax errors as command files. Syntax validation
// remains the responsibility of the normal flow validator.
func commandDeclarationPresent(content string) bool {
	var shape map[string]any
	if err := decodeConfigYAML([]byte(content), &shape); err != nil {
		return false
	}
	_, ok := shape["command"]
	return ok
}

// commandWritePath returns the compiler's app-relative source identity only
// for the one supported placement. In particular, it does not flatten a
// nested or outside path to its basename before compilation.
func commandWritePath(appDir, filePath string) (string, error) {
	if strings.TrimSpace(appDir) == "" {
		return "", fmt.Errorf("command declarations require an app directory")
	}
	root, err := filepath.Abs(appDir)
	if err != nil {
		return "", fmt.Errorf("resolve app directory: %w", err)
	}
	var rel string
	if filepath.IsAbs(filePath) {
		abs, err := filepath.Abs(filePath)
		if err != nil {
			return "", fmt.Errorf("resolve command path: %w", err)
		}
		rel, err = filepath.Rel(root, abs)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
			return "", fmt.Errorf("command path must stay inside the app directory")
		}
	} else {
		if filepath.IsAbs(filepath.Clean(filePath)) {
			return "", fmt.Errorf("command path must stay inside the app directory")
		}
		rel = filepath.Clean(filePath)
		if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			return "", fmt.Errorf("command path must stay inside the app directory")
		}
	}
	rel = filepath.ToSlash(rel)
	parts := strings.Split(rel, "/")
	if len(parts) != 2 || parts[0] != "flows" || strings.ToLower(filepath.Ext(rel)) != ".yaml" {
		return "", fmt.Errorf("a command declaration must be written to flows/<name>.yaml (directly in flows/, extension .yaml): %s", commandFileNameRule)
	}
	return rel, nil
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
	if file.On.Request != nil {
		if err := validateFlowPermissions(file.On.Request.Permissions); err != nil {
			return "flows.yaml: " + err.Error()
		}
	}
	if msg := validatePurgeCurrentUserContract(file); msg != "" {
		return msg
	}
	if msg := validateRevokeUserSessionsOutsideFlows(file); msg != "" {
		return msg
	}
	// Derive from flowRunTypes (flows_gha.go) - the SINGLE SOURCE the parser
	// switch also uses, so this validator can never drift behind a new step
	// type again. Empty `run:` is allowed (query:/if:/for_each: shorthand).
	knownRun := map[string]bool{"": true}
	for t := range flowRunTypes {
		knownRun[t] = true
	}
	if file.On.Request != nil {
		switch raw := file.On.Request.Verify.(type) {
		case nil, string:
			// Empty and legacy named/header verifiers retain their existing shape.
		case map[string]any:
			verify := parseVerifyMap(raw)
			if err := validateFlowVerifyConfig(verify, file.On.Request.Path); err != nil {
				return "flows.yaml: invalid verify config: " + err.Error()
			}
			if err := verifySkewWithinLimit(verify); err != nil {
				return "flows.yaml: invalid verify config: " + err.Error()
			}
		default:
			return fmt.Sprintf("flows.yaml: verify must be a string or map, got %T", raw)
		}
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
	// `run: proxy` steps: where they may run and what they take
	// (validators_flow_proxy.go).
	if msg := ghaProxyViolation(file); msg != "" {
		return msg
	}
	for jobName, job := range file.Jobs {
		if len(job.Steps) == 0 {
			return fmt.Sprintf(
				"flows.yaml: job %q has no steps. Every job needs at least one step under `steps:`.",
				jobName)
		}
		if err := flowValidateParallelHTTP(&Flow{Name: jobName, Steps: convertGHASteps(job.Steps)}); err != nil {
			return "flows.yaml: " + err.Error()
		}
		if file.On.Request != nil && file.On.Request.Transaction {
			flow := &Flow{Name: jobName, Trigger: FlowTrigger{Type: "http"}, Transaction: true, Steps: convertGHASteps(job.Steps)}
			if err := flowValidateTransactionalResponse(flow); err != nil {
				return "flows.yaml: " + err.Error()
			}
		}
		// `when:` is not a flow-engine key (only `if:` is), so yaml.v3 drops it
		// and the guard never applies. Catch it on ANY step, including nested
		// if/for_each/else/on_error branches - an `on_error:` respond branch is
		// exactly where the "my guard keeps firing" footgun lives.
		if msg := ghaWhenViolation(jobName, job.Steps); msg != "" {
			return msg
		}
		if msg := ghaBroadcastViolation(jobName, "", job.Steps); msg != "" {
			return msg
		}
		if msg := ghaNotifyViolation(jobName, "", job.Steps); msg != "" {
			return msg
		}
		if msg := ghaReservedStepIDViolation(jobName, job.Steps); msg != "" {
			return msg
		}
		if msg := ghaHandledStatusesViolation(jobName, "", job.Steps); msg != "" {
			return msg
		}
		for i, s := range job.Steps {
			if !knownRun[strings.ToLower(strings.TrimSpace(s.Run))] {
				return fmt.Sprintf(
					"flows.yaml: job %q step %d has `run: %s` which isn't a known step type.\n"+
						"Known: sql, sql_dynamic, api, email, sms, webhook, redirect, respond, parse, set, parallel, broadcast, notify.\n"+
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
			// sql_dynamic nested under if/for_each/parallel/else/on_error
			// runs exactly like a top-level one, so it gets the same check.
			if msg := ghaNestedSQLDynamicViolation(jobName, fmt.Sprintf("step %d", i), s); msg != "" {
				return msg
			}
		}
	}
	return ""
}

// ghaHandledStatusesViolation checks the opt-in response-status list at every
// executable nesting level. Because validateGHAFlowsContents is shared by
// file writes, `benmore check`, and the loader, malformed values cannot be
// silently dropped by withToAPI.
func ghaHandledStatusesViolation(jobName, parent string, steps []FlowStepGHA) string {
	for i, s := range steps {
		label := fmt.Sprintf("step %d", i)
		if parent != "" {
			label = parent + " > " + label
		}
		if strings.EqualFold(strings.TrimSpace(s.Run), "api") {
			if _, present := s.With["handled_statuses"]; present {
				if _, err := parseHandledStatuses(s.With["handled_statuses"]); err != nil {
					return fmt.Sprintf("flows.yaml: job %q %s with.handled_statuses %s", jobName, label, err)
				}
				if _, paginated := s.With["paginate"]; paginated {
					return fmt.Sprintf("flows.yaml: job %q %s cannot combine with.handled_statuses with with.paginate", jobName, label)
				}
			}
		}
		branches := []struct {
			name  string
			steps []FlowStepGHA
		}{
			{ghaNestedBodyName(s) + " steps", s.Steps},
			{"else", s.Else},
			{"on_error", s.OnError},
		}
		for _, branch := range branches {
			if msg := ghaHandledStatusesViolation(jobName, label+" > "+branch.name, branch.steps); msg != "" {
				return msg
			}
		}
	}
	return ""
}

// ghaNestedSQLDynamicViolation applies validateSQLDynamicSafety to every step
// nested below s: `steps:` (if / for_each / parallel bodies), `else:` and
// `on_error:`. These are every nesting key FlowStepGHA carries, and the
// parser (convertGHASteps) turns each into executable steps. The label is a
// readable path (`step 2 > for_each steps[0]`) so the author can find the
// offending step.
func ghaNestedSQLDynamicViolation(jobName, label string, s FlowStepGHA) string {
	branches := []struct {
		name  string
		steps []FlowStepGHA
	}{
		{ghaNestedBodyName(s) + " steps", s.Steps},
		{"else", s.Else},
		{"on_error", s.OnError},
	}
	for _, b := range branches {
		for i, child := range b.steps {
			childLabel := fmt.Sprintf("%s > %s[%d]", label, b.name, i)
			if msg := validateSQLDynamicSafetyAt(jobName, childLabel, child); msg != "" {
				return msg
			}
			if msg := ghaNestedSQLDynamicViolation(jobName, childLabel, child); msg != "" {
				return msg
			}
		}
	}
	return ""
}

// ghaBroadcastViolation checks every `run: broadcast` step, at any nesting
// depth: `with.room` must be a non-empty string whose literal characters are
// legal in a room name, `with.payload` must be present, and no other `with:`
// key is accepted (yaml would otherwise keep a misspelled `paylod:` and the
// step would fail only at run time). Shared by the write gate, `benmore check`
// and the flow loader through validateGHAFlowsContents.
func ghaBroadcastViolation(jobName, parent string, steps []FlowStepGHA) string {
	const example = "\n\nExample:\n" +
		"  - id: notify\n" +
		"    run: broadcast\n" +
		"    with:\n" +
		"      room: \"order-${{ steps.o.outputs.id }}\"\n" +
		"      payload: { kind: shipped, id: \"${{ steps.o.outputs.id }}\" }"
	for i, s := range steps {
		label := fmt.Sprintf("step %d", i)
		if parent != "" {
			label = fmt.Sprintf("%s[%d]", parent, i)
		}
		if strings.EqualFold(strings.TrimSpace(s.Run), "broadcast") {
			where := fmt.Sprintf("flows.yaml: job %q %s (run: broadcast)", jobName, label)
			room, isString := s.With["room"].(string)
			switch {
			case s.With["room"] == nil:
				return where + " requires `with.room` - the WebSocket room to send to." + example
			case !isString:
				return where + fmt.Sprintf(": `with.room` must be a string, got %T - quote it (room: \"42\")."+example, s.With["room"])
			case strings.TrimSpace(room) == "":
				return where + ": `with.room` is empty." + example
			}
			if bad := broadcastRoomLiteralViolation(room); bad != "" {
				return where + fmt.Sprintf(": `with.room` %q contains %s; a room name is 1-%d characters of a-z A-Z 0-9 _ - . : (`${{ }}` refs are filled in at run time).", room, bad, wsRoomNameMax)
			}
			if _, ok := s.With["payload"]; !ok {
				return where + " requires `with.payload` - the JSON value room members receive (an object, list, string or number; `${{ }}` refs resolve like a respond body)." + example
			}
			for key := range s.With {
				if key != "room" && key != "payload" {
					return where + fmt.Sprintf(": `with.%s` is not a broadcast option; the step takes only `room` and `payload`.", key)
				}
			}
		}
		for _, b := range []struct {
			name  string
			steps []FlowStepGHA
		}{{ghaNestedBodyName(s) + " steps", s.Steps}, {"else", s.Else}, {"on_error", s.OnError}} {
			if msg := ghaBroadcastViolation(jobName, label+" > "+b.name, b.steps); msg != "" {
				return msg
			}
		}
	}
	return ""
}

// ghaDeadConditionViolation refuses an `if:`, api `success_when:` or templated
// serve_file `disposition:` that can never evaluate true (flowConditionNeverHolds),
// at any nesting depth. Such a condition is silently false at run time, so a
// guard written with it never fires: the refusal branch is skipped and the
// flow carries on. Jobs are visited in name order for a stable message.
func ghaDeadConditionViolation(file FlowFileGHA) string {
	const grammar = " Conditions compare values with == != > < >= <=, join comparisons with && || and ! and parentheses, and read refs such as steps.<id>.outputs.<field>, params.<name>, user.<field> and env.<NAME>; functions (contains(), startsWith()), arithmetic and `in` are not supported. See api({at:'flows'})."
	var walk func(job, parent string, steps []FlowStepGHA) string
	walk = func(job, parent string, steps []FlowStepGHA) string {
		for i, s := range steps {
			label := fmt.Sprintf("step %d", i)
			if parent != "" {
				label = fmt.Sprintf("%s[%d]", parent, i)
			}
			where := fmt.Sprintf("flows.yaml: job %q %s", job, label)
			if s.If != "" {
				if why := flowConditionNeverHolds(ghaIfToFlowCondition(s.If)); why != "" {
					return fmt.Sprintf("%s: `if: %s` can never be true (%s), so the branch never runs.%s", where, truncate(s.If, 200), why, grammar)
				}
			}
			if v, ok := s.With["success_when"].(string); ok && strings.EqualFold(strings.TrimSpace(s.Run), "api") {
				if why := flowConditionNeverHolds(normalizeGHARefs(v)); why != "" {
					return fmt.Sprintf("%s: `success_when: %s` can never be true (%s), so every call fails.%s", where, truncate(v, 200), why, grammar)
				}
			}
			if v, ok := s.With["disposition"].(string); ok && strings.EqualFold(strings.TrimSpace(s.Run), "serve_file") {
				if why := flowValueTemplateNeverParses(normalizeGHARefs(v)); why != "" {
					return fmt.Sprintf("%s: `disposition: %s` can't be evaluated (%s), so the file is always served inline.%s", where, truncate(v, 200), why, grammar)
				}
			}
			for _, b := range []struct {
				name  string
				steps []FlowStepGHA
			}{{ghaNestedBodyName(s) + " steps", s.Steps}, {"else", s.Else}, {"on_error", s.OnError}} {
				if msg := walk(job, label+" > "+b.name, b.steps); msg != "" {
					return msg
				}
			}
		}
		return ""
	}
	jobs := make([]string, 0, len(file.Jobs))
	for name := range file.Jobs {
		jobs = append(jobs, name)
	}
	slices.Sort(jobs)
	for _, name := range jobs {
		if msg := walk(name, "", file.Jobs[name].Steps); msg != "" {
			return msg
		}
	}
	return ""
}

// broadcastRoomLiteralViolation describes the first character outside the
// room-name alphabet in the literal (non-`{{ }}`) part of a room template, or
// the literal length when it already exceeds the limit.
func broadcastRoomLiteralViolation(room string) string {
	literal := room
	for {
		start := strings.Index(literal, "{{")
		if start < 0 {
			break
		}
		end := strings.Index(literal[start:], "}}")
		if end < 0 {
			break
		}
		cut := start
		if cut > 0 && literal[cut-1] == '$' {
			cut--
		}
		literal = literal[:cut] + literal[start+end+2:]
	}
	literal = strings.TrimSpace(literal)
	if len(literal) > wsRoomNameMax {
		return fmt.Sprintf("%d literal characters", len(literal))
	}
	for _, r := range literal {
		ok := (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '_' || r == '-' || r == '.' || r == ':'
		if !ok {
			return fmt.Sprintf("the character %q", r)
		}
	}
	return ""
}

// ghaNestedBodyName names the construct that owns a step's `steps:` list,
// for validator messages.
func ghaNestedBodyName(s FlowStepGHA) string {
	switch run := strings.ToLower(strings.TrimSpace(s.Run)); {
	case run == "parallel":
		return "parallel"
	case run == "for_each" || (run == "" && s.ForEach != ""):
		return "for_each"
	case s.If != "":
		return "if"
	}
	return "nested"
}

// validatePurgeCurrentUserContract makes the server-only identity purge a
// deliberately small language inside the broader flow DSL. The action has no
// target parameter: it operates only on the immutable authenticated session.
// These shape checks prevent an app from accidentally exposing it to an
// anonymous, async, non-transactional, nested, or retrying execution path.
func validateRevokeUserSessionsOutsideFlows(file FlowFileGHA) string {
	var found bool
	var walk func([]FlowStepGHA)
	walk = func(steps []FlowStepGHA) {
		for _, step := range steps {
			if strings.EqualFold(strings.TrimSpace(step.Run), "revoke_user_sessions") {
				found = true
			}
			walk(step.Steps)
			walk(step.Else)
			walk(step.OnError)
		}
	}
	for _, cfg := range file.Jobs {
		walk(cfg.Steps)
	}
	if !found {
		return ""
	}
	return "flows.yaml: run: revoke_user_sessions is available only in the apply phase of an approved MCP command (flows/<name>.yaml with a `command:` block). Ordinary flows end a user's sessions through their own credential change or the admin console."
}

func validatePurgeCurrentUserContract(file FlowFileGHA) string {
	type occurrence struct {
		job    string
		index  int
		nested bool
		step   FlowStepGHA
	}
	var found []occurrence
	var walk func(string, []FlowStepGHA, bool)
	walk = func(job string, steps []FlowStepGHA, nested bool) {
		for i, step := range steps {
			if strings.EqualFold(strings.TrimSpace(step.Run), "purge_current_user") {
				found = append(found, occurrence{job: job, index: i, nested: nested, step: step})
			}
			walk(job, step.Steps, true)
			walk(job, step.Else, true)
			walk(job, step.OnError, true)
		}
	}
	for job, cfg := range file.Jobs {
		walk(job, cfg.Steps, false)
	}
	if len(found) == 0 {
		return ""
	}
	fail := func(reason string) string {
		return "flows.yaml: run: purge_current_user " + reason + ". It is a server-only, identity-bound account-erasure primitive; use one direct top-level step with `with: { confirm: '${{ params.confirm }}' }` on an auth-required transactional POST/DELETE flow."
	}
	if len(found) != 1 || len(file.Jobs) != 1 {
		return fail("must appear exactly once in a single-job flow")
	}
	if file.On.Request == nil {
		return fail("is allowed only on an HTTP request trigger")
	}
	method := strings.ToUpper(strings.TrimSpace(file.On.Request.Method))
	if method != http.MethodPost && method != http.MethodDelete {
		return fail("requires method POST or DELETE")
	}
	if strings.TrimSpace(file.On.Request.Auth) != "required" {
		return fail("requires `auth: required`")
	}
	if !file.On.Request.Transaction {
		return fail("requires `transaction: true`")
	}
	if strings.EqualFold(strings.TrimSpace(file.On.Request.Mode), "async") {
		return fail("cannot run in async mode because the live session identity must stay attached")
	}
	o := found[0]
	if o.nested || strings.TrimSpace(o.step.If) != "" {
		return fail("must be a direct top-level step, never nested or `if:`-gated")
	}
	if len(o.step.OnError) != 0 || len(o.step.Steps) != 0 || len(o.step.Else) != 0 || o.step.Retry != 0 {
		return fail("cannot have retry, on_error, steps, or else branches")
	}
	if len(o.step.With) != 1 {
		return fail("accepts exactly one `with:` key named `confirm`")
	}
	confirm, ok := o.step.With["confirm"].(string)
	if !ok || strings.TrimSpace(confirm) != "${{ params.confirm }}" {
		return fail("must bind confirmation directly from `${{ params.confirm }}`; a hardcoded confirmation is forbidden")
	}
	steps := file.Jobs[o.job].Steps
	for _, step := range steps[o.index+1:] {
		run := strings.ToLower(strings.TrimSpace(step.Run))
		if run == "" && strings.TrimSpace(step.Query) != "" {
			run = "sql"
		}
		if run != "sql" && run != "respond" {
			return fail("may be followed only by an audit/readback SQL step and the final respond step")
		}
		if strings.TrimSpace(step.If) != "" || len(step.Steps) != 0 || len(step.Else) != 0 || len(step.OnError) != 0 {
			return fail("may not be followed by conditional or nested cleanup")
		}
	}
	return ""
}

// readAppFileOrNil returns an app file's bytes, or nil when it is absent.
func readAppFileOrNil(appDir, name string) []byte {
	data, err := os.ReadFile(filepath.Join(appDir, name))
	if err != nil {
		return nil
	}
	return data
}

// validateFulltextEncryptedConflict refuses an encrypted column listed in a
// model's @@fulltext. The FTS5 index is external-content: its sync triggers
// index the plaintext the INSERT wrote, then the encryption trigger rewrites
// the column to ciphertext, so the index no longer matches its content and
// every INSERT fails with "database disk image is malformed". Even if it
// worked, the index shadow tables would hold the plaintext the column is
// encrypted to protect. only, when non-nil, restricts the check to those
// tables (the ones the file being written is responsible for).
func validateFulltextEncryptedConflict(schema string, enc *EncryptedFieldConfig, only map[string]bool) string {
	if enc == nil || strings.TrimSpace(schema) == "" {
		return ""
	}
	models, err := ParsePrismaSchema(schema)
	if err != nil {
		return ""
	}
	var conflicts []string
	for _, m := range models {
		if only != nil && !only[m.Table] {
			continue
		}
		encrypted := map[string]bool{}
		for _, def := range enc.Fields[m.Table] {
			encrypted[def.Column] = true
		}
		if len(encrypted) == 0 {
			continue
		}
		for _, idx := range m.FullText {
			for _, name := range prismaFullTextColumns(m, idx.Columns) {
				if encrypted[name] {
					conflicts = append(conflicts, fmt.Sprintf("%s.%s (model %s)", m.Table, name, m.Name))
				}
			}
		}
	}
	if len(conflicts) == 0 {
		return ""
	}
	return fmt.Sprintf(
		"antipattern [fulltext-encrypted-column] encrypted column(s) listed in @@fulltext: %s.\n"+
			"Full-text search cannot index an encrypted column: the FTS5 index is written from the plaintext, then the encryption trigger replaces the value with ciphertext, the index falls out of sync and every INSERT on the table fails (\"database disk image is malformed\"). The index would also store the plaintext you are encrypting.\n"+
			"Fix one side: remove the column from @@fulltext (keep search on non-sensitive columns such as a title), or stop encrypting it in encrypted.yaml. For exact-match lookup on an encrypted column use `blind_index:` instead.",
		strings.Join(conflicts, ", "))
}

// ghaRedirectWarnings flags `run: redirect` steps whose `to:` is templated
// without being pinned to a same-origin path and without an `allow_hosts:`
// list. At run time such a target is refused whenever it renders off-origin
// (flowRedirectTarget), because a request-controlled `to:` is an open
// redirect. Advisory: the flow still loads, and a target that happens to
// render same-origin still redirects. Shared by the write path (MCP
// write_file/edit_file report through RunCompleteCheck) and `benmore check`.
func ghaRedirectWarnings(content string) []string {
	var file FlowFileGHA
	if err := yamlUnmarshal([]byte(content), &file); err != nil || file.Jobs == nil {
		return nil
	}
	var out []string
	var walk func(job string, steps []FlowStepGHA)
	walk = func(job string, steps []FlowStepGHA) {
		for _, s := range steps {
			if strings.EqualFold(strings.TrimSpace(s.Run), "redirect") {
				to, _ := s.With["to"].(string)
				if flowRedirectTemplateUnpinned(to) && len(flowRedirectAllowHosts(s.With["allow_hosts"])) == 0 {
					label := s.ID
					if label == "" {
						label = "redirect"
					}
					out = append(out, fmt.Sprintf(
						"job %q step %q redirects to a templated `to: %s`. A templated target may only stay on this app's origin: it is refused at run time if it renders another host (open-redirect guard). Pin it to a path (`to: /orders/${{ steps.o.outputs.id }}`) or list the external hosts it may reach: `with: { to: ..., allow_hosts: [checkout.example.com] }`.",
						job, label, to))
				}
			}
			walk(job, s.Steps)
			walk(job, s.Else)
			walk(job, s.OnError)
		}
	}
	jobs := make([]string, 0, len(file.Jobs))
	for name := range file.Jobs {
		jobs = append(jobs, name)
	}
	slices.Sort(jobs)
	for _, name := range jobs {
		walk(name, file.Jobs[name].Steps)
	}
	return out
}

// flowRedirectTemplateUnpinned reports whether a redirect `to:` can render
// an off-origin target from substituted input: it contains a `{{ }}` /
// `${{ }}` reference or a `:param` token, and its literal prefix is not a
// same-origin path ("/x..." where the second byte is neither '/' nor '\'
// nor the start of a template).
func flowRedirectTemplateUnpinned(to string) bool {
	to = strings.TrimSpace(to)
	templated := strings.Contains(to, "{{")
	for i := 0; !templated && i+1 < len(to); i++ {
		if to[i] == ':' && isSQLIdentStart(to[i+1]) && (i == 0 || (to[i-1] != ':' && !isSQLIdentChar(to[i-1]))) {
			templated = true
		}
	}
	if !templated {
		return false
	}
	if len(to) >= 2 && to[0] == '/' && !strings.ContainsRune(`/\{$`, rune(to[1])) {
		return false
	}
	return true
}

// ghaWhenViolation recursively finds a `when:` key on any flow step, including
// nested if/for_each/else/on_error branches.
// ghaReservedStepIDViolation refuses the step id `params`:
// `${{ steps.params.outputs.x }}` would read as the request field
// `${{ params.x }}`.
func ghaReservedStepIDViolation(jobName string, steps []FlowStepGHA) string {
	for _, s := range steps {
		switch strings.TrimSpace(s.ID) {
		case "params":
			return fmt.Sprintf("flows.yaml: job %q has a step with id %q, which is a reserved template name; rename the step.", jobName, s.ID)
		}
		for _, nested := range [][]FlowStepGHA{s.Steps, s.Else, s.OnError} {
			if msg := ghaReservedStepIDViolation(jobName, nested); msg != "" {
				return msg
			}
		}
	}
	return ""
}

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
//  2. INSERT INTO … SELECT … ON CONFLICT … with no outer WHERE or
//     SELECT-closing clause - SQLite can parse ON as a join constraint.
//     Keep an existing predicate, or add `WHERE true` before ON CONFLICT.
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
	return validateSQLDynamicSafetyAt(jobName, fmt.Sprintf("step %d", stepIdx), s)
}

// validateSQLDynamicSafetyAt is validateSQLDynamicSafety with a free-form
// step label, so nested steps can be reported by their path.
func validateSQLDynamicSafetyAt(jobName, stepLabel string, s FlowStepGHA) string {
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
		// `params.X` is namespaced but is the request itself: the runtime
		// taint guard refuses it on every request, so the flow could never
		// run (it used to pass the write gate and fail when called).
		// An expression (`a && params.x`, `x == 'y'`) is checked ref by ref:
		// the runtime guard reads every ref in it (flowValueExprRefPaths).
		if flowValueExprUsesOperators(tok) {
			for _, ref := range flowValueExprRefs(tok, true) {
				if !strings.Contains(ref, ".") || strings.HasPrefix(ref, "params.") {
					tok = ref
					break
				}
			}
		}
		if base, _, _ := strings.Cut(tok, "|"); tok != "" && (!strings.Contains(tok, ".") || strings.HasPrefix(strings.TrimSpace(base), "params.")) {
			return fmt.Sprintf(
				"flows.yaml: job %q %s (`run: sql_dynamic`) interpolates a bare `{{%s}}` directly into the query.\n"+
					"sql_dynamic substitutes values as raw SQL TEXT, not bound parameters - a bare reference fed from request input is a SQL-injection hole.\n"+
					"For request input, use `run: sql` (or `query:`) where `${{ %s }}` / `:%s` bind as ? placeholders. Reserve sql_dynamic for SQL assembled from server-trusted values (`${{ env.X }}`, `${{ steps.<id>.outputs.<column> }}`).",
				jobName, stepLabel, tok, tok, tok)
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
				"flows.yaml: job %q %s (`run: sql_dynamic`) uses a `:%s` placeholder.\n"+
					"sql_dynamic does NOT bind `:params` - it text-substitutes them, so this is injectable from request input.\n"+
					"Use `run: sql` (or `query:`) where `:%s` binds as a ? placeholder.",
				jobName, stepLabel, name, name)
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

	// (2) SQLite requires the SELECT to end unambiguously before ON CONFLICT.
	// Any actual outer WHERE predicate works; a comment/string/subquery does not.
	if upsertSelectNeedsWhere(sql) {
		return fmt.Sprintf(
			"flows.yaml: job %q step %d uses INSERT INTO … SELECT … ON CONFLICT without an outer WHERE clause or another SELECT-closing clause. SQLite may parse ON as a join constraint and fail near DO.\n\n"+
				"Fix: keep your existing WHERE predicate, or add `WHERE true` between SELECT/FROM and ON CONFLICT. A WHERE inside a subquery, quoted value or comment does not separate the outer SELECT.\n\n"+
				"See https://sqlite.org/lang_upsert.html#parsing_ambiguity for why this exists.", jobName, stepIdx)
	}
	return ""
}

// upsertSelectNeedsWhere is a syntax hint, not a complete SQL parser. Use the
// shared SQLite scanner so quoted keywords/comments and nested SELECT clauses
// cannot stand in for the outer clause that disambiguates an upsert.
func upsertSelectNeedsWhere(query string) bool {
	for _, tokens := range sqlTokenStatements(sqlTokenize(query)) {
		verb := sqlStatementVerbIndex(tokens)
		keyword := func(i int, word string) bool {
			return i >= 0 && i < len(tokens) && tokens[i].kind == sqlTokWord && strings.EqualFold(tokens[i].text, word)
		}
		if !keyword(verb, "INSERT") && !keyword(verb, "REPLACE") {
			continue
		}
		depth := 0
		selected, from, closed := false, false, false
	statementLoop:
		for i := verb + 1; i < len(tokens); i++ {
			token := tokens[i]
			if token.kind == sqlTokPunct {
				switch token.text {
				case "(":
					depth++
				case ")":
					if depth > 0 {
						depth--
					}
				}
				continue
			}
			if depth != 0 || token.kind != sqlTokWord {
				continue
			}
			// Named bind parameters are operands, never clause keywords.
			if i > 0 && tokens[i-1].kind == sqlTokPunct && strings.Contains(":@$", tokens[i-1].text) {
				continue
			}
			switch strings.ToUpper(token.text) {
			case "SELECT":
				selected, from, closed = true, false, false
			case "FROM":
				if selected {
					from = true
				}
			case "WHERE", "HAVING", "LIMIT":
				if from {
					closed = true
				}
			case "GROUP", "ORDER":
				if from && keyword(i+1, "BY") {
					closed = true
				}
			case "ON":
				if selected && from && keyword(i+1, "CONFLICT") {
					if !closed {
						return true
					}
					break statementLoop
				}
			}
		}
	}
	return false
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
	"/_internal/", // embedded bm.js, sdui.js and other framework assets
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
	"/openapi.json",
	"/api/openapi.json",
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
	if err := yamlUnmarshal([]byte(content), &raw); err != nil || raw.Jobs == nil {
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
	if err := yamlUnmarshal([]byte(content), &top); err != nil {
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

	// Per-entry keys. yaml.v3 silently drops keys that don't exist on the
	// target struct (same hazard validateGHAFlowsContents guards for flows),
	// so an unrecognized action key parses clean, fires on every matching
	// row, and does nothing - indistinguishable from success. That exact
	// shape shipped: an `sms:` hook written against docs that promised it,
	// against a HookEntryYAML that had no SMS field, silently sent nothing.
	// Gate it at write time so the author hears about it immediately.
	var shaped map[string]map[string][]map[string]any
	if err := decodeConfigYAML([]byte(content), &shaped); err != nil {
		return fmt.Sprintf("hooks.yaml: %s", err)
	}
	var typed HooksYAML
	if err := decodeConfigYAML([]byte(content), &typed); err != nil {
		return fmt.Sprintf("hooks.yaml: %s", err)
	}
	for section, tables := range shaped {
		for table, entries := range tables {
			for i, e := range entries {
				for k := range e {
					if hookEntryKeys[k] {
						continue
					}
					return fmt.Sprintf(
						"hooks.yaml: unknown key %q in %s.%s[%d].\n\n"+
							"Valid keys: %s.\n"+
							"This matters more than a typo usually would: an unrecognized key is DROPPED silently, so the hook would fire and do nothing while the write still looked successful.\n"+
							"Common fabrications: `sms_body:`/`text:` (SMS body goes under `sms:` as `body:`), `send_email:` (use `email:`), `url:` (use `webhook:`), `condition:` (use `when:`).",
						k, section, table, i, strings.Join(hookEntryKeyList, ", "))
				}
			}
		}
	}
	return ""
}

// hookEntryKeys is the set of YAML keys a single hooks.yaml entry may
// carry, derived by reflection from HookEntryYAML's own struct tags.
//
// Deriving rather than hand-listing is the point: HookEntryYAML is what
// yaml.Unmarshal binds against, so it is the only thing that decides which
// keys survive. A hand-maintained list here would be a second source of
// truth and would drift behind the struct - which is precisely how `sms:`
// came to be documented but unparsed.
var hookEntryKeys = func() map[string]bool {
	keys := map[string]bool{}
	t := reflect.TypeOf(HookEntryYAML{})
	for i := range t.NumField() {
		tag := t.Field(i).Tag.Get("yaml")
		if tag == "" || tag == "-" {
			continue
		}
		keys[strings.Split(tag, ",")[0]] = true
	}
	return keys
}()

// hookEntryKeyList is hookEntryKeys sorted, for stable error messages.
// (There is a sortedKeys helper in mcp_tools_semantic.go, but that file is
// `!cli && platform` and this one is `!cli` - reusing it would break the
// framework and cloud builds.)
var hookEntryKeyList = slices.Sorted(maps.Keys(hookEntryKeys))

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
	if err := decodeConfigYAML([]byte(content), &probe); err != nil {
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
	if err := yamlUnmarshal([]byte(content), &raw); err != nil {
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
		// The table name is spliced into the encryption/blind-index trigger
		// SQL, which the connector's trigger check regenerates verbatim, so
		// it must be a plain identifier.
		if !membershipIdentRe.MatchString(tableName) {
			return fmt.Sprintf("antipattern [encrypted-yaml-shape] in encrypted.yaml: table name %q is not a plain identifier (letters, digits and _ only, not starting with a digit).", tableName)
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
			// Column names go into the trigger SQL the same way the table
			// name does; a plain identifier only.
			if !membershipIdentRe.MatchString(strings.TrimSpace(s)) {
				return fmt.Sprintf("antipattern [encrypted-yaml-shape] in encrypted.yaml: `tables.%s.fields[%d]` (%q) is not a plain column name (letters, digits and _ only, not starting with a digit).", tableName, i, s)
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
