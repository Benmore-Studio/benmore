//go:build !cli

package main

// Unified validation entry point. Both the CLI (`benmore check`) and
// the MCP (write_file / edit_file response) call into RunCompleteCheck
// so the agent and a human running the CLI see the EXACT same findings
// for the same app state.
//
// The design philosophy this commit codifies: the validators ARE the
// docs. Instead of telling the agent "here's how flows.yaml works"
// across a 12-page reference, the framework says "go ahead and write
// what you think it should look like, and on every mistake the loop
// returns the corrected shape with an example." The corpus already
// knows ~95% of what to do; the validators close the remaining 5%
// gap one wrong write at a time.
//
// A complete check has four layers, run in order:
//
//   1. Per-file syntactic validation (ValidateOnWrite)
//      Reuses the dispatcher that runs in write_file/edit_file. Each
//      file type gets its dedicated validator: Prisma parser, GHA
//      flow parser, gotmpl template parser, hooks key set, app.yaml
//      key set, and every hooks/workflows `when:` prepared against the
//      current schema.prisma - so a schema edit that breaks a `when:`
//      surfaces here even though the schema write itself passed.
//
//   2. Cross-file orphan-ref validation (CrossFileWarnings)
//      Walks hooks.yaml / workflows.yaml / flows.yaml inline SQL and
//      warns when they reference tables not declared in schema.prisma.
//
//   3. App-load smoke test
//      Calls loadApp(dir) and surfaces any error. Catches schema
//      migration failures, flow shape errors that slipped past the
//      static parser, computed-field SQL that fails to compile, etc.
//
//   4. Schema drift detection (DetectSchemaDrift)
//      Compares declared schema against the live database. Catches
//      manual ALTERs, skipped migrations, divergent state.
//
// Each layer can produce errors (the build is broken - agent must
// fix) or warnings (the build runs but the agent should know). Layers
// 3 + 4 only fire if layers 1 + 2 pass - there's no point trying to
// load an app whose schema.prisma doesn't parse.

import (
	"database/sql"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// piiColumnRe matches column names that commonly hold personal data. Used to
// warn when such a table is world/anon-readable.
// Boundaries are `(^|[^a-z])`/`([^a-z]|$)` rather than `\b`: the column is
// lowercased before matching and Go's regexp treats `_` as a word char, so `\b`
// would NEVER fire inside snake_case (user_email, phone_number, home_address) -
// exactly the common naming convention. `[^a-z]` treats `_`/digits/ends as
// boundaries so a PII token is caught as any underscore-delimited segment.
var piiColumnRe = regexp.MustCompile(`(^|[^a-z])(email|phone|mobile|address|ssn|sin|dob|date_of_birth|birth_?date|passport|licen[sc]e|card_?number|iban|account_?number|routing|tax_?id|national_?id)([^a-z]|$)`)

// CheckFinding is a single validation result. The agent's job is to
// fix every Severity="error" before deploy. Severity="warning"
// findings shouldn't block but should surface in tool responses.
type CheckFinding struct {
	Severity string `json:"severity"` // "error" | "warning"
	Source   string `json:"source"`   // which validator produced this ("syntax" | "cross_file" | "app_load" | "drift")
	File     string `json:"file,omitempty"`
	Message  string `json:"message"`
	// Docs is the address of the reference key that states the rule the
	// finding reports ("flows.step_keys"): read it with api(at:"<docs>") or
	// `benmore api <app> <docs>`. Empty for a finding no key covers
	// (refusal_docs.go).
	Docs string `json:"docs,omitempty"`
}

// CheckReport is the full output of RunCompleteCheck.
type CheckReport struct {
	Findings []CheckFinding `json:"findings"`
	// Errors / Warnings split for convenience - equivalent to
	// counting Severity values, but pre-computed because the agent
	// often wants "did anything block?" without iterating.
	Errors   int `json:"errors"`
	Warnings int `json:"warnings"`
}

// Clean returns true if no errors were produced (warnings are fine).
func (r CheckReport) Clean() bool { return r.Errors == 0 }

// RunCompleteCheck validates one app directory and returns a structured
// report. If `writtenPath` is non-empty, it's the file the caller just
// touched - that file's syntactic validators get priority in the report
// ordering so the agent sees their feedback first.
func RunCompleteCheck(dir, writtenPath string) CheckReport {
	return runCheck(dir, writtenPath, true)
}

// RunCompleteCheckWith is RunCompleteCheck with the live layers (2.9 unapplied
// schema changes, 3 app load, 4 drift) supplied by live: the platform router
// runs the source layers itself and asks the app's own process for the live
// ones (data channel op check_live), so it never opens the tenant database.
func RunCompleteCheckWith(dir string, live func(dir string) []CheckFinding) CheckReport {
	return runCheckWithLive(dir, "", true, live)
}

// RunSourceCheck is the write-path variant used by write_file / edit_file.
// It runs only the layers that read source files (1, 2, 2.5) and never
// opens the app's live data.db. Layers 3 + 4 (app load, drift) open the
// tenant database from the ROUTER process and re-run every migration and
// trigger install against it; on a large hosted app that work raced the
// per-app process's own SIGHUP reload for the SQLite write lock
// (_txlock=immediate, 10s busy_timeout), stalled every write response
// past the CLI deadline and surfaced in the app as
// `[locks] cleanup error: database is locked`. Those layers remain
// available on demand through the `check` tool / `benmore check`.
func RunSourceCheck(dir, writtenPath string) CheckReport {
	return runCheck(dir, writtenPath, false)
}

// sourceCheckFiles picks the layer-1 inputs for a check. The full check
// and a write of a file other files depend on (schema, app.yaml, the
// flows map) re-validate everything: a schema edit can break every hook
// `when:`. Any other write re-validates only the written file - the
// pre-write gate already ran its validator, and re-walking ~200 flow and
// page files on every .tsx push cost ~3.5s on a large app, which alone
// kept pushes slower than the 5s reload debounce.
func sourceCheckFiles(dir, writtenPath string, liveDB bool) []fileCheck {
	if liveDB || writtenPath == "" || writeAffectsOtherFiles(writtenPath) {
		return walkAppFiles(dir)
	}
	// Through the app's root, regular file only (walkAppFiles).
	data, err := readFileInRoot(dir, writtenPath)
	if err != nil {
		return nil
	}
	return []fileCheck{{relPath: writtenPath, content: string(data)}}
}

// cronFlowRefFindingsAfterWrite re-checks cron.yaml's `flow:` names after a
// write to flows/<name>.yaml, which can remove or rename a flow a job names:
// such a write re-validates only itself (sourceCheckFiles). A full check and
// a write that re-walks every file already checked cron.yaml through its
// validator (cronFlowRefProblems). Only a missing flow named after the
// written file is this write's doing and an error; a job that already named a
// missing flow is a warning, so a broken cron.yaml line does not block pushes
// of unrelated flows (cron.yaml's own write and `benmore check` still refuse
// it). The 2.7.311 fleet check found three live apps with such a line.
func cronFlowRefFindingsAfterWrite(dir, writtenPath string, liveDB bool) []CheckFinding {
	if liveDB || writtenPath == "" || writeAffectsOtherFiles(writtenPath) || !isFlowsSubdirFile(writtenPath) {
		return nil
	}
	data, err := readOptionalConfig(dir, "cron.yaml")
	if err != nil || data == nil {
		return nil
	}
	cfg, err := parseCronYAML(data)
	if err != nil {
		return nil
	}
	stem := strings.TrimSuffix(filepath.Base(writtenPath), filepath.Ext(writtenPath))
	var findings []CheckFinding
	for _, m := range cronFlowRefMissing(dir, cfg) {
		if m.flow == stem {
			findings = append(findings, CheckFinding{Severity: "error", Source: "syntax", File: "cron.yaml", Message: m.message})
			continue
		}
		// Filed under the written path: a push shows only its own file's
		// warnings (writeRelevantFindings), and the message names cron.yaml.
		findings = append(findings, CheckFinding{Severity: "warning", Source: "syntax", File: filepath.ToSlash(writtenPath), Message: m.message})
	}
	return findings
}

// writeRelevantFindings keeps, for a write of one file, every error and the
// warnings about that file. App-wide warnings (a protected column name in the
// schema, a redirect in another flow) used to be repeated on every push of
// any file - a static asset or a page - until agents stopped reading them.
// A write of a file others depend on (schema, app.yaml, flows.yaml,
// mcp.yaml) keeps them all, and a config write keeps the cross-file
// warnings, which name no single file; `benmore check` reports everything.
func writeRelevantFindings(writtenPath string, findings []CheckFinding) []CheckFinding {
	written := filepath.ToSlash(filepath.Clean(writtenPath))
	// A stale mcp.yaml review only turns the connector off (the app keeps
	// serving; the write response's mcp_connector_withheld says so). Writing
	// another file must not answer ok:false because of it: every scaffolded
	// app ships a reviewed mcp.yaml, so its first schema push did.
	if written != "mcp.yaml" {
		for i, f := range findings {
			if staleMCPReviewFinding(f) {
				findings[i].Severity = "warning"
			}
		}
	}
	// A retention.yaml the app already carries with a policy that does not
	// run is not this write's doing: its own write and `benmore check`
	// refuse it, a write of another file reports it as a warning. (A file
	// keyed by table name is a warning everywhere: retentionLegacyFindings.)
	if written != "retention.yaml" {
		for i, f := range findings {
			if deployedRetentionFinding(f) {
				findings[i].Severity = "warning"
			}
		}
	}
	if writeAffectsOtherFiles(writtenPath) {
		return findings
	}
	ext := strings.ToLower(filepath.Ext(written))
	config := ext == ".yaml" || ext == ".yml" || ext == ".prisma" || ext == ".sql"
	kept := findings[:0:0]
	for _, f := range findings {
		switch {
		case f.Severity == "error":
		case f.File != "" && filepath.ToSlash(filepath.Clean(f.File)) == written:
		case f.File == "" && config:
		default:
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// staleMCPReviewFinding reports whether f is the error a stale mcp.yaml review
// raises (its digests no longer match the source). It turns only the app's MCP
// connector off, so a write of any other file - and the CLI's check after a push
// batch - reads it as a warning.
func staleMCPReviewFinding(f CheckFinding) bool {
	return f.Severity == "error" && f.File == "mcp.yaml" && strings.Contains(f.Message, "digest mismatch")
}

// deployedRetentionFinding reports whether f is the write gate's finding on
// retention.yaml (retentionYAMLViolation). The app loads with such a file:
// the policies it concerns do not run.
func deployedRetentionFinding(f CheckFinding) bool {
	return f.Severity == "error" && f.Source == "syntax" && filepath.ToSlash(filepath.Clean(f.File)) == "retention.yaml"
}

// writeChangesFrameworkRoutes: workflows.yaml registers per-table transition
// routes an existing flow may already hold (flowRouteCollisionFindings).
func writeChangesFrameworkRoutes(writtenPath string) bool {
	return strings.EqualFold(filepath.Base(filepath.ToSlash(writtenPath)), "workflows.yaml")
}

func writeAffectsOtherFiles(writtenPath string) bool {
	switch strings.ToLower(filepath.Base(filepath.ToSlash(writtenPath))) {
	case "schema.prisma", "schema.sql", "schema.yaml", "app.yaml", "flows.yaml", "mcp.yaml":
		return true
	}
	return false
}

func hasFindingMessage(findings []CheckFinding, source, message string) bool {
	for _, f := range findings {
		if f.Source == source && f.Message == message {
			return true
		}
	}
	return false
}

func runCheck(dir, writtenPath string, liveDB bool) CheckReport {
	return runCheckWithLive(dir, writtenPath, liveDB, checkLiveLayers)
}

func runCheckWithLive(dir, writtenPath string, liveDB bool, live func(dir string) []CheckFinding) CheckReport {
	// Judge the written file by the path it landed at (validators_write.go).
	writtenPath = cleanWritePath(writtenPath)
	var findings []CheckFinding
	findings = append(findings, errorReportingEnvFindings(dir)...)
	findings = append(findings, cronMonitorFindings(dir)...)

	// Layer 1: per-file syntactic validation. Walk every file the
	// dispatcher knows about; each gets its validator. Threading the
	// app dir through gives the gotmpl validator partial-loading and
	// any future cross-file syntactic check the context it needs.
	for _, fileCheck := range sourceCheckFiles(dir, writtenPath, liveDB) {
		// Flow routes are checked app-wide below, once, instead of per file.
		if verdict, _ := writeGateVerdict(dir, fileCheck.relPath, fileCheck.content, false, false, nil); verdict.Message != "" {
			findings = append(findings, CheckFinding{
				Severity: "error",
				Source:   "syntax",
				File:     fileCheck.relPath,
				Message:  verdict.Message,
				Docs:     verdict.Docs,
			})
		} else if msg := appTestFileWarning(fileCheck.relPath, fileCheck.content); msg != "" {
			// A tests/*.yaml file that is valid YAML but that `benmore test`
			// cannot load (testrunner.go decodeAppTestFile).
			findings = append(findings, CheckFinding{
				Severity: "warning",
				Source:   "tests",
				File:     fileCheck.relPath,
				Message:  msg,
			})
		}
	}

	// cron.yaml names flows; a flows/<name>.yaml write can remove or rename
	// one, and such a write re-checks only its own file above.
	findings = append(findings, cronFlowRefFindingsAfterWrite(dir, writtenPath, liveDB)...)

	// Layer 2: cross-file warnings.
	for _, msg := range CrossFileWarnings(dir, writtenPath) {
		findings = append(findings, CheckFinding{
			Severity: "warning",
			Source:   "cross_file",
			Message:  msg,
		})
	}

	// Flow responses whose body Cloudflare replaces (502/504).
	findings = append(findings, edgeReplacedStatusWarnings(dir, writtenPath)...)

	// Transactional flows whose time limit outlasts the write-transaction
	// limit (the transaction rolls back first).
	findings = append(findings, transactionTimeoutWarnings(dir, writtenPath)...)

	// Step-output references to a column the SQL step does not return
	// (guards are refused by the flow validator; the rest warn).
	findings = append(findings, stepOutputRefWarnings(dir, writtenPath)...)

	// Flow values that are accepted and not honored as written: `min`/`max`
	// on an input that is not a number, and an event table only a migration
	// creates, whose spelling cannot be checked (the rest of that class is
	// refused by the flow validator; validators_flow_ignored_values.go).
	findings = append(findings, flowInputBoundsWarnings(dir, writtenPath)...)
	findings = append(findings, flowEventTableWarnings(dir, writtenPath)...)
	findings = append(findings, flowTransactionalSendWarnings(dir, writtenPath)...)
	// A `run: respond` with no `with:`: a 200 that ends the run.
	findings = append(findings, bareRespondWarnings(dir, writtenPath)...)
	// A `role:` gate that is not one role the app knows: it admits nobody
	// but a global admin (validators_flow_role_gate.go).
	findings = append(findings, flowRoleGateWarnings(dir, writtenPath)...)

	// Layer 2.5: protected-column-name collisions (v2.7.164). A column
	// named `role` / `password_hash` on an app table collides with the
	// framework's mass-assignment protection: client-supplied values are
	// SILENTLY stripped on POST/PATCH (only the X-Stripped-Fields header
	// signals it), so the field stores empty/default and the agent burns
	// a debugging cycle. Warning, not error - the column is legal and
	// server-side writes (flows, hooks, SQL) work fine.
	findings = append(findings, protectedColumnWarnings(dir)...)

	// Command flows that the current environment cannot load (no durable
	// ENCRYPTION_KEY): source checks pass them, the reload refuses them.
	findings = append(findings, appMCPCommandKeyFindings(dir, writtenPath, liveDB)...)

	// Command flows whose SQL matches rows with no predicate tied to the
	// caller: a command is not checked against the table's access rule
	// (app_mcp_command_caller_predicate.go). Advice, not a refusal.
	findings = append(findings, appMCPCommandCallerPredicateFindings(dir, writtenPath, liveDB)...)

	// A retention.yaml keyed by table name has never run: a warning with
	// the corrected file, not a refusal (retention_document.go).
	findings = append(findings, retentionLegacyFindings(dir)...)

	// app.yaml keys that are accepted and change nothing: a warning that
	// says what to write instead (app_yaml_no_effect.go).
	findings = append(findings, appYAMLNoEffectFindings(dir, writtenPath, liveDB)...)

	// app.yaml keys and values the loader accepts and does not read: an
	// unknown key in a section with a fixed set of keys, an unknown theme
	// or mode (app_yaml_unread.go).
	findings = append(findings, appYAMLUnreadFindings(dir, writtenPath, liveDB)...)

	// Money-as-Float: a payments/payouts app storing currency as REAL is a
	// rounding-bug waiting to happen. Warning - the column is legal.
	findings = append(findings, moneyFloatWarnings(dir)...)

	// PII exposed via a world/anon-readable table - confirm it's intentional.
	findings = append(findings, piiExposureWarnings(dir)...)

	// Authorization shapes that widen access (validators_authz.go).
	findings = append(findings, authzWarnings(dir)...)

	// What `compliance: hipaa` leaves to a flow's or hook's own SQL: writes
	// with no audit row, whole encrypted rows in a response
	// (validators_hipaa_flows.go).
	findings = append(findings, hipaaFlowFindings(dir, writtenPath)...)

	// WebSockets to hosts the page's connect-src does not allow.
	findings = append(findings, connectSrcWebSocketWarnings(dir)...)

	// A `pwa:` app whose manifest icon file is missing from static/.
	findings = append(findings, manifestIconWarnings(dir)...)

	// Flow-shape warnings re-parse every flow (~1.2s on a large app); a
	// write that is not a flow or a shared config file cannot change them.
	if liveDB || writtenPath == "" || writeAffectsOtherFiles(writtenPath) || isFlowsSubdirFile(writtenPath) || writeChangesFrameworkRoutes(writtenPath) {
		// Dead respond:/redirect: in an async flow (the 202 already went out).
		findings = append(findings, asyncRespondWarnings(dir)...)

		// Templated redirect targets that can render off-origin (refused at run
		// time unless the host is in allow_hosts).
		findings = append(findings, redirectWarnings(dir)...)

		// Flows whose route collides with a framework route (or another
		// flow): the runtime skips them at load. The write gate refuses
		// them per file (validateOnWriteIn); this registers every flow file
		// together, in load order, against the current schema, app.yaml
		// and workflows - which a later write can change under a flow.
		findings = append(findings, flowRouteCollisionFindings(dir)...)

		// Transition role names no other part of the app names (likely a
		// typo; workflow_roles.go). Flow role: gates count as naming one.
		findings = append(findings, workflowRoleWarnings(dir)...)
	}

	// If we already have syntax errors there's no point trying to
	// load the app - the load will just rediscover them with worse
	// error messages.
	if liveDB && countErrors(findings) == 0 {
		for _, f := range live(dir) {
			// The live layer re-reads env.yaml's delivery settings; report each once.
			if f.Source == "environment" && hasFindingMessage(findings, "environment", f.Message) {
				continue
			}
			// A ws_rooms rule the source layer already named.
			if rule := wsRoomFindingRule(f.Message); rule != "" && slices.ContainsFunc(findings, func(have CheckFinding) bool {
				return wsRoomFindingRule(have.Message) == rule
			}) {
				continue
			}
			findings = append(findings, f)
		}
	}

	// Browser bundles and <include> tags (after the live layers: they do not
	// stop the app from loading). The write gate checks the written file's
	// (validateOnWriteIn); this checks every bundle and page, or after a
	// write the bundles it is part of, so an error a write leaves in another
	// file, or one a batch write deferred, is reported.
	findings = append(findings, sourceRenderFindings(dir, writtenPath, liveDB, findings)...)

	if !liveDB && writtenPath != "" {
		findings = writeRelevantFindings(writtenPath, findings)
	}
	// Where each finding's rule is documented (refusal_docs.go).
	findings = withFindingDocs(findings)
	rpt := CheckReport{Findings: findings}
	for _, f := range findings {
		if f.Severity == "error" {
			rpt.Errors++
		} else {
			rpt.Warnings++
		}
	}
	return rpt
}

// sourceRenderFindings runs bundleCheckFindings and includeCheckFindings for
// a check: over the whole app, or after a write of writtenPath over what it
// affects. Build errors in a file the per-file layer already reported as
// unparsable would repeat it, so they are left out.
func sourceRenderFindings(dir, writtenPath string, liveDB bool, prior []CheckFinding) []CheckFinding {
	if liveDB {
		writtenPath = ""
	}
	unparsable := map[string]bool{}
	for _, f := range prior {
		if f.Severity == "error" && f.Source == "syntax" && strings.Contains(f.Message, "does not parse") {
			unparsable[filepath.ToSlash(f.File)] = true
		}
	}
	out := bundleCheckFindings(dir, writtenPath, unparsable)
	return append(out, includeCheckFindings(dir, writtenPath)...)
}

// checkLiveLayers runs the check layers that read the live database, loading
// the app from dir for layer 3 (benmore serve's boot check, before it serves,
// and `benmore check` in an app directory). Callers run it only when the
// source layers found no error.
func checkLiveLayers(dir string) []CheckFinding {
	return checkLiveLayersWith(dir, tryLoadApp)
}

// checkLiveLayersWith is checkLiveLayers with layer 3 supplied by loadErr. A
// serving process must not load its own app a second time (the load takes
// the connector policy lease and turns approved writes off, and can install
// another encryption key and environment): the data channel's check_live
// reports the outcome of the process's own last reload instead.
func checkLiveLayersWith(dir string, loadErr func(dir string) string) []CheckFinding {
	return checkLiveLayersWithDB(dir, nil, loadErr)
}

// checkLiveLayersWithDB is checkLiveLayersWith for the app's own serving
// process, which passes its open pool (db) so layers that read the live
// database use it rather than opening the file again. With db nil (benmore
// check in an app directory, serve's boot check) those layers are reported by
// the app load instead.
func checkLiveLayersWithDB(dir string, db *sql.DB, loadErr func(dir string) string) []CheckFinding {
	var findings []CheckFinding
	// Layer 2.9: schema.prisma changes the live database will not apply
	// (a type, nullability or default change, a removed field). The
	// write that made them answers with the same list (schema_unapplied.go).
	// Read before the load below, which records the new schema.
	findings = append(findings, schemaUnappliedFindings(dir)...)

	// Layer 2.95: a reviewed mcp.yaml with a schema.prisma that removes a model
	// the database still has: every reload and start refuses it. The write
	// gate refuses the same state (mcpManifestSchemaTransitionRefusal). Only
	// the serving process runs it, on its own pool; elsewhere the load below
	// reports the same refusal.
	transition := appMCPSchemaTransitionFindings(dir, db)
	findings = append(findings, transition...)

	// Layer 2.97: connector revision triggers that another trigger now fires
	// before refuse inserts into that table (app_mcp_revision_order.go). Loads
	// put them first; this reports a database where something else did not.
	// Only the serving process, on its own pool.
	findings = append(findings, appMCPRevisionTriggerOrderFindings(db)...)

	// Layer 2.98: rows in a workflow state workflows.yaml no longer declares
	// (workflow_state_removal.go). The hosted write gate refuses a change that
	// strands rows; this names rows stuck by any other route. Serving process
	// only, on its own pool.
	findings = append(findings, workflowStuckFindings(dir, db)...)

	// Layer 2.99: ws_rooms rules whose membership table or column the live
	// database does not have (validators_ws_rooms.go). The source layer
	// cannot judge what a migration creates. Serving process only.
	findings = append(findings, wsRoomLiveFindings(dir, db)...)

	// Layer 3: app load. Catches schema errors, flow runtime
	// rejections, etc. (the transition refusal above is reported once).
	if loadErr := loadErr(dir); loadErr != "" && (len(transition) == 0 || loadErr != transition[0].Message) {
		// DB-ping errors against a per-edit probe routinely
		// surface as transient false positives - the running
		// app's CRUD against the same file is healthy, the per-
		// edit check just races the WAL/SHM open or hits a
		// stale handle from the previous reload. Pre-2.7.31 this
		// flipped ok:false on the write response and produced a
		// scary `disk I/O error: no such file or directory`
		// finding for every edit while the corruption window
		// was open. Beacon + news + chat all logged this same
		// false-error pattern. Downgrade to a warning when the
		// data.db file actually exists on disk so the agent
		// doesn't burn turns chasing a phantom.
		severity := "error"
		if isTransientDBPingError(dir, loadErr) {
			severity = "warning"
		}
		findings = append(findings, CheckFinding{
			Severity: severity,
			Source:   "app_load",
			Message:  loadErr,
		})
	}

	for _, key := range []string{"SENTRY_DSN", "ERROR_SLACK_WEBHOOK", "SENTRY_MIN_LEVEL"} {
		if err := validateAppEnvValue(key, GetEnv(dir, key)); err != nil {
			findings = append(findings, CheckFinding{Severity: "warning", Source: "environment", Message: err.Error()})
		}
	}

	// Layer 4: drift detection. Only meaningful when there's a
	// live database to compare against - fresh apps without a
	// data.db still produce a clean report. extra_column drift
	// is benign noise during active schema iteration (agent
	// removes a field, the live column lingers until pruned) and
	// stays suppressed. extra_table USED to be suppressed for the
	// same reason, but in practice orphaned tables DO change app
	// behavior - auto-CRUD still mounts /api/<table> against them,
	// which can shadow or panic-collide with a flow at the same
	// path, and agents that hit "unfamiliar table in describe"
	// reach for hallucinated explanations ("framework template
	// inference") instead of cleanup. Surface them as warnings
	// with a prescriptive fix (keep it as a model, or drop it in a
	// migrations/ SQL file).
	if drifts := tryDriftCheck(dir); len(drifts) > 0 {
		for _, d := range drifts {
			// extra_column stays suppressed - really is benign.
			if d.Kind == "extra_column" {
				continue
			}
			where := d.Table
			if d.Column != "" {
				where = d.Table + "." + d.Column
			}
			findings = append(findings, CheckFinding{
				Severity: "warning",
				Source:   "drift",
				Message:  fmt.Sprintf("[%s] %s: %s", d.Kind, where, d.Detail),
			})
		}
	}
	return findings
}

// FormatReport renders a CheckReport for human consumption (CLI). The
// MCP path uses the structured Findings directly so the agent can
// react per-issue.
func FormatReport(rpt CheckReport) string {
	if rpt.Clean() && rpt.Warnings == 0 {
		return "check: clean - no issues found.\n"
	}
	var b strings.Builder
	if rpt.Errors > 0 {
		fmt.Fprintf(&b, "check: %d error(s)", rpt.Errors)
		if rpt.Warnings > 0 {
			fmt.Fprintf(&b, ", %d warning(s)", rpt.Warnings)
		}
		b.WriteByte('\n')
	} else {
		fmt.Fprintf(&b, "check: %d warning(s)\n", rpt.Warnings)
	}
	for _, f := range rpt.Findings {
		label := strings.ToUpper(f.Severity)
		if f.File != "" {
			fmt.Fprintf(&b, "\n%s [%s] %s:\n", label, f.Source, f.File)
		} else {
			fmt.Fprintf(&b, "\n%s [%s]:\n", label, f.Source)
		}
		// Indent the message for readability.
		for _, line := range strings.Split(f.Message, "\n") {
			fmt.Fprintf(&b, "  %s\n", line)
		}
		if line := findingDocsLine(f); line != "" {
			fmt.Fprintf(&b, "  %s\n", line)
		}
	}
	return b.String()
}

// walkAppFiles returns the contents of every file in the app
// directory that has a dedicated validator. We don't try to validate
// every file (CSS, static assets, etc.) - only the ones whose
// per-file validator is wired up in ValidateOnWrite.
// serveBootCheck runs the unified validators at `benmore serve` boot
// and prints findings to stderr (v2.7.164). Non-fatal: serve still
// boots; the point is that a broken flow file no longer loads silently
// only to be rejected later at push time. The validator stack now lives
// in the shared (`!cli`) build, so this runs in the framework and cloud
// editions too - the old platform-only no-op shim was removed.
func serveBootCheck(dir string) {
	// Its validation load closes the database just before the start-up load
	// opens it; a clean close there leaves the marker the start-up load reads
	// (db_clean_shutdown.go), so the file is not checked twice in one start.
	report := func() CheckReport {
		serveBootCheckActive.Store(true)
		defer serveBootCheckActive.Store(false)
		return RunCompleteCheck(dir, "")
	}()
	if len(report.Findings) == 0 {
		return
	}
	fmt.Fprintln(os.Stderr, FormatReport(report))
	if report.Errors > 0 {
		outcome := "the app will boot, but these would be rejected by `benmore push` / the platform write gate"
		for _, f := range report.Findings {
			if f.Severity == "error" && f.Source == "app_load" {
				outcome = "the app_load error stops the app from starting until it is fixed"
				break
			}
		}
		fmt.Fprintf(os.Stderr, "⚠ %d error(s) above - %s.\n\n", report.Errors, outcome)
	}
}

// protectedColumnWarnings scans schema.prisma for column names that
// collide with the framework's protected-field strip list. See the
// Layer 2.5 comment in RunCompleteCheck.
func protectedColumnWarnings(dir string) []CheckFinding {
	data, err := os.ReadFile(filepath.Join(dir, "schema.prisma"))
	if err != nil {
		return nil
	}
	models, err := ParsePrismaSchema(string(data))
	if err != nil {
		return nil // parse errors are Layer 1's job
	}
	// Only the names whose stripping is genuinely surprising. user_id /
	// created_at / updated_at are framework-managed on purpose and
	// their semantics are what an agent wants when declaring them.
	collisions := map[string]string{
		"role":          "rename it to something domain-specific (member_role, applicant_role, …)",
		"password_hash": "the framework manages credentials in _benmore_users; store app-level secrets under a different name",
	}
	var findings []CheckFinding
	for _, m := range models {
		for _, f := range m.Fields {
			if fix, hit := collisions[strings.ToLower(f.Column)]; hit {
				findings = append(findings, CheckFinding{
					Severity: "warning",
					Source:   "schema",
					File:     "schema.prisma",
					Message: fmt.Sprintf("%s.%s collides with a framework-protected field name: client-supplied values are silently stripped on POST/PATCH (the row saves with the column empty/default; only the X-Stripped-Fields response header signals it). If clients need to write this field, %s. Server-side writes (flows, hooks, benmore sql) are unaffected.",
						m.Table, f.Column, fix),
				})
			}
		}
	}
	return findings
}

// moneyFloatWarnings flags money-looking columns stored as REAL (Prisma
// Float/Decimal). Binary floating point can't represent decimal currency
// exactly, so it accumulates rounding error - dangerous in an app that takes
// payments or cuts payouts. Recommends integer cents. Warning, not error: the
// column is legal, and some "rate"/"amount" columns are genuinely fractional.
func moneyFloatWarnings(dir string) []CheckFinding {
	findings, _ := moneyFloatWarningsChecked(dir)
	return findings
}

func moneyFloatWarningsChecked(dir string) ([]CheckFinding, error) {
	data, err := os.ReadFile(filepath.Join(dir, "schema.prisma"))
	if err != nil {
		return nil, err
	}
	models, err := ParsePrismaSchema(string(data))
	if err != nil {
		return nil, err
	}
	moneyWord := map[string]bool{
		"amount": true, "price": true, "total": true, "subtotal": true,
		"fee": true, "payout": true, "balance": true, "cost": true,
		"refund": true, "charge": true, "salary": true, "revenue": true,
	}
	var findings []CheckFinding
	for _, m := range models {
		for _, f := range m.Fields {
			if f.Type != "REAL" {
				continue
			}
			col := strings.ToLower(f.Column)
			tokens := strings.Split(col, "_")
			last := tokens[len(tokens)-1]
			if !moneyWord[col] && !moneyWord[last] {
				continue
			}
			findings = append(findings, CheckFinding{
				Severity: "warning",
				Source:   "schema",
				File:     "schema.prisma",
				Message: fmt.Sprintf("%s.%s looks like money but is stored as Float/REAL - binary float can't hold decimal currency exactly and accumulates rounding error (dangerous for payments/payouts). Prefer integer cents (e.g. `%s_cents Int`) and format with bm.money() in the UI.",
					m.Table, f.Column, f.Column),
			})
		}
	}
	return findings, nil
}

// piiExposureWarnings flags tables that are world- or anon-readable
// (access.read: everyone|anon) AND carry PII-looking columns - i.e. anyone can
// read personal data. The access default is private, so this only fires on an
// explicit broad read mode. Warning: the exposure may be intentional (a public
// directory), but it should be a deliberate choice, not an accident.
func piiExposureWarnings(dir string) []CheckFinding {
	findings, _ := piiExposureWarningsChecked(dir)
	return findings
}

func piiExposureWarningsChecked(dir string) ([]CheckFinding, error) {
	data, err := os.ReadFile(filepath.Join(dir, "schema.prisma"))
	if err != nil {
		return nil, err
	}
	models, err := ParsePrismaSchema(string(data))
	if err != nil {
		return nil, err
	}
	access, err := loadAccessChecked(dir)
	if err != nil {
		return nil, err
	}
	if access == nil {
		return nil, nil
	}
	var findings []CheckFinding
	for _, m := range models {
		hasUID, hasGroup := false, false
		var pii []string
		for _, f := range m.Fields {
			c := strings.ToLower(f.Column)
			switch c {
			case "user_id":
				hasUID = true
			case "org_id", "group_id", "tenant_id", "company_id", "account_id":
				hasGroup = true
			}
			if piiColumnRe.MatchString(c) {
				pii = append(pii, f.Column)
			}
		}
		if len(pii) == 0 {
			continue
		}
		// A default mode is never everyone/anon, so a match here is an explicit
		// broad read rule (approximate hasUID/hasGroup can't cause a false hit).
		mode := access.ModeFor(m.Table, OpRead, hasUID, hasGroup)
		if mode == "everyone" || mode == "anon" {
			findings = append(findings, CheckFinding{
				Severity: "warning",
				Source:   "security",
				File:     "app.yaml",
				Message: fmt.Sprintf("table %q is %s-readable (access.read: %s) but has PII-looking column(s): %s. Anyone%s can read these rows. If that's not intended, scope the table (owner / group / role:...).",
					m.Table, mode, mode, strings.Join(pii, ", "),
					map[bool]string{true: " (even unauthenticated)", false: ""}[mode == "anon"]),
			})
		}
	}
	return findings, nil
}

// redirectWarnings runs the advisory flow-file warners - ghaRedirectWarnings
// (validators_write.go), ghaStepShadowWarnings (validators_step_shadow.go),
// ghaPrivateUploadRecordWarnings (flows_upload_owner.go) and
// ghaMissingRequestValueWarnings (validators_flow_ignored_values.go)
// - over flows.yaml and every flows/*.yaml file the runtime loads.
func redirectWarnings(dir string) []CheckFinding {
	paths := []string{"flows.yaml"}
	if entries, err := os.ReadDir(filepath.Join(dir, "flows")); err == nil {
		for _, e := range entries {
			if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
				paths = append(paths, filepath.Join("flows", e.Name()))
			}
		}
	}
	var findings []CheckFinding
	for _, rel := range paths {
		data, err := os.ReadFile(filepath.Join(dir, rel))
		if err != nil {
			continue
		}
		msgs := ghaRedirectWarnings(string(data))
		// A step id that is one of the runtime's identity names (`id: user`):
		// the caller's values win over its outputs (flows_step_identity_ids.go).
		msgs = append(msgs, ghaIdentityStepIDWarnings(string(data))...)
		// Step ids that shadow a request field (advisory; v2.7.248 made a
		// bare ref to such a name read the step).
		msgs = append(msgs, ghaStepShadowWarnings(string(data))...)
		// serve_file / delete_upload without `record:` where no caller
		// signs in: every user upload is refused (flows_upload_owner.go).
		msgs = append(msgs, ghaPrivateUploadRecordWarnings(string(data))...)
		// An optional request field with no fallback where a missing value
		// is compared, or sent, as its placeholder text
		// (validators_flow_ignored_values.go).
		msgs = append(msgs, ghaMissingRequestValueWarnings(string(data))...)
		for _, msg := range msgs {
			findings = append(findings, CheckFinding{
				Severity: "warning",
				Source:   "flows",
				File:     rel,
				Message:  msg,
			})
		}
	}
	return findings
}

// flowHasRespondStep reports whether any step (including nested if/for_each
// branches) responds or redirects.
func flowHasRespondStep(steps []FlowStep) bool {
	for _, s := range steps {
		if s.Type == "respond" || s.Type == "redirect" {
			return true
		}
		if flowHasRespondStep(s.Steps) || flowHasRespondStep(s.ElseSteps) || flowHasRespondStep(s.OnError) {
			return true
		}
	}
	return false
}

// checkSourceMaxFileBytes bounds one file the source check reads.
const checkSourceMaxFileBytes = 16 << 20

// walkAppFiles collects the files the source check validates. Every read
// goes through an os.Root at the app directory, regular files only and
// opened without blocking (readRegularInRoot): the check runs in the router
// after a hosted write, and a tenant link to another tenant's tree (or a
// FIFO) must not be read (security.md 4i).
func walkAppFiles(dir string) []fileCheck {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil
	}
	defer root.Close()
	return walkAppFilesIn(root)
}

func walkAppFilesIn(root *os.Root) []fileCheck {
	fsys := root.FS()
	read := func(rel string) ([]byte, error) {
		return readRegularInRoot(root, filepath.FromSlash(rel), checkSourceMaxFileBytes)
	}
	readDir := func(rel string) ([]fs.DirEntry, error) { return fs.ReadDir(fsys, rel) }
	exists := func(rel string) bool {
		_, err := root.Lstat(rel)
		return err == nil
	}
	candidates := []string{
		"mcp.yaml",
		"schema.prisma",
		"schema.sql",
		"schema.yaml",
		"app.yaml",
		"flows.yaml",
		"hooks.yaml",
		"workflows.yaml",
		"cron.yaml",
		"validators.yaml",
		"computed.yaml",
		"encrypted.yaml",
		"retention.yaml",
	}
	var out []fileCheck
	for _, rel := range candidates {
		if data, err := read(rel); err == nil {
			out = append(out, fileCheck{relPath: rel, content: string(data)})
		}
	}
	// flows/*.yaml - the loader merges these with flows.yaml and the write
	// gate validates them (isFlowsSubdirFile), so check them here too;
	// otherwise a step error in one (e.g. a `run: broadcast` without a room)
	// surfaced only as an app_load failure, and only when nothing else failed.
	if entries, err := readDir("flows"); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			rel := filepath.Join("flows", e.Name())
			if data, err := read(rel); err == nil {
				out = append(out, fileCheck{relPath: rel, content: string(data)})
			}
		}
	}
	// HTML pages - scan the top-level directory only (the page loader
	// is also flat).
	entries, err := readDir(".")
	if err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".html") {
				continue
			}
			if data, err := read(e.Name()); err == nil {
				out = append(out, fileCheck{relPath: e.Name(), content: string(data)})
			}
		}
	}
	// partials/*.html - each gets its own validation pass so a broken
	// partial surfaces independently rather than only as a vague
	// "no such template" error in every page that uses it. Layouts
	// and emails get the same treatment because they're agent-written
	// HTML with the same failure modes.
	for _, sub := range []string{"partials", "layouts", "emails"} {
		subEntries, err := readDir(sub)
		if err != nil {
			continue
		}
		for _, e := range subEntries {
			if e.IsDir() || !strings.HasSuffix(strings.ToLower(e.Name()), ".html") {
				continue
			}
			rel := filepath.Join(sub, e.Name())
			if data, err := read(rel); err == nil {
				out = append(out, fileCheck{relPath: rel, content: string(data)})
			}
		}
	}
	// tests/*.yaml - developer-written test cases. The YAML fallback
	// validator catches indentation/syntax mistakes before the runner
	// rejects them with a less-useful error.
	testEntries, err := readDir("tests")
	if err == nil {
		for _, e := range testEntries {
			if e.IsDir() || !(strings.HasSuffix(e.Name(), ".yaml") || strings.HasSuffix(e.Name(), ".yml")) {
				continue
			}
			rel := filepath.Join("tests", e.Name())
			if data, err := read(rel); err == nil {
				out = append(out, fileCheck{relPath: rel, content: string(data)})
			}
		}
	}

	// src/** and static/** scripts - the React+TS bundle source and the
	// TSX/compute modules the framework compiles. Recursive because larger
	// apps split into components/, lib/, etc. The dispatcher runs
	// detectFrameworkAntipatterns for SPA source (CDN imports,
	// ReactDOM.createRoot, localStorage auth, bare fetch mutations,
	// npm-package imports, etc.) and validateScriptSyntax for both, so a
	// script already deployed that does not parse is reported too.
	for _, sub := range []string{"src", "static"} {
		_ = fs.WalkDir(fsys, sub, func(rel string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil || d == nil {
				return nil
			}
			if d.IsDir() {
				if d.Name() == "node_modules" {
					return fs.SkipDir
				}
				return nil
			}
			if _, ok := scriptSyntaxLoaders[strings.ToLower(filepath.Ext(d.Name()))]; !ok {
				return nil
			}
			if data, err := read(rel); err == nil {
				out = append(out, fileCheck{relPath: rel, content: string(data)})
			}
			return nil
		})
	}

	// tsconfig.json - strict-mode + JSX settings check (validateTSConfig).
	// tsc is editor-only; esbuild does the actual build.
	if data, err := read("tsconfig.json"); err == nil {
		out = append(out, fileCheck{relPath: "tsconfig.json", content: string(data)})
	}

	// Forbidden paths - package.json, node_modules/, lock files, etc.
	// Surface their EXISTENCE as a finding regardless of content. The
	// dispatcher's validateForbiddenPath checks the path string; we
	// just need to feed it any path that matches.
	for _, name := range []string{"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", ".npmrc", "webpack.config.js", "vite.config.js", "vite.config.ts"} {
		if exists(name) {
			out = append(out, fileCheck{relPath: name, content: ""})
		}
	}
	if exists("node_modules") {
		out = append(out, fileCheck{relPath: "node_modules", content: ""})
	}
	return out
}

type fileCheck struct {
	relPath string
	content string
}

func countErrors(fs []CheckFinding) int {
	n := 0
	for _, f := range fs {
		if f.Severity == "error" {
			n++
		}
	}
	return n
}

// isTransientDBPingError reports whether loadErr looks like a
// per-probe DB-ping race rather than a true app-load failure. The
// pattern shows up across sessions as `ping database (corrupt + no
// usable backup): disk I/O error: no such file or directory` while
// the running app's CRUD against the same data.db keeps working -
// usually because the probe opens a fresh handle and races a hot-
// reload that's mid-rebinding WAL/SHM.
//
// We're conservative on what we demote: ONLY ping-error shapes, and
// ONLY when the data.db file actually exists on disk. Anything else
// (e.g. "schema error", "flow runtime rejection") stays an error.
func isTransientDBPingError(dir, loadErr string) bool {
	if !strings.Contains(loadErr, "ping database") &&
		!strings.Contains(loadErr, "disk I/O error: no such file") {
		return false
	}
	if st, err := os.Stat(filepath.Join(dir, "data.db")); err != nil || st.Size() == 0 {
		// Genuinely missing or zero-byte DB → keep the error.
		return false
	}
	return true
}

// tryLoadApp returns an error string if loading the app fails. Uses
// loadApp from main.go but routes any DB it opens to a temp location
// so a stale data.db on disk doesn't poison subsequent calls (most
// tests run inside t.TempDir() anyway; CLI users hit the real db
// which is the right behavior for `benmore check`).
func tryLoadApp(dir string) string {
	app, err := loadAppWithOptions(dir, appLoadOptions{checkOnly: true})
	if err != nil {
		return err.Error()
	}
	if app != nil && app.DB != nil {
		// serve's boot check hands its verification to the start-up load. The
		// load rewrites the file (trigger reinstalls), so the marker waits for
		// its timestamps to settle - worth it only for a database whose
		// quick_check would take longer than that wait.
		app.leaveCleanShutdownMarker(app.DB.Close(), dbFileSize(dir) >= serveBootHandoffMinBytes)
	}
	return ""
}

// checkDBRaceHook runs between openCheckDB's lstat and its open; tests use
// it to swap the file for a link in that window. Nil outside tests.
var checkDBRaceHook func(dbPath string)

// openCheckDB opens an app's live data.db for check_app's read layers (drift,
// unapplied changes). The lstat refuses a link that is already there; the
// open, as openTenantDB opens a tenant database, refuses one swapped in after
// the lstat, because every connection must be the file asked for. mode is
// "ro" or "rw" (which never creates a missing file).
func openCheckDB(dbPath, mode string) (*sql.DB, error) {
	if info, err := os.Lstat(dbPath); err != nil {
		return nil, err
	} else if !info.Mode().IsRegular() {
		return nil, errTenantDBRedirected
	}
	if checkDBRaceHook != nil {
		checkDBRaceHook(dbPath)
	}
	return openTenantDB("sqlite3", dbPath, sqliteRestoreURI(dbPath, mode))
}

// tryDriftCheck reads the declared schema, opens the live database
// (if present), and returns drift findings. Errors during the
// drift check itself are swallowed - the check is best-effort and
// shouldn't fail the whole report.
//
// It runs in the app's own process (check_live, serve's boot check) or for
// `benmore check` in an app directory, and opens the database as
// openTenantDB opens it: a data.db that is, or becomes, a link to another
// file is refused instead of reported on. mode=rw never creates a missing
// file.
func tryDriftCheck(dir string) []SchemaDrift {
	dbPath := filepath.Join(dir, "data.db")
	if info, err := os.Lstat(dbPath); err != nil || !info.Mode().IsRegular() {
		return nil
	}
	models, err := LoadSchemaModelsForDrift(dir)
	if err != nil || len(models) == 0 {
		return nil
	}
	db, err := openCheckDB(dbPath, "rw")
	if err != nil {
		return nil
	}
	defer db.Close()
	drifts, err := DetectSchemaDrift(db, models)
	if err != nil {
		return nil
	}
	return drifts
}
