//go:build !cli

package main

// Where a refusal's rule is documented.
//
// A write-gate refusal, a `benmore check` finding and a runtime error each
// say what is wrong. This file adds where the rule is written: the address
// of the key of the topic reference that states it, read with
// api(at:"<topic>.<key>") or `benmore api <app> <topic>.<key>`.
//
//	JSON   a `docs` field holding the address        "docs": "flows.step_keys"
//	text   one more line after the message           docs: api(at:"flows.step_keys")
//
// Three tables map a rule to its address. Nothing else holds an address:
//
//	gateRuleDocs      a write-gate rule (the validators write_file, edit_file,
//	                  `benmore push` and `benmore check` run on a file)
//	checkSourceDocs   a check finding, by its `source`
//	refusalDocs       a runtime refusal, by its `error` code or name
//
// The topic registry is compiled into the platform edition only, so this
// file does not import it; refusal_docs_registry_test.go (platform) checks
// every address here against the registry, and refusal_docs_test.go checks
// that every rule, source and error code has an entry.

import (
	"strings"
)

// docsRule is where one rule is documented.
type docsRule struct {
	// At is the address of the key that states the rule: "<topic>.<key>".
	At string
	// When narrows a rule whose refusals fall under several keys: the first
	// entry whose Has text is in the refusal's first line names the key, At
	// otherwise. Has is text the validator itself writes; a test fails when
	// no source file writes it any more.
	When []docsWhen
	// Exempt says why the rule carries no address. At is then empty.
	Exempt string
}

// docsWhen names the key for the refusals of a rule that contain Has.
type docsWhen struct{ Has, At string }

// address is the key that documents message under this rule. Only the
// message's first line is read: it states the problem, and the lines after
// it are advice that names many other things.
func (r docsRule) address(message string) string {
	first, _, _ := strings.Cut(message, "\n")
	for _, w := range r.When {
		if strings.Contains(first, w.Has) {
			return w.At
		}
	}
	return r.At
}

// docsLine is the text form of an address: its own line under a message.
func docsLine(at string) string { return `docs: api(at:"` + at + `")` }

// withDocsLine appends the address line to a text message that has none.
func withDocsLine(message, at string) string {
	if at == "" || message == "" {
		return message
	}
	return message + "\n" + docsLine(at)
}

// ===== Write gate =====

// gateRule names one rule of the write gate: a validator the dispatcher
// (validateOnWriteInPending, validators_write.go) runs on a written file, or a
// refusal write_file and edit_file add after it.
type gateRule string

const (
	// Any file.
	gateForbiddenPath gateRule = "forbidden_path"
	gateYAMLLimit     gateRule = "yaml_resource_limit"
	gateSecret        gateRule = "committed_secret"
	gateHIPAAUpload   gateRule = "hipaa_upload_kind"
	gateTableRoute    gateRule = "table_route_collision"
	gateLoadRefs      gateRule = "load_refs"
	gateEncryptedRead gateRule = "encrypted_compute"
	// Scripts and pages.
	gateBrowserSource gateRule = "browser_source"
	gateScriptSyntax  gateRule = "script_syntax"
	gateBundle        gateRule = "bundle"
	gatePage          gateRule = "page"
	gatePageRoute     gateRule = "page_route"
	gateGotmpl        gateRule = "gotmpl"
	gatePageEngine    gateRule = "page_engine"
	gateVideoAutoplay gateRule = "video_autoplay"
	gateInclude       gateRule = "include"
	gateTSConfig      gateRule = "tsconfig"
	// Schema.
	gateSchemaPrisma  gateRule = "schema_prisma"
	gateFulltextEnc   gateRule = "fulltext_encrypted"
	gateMemberOfShape gateRule = "member_of_shape"
	gateSchemaFile    gateRule = "schema_file_switch"
	// Flows.
	gateCommandFlow    gateRule = "command_flow"
	gateFlows          gateRule = "flows"
	gateFlowRoutes     gateRule = "flow_route_collision"
	gateFlowEventTable gateRule = "flow_event_table"
	// Other configuration files.
	gateHooks          gateRule = "hooks"
	gateWhen           gateRule = "when_condition"
	gateMCPManifest    gateRule = "mcp_manifest"
	gateCron           gateRule = "cron"
	gateWorkflows      gateRule = "workflows"
	gateAppYAML        gateRule = "app_yaml"
	gateHIPAAReadAudit gateRule = "hipaa_read_audit"
	gateWorkflowState  gateRule = "workflow_encrypted_state"
	gateAuthz          gateRule = "authz"
	gateSignupFields   gateRule = "signup_fields"
	gateCompliance     gateRule = "compliance_removal"
	gateAggregates     gateRule = "aggregates"
	gateEncryptedYAML  gateRule = "encrypted_yaml"
	gateValidatorsYAML gateRule = "validators_yaml"
	gateComputedYAML   gateRule = "computed_yaml"
	gateRetentionYAML  gateRule = "retention_yaml"
	gateFrameworkTable gateRule = "framework_table_config"
	gateYAMLSyntax     gateRule = "yaml_syntax"
	// write_file and edit_file, after the per-file validators.
	gateSourceReview     gateRule = "reviewed_source_rewrite"
	gateSchemaDrop       gateRule = "schema_drop"
	gateStateRemoval     gateRule = "workflow_state_removal"
	gateSchemaTransition gateRule = "mcp_schema_transition"
	gateSchemaReload     gateRule = "schema_reload"
	gateAutoRun          gateRule = "auto_run_config"
	gateStaticUpload     gateRule = "static_upload"
)

// gateRuleDocs is the address of every write-gate rule. A rule without one
// is listed with the reason (Exempt), so a new rule cannot go without.
var gateRuleDocs = map[gateRule]docsRule{
	gateForbiddenPath: {At: "frontend.how_compile_works"},
	gateYAMLLimit:     {At: "verification.yaml_resource_limits"},
	gateSecret:        {At: "recovery.file_tools"},
	gateHIPAAUpload:   {At: "uploads.hipaa"},
	gateTableRoute:    {At: "schema.reserved_table_names"},
	gateLoadRefs:      {At: "schema.config_references"},
	gateEncryptedRead: {At: "schema.computed_encrypted"},

	gateBrowserSource: {At: "frontend.gotchas", When: []docsWhen{
		{"jsx-cdn-react", "frontend.jsx_runtime"},
		{"spa-react-createroot", "frontend.jsx_runtime"},
		{"spa-cdn-import", "frontend.cdn_imports"},
	}},
	gateScriptSyntax: {At: "compute.write_time_parse"},
	gateBundle:       {At: "frontend.compile_errors"},
	gatePage: {At: "ssr.files", When: []docsWhen{
		{"dead-form", "ssr.forms"},
		{"nested-form", "ssr.forms"},
		{"method-override", "ssr.forms"},
		{"patch-missing-id", "ssr.forms"},
		{"security violation", "ssr.forms"},
		{"in a gotmpl page", "ssr.gotmpl"},
		{"jsx-cdn-react", "frontend.jsx_runtime"},
		{"sse-row-access", "sse.gotchas"},
		{"webrtc-hardcoded-stun", "webrtc.gotchas"},
		{"peer-mesh-stream-room", "webrtc.gotchas"},
		{"antipattern [", "ssr.mustache"},
	}},
	gatePageRoute:     {At: "frontend.ssr_path_params"},
	gateGotmpl:        {At: "ssr.gotmpl"},
	gatePageEngine:    {At: "ssr.page_settings"},
	gateVideoAutoplay: {At: "webrtc.gotchas"},
	gateInclude:       {At: "frontend.partials"},
	gateTSConfig:      {At: "frontend.how_compile_works"},

	gateSchemaPrisma: {At: "schema.field_types", When: []docsWhen{
		{"@@fulltext", "search.prisma_setup"},
		{"onDelete", "schema.referential_actions"},
		{"onUpdate", "schema.referential_actions"},
		{"@", "schema.attributes"},
	}},
	gateFulltextEnc:   {At: "encryption.fulltext"},
	gateMemberOfShape: {At: "access.member_of"},
	gateSchemaFile:    {At: "schema.schema_file"},

	gateCommandFlow: {At: "connector.connector_commands", When: []docsWhen{
		{"exactly one id column", "connector.dependency_shape"},
		// What command SQL may bind, call and touch has its own key.
		{"calls function", "connector.connector_command_sql"},
		{"command SQL", "connector.connector_command_sql"},
		{"SQL binding", "connector.connector_command_sql"},
	}},
	gateFlows: {At: "flows.yaml_example", When: []docsWhen{
		// The file and its trigger.
		{"unknown key", "flows.public_flows"},
		{"flows.yaml: input ", "flows.inputs_block"},
		{"flows.yaml: enum input ", "flows.inputs_block"},
		{"on.request.inputs", "flows.inputs_block"},
		{"on.request.strict_json", "flows.strict_json"},
		{"on.request.verify", "verify.built_in_recipes"},
		{"on.request.secret", "verify.built_in_recipes"},
		{"verify must be", "verify.built_in_recipes"},
		{"on.request.auth", "flows.public_flows"},
		{"on.request.role", "flows.role_gate"},
		{"on.request.mode", "async-flows.yaml_example"},
		{"flows.yaml: rate_limit", "flows.gotchas_request_input"},
		{"on.schedule", "flows.trigger_schedule"},
		{"on.event", "flows.trigger_event"},
		{"reserved prefix", "flows.route_collisions"},
		// Step types with a contract of their own.
		{"isn't a known step type", "flows.step_types"},
		{"using `when:`", "flows.step_types"},
		{"`run: sql_dynamic`", "sql-dynamic.validation"},
		{"can be cut off", "flows.gotchas_file_shape"},
		{"`run: proxy`", "flows.proxy.where"},
		{"proxy step", "flows.proxy_keys"},
		{"`with.url`", "flows.proxy_keys"},
		{"(run: broadcast)", "flows.broadcast_step"},
		{"purge_current_user", "auth.account_erasure"},
		{"revoke_user_sessions", "connector.connector_commands"},
		{"run: extract_text", "pdf.extract_text_flow"},
		{"`run: parse`", "parse.with_shape"},
		{"inside a `run: parallel` block", "flows.parallel"},
		{"with.attachments", "flows.email_attachments"},
		{"unsubscribe", "flows.email_headers"},
		{"with.handled_statuses", "flows.gotchas_outbound_calls"},
		{"with.paginate", "flows.api_paginate"},
		{"`with.json`", "flows.api_json_reference"},
		{"`with.payload`", "flows.webhook"},
		{"`with.flow`", "flows.enqueue"},
		{"`run: api` url", "flows.gotchas_outbound_calls"},
		// References and values.
		{"no step in this flow has id", "flows.step_ids"},
		{"`, but step ", "flows.step_output_refs"},
		{"steps after an unconditional", "flows.response_reachability"},
		{"doesn't parse as an expression", "flows.value_expressions"},
		{"can never be true", "flows.gotchas_conditions"},
		{"reserved template name", "flows.gotchas_request_input"},
		{"inside the quoted string", "flows.event_row_params"},
		{"RAISE()", "flows.upsert_select"},
		{"ON CONFLICT", "flows.upsert_select"},
		{"expect_rows", "flows.gotchas_sql_steps"},
		{"`retry", "flows.step_retry"},
		{"`as: ", "flows.for_each"},
		{"is not read", "flows.step_keys"},
		{"`with.query`", "flows.step_keys"},
	}},
	gateFlowRoutes:     {At: "flows.route_collisions"},
	gateFlowEventTable: {At: "flows.trigger_event"},

	gateHooks:       {At: "hooks.yaml_example"},
	gateWhen:        {At: "hooks.when_conditions"},
	gateMCPManifest: {At: "connector.manifest_authoring", When: []docsWhen{{"digest mismatch", "connector.connector_source_review"}}},
	gateCron:        {At: "cron.contract", When: []docsWhen{{"monitor", "cron.monitors"}}},
	gateWorkflows: {At: "workflows.keys", When: []docsWhen{
		{"is a framework table", "schema.framework_tables"},
		{"has column default", "workflows.state_default_check"},
		{"the same table", "workflows.one_per_table"},
	}},
	gateAppYAML: {At: "recovery.configuration_loading", When: []docsWhen{
		{"[unknown-app-yaml-key]", "recovery.configuration_loading"},
		{"-auth-key]", "auth.app_yaml_flags"},
		{"compliance: hipaa", "compliance.controls"},
		{"app.yaml: compliance", "compliance.controls"},
		{"[unknown-csp-key]", "csp.gotchas"},
		{"app.yaml: access.", "access.modes"},
		{"app.yaml: ws_rooms", "websocket.room_authorization"},
		{"app.yaml: auth.signup_rate_limit", "auth.signup_limits"},
		{"app.yaml: auth.", "auth.app_yaml_flags"},
		{"app.yaml: csp.", "csp.gotchas"},
		{"app.yaml: groups.", "scoping.tenant_bootstrap"},
		{"app.yaml: encrypted", "encryption.yaml_shape"},
		{"app.yaml: table_scopes", "rbac.gotchas"},
		{"app.yaml: role ", "rbac.roles_yaml"},
	}},
	gateHIPAAReadAudit: {At: "compliance.read_audit"},
	gateWorkflowState:  {At: "workflows.encrypted_state"},
	gateAuthz:          {At: "rbac.gotchas"},
	gateSignupFields:   {At: "auth.profile_fields"},
	gateCompliance:     {At: "compliance.controls"},
	gateAggregates:     {At: "aggregates.declare"},
	gateEncryptedYAML:  {At: "encryption.yaml_shape"},
	gateValidatorsYAML: {At: "schema.cross_field_validators"},
	gateComputedYAML:   {At: "computed.declare", When: []docsWhen{{"a framework table", "schema.framework_tables"}}},
	gateRetentionYAML:  {At: "retention.keys"},
	gateFrameworkTable: {At: "schema.framework_tables"},
	// A file no validator owns (tests/*.yaml, verify.yaml, a data file): the
	// YAML parser's own message, with its line, is the whole rule.
	gateYAMLSyntax: {Exempt: "a YAML syntax error in a file no validator owns; the parser's message is the rule"},

	gateSourceReview:     {At: "connector.connector_source_review"},
	gateSchemaDrop:       {At: "schema.removed_models", When: []docsWhen{{"applies a new migration file", "schema.migration_file_drops"}}},
	gateStateRemoval:     {At: "workflows.state_removal"},
	gateSchemaTransition: {At: "connector.destructive_schema"},
	gateSchemaReload:     {At: "recovery.failed_migration_push"},
	// Only the refusal of the path itself; a failure to resolve the path is
	// an I/O error and names no rule.
	gateAutoRun:      {When: []docsWhen{{"auto-run configuration", "sync-status.excludes"}}},
	gateStaticUpload: {At: "recovery.file_tools"},
}

// gateDocs is the key that documents message, a refusal of rule; "" when the
// rule has none.
func gateDocs(rule gateRule, message string) string {
	return gateRuleDocs[rule].address(message)
}

// gateRefusal is a write refusal raised outside the dispatcher, with its
// address line.
func gateRefusal(rule gateRule, message string) string {
	return withDocsLine(message, gateDocs(rule, message))
}

// gateVerdict is the write gate's answer for one file.
type gateVerdict struct {
	// Message is the refusal as the validators word it, "" when the file
	// passes: a check finding's `message`.
	Message string
	// Refusal is Message with an address line under each issue: the text a
	// refused write answers.
	Refusal string
	// Docs is the address of the first issue: a check finding's `docs`.
	Docs string
}

// newGateVerdict joins a write's issues the way the gate always has, and a
// second time with the address line of each issue's rule (rules[i] is the
// rule behind issues[i]; an issue with no rule gets no line). rename, when
// set, is applied to both (a flow file's own path, nameFlowFile); footer
// follows both.
func newGateVerdict(issues []string, rules map[int]gateRule, rename func(string) string, footer string) gateVerdict {
	if len(issues) == 0 {
		return gateVerdict{}
	}
	const between = "\n\n---\n\n"
	var v gateVerdict
	documented := make([]string, len(issues))
	for i, issue := range issues {
		at := ""
		if rule, ok := rules[i]; ok {
			at = gateDocs(rule, issue)
		}
		if v.Docs == "" {
			v.Docs = at
		}
		documented[i] = withDocsLine(issue, at)
	}
	v.Message, v.Refusal = strings.Join(issues, between), strings.Join(documented, between)
	if rename != nil {
		v.Message, v.Refusal = rename(v.Message), rename(v.Refusal)
	}
	if footer != "" {
		v.Message += "\n\n" + footer
		v.Refusal += "\n\n" + footer
	}
	return v
}

// ===== Check findings =====

// checkSourceDocs is the address of a check finding, by the `source` that
// names the layer that raised it. "syntax" is the write gate's own layer:
// its findings carry the address of their rule (gateRuleDocs), and the entry
// here covers the one syntax finding raised outside it.
var checkSourceDocs = map[string]docsRule{
	"syntax":     {At: "cron.contract"}, // cron.yaml naming a flow a write removed (cronFlowRefFindingsAfterWrite)
	"tests":      {At: "verification.test_file_load"},
	"cross_file": {At: "schema.config_references", When: []docsWhen{{"app.yaml: access.", "access.modes"}}},
	// An app.yaml key or value that is accepted and has no effect
	// (app_yaml_no_effect.go, app_yaml_unread.go).
	"config": {At: "frontend.site_identity", When: []docsWhen{
		{"is not a key the framework reads", "recovery.configuration_loading"},
		{"is not a value the framework knows", "ssr.appearance"},
		{"takes text", "recovery.configuration_loading"},
		// A switch or an enumeration written in a value that is not read
		// the way it is written (app_yaml_switch_values.go).
		{"`recording.", "frontend.ssr_session_recording"},
		{"`features.", "recovery.configuration_loading"},
		{"`oauth.", "oauth.configuration_notes"},
		{"`auth.identifier", "auth.app_yaml_flags"},
	}},
	"flows": {At: "flows.checked_values", When: []docsWhen{
		{"on.request.role", "flows.role_gate"},
		{"sends at once and is not undone", "flows.transactional_sends"},
		{"write-transaction limit", "flows.time_limits"},
		{"is `mode: async` but has a respond", "async-flows.hint"},
		{"redirects to a templated", "flows.redirect"},
		{"shadows the request field", "flows.step_named_request_fields"},
		{"`run: respond` has no `with:`", "flows.step_types"},
	}},
	"edge_status":  {At: "flows.edge_error_status"},
	"step_outputs": {At: "flows.step_output_refs"},
	"routes":       {At: "flows.route_collisions"},
	"schema": {At: "schema.field_types", When: []docsWhen{
		{"framework-protected field name", "scoping.how"},
	}},
	"security": {At: "access.gotchas", When: []docsWhen{
		{"opens a WebSocket to", "csp.websockets"},
		{"auth.require_mfa_for_roles", "mfa.config"},
		{"in unmask roles", "encryption.owner_alias"},
		{"join WebSocket rooms", "websocket.room_authorization"},
		{"app.yaml: ws_rooms", "websocket.room_authorization"},
		{"unique constraint", "scoping.tenant_unique_constraints"},
		{"is the groups membership table", "scoping.tenant_unique_constraints"},
		{"member-of membership table", "access.member_of"},
		{"groups.role_field", "scoping.tenant_roles"},
		{"holds the tenant role", "scoping.tenant_roles"},
		{"app.yaml: roles:", "rbac.gotchas"},
		{"on a table with user_id and no tenant key", "access.role_mode_rows"},
	}},
	"mcp_connector": {At: "connector.command_encryption_key", When: []docsWhen{
		{"revision ledger row missing", "connector.revision_trigger_order"},
		{"removes", "connector.destructive_schema"},
		{"has no predicate tied to the caller", "connector.caller_predicate"}, // appMCPCommandCallerPredicateDocs
	}},
	"compliance": {At: "audit.flow_writes", When: []docsWhen{
		{"responds with whole rows of step", "encryption.flow_results"},
	}},
	"retention":          {At: "retention.keys"},
	"pwa":                {At: "mobile.pwa"},
	"workflows":          {At: "workflows.role_lists"},
	"workflow_states":    {At: "workflows.state_removal"},
	"schema_not_applied": {At: "schema.unapplied_changes"},
	"app_load":           {At: "recovery.rejected_reload"},
	"app_live":           {At: "recovery.health_readiness"},
	"environment": {At: "errors.sentry", When: []docsWhen{
		{"monitor", "errors.cron_monitors"},
		{"ERROR_SLACK_WEBHOOK", "errors.slack"},
		{"SENTRY_MIN_LEVEL", "errors.minimum_level"},
	}},
	"drift":   {At: "schema.schema_drift"},
	"bundle":  {At: "frontend.compile_errors"},
	"include": {At: "frontend.partials"},
	// `benmore upgrade check` is the operator's pre-upgrade report on a host,
	// not a finding an app builder acts on.
	"upgrade": {Exempt: "operator report (benmore upgrade check), documented in the release runbook"},
	// The CLI's stand-in when a saved write answers error_summary and no
	// findings: it repeats that summary, which names no rule.
	"check": {Exempt: "the CLI's echo of error_summary, which names no rule"},
}

// checkFindingDocs is the key that documents a finding raised outside the
// write gate.
func checkFindingDocs(f CheckFinding) string {
	return checkSourceDocs[f.Source].address(f.Message)
}

// withFindingDocs fills the `docs` of every finding that has none.
func withFindingDocs(findings []CheckFinding) []CheckFinding {
	for i := range findings {
		if findings[i].Docs == "" {
			findings[i].Docs = checkFindingDocs(findings[i])
		}
	}
	return findings
}

// findingDocsLine is the address line a text rendering of f adds under its
// message, "" when f has none.
func findingDocsLine(f CheckFinding) string {
	if f.Docs == "" {
		return ""
	}
	return docsLine(f.Docs)
}

// ===== Runtime refusals =====

// Names of runtime refusals whose `error` is a sentence, not a code. A
// refusal with a stable code is keyed by that code.
const (
	refusalAuthRequired   = "authentication_required" // 401 {"error":"authentication required"} on auto-CRUD
	refusalCSRF           = "csrf"                    // 403 {"error":"Invalid CSRF token"}
	refusalScopeDenied    = "scope_denied"            // 403 {"error":"scope denied: ..."}
	refusalRecordLocked   = "record_locked"           // 409 {"error":"record is locked by another user"}
	refusalBodyTooLarge   = "request_body_too_large"  // 413
	refusalUploadTooLarge = "upload_body_too_large"   // 413 on a multipart create
	refusalValidatorRule  = "validator_rule"          // 422 from a validators.yaml rule
	refusalForeignKey     = "foreign_key_target"      // 422, a parent the caller cannot read
	refusalTenantRequired = "tenant_required"         // 422, a create with no tenant
	refusalFlowInput      = "flow_input"              // 422, a declared flow input
	refusalFlowRateLimit  = "flow_rate_limit"         // 429 from on.request.rate_limit
	refusalRateLimit      = "rate_limit"              // 429 from the app-wide limiter
	refusalIngestLimit    = "ingest_rate_limit"       // 429 on /api/<table>/ingest
	refusalLockRateLimit  = "lock_rate_limit"         // 429 on a lock acquire
	refusalNoFields       = "no_fields_to_update"     // 400, every submitted field stripped
	refusalWorkflowRole   = "workflow_role"           // 403 forbidden on a transition
	refusalPromoteUpgrade = "upgrade_required"        // promote on a plan without publishing
	refusalPlanChangeUse  = "plan_change_use"         // 409, a plan the account's use does not fit
	refusalConnectorError = "connector_error"         // a failed connector tool call; narrowed by its error_code
	refusalActAsReason    = "act_as_reason"           // a probe as an app user of a hipaa app with no reason
)

// refusalDocs is the address of a runtime refusal: by the stable code its
// answer carries in `error` (or `code`), or by one of the names above.
var refusalDocs = map[string]docsRule{
	// Auto-CRUD.
	refusalAuthRequired:      {At: "access.gotchas"},
	"forbidden":              {At: "access.operations", When: []docsWhen{{"belong to a tenant", "scoping.missing_group"}}},
	"not_found":              {At: "errors.common_envelopes"},
	refusalCSRF:              {At: "csrf.how_to_send"},
	refusalScopeDenied:       {At: "rbac.gotchas"},
	"conflict":               {At: "concurrency.timestamp_contract"},
	refusalRecordLocked:      {At: "locks.conflict"},
	refusalBodyTooLarge:      {At: "flows.request_body"},
	refusalUploadTooLarge:    {At: "uploads.size_limits"},
	refusalUploadFileSize:    {At: "uploads.size_limits"},
	refusalUploadFileType:    {At: "uploads.gotchas", When: []docsWhen{{"has no extension", "uploads.size_limits"}}},
	refusalMultipartUpdate:   {At: "uploads.multipart_bodies"},
	refusalValidatorRule:     {At: "schema.cross_field_validators"},
	refusalForeignKey:        {At: "scoping.foreign_keys"},
	refusalTenantRequired:    {At: "scoping.tenant_bootstrap"},
	refusalNoFields:          {At: "scoping.how", When: []docsWhen{{"changes only through a transition", "workflows.transition_writes"}, {"the admin panel never writes", "auth.admin_panel_accounts"}}},
	"field_owned_by_command": {At: "scoping.command_owned_fields"},
	uploadsDisabledCode:      {At: "uploads.feature_gate"},
	sharingDisabledCode:      {At: "permissions.sharing_switch"},
	"storage_limit":          {At: "recovery.storage_limit"},
	mediaAllowanceCode:       {At: "uploads.storage_allowance"},
	refusalWorkflowRole:      {At: "workflows.transition_roles"},
	// Rate limits.
	refusalFlowRateLimit: {At: "flows.gotchas_request_input"},
	refusalRateLimit:     {At: "errors.text_answers"},
	refusalIngestLimit:   {At: "ingest.rate_limit"},
	refusalLockRateLimit: {At: "locks.rate_limit"},
	// Flows.
	refusalFlowInput:      {At: "flows.inputs_block"},
	"template_unresolved": {At: "errors.common_envelopes"},
	"flow_no_response":    {At: "flows.step_failures"},
	"flow_timeout":        {At: "flows.time_limits"},
	// Sign-in state and account limits.
	"password_change_required":    {At: "auth.required_password_change"},
	"otp_required":                {At: "auth.step_pages"},
	"mfa_required":                {At: "mfa.login_steps"},
	emailVerificationRequiredCode: {At: "auth.account_state_signin"},
	"email_unverified":            {At: "scoping.email_keyed_grants"},
	"api_token_limit":             {At: "auth.credential_limits"},
	// A scoped credential on a page that requires sign-in, or on its PDF.
	scopedCredentialPageCode: {At: "auth.credential_limits"},
	// The admin panel's write routes on a table it only shows.
	"admin_table_read_only": {At: "auth.credential_limits", When: []docsWhen{{"is an audit table", "audit.append_only"}, {"holds role grants", "auth.admin_panel_accounts"}, {"is a framework table", "auth.admin_panel_accounts"}, {"is a version history table", "versioning.history_table"}}},
	// The admin panel's edit of another admin's sign-in identifier.
	adminIdentifierProtectedCode: {At: "auth.admin_panel_accounts"},
	// A role change that takes admin away from another admin.
	adminDemotionProtectedCode: {At: "auth.admin_panel_accounts"},
	// Other built-in routes.
	"report_source_limit_exceeded": {At: "query.report_sources"},
	"language_not_found":           {At: "i18n.endpoint"},
	"encryption_key_not_durable":   {At: "encryption.secret_durability"},
	"invalid_expires_in":           {At: "signed-urls.lifetime"},
	refusalPromoteUpgrade:          {At: "environments.publishing"},
	// A command aimed at the production of an app that has none.
	"no_production_instance": {At: "environments.no_production_instance"},
	// POST /platform/billing/plan: the first thing the refusal names as over.
	refusalPlanChangeUse: {At: "environments.publishing", When: []docsWhen{
		{"published where", "environments.publishing"},
		{"in total where", "environments.publishing"},
		{"collaborator", "collaborators.plans"},
		{"media storage", "uploads.storage_allowance"},
	}},
	// probe_route `as` / `benmore probe --as` on a compliance: hipaa app
	// with no stated reason.
	refusalActAsReason: {At: "compliance.workforce_reads"},
	// The app's MCP connector: _meta.docs of a failed tool call, by its
	// error_code (appMCPErrorCodes).
	refusalConnectorError: {At: "connector.connector_errors", When: []docsWhen{
		{"hook_refused", "connector.connector_hooks_effects"},
		{"expired_intent", "connector.connector_commit"},
		{"approval_required", "connector.connector_commit"},
		{"in_progress", "connector.connector_commit"},
		{"unknown_execution", "connector.connector_commit"},
		{"operation_limit", "connector.connector_commit"},
	}},
}

// refusalCodeExemptions are stable codes an answer carries that have no
// address, each with the reason. refusal_docs_test.go fails on a code in the
// runtime's source that is neither here nor in refusalDocs.
var refusalCodeExemptions = map[string]string{
	// OAuth 2.0 and its extensions define these codes and their meaning
	// (RFC 6749, 7591, 8628, 8707); a client reads the RFC, not the app docs.
	"invalid_request":         "OAuth protocol code",
	"invalid_grant":           "OAuth protocol code",
	"invalid_client_metadata": "OAuth protocol code",
	"invalid_redirect_uri":    "OAuth protocol code",
	"invalid_scope":           "OAuth protocol code",
	"invalid_target":          "OAuth protocol code",
	"invalid_token":           "OAuth protocol code",
	"unsupported_grant_type":  "OAuth protocol code",
	"access_denied":           "OAuth protocol code",
	"server_error":            "OAuth protocol code",
	"temporarily_unavailable": "OAuth protocol code",
	"too_many_requests":       "OAuth client-registration limit, answered in OAuth's error shape",
	// The platform operator's own surfaces, not an app's.
	"step_up_required":     "platform operator step-up, not an app route",
	"step_up_not_enrolled": "platform operator step-up, not an app route",
	"step_up_locked":       "platform operator step-up, not an app route",
	"step_up_invalid_code": "platform operator step-up, not an app route",
	"app_unavailable":      "the platform router's answer for an app that is down: nothing in the app's source decides it",
	"outcome_unknown":      "the platform router's answer for a write whose outcome it lost: nothing in the app's source decides it",
	// Internal or retired surfaces.
	"internal":               "the router-to-app data channel, never answered to an app's client",
	"hosted_builder_retired": "a retired dashboard route; the message says what to use",
}

// refusalDocsAt is the key that documents a runtime refusal; message narrows
// a code several rules answer.
func refusalDocsAt(name, message string) string {
	return refusalDocs[name].address(message)
}

// withRefusalDocs adds the `docs` address to a runtime refusal's JSON body.
func withRefusalDocs(body map[string]any, name string) map[string]any {
	message, _ := body["message"].(string)
	if hint, _ := body["hint"].(string); hint != "" {
		message += " " + hint
	}
	if at := refusalDocsAt(name, message); at != "" {
		body["docs"] = at
	}
	return body
}

// refusalTextNames are `error` sentences that mean the same on every route,
// so httpError (crud_http.go) adds the address wherever one is answered. A
// sentence whose meaning depends on the route gets its address at that route.
var refusalTextNames = []struct{ prefix, name string }{
	{"Invalid CSRF token", refusalCSRF},
	{"scope denied:", refusalScopeDenied},
}

// refusalTextDocs is the address for an `error` sentence httpError answers,
// "" for every sentence but the few in refusalTextNames.
func refusalTextDocs(sentence string) string {
	for _, t := range refusalTextNames {
		if strings.HasPrefix(sentence, t.prefix) {
			return refusalDocsAt(t.name, sentence)
		}
	}
	return ""
}
