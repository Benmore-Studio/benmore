//go:build !cli

package main

// GitHub Actions-shaped flows. The agent's training data is dense with
// `on:` + `jobs:` + `steps:` YAML - every active repo on the planet
// has at least one workflow file. We use that exact shape for Benmore's
// flow definitions; the existing flow runtime (sql, api, email,
// webhook, respond, etc.) stays unchanged, only the front-end YAML
// shape is new.
//
// What the agent writes:
//
//   on:
//     request:
//       method: POST
//       path: /api/sheet/save/:id
//       auth: required
//
//   jobs:
//     save:
//       steps:
//         - id: access
//           run: sql
//           query: SELECT user_id FROM sheets WHERE id = :id
//
//         - if: ${{ steps.access.outputs.user_id != user.id }}
//           run: respond
//           with:
//             status: 403
//             body: { error: forbidden }
//
//         - run: sql
//           query: UPDATE sheets SET name = :name WHERE id = :id
//
// Step actions (the `run:` field):
//   sql       - execute SQL. Required: `query:`. Outputs columns of
//               the first row under `steps.<id>.outputs.<col>`.
//   api       - outbound HTTP. Required: `with: { method, url, ... }`.
//   email     - send email. Required: `with: { to, subject, template }`.
//   webhook   - POST to URL. Required: `with: { url, body }`.
//   redirect  - 303 redirect. Required: `with: { to }`.
//   respond   - custom HTTP response. Required: `with: { status, body }`.
//   parse     - parse request body. Required: `with: { source: body }`.
//   set       - set named values. Required: `with: <map>`.
//
// Variable references use `${{ ... }}` (GHA shape). At parse time these
// are normalized to the runtime's `{{ ... }}` form:
//   ${{ steps.foo.outputs.bar }}  →  {{ foo.bar }}
//   ${{ env.NAME }}               →  {{ env.NAME }}
//   ${{ user.email }}             →  {{ user_email }}
//   ${{ user.id }}                →  {{ user_id }}
//   ${{ params.X }}               →  {{ X }}
//
// Conditionals on `if:` accept the same expressions; comparison
// operators are GHA-shaped (`==`, `!=`, `>`, `<`, `&&`, `||`).

import (
	"encoding/json"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FlowFileGHA is the top-level shape of the new flows.yaml.
type FlowFileGHA struct {
	On   FlowTriggerGHA        `yaml:"on"`
	Jobs map[string]FlowJobGHA `yaml:"jobs"`
	// Idempotent (top level, next to on/jobs) declares that every side
	// effect of the flow is safe to replay: a job of it interrupted by a
	// worker crash is requeued instead of failed (jobsRecoverOrphanedJobs).
	Idempotent bool `yaml:"idempotent"`
}

// FlowTriggerGHA is the `on:` map. Mirrors the shape every GitHub
// Actions workflow file uses.
//
//	on:
//	  request: { method, path, ... }
//	  schedule: { cron: "*/5 * * * *" }
//	  event: { table: notes, op: insert }
type FlowTriggerGHA struct {
	Request  *FlowRequestTrigger  `yaml:"request"`
	Schedule *FlowScheduleTrigger `yaml:"schedule"`
	Event    *FlowEventTrigger    `yaml:"event"`
}

// FlowScheduleTrigger fires on a cron schedule. Same parser the legacy
// `trigger: cron <expr>` shape used.
type FlowScheduleTrigger struct {
	Cron string `yaml:"cron"`
}

// FlowEventTrigger fires when a row mutates. `table` + one of
// `op: insert | update | delete`.
type FlowEventTrigger struct {
	Table string `yaml:"table"`
	Op    string `yaml:"op"`
}

// FlowRequestTrigger configures HTTP-triggered flows. Mirrors what
// used to live as "trigger: METHOD /path" + auth/role/transaction/verify
// on the old shape, just split into named fields for clarity.
type FlowRequestTrigger struct {
	Method      string   `yaml:"method"`
	Path        string   `yaml:"path"`
	Auth        string   `yaml:"auth"`
	Role        string   `yaml:"role"`
	Permissions []string `yaml:"permissions"`
	Transaction bool     `yaml:"transaction"`
	// StrictJSON makes this HTTP route accept only one bounded JSON object
	// with unambiguous keys before any flow step runs.
	StrictJSON yaml.Node `yaml:"strict_json"`
	// Verify configures inbound webhook signature verification. The
	// canonical shape is a YAML map declaring a recipe + its inputs:
	//
	//   verify:
	//     recipe: hmac_timestamp_dot_body
	//     header: X-Webhook-Signature
	//     timestamp_header: X-Webhook-Timestamp
	//     secret: "{{ env.WEBHOOK_SECRET }}"
	//     skew_seconds: 300
	//
	// See verify_recipe.go for the full list of recipes. The field is
	// typed `any` because yaml.v3 unmarshals a map shape into
	// map[string]any; the parser dispatches in loadOneGHAFile.
	Verify any    `yaml:"verify"`
	Secret string `yaml:"secret"`
	// Mode toggles the dispatch strategy. Empty / "sync" (default) runs
	// the flow inline on the request goroutine. "async" enqueues the
	// flow onto the background worker and returns {job_id, status_url}
	// immediately - required when carrier fan-outs / report generation
	// push wall time past Cloudflare's 30s edge timeout.
	Mode string `yaml:"mode"`
	// RateLimit caps invocation frequency, e.g. "5/hour per ip". See
	// flows_ratelimit.go / api(at:'flows').
	RateLimit string `yaml:"rate_limit"`
	// Inputs optionally declares the flow's expected inputs - a typed
	// signature, keyed by input name. Values are checked before execution;
	// path/query/body binding is unchanged. Declaring them lets the
	// frontend derive a form - bm.flows.<name>() gets a typed body and
	// the FlowForm component renders controls from this. See FlowInput.
	Inputs map[string]FlowInput `yaml:"inputs"`
}

// FlowInput is one declared input on a request-triggered flow. The
// type vocabulary matches the schema-descriptor control set so a single
// control-renderer serves both auto-CRUD forms and flow forms.
type FlowInput struct {
	Type     string   `yaml:"type" json:"type"` // text|textarea|number|bool|date|enum|email
	Required bool     `yaml:"required" json:"required,omitempty"`
	Label    string   `yaml:"label" json:"label,omitempty"`
	Help     string   `yaml:"help" json:"help,omitempty"`
	Values   []string `yaml:"values" json:"values,omitempty"` // enum only
	Default  any      `yaml:"default" json:"default,omitempty"`
	Min      *float64 `yaml:"min" json:"min,omitempty"` // number only
	Max      *float64 `yaml:"max" json:"max,omitempty"`
}

// FlowJobGHA holds the linear step list. Multiple jobs are allowed but
// they currently execute in series (no parallelism); we use the map
// shape to keep the GHA familiarity intact for the agent.
type FlowJobGHA struct {
	Steps []FlowStepGHA `yaml:"steps"`
}

// FlowStepGHA matches GHA's step shape closely. The `run:` field
// dispatches to step type; `with:` carries action-specific params.
//
// Two control-flow shapes that aren't a single `run:`:
//   - `for_each:` + `as:` - iterate over a previous step's rows
//   - `on_error:` - error-handling step list, runs only if the
//     containing step (or any sibling earlier in the on_error block)
//     errored out
//
// Not every step type reads every field, and each reads its own `with:`
// keys: flowStepKeyTable (validators_flow_step_keys.go) is the list, and the
// write gate refuses a key outside it.
type FlowStepGHA struct {
	ID string `yaml:"id"`
	If string `yaml:"if"`
	// When is NOT a real step key - the flow engine has no `when:`. It's
	// captured ONLY so the write-time validator can reject a `when:` typo
	// (which yaml.v3 would otherwise silently drop, leaving the intended
	// guard inert so the branch always runs). Never read by the runtime.
	When  string `yaml:"when"`
	Run   string `yaml:"run"`
	Query string `yaml:"query"` // shorthand for run: sql, with: { query: ... }
	// ExpectRows asserts on the row count of a `run: sql` / `run: sql_dynamic`
	// step (e.g. ">0", "=1", or a bare integer): rows returned by a SELECT or
	// a RETURNING write, rows affected by any other write. This is the
	// canonical position; `with.expect_rows` is read as the same assertion
	// (ghaStepExpectRows), as `params` is in both places.
	ExpectRows string `yaml:"expect_rows"`
	// RawParams accepts `params:` at the step root (sibling to the
	// `query:` shorthand). When the agent uses the shorthand they
	// don't have a `with:` block to put params under, so we pull
	// them up to the step level. Equivalent to `with.params:` semantically.
	RawParams  any            `yaml:"params"`
	With       map[string]any `yaml:"with"`
	Steps      []FlowStepGHA  `yaml:"steps"` // nested for compound if/for_each branches
	Else       []FlowStepGHA  `yaml:"else"`
	ForEach    string         `yaml:"for_each"`
	As         string         `yaml:"as"`
	OnError    []FlowStepGHA  `yaml:"on_error"`
	Retry      int            `yaml:"retry"`
	RetryDelay string         `yaml:"retry_delay"`
	Timeout    string         `yaml:"timeout"`
	// Only ordered recipe computation needs the source mapping order; With
	// remains the compatibility map used by validators and other actions.
	signComputeOrder []string
}

// UnmarshalYAML retains the one ordering-sensitive part of with.sign before
// decoding it through a generic map (whose later marshal sorts its keys).
func (s *FlowStepGHA) UnmarshalYAML(node *yaml.Node) error {
	type plain FlowStepGHA
	var decoded plain
	if err := node.Decode(&decoded); err != nil {
		return err
	}
	*s = FlowStepGHA(decoded)
	var ordered struct {
		With struct {
			Sign struct {
				Compute yaml.Node `yaml:"compute"`
			} `yaml:"sign"`
		} `yaml:"with"`
	}
	// Unrelated malformed sign shapes retain their existing parser behavior.
	if err := node.Decode(&ordered); err == nil {
		s.signComputeOrder = ghaOrderedMappingKeys(&ordered.With.Sign.Compute)
	}
	return nil
}

// ghaOrderedMappingKeys follows aliases and YAML merge precedence without
// re-expanding repeated aliases. Explicit entries replace merged entries and
// each source mapping retains its declaration order.
func ghaOrderedMappingKeys(node *yaml.Node) []string {
	memo := map[*yaml.Node][]string{}
	active := map[*yaml.Node]bool{}
	var keys func(*yaml.Node) []string
	keys = func(n *yaml.Node) []string {
		if n == nil || active[n] {
			return nil
		}
		if got, ok := memo[n]; ok {
			return got
		}
		active[n] = true
		defer delete(active, n)
		var out []string
		seen := map[string]bool{}
		add := func(k string) {
			if !seen[k] {
				seen[k] = true
				out = append(out, k)
			}
		}
		switch n.Kind {
		case yaml.AliasNode:
			out = keys(n.Alias)
		case yaml.SequenceNode:
			for _, child := range n.Content {
				for _, k := range keys(child) {
					add(k)
				}
			}
		case yaml.MappingNode:
			explicit := map[string]bool{}
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Tag != "!!merge" {
					explicit[n.Content[i].Value] = true
				}
			}
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Tag == "!!merge" {
					for _, k := range keys(n.Content[i+1]) {
						if !explicit[k] {
							add(k)
						}
					}
				} else {
					add(n.Content[i].Value)
				}
			}
		}
		memo[n] = out
		return out
	}
	return keys(node)
}

func (s FlowStepGHA) preserveSignComputeOrder(api *FlowAPICall) {
	if api.Sign == nil || api.Sign.Inline == nil || len(s.signComputeOrder) == 0 {
		return
	}
	bindings := api.Sign.Inline.Compute
	byName := make(map[string]RecipeBinding, len(bindings))
	for _, b := range bindings {
		byName[b.Name] = b
	}
	ordered := make([]RecipeBinding, 0, len(bindings))
	for _, name := range s.signComputeOrder {
		if b, ok := byName[name]; ok {
			ordered = append(ordered, b)
			delete(byName, name)
		}
	}
	for _, b := range bindings {
		if _, ok := byName[b.Name]; ok {
			ordered = append(ordered, b)
		}
	}
	api.Sign.Inline.Compute = ordered
}

// LoadFlowsGHA reads flows.yaml (and every flows/*.yaml file beside it)
// in the new GHA-shaped format and converts to the runtime's existing
// []Flow representation. The translation is mechanical: top-level
// on/jobs unrolls to one Flow per (trigger × job) pair, each step is
// mapped to its FlowStep equivalent.
//
// Multi-file layout: each YAML file may only declare one `on:` block
// (the GHA limitation, not ours). To register more than one trigger
// per app, drop additional GHA-shaped files under flows/*.yaml - they
// all get merged into the same []Flow list. Files that error are
// skipped with a warning so one bad file doesn't kill the others.
// LoadFlowsGHA is the compatibility entry point for GHA-only consumers.
func LoadFlowsGHA(dir string) []Flow {
	flows, err := loadFlowsChecked(dir, false)
	if err != nil {
		log.Printf("%s", err)
	}
	return flows
}

func loadOneGHAFile(path string) []Flow {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	flows, err := parseGHAFlowFile(path, data)
	if err != nil {
		log.Printf("%s", err)
	}
	return flows
}

func parseGHAFlowFile(path string, data []byte) ([]Flow, error) {
	// Named command declarations have stricter raw-node admission than this
	// compatibility decoder can provide. loadFlowsCheckedFromSources routes
	// them through the command compiler before reaching the ordinary GHA parser.
	var rawRoot map[string]any
	if err := decodeConfigYAML(data, &rawRoot); err == nil {
		if _, command := rawRoot["command"]; command {
			return nil, fmt.Errorf("%s: command declarations require the checked command compiler", path)
		}
	}
	var file FlowFileGHA
	if err := decodeConfigYAML(data, &file); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	if file.Jobs == nil || (file.On.Request == nil && file.On.Schedule == nil && file.On.Event == nil) {
		return nil, fmt.Errorf("%s: expected on and jobs with at least one trigger", path)
	}
	if msg := validateGHAFlowsContents(file); msg != "" {
		return nil, fmt.Errorf("%s: %s", path, msg)
	}
	if msg := detectLegacyShorthandInGHASteps(string(data)); msg != "" {
		return nil, fmt.Errorf("%s: %s", path, msg)
	}
	// Refused at write time; a deployed file keeps its lenient reading.
	for _, problem := range flowTriggerProblems(file) {
		log.Printf("WARNING: %s: %s", path, problem)
	}
	// Also refused at write time. A deployed file still loads, and the log
	// names each expect_rows that is not the assertion its author wrote.
	for _, problem := range flowExpectRowsProblems(string(data), file) {
		log.Printf("WARNING: %s: %s", path, problem)
	}
	// Step keys the step's type does not read: refused at write time too,
	// except those deployed apps carry, which only this log names.
	refusedKeys, ignoredKeys := flowStepKeyProblems(string(data), file)
	for _, problem := range append(refusedKeys, ignoredKeys...) {
		log.Printf("WARNING: %s: %s", path, problem)
	}
	// Step values that cannot be sent as written (a refused response
	// header, two bodies): refused at write time, dropped here with a log.
	for _, problem := range flowStepValueProblems(file) {
		log.Printf("WARNING: %s: %s", path, problem)
	}
	// Build the FlowTrigger from whichever `on:` shape was set.
	var trigger FlowTrigger
	var verify, secret, auth, role string
	var permissions []string
	var transaction, async bool
	var rateLimit *FlowRateLimit
	var verifyConfig *FlowVerify
	switch {
	case file.On.Request != nil:
		trigger = FlowTrigger{
			Type:   "http",
			Method: strings.ToUpper(file.On.Request.Method),
			Path:   file.On.Request.Path,
			Inputs: file.On.Request.Inputs,
		}
		strictJSON, err := flowStrictJSONFlag(file.On.Request.StrictJSON)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		trigger.StrictJSON = strictJSON
		if trigger.Method == "" {
			trigger.Method = "POST"
		}
		// Verify may be a plain string (legacy named provider / custom
		// header) OR a map (rich recipe shape). yaml.v3 hands us back
		// the runtime type as-is in the `any` field - discriminate here.
		switch raw := file.On.Request.Verify.(type) {
		case string:
			verify = raw
		case map[string]any:
			verifyConfig = parseVerifyMap(raw)
		case nil:
			// no verify configured
		default:
			return nil, fmt.Errorf("%s: verify must be a string or map", path)
		}
		secret = file.On.Request.Secret
		transaction = file.On.Request.Transaction
		auth = normalizeFlowAuth(file.On.Request.Auth, path)
		role = file.On.Request.Role
		permissions = file.On.Request.Permissions
		async = strings.EqualFold(strings.TrimSpace(file.On.Request.Mode), "async")
		rateLimit = parseRateLimit(file.On.Request.RateLimit)
		if verifyConfig != nil {
			if err := validateFlowVerifyConfig(verifyConfig, trigger.Path); err != nil {
				return nil, fmt.Errorf("%s: invalid verify config: %w", path, err)
			}
		}
	case file.On.Schedule != nil:
		trigger = FlowTrigger{Type: "cron", Cron: file.On.Schedule.Cron}
	case file.On.Event != nil:
		op := strings.ToLower(file.On.Event.Op)
		if op != "insert" && op != "update" && op != "delete" {
			op = "insert"
		}
		trigger = FlowTrigger{Type: "on_" + op, Table: file.On.Event.Table}
	}

	// v2.7.24+: when a file holds a single job (the common case for
	// per-file flows under flows/*.yaml), use the FILE basename as the
	// Flow.Name. The job key is an arbitrary inner label ("publish",
	// "build", "handle"); the file name ("publish_post", "generate_report")
	// is what the agent actually wrote and what the typed bm.flows.<name>
	// surface should match. When a file declares multiple jobs, fall
	// back to the job key - agents who reach for that shape already
	// know what they're doing.
	fileStem := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	useFileName := len(file.Jobs) == 1 && fileStem != "flows" // root flows.yaml stays per-job

	var out []Flow
	for name, job := range file.Jobs {
		flowName := name
		if useFileName {
			flowName = fileStem
		}
		flow := Flow{
			Name:         flowName,
			Trigger:      trigger,
			Verify:       verify,
			Secret:       secret,
			VerifyConfig: verifyConfig,
			Transaction:  transaction,
			Auth:         auth,
			Role:         role,
			Permissions:  permissions,
			Async:        async,
			Idempotent:   file.Idempotent,
			RateLimit:    rateLimit,
			Steps:        convertGHASteps(job.Steps),
		}
		if flowRequestSignedIn(file.On.Request) {
			dropSharedCacheControl(flow.Steps)
		}
		out = append(out, flow)
	}
	return out, nil
}

// normalizeFlowAuth maps a flow's `auth:` onto the two values the HTTP gate
// knows: "required" or open ("" / "none"). The gate (executeFlowHTTP) checked
// only the exact string "required", so `auth: true`, `auth: yes`,
// `auth: Required` or a typo registered a PUBLIC flow that bound the caller's
// session only when one happened to be present. Anything that isn't an
// explicit opt-out now requires sign-in, the same rule pages follow
// (normalizePageAuth).
func normalizeFlowAuth(auth, where string) string {
	norm, known := canonicalAuthValue(auth)
	if !known {
		log.Printf("WARNING flow %s: unknown auth=%q; treating it as auth: required", where, auth)
	}
	return norm
}

// flowVerifyKeys is the set of `verify:` map keys parseVerifyMap reads
// (TestFlowVerifyKeysMatchParser keeps the two together). The write gate
// refuses any other key (flowUnknownKeyViolation).
var flowVerifyKeys = map[string]bool{
	"recipe": true, "header": true, "timestamp_header": true, "secret": true, "previous_secret": true,
	"prefix": true, "path_param": true, "context": true, "skew_seconds": true,
}

// parseVerifyMap converts the YAML map shape of `verify:` into a
// FlowVerify. Unknown keys are ignored here so a deployed file keeps
// loading; the write gate and `benmore check` refuse them. Required
// fields and recipe-specific invariants are validated by both the loader and
// write-time validator through validateFlowVerifyConfig.
func parseVerifyMap(raw map[string]any) *FlowVerify {
	v := &FlowVerify{}
	if s, ok := raw["recipe"].(string); ok {
		v.Recipe = s
	}
	if s, ok := raw["header"].(string); ok {
		v.Header = s
	}
	if s, ok := raw["timestamp_header"].(string); ok {
		v.TimestampHeader = s
	}
	if s, ok := raw["secret"].(string); ok {
		// The docs show `secret: "${{ env.X }}"` (GHA refs) but
		// InterpolateEnv only honors the bare `{{env.X}}` form. Run
		// the same normalization the sign: path uses so both shapes
		// work - agents shouldn't have to learn which fields go
		// through which interpolator. The actual env lookup still
		// happens at request time so secret rotation stays live.
		v.Secret = normVerifyEnv(s)
	}
	if previous, ok := raw["previous_secret"]; ok {
		v.previousSet = true
		if s, ok := previous.(string); ok {
			v.PreviousSecret = normVerifyEnv(s)
		}
	}
	if s, ok := raw["prefix"].(string); ok {
		v.Prefix = s
	}
	if s, ok := raw["path_param"].(string); ok {
		v.PathParam = s
	}
	if s, ok := raw["context"].(string); ok {
		v.Context = s
	}
	switch n := raw["skew_seconds"].(type) {
	case int:
		v.SkewSeconds = n
	case int64:
		v.SkewSeconds = int(n)
	case float64:
		v.SkewSeconds = int(n)
	}
	return v
}

// normVerifyEnv accepts both documented env spellings:
// `${{ env.NAME }}` and `{{ env.NAME }}`. InterpolateEnv consumes the compact
// `{{env.NAME}}` representation, so canonicalize only a whole env reference;
// literal secrets on legacy recipes remain byte-for-byte untouched.
func normVerifyEnv(s string) string {
	s = normalizeGHARefs(s)
	trimmed := strings.TrimSpace(s)
	if strings.HasPrefix(trimmed, "{{") && strings.HasSuffix(trimmed, "}}") {
		inner := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(trimmed, "{{"), "}}"))
		if strings.HasPrefix(inner, "env.") {
			return "{{" + inner + "}}"
		}
	}
	return s
}

// convertGHASteps walks the GHA step list and emits FlowSteps the
// existing runtime understands. All `${{ ... }}` references in string
// fields are normalized to the runtime's `{{ ... }}` shape.
// flowRunTypes is the SINGLE SOURCE OF TRUTH for valid `run:` step types.
// Both the parser (the convertGHASteps switch below) and the write-time
// validator (validateGHAFlowsContents, validators_write.go) consult this map,
// so a step type can never again run successfully but fail validation - the
// drift that hid `compute` (v2.7.67) from the validator. When you add a
// `case` to the switch below, add the type here too (TestFlowRunTypesMatch
// guards the pairing).
var flowRunTypes = map[string]bool{
	"sql": true, "sql_dynamic": true, "api": true, "email": true, "sms": true,
	"webhook": true, "enqueue": true, "redirect": true, "respond": true, "parse": true, "set": true,
	"parallel": true, "compute": true, "if": true, "for_each": true,
	"serve_file": true, "delete_upload": true, "purge_current_user": true, "transcribe": true,
	"inspect_private_upload": true, "render_pdf_signatures": true,
	"revoke_user_sessions": true,
	"broadcast":            true,
}

// ghaStepRunType is the step type a GHA step resolves to. Shorthand shapes:
//   - `query: ...`            → sql
//   - `if: ...` (no `run:`)   → conditional branch wrapper
//   - `for_each: ...` (no `run:`) → iteration wrapper
//
// Shared by the parser and the write gate so both read a step the same way.
func ghaStepRunType(s FlowStepGHA) string {
	runType := strings.ToLower(strings.TrimSpace(s.Run))
	if runType == "" && s.Query != "" {
		runType = "sql"
	}
	if runType == "" && s.ForEach != "" {
		runType = "for_each"
	}
	if runType == "" && s.If != "" {
		runType = "if"
	}
	return runType
}

// flowRunTypeCountsRows reports the step types that have a row count for
// `expect_rows` to compare.
func flowRunTypeCountsRows(runType string) bool {
	return runType == "sql" || runType == "sql_dynamic"
}

// ghaWithExpectRows reads `with.expect_rows` the way the step-root key
// decodes into its string field: a string as written, a bare YAML integer
// (`expect_rows: 1`) as its decimal text. present is false when the key is
// absent. Any other YAML value (a float, a boolean, a list) renders to text
// evalExpectRows refuses, so it is rejected like the same value at the step
// root; a present key with no value (`expect_rows:`, or an unquoted `!=0`,
// which YAML reads as a tag on an empty scalar) is "" and present.
func ghaWithExpectRows(with map[string]any) (expr string, present bool) {
	v, present := with["expect_rows"]
	switch t := v.(type) {
	case nil:
		return "", present
	case string:
		return strings.TrimSpace(t), true
	case int:
		return strconv.Itoa(t), true
	case int64:
		return strconv.FormatInt(t, 10), true
	case uint64:
		return strconv.FormatUint(t, 10), true
	case float64:
		// Keeps its decimal point (`1.0`), which the step root refuses too.
		return strconv.FormatFloat(t, 'f', 1, 64), true
	}
	return strings.TrimSpace(fmt.Sprint(v)), true
}

// ghaStepExpectRows resolves a SQL step's `expect_rows` from its two
// positions: the step root (canonical) and `with:`, where authors also write
// it next to `params`. conflict is set, and no value returned, when both are
// written with different values: the runtime then refuses to run the step
// rather than pick one of two contradictory guards.
func ghaStepExpectRows(s FlowStepGHA) (expr, conflict string) {
	root := strings.TrimSpace(s.ExpectRows)
	under, _ := ghaWithExpectRows(s.With)
	switch {
	case root == "":
		return under, ""
	case under == "" || under == root:
		return root, ""
	}
	return "", fmt.Sprintf("expect_rows is declared twice with different values (%q at the step root, %q under with:)", root, under)
}

func convertGHASteps(steps []FlowStepGHA) []FlowStep {
	var out []FlowStep
	for _, s := range steps {
		fs := FlowStep{Name: s.ID}

		// Determine the step type (shorthand shapes: ghaStepRunType).
		runType := ghaStepRunType(s)

		switch runType {
		case "sql":
			fs.Type = "sql"
			fs.SQL = normalizeGHARefs(ghaStepSQLText(s))
			// `with.params: { name: <expr> }` binds named values to
			// `:name` placeholders in the query. Each value is stored
			// raw (with GHA refs normalized) and evaluated at run time
			// by execStepSQL so it sees current ctx.Data + env. Accept
			// the field both inside `with:` AND at step root (sibling
			// to `query:` shorthand) so agents using either form can
			// bind cross-step values. Pre-v2.5.9 only the with: form
			// worked, which forced agents using `query:` shorthand to
			// rewrite into the full form just to bind a step output.
			if p, ok := s.With["params"].(map[string]any); ok && len(p) > 0 {
				fs.SQLParams = stringMap(p)
			} else if p, ok := s.RawParams.(map[string]any); ok && len(p) > 0 {
				fs.SQLParams = stringMap(p)
			}
		case "sql_dynamic":
			// `run: sql_dynamic` is the opt-in escape hatch for queries
			// where `${{ ... }}` must be substituted as raw SQL TEXT
			// rather than bound as parameters. The motivating case is
			// an AI agent that generates SQL at runtime - the runtime
			// can't param-bind a query string into itself, only values
			// into placeholders. This step type pays for that
			// flexibility with explicit injection risk: `with.query:`
			// is rendered verbatim before execution.
			//
			// Only use this for queries assembled by trusted internal
			// callers (your own AI agent flow, your own admin tooling).
			// NEVER point it at user input.
			// It binds nothing, so `params` is not read here (the write gate
			// refuses it: flowStepKeyProblems).
			fs.Type = "sql_dynamic"
			fs.SQL = normalizeGHARefs(ghaStepSQLText(s))
		case "api":
			fs.Type = "api"
			fs.API = withToAPI(s.With)
			s.preserveSignComputeOrder(fs.API)
			// `with.timeout:` caps the outbound HTTP call (execStepAPI
			// defaults to 30s). Step-level `timeout:` (sibling of `run:`)
			// is mapped after the switch and takes precedence.
			if d := withDuration(s.With, "timeout"); d > 0 {
				fs.Timeout = d
			}
		case "enqueue":
			fs.Type = "enqueue"
			fs.Enqueue = &FlowEnqueue{With: map[string]string{}}
			invalid := false
			for key, target := range map[string]*string{"flow": &fs.Enqueue.Flow, "run_at": &fs.Enqueue.RunAt, "unique_key": &fs.Enqueue.UniqueKey} {
				if raw, present := s.With[key]; present {
					value, ok := raw.(string)
					if !ok {
						invalid = true
					} else {
						*target = normalizeGHARefs(value)
					}
				}
			}
			if payload, ok := s.With["with"].(map[string]any); ok {
				for key, value := range payload {
					text, ok := value.(string)
					if !ok {
						invalid = true
						break
					} // invalid loaded payload fails instead of silently dropping a field
					fs.Enqueue.With[key] = normalizeGHARefs(text)
				}
			} else if _, present := s.With["with"]; present {
				invalid = true
			}
			if invalid {
				fs.Enqueue.Flow = ""
			}
		case "email":
			fs.Type = "email"
			fs.Email = withToEmail(s.With)
		case "sms":
			fs.Type = "sms"
			fs.SMS = withToSMS(s.With)
		case "webhook":
			fs.Type = "webhook"
			if u, ok := s.With["url"].(string); ok {
				fs.Webhook = normalizeGHARefs(u)
			}
			if b, ok := s.With["body"].(string); ok {
				fs.WebhookBody = normalizeGHARefs(b)
			}
			fs.WebhookJSON = webhookJSONBody(s.With)
		case "redirect":
			fs.Type = "redirect"
			if t, ok := s.With["to"].(string); ok {
				fs.Redirect = normalizeGHARefs(t)
			}
			fs.RedirectAllowHosts = flowRedirectAllowHosts(s.With["allow_hosts"])
		case "respond":
			fs.Type = "respond"
			fs.Respond = withToRespond(s.With)
		case "serve_file":
			fs.Type = "serve_file"
			fs.ServeFile = &FlowServeFile{}
			if p, ok := s.With["path"].(string); ok {
				fs.ServeFile.Path = normalizeGHARefs(p)
			}
			if d, ok := s.With["disposition"].(string); ok {
				fs.ServeFile.Disposition = normalizeGHARefs(d)
			}
			if n, ok := s.With["filename"].(string); ok {
				fs.ServeFile.Filename = normalizeGHARefs(n)
			}
		case "delete_upload":
			fs.Type = "delete_upload"
			if p, ok := s.With["path"].(string); ok {
				fs.DeleteUpload = normalizeGHARefs(p)
			}
		case "inspect_private_upload":
			fs.Type = "inspect_private_upload"
			fs.InspectPrivateUpload = &FlowInspectPrivateUpload{}
			if p, ok := s.With["source_path"].(string); ok {
				fs.InspectPrivateUpload.SourcePath = normalizeGHARefs(p)
			}
			if k, ok := s.With["kind"].(string); ok {
				fs.InspectPrivateUpload.Kind = strings.ToLower(strings.TrimSpace(k))
			}
		case "render_pdf_signatures":
			fs.Type = "render_pdf_signatures"
			fs.RenderPDFSignatures = &FlowRenderPDFSignatures{}
			if p, ok := s.With["source_path"].(string); ok {
				fs.RenderPDFSignatures.SourcePath = normalizeGHARefs(p)
			}
			if h, ok := s.With["source_sha256"].(string); ok {
				fs.RenderPDFSignatures.SourceSHA256 = normalizeGHARefs(h)
			}
			if p, ok := s.With["placements_json"].(string); ok {
				fs.RenderPDFSignatures.PlacementsJSON = normalizeGHARefs(p)
			}
		case "purge_current_user":
			fs.Type = "purge_current_user"
			if confirm, ok := s.With["confirm"].(string); ok {
				fs.PurgeCurrentUserConfirm = normalizeGHARefs(confirm)
			}
		case "revoke_user_sessions":
			// Command-only (app_mcp_command_revoke.go); an ordinary flow
			// is refused by the write gate and by executeStep.
			fs.Type = "revoke_user_sessions"
			if id, ok := s.With["user_id"].(string); ok {
				fs.RevokeUserID = normalizeGHARefs(id)
			}
		case "transcribe":
			// `run: transcribe` - local audio→text via host ffmpeg +
			// whisper-cli (transcribe.go). `file:` is app-relative
			// (uploads/…) or a public https:// URL; model/language
			// optional. Values keep their `${{ }}` refs (normalized)
			// so the executor interpolates them per-request.
			fs.Type = "transcribe"
			fs.Transcribe = &FlowTranscribe{}
			if f, ok := s.With["file"].(string); ok {
				fs.Transcribe.File = normalizeGHARefs(f)
			}
			if m, ok := s.With["model"].(string); ok {
				fs.Transcribe.Model = normalizeGHARefs(m)
			}
			if l, ok := s.With["language"].(string); ok {
				fs.Transcribe.Language = normalizeGHARefs(l)
			}
			// `with.timeout:` caps the transcription like an api call's; a
			// step-level `timeout:` (mapped after the switch) wins. Only the
			// step-level key was read here before.
			if d := withDuration(s.With, "timeout"); d > 0 {
				fs.Timeout = d
			}
		case "broadcast":
			// `run: broadcast` - server message to a WebSocket room's
			// members (execStepBroadcast). The payload keeps its YAML shape
			// and resolves like a respond body; validated by
			// ghaBroadcastViolation (validators_write.go).
			fs.Type = "broadcast"
			fs.Broadcast = &FlowBroadcast{}
			if r, ok := s.With["room"].(string); ok {
				fs.Broadcast.Room = normalizeGHARefs(r)
			}
			if p, ok := s.With["payload"]; ok {
				fs.Broadcast.Payload = normalizeRefsInTree(p)
				fs.Broadcast.HasPayload = true
			}
		case "parse":
			fs.Type = "parse"
			if src, ok := s.With["source"].(string); ok {
				fs.Parse = src
			} else {
				fs.Parse = "body"
			}
		case "set":
			fs.Type = "set"
			fs.Set = stringMap(s.With)
		case "compute":
			// `run: compute` step (v2.7.67+) - invoke a server-side
			// TS/JS function from static/. Schema:
			//   - id: <name>
			//     run: compute
			//     module: <module-name-without-extension>
			//     function: <named-export>
			//     args: ${{ steps.X.outputs }}
			//     timeout: 10s   # optional, default 5s
			fs.Type = "compute"
			fs.Compute = &FlowCompute{}
			if mod, ok := s.With["module"].(string); ok {
				fs.Compute.Module = mod
			}
			if fn, ok := s.With["function"].(string); ok {
				fs.Compute.Function = fn
			}
			// `args` is preserved as a STRING (the raw expression) so
			// the runtime can re-interpolate it against the per-step
			// context. If the agent passes a map directly we JSON-
			// encode it; the runtime parses back to native at call time.
			// Preserve the native YAML shape (string ref OR a map/slice of
			// refs). The runtime (resolveComputeArgsValue) resolves each leaf
			// `${{ ... }}` to its NATIVE context value, so an args map of
			// per-field refs assembles a real object for goja - no need to
			// stringify-then-reparse (which mangled nested objects).
			if argsRaw, ok := s.With["args"]; ok {
				fs.Compute.Args = argsRaw
			}
			if d := withDuration(s.With, "timeout"); d > 0 {
				fs.Compute.Timeout = d
			}
		case "if":
			// A block: `if:` with `steps:` and no `run:`, or the same written
			// with `run: if`. An `if:` next to any other `run:` (or `query:`)
			// is that step, gated after the switch. `run: if` used to be
			// converted as its own inline step, which never returned: the
			// loader overflowed its stack.
			fs.Type = "if"
			fs.Condition = ghaIfToFlowCondition(s.If)
			fs.Steps = convertGHASteps(s.Steps)
			fs.ElseSteps = convertGHASteps(s.Else)
		case "parallel":
			// `run: parallel` + `steps: [...]` runs the inner steps
			// concurrently and waits for all to finish before
			// continuing. Each child step's output still lands at
			// ctx.Data[step.Name] like a sequential step; mutex inside
			// execStepParallel keeps writes from racing.
			fs.Type = "parallel"
			fs.Steps = convertGHASteps(s.Steps)
		case "for_each":
			fs.Type = "for_each"
			fs.ForEach = normalizeGHARefs(s.ForEach)
			// Strip the `{{ }}` braces the normalizer added - the
			// runtime's for_each expects a bare key (e.g. "rows" not
			// "{{rows}}").
			if strings.HasPrefix(fs.ForEach, "{{") && strings.HasSuffix(fs.ForEach, "}}") {
				fs.ForEach = strings.TrimSpace(fs.ForEach[2 : len(fs.ForEach)-2])
			}
			fs.ForAs = s.As
			if fs.ForAs == "" {
				fs.ForAs = "item"
			}
			fs.Steps = convertGHASteps(s.Steps)
		default:
			// Unknown run type. Emit a synthetic respond step that
			// returns 500 with the diagnostic, so the route fails
			// loudly instead of silently no-op'ing. The most common
			// cause is the GHA envelope (`on:` + `jobs:`) wrapped
			// around legacy step shorthand (`- sql: ...` / `- respond:
			// { json: ... }`). yaml.v3 silently drops keys that don't
			// exist on FlowStepGHA, so steps reach here with everything
			// blank.
			log.Printf("flows: step has no recognized action (run=%q query=%q if=%q for_each=%q) - flow registered but won't execute. Likely cause: GHA envelope mixed with legacy step shorthand. Check the step shape (run/query/if/for_each).",
				s.Run, s.Query, s.If, s.ForEach)
			fs.Type = "respond"
			fs.Respond = &FlowRespond{
				Status: 500,
				Body:   `{"error":"flow has unrecognized step - likely a GHA envelope mixed with legacy step shorthand. Each step needs one of: run / query / if / for_each."}`,
			}
			out = append(out, fs)
			continue
		}

		// Per-step modifiers must be mapped BEFORE the `if:` gate wrap
		// below - pre-v2.7.212 the wrap `continue`d past this block, so
		// retry/timeout/expect_rows/on_error were silently dropped from
		// any gated step.
		fs.Retry = s.Retry
		fs.ExpectRows = strings.TrimSpace(s.ExpectRows)
		// A SQL step also takes the assertion from `with.expect_rows`.
		// Before, only the step-root key was read, so a guard written next
		// to `params` under `with:` was accepted and never checked.
		if flowRunTypeCountsRows(fs.Type) {
			fs.ExpectRows, fs.ExpectRowsConflict = ghaStepExpectRows(s)
		}
		if s.RetryDelay != "" {
			fs.RetryDelay, _ = time.ParseDuration(s.RetryDelay)
		}
		if d := parseFlexDuration(s.Timeout); d > 0 {
			fs.Timeout = d
		}
		if len(s.OnError) > 0 {
			fs.OnError = convertGHASteps(s.OnError)
		}

		// `if:` may also appear on non-conditional steps as a per-step
		// gate. If we already classified the step as something other
		// than "if" but it has an If expression, wrap it.
		// The gate's `else:` is its other branch. It used to be read only on
		// an `if:` block, so `if:` + `run:` + `else:` skipped the else steps.
		if fs.Type != "if" && s.If != "" {
			out = append(out, FlowStep{
				Type:      "if",
				Condition: ghaIfToFlowCondition(s.If),
				Steps:     []FlowStep{fs},
				ElseSteps: convertGHASteps(s.Else),
			})
			continue
		}

		out = append(out, fs)
	}
	return out
}

// withDuration reads a duration off a `with:` block. Accepts Go
// duration strings ("570s", "10m"), bare numeric strings ("570"), and
// YAML numbers (570) - bare numbers are seconds, since that's what
// agents reach for first (evidence: issue #221 tried `timeout: 570`).
func withDuration(with map[string]any, key string) time.Duration {
	switch v := with[key].(type) {
	case string:
		return parseFlexDuration(v)
	case int:
		return time.Duration(v) * time.Second
	case float64:
		return time.Duration(v * float64(time.Second))
	}
	return 0
}

// parseFlexDuration parses "570s" / "10m" via time.ParseDuration, and
// falls back to treating a bare number ("570") as seconds.
func parseFlexDuration(v string) time.Duration {
	v = strings.TrimSpace(v)
	if v == "" {
		return 0
	}
	if d, err := time.ParseDuration(v); err == nil {
		return d
	}
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return time.Duration(n) * time.Second
	}
	return 0
}

// withToAPI maps a `with:` block onto FlowAPICall fields, applying
// GHA-ref normalization to every string value.
func withToAPI(with map[string]any) *FlowAPICall {
	api := &FlowAPICall{}
	if v, ok := with["method"].(string); ok {
		api.Method = strings.ToUpper(v)
	}
	if v, ok := with["url"].(string); ok {
		api.URL = normalizeGHARefs(v)
	}
	if v, ok := with["auth"].(string); ok {
		api.Auth = normalizeGHARefs(v)
	}
	if v, ok := with["body"].(string); ok {
		api.Body = normalizeGHARefs(v)
	}
	if hdrs, ok := with["headers"].(map[string]any); ok {
		api.Headers = stringMap(hdrs)
	}
	if q, ok := with["query"].(map[string]any); ok {
		api.Query = stringMap(q)
	}
	// Keep nested arrays/objects (normalizing ${{ }} refs on string leaves)
	// instead of flattening to map[string]string - mirrors withToRespond's
	// body handling. See benmore-go #94. A list is a JSON array body (it
	// used to be dropped).
	api.JSON, api.JSONArray = jsonBodyTree(with["json"])
	if f, ok := with["form"].(map[string]any); ok {
		api.Form = stringMap(f)
	}
	// `body:` written as a map or list is a JSON body too; it used to send
	// no body at all. Next to `json:` or `form:` the write gate refuses it
	// and a deployed file keeps sending the json or form body.
	if _, form := with["form"]; api.JSON == nil && api.JSONArray == nil && !form {
		api.JSON, api.JSONArray = jsonBodyTree(with["body"])
	}
	// `sign:` sub-block - the outbound-auth recipe. Pre-v2.5.8 the GHA
	// loader silently dropped this entire key; only the legacy text
	// parser handled `sign:`. Every agent writing a GHA-shaped flow
	// with a `sign:` recipe was shipping unauthenticated requests and
	// getting 401s with no diagnostic trail.
	if signRaw, ok := with["sign"].(map[string]any); ok {
		api.Sign = withToSign(signRaw)
	}
	if statuses, err := parseHandledStatuses(with["handled_statuses"]); err == nil {
		api.HandledStatuses = statuses
	}
	if pagRaw, ok := with["paginate"].(map[string]any); ok {
		api.Paginate = withToPaginate(pagRaw)
	}
	if v, ok := with["success_when"].(string); ok {
		api.SuccessWhen = normalizeGHARefs(v)
	}
	return api
}

// parseHandledStatuses accepts only explicit integer HTTP 4xx codes. The
// shared GHA validator calls this before either loading or accepting a flow;
// withToAPI therefore only copies the already-validated values.
func parseHandledStatuses(raw any) ([]int, error) {
	var values []any
	switch v := raw.(type) {
	case []any:
		values = v
	case []int:
		values = make([]any, len(v))
		for i, status := range v {
			values[i] = status
		}
	default:
		return nil, fmt.Errorf("must be a non-empty list of integer 4xx status codes")
	}
	if len(values) == 0 {
		return nil, fmt.Errorf("must be a non-empty list of integer 4xx status codes")
	}
	statuses := make([]int, 0, len(values))
	seen := make(map[int]bool, len(values))
	for _, value := range values {
		var status int
		switch n := value.(type) {
		case int:
			status = n
		case int64:
			if n < 400 || n > 499 {
				return nil, fmt.Errorf("status codes must be between 400 and 499")
			}
			status = int(n)
		case uint64:
			if n < 400 || n > 499 {
				return nil, fmt.Errorf("status codes must be between 400 and 499")
			}
			status = int(n)
		default:
			return nil, fmt.Errorf("status codes must be integers")
		}
		if status < 400 || status > 499 {
			return nil, fmt.Errorf("status codes must be between 400 and 499")
		}
		if seen[status] {
			return nil, fmt.Errorf("status code %d is duplicated", status)
		}
		seen[status] = true
		statuses = append(statuses, status)
	}
	return statuses, nil
}

// withToPaginate maps `with.paginate:` to FlowAPIPaginate. Defaults
// fill in the common shapes: cursor strategy with `?cursor=` param
// and `$.next_cursor` extraction.
func withToPaginate(raw map[string]any) *FlowAPIPaginate {
	p := &FlowAPIPaginate{}
	if v, ok := raw["strategy"].(string); ok {
		p.Strategy = strings.ToLower(strings.TrimSpace(v))
	}
	if v, ok := raw["cursor_param"].(string); ok {
		p.CursorParam = v
	}
	if v, ok := raw["cursor_field"].(string); ok {
		p.CursorField = v
	}
	if v, ok := raw["page_param"].(string); ok {
		p.PageParam = v
	}
	if v, ok := raw["page_start"].(int); ok {
		p.PageStart = v
	}
	if v, ok := raw["items_field"].(string); ok {
		p.ItemsField = v
	}
	if v, ok := raw["max_pages"].(int); ok {
		p.MaxPages = v
	}
	return p
}

// withToSign translates a `with.sign:` map into a FlowAPISign. The
// strategy: GHA-normalize every string value in the tree (so `${{ env.X }}`
// becomes `{{env.X}}` that the runtime + signer engine understand),
// re-marshal back to YAML text, then delegate to parseSignBlock - the
// same function the legacy text parser uses.
//
// FlowStepGHA retains and restores the source compute binding order after
// this map-based compatibility conversion. Named recipes keep their own
// original source order, as before.
func withToSign(signRaw map[string]any) *FlowAPISign {
	normalized := normalizeRefsInTree(signRaw)
	yamlBytes, err := yaml.Marshal(normalized)
	if err != nil {
		// Surfaced via _parse_error so applySigner refuses to send
		// rather than shipping an unauthenticated request.
		return &FlowAPISign{Bindings: map[string]string{"_parse_error": "withToSign yaml.Marshal: " + err.Error()}}
	}
	sign, err := parseSignBlock(string(yamlBytes))
	if err != nil {
		return &FlowAPISign{Bindings: map[string]string{"_parse_error": err.Error()}}
	}
	return sign
}

// normalizeRefsInTree walks an arbitrary YAML-parsed tree (map / slice /
// scalar) and replaces every string leaf's GHA refs (`${{ … }}`) with
// the runtime's mustache form (`{{…}}`). Used to bridge the gap
// between agents writing GHA-style refs everywhere and runtime
// components (sign engine, respond's JSON body interpolator, etc.)
// that only know how to read mustache.
func normalizeRefsInTree(v any) any {
	switch t := v.(type) {
	case string:
		return normalizeGHARefs(t)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, child := range t {
			out[k] = normalizeRefsInTree(child)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, child := range t {
			out[i] = normalizeRefsInTree(child)
		}
		return out
	default:
		return v
	}
}

// jsonBodyTree splits a `with:` value written as a JSON body: a map or a
// list, string leaves GHA-ref normalized. Anything else is neither.
func jsonBodyTree(v any) (object map[string]any, array []any) {
	switch t := v.(type) {
	case map[string]any:
		object, _ = normalizeRefsInTree(t).(map[string]any)
	case []any:
		array, _ = normalizeRefsInTree(t).([]any)
	}
	return object, array
}

// webhookJSONBody is a `run: webhook` step's JSON body: `with.payload`, or a
// `with.body` written as a map or list. A text `body:` wins over a payload
// (it is what the step sent before payload was read; the write gate refuses
// both together), and a payload that is not a map or list is not a body.
func webhookJSONBody(with map[string]any) any {
	if _, text := with["body"].(string); text {
		return nil
	}
	for _, key := range []string{"body", "payload"} {
		object, array := jsonBodyTree(with[key])
		switch {
		case object != nil:
			return object
		case array != nil:
			return array
		}
	}
	return nil
}

func withToEmail(with map[string]any) *FlowEmail {
	e := &FlowEmail{}
	for key, dst := range map[string]*string{"cc": &e.CC, "bcc": &e.BCC, "unsubscribe_one_click": &e.UnsubscribeOneClick} {
		if v, ok := with[key]; ok {
			*dst = normalizeGHARefs(fmt.Sprint(v))
		}
	}
	if v, ok := with["to"].(string); ok {
		e.To = normalizeGHARefs(v)
	}
	if v, ok := with["subject"].(string); ok {
		e.Subject = normalizeGHARefs(v)
	}
	if v, ok := with["template"].(string); ok {
		e.Template = v
	}
	// Per-send sender ("send as"). The from-domain is enforced downstream
	// (platform broker, or SendEmailOpts off-platform) - an unverified
	// domain is an error, never a quiet fallback to EMAIL_FROM.
	if v, ok := with["from"].(string); ok {
		e.From = normalizeGHARefs(v)
	}
	if v, ok := with["reply_to"].(string); ok {
		e.ReplyTo = normalizeGHARefs(v)
	}
	// List-Unsubscribe target, rendered at send time (flowEmailUnsubscribeURL).
	// It used to be accepted and never read.
	if v, ok := with["unsubscribe_url"].(string); ok {
		e.UnsubscribeURL = strings.TrimSpace(normalizeGHARefs(v))
	}
	// Inline bodies. `body:` is an alias for `html:` (agents reach for
	// both); `text:` is the plain-text part. Pre-v2.7.165 these keys were
	// silently dropped here, so even an explicit inline html: never
	// reached the provider request.
	if v, ok := with["html"].(string); ok {
		e.Html = normalizeGHARefs(v)
	}
	if e.Html == "" {
		if v, ok := with["body"].(string); ok {
			e.Html = normalizeGHARefs(v)
		}
	}
	if v, ok := with["text"].(string); ok {
		e.Text = normalizeGHARefs(v)
	}
	if d, ok := with["data"].(map[string]any); ok {
		e.Data = stringMap(d)
	}
	if e.Data == nil {
		// `vars:` alias - same shape, same meaning.
		if d, ok := with["vars"].(map[string]any); ok {
			e.Data = stringMap(d)
		}
	}
	for k, v := range e.Data {
		e.Data[k] = normalizeGHARefs(v)
	}
	// attachments: [{filename, content_type?, content}] — content is base64
	// (or a ${{ }} ref resolving to base64). Non-object entries are skipped.
	if raw, ok := with["attachments"].([]any); ok {
		for _, item := range raw {
			m, ok := item.(map[string]any)
			if !ok {
				continue
			}
			att := FlowAttachment{}
			if s, ok := m["filename"].(string); ok {
				att.Filename = normalizeGHARefs(s)
			}
			if s, ok := m["content_type"].(string); ok {
				att.ContentType = s
			}
			if s, ok := m["content"].(string); ok {
				att.Content = normalizeGHARefs(s)
			}
			if att.Content != "" {
				e.Attachments = append(e.Attachments, att)
			}
		}
	}
	return e
}

// withToSMS parses a `run: sms` step's `with:` block. `body:` is primary and
// `text:` is an alias - agents reach for both, and mirroring withToEmail's
// generosity here is cheaper than a support round-trip.
func withToSMS(with map[string]any) *FlowSMS {
	s := &FlowSMS{}
	if v, ok := with["to"].(string); ok {
		s.To = normalizeGHARefs(v)
	}
	if v, ok := with["body"].(string); ok {
		s.Body = normalizeGHARefs(v)
	}
	if s.Body == "" {
		if v, ok := with["text"].(string); ok {
			s.Body = normalizeGHARefs(v)
		}
	}
	return s
}

func withToRespond(with map[string]any) *FlowRespond {
	r := &FlowRespond{}
	// An integer 200-599, written as a number or quoted, is the status. Any
	// other value (a `${{ }}` template, text) is rendered when the step runs
	// and fails it unless it gives such an integer; it used to be dropped
	// and the response sent as 200.
	r.Status, r.StatusTemplate = respondStatusFromWith(with["status"])
	if r.Status == 0 && r.StatusTemplate == "" {
		r.Status = 200
	}
	// `body` accepts string-template (interpolated, may resolve to an
	// array or object), map (encoded as JSON object), or array
	// (encoded as JSON array). Map and array bodies need recursive
	// GHA-ref normalization on string leaves - pre-v2.5.8 they were
	// stored as-is, and execStepRespond's interpolateJSONValues only
	// understood mustache `{{…}}` so any `${{…}}` ref the agent typed
	// came back to the client as a literal string.
	if v, ok := with["body"].(string); ok {
		r.Body = normalizeGHARefs(v)
	} else if v, ok := with["body"].(map[string]any); ok {
		if normalized, ok := normalizeRefsInTree(v).(map[string]any); ok {
			r.JSON = normalized
		}
	} else if v, ok := with["body"].([]any); ok {
		if normalized, ok := normalizeRefsInTree(v).([]any); ok {
			r.JSONArray = normalized
		}
	} else if v, ok := with["json"].(map[string]any); ok {
		// `json: { ... }` - the legacy/cron path.
		if normalized, ok := normalizeRefsInTree(v).(map[string]any); ok {
			r.JSON = normalized
		}
	} else if v, ok := with["json"].(string); ok {
		// `json: "{{rows}}"` - agents reach for this shape constantly
		// (the storyforge debugging session was filled with it). Treat
		// it identically to a string body. execStepRespond's
		// bare-template path then resolves the template to whatever's
		// in ctx.Data - array, map, scalar - and JSON-encodes it.
		r.Body = normalizeGHARefs(v)
	} else if v, ok := with["json"].([]any); ok {
		if normalized, ok := normalizeRefsInTree(v).([]any); ok {
			r.JSONArray = normalized
		}
	}
	// Declared content type and response headers, through the allowlist
	// (flows_respond_headers.go). They used to be accepted and dropped.
	r.ContentType, r.Headers = respondHeadersFromWith(with)
	if (r.JSON != nil || r.JSONArray != nil) && r.ContentType != "" && !respondContentTypeIsJSON(r.ContentType) {
		// A map or list body is sent as JSON; a deployed file declaring
		// another type keeps answering application/json.
		r.ContentType = ""
	}
	return r
}

// stringMap coerces a generic YAML map to map[string]string, stringifying
// scalars and applying GHA-ref normalization to string values.
// yamlSerializeArgs converts a YAML-decoded value (map/slice/scalar)
// to a JSON string. Used by the `compute` step parser when the
// agent inlined a nested object literal as `args:` instead of an
// interpolation expression - we preserve the value verbatim by
// serialising to JSON, the runtime parses it back into the native
// shape before passing to JS.
func yamlSerializeArgs(v any) (string, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func stringMap(in map[string]any) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		switch s := v.(type) {
		case string:
			out[k] = normalizeGHARefs(s)
		default:
			out[k] = fmt.Sprintf("%v", v)
		}
	}
	return out
}

// ghaRefRe matches `${{ ... }}` (with whitespace tolerance).
var ghaRefRe = regexp.MustCompile(`\$\{\{\s*(.*?)\s*\}\}`)

// bracketIndexRe turns `[0]`, `[12]`, etc. into `.0`, `.12` so the
// runtime's dotted-path interpolation can resolve indexed access
// uniformly. e.g. `steps.x.outputs.rows[0].title` → `steps.x.outputs.rows.0.title`.
var bracketIndexRe = regexp.MustCompile(`\[(\d+)\]`)

// normalizeGHARefs translates `${{ expr }}` to the runtime's `{{...}}`
// form. The runtime's interpolator matches `{{key}}` with no inner
// whitespace (flows_interpolate.go interpolateCtx), so we emit that shape exactly
// - adding spaces here would silently break every substitution.
//
// `${{{ expr }}}` and `${{{{ expr }}}}` are the sanitized-HTML and raw forms
// an email step's inline `html:` understands (html_template.go); they keep
// their brace count.
func normalizeGHARefs(s string) string {
	if strings.Contains(s, "${{{") {
		for _, re := range []*regexp.Regexp{ghaRawRefRe, ghaSanitizedRefRe} {
			braces := strings.Count(re.String(), `\{`)
			s = re.ReplaceAllStringFunc(s, func(match string) string {
				return strings.Repeat("{", braces) + translateGHAExpr(re.FindStringSubmatch(match)[1]) + strings.Repeat("}", braces)
			})
		}
	}
	return ghaRefRe.ReplaceAllStringFunc(s, func(match string) string {
		m := ghaRefRe.FindStringSubmatch(match)
		expr := m[1]
		return "{{" + translateGHAExpr(expr) + "}}"
	})
}

var (
	ghaRawRefRe       = regexp.MustCompile(`\$\{\{\{\{\s*(.*?)\s*\}\}\}\}`)
	ghaSanitizedRefRe = regexp.MustCompile(`\$\{\{\{\s*(.*?)\s*\}\}\}`)
)

// ghaRefBase is the reference part of an expression, before any pipe.
func ghaRefBase(expr string) string {
	base, _, _ := strings.Cut(expr, "|")
	return strings.TrimSpace(base)
}

// ghaStripOutputsRows drops the `.outputs.rows` alias for "the result set",
// but only as a whole path segment. It used to be cut as a prefix, so
// `steps.x.outputs.rows_affected` (a write's count) became `x_affected` and
// never resolved, as did any column whose name starts with "rows".
func ghaStripOutputsRows(rest string) string {
	const alias = ".outputs.rows"
	i := strings.Index(rest, alias)
	if i < 0 {
		return rest
	}
	if end := i + len(alias); end < len(rest) {
		if c := rest[end]; c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') {
			return rest
		}
	}
	return rest[:i] + rest[i+len(alias):]
}

func translateGHAExpr(expr string) string {
	expr = strings.TrimSpace(expr)
	// Bracket-index notation [N] → .N so the runtime's dotted-path
	// interpolation can handle it uniformly. Done first so the rest
	// of this translation operates on dotted-only expressions.
	expr = bracketIndexRe.ReplaceAllString(expr, ".$1")
	switch {
	case strings.HasPrefix(expr, "steps."):
		// `outputs.rows` and `outputs.*` are both aliases for "the
		// slice this step produced." `outputs.0` is "the first row."
		// `outputs.field` is "field on the first row" (auto-coerced
		// for the single-row case so author-friendly templates like
		// `steps.user.outputs.email` work after a `WHERE id = :id`
		// query).
		rest := strings.TrimPrefix(expr, "steps.")
		// Both .outputs.rows and .outputs.* mean "the result set."
		rest = ghaStripOutputsRows(rest)
		rest = strings.Replace(rest, ".outputs.*", "", 1)
		// `.outputs.first[.<col>]` is documented sugar for row 0 (same as
		// `.outputs.rows[0]`). Map it to the `.0` index flattenData already
		// produces. Word-boundary-aware: `.outputs.first.x` → `.0.x` and a
		// trailing `.outputs.first` → `.0`, but `.outputs.firstname` (a real
		// column) is left for the generic `.outputs.` rule below. Pre-2.7.139
		// `.first` had NO handler → resolved to nothing on SELECT, silently
		// binding NULL / halting template_unresolved despite the docs.
		rest = strings.Replace(rest, ".outputs.first.", ".0.", 1)
		if strings.HasSuffix(rest, ".outputs.first") {
			rest = strings.TrimSuffix(rest, ".outputs.first") + ".0"
		}
		// Generic .outputs.<field> → .<field>
		rest = strings.Replace(rest, ".outputs.", ".", 1)
		// Trailing .outputs with nothing after means "the result set."
		rest = strings.TrimSuffix(rest, ".outputs")
		return rest
	case expr == "user.group_id" || expr == "user.org_id":
		return "user_group_id"
	case ghaRefBase(expr) == "user.group_id" || ghaRefBase(expr) == "user.org_id":
		// The same tenant ref with pipes or a fallback
		// (`user.org_id | default:''`) must not fall through to the
		// user row below.
		return "user_group_id " + expr[strings.Index(expr, "|"):]
	case strings.HasPrefix(expr, "user."):
		// Every `user.<field>` reference resolves through the same
		// path: the executor populates `ctx.Data["user"]` with the
		// full row from _benmore_users (auth.go LoadUserFields, gated
		// by `auth: required` on the route), and flattenData turns
		// that into `user.id`, `user.email`, `user.first_name`, etc.
		// in the lookup table. Pre-v2.7.5 we stripped the `user.`
		// prefix for non-id/email/role fields and looked up the bare
		// name (`first_name`) in the flat session map - but nothing
		// ever populated that key, so the rendered output silently
		// contained `{{first_name}}`. Keeping the `user.` prefix
		// uniformly so the same lookup machinery handles every field.
		return expr
	case strings.HasPrefix(expr, "params."):
		// Kept as `params.X` so a request field can be told apart from a
		// step output of the same name (flowLookup).
		return expr
	case strings.HasPrefix(expr, "env."):
		return expr // already in the runtime's syntax
	default:
		return expr
	}
}

// ghaIfToFlowCondition translates a GHA-style condition into the shape
// the legacy condition evaluator (hooks.go evaluateCondition) expects:
//
//	`<row-key> <op> <literal-or-template>`
//
// The evaluator treats the LEFT side as a key into the flow's row map
// and the RIGHT side as a literal string to compare against. So we
// can't wrap both sides in `{{ }}` - the left needs to be a raw ref
// like `note.user_id`, and the right gets interpolated to its literal
// value via `{{ ... }}` before evaluation.
//
// Operators recognized: `==`, `=`, `!=`, `>=`, `<=`, `>`, `<`. The
// legacy evaluator uses `=`/`!=`; we accept both `==` (GHA style) and
// `=` (SQL/agent-intuition style) and normalize to the legacy form.
//
// Right-hand-side wrapping: pre-v2.7.5 we wrapped EVERY rightVal in
// `{{...}}` so the runtime would interpolate it before the evaluator
// saw it. That worked for the case where right was itself a GHA
// reference (`${{ user.id }}`) - but broke for literal values
// (`if: ${{ X }} == 1` produced `X = {{1}}`, then `interpolateCtx`
// noted `1` as an unresolved ref under v2.7.5's loud-fail behavior,
// and the step halted with `template_unresolved`). Now we only wrap
// if right was originally a GHA expression. Bare literals (numbers,
// 'quoted strings', `true`/`false`) pass through unwrapped.
func ghaIfToFlowCondition(expr string) string {
	expr = strings.TrimSpace(expr)
	// Outer-wrapper strip: `${{ a == b }}` form.
	if strings.HasPrefix(expr, "${{") && strings.HasSuffix(expr, "}}") &&
		strings.Count(expr, "${{") == 1 {
		expr = strings.TrimSpace(expr[3 : len(expr)-2])
	}
	// `&&`, `||` between comparisons, `!` and parentheses: kept as written
	// for the expression grammar, which reads `${{ }}` spans and bare refs
	// itself (evaluateFlowCondition).
	if conditionUsesExpressionSyntax(expr) {
		return expr
	}
	// Order: longer ops first so `>=` doesn't match as `>` and `==`
	// doesn't match as `=`.
	for _, op := range []string{"!=", "==", ">=", "<=", "=", ">", "<"} {
		idx := strings.Index(expr, op)
		if idx < 0 {
			continue
		}
		left := strings.TrimSpace(expr[:idx])
		right := strings.TrimSpace(expr[idx+len(op):])
		// Each side might itself be a GHA-wrapped ref or a bare ref
		// or a literal. Normalize each one through unwrapGHA, then
		// translate via translateGHAExpr (which only handles bare
		// `steps.X.outputs.Y` / `user.Y` / `params.Y` / `env.Y`).
		leftWasRef, leftBare := unwrapGHA(left)
		rightWasRef, rightBare := unwrapGHA(right)
		// Inside one `${{ a == b }}` the outer wrapper is already gone, so
		// a ref on the right has no wrapper of its own: a namespaced ref
		// (steps./params./user./env.) is a ref wherever it sits. Read as
		// literal text, `${{ params.token == steps.t.outputs.token }}` held
		// for a request that sent the text "t.token".
		if !rightWasRef && ghaNamespacedRef(rightBare) {
			rightWasRef = true
		}
		// A literal on the left of a ref (`5 < params.n`, `'x' == user.role`)
		// would be read as a field named "5": compare the ref with the
		// literal, mirroring the operator.
		if !leftWasRef && ghaConditionLiteral(leftBare) && rightWasRef {
			leftBare, rightBare = rightBare, leftBare
			rightWasRef = false
			op = mirrorConditionOperator(op)
		}
		leftKey := translateGHAExpr(leftBare)
		rightVal := translateGHAExpr(rightBare)
		// Wrap rightVal in `{{...}}` ONLY if it was a GHA expression
		// (i.e. it'll need runtime interpolation against ctx.Data).
		// Literals pass through unwrapped so v2.7.5's loud-fail-on-
		// unresolved-template logic doesn't flag `{{1}}` / `{{true}}`
		// / `{{'won'}}` as a missing ref and halt the step.
		_ = leftWasRef // leftKey is always a bare key for the evaluator
		var rightForEvaluator string
		if rightWasRef {
			rightForEvaluator = "{{" + rightVal + "}}"
		} else {
			rightForEvaluator = rightVal
		}
		// Normalize == to legacy =.
		if op == "==" {
			op = "="
		}
		return fmt.Sprintf("%s %s %s", leftKey, op, rightForEvaluator)
	}
	// No comparison op - treat as a boolean truth check. Translate the
	// inline ref to a bare row-key reference (no braces), so the
	// evaluator's `row[lhs]` lookup hits the right key. Pre-v2.7.5 we
	// returned `normalizeGHARefs(expr)` which left `{{...}}` braces
	// around the lhs - the evaluator then looked up the literal
	// `{{key}}` string in the row map (always missing) and the truth
	// check evaluated false every time.
	_, bare := unwrapGHA(expr)
	return translateGHAExpr(bare)
}

// ghaNamespacedRef reports whether s (one side of a comparison, without a
// `${{ }}` wrapper) is a ref in one of the flow namespaces: steps., params.,
// user. or env., optionally piped. A bare word (`paid`) stays a literal.
func ghaNamespacedRef(s string) bool {
	base := ghaRefBase(s)
	switch {
	case strings.HasPrefix(base, "steps."), strings.HasPrefix(base, "params."),
		strings.HasPrefix(base, "user."), strings.HasPrefix(base, "env."):
	default:
		return false
	}
	for i := 0; i < len(base); i++ {
		c := base[i]
		if !(c == '_' || c == '-' || c == '.' || c == '[' || c == ']' ||
			(c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')) {
			return false
		}
	}
	return true
}

// ghaConditionLiteral reports whether s is a literal operand: quoted text, a
// number, true, false or null.
func ghaConditionLiteral(s string) bool {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && (s[0] == '\'' || s[0] == '"') && s[len(s)-1] == s[0] {
		return true
	}
	switch strings.ToLower(s) {
	case "true", "false", "null":
		return true
	}
	_, err := strconv.ParseFloat(s, 64)
	return err == nil
}

// mirrorConditionOperator is op with its operands swapped (a < b is b > a).
func mirrorConditionOperator(op string) string {
	switch op {
	case "<":
		return ">"
	case ">":
		return "<"
	case "<=":
		return ">="
	case ">=":
		return "<="
	}
	return op
}

// unwrapGHA strips a `${{ ... }}` wrapper from a single token if
// present and reports whether the token was wrapped. Used by
// ghaIfToFlowCondition to normalize each side of a comparison
// individually - translateGHAExpr only understands bare dotted refs
// (`steps.x.outputs.y`, `user.id`), not the wrapped form.
func unwrapGHA(s string) (wrapped bool, bare string) {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "${{") && strings.HasSuffix(s, "}}") {
		return true, strings.TrimSpace(s[3 : len(s)-2])
	}
	return false, s
}
