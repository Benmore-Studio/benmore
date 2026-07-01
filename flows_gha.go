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
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// FlowFileGHA is the top-level shape of the new flows.yaml.
type FlowFileGHA struct {
	On   FlowTriggerGHA        `yaml:"on"`
	Jobs map[string]FlowJobGHA `yaml:"jobs"`
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
	Method      string `yaml:"method"`
	Path        string `yaml:"path"`
	Auth        string `yaml:"auth"`
	Role        string `yaml:"role"`
	Transaction bool   `yaml:"transaction"`
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
	// signature, keyed by input name. PURELY DECLARATIVE: the runtime
	// already accepts path/query/body params regardless (executeFlowHTTP
	// merges them into ctx.Params/ctx.Data). Declaring them lets the
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
	// ExpectRows asserts on rows affected by a write step (e.g. ">0").
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
func LoadFlowsGHA(dir string) []Flow {
	var out []Flow

	// Root flows.yaml (the historical entry point).
	if flows := loadOneGHAFile(filepath.Join(dir, "flows.yaml")); flows != nil {
		out = append(out, flows...)
	}

	// Plus every flows/*.yaml beside it. Before v2.3.1 these files
	// were silently ignored - agents who wrote per-flow files under
	// flows/ saw routes return 404. Now we scan the directory.
	flowsDir := filepath.Join(dir, "flows")
	if entries, err := os.ReadDir(flowsDir); err == nil {
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".yaml") {
				continue
			}
			if flows := loadOneGHAFile(filepath.Join(flowsDir, e.Name())); flows != nil {
				out = append(out, flows...)
			}
		}
	}

	return out
}

// loadOneGHAFile parses a single GHA-shaped flow file. Returns nil if
// the file doesn't look GHA-shaped (caller will fall through to the
// legacy parser for the root flows.yaml).
func loadOneGHAFile(path string) []Flow {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	var file FlowFileGHA
	if err := yaml.Unmarshal(data, &file); err != nil {
		log.Printf("flows: parse %s: %s", path, err)
		return nil
	}
	// Reject anything that doesn't look GHA-shaped so the legacy
	// loader gets a turn - at least one of request/schedule/event,
	// AND a non-empty jobs map.
	if file.Jobs == nil {
		return nil
	}
	if file.On.Request == nil && file.On.Schedule == nil && file.On.Event == nil {
		return nil
	}

	// Build the FlowTrigger from whichever `on:` shape was set.
	var trigger FlowTrigger
	var verify, secret, auth, role string
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
			log.Printf("flows: `verify:` must be a string or a map, got %T - ignoring", raw)
		}
		secret = file.On.Request.Secret
		transaction = file.On.Request.Transaction
		auth = file.On.Request.Auth
		role = file.On.Request.Role
		async = strings.EqualFold(strings.TrimSpace(file.On.Request.Mode), "async")
		rateLimit = parseRateLimit(file.On.Request.RateLimit)
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
			Async:        async,
			RateLimit:    rateLimit,
			Steps:        convertGHASteps(job.Steps),
		}
		out = append(out, flow)
	}
	return out
}

// parseVerifyMap converts the YAML map shape of `verify:` into a
// FlowVerify. Unknown keys are ignored (forward compat for new built-in
// options). Missing required keys are NOT validated here - the runtime
// reports a precise error from runVerifyRecipe so the agent gets the
// failure message at request time with the actual values in scope.
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
		v.Secret = normalizeGHARefs(s)
	}
	if s, ok := raw["prefix"].(string); ok {
		v.Prefix = s
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
	"sql": true, "sql_dynamic": true, "api": true, "email": true, "webhook": true,
	"redirect": true, "respond": true, "parse": true, "set": true, "parallel": true,
	"compute": true, "if": true, "for_each": true, "serve_file": true,
}

func convertGHASteps(steps []FlowStepGHA) []FlowStep {
	var out []FlowStep
	for _, s := range steps {
		fs := FlowStep{Name: s.ID}

		// Determine the step type. Shorthand shapes:
		//   - `query: ...`            → sql
		//   - `if: ...` (no `run:`)   → conditional branch wrapper
		//   - `for_each: ...` (no `run:`) → iteration wrapper
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

		switch runType {
		case "sql":
			fs.Type = "sql"
			if s.Query != "" {
				fs.SQL = normalizeGHARefs(s.Query)
			} else if q, ok := s.With["query"].(string); ok {
				fs.SQL = normalizeGHARefs(q)
			}
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
			fs.Type = "sql_dynamic"
			if s.Query != "" {
				fs.SQL = normalizeGHARefs(s.Query)
			} else if q, ok := s.With["query"].(string); ok {
				fs.SQL = normalizeGHARefs(q)
			}
		case "api":
			fs.Type = "api"
			fs.API = withToAPI(s.With)
		case "email":
			fs.Type = "email"
			fs.Email = withToEmail(s.With)
		case "webhook":
			fs.Type = "webhook"
			if u, ok := s.With["url"].(string); ok {
				fs.Webhook = normalizeGHARefs(u)
			}
			if b, ok := s.With["body"].(string); ok {
				fs.WebhookBody = normalizeGHARefs(b)
			}
		case "redirect":
			fs.Type = "redirect"
			if t, ok := s.With["to"].(string); ok {
				fs.Redirect = normalizeGHARefs(t)
			}
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
				fs.ServeFile.Disposition = d
			}
			if n, ok := s.With["filename"].(string); ok {
				fs.ServeFile.Filename = normalizeGHARefs(n)
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
			if to, ok := s.With["timeout"].(string); ok {
				if d, err := time.ParseDuration(to); err == nil {
					fs.Compute.Timeout = d
				}
			}
		case "if":
			fs.Type = "if"
			fs.Condition = ghaIfToFlowCondition(s.If)
			// In GHA, an `if:` step may carry a single inline `run:` action
			// OR nest a `steps:` block. We support both: if the step has a
			// non-empty Run + With/Query, treat it as a one-step branch.
			if s.Run != "" {
				inline := s
				inline.If = "" // avoid recursion into nested if
				fs.Steps = convertGHASteps([]FlowStepGHA{inline})
			} else {
				fs.Steps = convertGHASteps(s.Steps)
			}
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

		// `if:` may also appear on non-conditional steps as a per-step
		// gate. If we already classified the step as something other
		// than "if" but it has an If expression, wrap it.
		if fs.Type != "if" && s.If != "" {
			out = append(out, FlowStep{
				Type:      "if",
				Condition: ghaIfToFlowCondition(s.If),
				Steps:     []FlowStep{fs},
			})
			continue
		}

		fs.Retry = s.Retry
		fs.ExpectRows = strings.TrimSpace(s.ExpectRows)
		if s.RetryDelay != "" {
			fs.RetryDelay, _ = time.ParseDuration(s.RetryDelay)
		}
		if s.Timeout != "" {
			fs.Timeout, _ = time.ParseDuration(s.Timeout)
		}
		if len(s.OnError) > 0 {
			fs.OnError = convertGHASteps(s.OnError)
		}
		out = append(out, fs)
	}
	return out
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
	if j, ok := with["json"].(map[string]any); ok {
		// Keep nested arrays/objects (normalizing ${{ }} refs on string
		// leaves) instead of flattening to map[string]string - mirrors
		// withToRespond's body handling. See benmore-go #94.
		if normalized, ok := normalizeRefsInTree(j).(map[string]any); ok {
			api.JSON = normalized
		}
	}
	if f, ok := with["form"].(map[string]any); ok {
		api.Form = stringMap(f)
	}
	// `sign:` sub-block - the outbound-auth recipe. Pre-v2.5.8 the GHA
	// loader silently dropped this entire key; only the legacy text
	// parser handled `sign:`. Every agent writing a GHA-shaped flow
	// with a `sign:` recipe was shipping unauthenticated requests and
	// getting 401s with no diagnostic trail.
	if signRaw, ok := with["sign"].(map[string]any); ok {
		api.Sign = withToSign(signRaw)
	}
	if pagRaw, ok := with["paginate"].(map[string]any); ok {
		api.Paginate = withToPaginate(pagRaw)
	}
	if v, ok := with["success_when"].(string); ok {
		api.SuccessWhen = normalizeGHARefs(v)
	}
	return api
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
// Caveat - compute: binding order: yaml.Marshal of a map[string]any
// emits keys in sorted order, not insertion order. For sign blocks with
// multiple sequential compute: bindings where later bindings reference
// earlier ones, the GHA shape can produce a different evaluation order
// than the agent typed. Single-binding compute + headers-only sign
// (the common cases) are unaffected. Multi-binding compute with
// dependencies should use a `recipe: <built-in>` reference instead;
// built-in recipe text preserves order because it's stored as a string.
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

func withToEmail(with map[string]any) *FlowEmail {
	e := &FlowEmail{}
	if v, ok := with["to"].(string); ok {
		e.To = normalizeGHARefs(v)
	}
	if v, ok := with["subject"].(string); ok {
		e.Subject = normalizeGHARefs(v)
	}
	if v, ok := with["template"].(string); ok {
		e.Template = v
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
	return e
}

func withToRespond(with map[string]any) *FlowRespond {
	r := &FlowRespond{}
	if v, ok := with["status"].(int); ok {
		r.Status = v
	}
	if r.Status == 0 {
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
// whitespace (flows.go interpolateCtx), so we emit that shape exactly
// - adding spaces here would silently break every substitution.
func normalizeGHARefs(s string) string {
	return ghaRefRe.ReplaceAllStringFunc(s, func(match string) string {
		m := ghaRefRe.FindStringSubmatch(match)
		expr := m[1]
		return "{{" + translateGHAExpr(expr) + "}}"
	})
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
		rest = strings.Replace(rest, ".outputs.rows", "", 1)
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
		return strings.TrimPrefix(expr, "params.")
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
