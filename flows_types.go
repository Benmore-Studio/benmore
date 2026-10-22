//go:build !cli

package main

// Flow declarations, step configuration, and execution context.

import (
	"database/sql"
	"net/http"
	"sync"
	"time"
)

// Flow represents a named workflow triggered by HTTP, cron, or data events.
type Flow struct {
	Name       string
	Source     string // relative checked source file, for mechanical inventory
	sourceHash string // exact bytes parsed by the checked loader
	Trigger    FlowTrigger
	// Verify is the legacy string-shaped verifier: a named provider
	// ("stripe", "github", "slack", "shopify") or a custom header name
	// for HMAC-SHA256 fallback. Kept for back-compat. New flows should
	// prefer VerifyConfig (the recipe form) for richer control -
	// timestamp/replay protection, explicit signature prefixes, etc.
	Verify       string
	Secret       string
	VerifyConfig *FlowVerify
	Transaction  bool     // wrap all SQL steps in BEGIN/COMMIT
	Auth         string   // "required" to require login
	Role         string   // required role (e.g. "admin")
	Permissions  []string // reviewed scope requirements, also enforced for direct HTTP
	// Async, when true, makes an HTTP-triggered flow enqueue itself onto
	// the background job worker instead of running inline. The HTTP
	// handler responds immediately with {job_id, status_url} and the
	// worker invokes executeFlowJob with the captured params. Authored
	// as `mode: async` on the `on.request` block.
	//
	// This sidesteps the platform's 30s edge-gateway timeout when a flow
	// fans out to slow external APIs (carrier integrations, long
	// reports). Clients poll status_url. Steps that depend on the live
	// http.ResponseWriter (respond/redirect) silently no-op in the
	// async path - by definition the response was already sent.
	Async      bool
	Idempotent bool `yaml:"idempotent"`
	// RateLimit, when set (via `rate_limit:` on on.request), caps how often the
	// flow can be invoked per requester before it 429s - see flows_ratelimit.go.
	RateLimit *FlowRateLimit
	Steps     []FlowStep
	// Command is a private, source-owned named declaration. It is inert in the
	// ordinary HTTP/job executors; only the approved MCP operation can consume it.
	Command *FlowCommand
}

// FlowTrigger defines what starts a flow.
type FlowTrigger struct {
	Type   string // "http", "cron", "on_insert", "on_update", "on_delete"
	Method string // GET, POST
	Path   string // /api/checkout/:deal_id
	// StrictJSON requires a bounded, duplicate-free JSON object for this HTTP route.
	StrictJSON bool
	Cron       string // "every 5m", "every monday 9am"
	Table      string // for data triggers
	// Inputs is the optional declared input signature (http triggers).
	// Surfaced in /_internal/flows.json so bm.flows typing + the FlowForm
	// component can derive a form. Declared values are validated before execution.
	Inputs map[string]FlowInput
}

// FlowStep represents a single step in a flow pipeline.
type FlowStep struct {
	Name string
	Type string // "sql", "api", "email", "webhook", "ws", "redirect", "respond", "if", "for_each", "set", "parse"
	SQL  string
	// SQLParams binds named values to `:name` placeholders in SQL,
	// resolved per-step via interpolateCtx (env + step outputs + path
	// params + session) before the query runs. Complex values
	// (slice/map) are JSON-encoded automatically, so combining with
	// SQLite's json_each() / json_extract() works out of the box.
	//
	// Authored as `with.params: { name: <expr> }` on a `run: sql` step.
	// Pre-v2.5.7 the framework dropped this key silently, forcing
	// agents to insert a `run: set` step or interpolate {{ }} into the
	// query body - both worked but neither was the natural shape and
	// the doc led every agent to the dropped-key footgun.
	SQLParams map[string]string
	// CommandSQLParams preserves typed references before ordinary flow
	// conversion flattens user.group_id into a runtime context key.
	CommandSQLParams map[string]FlowCommandParamRef
	// ExpectRowsConflict is set by the loader when the step declares
	// expect_rows at the step root and under `with:` with different values.
	// The step then refuses to run (executeStep).
	ExpectRowsConflict string
	// ExpectRows asserts on the row count of a `run: sql` / `run: sql_dynamic`
	// step, e.g. ">0", ">=1", "=1", "0": the rows RETURNED by a SELECT or by
	// a write with RETURNING (one row per row it changed), the rows AFFECTED
	// by any other INSERT/UPDATE/DELETE. When the assertion fails the flow
	// fails LOUD instead of falling through to a 200 - closing the "guarded
	// INSERT…SELECT…WHERE inserted nothing but the flow still returned
	// {ok:true}" trap. A write without RETURNING always stores its count as
	// the step output `rows_affected`.
	//
	// It is evaluated on every statement shape (execStepSQL,
	// routeAssertedFlowSQL); a statement with no row count (DDL, a mixed
	// script) is refused before it runs, never run with the assertion
	// skipped. Other step types carry no assertion: the write gate refuses
	// the key there (expectRowsViolation).
	ExpectRows  string
	API         *FlowAPICall
	Email       *FlowEmail
	SMS         *FlowSMS
	Webhook     string
	WebhookBody string
	// WebhookJSON is a `run: webhook` step's `with.payload` (or a `body:`
	// written as a map or list): the JSON body, string leaves GHA-ref
	// normalized and resolved like an api `json:` body at send time. Nil when
	// the step declares none; the step then sends WebhookBody, or with no body
	// the whole flow context (execStepWebhook).
	WebhookJSON any
	WS          *FlowWS        // legacy `ws:` room message step
	Broadcast   *FlowBroadcast // `run: broadcast` room message step
	Enqueue     *FlowEnqueue   // enqueue a job for background processing
	Redirect    string
	Respond     *FlowRespond
	Condition   string     // for "if" steps
	Steps       []FlowStep // nested steps (for if/for_each)
	ElseSteps   []FlowStep // else branch
	ForEach     string     // variable name to iterate
	ForAs       string     // loop variable name
	Set         map[string]string
	Parse       string // "body" to parse request body
	Retry       int
	RetryDelay  time.Duration
	OnError     []FlowStep
	Timeout     time.Duration
	// Compute carries the (module, function, args) tuple for a
	// `run: compute` step (v2.7.67+). The step compiles + runs a
	// TS/JS module from static/ via goja, returns the named
	// function's result into step outputs. See compute.go.
	Compute *FlowCompute
	// ServeFile streams a file from the app's uploads/ dir as the
	// terminal response (v2.7.125+). The flow IS the authorization - so
	// a private file (uploads/private/...) can be served to an anon
	// caller the flow has already gated, without minting a signed URL.
	ServeFile *FlowServeFile
	// DeleteUpload is an interpolated stored private-upload reference for the
	// server-only run: delete_upload step.
	DeleteUpload string
	// InspectPrivateUpload reads a bounded app-owned PDF or PNG in the
	// isolated parser and returns a server-derived hash and dimensions.
	InspectPrivateUpload *FlowInspectPrivateUpload
	// RenderPDFSignatures stamps signature PNGs onto a new immutable PDF.
	RenderPDFSignatures *FlowRenderPDFSignatures
	// RevokeUserID is the authored `user_id` of a command-only
	// `run: revoke_user_sessions` step (app_mcp_command_revoke.go);
	// CommandRevokeRef is its compiled captured-intent reference.
	RevokeUserID     string
	CommandRevokeRef FlowCommandParamRef
	// PurgeCurrentUserConfirm is the request-bound confirmation for the
	// identity-bound run: purge_current_user step. The executor never accepts a
	// target id: it purges only the immutable authenticated Session on the flow
	// context. See account_purge.go.
	PurgeCurrentUserConfirm string
	// Transcribe carries the (file, model, language) tuple for a
	// `run: transcribe` step - local audio→text via host ffmpeg +
	// whisper-cli. See transcribe.go.
	Transcribe *FlowTranscribe
	// RedirectAllowHosts lists the off-origin hosts a templated
	// `run: redirect` `to:` may target (`with: { allow_hosts: [...] }`).
	// Without it a templated target must stay same-origin; see
	// flowRedirectTarget.
	RedirectAllowHosts []string
}

// FlowServeFile is the payload for a `run: serve_file` step.
//
//   - run: serve_file
//     with:
//     path: ${{ steps.item.outputs.file_url }}  # /uploads/private/x.pdf
//     disposition: inline                        # inline (default) | attachment | ${{ expr }}
//     filename: "Q4 report.pdf"                  # optional download name
type FlowServeFile struct {
	Path        string
	Disposition string // "inline" (default) or "attachment"; may be a ${{ }} expression
	Filename    string // optional Content-Disposition filename
}

type FlowInspectPrivateUpload struct {
	SourcePath string
	Kind       string
}

type FlowRenderPDFSignatures struct {
	SourcePath     string
	SourceSHA256   string
	PlacementsJSON string
}

// FlowTranscribe is the payload for a `run: transcribe` step - local
// Whisper transcription via host binaries (no vendor, no API key).
//
//   - id: t
//     run: transcribe
//     with:
//     file: uploads/brief.webm   # app-relative path (primary) or public https:// URL
//     model: base.en             # optional, default WHISPER_MODEL (small.en)
//     language: en               # optional, passed to whisper as -l
//
// Outputs: steps.<id>.outputs.text (transcript) and
// steps.<id>.outputs.audio_path. Engine + env knobs: transcribe.go.
type FlowTranscribe struct {
	File     string
	Model    string
	Language string
}

// FlowCompute is the payload for a `run: compute` step.
//
//   - id: irr
//     run: compute
//     module: par-engine        # static/par-engine.ts (auto-resolved)
//     function: irrForInputs    # named export
//     args: ${{ steps.forecast.outputs.first }}
//     timeout: 10s              # optional, default 5s
//
// Args is interpolated through the flow's template engine before
// the JS call, so any `${{ steps.X.outputs.Y }}` reference resolves
// to its concrete value at run time.
type FlowCompute struct {
	Module   string
	Function string
	Args     any           // native YAML shape: a single ref string, OR a map/slice of refs - resolved to native values at call time (resolveComputeArgsValue)
	Timeout  time.Duration // 0 → compute.go uses its 5s default
}

// FlowEnqueue queues a job for the background worker. Use for any
// work that might take more than ~30s - long API calls, report
// generation, batch processing - where the user shouldn't wait for
// a synchronous response. The named flow (must have `on: job:`
// trigger) runs out-of-band with no request timeout.
//
//   - enqueue:
//     flow: generate_report
//     with:
//     user_id: "{{user.id}}"
//     date_range: "30d"
//     run_at: "{{now + 1h}}"   # optional scheduled delivery
type FlowEnqueue struct {
	Flow      string
	With      map[string]string
	RunAt     string // optional ISO timestamp; empty = run ASAP
	UniqueKey string // optional idempotency key for active pending/running jobs (PR #10)
}

// FlowWS broadcasts a payload to a WebSocket room. Used by `ws:` steps
// in flows.yaml - clients that have joined the same scope-namespaced
// room receive the message instantly.
//
//   - id: notify
//     ws:
//     room: "order-{{order_id}}"
//     payload: {"status": "shipped", "tracking": "{{tracking_no}}"}
type FlowWS struct {
	Room    string
	Payload string
}

// FlowBroadcast is a `run: broadcast` step: a server message to the current
// members of a WebSocket room (execStepBroadcast, flows_realtime.go).
//
//   - id: notify
//     run: broadcast
//     with:
//     room: "order-${{ steps.o.outputs.id }}"
//     payload: { kind: shipped, tracking: "${{ steps.o.outputs.tracking }}" }
//
// Room is GHA-ref normalized; Payload keeps its YAML shape (map, list or
// scalar) with every string leaf normalized, and resolves like a respond body.
type FlowBroadcast struct {
	Room       string
	Payload    any
	HasPayload bool // `payload:` key present (an explicit null counts)
}

// FlowAPICall represents an outbound HTTP request step.
type FlowAPICall struct {
	Method  string
	URL     string
	Auth    string
	Headers map[string]string
	// Query holds `with.query:` map entries - appended to the URL as
	// ?k=v&k2=v2 before the request fires. Pre-v2.5.9 this key was
	// silently dropped on the GHA path, so every flow filtering an
	// outbound carrier API by `customer_id` (or anything else) sent
	// no filter. Values are GHA-ref-normalized at parse time + final
	// ctx interpolation happens in execStepAPI before URL escape.
	Query map[string]string
	// JSON is the `json:` request body. It is map[string]any (not
	// map[string]string) so nested arrays/objects round-trip to the
	// upstream API - e.g. Modern Treasury's required `routing_details`/
	// `account_details` arrays. String leaves are ctx-interpolated and
	// the whole structure is json.Marshal'd at send time (execStepAPI).
	// Mirrors FlowRespond.JSON. See benmore-go #94.
	JSON map[string]any
	// JSONArray is a JSON list body: `with.json` written as a list, or
	// `with.body` written as one. Resolved and sent like JSON.
	JSONArray []any
	Form      map[string]string
	Body      string
	// Sign, if set, runs a recipe-based signer over the built request
	// before it ships. The recipe (named built-in or inline) declares
	// optional token exchange + ordered compute bindings + headers/query
	// to set. See signers.go + signer_recipe*.go.
	Sign *FlowAPISign
	// HandledStatuses opts selected explicit HTTP 4xx responses into the
	// normal response-envelope path. Transport errors and 5xx stay errors.
	HandledStatuses []int
	// Paginate, if set, makes the step loop the request and accumulate
	// items across pages. Eliminates the `?limit=500` footgun where a
	// hardcoded cap silently drops data as the upstream grows. See
	// FlowAPIPaginate for strategy / param shape.
	Paginate *FlowAPIPaginate
	// SuccessWhen is a SQL-style boolean expression evaluated against
	// the parsed JSON response. When set AND it evaluates false, the
	// step errors with `api: success_when failed`. Without it, the
	// only failure signal is the HTTP status code - and many APIs
	// return 200 with `{"status":"error","reason":"..."}` envelopes
	// (rss2json, several CRM webhooks). Multiple real apps
	// hit this during builds and silently ingested error envelopes
	// as if they were data.
	//
	// Example:
	//   - run: api
	//     with:
	//       url: https://api.rss2json.com/v1/api.json?rss_url=...
	//       success_when: ${{ steps.fetch.outputs.json.status }} == 'ok'
	//
	// References the step's OWN outputs.json - the response is parsed
	// before the check fires.
	SuccessWhen string
}

// FlowAPIPaginate configures repeated requests to fetch all pages from
// a paginated upstream. The step's output becomes
// `{ items: [...], pages_fetched: N }` and downstream `${{ steps.X.
// outputs.items }}` references see the accumulated list. Hard-capped
// by MaxPages to avoid runaway loops.
type FlowAPIPaginate struct {
	// Strategy: "cursor" (extract next-cursor from response) or "page"
	// (increment a numeric page counter). Empty defaults to "cursor".
	Strategy string
	// Cursor-strategy fields.
	CursorParam string // query param name to send cursor in (default "cursor")
	CursorField string // JSON path to read next cursor from each response (e.g. "$.next_cursor")
	// Page-strategy fields.
	PageParam string // query param name (default "page")
	PageStart int    // first page number (default 1)
	// Either strategy.
	ItemsField string // JSON path to the items array in each response (e.g. "$.shipments")
	MaxPages   int    // safety cap (default 50, hard max 500)
}

// FlowSMS is a `run: sms` step. Delivery goes through SendSMS, so an
// explicitly configured provider (Twilio via SMS_ACCOUNT_SID, or
// SMS_WEBHOOK_URL) wins and the hosted platform's shared number is the
// fallback - the flow YAML is identical either way.
//
//	steps:
//	  - id: notify
//	    run: sms
//	    with:
//	      to: "${{ steps.u.outputs.phone }}"
//	      body: "Your code is ${{ steps.otp.outputs.code }}"
//
// `text:` is accepted as an alias for `body:`, mirroring run: email.
type FlowSMS struct {
	To   string
	Body string // inline message text (accepted keys: body, text)
}

// FlowEmail represents an email step.
type FlowEmail struct {
	CC                  string
	BCC                 string
	UnsubscribeOneClick string // literal or template resolving to true/false
	To                  string
	Subject             string
	Template            string            // emails/<name>.html (or literal path) rendered as the HTML body
	Html                string            // inline HTML body (accepted keys: html, body)
	Text                string            // inline plain-text body / multipart alt
	Data                map[string]string // extra template vars, overlaid on the flow context (alias: vars)
	Attachments         []FlowAttachment  // files attached to the send (base64 content)
	// From overrides EMAIL_FROM for this one send ("send as"). The
	// from-domain is NOT the flow's to choose freely: on the hosted
	// platform the email broker refuses any domain not verified for this
	// app, and off-platform SendEmailOpts refuses any domain other than
	// the configured sender's. Both refuse loudly - there is no silent
	// fallback to EMAIL_FROM, because a silent fallback is what hid the
	// dropped `from:` for weeks.
	From    string
	ReplyTo string // Reply-To header; a reply target, not a sender identity, so unconstrained
	// UnsubscribeURL is `with.unsubscribe_url`, rendered at send time into a
	// List-Unsubscribe header. It must render to an https URL. One-click is
	// opt-in and requires a valid URL; ordinary mail can omit the header.
	UnsubscribeURL string
}

// FlowAttachment is one attachment on a `run: email` step. Content is base64;
// filename and content are interpolated at exec time so a flow can pass bytes
// produced by an earlier step (e.g. content: "${{ steps.pdf.outputs.b64 }}").
type FlowAttachment struct {
	Filename    string
	ContentType string
	Content     string // base64-encoded file bytes
}

// FlowRespond represents a custom HTTP response.
type FlowRespond struct {
	Status int
	// StatusTemplate is a `status:` written as a template
	// (`${{ steps.calc.outputs.status }}`). It is rendered when the step
	// runs and must give an integer 200-599, or the step fails; Status is
	// then unused. A quoted number ("404") is read into Status at load.
	StatusTemplate string
	JSON           map[string]any
	JSONArray      []any // for `body: [...]` / `json: [...]` forms
	Body           string
	// ContentType is the declared Content-Type (`with.content_type`, or a
	// Content-Type entry under `with.headers`), a literal media type. With
	// it a text body is sent as written instead of JSON-encoded
	// (execStepRespond); see flows_respond_headers.go for the rules.
	ContentType string
	// Headers are the other `with.headers` entries that passed the response
	// header allowlist (respondHeaderRefusal), in name order. Values are
	// templates rendered when the step runs.
	Headers []FlowRespondHeader
}

// FlowRespondHeader is one allowed response header of a `run: respond` step.
type FlowRespondHeader struct {
	Name  string // canonical form (http.CanonicalHeaderKey)
	Value string // template, GHA refs normalized
}

// FlowContext holds execution state for a flow run.
type FlowContext struct {
	App       *App
	Request   *http.Request
	Writer    http.ResponseWriter
	apiClient *http.Client // per-execution internal test client for api and webhook steps; nil uses the strict SSRF client
	// privateResponse remembers identity injected into a public flow even if
	// a later step revokes the session. It grants no step authorization.
	privateResponse bool
	// Session is the immutable authenticated actor captured by the HTTP entry
	// point. Destructive server-only steps must authorize from this value, never
	// from ctx.Data/Params, which are mutable and may be request-controlled.
	Session *Session
	Data    map[string]any    // named step results
	Params  map[string]string // path and query params
	// RequestKeys records which Params/Data keys were sourced directly
	// from the inbound HTTP request (path params, query string, form
	// fields, JSON body). It is the taint set used by
	// flowDynamicGuardRequestRefs to forbid request-controlled values
	// from being interpolated as raw SQL text in `run: sql_dynamic`
	// steps (M-1). Only executeFlowHTTP populates it; internal/job
	// invocations leave it nil (those params originate server-side).
	RequestKeys map[string]bool
	// SecretKeys records which Data keys hold a value derived from the
	// app's env (flows_taint.go). A `run: api` or `run: webhook` call that
	// sends one carries the app's secrets, so request input may not choose
	// its host (flows_api_url.go). Like RequestKeys it only grows, and it is
	// shared with on_error contexts and carried to enqueued jobs.
	SecretKeys map[string]bool
	// requestStepSources holds, for each request-tainted step output, the
	// author-written strings of the step that produced it, so a URL that
	// step fixed (a literal, an env value) can still name the host of a
	// call that sends secret-derived values (flowValueAuthoredByStep).
	requestStepSources map[string][]string
	// NullParams records which keys in Params should bind as SQL NULL
	// (not the empty string). ctx.Params is map[string]string for
	// historical HTTP-path-param reasons - empty string and NULL are
	// indistinguishable in that representation. The SQL bind path
	// reads this sidecar to decide. Set by resolveSQLParamValue when
	// the source expression resolves to Go `nil`.
	NullParams map[string]bool
	Stopped    bool // set by redirect/respond to halt pipeline
	// errorResponse means an on_error handler produced the terminal HTTP
	// response. Error remains set for diagnostics and transaction rollback.
	errorResponse bool
	Error         error
	FailedStep    string    // name (or type) of the step that set Error - used by flow_no_response diagnostic
	FailedType    string    // step.Type of the failure (sql / api / parse / respond / etc) - drives step-type-specific hints
	StepsRun      int       // count of steps actually executed before stopped/errored
	mcpReadConn   *sql.Conn // private connector reads pin a protected connection
	mcpReadKey    []byte
	Tx            *sql.Tx // active transaction (nil if not transactional)
	// TxMu serializes access to Tx. database/sql's *sql.Tx is NOT safe for
	// concurrent use, but a flow that is both `transaction: true` and
	// contains a `parallel:` block fans SQL steps out across goroutines
	// that all resolve the same ctx.Tx via flowDB. Without serialization
	// those concurrent Query/Exec calls race and error at runtime. When no
	// transaction is active (ctx.Tx == nil) the underlying *sql.DB pool is
	// already concurrency-safe, so this lock is only taken on the
	// transactional path.
	TxMu sync.Mutex
	// Parallel branches retain the parent's transaction lock for steps such
	// as enqueue, while their maps, control state and caches stay private.
	parallelTxMu *sync.Mutex
	// Actual output assignments for deterministic merges at a parallel join.
	parallelOutputs map[string]bool
	// DataMu protects context value helpers. Parallel branches own separate
	// maps and control state; their results merge only after all branches join.
	DataMu sync.Mutex
	// MissingRefs records every `${{ ... }}` (or `{{ ... }}`) expression
	// that failed to resolve during interpolation of the *current* step.
	// The step dispatcher resets this before each step and halts the
	// flow if any entries remain after the step completed - pre-v2.7.5
	// the runtime silently emitted the literal `{{ws.id}}` text into
	// query strings, response bodies, and URLs, so the chain of failure
	// (unresolved → NULL bind → unique constraint → rollback → no row
	// in DB → client sees placeholder text) was nearly impossible to
	// diagnose without instrumenting the wire. The framework now halts
	// with a clear error instead of emitting literal placeholder text.
	MissingRefs []string
	// reachedSteps names every step execution has reached, whether it ran
	// or was skipped (markStepsReached). A compute argument that names one
	// of them but has no value resolves to null instead of stopping the
	// flow (resolveComputeArgString). Shared with on_error contexts; a
	// parallel branch gets a copy that is merged back at the join.
	reachedSteps map[string]bool
	// Writes collects the app tables this run's SQL steps wrote, so the
	// entry point can announce them as realtime table events once they are
	// durable (flows_realtime.go). Shared by pointer with on_error contexts.
	// Nil means the run does not announce (a caller that never finishes a
	// run through announceFlowWrites).
	Writes *flowWriteLog
	// command is a private source-owned execution guard. It is never populated
	// by ordinary HTTP, job, event, or cron flow dispatch.
	command *appMCPCommandExecution
	// flatCache memoizes flatDataForCtx until Data or env changes.
	flatCache flowFlatCache
	// lazyShadow holds request fields named like a set key, loop variable
	// or unnamed parse output that are still readable by their bare name
	// (flows.go, shadowStepNamedRequestKeys). Shared with on_error contexts.
	lazyShadow *flowLazyShadow
}

// noteMissingRef appends an unresolved expression to ctx.MissingRefs so
// the step dispatcher can halt with a useful error after the step's
// interpolation completes. Duplicate entries are collapsed because the
// same template can render dozens of times in a single step (e.g. a
// `respond:` body referencing `${{ steps.ws.outputs.id }}` in five
// fields), and one entry per unique ref is enough signal.
func (ctx *FlowContext) noteMissingRef(expr string) {
	if ctx == nil || expr == "" {
		return
	}
	ctx.DataMu.Lock()
	defer ctx.DataMu.Unlock()
	for _, existing := range ctx.MissingRefs {
		if existing == expr {
			return
		}
	}
	ctx.MissingRefs = append(ctx.MissingRefs, expr)
}

// takeMissingRefs returns + clears ctx.MissingRefs. The step dispatcher
// calls this at step boundaries to (a) check whether the step's
// interpolation passed and (b) reset state for the next step.
func (ctx *FlowContext) takeMissingRefs() []string {
	if ctx == nil {
		return nil
	}
	ctx.DataMu.Lock()
	defer ctx.DataMu.Unlock()
	if len(ctx.MissingRefs) == 0 {
		return nil
	}
	out := ctx.MissingRefs
	ctx.MissingRefs = nil
	return out
}

// setStepOutput stores a step's result under step.Name in ctx.Data and
// also flattens the value so dotted-path lookups work. Centralizes the
// concurrent-write protection added for the `parallel:` step type.
func (ctx *FlowContext) setStepOutput(name string, value any) {
	if name == "" {
		return
	}
	ctx.DataMu.Lock()
	defer ctx.DataMu.Unlock()
	ctx.Data[name] = value
	if m, ok := value.(map[string]any); ok {
		flattenIntoCtx(ctx.Data, name, m)
	}
}
