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
	Name    string
	Trigger FlowTrigger
	// Verify is the legacy string-shaped verifier: a named provider
	// ("stripe", "github", "slack", "shopify") or a custom header name
	// for HMAC-SHA256 fallback. Kept for back-compat. New flows should
	// prefer VerifyConfig (the recipe form) for richer control -
	// timestamp/replay protection, explicit signature prefixes, etc.
	Verify       string
	Secret       string
	VerifyConfig *FlowVerify
	Transaction  bool   // wrap all SQL steps in BEGIN/COMMIT
	Auth         string // "required" to require login
	Role         string // required role (e.g. "admin")
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
}

// FlowTrigger defines what starts a flow.
type FlowTrigger struct {
	Type   string // "http", "cron", "on_insert", "on_update", "on_delete"
	Method string // GET, POST
	Path   string // /api/checkout/:deal_id
	Cron   string // "every 5m", "every monday 9am"
	Table  string // for data triggers
	// Inputs is the optional declared input signature (http triggers).
	// Surfaced in /_internal/flows.json so bm.flows typing + the FlowForm
	// component can derive a form. Runtime behavior is unaffected.
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
	// ExpectRows asserts on the number of rows a non-row-producing
	// `run: sql` step (INSERT/UPDATE/DELETE) affected, e.g. ">0", ">=1",
	// "=1", "0". When the assertion fails the flow fails LOUD instead of
	// falling through to a 200 - closing the "guarded INSERT…SELECT…WHERE
	// inserted nothing but the flow still returned {ok:true}" trap. The
	// affected count is always exposed as `steps.<id>.outputs.rows_affected`.
	ExpectRows  string
	API         *FlowAPICall
	Email       *FlowEmail
	SMS         *FlowSMS
	Webhook     string
	WebhookBody string
	WS          *FlowWS      // ws broadcast step
	Enqueue     *FlowEnqueue // enqueue a job for background processing
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
	// PurgeCurrentUserConfirm is the request-bound confirmation for the
	// identity-bound run: purge_current_user step. The executor never accepts a
	// target id: it purges only the immutable authenticated Session on the flow
	// context. See account_purge.go.
	PurgeCurrentUserConfirm string
	// Transcribe carries the (file, model, language) tuple for a
	// `run: transcribe` step - local audio→text via host ffmpeg +
	// whisper-cli. See transcribe.go.
	Transcribe *FlowTranscribe
	// Trusted opts a `run: sql_dynamic` step into consuming
	// request-sourced references as raw SQL text. sql_dynamic interpolates
	// `{{ }}` / `:param` refs directly into the query string (no param
	// binding), so a request-controlled value reaching it is a SQL
	// injection sink. By default flowDynamicGuardRequestRefs rejects any
	// sql_dynamic step that references request-sourced data; authors who
	// genuinely assemble SQL from trusted-internal callers must set
	// `trusted: true` to acknowledge the risk. Authored as `trusted: true`
	// on the step (parsed in flows_gha.go).
	Trusted bool
}

// FlowServeFile is the payload for a `run: serve_file` step.
//
//   - run: serve_file
//     with:
//     path: ${{ steps.item.outputs.file_url }}  # /uploads/private/x.pdf
//     disposition: inline                        # inline (default) | attachment
//     filename: "Q4 report.pdf"                  # optional download name
type FlowServeFile struct {
	Path        string
	Disposition string // "inline" (default) or "attachment"
	Filename    string // optional Content-Disposition filename
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
	Form map[string]string
	Body string
	// Sign, if set, runs a recipe-based signer over the built request
	// before it ships. The recipe (named built-in or inline) declares
	// optional token exchange + ordered compute bindings + headers/query
	// to set. See signers.go + signer_recipe*.go.
	Sign *FlowAPISign
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
	To          string
	Subject     string
	Template    string            // emails/<name>.html (or literal path) rendered as the HTML body
	Html        string            // inline HTML body (accepted keys: html, body)
	Text        string            // inline plain-text body / multipart alt
	Data        map[string]string // extra template vars, overlaid on the flow context (alias: vars)
	Attachments []FlowAttachment  // files attached to the send (base64 content)
	// From overrides EMAIL_FROM for this one send ("send as"). The
	// from-domain is NOT the flow's to choose freely: on the hosted
	// platform the email broker refuses any domain not verified for this
	// app, and off-platform SendEmailOpts refuses any domain other than
	// the configured sender's. Both refuse loudly - there is no silent
	// fallback to EMAIL_FROM, because a silent fallback is what hid the
	// dropped `from:` for weeks.
	From    string
	ReplyTo string // Reply-To header; a reply target, not a sender identity, so unconstrained
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
	Status    int
	JSON      map[string]any
	JSONArray []any // for `body: [...]` / `json: [...]` forms
	Body      string
}

// FlowContext holds execution state for a flow run.
type FlowContext struct {
	App     *App
	Request *http.Request
	Writer  http.ResponseWriter
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
	// NullParams records which keys in Params should bind as SQL NULL
	// (not the empty string). ctx.Params is map[string]string for
	// historical HTTP-path-param reasons - empty string and NULL are
	// indistinguishable in that representation. The SQL bind path
	// reads this sidecar to decide. Set by resolveSQLParamValue when
	// the source expression resolves to Go `nil`.
	NullParams map[string]bool
	Stopped    bool // set by redirect/respond to halt pipeline
	Error      error
	FailedStep string  // name (or type) of the step that set Error - used by flow_no_response diagnostic
	FailedType string  // step.Type of the failure (sql / api / parse / respond / etc) - drives step-type-specific hints
	StepsRun   int     // count of steps actually executed before stopped/errored
	Tx         *sql.Tx // active transaction (nil if not transactional)
	// TxMu serializes access to Tx. database/sql's *sql.Tx is NOT safe for
	// concurrent use, but a flow that is both `transaction: true` and
	// contains a `parallel:` block fans SQL steps out across goroutines
	// that all resolve the same ctx.Tx via flowDB. Without serialization
	// those concurrent Query/Exec calls race and error at runtime. When no
	// transaction is active (ctx.Tx == nil) the underlying *sql.DB pool is
	// already concurrency-safe, so this lock is only taken on the
	// transactional path.
	TxMu sync.Mutex
	// DataMu protects Data + Params + StepsRun + Error + FailedStep +
	// Stopped from concurrent step writes. Only the `parallel:` step
	// fans out goroutines today; sequential paths take Lock+Unlock as
	// no-op overhead.
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
