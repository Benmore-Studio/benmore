//go:build !cli

package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"sort"
	"sync"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// Flow represents a named workflow triggered by HTTP, cron, or data events.
type Flow struct {
	Name string
	Trigger     FlowTrigger
	// Verify is the legacy string-shaped verifier: a named provider
	// ("stripe", "github", "slack", "shopify") or a custom header name
	// for HMAC-SHA256 fallback. Kept for back-compat. New flows should
	// prefer VerifyConfig (the recipe form) for richer control -
	// timestamp/replay protection, explicit signature prefixes, etc.
	Verify      string
	Secret      string
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
	Async bool
	Steps []FlowStep
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
	Name        string
	Type        string // "sql", "api", "email", "webhook", "ws", "redirect", "respond", "if", "for_each", "set", "parse"
	SQL         string
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
	SQLParams   map[string]string
	API         *FlowAPICall
	Email       *FlowEmail
	Webhook     string
	WebhookBody string
	WS          *FlowWS // ws broadcast step
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
}

// FlowServeFile is the payload for a `run: serve_file` step.
//
//	- run: serve_file
//	  with:
//	    path: ${{ steps.item.outputs.file_url }}  # /uploads/private/x.pdf
//	    disposition: inline                        # inline (default) | attachment
//	    filename: "Q4 report.pdf"                  # optional download name
type FlowServeFile struct {
	Path        string
	Disposition string // "inline" (default) or "attachment"
	Filename    string // optional Content-Disposition filename
}

// FlowCompute is the payload for a `run: compute` step.
//
//	- id: irr
//	  run: compute
//	  module: par-engine        # static/par-engine.ts (auto-resolved)
//	  function: irrForInputs    # named export
//	  args: ${{ steps.forecast.outputs.first }}
//	  timeout: 10s              # optional, default 5s
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
//       flow: generate_report
//       with:
//         user_id: "{{user.id}}"
//         date_range: "30d"
//       run_at: "{{now + 1h}}"   # optional scheduled delivery
type FlowEnqueue struct {
	Flow    string
	With    map[string]string
	RunAt   string // optional ISO timestamp; empty = run ASAP
}

// FlowWS broadcasts a payload to a WebSocket room. Used by `ws:` steps
// in flows.yaml - clients that have joined the same scope-namespaced
// room receive the message instantly.
//
//   - id: notify
//     ws:
//       room: "order-{{order_id}}"
//       payload: {"status": "shipped", "tracking": "{{tracking_no}}"}
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
	Query   map[string]string
	JSON    map[string]string
	Form    map[string]string
	Body    string
	// Sign, if set, runs a recipe-based signer over the built request
	// before it ships. The recipe (named built-in or inline) declares
	// optional token exchange + ordered compute bindings + headers/query
	// to set. See signers.go + signer_recipe*.go.
	Sign    *FlowAPISign
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

// FlowEmail represents an email step.
type FlowEmail struct {
	To       string
	Subject  string
	Template string            // emails/<name>.html (or literal path) rendered as the HTML body
	Html     string            // inline HTML body (accepted keys: html, body)
	Text     string            // inline plain-text body / multipart alt
	Data     map[string]string // extra template vars, overlaid on the flow context (alias: vars)
}

// FlowRespond represents a custom HTTP response.
type FlowRespond struct {
	Status    int
	JSON      map[string]any
	JSONArray []any  // for `body: [...]` / `json: [...]` forms
	Body      string
}

// FlowContext holds execution state for a flow run.
type FlowContext struct {
	App     *App
	Request *http.Request
	Writer  http.ResponseWriter
	Data    map[string]any   // named step results
	Params  map[string]string // path and query params
	// NullParams records which keys in Params should bind as SQL NULL
	// (not the empty string). ctx.Params is map[string]string for
	// historical HTTP-path-param reasons - empty string and NULL are
	// indistinguishable in that representation. The SQL bind path
	// reads this sidecar to decide. Set by resolveSQLParamValue when
	// the source expression resolves to Go `nil`.
	NullParams map[string]bool
	Stopped bool             // set by redirect/respond to halt pipeline
	Error   error
	FailedStep string        // name (or type) of the step that set Error - used by flow_no_response diagnostic
	FailedType string        // step.Type of the failure (sql / api / parse / respond / etc) - drives step-type-specific hints
	StepsRun   int           // count of steps actually executed before stopped/errored
	Tx      *sql.Tx          // active transaction (nil if not transactional)
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

// LoadFlows reads flows.yaml from the app directory.
func LoadFlows(dir string) []Flow {
	path := filepath.Join(dir, "flows.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseFlows(string(data))
}

// RegisterFlows sets up HTTP handlers and cron jobs for all flows.
//
// HTTP-flow patterns may collide with auto-CRUD routes (RegisterCRUD
// runs first in server.go and mounts /api/<table> for every Prisma
// model). http.ServeMux.HandleFunc panics on a duplicate registration,
// which would crash the per-app process on every reload. We guard with
// a recover() per flow so one bad flow can't take the whole app down,
// log a loud error, and continue registering the rest. The write-time
// validator catches the same case prescriptively so agents fix it
// before saving - this is just the runtime safety net for any flows
// that bypassed validation (legacy files on disk, etc.).
func RegisterFlows(mux *http.ServeMux, app *App, flows []Flow) {
	for _, flow := range flows {
		f := flow
		switch f.Trigger.Type {
		case "http":
			// Convert :param to {param} for Go 1.22 ServeMux pattern matching
			muxPath := f.Trigger.Path
			parts := strings.Split(muxPath, "/")
			for i, part := range parts {
				if strings.HasPrefix(part, ":") {
					parts[i] = "{" + strings.TrimPrefix(part, ":") + "}"
				}
			}
			muxPath = strings.Join(parts, "/")
			pattern := fmt.Sprintf("%s %s", f.Trigger.Method, muxPath)
			func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("ERROR: flow %q at %s collides with an existing route (likely auto-CRUD on a same-named table) - skipping flow registration. Move the flow to a different path (e.g. /api/%s/all) or remove the matching Prisma model. mux.HandleFunc panicked: %v",
							f.Name, pattern, strings.TrimPrefix(f.Trigger.Path, "/api/"), r)
					}
				}()
				mux.HandleFunc(pattern, func(w http.ResponseWriter, r *http.Request) {
					executeFlowHTTP(app, &f, w, r)
				})
				log.Printf("  flow: %s %s → %s", f.Trigger.Method, f.Trigger.Path, f.Name)
			}()

		case "cron":
			// v2.7.41: cron flows are scheduled via the persistent
			// StartCronScheduler path (see mergeFlowCronsIntoConfig in
			// cron.go). We DON'T spawn the legacy `for { time.Sleep …
			// }` goroutine here anymore - that goroutine had no stop
			// channel and no persistence, so every SIGHUP started a
			// fresh 15m sleep from now, resetting the schedule window
			// from the agent's perspective. The persistent scheduler
			// uses _benmore_cron_state as the source of truth so
			// edits never reset the timer.
			log.Printf("  flow: cron %s → %s (via persistent scheduler)", f.Trigger.Cron, f.Name)
		}
	}
}

// FireFlowsForEvent triggers all data-event flows for a given table/event.
func FireFlowsForEvent(app *App, event, table string, row map[string]any) {
	for _, flow := range app.Flows {
		if flow.Trigger.Type == event && flow.Trigger.Table == table {
			f := flow
			go func() {
				defer func() {
					if r := recover(); r != nil {
						log.Printf("FLOW EVENT PANIC [%s]: %v", f.Name, r)
					}
				}()
				ctx := &FlowContext{
					App:    app,
					Data:   make(map[string]any),
					Params: make(map[string]string),
				}
				// Seed context with row data
				for k, v := range row {
					ctx.Data[k] = v
				}
				// Start transaction if flow requires it
				if f.Transaction {
					tx, err := app.DB.Begin()
					if err != nil {
						log.Printf("FLOW ERROR [%s] begin tx: %s", f.Name, err)
						return
					}
					ctx.Tx = tx
				}
				executeSteps(ctx, f.Steps)
				// Commit or rollback
				if ctx.Tx != nil {
					if ctx.Error != nil {
						ctx.Tx.Rollback()
					} else {
						ctx.Tx.Commit()
					}
				}
				if ctx.Error != nil {
					log.Printf("FLOW ERROR [%s] %s", f.Name, ctx.Error)
				}
			}()
		}
	}
}

func executeFlowHTTP(app *App, flow *Flow, w http.ResponseWriter, r *http.Request) {
	ctx := &FlowContext{
		App:     app,
		Request: r,
		Writer:  w,
		Data:    make(map[string]any),
		Params:  make(map[string]string),
	}

	// Extract path params from the original :param definitions
	pathParts := strings.Split(flow.Trigger.Path, "/")
	reqParts := strings.Split(r.URL.Path, "/")
	for i, part := range pathParts {
		if strings.HasPrefix(part, ":") && i < len(reqParts) {
			paramName := strings.TrimPrefix(part, ":")
			ctx.Params[paramName] = reqParts[i]
			ctx.Data[paramName] = reqParts[i]
		}
	}
	// Also try Go 1.22 PathValue for {param} patterns
	for _, part := range pathParts {
		if strings.HasPrefix(part, ":") {
			paramName := strings.TrimPrefix(part, ":")
			if val := r.PathValue(paramName); val != "" {
				ctx.Params[paramName] = val
				ctx.Data[paramName] = val
			}
		}
	}

	// Extract query params
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			ctx.Params[k] = v[0]
			ctx.Data[k] = v[0]
		}
	}

	// Extract POST form data (application/x-www-form-urlencoded or multipart)
	if r.Method == "POST" {
		r.ParseForm()
		for k, v := range r.PostForm {
			if len(v) > 0 && k != "csrf_token" {
				ctx.Params[k] = v[0]
				ctx.Data[k] = v[0]
			}
		}
	}

	// Extract JSON body fields into ctx.Params. Pre-v2.5.9 path params,
	// query string, and form-encoded bodies all auto-populated
	// ctx.Params, but JSON bodies didn't - so `POST /api/foo` with
	// {"customer_id":"abc"} left `:customer_id` unbound in subsequent
	// SQL steps. Now any object-shaped JSON body lands the same way as
	// a form body. Body is restored on r.Body so downstream `parse:`
	// steps still see it.
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		if strings.Contains(ct, "application/json") && r.Body != nil {
			rawBody, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
			r.Body = io.NopCloser(bytes.NewReader(rawBody))
			var data map[string]any
			if err := json.Unmarshal(rawBody, &data); err == nil {
				for k, v := range data {
					if _, taken := ctx.Params[k]; taken {
						continue
					}
					// JSON null → bind SQL NULL via NullParams sidecar.
					// Pre-v2.7.4 hit the default arm and json.Marshal'd
					// nil to the literal "null" string.
					if v == nil {
						ctx.Params[k] = ""
						if ctx.NullParams == nil {
							ctx.NullParams = map[string]bool{}
						}
						ctx.NullParams[k] = true
						ctx.Data[k] = nil
						continue
					}
					switch val := v.(type) {
					case string:
						ctx.Params[k] = val
					case bool, float64, int, int64:
						ctx.Params[k] = fmt.Sprintf("%v", val)
					default:
						// Slices/maps: store as JSON string so SQL
						// json_each(:name) consumes them naturally.
						if b, err := json.Marshal(v); err == nil {
							ctx.Params[k] = string(b)
						}
					}
					ctx.Data[k] = v
				}
			}
		}
	}

	// Auth enforcement for HTTP-triggered flows
	if flow.Auth == "required" || flow.Role != "" {
		session := getSession(app, r)
		if session == nil {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		if flow.Role != "" && session.Role != flow.Role && !session.IsAdmin() {
			http.Error(w, "Forbidden", http.StatusForbidden)
			return
		}
		// Inject session context. Legacy flat keys (user_id / user_email /
		// user_role) stay for backwards-compat with older flows. The
		// `user` object is the supported form going forward - it carries
		// every non-sensitive column on _benmore_users (first_name,
		// last_name, plan, verified, custom signup_fields, …), so
		// `${{ user.first_name }}` / `${{ user.plan }}` resolve the same
		// way `{{user.field}}` does in templates. Pre-v2.7.5 the user
		// scope only carried id/email/role and any other reference
		// silently left literal `{{first_name}}` in flow output -
		// the same trap an earlier app build hit.
		ctx.Data["user_id"] = session.UserID
		ctx.Data["user_email"] = session.Email
		ctx.Data["user_role"] = session.Role
		if userRow := LoadUserFields(app.DB, session.UserID); userRow != nil {
			ctx.Data["user"] = userRow
		} else {
			// Fall back to the session-only fields so `${{ user.id }}` /
			// `${{ user.email }}` / `${{ user.role }}` still resolve even
			// if the user row is unreachable (rare - would mean the row
			// was deleted between session lookup and field load).
			ctx.Data["user"] = map[string]any{
				"id":    session.UserID,
				"email": session.Email,
				"role":  session.Role,
			}
		}
	}

	// Webhook signature verification - rich recipe form takes precedence
	// over the legacy string form so flows that declare both (during a
	// migration) get the precise behavior they configured. The recipe
	// form returns a granular error logged server-side; clients still
	// only see "Invalid signature" / 401 so check-which-check-failed
	// isn't an oracle for attackers.
	if flow.VerifyConfig != nil {
		if err := runVerifyRecipe(flow.VerifyConfig, r, app.Dir); err != nil {
			log.Printf("FLOW VERIFY REJECT [%s]: %s", flow.Name, err)
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}
	} else if flow.Verify != "" {
		if !verifyWebhookSignature(flow, r, app.Dir) {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}
	}

	// Async flow: enqueue + respond {job_id, status_url} immediately.
	// The background worker (StartJobWorker) picks the job up and runs
	// executeFlowJob with the captured ctx.Data. This dodges the 30s
	// edge gateway timeout for flows that fan out across slow upstream
	// APIs - clients poll status_url instead of holding a connection
	// open. Steps that depend on http.ResponseWriter (respond, redirect)
	// silently no-op in the worker - the HTTP response was already sent.
	if flow.Async {
		payload := make(map[string]any, len(ctx.Data))
		for k, v := range ctx.Data {
			payload[k] = v
		}
		jobID, jobToken, err := EnqueueJob(app.DB, flow.Name, payload, nil)
		if err != nil {
			log.Printf("FLOW ASYNC ENQUEUE ERROR [%s]: %s", flow.Name, err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		json.NewEncoder(w).Encode(map[string]any{
			"job_id": jobID,
			"status": "pending",
			// status_url carries the capability token - the submitter polls
			// with it; without it the job id alone can't read status/error.
			"status_url": fmt.Sprintf("/api/_jobs/%d/status?token=%s", jobID, jobToken),
			"flow":       flow.Name,
		})
		return
	}

	// Start transaction if flow requires it
	if flow.Transaction {
		tx, err := app.DB.Begin()
		if err != nil {
			log.Printf("FLOW ERROR [%s] begin tx: %s", flow.Name, err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		ctx.Tx = tx
	}

	executeSteps(ctx, flow.Steps)

	// Commit or rollback transaction
	if ctx.Tx != nil {
		if ctx.Error != nil {
			ctx.Tx.Rollback()
		} else {
			if err := ctx.Tx.Commit(); err != nil {
				log.Printf("FLOW ERROR [%s] commit: %s", flow.Name, err)
				ctx.Error = err
			}
		}
	}

	if ctx.Error != nil {
		log.Printf("FLOW ERROR [%s] %s", flow.Name, ctx.Error)
		if !ctx.Stopped {
			http.Error(w, "Internal error", http.StatusInternalServerError)
		}
	}

	// Default response if nothing responded. Pre-v2.3.1 this was a
	// flat 200 + `{"status":"ok"}`, which was disastrous for debugging:
	// a flow whose steps ran but never reached a respond step returned
	// a success-looking body, browsers parsed it as if it were data,
	// and .filter() / .map() calls downstream crashed without anyone
	// knowing the flow was broken. Now we return 500 with a diagnostic
	// so the route's bad state is visible at the network layer.
	if !ctx.Stopped {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		resp := map[string]any{
			"error":          "flow_no_response",
			"flow":           flow.Name,
			"steps_declared": len(flow.Steps),
			"steps_run":      ctx.StepsRun,
		}
		if ctx.Error != nil {
			// A step errored out - surface which one + the error so the
			// agent jumps straight to the failing step. This is the
			// vastly more common case for "no response" in practice.
			resp["failed_step"] = ctx.FailedStep
			resp["failed_type"] = ctx.FailedType
			resp["step_error"] = ctx.Error.Error()
			resp["hint"] = stepFailureHint(ctx.FailedStep, ctx.FailedType, ctx.Error.Error())
		} else {
			resp["hint"] = "every step ran without erroring, but no step was a `run: respond` (or `run: redirect`). Add a `- run: respond` step at the end of the job, with `with: { status: 200, body: { ok: true } }`."
		}
		json.NewEncoder(w).Encode(resp)
	}
}

// quoteForHint returns `"name"` for non-empty names, or `(unnamed)` so
// the hint sentence reads cleanly when the step had no id/name.
func quoteForHint(s string) string {
	if s == "" {
		return "(unnamed)"
	}
	return `"` + s + `"`
}

// stepFailureHint returns a tailored remediation hint based on the
// step type that failed. Pre-2.7.37 every step emitted the same generic
// boilerplate; agents re-read it every time without learning anything
// useful. Now each step type has its own diagnostic pointer.
func stepFailureHint(name, stepType, errMsg string) string {
	prefix := "step " + quoteForHint(name) + " (run: " + stepType + ") errored before any respond step ran. "
	em := strings.ToLower(errMsg)
	switch stepType {
	case "sql":
		switch {
		case strings.Contains(em, "no such table"):
			return prefix + "The table doesn't exist yet. Add it to schema.prisma (the table name is pluralized: Note → notes, Category → categories), then restart so migrations apply. Query sqlite_master to see what tables exist."
		case strings.Contains(em, "no such column"):
			return prefix + "The column doesn't exist on the table. Pull the schema with `describe_table` to see the live columns. If you just added the field to schema.prisma, push schema.prisma so the migration applies before this flow runs."
		case strings.Contains(em, "malformed json"):
			return prefix + "json_each() / json_extract() got a value that isn't valid JSON. Most common cause: passing a complex `${{ X }}` reference through a pipe that string-coerces. v2.7.35+ JSON-encodes typed slices/maps automatically; if you're still seeing this, the value is probably literal text that doesn't parse - log the param value via a debug `respond:` step to inspect."
		case strings.Contains(em, "not null constraint failed"):
			return prefix + "A column was declared NOT NULL but the INSERT didn't supply it. Either provide the value, add a `@default(...)` to the Prisma field, or make the field nullable with `?`."
		case strings.Contains(em, "unique constraint failed"):
			return prefix + "Duplicate-key violation. Add `ON CONFLICT (...) DO NOTHING` or `ON CONFLICT (...) DO UPDATE SET ...` to make the upsert idempotent, OR pre-check existence before the INSERT."
		}
		return prefix + "Read step_error above for the SQL engine's exact message. Common causes: typo in column/table name, missing migration (push schema.prisma), or a NOT NULL column without a default."
	case "api":
		switch {
		case strings.Contains(em, "ssrf"), strings.Contains(em, "blocked"):
			return prefix + "Outbound URL was blocked by the SSRF guard. The framework refuses to hit private IP ranges (10.0/8, 172.16/12, 192.168/16, 169.254/16) from app code. Use a public endpoint."
		case strings.Contains(em, "success_when failed"):
			return prefix + "The HTTP status was 2xx but the success_when: predicate evaluated false. Inspect the response shape via `steps.<id>.outputs.body` or `.json` - many APIs return 200 with an error envelope (status:'error', code:'forbidden', etc.)."
		case strings.Contains(em, "returned 4"), strings.Contains(em, "returned 5"):
			return prefix + "Upstream returned an error status. Check the `sign:` recipe (auth) and the URL. If this is OAuth, verify the credentials are set in env.yaml."
		case strings.Contains(em, "context deadline exceeded"), strings.Contains(em, "timeout"):
			return prefix + "Upstream timed out. Default HTTP timeout is 30s. If the call legitimately takes longer, add `mode: async` on the route's `on.request` block so the flow runs in the background and the HTTP handler returns 202 immediately."
		}
		return prefix + "Read step_error above for the network-layer cause (timeout, DNS, TLS, status code). For auth failures: check the `sign:` recipe and env vars via `describe_auth`."
	case "parse":
		return prefix + "`run: parse` couldn't read the body. Check (a) format: is the right one (xml / csv / html), (b) the body actually has the shape you expect - log `steps.<upstream>.outputs.body` via a debug respond step to inspect."
	case "respond":
		return prefix + "`run: respond` couldn't render the body. Most common: a `${{ steps.<id>.outputs.<col> }}` reference that didn't resolve. Check unresolved_refs in the error body. Common causes: (a) the upstream step has no `id:` set, (b) the column wasn't in the INSERT/UPDATE's RETURNING clause."
	case "redirect":
		return prefix + "`run: redirect` couldn't compute the `to:` URL. Check that any `${{ ... }}` refs in `to:` resolve."
	case "email":
		return prefix + "Email send failed. Verify EMAIL_FROM is set and the configured provider (Resend / SMTP) has working credentials. `describe_auth` shows the email config."
	case "webhook":
		return prefix + "Webhook delivery failed. Same diagnostics as `run: api` (network, status code, SSRF guard). If the receiver requires HMAC, use `run: api` with a `sign:` recipe instead - `run: webhook` is the legacy unsigned path."
	case "enqueue":
		return prefix + "Couldn't enqueue the background job. Check the target flow name exists and the job-worker table (`_benmore_jobs`) is writable."
	case "if", "for_each", "parallel":
		return prefix + "Control-flow step's expression couldn't be evaluated. For `if:`, check the comparison operands resolve. For `for_each:`, check the iterable source is a slice (not a string)."
	}
	return prefix + "Read step_error above for the upstream cause."
}

// resolveSQLParamValue evaluates a `with.params:` value for a sql step.
// The raw expression has already had its GHA refs normalized to `{{...}}`
// shape; we run interpolateCtx to fully resolve it against the current
// flow context, then string-coerce. Complex values (slices/maps) get
// JSON-encoded so the agent can pair them with SQLite's json_each() /
// json_extract() without an explicit `| json` pipe in the YAML.
//
// The rawExpr is typically a single `{{...}}` placeholder. If it
// resolves to a primitive (string/number/bool), the rendered form is
// used as-is. If it resolves to a slice or map, the resolved value
// (not the rendered string) is JSON-encoded.
//
// Returns (rendered, isNil). isNil is true when a single-placeholder
// expression resolved to Go `nil`; the SQL bind path uses this to
// bind SQL NULL instead of the literal string. Before this signal
// existed, nil values rendered as `"<nil>"` (Go's fmt default) and
// landed in DB columns as the literal three-character string.
func resolveSQLParamValue(rawExpr string, ctx *FlowContext) (string, bool) {
	rendered := interpolateCtx(rawExpr, ctx)
	// Fast path: pure scalar (no leftover template, value already
	// rendered to a primitive string representation). Most params hit
	// this - IDs, status filters, counts.
	trimmed := strings.TrimSpace(rawExpr)
	if !strings.HasPrefix(trimmed, "{{") || !strings.HasSuffix(trimmed, "}}") {
		return rendered, false
	}
	// Single-placeholder form: check the raw value type in ctx.Data so
	// slices/maps can be JSON-encoded.
	inner := strings.TrimSpace(trimmed[2 : len(trimmed)-2])
	// Strip any pipe chain - `{{ x | length }}` always produces a
	// string from ApplyPipe, never nil.
	key := inner
	if pipeIdx := strings.Index(inner, "|"); pipeIdx >= 0 {
		key = strings.TrimSpace(inner[:pipeIdx])
		// Piped expressions don't go through the nil-checks below.
		flat := flattenData(ctx.Data)
		if _, exists := flat[key]; exists {
			return rendered, false
		}
		return rendered, false
	}
	flat := flattenData(ctx.Data)
	if v, ok := flat[key]; ok {
		if v == nil {
			return "", true
		}
		switch v.(type) {
		case []any, []map[string]any, map[string]any:
			if b, err := json.Marshal(v); err == nil {
				return string(b), false
			}
		}
	}
	return rendered, false
}

func executeSteps(ctx *FlowContext, steps []FlowStep) {
	for _, step := range steps {
		if ctx.Stopped {
			return
		}

		var err error
		retries := step.Retry
		if retries == 0 {
			retries = 1
		}

		for attempt := 0; attempt < retries; attempt++ {
			err = executeStep(ctx, &step)
			if err == nil {
				break
			}
			if attempt < retries-1 {
				delay := step.RetryDelay
				if delay == 0 {
					delay = 2 * time.Second
				}
				time.Sleep(delay)
			}
		}

		ctx.StepsRun++
		if err != nil {
			ctx.Error = err
			if step.Name != "" {
				ctx.FailedStep = step.Name
			} else {
				ctx.FailedStep = step.Type
			}
			ctx.FailedType = step.Type
			// Run on_error steps
			if len(step.OnError) > 0 {
				ctx.Data["error"] = err.Error()
				errCtx := &FlowContext{App: ctx.App, Data: ctx.Data, Params: ctx.Params}
				executeSteps(errCtx, step.OnError)
			}
			return
		}
	}
}

func executeStep(ctx *FlowContext, step *FlowStep) error {
	// Reset the per-step missing-ref tally. Interpolators called by the
	// concrete step handler will append any unresolved `${{ ... }}`
	// expressions; we check after the step runs and halt the flow if
	// any remain. Two reasons for the post-step check rather than a
	// hard error mid-interpolation:
	//   1. The interpolators are called from ~30 sites with non-error
	//      return signatures; threading errors through every caller
	//      would be a large invasive change for the same effect.
	//   2. A single step may interpolate multiple fields (respond body
	//      with 8 keys, headers, query string); collecting all the
	//      misses lets us report them together instead of failing on
	//      the first one and re-running to find the next.
	ctx.takeMissingRefs()

	var err error
	switch step.Type {
	case "sql":
		err = execStepSQL(ctx, step)
	case "sql_dynamic":
		err = execStepSQLDynamic(ctx, step)
	case "api":
		err = execStepAPI(ctx, step)
	case "webhook":
		err = execStepWebhook(ctx, step)
	case "ws":
		err = execStepWS(ctx, step)
	case "enqueue":
		err = execStepEnqueue(ctx, step)
	case "email":
		err = execStepEmail(ctx, step)
	case "redirect":
		err = execStepRedirect(ctx, step)
	case "respond":
		err = execStepRespond(ctx, step)
	case "serve_file":
		err = execStepServeFile(ctx, step)
	case "if":
		err = execStepIf(ctx, step)
	case "for_each":
		err = execStepForEach(ctx, step)
	case "set":
		err = execStepSet(ctx, step)
	case "parse":
		err = execStepParse(ctx, step)
	case "parallel":
		err = execStepParallel(ctx, step)
	case "compute":
		err = execStepCompute(ctx, step)
	default:
		return fmt.Errorf("unknown step type: %s", step.Type)
	}

	// If the step itself errored, preserve that error - the caller's
	// FailedStep diagnostic is more useful when it names the original
	// failure, not "after-the-fact unresolved refs."
	if err != nil {
		return err
	}

	// Surface any unresolved templates the step's interpolations left
	// behind. Composite steps (parallel / for_each / if) call
	// executeStep recursively for each child; the recursive call's
	// dispatcher handles the missing-ref check for that child, so by
	// the time we get back here only the outer step's *own* template
	// fields remain in MissingRefs.
	if missing := ctx.takeMissingRefs(); len(missing) > 0 {
		stepLabel := step.Name
		if stepLabel == "" {
			stepLabel = step.Type
		}
		return fmt.Errorf(
			"unresolved template reference(s) in step %q: %s - "+
				"these `${{ ... }}` expressions had no value in scope when "+
				"the step ran. Common causes: (a) a previous step's id "+
				"is misspelled or missing, (b) `INSERT … RETURNING` was "+
				"expected to expose values via `steps.X.outputs.<col>` "+
				"but the SQL step didn't capture them - check that the "+
				"capturing step has an `id:` and that RETURNING includes "+
				"the column you reference, (c) `${{ user.<field> }}` is "+
				"referenced but the column doesn't exist on _benmore_users "+
				"or the route isn't `auth: required`",
			stepLabel, strings.Join(missing, ", "),
		)
	}
	return nil
}

// execStepParallel runs all child steps concurrently and waits for
// every one to finish. Used to overlap independent outbound calls -
// the canonical case is a unified endpoint that fans out to three
// carrier APIs. Sequential fan-out (one carrier after another) was
// the dominant cost in a live demo; parallel cuts the
// load time from sum-of-latencies to max-of-latencies.
//
// Each child's output still lands at ctx.Data[step.Name] like any
// sequential step. Concurrent writes to ctx.Data are serialized by
// ctx.dataMu (added below). Errors from any branch fail the whole
// parallel block - the first error wins; remaining branches finish
// then results are discarded.
func execStepParallel(ctx *FlowContext, step *FlowStep) error {
	if len(step.Steps) == 0 {
		return nil
	}
	var wg sync.WaitGroup
	errCh := make(chan error, len(step.Steps))
	for i := range step.Steps {
		wg.Add(1)
		child := step.Steps[i]
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					errCh <- fmt.Errorf("parallel branch %q panicked: %v", child.Name, r)
				}
			}()
			if err := executeStep(ctx, &child); err != nil {
				errCh <- err
			}
		}()
	}
	wg.Wait()
	close(errCh)
	for err := range errCh {
		if err != nil {
			return err
		}
	}
	return nil
}

// flowDB returns the transaction if active, otherwise the app database.
func flowDB(ctx *FlowContext) interface {
	Exec(query string, args ...any) (sql.Result, error)
	Query(query string, args ...any) (*sql.Rows, error)
	QueryRow(query string, args ...any) *sql.Row
} {
	if ctx.Tx != nil {
		return ctx.Tx
	}
	return ctx.App.DB
}

func execStepSQL(ctx *FlowContext, step *FlowStep) error {
	// Resolve any explicit step-local params (`with.params:` in the
	// flow YAML) and merge them into ctx.Params for the duration of
	// this step. interpolateCtxSafe reads `:name` placeholders from
	// ctx.Params, so this is the simplest plumbing. Complex values
	// (slice/map) are JSON-encoded so they pair with SQLite's
	// json_each() / json_extract() without any extra agent ceremony.
	var restoreParams func()
	if len(step.SQLParams) > 0 {
		backup := make(map[string]string, len(step.SQLParams))
		backupNull := make(map[string]bool, len(step.SQLParams))
		for k := range step.SQLParams {
			if old, ok := ctx.Params[k]; ok {
				backup[k] = old
			}
			if ctx.NullParams != nil {
				if wasNull, ok := ctx.NullParams[k]; ok {
					backupNull[k] = wasNull
				}
			}
		}
		if ctx.NullParams == nil {
			ctx.NullParams = make(map[string]bool, len(step.SQLParams))
		}
		for k, rawExpr := range step.SQLParams {
			val, isNil := resolveSQLParamValue(rawExpr, ctx)
			ctx.Params[k] = val
			if isNil {
				ctx.NullParams[k] = true
			} else {
				delete(ctx.NullParams, k)
			}
		}
		restoreParams = func() {
			for k := range step.SQLParams {
				if old, ok := backup[k]; ok {
					ctx.Params[k] = old
				} else {
					delete(ctx.Params, k)
				}
				if wasNull, ok := backupNull[k]; ok {
					ctx.NullParams[k] = wasNull
				} else {
					delete(ctx.NullParams, k)
				}
			}
		}
		defer restoreParams()
	}

	// Use safe interpolation to prevent SQL injection from external data
	query, args := interpolateCtxSafe(step.SQL, ctx)
	db := flowDB(ctx)

	// Detect statement shape. SELECT and any mutation that carries a
	// `RETURNING …` clause both produce rows; route them through Query
	// so ctx.Data[step.Name] captures the values exactly the way
	// `${{ steps.X.outputs.<col> }}` expects. Pre-v2.7.5 every non-
	// SELECT went to db.Exec, which silently dropped RETURNING output
	// - agents wrote
	//   `INSERT … RETURNING id` followed by `${{ steps.ws.outputs.id }}`
	// expecting it to work (it matches every other SQL framework's
	// shape), found `{{ws.id}}` leaking literally into responses,
	// and then had to rewrite as INSERT + follow-up SELECT.
	//
	// Detection is regex-free on purpose: `\bRETURNING\b` test against
	// the uppercased query, after a quick prefix check so we don't pay
	// the scan cost on the common SELECT path.
	//
	// THREE row-producing shapes:
	//   1. `SELECT …` - plain query
	//   2. `WITH foo AS (…) SELECT …` - CTE. Pre-v2.7.6 the prefix
	//      check missed this (starts with WITH, not SELECT), so every
	//      CTE-shaped step landed in db.Exec and the output silently
	//      vanished. Every agent writing non-trivial business rules
	//      hit this - risk-gate calcs (`WITH ref AS …, calc AS …
	//      SELECT …`) are the canonical case. An earlier app build
	//      worked around it by rewriting CTEs as nested subqueries.
	//   3. `INSERT/UPDATE/DELETE … RETURNING …` - already handled by
	//      hasReturningClause since v2.7.5.
	//
	// db.Query is safe for any statement type in SQLite - non-row-
	// producing variants just return an empty result set, no error.
	upper := strings.TrimSpace(strings.ToUpper(query))
	startsWithRowProducer := strings.HasPrefix(upper, "SELECT") ||
		strings.HasPrefix(upper, "WITH")
	hasReturning := !startsWithRowProducer && hasReturningClause(upper)
	// Serialize the actual DB call when running inside a transaction:
	// *sql.Tx is not safe for concurrent use, so a `parallel:` block of
	// SQL steps inside a `transaction: true` flow would otherwise race.
	// The DB pool (ctx.Tx == nil path) is already concurrency-safe, so we
	// only pay the lock on the transactional path.
	if ctx.Tx != nil {
		ctx.TxMu.Lock()
		defer ctx.TxMu.Unlock()
	}
	if startsWithRowProducer || hasReturning {
		sqlRows, err := db.Query(query, args...)
		if err != nil {
			return fmt.Errorf("sql: %w", err)
		}
		rows, _ := scanRows(sqlRows)
		if step.Name != "" {
			// Always store as a slice. Pre-v2.3.2 we collapsed a
			// single-row result into a bare map at ctx.Data[step.Name]
			// - that was nice for `{{step.field}}` templates after a
			// single-row WHERE id = :id query, but it made
			// `outputs.rows` / `outputs.*` templates return an object
			// instead of a 1-element array when there was exactly one
			// match. Frontend code then had to handle both shapes.
			//
			// flattenData below restores the per-field shortcut for
			// the 1-row case, so `{{step.field}}` still works AND
			// `{{step.rows}}` returns a real slice.
			ctx.DataMu.Lock()
			ctx.Data[step.Name] = rows
			ctx.DataMu.Unlock()
		}
	} else {
		if _, err := db.Exec(query, args...); err != nil {
			return fmt.Errorf("sql: %w", err)
		}
	}
	return nil
}

// hasReturningClause reports whether the (already-uppercased) query
// contains a `RETURNING …` clause as a standalone keyword. We do a
// substring match guarded by simple word-boundary checks so an
// identifier or string literal that happens to contain "RETURNING"
// doesn't trip the detector. The guard is intentionally permissive:
// `RETURNING` is so uncommon outside its SQL keyword usage that a
// false positive would only land if someone named a column `returning`
// AND referenced it as a bare identifier in a non-RETURNING statement
// - vanishingly rare and the worst outcome is a Query call instead
// of an Exec call on a mutation, which still executes correctly.
func hasReturningClause(upperQuery string) bool {
	const kw = "RETURNING"
	idx := strings.Index(upperQuery, kw)
	if idx < 0 {
		return false
	}
	// Require a non-identifier char before the keyword (start of string
	// or whitespace/punctuation). Without this, an identifier ending in
	// "RETURNING" (e.g. a column literally named `is_returning`) would
	// match.
	if idx > 0 {
		prev := upperQuery[idx-1]
		if (prev >= 'A' && prev <= 'Z') || (prev >= '0' && prev <= '9') || prev == '_' {
			return false
		}
	}
	// Require a non-identifier char after the keyword.
	end := idx + len(kw)
	if end < len(upperQuery) {
		next := upperQuery[end]
		if (next >= 'A' && next <= 'Z') || (next >= '0' && next <= '9') || next == '_' {
			return false
		}
	}
	return true
}

// execStepSQLDynamic is the text-interpolation counterpart to
// execStepSQL. It uses interpolateCtx (which substitutes `{{ ... }}`
// values as raw text into the query string) instead of
// interpolateCtxSafe (which replaces them with `?` placeholders and
// binds values). This is the only path that lets an AI agent's
// generated SQL actually execute: a query string cannot be
// param-bound into itself.
//
// SECURITY: the resolved query is logged and the WHOLE statement is
// inherently injection-shaped - `{{ q }}` becomes literal SQL bytes,
// not a bound value. Use only when the SQL is assembled by trusted
// internal callers (LLM agent flow, admin tooling). NEVER funnel
// user-typed input through this path.
func execStepSQLDynamic(ctx *FlowContext, step *FlowStep) error {
	// Same per-step param overlay as execStepSQL - but written into
	// BOTH ctx.Params (for `:name` placeholders) AND ctx.Data (for
	// `{{name}}` text substitutions, which is the dominant form in
	// sql_dynamic since the whole point is text interpolation).
	// Restored on exit so the overlay doesn't leak into siblings.
	var restoreParams func()
	if len(step.SQLParams) > 0 {
		paramBackup := make(map[string]string, len(step.SQLParams))
		dataBackup := make(map[string]any, len(step.SQLParams))
		dataHad := make(map[string]bool, len(step.SQLParams))
		ctx.DataMu.Lock()
		for k := range step.SQLParams {
			if old, ok := ctx.Params[k]; ok {
				paramBackup[k] = old
			}
			if old, ok := ctx.Data[k]; ok {
				dataBackup[k] = old
				dataHad[k] = true
			}
		}
		for k, rawExpr := range step.SQLParams {
			resolved, _ := resolveSQLParamValue(rawExpr, ctx)
			// sql_dynamic is text-substitution only - NULL has no
			// stable serialization in raw SQL bytes anyway. Resolved
			// empty string is the closest sensible value for nil here.
			ctx.Params[k] = resolved
			ctx.Data[k] = resolved
		}
		ctx.DataMu.Unlock()
		restoreParams = func() {
			ctx.DataMu.Lock()
			defer ctx.DataMu.Unlock()
			for k := range step.SQLParams {
				if old, ok := paramBackup[k]; ok {
					ctx.Params[k] = old
				} else {
					delete(ctx.Params, k)
				}
				if dataHad[k] {
					ctx.Data[k] = dataBackup[k]
				} else {
					delete(ctx.Data, k)
				}
			}
		}
		defer restoreParams()
	}

	query := interpolateCtx(step.SQL, ctx)
	db := flowDB(ctx)

	// Log the resolved query - sql_dynamic is high-risk; surfacing the
	// final SQL into the request log makes audits/reviews tractable.
	log.Printf("flows: sql_dynamic step=%q query=%q", step.Name, query)

	// Same prefix detection as execStepSQL - SELECT, WITH (CTE), or
	// INSERT/UPDATE/DELETE … RETURNING all produce rows we want to
	// capture into ctx.Data[step.Name]. See the longer comment in
	// execStepSQL for context.
	upper := strings.TrimSpace(strings.ToUpper(query))
	startsWithRowProducer := strings.HasPrefix(upper, "SELECT") ||
		strings.HasPrefix(upper, "WITH")
	hasReturning := !startsWithRowProducer && hasReturningClause(upper)
	if startsWithRowProducer || hasReturning {
		sqlRows, err := db.Query(query)
		if err != nil {
			return fmt.Errorf("sql_dynamic: %w", err)
		}
		rows, _ := scanRows(sqlRows)
		if step.Name != "" {
			ctx.DataMu.Lock()
			ctx.Data[step.Name] = rows
			ctx.DataMu.Unlock()
		}
	} else {
		if _, err := db.Exec(query); err != nil {
			return fmt.Errorf("sql_dynamic: %w", err)
		}
	}
	return nil
}

func execStepAPI(ctx *FlowContext, step *FlowStep) error {
	api := step.API
	if api == nil {
		return fmt.Errorf("api step has no config")
	}
	// Pagination wrapper: loops the single-shot path until the upstream
	// runs out of pages, accumulates items, sets the step output to
	// { items: [...], pages_fetched: N }. Without this, every flow with
	// a hardcoded `?limit=500` would silently drop data past the cap.
	if api.Paginate != nil {
		return execStepAPIPaginated(ctx, step)
	}

	url := interpolateCtx(api.URL, ctx)
	url = InterpolateEnv(url, ctx.App.Dir)

	// Append `with.query:` params to the URL. Keys + values are
	// percent-encoded; values flow through ctx interpolation + env so
	// `${{ user.customer_id }}` or `${{ env.X }}` resolve here.
	if len(api.Query) > 0 {
		sep := "?"
		if strings.Contains(url, "?") {
			sep = "&"
		}
		var parts []string
		for k, v := range api.Query {
			resolved := InterpolateEnv(interpolateCtx(v, ctx), ctx.App.Dir)
			parts = append(parts, neturl.QueryEscape(k)+"="+neturl.QueryEscape(resolved))
		}
		url += sep + strings.Join(parts, "&")
	}

	// SSRF protection: block requests to private/internal IPs.
	if isPrivateURL(url) {
		return fmt.Errorf("SECURITY: blocked API request to private URL: %s", url)
	}

	var body io.Reader
	var bodyBytes []byte // captured for signers that hash the payload (AWS sigv4 etc.)
	contentType := "application/json"

	if api.JSON != nil {
		jsonData := make(map[string]string)
		for k, v := range api.JSON {
			jsonData[k] = interpolateCtx(v, ctx)
		}
		bodyBytes, _ = json.Marshal(jsonData)
		body = bytes.NewReader(bodyBytes)
	} else if api.Form != nil {
		var formParts []string
		for k, v := range api.Form {
			formParts = append(formParts, fmt.Sprintf("%s=%s", k, interpolateCtx(v, ctx)))
		}
		bodyBytes = []byte(strings.Join(formParts, "&"))
		body = bytes.NewReader(bodyBytes)
		contentType = "application/x-www-form-urlencoded"
	} else if api.Body != "" {
		bodyBytes = []byte(interpolateCtx(api.Body, ctx))
		body = bytes.NewReader(bodyBytes)
	}

	method := api.Method
	if method == "" {
		method = "GET"
	}

	// Circuit breaker: skip if endpoint is known-dead
	host := extractHost(url)
	if err := CheckCircuit(host); err != nil {
		return fmt.Errorf("api %s: %s", url, err)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		return fmt.Errorf("api: %w", err)
	}
	req.Header.Set("Content-Type", contentType)

	if api.Auth != "" {
		auth := InterpolateEnv(interpolateCtx(api.Auth, ctx), ctx.App.Dir)
		req.Header.Set("Authorization", auth)
	}
	for k, v := range api.Headers {
		req.Header.Set(k, InterpolateEnv(interpolateCtx(v, ctx), ctx.App.Dir))
	}

	// Pluggable outbound signing - interpolates bindings against the
	// flow context + env, then runs the recipe (named built-in or
	// inline). The recipe mutates req headers / query before send.
	// bodyBytes is the source-of-truth payload for hashing.
	if api.Sign != nil {
		signCfg := *api.Sign // shallow copy
		if api.Sign.Bindings != nil {
			interpolated := make(map[string]string, len(api.Sign.Bindings))
			for k, v := range api.Sign.Bindings {
				interpolated[k] = InterpolateEnv(interpolateCtx(v, ctx), ctx.App.Dir)
			}
			signCfg.Bindings = interpolated
		}
		if err := applySigner(req, bodyBytes, &signCfg, ctx.App); err != nil {
			return fmt.Errorf("api %s: %w", url, err)
		}
	}

	timeout := 30 * time.Second
	if step.Timeout > 0 {
		timeout = step.Timeout
	}
	client := safeHTTPClientStrict(timeout)

	resp, err := client.Do(req)
	if err != nil {
		RecordFailure(host)
		return fmt.Errorf("api %s: %w", url, err)
	}
	defer resp.Body.Close()

	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if resp.StatusCode >= 500 {
		RecordFailure(host)
	} else {
		RecordSuccess(host)
	}

	if resp.StatusCode >= 400 {
		return fmt.Errorf("api %s returned %d: %s", url, resp.StatusCode, string(respBody[:min(len(respBody), 200)]))
	}

	if step.Name != "" {
		envelope := buildAPIResponseEnvelope(resp.StatusCode, resp.Header, respBody)
		ctx.DataMu.Lock()
		ctx.Data[step.Name] = envelope
		flattenIntoCtx(ctx.Data, step.Name, envelope)
		ctx.DataMu.Unlock()
	}

	// success_when: predicate evaluated against the just-stored
	// response envelope. Catches the "API returned 200 + error
	// envelope" shape where the HTTP status alone lies (rss2json,
	// several CRM webhooks). Multiple real apps both ingested
	// error envelopes as data because the step claimed success.
	if step.API != nil && step.API.SuccessWhen != "" {
		if !evaluateFlowCondition(step.API.SuccessWhen, ctx) {
			return fmt.Errorf(
				"api: success_when failed (%s) - response was %d but the predicate evaluated false; check the response body via steps.%s.outputs.body",
				step.API.SuccessWhen, resp.StatusCode, step.Name,
			)
		}
	}

	return nil
}

// buildAPIResponseEnvelope assembles the per-step output map that
// `${{ steps.<id>.outputs.<field> }}` reads from for a `run: api`
// step. Pulled out so the response-shaping logic can be unit-tested
// without standing up the network path (httptest binds to loopback,
// which the SSRF guard rightly rejects).
//
// Envelope shape - every key matches the build doc's promised access:
//   - status  (int):     HTTP status code
//   - body    (string):  raw response body
//   - headers (map):     response headers, single-value headers flattened
//                        to a scalar, multi-value headers stay as []string
//   - json    (any):     parsed body when the response is valid JSON;
//                        omitted otherwise
//
// Back-compat: when the body parses to a JSON object, its top-level
// fields are aliased onto the envelope directly so legacy flows that
// read `${{ steps.<id>.outputs.<field> }}` (without the `.json.`
// prefix) keep working. Conflicts with the four envelope keys
// (status/body/headers/json) leave the envelope key intact.
// execStepAPIPaginated loops the API call until the upstream stops
// returning items (or the next-cursor goes empty), accumulating items
// across pages into one combined slice. Step output is
// `{ items: [...], pages_fetched: N, last_status: 200 }`.
//
// Safety: hard-capped by MaxPages (default 50, cap 500) - silly upstreams
// that return one item per page can't lock the worker.
// Mutates a local copy of api.Query each iteration; the original step
// config is left untouched so concurrent invocations stay independent.
func execStepAPIPaginated(ctx *FlowContext, step *FlowStep) error {
	pag := step.API.Paginate
	strategy := pag.Strategy
	if strategy == "" {
		strategy = "cursor"
	}
	maxPages := pag.MaxPages
	if maxPages <= 0 {
		maxPages = 50
	}
	if maxPages > 500 {
		maxPages = 500
	}
	itemsField := pag.ItemsField
	if itemsField == "" {
		itemsField = "$.items" // sensible default
	}

	// Per-iteration copy of api.Query so we can mutate cursor/page
	// values without affecting the source step config.
	baseQuery := map[string]string{}
	for k, v := range step.API.Query {
		baseQuery[k] = v
	}

	var accum []any
	var lastStatus int
	page := pag.PageStart
	if page <= 0 {
		page = 1
	}
	cursor := ""

	for i := 0; i < maxPages; i++ {
		iterQuery := map[string]string{}
		for k, v := range baseQuery {
			iterQuery[k] = v
		}
		switch strategy {
		case "cursor":
			cp := pag.CursorParam
			if cp == "" {
				cp = "cursor"
			}
			if cursor != "" {
				iterQuery[cp] = cursor
			}
		case "page":
			pp := pag.PageParam
			if pp == "" {
				pp = "page"
			}
			iterQuery[pp] = fmt.Sprintf("%d", page)
		default:
			return fmt.Errorf("paginate: unknown strategy %q (use 'cursor' or 'page')", strategy)
		}

		// Build a single-shot step for this iteration. Reuses
		// execStepAPI's single-request path by temporarily swapping
		// the Query map; restored before next iteration.
		origQuery := step.API.Query
		step.API.Query = iterQuery
		// Suppress recursion: clear the Paginate pointer for the inner
		// call so it takes the single-shot branch.
		origPaginate := step.API.Paginate
		step.API.Paginate = nil
		err := execStepAPI(ctx, step)
		step.API.Query = origQuery
		step.API.Paginate = origPaginate
		if err != nil {
			return err
		}

		// Pull the envelope back from ctx.Data, extract items + cursor.
		ctx.DataMu.Lock()
		var envelope any
		if step.Name != "" {
			envelope = ctx.Data[step.Name]
		}
		ctx.DataMu.Unlock()

		items, cur, status := extractPageItems(envelope, itemsField, pag.CursorField)
		lastStatus = status
		if len(items) == 0 {
			break
		}
		accum = append(accum, items...)
		if strategy == "cursor" {
			if cur == "" {
				break // upstream done
			}
			cursor = cur
		} else {
			page++
		}
	}

	// Set the accumulated output. Overwrites the single-shot envelope.
	if step.Name != "" {
		ctx.DataMu.Lock()
		out := map[string]any{
			"items":         accum,
			"pages_fetched": len(accum) / max(1, len(accum)/maxPages+1), // best-effort
			"item_count":    len(accum),
			"last_status":   lastStatus,
		}
		ctx.Data[step.Name] = out
		flattenIntoCtx(ctx.Data, step.Name, out)
		ctx.DataMu.Unlock()
	}
	return nil
}

// extractPageItems pulls (items, nextCursor, statusCode) out of an
// API-step envelope based on the configured JSON paths. Lenient about
// shape: items_field can point at a top-level array or a nested one;
// cursor_field is treated as a plain dotted path under the JSON body.
// Returns zero items when paths don't resolve - the paginator treats
// that as "we're done."
func extractPageItems(envelope any, itemsField, cursorField string) ([]any, string, int) {
	envMap, _ := envelope.(map[string]any)
	if envMap == nil {
		return nil, "", 0
	}
	status, _ := envMap["status"].(int)
	body, _ := envMap["json"]
	if body == nil {
		// Try parsing the raw body if json didn't pre-parse.
		if raw, ok := envMap["body"].(string); ok && raw != "" {
			var parsed any
			if json.Unmarshal([]byte(raw), &parsed) == nil {
				body = parsed
			}
		}
	}
	items := lookupJSONPath(body, itemsField)
	itemsSlice, _ := items.([]any)
	cursor := ""
	if cursorField != "" {
		if v := lookupJSONPath(body, cursorField); v != nil {
			cursor = fmt.Sprintf("%v", v)
		}
	}
	return itemsSlice, cursor, status
}

// lookupJSONPath is a tiny dotted-path resolver: "$.foo.bar" reads
// body.foo.bar. Supports the leading "$." or bare-dotted form. No array
// indexing - agents who need that should use json_extract() in SQL
// instead.
func lookupJSONPath(body any, path string) any {
	if body == nil || path == "" {
		return nil
	}
	path = strings.TrimPrefix(path, "$.")
	path = strings.TrimPrefix(path, "$")
	cur := body
	for _, seg := range strings.Split(path, ".") {
		if seg == "" {
			continue
		}
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = m[seg]
	}
	return cur
}

func buildAPIResponseEnvelope(statusCode int, header http.Header, respBody []byte) map[string]any {
	hdrs := make(map[string]any, len(header))
	for k, v := range header {
		if len(v) == 1 {
			hdrs[k] = v[0]
		} else {
			hdrs[k] = v
		}
	}
	envelope := map[string]any{
		"status":  statusCode,
		"body":    string(respBody),
		"headers": hdrs,
	}
	var parsed any
	if err := json.Unmarshal(respBody, &parsed); err == nil {
		envelope["json"] = parsed
		if m, ok := parsed.(map[string]any); ok {
			for k, v := range m {
				if _, taken := envelope[k]; !taken {
					envelope[k] = v
				}
			}
		}
	}
	return envelope
}

func execStepWebhook(ctx *FlowContext, step *FlowStep) error {
	url := InterpolateEnv(interpolateCtx(step.Webhook, ctx), ctx.App.Dir)

	// SSRF protection: block requests to private/internal IPs
	if isPrivateURL(url) {
		return fmt.Errorf("SECURITY: blocked webhook to private URL: %s", url)
	}

	body := interpolateCtx(step.WebhookBody, ctx)
	if body == "" {
		data, _ := json.Marshal(ctx.Data)
		body = string(data)
	}

	req, err := http.NewRequest("POST", url, strings.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")

	client := safeHTTPClientStrict(10 * time.Second)
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}

// execStepEnqueue inserts a job into _benmore_jobs. The named flow
// is invoked later by the background worker - out-of-band from the
// request lifecycle, so it can run for minutes/hours without
// blocking. Payload is interpolated from the current flow context.
func execStepEnqueue(ctx *FlowContext, step *FlowStep) error {
	if step.Enqueue == nil || step.Enqueue.Flow == "" {
		return fmt.Errorf("enqueue step requires flow:")
	}
	flowName := interpolateCtx(step.Enqueue.Flow, ctx)
	payload := map[string]any{}
	for k, v := range step.Enqueue.With {
		payload[k] = interpolateCtx(v, ctx)
	}
	var runAt *time.Time
	if step.Enqueue.RunAt != "" {
		v := interpolateCtx(step.Enqueue.RunAt, ctx)
		if t, err := time.Parse(time.RFC3339, v); err == nil {
			runAt = &t
		}
	}
	var (
		id       int64
		jobToken string
		err      error
	)
	if ctx.Tx != nil {
		// Serialize Tx access: a `parallel:` block inside a transactional
		// flow may enqueue concurrently, and *sql.Tx is not safe for
		// concurrent use. See FlowContext.TxMu.
		ctx.TxMu.Lock()
		id, jobToken, err = EnqueueJobTx(ctx.Tx, flowName, payload, runAt)
		ctx.TxMu.Unlock()
	} else {
		id, jobToken, err = EnqueueJob(ctx.App.DB, flowName, payload, runAt)
	}
	if err != nil {
		return fmt.Errorf("enqueue %s: %w", flowName, err)
	}
	if ctx.Data == nil {
		ctx.Data = map[string]any{}
	}
	if step.Name != "" {
		// Expose status_token so a respond step can build a pollable
		// status_url: /api/_jobs/${{steps.x.outputs.job_id}}/status?token=${{steps.x.outputs.status_token}}
		ctx.Data[step.Name] = map[string]any{"job_id": id, "flow": flowName, "status_token": jobToken}
	}
	return nil
}

// execStepWS broadcasts a payload to every WebSocket client joined
// to the named room. Room IDs interpolate flow context variables and
// are scope-namespaced server-side, so a flow firing
// room="order-{{order_id}}" reaches every authenticated client in
// the matching group/user scope. Payload defaults to the full
// JSON-serialized context when not supplied, matching the webhook
// step's convention.
func execStepWS(ctx *FlowContext, step *FlowStep) error {
	if step.WS == nil || step.WS.Room == "" {
		return fmt.Errorf("ws step requires room")
	}
	room := interpolateCtx(step.WS.Room, ctx)
	if room == "" {
		return fmt.Errorf("ws step room interpolated to empty string")
	}
	payload := interpolateCtx(step.WS.Payload, ctx)
	if payload == "" {
		data, _ := json.Marshal(ctx.Data)
		payload = string(data)
	}
	BroadcastWSToRoomGlobal(room, payload)
	return nil
}

func execStepEmail(ctx *FlowContext, step *FlowStep) error {
	if step.Email == nil {
		return fmt.Errorf("email step has no config")
	}
	to := interpolateCtx(step.Email.To, ctx)
	subject := interpolateCtx(step.Email.Subject, ctx)

	html, text, err := resolveEmailBody(ctx, step.Email)
	if err != nil {
		return err
	}

	appDir := ""
	if ctx.App != nil {
		appDir = ctx.App.Dir
	}
	return SendEmailOpts(appDir, EmailOpts{To: to, Subject: subject, BodyHTML: html, BodyText: text})
}

// emailTemplateCandidates returns the relative paths tried for an email
// step's `template:` value, in order. A bare name resolves like hook
// emails do (emails/<name>.html), so `template: external-invite`,
// `template: external-invite.html`, and `template: emails/external-invite.html`
// all reach the same file; templates/ is the other carve-out dir for
// full-HTML email bodies.
func emailTemplateCandidates(tmpl string) []string {
	candidates := []string{tmpl}
	if !strings.HasSuffix(tmpl, ".html") {
		candidates = append(candidates, tmpl+".html")
	}
	if !strings.Contains(tmpl, "/") {
		for _, dir := range []string{"emails", "templates"} {
			candidates = append(candidates, filepath.Join(dir, tmpl))
			if !strings.HasSuffix(tmpl, ".html") {
				candidates = append(candidates, filepath.Join(dir, tmpl+".html"))
			}
		}
	}
	return candidates
}

// resolveEmailBody produces the HTML + plain-text bodies for an email
// step. Pre-v2.7.165 this logic only honored `template:` as a literal
// app-root path and passed everything else through as an empty body -
// the provider request then carried no html/text at all and Resend
// 422'd the flow ("Missing 'html' or 'text' field").
func resolveEmailBody(ctx *FlowContext, email *FlowEmail) (html, text string, err error) {
	if email.Html != "" {
		html = interpolateCtx(email.Html, ctx)
	}
	if email.Text != "" {
		text = interpolateCtx(email.Text, ctx)
	}

	if tmpl := email.Template; tmpl != "" && ctx.App != nil {
		// Render context: the flow's flattened data (+ env overlay) with
		// the step's `data:` map interpolated and overlaid on top.
		renderData := flatDataForCtx(ctx)
		for k, v := range email.Data {
			renderData[k] = interpolateCtx(v, ctx)
		}
		found := false
		candidates := emailTemplateCandidates(tmpl)
		appRoot, _ := filepath.Abs(ctx.App.Dir)
		for _, c := range candidates {
			// Contain the candidate to the app dir (mirrors
			// execStepServeFile's uploads/ guard): `template:` is
			// developer-controlled, but a `..`-shaped value must not read
			// outside the app tree (2026-06-11 audit).
			full, absErr := filepath.Abs(filepath.Join(ctx.App.Dir, c))
			if absErr != nil || (full != appRoot && !strings.HasPrefix(full, appRoot+string(os.PathSeparator))) {
				continue
			}
			raw, readErr := os.ReadFile(full)
			if readErr != nil {
				continue
			}
			html = RenderMustache(stripEmailFrontmatter(string(raw)), renderData)
			found = true
			break
		}
		if !found {
			return "", "", fmt.Errorf("email step: template %q not found (tried %s)", tmpl, strings.Join(candidates, ", "))
		}
	}

	if html == "" && text == "" {
		return "", "", fmt.Errorf("email step has no body: set `template: <name>` (rendered from emails/<name>.html) or an inline `html:` / `text:` on the step - the provider rejects body-less messages")
	}
	return html, text, nil
}

func execStepRedirect(ctx *FlowContext, step *FlowStep) error {
	if ctx.Writer == nil || ctx.Request == nil {
		return nil // not an HTTP-triggered flow
	}
	url := interpolateCtx(step.Redirect, ctx)
	http.Redirect(ctx.Writer, ctx.Request, url, http.StatusSeeOther)
	ctx.Stopped = true
	return nil
}

// execStepServeFile streams a file from the app's uploads/ directory as
// the terminal response. The flow itself is the authorization gate - it
// reads the bytes off disk directly, bypassing the /uploads/ HTTP route
// - so a flow that has already validated (e.g.) a data-room share token
// can serve a PRIVATE file (uploads/private/...) to an anonymous caller
// WITHOUT minting a signed URL. No signed URL escapes to be reshared;
// the gate is the only path to the bytes.
func execStepServeFile(ctx *FlowContext, step *FlowStep) error {
	if ctx.Writer == nil || ctx.Request == nil {
		return nil // not an HTTP-triggered flow
	}
	if step.ServeFile == nil || step.ServeFile.Path == "" {
		return fmt.Errorf("serve_file step missing `path:` - point at an uploaded file, e.g. path: ${{ steps.item.outputs.file_url }}")
	}
	raw := strings.TrimSpace(interpolateCtx(step.ServeFile.Path, ctx))
	if raw == "" {
		http.Error(ctx.Writer, "Not found", http.StatusNotFound)
		ctx.Stopped = true
		return nil
	}
	cfg := getPlatformMedia()

	// Compute the local-disk candidate once (traversal-guarded to uploads/).
	rel := filepath.Clean(strings.TrimPrefix(strings.TrimPrefix(raw, "/"), "uploads/"))
	uploadsRoot := filepath.Join(ctx.App.Dir, "uploads")
	fullPath := filepath.Join(uploadsRoot, rel)
	inUploads := fullPath == uploadsRoot || strings.HasPrefix(fullPath, uploadsRoot+string(os.PathSeparator))
	localExists := false
	if inUploads {
		if info, err := os.Stat(fullPath); err == nil && !info.IsDir() {
			localExists = true
		}
	}
	isCDNURL := cfg != nil && strings.HasPrefix(raw, "https://"+cfg.CDNDomain+"/")

	// CDN backend: serve via a CloudFront redirect - SIGNED + short-TTL for
	// private files (the flow has already authorized this request), plain
	// for public. Bytes never transit the app; the URL is on the cookieless
	// origin. Prefer a still-present LOCAL file over a maybe-missing S3
	// object (pre-migration window): only go to CDN for an actual CDN URL,
	// or a logical path whose local file is absent (migrated / new upload).
	if cfg != nil && (isCDNURL || !localExists) {
		if url, isPrivate, ok := cdnURLForServe(ctx.App, raw, cfg); ok {
			target := url
			if isPrivate {
				expires := time.Now().Add(120 * time.Second).Unix()
				signed, err := signCloudFrontURL(url, expires, cfg.KeyPairID, cfg.PrivateKey)
				if err != nil {
					http.Error(ctx.Writer, "media signing unavailable", http.StatusInternalServerError)
					ctx.Stopped = true
					return nil
				}
				target = signed
			}
			http.Redirect(ctx.Writer, ctx.Request, target, http.StatusFound)
			ctx.Stopped = true
			return nil
		}
	}

	// Local-disk serve (file present on disk, or CDN not configured).
	if !inUploads || !localExists {
		http.Error(ctx.Writer, "Not found", http.StatusNotFound)
		ctx.Stopped = true
		return nil
	}
	// XSS-safe content-type/disposition defaults (forces attachment for
	// active content like .html/.svg even when inline is requested).
	applyUploadDispositionHeaders(ctx.Writer, fullPath)
	// Explicit attachment override (the "Download" affordance) wins.
	if strings.EqualFold(step.ServeFile.Disposition, "attachment") {
		name := step.ServeFile.Filename
		if name == "" {
			name = filepath.Base(fullPath)
		}
		ctx.Writer.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, name))
	} else if step.ServeFile.Filename != "" {
		// Inline with a suggested filename (only set if the safety helper
		// left it inline - i.e. it didn't force an attachment).
		if ctx.Writer.Header().Get("Content-Disposition") == "" {
			ctx.Writer.Header().Set("Content-Disposition", fmt.Sprintf(`inline; filename=%q`, step.ServeFile.Filename))
		}
	}
	// http.ServeFile handles Content-Type, Range requests, and caching.
	http.ServeFile(ctx.Writer, ctx.Request, fullPath)
	ctx.Stopped = true
	return nil
}

func execStepRespond(ctx *FlowContext, step *FlowStep) error {
	if ctx.Writer == nil {
		return nil
	}
	r := step.Respond
	if r == nil {
		return nil
	}
	status := r.Status
	if status == 0 {
		status = 200
	}
	// Bare-template body shortcut. When body is a single `{{var}}` or
	// `{{var.path}}` reference, resolve it from context - including
	// dotted/indexed paths through flattenData - and marshal the
	// resolved value as JSON directly. Closes the gap where every
	// agent's "respond with the rows from my SQL query" intent had to
	// be wrapped as `json: { rows: "{{rows}}" }`.
	if r.Body != "" {
		trimmed := strings.TrimSpace(r.Body)
		if strings.HasPrefix(trimmed, "{{") && strings.HasSuffix(trimmed, "}}") && strings.Count(trimmed, "{{") == 1 {
			key := strings.TrimSpace(trimmed[2 : len(trimmed)-2])
			// Try the flattened path map first so dotted/indexed
			// accesses like `stories.0`, `user.email` resolve.
			flat := flattenData(ctx.Data)
			if ctxVal, ok := flat[key]; ok {
				ctx.Writer.Header().Set("Content-Type", "application/json")
				ctx.Writer.WriteHeader(status)
				json.NewEncoder(ctx.Writer).Encode(ctxVal)
				ctx.Stopped = true
				return nil
			}
			if ctxVal, ok := ctx.Data[key]; ok {
				ctx.Writer.Header().Set("Content-Type", "application/json")
				ctx.Writer.WriteHeader(status)
				json.NewEncoder(ctx.Writer).Encode(ctxVal)
				ctx.Stopped = true
				return nil
			}
			// Bare template that didn't resolve. Fail loudly with a
			// diagnostic that names the missing key + what's actually
			// in ctx.Data. Pre-v2.3.2 we fell through and wrote the
			// literal `{{key}}` to the response - the storyforge
			// debugging session was filled with this footgun.
			keys := make([]string, 0, len(ctx.Data))
			for k := range ctx.Data {
				keys = append(keys, k)
			}
			ctx.Writer.Header().Set("Content-Type", "application/json")
			ctx.Writer.WriteHeader(500)
			json.NewEncoder(ctx.Writer).Encode(map[string]any{
				"error":          "template_unresolved",
				"unresolved_key": key,
				"available_keys": keys,
				"hint":           "the body template referenced {{" + key + "}} but no step produced that key. Check (a) the step that should produce it has `id: <name>` set, (b) the path matches (steps.<id>.outputs / steps.<id>.outputs.rows / steps.<id>.outputs[0]), (c) the step actually ran (no prior step errored). Run describe_flows to see the resolved step list.",
			})
			ctx.Stopped = true
			return nil
		}
	}
	wrote := false
	// Render into a buffer first, then check ctx.MissingRefs, THEN write
	// the response. Pre-v2.7.5 we wrote headers + status before
	// interpolation finished - by the time the dispatcher noticed the
	// unresolved `${{ ... }}` references, a 200 + half-broken body was
	// already on the wire. Now: if any reference failed to resolve, we
	// emit a 500 with a structured `template_unresolved` envelope
	// instead of the half-broken success response.
	if r.JSONArray != nil {
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(r.JSONArray); err != nil {
			return err
		}
		if missing := ctx.takeMissingRefs(); len(missing) > 0 {
			writeRespondUnresolved(ctx.Writer, missing, ctx.Data)
			ctx.Stopped = true
			return nil
		}
		ctx.Writer.Header().Set("Content-Type", "application/json")
		ctx.Writer.WriteHeader(status)
		_, _ = ctx.Writer.Write(buf.Bytes())
		wrote = true
	} else if r.JSON != nil {
		// Interpolate {{var}} placeholders in JSON values before encoding
		resolved := interpolateJSONValues(r.JSON, ctx)
		if missing := ctx.takeMissingRefs(); len(missing) > 0 {
			writeRespondUnresolved(ctx.Writer, missing, ctx.Data)
			ctx.Stopped = true
			return nil
		}
		var buf bytes.Buffer
		if err := json.NewEncoder(&buf).Encode(resolved); err != nil {
			return err
		}
		ctx.Writer.Header().Set("Content-Type", "application/json")
		ctx.Writer.WriteHeader(status)
		_, _ = ctx.Writer.Write(buf.Bytes())
		wrote = true
	} else if r.Body != "" {
		rendered := interpolateCtx(r.Body, ctx)
		if missing := ctx.takeMissingRefs(); len(missing) > 0 {
			writeRespondUnresolved(ctx.Writer, missing, ctx.Data)
			ctx.Stopped = true
			return nil
		}
		ctx.Writer.WriteHeader(status)
		_, _ = ctx.Writer.Write([]byte(rendered))
		wrote = true
	}
	if wrote {
		ctx.Stopped = true
	}
	// If we got here without writing, fall through to the global
	// default-response path in executeFlow (which now emits a 500
	// + flow_no_response diagnostic instead of "status: ok").
	return nil
}

// writeRespondUnresolved emits the 500 envelope the dispatcher uses for
// respond steps whose template body referenced unresolved `${{ ... }}`
// expressions. Lists the missing refs + a sorted snapshot of what was
// in ctx.Data, so the agent can see whether the missing key is a typo,
// a step that didn't run, or a name they expected the framework to
// provide automatically (e.g. an unresolved `${{ user.first_name }}`
// when auth wasn't required on the route).
func writeRespondUnresolved(w http.ResponseWriter, missing []string, data map[string]any) {
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(500)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error":           "template_unresolved",
		"unresolved_refs": missing,
		"available_keys":  keys,
		"hint":            "the respond step's body referenced template variables that didn't resolve. Most common: (a) the step you reference has no `id:` set, (b) you used `${{ steps.<id>.outputs.<col> }}` but the upstream SQL was INSERT/UPDATE without RETURNING - add RETURNING <col> so the value is captured, (c) you referenced `${{ user.<field> }}` on a route without `auth: required`. Pre-v2.7.5 the literal placeholder text would have been baked into the response - now it's surfaced explicitly here.",
	})
}

// interpolateJSONValues resolves {{var}} placeholders in JSON response values.
// If a value resolves to flow context data (e.g. a query result), it inlines the actual data.
//
// JSON-string inlining (v2.5.9+): when an interpolated value resolves
// to a string that itself parses as a JSON array or object, decode it
// and emit the structured value. This matches what agents expect when
// pairing SQL `json_group_array()` / `json_object()` with respond.json
// - pre-fix, the JSON-encoded TEXT came back from SQLite verbatim and
// got double-quoted in the response (an earlier app build had to
// flatten arrays + reassemble in JS).
func interpolateJSONValues(m map[string]any, ctx *FlowContext) map[string]any {
	result := make(map[string]any, len(m))
	for k, v := range m {
		result[k] = resolveJSONValue(v, ctx)
	}
	return result
}

// resolveJSONValue resolves one respond-body value (recursing into nested
// objects + arrays). A whole-value `{{ref}}` is emitted as its NATIVE Go
// value (so arrays/objects become real JSON), not fmt.Sprintf'd.
func resolveJSONValue(v any, ctx *FlowContext) any {
	switch val := v.(type) {
	case string:
		// Whole-value single-ref: `{{x}}` and nothing else around it.
		trimmed := strings.TrimSpace(val)
		if strings.HasPrefix(trimmed, "{{") && strings.HasSuffix(trimmed, "}}") && strings.Count(trimmed, "{{") == 1 {
			key := strings.TrimSpace(trimmed[2 : len(trimmed)-2])
			// Raw ctx.Data covers top-level step values (`{{r}}`,
			// `{{r.outputs}}`).
			if ctxVal, ok := ctx.Data[key]; ok {
				return maybeDecodeJSONString(ctxVal)
			}
			// NESTED whole-refs (`{{r.years}}`, `{{r.obj}}`) only exist in
			// the FLATTENED view - ctx.Data has the parent map, not the
			// dotted key. Pre-fix this missed here and fell through to
			// fmt.Sprintf, so a slice came out as "[2025 2026]" and a map
			// as "map[a:1 b:2]" (not even valid JSON). Look it up flat so
			// the native array/object/number is emitted. (Refs with pipes
			// or operators won't match either map and correctly fall
			// through to interpolateCtx below, which applies the pipe.)
			if ctxVal, ok := flatDataForCtx(ctx)[key]; ok {
				return maybeDecodeJSONString(ctxVal)
			}
		}
		// Otherwise interpolate as string, then check if the rendered
		// result looks like JSON.
		return maybeDecodeJSONString(interpolateCtx(val, ctx))
	case map[string]any:
		return interpolateJSONValues(val, ctx)
	case []any:
		// Array literals in the body interpolate element-by-element.
		arr := make([]any, len(val))
		for i, item := range val {
			arr[i] = resolveJSONValue(item, ctx)
		}
		return arr
	default:
		return v
	}
}

// maybeDecodeJSONString inlines a stringified JSON value (the typical
// output of SQLite's json_group_array() / json_object()) into the
// native Go value. Non-string inputs pass through. Strings that don't
// look like JSON pass through unchanged.
func maybeDecodeJSONString(v any) any {
	s, ok := v.(string)
	if !ok {
		return v
	}
	trimmed := strings.TrimSpace(s)
	if len(trimmed) < 2 {
		return v
	}
	first := trimmed[0]
	last := trimmed[len(trimmed)-1]
	if !((first == '[' && last == ']') || (first == '{' && last == '}')) {
		return v
	}
	var decoded any
	if err := json.Unmarshal([]byte(trimmed), &decoded); err != nil {
		return v
	}
	return decoded
}

func execStepIf(ctx *FlowContext, step *FlowStep) error {
	if evaluateFlowCondition(step.Condition, ctx) {
		executeSteps(ctx, step.Steps)
	} else if len(step.ElseSteps) > 0 {
		executeSteps(ctx, step.ElseSteps)
	}
	return ctx.Error
}

func execStepForEach(ctx *FlowContext, step *FlowStep) error {
	items, ok := ctx.Data[step.ForEach]
	if !ok {
		return nil
	}

	var rows []map[string]any
	switch v := items.(type) {
	case []map[string]any:
		rows = v
	case []any:
		for _, item := range v {
			if m, ok := item.(map[string]any); ok {
				rows = append(rows, m)
			}
		}
	}

	as := step.ForAs
	if as == "" {
		as = "item"
	}

	for _, row := range rows {
		// Create sub-context with loop variable - recursively flatten nested maps
		ctx.Data[as] = row
		flattenIntoCtx(ctx.Data, as, row)
		executeSteps(ctx, step.Steps)
		if ctx.Stopped || ctx.Error != nil {
			return ctx.Error
		}
	}
	return nil
}

// flattenIntoCtx recursively flattens a map into dot-notation keys in ctx.Data.
// e.g. flattenIntoCtx(data, "geo", {"results": [{"geometry": {"location": {"lat": 39.9}}}]})
// produces data["geo.results"] = [...], and for arrays: data["geo.results.0.geometry.location.lat"] = 39.9
func flattenIntoCtx(data map[string]any, prefix string, m map[string]any) {
	for k, v := range m {
		key := prefix + "." + k
		data[key] = v
		switch val := v.(type) {
		case map[string]any:
			flattenIntoCtx(data, key, val)
		case []any:
			for i, item := range val {
				iKey := fmt.Sprintf("%s.%d", key, i)
				data[iKey] = item
				if im, ok := item.(map[string]any); ok {
					flattenIntoCtx(data, iKey, im)
				}
			}
		}
	}
}

func execStepSet(ctx *FlowContext, step *FlowStep) error {
	// Interpolate all values once, then expose them two ways:
	//   - At ctx.Data[step.Name] = {k: v, ...} so GHA-style references
	//     `${{ steps.<id>.outputs.<k> }}` (translated to `{{<id>.<k>}}`)
	//     resolve correctly. This matches what sql/api/email steps do
	//     and is what the build doc promises.
	//   - At ctx.Data[k] directly, for backwards compat with flows that
	//     reference `{{k}}` without a step name prefix.
	resolved := make(map[string]any, len(step.Set))
	for k, v := range step.Set {
		val := interpolateCtx(v, ctx)
		resolved[k] = val
	}
	ctx.DataMu.Lock()
	for k, val := range resolved {
		ctx.Data[k] = val
	}
	if step.Name != "" {
		ctx.Data[step.Name] = resolved
	}
	ctx.DataMu.Unlock()
	return nil
}

func execStepParse(ctx *FlowContext, step *FlowStep) error {
	if step.Parse == "body" && ctx.Request != nil {
		// Try form data first (Content-Type: application/x-www-form-urlencoded)
		contentType := ctx.Request.Header.Get("Content-Type")
		if strings.Contains(contentType, "form-urlencoded") || strings.Contains(contentType, "multipart") {
			ctx.Request.ParseForm()
			name := step.Name
			if name == "" {
				name = "form"
			}
			formData := make(map[string]any)
			for k, v := range ctx.Request.Form {
				if len(v) > 0 {
					formData[k] = v[0]
					ctx.Data[name+"."+k] = v[0]
				}
			}
			ctx.Data[name] = formData
			return nil
		}

		// Fall back to JSON
		body, err := io.ReadAll(io.LimitReader(ctx.Request.Body, 1<<20))
		if err != nil {
			return err
		}
		var data any
		if err := json.Unmarshal(body, &data); err != nil {
			return fmt.Errorf("parse body: %w", err)
		}
		name := step.Name
		if name == "" {
			name = "body"
		}
		ctx.Data[name] = data
		if m, ok := data.(map[string]any); ok {
			for k, v := range m {
				ctx.Data[name+"."+k] = v
			}
			// Also flatten into data.object pattern for Stripe-style webhooks
			if obj, ok := m["data"]; ok {
				if om, ok := obj.(map[string]any); ok {
					for k, v := range om {
						ctx.Data[name+".data."+k] = v
					}
					if inner, ok := om["object"]; ok {
						if im, ok := inner.(map[string]any); ok {
							for k, v := range im {
								ctx.Data[name+".data.object."+k] = v
							}
						}
					}
				}
			}
		}
	}
	return nil
}

// execStepCompute runs a `run: compute` step (v2.7.67+) - server-side
// JS execution of a function in a static/ TS/JS module via goja. See
// compute.go for the runtime + sandbox details. The pattern:
//
//	- id: forecast
//	  run: sql
//	  with: SELECT * FROM forecasts WHERE id = :id
//
//	- id: irr
//	  run: compute
//	  module: par-engine
//	  function: irrForInputs
//	  args: ${{ steps.forecast.outputs.first }}
//	  timeout: 10s
//
// The function's return value lands at ctx.Data[step.Name] (and a
// `.outputs` alias under the same name) so downstream steps reference
// it via `${{ steps.<id>.outputs }}` - same shape as sql / api steps.
// resolveComputeArgsValue turns a `run: compute` args spec into a native Go
// value for goja. Strings that are a SINGLE whole ref (`${{ x }}` / `{{ x }}`)
// resolve to the native context value (object/array/scalar); maps and slices
// recurse leaf-by-leaf (so `args: {a: ${{...}}, b: ${{...}}}` builds a real
// object); other strings are interpolated; numbers/bools pass through.
func resolveComputeArgsValue(raw any, ctx *FlowContext) any {
	switch v := raw.(type) {
	case nil:
		return nil
	case string:
		return resolveComputeArgString(v, ctx)
	case map[string]any:
		out := make(map[string]any, len(v))
		for k, vv := range v {
			out[k] = resolveComputeArgsValue(vv, ctx)
		}
		return out
	case []any:
		out := make([]any, len(v))
		for i, vv := range v {
			out[i] = resolveComputeArgsValue(vv, ctx)
		}
		return out
	default:
		return v // number, bool, etc.
	}
}

func resolveComputeArgString(s string, ctx *FlowContext) any {
	// Normalize with the SAME translator the rest of the framework uses
	// (translateGHAExpr via normalizeGHARefs): strips `steps.`, collapses
	// `.outputs.rows`/`.outputs.*`/`.outputs.<field>`, and turns `[N]` into
	// `.N`. So `${{ steps.forecast.outputs.rows }}` → {{forecast}} (the array)
	// and `${{ steps.forecast.outputs.rows[0].col }}` → {{forecast.0.col}}.
	// Without this the raw ref never matched the flattened context keys and
	// whole-object/array refs resolved to null.
	norm := normalizeGHARefs(strings.TrimSpace(s))
	if inner := wholeTemplateRef(norm); inner != "" {
		if val, ok := resolveBindExpr(inner, flattenData(ctx.Data)); ok {
			return val
		}
		return nil
	}
	return interpolateCtx(s, ctx) // literal or text with embedded refs
}

// wholeTemplateRef returns the inner expression if the ENTIRE string is one
// `${{ ... }}` or `{{ ... }}` ref (no surrounding text, no second ref), else "".
func wholeTemplateRef(s string) string {
	for _, p := range [][2]string{{"${{", "}}"}, {"{{", "}}"}} {
		if strings.HasPrefix(s, p[0]) && strings.HasSuffix(s, p[1]) && len(s) > len(p[0])+len(p[1]) {
			inner := strings.TrimSpace(s[len(p[0]) : len(s)-len(p[1])])
			if !strings.Contains(inner, "{{") && !strings.Contains(inner, "}}") {
				return inner
			}
		}
	}
	return ""
}

func execStepCompute(ctx *FlowContext, step *FlowStep) error {
	if step.Compute == nil {
		return fmt.Errorf("compute step missing compute config - required keys: module, function")
	}
	if step.Compute.Module == "" {
		return fmt.Errorf("compute step missing `module:` - point at a TS/JS file in static/ (without extension)")
	}
	if step.Compute.Function == "" {
		return fmt.Errorf("compute step missing `function:` - name of the exported function to invoke")
	}
	if ctx.App == nil {
		return fmt.Errorf("compute step requires an app context (current ctx has none - running outside the request path?)")
	}
	// Resolve args to a NATIVE value so goja receives real objects, not a
	// stringified "map[...]". A single whole-string ref (`${{ steps.X.outputs }}`)
	// resolves to that step's actual value; a MAP of refs assembles a real
	// object field-by-field; literals/embedded-text fall back to string
	// interpolation. (Pre-fix this ran interpolateCtx → mangled any object.)
	argsValue := resolveComputeArgsValue(step.Compute.Args, ctx)
	result, err := RunCompute(ctx.App, step.Compute.Module, step.Compute.Function, argsValue, step.Compute.Timeout)
	if err != nil {
		return err
	}
	// Land the result the same way sql/api steps do - at the step
	// name AND under a `.outputs` alias so `steps.<id>.outputs`
	// references in downstream YAML resolve cleanly.
	if step.Name != "" {
		ctx.DataMu.Lock()
		ctx.Data[step.Name] = result
		ctx.Data[step.Name+".outputs"] = result
		ctx.DataMu.Unlock()
	}
	return nil
}

// resolveBindExpr splits a `{{ key | pipe1 | pipe2:arg }}` expression,
// looks up the base key in flatData, applies pipes left-to-right, and
// returns the final value + ok. The base key is whatever appears before
// the first pipe (or the whole expression if there are no pipes).
//
// Without pipes: returns the native value (slice / map / scalar) so the
// SQL driver can bind scalars and the caller can reject non-scalars
// with a useful error.
//
// With pipes: pipes are applied via ApplyPipe and the result is a
// string (every pipe stringifies, by design). This lets `{{ steps.X.
// outputs.rows | length }}` bind an integer-shaped string into a SQL
// `?` placeholder instead of trying to bind a slice (which the agent
// would otherwise hit as `sql: unrecognized token: "{"`).
func resolveBindExpr(expr string, flatData map[string]any) (any, bool) {
	// JS/GHA-style `a || fallback`: try the left operand; if it's missing
	// OR empty, use the right (a quoted literal or another ref). Agents
	// reach for `||` intuitively (the `| default:` pipe also works). Handle
	// `||` BEFORE the single-pipe split so it isn't mistaken for two pipes.
	if i := strings.Index(expr, "||"); i >= 0 {
		left := strings.TrimSpace(expr[:i])
		right := strings.TrimSpace(expr[i+2:])
		if v, ok := resolveBindExpr(left, flatData); ok && !isEmptyish(v) {
			return v, true
		}
		return resolveFallbackOperand(right, flatData)
	}
	parts := strings.Split(expr, "|")
	base := strings.TrimSpace(parts[0])
	val, ok := flatData[base]
	if !ok {
		// Base ref doesn't resolve in current scope. Pre-v2.7.6 this
		// always returned (nil, false), which the v2.7.5 loud-fail
		// logic then escalated to a `template_unresolved` halt - even
		// for genuinely optional refs the agent had defaulted via
		// `| default:''`. An earlier app build hit this on every
		// `${{ params.optional_field | default:'' }}` template the
		// client could legitimately omit.
		//
		// Now: if ANY pipe in the chain is `default:<value>`, we
		// short-circuit the missing-ref escalation. The default value
		// becomes the resolved value, and any pipes AFTER `default:`
		// (e.g. `| default:'' | upper`) still get applied.
		for i, p := range parts[1:] {
			name, arg, hasArg := splitPipeNameArg(p)
			if name == "default" && hasArg {
				cur := any(arg)
				for _, later := range parts[1+i+1:] {
					cur = ApplyPipe(cur, strings.TrimSpace(later))
				}
				return cur, true
			}
		}
		return nil, false
	}
	if len(parts) == 1 {
		return val, true
	}
	cur := val
	for _, p := range parts[1:] {
		cur = ApplyPipe(cur, strings.TrimSpace(p))
	}
	return cur, true
}

// isEmptyish reports whether a resolved value should trigger an `||`
// fallback - nil, blank string, or an empty collection.
func isEmptyish(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(t) == ""
	case []any:
		return len(t) == 0
	case []map[string]any:
		return len(t) == 0
	case map[string]any:
		return len(t) == 0
	}
	return false
}

// resolveFallbackOperand resolves the right side of an `a || b`: a quoted
// literal ('x' / "x") strips to its contents; otherwise it's resolved as a
// ref (allowing `a || b || c` chains), falling back to the bare text so
// `${{ x || none }}` yields "none" rather than an unresolved-ref halt.
func resolveFallbackOperand(s string, flatData map[string]any) (any, bool) {
	if len(s) >= 2 && ((s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"')) {
		return s[1 : len(s)-1], true
	}
	if v, ok := resolveBindExpr(s, flatData); ok {
		return v, true
	}
	return s, true
}

// splitPipeNameArg splits a pipe expression like `default:''` into
// ("default", "", true) or `length` into ("length", "", false). The
// arg can be quoted with single or double quotes; quotes are stripped.
// Used by resolveBindExpr to detect `default:` short-circuits.
func splitPipeNameArg(pipeExpr string) (name, arg string, hasArg bool) {
	pipeExpr = strings.TrimSpace(pipeExpr)
	colon := strings.Index(pipeExpr, ":")
	if colon < 0 {
		return pipeExpr, "", false
	}
	name = strings.TrimSpace(pipeExpr[:colon])
	arg = strings.TrimSpace(pipeExpr[colon+1:])
	// Strip surrounding quotes if present.
	if len(arg) >= 2 {
		if (arg[0] == '\'' && arg[len(arg)-1] == '\'') ||
			(arg[0] == '"' && arg[len(arg)-1] == '"') {
			arg = arg[1 : len(arg)-1]
		}
	}
	return name, arg, true
}

// sqlBindValue converts a string param to int64/float64 when - and only
// when - the numeric form round-trips back to the EXACT same string.
//
// Why: ctx.Params is map[string]string, so every :param used to bind as
// TEXT. SQLite compares a TEXT value as GREATER than any number when
// neither operand picks up column affinity - which is exactly the shape
// of a flow guard like `WHERE :amt >= (SELECT SUM(...))`: the bound
// '5000' silently beat 10515 and the guard NEVER fired. No error, no
// warning - the worst failure class. Comparisons against real columns
// were saved by column affinity, which is why the bug only bit
// expression comparisons.
//
// The canonical round-trip requirement is the safety valve: '01234',
// '5e3', '1.50' and '+1' all keep binding as TEXT (their numeric form
// prints differently), so zip codes and phone numbers still compare
// byte-for-byte against TEXT columns. A value that DOES round-trip
// ('5000', '6.5') is indistinguishable from its number even against a
// TEXT-affinity column - SQLite converts the number back to the same
// string - so the rewrite is observable only where the old behavior was
// wrong.
//
// Sibling: hooks.go's coerceNumericBind fixes the same trap for hook
// SQL with a more permissive rule (regex; coerces '1.50' → 1.5). Flow
// params come from URLs/JSON where identifier-shaped strings are
// common, so the stricter round-trip rule is deliberate here - don't
// "unify" them without weighing that trade-off.
func sqlBindValue(s string) any {
	if s == "" {
		return s
	}
	if c := s[0]; c != '-' && (c < '0' || c > '9') {
		return s
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		if strconv.FormatInt(i, 10) == s {
			return i
		}
		return s
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		if strconv.FormatFloat(f, 'f', -1, 64) == s {
			return f
		}
	}
	return s
}

// interpolateCtxSafe replaces {{var}} with ? placeholders for SQL parameterization.
// Processes left-to-right through the string to maintain correct arg ordering.
func interpolateCtxSafe(template string, ctx *FlowContext) (string, []any) {
	// First pass: replace :param with ? placeholders (path params are user input, must be parameterized)
	var paramResult strings.Builder
	var paramArgs []any
	tmp := template
	for {
		// Find the earliest :param match WITH word-boundary enforcement.
		//
		// Pre-v2.7.6 the loop did `strings.Index(tmp, ":"+k)` with no
		// boundary check after the name. If both `:expo` and `:export`
		// were registered params, the search for `:expo` would happily
		// match the first 5 chars of `:export` in the query, leaving
		// the trailing `rt` literal in the SQL after the `?` was
		// inserted. SQLite then either failed to parse or bound the
		// wrong column. Same shape as the v2.7.5 INSERT…RETURNING bug:
		// "prefix-based detection without a boundary" was the root cause.
		//
		// Fix: require the char AFTER the param name to be a non-
		// identifier (or EOF). Valid SQL identifier chars are letters,
		// digits, underscores - so `:expo,` and `:expo)` and `:expo `
		// all match, but `:export` and `:expoXYZ` and `:expo_v2` do not.
		bestIdx := -1
		bestKey := ""
		bestVal := ""
		for k, v := range ctx.Params {
			searchIdx := 0
			for {
				rel := strings.Index(tmp[searchIdx:], ":"+k)
				if rel < 0 {
					break
				}
				abs := searchIdx + rel
				// Boundary check: char after the param name must be a
				// non-identifier (or end of string).
				end := abs + len(":"+k)
				if end < len(tmp) {
					c := tmp[end]
					isIdent := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
						(c >= '0' && c <= '9') || c == '_'
					if isIdent {
						// Not a real match - keep scanning past this position.
						searchIdx = abs + 1
						continue
					}
				}
				if bestIdx < 0 || abs < bestIdx {
					bestIdx = abs
					bestKey = k
					bestVal = v
				}
				break
			}
		}
		if bestIdx < 0 {
			paramResult.WriteString(tmp)
			break
		}
		paramResult.WriteString(tmp[:bestIdx])
		paramResult.WriteByte('?')
		// NullParams sidecar: if the source expression resolved to Go
		// nil, bind SQL NULL rather than the empty string. Distinguishes
		// "explicit null" from "explicit empty string" - both look the
		// same in ctx.Params (which is map[string]string) but mean
		// different things to the column.
		if ctx.NullParams != nil && ctx.NullParams[bestKey] {
			paramArgs = append(paramArgs, nil)
		} else {
			paramArgs = append(paramArgs, sqlBindValue(bestVal))
		}
		tmp = tmp[bestIdx+len(":"+bestKey):]
	}

	result := InterpolateEnv(paramResult.String(), ctx.App.Dir)

	flatData := flatDataForCtx(ctx)

	// Second pass LEFT-TO-RIGHT: scan for {{ }}, resolve each one in order
	// Start with param args collected above, then append data args in order
	args := make([]any, 0, len(paramArgs))
	args = append(args, paramArgs...)
	var output strings.Builder
	i := 0
	for i < len(result) {
		// Check for '{{key}}' (quoted placeholder - inline as literal, SQL-escaped)
		if i+3 < len(result) && result[i] == '\'' && result[i+1] == '{' && result[i+2] == '{' {
			end := strings.Index(result[i+3:], "}}'")
			if end >= 0 {
				expr := strings.TrimSpace(result[i+3 : i+3+end])
				if val, ok := resolveBindExpr(expr, flatData); ok {
					// Inline the value inside quotes (escape single quotes to prevent injection)
					s := fmt.Sprintf("%v", val)
					s = strings.ReplaceAll(s, "'", "''")
					output.WriteByte('\'')
					output.WriteString(s)
					output.WriteByte('\'')
					i = i + 3 + end + 3
					continue
				}
				// Note the unresolved ref so the step dispatcher can
				// halt with a clear error instead of binding the literal
				// `{{ws.id}}` string into the SQL. Without this branch
				// the placeholder character (?) below would bind the
				// quoted literal text as a string param, the row would
				// land with a malformed foreign key, and the failure
				// would surface three steps later as a UNIQUE constraint
				// rollback with no obvious connection to the unresolved
				// reference.
				ctx.noteMissingRef(expr)
			}
		}
		// Check for {{key}} (unquoted placeholder)
		if i+2 < len(result) && result[i] == '{' && result[i+1] == '{' {
			end := strings.Index(result[i+2:], "}}")
			if end >= 0 {
				expr := strings.TrimSpace(result[i+2 : i+2+end])
				if val, ok := resolveBindExpr(expr, flatData); ok {
					output.WriteByte('?')
					// Pipe results stringify by design (resolveBindExpr), so
					// `{{ rows | length }}` arrives here as "3" - give it the
					// same canonical-numeric treatment as :params so it
					// compares numerically too.
					if s, isStr := val.(string); isStr {
						val = sqlBindValue(s)
					}
					args = append(args, val)
					i = i + 2 + end + 2
					continue
				}
				ctx.noteMissingRef(expr)
			}
		}
		output.WriteByte(result[i])
		i++
	}

	return output.String(), args
}

// interpolateCtx replaces {{var}} and {{var | pipe}} with context data.
// Mirrors interpolateCtxSafe's scan-based parser so pipe expressions
// behave identically across SQL (param-bound) and non-SQL (string
// substitution) contexts. Used by respond:, headers:, run: api, etc.
func interpolateCtx(template string, ctx *FlowContext) string {
	result := template
	// Replace :param with param values
	for k, v := range ctx.Params {
		result = strings.ReplaceAll(result, ":"+k, v)
	}
	// Replace {{env.X}}
	result = InterpolateEnv(result, ctx.App.Dir)
	flatData := flatDataForCtx(ctx)

	var output strings.Builder
	i := 0
	for i < len(result) {
		if i+2 < len(result) && result[i] == '{' && result[i+1] == '{' {
			end := strings.Index(result[i+2:], "}}")
			if end >= 0 {
				expr := strings.TrimSpace(result[i+2 : i+2+end])
				if val, ok := resolveBindExpr(expr, flatData); ok {
					// Render nil as empty string instead of Go's default
					// "<nil>" - that literal was leaking into UI columns,
					// JSON responses, and SQL inserts (where it landed
					// as the three-character string). For SQL bind, the
					// proper NULL handling lives in interpolateCtxSafe
					// via ctx.NullParams; this branch covers all the
					// non-SQL string-substitution callers (respond:,
					// headers:, run: api URLs).
					if val == nil {
						i = i + 2 + end + 2
						continue
					}
					output.WriteString(fmt.Sprintf("%v", val))
					i = i + 2 + end + 2
					continue
				}
				// Unresolved reference - record it so the step
				// dispatcher can halt with a clear error. Pre-v2.7.5 the
				// literal `{{first_name}}` text was emitted into the
				// surrounding string, then leaked into HTTP responses
				// (where the client saw raw `{{ws.name}}` placeholders),
				// SQL queries (where it parsed as identifier or got bound
				// as a literal string), and webhook bodies.
				ctx.noteMissingRef(expr)
			}
		}
		output.WriteByte(result[i])
		i++
	}
	return output.String()
}

// flattenData walks ctx.Data and produces a flat key→value map keyed
// by dotted paths. Supports nested maps AND slices uniformly:
//
//   ctx.Data = { "stories": [{"id":1,"title":"X"}, {"id":2,"title":"Y"}] }
//
// produces (among others):
//   "stories"             → the whole slice
//   "stories.0"           → the first row (map)
//   "stories.0.title"     → "X"
//   "stories.0.id"        → 1
//   "stories.1.title"     → "Y"
//
// AND a single-element-slice promotes its element to the slice key
// itself, so `{{user}}` resolves to `{...}` when the SQL returned
// exactly one row. This preserves the old "1-row → object" template
// ergonomics while making `outputs.*` always work as an array.
// flatDataForCtx is the canonical lookup table for `{{ ... }}`
// references in flow templating. It returns flattenData(ctx.Data)
// PLUS every env var the app can see, surfaced under the `env.<key>`
// namespace.
//
// Why the env overlay (v2.7.7+): InterpolateEnv runs as a pre-pass
// and substitutes the literal `{{env.X}}` form before the main scan
// reaches resolveBindExpr. But it doesn't match pipe-form refs like
// `{{env.X | default:'fallback'}}` - those survive past
// InterpolateEnv and hit the main scanner, which used to find
// nothing in flatData and fall back to the default (masking the
// real env value with the fallback). By overlaying env vars into
// flatData, the pipe-form resolves correctly: present env wins,
// missing env triggers the default-pipe short-circuit added in
// v2.7.6.
//
// The overlay is read-only: we don't mutate the per-app store from
// here, just copy the snapshot at template-resolution time.
func flatDataForCtx(ctx *FlowContext) map[string]any {
	flat := flattenData(ctx.Data)
	if ctx == nil || ctx.App == nil {
		return flat
	}
	absDir, _ := filepath.Abs(ctx.App.Dir)
	appEnvStore.mu.RLock()
	vars, ok := appEnvStore.apps[absDir]
	appEnvStore.mu.RUnlock()
	// Per-app store wins; fall back to global EnvVars for keys not in
	// the per-app store. Matches InterpolateEnv's lookup order.
	for k, v := range EnvVars {
		flat["env."+k] = v
	}
	if ok {
		for k, v := range vars {
			flat["env."+k] = v
		}
	}
	return flat
}

func flattenData(data map[string]any) map[string]any {
	flat := make(map[string]any)
	for k, v := range data {
		flattenInto(flat, k, v)
		// Single-element slice → also expose the element under the
		// step's key directly (e.g. `{{user.email}}` works after a
		// `SELECT * FROM users WHERE id = :id`).
		if slice, ok := v.([]map[string]any); ok && len(slice) == 1 {
			for mk, mv := range slice[0] {
				key := k + "." + mk
				if _, exists := flat[key]; !exists {
					flat[key] = mv
				}
			}
		} else if slice, ok := v.([]any); ok && len(slice) == 1 {
			if m, ok := slice[0].(map[string]any); ok {
				for mk, mv := range m {
					key := k + "." + mk
					if _, exists := flat[key]; !exists {
						flat[key] = mv
					}
				}
			}
		}
		// `.first` sugar - always exposes row 0 from a slice result,
		// regardless of how many rows came back. Lets multi-row SELECTs
		// use object access for the top hit (e.g.
		// `${{ steps.recent_posts.outputs.first.title }}`) without
		// resorting to `.0.title` index notation. Distinct from the
		// auto-collapse above: that triggers only on len==1; this one
		// is always-on, and `.first` is the explicit ask.
		firstKey := k + ".first"
		if slice, ok := v.([]map[string]any); ok && len(slice) > 0 {
			flat[firstKey] = map[string]any(slice[0])
			for mk, mv := range slice[0] {
				key := firstKey + "." + mk
				if _, exists := flat[key]; !exists {
					flat[key] = mv
				}
			}
		} else if slice, ok := v.([]any); ok && len(slice) > 0 {
			if m, ok := slice[0].(map[string]any); ok {
				flat[firstKey] = m
				for mk, mv := range m {
					key := firstKey + "." + mk
					if _, exists := flat[key]; !exists {
						flat[key] = mv
					}
				}
			}
		}
	}
	return flat
}

// flattenInto recurses through maps + slices, keyed by dotted path.
func flattenInto(flat map[string]any, prefix string, v any) {
	flat[prefix] = v
	switch t := v.(type) {
	case map[string]any:
		for k, child := range t {
			flattenInto(flat, prefix+"."+k, child)
		}
	case []map[string]any:
		for i, row := range t {
			flattenInto(flat, fmt.Sprintf("%s.%d", prefix, i), map[string]any(row))
		}
	case []any:
		for i, child := range t {
			flattenInto(flat, fmt.Sprintf("%s.%d", prefix, i), child)
		}
	}
}

func evaluateFlowCondition(condition string, ctx *FlowContext) bool {
	flat := flattenData(ctx.Data)
	row := make(map[string]any)
	for k, v := range flat {
		row[k] = v
	}
	// Resolution strategy. We split on the operator, then:
	//
	//   - If the LHS contains a pipe (`|`) or any other template
	//     machinery, resolve it through interpolateCtx so the pipe
	//     applies (`|default:''` / `|upper` / etc) and compare the
	//     resolved literal directly against the resolved RHS. Pre-
	//     2.7.32 the LHS was always handed to evaluateCondition as a
	//     row-key - so `existing.account_id | default:'' = ''` became
	//     `row["existing.account_id | default:''"]`, ALWAYS missing,
	//     ALWAYS resolved to "", ALWAYS true. That's the Stripe-
	//     onboard duplicate-account bug: the `if: ${{...|default:''}}
	//     == ''` gate always fired even when account_id was set, so
	//     every onboard click created a fresh Stripe Connect account.
	//
	//   - Otherwise (bare key like `status`), keep the legacy
	//     row-key lookup path so hook conditions
	//     (`when: status = 'won'`) keep working.
	//
	// Order matters: check longer ops first (>=, <=, !=) before single-char ops.
	for _, op := range []string{">=", "<=", "!=", "=", ">", "<"} {
		if idx := strings.Index(condition, op); idx > 0 {
			lhs := strings.TrimSpace(condition[:idx])
			rhs := strings.TrimSpace(condition[idx+len(op):])
			rhs = interpolateCtx(rhs, ctx)
			if conditionLHSNeedsResolution(lhs) {
				expr := lhs
				if !strings.Contains(expr, "{{") {
					expr = "{{" + expr + "}}"
				}
				resolved := interpolateCtx(expr, ctx)
				return compareLiteralCondition(resolved, op, strings.Trim(rhs, `"'`))
			}
			return evaluateCondition(lhs+" "+op+" "+rhs, row)
		}
	}
	// No operator → boolean truthiness check. evaluateCondition only
	// understands `lhs OP rhs`; handed an operator-less condition it
	// loops, matches no operator, and falls through to `return false` -
	// so bare-boolean gates like `if: ${{ gate.ok }}` (where gate.ok is
	// the boolean true from a compute step) silently NEVER fired,
	// stranding the success branch and 500ing as flow_no_response. The
	// `== false` form worked (it has an operator), which is why only the
	// truthy branch was broken.
	//
	// Resolution order, each step narrower than the last:
	//
	//  1. Direct flattened-row key - a real bool/number/string from a
	//     step output or a request param (`gate.ok`, an empty-string
	//     param) is judged as ITSELF, so `{"x":""}` is correctly falsy.
	//  2. A `{{...}}`-braced expression (legacy hook `when:` /
	//     `success_when:` shapes) - interpolate, judge the rendered text.
	//  3. Otherwise resolve through resolveBindExpr so `| default:`, `||`
	//     and dotted paths actually APPLY. Pre-2.7.136 the no-op path
	//     fell straight to interpolateCtx, which only touches `{{ }}`
	//     braces - but ghaIfToFlowCondition strips those for operator-less
	//     conditions, so `if: ${{ params.x | default:'' }}` arrived as the
	//     bare string `x | default:''`, matched no row key, rendered to
	//     ITSELF (no braces to expand), and `isTruthyCondition` of that
	//     non-empty literal was ALWAYS true. The pipe/`||` never ran. Now
	//     it does: a missing base with `| default:''` resolves to "" →
	//     falsy; `|| ''` falls back to "" → falsy.
	//  4. Still unresolved → a recognized value literal (`true`/`1`/`'x'`)
	//     is judged by its literal truthiness; anything else is an
	//     identifier that referenced ABSENT data, which is falsy JS-style
	//     (the old code returned the bare identifier text → truthy, so an
	//     omitted `${{ params.x }}` wrongly fired the branch).
	key := strings.TrimSpace(condition)
	if v, ok := row[key]; ok {
		return isTruthyCondition(v)
	}
	if strings.Contains(key, "{{") {
		return isTruthyCondition(strings.TrimSpace(interpolateCtx(condition, ctx)))
	}
	if v, ok := resolveBindExpr(key, flatDataForCtx(ctx)); ok {
		return isTruthyCondition(v)
	}
	return conditionLiteralTruthy(key)
}

// isTruthyCondition judges an operator-less `if:` value JS-style so a
// compute step returning { ok: true } gates as expected. Real bools use
// their value; everything else is falsey only when empty / "false" / "0"
// / "no" / "null" / "undefined" / "nan" / "<nil>" (case-insensitive).
func isTruthyCondition(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case []any:
		return len(t) > 0 // empty result set / array → falsy
	case []map[string]any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	}
	s := strings.ToLower(strings.TrimSpace(fmt.Sprintf("%v", v)))
	switch s {
	// includes the stringified empty-collection forms ("[]", "map[]", "{}")
	// so `if: ${{ steps.x.outputs.rows }}` is FALSE on an empty result.
	case "", "false", "0", "0.0", "no", "null", "undefined", "nan", "<nil>", "[]", "map[]", "{}":
		return false
	}
	return true
}

// conditionLiteralTruthy judges an operator-less `if:` value that did NOT
// resolve as a data ref (no row key, no `{{ }}`, no resolvable bind expr).
// A recognized value literal is judged by its literal truthiness; anything
// else is a bare identifier that referenced ABSENT data and is falsy - the
// JS/GHA reading of an undefined variable in a boolean context. This is the
// branch that stops an omitted `${{ params.x }}` (translated to the bare
// token `x`) from rendering to its own name and reading as truthy.
func conditionLiteralTruthy(s string) bool {
	s = strings.TrimSpace(s)
	// Quoted string literal: 'x' / "x" - truthy iff non-empty inside.
	if len(s) >= 2 && ((s[0] == '\'' && s[len(s)-1] == '\'') || (s[0] == '"' && s[len(s)-1] == '"')) {
		return strings.TrimSpace(s[1:len(s)-1]) != ""
	}
	switch strings.ToLower(s) {
	case "true":
		return true
	case "", "false", "no", "null", "undefined", "nan":
		return false
	}
	// Numeric literal → JS truthiness (0 / 0.0 false, everything else true).
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		return f != 0
	}
	// A bare identifier (foo / a.b.c) that reached here didn't resolve in
	// any scope → it's a missing ref, not a literal → falsy.
	return false
}

// conditionLHSNeedsResolution returns true when the LHS of a flow
// condition contains pipe modifiers or template machinery that must
// be processed before comparison. The legacy `status = 'won'` shape
// (bare key) stays on the row-lookup path; anything with a pipe (or
// `{{}}` braces, which shouldn't happen post-normalization but is
// defensive) gets resolved through interpolateCtx.
func conditionLHSNeedsResolution(lhs string) bool {
	if strings.Contains(lhs, "|") {
		return true
	}
	if strings.Contains(lhs, "{{") || strings.Contains(lhs, "}}") {
		return true
	}
	return false
}

// compareLiteralCondition compares two already-resolved string
// literals via the operator. Numeric ops attempt a numeric compare
// first so `count > 5` works as expected (string-only compare would
// order `"10"` before `"5"` lexicographically). Equality ops are
// always string-compared.
func compareLiteralCondition(actual, op, expected string) bool {
	switch op {
	case "=":
		return actual == expected
	case "!=":
		return actual != expected
	case ">", "<", ">=", "<=":
		// Try numeric first; fall through to string if either side
		// isn't a number.
		a, aErr := strconv.ParseFloat(actual, 64)
		b, bErr := strconv.ParseFloat(expected, 64)
		if aErr == nil && bErr == nil {
			switch op {
			case ">":
				return a > b
			case "<":
				return a < b
			case ">=":
				return a >= b
			case "<=":
				return a <= b
			}
		}
		switch op {
		case ">":
			return actual > expected
		case "<":
			return actual < expected
		case ">=":
			return actual >= expected
		case "<=":
			return actual <= expected
		}
	}
	return false
}

func verifyWebhookSignature(flow *Flow, r *http.Request, appDir string) bool {
	secret := InterpolateEnv(flow.Secret, appDir)
	if secret == "" {
		return true
	}

	// Named provider shortcuts - use canonical signature formats.
	// These match the `verify: <name>` value in flows.yaml.
	switch strings.ToLower(flow.Verify) {
	case "stripe":
		return verifyStripeSignature(r.Header.Get("Stripe-Signature"), secret, r)
	case "github", "github_sha256":
		return verifyPrefixedHMAC(r.Header.Get("X-Hub-Signature-256"), "sha256=", secret, r)
	case "shopify":
		return verifyRawHMACBase64(r.Header.Get("X-Shopify-Hmac-Sha256"), secret, r)
	case "slack":
		return verifySlackSignature(r.Header.Get("X-Slack-Signature"), r.Header.Get("X-Slack-Request-Timestamp"), secret, r)
	}

	// Generic verification: check common auth patterns. Compare in constant
	// time (subtle.ConstantTimeCompare) - a plain `==` short-circuits on the
	// first differing byte and leaks the secret to a timing side-channel, the
	// same class of bug the HMAC paths already avoid with hmac.Equal.
	// 1. Bearer token in Authorization header
	if authHeader := r.Header.Get("Authorization"); subtle.ConstantTimeCompare([]byte(authHeader), []byte("Bearer "+secret)) == 1 {
		return true
	}
	// 2. Secret in X-Webhook-Secret header
	if secretHeader := r.Header.Get("X-Webhook-Secret"); subtle.ConstantTimeCompare([]byte(secretHeader), []byte(secret)) == 1 {
		return true
	}
	// 3. HMAC signature verification (works with any provider that uses HMAC-SHA256)
	// Check common signature headers
	for _, headerName := range []string{
		flow.Verify, // Custom header name from verify: field (e.g., "X-Hub-Signature-256")
		"X-Signature",
		"X-Webhook-Signature",
	} {
		if headerName == "" {
			continue
		}
		sig := r.Header.Get(headerName)
		if sig != "" && verifyHMACSHA256(sig, secret, r) {
			return true
		}
	}

	return false
}

// verifyStripeSignature validates a Stripe webhook per
// https://stripe.com/docs/webhooks/signatures. Header format:
//
//	Stripe-Signature: t=1492774577,v1=<hex>,v0=<hex>
//
// Signed payload is "<t>.<body>". Timestamps outside a 5 min window are
// rejected (replay protection). Both v1 and v0 (legacy) are accepted.
func verifyStripeSignature(header, secret string, r *http.Request) bool {
	if header == "" {
		return false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	var ts string
	var sigs []string
	for _, part := range strings.Split(header, ",") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		switch kv[0] {
		case "t":
			ts = kv[1]
		case "v1", "v0":
			sigs = append(sigs, kv[1])
		}
	}
	if ts == "" || len(sigs) == 0 {
		return false
	}

	// Replay protection: 5 min window
	tsInt, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		return false
	}
	if skew := time.Now().Unix() - tsInt; skew < -300 || skew > 300 {
		return false
	}

	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + string(body)))
	expected := hex.EncodeToString(mac.Sum(nil))
	for _, sig := range sigs {
		if hmac.Equal([]byte(sig), []byte(expected)) {
			return true
		}
	}
	return false
}

// verifyPrefixedHMAC checks a header like "sha256=<hex>" against HMAC of body.
// Used by GitHub (X-Hub-Signature-256) and compatible providers.
func verifyPrefixedHMAC(header, prefix, secret string, r *http.Request) bool {
	if header == "" || !strings.HasPrefix(header, prefix) {
		return false
	}
	sig := strings.TrimPrefix(header, prefix)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sig), []byte(expected))
}

// verifyRawHMACBase64 checks a base64-encoded HMAC-SHA256 of the body.
// Used by Shopify (X-Shopify-Hmac-Sha256).
func verifyRawHMACBase64(header, secret string, r *http.Request) bool {
	if header == "" {
		return false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(header), []byte(expected))
}

// verifySlackSignature validates a Slack webhook per
// https://api.slack.com/authentication/verifying-requests-from-slack
// Signed payload is "v0:<ts>:<body>"; header format "v0=<hex>".
func verifySlackSignature(sigHeader, tsHeader, secret string, r *http.Request) bool {
	if sigHeader == "" || tsHeader == "" {
		return false
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return false
	}
	r.Body = io.NopCloser(bytes.NewBuffer(body))
	tsInt, err := strconv.ParseInt(tsHeader, 10, 64)
	if err != nil {
		return false
	}
	if skew := time.Now().Unix() - tsInt; skew < -300 || skew > 300 {
		return false
	}
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte("v0:" + tsHeader + ":" + string(body)))
	expected := "v0=" + hex.EncodeToString(mac.Sum(nil))
	return hmac.Equal([]byte(sigHeader), []byte(expected))
}

// verifyHMACSHA256 verifies an HMAC-SHA256 signature against the request body.
func verifyHMACSHA256(signature, secret string, r *http.Request) bool {
	// Read body (already consumed by flow parsing, so check if available)
	body, err := io.ReadAll(r.Body)
	if err != nil || len(body) == 0 {
		return false
	}
	// Restore body for downstream processing
	r.Body = io.NopCloser(bytes.NewBuffer(body))

	// Strip common prefixes (sha256=, v1=, etc.)
	sig := signature
	for _, prefix := range []string{"sha256=", "v1=", "sha1="} {
		sig = strings.TrimPrefix(sig, prefix)
	}

	// Compute HMAC-SHA256
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write(body)
	expected := hex.EncodeToString(mac.Sum(nil))

	return hmac.Equal([]byte(sig), []byte(expected))
}

// ===== Cron =====
//
// v2.7.41: flow-level `trigger.cron` declarations are now scheduled
// via the persistent StartCronScheduler path in cron.go (see
// mergeFlowCronsIntoConfig). The legacy `runCronFlow` /
// `parseCronInterval` helpers that ran cron flows from a bare
// `for { time.Sleep(interval); ... }` loop were removed here - they
// had no stop channel and no persistence, so every SIGHUP-driven
// hot reload spawned a fresh goroutine that started its sleep
// countdown from zero. From the agent's perspective the schedule
// window "reset" on every edit. The persistent scheduler consults
// _benmore_cron_state as the source of truth, so hot reload no
// longer affects when a cron job is next due to fire.

// ===== YAML Parser =====

func parseFlows(content string) []Flow {
	var flows []Flow
	var current *Flow
	var stepStack []*[]FlowStep
	var currentStep *FlowStep

	lines := strings.Split(content, "\n")

	for i := 0; i < len(lines); i++ {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		indent := len(line) - len(strings.TrimLeft(line, " "))

		// Flow name (indent 0)
		if indent == 0 && strings.HasSuffix(trimmed, ":") {
			if current != nil {
				flows = append(flows, *current)
			}
			current = &Flow{
				Name:  strings.TrimSuffix(trimmed, ":"),
				Steps: []FlowStep{},
			}
			stepStack = []*[]FlowStep{&current.Steps}
			currentStep = nil
			continue
		}

		if current == nil {
			continue
		}

		// Flow-level properties (indent 2)
		if indent == 2 {
			parts := strings.SplitN(trimmed, ":", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			val := strings.TrimSpace(parts[1])
			val = strings.Trim(val, `"'`)

			switch key {
			case "trigger":
				current.Trigger = parseTrigger(val)
			case "verify":
				current.Verify = val
			case "secret":
				current.Secret = val
			case "auth":
				current.Auth = val
			case "role":
				current.Role = val
			}
			continue
		}

		// Steps (indent 4+)
		if indent >= 4 && len(stepStack) > 0 {
			// Adjust stack depth based on indentation:
			// indent 4 = depth 1 (top-level steps)
			// indent 8 = depth 2 (nested steps inside if/for_each)
			// indent 12 = depth 3 (double-nested)
			targetDepth := (indent - 2) / 2 // 4->1, 6->2, 8->3, 10->4
			if targetDepth < 1 {
				targetDepth = 1
			}
			// Pop stack if we've come back out to a shallower level
			for len(stepStack) > targetDepth {
				stepStack = stepStack[:len(stepStack)-1]
				currentStep = nil
			}

			target := stepStack[len(stepStack)-1]

			// List item
			if strings.HasPrefix(trimmed, "- ") {
				trimmed = strings.TrimPrefix(trimmed, "- ")

				// Parse step
				step := parseFlowStepLine(trimmed)
				if step != nil {
					*target = append(*target, *step)
					currentStep = &(*target)[len(*target)-1]
				}
				continue
			}

			// Sub-property of current step
			if currentStep != nil {
				parts := strings.SplitN(trimmed, ":", 2)
				if len(parts) == 2 {
					key := strings.TrimSpace(parts[0])
					val := strings.TrimSpace(parts[1])
					val = strings.Trim(val, `"'`)

					// Block sub-properties that declare / promote the step's type.
					// Enables the idiomatic:
					//   - name: room
					//     api:
					//       method: POST
					// pattern where `- name: room` creates a placeholder step
					// and `api:` here promotes it to an API step before the
					// nested method/url/json lines get applied.
					if val == "" {
						switch key {
						case "api":
							if currentStep.API == nil {
								currentStep.API = &FlowAPICall{}
							}
							if currentStep.Type == "" {
								currentStep.Type = "api"
							}
							continue
						case "email":
							if currentStep.Email == nil {
								currentStep.Email = &FlowEmail{}
							}
							if currentStep.Type == "" {
								currentStep.Type = "email"
							}
							continue
						case "respond":
							if currentStep.Respond == nil {
								currentStep.Respond = &FlowRespond{}
							}
							if currentStep.Type == "" {
								currentStep.Type = "respond"
							}
							continue
						}
					}

					// Inline sub-properties that declare the step's type +
					// value in a single line (e.g. `sql: "UPDATE ..."` under
					// `- name: updater`). Only applied when the current step
					// doesn't already have a type.
					if currentStep.Type == "" && val != "" {
						switch key {
						case "sql":
							currentStep.Type = "sql"
							currentStep.SQL = val
							continue
						case "webhook":
							currentStep.Type = "webhook"
							currentStep.Webhook = val
							continue
						case "redirect":
							currentStep.Type = "redirect"
							currentStep.Redirect = val
							continue
						case "parse":
							currentStep.Type = "parse"
							currentStep.Parse = val
							continue
						}
					}

					// "steps:" pushes nested step list onto stack
					if key == "steps" && val == "" {
						stepStack = append(stepStack, &currentStep.Steps)
						currentStep = nil
						continue
					}
					// "else:" pushes else branch onto stack
					if key == "else" && val == "" {
						stepStack = append(stepStack, &currentStep.ElseSteps)
						currentStep = nil
						continue
					}
					// "json:" sub-block for respond/api steps - collect indented key-value pairs
					if key == "json" && val == "" {
						// Read subsequent indented lines as JSON key-value pairs
						jsonMap := make(map[string]any)
						for i+1 < len(lines) {
							nextLine := lines[i+1]
							nextTrimmed := strings.TrimSpace(nextLine)
							nextIndent := len(nextLine) - len(strings.TrimLeft(nextLine, " "))
							if nextTrimmed == "" || nextTrimmed[0] == '#' {
								i++
								continue
							}
							if nextIndent <= indent {
								break // back to same or shallower level
							}
							jParts := strings.SplitN(nextTrimmed, ":", 2)
							if len(jParts) == 2 {
								jKey := strings.TrimSpace(jParts[0])
								jVal := strings.TrimSpace(jParts[1])
								jVal = strings.Trim(jVal, `"'`)
								jsonMap[jKey] = jVal
							}
							i++
						}
						if currentStep.Respond != nil {
							currentStep.Respond.JSON = jsonMap
						} else if currentStep.API != nil {
							// Convert to map[string]string for API JSON field
							apiJSON := make(map[string]string, len(jsonMap))
							for jk, jv := range jsonMap {
								apiJSON[jk] = fmt.Sprintf("%v", jv)
							}
							currentStep.API.JSON = apiJSON
						}
						continue
					}

					// "form:" sub-block for api steps - collect form key-value pairs
					if key == "form" && val == "" && currentStep.API != nil {
						formMap := make(map[string]string)
						for i+1 < len(lines) {
							nextLine := lines[i+1]
							nextTrimmed := strings.TrimSpace(nextLine)
							nextIndent := len(nextLine) - len(strings.TrimLeft(nextLine, " "))
							if nextTrimmed == "" || nextTrimmed[0] == '#' {
								i++
								continue
							}
							if nextIndent <= indent {
								break
							}
							fParts := strings.SplitN(nextTrimmed, ":", 2)
							if len(fParts) == 2 {
								fKey := strings.TrimSpace(fParts[0])
								fVal := strings.TrimSpace(fParts[1])
								fVal = strings.Trim(fVal, `"'`)
								formMap[fKey] = fVal
							}
							i++
						}
						currentStep.API.Form = formMap
						continue
					}

					// "headers:" sub-block for api steps
					if key == "headers" && val == "" && currentStep.API != nil {
						headerMap := make(map[string]string)
						for i+1 < len(lines) {
							nextLine := lines[i+1]
							nextTrimmed := strings.TrimSpace(nextLine)
							nextIndent := len(nextLine) - len(strings.TrimLeft(nextLine, " "))
							if nextTrimmed == "" || nextTrimmed[0] == '#' {
								i++
								continue
							}
							if nextIndent <= indent {
								break
							}
							hParts := strings.SplitN(nextTrimmed, ":", 2)
							if len(hParts) == 2 {
								hKey := strings.TrimSpace(hParts[0])
								hVal := strings.TrimSpace(hParts[1])
								hVal = strings.Trim(hVal, `"'`)
								headerMap[hKey] = hVal
							}
							i++
						}
						currentStep.API.Headers = headerMap
						continue
					}

					// "sign:" sub-block for api steps - outbound auth recipe.
					// Captures the indented block raw and hands it to
					// parseSignBlock (yaml.v3) so we get proper map-order
					// preservation for compute: and nested before:/request:.
					if key == "sign" && val == "" && currentStep.API != nil {
						var block []string
						minIndent := -1
						for i+1 < len(lines) {
							nextLine := lines[i+1]
							nextTrimmed := strings.TrimSpace(nextLine)
							nextIndent := len(nextLine) - len(strings.TrimLeft(nextLine, " "))
							if nextTrimmed == "" || nextTrimmed[0] == '#' {
								block = append(block, nextLine)
								i++
								continue
							}
							if nextIndent <= indent {
								break
							}
							block = append(block, nextLine)
							if minIndent < 0 || nextIndent < minIndent {
								minIndent = nextIndent
							}
							i++
						}
						// Dedent block to column 0 so yaml.v3 parses it.
						var dedented []string
						for _, l := range block {
							if minIndent > 0 && len(l) >= minIndent && strings.TrimSpace(l) != "" {
								dedented = append(dedented, l[minIndent:])
							} else {
								dedented = append(dedented, strings.TrimLeft(l, " "))
							}
						}
						sign, err := parseSignBlock(strings.Join(dedented, "\n"))
						if err != nil {
							// Parse errors stop here - without a usable sign block,
							// the request would ship unauthenticated. Better to fail
							// at load time than at 403 time. We surface the error via
							// a flag the API step can refuse to run with.
							currentStep.API.Sign = &FlowAPISign{Bindings: map[string]string{"_parse_error": err.Error()}}
						} else {
							currentStep.API.Sign = sign
						}
						continue
					}

					applyStepProperty(currentStep, key, val)
				}
			}
		}
	}

	if current != nil {
		flows = append(flows, *current)
	}

	return flows
}

func parseTrigger(val string) FlowTrigger {
	val = strings.TrimSpace(val)

	if strings.HasPrefix(val, "POST ") || strings.HasPrefix(val, "GET ") {
		parts := strings.SplitN(val, " ", 2)
		return FlowTrigger{Type: "http", Method: parts[0], Path: parts[1]}
	}
	if strings.HasPrefix(val, "cron ") {
		return FlowTrigger{Type: "cron", Cron: strings.TrimPrefix(val, "cron ")}
	}
	if strings.HasPrefix(val, "on_insert ") {
		return FlowTrigger{Type: "on_insert", Table: strings.TrimPrefix(val, "on_insert ")}
	}
	if strings.HasPrefix(val, "on_update ") {
		return FlowTrigger{Type: "on_update", Table: strings.TrimPrefix(val, "on_update ")}
	}
	if strings.HasPrefix(val, "on_delete ") {
		return FlowTrigger{Type: "on_delete", Table: strings.TrimPrefix(val, "on_delete ")}
	}

	return FlowTrigger{}
}

func parseFlowStepLine(line string) *FlowStep {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) != 2 {
		return nil
	}
	key := strings.TrimSpace(parts[0])
	val := strings.TrimSpace(parts[1])
	val = strings.Trim(val, `"'`)

	switch key {
	case "sql":
		return &FlowStep{Type: "sql", SQL: val}
	case "webhook":
		return &FlowStep{Type: "webhook", Webhook: val}
	case "redirect":
		return &FlowStep{Type: "redirect", Redirect: val}
	case "if":
		return &FlowStep{Type: "if", Condition: val, Steps: []FlowStep{}}
	case "for_each":
		return &FlowStep{Type: "for_each", ForEach: val, Steps: []FlowStep{}}
	case "parse":
		return &FlowStep{Type: "parse", Parse: val}
	case "email":
		return &FlowStep{Type: "email", Email: &FlowEmail{}}
	case "api":
		return &FlowStep{Type: "api", API: &FlowAPICall{}}
	case "respond":
		return &FlowStep{Type: "respond", Respond: &FlowRespond{}}
	}

	// "name: step_name" starts a step whose type is declared via subsequent
	// sub-properties (api:, email:, sql:, etc.). Returning a placeholder here
	// means sub-properties apply to this step instead of leaking onto the
	// previous one or being silently dropped.
	if key == "name" {
		return &FlowStep{Name: val}
	}

	return nil
}

func applyStepProperty(step *FlowStep, key, val string) {
	switch key {
	case "name":
		step.Name = val
	case "body":
		if step.Type == "webhook" {
			step.WebhookBody = val
		} else if step.Email != nil {
			step.Email.Html = val
		} else if step.Respond != nil {
			step.Respond.Body = val
		} else if step.API != nil {
			step.API.Body = val
		}
	case "html":
		if step.Email != nil {
			step.Email.Html = val
		} else if step.Respond != nil && val != "" {
			// Preserve the pre-existing respond-JSON fallthrough for this key.
			if step.Respond.JSON == nil {
				step.Respond.JSON = make(map[string]any)
			}
			step.Respond.JSON[key] = val
		}
	case "text":
		if step.Email != nil {
			step.Email.Text = val
		} else if step.Respond != nil && val != "" {
			if step.Respond.JSON == nil {
				step.Respond.JSON = make(map[string]any)
			}
			step.Respond.JSON[key] = val
		}
	case "method":
		if step.API != nil {
			step.API.Method = val
		}
	case "url":
		if step.API != nil {
			step.API.URL = val
		}
	case "auth":
		if step.API != nil {
			step.API.Auth = val
		}
	case "status":
		if step.Respond != nil {
			fmt.Sscanf(val, "%d", &step.Respond.Status)
		}
	case "to":
		if step.Email != nil {
			step.Email.To = val
		}
	case "subject":
		if step.Email != nil {
			step.Email.Subject = val
		}
	case "template":
		if step.Email != nil {
			step.Email.Template = val
		}
	case "as":
		if step.Type == "for_each" {
			step.ForAs = val
		}
	case "retry":
		fmt.Sscanf(val, "%d", &step.Retry)
	case "retry_delay":
		step.RetryDelay, _ = time.ParseDuration(val)
	case "timeout":
		step.Timeout, _ = time.ParseDuration(val)
	default:
		// Handle respond JSON sub-keys: any unknown key under a respond step becomes a JSON field
		if step.Respond != nil && val != "" {
			if step.Respond.JSON == nil {
				step.Respond.JSON = make(map[string]any)
			}
			step.Respond.JSON[key] = val
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
