//go:build !cli

package main

// Flow loading, route registration, event dispatch, and HTTP execution lifecycle.
// Step implementations and parsing live in flows_*.go; persistent scheduling lives in cron.go.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// LoadFlows reads flows.yaml from the app directory.
func LoadFlows(dir string) []Flow {
	path := filepath.Join(dir, "flows.yaml")
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	return parseFlows(string(data))
}

// flowParallelHasSQL reports whether a `parallel` step has any SQL
// (sql / sql_dynamic) step nested anywhere beneath it. Used to reject
// SQL inside a parallel-in-transaction block, where the children would
// otherwise share one non-concurrency-safe *sql.Tx.
func flowParallelHasSQL(parallel *FlowStep) bool {
	var walk func(steps []FlowStep) bool
	walk = func(steps []FlowStep) bool {
		for i := range steps {
			s := &steps[i]
			if s.Type == "sql" || s.Type == "sql_dynamic" {
				return true
			}
			if walk(s.Steps) || walk(s.ElseSteps) || walk(s.OnError) {
				return true
			}
		}
		return false
	}
	return walk(parallel.Steps)
}

// flowValidateParallelTx implements H-4: in a transaction:true flow,
// parallel children all run against the same ctx.Tx, but database/sql's
// *sql.Tx is explicitly NOT safe for concurrent use. Reject any
// sql/sql_dynamic step nested inside a parallel block of a transactional
// flow at validation time so the author fixes it before it ships,
// instead of hitting a nondeterministic data race at runtime. Returns a
// descriptive error naming the flow, or nil when the flow is safe.
func flowValidateParallelTx(flow *Flow) error {
	if flow == nil || !flow.Transaction {
		return nil
	}
	var walk func(steps []FlowStep) error
	walk = func(steps []FlowStep) error {
		for i := range steps {
			s := &steps[i]
			if s.Type == "parallel" && flowParallelHasSQL(s) {
				return fmt.Errorf("flow %q: a parallel block contains SQL steps but the flow is transaction:true - a *sql.Tx cannot be shared across the parallel goroutines (data race). Move the SQL out of the parallel block, or remove transaction:true", flow.Name)
			}
			if err := walk(s.Steps); err != nil {
				return err
			}
			if err := walk(s.ElseSteps); err != nil {
				return err
			}
			if err := walk(s.OnError); err != nil {
				return err
			}
		}
		return nil
	}
	return walk(flow.Steps)
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
		// H-4: reject SQL-in-parallel-in-transaction at registration time.
		// Skip registering the offending flow (rather than crash the app)
		// and log loudly so the author fixes the unsafe shared-*sql.Tx
		// pattern before it can race.
		if err := flowValidateParallelTx(&f); err != nil {
			log.Printf("ERROR: %s - skipping flow registration", err)
			continue
		}
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
	app.mu.RLock()
	flows := append([]Flow(nil), app.Flows...)
	app.mu.RUnlock()
	for _, flow := range flows {
		if flow.Trigger.Type == event && flow.Trigger.Table == table {
			f := flow
			select {
			case flowsEventSem <- struct{}{}:
				safeGo("flows.event:"+f.Name, func() {
					defer func() { <-flowsEventSem }()
					runFlowEvent(app, f, row)
				})
			default:
				runFlowEvent(app, f, row)
			}
		}
	}
}

const flowsEventFanoutLimit = 32

var flowsEventSem = make(chan struct{}, flowsEventFanoutLimit)

func runFlowEvent(app *App, f Flow, row map[string]any) {
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
}

// The returned error lets internal dispatchers observe failures after a respond
// step (in particular a failed transaction commit), even if headers were sent.
func executeFlowHTTP(app *App, flow *Flow, w http.ResponseWriter, r *http.Request) error {
	return executeFlowHTTPAs(app, flow, w, r, nil)
}

// scheduledActor is supplied only by the scheduler after owner/permission checks.
// It never comes from an HTTP header or body and cannot mint a login session.
func executeFlowHTTPAs(app *App, flow *Flow, w http.ResponseWriter, r *http.Request, scheduledActor *Session) (executionErr error) {
	// Declarative rate limiting (opt-in via `rate_limit:` on on.request).
	// Reject over-limit requests with 429 + Retry-After BEFORE any work runs.
	if flow.RateLimit != nil {
		key := rateLimitKey(app, flow.RateLimit.Scope, r)
		if scheduledActor != nil {
			key = rateLimitKeyForSession(scheduledActor, flow.RateLimit.Scope, r)
		}
		if !flowLimiterFor(app, flow).Allow(key) {
			w.Header().Set("Retry-After", strconv.Itoa(int(flow.RateLimit.Window.Seconds())))
			http.Error(w, "rate limit exceeded - retry after "+flow.RateLimit.Window.String(), http.StatusTooManyRequests)
			if scheduledActor != nil {
				return errScheduledFlowRateLimited
			}
			return
		}
	}
	ctx := &FlowContext{
		App:     app,
		Request: r,
		Writer:  w,
		Data:    make(map[string]any),
		Params:  make(map[string]string),
		// Taint set: every key written below originates from the inbound
		// request, so sql_dynamic must treat it as untrusted (see M-1 /
		// flowDynamicGuardRequestRefs).
		RequestKeys: make(map[string]bool),
	}
	defer func() { executionErr = ctx.Error }()

	// A purge flow must not send its irreversible-looking success response
	// before SQLite has actually committed. Ordinary transactional flows retain
	// their existing streaming behavior; the identity-erasure primitive uses a
	// small response buffer and flushes it only after a successful commit.
	var purgeResponse *flowResponseBuffer
	if flowHasPurgeCurrentUser(flow.Steps) {
		purgeResponse = newFlowResponseBuffer()
		ctx.Writer = purgeResponse
	}

	// Extract path params from the original :param definitions
	pathParts := strings.Split(flow.Trigger.Path, "/")
	reqParts := strings.Split(r.URL.Path, "/")
	for i, part := range pathParts {
		if strings.HasPrefix(part, ":") && i < len(reqParts) {
			paramName := strings.TrimPrefix(part, ":")
			ctx.Params[paramName] = reqParts[i]
			ctx.Data[paramName] = reqParts[i]
			ctx.RequestKeys[paramName] = true
		}
	}
	// Also try Go 1.22 PathValue for {param} patterns
	for _, part := range pathParts {
		if strings.HasPrefix(part, ":") {
			paramName := strings.TrimPrefix(part, ":")
			if val := r.PathValue(paramName); val != "" {
				ctx.Params[paramName] = val
				ctx.Data[paramName] = val
				ctx.RequestKeys[paramName] = true
			}
		}
	}

	// Extract query params
	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			ctx.Params[k] = v[0]
			ctx.Data[k] = v[0]
			ctx.RequestKeys[k] = true
		}
	}

	// Verify inbound webhooks against the untouched request body. This must
	// stay before ParseForm and JSON binding: both consume r.Body, and an HMAC
	// over reconstructed or truncated bytes is not the provider's signature.
	// Path params are already available above for path-bound bearer recipes.
	// Rich recipe form takes precedence over the legacy string form so flows
	// can migrate without an ambiguous verification order.
	if flow.VerifyConfig != nil {
		if err := runVerifyRecipe(flow.VerifyConfig, r, app.Dir); err != nil {
			log.Printf("FLOW VERIFY REJECT [%s]: %s", flow.Name, err)
			if errors.Is(err, errVerifyBodyTooLarge) {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, "Invalid signature", http.StatusUnauthorized)
			}
			return
		}
	} else if flow.Verify != "" {
		if !verifyWebhookSignature(flow, r, app.Dir) {
			http.Error(w, "Invalid signature", http.StatusUnauthorized)
			return
		}
	}

	// Extract POST form data (application/x-www-form-urlencoded or multipart)
	if r.Method == "POST" {
		r.ParseForm()
		for k, v := range r.PostForm {
			if len(v) > 0 && k != "csrf_token" {
				ctx.Params[k] = v[0]
				ctx.Data[k] = v[0]
				ctx.RequestKeys[k] = true
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
	if scheduledActor != nil || r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		if strings.Contains(ct, "application/json") && r.Body != nil {
			rawBody, _ := io.ReadAll(io.LimitReader(r.Body, flowVerifyBodyMaxBytes))
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
						ctx.RequestKeys[k] = true
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
					ctx.RequestKeys[k] = true
				}
			}
		}
	}

	// CSRF + Bearer gate for state-changing HTTP-triggered flows. Mirrors
	// the CRUD/workflow/webhook handlers: a cookie-authenticated, mutating
	// request must carry a valid CSRF token; Bearer-token (API) callers are
	// exempt because they don't ride on ambient cookies. Without this,
	// HTTP flows were the one mutation surface a cross-site form could
	// drive using the victim's session cookie.
	//
	// The check is scoped to requests that actually carry the session
	// cookie: CSRF is an ambient-credential attack, so a request with no
	// `_benmore_session` cookie has no victim session to ride and is not a
	// CSRF vector (this also preserves cookieless API/webhook callers).
	// GET/HEAD/OPTIONS are nullipotent by convention and skip the check.
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		if c, _ := r.Cookie(sessionCookieName); c != nil && !isBearerAuth(r) && !validateCSRF(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
	}

	// Auth enforcement for HTTP-triggered flows
	if scheduledActor != nil || flow.Auth == "required" || flow.Role != "" {
		session := scheduledActor
		if session == nil {
			session = getSession(app, r)
		}
		if session == nil {
			// RFC 9728 pointer so MCP clients hitting an auth-required
			// flow discover the app's OAuth provider and start the flow.
			SetAppOAuthChallenge(w, r)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		// Use the shared multi-role resolver (session.Roles via
		// HasAnyRole) instead of a single-field session.Role compare. The
		// old check ignored grants in _benmore_user_roles, so a user
		// holding the required role only via the join table was wrongly
		// denied (and an admin grant via the join table didn't bypass).
		if flow.Role != "" && !HasAnyRole(session, []string{flow.Role}) {
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
		for key := range ctx.Data {
			if strings.HasPrefix(key, "user.") {
				delete(ctx.Data, key)
				delete(ctx.Params, key)
				delete(ctx.RequestKeys, key)
				delete(ctx.NullParams, key)
			}
		}

		ctx.Data["user_id"] = session.UserID
		ctx.Data["user_email"] = session.Email
		ctx.Data["user_role"] = session.Role
		ctx.Session = session
		if userRow := LoadUserFields(app.DB, session.UserID); userRow != nil {
			if scheduledActor != nil {
				userRow["role"] = session.Role
			}
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

		for _, key := range []string{"user", "user_id", "user_email", "user_role", "_group_id", "_group_key"} {
			delete(ctx.Params, key)
			delete(ctx.NullParams, key)
			delete(ctx.RequestKeys, key)
		}
		ctx.Params["user_id"] = fmt.Sprint(session.UserID)
		ctx.Params["user_email"] = session.Email
		ctx.Params["user_role"] = session.Role
		ctx.Data["_group_id"] = ""
		ctx.Data["_group_key"] = ""
		ctx.Params["_group_id"] = ""
		ctx.Params["_group_key"] = ""

		// Tenant row-scoping affordance for flow SQL. When this app is
		// multi-tenant (groups configured) and the session is bound to a
		// tenant (and is not an admin bypassing scope), expose the
		// server-resolved effective tenant key so authored SQL can scope
		// rows with a TRUSTED value (e.g. `WHERE <group_key> = :_group_id`)
		// instead of trusting a request-supplied group id. This is bound,
		// never request-tainted, so it stays usable even from sql_dynamic.
		if app.Group != nil && app.Group.Key != "" && session.EffectiveHasGroup() && !session.IsAdminBypass() {
			gid := session.EffectiveGroupID()
			ctx.Params["_group_id"] = gid
			ctx.Data["_group_id"] = gid
			ctx.Data["_group_key"] = app.Group.Key
			ctx.Params["_group_key"] = app.Group.Key
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
	var guard *txCommitGuard
	if flow.Transaction {
		tx, err := app.DB.Begin()
		if err != nil {
			log.Printf("FLOW ERROR [%s] begin tx: %s", flow.Name, err)
			http.Error(w, "Internal error", http.StatusInternalServerError)
			return
		}
		ctx.Tx = tx
		// guard (txCommitGuard, jobs.go) finalizes the *sql.Tx exactly once even
		// if executeSteps PANICS. recoverMiddleware (host.go/router.go/server.go)
		// is the OUTERMOST defer and swallows the panic, so without this the stack
		// unwinds straight past the commit/rollback below and the *sql.Tx is never
		// finalized: its connection never returns to the pool, and under SQLite WAL
		// an unreturned write-tx holds the app's write lock UNTIL RESTART - the
		// sustained "[locks] cleanup error: database is locked" storm. cron.go and
		// jobs.go already guard their tx paths; this is the HTTP flow route (every
		// browser request), and it was the one holding-lock path they missed.
		guard = &txCommitGuard{tx: tx}
		defer guard.rollbackUnlessHandled()
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
		guard.MarkHandled()
	}
	if purgeResponse != nil {
		if ctx.Error == nil {
			purgeResponse.flushTo(w)
		} else {
			// Discard any success body/status produced before a rollback or failed
			// commit and let the normal error path write to the real response.
			ctx.Writer = w
			ctx.Stopped = false
		}
	}

	if ctx.Error != nil {
		log.Printf("FLOW ERROR [%s] %s", flow.Name, ctx.Error)
		if !ctx.Stopped {
			http.Error(w, "Internal error", http.StatusInternalServerError)
		}
	}

	// Scheduled jobs historically did not need an HTTP respond step. Preserve
	// that contract while retaining HTTP input taint, identity and policy gates.
	if scheduledActor != nil && ctx.Error == nil && !ctx.Stopped {
		return
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
			// A step errored out. Log the granular detail (failing step,
			// type, raw error, hint) server-side, but DO NOT leak the raw
			// SQL/step error text to the client - it can expose schema,
			// query shape, and internal paths. The client gets only a
			// generic marker; operators correlate via the server log.
			log.Printf("FLOW ERROR DETAIL [%s] failed_step=%q failed_type=%q error=%s hint=%s",
				flow.Name, ctx.FailedStep, ctx.FailedType, ctx.Error.Error(),
				stepFailureHint(ctx.FailedStep, ctx.FailedType, ctx.Error.Error()))
			resp["failed_step"] = ctx.FailedStep
			resp["failed_type"] = ctx.FailedType
		} else {
			resp["hint"] = "every step ran without erroring, but no step was a `run: respond` (or `run: redirect`). Add a `- run: respond` step at the end of the job, with `with: { status: 200, body: { ok: true } }`."
		}
		json.NewEncoder(w).Encode(resp)
	}
	return

}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
