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
	"maps"
	"mime"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
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
	if err := flowValidateParallelHTTP(flow); err != nil {
		return err
	}
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
func RegisterFlows(mux appRouteRegistrar, app *App, flows []Flow) map[string]string {
	registered := make(map[string]string)
	for _, flow := range flows {
		f := flow
		if f.Command != nil || f.Trigger.Type == "command" {
			continue
		}
		if err := flowValidateTransactionalResponse(&f); err != nil {
			log.Printf("ERROR: %s - skipping flow registration", err)
			continue
		}
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
				registered[f.Name] = pattern
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
	return registered
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
	runFlowEventWith(app, f, row, nil)
}

// runFlowEventWith is runFlowEvent with a hook that sees the finished
// context (tests).
func runFlowEventWith(app *App, f Flow, row map[string]any, done func(*FlowContext)) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("FLOW EVENT PANIC [%s]: %v", f.Name, r)
		}
	}()
	ctx := &FlowContext{
		App:         app,
		Data:        make(map[string]any),
		Params:      make(map[string]string),
		Writes:      newFlowWriteLog(),
		RequestKeys: flowEventRowTaint(app, row),
	}
	if done != nil {
		defer done(ctx)
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
	committed := false
	if ctx.Tx != nil {
		if ctx.Error != nil {
			ctx.Tx.Rollback()
		} else if err := ctx.Tx.Commit(); err != nil {
			ctx.Error = fmt.Errorf("commit: %w", err)
		} else {
			committed = true
		}
	}
	announceFlowWrites(ctx, committed)
	if ctx.Error != nil {
		log.Printf("FLOW ERROR [%s] %s", f.Name, ctx.Error)
	}
}

// flowEventRowTaint is the request-taint set of a data-event flow. The row is
// what the caller just wrote, so its columns are request input for the
// sql_dynamic and enqueue guards, as they were on the write itself. The
// columns the framework sets (the id, owner, tenant, timestamps and session
// keys, and their old_* copies) are trusted: realtime scoping reads the owner
// and tenant from them (sessionlessWriteScope).
func flowEventRowTaint(app *App, row map[string]any) map[string]bool {
	trusted := map[string]bool{
		"id": true, "user_id": true, "created_at": true, "updated_at": true, "deleted_at": true,
		"user_email": true, "user_role": true, "user_roles": true, "user_group_id": true,
		"_group_id": true, "_group_key": true,
	}
	if app != nil && app.Group != nil && app.Group.Key != "" {
		trusted[app.Group.Key] = true
	}
	keys := make(map[string]bool, len(row))
	for k := range row {
		if trusted[k] || trusted[strings.TrimPrefix(k, "old_")] {
			continue
		}
		keys[k] = true
	}
	return keys
}

// The returned error lets internal dispatchers observe failures after a respond
// step (in particular a failed transaction commit), even if headers were sent.
func executeFlowHTTP(app *App, flow *Flow, w http.ResponseWriter, r *http.Request) error {
	return executeFlowHTTPAs(app, flow, w, r, nil)
}

// scheduledActor is supplied only by the scheduler after owner/permission checks.
// It never comes from an HTTP header or body and cannot mint a login session.
func executeFlowHTTPAs(app *App, flow *Flow, w http.ResponseWriter, r *http.Request, scheduledActor *Session) (executionErr error) {
	return executeFlowHTTPAsWithAPIClient(app, flow, w, r, scheduledActor, nil)
}

// executeFlowHTTPAsWithAPIClient is the package-private native-test seam for
// running a parsed HTTP flow against a controlled transport. Production callers
// use executeFlowHTTPAs, which always leaves the client nil and uses the strict
// SSRF-guarded client. URL validation in execAPIRequest remains unconditional.
func executeFlowHTTPAsWithAPIClient(app *App, flow *Flow, w http.ResponseWriter, r *http.Request, scheduledActor *Session, apiClient *http.Client) (executionErr error) {
	if flow != nil && (flow.Command != nil || flow.Trigger.Type == "command") {
		return fmt.Errorf("command declarations cannot execute as ordinary HTTP flows")
	}
	if err := flowValidateTransactionalResponse(flow); err != nil {
		serverError(w, r, app, "flow "+flow.Name, err, "Invalid flow configuration")
		return err
	}
	if err := flowValidateParallelHTTP(flow); err != nil {
		serverError(w, r, app, "flow "+flow.Name, err, "Invalid flow configuration")
		return err
	}
	var strictJSONBody map[string]any
	if flow.Trigger.StrictJSON {
		mediaType, _, mediaErr := mime.ParseMediaType(r.Header.Get("Content-Type"))
		if mediaErr != nil || !strings.EqualFold(mediaType, "application/json") {
			http.Error(w, "Invalid JSON request", http.StatusBadRequest)
			return errInvalidStrictJSONRequest
		}
		rawBody, readErr := io.ReadAll(io.LimitReader(r.Body, flowStrictJSONMaxBytes+1))
		if readErr != nil || len(rawBody) > flowStrictJSONMaxBytes {
			http.Error(w, "Invalid JSON request", http.StatusBadRequest)
			return errInvalidStrictJSONRequest
		}
		var decodeErr error
		strictJSONBody, decodeErr = decodeStrictFlowJSON(rawBody)
		if decodeErr != nil {
			http.Error(w, "Invalid JSON request", http.StatusBadRequest)
			return errInvalidStrictJSONRequest
		}
		r.Body = io.NopCloser(bytes.NewReader(rawBody))
	}
	privateFlow, connectorRead := r.Context().Value(appMCPPrivateFlowKey{}).(*appMCPPrivateFlow)
	if connectorRead && (privateFlow == nil || privateFlow.flow != flow || appMCPReadFlowPolicy(flow) != nil || getSession(app, r) == nil) {
		http.Error(w, "Connector grant denied", 403)
		return errAppMCPGrantDenied
	}
	// Declarative rate limiting (opt-in via `rate_limit:` on on.request).
	// Reject over-limit requests with 429 + Retry-After BEFORE any work runs.
	if flow.RateLimit != nil {
		key := rateLimitKey(app, flow.RateLimit.Scope, r)
		if scheduledActor != nil {
			key = rateLimitKeyForSession(scheduledActor, flow.RateLimit.Scope, r)
		} else if connectorRead && flow.RateLimit.Scope == "ip" {
			// A connector call is in-process and has no client address; an
			// ip bucket would be one bucket shared by every connected user.
			key = "mcp:u:" + strconv.FormatInt(privateFlow.actor.UserID, 10)
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
		App:       app,
		Request:   r,
		Writer:    w,
		apiClient: apiClient,
		Data:      make(map[string]any),
		Params:    make(map[string]string),
		// Taint set: every key written below originates from the inbound
		// request, so sql_dynamic must treat it as untrusted (see M-1 /
		// flowDynamicGuardRequestRefs).
		RequestKeys: make(map[string]bool),
		Writes:      newFlowWriteLog(),
	}
	defer func() { executionErr = ctx.Error }()

	// Transactional responses stay private until COMMIT succeeds.
	var responseBuffer *flowResponseBuffer
	if flow.Transaction {
		responseBuffer = newFlowResponseBuffer()
		ctx.Writer = responseBuffer
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
		// The provider verifiers read the whole body; buffer it under the
		// same cap as the recipe form first, so an unauthenticated caller
		// cannot make the process hold an arbitrarily large body.
		if _, err := readVerifyBody(r); err != nil {
			if errors.Is(err, errVerifyBodyTooLarge) {
				http.Error(w, "Request body too large", http.StatusRequestEntityTooLarge)
			} else {
				http.Error(w, "Invalid signature", http.StatusUnauthorized)
			}
			return
		}
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
	if connectorRead || scheduledActor != nil || r.Method == "POST" || r.Method == "PUT" || r.Method == "PATCH" {
		ct := strings.ToLower(r.Header.Get("Content-Type"))
		if strings.Contains(ct, "application/json") && r.Body != nil {
			rawBody, readErr := io.ReadAll(io.LimitReader(r.Body, flowVerifyBodyMaxBytes+1))
			if len(flow.Trigger.Inputs) > 0 && (readErr != nil || int64(len(rawBody)) > flowVerifyBodyMaxBytes) {
				http.Error(w, "Invalid or oversized flow request body", http.StatusBadRequest)
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(rawBody))
			var data map[string]any
			decode := func() error {
				if flow.Trigger.StrictJSON {
					data = strictJSONBody
					return nil
				}
				if !connectorRead {
					return json.Unmarshal(rawBody, &data)
				}
				decoder := json.NewDecoder(bytes.NewReader(rawBody))
				decoder.UseNumber()
				return decoder.Decode(&data)
			}
			if err := decode(); len(flow.Trigger.Inputs) > 0 && (err != nil || data == nil) {
				http.Error(w, "Flow request body must be a JSON object", http.StatusBadRequest)
				return
			} else if err == nil {
				// A later parse step can consume body values even when query/path
				// binding wins. Validate every declared body value before skipping it.
				bodyInputs := make(map[string]FlowInput)
				for name := range data {
					if input, ok := flow.Trigger.Inputs[name]; ok {
						bodyInputs[name] = input
					}
				}
				if err := validateFlowInputValues(bodyInputs, data); err != nil {
					http.Error(w, err.Error(), http.StatusUnprocessableEntity)
					return
				}
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
	// session cookie has no victim session to ride and is not a
	// CSRF vector (this also preserves cookieless API/webhook callers).
	// GET/HEAD/OPTIONS are nullipotent by convention and skip the check.
	switch r.Method {
	case http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete:
		// Connector dispatch (connectorRead) is an in-process call whose request
		// carries no cookie; it is recognized only through an unexported context
		// value no HTTP request can supply.
		if c, _ := requestSessionCookie(r); c != nil && !connectorRead && !isBearerAuth(r) && !validateCSRF(r) {
			http.Error(w, "Invalid CSRF token", http.StatusForbidden)
			return
		}
	}

	// Identity keys are server-owned in EVERY flow. Strip any request-supplied
	// value first: an auth-required flow re-populates them from the session
	// below, and a public flow must never bind a caller-claimed user id or
	// tenant (it gets the real identity only if the caller is signed in).
	stripRequestIdentityKeys(ctx)
	// Step outputs can shadow request names; retain the declared input values
	// before that move so both optional and required inputs remain checked.
	inputValues := make(map[string]any, len(flow.Trigger.Inputs))
	for name := range flow.Trigger.Inputs {
		if value, present := ctx.Data[name]; present {
			inputValues[name] = value
		}
	}
	shadowStepNamedRequestKeys(ctx, flow.Steps)
	if scheduledActor == nil && flow.Auth != "required" && flow.Role == "" && len(flow.Permissions) == 0 {
		// Anonymous default: identity placeholders bind SQL NULL.
		if ctx.NullParams == nil {
			ctx.NullParams = map[string]bool{}
		}
		for _, key := range []string{"user_id", "user_email", "_group_id", "_group_key"} {
			ctx.Params[key] = ""
			ctx.NullParams[key] = true
		}
		if session := getSession(app, r); session != nil {
			ctx.privateResponse = true
			delete(ctx.NullParams, "user_id")
			delete(ctx.NullParams, "user_email")
			ctx.Data["user_id"] = session.UserID
			ctx.Data["user_email"] = session.Email
			ctx.Params["user_id"] = fmt.Sprint(session.UserID)
			ctx.Params["user_email"] = session.Email
		}
	}

	// Auth enforcement for HTTP-triggered flows
	if scheduledActor != nil || flow.Auth == "required" || flow.Role != "" || len(flow.Permissions) > 0 {
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
		if len(flow.Permissions) > 0 && !scopesWithin(session.Scopes, strings.Join(flow.Permissions, " ")) {
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

		for _, key := range flowIdentityKeys {
			delete(ctx.Params, key)
			delete(ctx.NullParams, key)
			delete(ctx.RequestKeys, key)
		}
		// `${{ user.group_id }}` / `${{ user.org_id }}` translate to
		// user_group_id: the caller's current tenant (an admin's act-as
		// tenant), as in hooks. Nothing set it for flows, so the only
		// value it could take was a same-named request field.
		delete(ctx.Data, "user_group_id")
		if gid := session.EffectiveGroupID(); gid != "" {
			ctx.Data["user_group_id"] = gid
			ctx.Params["user_group_id"] = gid
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

	if err := validateFlowInputValues(flow.Trigger.Inputs, inputValues); err != nil {
		http.Error(w, err.Error(), http.StatusUnprocessableEntity)
		return
	}

	if connectorRead {
		closeConn, err := startAppMCPReadFlow(ctx)
		if err != nil {
			serverError(w, r, app, "flow "+flow.Name, err, "Connector read unavailable")
			ctx.Error = err
			return
		}
		defer closeConn()
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
		// The request-taint set must survive the async boundary, or the
		// worker runs sql_dynamic with no taint and the M-1 guard never fires.
		// Written after the copy so a request field of the same name cannot
		// forge or clear it.
		if len(ctx.RequestKeys) > 0 {
			keys := make([]string, 0, len(ctx.RequestKeys))
			for k := range ctx.RequestKeys {
				keys = append(keys, k)
			}
			payload[flowRequestKeysPayloadField] = keys
		} else {
			delete(payload, flowRequestKeysPayloadField)
		}
		// Nothing has run yet, so nothing is secret-derived; a request field
		// of the reserved name must not reach the worker as the secret set.
		delete(payload, flowSecretKeysPayloadField)
		// The signed-in caller the job runs for, so the worker can re-check
		// the account before it acts for them (flowJobActorLive). Written
		// after the copy, like the taint set, so a request can't set it.
		if ctx.Session != nil && ctx.Session.UserID > 0 {
			payload[flowJobActorPayloadField] = snapshotFlowJobActor(ctx.Session)
		} else {
			delete(payload, flowJobActorPayloadField)
		}
		jobID, jobToken, err := EnqueueJob(app.DB, flow.Name, payload, nil)
		if err != nil {
			id := recordRequestError(r, serverErrorDetail("flow "+flow.Name+" enqueue", err))
			log.Printf("FLOW ASYNC ENQUEUE ERROR [%s]: %s (request %s)", flow.Name, err, id)
			answerServerError(w, app, http.StatusInternalServerError, id, err, "Internal error")
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
	if flow.Transaction && connectorRead {
		if err := appMCPReadFlowTransaction(ctx, "BEGIN"); err != nil {
			ctx.Error = err
			return
		}
		defer appMCPReadFlowTransaction(ctx, "ROLLBACK")
	} else if flow.Transaction {
		tx, err := app.DB.Begin()
		if err != nil {
			log.Printf("FLOW ERROR [%s] begin tx: %s", flow.Name, err)
			ctx.Error = err
		} else {
			ctx.Tx = tx
			// guard (txCommitGuard, jobs.go) finalizes the *sql.Tx exactly once even
			// if executeSteps PANICS. recoverMiddleware (host.go/router.go/server.go)
			// is the OUTERMOST defer and swallows the panic, so without this the stack
			// unwinds straight past the commit/rollback below and the *sql.Tx is never
			// finalized: its connection never returns to the pool, and under SQLite WAL
			// an unreturned write-tx holds the app's write lock UNTIL RESTART - the
			// sustained "[locks] cleanup error: database is locked" storm. cron.go and
			// jobs.go already guard their tx paths; this is the HTTP flow route.
			guard = &txCommitGuard{tx: tx}
			defer guard.rollbackUnlessHandled()
		}
	}

	if ctx.Error == nil {
		executeSteps(ctx, flow.Steps)
	}
	if responseBuffer != nil && responseBuffer.err != nil && ctx.Error == nil {
		ctx.Error = responseBuffer.err
	}

	// Commit or rollback transaction
	committed := false
	if ctx.Tx != nil {
		if ctx.Error != nil {
			ctx.Tx.Rollback()
		} else {
			if err := ctx.Tx.Commit(); err != nil {
				log.Printf("FLOW ERROR [%s] commit: %s", flow.Name, err)
				ctx.Error = err
			} else {
				committed = true
			}
		}
		guard.MarkHandled()
	}
	if connectorRead && flow.Transaction {
		statement := "COMMIT"
		if ctx.Error != nil {
			statement = "ROLLBACK"
		}
		if err := appMCPReadFlowTransaction(ctx, statement); err != nil {
			ctx.Error = err
		}
	}
	// The cause, for the server-side record: a connector read's result
	// replaces it with a fixed failure code below.
	failure := ctx.Error
	if connectorRead && ctx.Error != nil {
		ctx.Error = appMCPResultFailure("incomplete_result")
	}
	announceFlowWrites(ctx, committed)
	if responseBuffer != nil {
		// An error handler may deliberately answer after the failed transaction
		// rolls back. Keep the original failure, and never release an incomplete
		// buffer or a failed connector read's result.
		canRespond := ctx.Error == nil || ctx.errorResponse && !connectorRead
		if canRespond && responseBuffer.err == nil && responseBuffer.status != 0 {
			responseBuffer.flushTo(w)
		} else if ctx.Error != nil {
			// Discard output produced before a rollback or failed commit.
			ctx.Writer = w
			ctx.Stopped = false
		}
	}

	// A failed flow's request log row carries what broke (failing step, its
	// type, the error and the step hint), under the request id its answer
	// carries; the journal keeps the FLOW ERROR lines.
	requestID := ""
	if ctx.Error != nil {
		requestID = recordRequestError(r, flowFailureDetail(flow, ctx, failure))
		log.Printf("FLOW ERROR [%s] %s (request %s)", flow.Name, failure, requestID)
		if !ctx.Stopped {
			// A write past the app's storage limit is a capacity condition the
			// caller can act on, not a server fault.
			if respondStorageFull(w, app, ctx.Error) {
				return
			}
			answerServerError(w, app, http.StatusInternalServerError, requestID, failure, "Internal error")
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
		if requestID == "" {
			requestID = recordRequestError(r, fmt.Sprintf("[flow %s] flow_no_response: %d of %d steps ran without erroring and none responded", flow.Name, ctx.StepsRun, len(flow.Steps)))
			w.Header().Set(requestIDHeader, requestID)
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusInternalServerError)
		resp := map[string]any{
			"error":          "flow_no_response",
			"flow":           flow.Name,
			"steps_declared": len(flow.Steps),
			"steps_run":      ctx.StepsRun,
			"request_id":     requestID,
		}
		if ctx.Error != nil {
			// A step errored out. Log the granular detail (failing step,
			// type, raw error, hint) server-side, but DO NOT leak the raw
			// SQL/step error text to the client - it can expose schema,
			// query shape, and internal paths. The client gets only a
			// generic marker; operators correlate via the server log and
			// the request log row of request_id.
			log.Printf("FLOW ERROR DETAIL [%s] failed_step=%q failed_type=%q error=%s hint=%s request=%s",
				flow.Name, ctx.FailedStep, ctx.FailedType, errorText(failure),
				stepFailureHint(ctx.FailedStep, ctx.FailedType, errorText(failure)), requestID)
			resp["failed_step"] = ctx.FailedStep
			resp["failed_type"] = ctx.FailedType
		} else {
			resp["hint"] = "every step ran without erroring, but no step was a `run: respond` (or `run: redirect`). Add a `- run: respond` step at the end of the job, with `with: { status: 200, body: { ok: true } }`."
		}
		json.NewEncoder(w).Encode(resp)
	}
	return

}

// flowFailureDetail is a failed flow's request log error: the failing step,
// its type, the error and the step-type hint, as the FLOW ERROR DETAIL line
// has them. A failure outside a step (begin, commit) has no step.
func flowFailureDetail(flow *Flow, ctx *FlowContext, failure error) string {
	msg := errorText(failure)
	if ctx.FailedStep == "" {
		return fmt.Sprintf("[flow %s] %s", flow.Name, msg)
	}
	return fmt.Sprintf("[flow %s] failed_step=%q failed_type=%q error=%s hint=%s",
		flow.Name, ctx.FailedStep, ctx.FailedType, msg, stepFailureHint(ctx.FailedStep, ctx.FailedType, msg))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// flowRequestKeysPayloadField carries an async flow's request-taint set
// (FlowContext.RequestKeys) through the job payload to executeFlowJob.
const flowRequestKeysPayloadField = "__benmore_request_keys"

// flowSecretKeysPayloadField carries the secret-derived keys of an enqueue
// step's payload (FlowContext.SecretKeys) to the job flow.
const flowSecretKeysPayloadField = "__benmore_secret_keys"

// flowJobActorPayloadField carries server-owned identity and restrictions for
// an async HTTP flow. It never contains a reusable credential.
const flowJobActorPayloadField = "__benmore_job_actor"

type flowJobActorSnapshot struct {
	Version            int      `json:"version"`
	UserID             int64    `json:"user_id"`
	GroupID            string   `json:"group_id"`
	ActingAsGroup      string   `json:"acting_as_group"`
	Scopes             string   `json:"scopes"`
	CredentialScopes   string   `json:"credential_scopes"`
	Roles              []string `json:"roles"`
	GlobalAdmin        bool     `json:"global_admin"`
	ConnectorGrant     bool     `json:"connector_grant"`
	ImpersonatorUserID int64    `json:"impersonator_user_id"`
	ImpersonatorEmail  string   `json:"impersonator_email"`
}

func snapshotFlowJobActor(session *Session) flowJobActorSnapshot {
	roles := append([]string(nil), session.Roles...)
	if len(roles) == 0 && session.Role != "" {
		roles = []string{session.Role}
	}
	return flowJobActorSnapshot{
		Version: 1, UserID: session.UserID, GroupID: session.GroupID,
		ActingAsGroup: session.ActingAsGroup, Scopes: session.Scopes,
		CredentialScopes: session.CredentialScopes, Roles: roles,
		GlobalAdmin: session.IsAdmin(), ConnectorGrant: session.connectorGrant,
		ImpersonatorUserID: session.ImpersonatorUserID, ImpersonatorEmail: session.ImpersonatorEmail,
	}
}

// Numeric actors were queued by older runtimes without their restrictions.
// Keep those jobs usable, but never infer direct-sign-in authority from them.
func takeFlowJobActor(data map[string]any) (*flowJobActorSnapshot, error) {
	raw, ok := data[flowJobActorPayloadField]
	if !ok {
		return nil, nil
	}
	delete(data, flowJobActorPayloadField)
	switch raw.(type) {
	case int, int64, float64, json.Number, string:
		if id := toInt64(raw); id > 0 {
			return &flowJobActorSnapshot{UserID: id}, nil
		}
	}
	encoded, err := json.Marshal(raw)
	var actor flowJobActorSnapshot
	if err != nil || json.Unmarshal(encoded, &actor) != nil || actor.Version != 1 || actor.UserID <= 0 {
		return nil, fmt.Errorf("invalid queued flow identity")
	}
	return &actor, nil
}

// takeFlowRequestKeys removes the reserved taint field from a job payload
// and returns the taint set it carried (nil when absent).
func takeFlowRequestKeys(data map[string]any) map[string]bool {
	raw, ok := data[flowRequestKeysPayloadField]
	if !ok {
		return nil
	}
	delete(data, flowRequestKeysPayloadField)
	keys := map[string]bool{}
	switch list := raw.(type) {
	case []any:
		for _, k := range list {
			if s, ok := k.(string); ok && s != "" {
				keys[s] = true
			}
		}
	case []string:
		for _, s := range list {
			if s != "" {
				keys[s] = true
			}
		}
	}
	return keys
}

// takeFlowSecretKeys removes the reserved secret-taint field from a job
// payload and returns the keys it marked (nil when absent).
func takeFlowSecretKeys(data map[string]any) map[string]bool {
	raw, ok := data[flowSecretKeysPayloadField]
	if !ok {
		return nil
	}
	delete(data, flowSecretKeysPayloadField)
	return takeFlowRequestKeys(map[string]any{flowRequestKeysPayloadField: raw})
}

// shadowStepNamedRequestKeys moves request fields whose name is also a step
// id off the top level of ctx.Data, into flowStepNamedParamsKey. A step's
// output lives at ctx.Data[<id>], so a same-named request field could stand
// in for the output of a step that was skipped or hasn't run. The value
// stays readable as `${{ params.<id> }}` and `:<id>` (ctx.Params).
//
// Step ids are not the only names a step writes at the top level: `run:
// set` writes every one of its keys there, a for_each writes its loop
// variable (`as:`, default `item`), and an unnamed parse step writes `body`
// or `form`. A request field with one of those names could stand in for a
// skipped `set` (`if: ${{ allowed }}` after a set that never ran) the same
// way. Those names are common request field names, though, and a flow often
// reads the request's value before the step that redefines the name (an
// early step reads `text`, a later set writes its own `text`). So a request
// field named like one of them stays readable by its bare name until
// execution reaches a step that defines the name - whether that step runs
// or is skipped - and is shadowed from then on (shadowReachedSteps).
func shadowStepNamedRequestKeys(ctx *FlowContext, steps []FlowStep) {
	ids := map[string]bool{}
	var collect func([]FlowStep)
	collect = func(list []FlowStep) {
		for _, s := range list {
			if s.Name != "" {
				ids[s.Name] = true
			}
			collect(s.Steps)
			collect(s.ElseSteps)
			collect(s.OnError)
		}
	}
	collect(steps)
	idPrefixes := flowNamePrefixes(ids)
	defined := map[string]bool{}
	flowDefinedNames(steps, true, defined)
	definedPrefixes := flowNamePrefixes(defined)
	shadow := map[string]any{}
	pending := map[string]bool{}
	for key := range ctx.RequestKeys {
		if _, ok := ctx.Data[key]; !ok {
			continue
		}
		switch {
		case flowRequestKeyNamed(key, ids, idPrefixes):
			shadow[key] = ctx.Data[key]
			delete(ctx.Data, key)
		case flowRequestKeyNamed(key, defined, definedPrefixes):
			pending[key] = true
		}
	}
	if len(shadow) > 0 {
		ctx.Data[flowStepNamedParamsKey] = shadow
	}
	if len(pending) > 0 {
		ctx.lazyShadow = &flowLazyShadow{pending: pending}
	}
}

// flowLazyShadow is the set of request fields still readable by a bare name
// that some step in the flow defines.
type flowLazyShadow struct {
	mu      sync.Mutex
	pending map[string]bool
}

// flowRequestKeyNamed reports whether request key reads like name: the same
// name, a dotted key under it (`coupon.discount` under `coupon`), or an
// object that flattens onto a dotted name (`gate` onto `gate.ok`).
func flowRequestKeyNamed(key string, names, prefixes map[string]bool) bool {
	head, _, _ := strings.Cut(key, ".")
	return names[key] || names[head] || prefixes[key]
}

// flowNamePrefixes returns every proper dotted prefix of the names.
func flowNamePrefixes(names map[string]bool) map[string]bool {
	prefixes := map[string]bool{}
	for name := range names {
		for i := 1; i < len(name); i++ {
			if name[i] == '.' {
				prefixes[name[:i]] = true
			}
		}
	}
	return prefixes
}

// flowDefinedNames adds the top-level names the steps write besides their
// ids: set keys, a for_each loop variable, an unnamed parse step's outputs.
// deep includes nested steps (blocks, loop bodies, else branches) and every
// on_error handler; otherwise only the steps' own names and their on_error
// handlers are added.
func flowDefinedNames(steps []FlowStep, deep bool, into map[string]bool) {
	for i := range steps {
		s := &steps[i]
		for k := range s.Set {
			if k != "" {
				into[k] = true
			}
		}
		if s.Type == "for_each" || s.ForEach != "" {
			if s.ForAs != "" {
				into[s.ForAs] = true
			} else {
				into["item"] = true
			}
		}
		if s.Type == "parse" && s.Name == "" {
			into["body"] = true
			into["form"] = true
		}
		flowDefinedNames(s.OnError, true, into)
		if deep {
			flowDefinedNames(s.Steps, true, into)
			flowDefinedNames(s.ElseSteps, true, into)
		}
	}
}

// shadowReachedSteps shadows the pending request fields named like a name
// the steps define (see flowDefinedNames for deep): execution has reached
// the point where those names belong to the flow, whether the steps then
// run or are skipped. A field moves to flowStepNamedParamsKey, so it stays
// readable as `${{ params.<name> }}` and `:<name>`.
func shadowReachedSteps(ctx *FlowContext, steps []FlowStep, deep bool) {
	if ctx == nil || ctx.lazyShadow == nil || len(steps) == 0 {
		return
	}
	ls := ctx.lazyShadow
	ls.mu.Lock()
	defer ls.mu.Unlock()
	if len(ls.pending) == 0 {
		return
	}
	names := map[string]bool{}
	flowDefinedNames(steps, deep, names)
	if len(names) == 0 {
		return
	}
	prefixes := flowNamePrefixes(names)
	ctx.DataMu.Lock()
	defer ctx.DataMu.Unlock()
	var store map[string]any
	for key := range ls.pending {
		if !flowRequestKeyNamed(key, names, prefixes) {
			continue
		}
		delete(ls.pending, key)
		v, ok := ctx.Data[key]
		if !ok {
			continue
		}
		if store == nil {
			// A new map, not an edit in place (flows_flat_cache.go).
			store = map[string]any{}
			if old, ok := ctx.Data[flowStepNamedParamsKey].(map[string]any); ok {
				maps.Copy(store, old)
			}
		}
		store[key] = v
		delete(ctx.Data, key)
	}
	if store != nil {
		ctx.Data[flowStepNamedParamsKey] = store
	}
}

// flowIdentityKeys are set only by the runtime from the authenticated
// session; request input may never supply them.
var flowIdentityKeys = []string{"user", "user_id", "user_email", "user_role", "user_group_id", "_group_id", "_group_key"}

// stripRequestIdentityKeys removes request-supplied identity values (and any
// `user.*` dotted keys) from a flow context before execution.
func stripRequestIdentityKeys(ctx *FlowContext) {
	drop := func(key string) {
		delete(ctx.Data, key)
		delete(ctx.Params, key)
		delete(ctx.NullParams, key)
		delete(ctx.RequestKeys, key)
	}
	for _, key := range flowIdentityKeys {
		drop(key)
	}
	// `user.*` is the session's; `env` / `env.*` is the app environment.
	// A request field under either name would shadow them in templates.
	reserved := func(key string) bool {
		return strings.HasPrefix(key, "user.") || key == "env" || strings.HasPrefix(key, "env.") ||
			key == flowStepNamedParamsKey || strings.HasPrefix(key, flowStepNamedParamsKey+".")
	}
	for key := range ctx.Data {
		if reserved(key) {
			drop(key)
		}
	}
	for key := range ctx.Params {
		if reserved(key) {
			drop(key)
		}
	}
}
