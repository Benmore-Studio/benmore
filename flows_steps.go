//go:build !cli

package main

// Flow step dispatch, retries, failure handling, and bounded parallel execution.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// A nested handler may end the transaction before its enclosing step returns.
// Preserve that terminal boundary through wrapped errors so an enclosing retry
// cannot repeat effects or replace the original cause with sql.ErrTxDone.
type flowTransactionRolledBackError struct{ cause error }

func (e *flowTransactionRolledBackError) Error() string { return e.cause.Error() }
func (e *flowTransactionRolledBackError) Unwrap() error { return e.cause }

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
		case strings.Contains(em, "no sql statement"):
			return prefix + "The step has no SQL statement to run. Write it as `with.query` (or `query:` at the step root); `with.sql` is not read, and a text that is only a comment is not a statement."
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
			return prefix + "Upstream timed out. Default HTTP timeout is 30s; raise it with `timeout: 570s` under the api step's `with:` (or at step level). If the call legitimately takes longer than 30s, also add `mode: async` on the route's `on.request` block so the flow runs in the background and the HTTP handler returns 202 immediately."
		}
		return prefix + "Read step_error above for the network-layer cause (timeout, DNS, TLS, status code). For auth failures: check the `sign:` recipe and env vars via `describe_auth`."
	case "parse":
		return prefix + "`run: parse` couldn't read the body. Check (a) format: is the right one (xml / csv / html), (b) the body actually has the shape you expect - log `steps.<upstream>.outputs.body` via a debug respond step to inspect."
	case "respond":
		return prefix + "`run: respond` couldn't render the body. Most common: a `${{ steps.<id>.outputs.<col> }}` reference that didn't resolve. Check unresolved_refs in the error body. Common causes: (a) the upstream step has no `id:` set, (b) the column wasn't in the INSERT/UPDATE's RETURNING clause."
	case "redirect":
		return prefix + "`run: redirect` couldn't compute the `to:` URL. Check that any `${{ ... }}` refs in `to:` resolve."
	case "email":
		return prefix + "Email send failed. Verify EMAIL_FROM is a verified sending domain (platform SES) or, off-platform, that SMTP credentials work. `describe_auth` shows the email config."
	case "sms":
		return prefix + "SMS send failed. On the hosted platform every app can text via the shared number - check `benmore sms <app>` for quota/pause state, that `to:` is E.164 (+1...) and within the allowed calling prefixes, and that the per-recipient velocity cap (5 / 10 min) isn't tripped. Self-hosted: set SMS_ACCOUNT_SID/SMS_AUTH_TOKEN (Twilio) or SMS_WEBHOOK_URL."
	case "webhook":
		return prefix + "Webhook delivery failed. Same diagnostics as `run: api` (network, status code, SSRF guard). If the receiver requires HMAC, use `run: api` with a `sign:` recipe instead - `run: webhook` is the legacy unsigned path."
	case "broadcast":
		return prefix + "`run: broadcast` couldn't send. Check that `with.room` renders a valid room name (1-128 characters of a-z A-Z 0-9 _ - . :), that the JSON payload is at most 64 KiB, and - in an app with `groups:` - that the flow runs with a signed-in session (`auth: required`), because a server room message needs the caller's tenant."
	case "enqueue":
		return prefix + "Couldn't enqueue the background job. Check the target flow name exists and the job-worker table (`_benmore_jobs`) is writable."
	case "if", "for_each", "parallel":
		return prefix + "Control-flow step's expression couldn't be evaluated. For `if:`, check the comparison operands resolve. For `for_each:`, check the iterable source is a slice (not a string)."
	}
	return prefix + "Read step_error above for the upstream cause."
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
		if ctx.command != nil && retries != 1 {
			ctx.Error = fmt.Errorf("command runtime refuses retries")
			return
		}

		for attempt := 0; attempt < retries; attempt++ {
			err = executeStep(ctx, &step)
			var rolledBack *flowTransactionRolledBackError
			if err == nil || errors.As(err, &rolledBack) || ctx.Stopped && ctx.errorResponse || ctx.mcpReadConn != nil && ctx.Request.Context().Err() != nil {
				break
			}
			if attempt < retries-1 {
				delay := step.RetryDelay
				if delay == 0 {
					delay = 2 * time.Second
				}
				if ctx.mcpReadConn != nil {
					timer := time.NewTimer(delay)
					select {
					case <-ctx.Request.Context().Done():
					case <-timer.C:
					}
					timer.Stop()
				} else {
					time.Sleep(delay)
				}
			}
		}

		ctx.StepsRun++
		if ctx.Stopped && ctx.errorResponse {
			// A nested handler answered the request. Preserve its original
			// error without running an enclosing handler or resuming steps.
			return
		}
		if err != nil {
			ctx.Error = err
			if step.Name != "" {
				ctx.FailedStep = step.Name
			} else {
				ctx.FailedStep = step.Type
			}
			ctx.FailedType = step.Type
			// Run on_error steps
			if ctx.command == nil && len(step.OnError) > 0 {
				// The handler writes outside the failed transaction. Release its
				// connection and SQLite write lock first, or the handler blocks on
				// our own transaction and loses its independent failure journal.
				if ctx.Tx != nil {
					ctx.transactionMutex().Lock()
					rollbackErr := ctx.Tx.Rollback()
					ctx.transactionMutex().Unlock()
					if rollbackErr != nil && rollbackErr != sql.ErrTxDone {
						ctx.Error = &flowTransactionRolledBackError{cause: fmt.Errorf("%w (rollback before error handler: %v)", err, rollbackErr)}
						return
					}
					ctx.Error = &flowTransactionRolledBackError{cause: err}
				}
				ctx.Data["error"] = err.Error()
				// A handler shares HTTP and value/security state but starts
				// with fresh error/control state. It still runs outside Tx:
				// handler writes are durable independently of the failed run.
				// The HTTP writer may be the transaction's private buffer.
				errCtx := &FlowContext{
					App: ctx.App, Session: ctx.Session, Request: ctx.Request, Writer: ctx.Writer,
					privateResponse: ctx.privateResponse, apiClient: ctx.apiClient,
					Data: ctx.Data, Params: ctx.Params, NullParams: ctx.NullParams,
					RequestKeys: ctx.RequestKeys, SecretKeys: ctx.SecretKeys, requestStepSources: ctx.requestStepSources,
					Writes: ctx.Writes, lazyShadow: ctx.lazyShadow, parallelOutputs: ctx.parallelOutputs, reachedSteps: ctx.reachedSteps,
					mcpReadConn: ctx.mcpReadConn, mcpReadKey: ctx.mcpReadKey,
				}
				executeSteps(errCtx, step.OnError)
				ctx.StepsRun += errCtx.StepsRun
				ctx.RequestKeys, ctx.SecretKeys, ctx.requestStepSources = errCtx.RequestKeys, errCtx.SecretKeys, errCtx.requestStepSources
				ctx.NullParams = errCtx.NullParams
				ctx.privateResponse = ctx.privateResponse || errCtx.privateResponse
				ctx.flatCache.invalidate()
				if errCtx.Stopped && (errCtx.Error == nil || errCtx.errorResponse) {
					ctx.Stopped, ctx.errorResponse = true, true
				}
			}
			return
		}
	}
}

func executeStep(ctx *FlowContext, step *FlowStep) error {
	if ctx != nil && ctx.command != nil {
		if err := ctx.command.guardStep(step); err != nil {
			return err
		}
	}
	if err := appMCPFlowStepGuard(ctx, step); err != nil {
		return err
	}
	ctx.markStepsReached(step)
	// Two different guards on one statement: running it under either would
	// silently drop the other, so the step does not run (ghaStepExpectRows).
	if step.ExpectRowsConflict != "" {
		return fmt.Errorf("sql: step %q was not run: %s. Keep one; the step-root key is the canonical position", step.Name, step.ExpectRowsConflict)
	}
	// Execution has reached this step, so request fields named like what it
	// defines are shadowed from here on (shadowStepNamedRequestKeys). An if
	// block and a loop decide their nested steps themselves (execStepIf,
	// execStepForEach); any other step owns its whole subtree, including
	// a parallel block's children. An on_error handler's names are decided
	// when its step is reached, whether or not the handler runs.
	switch step.Type {
	case "if", "for_each":
		shadowReachedSteps(ctx, step.OnError, true)
	default:
		shadowReachedSteps(ctx, []FlowStep{*step}, true)
	}
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

	// Outputs derived from request input stay request input (flows_taint.go).
	// Computed from the taint state before the step runs, so an on_error
	// handler and any retry see the same set.
	ctx.taintStepOutputs(step)

	var restoreCommandDeadline func()
	if ctx.command != nil && step.Timeout > 0 {
		parent := ctx.command.capability.ctx
		stepCtx, cancel := context.WithTimeout(parent, step.Timeout)
		ctx.command.capability.ctx = stepCtx
		restoreCommandDeadline = func() {
			ctx.command.capability.ctx = parent
			cancel()
		}
	}
	var err error
	switch step.Type {
	case "sql":
		if ctx.command != nil {
			err = ctx.command.executeSQL(ctx, step)
		} else {
			err = execStepSQL(ctx, step)
		}
	case "sql_dynamic":
		err = execStepSQLDynamic(ctx, step)
	case "api":
		err = execStepAPI(ctx, step)
	case "webhook":
		err = execStepWebhook(ctx, step)
	case "ws":
		err = execStepWS(ctx, step)
	case "broadcast":
		err = execStepBroadcast(ctx, step)
	case "enqueue":
		err = execStepEnqueue(ctx, step)
	case "email":
		err = execStepEmail(ctx, step)
	case "sms":
		err = execStepSMS(ctx, step)
	case "redirect":
		err = execStepRedirect(ctx, step)
	case "respond":
		if ctx.command != nil {
			err = ctx.command.respond(ctx, step)
		} else {
			err = execStepRespond(ctx, step)
		}
	case "serve_file":
		err = execStepServeFile(ctx, step)
	case "delete_upload":
		err = execStepDeleteUpload(ctx, step)
	case "inspect_private_upload":
		err = execStepInspectPrivateUpload(ctx, step)
	case "render_pdf_signatures":
		err = execStepRenderPDFSignatures(ctx, step)
	case "purge_current_user":
		err = execStepPurgeCurrentUser(ctx, step)
	case "transcribe":
		err = execStepTranscribe(ctx, step)
	case "revoke_user_sessions":
		if ctx.command == nil {
			err = errors.New("revoke_user_sessions runs only in an approved MCP command")
		} else {
			err = ctx.command.revokeUserSessions(ctx, step)
		}
	case "if":
		if ctx.command != nil {
			err = execStepCommandIf(ctx, step)
		} else {
			err = execStepIf(ctx, step)
		}
	case "for_each":
		if ctx.command != nil {
			err = execStepCommandForEach(ctx, step)
		} else {
			err = execStepForEach(ctx, step)
		}
	case "set":
		if ctx.command != nil {
			err = execStepCommandSet(ctx, step)
		} else {
			err = execStepSet(ctx, step)
		}
	case "parse":
		err = execStepParse(ctx, step)
	case "parallel":
		err = execStepParallel(ctx, step)
	case "compute":
		if ctx.command != nil {
			err = execStepCommandCompute(ctx, step)
		} else {
			err = execStepCompute(ctx, step)
		}
	default:
		if restoreCommandDeadline != nil {
			restoreCommandDeadline()
		}
		return fmt.Errorf("unknown step type: %s", step.Type)
	}
	if restoreCommandDeadline != nil {
		restoreCommandDeadline()
	}

	// If the step itself errored, preserve that error - the caller's
	// FailedStep diagnostic is more useful when it names the original
	// failure, not "after-the-fact unresolved refs."
	if err != nil {
		return err
	}
	ctx.noteParallelOutputs(step)

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
// Each child sees the same input snapshot and publishes its changes at the
// join, in declaration order. The first error in that order fails the block;
// every sibling still finishes, and failed-block outputs are discarded.
func execStepParallel(ctx *FlowContext, step *FlowStep) error {
	if len(step.Steps) == 0 {
		return nil
	}
	if err := flowValidateParallelHTTP(&Flow{Steps: []FlowStep{*step}}); err != nil {
		return err
	}
	if ctx.command != nil || ctx.mcpReadConn != nil {
		return fmt.Errorf("parallel: connector executions do not support parallel steps")
	}
	// H-4 runtime backstop: a *sql.Tx is NOT safe for concurrent use, so
	// parallel children must never share ctx.Tx. flowValidateParallelTx
	// rejects this at registration time; this guard catches any flow that
	// bypassed validation (legacy on-disk file, hot-reload race) before it
	// can corrupt the shared transaction. Fail closed rather than risk a
	// data race on the connection.
	if ctx.Tx != nil && flowParallelHasSQL(step) {
		return fmt.Errorf("parallel: SQL steps are not allowed inside a parallel block of a transaction:true flow (a *sql.Tx cannot be shared across goroutines); move the SQL out of the parallel block or drop transaction:true")
	}
	var wg sync.WaitGroup
	before := newParallelFlowContext(ctx)
	children := make([]*FlowContext, len(step.Steps))
	errs := make([]error, len(step.Steps))
	for i := range step.Steps {
		children[i] = newParallelFlowContext(before)
		wg.Add(1)
		child := step.Steps[i]
		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					errs[i] = fmt.Errorf("parallel branch %q panicked: %v", child.Name, r)
				}
			}()
			errs[i] = executeStep(children[i], &child)
		}()
	}
	wg.Wait()
	for _, child := range children {
		ctx.StepsRun += child.StepsRun
	}
	var firstErr error
	var transactionRolledBack bool
	for _, err := range errs {
		if firstErr == nil && err != nil {
			firstErr = err
		}
		var rolledBack *flowTransactionRolledBackError
		transactionRolledBack = transactionRolledBack || errors.As(err, &rolledBack)
	}
	if firstErr != nil {
		// A later sibling can have ended the shared transaction. Preserve
		// declaration-order diagnostics without letting that earlier error
		// hide the terminal boundary from an enclosing retry.
		if transactionRolledBack {
			return &flowTransactionRolledBackError{cause: firstErr}
		}
		return firstErr
	}
	for _, child := range children {
		mergeParallelFlowContext(ctx, before, child)
	}
	return nil
}
