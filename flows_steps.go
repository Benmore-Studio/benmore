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
	// A step that writes, sends or queues stops on a reference with no value
	// before it acts (unresolvedRefsBeforeEffect); its usual hint (the SQL
	// engine's message, the mail provider's settings) would point away from
	// the cause.
	if strings.Contains(em, "unresolved template reference") {
		if did := unresolvedRefStepOutcome[stepType]; did != "" {
			return prefix + "A `${{ }}` reference in the step had no value, so " + did + ". step_error names the reference. Give an optional value a fallback (`${{ params.note || '' }}` or `| default:''`). A step's output is `${{ steps.<id>.outputs.<column> }}`: check the step id and that its SELECT or RETURNING list has the column."
		}
	}
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
		case strings.Contains(em, "with.params does not define"):
			return prefix + "A `:name` in the query binds the request field, path parameter or with.params value of that name, and step_error names the ones that had none. Send the field, or give it a value in the step's `with.params` (with a fallback: `params: {title: \"${{ params.title || 'Untitled' }}\"}`), or declare it under `on.request.inputs:` with `required: true` (refused with 422 before any step) or a `default:`."
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
		case strings.Contains(em, "paginate:"):
			return prefix + "The step's `with.paginate` block cannot be run as written. `strategy` is `cursor` (the default) or `page`; the cursor strategy needs `cursor_field`, the dotted path of the next cursor in each answer. See api(at:\"flows\") → checked_values."
		case strings.Contains(em, "success_when failed"):
			return prefix + "The HTTP status was 2xx but the success_when: predicate evaluated false. Inspect the response shape via `steps.<id>.outputs.body` or `.json` - many APIs return 200 with an error envelope (status:'error', code:'forbidden', etc.)."
		case strings.Contains(em, "returned 4"), strings.Contains(em, "returned 5"):
			return prefix + "Upstream returned an error status. Check the `sign:` recipe (auth) and the URL. If this is OAuth, verify the credentials are set in env.yaml."
		case strings.Contains(em, "context deadline exceeded"), strings.Contains(em, "timeout"):
			return prefix + "Upstream timed out. Default HTTP timeout is 30s; raise it with `timeout: 570s` under the api step's `with:` (or at step level). A synchronous flow also has its own limit (`on.request.timeout`, 30s by default, at most 95s hosted), which cuts the call. If it legitimately takes longer, add `mode: async` on the route's `on.request` block so the flow runs in the background and the HTTP handler returns 202 immediately."
		}
		return prefix + "Read step_error above for the network-layer cause (timeout, DNS, TLS, status code). For auth failures: check the `sign:` recipe and env vars via `describe_auth`."
	case "parse":
		return prefix + "`run: parse` couldn't read the body. Check (a) format: is the right one (xml / csv / html), (b) the body actually has the shape you expect - log `steps.<upstream>.outputs.body` via a debug respond step to inspect."
	case "respond":
		return prefix + "`run: respond` couldn't render the body. Most common: a `${{ steps.<id>.outputs.<col> }}` reference that didn't resolve. Check unresolved_refs in the error body. Common causes: (a) the upstream step has no `id:` set, (b) the column wasn't in the INSERT/UPDATE's RETURNING clause."
	case "redirect":
		return prefix + "`run: redirect` couldn't compute the `to:` URL. Check that any `${{ ... }}` refs in `to:` resolve."
	case "email":
		if strings.Contains(em, "attachment") {
			return prefix + "An attachment the step declares could not be built, so nothing was sent. `with.attachments` is a list of `{ filename, content, content_type }`; `content` is the file's bytes as base64 (use `| base64` to encode text a step produced) and must not render empty. There is no `path:` key."
		}
		return prefix + "Email send failed. Verify EMAIL_FROM is a verified sending domain (platform SES) or, off-platform, that SMTP credentials work. `describe_auth` shows the email config."
	case "sms":
		return prefix + "SMS send failed. On the hosted platform every app can text via the shared number - check `benmore sms <app>` for quota/pause state, that `to:` is E.164 (+1...) and within the allowed calling prefixes, and that the per-recipient velocity cap (5 / 10 min) isn't tripped. Self-hosted: set SMS_ACCOUNT_SID/SMS_AUTH_TOKEN (Twilio) or SMS_WEBHOOK_URL."
	case "webhook":
		return prefix + "Webhook delivery failed. Same diagnostics as `run: api` (network, status code, SSRF guard). If the receiver requires HMAC, use `run: api` with a `sign:` recipe instead - `run: webhook` is the legacy unsigned path."
	case "broadcast":
		return prefix + "`run: broadcast` couldn't send. Check that `with.room` renders a valid room name (1-128 characters of a-z A-Z 0-9 _ - . :), that the JSON payload is at most 64 KiB, and - in an app with `groups:` - that the flow runs with a signed-in session (`auth: required`), because a server room message needs the caller's tenant."
	case "notify":
		if strings.Contains(em, "no user has id") {
			return prefix + "`with.user_id` named no user, so nothing was stored. Read the recipient from a row that holds a user id (`_benmore_users.id`), or catch the failure with an `on_error:` handler on the step."
		}
		return prefix + "`run: notify` couldn't create the notification. `with.user_id` must render a user id (a whole number) and `with.title` must not be empty. See api(at:\"notifications\") → flow_step."
	case "enqueue":
		return prefix + "Couldn't enqueue the background job. Check the target flow name exists and the job-worker table (`_benmore_jobs`) is writable."
	case "proxy":
		switch {
		case strings.Contains(em, "content-type"):
			return prefix + "The upstream answered a media type the step does not serve. A proxy step serves only the types in its `content_types:` (images, audio, video, PDF, CSV, ZIP; never HTML, SVG, XML or JSON) and checks the upstream's Content-Type before sending anything. Check what the service answers, and that it labels the body (application/octet-stream is refused)."
		case strings.Contains(em, "content-encoding"):
			return prefix + "The upstream compressed its answer with an encoding the step does not decode. Do not set Accept-Encoding (the step refuses it); the client asks for gzip itself and decodes it."
		case strings.Contains(em, "answered"):
			return prefix + "The upstream answered an error status, so nothing was streamed. Check the URL, the `auth:`/`headers:` credentials (env values) and the request body."
		case strings.Contains(em, "max_bytes"):
			return prefix + "The upstream body is larger than `max_bytes` (default 10 MiB, at most 100 MiB). A gzip answer counts its decoded bytes. Raise `max_bytes:` or fetch a smaller rendition."
		case strings.Contains(em, "scheme or host"):
			return prefix + "A proxy step's scheme and host must be literal text or an env value; request input and step outputs may fill path segments and query values only."
		case strings.Contains(em, "even with `path_slashes"):
			return prefix + "With `path_slashes: true` a stored value may span path segments, but never with an empty segment (a leading, trailing or doubled `/`), a `.` or `..` segment, a `\\`, or an encoded `/` or `\\`. Fix the stored value, or pass it as a query value."
		case strings.Contains(em, "path segment"):
			return prefix + "Every value placed in the URL path that is not literal text or an env value (request input, a stored row, a step output) must be one plain segment: no `/` or `\\` (also percent-encoded) and not `.` or `..`. Pass a value like a file path as a query value (`?file=${{ params.file }}`), or, for a stored file key such as `users/42/a.png`, set `path_slashes: true` on the step."
		case strings.Contains(em, "could not resolve"):
			return prefix + "The upstream host name did not resolve (DNS), so nothing was sent. Check the host in `url:` (or the env value that holds it)."
		case strings.Contains(em, "redirected"):
			return prefix + "The upstream redirected to another host, from https to http, or to another port, or redirected a POST or more than 10 times. A proxy step follows redirects only for GET and only on the URL's own origin; point `url:` at the final address."
		case strings.Contains(em, "csrf"):
			return prefix + "An upstream POST runs only in a POST, PUT, PATCH or DELETE flow; a GET flow skips the CSRF check. Change the flow's `on.request.method`, or send a GET upstream."
		case strings.Contains(em, "first byte"):
			return prefix + "The upstream sent its headers but no body before it failed or the time ran out; nothing was sent and the flow answered its error. Raise `timeout:` if the service is slow to start its answer, or check the service."
		}
		return prefix + "Read step_error above for the cause (SSRF guard, timeout, redirect to another host, status). See api(at:\"flows\") → proxy."
	case "sql_dynamic":
		switch {
		case strings.Contains(em, "unresolved template reference"):
			return prefix + "A reference in the query had no value, so the statement did not run. A step's output is `${{ steps.<id>.outputs.<column> }}` (the first row's column; `outputs.rows` is every row); `{{steps.<id>.<column>}}` without `outputs` is never filled in. Check the step id and that its SELECT or RETURNING list has the column."
		case strings.Contains(em, "unrecognized token"):
			return prefix + "SQLite could not read part of the rendered statement. The token is redacted because sql_dynamic substitutes values as SQL text, which can hold env values and row data. The usual cause is template text that was not replaced or a substituted value that is not valid SQL: write step outputs as `${{ steps.<id>.outputs.<column> }}` (`{{steps.<id>.<column>}}` is never filled in), and quote substituted text values. The flow's `template=` log line shows the query as written."
		}
		return prefix + "Read step_error above for the SQL engine's message. sql_dynamic substitutes `${{ }}` values as SQL text, so check the statement each value produces; a step's output is `${{ steps.<id>.outputs.<column> }}`."
	case "if", "for_each", "parallel":
		if strings.Contains(em, "loop variable") {
			return prefix + "The loop's `as:` is a name the runtime owns (`user`, `user_id` and the other identity names, or `env`), so the loop was not run: its elements would have stood in for the signed-in caller. Give the loop variable a name of its own, for example `as: row`."
		}
		return prefix + "Control-flow step's expression couldn't be evaluated. For `if:`, check the comparison operands resolve. For `for_each:`, check the iterable source is a slice (not a string)."
	}
	return prefix + "Read step_error above for the upstream cause."
}

// unresolvedRefStepOutcome says, per step type, what did not happen when the
// step stopped on a reference with no value. Only types that check before
// acting are listed; sql_dynamic keeps its own hint in stepFailureHint.
var unresolvedRefStepOutcome = map[string]string{
	"sql":        "the statement did not run and nothing was written",
	"email":      "nothing was sent",
	"sms":        "nothing was sent",
	"enqueue":    "no job was queued",
	"ws":         "nothing was sent to the room",
	"transcribe": "the file was not fetched or transcribed",
}

func executeSteps(ctx *FlowContext, steps []FlowStep) {
	for _, step := range steps {
		if ctx.Stopped {
			return
		}
		// A synchronous run stops at its time limit (flows_time_limit.go):
		// the next step does not start.
		if ctx.timeLimitReached() {
			label := flowStepDisplayName(step.Name)
			if label == "" {
				label = step.Type
			}
			ctx.Error = ctx.timeLimitError(quoteForHint(label))
			ctx.FailedStep, ctx.FailedType = label, step.Type
			return
		}

		var err error
		// `retry` is the total number of attempts; unset is one. A negative
		// value used to run the loop below zero times: the step was skipped
		// and the flow carried on as if it had succeeded. It runs once (the
		// write gate refuses the value, flowStepRetryProblems).
		retries := max(step.Retry, 1)
		if ctx.command != nil && step.Retry != 0 && step.Retry != 1 {
			ctx.Error = fmt.Errorf("command runtime refuses retries")
			return
		}

		for attempt := 0; attempt < retries; attempt++ {
			err = executeStep(ctx, &step)
			var rolledBack *flowTransactionRolledBackError
			// A proxy step that has started its answer is never run again.
			if err == nil || errors.As(err, &rolledBack) || ctx.Stopped && ctx.errorResponse || ctx.responseAborted || ctx.mcpReadConn != nil && ctx.Request.Context().Err() != nil || ctx.timeLimitReached() {
				break
			}
			if attempt < retries-1 {
				delay := step.RetryDelay
				if delay <= 0 {
					delay = flowRetryDelayDefault
				}
				if ctx.mcpReadConn != nil {
					timer := time.NewTimer(delay)
					select {
					case <-ctx.Request.Context().Done():
					case <-timer.C:
					}
					timer.Stop()
				} else {
					ctx.waitRetryDelay(delay)
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
			// An if block or a loop fails when a step inside it failed, and
			// that step has already named itself. Keep its name and type, so
			// the answer's failed_step, failed_type, reason and hint are the
			// ones the step gets outside a block: a proxy step's refused URL
			// inside `if:` answered "the if step failed" with the if hint,
			// while its timeout answered "the step timed out".
			if !(step.Type == "if" || step.Type == "for_each") || ctx.FailedType == "" {
				if step.Name != "" {
					ctx.FailedStep = flowStepDisplayName(step.Name)
				} else {
					ctx.FailedStep = step.Type
				}
				ctx.FailedType = step.Type
			}
			// A run its time limit ended answers the time-limit error; its
			// handler would start with no time left (flows_time_limit.go).
			if ctx.timeLimitReached() {
				return
			}
			// Run on_error steps. A proxy step that failed after writing part
			// of its answer has no handler: the entry point aborts the response.
			if ctx.command == nil && len(step.OnError) > 0 && !ctx.responseAborted {
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
					flushFlowTxReadAudit(ctx)
					// The writes the rollback undid no longer exist: their
					// RETURNING ids and counts would mislead the handler (an
					// id the handler's own insert can reuse).
					ctx.forgetRolledBackWriteOutputs()
				}
				// `${{ error }}` is what a handler responds with, stores or
				// sends on, so it is the text step_error shows an app admin
				// (flowFailureText: env and secret-derived values replaced by
				// [redacted]; serverErrorText: one line, credential shapes
				// redacted), never the raw error. The raw text of a failed
				// `run: api` holds its whole URL, env token included, and a
				// public flow's handler returned it to anonymous callers.
				ctx.Data["error"] = serverErrorText(flowFailureText(ctx, err))
				ctx.markErrorValueTaint(&step)
				// A handler shares HTTP and value/security state but starts
				// with fresh error/control state. It still runs outside Tx:
				// handler writes are durable independently of the failed run.
				// The HTTP writer may be the transaction's private buffer.
				errCtx := &FlowContext{
					App: ctx.App, Session: ctx.Session, Request: ctx.Request, Writer: ctx.Writer,
					privateResponse: ctx.privateResponse, verifiedRequest: ctx.verifiedRequest, apiClient: ctx.apiClient,
					Data: ctx.Data, Params: ctx.Params, NullParams: ctx.NullParams,
					RequestKeys: ctx.RequestKeys, SecretKeys: ctx.SecretKeys, SQLTextKeys: ctx.SQLTextKeys, requestStepSources: ctx.requestStepSources, computedKeys: ctx.computedKeys,
					Writes: ctx.Writes, lazyShadow: ctx.lazyShadow, parallelOutputs: ctx.parallelOutputs, reachedSteps: ctx.reachedSteps,
					mcpReadConn: ctx.mcpReadConn, mcpReadKey: ctx.mcpReadKey, queuedBody: ctx.queuedBody, requestOnlyParams: ctx.requestOnlyParams,
					execCtx: ctx.execCtx, timeLimit: ctx.timeLimit, backgroundRun: ctx.backgroundRun,
				}
				executeSteps(errCtx, step.OnError)
				ctx.StepsRun += errCtx.StepsRun
				ctx.RequestKeys, ctx.SecretKeys, ctx.SQLTextKeys, ctx.requestStepSources = errCtx.RequestKeys, errCtx.SecretKeys, errCtx.SQLTextKeys, errCtx.requestStepSources
				ctx.computedKeys = errCtx.computedKeys
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
		return fmt.Errorf("sql: step %q was not run: %s. Keep one; the step-root key is the canonical position", flowStepDisplayName(step.Name), step.ExpectRowsConflict)
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
	case "notify":
		err = execStepNotify(ctx, step)
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
	case "proxy":
		err = execStepProxy(ctx, step)
	case "delete_upload":
		err = execStepDeleteUpload(ctx, step)
	case "inspect_private_upload":
		err = execStepInspectPrivateUpload(ctx, step)
	case "extract_text":
		err = execStepExtractText(ctx, step)
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
	// fields remain in MissingRefs. A step that writes, sends or queues has
	// already made this check before acting (unresolvedRefsBeforeEffect).
	// What reaches here is a step with no such effect (set, parse), an `if:`
	// block's own condition when no branch step ran, and `run: redirect`,
	// which has answered by now (flows_condition_missing_ref_test.go).
	if missing := ctx.takeMissingRefs(); len(missing) > 0 {
		return unresolvedStepRefsError(step, missing)
	}
	return nil
}

// unresolvedStepRefsError is a step's failure when its templates referenced
// values that were not in scope. missing holds the author's reference text,
// never a resolved value.
func unresolvedStepRefsError(step *FlowStep, missing []string) error {
	stepLabel := flowStepDisplayName(step.Name)
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

// unresolvedRefsBeforeEffect is the check a step that writes, sends or queues
// makes once every one of its templates is rendered and before it acts: the
// failure executeStep would report after the step, returned while nothing has
// happened yet. The dispatcher's own check runs after the handler, which is
// too late for an effect that cannot be taken back: a `run: sql` step stored
// the row with the text `{{params.b}}` in it (three times with `retry: 3`), an
// email and a text message went out with the placeholder, and a job was
// queued carrying it. nil when every reference resolved.
func (ctx *FlowContext) unresolvedRefsBeforeEffect(step *FlowStep) error {
	if missing := ctx.takeMissingRefs(); len(missing) > 0 {
		return unresolvedStepRefsError(step, missing)
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
		// The block fails with its first branch's error; a queued run is
		// retried only if every failed branch could change on a re-run.
		if flowFailureRetryable(firstErr) {
			for _, err := range errs {
				if err != nil && !flowFailureRetryable(err) {
					firstErr = jobNotRetryable{firstErr}
					break
				}
			}
		}
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
