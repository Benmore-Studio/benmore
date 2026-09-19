//go:build !cli

package main

// Flow step dispatch, retries, failure handling, and bounded parallel execution.

import (
	"fmt"
	"strings"
	"sync"
	"time"
)

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
				errCtx := &FlowContext{App: ctx.App, Session: ctx.Session, Data: ctx.Data, Params: ctx.Params}
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
	case "sms":
		err = execStepSMS(ctx, step)
	case "redirect":
		err = execStepRedirect(ctx, step)
	case "respond":
		err = execStepRespond(ctx, step)
	case "serve_file":
		err = execStepServeFile(ctx, step)
	case "delete_upload":
		err = execStepDeleteUpload(ctx, step)
	case "purge_current_user":
		err = execStepPurgeCurrentUser(ctx, step)
	case "transcribe":
		err = execStepTranscribe(ctx, step)
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
