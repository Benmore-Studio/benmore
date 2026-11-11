//go:build !cli

package main

// Time limit for a synchronous HTTP flow (`on.request.timeout`).
//
// A synchronous flow used to have no time limit of its own. The app server's
// WriteTimeout (30 s) closed the connection under it while the flow kept
// running: on 2026-10-29 a 40 s `transaction: true` flow on a hosted dev app
// committed all 5,000 of its updates (request log 200) and the caller got an
// error page, with no way to know the work had been done.
//
// Every synchronous HTTP flow now runs under a deadline: 30 s by default,
// `on.request.timeout:` (a Go duration or whole seconds) per flow, at most
// 95 s on the hosted platform, where Cloudflare ends a request whose answer
// has not started after about 100 s. Self-hosted, BENMORE_FLOW_TIMEOUT_MAX
// raises the maximum. The deadline is carried by the flow's execution
// context (FlowContext.execCtx):
//
//   - a `transaction: true` flow begins its transaction with that context, so
//     at the deadline database/sql rolls it back, a statement still running
//     is interrupted (ExecContext/QueryContext) and COMMIT is refused: none of
//     its writes are kept;
//   - every flow checks the deadline before each step and stops; statements
//     of a non-transactional flow that already ran stay committed;
//   - outbound calls (`run: api`, `run: webhook`) and `run: compute` are cut
//     at the deadline; other steps finish the call they are in.
//
// The caller gets a known answer (writeFlowTimeLimit): 503 with
// `outcome: rolled_back` when the transaction was rolled back, 500 with
// `outcome: stopped` when a non-transactional flow stopped part way. Not 504:
// Cloudflare replaces a 502 or 504 body from the origin with its own text, so
// the outcome would be lost (validators_edge_status.go). For the answer to be
// deliverable, the request's write deadline is moved past the flow's
// (extendFlowAnswerDeadline) for that request only.
//
// Async (`mode: async`), scheduled, data-event and connector-read runs keep
// their own bounds and are unchanged.

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// flowTimeoutHostedMax is the longest `on.request.timeout` on the hosted
	// platform. Cloudflare answers 524 when the origin has not started its
	// answer about 100 s after the request; 95 s leaves room for the request
	// to reach the flow and the answer to start.
	flowTimeoutHostedMax = 95 * time.Second
	// flowTimeoutMinimum is the shortest declared limit the write gate
	// accepts.
	flowTimeoutMinimum = time.Second
	// flowTimeoutMaxEnv raises the maximum for a self-hosted server. Ignored
	// on the hosted platform (an app's env reaches its process environment).
	flowTimeoutMaxEnv = "BENMORE_FLOW_TIMEOUT_MAX"
)

var (
	// flowTimeoutDefault is the limit of a synchronous flow that declares
	// none: the app server's 30 s response deadline, which used to cut such a
	// flow's answer (not the flow). A variable so tests can shorten it.
	flowTimeoutDefault = 30 * time.Second
	// flowAnswerTime is how long after the flow's deadline the answer may
	// still take to write. A variable so tests can shorten it.
	flowAnswerTime = 10 * time.Second
)

// parseFlowRequestTimeout reads `on.request.timeout`: a Go duration ("45s",
// "1m30s") or a whole number of seconds ("45"; YAML hands an unquoted number
// over as its text). Empty means not declared.
func parseFlowRequestTimeout(raw string) (time.Duration, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return 0, nil
	}
	if n, err := strconv.Atoi(raw); err == nil {
		if n <= 0 {
			return 0, fmt.Errorf("must be positive")
		}
		return time.Duration(n) * time.Second, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("not a Go duration (like 45s or 1m30s) or whole seconds")
	}
	if d <= 0 {
		return 0, fmt.Errorf("must be positive")
	}
	return d, nil
}

var warnedFlowTimeoutMax sync.Map

// flowRequestTimeoutMax is the longest time limit a synchronous flow may
// have in this process: 95 s on the hosted platform (the platform edition
// that validates pushes, and every hosted app process), otherwise
// BENMORE_FLOW_TIMEOUT_MAX when set, else the hosted maximum, so an app that
// passes `benmore check` self-hosted also loads hosted.
func flowRequestTimeoutMax() time.Duration {
	if editionName == "platform" || hostedTenantProcess() {
		return flowTimeoutHostedMax
	}
	raw := strings.TrimSpace(os.Getenv(flowTimeoutMaxEnv))
	if raw == "" {
		return flowTimeoutHostedMax
	}
	d, err := parseFlowRequestTimeout(raw)
	if err != nil || d < flowTimeoutDefault {
		if _, seen := warnedFlowTimeoutMax.LoadOrStore(raw, true); !seen {
			log.Printf("flows: %s=%q is not a duration of at least %s; using %s", flowTimeoutMaxEnv, raw, flowTimeoutDefault, flowTimeoutHostedMax)
		}
		return flowTimeoutHostedMax
	}
	return d
}

// flowRequestTimeout is the time limit a synchronous run of flow gets: its
// declared `on.request.timeout`, else the default, never above the maximum
// (a deployed file over it loads; the write gate refuses it).
func flowRequestTimeout(flow *Flow) time.Duration {
	limit := flowTimeoutDefault
	if flow != nil && flow.Timeout > 0 {
		limit = flow.Timeout
	}
	if max := flowRequestTimeoutMax(); limit > max {
		limit = max
	}
	return limit
}

// flowRequestTimeoutViolation is the write gate's and `benmore check`'s
// refusal of an `on.request.timeout` the runtime would not honor as written.
func flowRequestTimeoutViolation(req *FlowRequestTrigger) string {
	if req == nil || strings.TrimSpace(req.Timeout) == "" {
		return ""
	}
	if strings.EqualFold(strings.TrimSpace(req.Mode), "async") {
		return fmt.Sprintf("flows.yaml: on.request.timeout %q is set on a `mode: async` flow. The time limit is for a flow that answers inline; an async flow runs in the job worker and answers 202 at once. Remove `timeout:` (or drop `mode: async`).", req.Timeout)
	}
	d, err := parseFlowRequestTimeout(req.Timeout)
	if err != nil {
		return fmt.Sprintf("flows.yaml: on.request.timeout %q: %s. Write a Go duration (`timeout: 45s`, `timeout: 1m30s`) or whole seconds (`timeout: 45`).", req.Timeout, err)
	}
	if d < flowTimeoutMinimum {
		return fmt.Sprintf("flows.yaml: on.request.timeout %q is under %s. Omit it for the default %s.", req.Timeout, flowTimeoutMinimum, flowTimeoutDefault)
	}
	if max := flowRequestTimeoutMax(); d > max {
		return fmt.Sprintf("flows.yaml: on.request.timeout %q is over the maximum %s. On the hosted platform Cloudflare ends a request whose answer has not started after about 100 s, so a synchronous flow may run at most %s (a self-hosted server raises its maximum with %s). Work that takes longer belongs in an async flow (`mode: async`), which answers 202 with a job id at once.", req.Timeout, max, flowTimeoutHostedMax, flowTimeoutMaxEnv)
	}
	return ""
}

// startFlowTimeLimit gives a synchronous HTTP run of flow its deadline. The
// context keeps the request's values but not its cancellation: a caller who
// disconnects does not roll back work that would otherwise finish, as before.
func startFlowTimeLimit(ctx *FlowContext, flow *Flow, w http.ResponseWriter, r *http.Request) context.CancelFunc {
	limit := flowRequestTimeout(flow)
	execCtx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), limit)
	ctx.execCtx, ctx.timeLimit = execCtx, limit
	extendFlowAnswerDeadline(w, r, limit)
	return cancel
}

// extendFlowAnswerDeadline moves this request's write deadline to the flow's
// deadline plus flowAnswerTime, so the answer (success, or the time-limit
// error) can be written. The server's own WriteTimeout counts from the
// request's headers and would otherwise close the connection before a flow
// at its limit answers. It never shortens what the server gives: a server
// with no WriteTimeout (where a deadline set here would also outlive this
// request on the connection) or one long enough, even after the slowest body
// its ReadTimeout allows (the `benmore host` front door's 300 s), is left
// alone; Go resets the deadline for the connection's next request. A writer
// that cannot reach the connection (a recorder, an in-process capture) keeps
// its own.
func extendFlowAnswerDeadline(w http.ResponseWriter, r *http.Request, limit time.Duration) {
	window := limit + flowAnswerTime
	if srv, ok := r.Context().Value(http.ServerContextKey).(*http.Server); ok {
		if srv.WriteTimeout <= 0 || srv.WriteTimeout >= window+srv.ReadTimeout {
			return
		}
		if window < srv.WriteTimeout {
			window = srv.WriteTimeout
		}
	}
	_ = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(window))
}

// errFlowTimeLimit matches (errors.Is) the error a flow stopped at its time
// limit reports.
var errFlowTimeLimit = errors.New("flow time limit reached")

type flowTimeLimitError struct {
	limit time.Duration
	step  string
}

func (e *flowTimeLimitError) Error() string {
	if e.step != "" {
		return fmt.Sprintf("flow time limit of %s reached before step %s", e.limit, e.step)
	}
	return fmt.Sprintf("flow time limit of %s reached", e.limit)
}

func (e *flowTimeLimitError) Is(target error) bool { return target == errFlowTimeLimit }

// execContext is the context a step's database and outbound calls run
// under: the flow's deadline for a synchronous HTTP run, else Background
// (async, scheduled and event runs, exactly as before).
func (ctx *FlowContext) execContext() context.Context {
	if ctx != nil && ctx.execCtx != nil {
		return ctx.execCtx
	}
	return context.Background()
}

// timeLimitReached reports whether the run's deadline has passed.
func (ctx *FlowContext) timeLimitReached() bool {
	return ctx != nil && ctx.execCtx != nil && ctx.execCtx.Err() != nil
}

// timeLimitError is the error of a run stopped before step (named or typed).
func (ctx *FlowContext) timeLimitError(step string) error {
	return &flowTimeLimitError{limit: ctx.timeLimit, step: step}
}

// boundStepTimeout caps a step's own timeout at the time left before the
// run's deadline. It returns 0 when no time is left.
func (ctx *FlowContext) boundStepTimeout(timeout time.Duration) time.Duration {
	if ctx == nil || ctx.execCtx == nil {
		return timeout
	}
	deadline, ok := ctx.execCtx.Deadline()
	if !ok {
		return timeout
	}
	left := time.Until(deadline)
	if left <= 0 {
		return 0
	}
	if timeout <= 0 || left < timeout {
		return left
	}
	return timeout
}

// waitRetryDelay sleeps a retry's delay, ending early at the deadline.
func (ctx *FlowContext) waitRetryDelay(delay time.Duration) {
	if ctx == nil || ctx.execCtx == nil {
		time.Sleep(delay)
		return
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.execCtx.Done():
	case <-timer.C:
	}
}

// flowStoppedByTimeLimit reports whether a failed synchronous run failed
// because a time limit ended it: its own deadline, or the database write
// lock limit (BENMORE_DB_WRITE_TX_LIMIT, db_write_lock.go), which rolls a
// transaction back the same way.
func flowStoppedByTimeLimit(ctx *FlowContext) bool {
	if ctx == nil || ctx.Error == nil {
		return false
	}
	return ctx.timeLimitReached() || errors.Is(ctx.Error, errFlowTimeLimit) || errors.Is(ctx.Error, errWriteTxExpired)
}

// writeFlowTimeLimit answers a synchronous flow that a time limit stopped.
// rolledBack: the flow's transaction was rolled back, so none of its
// database writes were kept (503, safe to send again). Otherwise the flow
// had no transaction and stopped part way: statements that ran before the
// limit are committed (500, check before sending again). Outbound calls that
// were made are never undone. No Retry-After: the same request would most
// likely reach the same limit.
func writeFlowTimeLimit(w http.ResponseWriter, flow *Flow, ctx *FlowContext, rolledBack bool, requestID string) {
	limit := ctx.timeLimit
	status, outcome := http.StatusInternalServerError, "stopped"
	message := fmt.Sprintf("The flow %s did not finish within its time limit of %s and was stopped after %d steps. It has no transaction, so database writes made by the steps that ran are committed; the remaining steps did not run.", flow.Name, limit, ctx.StepsRun)
	if rolledBack {
		status, outcome = http.StatusServiceUnavailable, "rolled_back"
		message = fmt.Sprintf("The flow %s did not finish within its time limit of %s. Its transaction was rolled back, so the writes made in it were not kept.", flow.Name, limit)
		if errors.Is(ctx.Error, errWriteTxExpired) && !ctx.timeLimitReached() {
			message = fmt.Sprintf("The flow %s held the database write lock longer than BENMORE_DB_WRITE_TX_LIMIT. Its transaction was rolled back, so the writes made in it were not kept.", flow.Name)
		}
	}
	message += " Outbound calls it already made are not undone."
	h := w.Header()
	h.Del("Content-Length")
	h.Set("X-Content-Type-Options", "nosniff")
	h.Set("Cache-Control", "no-store")
	h.Set("X-Benmore-Outcome", outcome)
	h.Set(requestIDHeader, requestID)
	httpJSON(w, status, map[string]any{
		"error":           "flow_timeout",
		"flow":            flow.Name,
		"outcome":         outcome,
		"rolled_back":     rolledBack,
		"timeout_seconds": limit.Seconds(),
		"steps_run":       ctx.StepsRun,
		"failed_step":     ctx.FailedStep,
		"request_id":      requestID,
		"message":         message,
		"hint":            "Raise `on.request.timeout:` (at most 95s on the hosted platform), make the slow step faster, or move long work to an async flow (`mode: async`, api(at:\"async-flows\")).",
		"docs":            refusalDocsAt("flow_timeout", ""),
	})
}
