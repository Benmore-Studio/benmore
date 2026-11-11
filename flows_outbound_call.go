//go:build !cli

package main

// The bounds of one outbound call a flow step makes (`run: api`,
// `run: webhook`, `run: proxy`), and whether a call that got no answer
// counts against the host's circuit breaker (circuitbreaker.go).
//
// A call gets no answer for one of four reasons:
//
//   - the transport failed while the call still had time (connection
//     refused or reset, DNS, TLS): the host's fault, counted;
//   - the step's own allowance ran out (`timeout:`, else the step's
//     default): the host did not answer within what the step gives it,
//     which is the same for every run of every flow, so it counts;
//   - the flow's time limit (`on.request.timeout`, flows_time_limit.go)
//     came first: the run had less time left than the step allows, which
//     says nothing about the host, so it does not count;
//   - the caller went away (run: api and run: proxy end with the caller's
//     request): not counted either.
//
// The last two count neither as a failure nor as a success. They used to
// count as failures, so a host slower than one flow's short limit, or five
// requests a client aborted (`curl --max-time`), opened the circuit and
// every flow of the app calling that host failed for the 60 s cooldown
// (round 2026-11-04). In a synchronous flow the flow's limit (30 s by
// default) usually ends a hung call before a step's 30 s default does; a
// step `timeout:` shorter than the flow's limit makes a host that hangs
// count.

import (
	"context"
	"errors"
	"time"
)

const (
	// flowAPIDefaultTimeout is a `run: api` step's allowance without
	// `timeout:`.
	flowAPIDefaultTimeout = 30 * time.Second
)

// flowWebhookTimeout is how long a `run: webhook` delivery may take (the
// step has no `timeout:` of its own). A variable so tests can shorten it.
var flowWebhookTimeout = 10 * time.Second

// outboundCall is one outbound call's context and what can end it.
type outboundCall struct {
	ctx context.Context
	// ownLimitFirst: the step's allowance ends before the run's time
	// limit, so a deadline that ends the call is the step's own.
	ownLimitFirst bool
}

// startOutboundCall bounds a call by the step's allowance and by the run's
// time limit (a synchronous request flow's execContext), and, when
// followCaller is set, ends it when the caller's request ends. The context
// keeps the request's values. The returned func releases it.
func (ctx *FlowContext) startOutboundCall(allowance time.Duration, followCaller bool) (outboundCall, context.CancelFunc) {
	parent := context.Background()
	switch {
	case ctx != nil && ctx.execCtx != nil:
		parent = ctx.execCtx
	case ctx != nil && ctx.Request != nil:
		parent = context.WithoutCancel(ctx.Request.Context())
	}
	ownDeadline := time.Now().Add(allowance)
	callCtx, cancel := context.WithDeadline(parent, ownDeadline)
	call := outboundCall{ctx: callCtx, ownLimitFirst: true}
	if runDeadline, ok := parent.Deadline(); ok && !ownDeadline.Before(runDeadline) {
		call.ownLimitFirst = false
	}
	if followCaller && ctx != nil && ctx.Request != nil {
		stop := context.AfterFunc(ctx.Request.Context(), cancel)
		return call, func() { stop(); cancel() }
	}
	return call, cancel
}

// countsAgainstHost reports whether a call that got no answer is the host's
// fault (see the file comment).
func (c outboundCall) countsAgainstHost() bool {
	switch err := c.ctx.Err(); {
	case err == nil:
		// The transport failed while the call still had time, or the
		// client's own limit (the step's allowance) ended it.
		return true
	case errors.Is(err, context.DeadlineExceeded):
		return c.ownLimitFirst
	default:
		// Canceled: the caller went away.
		return false
	}
}

// recordFailure counts a call that got no answer against key's circuit when
// the host is to blame.
func (c outboundCall) recordFailure(key string) {
	if c.countsAgainstHost() {
		RecordFailure(key)
	}
}
