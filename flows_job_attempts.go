//go:build !cli

package main

// How many times a queued flow job runs.
//
// A flow job (a `mode: async` request, a `run: enqueue` step, a connector
// command's data-event flow) runs ONCE. Its steps commit as they go (each SQL
// statement on its own unless the flow is `transaction: true`) and its
// outbound calls, emails and on_error handlers have happened by the time it
// fails, so running it again from step 1 repeats them: one payment request
// used to insert three charges and call the provider three times.
//
// A flow whose author knows a re-run is safe opts in with
// `on.request.max_attempts: N` (at most flowJobMaxAttemptsCap). Even then a
// failed run is repeated only when its failure is one a later run can change
// (flowFailureRetryable): an outbound call that got no answer, timed out, met
// an open circuit breaker or was answered 408, 429, 500, 502, 503 or 504, or a
// busy/locked database. A body that is not JSON, a value missing from scope, a
// refused or failing SQL statement, a 4xx answer: the job fails at once.

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"

	sqlite3 "github.com/mattn/go-sqlite3"
)

// flowJobMaxAttemptsCap is the most runs `on.request.max_attempts` may ask
// for. With the worker's doubling backoff (30 s, 60 s, 120 s, 240 s) the last
// of five runs starts about 7.5 minutes after the first failed.
const flowJobMaxAttemptsCap = 5

// idempotentFlowCrashClaims is how many times a job of a flow declaring
// `idempotent: true` may be claimed across worker crashes (lease recovery
// requeues it). It is the queue's old default budget, kept separate from
// max_attempts so making flow jobs run once on failure leaves crash
// recovery of idempotent flows as it was.
const idempotentFlowCrashClaims = 3

// flowMaxAttemptsViolation is the write gate's and `benmore check`'s
// refusal of an `on.request.max_attempts` the runtime would not honor.
func flowMaxAttemptsViolation(req *FlowRequestTrigger) string {
	if req == nil || req.MaxAttempts == nil {
		return ""
	}
	if n := *req.MaxAttempts; n < 1 || n > flowJobMaxAttemptsCap {
		return fmt.Sprintf("flows.yaml: on.request.max_attempts %d is not between 1 and %d. It is how many runs a queued job of this flow (its `mode: async` jobs and `run: enqueue` jobs naming it) may take in all, counting the first. A retry re-runs the flow from step 1 and repeats every side effect the failed run committed, so omit it (one run) unless every step is safe to repeat. See api(at:\"async-flows\") → retries.", n, flowJobMaxAttemptsCap)
	}
	return ""
}

// flowLoadedMaxAttempts is the run count a deployed file's
// `on.request.max_attempts` gives: absent means one; a value out of range
// (refused at write time) is clamped and logged so the file keeps loading.
func flowLoadedMaxAttempts(raw *int, where string, warn flowLoadWarn) int {
	if raw == nil {
		return 1
	}
	n := *raw
	switch {
	case n < 1:
		warn.printf("WARNING: %s: on.request.max_attempts %d is under 1; its jobs run once", where, n)
		return 1
	case n > flowJobMaxAttemptsCap:
		warn.printf("WARNING: %s: on.request.max_attempts %d is over the maximum %d; its jobs run at most %d times", where, n, flowJobMaxAttemptsCap, flowJobMaxAttemptsCap)
		return flowJobMaxAttemptsCap
	}
	return n
}

// flowJobMaxAttempts is how many runs a queued job of flow may take.
func flowJobMaxAttempts(flow *Flow) int {
	if flow == nil || flow.MaxAttempts < 1 {
		return 1
	}
	return min(flow.MaxAttempts, flowJobMaxAttemptsCap)
}

// flowJobMaxAttemptsByName looks the flow up in the app's current flows; a
// name that matches none gets one run.
func flowJobMaxAttemptsByName(app *App, name string) int {
	if app == nil {
		return 1
	}
	app.mu.RLock()
	flows := app.Flows
	app.mu.RUnlock()
	for i := range flows {
		if flows[i].Name == name {
			return flowJobMaxAttempts(&flows[i])
		}
	}
	return 1
}

// flowJobAttemptBudget is how many runs a flow job that just failed with err
// may take in all. The flow's current definition decides (it is what the
// worker runs), bounded by what the job was queued with, so a job queued
// before this rule (the column default, 3) runs once unless its flow opts in.
func flowJobAttemptBudget(app *App, flowName string, queued int, err error) int {
	if !flowFailureRetryable(err) {
		return 1
	}
	return min(queued, flowJobMaxAttemptsByName(app, flowName))
}

// flowTransientError marks a step failure a later run of the flow can change.
// Its text is the wrapped error's.
type flowTransientError struct{ error }

func (e flowTransientError) Unwrap() error { return e.error }

// flowFailureRetryable reports whether a failed flow run may be run again
// (when its flow opts in). Only failures marked transient where they happen
// and a busy or locked database qualify; anything unrecognized does not.
func flowFailureRetryable(err error) bool {
	if err == nil {
		return false
	}
	var final jobNotRetryable
	if errors.As(err, &final) {
		return false
	}
	var transient flowTransientError
	if errors.As(err, &transient) {
		return true
	}
	var sqliteErr sqlite3.Error
	return errors.As(err, &sqliteErr) && (sqliteErr.Code == sqlite3.ErrBusy || sqliteErr.Code == sqlite3.ErrLocked)
}

// flowOutboundTransportError marks err transient when the outbound call it
// reports got no usable answer for a reason that can pass: a timeout, a
// refused, reset or unreachable connection, a temporary DNS failure, or a
// connection that closed mid-answer. A refused destination (the SSRF dial
// guard, a cross-host redirect) or a TLS failure stays as it is.
func flowOutboundTransportError(err error) error {
	if err == nil || !outboundTransportTransient(err) {
		return err
	}
	return flowTransientError{err}
}

func outboundTransportTransient(err error) bool {
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return true
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return dnsErr.IsTemporary || dnsErr.IsTimeout
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	for _, errno := range []syscall.Errno{syscall.ECONNREFUSED, syscall.ECONNRESET, syscall.ECONNABORTED, syscall.EPIPE, syscall.EHOSTUNREACH, syscall.ENETUNREACH, syscall.ETIMEDOUT} {
		if errors.Is(err, errno) {
			return true
		}
	}
	return false
}

// flowOutboundStatusError marks err transient when the upstream answered a
// status that says "try again later".
func flowOutboundStatusError(status int, err error) error {
	switch status {
	case 408, 429, 500, 502, 503, 504:
		return flowTransientError{err}
	}
	return err
}
