//go:build !cli

package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// An outbound call cut by the caller leaving or by the flow's own time limit
// is not the upstream's fault, so it must not count toward the host's
// circuit breaker (round 2026-11-04): five requests aborted by their caller
// (`curl --max-time 0.6`) against a proxy flow on a slow host opened the
// circuit, and every flow of the app calling that host answered 500 for the
// 60 s cooldown. Only the step's own timeout, a transport failure or a 5xx
// counts.

// slowOutboundUpstream answers after delay unless the call is cut first.
func slowOutboundUpstream(t *testing.T, delay time.Duration) *proxyUpstream {
	return startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
			return
		case <-time.After(delay):
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("png"))
	})
}

// outboundStep is one step of the given type calling url; stepTimeout 0
// keeps the step's default allowance.
func outboundStep(kind, url string, stepTimeout time.Duration) FlowStep {
	switch kind {
	case "api":
		return FlowStep{Name: "call", Type: "api", Timeout: stepTimeout, API: &FlowAPICall{URL: url, Method: "GET"}}
	case "webhook":
		return FlowStep{Name: "notify", Type: "webhook", Webhook: url, WebhookBody: `{"ping":true}`}
	default:
		step := proxyStep(url, "image/png")
		step.Timeout = stepTimeout
		return step
	}
}

// runSyncOutbound runs step the way a synchronous request flow does: the
// run's time limit is detached from the caller (startFlowTimeLimit), and
// callerLeaves (if > 0) is when the caller disconnects.
func runSyncOutbound(app *App, step FlowStep, limit, callerLeaves time.Duration) *FlowContext {
	callerCtx, leave := context.WithCancel(context.Background())
	defer leave()
	r := httptest.NewRequest("GET", "/api/p", nil).WithContext(callerCtx)
	ctx := proxyStepCtx(app, httptest.NewRecorder(), r)
	execCtx, cancel := context.WithTimeout(context.WithoutCancel(callerCtx), limit)
	defer cancel()
	ctx.execCtx, ctx.timeLimit = execCtx, limit
	if callerLeaves > 0 {
		timer := time.AfterFunc(callerLeaves, leave)
		defer timer.Stop()
	}
	executeSteps(ctx, []FlowStep{step})
	return ctx
}

func circuitFailures(app *App, url string) int {
	globalBreaker.mu.Lock()
	defer globalBreaker.mu.Unlock()
	if c := globalBreaker.circuits[circuitKey(app, url)]; c != nil {
		return c.failures
	}
	return 0
}

func TestOutboundBreakerIgnoresCallerDisconnect(t *testing.T) {
	for _, kind := range []string{"api", "webhook", "proxy"} {
		t.Run(kind, func(t *testing.T) {
			resetCircuitsForTest(t)
			upstream := slowOutboundUpstream(t, 400*time.Millisecond)
			app, cleanup := newTestApp(t)
			defer cleanup()
			url := "http://" + proxyTestHost + "/slow.png"
			for i := 0; i <= cbFailureThreshold; i++ {
				ctx := runSyncOutbound(app, outboundStep(kind, url, 0), 5*time.Second, 50*time.Millisecond)
				// run: webhook does not follow the caller: its delivery
				// finishes. run: api and run: proxy end with the caller.
				if kind == "webhook" && ctx.Error != nil {
					t.Fatalf("webhook delivery after the caller left: %v", ctx.Error)
				}
				if kind != "webhook" && (ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "canceled")) {
					t.Fatalf("call %d after the caller left: err=%v, want it cut", i, ctx.Error)
				}
			}
			if n := circuitFailures(app, url); n != 0 {
				t.Fatalf("caller disconnects counted %d failures against the host", n)
			}
			before := upstream.count()
			ctx := runSyncOutbound(app, outboundStep(kind, url, 0), 5*time.Second, 0)
			if ctx.Error != nil || upstream.count() != before+1 {
				t.Fatalf("a call from a caller who stays: err=%v, upstream calls %d -> %d", ctx.Error, before, upstream.count())
			}
		})
	}
}

func TestOutboundBreakerIgnoresFlowTimeLimit(t *testing.T) {
	for _, kind := range []string{"api", "webhook", "proxy"} {
		t.Run(kind, func(t *testing.T) {
			resetCircuitsForTest(t)
			slowOutboundUpstream(t, 3*time.Second)
			app, cleanup := newTestApp(t)
			defer cleanup()
			url := "http://" + proxyTestHost + "/slow.png"
			for i := 0; i <= cbFailureThreshold; i++ {
				started := time.Now()
				ctx := runSyncOutbound(app, outboundStep(kind, url, 0), 100*time.Millisecond, 0)
				if ctx.Error == nil || time.Since(started) > 2*time.Second {
					t.Fatalf("call %d: err=%v after %s, want it cut at the flow's 100ms limit", i, ctx.Error, time.Since(started))
				}
				if strings.Contains(ctx.Error.Error(), "circuit") {
					t.Fatalf("call %d was refused by the breaker: %v", i, ctx.Error)
				}
			}
			if n := circuitFailures(app, url); n != 0 {
				t.Fatalf("the flow's own time limit counted %d failures against the host", n)
			}
		})
	}
}

// The step's own allowance still counts: a host that does not answer within
// it is slow for every flow, so the breaker opens and later calls are
// refused without reaching it.
func TestOutboundBreakerCountsStepTimeout(t *testing.T) {
	saved := flowWebhookTimeout
	flowWebhookTimeout = 100 * time.Millisecond
	t.Cleanup(func() { flowWebhookTimeout = saved })
	for _, kind := range []string{"api", "webhook", "proxy"} {
		t.Run(kind, func(t *testing.T) {
			resetCircuitsForTest(t)
			upstream := slowOutboundUpstream(t, 3*time.Second)
			app, cleanup := newTestApp(t)
			defer cleanup()
			url := "http://" + proxyTestHost + "/slow.png"
			for i := 0; i < cbFailureThreshold; i++ {
				ctx := runSyncOutbound(app, outboundStep(kind, url, 100*time.Millisecond), 5*time.Second, 0)
				if ctx.Error == nil {
					t.Fatalf("call %d to a host slower than the step timeout succeeded", i)
				}
			}
			if n := circuitFailures(app, url); n != cbFailureThreshold {
				t.Fatalf("step timeouts counted %d failures, want %d", n, cbFailureThreshold)
			}
			before := upstream.count()
			ctx := runSyncOutbound(app, outboundStep(kind, url, 100*time.Millisecond), 5*time.Second, 0)
			if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "circuit open") || upstream.count() != before {
				t.Fatalf("after %d step timeouts: err=%v, upstream calls %d -> %d; want the breaker to refuse without calling", cbFailureThreshold, ctx.Error, before, upstream.count())
			}
		})
	}
}

// The reported case end to end: callers who give up on a public proxy flow
// (an HTTP client timeout) leave the host's circuit closed, and the next
// caller gets the upstream's answer instead of a 500.
func TestProxyCallerAbortsDoNotOpenCircuit(t *testing.T) {
	resetCircuitsForTest(t)
	var slow atomic.Bool
	slow.Store(true)
	startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if slow.Load() {
			select {
			case <-r.Context().Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("png"))
	})
	app, base := serveProxyFlow(t, proxyFlow("GET", "/api/img", "url: http://"+proxyTestHost+"/slow.png", "content_types: [image/png]"))
	impatient := &http.Client{Timeout: 150 * time.Millisecond}
	for i := 0; i <= cbFailureThreshold; i++ {
		if resp, err := impatient.Get(base + "/api/img"); err == nil {
			resp.Body.Close()
			t.Fatalf("request %d was answered (%d) before the client gave up", i, resp.StatusCode)
		}
	}
	// Each abort reaches the server asynchronously; wait until the last
	// proxied call has ended.
	deadline := time.Now().Add(600 * time.Millisecond)
	for time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
		if n := circuitFailures(app, "http://"+proxyTestHost+"/slow.png"); n != 0 {
			t.Fatalf("caller aborts counted %d failures against the host", n)
		}
	}
	slow.Store(false)
	resp, body := mustGet(t, base+"/api/img")
	if resp.StatusCode != http.StatusOK || body != "png" {
		t.Fatalf("next caller: status %d body %q, want the upstream's image", resp.StatusCode, body)
	}
}
