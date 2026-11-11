//go:build !cli

package main

import (
	"context"
	"fmt"
)

type errorSinkResult struct {
	Status     int  `json:"status"`
	OK         bool `json:"ok"`
	Rejected   bool `json:"rejected"`
	Muted      bool `json:"muted"`
	Configured bool `json:"configured"`
}

type errorReportingTestResult struct {
	Sentry   errorSinkResult  `json:"sentry"`
	Slack    errorSinkResult  `json:"slack"`
	Counters map[string]int64 `json:"counters"`
}

func testErrorReporting(ctx context.Context, app *App) (errorReportingTestResult, error) {
	r := app.getErrorReporter()
	reply := make(chan errorReportingTestResult, 1)
	select {
	case <-r.done:
		return errorReportingTestResult{}, fmt.Errorf("error reporter stopped")
	case <-ctx.Done():
		return errorReportingTestResult{}, ctx.Err()
	case r.queue <- errorEvent{testReply: reply}:
	default:
		return errorReportingTestResult{}, appDataFail("busy", "error reporter queue is full; retry shortly")
	}
	select {
	case result := <-reply:
		return result, nil
	case <-ctx.Done():
		return errorReportingTestResult{}, ctx.Err()
	case <-r.done:
		return errorReportingTestResult{}, fmt.Errorf("error reporter stopped before the test completed")
	}
}

func (r *errorReporter) processTest(ctx context.Context, reply chan errorReportingTestResult) {
	ev := scrubErrorEvent(r.app, errorEvent{Source: "server", Kind: "test", Level: "error", Type: "error_reporting_test", Message: "Benmore error reporting test", Mechanism: "generic", Handled: true})
	r.counters.captured.Add(1)
	// The group shows the test ran but is recorded resolved: a synthetic
	// event must not count as an open failure in health.
	r.ensureTable(ctx)
	if _, _, err := recordGroupContext(ctx, r.app, ev, r.now()); err != nil {
		r.counters.failed.Add(1)
	} else if _, err := r.app.DB.ExecContext(ctx, `UPDATE _benmore_error_groups SET resolved_at=? WHERE group_key=?`, r.now().UTC().Format(errorTimeFormat), errorGroupKey(ev)); err != nil {
		r.counters.failed.Add(1)
	}
	out := errorReportingTestResult{}
	out.Sentry.Configured = GetEnv(r.app.Dir, "SENTRY_DSN") != ""
	out.Slack.Configured = GetEnv(r.app.Dir, "ERROR_SLACK_WEBHOOK") != ""
	if out.Sentry.Configured {
		// Test sends spend their own budget, never the one real failures use.
		result := r.sendEventBudget(ctx, ev, "test")
		out.Sentry.Status, out.Sentry.OK, out.Sentry.Rejected = result.Status, result.OK, result.Rejected
		out.Sentry.Muted = len(result.MutedCategories) > 0
	}
	if out.Slack.Configured {
		if r.allow("test:slack") {
			result := r.sendSlackDirect(ctx, ev)
			out.Slack.Status, out.Slack.OK, out.Slack.Rejected = result.Status, result.OK, result.Rejected
			out.Slack.Muted = len(result.MutedCategories) > 0
		} else {
			r.counters.throttled.Add(1)
			out.Slack.Muted = true
		}
	}
	out.Counters = r.counters.snapshot()
	reply <- out
}
