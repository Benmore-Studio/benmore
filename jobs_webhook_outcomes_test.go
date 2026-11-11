//go:build !cli

package main

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type webhookOutcomeTransport struct {
	status int
	err    error
}

func (rt webhookOutcomeTransport) RoundTrip(*http.Request) (*http.Response, error) {
	if rt.err != nil {
		return nil, rt.err
	}
	return &http.Response{StatusCode: rt.status, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(""))}, nil
}

func TestProcessNextJobPersistsWebhookOutcomesWithoutUnsafeReplay(t *testing.T) {
	for _, tc := range []struct {
		name         string
		status       int
		transportErr error
		command      bool
		wantStatus   string
		wantUnknown  bool
	}{
		{name: "success", status: http.StatusNoContent, wantStatus: "completed"},
		{name: "permanent 4xx", status: http.StatusBadRequest, wantStatus: "failed"},
		{name: "retryable 429", status: http.StatusTooManyRequests, wantStatus: "pending"},
		{name: "command 429", status: http.StatusTooManyRequests, command: true, wantStatus: "failed"},
		{name: "lost response", transportErr: errors.New("connection reset"), wantStatus: "failed", wantUnknown: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app, done := newTestApp(t)
			defer done()
			EnsureJobsTable(app.DB)
			jobType := "webhook_outcome_test"
			testJobExecutors[jobType] = func(_ *App, _ string, data map[string]any) error {
				req, err := http.NewRequest(http.MethodPost, "https://hooks.example.test/", strings.NewReader("{}"))
				if err != nil {
					return err
				}
				_, err = postWebhook(&http.Client{Transport: webhookOutcomeTransport{status: tc.status, err: tc.transportErr}}, req)
				return webhookDeliveryError(err, data["command_effect"] == true)
			}
			t.Cleanup(func() { delete(testJobExecutors, jobType) })
			payload, err := json.Marshal(map[string]any{"command_effect": tc.command})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := app.DB.Exec("INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at) VALUES (?, 'webhook_outcome_test', ?, datetime('now'))", jobType, string(payload)); err != nil {
				t.Fatal(err)
			}

			if !processNextJob(app) {
				t.Fatal("worker did not claim the webhook job")
			}
			var status, jobError string
			var attempts int
			if err := app.DB.QueryRow("SELECT status, COALESCE(error,''), attempts FROM _benmore_jobs WHERE job_type=?", jobType).Scan(&status, &jobError, &attempts); err != nil {
				t.Fatal(err)
			}
			if status != tc.wantStatus || attempts != 1 {
				t.Fatalf("worker outcome = %s after %d attempts, want %s after one", status, attempts, tc.wantStatus)
			}
			if tc.wantUnknown {
				if !strings.HasPrefix(jobError, "unknown:") || appMCPEffectStatus("failed", jobError, "", time.Now()) != appMCPEffectUnknown {
					t.Fatalf("lost response is not recorded as unknown: %q", jobError)
				}
			}
			if processNextJob(app) {
				t.Fatal("worker replayed a completed, failed, or backing-off delivery")
			}
			if err := app.DB.QueryRow("SELECT attempts FROM _benmore_jobs WHERE job_type=?", jobType).Scan(&attempts); err != nil || attempts != 1 {
				t.Fatalf("worker replayed delivery: attempts=%d err=%v", attempts, err)
			}
		})
	}
}

// A delivery refused by an open circuit sent nothing, so it keeps its
// attempt and waits for the cooldown: an outage longer than the retry
// backoff used to fail every queued delivery without one request.
func TestWebhookDeliveryDeferredByOpenCircuitKeepsItsAttempt(t *testing.T) {
	app, _, _, _, got := sealedJobApp(t)
	host := circuitKey(app, sealedJobSubURL)
	for i := 0; i < cbFailureThreshold; i++ {
		RecordFailure(host)
	}
	t.Cleanup(func() { RecordSuccess(host) })
	sub, _ := json.Marshal(map[string]any{"_webhook_subscription": map[string]any{"webhook_id": "1", "url": sealedJobSubURL, "event": "insert", "table": "patients"}, "_row": map[string]any{"id": 1}})
	mustExecArgs(t, app.DB, "INSERT INTO _benmore_jobs (job_type, flow_name, payload, run_at) VALUES ('webhook_subscription', 'webhook_subscription', ?, datetime('now'))", string(sub))
	for i := 0; i < 4; i++ { // more claims than max_attempts (3)
		mustExecArgs(t, app.DB, "UPDATE _benmore_jobs SET not_before = NULL")
		if !processNextJob(app) {
			t.Fatal("worker did not claim the delivery")
		}
	}
	var status, notBefore string
	var attempts int
	if err := app.DB.QueryRow("SELECT status, attempts, COALESCE(not_before,'') FROM _benmore_jobs").Scan(&status, &attempts, &notBefore); err != nil {
		t.Fatal(err)
	}
	// not_before is rounded up past the cooldown: truncated, the delivery
	// was claimable while the circuit was still open and spun the worker.
	if status != "pending" || attempts != 0 || notBefore <= time.Now().Add(cbCooldown).UTC().Format(sqliteDateTimeLayout) {
		t.Fatalf("deferred delivery: status=%s attempts=%d not_before=%q, want pending, 0 attempts, not_before past the cooldown", status, attempts, notBefore)
	}
	// `flush: jobs` finishes instead of re-claiming the deferred delivery
	// until the circuit closes.
	start := time.Now()
	FlushJobs(app)
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("FlushJobs took %s against an open circuit", took)
	}
	if err := app.DB.QueryRow("SELECT status, attempts FROM _benmore_jobs").Scan(&status, &attempts); err != nil || status != "pending" || attempts != 0 {
		t.Fatalf("after flush: status=%s attempts=%d err=%v, want pending with its attempt", status, attempts, err)
	}
	select {
	case d := <-got:
		t.Fatalf("a delivery was sent through an open circuit: %v", d)
	default:
	}
}
