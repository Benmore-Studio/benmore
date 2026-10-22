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
