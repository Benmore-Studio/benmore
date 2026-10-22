//go:build !cli

package main

import (
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

type failingWebhookTransport struct{}

func (failingWebhookTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("connection reset")
}

func TestPostWebhookClassifiesDeliveryOutcomes(t *testing.T) {
	for _, tc := range []struct {
		status    int
		wantFail  bool
		wantFinal bool
	}{
		{http.StatusOK, false, false},
		{http.StatusNoContent, false, false},
		{http.StatusFound, true, true},
		{http.StatusBadRequest, true, true},
		{http.StatusRequestTimeout, true, false},
		{http.StatusTooManyRequests, true, false},
		{http.StatusInternalServerError, true, false},
		{http.StatusServiceUnavailable, true, false},
	} {
		t.Run(fmt.Sprint(tc.status), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			req, err := http.NewRequest(http.MethodPost, server.URL, strings.NewReader("{}"))
			if err != nil {
				t.Fatal(err)
			}
			status, err := postWebhook(server.Client(), req)
			if status != tc.status || (err != nil) != tc.wantFail {
				t.Fatalf("postWebhook = (%d, %v), want status %d failure=%v", status, err, tc.status, tc.wantFail)
			}
			if err != nil {
				var final jobNotRetryable
				if errors.As(err, &final) != tc.wantFinal {
					t.Fatalf("permanent=%v, want %v: %v", errors.As(err, &final), tc.wantFinal, err)
				}
			}
		})
	}
}

func TestPostWebhookTransportFailureIsUnknownAndFinal(t *testing.T) {
	client := &http.Client{Transport: failingWebhookTransport{}}
	req, err := http.NewRequest(http.MethodPost, "https://hooks.example.test", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := postWebhook(client, req); err == nil || !strings.HasPrefix(err.Error(), "unknown:") {
		t.Fatalf("transport error = %v, want unknown", err)
	} else {
		var final jobNotRetryable
		if !errors.As(err, &final) {
			t.Fatalf("transport error is retryable: %v", err)
		}
	}
}

func TestPostWebhookDoesNotFollowRedirects(t *testing.T) {
	var targetCalls atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, httptest.NewRequest(http.MethodPost, "/", nil), target.URL, http.StatusFound)
	}))
	defer source.Close()
	req, err := http.NewRequest(http.MethodPost, source.URL, strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	status, err := postWebhook(source.Client(), req)
	var final jobNotRetryable
	if status != http.StatusFound || !errors.As(err, &final) || targetCalls.Load() != 0 {
		t.Fatalf("redirect outcome = (%d, %v), target calls=%d; want permanent 302 and no follow", status, err, targetCalls.Load())
	}
}

func TestWebhookHostForLogOmitsURLCredentialsAndQuery(t *testing.T) {
	if got := webhookHostForLog("https://alice:secret@example.test/hook?token=private"); got != "example.test" {
		t.Fatalf("logged host = %q, want hostname only", got)
	}
}
