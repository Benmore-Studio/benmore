//go:build !cli

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestSentryDSN(t *testing.T) {
	for _, tc := range []struct{ raw, endpoint string }{
		{"https://public@sentry.example/123", "https://sentry.example/api/123/envelope/"},
		{"https://public@sentry.example:8443/prefix/123", "https://sentry.example:8443/prefix/api/123/envelope/"},
	} {
		d, err := parseSentryDSN(tc.raw)
		if err != nil || d.envelopeURL() != tc.endpoint || d.PublicKey != "public" {
			t.Fatalf("parse: %+v %v", d, err)
		}
	}
	for _, raw := range []string{
		"http://privatekey@sentry.example/1", "https://privatekey:password@sentry.example/1",
		"https://privatekey@sentry.example/no", "https://privatekey@sentry.example/1?x=1",
		"https://privatekey@sentry.example/1#x", "https://privatekey@sentry.example/1?",
		"https://privatekey@/1", "https://sentry.example/1", "https://@sentry.example/1",
		"https://privatekey@sentry.example/", "https://privatekey@sentry.example/a/../1",
		"https://privatekey%0a@sentry.example/1", "https://privatekey@sentry.example/a%2fb/1",
	} {
		_, err := parseSentryDSN(raw)
		if err == nil {
			t.Fatalf("accepted invalid DSN %q", raw)
		}
		if strings.Contains(err.Error(), "privatekey") {
			t.Fatal("DSN error leaked key")
		}
	}
	seen := map[string]bool{}
	for i := 0; i < 100; i++ {
		id := newSentryEventID()
		if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) || seen[id] {
			t.Fatal("invalid or reused event id")
		}
		seen[id] = true
	}
}

func TestSentryEnvelopeBytes(t *testing.T) {
	id := "0123456789abcdef0123456789abcdef"
	payload := []byte(`{"message":"line\nnext ✓"}`)
	body := buildEnvelope(id, envelopeItem{Type: "event", Payload: payload}, envelopeItem{Type: "client_report", Payload: []byte(`{}`)})
	lines := bytes.Split(body, []byte("\n"))
	if len(lines) != 6 {
		t.Fatalf("envelope lines: %q", body)
	}
	var header struct {
		EventID string                         `json:"event_id"`
		SentAt  string                         `json:"sent_at"`
		SDK     struct{ Name, Version string } `json:"sdk"`
	}
	if err := json.Unmarshal(lines[0], &header); err != nil {
		t.Fatal(err)
	}
	if header.EventID != id || header.SDK.Name != "benmore.go" || header.SDK.Version != version {
		t.Fatalf("header: %+v", header)
	}
	if _, err := time.Parse(time.RFC3339Nano, header.SentAt); err != nil {
		t.Fatal(err)
	}
	var item struct {
		Type   string `json:"type"`
		Length int    `json:"length"`
	}
	if err := json.Unmarshal(lines[1], &item); err != nil {
		t.Fatal(err)
	}
	if item.Type != "event" || item.Length != len(payload) || !bytes.Equal(lines[2], payload) {
		t.Fatalf("item: %q", body)
	}
	if string(lines[3]) != `{"type":"client_report","length":2}` || string(lines[4]) != "{}" {
		t.Fatalf("golden item bytes: %q", body)
	}
}

// The injected transport sends to a local test server; production URL admission
// remains HTTPS-only and guarded by sentrySendable and safeHTTPClientStrict.
type sentryTestTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (tr sentryTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.URL.Scheme, r.URL.Host = tr.target.Scheme, tr.target.Host
	return tr.base.RoundTrip(r)
}

func TestSentryDeliveryAndMute(t *testing.T) {
	for _, tc := range []struct {
		name                             string
		status                           int
		limits, retry                    string
		delay                            time.Duration
		errorMute, monitorMute, rejected bool
	}{
		{"ok", 200, "", "", 0, false, false, false},
		{"error_limit", 429, "60:error:organization", "", time.Minute, true, false, false},
		{"all_limit", 429, "", "7", 7 * time.Second, true, true, false},
		{"default_limit", 429, "", "", time.Minute, true, true, false},
		{"rejected", 401, "", "", 10 * time.Minute, true, true, true},
		{"forbidden", 403, "", "", 10 * time.Minute, true, true, true},
		{"proactive", 200, "60:error:organization", "", time.Minute, true, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := bytes.Repeat([]byte("payload\n"), 200)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/api/123/envelope/" || r.Method != "POST" {
					t.Errorf("request: %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("Content-Type") != "application/x-sentry-envelope" || !strings.Contains(r.Header.Get("X-Sentry-Auth"), "sentry_key=public") {
					t.Error("missing envelope headers")
				}
				if r.Header.Get("Content-Encoding") != "gzip" {
					t.Error("large body not compressed")
				}
				gz, err := gzip.NewReader(r.Body)
				if err != nil {
					t.Error(err)
					return
				}
				defer gz.Close()
				got, err := io.ReadAll(gz)
				if err != nil || !bytes.Equal(got, body) {
					t.Error("body changed in transit")
				}
				w.Header().Set("X-Sentry-Rate-Limits", tc.limits)
				w.Header().Set("Retry-After", tc.retry)
				w.WriteHeader(tc.status)
			}))
			defer server.Close()
			u, _ := url.Parse(server.URL)
			client := &http.Client{Transport: sentryTestTransport{u, server.Client().Transport}}
			d, _ := parseSentryDSN("https://public@sentry.example/123")
			result := deliverEnvelope(context.Background(), client, d, body)
			if result.Status != tc.status || result.OK != (tc.status == 200) || result.Rejected != tc.rejected || result.RetryAfter != tc.delay {
				t.Fatalf("result: %+v", result)
			}
			var mute sentryMuteState
			mute.apply(result)
			if mute.muted("error") != tc.errorMute || mute.muted("monitor") != tc.monitorMute {
				t.Fatalf("mute state: %+v", result)
			}
		})
	}
}

func TestSentryRateLimitsSeparateDurations(t *testing.T) {
	now := time.Now()
	h := http.Header{"X-Sentry-Rate-Limits": []string{"60:error:organization, 7:monitor;transaction:organization"}}
	limits := parseSentryRateLimits(h, now)
	if limits["error"].Sub(now) != time.Minute || limits["monitor"].Sub(now) != 7*time.Second {
		t.Fatalf("limits: %v", limits)
	}
	var mute sentryMuteState
	mute.apply(deliveryResult{limits: map[string]time.Time{"error": now.Add(-time.Second), "monitor": now.Add(time.Minute)}})
	if mute.muted("error") || !mute.muted("monitor") {
		t.Fatal("expired category still muted or live category ignored")
	}
}
