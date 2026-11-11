//go:build !cli

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

type sentryDSN struct{ PublicKey, Host, PathPrefix, ProjectID string }

var sentryKeyRE = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
var sentryProjectRE = regexp.MustCompile(`^[0-9]+$`)

// Errors are deliberately fixed text: a parser error can contain the DSN key.
func parseSentryDSN(raw string) (sentryDSN, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User == nil || u.Opaque != "" {
		return sentryDSN{}, fmt.Errorf("SENTRY_DSN requires HTTPS, a public key and a host")
	}
	if _, password := u.User.Password(); password || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") {
		return sentryDSN{}, fmt.Errorf("SENTRY_DSN cannot contain a password, query or fragment")
	}
	if !sentryKeyRE.MatchString(u.User.Username()) || u.RawPath != "" {
		return sentryDSN{}, fmt.Errorf("SENTRY_DSN contains an invalid key or escaped path")
	}
	parts := strings.Split(strings.TrimPrefix(u.Path, "/"), "/")
	for _, p := range parts {
		if p == "" || p == "." || p == ".." {
			return sentryDSN{}, fmt.Errorf("SENTRY_DSN contains an invalid path")
		}
	}
	project := parts[len(parts)-1]
	if !sentryProjectRE.MatchString(project) {
		return sentryDSN{}, fmt.Errorf("SENTRY_DSN requires a numeric project id")
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return sentryDSN{}, fmt.Errorf("SENTRY_DSN contains an invalid port")
		}
	}
	prefix := ""
	if len(parts) > 1 {
		prefix = "/" + strings.Join(parts[:len(parts)-1], "/")
	}
	return sentryDSN{PublicKey: u.User.Username(), Host: u.Host, PathPrefix: prefix, ProjectID: project}, nil
}

func (d sentryDSN) envelopeURL() string {
	return (&url.URL{Scheme: "https", Host: d.Host, Path: d.PathPrefix + "/api/" + d.ProjectID + "/envelope/"}).String()
}

func newSentryEventID() string {
	var id [16]byte
	// crypto/rand.Read never returns an error on supported Go versions.
	_, _ = rand.Read(id[:])
	return hex.EncodeToString(id[:])
}

type envelopeItem struct {
	Type    string
	Payload []byte
}

func buildEnvelope(eventID string, items ...envelopeItem) []byte {
	header := struct {
		EventID string `json:"event_id,omitempty"`
		SentAt  string `json:"sent_at"`
		SDK     struct {
			Name    string `json:"name"`
			Version string `json:"version"`
		} `json:"sdk"`
	}{EventID: eventID, SentAt: time.Now().UTC().Format(time.RFC3339Nano)}
	header.SDK.Name, header.SDK.Version = "benmore.go", version
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	_ = enc.Encode(header)
	for _, item := range items {
		_ = enc.Encode(struct {
			Type   string `json:"type"`
			Length int    `json:"length"`
		}{item.Type, len(item.Payload)})
		out.Write(item.Payload)
		out.WriteByte('\n')
	}
	return out.Bytes()
}

type deliveryResult struct {
	OK              bool
	Status          int
	RetryAfter      time.Duration
	MutedCategories []string
	Rejected        bool
	// Preserve individual deadlines: using the longest delay for every category
	// would mute monitors when only error events exhausted their quota.
	limits map[string]time.Time
}

func deliverEnvelope(ctx context.Context, client *http.Client, d sentryDSN, body []byte) deliveryResult {
	compressed := len(body) > 1024
	if compressed {
		var buf bytes.Buffer
		gz := gzip.NewWriter(&buf)
		_, _ = gz.Write(body)
		_ = gz.Close()
		body = buf.Bytes()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, d.envelopeURL(), bytes.NewReader(body))
	if err != nil {
		return deliveryResult{}
	}
	req.Header.Set("Content-Type", "application/x-sentry-envelope")
	req.Header.Set("X-Sentry-Auth", "Sentry sentry_version=7, sentry_key="+d.PublicKey+", sentry_client=benmore.go/"+version)
	if compressed {
		req.Header.Set("Content-Encoding", "gzip")
	}
	resp, err := client.Do(req)
	if err != nil {
		return deliveryResult{}
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 1<<20))
	now := time.Now()
	result := deliveryResult{OK: resp.StatusCode >= 200 && resp.StatusCode < 300, Status: resp.StatusCode,
		Rejected: resp.StatusCode == 401 || resp.StatusCode == 403, limits: parseSentryRateLimits(resp.Header, now)}
	if result.Rejected {
		result.limits[""] = now.Add(10 * time.Minute)
	}
	if resp.StatusCode == 429 && len(result.limits) == 0 {
		delay := time.Minute
		if seconds, err := strconv.ParseFloat(resp.Header.Get("Retry-After"), 64); err == nil {
			delay = sentryRetryDuration(seconds)
		} else if at, err := http.ParseTime(resp.Header.Get("Retry-After")); err == nil && at.After(now) {
			delay = at.Sub(now)
		}
		result.limits[""] = now.Add(delay)
	}
	for category, until := range result.limits {
		result.MutedCategories = append(result.MutedCategories, category)
		if delay := until.Sub(now); delay > result.RetryAfter {
			result.RetryAfter = delay
		}
	}
	return result
}

func sentryRetryDuration(seconds float64) time.Duration {
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) || seconds < 0 {
		return time.Minute
	}
	// Avoid duration overflow from an untrusted response header.
	if seconds > float64((1<<63-1)/int64(time.Second)) {
		return time.Duration(1<<63 - 1)
	}
	return time.Duration(seconds * float64(time.Second))
}

func parseSentryRateLimits(h http.Header, now time.Time) map[string]time.Time {
	limits := map[string]time.Time{}
	for _, header := range h.Values("X-Sentry-Rate-Limits") {
		for _, quota := range strings.Split(header, ",") {
			fields := strings.Split(strings.TrimSpace(quota), ":")
			if len(fields) < 2 {
				continue
			}
			seconds, err := strconv.ParseFloat(strings.TrimSpace(fields[0]), 64)
			if err != nil {
				seconds = 60
			}
			until := now.Add(sentryRetryDuration(seconds))
			for _, category := range strings.Split(fields[1], ";") {
				category = strings.TrimSpace(category)
				if until.After(limits[category]) {
					limits[category] = until
				}
			}
		}
	}
	return limits
}

// A state belongs to one app's current DSN, never to the process as a whole.
type sentryMuteState struct {
	mu        sync.Mutex
	until     map[string]time.Time
	connected bool
	rejected  bool
}

func (m *sentryMuteState) status() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	if m.rejected && now.Before(m.until[""]) {
		return "rejected"
	}
	if now.Before(m.until[""]) || now.Before(m.until["error"]) {
		return "rate_limited"
	}
	if m.connected {
		return "connected"
	}
	return "configured"
}

func (m *sentryMuteState) muted(category string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	now := time.Now()
	return now.Before(m.until[""]) || now.Before(m.until[category])
}

func (m *sentryMuteState) apply(result deliveryResult) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if result.OK {
		m.connected = true
		m.rejected = false
	}
	if result.Rejected {
		m.rejected = true
	}
	if m.until == nil {
		m.until = map[string]time.Time{}
	}
	for category, until := range result.limits {
		if until.After(m.until[category]) {
			m.until[category] = until
		}
	}
}

func sentryHTTPClient() *http.Client  { return safeHTTPClientStrict(5 * time.Second) }
func sentrySendable(d sentryDSN) bool { return !isPrivateURL(d.envelopeURL()) }
