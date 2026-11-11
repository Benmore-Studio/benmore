//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// A video served through serve_file is played from the URL the browser was
// redirected to, with range requests for as long as it plays: its signed link
// must outlive playback, while a document link stays short.
func TestServeFileSignedLinkLifetimeFollowsMediaType(t *testing.T) {
	t.Setenv("BENMORE_BIND_LOOPBACK", "1")
	cases := []struct {
		file      string
		expiresIn time.Duration
		want      float64
	}{
		{"a.pdf", 0, serveFileSignTTL.Seconds()},
		{"talk.mp4", 0, mediaPlaybackSignTTL.Seconds()},
		{"talk.MOV", 0, mediaPlaybackSignTTL.Seconds()},
		{"episode.m4a", 0, mediaPlaybackSignTTL.Seconds()},
		{"a.pdf", 30 * time.Minute, 1800},
		{"talk.webm", 6 * time.Hour, oauthMaxSignedURLTTL.Seconds()},
		{"talk.webm", 48 * time.Hour, oauthMaxSignedURLTTL.Seconds()},
	}
	for _, tc := range cases {
		t.Run(tc.file+"/"+tc.expiresIn.String(), func(t *testing.T) {
			broker := startFakeMediaBroker(t, map[string]any{"url": "https://cdn.example.test/router-signed", "key": "k"})
			cfg := testMediaConfig(t)
			withPlatformMedia(t, cfg)
			// serve_file consults the app's upload ownership records.
			app, cleanup := newTestApp(t)
			defer cleanup()
			key := "private/" + appMediaPrefix(app) + "/uploads/private/" + tc.file
			rec := httptest.NewRecorder()
			ctx := &FlowContext{App: app, Writer: rec, Request: httptest.NewRequest(http.MethodGet, "/f/doc", nil), Data: map[string]any{}, Params: map[string]string{}}
			step := &FlowStep{Type: "serve_file", ServeFile: &FlowServeFile{Path: "https://" + cfg.CDNDomain + "/" + key, ExpiresIn: tc.expiresIn}}
			if err := execStepServeFile(ctx, step); err != nil {
				t.Fatal(err)
			}
			if rec.Code != http.StatusFound {
				t.Fatalf("serve_file = %d, want 302", rec.Code)
			}
			reqs := broker.requests()
			if len(reqs) != 1 {
				t.Fatalf("broker saw %d requests", len(reqs))
			}
			if got, _ := reqs[0]["expires_in"].(float64); got != tc.want {
				t.Fatalf("requested lifetime = %v, want %v", got, tc.want)
			}
		})
	}
}

// bm.signedUrl (GET /api/_signed_url) uses the same media-aware default when
// the caller names no lifetime, and never exceeds the 6h ceiling.
func TestSignedLinkTTLDefaults(t *testing.T) {
	for _, tc := range []struct {
		path      string
		requested time.Duration
		fallback  time.Duration
		want      time.Duration
	}{
		{"/uploads/private/a.pdf", 0, time.Hour, time.Hour},
		{"/uploads/private/clip.mp4", 0, time.Hour, mediaPlaybackSignTTL},
		{"https://cdn.example.test/private/p/uploads/private/clip.mp3?x=1", 0, serveFileSignTTL, mediaPlaybackSignTTL},
		{"/uploads/private/clip.mp4", 10 * time.Minute, time.Hour, 10 * time.Minute},
		{"/uploads/private/clip.m3u8", 0, time.Hour, time.Hour},
		{"/uploads/private/a.pdf", 7 * time.Hour, time.Hour, oauthMaxSignedURLTTL},
	} {
		if got := signedLinkTTL(tc.path, tc.requested, tc.fallback); got != tc.want {
			t.Errorf("signedLinkTTL(%q, %s, %s) = %s, want %s", tc.path, tc.requested, tc.fallback, got, tc.want)
		}
	}
}

func TestParseSignedLinkLifetime(t *testing.T) {
	ok := map[any]time.Duration{
		7200:        2 * time.Hour,
		int64(60):   time.Minute,
		float64(90): 90 * time.Second,
		"3600":      time.Hour,
		"2h":        2 * time.Hour,
		" 90m ":     90 * time.Minute,
		"6h":        6 * time.Hour,
		uint64(30):  30 * time.Second,
	}
	for in, want := range ok {
		got, err := parseSignedLinkLifetime(in)
		if err != nil || got != want {
			t.Errorf("parseSignedLinkLifetime(%#v) = %s, %v; want %s", in, got, err, want)
		}
	}
	for _, in := range []any{0, -5, "0s", "500ms", "7h", 21601, "21601", int64(1) << 62, float64(1.5), "soon", "${{ params.ttl }}", "{{ttl}}", true, nil, []any{1}} {
		if got, err := parseSignedLinkLifetime(in); err == nil {
			t.Errorf("parseSignedLinkLifetime(%#v) = %s, want an error", in, got)
		}
	}
}

// with.expires_in is a literal the write gate checks; the loader keeps a
// valid value on the step.
func TestServeFileExpiresInIsValidatedAndLoaded(t *testing.T) {
	flow := func(v string) string {
		return "on:\n  request:\n    path: /video\n    method: GET\njobs:\n  main:\n    steps:\n      - run: serve_file\n        with:\n          path: /uploads/private/talk.mp4\n          expires_in: " + v + "\n"
	}
	if msg := ValidateOnWrite("flows/video.yaml", flow("2h")); msg != "" {
		t.Fatalf("valid expires_in refused: %s", msg)
	}
	for _, bad := range []string{"12h", "\"${{ params.ttl }}\"", "soon", "0"} {
		msg := ValidateOnWrite("flows/video.yaml", flow(bad))
		if !strings.Contains(msg, "expires_in") {
			t.Fatalf("expires_in %s accepted (msg %q)", bad, msg)
		}
	}
	flows, err := parseGHAFlowFile("flows/video.yaml", []byte(flow("7200")))
	if err != nil || len(flows) != 1 || len(flows[0].Steps) != 1 || flows[0].Steps[0].ServeFile == nil {
		t.Fatalf("parse: %v %+v", err, flows)
	}
	if got := flows[0].Steps[0].ServeFile.ExpiresIn; got != 2*time.Hour {
		t.Fatalf("loaded expires_in = %s, want 2h", got)
	}
}
