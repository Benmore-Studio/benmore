//go:build !cli

package main

// `run: proxy` (flows_proxy.go, validators_flow_proxy.go). Upstreams are
// httptest servers reached through the production strict client: URLs keep
// a public address literal (they pass isPrivateURL), and the strict
// transport is pointed at the test server for the test.

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

const proxyTestHost = "93.184.216.34"

type proxyUpstream struct {
	mu       sync.Mutex
	requests []*http.Request
	bodies   []string
}

func (u *proxyUpstream) count() int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return len(u.requests)
}

func (u *proxyUpstream) last(t *testing.T) (*http.Request, string) {
	t.Helper()
	u.mu.Lock()
	defer u.mu.Unlock()
	if len(u.requests) == 0 {
		t.Fatal("the upstream was never called")
	}
	return u.requests[len(u.requests)-1], u.bodies[len(u.bodies)-1]
}

// startProxyUpstream answers every outbound strict-client connection with h.
func startProxyUpstream(t *testing.T, h http.HandlerFunc) *proxyUpstream {
	t.Helper()
	u := &proxyUpstream{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		u.mu.Lock()
		u.requests = append(u.requests, r.Clone(context.Background()))
		u.bodies = append(u.bodies, string(body))
		u.mu.Unlock()
		h(w, r)
	}))
	t.Cleanup(srv.Close)
	saved := strictOutboundTransport
	strictOutboundTransport = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
	}}
	t.Cleanup(func() { strictOutboundTransport = saved })
	return u
}

// serveProxyFlow passes source through the write gate, loads it and serves
// it from a real HTTP server (so an aborted answer is a real abort).
func serveProxyFlow(t *testing.T, source string) (*App, string) {
	t.Helper()
	if msg := ValidateOnWrite("flows/p.yaml", source); msg != "" {
		t.Fatalf("write gate refused the flow: %s", msg)
	}
	app, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	flows, err := parseGHAFlowFile("flows/p.yaml", []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, flows)
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return app, srv.URL
}

// proxyFlow is a public GET (or POST) request flow, rate limited as a public
// proxy flow must be, whose one step is a proxy step with the given `with:`
// lines.
func proxyFlow(method, path string, with ...string) string {
	return "on:\n  request:\n    method: " + method + "\n    path: " + path + "\n    rate_limit: 1000/min\njobs:\n  p:\n    steps:\n      - run: proxy\n        with:\n          " + strings.Join(with, "\n          ") + "\n"
}

func proxyStepCtx(app *App, w http.ResponseWriter, r *http.Request) *FlowContext {
	return &FlowContext{App: app, Request: r, Writer: w, liveResponse: true,
		Data: map[string]any{}, Params: map[string]string{}, RequestKeys: map[string]bool{}}
}

func proxyStep(url string, types ...string) FlowStep {
	return FlowStep{Name: "p", Type: "proxy", Proxy: &FlowProxy{Request: &FlowAPICall{URL: url}, ContentTypes: types}}
}

func mustGet(t *testing.T, url string) (*http.Response, string) {
	t.Helper()
	resp, err := http.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return resp, string(body)
}

// The ElevenLabs shape: a POST whose key comes from env and whose JSON body
// carries request input; the audio comes back with the allow-listed type and
// the protective headers, and nothing else of the upstream's.
func TestProxyStreamsAudioPostWithEnvSecretHeader(t *testing.T) {
	upstream := startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		w.Header().Set("ETag", `"v1"`)
		w.Header().Set("Content-Length", "6")
		_, _ = w.Write([]byte("ID3abc"))
	})
	app, base := serveProxyFlow(t, proxyFlow("POST", "/api/speak/:voice",
		"url: http://"+proxyTestHost+"/v1/text-to-speech/${{ params.voice }}",
		"method: POST",
		`headers: { xi-api-key: "${{ env.ELEVENLABS_KEY }}" }`,
		`json: { text: "${{ params.text }}", model_id: eleven_multilingual_v2 }`,
		"content_types: [audio/mpeg]",
		"max_bytes: 1MB",
	))
	SetAppEnv(app.Dir, "ELEVENLABS_KEY", "xi-test-secret")
	resp, err := http.Post(base+"/api/speak/voice-7", "application/json", strings.NewReader(`{"text":"say \"hi\""}`))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || string(body) != "ID3abc" {
		t.Fatalf("answer = %d %q", resp.StatusCode, body)
	}
	for name, want := range map[string]string{
		"Content-Type":            "audio/mpeg",
		"X-Content-Type-Options":  "nosniff",
		"Content-Security-Policy": "default-src 'none'; sandbox",
		"Content-Disposition":     "inline",
		"Cache-Control":           "private, no-store",
		"Etag":                    `"v1"`,
		"Content-Length":          "6",
	} {
		if got := resp.Header.Get(name); got != want {
			t.Errorf("%s = %q, want %q", name, got, want)
		}
	}
	req, sent := upstream.last(t)
	if req.Method != "POST" || req.URL.Path != "/v1/text-to-speech/voice-7" || req.Header.Get("Xi-Api-Key") != "xi-test-secret" || req.Header.Get("Content-Type") != "application/json" {
		t.Fatalf("upstream request = %s %s %v", req.Method, req.URL, req.Header)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(sent), &got); err != nil || got["text"] != `say "hi"` || got["model_id"] != "eleven_multilingual_v2" {
		t.Fatalf("upstream body = %s (%v)", sent, err)
	}
}

// Request input fills a path segment, encoded so it stays one segment, and
// a query value, encoded as one value. Request input that holds `/` or `\`
// (plain, percent-encoded or double-encoded) or is a dot segment is refused
// in the path before anything is sent: an upstream that decodes %2F and
// normalizes would serve another endpoint with the author's credentials.
// The upstream's own caching directives never reach the caller.
func TestProxyImageGetEncodesRequestPathSegment(t *testing.T) {
	upstream := startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=60")
		_, _ = w.Write([]byte("\x89PNG"))
	})
	_, base := serveProxyFlow(t, proxyFlow("GET", "/api/img",
		"url: http://"+proxyTestHost+"/images/${{ params.name }}?w=${{ params.w }}",
		"content_types: [image/png, image/jpeg]",
	))
	resp, body := mustGet(t, base+"/api/img?name=a+b%3Fx%3D1%23y%26z&w=64%26raw%3D1%2F..%2Fx")
	if resp.StatusCode != 200 || body != "\x89PNG" || resp.Header.Get("Cache-Control") != "private, no-store" || resp.Header.Get("Content-Type") != "image/png" {
		t.Fatalf("answer = %d %q %v", resp.StatusCode, body, resp.Header)
	}
	req, _ := upstream.last(t)
	if req.RequestURI != "/images/a%20b%3Fx=1%23y&z?w=64%26raw%3D1%2F..%2Fx" {
		t.Fatalf("upstream request URI = %q: a request value left its segment", req.RequestURI)
	}
	for _, name := range []string{
		"..%2Fadmin%2Fkeys", // ../admin/keys
		"..%252Fadmin",      // ..%2Fadmin
		"a%25252Fb",         // a%252Fb, decoded twice
		"a%5Cb",             // a\b
		"a%255cb",           // a%5cb
		"..",
		".",
		"%252e%252e", // %2e%2e
	} {
		resp, body := mustGet(t, base+"/api/img?w=1&name="+name)
		if resp.StatusCode != 500 || upstream.count() != 1 || strings.Contains(body, "PNG") {
			t.Fatalf("name=%s: %d %s (upstream calls %d)", name, resp.StatusCode, body, upstream.count())
		}
	}
	// The step's own error says why.
	app, cleanup := newTestApp(t)
	defer cleanup()
	rr := httptest.NewRecorder()
	ctx := proxyStepCtx(app, rr, httptest.NewRequest("GET", "/api/img", nil))
	ctx.Data["name"], ctx.RequestKeys["name"] = "..%2Fadmin", true
	executeSteps(ctx, []FlowStep{proxyStep("http://"+proxyTestHost+"/images/{{name}}", "image/png")})
	if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "one path segment only") || rr.Body.Len() != 0 || upstream.count() != 1 {
		t.Fatalf("encoded slash: err=%v body=%q upstream=%d", ctx.Error, rr.Body.String(), upstream.count())
	}
	// A value the flow did not take from the request (a stored file key) is
	// one plain segment too; `path_slashes: true` lets it span segments
	// (flows_proxy_path_values_test.go).
	ctx = proxyStepCtx(app, httptest.NewRecorder(), httptest.NewRequest("GET", "/api/img", nil))
	ctx.Data["key"] = "users/42/a.png"
	executeSteps(ctx, []FlowStep{proxyStep("http://"+proxyTestHost+"/images/{{key}}", "image/png")})
	if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "one path segment only") || upstream.count() != 1 {
		t.Fatalf("stored key: err=%v upstream=%d", ctx.Error, upstream.count())
	}
	step := proxyStep("http://"+proxyTestHost+"/images/{{key}}", "image/png")
	step.Proxy.PathSlashes = true
	ctx = proxyStepCtx(app, httptest.NewRecorder(), httptest.NewRequest("GET", "/api/img", nil))
	ctx.Data["key"] = "users/42/a.png"
	executeSteps(ctx, []FlowStep{step})
	if req, _ := upstream.last(t); ctx.Error != nil || req.RequestURI != "/images/users/42/a.png" {
		t.Fatalf("stored key with path_slashes: err=%v uri=%q", ctx.Error, req.RequestURI)
	}
}

// The scheme and host are the author's: refused at write time and again
// when the step runs, for request input and for any step output alike.
func TestProxyRefusesRequestChosenHost(t *testing.T) {
	for name, url := range map[string]string{
		"request host":       "https://${{ params.host }}/v1/file",
		"request scheme":     "${{ params.scheme }}://api.example.com/v1",
		"step output url":    "${{ steps.lookup.outputs.url }}",
		"host suffix":        "https://api.example.com${{ params.x }}/v1",
		"after env host":     "${{ env.API_HOST }}${{ params.x }}/v1",
		"colon placeholder":  "https://api.example.com:port/v1",
		"not http":           "ftp://api.example.com/x",
		"relative reference": "/api/internal",
	} {
		msg := ValidateOnWrite("flows/p.yaml", proxyFlow("GET", "/api/p", "url: "+url, "content_types: [image/png]"))
		if msg == "" {
			t.Errorf("%s: write gate accepted url %s", name, url)
		}
	}
	for _, url := range []string{
		"https://api.example.com/v1/${{ params.id }}?q=${{ params.q }}",
		"${{ env.API_BASE }}/v1/${{ params.id }}",
		"https://${{ env.API_HOST }}/v1/${{ params.id }}",
		"https://api.example.com:8443/v1",
	} {
		if msg := ValidateOnWrite("flows/p.yaml", proxyFlow("GET", "/api/p", "url: "+url, "content_types: [image/png]")); msg != "" {
			t.Errorf("write gate refused authored host %s: %s", url, msg)
		}
	}

	upstream := startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("png"))
	})
	app, cleanup := newTestApp(t)
	defer cleanup()
	for name, tainted := range map[string]bool{"request input": true, "untainted step output": false} {
		rr := httptest.NewRecorder()
		ctx := proxyStepCtx(app, rr, httptest.NewRequest("GET", "/api/p", nil))
		ctx.Data["host"] = proxyTestHost
		ctx.RequestKeys["host"] = tainted
		executeSteps(ctx, []FlowStep{proxyStep("http://{{host}}/x", "image/png")})
		if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "scheme or host") || rr.Body.Len() != 0 || upstream.count() != 0 {
			t.Fatalf("%s: err=%v body=%q upstream=%d", name, ctx.Error, rr.Body.String(), upstream.count())
		}
	}
}

// A private host is refused when written and when an env value holds it.
func TestProxyRefusesPrivateHosts(t *testing.T) {
	for _, url := range []string{"http://127.0.0.1/x", "http://10.0.0.5/x", "http://localhost:8080/x", "http://metadata.internal/x", "http://[::1]/x", "http://169.254.169.254/latest"} {
		if msg := ValidateOnWrite("flows/p.yaml", proxyFlow("GET", "/api/p", "url: "+url, "content_types: [image/png]")); !strings.Contains(msg, "private or internal") {
			t.Errorf("write gate on %s: %q", url, msg)
		}
	}
	upstream := startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("png"))
	})
	app, cleanup := newTestApp(t)
	defer cleanup()
	SetAppEnv(app.Dir, "METADATA_BASE", "http://169.254.169.254")
	rr := httptest.NewRecorder()
	ctx := proxyStepCtx(app, rr, httptest.NewRequest("GET", "/api/p", nil))
	executeSteps(ctx, []FlowStep{proxyStep("{{env.METADATA_BASE}}/latest/meta-data", "image/png")})
	if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "SECURITY: proxy refused a private") || upstream.count() != 0 || rr.Body.Len() != 0 {
		t.Fatalf("env private host: err=%v upstream=%d body=%q", ctx.Error, upstream.count(), rr.Body.String())
	}
}

// An upstream type outside the step's list (or the framework's) fails the
// step before anything is written: the caller gets the flow's error answer,
// never the upstream body.
func TestProxyRefusesDisallowedUpstreamType(t *testing.T) {
	var mu sync.Mutex
	contentType, encoding := "", ""
	startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if contentType == "-" {
			w.Header()["Content-Type"] = nil // no type, and no sniffed one
		} else {
			w.Header().Set("Content-Type", contentType)
		}
		if encoding != "" {
			w.Header().Set("Content-Encoding", encoding)
		}
		mu.Unlock()
		_, _ = w.Write([]byte("<script>UPSTREAM-MARKER</script>"))
	})
	_, base := serveProxyFlow(t, proxyFlow("GET", "/api/img", "url: http://"+proxyTestHost+"/f", "content_types: [image/png]"))
	for _, tc := range []struct{ contentType, encoding string }{
		{"text/html; charset=utf-8", ""},
		{"image/svg+xml", ""},
		{"application/json", ""},
		{"application/xml", ""},
		{"application/octet-stream", ""},
		{"application/javascript", ""},
		{"audio/mpeg", ""}, // allowed by the framework, not by this step
		{"-", ""},          // unlabeled: never sniffed
		{"image/png", "br"},
	} {
		mu.Lock()
		contentType, encoding = tc.contentType, tc.encoding
		mu.Unlock()
		resp, body := mustGet(t, base+"/api/img")
		if resp.StatusCode != 500 || strings.Contains(body, "UPSTREAM-MARKER") || strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
			t.Fatalf("%+v: answer %d %s %q", tc, resp.StatusCode, resp.Header.Get("Content-Type"), body)
		}
		if !strings.Contains(body, "flow_no_response") {
			t.Fatalf("%+v: not the flow's error answer: %s", tc, body)
		}
	}
}

// content_types must be a subset of the framework list, written alone.
func TestProxyWriteGateRefusesContentTypesOutsideList(t *testing.T) {
	for _, line := range []string{
		"content_types: [text/html]",
		"content_types: [image/svg+xml]",
		"content_types: [application/json]",
		"content_types: [image/png, text/javascript]",
		`content_types: ["text/csv; charset=utf-8"]`,
		"content_types: []",
		"max_bytes: 1MB",
	} {
		if msg := ValidateOnWrite("flows/p.yaml", proxyFlow("GET", "/api/p", "url: https://api.example.com/f", line)); !strings.Contains(msg, "content") {
			t.Errorf("%s: write gate said %q", line, msg)
		}
	}
	if msg := ValidateOnWrite("flows/p.yaml", proxyFlow("GET", "/api/p", "url: https://api.example.com/f", "content_types: [audio/mpeg, image/png, application/pdf, text/csv, application/zip, video/mp4]")); msg != "" {
		t.Fatalf("allowed types refused: %s", msg)
	}
}

// A declared length over max_bytes is refused before the status is written.
func TestProxyRefusesDeclaredLengthOverCap(t *testing.T) {
	startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Content-Length", "2048")
		_, _ = w.Write([]byte(strings.Repeat("P", 2048)))
	})
	_, base := serveProxyFlow(t, proxyFlow("GET", "/api/img", "url: http://"+proxyTestHost+"/big.png", "content_types: [image/png]", "max_bytes: 1KB"))
	resp, body := mustGet(t, base+"/api/img")
	if resp.StatusCode != 500 || strings.Contains(body, "PPPP") || !strings.Contains(body, "flow_no_response") {
		t.Fatalf("over-cap declared length: %d %q", resp.StatusCode, body)
	}
}

// A body that passes max_bytes while streaming aborts the connection: the
// caller has the bytes sent so far and a read error, never a clean end.
func TestProxyAbortsStreamOverCap(t *testing.T) {
	startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write([]byte(strings.Repeat("a", 512)))
		w.(http.Flusher).Flush()
		time.Sleep(100 * time.Millisecond)
		_, _ = w.Write([]byte(strings.Repeat("b", 4096)))
	})
	_, base := serveProxyFlow(t, proxyFlow("GET", "/api/audio", "url: http://"+proxyTestHost+"/stream.mp3", "content_types: [audio/mpeg]", "max_bytes: 1KB"))
	resp, err := http.Get(base + "/api/audio")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, readErr := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 || readErr == nil || string(body) != strings.Repeat("a", 512) {
		t.Fatalf("over-cap stream: status %d, read error %v, %d bytes", resp.StatusCode, readErr, len(body))
	}
}

// Nothing of the caller's reaches the upstream but the author's headers,
// and nothing of the upstream's reaches the caller but allow-listed ones.
func TestProxyHeaderIsolation(t *testing.T) {
	upstream := startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Type", "image/webp")
		h.Set("Set-Cookie", "upstream_session=leak; Path=/")
		h.Set("Access-Control-Allow-Origin", "*")
		h.Set("Content-Security-Policy", "script-src *")
		h.Set("Location", "https://evil.example/")
		h.Set("Link", "<https://evil.example/x.js>; rel=preload")
		h.Set("X-Upstream-Internal", "secret")
		h.Set("Last-Modified", "Wed, 21 Oct 2015 07:28:00 GMT")
		_, _ = w.Write([]byte("RIFFwebp"))
	})
	app, base := serveProxyFlow(t, proxyFlow("GET", "/api/img", "url: http://"+proxyTestHost+"/i.webp", "content_types: [image/webp]", `auth: "Bearer ${{ env.UPSTREAM_TOKEN }}"`))
	SetAppEnv(app.Dir, "UPSTREAM_TOKEN", "author-token")
	req, _ := http.NewRequest("GET", base+"/api/img", nil)
	req.Header.Set("Cookie", "caller_cookie=private; benmore_other=x")
	req.Header.Set("Authorization", "Bearer caller-token")
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	req.Header.Set("Referer", "https://app.example/secret-page?token=t")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	for _, name := range []string{"Set-Cookie", "Access-Control-Allow-Origin", "Location", "Link", "X-Upstream-Internal"} {
		if v := resp.Header.Get(name); v != "" {
			t.Errorf("upstream %s reached the caller: %q", name, v)
		}
	}
	if resp.Header.Get("Content-Security-Policy") != "default-src 'none'; sandbox" || resp.Header.Get("Last-Modified") != "Wed, 21 Oct 2015 07:28:00 GMT" {
		t.Errorf("headers = %v", resp.Header)
	}
	sent, _ := upstream.last(t)
	if sent.Header.Get("Cookie") != "" || sent.Header.Get("Referer") != "" || sent.Header.Get("X-Forwarded-For") != "" || sent.Header.Get("Authorization") != "Bearer author-token" {
		t.Fatalf("upstream got the caller's headers: %v", sent.Header)
	}
}

// PDF, CSV and ZIP are attachments whatever the step says; the download
// name is cut to a safe base name and a CSV keeps only a safe charset.
func TestProxyCSVForcedAttachment(t *testing.T) {
	startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", `text/csv; charset=UTF-8; header="present"`)
		_, _ = w.Write([]byte("a,b\n1,2\n"))
	})
	_, base := serveProxyFlow(t, proxyFlow("GET", "/api/report",
		"url: http://"+proxyTestHost+"/report.csv",
		"content_types: [text/csv]",
		"disposition: inline",
		`filename: "${{ params.name }}.csv"`,
	))
	resp, body := mustGet(t, base+"/api/report?name=..%2F..%2Fetc%2Fpass%22wd")
	if resp.StatusCode != 200 || body != "a,b\n1,2\n" {
		t.Fatalf("answer %d %q", resp.StatusCode, body)
	}
	if got := resp.Header.Get("Content-Disposition"); got != "attachment; filename=pass_wd.csv" {
		t.Errorf("Content-Disposition = %q", got)
	}
	if got := resp.Header.Get("Content-Type"); got != "text/csv; charset=utf-8" {
		t.Errorf("Content-Type = %q", got)
	}
	if resp.Header.Get("X-Content-Type-Options") != "nosniff" || resp.Header.Get("Content-Security-Policy") != "default-src 'none'; sandbox" {
		t.Errorf("protective headers missing: %v", resp.Header)
	}
}

// An upstream error status is not streamed: the step fails, and the flow's
// own error handling answers (here an on_error respond).
func TestProxyUpstreamErrorStatusFailsStep(t *testing.T) {
	upstream := startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.WriteHeader(http.StatusBadGateway)
		_, _ = w.Write([]byte("UPSTREAM-ERROR-PAGE"))
	})
	app, cleanup := newTestApp(t)
	defer cleanup()
	rr := httptest.NewRecorder()
	ctx := proxyStepCtx(app, rr, httptest.NewRequest("GET", "/api/p", nil))
	executeSteps(ctx, []FlowStep{proxyStep("http://"+proxyTestHost+"/x.png", "image/png")})
	if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "proxy upstream answered 502") || rr.Body.Len() != 0 || ctx.Stopped {
		t.Fatalf("err=%v body=%q stopped=%v", ctx.Error, rr.Body.String(), ctx.Stopped)
	}

	_, base := serveProxyFlow(t, "on:\n  request:\n    method: GET\n    path: /api/p\n    rate_limit: 1000/min\njobs:\n  p:\n    steps:\n      - run: proxy\n        with:\n          url: http://"+proxyTestHost+"/x.png\n          content_types: [image/png]\n        on_error:\n          - run: respond\n            with: { status: 503, json: { error: upstream_unavailable } }\n")
	resp, body := mustGet(t, base+"/api/p")
	if resp.StatusCode != 503 || !strings.Contains(body, "upstream_unavailable") || strings.Contains(body, "UPSTREAM-ERROR-PAGE") || upstream.count() != 2 {
		t.Fatalf("handled failure: %d %q (upstream calls %d)", resp.StatusCode, body, upstream.count())
	}
}

// A proxy step answers a live caller only.
func TestProxyRefusedWithoutLiveCaller(t *testing.T) {
	const step = "      - run: proxy\n        with:\n          url: https://api.example.com/f.png\n          content_types: [image/png]\n"
	const nested = "          - run: proxy\n            with:\n              url: https://api.example.com/f.png\n              content_types: [image/png]\n"
	const request = "on:\n  request:\n    method: GET\n    path: /api/p\n    rate_limit: 1000/min\n"
	for name, source := range map[string]string{
		"async":       "on:\n  request:\n    method: GET\n    path: /api/p\n    rate_limit: 1000/min\n    mode: async\njobs:\n  p:\n    steps:\n" + step,
		"schedule":    "on:\n  schedule:\n    cron: every 5m\njobs:\n  p:\n    steps:\n" + step,
		"event":       "on:\n  event:\n    table: notes\n    op: insert\njobs:\n  p:\n    steps:\n" + step,
		"on_error":    request + "jobs:\n  p:\n    steps:\n      - query: SELECT 1\n        on_error:\n" + nested + "      - run: respond\n        with: { status: 200 }\n",
		"parallel":    request + "jobs:\n  p:\n    steps:\n      - run: parallel\n        steps:\n" + nested,
		"transaction": "on:\n  request:\n    method: GET\n    path: /api/p\n    rate_limit: 1000/min\n    transaction: true\njobs:\n  p:\n    steps:\n" + step,
	} {
		if msg := ValidateOnWrite("flows/p.yaml", source); !strings.Contains(msg, "proxy") {
			t.Errorf("%s: write gate said %q", name, msg)
		}
	}

	upstream := startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("png"))
	})
	app, cleanup := newTestApp(t)
	defer cleanup()
	url := "http://" + proxyTestHost + "/x.png"
	// A job worker or scheduler context: no live caller.
	worker := &FlowContext{App: app, Data: map[string]any{}, Params: map[string]string{}}
	executeSteps(worker, []FlowStep{proxyStep(url, "image/png")})
	// An on_error handler of a live request.
	rr := httptest.NewRecorder()
	live := proxyStepCtx(app, rr, httptest.NewRequest("GET", "/api/p", nil))
	failing := FlowStep{Name: "q", Type: "sql", SQL: "SELECT nope FROM missing_table", OnError: []FlowStep{proxyStep(url, "image/png")}}
	executeSteps(live, []FlowStep{failing})
	// A transaction.
	tx, err := app.DB.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback()
	inTx := proxyStepCtx(app, httptest.NewRecorder(), httptest.NewRequest("GET", "/api/p", nil))
	inTx.Tx = tx
	executeSteps(inTx, []FlowStep{proxyStep(url, "image/png")})
	if worker.Error == nil || !strings.Contains(worker.Error.Error(), "synchronous request flow") || rr.Body.Len() != 0 || inTx.Error == nil || !strings.Contains(inTx.Error.Error(), "transaction") || upstream.count() != 0 {
		t.Fatalf("worker=%v handler body=%q tx=%v upstream=%d", worker.Error, rr.Body.String(), inTx.Error, upstream.count())
	}
}

// The step's timeout and the flow's time limit both end the call.
func TestProxyTimeoutRespected(t *testing.T) {
	startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-time.After(3 * time.Second):
		}
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("png"))
	})
	app, cleanup := newTestApp(t)
	defer cleanup()
	url := "http://" + proxyTestHost + "/slow.png"

	step := proxyStep(url, "image/png")
	step.Timeout = 200 * time.Millisecond
	ctx := proxyStepCtx(app, httptest.NewRecorder(), httptest.NewRequest("GET", "/api/p", nil))
	started := time.Now()
	executeSteps(ctx, []FlowStep{step})
	if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "deadline exceeded") || time.Since(started) > 2*time.Second {
		t.Fatalf("step timeout: err=%v after %s", ctx.Error, time.Since(started))
	}

	ctx = proxyStepCtx(app, httptest.NewRecorder(), httptest.NewRequest("GET", "/api/p", nil))
	execCtx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	ctx.execCtx, ctx.timeLimit = execCtx, 300*time.Millisecond
	started = time.Now()
	executeSteps(ctx, []FlowStep{proxyStep(url, "image/png")})
	if ctx.Error == nil || time.Since(started) > 2*time.Second || !flowStoppedByTimeLimit(ctx) {
		t.Fatalf("flow time limit: err=%v after %s", ctx.Error, time.Since(started))
	}
}

// Redirects stay on the URL's own origin and are never followed for POST.
func TestProxyRefusesCrossHostRedirect(t *testing.T) {
	var mu sync.Mutex
	hits := map[string]int{}
	startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits[r.URL.Path]++
		mu.Unlock()
		switch r.URL.Path {
		case "/elsewhere":
			http.Redirect(w, r, "http://93.184.216.35/final", http.StatusFound)
		case "/same":
			http.Redirect(w, r, "/final", http.StatusFound)
		case "/post":
			http.Redirect(w, r, "/final", http.StatusTemporaryRedirect)
		default:
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte("final"))
		}
	})
	app, cleanup := newTestApp(t)
	defer cleanup()
	final := func() int {
		mu.Lock()
		defer mu.Unlock()
		return hits["/final"]
	}
	run := func(path, method string) (*FlowContext, *httptest.ResponseRecorder) {
		step := proxyStep("http://"+proxyTestHost+path, "image/png")
		step.Proxy.Request.Method = method
		if method == "POST" {
			step.Proxy.Request.Body = "{}"
		}
		rr := httptest.NewRecorder()
		ctx := proxyStepCtx(app, rr, httptest.NewRequest(method, "/api/p", nil))
		executeSteps(ctx, []FlowStep{step})
		return ctx, rr
	}
	if ctx, rr := run("/elsewhere", "GET"); ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "another host") || rr.Body.Len() != 0 || final() != 0 {
		t.Fatalf("cross-host redirect: err=%v body=%q final=%d", ctx.Error, rr.Body.String(), final())
	}
	if ctx, rr := run("/post", "POST"); ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "only for GET") || rr.Body.Len() != 0 || final() != 0 {
		t.Fatalf("POST redirect: err=%v body=%q final=%d", ctx.Error, rr.Body.String(), final())
	}
	if ctx, rr := run("/same", "GET"); ctx.Error != nil || rr.Body.String() != "final" || final() != 1 {
		t.Fatalf("same-origin redirect: err=%v body=%q", ctx.Error, rr.Body.String())
	}
}

// The write gate and `benmore check` refuse a proxy step's keys and values
// it does not take.
func TestProxyWriteGateAndCheckRefuseBadValues(t *testing.T) {
	const url = "url: https://api.example.com/f"
	for name, lines := range map[string][]string{
		"unknown key":      {url, "content_types: [image/png]", "sign: { recipe: bearer_token }"},
		"query key":        {url, "content_types: [image/png]", "query: { a: b }"},
		"method PUT":       {url, "content_types: [image/png]", "method: PUT"},
		"templated method": {url, "content_types: [image/png]", "method: ${{ params.m }}"},
		"max over ceiling": {url, "content_types: [image/png]", "max_bytes: 200MB"},
		"max unparsable":   {url, "content_types: [image/png]", "max_bytes: lots"},
		"timeout too long": {url, "content_types: [image/png]", "timeout: 500s"},
		"timeout garbage":  {url, "content_types: [image/png]", "timeout: soon"},
		"accept-encoding":  {url, "content_types: [image/png]", "headers: { Accept-Encoding: gzip }"},
		"range header":     {url, "content_types: [image/png]", "headers: { Range: bytes=0-10 }"},
		"method override":  {url, "content_types: [image/png]", "method: POST", "body: x", `headers: { X-HTTP-Method-Override: "${{ params.m }}" }`},
		"GET with body":    {url, "content_types: [image/png]", "json: { a: 1 }"},
		"two bodies":       {url, "content_types: [image/png]", "method: POST", "body: x", "json: { a: 1 }"},
		"disposition":      {url, "content_types: [image/png]", "disposition: ${{ params.d }}"},
		"filename":         {url, "content_types: [image/png]", `filename: "../etc/passwd"`},
		"no url":           {"content_types: [image/png]"},
	} {
		source := proxyFlow("POST", "/api/p", lines...)
		if msg := ValidateOnWrite("flows/p.yaml", source); msg == "" {
			t.Errorf("%s: write gate accepted it", name)
		}
		if name != "unknown key" {
			continue
		}
		// `benmore check` runs the same dispatcher over the app's files.
		dir := t.TempDir()
		if err := os.MkdirAll(filepath.Join(dir, "flows"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "flows", "p.yaml"), []byte(source), 0o644); err != nil {
			t.Fatal(err)
		}
		report := RunSourceCheck(dir, "")
		found := false
		for _, f := range report.Findings {
			found = found || f.Severity == "error" && strings.Contains(f.Message, "sign")
		}
		if !found {
			t.Errorf("benmore check did not refuse the proxy step: %+v", report.Findings)
		}
	}
	if msg := ValidateOnWrite("flows/p.yaml", proxyFlow("POST", "/api/p", url, "method: post", "content_types: [application/pdf]", "max_bytes: 100MB", "timeout: 45s", "disposition: attachment", "filename: invoice-2026.pdf", `auth: "Bearer ${{ env.KEY }}"`, `body: '{"id": ${{ params.id }}}'`)); msg != "" {
		t.Fatalf("a valid step was refused: %s", msg)
	}
}

// The answer's Cache-Control is the step's literal `cache_control:`, else
// `private, no-store`; a private answer never takes a shared value, and a
// value that does not parse is never sent.
func TestProxyCacheControl(t *testing.T) {
	for _, tc := range []struct {
		authored string
		private  bool
		want     string
	}{
		{"", false, "private, no-store"},
		{"", true, "private, no-store"},
		{"public, max-age=600", false, "public, max-age=600"},
		{"public, max-age=600", true, "private, no-store"},
		{"max-age=60", true, "private, no-store"}, // no private: a shared cache may keep it
		{"Private, Max-Age=300", true, "private, max-age=300"},
		{"no-store", false, "no-store"},
		{`private="Set-Cookie"`, false, "private, no-store"},
		{"max-age=60, x-evil", false, "private, no-store"},
		{"public, s-maxage=31536000, immutable", false, "public, s-maxage=31536000, immutable"},
		{"{{cc}}", false, "private, no-store"},
	} {
		if got := proxyCacheControl(tc.authored, tc.private); got != tc.want {
			t.Errorf("proxyCacheControl(%q, %v) = %q, want %q", tc.authored, tc.private, got, tc.want)
		}
	}
}

// proxyBehindRouter serves the flow (plus a slow /warm route) behind
// recoverMiddleware on a real server, fronted by an httputil.ReverseProxy
// with a keep-alive transport like the router's (router.go). frontErrors
// counts the front proxy's ErrorHandler calls (outcome_unknown in
// production).
func proxyBehindRouter(t *testing.T, source string, setup func(*App)) (front string, frontErrors func() int) {
	t.Helper()
	if msg := ValidateOnWrite("flows/p.yaml", source); msg != "" {
		t.Fatalf("write gate refused the flow: %s", msg)
	}
	app, cleanup := newTestApp(t)
	t.Cleanup(cleanup)
	if setup != nil {
		setup(app)
	}
	flows, err := parseGHAFlowFile("flows/p.yaml", []byte(source))
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	RegisterFlows(mux, app, flows)
	mux.HandleFunc("/warm", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(150 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	})
	appSrv := httptest.NewServer(recoverMiddleware(mux))
	t.Cleanup(appSrv.Close)
	target, _ := url.Parse(appSrv.URL)
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.Transport = &http.Transport{MaxIdleConnsPerHost: 8}
	var mu sync.Mutex
	n := 0
	rp.ErrorHandler = func(w http.ResponseWriter, r *http.Request, err error) {
		mu.Lock()
		n++
		mu.Unlock()
		w.WriteHeader(http.StatusBadGateway)
	}
	frontSrv := httptest.NewServer(recoverMiddleware(rp))
	t.Cleanup(frontSrv.Close)
	// Several idle keep-alive connections between the front and the app:
	// the transport retries a replayable GET on another one when a reused
	// connection closes with no answer.
	var wg sync.WaitGroup
	for range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(frontSrv.URL + "/warm")
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}()
	}
	wg.Wait()
	return frontSrv.URL, func() int {
		mu.Lock()
		defer mu.Unlock()
		return n
	}
}

// proxyPlaysFlow is a public GET flow that records a play, then proxies.
func proxyPlaysFlow(with ...string) string {
	return "on:\n  request:\n    method: GET\n    path: /api/tts\n    rate_limit: 1000/min\njobs:\n  p:\n    steps:\n" +
		"      - run: sql\n        with:\n          query: INSERT INTO plays (n) VALUES ('x')\n" +
		"      - run: proxy\n        with:\n          " + strings.Join(with, "\n          ") + "\n"
}

func proxyPlaysTable(t *testing.T) (func(*App), func() int) {
	var app *App
	return func(a *App) {
			app = a
			mustExec(t, a.DB, "CREATE TABLE plays (id INTEGER PRIMARY KEY AUTOINCREMENT, n TEXT)")
		}, func() int {
			var n int
			if err := app.DB.QueryRow("SELECT COUNT(*) FROM plays").Scan(&n); err != nil {
				t.Fatal(err)
			}
			return n
		}
}

// A stream that fails before its first byte (the upstream sends its headers
// and dies, or stalls past the step's timeout) fails the step with nothing
// written, so the flow answers its normal error. It used to write the status
// and abort with no byte on the wire, and the router's keep-alive transport
// replayed the GET on another connection: one client request ran the flow
// (its INSERT and the upstream call) once per idle connection.
func TestProxyNoReplayWhenStreamFailsBeforeFirstByte(t *testing.T) {
	for name, tc := range map[string]struct {
		upstream http.HandlerFunc
		timeout  string
	}{
		"upstream dies after headers": {upstream: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "audio/mpeg")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			panic(http.ErrAbortHandler)
		}},
		"upstream stalls after headers": {timeout: "timeout: 1s", upstream: func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "audio/mpeg")
			w.WriteHeader(200)
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-time.After(5 * time.Second):
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			upstream := startProxyUpstream(t, tc.upstream)
			with := []string{"url: http://" + proxyTestHost + "/v1/tts", "content_types: [audio/mpeg]"}
			if tc.timeout != "" {
				with = append(with, tc.timeout)
			}
			setup, plays := proxyPlaysTable(t)
			front, frontErrors := proxyBehindRouter(t, proxyPlaysFlow(with...), setup)
			resp, body := mustGet(t, front+"/api/tts")
			if resp.StatusCode != http.StatusInternalServerError || !strings.Contains(body, "flow") || strings.Contains(resp.Header.Get("Content-Type"), "audio") {
				t.Fatalf("answer %d %s %q: want the flow's normal error answer", resp.StatusCode, resp.Header.Get("Content-Type"), body)
			}
			if upstream.count() != 1 || plays() != 1 || frontErrors() != 0 {
				t.Fatalf("one client GET -> upstream calls %d, flow INSERTs %d, front proxy errors %d; want 1, 1, 0", upstream.count(), plays(), frontErrors())
			}
		})
	}
}

// A stream that fails after its first byte aborts the response: the status
// and the first bytes were flushed, so the front proxy passes the abort on
// (the client's read fails) and never replays the request.
func TestProxyAbortMidBodyIsNotReplayed(t *testing.T) {
	upstream := startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write([]byte(strings.Repeat("a", 100)))
		w.(http.Flusher).Flush()
		time.Sleep(50 * time.Millisecond)
		panic(http.ErrAbortHandler)
	})
	setup, plays := proxyPlaysTable(t)
	front, frontErrors := proxyBehindRouter(t, proxyPlaysFlow("url: http://"+proxyTestHost+"/v1/tts", "content_types: [audio/mpeg]"), setup)
	resp, err := http.Get(front + "/api/tts")
	if err != nil {
		t.Fatal(err)
	}
	body, readErr := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != 200 || readErr == nil || string(body) != strings.Repeat("a", 100) {
		t.Fatalf("status %d, read error %v, %d bytes: want 200, the first 100 bytes and a failed read", resp.StatusCode, readErr, len(body))
	}
	if upstream.count() != 1 || plays() != 1 || frontErrors() != 0 {
		t.Fatalf("upstream calls %d, flow INSERTs %d, front proxy errors %d; want 1, 1, 0", upstream.count(), plays(), frontErrors())
	}
}

// A first chunk over max_bytes, with no declared length, is refused before
// anything is written: the flow's normal error, not an abort.
func TestProxyRefusesFirstChunkOverCap(t *testing.T) {
	startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.(http.Flusher).Flush() // chunked: no Content-Length
		_, _ = w.Write([]byte(strings.Repeat("P", 2048)))
	})
	_, base := serveProxyFlow(t, proxyFlow("GET", "/api/img", "url: http://"+proxyTestHost+"/big.png", "content_types: [image/png]", "max_bytes: 1KB"))
	resp, body := mustGet(t, base+"/api/img")
	if resp.StatusCode != 500 || strings.Contains(body, "PPPP") || !strings.Contains(body, "flow") {
		t.Fatalf("first chunk over cap: %d %q", resp.StatusCode, body)
	}
}

// The download name's extension is the served type's: request input can
// name the file but not make it a .bat, .html or .svg. Shared caching is off
// unless the step opts in, whatever the upstream says.
func TestProxyDownloadNameFollowsServedType(t *testing.T) {
	startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Cache-Control", "public, s-maxage=31536000, max-age=31536000, immutable")
		w.Header().Set("Expires", "Thu, 01 Jan 2037 00:00:00 GMT")
		_, _ = w.Write([]byte("name\r\ncalc.exe\r\n"))
	})
	_, base := serveProxyFlow(t, proxyFlow("GET", "/api/export",
		"url: http://"+proxyTestHost+"/export?token=${{ params.token }}",
		"content_types: [text/csv]",
		"disposition: attachment",
		`filename: "${{ params.name }}"`,
	))
	for name, want := range map[string]string{
		"report.bat":   "attachment; filename=report.csv",
		"invoice.html": "attachment; filename=invoice.csv",
		"x.svg":        "attachment; filename=x.csv",
		"setup.cmd":    "attachment; filename=setup.csv",
		"export.CSV":   "attachment; filename=export.CSV",
		"notes":        "attachment; filename=notes.csv",
	} {
		resp, _ := mustGet(t, base+"/api/export?token=share-123&name="+url.QueryEscape(name))
		if got := resp.Header.Get("Content-Disposition"); resp.StatusCode != 200 || got != want {
			t.Errorf("name=%s: %d Content-Disposition %q, want %q", name, resp.StatusCode, got, want)
		}
		if cc := resp.Header.Get("Cache-Control"); cc != "private, no-store" || resp.Header.Get("Expires") != "" {
			t.Errorf("name=%s: Cache-Control %q Expires %q: the upstream's shared lifetime reached the caller", name, cc, resp.Header.Get("Expires"))
		}
	}
	for _, tc := range []struct{ name, mediaType, want string }{
		{"speech.mp3", "audio/mpeg", "speech.mp3"},
		{"speech.wav", "audio/mpeg", "speech.mp3"},
		{"photo.JPEG", "image/jpeg", "photo.JPEG"},
		{"v1.2 report", "text/csv", "v1.2 report.csv"},
		{"x.tar.gz", "application/zip", "x.tar.zip"},
		{"../../evil.html", "application/pdf", "evil.pdf"},
		{".bat", "application/pdf", "bat.pdf"},
		{"", "application/pdf", ""},
		{"a.png", "application/x-unknown", ""},
		{strings.Repeat("n", 200) + ".bat", "text/csv", strings.Repeat("n", 124) + ".csv"},
	} {
		if got := proxyDownloadName(tc.name, tc.mediaType); got != tc.want {
			t.Errorf("proxyDownloadName(%q, %q) = %q, want %q", tc.name, tc.mediaType, got, tc.want)
		}
	}
	for mediaType := range proxyContentTypes {
		if len(proxyTypeExtensions[mediaType]) == 0 {
			t.Errorf("allow-listed type %s has no download extension", mediaType)
		}
	}
}

// `cache_control:` is the only way a proxied answer becomes cacheable. A
// value a shared cache may store is accepted only on an `auth: none` flow,
// written literally; a flow that checks the caller may declare only a
// private form. The loader drops a shared value from such a flow.
func TestProxyCacheControlOptIn(t *testing.T) {
	const url = "url: https://api.example.com/f"
	flow := func(auth, cacheControl string) string {
		return "on:\n  request:\n    method: GET\n    path: /api/p\n    rate_limit: 100/min\n" + auth +
			"jobs:\n  p:\n    steps:\n      - run: proxy\n        with:\n          " + url +
			"\n          content_types: [image/png]\n          cache_control: " + cacheControl + "\n"
	}
	for _, tc := range []struct {
		auth, cacheControl string
		ok                 bool
	}{
		{"    auth: none\n", `"public, max-age=300"`, true},
		{"", `"public, s-maxage=600, stale-if-error=60"`, true},
		{"    auth: none\n", `"max-age=60"`, true},
		{"    auth: required\n", `"private, max-age=300"`, true},
		{"    auth: required\n", `"no-store"`, true},
		{"    auth: required\n", `"public, max-age=300"`, false},
		{"    auth: required\n", `"max-age=300"`, false},
		{"    auth: optional\n", `"public, max-age=300"`, false},
		{"    role: editor\n", `"s-maxage=300"`, false},
		{"    auth: none\n", `"public, max-age=${{ params.ttl }}"`, false},
		{"    auth: none\n", `"max-age=lots"`, false},
		{"    auth: none\n", `"public, private"`, false},
		{"    auth: none\n", `'private="Set-Cookie"'`, false},
		{"    auth: none\n", `"public, x-evil"`, false},
		{"    auth: none\n", `[public]`, false},
	} {
		msg := ValidateOnWrite("flows/p.yaml", flow(tc.auth, tc.cacheControl))
		if (msg == "") != tc.ok {
			t.Errorf("%q cache_control %s: write gate said %q, want accepted=%v", tc.auth, tc.cacheControl, msg, tc.ok)
		}
	}

	startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		_, _ = w.Write([]byte("png"))
	})
	_, base := serveProxyFlow(t, proxyFlow("GET", "/api/img", "url: http://"+proxyTestHost+"/i.png", "content_types: [image/png]", `cache_control: "public, max-age=300"`))
	if resp, _ := mustGet(t, base+"/api/img"); resp.Header.Get("Cache-Control") != "public, max-age=300" {
		t.Fatalf("opted-in anonymous answer: Cache-Control %q", resp.Header.Get("Cache-Control"))
	}

	steps := []FlowStep{
		{Type: "proxy", Proxy: &FlowProxy{CacheControl: "public, max-age=60"}},
		{Type: "proxy", Proxy: &FlowProxy{CacheControl: "private, max-age=60"}},
	}
	dropSharedCacheControl(steps)
	if steps[0].Proxy.CacheControl != "" || steps[1].Proxy.CacheControl != "private, max-age=60" {
		t.Fatalf("loader drop: %q %q", steps[0].Proxy.CacheControl, steps[1].Proxy.CacheControl)
	}
}

// An upstream POST needs a flow the CSRF check covers: refused in a GET
// flow when written and when run, so a cross-site link cannot trigger it.
func TestProxyUpstreamPostNeedsNonGetFlow(t *testing.T) {
	const url = "url: https://api.example.com/f"
	if msg := ValidateOnWrite("flows/p.yaml", proxyFlow("GET", "/api/p", url, "method: POST", "json: { a: 1 }", "content_types: [audio/mpeg]")); !strings.Contains(msg, "CSRF") {
		t.Fatalf("GET flow with an upstream POST: write gate said %q", msg)
	}
	for _, method := range []string{"POST", "PUT", "PATCH", "DELETE"} {
		if msg := ValidateOnWrite("flows/p.yaml", proxyFlow(method, "/api/p", url, "method: POST", "json: { a: 1 }", "content_types: [audio/mpeg]")); msg != "" {
			t.Errorf("%s flow with an upstream POST refused: %s", method, msg)
		}
	}
	upstream := startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "audio/mpeg")
		_, _ = w.Write([]byte("ID3"))
	})
	app, cleanup := newTestApp(t)
	defer cleanup()
	step := proxyStep("http://"+proxyTestHost+"/v1/tts", "audio/mpeg")
	step.Proxy.Request.Method, step.Proxy.Request.Body = "POST", "{}"
	for _, method := range []string{"GET", "HEAD"} {
		rr := httptest.NewRecorder()
		ctx := proxyStepCtx(app, rr, httptest.NewRequest(method, "/api/p", nil))
		executeSteps(ctx, []FlowStep{step})
		if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "CSRF") || rr.Body.Len() != 0 || upstream.count() != 0 {
			t.Fatalf("%s request: err=%v body=%q upstream=%d", method, ctx.Error, rr.Body.String(), upstream.count())
		}
	}
	rr := httptest.NewRecorder()
	ctx := proxyStepCtx(app, rr, httptest.NewRequest("POST", "/api/p", nil))
	executeSteps(ctx, []FlowStep{step})
	if ctx.Error != nil || rr.Body.String() != "ID3" || upstream.count() != 1 {
		t.Fatalf("POST request: err=%v body=%q upstream=%d", ctx.Error, rr.Body.String(), upstream.count())
	}
}

// A flow anonymous callers can run must declare a rate_limit before it may
// proxy: otherwise it is an open bandwidth relay to the author's upstream.
func TestProxyAnonymousFlowNeedsRateLimit(t *testing.T) {
	flow := func(request string) string {
		return "on:\n  request:\n    method: GET\n    path: /api/p\n" + request +
			"jobs:\n  p:\n    steps:\n      - run: proxy\n        with:\n          url: https://api.example.com/f.png\n          content_types: [image/png]\n"
	}
	for request, ok := range map[string]bool{
		"":                     false,
		"    auth: none\n":     false,
		"    auth: public\n":   false,
		"    auth: optional\n": false,
		"    auth: none\n    rate_limit: 30/minute per ip\n": true,
		"    auth: required\n":                               true,
		"    role: editor\n":                                 true,
		"    permissions: [files:read]\n":                    true,
	} {
		msg := ValidateOnWrite("flows/p.yaml", flow(request))
		if (msg == "") != ok || !ok && !strings.Contains(msg, "rate_limit") {
			t.Errorf("%q: write gate said %q, want accepted=%v", request, msg, ok)
		}
	}
	// `benmore check` runs the same dispatcher over the app's files.
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "flows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "flows", "p.yaml"), []byte(flow("    auth: none\n")), 0o644); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range RunSourceCheck(dir, "").Findings {
		found = found || f.Severity == "error" && strings.Contains(f.Message, "rate_limit")
	}
	if !found {
		t.Error("benmore check did not refuse the unlimited anonymous proxy flow")
	}
}
