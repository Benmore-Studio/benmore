//go:build !cli

package main

// `run: proxy` path values, numeric private hosts and messages (round
// 2026-11-04 media findings 3, 10 and 11).

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// proxyDocsFlow is a public, rate-limited GET flow that reads one stored
// remote_slug with query and proxies the image it names.
func proxyDocsFlow(path, query string, with ...string) string {
	extra := ""
	for _, line := range with {
		extra += "          " + line + "\n"
	}
	return "on:\n  request:\n    method: GET\n    path: " + path + "\n    rate_limit: 1000/min\njobs:\n  p:\n    steps:\n" +
		"      - id: doc\n        run: sql\n        with:\n          query: \"" + query + "\"\n" +
		"      - run: proxy\n        with:\n          url: http://" + proxyTestHost + "/image/${{ steps.doc.outputs.rows[0].remote_slug }}\n" +
		"          content_types: [image/png]\n" + extra
}

func proxyPNGUpstream(t *testing.T) *proxyUpstream {
	t.Helper()
	return startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "image/png")
		_, _ = w.Write([]byte("\x89PNG"))
	})
}

// proxyFlowDiag GETs url and reads the answer: the body, and the
// flow_no_response diagnostic when the flow failed.
func proxyFlowDiag(t *testing.T, url string) (int, string, map[string]any) {
	t.Helper()
	resp, body := mustGet(t, url)
	var diag map[string]any
	if resp.StatusCode != 200 {
		_ = json.Unmarshal([]byte(body), &diag)
	}
	return resp.StatusCode, body, diag
}

// A value the user wrote earlier (auto-CRUD) and a SQL step read back
// without request input is not request-tainted, and it went out as
// `/image/..%2Fbytes%2F64`: an upstream that decodes %2F and normalizes
// serves another endpoint with the author's credentials. Every value the
// author did not write is now one plain path segment.
func TestProxyStoredPathValueIsOnePlainSegment(t *testing.T) {
	upstream := proxyPNGUpstream(t)
	app, base := serveProxyFlow(t, proxyDocsFlow("/api/latest-cover", "SELECT remote_slug FROM documents ORDER BY id DESC LIMIT 1"))
	mustExec(t, app.DB, "CREATE TABLE documents (id INTEGER PRIMARY KEY, remote_slug TEXT)")
	mustExec(t, app.DB, "INSERT INTO documents (remote_slug) VALUES ('png')")

	set := func(v string) {
		t.Helper()
		if _, err := app.DB.Exec("UPDATE documents SET remote_slug = ?", v); err != nil {
			t.Fatal(err)
		}
	}
	if status, body, _ := proxyFlowDiag(t, base+"/api/latest-cover"); status != 200 || body != "\x89PNG" {
		t.Fatalf("plain stored value: %d %q", status, body)
	}
	if req, _ := upstream.last(t); req.RequestURI != "/image/png" {
		t.Fatalf("upstream URI = %q", req.RequestURI)
	}
	set("a b?c#d")
	if status, _, _ := proxyFlowDiag(t, base+"/api/latest-cover"); status != 200 {
		t.Fatalf("stored value with reserved characters: %d", status)
	}
	if req, _ := upstream.last(t); req.RequestURI != "/image/a%20b%3Fc%23d" {
		t.Fatalf("stored value left its segment: %q", req.RequestURI)
	}
	calls := upstream.count()
	for _, stored := range []string{"../bytes/64", "bytes/64", "..%2Fbytes%2F64", "..%252Fbytes", `a\b`, "a%5Cb", "..", ".", "%2e%2e", "users/42/a.png"} {
		set(stored)
		status, body, diag := proxyFlowDiag(t, base+"/api/latest-cover")
		if status != 500 || upstream.count() != calls || strings.Contains(body, "PNG") {
			t.Fatalf("stored %q: %d %s (upstream calls %d, want %d)", stored, status, body, upstream.count(), calls)
		}
		if diag["failed_type"] != "proxy" || diag["reason"] != "the outbound URL was refused" {
			t.Fatalf("stored %q: diagnostic %v", stored, diag)
		}
	}

	// The step's own error names the value and the opt-in.
	rr := httptest.NewRecorder()
	ctx := proxyStepCtx(app, rr, httptest.NewRequest("GET", "/api/x", nil))
	ctx.Data["key"] = "users/42/a.png"
	executeSteps(ctx, []FlowStep{proxyStep("http://"+proxyTestHost+"/images/{{key}}", "image/png")})
	if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "one path segment only") || !strings.Contains(ctx.Error.Error(), "path_slashes") || rr.Body.Len() != 0 || upstream.count() != calls {
		t.Fatalf("stored key: err=%v body=%q upstream=%d", ctx.Error, rr.Body.String(), upstream.count())
	}
	// Literal text and env values are the author's and stay as written.
	SetAppEnv(app.Dir, "IMAGE_PREFIX", "v2/images")
	ctx = proxyStepCtx(app, httptest.NewRecorder(), httptest.NewRequest("GET", "/api/x", nil))
	executeSteps(ctx, []FlowStep{proxyStep("http://"+proxyTestHost+"/{{env.IMAGE_PREFIX}}/a/c.png", "image/png")})
	if req, _ := upstream.last(t); ctx.Error != nil || req.RequestURI != "/v2/images/a/c.png" {
		t.Fatalf("authored values: err=%v uri=%q", ctx.Error, req.RequestURI)
	}
}

// `path_slashes: true` lets a value from a data step (a stored file key,
// also one read by a request id) span path segments, each escaped; an empty
// or dot segment, a backslash and an encoded slash or backslash are still
// refused, and request text stays one plain segment.
func TestProxyPathSlashesOptIn(t *testing.T) {
	upstream := proxyPNGUpstream(t)
	app, base := serveProxyFlow(t, proxyDocsFlow("/api/latest-cover", "SELECT remote_slug FROM documents ORDER BY id DESC LIMIT 1", "path_slashes: true"))
	mustExec(t, app.DB, "CREATE TABLE documents (id INTEGER PRIMARY KEY, remote_slug TEXT)")
	mustExec(t, app.DB, "INSERT INTO documents (remote_slug) VALUES ('users/42/a.png')")
	set := func(v string) {
		t.Helper()
		if _, err := app.DB.Exec("UPDATE documents SET remote_slug = ?", v); err != nil {
			t.Fatal(err)
		}
	}
	for stored, uri := range map[string]string{
		"users/42/a.png":   "/image/users/42/a.png",
		"users/4 2/a?.png": "/image/users/4%202/a%3F.png",
		"png":              "/image/png",
	} {
		set(stored)
		if status, body, _ := proxyFlowDiag(t, base+"/api/latest-cover"); status != 200 || body != "\x89PNG" {
			t.Fatalf("stored %q: %d %q", stored, status, body)
		}
		if req, _ := upstream.last(t); req.RequestURI != uri {
			t.Fatalf("stored %q went out as %q, want %q", stored, req.RequestURI, uri)
		}
	}
	calls := upstream.count()
	for _, stored := range []string{
		"../bytes/64", "users/../x", "users/./x", "users/..", "users//x", "/users/x", "users/x/",
		`users\x`, "users/%2e%2e/x", "users/a%2Fb", "users/a%252Fb", "users/a%5cb", "..",
	} {
		set(stored)
		status, body, diag := proxyFlowDiag(t, base+"/api/latest-cover")
		if status != 500 || upstream.count() != calls || diag["reason"] != "the outbound URL was refused" {
			t.Fatalf("stored %q: %d %s (upstream calls %d, want %d)", stored, status, body, upstream.count(), calls)
		}
	}

	// A row read by a request id is data, not request text: it may span
	// segments under the opt-in.
	idApp, byID := serveProxyFlow(t, proxyDocsFlow("/api/docs/:id/cover", "SELECT remote_slug FROM documents WHERE id = :id", "path_slashes: true"))
	mustExec(t, idApp.DB, "CREATE TABLE documents (id INTEGER PRIMARY KEY, remote_slug TEXT)")
	mustExec(t, idApp.DB, "INSERT INTO documents (remote_slug) VALUES ('users/7/b.png')")
	if status, body, _ := proxyFlowDiag(t, byID+"/api/docs/1/cover"); status != 200 {
		t.Fatalf("row read by id: %d %s", status, body)
	}
	if req, _ := upstream.last(t); req.RequestURI != "/image/users/7/b.png" {
		t.Fatalf("row read by id went out as %q", req.RequestURI)
	}

	// Request text never spans segments.
	_, direct := serveProxyFlow(t, proxyFlow("GET", "/api/img", "url: http://"+proxyTestHost+"/image/${{ params.p }}", "content_types: [image/png]", "path_slashes: true"))
	calls = upstream.count()
	if status, _, _ := proxyFlowDiag(t, direct+"/api/img?p=users%2F42%2Fa.png"); status != 500 || upstream.count() != calls {
		t.Fatalf("request text with a slash: %d (upstream %d)", status, upstream.count())
	}
	if status, _, _ := proxyFlowDiag(t, direct+"/api/img?p=a.png"); status != 200 {
		t.Fatalf("plain request text: %d", status)
	}

	// The key takes a literal boolean.
	for value, ok := range map[string]bool{"true": true, "false": true, `"yes"`: false, "${{ params.s }}": false, "1": false} {
		msg := ValidateOnWrite("flows/p.yaml", proxyFlow("GET", "/api/img", "url: https://api.example.com/f/${{ params.p }}", "content_types: [image/png]", "path_slashes: "+value))
		if (msg == "") != ok || !ok && !strings.Contains(msg, "path_slashes") {
			t.Errorf("path_slashes: %s: write gate said %q, want accepted=%v", value, msg, ok)
		}
	}
}

// inet_aton spellings of a private address (`127.1`, `0x7f000001`,
// `2130706433`, `0177.0.0.1`) passed the write gate; the runtime refused
// them. The gate now reads them as the resolver does.
func TestProxyWriteGateRefusesNumericPrivateHosts(t *testing.T) {
	for _, url := range []string{
		"http://127.1/x", "http://0x7f000001/x", "http://2130706433/x", "http://0177.0.0.1/x",
		"http://0x7f.1/x", "http://127.000.000.001/x", "http://10.1/x", "http://0xa9.0xfe.0xa9.0xfe/latest",
		"http://0/x", "http://[fe80::1%25eth0]/x", "http://[::ffff:7f00:1]/x", "http://127.1./x",
	} {
		if msg := ValidateOnWrite("flows/p.yaml", proxyFlow("GET", "/api/p", "url: "+url, "content_types: [image/png]")); !strings.Contains(msg, "private or internal") {
			t.Errorf("write gate on %s: %q", url, msg)
		}
	}
	for _, url := range []string{"http://134744072/x", "http://api.example.com/x", "http://1.2.3.4/x", "http://0x7f.example.com/x"} {
		if msg := ValidateOnWrite("flows/p.yaml", proxyFlow("GET", "/api/p", "url: "+url, "content_types: [image/png]")); msg != "" {
			t.Errorf("write gate refused public host %s: %q", url, msg)
		}
	}
	for host, want := range map[string]string{
		"127.1": "127.0.0.1", "0x7f000001": "127.0.0.1", "2130706433": "127.0.0.1", "0177.0.0.1": "127.0.0.1",
		"0x7F.1": "127.0.0.1", "10.1": "10.0.0.1", "192.168.257": "192.168.1.1", "1.2.3.4": "1.2.3.4", "0": "0.0.0.0", "1.2.3.4.": "1.2.3.4",
		"example.com": "", "1.2.3.4.5": "", "256.1.1.1": "", "1.2.3.256": "", "0x100000000": "", "1..2": "", "": "",
		"08.1.1.1": "", "1e3": "", "-1": "", "+1": "", "1_0": "", "0x": "", "0x7f.example": "", "4294967296": "",
	} {
		ip := parseInetAtonIPv4(host)
		got := ""
		if ip != nil {
			got = ip.String()
		}
		if got != want {
			t.Errorf("parseInetAtonIPv4(%q) = %q, want %q", host, got, want)
		}
	}
	// The runtime check reads them the same way, with no DNS lookup.
	saved := outboundLookupIP
	t.Cleanup(func() { outboundLookupIP = saved })
	outboundLookupIP = func(_ context.Context, host string) ([]net.IP, error) { return nil, errors.New("no DNS in this test") }
	for _, url := range []string{"http://0x7f000001/", "http://127.1/", "http://2130706433/", "http://[fe80::1%25eth0]/"} {
		if err := outboundURLCheck(url); !errors.Is(err, errOutboundPrivate) {
			t.Errorf("outboundURLCheck(%s) = %v, want private", url, err)
		}
	}
}

// A host that does not resolve said "refused a private or internal
// address"; it now says it could not be resolved. A private address still
// says private.
func TestProxyNamesAnUnresolvedHost(t *testing.T) {
	upstream := proxyPNGUpstream(t)
	saved := outboundLookupIP
	t.Cleanup(func() { outboundLookupIP = saved })
	outboundLookupIP = func(_ context.Context, host string) ([]net.IP, error) {
		switch host {
		case "nowhere.example":
			return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
		case "inside.example":
			return []net.IP{net.ParseIP("10.0.0.7")}, nil
		}
		return saved(context.Background(), host)
	}
	app, cleanup := newTestApp(t)
	defer cleanup()
	run := func(url string) *FlowContext {
		rr := httptest.NewRecorder()
		ctx := proxyStepCtx(app, rr, httptest.NewRequest("GET", "/api/p", nil))
		executeSteps(ctx, []FlowStep{proxyStep(url, "image/png")})
		if rr.Body.Len() != 0 || upstream.count() != 0 {
			t.Fatalf("%s: something was sent: body=%q upstream=%d", url, rr.Body.String(), upstream.count())
		}
		return ctx
	}
	ctx := run("http://nowhere.example/a.png")
	if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "could not resolve") || strings.Contains(ctx.Error.Error(), "private") {
		t.Fatalf("unresolved host: %v", ctx.Error)
	}
	if got := flowFailureReason("proxy", ctx.Error); got != "the upstream host could not be resolved" {
		t.Fatalf("unresolved host reason = %q", got)
	}
	ctx = run("http://inside.example/a.png")
	if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "SECURITY: proxy refused a private or internal address") {
		t.Fatalf("private host: %v", ctx.Error)
	}
	if got := flowFailureReason("proxy", ctx.Error); got != "the outbound URL was refused" {
		t.Fatalf("private host reason = %q", got)
	}
}

// An https to http redirect on the same host was reported as "redirected to
// another host"; the message now names the change.
func TestProxyRedirectMessageNamesTheChange(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/downgrade":
			http.Redirect(w, r, "http://"+proxyTestHost+"/final", http.StatusFound)
		case "/port":
			http.Redirect(w, r, "https://"+proxyTestHost+":8443/final", http.StatusFound)
		case "/host":
			http.Redirect(w, r, "https://93.184.216.35/final", http.StatusFound)
		default:
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write([]byte("final"))
		}
	}))
	t.Cleanup(srv.Close)
	saved := strictOutboundTransport
	strictOutboundTransport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec // test server
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", srv.Listener.Addr().String())
		},
	}
	t.Cleanup(func() { strictOutboundTransport = saved })
	app, cleanup := newTestApp(t)
	defer cleanup()
	for path, want := range map[string]string{
		"/downgrade": "from https to http",
		"/port":      "another port",
		"/host":      "another host",
	} {
		rr := httptest.NewRecorder()
		ctx := proxyStepCtx(app, rr, httptest.NewRequest("GET", "/api/p", nil))
		executeSteps(ctx, []FlowStep{proxyStep("https://"+proxyTestHost+path, "image/png")})
		if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), want) || rr.Body.Len() != 0 {
			t.Fatalf("%s: err=%v body=%q, want %q", path, ctx.Error, rr.Body.String(), want)
		}
		if path != "/host" && strings.Contains(ctx.Error.Error(), "another host") {
			t.Fatalf("%s: a same-host redirect was reported as another host: %v", path, ctx.Error)
		}
		if got := flowFailureReason("proxy", ctx.Error); got != "the upstream redirected outside the URL's own origin" {
			t.Fatalf("%s: reason = %q", path, got)
		}
	}
	rr := httptest.NewRecorder()
	ctx := proxyStepCtx(app, rr, httptest.NewRequest("GET", "/api/p", nil))
	executeSteps(ctx, []FlowStep{proxyStep("https://"+proxyTestHost+"/final", "image/png")})
	if ctx.Error != nil || rr.Body.String() != "final" {
		t.Fatalf("no redirect: err=%v body=%q", ctx.Error, rr.Body.String())
	}
}

// The client asks for gzip and decodes it: the caller gets the decoded
// bytes, and max_bytes counts decoded bytes, so a small compressed body
// that expands past the cap is refused. Any other encoding fails the step.
func TestProxyDecodesGzipAndCapsDecodedBytes(t *testing.T) {
	csv := strings.Repeat("id,name\n1,alpha\n", 256) // 4096 bytes
	var compressed bytes.Buffer
	zw := gzip.NewWriter(&compressed)
	_, _ = zw.Write([]byte(csv))
	_ = zw.Close()
	upstream := startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		if r.URL.Path == "/br" {
			w.Header().Set("Content-Encoding", "br")
			_, _ = w.Write([]byte("not really brotli"))
			return
		}
		if !strings.Contains(r.Header.Get("Accept-Encoding"), "gzip") {
			_, _ = w.Write([]byte(csv))
			return
		}
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed.Bytes())
	})
	app, cleanup := newTestApp(t)
	defer cleanup()
	run := func(path string, maxBytes int64) (*FlowContext, *httptest.ResponseRecorder) {
		step := proxyStep("http://"+proxyTestHost+path, "text/csv")
		step.Proxy.MaxBytes = maxBytes
		rr := httptest.NewRecorder()
		ctx := proxyStepCtx(app, rr, httptest.NewRequest("GET", "/api/p", nil))
		executeSteps(ctx, []FlowStep{step})
		return ctx, rr
	}
	ctx, rr := run("/gz", 8<<10)
	if ctx.Error != nil || rr.Body.String() != csv || rr.Header().Get("Content-Encoding") != "" {
		t.Fatalf("gzip answer: err=%v body %d bytes, encoding %q", ctx.Error, rr.Body.Len(), rr.Header().Get("Content-Encoding"))
	}
	if req, _ := upstream.last(t); !strings.Contains(req.Header.Get("Accept-Encoding"), "gzip") {
		t.Fatalf("the client did not ask for gzip: %v", req.Header)
	}
	if compressed.Len() >= 1024 {
		t.Fatalf("test body compresses to %d bytes; it must be under the 1 KiB cap", compressed.Len())
	}
	ctx, rr = run("/gz", 1<<10)
	if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "max_bytes") || rr.Body.Len() != 0 {
		t.Fatalf("decoded body over max_bytes: err=%v body %d bytes", ctx.Error, rr.Body.Len())
	}
	ctx, rr = run("/br", 8<<10)
	if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "Content-Encoding") || rr.Body.Len() != 0 {
		t.Fatalf("br answer: err=%v body %q", ctx.Error, rr.Body.String())
	}
}

// A proxy step inside for_each answered for the first item only (the step
// stops the flow); it is refused when written, at any depth in the loop.
func TestProxyRefusedInsideForEach(t *testing.T) {
	flow := func(steps string) string {
		return "on:\n  request:\n    method: GET\n    path: /api/p\n    auth: required\njobs:\n  p:\n    steps:\n" +
			"      - id: list\n        run: sql\n        with:\n          query: \"SELECT 'a.png' AS name\"\n" + steps
	}
	proxy := func(indent string) string {
		return indent + "- run: proxy\n" + indent + "  with:\n" + indent + "    url: https://api.example.com/f/${{ item.name }}\n" + indent + "    content_types: [image/png]\n"
	}
	for name, steps := range map[string]string{
		"in loop":         "      - for_each: ${{ steps.list.outputs.rows }}\n        steps:\n" + proxy("          "),
		"in if in loop":   "      - for_each: ${{ steps.list.outputs.rows }}\n        steps:\n          - if: ${{ item.name }} == 'a.png'\n            steps:\n" + proxy("              "),
		"in else in loop": "      - for_each: ${{ steps.list.outputs.rows }}\n        steps:\n          - if: ${{ item.name }} == 'x'\n            steps:\n              - run: respond\n                with: { status: 200, body: x }\n            else:\n" + proxy("              "),
	} {
		if msg := ValidateOnWrite("flows/p.yaml", flow(steps)); !strings.Contains(msg, "for_each") {
			t.Errorf("%s: write gate said %q", name, msg)
		}
	}
	inIf := "      - if: ${{ steps.list.outputs.rows[0].name }} == 'a.png'\n        steps:\n" + strings.ReplaceAll(proxy("          "), "item.name", "steps.list.outputs.rows[0].name")
	if msg := ValidateOnWrite("flows/p.yaml", flow(inIf)); msg != "" {
		t.Fatalf("a proxy step in an if block was refused: %s", msg)
	}
}

// A proxy step that fails inside an `if:` block answered failed_type "if"
// and the reason "the if step failed", except for a timeout or a missing
// value: the reason depended on the kind of error. The block now keeps the
// failed step's own name, type and reason, as outside the block.
func TestProxyFailureInsideIfKeepsTheStepReason(t *testing.T) {
	startProxyUpstream(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/missing.png" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<p>"))
	})
	step := func(indent, path string) string {
		return indent + "- id: fetch\n" + indent + "  run: proxy\n" + indent + "  with:\n" + indent + "    url: http://" + proxyTestHost + path + "\n" + indent + "    content_types: [image/png]\n"
	}
	head := "on:\n  request:\n    method: GET\n    path: /api/p\n    rate_limit: 1000/min\njobs:\n  p:\n    steps:\n"
	for path, reason := range map[string]string{
		"/missing.png": "the upstream service answered with an error status",
		"/page.png":    "the upstream answered a media type the step does not serve",
	} {
		_, plain := serveProxyFlow(t, head+step("      ", path))
		_, nested := serveProxyFlow(t, head+"      - if: ${{ params.go }} == 'yes'\n        steps:\n"+step("          ", path))
		_, deeper := serveProxyFlow(t, head+"      - if: ${{ params.go }} == 'yes'\n        steps:\n          - if: ${{ params.go }} != 'no'\n            steps:\n"+step("              ", path))
		for name, base := range map[string]string{"plain": plain, "in if": nested, "in nested if": deeper} {
			status, body, diag := proxyFlowDiag(t, base+"/api/p?go=yes")
			if status != 500 || diag["failed_step"] != "fetch" || diag["failed_type"] != "proxy" || diag["reason"] != reason {
				t.Errorf("%s %s: %d failed_step=%v failed_type=%v reason=%v (%s)", name, path, status, diag["failed_step"], diag["failed_type"], diag["reason"], body)
			}
		}
	}
}
