//go:build !cli

package main

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPDFChromeArgsUseEphemeralCredentialStore(t *testing.T) {
	args := pdfChromeArgs("127.0.0.1:4321", "http://document.test/report", "/tmp/report.pdf", "/tmp/profile")
	for _, want := range []string{"--password-store=basic", "--use-mock-keychain", "--user-data-dir=/tmp/profile"} {
		count := 0
		for _, arg := range args {
			if arg == want {
				count++
			}
		}
		if count != 1 {
			t.Errorf("ephemeral PDF args require exactly one %q, got %d", want, count)
		}
	}
}

// The sandbox proxy serves only the one document and tunnels only HTTPS to
// allowed hosts that resolve publicly.
func TestPDFSandboxProxyServesOnlyTheDocument(t *testing.T) {
	sb, err := newPDFSandbox([]byte("<p>doc</p>"), "default-src 'self'", []string{"localhost", "cdn.example.test"})
	if err != nil {
		t.Fatal(err)
	}
	defer sb.Close()
	get := func(url string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("GET", url, nil)
		rec := httptest.NewRecorder()
		sb.ServeHTTP(rec, req)
		return rec
	}
	if rec := get(sb.DocURL()); rec.Code != 200 || rec.Body.String() != "<p>doc</p>" || rec.Header().Get("Content-Security-Policy") == "" {
		t.Fatalf("document: %d %q csp=%q", rec.Code, rec.Body.String(), rec.Header().Get("Content-Security-Policy"))
	}
	if rec := get("http://" + pdfOriginHost + "/other"); rec.Code != http.StatusNotFound {
		t.Fatalf("other origin path: %d", rec.Code)
	}
	if rec := get("http://127.0.0.1:9/secret"); rec.Code != http.StatusForbidden {
		t.Fatalf("plain http to loopback: %d", rec.Code)
	}
	if rec := get("http://cdn.example.test/x.js"); rec.Code != http.StatusForbidden {
		t.Fatalf("plain http to an allowed host: %d", rec.Code)
	}

	connect := func(target string) string {
		c, err := net.Dial("tcp", sb.ProxyAddr())
		if err != nil {
			t.Fatal(err)
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(15 * time.Second))
		fmt.Fprintf(c, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", target, target)
		line, _ := bufio.NewReader(c).ReadString('\n')
		return line
	}
	for _, target := range []string{"evil.example.test:443", "cdn.example.test:80", "localhost:443"} {
		if line := connect(target); strings.Contains(line, " 200 ") {
			t.Errorf("CONNECT %s was tunnelled: %q", target, line)
		}
	}
	args := strings.Join(pdfChromeArgs(sb.ProxyAddr(), sb.DocURL(), "/tmp/x.pdf", "/tmp/p"), " ")
	for _, want := range []string{"--proxy-server=http://" + sb.ProxyAddr(), "--proxy-bypass-list=<-loopback>", "--host-resolver-rules=", "disable_non_proxied_udp"} {
		if !strings.Contains(args, want) {
			t.Errorf("chrome args missing %q: %s", want, args)
		}
	}
	if strings.Contains(args, "file://") {
		t.Errorf("chrome renders from file://: %s", args)
	}
}

// End to end with a real headless Chrome (skipped when none is installed).
// Two renders, each deterministic: a page that navigates to a loopback
// service at once (Chrome must ask the sandbox proxy, which refuses it; a
// page that navigates away may not print, which fails closed), and a page
// that tries to reach a local file by navigation and meta refresh (refused,
// and the PDF is still produced). No loopback request may ever arrive.
func TestPDFRenderCannotReachLocalFilesOrLoopback(t *testing.T) {
	chrome := findChrome()
	if chrome == "" {
		t.Skip("no Chrome installed")
	}
	if !headlessPrintWorks(t, chrome) {
		t.Skip("headless Chrome cannot print in this environment")
	}
	var hits atomic.Int32
	canary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte("canary"))
	}))
	defer canary.Close()
	canaryHost := strings.TrimPrefix(canary.URL, "http://")

	var mu sync.Mutex
	var seen []string
	pdfSandboxObserve = func(r *http.Request) {
		mu.Lock()
		seen = append(seen, r.Method+" "+r.Host)
		mu.Unlock()
	}
	defer func() { pdfSandboxObserve = nil }()
	render := func(doc string) (pdf bool, requests []string) {
		t.Helper()
		mu.Lock()
		seen = nil
		mu.Unlock()
		dir := t.TempDir()
		sb, err := newPDFSandbox([]byte(doc), "default-src 'self' 'unsafe-inline'", []string{"marker.example.test"})
		if err != nil {
			t.Fatal(err)
		}
		defer sb.Close()
		pdfPath := filepath.Join(dir, "out.pdf")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, chrome, pdfChromeArgs(sb.ProxyAddr(), sb.DocURL(), pdfPath, filepath.Join(dir, "profile"))...)
		cmd.WaitDelay = 5 * time.Second
		if out, err := runPDFChrome(ctx, cmd, pdfPath); err != nil {
			t.Fatalf("chrome: %v\n%s", err, out)
		}
		time.Sleep(500 * time.Millisecond)
		complete := pdfOutputComplete(pdfPath)
		mu.Lock()
		defer mu.Unlock()
		return complete, append([]string(nil), seen...)
	}
	contains := func(reqs []string, host string) bool {
		for _, r := range reqs {
			if strings.HasSuffix(r, " "+host) {
				return true
			}
		}
		return false
	}

	_, reqs := render(fmt.Sprintf(`<!doctype html><html><head><link rel="stylesheet" href="%[1]s/css"></head>
<body><h1>report</h1><img src="%[1]s/img"><script>fetch(%[2]q).catch(function(){}); location = %[3]q;</script></body></html>`,
		canary.URL, canary.URL+"/fetch", canary.URL+"/nav"))
	if !contains(reqs, pdfOriginHost) {
		t.Fatalf("the document was not loaded through the sandbox (proxy saw %q)", reqs)
	}
	if !contains(reqs, canaryHost) {
		t.Fatalf("the loopback navigation did not go through the sandbox proxy (proxy saw %q)", reqs)
	}

	dir := t.TempDir()
	marker := filepath.Join(dir, "local.html")
	// If the renderer ever loaded this local page, it would ask the proxy
	// for the marker host.
	os.WriteFile(marker, []byte(`<img src="https://marker.example.test/loaded.png">`), 0600)
	pdf, reqs := render(fmt.Sprintf(`<!doctype html><html><head><meta http-equiv="refresh" content="0;url=file://%[1]s"></head>
<body><h1>report</h1><script>try { location = %[2]q } catch (e) {}</script></body></html>`, marker, "file://"+marker))
	if !pdf {
		t.Fatalf("no PDF produced for a page whose local-file navigation was refused (proxy saw %q)", reqs)
	}
	if contains(reqs, "marker.example.test") {
		t.Fatalf("renderer loaded a local file (proxy saw %q)", reqs)
	}
	if n := hits.Load(); n != 0 {
		t.Fatalf("renderer reached a loopback service %d time(s)", n)
	}
}

// headlessPrintWorks reports whether this machine's Chrome can print a
// trivial page headlessly (some desktop sessions hang instead).
func headlessPrintWorks(t *testing.T, chrome string) bool {
	dir := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, chrome, "--headless=new", "--disable-gpu", "--no-sandbox",
		"--user-data-dir="+filepath.Join(dir, "profile"), "--print-to-pdf="+filepath.Join(dir, "probe.pdf"), "data:text/html,probe")
	cmd.WaitDelay = 2 * time.Second
	path := filepath.Join(dir, "probe.pdf")
	if _, err := runPDFChrome(ctx, cmd, path); err != nil {
		return false
	}
	return pdfOutputComplete(path)
}
