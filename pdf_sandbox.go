//go:build !cli

package main

// PDF render sandbox. Headless Chrome used to print the rendered page from a
// file:// URL. The print CSP blocked file: subresources, but not top-level
// navigation, so page script or a meta refresh could navigate the renderer
// to file:///…/env.yaml, /proc/self/environ or a loopback service and print
// that instead. Now:
//
//   - the document is served from an isolated, non-routable http origin
//     (pdfOriginHost), and Chrome refuses to navigate an http page to file:;
//   - every request Chrome makes goes through an in-process proxy that
//     serves only that document and tunnels only HTTPS to the hosts the
//     page's own CSP allows, dialing through the private-address guard;
//   - DNS resolution in Chrome and non-proxied WebRTC UDP are disabled, so
//     nothing reaches the network except through the proxy.

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// pdfOriginHost is the origin the document is served from. .invalid never
// resolves, so the only way to reach it is through the sandbox proxy.
const pdfOriginHost = "pdf.benmore.invalid"

type pdfSandbox struct {
	doc   []byte
	token string
	csp   string
	allow map[string]bool // lowercase hostnames HTTPS may be tunnelled to
	ln    net.Listener
	srv   *http.Server
	wg    sync.WaitGroup
}

// newPDFSandbox starts the proxy for one render. allowHosts are the
// hostnames the page CSP names; csp is sent as the document's policy.
func newPDFSandbox(doc []byte, csp string, allowHosts []string) (*pdfSandbox, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	s := &pdfSandbox{doc: doc, token: hex.EncodeToString(b), csp: csp, allow: map[string]bool{}, ln: ln}
	for _, h := range allowHosts {
		if h = strings.ToLower(strings.TrimSpace(h)); h != "" {
			s.allow[h] = true
		}
	}
	s.srv = &http.Server{Handler: s, ReadHeaderTimeout: 10 * time.Second}
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.srv.Serve(ln)
	}()
	return s, nil
}

func (s *pdfSandbox) ProxyAddr() string { return s.ln.Addr().String() }
func (s *pdfSandbox) DocURL() string    { return "http://" + pdfOriginHost + "/" + s.token }

func (s *pdfSandbox) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	s.srv.Shutdown(ctx)
	s.srv.Close()
	s.wg.Wait()
}

// pdfSandboxObserve, when set (tests only), sees every request Chrome sends
// through the proxy.
var pdfSandboxObserve func(r *http.Request)

func (s *pdfSandbox) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if pdfSandboxObserve != nil {
		pdfSandboxObserve(r)
	}
	if r.Method == http.MethodConnect {
		s.tunnel(w, r)
		return
	}
	host := strings.ToLower(r.URL.Hostname())
	if host == "" {
		host = strings.ToLower(r.Host)
	}
	if host != pdfOriginHost {
		// Plain-http fetches and navigations anywhere else are refused;
		// allowed hosts are reachable over HTTPS only.
		http.Error(w, "blocked", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodGet || r.URL.Path != "/"+s.token {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Security-Policy", s.csp)
	w.Header().Set("Cache-Control", "no-store")
	w.Write(s.doc)
}

// tunnel handles CONNECT for an allowed host on port 443, dialing through
// the private-address guard so an allowed name that resolves internally is
// still refused.
func (s *pdfSandbox) tunnel(w http.ResponseWriter, r *http.Request) {
	host, port, err := net.SplitHostPort(r.Host)
	if err != nil || port != "443" || !s.allow[strings.ToLower(host)] {
		http.Error(w, "blocked", http.StatusForbidden)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "unsupported", http.StatusInternalServerError)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 10*time.Second)
	upstream, err := publicOnlyDialer.DialContext(ctx, "tcp", r.Host)
	cancel()
	if err != nil {
		http.Error(w, "blocked", http.StatusBadGateway)
		return
	}
	client, buf, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	deadline := time.Now().Add(30 * time.Second)
	client.SetDeadline(deadline)
	upstream.SetDeadline(deadline)
	client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))
	done := make(chan struct{}, 2)
	go func() {
		if n := buf.Reader.Buffered(); n > 0 {
			p, _ := buf.Reader.Peek(n)
			upstream.Write(p)
		}
		io.Copy(upstream, client)
		done <- struct{}{}
	}()
	go func() {
		io.Copy(client, upstream)
		done <- struct{}{}
	}()
	<-done
	client.Close()
	upstream.Close()
}

// pdfChromeArgs is the headless Chrome command line for one sandboxed
// render.
func pdfChromeArgs(proxyAddr, docURL, pdfPath, profileDir string) []string {
	return []string{
		"--headless=new",
		"--disable-gpu",
		"--no-sandbox",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--disable-sync",
		"--disable-background-networking",
		"--disable-component-update",
		"--user-data-dir=" + profileDir,
		// Everything through the sandbox proxy, loopback included.
		"--proxy-server=http://" + proxyAddr,
		"--proxy-bypass-list=<-loopback>",
		// Chrome itself resolves nothing; only the proxy dials out.
		"--host-resolver-rules=MAP * ~NOTFOUND , EXCLUDE 127.0.0.1",
		// WebRTC UDP would bypass the proxy.
		"--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--webrtc-ip-handling-policy=disable_non_proxied_udp",
		"--print-to-pdf=" + pdfPath,
		docURL,
	}
}

// pdfPolicy builds the render CSP from the same host allowlists page
// responses use (framework CDNs plus the app's `csp:` extensions) and
// returns the hostnames the proxy may tunnel to. Frames, objects, forms and
// base changes are off: a PDF needs none of them.
func pdfPolicy(app *App) (csp string, hosts []string) {
	d := pageCSPDirectives(app)
	seen := map[string]bool{}
	for _, v := range d {
		for _, tok := range strings.Fields(v) {
			if !strings.HasPrefix(tok, "https://") {
				continue
			}
			h := strings.TrimPrefix(tok, "https://")
			if i := strings.IndexAny(h, "/:"); i >= 0 {
				h = h[:i]
			}
			if h == "" || strings.Contains(h, "*") || seen[h] {
				continue
			}
			seen[h] = true
			hosts = append(hosts, h)
		}
	}
	keep := func(v string) string {
		var out []string
		for _, tok := range strings.Fields(v) {
			if tok == "'unsafe-inline'" || tok == "data:" || (strings.HasPrefix(tok, "https://") && !strings.Contains(tok, "*")) {
				out = append(out, tok)
			}
		}
		return strings.Join(out, " ")
	}
	csp = fmt.Sprintf("default-src 'self'; script-src 'self' %s; style-src 'self' %s; img-src 'self' data: %s; font-src 'self' data: %s; connect-src 'self' %s; media-src 'self' data:; frame-src 'none'; object-src 'none'; child-src 'none'; worker-src 'none'; base-uri 'none'; form-action 'none'",
		keep(d["script_src"]), keep(d["style_src"]), keep(d["img_src"]), keep(d["font_src"]), keep(d["connect_src"]))
	return csp, hosts
}
