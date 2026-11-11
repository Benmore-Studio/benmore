//go:build !cli

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// connectSrcOf serves one page response through the security-header
// middleware and returns the connect-src sources of its CSP.
func connectSrcOf(t *testing.T, app *App, host string) []string {
	t.Helper()
	h := securityHeaders(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}), false, app)
	r := httptest.NewRequest("GET", "/", nil)
	r.Host = host
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	var directives []string
	for _, d := range strings.Split(w.Header().Get("Content-Security-Policy"), ";") {
		if fields := strings.Fields(d); len(fields) > 0 && fields[0] == "connect-src" {
			directives = append(directives, strings.Join(fields[1:], " "))
		}
	}
	if len(directives) != 1 {
		t.Fatalf("connect-src directives = %q in %q", directives, w.Header().Get("Content-Security-Policy"))
	}
	return strings.Fields(directives[0])
}

// The default connect-src was `'self' wss: ws:`, so page code (or markup
// injected into a page) could open a WebSocket to any host. It is now the
// app's own origin, its own realtime origin named explicitly, and what
// csp.connect_src declares.
func TestPageCSPConnectSrcIsTheAppsOwnOrigin(t *testing.T) {
	t.Setenv("BENMORE_CF_ANALYTICS", "")
	withPlatformMedia(t, nil)
	app := &App{Dir: t.TempDir()}
	// Besides https:// script CDNs (which cannot carry a WebSocket), only the
	// app's own origin.
	var webSockets []string
	for _, s := range connectSrcOf(t, app, "shop.example.test") {
		if !strings.HasPrefix(s, "https://") {
			webSockets = append(webSockets, s)
		}
	}
	if got := strings.Join(webSockets, " "); got != "'self' wss://shop.example.test ws://shop.example.test" {
		t.Fatalf("connect-src WebSocket sources = %q", got)
	}

	app.Design = &DesignConfig{CSP: map[string]string{"connect_src": "wss://ws-feed.exchange.coinbase.com"}}
	sources := connectSrcOf(t, app, "shop.example.test:8443")
	for _, want := range []string{"'self'", "wss://shop.example.test:8443", "wss://ws-feed.exchange.coinbase.com"} {
		if !strings.Contains(" "+strings.Join(sources, " ")+" ", " "+want+" ") {
			t.Fatalf("connect-src %q lacks %s", sources, want)
		}
	}
	for _, s := range sources {
		if s == "wss:" || s == "ws:" || s == "*" {
			t.Fatalf("connect-src %q still allows every host", sources)
		}
	}

	// A Host that is not a plain host[:port] never reaches the header.
	for _, host := range []string{"evil.test;script-src *", "a b", "x'y", ""} {
		got := connectSrcOf(t, &App{Dir: t.TempDir()}, host)
		for _, s := range got {
			if strings.HasPrefix(s, "ws") || strings.Contains(s, "evil") {
				t.Fatalf("Host %q: connect-src = %q", host, got)
			}
		}
	}
}

// bm.js realtime connects to the page's own host, which the own-origin
// sources above allow.
func TestBMRealtimeConnectsToTheOwnOrigin(t *testing.T) {
	src, err := os.ReadFile("embedded/bm.js")
	if err != nil {
		t.Fatal(err)
	}
	// bm.room builds the URL once and reopens it on every reconnect.
	if !strings.Contains(string(src), "const url = `${proto}://${location.host}/ws`;") || !strings.Contains(string(src), "new WebSocket(url)") {
		t.Fatal("bm.js no longer opens its socket at its own host; check the connect-src default")
	}
	if webSocketLiteralRe.Match(src) {
		t.Fatalf("bm.js names a WebSocket host: %s", webSocketLiteralRe.Find(src))
	}
}

func writeAppFile(t *testing.T, dir, name, content string) {
	t.Helper()
	path := filepath.Join(dir, filepath.FromSlash(name))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func webSocketWarnings(report CheckReport) []CheckFinding {
	var out []CheckFinding
	for _, f := range report.Findings {
		if strings.Contains(f.Message, "opens a WebSocket to") {
			out = append(out, f)
		}
	}
	return out
}

// benmore check and the post-write check warn about a WebSocket to a host the
// page's connect-src does not allow, naming the line and the app.yaml line.
func TestCheckWarnsAboutWebSocketHostsOutsideConnectSrc(t *testing.T) {
	dir := t.TempDir()
	writeAppFile(t, dir, "app.yaml", "name: markets\n")
	writeAppFile(t, dir, "static/app.tsx", "import { room } from 'bm';\n\nconst feed = new WebSocket('wss://ws-feed.exchange.coinbase.com');\nconst own = new WebSocket(`wss://${location.host}/ws`);\nconst local = new WebSocket('ws://localhost:8080');\n")
	writeAppFile(t, dir, "static/other.ts", "export const x = 1;\n")

	warnings := webSocketWarnings(RunSourceCheck(dir, ""))
	if len(warnings) != 1 {
		t.Fatalf("warnings = %+v", warnings)
	}
	w := warnings[0]
	if w.Severity != "warning" || w.File != "static/app.tsx" {
		t.Fatalf("finding = %+v", w)
	}
	for _, want := range []string{"static/app.tsx:3", "wss://ws-feed.exchange.coinbase.com", `connect_src: "wss://ws-feed.exchange.coinbase.com"`} {
		if !strings.Contains(w.Message, want) {
			t.Fatalf("message %q lacks %q", w.Message, want)
		}
	}
	// A write of the file shows it; a write of another static file does not.
	if len(webSocketWarnings(RunSourceCheck(dir, "static/app.tsx"))) != 1 || len(webSocketWarnings(RunSourceCheck(dir, "static/other.ts"))) != 0 {
		t.Fatal("the warning is not tied to the file that opens the socket")
	}

	for declared, wantWarning := range map[string]bool{
		"wss://ws-feed.exchange.coinbase.com":                         false,
		"https://api.example.com wss://ws-feed.exchange.coinbase.com": false,
		"wss://*.coinbase.com":                                        false,
		"wss:":                                                        false,
		"ws:":                                                         false,
		"https://ws-feed.exchange.coinbase.com":                       true, // an https source does not allow wss
		"ws-feed.exchange.coinbase.com":                               true, // nor does a scheme-less one from an HTTPS page
		"wss://exchange.coinbase.com.example.test":                    true,
	} {
		writeAppFile(t, dir, "app.yaml", "name: markets\ncsp:\n  connect_src: \""+declared+"\"\n")
		got := webSocketWarnings(RunSourceCheck(dir, ""))
		if (len(got) > 0) != wantWarning {
			t.Errorf("csp.connect_src %q: warnings = %+v", declared, got)
		}
		if wantWarning && !strings.Contains(got[0].Message, declared+" wss://ws-feed.exchange.coinbase.com") {
			t.Errorf("the suggested line drops what is declared: %q", got[0].Message)
		}
	}
}
