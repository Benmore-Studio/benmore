//go:build !cli

package main

import (
	"bytes"
	"database/sql"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// fakePDFChrome installs a stand-in for Chrome (a shell script, never a real
// browser) as the /pdf renderer for one test.
func fakePDFChrome(t *testing.T, script string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fake-chrome")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script+"\n"), mode); err != nil {
		t.Fatal(err)
	}
	old := pdfChromeLocator
	pdfChromeLocator = func() string { return path }
	t.Cleanup(func() { pdfChromeLocator = old })
	return path
}

func pdfTestApp(t *testing.T) *App {
	t.Helper()
	dir := t.TempDir()
	db, err := sql.Open("sqlite3_benmore", sqliteAppDSN(filepath.Join(dir, "data.db"), dir))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	page := &Page{File: "receipt.html", Route: "/receipt", Title: "Receipt", RawHTML: `<page title="Receipt"><h1>Receipt</h1></page>`}
	return &App{Dir: dir, DB: db, Pages: map[string]*Page{"/receipt": page}}
}

func capturePDFLog(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	return &logs
}

// On a hosted dev instance Chrome died with `signal: aborted (core dumped)`
// and /pdf answered an opaque 500, although the docs promise 501 `PDF
// generation unavailable` when the host cannot print. Every way the renderer
// can fail to produce a PDF (crash, failed start, error exit, no output) now
// answers that 501 with a stable reason, and Chrome's output - temporary
// paths, flags, the binary - reaches only the log, also in dev mode.
func TestPDFRouteRendererFailureAnswers501(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the stand-in renderer is a shell script")
	}
	const marker = "FAKE-CHROME-OUTPUT"
	for _, tc := range []struct {
		name, script string
		mode         os.FileMode
		reason, text string
	}{
		{"crash", "echo " + marker + " \"$0\" >&2; kill -ABRT $$", 0o755, "renderer_crashed", "renderer crashed"},
		{"error exit", "echo " + marker + " \"$0\" >&2; exit 3", 0o755, "renderer_failed", "renderer exited with an error"},
		{"no output", "echo " + marker + " \"$0\" >&2; exit 0", 0o755, "renderer_no_output", "renderer wrote no PDF"},
		{"cannot start", "exit 0", 0o644, "renderer_start_failed", "renderer could not start"},
	} {
		for _, dev := range []bool{false, true} {
			name := tc.name
			if dev {
				name += "/dev mode"
			}
			t.Run(name, func(t *testing.T) {
				chrome := fakePDFChrome(t, tc.script, tc.mode)
				logs := capturePDFLog(t)
				app := pdfTestApp(t)
				app.DevMode = dev
				mux := http.NewServeMux()
				RegisterPDFRoutes(mux, app)
				w := httptest.NewRecorder()
				mux.ServeHTTP(w, httptest.NewRequest("GET", "/pdf/receipt", nil))

				if w.Code != http.StatusNotImplemented {
					t.Fatalf("status %d (%q), want 501", w.Code, w.Body.String())
				}
				if got := w.Header().Get(pdfUnavailableHeader); got != tc.reason {
					t.Fatalf("%s = %q, want %q", pdfUnavailableHeader, got, tc.reason)
				}
				body := w.Body.String()
				id := w.Header().Get(requestIDHeader)
				if !strings.HasPrefix(body, "PDF generation unavailable - "+tc.text) || id == "" || !strings.Contains(body, id) {
					t.Fatalf("body %q (request id %q), want the documented text, reason and request id", body, id)
				}
				for _, leak := range []string{marker, chrome, filepath.Dir(chrome), "signal", "exit status", "benmore-pdf"} {
					if strings.Contains(body, leak) {
						t.Fatalf("501 body leaks %q: %q", leak, body)
					}
				}
				logged := logs.String()
				if !strings.Contains(logged, "PDF ERROR [/receipt]") || !strings.Contains(logged, tc.reason) {
					t.Fatalf("the cause was not logged: %q", logged)
				}
				if tc.name != "cannot start" && !strings.Contains(logged, marker) {
					t.Fatalf("Chrome's output was not logged: %q", logged)
				}
			})
		}
	}
}

// No Chrome at all keeps its documented answer.
func TestPDFRouteWithoutChromeAnswers501(t *testing.T) {
	old := pdfChromeLocator
	pdfChromeLocator = func() string { return "" }
	t.Cleanup(func() { pdfChromeLocator = old })
	app := pdfTestApp(t)
	mux := http.NewServeMux()
	RegisterPDFRoutes(mux, app)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/pdf/receipt", nil))
	if w.Code != http.StatusNotImplemented || !strings.HasPrefix(w.Body.String(), "PDF generation unavailable - Chrome not installed") {
		t.Fatalf("no Chrome: %d %q", w.Code, w.Body.String())
	}
}

// The hosted app units set MemoryDenyWriteExecute=true and give the process
// a private /tmp but the host's /dev/shm, so the renderer runs V8 without
// JIT and keeps shared memory in /tmp.
func TestPDFChromeArgsFitTheHostedAppUnit(t *testing.T) {
	args := pdfChromeArgs("127.0.0.1:4321", "http://document.test/report", "/tmp/report.pdf", "/tmp/profile")
	for _, want := range []string{"--js-flags=--jitless", "--disable-dev-shm-usage", "--no-sandbox", "--headless=new", "--no-zygote", "--disable-gpu", "--disable-software-rasterizer"} {
		count := 0
		for _, arg := range args {
			if arg == want {
				count++
			}
		}
		if count != 1 {
			t.Errorf("PDF args need exactly one %q, got %d in %q", want, count, args)
		}
	}
	if last := args[len(args)-1]; last != "http://document.test/report" {
		t.Errorf("the document URL must stay the last argument, got %q", last)
	}
}

// On a hosted dev instance every Chrome child died with
// `credentials.cc:365 Check failed: Operation not permitted`, then the
// browser with "GPU process isn't usable. Goodbye.", so /pdf answered 501
// renderer_crashed. Chrome's zygote forks each renderer, GPU and utility
// process and drops its capabilities with capset(2); the app units deny
// capset (SystemCallFilter=~@privileged, SystemCallErrorNumber=EPERM). The
// render must start its children without the zygote, which Chrome accepts
// only together with --no-sandbox (it exits otherwise), and must not bring
// back SwiftShader, whose shader JIT MemoryDenyWriteExecute refuses.
func TestPDFChromeArgsStartChildrenWithoutTheZygote(t *testing.T) {
	args := pdfChromeArgs("127.0.0.1:4321", "http://document.test/report", "/tmp/report.pdf", "/tmp/profile")
	has := func(flag string) bool {
		for _, arg := range args {
			if arg == flag {
				return true
			}
		}
		return false
	}
	if !has("--no-zygote") {
		t.Fatalf("children are forked by the zygote, which calls capset the units deny: %q", args)
	}
	if !has("--no-sandbox") {
		t.Fatalf("Chrome refuses --no-zygote without --no-sandbox: %q", args)
	}
	if !has("--disable-gpu") || !has("--disable-software-rasterizer") {
		t.Fatalf("the GPU process may load SwiftShader, whose JIT the units refuse: %q", args)
	}
	for _, arg := range args {
		for _, refused := range []string{"--enable-unsafe-swiftshader", "--use-angle=", "--use-gl=", "--enable-gpu", "--zygote-", "--js-flags=--no-jitless"} {
			if strings.HasPrefix(arg, refused) {
				t.Errorf("%q undoes what the hosted units need", arg)
			}
		}
	}
}
