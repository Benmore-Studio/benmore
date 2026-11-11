//go:build linux && !cli

package main

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// pdfUnitSandboxEnv is set only by scripts/test-pdf-unit-sandbox.py, which
// runs this test binary inside a transient unit carrying an app unit
// template's sandbox, as root on a disposable Linux runner.
const pdfUnitSandboxEnv = "BENMORE_PDF_UNIT_SANDBOX"

// GET /pdf/<page> runs headless Chrome inside the app's unit, and the units
// deny what a desktop Chrome assumes: capset and the other @privileged calls
// (SystemCallErrorNumber=EPERM), new namespaces, and memory that is writable
// and executable. On 2026-11-04 every hosted render died at Chrome's zygote
// (credentials.cc:365, "Operation not permitted") while every test passed,
// because no test ran Chrome under that policy. Inside the unit this first
// proves the policy is in force, then prints a page through the route with
// the host's real Chrome.
func TestPDFRendersUnderHostedAppUnit(t *testing.T) {
	if os.Getenv(pdfUnitSandboxEnv) != "1" {
		t.Skip("runs only inside the app unit sandbox: scripts/test-pdf-unit-sandbox.py")
	}
	chrome := findChrome()
	if chrome == "" {
		t.Fatal("no Chrome installed; the unit sandbox check needs the host's real Chrome")
	}
	requirePDFUnitPolicy(t)

	warmTestChrome(t, chrome)
	logs := capturePDFLog(t)
	app := pdfTestApp(t)
	mux := http.NewServeMux()
	RegisterPDFRoutes(mux, app)
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest("GET", "/pdf/receipt", nil))
	body := w.Body.Bytes()
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/pdf" ||
		!bytes.HasPrefix(body, []byte("%PDF-")) || !bytes.HasSuffix(bytes.TrimSpace(body), []byte("%%EOF")) {
		t.Fatalf("GET /pdf/receipt under the unit: %d %s %q (%d bytes)\n%s",
			w.Code, w.Header().Get(pdfUnavailableHeader), w.Header().Get("Content-Type"), len(body), logs.String())
	}
	t.Logf("GET /pdf/receipt under the unit: %d bytes of PDF", len(body))

	// A record of what the units do to the previous flag set (children
	// forked by the zygote, SwiftShader allowed). Logged, not asserted: the
	// gate is the render above.
	t.Run("previous_flags", func(t *testing.T) {
		dir := t.TempDir()
		sandbox, err := newPDFSandbox([]byte("<!doctype html><p>previous flags</p>"), "default-src 'none'", nil)
		if err != nil {
			t.Fatal(err)
		}
		defer sandbox.Close()
		path := filepath.Join(dir, "out.pdf")
		args := pdfArgsWithout(pdfChromeArgs(sandbox.ProxyAddr(), sandbox.DocURL(), path, filepath.Join(dir, "profile")),
			"--no-zygote", "--disable-software-rasterizer")
		ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, chrome, args...)
		cmd.WaitDelay = 5 * time.Second
		out, err := runPDFChrome(ctx, cmd, path)
		if err == nil && pdfOutputComplete(path) {
			t.Logf("the previous flags printed too under this unit")
			return
		}
		if len(out) > pdfRendererLogTail {
			out = out[len(out)-pdfRendererLogTail:]
		}
		t.Logf("the previous flags failed under this unit (%s): %v\n%s", classifyPDFRendererFailure(err).reason, err, out)
	})
}

// requirePDFUnitPolicy fails unless this process runs under the hosted
// units' syscall policy: capset refused (the call Chrome's zygote makes in
// every child) and no memory both writable and executable
// (MemoryDenyWriteExecute: EPERM from systemd's seccomp filter, EACCES where
// it uses the kernel's PR_SET_MDWE). Without it a passing render proves
// nothing about a hosted app.
func requirePDFUnitPolicy(t *testing.T) {
	t.Helper()
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	// Dropping every capability of this thread: it holds none in the unit.
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3}
	var data [2]unix.CapUserData
	if err := unix.Capset(&hdr, &data[0]); !errors.Is(err, unix.EPERM) {
		t.Fatalf("capset returned %v, want EPERM: this is not the app unit's syscall policy", err)
	}
	mem, err := unix.Mmap(-1, 0, os.Getpagesize(), unix.PROT_READ|unix.PROT_WRITE|unix.PROT_EXEC, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err == nil {
		unix.Munmap(mem)
		t.Fatal("writable and executable memory was mapped: MemoryDenyWriteExecute is not in force")
	}
	if !errors.Is(err, unix.EPERM) && !errors.Is(err, unix.EACCES) {
		t.Fatalf("W+X mmap failed with %v, want EPERM or EACCES", err)
	}
}

// pdfArgsWithout returns args without the named flags.
func pdfArgsWithout(args []string, drop ...string) []string {
	var out []string
	for _, arg := range args {
		if !slices.Contains(drop, arg) {
			out = append(out, arg)
		}
	}
	return out
}
