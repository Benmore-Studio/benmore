//go:build !cli

package main

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// Chrome tests and a cold disk.
//
// A test that starts Chrome is often the first program on a CI runner to read
// Chrome's binary, libraries and resources: about 130 MB, as some 1,300 page
// faults. A diagnostic run measured that first start at 4.5 to 7 s with a
// quarter of a second of it on the CPU, and every later start at about 0.25 s;
// on runners whose disk was busier it took tens of seconds. Each test process
// paid it in whichever Chrome test came first, and that test's own deadline
// absorbed it: `chrome --version` passed the artifact probe's 10 s, chromedp
// gave up after its 20 s ("websocket url timeout reached"), a print to PDF
// passed its 30 s budget, and a timed browser action spent its slack on it.
//
// Those deadlines bound what a running host does, not how fast a CI disk
// reads. warmTestChrome pages Chrome in once per test process, under a
// deadline of its own, before a test starts its clock.

// chromeWarmTimeout bounds the one warm-up a test process makes.
const chromeWarmTimeout = 3 * time.Minute

var chromeWarm struct {
	once sync.Once
	took time.Duration
	err  error
}

// warmTestChrome prints a one-line page to PDF through the renderer's own
// launch path (runPDFChrome, the sandbox proxy and pdfChromeArgs, so the
// keychain-free flags and private profile too): the browser, a renderer,
// fonts and printing, which together cover what the Chrome tests load. It
// asserts nothing: a failed warm-up is logged, and the test then starts Chrome
// itself and reports whatever it sees, so a broken Chrome still fails.
func warmTestChrome(t testing.TB, chrome string) {
	t.Helper()
	first := false
	chromeWarm.once.Do(func() {
		first = true
		start := time.Now()
		chromeWarm.err = printChromeWarmupPDF(chrome, chromeWarmTimeout)
		chromeWarm.took = time.Since(start)
	})
	switch {
	case first:
		t.Logf("Chrome warm-up took %s (err=%v)", chromeWarm.took.Round(time.Millisecond), chromeWarm.err)
	case chromeWarm.err != nil:
		t.Logf("this process's Chrome warm-up failed after %s: %v", chromeWarm.took.Round(time.Millisecond), chromeWarm.err)
	}
}

func printChromeWarmupPDF(chrome string, timeout time.Duration) error {
	dir, err := os.MkdirTemp("", "benmore-chrome-warm-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	sandbox, err := newPDFSandbox([]byte("<!doctype html><title>warm</title><p>warm</p>"), "default-src 'none'; style-src 'unsafe-inline'", nil)
	if err != nil {
		return err
	}
	defer sandbox.Close()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	path := filepath.Join(dir, "warm.pdf")
	cmd := exec.CommandContext(ctx, chrome, pdfChromeArgs(sandbox.ProxyAddr(), sandbox.DocURL(), path, filepath.Join(dir, "profile"))...)
	cmd.WaitDelay = 5 * time.Second
	_, err = runPDFChrome(ctx, cmd, path)
	return err
}
