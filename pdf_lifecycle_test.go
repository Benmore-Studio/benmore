//go:build !cli && !windows

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestPDFChromeLifecycleFixture(t *testing.T) {
	mode := os.Getenv("BENMORE_PDF_JOB_FIXTURE")
	if mode == "" {
		return
	}
	data := "%PDF-1.7\nunfinished"
	if mode == "complete" {
		data = "%PDF-1.7\nfixture\n%%EOF\n"
	}
	if err := os.WriteFile(os.Getenv("BENMORE_PDF_JOB_PATH"), []byte(data), 0600); err != nil {
		os.Exit(2)
	}
	// Model a printer that has written its output but will not shut down.
	time.Sleep(time.Minute)
	os.Exit(0)
}

func TestPDFChromeLifecycleStopsCompletedOutputAndRejectsPartial(t *testing.T) {
	for _, mode := range []string{"complete", "partial"} {
		t.Run(mode, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "out.pdf")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPDFChromeLifecycleFixture$")
			cmd.Env = append(os.Environ(), "BENMORE_PDF_JOB_FIXTURE="+mode, "BENMORE_PDF_JOB_PATH="+path)
			started := time.Now()
			_, err := runPDFChrome(ctx, cmd, path)
			if mode == "complete" {
				if err != nil || !pdfOutputComplete(path) {
					t.Fatalf("completed print failed: %v", err)
				}
				if time.Since(started) >= 2*time.Second {
					t.Fatal("completed printer was left until the deadline")
				}
			} else {
				if !errors.Is(err, context.DeadlineExceeded) || pdfOutputComplete(path) {
					t.Fatalf("partial output accepted: %v", err)
				}
				if _, err := os.Stat(path); err != nil {
					t.Fatal("partial printer did not write its output")
				}
			}
			if cmd.ProcessState == nil {
				t.Fatal("printer was not reaped")
			}
		})
	}
}

func TestPDFChromeLifecycleCleansHelpersAfterParentExit(t *testing.T) {
	for _, timeout := range []time.Duration{100 * time.Millisecond, 2 * time.Second} {
		t.Run(timeout.String(), func(t *testing.T) {
			dir := t.TempDir()
			pidPath := filepath.Join(dir, "helper.pid")
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			cmd := exec.CommandContext(ctx, "sh", "-c", fmt.Sprintf("sleep 60 &\necho $! > %q\nexit 0", pidPath))
			cmd.WaitDelay = 300 * time.Millisecond
			_, err := runPDFChrome(ctx, cmd, filepath.Join(dir, "absent.pdf"))
			if timeout < time.Second {
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("lost cancellation: %v", err)
				}
			} else if !errors.Is(err, exec.ErrWaitDelay) {
				t.Fatalf("lost inherited-pipe failure: %v", err)
			}
			raw, err := os.ReadFile(pidPath)
			if err != nil {
				t.Fatal(err)
			}
			pid, err := strconv.Atoi(strings.TrimSpace(string(raw)))
			if err != nil || pid <= 0 {
				t.Fatalf("invalid helper pid: %q", raw)
			}
			t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
			deadline := time.Now().Add(2 * time.Second)
			for !processTerminated(pid) {
				if time.Now().After(deadline) {
					t.Fatal("owned helper survived parent exit")
				}
				time.Sleep(20 * time.Millisecond)
			}
		})
	}
}
