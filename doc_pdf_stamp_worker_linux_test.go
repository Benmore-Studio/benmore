//go:build linux && (amd64 || arm64) && !cli

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAppMCPPDFStampRunsConfinedChildAndHashesExactOutput(t *testing.T) {
	appDir := requireAppMCPPDFSandbox(t)
	source := stampFixturePDF()
	sourceBefore := append([]byte(nil), source...)
	image := stampFixturePNG(t, 20, 10)
	placements := []pdfStampPlacement{{Page: 2, Rect: pdfStampRect{X: .25, Y: .2, Width: .5, Height: .5}, Signature: image}}
	got, err := appMCPPDFStamp(context.Background(), appDir, source, placements)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(source, sourceBefore) {
		t.Fatal("isolated worker changed the source PDF")
	}
	sum := sha256.Sum256(got.PDF)
	if got.SHA256 != hex.EncodeToString(sum[:]) || len(got.PDF) == 0 || len(got.PDF) > pdfStampMaxOutputBytes {
		t.Fatalf("worker output hash/size mismatch: hash=%q bytes=%d", got.SHA256, len(got.PDF))
	}
	if err := verifyStampRaster(t, got.PDF, 2); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPPDFStampChildRejectsMalformedAndOversizeFrames(t *testing.T) {
	requireAppMCPPDFSandbox(t)
	tests := []struct {
		name string
		data []byte
	}{
		{name: "truncated header", data: []byte{0, 0, 0, 8, '{'}},
		{name: "oversized declared source", data: pdfStampOversizeSourceFrame(t)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			runDir, err := appMCPPDFCreateTempRunDir()
			if err != nil {
				t.Fatal(err)
			}
			defer os.RemoveAll(runDir)
			cmd, err := appMCPPDFStampRestrictedCommand(context.Background(), runDir, appMCPPDFTestAppDir(t))
			if err != nil {
				t.Fatal(err)
			}
			cmd.Stdin = bytes.NewReader(tc.data)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err = cmd.Run()
			if err == nil || stdout.Len() != 0 || !bytes.Contains(stderr.Bytes(), []byte("pdf_stamp_failed")) {
				t.Fatalf("malformed child result: stdout=%d stderr=%q err=%v", stdout.Len(), stderr.String(), err)
			}
		})
	}
}

func pdfStampOversizeSourceFrame(t *testing.T) []byte {
	t.Helper()
	header, err := json.Marshal(pdfStampWorkerHeader{SourceBytes: uint64(pdfStampMaxInputBytes + 1), Placements: []pdfStampWorkerPlacement{{Page: 1, Rect: pdfStampRect{X: .1, Y: .1, Width: .2, Height: .2}, SignatureBytes: 1}}})
	if err != nil {
		t.Fatal(err)
	}
	frame := make([]byte, 4+len(header))
	binary.BigEndian.PutUint32(frame[:4], uint32(len(header)))
	copy(frame[4:], header)
	return frame
}

func TestAppMCPPDFStampChildHonorsDeadline(t *testing.T) {
	requireAppMCPPDFSandbox(t)
	placements := make([]pdfStampPlacement, pdfStampMaxPlacements)
	image := stampFixturePNG(t, 20, 10)
	for i := range placements {
		placements[i] = pdfStampPlacement{Page: 1, Rect: pdfStampRect{X: .1, Y: .1, Width: .2, Height: .2}, Signature: image}
	}
	frame, err := encodePDFStampWorkerRequest(stampFixturePDF(), placements)
	if err != nil {
		t.Fatal(err)
	}
	runDir, err := appMCPPDFCreateTempRunDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(runDir)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	cmd, err := appMCPPDFStampRestrictedCommand(ctx, runDir, appMCPPDFTestAppDir(t))
	if err != nil {
		t.Fatal(err)
	}
	cmd.Stdin = bytes.NewReader(frame)
	if err := cmd.Start(); err != nil {
		t.Fatalf("start worker: %v", err)
	}
	err = cmd.Wait()
	if !errors.Is(ctx.Err(), context.DeadlineExceeded) || err == nil {
		t.Fatalf("worker did not stop at caller deadline: context=%v wait=%v", ctx.Err(), err)
	}
}

func TestAppMCPPDFStampRejectsUnboundedRequestBeforeChild(t *testing.T) {
	appDir := requireAppMCPPDFSandbox(t)
	_, err := appMCPPDFStamp(context.Background(), appDir, make([]byte, pdfStampMaxInputBytes+1), []pdfStampPlacement{{Page: 1, Rect: pdfStampRect{X: .1, Y: .1, Width: .2, Height: .2}, Signature: stampFixturePNG(t, 2, 1)}})
	if err == nil {
		t.Fatal("oversized request reached PDF stamp worker")
	}
}

func TestAppMCPPDFStampRunCannotBeInvokedWithoutTheSandbox(t *testing.T) {
	appDir := requireAppMCPPDFSandbox(t)
	runDir, err := appMCPPDFCreateTempRunDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(runDir)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(executable, appMCPPDFWorkerInvocationArgs(executable, []string{"--stamp-run", runDir, appDir})...)
	cmd.Dir = runDir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TMPDIR=" + runDir}
	if err := cmd.Run(); err == nil || !appMCPPDFWorkerFailure(err) {
		t.Fatalf("direct stage-two invocation bypassed confinement: %v", err)
	}
}

func TestAppMCPPDFStampMemoryLimitChildProbe(t *testing.T) {
	if os.Getenv("BENMORE_PDF_STAMP_MEMORY_PROBE") != "1" {
		return
	}
	// Prove the mapping is allowed before installing the worker's hard-VM
	// limit. Use mmap directly: Go's heap allocator (especially under -race)
	// can fail with a runtime-specific diagnostic before this kernel boundary.
	if appMCPPDFTestAnonymousMapping(128<<20) != 0 {
		appMCPPDFRawExit(4)
	}
	baseline, err := appMCPPDFTestCurrentVirtualMemoryBytes()
	limit := baseline + (64 << 20)
	if err != nil || limit < baseline || appMCPPDFSetAddressSpaceLimit(limit) != nil {
		appMCPPDFRawExit(3)
	}
	var installed unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_AS, &installed) != nil || installed.Cur != limit || installed.Max != limit {
		appMCPPDFRawExit(5)
	}
	if appMCPPDFTestAnonymousMapping(1<<20) != 0 {
		appMCPPDFRawExit(6)
	}
	if appMCPPDFTestAnonymousMapping(128<<20) != unix.ENOMEM {
		appMCPPDFRawExit(7)
	}
	// A distinct exit proves this exact branch ran; returning through testing
	// or the race runtime could allocate again after the address-space cap.
	appMCPPDFRawExit(42)
}

func appMCPPDFTestAnonymousMapping(length uintptr) syscall.Errno {
	address, _, errno := unix.RawSyscall6(unix.SYS_MMAP, 0, length, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANON, ^uintptr(0), 0)
	if errno != 0 {
		return errno
	}
	_, _, errno = unix.RawSyscall(unix.SYS_MUNMAP, address, length, 0)
	return errno
}

func appMCPPDFTestCurrentVirtualMemoryBytes() (uint64, error) {
	statm, err := os.ReadFile("/proc/self/statm")
	if err != nil {
		return 0, err
	}
	fields := strings.Fields(string(statm))
	if len(fields) == 0 {
		return 0, errors.New("empty statm")
	}
	pages, err := strconv.ParseUint(fields[0], 10, 64)
	pageSize := uint64(os.Getpagesize())
	if err != nil || pageSize == 0 || pages > ^uint64(0)/pageSize {
		return 0, errors.New("invalid statm")
	}
	return pages * pageSize, nil
}

func TestAppMCPPDFStampMemoryLimitIsEnforcedInChildOnly(t *testing.T) {
	var before, after unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_AS, &before); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestAppMCPPDFStampMemoryLimitChildProbe$")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "BENMORE_PDF_STAMP_MEMORY_PROBE=1"}
	cmd.WaitDelay = time.Second
	var output bytes.Buffer
	cmd.Stdout, cmd.Stderr = &output, &output
	err := cmd.Run()
	if limitErr := unix.Getrlimit(unix.RLIMIT_AS, &after); limitErr != nil || before != after {
		t.Fatalf("child changed the parent address-space limit: before=%+v after=%+v err=%v", before, after, limitErr)
	}
	var exitErr *exec.ExitError
	if ctx.Err() != nil || !errors.As(err, &exitErr) || exitErr.ExitCode() != 42 || output.Len() != 0 {
		t.Fatalf("child did not fail at the kernel RLIMIT_AS allocation boundary: err=%v output=%q", err, output.String())
	}
	if errno := appMCPPDFTestAnonymousMapping(128 << 20); errno != 0 {
		t.Fatalf("parent mapping failed after child-only limit: %v", errno)
	}
	probe := make([]byte, 1<<20)
	probe[0] = 1
	runtime.KeepAlive(probe)
}
