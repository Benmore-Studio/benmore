//go:build linux && (amd64 || arm64) && !cli

package main

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestMain(m *testing.M) {
	if appMCPPDFHelperMain() {
		return
	}
	if err := appMCPPDFConfigureTestWorker(); err != nil {
		fmt.Fprintln(os.Stderr, "PDF test worker:", err)
		os.Exit(2)
	}
	os.Exit(m.Run())
}

func TestAppMCPPDFSeccompProbe(t *testing.T) {
	if !appMCPPDFIsolationAvailable(appMCPPDFTestAppDir(t)) {
		t.Skip("host denies unprivileged seccomp or Landlock; PDF capability correctly fails closed")
	}
}

// requireAppMCPPDFSandbox returns an app directory the sandbox probe proved
// unreadable, or skips (fails under BENMORE_REQUIRE_PDF_INTEGRATION).
func requireAppMCPPDFSandbox(t *testing.T) string {
	t.Helper()
	appDir := appMCPPDFTestAppDir(t)
	if !appMCPPDFIsolationAvailable(appDir) {
		if os.Getenv("BENMORE_REQUIRE_PDF_INTEGRATION") == "1" {
			t.Fatal("mandatory PDF sandbox probe is unavailable")
		}
		t.Skip("host denies the PDF sandbox; PDF capability correctly fails closed")
	}
	return appDir
}

// A parser child runs under Landlock: it can neither read the app's files nor
// write into the app directory. Before, only the network was blocked, so a
// Poppler or Tesseract exploit could read data.db and .benmore/env.
func TestAppMCPPDFWorkerCannotReadOrWriteAppDirectory(t *testing.T) {
	appDir := requireAppMCPPDFSandbox(t)
	if _, err := os.Stat(appMCPPDFTextPath); err != nil {
		if os.Getenv("BENMORE_REQUIRE_PDF_INTEGRATION") == "1" {
			t.Fatal(err)
		}
		t.Skip("fixed Poppler binaries are not installed")
	}
	secret := filepath.Join(appDir, "secret.pdf")
	data := appMCPTestPDF(t, "Confidential")
	if err := os.WriteFile(secret, data, 0600); err != nil {
		t.Fatal(err)
	}
	run, err := appMCPPDFCreateTempRunDir()
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(run)
	input := filepath.Join(run, "input.pdf")
	if err := os.WriteFile(input, data, 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), appMCPPDFPageTimeout)
	defer cancel()
	tempBytes := appMCPPDFTempBytes(int64(len(data)))
	// Control: the same parser reads its own run directory.
	if out, _, err := appMCPPDFRun(ctx, appMCPPDFTextPath, []string{input, "-"}, tempBytes, 1<<20, run); err != nil || !strings.Contains(string(out), "Confidential") {
		t.Fatalf("parser could not read its own run directory: out=%q err=%v", out, err)
	}
	if out, stderr, err := appMCPPDFRun(ctx, appMCPPDFTextPath, []string{secret, "-"}, tempBytes, 1<<20, run); err == nil || strings.Contains(string(out), "Confidential") {
		t.Fatalf("parser read the app directory: out=%q stderr=%q err=%v", out, stderr, err)
	}
	stolen := filepath.Join(appDir, "stolen")
	_, _, _ = appMCPPDFRun(ctx, appMCPPDFRenderPath, appMCPPDFRenderArgs(input, stolen, 1), tempBytes, 1, run)
	if _, err := os.Lstat(stolen + ".png"); !os.IsNotExist(err) {
		t.Fatalf("parser wrote into the app directory: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(run, "page.png")); !os.IsNotExist(err) {
		t.Fatalf("unexpected run-directory output: %v", err)
	}
	if _, _, err := appMCPPDFRun(ctx, appMCPPDFRenderPath, appMCPPDFRenderArgs(input, filepath.Join(run, "page"), 1), tempBytes, 1, run); err != nil {
		t.Fatalf("parser could not write its own run directory: %v", err)
	}
}

// The probe must prove the app directory is unreadable; an app directory
// inside a tree the parsers may read fails it, so PDF stays unavailable.
func TestAppMCPPDFProbeRefusesReadableAppDirectory(t *testing.T) {
	requireAppMCPPDFSandbox(t)
	for _, dir := range []string{"/etc", "/usr/share", filepath.Dir(appMCPPDFEnglishData)} {
		if _, err := os.Stat(dir); err != nil {
			continue
		}
		if appMCPPDFIsolationAvailable(dir) {
			t.Errorf("probe accepted %s, which the parser sandbox can read", dir)
		}
	}
	if appMCPPDFIsolationAvailable(filepath.Join(t.TempDir(), "missing")) {
		t.Error("probe accepted an app directory it could not read before confinement")
	}
	if appMCPPDFIsolationAvailable("") {
		t.Error("probe accepted an empty app directory")
	}
}

func TestAppMCPPDFLandlockRulesExcludeAppData(t *testing.T) {
	run := filepath.Join(appMCPPDFTempRootPath, "run-test")
	writable := map[string]bool{}
	for _, rule := range appMCPPDFLandlockRules(run) {
		if rule.access&^uint64(appMCPPDFLandlockHandled) != 0 {
			t.Errorf("rule %s grants unhandled rights %#x", rule.path, rule.access)
		}
		if rule.access&(unix.LANDLOCK_ACCESS_FS_WRITE_FILE|unix.LANDLOCK_ACCESS_FS_MAKE_REG|unix.LANDLOCK_ACCESS_FS_REMOVE_FILE|unix.LANDLOCK_ACCESS_FS_TRUNCATE) != 0 {
			writable[rule.path] = true
		}
		for _, private := range []string{"/opt", "/home", "/root", "/tmp", "/var/lib", "/proc", "/"} {
			if rule.path == private {
				t.Errorf("rule grants %s", private)
			}
		}
	}
	if len(writable) != 2 || !writable[run] || !writable["/dev/null"] {
		t.Fatalf("writable rules = %v, want only the run directory and /dev/null", writable)
	}
}

// The probe must exercise everything the worker sets up, its resource limits
// included. Before, it never called setrlimit, so a host whose hard limits
// refuse the worker's limits passed the probe and failed every extraction.
func TestAppMCPPDFProbeAppliesWorkerResourceLimits(t *testing.T) {
	if os.Getenv("BENMORE_TEST_PDF_PROBE_LOW_HARD_FSIZE") == "1" {
		// Child: a hard file-size limit below the worker's temporary-byte cap,
		// inherited by the probe it starts.
		if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &unix.Rlimit{Cur: 1 << 20, Max: 1 << 20}); err != nil {
			t.Fatal(err)
		}
		if appMCPPDFIsolationAvailable(appMCPPDFTestAppDir(t)) {
			t.Fatal("probe passed although the worker's resource limits cannot be applied")
		}
		return
	}
	requireAppMCPPDFSandbox(t)
	cmd := exec.Command(os.Args[0], "-test.run=^TestAppMCPPDFProbeAppliesWorkerResourceLimits$", "-test.count=1", "-test.v")
	cmd.Env = append(os.Environ(), "BENMORE_TEST_PDF_PROBE_LOW_HARD_FSIZE=1")
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "--- PASS: TestAppMCPPDFProbeAppliesWorkerResourceLimits") {
		t.Fatalf("probe under a low hard file-size limit: %v\n%s", err, out)
	}
}

func TestAppMCPPDFTempRootIsPrivateAndOwned(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private-root")
	run, err := appMCPPDFCreateTempRunDirUnder(root)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	for _, path := range []string{root, run} {
		info, err := os.Lstat(path)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
			t.Fatalf("unsafe temp directory %q: info=%v err=%v", path, info, err)
		}
	}
	if !appMCPPDFValidatePrivateDir(run) {
		t.Fatal("worker private-directory check rejected its own 0700 directory")
	}
	if root == run {
		t.Fatal("run directory must be fresh beneath the fixed root")
	}
}

func TestAppMCPPDFTempRootRejectsSymlinkAndUnsafeMode(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := appMCPPDFCreateTempRunDirUnder(link); err == nil {
		t.Fatal("accepted temp root symlink")
	}
	unsafe := filepath.Join(base, "unsafe")
	if err := os.Mkdir(unsafe, 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := appMCPPDFCreateTempRunDirUnder(unsafe); err == nil {
		t.Fatal("accepted non-private temp root")
	}
	if appMCPPDFValidatePrivateDir(unsafe) {
		t.Fatal("worker accepted non-private temp directory")
	}
}

func TestAppMCPPDFCapabilityCheckAndProcessInspectionDenials(t *testing.T) {
	if !appMCPPDFCapabilitySetsEmpty([]byte("CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000000\nCapBnd:\t00000000a00425fb\nCapAmb:\t0000000000000000\n")) {
		t.Fatal("rejected empty capability sets")
	}
	if appMCPPDFCapabilitySetsEmpty([]byte("CapInh:\t0000000000000000\nCapPrm:\t0000000000000000\nCapEff:\t0000000000000001\nCapBnd:\t0000000000000000\nCapAmb:\t0000000000000000\n")) {
		t.Fatal("accepted non-empty effective capabilities")
	}
	blocked := make(map[uint32]bool)
	for _, syscallNumber := range appMCPPDFBlockedSyscalls() {
		blocked[syscallNumber] = true
	}
	for _, syscallNumber := range []uint32{unix.SYS_PIDFD_GETFD, unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV, unix.SYS_SOCKET, unix.SYS_CONNECT, unix.SYS_IO_URING_SETUP, unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY, unix.SYS_KEYCTL} {
		if !blocked[syscallNumber] {
			t.Errorf("network/process-inspection syscall %d is not blocked", syscallNumber)
		}
	}
}
