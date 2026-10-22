//go:build linux && (amd64 || arm64) && !cli

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	appMCPPDFWorkerSetupExit = 125
	appMCPPDFProbeTimeout    = 15 * time.Second
)

// Tests may select an identically built, uninstrumented helper: the race
// runtime cannot fit inside the PDF child's production address-space cap.
// Production always launches this executable; no configuration selects it.
var appMCPPDFWorkerExecutable = os.Executable

func appMCPPDFHelperMain() bool {
	markerIndex := -1
	if len(os.Args) > 1 && os.Args[1] == appMCPPDFWorkerMarker {
		markerIndex = 1
	} else {
		for i := 1; i+1 < len(os.Args); i++ {
			if os.Args[i] == "--" && os.Args[i+1] == appMCPPDFWorkerMarker {
				markerIndex = i + 1
				break
			}
		}
	}
	if markerIndex < 0 {
		return false
	}
	// PR_SET_SECCOMP and landlock_restrict_self are thread-local; keep the
	// helper on the confined thread through the probe or exec (which discards
	// every other Go runtime thread).
	runtime.LockOSThread()
	args := os.Args[markerIndex+1:]
	if len(args) > 0 && args[0] == "--stamp" {
		if len(args) != 3 {
			appMCPPDFRawExit(appMCPPDFWorkerSetupExit)
		}
		appMCPPDFStampWorkerExec(args[1], args[2])
		appMCPPDFRawExit(appMCPPDFWorkerSetupExit)
	}
	if len(args) > 0 && args[0] == "--inspect" {
		if len(args) != 3 {
			appMCPPDFRawExit(appMCPPDFWorkerSetupExit)
		}
		appMCPPDFInspectWorkerExec(args[1], args[2])
		appMCPPDFRawExit(appMCPPDFWorkerSetupExit)
	}
	if len(args) > 0 && args[0] == "--stamp-run" {
		if len(args) != 3 {
			appMCPPDFRawExit(appMCPPDFWorkerSetupExit)
		}
		code := appMCPPDFStampWorkerExit(args[1], args[2])
		appMCPPDFRawExit(code)
	}
	if len(args) > 0 && args[0] == "--inspect-run" {
		if len(args) != 3 {
			appMCPPDFRawExit(appMCPPDFWorkerSetupExit)
		}
		code := appMCPPDFInspectWorkerExit(args[1], args[2])
		appMCPPDFRawExit(code)
	}
	if len(args) > 0 && args[0] == "--probe" {
		if len(args) != 2 {
			os.Exit(appMCPPDFWorkerSetupExit)
		}
		os.Exit(appMCPPDFProbe(args[1]))
	}
	if len(args) < 4 {
		os.Exit(appMCPPDFWorkerSetupExit)
	}
	tempBytes, err := strconv.ParseUint(args[0], 10, 64)
	if err != nil || tempBytes == 0 || tempBytes > uint64(appMCPPDFMaxTempBytes) {
		os.Exit(appMCPPDFWorkerSetupExit)
	}
	tempDir := filepath.Clean(args[1])
	if tempDir != args[1] || filepath.Dir(tempDir) != appMCPPDFTempRootPath || !appMCPPDFValidatePrivateDir(tempDir) {
		os.Exit(appMCPPDFWorkerSetupExit)
	}
	binary := args[2]
	if binary != appMCPPDFTextPath && binary != appMCPPDFInfoPath && binary != appMCPPDFRenderPath && binary != appMCPPDFOCRPath {
		os.Exit(appMCPPDFWorkerSetupExit)
	}
	if !appMCPPDFNoCapabilities() {
		os.Exit(appMCPPDFWorkerSetupExit)
	}
	// Everything exec needs is built before the limits: see appMCPPDFLimitAndExec.
	path, pathErr := syscall.BytePtrFromString(binary)
	argv, argvErr := syscall.SlicePtrFromStrings(append([]string{binary}, args[3:]...))
	envv, envErr := syscall.SlicePtrFromStrings([]string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TMPDIR=" + tempDir})
	if pathErr != nil || argvErr != nil || envErr != nil {
		os.Exit(appMCPPDFWorkerSetupExit)
	}
	limits := appMCPPDFResourceLimits(tempBytes)
	if err := appMCPPDFConfineFilesystem(tempDir); err != nil {
		os.Exit(appMCPPDFWorkerSetupExit)
	}
	if err := appMCPPDFInstallNetworkFilter(); err != nil {
		os.Exit(appMCPPDFWorkerSetupExit)
	}
	appMCPPDFLimitAndExec(limits, path, argv, envv)
	return true
}

// Stage one applies Landlock to its locked thread and then execs a fresh copy
// of the binary. The Go PDF parser only runs after exec, so every runtime thread
// inherits the confinement instead of leaving preexisting threads unrestricted.
func appMCPPDFStampWorkerExec(runDir, appDir string) {
	appMCPPDFWorkerExec(runDir, appDir, "--stamp-run")
}

func appMCPPDFInspectWorkerExec(runDir, appDir string) {
	appMCPPDFWorkerExec(runDir, appDir, "--inspect-run")
}

func appMCPPDFWorkerExec(runDir, appDir, mode string) {
	if runDir == "" || filepath.Clean(runDir) != runDir || filepath.Dir(runDir) != appMCPPDFTempRootPath || !appMCPPDFValidatePrivateDir(runDir) ||
		appDir == "" || !filepath.IsAbs(appDir) || filepath.Clean(appDir) != appDir || !appMCPPDFCanOpen(appDir, unix.O_DIRECTORY) || !appMCPPDFNoCapabilities() {
		appMCPPDFRawExit(appMCPPDFWorkerSetupExit)
	}
	executable, err := os.Executable()
	if err != nil {
		appMCPPDFRawExit(appMCPPDFWorkerSetupExit)
	}
	path, pathErr := syscall.BytePtrFromString(executable)
	argvStrings := append([]string{executable}, appMCPPDFWorkerInvocationArgs(executable, []string{mode, runDir, appDir})...)
	argv, argvErr := syscall.SlicePtrFromStrings(argvStrings)
	envv, envErr := syscall.SlicePtrFromStrings([]string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TMPDIR=" + runDir})
	if pathErr != nil || argvErr != nil || envErr != nil {
		appMCPPDFRawExit(appMCPPDFWorkerSetupExit)
	}
	limits := []appMCPPDFResourceLimit{
		{unix.RLIMIT_CPU, unix.Rlimit{Cur: uint64(appMCPPDFPageTimeout.Seconds()), Max: uint64(appMCPPDFPageTimeout.Seconds())}},
		{unix.RLIMIT_FSIZE, unix.Rlimit{Cur: uint64(pdfStampMaxOutputBytes), Max: uint64(pdfStampMaxOutputBytes)}},
	}
	if err := appMCPPDFConfineFilesystemForExec(runDir, executable); err != nil || appMCPPDFInstallNetworkFilter() != nil {
		appMCPPDFRawExit(appMCPPDFWorkerSetupExit)
	}
	appMCPPDFLimitAndExec(limits, path, argv, envv)
}

// appMCPPDFStampWorkerExit runs in the second, already confined process. It
// verifies the inherited filesystem and network restrictions before parsing.
func appMCPPDFStampWorkerExit(runDir, appDir string) int {
	return appMCPPDFWorkerExit(runDir, appDir, "stamp")
}

func appMCPPDFInspectWorkerExit(runDir, appDir string) int {
	return appMCPPDFWorkerExit(runDir, appDir, "inspect")
}

func appMCPPDFWorkerExit(runDir, appDir, operation string) int {
	if runDir == "" || filepath.Clean(runDir) != runDir || filepath.Dir(runDir) != appMCPPDFTempRootPath || !appMCPPDFValidatePrivateDir(runDir) ||
		appDir == "" || !filepath.IsAbs(appDir) || filepath.Clean(appDir) != appDir || !appMCPPDFDeniedByLandlock(appDir, unix.O_DIRECTORY) {
		return appMCPPDFWorkerSetupExit
	}
	var cpuLimit, fileLimit unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_CPU, &cpuLimit) != nil || cpuLimit.Cur > uint64(appMCPPDFPageTimeout.Seconds()) ||
		unix.Getrlimit(unix.RLIMIT_FSIZE, &fileLimit) != nil || fileLimit.Cur > pdfStampMaxOutputBytes {
		return appMCPPDFWorkerSetupExit
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if fd >= 0 {
		_ = unix.Close(fd)
		return appMCPPDFWorkerSetupExit
	}
	if !errors.Is(err, unix.EPERM) {
		return appMCPPDFWorkerSetupExit
	}
	debug.SetMemoryLimit(pdfStampWorkerMemoryLimit)
	if appMCPPDFSetAddressSpaceLimit(pdfStampWorkerAddressSpaceLimit) != nil {
		return appMCPPDFWorkerSetupExit
	}
	var workerErr error
	if operation == "stamp" {
		workerErr = runPDFStampWorker(os.Stdin, os.Stdout)
	} else if operation == "inspect" {
		workerErr = runPDFInspectWorker(os.Stdin, os.Stdout)
	} else {
		workerErr = errPDFStampWorkerRequest
	}
	if workerErr != nil {
		// Do not return parser internals or document bytes to logs.
		_, _ = os.Stderr.Write([]byte("pdf_stamp_failed\n"))
		return 2
	}
	return 0
}

// appMCPPDFSetAddressSpaceLimit applies a hard total virtual-address ceiling
// after Go has initialized. Unlike the GC target, RLIMIT_AS is kernel-enforced.
func appMCPPDFSetAddressSpaceLimit(limitBytes uint64) error {
	if limitBytes == 0 {
		return errAppMCPPDFUnavailable
	}
	limit := unix.Rlimit{Cur: limitBytes, Max: limitBytes}
	if err := unix.Setrlimit(unix.RLIMIT_AS, &limit); err != nil {
		return errAppMCPPDFUnavailable
	}
	var current unix.Rlimit
	if unix.Getrlimit(unix.RLIMIT_AS, &current) != nil || current.Cur > limitBytes || current.Max > limitBytes {
		return errAppMCPPDFUnavailable
	}
	return nil
}

// appMCPPDFProbe runs the worker's setup sequence without a parser and reports
// 0 only when every step held: empty capabilities, the filesystem ruleset (the
// app directory, readable before, is denied after, while the parsers'
// directory stays readable), the network filter (socket() fails with EPERM) and, last as
// in the worker, the resource limits.
func appMCPPDFProbe(appDir string) int {
	if !filepath.IsAbs(appDir) || filepath.Clean(appDir) != appDir || !appMCPPDFNoCapabilities() {
		return appMCPPDFWorkerSetupExit
	}
	// A denial proves nothing about a directory this process could not read anyway.
	if !appMCPPDFCanOpen(appDir, unix.O_DIRECTORY) {
		return 1
	}
	limits := appMCPPDFResourceLimits(uint64(appMCPPDFMaxTempBytes))
	if err := appMCPPDFConfineFilesystem(""); err != nil {
		return appMCPPDFWorkerSetupExit
	}
	if err := appMCPPDFInstallNetworkFilter(); err != nil {
		return appMCPPDFWorkerSetupExit
	}
	if fd, err := unix.Open(appDir, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0); fd >= 0 || !errors.Is(err, unix.EACCES) {
		if fd >= 0 {
			_ = unix.Close(fd)
		}
		return 1
	}
	if !appMCPPDFCanOpen(filepath.Dir(appMCPPDFTextPath), unix.O_DIRECTORY) {
		return 1
	}
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_STREAM, 0)
	if fd >= 0 {
		_ = unix.Close(fd)
		return 1
	}
	if !errors.Is(err, unix.EPERM) {
		return 1
	}
	if appMCPPDFApplyResourceLimits(limits) != 0 {
		return appMCPPDFWorkerSetupExit
	}
	appMCPPDFRawExit(0)
	return 0
}

func appMCPPDFCanOpen(path string, flags int) bool {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|flags, 0)
	if err != nil {
		return false
	}
	_ = unix.Close(fd)
	return true
}

func appMCPPDFDeniedByLandlock(path string, flags int) bool {
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_CLOEXEC|flags, 0)
	if fd >= 0 {
		_ = unix.Close(fd)
		return false
	}
	return errors.Is(err, unix.EACCES)
}

// Landlock confines the parser's filesystem view. Every filesystem right
// through ABI 3 is handled, so anything a rule below does not grant is denied:
// ABI 3 is the first that also confines truncate(2), so an older kernel counts
// as unavailable rather than leaving the app's files truncatable.
const (
	appMCPPDFLandlockMinABI   = 3
	appMCPPDFLandlockRead     = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_READ_DIR
	appMCPPDFLandlockExecute  = appMCPPDFLandlockRead | unix.LANDLOCK_ACCESS_FS_EXECUTE
	appMCPPDFLandlockExecFile = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_EXECUTE
	appMCPPDFLandlockFileRW   = unix.LANDLOCK_ACCESS_FS_READ_FILE | unix.LANDLOCK_ACCESS_FS_WRITE_FILE | unix.LANDLOCK_ACCESS_FS_TRUNCATE
	appMCPPDFLandlockRunDir   = appMCPPDFLandlockFileRW | unix.LANDLOCK_ACCESS_FS_READ_DIR | unix.LANDLOCK_ACCESS_FS_REMOVE_DIR |
		unix.LANDLOCK_ACCESS_FS_REMOVE_FILE | unix.LANDLOCK_ACCESS_FS_MAKE_DIR | unix.LANDLOCK_ACCESS_FS_MAKE_REG
	appMCPPDFLandlockHandled = appMCPPDFLandlockExecute | appMCPPDFLandlockRunDir | unix.LANDLOCK_ACCESS_FS_MAKE_CHAR |
		unix.LANDLOCK_ACCESS_FS_MAKE_SOCK | unix.LANDLOCK_ACCESS_FS_MAKE_FIFO | unix.LANDLOCK_ACCESS_FS_MAKE_BLOCK |
		unix.LANDLOCK_ACCESS_FS_MAKE_SYM | unix.LANDLOCK_ACCESS_FS_REFER
)

type appMCPPDFLandlockRule struct {
	path   string
	access uint64
}

// appMCPPDFLandlockRules are the only paths a parser may touch: the system
// trees it loads code, configuration, fonts and OCR data from, read-only, and
// /dev/null plus its own run directory read-write. The app directory (data.db,
// .benmore/env, source) is under no rule.
func appMCPPDFLandlockRules(runDir string) []appMCPPDFLandlockRule {
	rules := []appMCPPDFLandlockRule{
		{"/usr", appMCPPDFLandlockExecute}, {"/bin", appMCPPDFLandlockExecute},
		{"/lib", appMCPPDFLandlockExecute}, {"/lib32", appMCPPDFLandlockExecute},
		{"/lib64", appMCPPDFLandlockExecute}, {"/libx32", appMCPPDFLandlockExecute},
		{"/etc", appMCPPDFLandlockRead}, {"/var/cache/fontconfig", appMCPPDFLandlockRead},
		{filepath.Dir(appMCPPDFEnglishData), appMCPPDFLandlockRead},
		{"/dev/null", appMCPPDFLandlockFileRW},
	}
	if runDir != "" {
		rules = append(rules, appMCPPDFLandlockRule{runDir, appMCPPDFLandlockRunDir})
	}
	return rules
}

// appMCPPDFConfineFilesystem restricts the calling thread (and what it execs)
// to appMCPPDFLandlockRules. It fails when Landlock is missing, disabled,
// filtered by the service's syscall policy or older than ABI 3.
func appMCPPDFConfineFilesystem(runDir string) error {
	return appMCPPDFConfineFilesystemForExec(runDir, "")
}

func appMCPPDFConfineFilesystemForExec(runDir, executable string) error {
	abi, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, 0, 0, unix.LANDLOCK_CREATE_RULESET_VERSION)
	if errno != 0 {
		return errno
	}
	if int(abi) < appMCPPDFLandlockMinABI {
		return errors.New("landlock ABI is too old to confine truncate")
	}
	attr := unix.LandlockRulesetAttr{Access_fs: appMCPPDFLandlockHandled}
	// Only handled_access_fs is passed: the size every Landlock ABI accepts.
	rulesetFD, _, errno := unix.Syscall(unix.SYS_LANDLOCK_CREATE_RULESET, uintptr(unsafe.Pointer(&attr)), unsafe.Sizeof(attr.Access_fs), 0)
	if errno != 0 {
		return errno
	}
	defer unix.Close(int(rulesetFD))
	rules := appMCPPDFLandlockRules(runDir)
	if executable != "" {
		if !filepath.IsAbs(executable) || filepath.Clean(executable) != executable {
			return errAppMCPPDFUnavailable
		}
		granted := false
		for _, root := range []string{"/usr", "/bin", "/lib", "/lib32", "/lib64", "/libx32"} {
			rel, err := filepath.Rel(root, executable)
			if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
				granted = true
				break
			}
		}
		if !granted {
			rules = append(rules, appMCPPDFLandlockRule{executable, appMCPPDFLandlockExecFile})
		}
	}
	for _, rule := range rules {
		pathFD, err := unix.Open(rule.path, unix.O_PATH|unix.O_CLOEXEC, 0)
		if errors.Is(err, unix.ENOENT) && rule.path != runDir && rule.path != "/dev/null" {
			continue // an absent system tree grants nothing
		}
		if err != nil {
			return err
		}
		beneath := unix.LandlockPathBeneathAttr{Allowed_access: rule.access, Parent_fd: int32(pathFD)}
		_, _, errno := unix.Syscall6(unix.SYS_LANDLOCK_ADD_RULE, rulesetFD, unix.LANDLOCK_RULE_PATH_BENEATH, uintptr(unsafe.Pointer(&beneath)), 0, 0, 0)
		_ = unix.Close(pathFD)
		if errno != 0 {
			return errno
		}
	}
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	if _, _, errno := unix.Syscall(unix.SYS_LANDLOCK_RESTRICT_SELF, rulesetFD, 0, 0); errno != 0 {
		return errno
	}
	return nil
}

func appMCPPDFNoCapabilities() bool {
	status, err := os.ReadFile("/proc/self/status")
	return err == nil && appMCPPDFCapabilitySetsEmpty(status)
}

func appMCPPDFCapabilitySetsEmpty(status []byte) bool {
	wanted := map[string]bool{"CapInh": false, "CapPrm": false, "CapEff": false, "CapAmb": false}
	for _, line := range strings.Split(string(status), "\n") {
		fields := strings.SplitN(line, ":", 2)
		if len(fields) != 2 {
			continue
		}
		if _, ok := wanted[fields[0]]; !ok {
			continue
		}
		value, err := strconv.ParseUint(strings.TrimSpace(fields[1]), 16, 64)
		if err != nil || value != 0 {
			return false
		}
		wanted[fields[0]] = true
	}
	for _, found := range wanted {
		if !found {
			return false
		}
	}
	return true
}

func appMCPPDFCreateTempRunDir() (string, error) {
	return appMCPPDFCreateTempRunDirUnder(appMCPPDFTempRootPath)
}

func appMCPPDFCreateTempRunDirUnder(root string) (string, error) {
	if !filepath.IsAbs(root) || filepath.Clean(root) != root {
		return "", errAppMCPPDFUnavailable
	}
	if err := os.Mkdir(root, 0700); err != nil && !errors.Is(err, os.ErrExist) {
		return "", errAppMCPPDFUnavailable
	}
	fd, err := unix.Open(root, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return "", errAppMCPPDFUnavailable
	}
	defer unix.Close(fd)
	var rootStat unix.Stat_t
	if err := unix.Fstat(fd, &rootStat); err != nil || rootStat.Uid != uint32(os.Geteuid()) || rootStat.Mode&unix.S_IFMT != unix.S_IFDIR || rootStat.Mode&0777 != 0700 {
		return "", errAppMCPPDFUnavailable
	}
	for attempt := 0; attempt < 3; attempt++ {
		var random [16]byte
		if _, err := rand.Read(random[:]); err != nil {
			return "", errAppMCPPDFUnavailable
		}
		name := "run-" + hex.EncodeToString(random[:])
		if err := unix.Mkdirat(fd, name, 0700); errors.Is(err, unix.EEXIST) {
			continue
		} else if err != nil {
			return "", errAppMCPPDFUnavailable
		}
		dir := filepath.Join(root, name)
		runFD, err := unix.Openat(fd, name, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			_ = unix.Unlinkat(fd, name, unix.AT_REMOVEDIR)
			return "", errAppMCPPDFUnavailable
		}
		var runStat unix.Stat_t
		statErr := unix.Fstat(runFD, &runStat)
		_ = unix.Close(runFD)
		if statErr != nil || runStat.Uid != uint32(os.Geteuid()) || runStat.Mode&unix.S_IFMT != unix.S_IFDIR || runStat.Mode&0777 != 0700 {
			_ = unix.Unlinkat(fd, name, unix.AT_REMOVEDIR)
			return "", errAppMCPPDFUnavailable
		}
		return dir, nil
	}
	return "", errAppMCPPDFUnavailable
}

func appMCPPDFValidatePrivateDir(path string) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 {
		return false
	}
	var stat unix.Stat_t
	if err := unix.Lstat(path, &stat); err != nil {
		return false
	}
	return stat.Uid == uint32(os.Geteuid()) && stat.Mode&unix.S_IFMT == unix.S_IFDIR && stat.Mode&0777 == 0700
}

type appMCPPDFResourceLimit struct {
	resource uintptr
	limit    unix.Rlimit
}

func appMCPPDFResourceLimits(tempBytes uint64) []appMCPPDFResourceLimit {
	limits := []appMCPPDFResourceLimit{
		{unix.RLIMIT_AS, unix.Rlimit{Cur: uint64(appMCPPDFPageMemoryBytes)}},
		{unix.RLIMIT_CPU, unix.Rlimit{Cur: uint64(appMCPPDFPageTimeout.Seconds())}},
		{unix.RLIMIT_FSIZE, unix.Rlimit{Cur: tempBytes}},
	}
	for i := range limits {
		limits[i].limit.Max = limits[i].limit.Cur
	}
	return limits
}

// RLIMIT_AS sits far below the address space the Go runtime has already
// reserved (its page-allocator and scavenger indexes alone reserve more), so
// once it applies every new runtime mapping fails: a thread the scheduler
// starts while this goroutine blocks in a syscall, or a new heap arena, kills
// the helper ("pdf tool failed") before the parser runs. The limits therefore
// come last, and they and execve are raw syscalls on arguments built
// beforehand: nothing between them allocates, enters the scheduler or needs a
// thread. A raw execve skips syscall.Exec's restore of the soft RLIMIT_NOFILE
// that Go raised at startup; the parser may raise that soft limit to the hard
// limit itself anyway, so it grants nothing.
func appMCPPDFApplyResourceLimits(limits []appMCPPDFResourceLimit) syscall.Errno {
	for i := range limits {
		if _, _, errno := unix.RawSyscall6(unix.SYS_PRLIMIT64, 0, limits[i].resource, uintptr(unsafe.Pointer(&limits[i].limit)), 0, 0, 0); errno != 0 {
			return errno
		}
	}
	return 0
}

func appMCPPDFLimitAndExec(limits []appMCPPDFResourceLimit, path *byte, argv, envv []*byte) {
	if appMCPPDFApplyResourceLimits(limits) != 0 {
		appMCPPDFRawExit(appMCPPDFWorkerSetupExit)
	}
	unix.RawSyscall(unix.SYS_EXECVE, uintptr(unsafe.Pointer(path)), uintptr(unsafe.Pointer(&argv[0])), uintptr(unsafe.Pointer(&envv[0])))
	runtime.KeepAlive(limits)
	runtime.KeepAlive(path)
	runtime.KeepAlive(argv)
	runtime.KeepAlive(envv)
	appMCPPDFRawExit(127)
}

// appMCPPDFRawExit leaves without os.Exit's hooks, which may allocate.
func appMCPPDFRawExit(code int) {
	unix.RawSyscall(unix.SYS_EXIT_GROUP, uintptr(code), 0, 0)
}

func appMCPPDFBlockedSyscalls() []uint32 {
	return []uint32{
		unix.SYS_SOCKET, unix.SYS_SOCKETPAIR, unix.SYS_CONNECT, unix.SYS_BIND,
		unix.SYS_LISTEN, unix.SYS_ACCEPT, unix.SYS_ACCEPT4, unix.SYS_SENDTO,
		unix.SYS_RECVFROM, unix.SYS_SENDMSG, unix.SYS_RECVMSG, unix.SYS_SHUTDOWN,
		unix.SYS_GETSOCKNAME, unix.SYS_GETPEERNAME, unix.SYS_SETSOCKOPT,
		unix.SYS_GETSOCKOPT, unix.SYS_SENDMMSG, unix.SYS_RECVMMSG,
		unix.SYS_IO_URING_SETUP, unix.SYS_IO_URING_ENTER, unix.SYS_IO_URING_REGISTER,
		unix.SYS_PIDFD_GETFD, unix.SYS_PTRACE, unix.SYS_PROCESS_VM_READV, unix.SYS_PROCESS_VM_WRITEV,
		// request_key upcalls run a host helper outside this filter; with
		// keyutils installed the dns_resolver type makes it resolve an
		// attacker-chosen name, a DNS channel out of the sandbox. Poppler and
		// Tesseract never use kernel keyrings.
		unix.SYS_ADD_KEY, unix.SYS_REQUEST_KEY, unix.SYS_KEYCTL,
	}
}

func appMCPPDFInstallNetworkFilter() error {
	if err := unix.Prctl(unix.PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); err != nil {
		return err
	}
	blocked := appMCPPDFBlockedSyscalls()
	filter := make([]unix.SockFilter, 0, 6+len(blocked)*2)
	auditArch := uint32(unix.AUDIT_ARCH_AARCH64)
	if runtime.GOARCH == "amd64" {
		auditArch = unix.AUDIT_ARCH_X86_64
	}
	filter = append(filter,
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 4}, // seccomp_data.arch
		unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: auditArch, Jt: 1},
		unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		unix.SockFilter{Code: unix.BPF_LD | unix.BPF_W | unix.BPF_ABS, K: 0}, // seccomp_data.nr
	)
	if runtime.GOARCH == "amd64" {
		filter = append(filter,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JSET | unix.BPF_K, K: 0x40000000, Jf: 1},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_KILL_PROCESS},
		)
	}
	for _, syscallNumber := range blocked {
		filter = append(filter,
			unix.SockFilter{Code: unix.BPF_JMP | unix.BPF_JEQ | unix.BPF_K, K: syscallNumber, Jf: 1},
			unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ERRNO | uint32(unix.EPERM)},
		)
	}
	filter = append(filter, unix.SockFilter{Code: unix.BPF_RET | unix.BPF_K, K: unix.SECCOMP_RET_ALLOW})
	program := unix.SockFprog{Len: uint16(len(filter)), Filter: &filter[0]}
	result, _, errno := unix.Syscall(unix.SYS_SECCOMP, unix.SECCOMP_SET_MODE_FILTER, unix.SECCOMP_FILTER_FLAG_TSYNC, uintptr(unsafe.Pointer(&program)))
	runtime.KeepAlive(filter)
	runtime.KeepAlive(program)
	if errno != 0 {
		return errno
	}
	if result != 0 {
		return errors.New("seccomp filter could not synchronize all threads")
	}
	return nil
}

// appMCPPDFIsolationAvailable reports whether a parser child can run fully
// confined, proving with appDir that the app's own directory is unreadable.
func appMCPPDFIsolationAvailable(appDir string) bool {
	if appDir == "" {
		return false
	}
	appDir, err := filepath.Abs(appDir)
	if err != nil {
		return false
	}
	executable, err := appMCPPDFWorkerExecutable()
	if err != nil {
		return false
	}
	// The probe starts a fresh copy of this (large) binary. Under the hosted
	// units' CPU quota its start-up alone can take seconds; a timeout only
	// ever makes PDF unavailable, so it is generous rather than tight.
	ctx, cancel := context.WithTimeout(context.Background(), appMCPPDFProbeTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, appMCPPDFWorkerInvocationArgs(executable, []string{"--probe", appDir})...)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TMPDIR=/tmp"}
	cmd.WaitDelay = time.Second
	return cmd.Run() == nil
}

func appMCPPDFRestrictedCommand(ctx context.Context, binary string, args []string, tempBytes int64, tempDir string) (*exec.Cmd, error) {
	if tempBytes < 1 || tempBytes > appMCPPDFMaxTempBytes || tempDir == "" {
		return nil, errAppMCPPDFUnavailable
	}
	executable, err := appMCPPDFWorkerExecutable()
	if err != nil {
		return nil, errAppMCPPDFUnavailable
	}
	argvBytes := len(binary) + len(tempDir)
	for _, arg := range args {
		argvBytes += len(arg) + 1
	}
	if argvBytes > 128<<10 {
		return nil, errAppMCPPDFUnavailable
	}
	workerArgs := appMCPPDFWorkerArgs(tempBytes, tempDir, binary, args)
	if workerArgs == nil {
		return nil, errAppMCPPDFUnavailable
	}
	cmd := exec.CommandContext(ctx, executable, appMCPPDFWorkerInvocationArgs(executable, workerArgs)...)
	cmd.Dir = tempDir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TMPDIR=" + tempDir}
	// os/exec closes every descriptor except stdin/stdout/stderr; no app sockets
	// or database descriptors cross this exec boundary.
	return cmd, nil
}

func appMCPPDFStampRestrictedCommand(ctx context.Context, runDir, appDir string) (*exec.Cmd, error) {
	return appMCPPDFRestrictedPDFCommand(ctx, runDir, appDir, "--stamp")
}

func appMCPPDFInspectRestrictedCommand(ctx context.Context, runDir, appDir string) (*exec.Cmd, error) {
	return appMCPPDFRestrictedPDFCommand(ctx, runDir, appDir, "--inspect")
}

func appMCPPDFRestrictedPDFCommand(ctx context.Context, runDir, appDir, mode string) (*exec.Cmd, error) {
	if ctx == nil || ctx.Err() != nil || runDir == "" || filepath.Clean(runDir) != runDir || filepath.Dir(runDir) != appMCPPDFTempRootPath || !appMCPPDFValidatePrivateDir(runDir) ||
		appDir == "" || !filepath.IsAbs(appDir) || filepath.Clean(appDir) != appDir || (mode != "--stamp" && mode != "--inspect") {
		return nil, errAppMCPPDFUnavailable
	}
	executable, err := appMCPPDFWorkerExecutable()
	if err != nil {
		return nil, errAppMCPPDFUnavailable
	}
	cmd := exec.CommandContext(ctx, executable, appMCPPDFWorkerInvocationArgs(executable, []string{mode, runDir, appDir})...)
	cmd.Dir = runDir
	cmd.Env = []string{"PATH=/usr/bin:/bin", "LANG=C", "LC_ALL=C", "TMPDIR=" + runDir}
	return cmd, nil
}

func appMCPPDFWorkerFailure(err error) bool {
	var exitErr *exec.ExitError
	return errors.As(err, &exitErr) && exitErr.ExitCode() == appMCPPDFWorkerSetupExit
}
