//go:build !cli && !windows

package main

// Tests for the `run: transcribe` engine (transcribe.go). All integration
// tests use FAKE ffmpeg / whisper-cli shell scripts dropped into a temp dir
// that is prepended to PATH - no real binaries, no real model, no network.
// The one real-model test (TestTranscribeRealModel) is opt-in via
// WHISPER_REAL_TEST=1.
//
// Windows is excluded: the fakes are POSIX sh scripts and the process-group
// kill assertions use unix signals (mirrors the fileowner_unix.go seam).

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// writeFakeBin drops an executable POSIX sh script named `name` into dir.
func writeFakeBin(t *testing.T, dir, name, script string) {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+script+"\n"), 0o755); err != nil {
		t.Fatalf("write fake %s: %v", name, err)
	}
}

// fakeFfmpegScript copies the `-i` input arg to the last arg (the wav path),
// mirroring the real exec contract's decode step.
const fakeFfmpegScript = `in=""; prev=""; last=""
for a in "$@"; do
  if [ "$prev" = "-i" ]; then in="$a"; fi
  prev="$a"; last="$a"
done
cp "$in" "$last"`

// fakeWhisperScript writes a known transcript into <--output-file value>.txt.
const fakeWhisperScript = `out=""; prev=""
for a in "$@"; do
  if [ "$prev" = "--output-file" ]; then out="$a"; fi
  prev="$a"
done
printf 'hello from whisper' > "$out.txt"`

// setFakePATH points PATH at binDir plus the system dirs (for `nice` and
// `sh` utilities like cp). whisper-cli never lives in /usr/bin or /bin, and
// any real ffmpeg there is shadowed by the fake in binDir.
func setFakePATH(t *testing.T, binDir string) {
	t.Helper()
	t.Setenv("PATH", binDir+":/usr/bin:/bin")
}

// seedModel creates a dummy ggml model file and points WHISPER_MODEL_DIR at
// its dir so the pre-exec model existence check passes.
func seedModel(t *testing.T, model string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "ggml-"+model+".bin")
	if err := os.WriteFile(p, []byte("fake-model"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHISPER_MODEL_DIR", dir)
	return p
}

// seedUpload writes uploads/<name> inside the app dir and returns its
// app-relative path.
func seedUpload(t *testing.T, app *App, name string) string {
	t.Helper()
	rel := filepath.Join("uploads", name)
	full := filepath.Join(app.Dir, rel)
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte("fake-audio-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}
	return rel
}

func TestTranscribeHappyPathLocalFile(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	binDir := t.TempDir()
	writeFakeBin(t, binDir, "ffmpeg", fakeFfmpegScript)
	writeFakeBin(t, binDir, "whisper-cli", fakeWhisperScript)
	setFakePATH(t, binDir)
	seedModel(t, "small.en")

	// Redirect the engine's os.MkdirTemp workspace into a dir we can
	// inspect, so we can assert the temp workspace is cleaned up.
	scratch := t.TempDir()
	t.Setenv("TMPDIR", scratch)

	rel := seedUpload(t, app, "brief.webm")

	res, err := RunTranscribe(context.Background(), app, rel, "", "")
	if err != nil {
		t.Fatalf("RunTranscribe: %v", err)
	}
	if res.Text != "hello from whisper" {
		t.Errorf("Text = %q, want %q", res.Text, "hello from whisper")
	}
	if res.AudioPath != rel {
		t.Errorf("AudioPath = %q, want %q", res.AudioPath, rel)
	}

	// Temp workspace removed afterward.
	entries, err := os.ReadDir(scratch)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "benmore-transcribe") {
			t.Errorf("temp workspace %s not cleaned up", e.Name())
		}
	}
}

func TestTranscribeMissingWhisperBinary(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	binDir := t.TempDir()
	writeFakeBin(t, binDir, "ffmpeg", fakeFfmpegScript)
	// PATH deliberately contains ONLY the fake dir - no whisper-cli
	// anywhere. (No system dirs: some hosts have /usr/bin/ffmpeg but
	// none ship whisper-cli; keeping the PATH minimal makes both
	// missing-binary tests deterministic.)
	t.Setenv("PATH", binDir)
	seedModel(t, "small.en")

	_, err := RunTranscribe(context.Background(), app, seedUpload(t, app, "a.webm"), "", "")
	if err == nil {
		t.Fatal("expected error for missing whisper-cli")
	}
	for _, want := range []string{"WHISPER_BIN", "install"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
}

func TestTranscribeMissingFfmpeg(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	binDir := t.TempDir()
	writeFakeBin(t, binDir, "whisper-cli", fakeWhisperScript)
	t.Setenv("PATH", binDir)
	seedModel(t, "small.en")

	_, err := RunTranscribe(context.Background(), app, seedUpload(t, app, "a.webm"), "", "")
	if err == nil {
		t.Fatal("expected error for missing ffmpeg")
	}
	if !strings.Contains(err.Error(), "FFMPEG_BIN") {
		t.Errorf("error %q does not name FFMPEG_BIN", err)
	}
}

func TestTranscribeTimeoutKillsProcessGroup(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	binDir := t.TempDir()
	pidFile := filepath.Join(t.TempDir(), "grandchild.pid")
	writeFakeBin(t, binDir, "ffmpeg", fakeFfmpegScript)
	// Fake whisper spawns a background GRANDCHILD (`sleep 60 &`), records
	// the GRANDCHILD's pid, and waits on it. Probing the grandchild is
	// what gives this test teeth: exec.CommandContext's DEFAULT cancel
	// kills only the direct child (the sh script), which would leave the
	// grandchild orphaned - every earlier assertion (timeout error,
	// prompt elapsed, direct-child death) passes under that mutant. Only
	// the group kill (Setpgid + Kill(-pid), transcribe_unix.go) reaches
	// the grandchild, so removing it turns this test red.
	writeFakeBin(t, binDir, "whisper-cli",
		fmt.Sprintf("sleep 60 &\necho $! > %q\nwait", pidFile))
	setFakePATH(t, binDir)
	seedModel(t, "small.en")
	t.Setenv("TRANSCRIBE_TIMEOUT", "1s")

	start := time.Now()
	_, err := RunTranscribe(context.Background(), app, seedUpload(t, app, "a.webm"), "", "")
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("expected timeout error")
	}
	if elapsed > 10*time.Second {
		t.Errorf("timeout took %s - subprocess was not killed promptly", elapsed)
	}
	if !strings.Contains(err.Error(), "TRANSCRIBE_TIMEOUT") {
		t.Errorf("timeout error %q should name TRANSCRIBE_TIMEOUT (the remedy)", err)
	}

	// No orphan: the GRANDCHILD must be gone. It is two forks below the
	// exec'd process (nice → sh → sleep), so only the process-group kill
	// can have reached it.
	raw, readErr := os.ReadFile(pidFile)
	if readErr != nil {
		t.Fatalf("fake whisper never ran: %v", readErr)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(raw)))
	if pid <= 0 {
		t.Fatalf("bad pid %q", raw)
	}
	// Best-effort reap if the assertion below fails - don't leave a
	// 60s sleep on the host.
	t.Cleanup(func() { _ = syscall.Kill(pid, syscall.SIGKILL) })
	deadline := time.Now().Add(5 * time.Second)
	for {
		if processTerminated(pid) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("orphaned grandchild process %d still alive after timeout - the group kill did not reach it", pid)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// processTerminated reports whether pid no longer runs. kill(pid, 0)
// alone is NOT a liveness probe on Linux: it returns success for an
// unreaped ZOMBIE, and whether a SIGKILLed orphan gets reaped inside
// our probe window depends entirely on the environment's PID 1 /
// subreaper (GitHub Actions' runner holds zombies long enough to flake
// this test; macOS reaps immediately, which is why the gap never
// showed locally). A zombie means the signal WAS delivered and the
// process is dead - exactly what the kill test asserts - so state Z/X
// counts as terminated. On platforms without /proc (macOS) the ESRCH
// check alone is sufficient because reaping there is prompt.
func processTerminated(pid int) bool {
	if err := syscall.Kill(pid, 0); err != nil {
		return true // ESRCH: gone (EPERM impossible for our own descendant)
	}
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return false // no /proc (macOS): kill(0) success == genuinely alive
	}
	// /proc/<pid>/stat is "pid (comm) STATE ..." - comm may contain
	// spaces/parens, so take the first field after the LAST ')'.
	s := string(stat)
	i := strings.LastIndexByte(s, ')')
	if i < 0 || i+2 >= len(s) {
		return false
	}
	state := s[i+2]
	return state == 'Z' || state == 'X'
}

func TestTranscribePathEscapeRejected(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	binDir := t.TempDir()
	invocations := filepath.Join(t.TempDir(), "invocations.log")
	record := fmt.Sprintf("echo invoked >> %q", invocations)
	writeFakeBin(t, binDir, "ffmpeg", record)
	writeFakeBin(t, binDir, "whisper-cli", record)
	setFakePATH(t, binDir)
	seedModel(t, "small.en")

	// Containment root is <app>/uploads, not the app dir (serve_file
	// parity): traversal OUT of uploads/ is rejected even when the
	// target is still inside the app dir (env.yaml, data.db).
	for _, in := range []string{"../../etc/passwd", "uploads/../env.yaml", "../data.db", "/etc/passwd"} {
		_, err := RunTranscribe(context.Background(), app, in, "", "")
		if err == nil {
			t.Fatalf("input %q: expected path-escape error", in)
		}
		if !strings.Contains(err.Error(), "escapes") {
			t.Errorf("input %q: error %q should say the path escapes the uploads/ directory", in, err)
		}
	}

	// A real file at the app ROOT (outside uploads/) is unreachable:
	// the input is rooted into uploads/, where it doesn't exist.
	if err := os.WriteFile(filepath.Join(app.Dir, "notes.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := RunTranscribe(context.Background(), app, "notes.txt", "", "")
	if err == nil {
		t.Fatal("expected app-root file (outside uploads/) to be unreachable")
	}
	if !strings.Contains(err.Error(), "uploads/") {
		t.Errorf("error %q should point at the uploads/ containment root", err)
	}

	if _, statErr := os.Stat(invocations); !os.IsNotExist(statErr) {
		t.Errorf("a binary was exec'd despite the path rejection (log exists: %v)", statErr)
	}
}

func TestTranscribeModelNameRejectsPathSeparators(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	binDir := t.TempDir()
	writeFakeBin(t, binDir, "ffmpeg", fakeFfmpegScript)
	writeFakeBin(t, binDir, "whisper-cli", fakeWhisperScript)
	setFakePATH(t, binDir)
	seedModel(t, "small.en")
	rel := seedUpload(t, app, "a.webm")

	// `model` is a name, not a path: ggml-a/../../x.bin would clean to
	// a file OUTSIDE WHISPER_MODEL_DIR.
	for _, m := range []string{"a/../../x", "../evil", `a\..\..\x`, "sub/model"} {
		_, err := RunTranscribe(context.Background(), app, rel, m, "")
		if err == nil {
			t.Fatalf("model %q: expected invalid-model-name error", m)
		}
		if !strings.Contains(err.Error(), "invalid model name") {
			t.Errorf("model %q: error %q should say invalid model name", m, err)
		}
	}

	// Dots WITHIN a name (small.en, base.en) stay valid.
	if _, err := RunTranscribe(context.Background(), app, rel, "small.en", ""); err != nil {
		t.Errorf("model small.en should be accepted: %v", err)
	}
}

func TestTranscribeSerializedPerProcess(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	binDir := t.TempDir()
	logFile := filepath.Join(t.TempDir(), "windows.log")
	writeFakeBin(t, binDir, "ffmpeg", fakeFfmpegScript)
	// Fake whisper marks its execution window in a shared log. If two
	// invocations overlap, the log shows start,start,... interleaving.
	writeFakeBin(t, binDir, "whisper-cli", fmt.Sprintf(
		"echo start >> %[1]q\nsleep 0.3\n"+fakeWhisperScript+"\necho end >> %[1]q", logFile))
	setFakePATH(t, binDir)
	seedModel(t, "small.en")

	relA := seedUpload(t, app, "a.webm")
	relB := seedUpload(t, app, "b.webm")

	var wg sync.WaitGroup
	errs := make([]error, 2)
	for i, rel := range []string{relA, relB} {
		wg.Add(1)
		go func(i int, rel string) {
			defer wg.Done()
			_, errs[i] = RunTranscribe(context.Background(), app, rel, "", "")
		}(i, rel)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("call %d: %v", i, err)
		}
	}

	raw, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatal(err)
	}
	got := strings.Fields(string(raw))
	want := []string{"start", "end", "start", "end"}
	if len(got) != len(want) {
		t.Fatalf("execution log = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("execution windows overlap - log = %v, want %v (semaphore not serializing)", got, want)
		}
	}
}

func TestTranscribeModelPathResolution(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	binDir := t.TempDir()
	argvFile := filepath.Join(t.TempDir(), "argv.log")
	writeFakeBin(t, binDir, "ffmpeg", fakeFfmpegScript)
	writeFakeBin(t, binDir, "whisper-cli",
		fmt.Sprintf("echo \"$@\" > %q\n", argvFile)+fakeWhisperScript)
	setFakePATH(t, binDir)

	modelDir := t.TempDir()
	modelPath := filepath.Join(modelDir, "ggml-base.en.bin")
	if err := os.WriteFile(modelPath, []byte("fake-model"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WHISPER_MODEL", "base.en")
	t.Setenv("WHISPER_MODEL_DIR", modelDir)

	rel := seedUpload(t, app, "a.webm")
	if _, err := RunTranscribe(context.Background(), app, rel, "", ""); err != nil {
		t.Fatalf("RunTranscribe: %v", err)
	}
	argv, err := os.ReadFile(argvFile)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(argv), "-m "+modelPath) {
		t.Errorf("whisper argv %q does not carry -m %s", argv, modelPath)
	}

	// Missing model file → actionable error naming the expected path and
	// the download URL pattern.
	if err := os.Remove(modelPath); err != nil {
		t.Fatal(err)
	}
	_, err = RunTranscribe(context.Background(), app, rel, "", "")
	if err == nil {
		t.Fatal("expected missing-model error")
	}
	for _, want := range []string{modelPath, "huggingface.co/ggerganov/whisper.cpp"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("missing-model error %q does not contain %q", err, want)
		}
	}
}

// ---- URL-input branch (downloadTranscribeURL / fetchTranscribeURL) ----
//
// The full URL→transcription pipeline cannot run under test: the
// production path uses safeHTTPClientStrict, which fail-closes on
// loopback (httptest) at BOTH the isPrivateURL pre-check and dial time,
// and this codebase deliberately has no resolver-stub seam (see the
// identical note for run: api at flows_test.go). So the branch is
// covered in two halves: the SSRF pre-check is asserted against a real
// loopback server (which proves the guard), and the download semantics
// (bytes land, HTTP ≥ 400, size cap, temp cleanup) are asserted on
// fetchTranscribeURL with an injected client + cap.

func TestTranscribeURLPrivateIPRejected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("SSRF pre-check let the request reach the server")
	}))
	defer srv.Close()

	// httptest binds 127.0.0.1 - exactly the private/internal shape the
	// pre-check must reject, before any request is made.
	_, _, err := downloadTranscribeURL(context.Background(), srv.URL, transcribeConfig())
	if err == nil {
		t.Fatal("expected private-IP URL to be rejected")
	}
	if !strings.Contains(err.Error(), "private/internal") {
		t.Errorf("error %q should name the private/internal block", err)
	}
}

func TestTranscribeURLDownloadHappyPath(t *testing.T) {
	const audio = "fake-audio-bytes-from-cdn"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(audio))
	}))
	defer srv.Close()

	path, cleanup, err := fetchTranscribeURL(context.Background(), srv.Client(), srv.URL, maxAudioDownload)
	if err != nil {
		t.Fatalf("fetchTranscribeURL: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read downloaded file: %v", err)
	}
	if string(got) != audio {
		t.Errorf("downloaded bytes = %q, want %q", got, audio)
	}
	cleanup()
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Errorf("cleanup left the temp download %s behind", path)
	}
}

func TestTranscribeURLDownloadHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "boom", http.StatusInternalServerError)
	}))
	defer srv.Close()

	scratch := t.TempDir()
	t.Setenv("TMPDIR", scratch)

	_, _, err := fetchTranscribeURL(context.Background(), srv.Client(), srv.URL, maxAudioDownload)
	if err == nil {
		t.Fatal("expected error for HTTP 500")
	}
	for _, want := range []string{"500", "publicly readable"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not contain %q", err, want)
		}
	}
	assertNoTranscribeTempLeft(t, scratch)
}

func TestTranscribeURLDownloadSizeCapEnforced(t *testing.T) {
	big := bytes.Repeat([]byte("a"), 4096)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(big)
	}))
	defer srv.Close()

	scratch := t.TempDir()
	t.Setenv("TMPDIR", scratch)

	// maxBytes is a parameter precisely so the cap is testable without
	// serving a real 1GB body; production passes maxAudioDownload.
	_, _, err := fetchTranscribeURL(context.Background(), srv.Client(), srv.URL, 1024)
	if err == nil {
		t.Fatal("expected error for over-cap download")
	}
	if !strings.Contains(err.Error(), "cap") {
		t.Errorf("error %q should name the size cap", err)
	}
	assertNoTranscribeTempLeft(t, scratch)
}

// assertNoTranscribeTempLeft fails the test if a benmore-transcribe-dl
// temp file survived in dir - error paths must clean up their partial
// download.
func assertNoTranscribeTempLeft(t *testing.T, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "benmore-transcribe-dl") {
			t.Errorf("temp download %s not cleaned up on the error path", e.Name())
		}
	}
}

// TestTranscribeRealModel exercises real ffmpeg + whisper-cli + a real ggml
// model. Opt-in: WHISPER_REAL_TEST=1 plus binaries on PATH and the model
// present. Sample defaults to whisper.cpp's samples/jfk.wav convention -
// point WHISPER_REAL_SAMPLE at a local audio file.
func TestTranscribeRealModel(t *testing.T) {
	if os.Getenv("WHISPER_REAL_TEST") != "1" {
		t.Skip("set WHISPER_REAL_TEST=1 (and WHISPER_REAL_SAMPLE=/path/to/jfk.wav) to run the real-model test")
	}
	sample := os.Getenv("WHISPER_REAL_SAMPLE")
	if sample == "" {
		t.Skip("WHISPER_REAL_SAMPLE not set - point it at whisper.cpp samples/jfk.wav")
	}
	app, cleanup := newTestApp(t)
	defer cleanup()

	raw, err := os.ReadFile(sample)
	if err != nil {
		t.Fatalf("read sample: %v", err)
	}
	rel := filepath.Join("uploads", filepath.Base(sample))
	if err := os.MkdirAll(filepath.Join(app.Dir, "uploads"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.Dir, rel), raw, 0o644); err != nil {
		t.Fatal(err)
	}

	res, err := RunTranscribe(context.Background(), app, rel, "", "")
	if err != nil {
		t.Fatalf("RunTranscribe: %v", err)
	}
	if strings.TrimSpace(res.Text) == "" {
		t.Error("real transcription returned empty text")
	}
	t.Logf("real transcript: %s", res.Text)
}
