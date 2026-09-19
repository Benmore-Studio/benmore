//go:build !cli

package main

// transcribe.go - the `run: transcribe` engine: local audio→text via
// prebuilt host binaries (ffmpeg for decode→16kHz mono WAV, whisper-cli
// from whisper.cpp for inference). Exec, not CGo: zero build-system
// impact, crash isolation (a whisper segfault can't hurt the app
// process), upgrades = replace a binary on the host. No vendor, no API
// key - every edition ships it (this file is runtime-untagged like the
// rest of the flow engine).
//
// Exec contract (pinned by transcribe_test.go - do not parse stdout,
// it is version-dependent noise; the transcript is read from the
// --output-file .txt):
//
//	ffmpeg -nostdin -y -i <in> -ar 16000 -ac 1 -f wav <tmp.wav>
//	whisper-cli -m <model> -f <tmp.wav> --output-txt --output-file <base> --threads <N>
//
// Both invocations are argv slices - never a shell string. The whisper
// call is wrapped in `nice -n <level>` on unix (transcribe_unix.go) so
// inference can't starve the app process.
//
// Resource posture: one concurrent transcription per app process
// (transcribeSem), capped threads, subprocess in its own process group
// so a context timeout kills ffmpeg/whisper AND their children.

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"net/http"
	neturl "net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// TranscribeResult is what a `run: transcribe` step publishes:
// steps.<id>.outputs.text and steps.<id>.outputs.audio_path.
type TranscribeResult struct {
	Text      string // transcript, whitespace-trimmed
	AudioPath string // the app-relative input path (or the source URL)
}

// transcribeSem serializes transcriptions per app process. Whisper
// inference is CPU-bound; running two at once on a shared host doubles
// the wall time of both and starves the app. A queued second job WAITS
// (subject to the caller's context deadline) - it does not fail.
var transcribeSem = make(chan struct{}, 1)

// transcribeCfg carries the env-resolved knobs. All optional with sane
// defaults - see transcribeConfig.
type transcribeCfg struct {
	ffmpegBin  string        // FFMPEG_BIN (default "ffmpeg" from PATH)
	whisperBin string        // WHISPER_BIN (default "whisper-cli" from PATH)
	model      string        // WHISPER_MODEL (default "small.en")
	modelDir   string        // WHISPER_MODEL_DIR (default /opt/benmore/models, fallback ./models)
	timeout    time.Duration // TRANSCRIBE_TIMEOUT (default 10m)
	threads    int           // TRANSCRIBE_THREADS (default 2)
	nice       int           // TRANSCRIBE_NICE (default 19)
}

// transcribeConfig resolves the engine's env vars with defaults. Invalid
// values fall back to the default rather than erroring - a typo'd
// TRANSCRIBE_TIMEOUT shouldn't take transcription down entirely.
func transcribeConfig() transcribeCfg {
	cfg := transcribeCfg{
		ffmpegBin:  "ffmpeg",
		whisperBin: "whisper-cli",
		model:      "small.en",
		modelDir:   "/opt/benmore/models",
		timeout:    10 * time.Minute,
		threads:    2,
		nice:       19,
	}
	if v := strings.TrimSpace(os.Getenv("FFMPEG_BIN")); v != "" {
		cfg.ffmpegBin = v
	}
	if v := strings.TrimSpace(os.Getenv("WHISPER_BIN")); v != "" {
		cfg.whisperBin = v
	}
	if v := strings.TrimSpace(os.Getenv("WHISPER_MODEL")); v != "" {
		cfg.model = v
	}
	if v := strings.TrimSpace(os.Getenv("WHISPER_MODEL_DIR")); v != "" {
		cfg.modelDir = v
	} else if _, err := os.Stat(cfg.modelDir); err != nil {
		// Default dir absent (dev laptop, self-hosted box) → fall back
		// to ./models relative to the process working dir.
		cfg.modelDir = "./models"
	}
	if v := strings.TrimSpace(os.Getenv("TRANSCRIBE_TIMEOUT")); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			cfg.timeout = d
		}
	}
	if v := strings.TrimSpace(os.Getenv("TRANSCRIBE_THREADS")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.threads = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("TRANSCRIBE_NICE")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			cfg.nice = n
		}
	}
	return cfg
}

// RunTranscribe converts `input` (an app-relative path like
// uploads/brief.webm, or a public http(s) URL) to text using local
// ffmpeg + whisper-cli. `model` overrides WHISPER_MODEL for this call;
// `language` (optional) is passed to whisper as `-l <lang>`. Blocks
// until the per-process slot is free; the config timeout (or the
// caller's earlier ctx deadline) bounds the whole call including the
// wait.
func RunTranscribe(ctx context.Context, app *App, input, model, language string) (TranscribeResult, error) {
	var zero TranscribeResult
	cfg := transcribeConfig()
	if m := strings.TrimSpace(model); m != "" {
		cfg.model = m
	}
	// `model` is a NAME (it resolves to ggml-<model>.bin inside
	// WHISPER_MODEL_DIR), never a path. Reject separators and `..` so a
	// flow-authored `model: a/../../x` can't clean to a file outside the
	// model dir.
	if strings.ContainsAny(cfg.model, `/\`) || strings.Contains(cfg.model, "..") {
		return zero, fmt.Errorf("transcribe: invalid model name %q - use a bare model name like base.en (it resolves to ggml-<model>.bin inside WHISPER_MODEL_DIR), not a path", cfg.model)
	}

	// Preflight the host dependencies before touching the input - the
	// error messages ARE the install runbook.
	ffmpegPath, err := exec.LookPath(cfg.ffmpegBin)
	if err != nil {
		return zero, fmt.Errorf("transcribe: ffmpeg not found (%q) - install ffmpeg (apt-get install ffmpeg / brew install ffmpeg) or set FFMPEG_BIN to the binary path: %w", cfg.ffmpegBin, err)
	}
	whisperPath, err := exec.LookPath(cfg.whisperBin)
	if err != nil {
		return zero, fmt.Errorf("transcribe: whisper-cli not found (%q) - install whisper.cpp (https://github.com/ggml-org/whisper.cpp) or set WHISPER_BIN to the binary path: %w", cfg.whisperBin, err)
	}
	modelPath := filepath.Join(cfg.modelDir, "ggml-"+cfg.model+".bin")
	if _, statErr := os.Stat(modelPath); statErr != nil {
		return zero, fmt.Errorf("transcribe: whisper model %q not found at %s - download it: https://huggingface.co/ggerganov/whisper.cpp/resolve/main/ggml-%s.bin (or set WHISPER_MODEL / WHISPER_MODEL_DIR)", cfg.model, modelPath, cfg.model)
	}

	// The config timeout bounds everything below: the wait for the
	// per-process slot, input download, and both subprocesses. Callers
	// with a tighter deadline (async job budget) keep theirs.
	ctx, cancel := context.WithTimeout(ctx, cfg.timeout)
	defer cancel()

	// One transcription per app process, acquired BEFORE the input is
	// downloaded: a queued request must not hold up to 1GB of temp disk
	// (maxAudioDownload) while it waits its turn - with N concurrent
	// triggers all downloading before waiting, worst case was N GB of
	// temp disk on a shared host. select honors the context so a queued
	// job waits instead of failing, but not past its deadline (the same
	// ctx the download and subprocesses below are bounded by).
	select {
	case transcribeSem <- struct{}{}:
		defer func() { <-transcribeSem }()
	case <-ctx.Done():
		return zero, fmt.Errorf("transcribe: timed out waiting for the transcription slot (one runs at a time per app; raise TRANSCRIBE_TIMEOUT if recordings are long): %w", ctx.Err())
	}

	srcPath, audioRef, srcCleanup, err := resolveTranscribeInput(ctx, app, input, cfg)
	if err != nil {
		return zero, err
	}
	defer srcCleanup()

	workDir, err := os.MkdirTemp("", "benmore-transcribe-*")
	if err != nil {
		return zero, fmt.Errorf("transcribe: create temp workspace: %w", err)
	}
	defer os.RemoveAll(workDir)

	// Decode → 16kHz mono WAV (the input whisper.cpp expects).
	wavPath := filepath.Join(workDir, "audio.wav")
	ffmpegArgv := []string{ffmpegPath, "-nostdin", "-y", "-i", srcPath, "-ar", "16000", "-ac", "1", "-f", "wav", wavPath}
	if err := runTranscribeCmd(ctx, ffmpegArgv, "ffmpeg (audio decode)"); err != nil {
		return zero, err
	}

	// Inference. Wrapped in `nice` (unix) so it can't starve the app;
	// transcript lands at <outBase>.txt - stdout is never parsed.
	outBase := filepath.Join(workDir, "transcript")
	whisperArgv := append(transcribeNicePrefix(cfg.nice),
		whisperPath, "-m", modelPath, "-f", wavPath,
		"--output-txt", "--output-file", outBase,
		"--threads", strconv.Itoa(cfg.threads))
	if lang := strings.TrimSpace(language); lang != "" {
		whisperArgv = append(whisperArgv, "-l", lang)
	}
	if err := runTranscribeCmd(ctx, whisperArgv, "whisper-cli (inference)"); err != nil {
		return zero, err
	}

	raw, err := os.ReadFile(outBase + ".txt")
	if err != nil {
		return zero, fmt.Errorf("transcribe: whisper-cli produced no transcript at %s.txt - the binary may be too old for --output-txt/--output-file; rebuild whisper.cpp from a current checkout: %w", outBase, err)
	}
	return TranscribeResult{Text: strings.TrimSpace(string(raw)), AudioPath: audioRef}, nil
}

// execStepTranscribe runs a `run: transcribe` flow step. The step's
// `with:` values go through the same ${{ }} resolvers as `run: api`
// fields (interpolateCtx for step outputs/params, InterpolateEnv for
// env refs). Outputs are published exactly like an api step's envelope:
// steps.<id>.outputs.text + steps.<id>.outputs.audio_path.
//
// Context: an HTTP-triggered flow inherits the request's lifetime; an
// async/job-triggered flow (ctx.Request == nil) has no per-step
// deadline, so RunTranscribe's own TRANSCRIBE_TIMEOUT (default 10m)
// bounds the call in both shapes.
func execStepTranscribe(ctx *FlowContext, step *FlowStep) error {
	cfg := step.Transcribe
	if cfg == nil || strings.TrimSpace(cfg.File) == "" {
		return fmt.Errorf("transcribe step missing `with.file:` - point it at an uploaded audio file, e.g. file: uploads/brief.webm (or ${{ steps.item.outputs.audio_url }})")
	}
	file := strings.TrimSpace(InterpolateEnv(interpolateCtx(cfg.File, ctx), ctx.App.Dir))
	model := strings.TrimSpace(InterpolateEnv(interpolateCtx(cfg.Model, ctx), ctx.App.Dir))
	language := strings.TrimSpace(InterpolateEnv(interpolateCtx(cfg.Language, ctx), ctx.App.Dir))

	goCtx := context.Background()
	if ctx.Request != nil {
		goCtx = ctx.Request.Context()
	}
	// Step-level `timeout:` (parsed for every step by flows_gha.go, same
	// as `run: api` consumes at execStepAPI) caps this call too. It nests
	// OUTSIDE RunTranscribe's own TRANSCRIBE_TIMEOUT context, so the
	// effective deadline is the SMALLER of the two.
	if step.Timeout > 0 {
		var cancel context.CancelFunc
		goCtx, cancel = context.WithTimeout(goCtx, step.Timeout)
		defer cancel()
	}
	res, err := RunTranscribe(goCtx, ctx.App, file, model, language)
	if err != nil {
		return err
	}
	if step.Name != "" {
		out := map[string]any{"text": res.Text, "audio_path": res.AudioPath}
		ctx.DataMu.Lock()
		ctx.Data[step.Name] = out
		flattenIntoCtx(ctx.Data, step.Name, out)
		ctx.DataMu.Unlock()
	}
	return nil
}

// resolveTranscribeInput turns the step's `file:` value into a local
// path ffmpeg can read. Local-file-first: the primary shape is a path
// inside the app's own uploads/ subtree - no HTTP hop. http(s) URLs
// are the secondary shape, downloaded via the existing SSRF-guarded
// fetch path (isPrivateURL + safeHTTPClientStrict - reused, not
// reimplemented).
// Returns the readable path, the value to publish as outputs.audio_path,
// and a cleanup func for any temp download.
func resolveTranscribeInput(ctx context.Context, app *App, input string, cfg transcribeCfg) (string, string, func(), error) {
	noop := func() {}
	in := strings.TrimSpace(input)
	if in == "" {
		return "", "", noop, fmt.Errorf("transcribe: no input - set `with.file:` to a path inside the app (e.g. uploads/brief.webm) or an https:// URL")
	}

	if u, err := neturl.Parse(in); err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		// Private platform-CDN objects are stored UNSIGNED (a direct GET 403s),
		// so a private-tier audio_url (e.g. onboarding voice briefs, now on the
		// private tier so the raw URL is not anon-readable) can't be fetched as
		// a plain URL. When `file:` names THIS app's own private CDN object,
		// mint a short-TTL signed CloudFront URL for the server-side fetch. The
		// audio therefore never needs to be public and transcription still
		// works. Public CDN objects and arbitrary URLs pass through unchanged;
		// off-platform / local-disk deployments (getPlatformMedia()==nil) are a
		// no-op. The ORIGINAL url is still what we publish as audio_path.
		fetchURL := in
		if signed, ok := signPrivateCDNURLForApp(app, in); ok {
			fetchURL = signed
		}
		path, cleanup, err := downloadTranscribeURL(ctx, fetchURL, cfg)
		if err != nil {
			return "", "", noop, err
		}
		return path, in, cleanup, nil
	}

	// Path input: contained to the app's uploads/ SUBTREE - the same
	// rooting execStepServeFile uses (flows_response.go). Uploads are the only
	// place audio legitimately lives; rooting at <app>/uploads (not the
	// app dir) keeps a request-tainted `file:` ref away from env.yaml,
	// data.db and .benmore/*. An optional leading "/" or "uploads/"
	// prefix is normalized away, so "/uploads/x.webm", "uploads/x.webm"
	// and "x.webm" all resolve to <app>/uploads/x.webm.
	if filepath.IsAbs(in) {
		return "", "", noop, fmt.Errorf("transcribe: input path %q escapes the app's uploads/ directory - use an uploads/-relative path (e.g. uploads/brief.webm) or an https:// URL", in)
	}
	rel := filepath.Clean(strings.TrimPrefix(strings.TrimPrefix(in, "/"), "uploads/"))
	uploadsRoot := filepath.Join(filepath.Clean(app.Dir), "uploads")
	full := filepath.Join(uploadsRoot, rel)
	if full == uploadsRoot || !strings.HasPrefix(full, uploadsRoot+string(os.PathSeparator)) {
		return "", "", noop, fmt.Errorf("transcribe: input path %q escapes the app's uploads/ directory - use an uploads/-relative path (e.g. uploads/brief.webm) or an https:// URL", in)
	}
	info, err := os.Stat(full)
	if err != nil || info.IsDir() {
		return "", "", noop, fmt.Errorf("transcribe: input file %q not found under the app's uploads/ directory (looked at %s) - upload it first, or pass an https:// URL", in, full)
	}
	return full, filepath.ToSlash(filepath.Join("uploads", rel)), noop, nil
}

// signPrivateCDNURLForApp returns a short-TTL signed CloudFront URL for
// rawURL when, and only when, it is THIS app's own PRIVATE platform-CDN
// object (host == the media CDN domain and key == private/<app-prefix>/…).
// Private CDN objects are stored unsigned and 403 a direct GET, so a
// server-side transcribe fetch of a private audio_url needs a signature.
// Scoping to the app's own private prefix means it can never sign another
// app's file or a public object. Returns ("", false) - a safe no-op - when
// the platform media CDN is not configured, the URL isn't a CDN object, or
// it isn't this app's private object, so nothing changes off-platform or in
// tests. The TTL is deliberately short (a signed URL is a bearer credential;
// see signCloudFrontURL) and only has to outlive the immediate download.
func signPrivateCDNURLForApp(app *App, rawURL string) (string, bool) {
	cfg := getPlatformMedia()
	if cfg == nil || app == nil {
		return "", false
	}
	u, err := neturl.Parse(rawURL)
	if err != nil || u.Host != cfg.CDNDomain {
		return "", false
	}
	key := strings.TrimPrefix(u.Path, "/")
	if !strings.HasPrefix(key, "private/"+appMediaPrefix(app)+"/") {
		return "", false
	}
	expires := time.Now().Add(2 * time.Minute).Unix()
	signed, err := signCloudFrontURL(rawURL, expires, cfg.KeyPairID, cfg.PrivateKey)
	if err != nil {
		// Log before the unsigned fallback - otherwise a misconfigured
		// CloudFront key pair (bad private key, wrong key-pair ID) is
		// invisible here and only surfaces downstream as a misleading
		// "audio URL must be publicly readable" 4xx from the plain GET.
		log.Printf("transcribe: signCloudFrontURL failed for %s (falling back to unsigned, which will likely 403): %s", key, err)
		return "", false
	}
	return signed, true
}

// maxAudioDownload caps a URL-input download - a recording, not a
// filesystem.
const maxAudioDownload = 1 << 30 // 1GB

// downloadTranscribeURL fetches a public audio URL to a temp file using
// the framework's SSRF-guarded client (redirects re-checked, dial-time
// IP validation - the same posture as flow `run: api`).
func downloadTranscribeURL(ctx context.Context, rawURL string, cfg transcribeCfg) (string, func(), error) {
	if isPrivateURL(rawURL) {
		return "", func() {}, fmt.Errorf("transcribe: SECURITY: blocked download from private/internal URL: %s", rawURL)
	}
	return fetchTranscribeURL(ctx, safeHTTPClientStrict(cfg.timeout), rawURL, maxAudioDownload)
}

// fetchTranscribeURL is the GET + temp-file copy half of
// downloadTranscribeURL, split out so the status/cap/cleanup logic is
// unit-testable: the production client (safeHTTPClientStrict) rightly
// refuses loopback, so tests inject httptest's own client and a small
// maxBytes instead of stubbing the resolver (no such seam exists in
// this codebase - see flows_test.go's identical note for run: api).
func fetchTranscribeURL(ctx context.Context, client *http.Client, rawURL string, maxBytes int64) (string, func(), error) {
	noop := func() {}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", noop, fmt.Errorf("transcribe: bad input URL %q: %w", rawURL, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return "", noop, fmt.Errorf("transcribe: download %s: %w", rawURL, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 400 {
		return "", noop, fmt.Errorf("transcribe: download %s returned %d - the audio URL must be publicly readable", rawURL, resp.StatusCode)
	}

	tmp, err := os.CreateTemp("", "benmore-transcribe-dl-*")
	if err != nil {
		return "", noop, fmt.Errorf("transcribe: create temp download file: %w", err)
	}
	cleanup := func() { os.Remove(tmp.Name()) }
	n, err := io.Copy(tmp, io.LimitReader(resp.Body, maxBytes+1))
	closeErr := tmp.Close()
	if err != nil || closeErr != nil {
		cleanup()
		return "", noop, fmt.Errorf("transcribe: download %s: %w", rawURL, errorsJoinFirst(err, closeErr))
	}
	if n > maxBytes {
		cleanup()
		return "", noop, fmt.Errorf("transcribe: download %s exceeds the %dMB cap - host the file locally in uploads/ instead", rawURL, maxBytes>>20)
	}
	return tmp.Name(), cleanup, nil
}

// errorsJoinFirst returns the first non-nil error (both args may be nil
// only when the caller already knows one is set).
func errorsJoinFirst(a, b error) error {
	if a != nil {
		return a
	}
	return b
}

// runTranscribeCmd executes one argv (never a shell string) with the
// subprocess in its own process group (unix), stderr captured into the
// error, and a context-driven group kill so ffmpeg/whisper children die
// with the parent on timeout.
func runTranscribeCmd(ctx context.Context, argv []string, label string) error {
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	var stderr bytes.Buffer
	cmd.Stdout = io.Discard
	cmd.Stderr = &stderr
	setTranscribeProcAttrs(cmd)
	// WaitDelay is a PORTABLE exec.Cmd field and must be set for every
	// GOOS - Windows most of all: it has no process-group kill (the
	// stub's Cancel kills only the direct child), so a helper child
	// surviving the kill while holding the inherited stderr pipe would
	// block Wait forever, never return from RunTranscribe, and wedge
	// the cap-1 transcribeSem for the life of the process. With
	// WaitDelay, Wait gives up on the remaining pipe output after 5s.
	cmd.WaitDelay = 5 * time.Second
	err := cmd.Run()
	if err == nil {
		return nil
	}
	if ctx.Err() != nil {
		return fmt.Errorf("transcribe: %s exceeded the time budget and was killed - raise TRANSCRIBE_TIMEOUT (default 10m) for long recordings: %w", label, ctx.Err())
	}
	tail := stderr.String()
	if len(tail) > 400 {
		tail = "…" + tail[len(tail)-400:]
	}
	return fmt.Errorf("transcribe: %s failed: %w - stderr: %s", label, err, strings.TrimSpace(tail))
}
