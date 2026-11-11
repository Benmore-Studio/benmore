//go:build !cli && !windows

package main

// Tests for the `run: transcribe` flow step surface (flows_gha.go
// registration + flows_steps.go dispatcher). Engine-level behavior is covered
// by transcribe_test.go; these tests pin the YAML surface: parse,
// validator agreement, ${{ steps.<id>.outputs.text }} publication, and
// the actionable step_error path. Fake-binary helpers (writeFakeBin,
// setFakePATH, seedModel, seedUpload) come from transcribe_test.go.
//
// !windows for the same reason as transcribe_test.go: the fakes are
// POSIX sh scripts.

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const transcribeFlowYAML = `on:
  request:
    method: POST
    path: /api/transcribe-brief
jobs:
  main:
    steps:
      - id: t
        run: transcribe
        with:
          file: uploads/x.webm
          model: base.en
          language: en
      - run: respond
        with:
          json:
            transcript: "${{ steps.t.outputs.text }}"
            audio: "${{ steps.t.outputs.audio_path }}"
`

func TestTranscribeStepParsesAndRegisters(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "flows.yaml"), []byte(transcribeFlowYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(dir)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	steps := flows[0].Steps
	if len(steps) != 2 {
		t.Fatalf("expected 2 steps, got %d", len(steps))
	}
	st := steps[0]
	if st.Type != "transcribe" {
		t.Fatalf("step Type = %q, want %q", st.Type, "transcribe")
	}
	if st.Transcribe == nil {
		t.Fatal("step.Transcribe not populated from with:")
	}
	if st.Transcribe.File != "uploads/x.webm" {
		t.Errorf("File = %q, want uploads/x.webm", st.Transcribe.File)
	}
	if st.Transcribe.Model != "base.en" {
		t.Errorf("Model = %q, want base.en", st.Transcribe.Model)
	}
	if st.Transcribe.Language != "en" {
		t.Errorf("Language = %q, want en", st.Transcribe.Language)
	}

	// Parser↔validator single-source contract (flowRunTypes): the
	// write-time validator must accept what the parser runs.
	// TestFlowRunTypesMatch (flows_validator_test.go, platform build)
	// sweeps every registered type; this pins the new one directly.
	if msg := validateFlowsYAML(transcribeFlowYAML); msg != "" {
		t.Errorf("validateFlowsYAML rejected a valid run: transcribe flow: %s", msg)
	}
}

func TestTranscribeStepExecutes(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	binDir := t.TempDir()
	writeFakeBin(t, binDir, "ffmpeg", fakeFfmpegScript)
	writeFakeBin(t, binDir, "whisper-cli", fakeWhisperScript)
	setFakePATH(t, binDir)
	seedModel(t, "base.en")
	seedUpload(t, app, "x.webm")

	if err := os.WriteFile(filepath.Join(app.Dir, "flows.yaml"), []byte(transcribeFlowYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(app.Dir)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	rec := httptest.NewRecorder()
	ctx := &FlowContext{
		App:     app,
		Request: httptest.NewRequest("POST", "/api/transcribe-brief", nil),
		Writer:  rec,
		Data:    map[string]any{},
		Params:  map[string]string{},
	}
	executeSteps(ctx, flows[0].Steps)
	if ctx.Error != nil {
		t.Fatalf("flow errored: %v (failed step %q)", ctx.Error, ctx.FailedStep)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "hello from whisper") {
		t.Errorf("response %q does not contain the fake transcript", body)
	}
	if !strings.Contains(body, "uploads/x.webm") {
		t.Errorf("response %q does not carry outputs.audio_path", body)
	}
}

// TestTranscribeStepTimeoutHonored pins step-level `timeout:` on a
// `run: transcribe` step (parsed by flows_gha.go for every step, and
// consumed here the same way `run: api` consumes it): the effective
// deadline is the SMALLER of the step timeout and TRANSCRIBE_TIMEOUT.
// With the default 10m TRANSCRIBE_TIMEOUT and a 1s step timeout, a fake
// whisper that sleeps 60s must be killed within seconds - if the step
// timeout were silently ignored (the pre-fix behavior), this test would
// hang toward the 60s sleep and fail the elapsed bound.
func TestTranscribeStepTimeoutHonored(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	binDir := t.TempDir()
	writeFakeBin(t, binDir, "ffmpeg", fakeFfmpegScript)
	writeFakeBin(t, binDir, "whisper-cli", "sleep 60")
	setFakePATH(t, binDir)
	seedModel(t, "base.en")
	seedUpload(t, app, "x.webm")

	const yamlWithTimeout = `on:
  request:
    method: POST
    path: /api/transcribe-brief
jobs:
  main:
    steps:
      - id: t
        run: transcribe
        timeout: 1s
        with:
          file: uploads/x.webm
          model: base.en
`
	if err := os.WriteFile(filepath.Join(app.Dir, "flows.yaml"), []byte(yamlWithTimeout), 0o644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(app.Dir)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}
	if got := flows[0].Steps[0].Timeout; got != time.Second {
		t.Fatalf("parsed step Timeout = %v, want 1s", got)
	}

	ctx := &FlowContext{
		App:     app,
		Request: httptest.NewRequest("POST", "/api/transcribe-brief", nil),
		Writer:  httptest.NewRecorder(),
		Data:    map[string]any{},
		Params:  map[string]string{},
	}
	start := time.Now()
	executeSteps(ctx, flows[0].Steps)
	elapsed := time.Since(start)
	if ctx.Error == nil {
		t.Fatal("expected the step to time out")
	}
	if !strings.Contains(ctx.Error.Error(), "time budget") {
		t.Errorf("error %q should say the time budget was exceeded", ctx.Error)
	}
	// 1s deadline + 5s WaitDelay headroom, far below the 60s sleep (and
	// the 10m TRANSCRIBE_TIMEOUT that would apply without `timeout:`).
	if elapsed > 15*time.Second {
		t.Errorf("step took %s - step-level timeout: was not honored", elapsed)
	}
}

// `with.timeout` caps a transcription as well. It was read only on api and
// compute steps, so on this step it was accepted and dropped and
// TRANSCRIBE_TIMEOUT alone applied. The step-level key still wins.
func TestTranscribeWithTimeoutHonored(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	binDir := t.TempDir()
	writeFakeBin(t, binDir, "ffmpeg", fakeFfmpegScript)
	writeFakeBin(t, binDir, "whisper-cli", "sleep 60")
	setFakePATH(t, binDir)
	seedModel(t, "base.en")
	seedUpload(t, app, "x.webm")

	const yamlWithTimeout = `on:
  request:
    method: POST
    path: /api/transcribe-brief
jobs:
  main:
    steps:
      - id: t
        run: transcribe
        with:
          file: uploads/x.webm
          model: base.en
          timeout: 1
      - id: both
        run: transcribe
        timeout: 2s
        with:
          file: uploads/x.webm
          timeout: 90s
`
	if msg := validateFlowsYAML(yamlWithTimeout); msg != "" {
		t.Fatalf("write gate refused with.timeout on run: transcribe: %s", msg)
	}
	if err := os.WriteFile(filepath.Join(app.Dir, "flows.yaml"), []byte(yamlWithTimeout), 0o644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(app.Dir)
	if len(flows) != 1 || len(flows[0].Steps) != 2 {
		t.Fatalf("expected 1 flow of 2 steps, got %d flows", len(flows))
	}
	if got := flows[0].Steps[0].Timeout; got != time.Second {
		t.Fatalf("with.timeout: parsed step Timeout = %v, want 1s", got)
	}
	if got := flows[0].Steps[1].Timeout; got != 2*time.Second {
		t.Fatalf("step-level timeout over with.timeout: parsed step Timeout = %v, want 2s", got)
	}

	ctx := &FlowContext{
		App:     app,
		Request: httptest.NewRequest("POST", "/api/transcribe-brief", nil),
		Writer:  httptest.NewRecorder(),
		Data:    map[string]any{},
		Params:  map[string]string{},
	}
	start := time.Now()
	executeSteps(ctx, flows[0].Steps[:1])
	elapsed := time.Since(start)
	if ctx.Error == nil || !strings.Contains(ctx.Error.Error(), "time budget") {
		t.Fatalf("error = %v, want the time budget to be exceeded", ctx.Error)
	}
	if elapsed > 15*time.Second {
		t.Errorf("step took %s - with.timeout was not honored", elapsed)
	}
}

func TestTranscribeStepMissingBinaryErrors(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	// PATH carries ffmpeg but NO whisper-cli - a host without the
	// transcriber. The flow must fail loud through the normal step_error
	// path with the actionable remedy in the message.
	binDir := t.TempDir()
	writeFakeBin(t, binDir, "ffmpeg", fakeFfmpegScript)
	t.Setenv("PATH", binDir)
	seedModel(t, "base.en")
	seedUpload(t, app, "x.webm")

	if err := os.WriteFile(filepath.Join(app.Dir, "flows.yaml"), []byte(transcribeFlowYAML), 0o644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(app.Dir)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow, got %d", len(flows))
	}

	ctx := &FlowContext{
		App:     app,
		Request: httptest.NewRequest("POST", "/api/transcribe-brief", nil),
		Writer:  httptest.NewRecorder(),
		Data:    map[string]any{},
		Params:  map[string]string{},
	}
	executeSteps(ctx, flows[0].Steps)
	if ctx.Error == nil {
		t.Fatal("expected the flow to error with whisper-cli missing")
	}
	for _, want := range []string{"WHISPER_BIN", "install"} {
		if !strings.Contains(ctx.Error.Error(), want) {
			t.Errorf("flow error %q does not contain %q", ctx.Error, want)
		}
	}
	if ctx.FailedStep != "t" {
		t.Errorf("FailedStep = %q, want %q", ctx.FailedStep, "t")
	}
	if ctx.FailedType != "transcribe" {
		t.Errorf("FailedType = %q, want %q", ctx.FailedType, "transcribe")
	}
}
