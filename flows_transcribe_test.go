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
	"fmt"
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

// TestTranscribeBriefFlowYAML executes the REAL _platform flow
// (apps/_platform/flows/transcribe_brief.yaml - the file the portal
// ships, not a fixture copy) through the real loader against a seeded
// sqlite fixture with fake binaries: the closest repeatable
// approximation of the portal happy path the Go harness can express.
// (The full HTTP shape - member submit → 202 → job worker - needs a
// running server + session auth + the jobs worker; the degraded half of
// that is pinned by apps/_platform/tests/portal_onboarding.yaml.)
// This pins the guard SELECT shape, the `save` UPDATE with
// expect_rows "=1", the announce INSERT..SELECT channel targeting, the
// non-member no-op, and the retry-safety no-op (status != 'pending').
func TestTranscribeBriefFlowYAML(t *testing.T) {
	platformDir := filepath.Join("apps", "_platform")
	if _, err := os.Stat(platformDir); os.IsNotExist(err) {
		t.Skip("private platform fixture is not shipped in the framework export")
	} else if err != nil {
		t.Fatal(err)
	}

	app, cleanup := newTestApp(t)
	defer cleanup()

	binDir := t.TempDir()
	writeFakeBin(t, binDir, "ffmpeg", fakeFfmpegScript)
	writeFakeBin(t, binDir, "whisper-cli", fakeWhisperScript)
	setFakePATH(t, binDir)
	seedModel(t, "small.en")

	// The actual shipped flow file, loaded from the repo tree.
	raw, err := os.ReadFile(filepath.Join(platformDir, "flows", "transcribe_brief.yaml"))
	if err != nil {
		t.Fatalf("read the shipped flow: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(app.Dir, "flows"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(app.Dir, "flows", "transcribe_brief.yaml"), raw, 0o644); err != nil {
		t.Fatal(err)
	}
	flows := LoadFlowsGHA(app.Dir)
	if len(flows) != 1 {
		t.Fatalf("expected 1 flow from transcribe_brief.yaml, got %d", len(flows))
	}

	// Minimal portal fixture: one project, one member (user 42), a
	// #general standard channel, and a pending submission with audio.
	for _, q := range []string{
		`CREATE TABLE svc_projects (id INTEGER PRIMARY KEY, slack_channel_id TEXT)`,
		`CREATE TABLE svc_members (project_id INTEGER, user_id INTEGER)`,
		`CREATE TABLE svc_channels (id INTEGER PRIMARY KEY, project_id INTEGER, kind TEXT, name TEXT)`,
		`CREATE TABLE svc_onboarding (id INTEGER PRIMARY KEY, project_id INTEGER, audio_url TEXT, transcript TEXT, status TEXT, updated_at TEXT)`,
		`CREATE TABLE svc_messages (id INTEGER PRIMARY KEY AUTOINCREMENT, project_id INTEGER, channel_id INTEGER, sender_kind TEXT, body TEXT, origin TEXT, created_at TEXT, updated_at TEXT)`,
		`INSERT INTO svc_projects (id, slack_channel_id) VALUES (1, NULL)`,
		`INSERT INTO svc_members (project_id, user_id) VALUES (1, 42)`,
		`INSERT INTO svc_channels (id, project_id, kind, name) VALUES (10, 1, 'standard', 'general')`,
		`INSERT INTO svc_onboarding (id, project_id, audio_url, status) VALUES (7, 1, '/uploads/onboarding/7.webm', 'pending')`,
	} {
		mustExec(t, app.DB, q)
	}
	audioFull := filepath.Join(app.Dir, "uploads", "onboarding", "7.webm")
	if err := os.MkdirAll(filepath.Dir(audioFull), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(audioFull, []byte("fake-audio-bytes"), 0o644); err != nil {
		t.Fatal(err)
	}

	runFlow := func(submissionID, userID int) *FlowContext {
		ctx := &FlowContext{
			App:    app,
			Data:   map[string]any{"submission_id": fmt.Sprint(submissionID), "user": map[string]any{"id": userID}},
			Params: map[string]string{},
		}
		executeSteps(ctx, flows[0].Steps)
		return ctx
	}

	// Happy path: member 42, pending submission 7 → transcript saved,
	// status flipped, one system announce in #general.
	if ctx := runFlow(7, 42); ctx.Error != nil {
		t.Fatalf("happy path errored: %v (step %q)", ctx.Error, ctx.FailedStep)
	}
	var transcript, status string
	if err := app.DB.QueryRow(`SELECT transcript, status FROM svc_onboarding WHERE id = 7`).Scan(&transcript, &status); err != nil {
		t.Fatal(err)
	}
	if transcript != "hello from whisper" {
		t.Errorf("transcript = %q, want the fake transcript", transcript)
	}
	if status != "transcribed" {
		t.Errorf("status = %q, want transcribed", status)
	}
	var msgs int
	var channelID int
	if err := app.DB.QueryRow(`SELECT COUNT(*), COALESCE(MAX(channel_id),0) FROM svc_messages WHERE project_id = 1 AND sender_kind = 'system'`).Scan(&msgs, &channelID); err != nil {
		t.Fatal(err)
	}
	if msgs != 1 {
		t.Fatalf("announce messages = %d, want exactly 1", msgs)
	}
	if channelID != 10 {
		t.Errorf("announce landed in channel %d, want the #general channel 10", channelID)
	}

	// Retry safety (the async worker retries a failed job): re-running
	// for the SAME submission finds no 'pending' row → guard SELECT is
	// empty → clean no-op, no double-announce.
	if ctx := runFlow(7, 42); ctx.Error != nil {
		t.Fatalf("retry re-run errored: %v", ctx.Error)
	}
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM svc_messages`).Scan(&msgs); err != nil {
		t.Fatal(err)
	}
	if msgs != 1 {
		t.Errorf("re-run double-announced: %d messages, want still 1", msgs)
	}

	// Non-member no-op: user 99 is not on project 1, so a fresh pending
	// submission stays untouched and nothing is announced - the same
	// uniform "completed" a missing id gets (no existence oracle).
	mustExec(t, app.DB, `INSERT INTO svc_onboarding (id, project_id, audio_url, status) VALUES (8, 1, '/uploads/onboarding/7.webm', 'pending')`)
	if ctx := runFlow(8, 99); ctx.Error != nil {
		t.Fatalf("non-member run errored: %v", ctx.Error)
	}
	if err := app.DB.QueryRow(`SELECT status FROM svc_onboarding WHERE id = 8`).Scan(&status); err != nil {
		t.Fatal(err)
	}
	if status != "pending" {
		t.Errorf("non-member run touched the row: status = %q, want pending", status)
	}
	if err := app.DB.QueryRow(`SELECT COUNT(*) FROM svc_messages`).Scan(&msgs); err != nil {
		t.Fatal(err)
	}
	if msgs != 1 {
		t.Errorf("non-member run announced: %d messages, want still 1", msgs)
	}
}

func TestTranscribeStepMissingBinaryErrors(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()

	// PATH carries ffmpeg but NO whisper-cli - the portal's degrade
	// scenario. The flow must fail loud through the normal step_error
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
