//go:build !cli && !windows

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A `run: transcribe` step whose `file:`, `model:` or `language:` reads a
// value that does not exist fails before the file is fetched or decoded
// (unresolvedRefsBeforeEffect). The fakes are the ones transcribe_test.go
// uses; this ffmpeg leaves a marker when it is started.
func TestTranscribeStepWithAnUnresolvedReferenceRunsNothing(t *testing.T) {
	app, cleanup := newTestApp(t)
	defer cleanup()
	binDir := t.TempDir()
	marker := filepath.Join(t.TempDir(), "ffmpeg-ran")
	writeFakeBin(t, binDir, "ffmpeg", "touch '"+marker+"'\n"+fakeFfmpegScript)
	writeFakeBin(t, binDir, "whisper-cli", fakeWhisperScript)
	setFakePATH(t, binDir)
	seedModel(t, "small.en")
	rel := seedUpload(t, app, "brief.webm")

	ctx := &FlowContext{App: app, Data: map[string]any{"lang": "en"}, Params: map[string]string{}}
	step := &FlowStep{Name: "t", Type: "transcribe", Transcribe: &FlowTranscribe{File: rel, Language: "{{nope.lang}}"}}
	if err := executeStep(ctx, step); err == nil || !strings.Contains(err.Error(), "unresolved template reference") {
		t.Fatalf("unresolved language reference: err=%v", err)
	}
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the audio was decoded before the step failed on its reference")
	}
	step.Transcribe.Language = "{{lang}}"
	if err := executeStep(ctx, step); err != nil || ctx.Data["t.text"] != "hello from whisper" {
		t.Fatalf("a transcribe step whose references resolve: err=%v text=%v", err, ctx.Data["t.text"])
	}
	if _, err := os.Stat(marker); err != nil {
		t.Fatal("the resolved step did not decode the audio")
	}
}
