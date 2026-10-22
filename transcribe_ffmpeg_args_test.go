//go:build !cli

package main

import (
	"slices"
	"strings"
	"testing"
)

// ffmpeg picks its demuxer from the file's content, so an uploaded HLS
// playlist or ffconcat script would otherwise make it open URLs or other
// local files. The decode command must confine protocols and demuxers, and
// those are input options, so they must come before -i.
func TestTranscribeFFmpegArgvConfinesInput(t *testing.T) {
	argv := transcribeFFmpegArgv("/usr/bin/ffmpeg", "/apps/a/uploads/x:y.webm", "/tmp/w/audio.wav")
	in := slices.Index(argv, "-i")
	if in < 0 || argv[in+1] != "file:/apps/a/uploads/x:y.webm" {
		t.Fatalf("input must be passed as an explicit file: URL, got %q", argv)
	}
	optionValue := func(flag string) string {
		i := slices.Index(argv, flag)
		if i < 0 || i > in {
			t.Fatalf("%s must be set as an input option before -i: %q", flag, argv)
		}
		return argv[i+1]
	}
	if got := optionValue("-protocol_whitelist"); got != "file" {
		t.Fatalf("protocol whitelist = %q, want file only", got)
	}
	formats := strings.Split(optionValue("-format_whitelist"), ",")
	for _, banned := range []string{"hls", "concat", "image2", "tty", "lavfi", "subfile", "data"} {
		if slices.Contains(formats, banned) {
			t.Fatalf("demuxer %q must not be allowed: %v", banned, formats)
		}
	}
	for _, want := range []string{"mov", "matroska", "webm", "ogg", "mp3", "wav"} {
		if !slices.Contains(formats, want) {
			t.Fatalf("common audio demuxer %q missing: %v", want, formats)
		}
	}
	if argv[len(argv)-1] != "/tmp/w/audio.wav" {
		t.Fatalf("output must stay the last argument: %q", argv)
	}
}
