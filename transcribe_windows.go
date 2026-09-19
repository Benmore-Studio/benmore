//go:build !cli && windows

package main

// Windows stubs for the unix process-control helpers in
// transcribe_unix.go (same per-GOOS seam as fileowner_windows.go).
// Windows has no unix process groups or `nice`; exec.CommandContext's
// default cancel (kill the direct child) is the available behavior.
// The portable cmd.WaitDelay set in runTranscribeCmd (transcribe.go)
// is what keeps a surviving helper child - which the default cancel
// cannot reach - from blocking Wait on the inherited stderr pipe and
// wedging the transcription semaphore forever.

import "os/exec"

func setTranscribeProcAttrs(cmd *exec.Cmd) {}

// transcribeNicePrefix: no `nice` on Windows - invoke whisper directly.
func transcribeNicePrefix(int) []string { return nil }
