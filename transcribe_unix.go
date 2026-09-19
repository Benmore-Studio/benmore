//go:build !cli && !windows

package main

// Unix process-control half of transcribe.go. Split per-GOOS because
// syscall.SysProcAttr.Setpgid / syscall.Kill do not exist on Windows
// (the cloud CLI ships a windows/amd64 binary) - same seam as
// fileowner_unix.go. See transcribe_windows.go for the stubs.
//
// Note: cmd.WaitDelay is NOT set here - it is a portable exec.Cmd
// field that every GOOS needs (Windows most of all), so it lives in
// runTranscribeCmd (transcribe.go).

import (
	"os/exec"
	"strconv"
	"syscall"
)

// setTranscribeProcAttrs puts the child in its OWN process group and
// arranges for a context cancellation to SIGKILL the whole group -
// ffmpeg and whisper spawn helper children, and killing only the direct
// child would orphan them mid-inference.
func setTranscribeProcAttrs(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		// Negative pid = the process group (Setpgid above made the
		// child its own group leader, so -pid targets it + children).
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}

// transcribeNicePrefix wraps the inference invocation in
// `nice -n <level>` so a transcription can't starve the app process.
// Returned as argv parts (never a shell string).
func transcribeNicePrefix(level int) []string {
	return []string{"nice", "-n", strconv.Itoa(level)}
}
