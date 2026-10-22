//go:build linux && !cli

package main

import (
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
)

const prGetDumpable = 3

func currentDumpable(t *testing.T) uintptr {
	t.Helper()
	v, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prGetDumpable, 0, 0)
	if errno != 0 {
		t.Fatal(errno)
	}
	return v
}

// The helper process reports its dumpable attribute; init has already run.
func TestDumpableHelperProcess(t *testing.T) {
	if os.Getenv("BENMORE_DUMPABLE_HELPER") != "1" {
		t.Skip("helper process only")
	}
	os.Stdout.WriteString("dumpable=" + string(rune('0'+currentDumpable(t))) + "\n")
}

// Hosted tenant processes are not dumpable (so a same-UID dev process cannot
// open /proc/<pid>/root of its prod sibling); other processes are untouched.
func TestHostedTenantProcessIsNotDumpable(t *testing.T) {
	run := func(hosted string) string {
		cmd := exec.Command(os.Args[0], "-test.run=^TestDumpableHelperProcess$")
		cmd.Env = append(os.Environ(), "BENMORE_DUMPABLE_HELPER=1", "BENMORE_BIND_LOOPBACK="+hosted)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("helper: %v: %s", err, out)
		}
		return string(out)
	}
	if out := run("1"); !strings.Contains(out, "dumpable=0") {
		t.Fatalf("hosted tenant process is dumpable: %s", out)
	}
	if out := run(""); !strings.Contains(out, "dumpable=1") {
		t.Fatalf("a non-hosted process was made non-dumpable: %s", out)
	}
}
