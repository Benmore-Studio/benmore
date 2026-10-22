//go:build linux && !cli

package main

import (
	"log"
	"syscall"
)

// prSetDumpable is PR_SET_DUMPABLE from <linux/prctl.h>.
const prSetDumpable = 4

// A dev instance shares its UID with the same app's prod instance (the dev
// unit reuses benmore-app-<sub>), so mount-namespace masking is the only thing
// keeping dev code away from prod's files. A same-UID process can still reach
// another process's mount namespace through /proc/<pid>/root (and read its
// memory with ptrace) while that process is dumpable. Marking every hosted
// tenant process non-dumpable makes those /proc entries root-owned and refuses
// the same-UID ptrace-read, so a compromised dev process cannot walk into prod's
// view of the filesystem, including its MCP authority directory.
//
// Scope: hosted tenant processes only (hostedTenantProcess), so development
// tooling and self-hosted serve are unaffected. Residual: execve resets the
// attribute, so a helper the app spawns is dumpable again; the units' empty
// capability set, @system-service filter and RestrictNamespaces remain the
// other layers.
func init() {
	if !hostedTenantProcess() {
		return
	}
	markProcessNonDumpable()
}

// markProcessNonDumpable is also called by `upgrade-check`: the release tool
// runs it as the app's own user inside that instance's view of the
// filesystem, where a dumpable process would lend that view to the app's
// other instance for as long as the check runs.
func markProcessNonDumpable() {
	if _, _, errno := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); errno != 0 {
		log.Printf("SECURITY: could not mark the hosted tenant process non-dumpable: %v", errno)
	}
}
