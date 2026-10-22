//go:build !linux || (!amd64 && !arm64) || cli

package main

import (
	"context"
	"os/exec"
)

func appMCPPDFHelperMain() bool               { return false }
func appMCPPDFIsolationAvailable(string) bool { return false }
func appMCPPDFCreateTempRunDir() (string, error) {
	return "", errAppMCPPDFUnavailable
}

func appMCPPDFRestrictedCommand(context.Context, string, []string, int64, string) (*exec.Cmd, error) {
	return nil, errAppMCPPDFUnavailable
}

func appMCPPDFStampRestrictedCommand(context.Context, string, string) (*exec.Cmd, error) {
	return nil, errAppMCPPDFUnavailable
}

func appMCPPDFInspectRestrictedCommand(context.Context, string, string) (*exec.Cmd, error) {
	return nil, errAppMCPPDFUnavailable
}

func appMCPPDFWorkerFailure(error) bool { return false }
