//go:build !cli

package main

import (
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestServerNewInvalidUsageExitsTwo(t *testing.T) {
	if os.Getenv("BENMORE_TEST_NEW_USAGE") == "1" {
		os.Args = []string{"benmore", "new", "--bad"}
		runServerNew()
		return
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestServerNewInvalidUsageExitsTwo$")
	cmd.Env = append(os.Environ(), "BENMORE_TEST_NEW_USAGE=1")
	err := cmd.Run()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 2 {
		t.Fatalf("invalid new usage = %v; want exit 2", err)
	}
}

func TestServerNewReportsResolvedDirectoryAndEditionWorkflow(t *testing.T) {
	oldArgs, oldStdout := os.Args, os.Stdout
	oldWD, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		os.Args, os.Stdout = oldArgs, oldStdout
		_ = os.Chdir(oldWD)
	})

	root := t.TempDir()
	if err := os.Chdir(root); err != nil {
		t.Fatal(err)
	}
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	os.Args = []string{"benmore", "new", "crm"}
	runServerNew()
	_ = w.Close()
	out, err := io.ReadAll(r)
	_ = r.Close()
	if err != nil {
		t.Fatal(err)
	}

	text := string(out)
	wantDir, err := filepath.Abs("crm")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text, "Created "+wantDir) {
		t.Fatalf("output did not report resolved directory %q:\n%s", wantDir, text)
	}
	if editionName == "framework" {
		if !strings.Contains(text, "benmore serve") || !strings.Contains(text, "http://localhost:8080") {
			t.Fatalf("framework next steps omitted self-hosted serve:\n%s", text)
		}
		return
	}
	if strings.Contains(text, "localhost") || strings.Contains(text, "benmore serve") {
		t.Fatalf("hosted next steps advertised a local server:\n%s", text)
	}
	for _, want := range []string{"cd \"" + wantDir + "\"", "benmore deploy", "benmore open ."} {
		if !strings.Contains(text, want) {
			t.Fatalf("hosted next steps omitted %q:\n%s", want, text)
		}
	}
}
