//go:build !cli

package main

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func artifactChromeVersionFixture(t *testing.T, body string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("version probe fixture requires a POSIX shell")
	}
	path := filepath.Join(t.TempDir(), "chrome-version")
	// exec replaces the shell so cancelling the probe cannot leave a sleeping
	// child holding the output pipe open after the parent process is killed.
	script := "#!/bin/sh\nif [ \"$#\" -ne 1 ] || [ \"$1\" != \"--version\" ]; then exit 7; fi\n" + body + "\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAppMCPArtifactChromeVersionColdStart(t *testing.T) {
	chrome := artifactChromeVersionFixture(t, "printf 'Chromium 130.0.6723.91\\n'\nexec /bin/sleep 4")
	version, err := appMCPProbeArtifactChromeVersion(context.Background(), chrome)
	if err != nil || version != "Chromium 130.0.6723.91" {
		t.Fatalf("valid provider taking longer than three seconds was refused: version=%q err=%v", version, err)
	}
}

func TestAppMCPArtifactChromeVersionCallerDeadline(t *testing.T) {
	chrome := artifactChromeVersionFixture(t, "printf 'Chromium 130.0.6723.91\\n'\nexec /bin/sleep 30")
	ctx, cancel := context.WithTimeout(context.Background(), 250*time.Millisecond)
	defer cancel()
	started := time.Now()
	version, err := appMCPProbeArtifactChromeVersion(ctx, chrome)
	if err == nil || version != "" || ctx.Err() != context.DeadlineExceeded {
		t.Fatalf("caller deadline must refuse the provider: version=%q err=%v context=%v", version, err, ctx.Err())
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("caller deadline did not promptly stop the provider: %s", elapsed)
	}
}

func TestAppMCPArtifactChromeVersionCallerCancellation(t *testing.T) {
	chrome := artifactChromeVersionFixture(t, "printf 'Chromium 130.0.6723.91\\n'\nexec /bin/sleep 30")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	timer := time.AfterFunc(250*time.Millisecond, cancel)
	defer timer.Stop()
	started := time.Now()
	version, err := appMCPProbeArtifactChromeVersion(ctx, chrome)
	if err == nil || version != "" || ctx.Err() != context.Canceled {
		t.Fatalf("cancelled caller must refuse the provider: version=%q err=%v context=%v", version, err, ctx.Err())
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("caller cancellation did not promptly stop the provider: %s", elapsed)
	}
}

func TestAppMCPArtifactChromeVersionProbeTimeout(t *testing.T) {
	chrome := artifactChromeVersionFixture(t, "printf 'Chromium 130.0.6723.91\\n'\nexec /bin/sleep 30")
	started := time.Now()
	version, err := appMCPProbeArtifactChromeVersion(context.Background(), chrome)
	if err == nil || version != "" {
		t.Fatalf("provider exceeding the probe budget must be refused: version=%q err=%v", version, err)
	}
	if elapsed := time.Since(started); elapsed < 9*time.Second || elapsed > 20*time.Second {
		t.Fatalf("expected the bounded ten-second probe budget, took %s", elapsed)
	}
}

func TestAppMCPArtifactChromeVersionInvalidProvider(t *testing.T) {
	for _, tc := range []struct {
		name string
		body string
	}{
		{name: "empty", body: "exit 0"},
		{name: "oversized", body: "printf '" + strings.Repeat("v", 257) + "'"},
		{name: "nonzero_exit", body: "printf 'Chromium 130.0.6723.91\\n'\nexit 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			version, err := appMCPProbeArtifactChromeVersion(context.Background(), artifactChromeVersionFixture(t, tc.body))
			if err == nil || version != "" {
				t.Fatalf("invalid provider was accepted: version=%q err=%v", version, err)
			}
		})
	}
	t.Run("missing", func(t *testing.T) {
		version, err := appMCPProbeArtifactChromeVersion(context.Background(), filepath.Join(t.TempDir(), "missing-chrome"))
		if err == nil || version != "" {
			t.Fatalf("missing provider was accepted: version=%q err=%v", version, err)
		}
	})
}
