//go:build !cli && !windows

package main

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var pdfHomeKeys = []string{"HOME", "XDG_CACHE_HOME", "XDG_CONFIG_HOME", "XDG_DATA_HOME", "XDG_RUNTIME_DIR"}

func TestPDFChromeHomeFixture(t *testing.T) {
	mode := os.Getenv("BENMORE_PDF_HOME_FIXTURE")
	if mode == "" {
		return
	}
	observed := map[string]string{}
	for _, key := range pdfHomeKeys {
		dir := os.Getenv(key)
		observed[key] = dir
		if err := os.MkdirAll(dir, 0700); err != nil {
			os.Exit(41)
		}
		if err := os.WriteFile(filepath.Join(dir, "renderer-residue"), []byte(key), 0600); err != nil {
			os.Exit(42)
		}
	}
	raw, _ := json.Marshal(observed)
	if err := os.WriteFile(os.Getenv("BENMORE_PDF_HOME_OBSERVATION"), raw, 0600); err != nil {
		os.Exit(43)
	}
	if strings.HasPrefix(mode, "cleanup-") {
		locked := filepath.Join(os.Getenv("HOME"), "cleanup-denied")
		if err := os.Mkdir(locked, 0700); err != nil {
			os.Exit(47)
		}
		if err := os.WriteFile(filepath.Join(locked, "residue"), []byte("fixture"), 0600); err != nil {
			os.Exit(48)
		}
		if err := os.Chmod(locked, 0000); err != nil {
			os.Exit(49)
		}
		mode = strings.TrimPrefix(mode, "cleanup-")
	}
	switch mode {
	case "success":
		if err := os.WriteFile(os.Getenv("BENMORE_PDF_HOME_OUTPUT"), []byte("%PDF-1.7\nfixture\n%%EOF\n"), 0600); err != nil {
			os.Exit(44)
		}
		os.Exit(0)
	case "failure":
		os.Exit(23)
	case "timeout":
		time.Sleep(time.Minute)
		os.Exit(45)
	default:
		os.Exit(46)
	}
}

// A renderer may create desktop caches even when it exits before producing a
// PDF. Those files must never land in the app's HOME or become app source.
func TestPDFChromeKeepsHomeStateInsideTemporaryJob(t *testing.T) {
	for _, mode := range []string{"success", "success-inherited", "failure", "timeout"} {
		t.Run(mode, func(t *testing.T) {
			fixtureMode := strings.TrimSuffix(mode, "-inherited")
			appHome, job := t.TempDir(), t.TempDir()
			path := filepath.Join(job, "output.pdf")
			observation := filepath.Join(job, "environment.json")
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPDFChromeHomeFixture$")
			if mode == "success-inherited" {
				t.Setenv("BENMORE_PDF_HOME_FIXTURE", fixtureMode)
				t.Setenv("BENMORE_PDF_HOME_OBSERVATION", observation)
				t.Setenv("BENMORE_PDF_HOME_OUTPUT", path)
				for _, key := range pdfHomeKeys {
					t.Setenv(key, filepath.Join(appHome, key))
				}
			} else {
				cmd.Env = append(os.Environ(), "BENMORE_PDF_HOME_FIXTURE="+fixtureMode, "BENMORE_PDF_HOME_OBSERVATION="+observation, "BENMORE_PDF_HOME_OUTPUT="+path)
				for _, key := range pdfHomeKeys {
					cmd.Env = append(cmd.Env, key+"="+filepath.Join(appHome, key))
				}
			}
			_, err := runPDFChrome(ctx, cmd, path)
			switch fixtureMode {
			case "success":
				if err != nil || !pdfOutputComplete(path) {
					t.Fatalf("successful fixture: %v", err)
				}
			case "failure":
				var exitErr *exec.ExitError
				if !errors.As(err, &exitErr) || exitErr.ExitCode() != 23 {
					t.Fatalf("lost renderer failure: %v", err)
				}
			case "timeout":
				if !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("lost renderer deadline: %v", err)
				}
			}
			if cmd.ProcessState == nil {
				t.Fatal("renderer was not reaped before cleanup")
			}
			raw, err := os.ReadFile(observation)
			if err != nil {
				t.Fatal(err)
			}
			var observed map[string]string
			if err := json.Unmarshal(raw, &observed); err != nil {
				t.Fatal(err)
			}
			for _, key := range pdfHomeKeys {
				dir := observed[key]
				rel, err := filepath.Rel(job, dir)
				if err != nil || rel == "." || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) || filepath.IsAbs(rel) {
					t.Errorf("%s escaped private job: %q", key, dir)
				}
				if _, err := os.Stat(dir); !os.IsNotExist(err) {
					t.Errorf("%s residue survived renderer completion: %v", key, err)
				}
			}
			entries, err := os.ReadDir(appHome)
			if err != nil || len(entries) != 0 {
				t.Errorf("renderer wrote to app home: %d entries, %v", len(entries), err)
			}
		})
	}
}

func TestPDFChromeHomeCleanupWhenStartFails(t *testing.T) {
	job := t.TempDir()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, filepath.Join(job, "missing-renderer"))
	if _, err := runPDFChrome(ctx, cmd, filepath.Join(job, "out.pdf")); err == nil {
		t.Fatal("missing renderer accepted")
	}
	entries, err := os.ReadDir(job)
	if err != nil || len(entries) != 0 {
		t.Fatalf("failed start left runtime directories: %d entries, %v", len(entries), err)
	}
}

// Use a real renderer-created directory whose permissions prevent RemoveAll,
// so cleanup failures cannot be mistaken for successful, residue-free renders.
func TestPDFChromeHomeCleanupFailurePreservesRendererError(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can remove the permission-denied fixture directory")
	}
	for _, mode := range []string{"success", "failure"} {
		t.Run(mode, func(t *testing.T) {
			job := t.TempDir()
			path := filepath.Join(job, "output.pdf")
			observation := filepath.Join(job, "environment.json")
			// Register restoration before the child can create the directory,
			// including when a later assertion fails or the fixture times out.
			t.Cleanup(func() {
				matches, err := filepath.Glob(filepath.Join(job, "chrome-home-*", "cleanup-denied"))
				if err != nil {
					t.Error(err)
				}
				for _, locked := range matches {
					if err := os.Chmod(locked, 0700); err != nil && !os.IsNotExist(err) {
						t.Errorf("restore fixture permissions: %v", err)
					}
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestPDFChromeHomeFixture$")
			cmd.Env = append(os.Environ(), "BENMORE_PDF_HOME_FIXTURE=cleanup-"+mode, "BENMORE_PDF_HOME_OBSERVATION="+observation, "BENMORE_PDF_HOME_OUTPUT="+path)
			_, runErr := runPDFChrome(ctx, cmd, path)
			if cmd.ProcessState == nil {
				t.Fatal("renderer was not reaped before cleanup")
			}
			raw, err := os.ReadFile(observation)
			if err != nil {
				t.Fatal(err)
			}
			var observed map[string]string
			if err := json.Unmarshal(raw, &observed); err != nil {
				t.Fatal(err)
			}
			if _, err := os.ReadDir(filepath.Join(observed["HOME"], "cleanup-denied")); !errors.Is(err, os.ErrPermission) {
				t.Skipf("filesystem did not preserve a permission-denied cleanup fixture: %v", err)
			}
			if runErr == nil || !strings.Contains(runErr.Error(), "PDF runtime home cleanup:") || !errors.Is(runErr, os.ErrPermission) {
				t.Fatalf("cleanup denial was not reported: %v", runErr)
			}
			var exitErr *exec.ExitError
			if mode == "failure" {
				if !errors.As(runErr, &exitErr) || exitErr.ExitCode() != 23 {
					t.Fatalf("cleanup failure obscured renderer exit 23: %v", runErr)
				}
			} else if errors.As(runErr, &exitErr) || !pdfOutputComplete(path) {
				t.Fatalf("successful renderer result changed: %v", runErr)
			}
		})
	}
}
