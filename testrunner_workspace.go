//go:build !cli

package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// `benmore test` runs on a disposable copy of the app's source. It used to load
// the app in place after deleting data.db, so it refused every directory with a
// .benmore/ ("looks like a deployed app"), the sign it took for a hosted app.
// Cloud deploy and pull write .benmore/app into every linked workspace and an
// app load writes .benmore/app_id, so it refused every linked workspace and its
// own second run in a fresh one. In the copy nothing of the workspace is
// written: its data.db, uploads/ and .benmore/ stay as they are.

// runServerTestsOnCopy runs `benmore test` for dir (mode all, app or framework)
// and returns the results. A run that cannot reach the tests (a hosted app
// instance, a copy or load failure) returns a failed result for that step and
// a SUMMARY entry, and the error.
func runServerTestsOnCopy(dir, mode string) ([]AppTestResult, error) {
	if hostedAppInstanceDir(dir) {
		err := fmt.Errorf("refusing to run tests in %s: it is a hosted app instance (.benmore/server-secret). Run benmore test in a workspace of the app (benmore pull) instead", dir)
		return testSetupFailure(nil, "hosted app", err), err
	}
	tmp, err := os.MkdirTemp("", "benmore-test-*")
	if err != nil {
		err = fmt.Errorf("copy source: %w", err)
		return testSetupFailure(nil, "copy source", err), err
	}
	defer os.RemoveAll(tmp)
	if resolved, resolveErr := filepath.EvalSymlinks(tmp); resolveErr == nil {
		tmp = resolved
	}
	copyDir := filepath.Join(tmp, filepath.Base(dir))
	if err := copyTestSource(dir, copyDir, true); err != nil {
		err = fmt.Errorf("copy source: %w", err)
		return testSetupFailure(nil, "copy source", err), err
	}
	// Before the load: the source checks a push runs (sourceCheckTestResults),
	// so a file the platform refuses fails here too.
	results := sourceCheckTestResults(copyDir)
	app, err := loadAppForServerTests(copyDir)
	if err != nil {
		err = fmt.Errorf("load app: %w", err)
		return testSetupFailure(results, "load app", err), err
	}
	defer app.Shutdown()
	switch mode {
	case "app":
		results = append(results, RunAppTests(app)...)
	case "framework":
		results = append(results, RunAllTests(app, GenerateFrameworkTests(app), false)...)
	default:
		results = append(results, RunAllTests(app, GenerateFrameworkTests(app), true)...)
	}
	return results, nil
}

// testSetupFailure appends a failed result for the step the run could not get
// past and a SUMMARY entry, so `benmore test --json` shows that the tests did
// not run. A refused run used to print only the source-check results.
func testSetupFailure(results []AppTestResult, step string, err error) []AppTestResult {
	results = append(results, AppTestResult{File: "setup", Test: step, Pass: false, Message: err.Error()})
	total, passed := testResultCounts(results)
	return append(results, AppTestResult{File: "SUMMARY", Test: "TOTAL", Pass: false,
		Message: fmt.Sprintf("%d/%d tests passed; the tests did not run: %s", passed, total, err)})
}

// hostedAppInstanceDir reports whether dir is an app instance the platform
// serves: the router writes .benmore/server-secret into every instance under
// its apps directory. A workspace never has one (pull and deploy leave
// .benmore/ out of the source they move).
func hostedAppInstanceDir(dir string) bool {
	_, err := os.Lstat(filepath.Join(dir, ".benmore", "server-secret"))
	return err == nil
}

// copyTestSource copies an app's source tree for a test run. It leaves out
// framework and version-control state (.benmore, .git), dependencies
// (node_modules), stored data (uploads/, data.db and other SQLite files),
// secret files and key material, and anything that is not a regular file.
// keepEnv keeps env.yaml, which the app reads its configuration from:
// `benmore test` loads the app with it as it always has, while `benmore
// verify` copies no secrets.
func copyTestSource(src, dst string, keepEnv bool) error {
	srcAbs, err := filepath.Abs(src)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dst, 0o755); err != nil {
		return err
	}
	return filepath.Walk(srcAbs, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(srcAbs, path)
		if err != nil || rel == "." {
			return err
		}
		relSlash := filepath.ToSlash(rel)
		first := strings.Split(relSlash, "/")[0]
		if first == ".benmore" || first == ".git" || first == "uploads" || first == "node_modules" || restoreStagePath(relSlash) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		base := filepath.Base(relSlash)
		if keepEnv && relSlash == "env.yaml" {
			// The app's own environment file, at the app root.
		} else if base == "env.yaml" || base == "secrets.yaml" || base == ".env" || strings.HasPrefix(base, ".env.") ||
			base == "data.db" || strings.HasPrefix(base, "data.db-") || strings.HasSuffix(base, ".db") ||
			strings.HasSuffix(base, ".sqlite") || strings.HasSuffix(base, ".key") || strings.HasSuffix(base, ".pem") {
			return nil
		}
		target := filepath.Join(dst, rel)
		if info.IsDir() {
			return os.MkdirAll(target, info.Mode().Perm())
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return copyTestSourceFile(path, target, info.Mode().Perm())
	})
}

func copyTestSourceFile(src, dst string, mode os.FileMode) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	out, err := os.OpenFile(dst, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, mode)
	if err != nil {
		_ = in.Close()
		return err
	}
	_, copyErr := io.Copy(out, in)
	inErr := in.Close()
	outErr := out.Close()
	return errors.Join(copyErr, inErr, outErr)
}
