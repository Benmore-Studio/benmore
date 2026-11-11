//go:build !cli

package main

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"

	"go.yaml.in/yaml/v3"
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
	copyDir, removeCopy, err := disposableTestCopy(dir, "benmore-test-*", filepath.Base(dir), true)
	if err != nil {
		err = fmt.Errorf("copy source: %w", err)
		return testSetupFailure(nil, "copy source", err), err
	}
	defer removeCopy()
	// Before the load: the source checks a push runs (sourceCheckTestResults),
	// so a file the platform refuses fails here too.
	releaseLog := holdLoadLog()
	results := sourceCheckTestResults(copyDir)
	app, err := loadAppForServerTests(copyDir)
	releaseLog(err != nil)
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
	return testRunResults(results), nil
}

// holdLoadLog keeps what the source check and the app load log out of the
// output of `benmore test`: about 70 lines of load phases, several of them
// four times, stood before the results of every run. The returned function
// ends the hold: a failed load prints everything it logged, a load that
// worked prints each WARNING line once. What the tests log is not held.
func holdLoadLog() func(failed bool) {
	out, held := log.Writer(), &bytes.Buffer{}
	log.SetOutput(held)
	return func(failed bool) {
		log.SetOutput(out)
		printed := map[string]bool{}
		for _, line := range strings.SplitAfter(held.String(), "\n") {
			at := strings.Index(line, "WARNING")
			if failed || (at >= 0 && !printed[line[at:]]) {
				_, _ = io.WriteString(out, line)
			}
			if at >= 0 {
				printed[line[at:]] = true
			}
		}
	}
}

// testRunResults is what a run reports once the tests ran: every result once,
// and a SUMMARY that counts all of them. The SUMMARY used to count only the
// tests, so with a failed source check `--json` said `4/10 tests passed`
// where the text output of the same run said `test: 4/11 passed`. A test file
// that is not YAML failed twice, as the push's syntax check and as the
// runner's `load`: it is reported once, as `load`.
func testRunResults(results []AppTestResult) []AppTestResult {
	notYAML := map[string]bool{}
	for _, r := range results {
		if r.Test == "load" && strings.HasPrefix(r.Message, appTestFileNotLoaded+appTestFileNotYAML) {
			notYAML[r.File] = true
		}
	}
	out := results[:0:0]
	summarized := false
	for _, r := range results {
		if r.File == "SUMMARY" && r.Test == "TOTAL" {
			summarized = true
			continue
		}
		if notYAML[r.File] && strings.HasPrefix(r.Test, sourceCheckTestPrefix) {
			continue
		}
		out = append(out, r)
	}
	if summarized {
		out = append(out, testRunSummary(out))
	}
	return out
}

// disposableTestCopy copies the app source at src into a new directory
// <temp>/<name> for a test run and returns it with the function that removes
// it. keepEnv is copyTestSource's.
//
// The copy's path holds no symbolic link. An app loads only from its canonical
// path (the connector authority binding refuses any other), and the system
// temp directory is often a link: macOS sets TMPDIR under /var, a link to
// /private/var. `benmore verify` did not resolve it, so there its tests
// stopped at "application authority locator requires its original canonical
// app path" while `benmore test` passed.
func disposableTestCopy(src, pattern, name string, keepEnv bool) (copyDir string, remove func(), err error) {
	tmp, err := os.MkdirTemp("", pattern)
	if err != nil {
		return "", nil, err
	}
	remove = func() { _ = os.RemoveAll(tmp) }
	resolved, err := filepath.EvalSymlinks(tmp)
	if err != nil {
		remove()
		return "", nil, err
	}
	copyDir = filepath.Join(resolved, name)
	if err := copyTestSource(src, copyDir, keepEnv); err != nil {
		remove()
		return "", nil, err
	}
	if err := giveTestCopyCommandKey(copyDir); err != nil {
		remove()
		return "", nil, err
	}
	return copyDir, remove, nil
}

// giveTestCopyCommandKey writes a new random ENCRYPTION_KEY into the env.yaml
// of a disposable copy whose source binds MCP commands and whose environment
// sets no key. Such an app refuses to load without a configured key
// (appMCPConfiguredLifecycleKey), because sealed approvals must stay readable
// across restarts. A test run keeps nothing: its database is created empty in
// the copy and removed with it, so the key seals only rows of that run and is
// gone with them. A workspace of a hosted app has no env.yaml (the platform
// holds the instance's key), and `benmore verify` copies none, so without
// this no test of such an app could run. The key never leaves the copy: it is
// not printed, not put in the process environment and not written to dir's
// source. Every other app loads as before, with no key added.
func giveTestCopyCommandKey(copyDir string) error {
	if !appSourceDeclaresMCPCommands(copyDir) {
		return nil
	}
	if has, known := appEnvironmentHasEncryptionKey(copyDir); has || !known {
		return nil // configured, or an env.yaml the load itself reports on
	}
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return fmt.Errorf("test encryption key: %w", err)
	}
	path := filepath.Join(copyDir, "env.yaml")
	existing, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	vars := map[string]string{}
	if len(existing) > 0 {
		if err := decodeConfigYAML(existing, &vars); err != nil {
			return nil // unreachable after a readable environment; the load reports it
		}
	}
	vars["ENCRYPTION_KEY"] = hex.EncodeToString(random)
	data, err := yaml.Marshal(vars)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
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
