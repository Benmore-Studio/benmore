//go:build !cli

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func TestLocalRotationCaptureFailsClosedOnIsolationAndUnsafeYAML(t *testing.T) {
	oldSource, newSource := rotationJournalTestKeys()
	t.Run("isolated-app", func(t *testing.T) {
		app, lease := rotationJournalTestLease(t)
		if err := os.WriteFile(filepath.Join(app, "env.yaml"), []byte("ENCRYPTION_KEY: "+oldSource+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		prior := isolateAppEnvironment.Load()
		isolateAppEnvironment.Store(true)
		t.Cleanup(func() { isolateAppEnvironment.Store(prior) })
		if _, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource); !errors.Is(err, errAppRotationUnsupported) {
			t.Fatalf("isolated app selected local YAML backend: %v", err)
		}
	})
	t.Run("duplicate-key-YAML", func(t *testing.T) {
		app, lease := rotationJournalTestLease(t)
		prior := isolateAppEnvironment.Load()
		isolateAppEnvironment.Store(false)
		t.Cleanup(func() { isolateAppEnvironment.Store(prior) })
		rotationUnsetEnv(t, "ENCRYPTION_KEY")
		rotationUnsetEnv(t, "CREDENTIALS_DIRECTORY")
		data := []byte("ENCRYPTION_KEY: " + oldSource + "\nENCRYPTION_KEY: " + oldSource + "\n")
		if err := os.WriteFile(filepath.Join(app, "env.yaml"), data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource); !errors.Is(err, errAppRotationUnsupported) {
			t.Fatalf("duplicate YAML key accepted for rotation: %v", err)
		}
	})
	t.Run("symlink-YAML", func(t *testing.T) {
		app, lease := rotationJournalTestLease(t)
		prior := isolateAppEnvironment.Load()
		isolateAppEnvironment.Store(false)
		t.Cleanup(func() { isolateAppEnvironment.Store(prior) })
		rotationUnsetEnv(t, "ENCRYPTION_KEY")
		outside := filepath.Join(t.TempDir(), "env.yaml")
		if err := os.WriteFile(outside, []byte("ENCRYPTION_KEY: "+oldSource+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(outside, filepath.Join(app, "env.yaml")); err != nil {
			t.Fatal(err)
		}
		if _, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource); !errors.Is(err, errAppRotationUnsupported) {
			t.Fatalf("symlink YAML accepted for rotation: %v", err)
		}
	})
	t.Run("unsafe-mode-YAML", func(t *testing.T) {
		app, lease := rotationJournalTestLease(t)
		prior := isolateAppEnvironment.Load()
		isolateAppEnvironment.Store(false)
		t.Cleanup(func() { isolateAppEnvironment.Store(prior) })
		rotationUnsetEnv(t, "ENCRYPTION_KEY")
		rotationUnsetEnv(t, "CREDENTIALS_DIRECTORY")
		path := filepath.Join(app, "env.yaml")
		if err := os.WriteFile(path, []byte("ENCRYPTION_KEY: "+oldSource+"\n"), 0600); err != nil {
			t.Fatal(err)
		}
		snap, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource)
		if err != nil {
			t.Fatalf("valid baseline did not capture: %v", err)
		}
		if _, err := prepareAppRotationJournal(context.Background(), lease, rotationJournalTestIdentity(), snap); err != nil {
			t.Fatalf("valid baseline did not prepare: %v", err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if _, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource); !errors.Is(err, errAppRotationUnsupported) {
			t.Fatalf("group-readable secret YAML was accepted: %v", err)
		}
	})
}

func TestLocalRotationBackendRevalidatesGeneratedGuardAndCancellation(t *testing.T) {
	app, lease := rotationJournalTestLease(t)
	oldSource, newSource := rotationJournalTestKeys()
	prior := isolateAppEnvironment.Load()
	isolateAppEnvironment.Store(false)
	t.Cleanup(func() { isolateAppEnvironment.Store(prior) })
	rotationUnsetEnv(t, "ENCRYPTION_KEY")
	rotationUnsetEnv(t, "CREDENTIALS_DIRECTORY")
	original := []byte("ENCRYPTION_KEY: " + oldSource + "\nKEEP: retained\n")
	if err := os.WriteFile(filepath.Join(app, "env.yaml"), original, 0600); err != nil {
		t.Fatal(err)
	}
	generatedDir := filepath.Join(app, ".benmore")
	if err := os.Mkdir(generatedDir, 0700); err != nil {
		t.Fatal(err)
	}
	generated := []byte("OTHER=\"preserved\"\n")
	if err := os.WriteFile(filepath.Join(generatedDir, "env"), generated, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := prepareAppRotationJournal(context.Background(), lease, rotationJournalTestIdentity(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	changedGuard := []byte("OTHER=\"changed\"\n")
	if err := os.WriteFile(filepath.Join(generatedDir, "env"), changedGuard, 0600); err != nil {
		t.Fatal(err)
	}
	if err := persistLocalRotationBackend(context.Background(), lease, journal); !errors.Is(err, errAppRotationConflict) {
		t.Fatalf("changed generated-file guard was overwritten: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(app, "env.yaml"))
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("generated-file conflict changed the lower-priority YAML")
	}
	if err := os.WriteFile(filepath.Join(generatedDir, "env"), generated, 0600); err != nil {
		t.Fatal(err)
	}
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := persistLocalRotationBackend(canceled, lease, journal); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled local persistence did not stop before mutation: %v", err)
	}
	got, err = os.ReadFile(filepath.Join(app, "env.yaml"))
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("canceled local persistence changed YAML")
	}
	if strings.Contains(journal.String()+journal.GoString(), oldSource) || strings.Contains(journal.String()+journal.GoString(), newSource) {
		t.Fatal("secret-bearing journal formatting exposed key source")
	}
}

func TestLocalRotationRejectsSameByteFileReplacementByIdentity(t *testing.T) {
	app, lease := rotationJournalTestLease(t)
	oldSource, newSource := rotationJournalTestKeys()
	prior := isolateAppEnvironment.Load()
	isolateAppEnvironment.Store(false)
	t.Cleanup(func() { isolateAppEnvironment.Store(prior) })
	rotationUnsetEnv(t, "ENCRYPTION_KEY")
	rotationUnsetEnv(t, "CREDENTIALS_DIRECTORY")
	original := []byte("ENCRYPTION_KEY: " + oldSource + "\nKEEP: retained\n")
	path := filepath.Join(app, "env.yaml")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := prepareAppRotationJournal(context.Background(), lease, rotationJournalTestIdentity(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(app, "env.replacement")
	if err := os.WriteFile(replacement, original, 0600); err != nil {
		t.Fatal(err)
	}
	oldInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	newInfo, err := os.Stat(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if os.SameFile(oldInfo, newInfo) {
		t.Fatal("fixture replacement reused the source inode")
	}
	if err := os.Rename(replacement, path); err != nil {
		t.Fatal(err)
	}
	if err := persistLocalRotationBackend(context.Background(), lease, journal); !errors.Is(err, errAppRotationConflict) {
		t.Fatalf("same-byte replacement inode was not rejected: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("identity conflict changed environment bytes")
	}
}

func TestLocalRotationRechecksSameValueProcessWinnerBeforeWriteAndRetry(t *testing.T) {
	app, lease := rotationJournalTestLease(t)
	oldSource, newSource := rotationJournalTestKeys()
	prior := isolateAppEnvironment.Load()
	isolateAppEnvironment.Store(false)
	t.Cleanup(func() { isolateAppEnvironment.Store(prior) })
	rotationUnsetEnv(t, "ENCRYPTION_KEY")
	rotationUnsetEnv(t, "CREDENTIALS_DIRECTORY")
	original := []byte("ENCRYPTION_KEY: " + oldSource + "\nKEEP: retained\n")
	path := filepath.Join(app, "env.yaml")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	snapshot, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := prepareAppRotationJournal(context.Background(), lease, rotationJournalTestIdentity(), snapshot)
	if err != nil {
		t.Fatal(err)
	}
	rotationSetEnv(t, "ENCRYPTION_KEY", oldSource)
	if err := persistLocalRotationBackend(context.Background(), lease, journal); !errors.Is(err, errAppRotationConflict) {
		t.Fatalf("same-value process winner was written beneath: %v", err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatal("same-value process conflict changed YAML")
	}
	rotationUnsetEnv(t, "ENCRYPTION_KEY")
	if err := persistLocalRotationBackend(context.Background(), lease, journal); err != nil {
		t.Fatal(err)
	}
	rotationSetEnv(t, "ENCRYPTION_KEY", newSource)
	if err := verifyLocalRotationBackend(context.Background(), lease, journal); !errors.Is(err, errAppRotationConflict) {
		t.Fatalf("same-value process winner was accepted on exact-new verification: %v", err)
	}
}

func TestLocalRotationRejectsAppDirectorySymlinkAlias(t *testing.T) {
	app, lease := rotationJournalTestLease(t)
	oldSource, newSource := rotationJournalTestKeys()
	prior := isolateAppEnvironment.Load()
	isolateAppEnvironment.Store(false)
	t.Cleanup(func() { isolateAppEnvironment.Store(prior) })
	rotationUnsetEnv(t, "ENCRYPTION_KEY")
	rotationUnsetEnv(t, "CREDENTIALS_DIRECTORY")
	path := filepath.Join(app, "env.yaml")
	original := []byte("ENCRYPTION_KEY: " + oldSource + "\nKEEP: retained\n")
	if err := os.WriteFile(path, original, 0600); err != nil {
		t.Fatal(err)
	}
	baseline, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource)
	if err != nil || baseline == nil || baseline.EffectiveSource != "env.yaml" {
		t.Fatalf("canonical app positive capture failed: snapshot=%v err=%v", baseline, err)
	}
	before, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if !before.Mode().IsRegular() || before.Mode().Perm() != 0600 {
		t.Fatalf("canonical environment fixture metadata: mode=%v", before.Mode())
	}
	appInfoBefore, err := os.Stat(app)
	if err != nil {
		t.Fatal(err)
	}
	authorityPath := lease.authorityPath
	authorityPathInfo, err := os.Lstat(authorityPath)
	if err != nil || !authorityPathInfo.IsDir() || authorityPathInfo.Mode().Perm() != 0700 || authorityPathInfo.Mode()&os.ModeSymlink != 0 {
		t.Fatalf("canonical authority root path metadata: info=%v err=%v", authorityPathInfo, err)
	}
	rootHandle, err := lease.root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	authorityIdentity, statErr := rootHandle.Stat()
	closeErr := rootHandle.Close()
	if statErr != nil || closeErr != nil || !os.SameFile(authorityPathInfo, authorityIdentity) {
		t.Fatalf("capture canonical authority identity from held root: stat=%v close=%v", statErr, closeErr)
	}
	journalName := rotationJournalName(lease.key)
	checkedAuthorityInventory := func() (names []string, retErr error) {
		pathInfo, err := os.Lstat(authorityPath)
		if err != nil || !pathInfo.IsDir() || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(authorityIdentity, pathInfo) {
			return nil, errors.Join(errors.New("canonical authority root path changed"), err)
		}
		root, err := os.OpenRoot(authorityPath)
		if err != nil {
			return nil, err
		}
		defer func() { retErr = errors.Join(retErr, root.Close()) }()
		opened, err := root.Open(".")
		if err != nil {
			return nil, err
		}
		openedInfo, statErr := opened.Stat()
		entries, readErr := opened.ReadDir(-1)
		closeErr := opened.Close()
		currentPathInfo, pathErr := os.Lstat(authorityPath)
		if statErr != nil || readErr != nil || closeErr != nil || pathErr != nil || !os.SameFile(authorityIdentity, openedInfo) || !os.SameFile(currentPathInfo, openedInfo) {
			return nil, errors.Join(errors.New("checked canonical authority root identity changed"), statErr, readErr, closeErr, pathErr)
		}
		names = make([]string, 0, len(entries))
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		sort.Strings(names)
		if _, err := root.Lstat(journalName); !os.IsNotExist(err) {
			return nil, errors.Join(errors.New("canonical rotation journal unexpectedly exists"), err)
		}
		return names, nil
	}
	sameInventory := func(left, right []string) bool {
		if len(left) != len(right) {
			return false
		}
		for i := range left {
			if left[i] != right[i] {
				return false
			}
		}
		return true
	}
	inventoryBefore, err := checkedAuthorityInventory()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(authorityPath, journalName)); !os.IsNotExist(err) {
		t.Fatalf("canonical journal existed before alias checks: %v", err)
	}
	alias := filepath.Join(t.TempDir(), "app-alias")
	if err := os.Symlink(app, alias); err != nil {
		t.Fatal(err)
	}
	aliasInfo, err := os.Lstat(alias)
	if err != nil {
		t.Fatal(err)
	}
	if aliasInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatal("directory alias fixture is not a symlink")
	}
	resolved, err := filepath.EvalSymlinks(alias)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Clean(resolved) != app {
		t.Fatalf("directory symlink resolves to %q, want canonical app %q", resolved, app)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}
	aliasLease, err := acquireAppMCPAuthorityLease(context.Background(), alias)
	if aliasLease != nil {
		_ = aliasLease.Close()
		t.Fatal("alias authority constructor returned a lease")
	}
	if err == nil || err.Error() != "application authority locator requires its original canonical app path" {
		t.Fatalf("alias authority constructor did not return the specific canonical-path refusal: %v", err)
	}
	after, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, original) {
		t.Fatalf("alias constructor refusal changed environment bytes: %v", err)
	}
	if !os.SameFile(before, after) || !after.Mode().IsRegular() || after.Mode().Perm() != 0600 {
		t.Fatal("alias constructor refusal changed environment identity or mode")
	}
	aliasInfoAfter, err := os.Lstat(alias)
	if err != nil || !os.SameFile(aliasInfo, aliasInfoAfter) || aliasInfoAfter.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("alias constructor refusal changed symlink identity: info=%v err=%v", aliasInfoAfter, err)
	}
	resolved, err = filepath.EvalSymlinks(alias)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil || filepath.Clean(resolved) != app {
		t.Fatalf("alias constructor refusal changed symlink target: resolved=%q err=%v", resolved, err)
	}
	inventoryAfterAlias, err := checkedAuthorityInventory()
	if err != nil || !sameInventory(inventoryBefore, inventoryAfterAlias) {
		t.Fatalf("alias constructor refusal changed checked authority inventory: before=%v after=%v err=%v", inventoryBefore, inventoryAfterAlias, err)
	}

	canonicalLease, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatalf("genuine canonical owner did not recover after alias refusal: %v", err)
	}
	t.Cleanup(func() {
		if err := canonicalLease.Close(); err != nil {
			t.Errorf("close recovered canonical owner: %v", err)
		}
	})
	recoveredCapture, err := captureLocalRotationBackend(context.Background(), canonicalLease, oldSource, newSource)
	if err != nil || recoveredCapture == nil || recoveredCapture.EffectiveSource != "env.yaml" || !bytes.Equal(recoveredCapture.OriginalBytes, original) {
		t.Fatalf("canonical backend capture did not recover after alias refusal: snapshot=%v err=%v", recoveredCapture, err)
	}
	inventoryAfterRecovery, err := checkedAuthorityInventory()
	if err != nil || !sameInventory(inventoryBefore, inventoryAfterRecovery) {
		t.Fatalf("recovery capture changed checked authority inventory: before=%v after=%v err=%v", inventoryBefore, inventoryAfterRecovery, err)
	}

	retained := app + ".retained"
	moved, aliasInstalled, restored := false, false, false
	var replacementLinkInfo os.FileInfo
	restoreOriginalApp := func() error {
		if restored {
			return nil
		}
		if aliasInstalled {
			current, err := os.Lstat(app)
			if err != nil {
				return err
			}
			target, err := os.Readlink(app)
			if err != nil || current.Mode()&os.ModeSymlink == 0 || target != retained || (replacementLinkInfo != nil && !os.SameFile(replacementLinkInfo, current)) {
				return errors.Join(errors.New("refusing to remove a non-fixture application replacement"), err)
			}
			if err := os.Remove(app); err != nil {
				return err
			}
			aliasInstalled = false
		}
		if moved {
			if _, err := os.Lstat(app); err == nil || !os.IsNotExist(err) {
				return errors.Join(errors.New("original application restore path is not absent"), err)
			}
			if err := os.Rename(retained, app); err != nil {
				return err
			}
			moved = false
		}
		restored = true
		return nil
	}
	if err := os.Rename(app, retained); err != nil {
		t.Fatal(err)
	}
	moved = true
	t.Cleanup(func() {
		if err := restoreOriginalApp(); err != nil {
			t.Errorf("restore original application during cleanup: %v", err)
		}
	})
	if err := os.Symlink(retained, app); err != nil {
		t.Fatalf("install application replacement symlink: %v", err)
	}
	aliasInstalled = true
	replacementLinkInfo, err = os.Lstat(app)
	if err != nil || replacementLinkInfo.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("replacement application is not the fixture symlink: info=%v err=%v", replacementLinkInfo, err)
	}
	linkTarget, err := os.Readlink(app)
	if err != nil || linkTarget != retained {
		t.Fatalf("replacement symlink target is not the retained original app: target=%q err=%v", linkTarget, err)
	}
	retainedInfo, err := os.Stat(retained)
	if err != nil || !os.SameFile(appInfoBefore, retainedInfo) {
		t.Fatalf("retained sibling is not the original application: info=%v err=%v", retainedInfo, err)
	}
	resolvedReplacement, err := filepath.EvalSymlinks(app)
	if err != nil {
		t.Fatal(err)
	}
	resolvedReplacement, err = filepath.Abs(resolvedReplacement)
	if err != nil || filepath.Clean(resolvedReplacement) != retained {
		t.Fatalf("replacement app does not resolve to retained original: resolved=%q err=%v", resolvedReplacement, err)
	}
	refusedCapture, err := captureLocalRotationBackend(context.Background(), canonicalLease, oldSource, newSource)
	// validateRotationAuthorityRoot rejects the changed lease path before backend capture's later path checks.
	if refusedCapture != nil || err == nil || err.Error() != "rotation authority lease is unavailable" {
		t.Fatalf("unchanged genuine lease did not fail at authority validation for replaced app path: snapshot=%v err=%v", refusedCapture, err)
	}
	retainedEnvPath := filepath.Join(retained, "env.yaml")
	retainedEnvInfo, envStatErr := os.Lstat(retainedEnvPath)
	retainedEnvBytes, envReadErr := os.ReadFile(retainedEnvPath)
	if envStatErr != nil || envReadErr != nil || !os.SameFile(before, retainedEnvInfo) || !retainedEnvInfo.Mode().IsRegular() || retainedEnvInfo.Mode().Perm() != 0600 || !bytes.Equal(retainedEnvBytes, original) {
		t.Fatalf("backend refusal changed retained environment identity/bytes: stat=%v read=%v", envStatErr, envReadErr)
	}
	aliasInfoAfter, err = os.Lstat(alias)
	if err != nil || !os.SameFile(aliasInfo, aliasInfoAfter) {
		t.Fatalf("replacement refusal changed original test alias: info=%v err=%v", aliasInfoAfter, err)
	}
	resolved, err = filepath.EvalSymlinks(alias)
	if err != nil {
		t.Fatal(err)
	}
	resolved, err = filepath.Abs(resolved)
	if err != nil || filepath.Clean(resolved) != retained {
		t.Fatalf("test alias no longer resolves through replacement to retained original: resolved=%q err=%v", resolved, err)
	}
	inventoryDuringReplacement, err := checkedAuthorityInventory()
	if err != nil || !sameInventory(inventoryBefore, inventoryDuringReplacement) {
		t.Fatalf("replacement refusal changed checked authority inventory: before=%v after=%v err=%v", inventoryBefore, inventoryDuringReplacement, err)
	}
	if err := restoreOriginalApp(); err != nil {
		t.Fatalf("restore exact original application path: %v", err)
	}
	restoredAppInfo, err := os.Stat(app)
	if err != nil || !os.SameFile(appInfoBefore, restoredAppInfo) {
		t.Fatalf("restored app path is not the original native directory: info=%v err=%v", restoredAppInfo, err)
	}
	restoredEnvInfo, err := os.Lstat(path)
	if err != nil || !os.SameFile(before, restoredEnvInfo) || !restoredEnvInfo.Mode().IsRegular() || restoredEnvInfo.Mode().Perm() != 0600 {
		t.Fatalf("restored environment file identity or mode changed: info=%v err=%v", restoredEnvInfo, err)
	}
	restoredEnvBytes, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(restoredEnvBytes, original) {
		t.Fatalf("restored environment file bytes changed: %v", err)
	}
	recoveredAgain, err := captureLocalRotationBackend(context.Background(), canonicalLease, oldSource, newSource)
	if err != nil || recoveredAgain == nil || recoveredAgain.EffectiveSource != "env.yaml" || !bytes.Equal(recoveredAgain.OriginalBytes, original) {
		t.Fatalf("backend capture did not recover after exact app restoration: snapshot=%v err=%v", recoveredAgain, err)
	}
	inventoryAfterRestore, err := checkedAuthorityInventory()
	if err != nil || !sameInventory(inventoryBefore, inventoryAfterRestore) {
		t.Fatalf("restored capture changed checked authority inventory: before=%v after=%v err=%v", inventoryBefore, inventoryAfterRestore, err)
	}
	if err := canonicalLease.Close(); err != nil {
		t.Fatal(err)
	}
	freshLease, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatalf("canonical owner did not reacquire after normal release: %v", err)
	}
	t.Cleanup(func() {
		if err := freshLease.Close(); err != nil {
			t.Errorf("close fresh canonical owner: %v", err)
		}
	})
	if err := freshLease.Close(); err != nil {
		t.Fatal(err)
	}
}
