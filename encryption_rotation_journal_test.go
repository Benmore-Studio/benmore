//go:build !cli

package main

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func rotationJournalTestKeys() (string, string) {
	return strings.Repeat("01", 32), strings.Repeat("02", 32)
}

func rotationSetEnv(t *testing.T, key, value string) {
	t.Helper()
	old, had := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, old)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

func rotationUnsetEnv(t *testing.T, key string) {
	t.Helper()
	old, had := os.LookupEnv(key)
	if err := os.Unsetenv(key); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if had {
			_ = os.Setenv(key, old)
		} else {
			_ = os.Unsetenv(key)
		}
	})
}

func rotationJournalTestIdentity() appRotationTransitionIdentity {
	return appRotationTransitionIdentity{OldGeneration: strings.Repeat("a", 64), NewGeneration: strings.Repeat("b", 64), RotationID: strings.Repeat("c", 64), OldMarkerDigest: strings.Repeat("d", 64), WriteEpoch: strings.Repeat("e", 64), MarkerVersion: 2}
}

func rotationJournalTestLease(t *testing.T) (string, *appMCPAuthorityLease) {
	t.Helper()
	app, err := filepath.Abs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	app, err = filepath.EvalSymlinks(app)
	if err != nil {
		t.Fatal(err)
	}
	app = filepath.Clean(app)
	authority := t.TempDir()
	if err := os.Chmod(authority, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	lease, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lease.Close() })
	return app, lease
}

func rotationJournalTestSnapshot(lease *appMCPAuthorityLease, app, oldSource, newSource string) appRotationBackendSnapshot {
	original := []byte("ENCRYPTION_KEY: " + oldSource + "\nKEEP: retained\n")
	desired := []byte("ENCRYPTION_KEY: " + newSource + "\nKEEP: retained\n")
	info, _ := os.Stat(app)
	return appRotationBackendSnapshot{Kind: appRotationLocalYAML, OwnerHash: lease.key, AppPath: app, AppDirectoryID: rotationFileIdentity(info), OldSource: oldSource, NewSource: newSource, EffectiveSource: "env.yaml", OriginalExists: true, OriginalMode: 0600, OriginalFileID: "device:inode", OriginalHash: hashBytesSHA256(original), OriginalBytes: original, DesiredBytes: desired}
}

func TestAppRotationJournalIsImmutableCanonicalAndOwnerBound(t *testing.T) {
	app, lease := rotationJournalTestLease(t)
	oldSource, newSource := rotationJournalTestKeys()
	backend := rotationJournalTestSnapshot(lease, app, oldSource, newSource)
	identity := rotationJournalTestIdentity()
	journal, err := prepareAppRotationJournal(context.Background(), lease, identity, &backend)
	if err != nil {
		t.Fatal("prepare rotation journal failed")
	}
	if journal == nil || !validRotationHex(journal.digest) {
		t.Fatal("prepared journal lacks validated disk digest")
	}
	info, err := lease.root.Lstat(rotationJournalName(lease.key))
	if err != nil || info.Mode().Perm() != 0600 || !info.Mode().IsRegular() || !fileOwnedByProcess(info) {
		t.Fatal("journal is not an owner-only regular file")
	}
	read, err := readAppRotationJournal(context.Background(), lease)
	if err != nil || read.digest != journal.digest {
		t.Fatal("journal readback changed its canonical bytes")
	}
	repeat, err := prepareAppRotationJournal(context.Background(), lease, identity, &backend)
	if err != nil || repeat.digest != journal.digest {
		t.Fatal("identical intent did not return the existing immutable journal")
	}
	other := identity
	other.RotationID = strings.Repeat("f", 64)
	if _, err := prepareAppRotationJournal(context.Background(), lease, other, &backend); !errors.Is(err, errAppRotationConflict) {
		t.Fatal("conflicting intent overwrote the immutable journal")
	}
	if got := journal.String() + journal.GoString() + journal.record.String() + journal.record.Backend.String() + journal.record.Backend.GoString(); strings.Contains(got, oldSource) || strings.Contains(got, newSource) {
		t.Fatal("secret-bearing record formatting was not redacted")
	}
	if _, err := prepareAppRotationJournal(nil, lease, identity, &backend); err == nil {
		t.Fatal("nil context accepted")
	}
	bad := backend
	bad.AppPath = t.TempDir()
	if err := validateRotationIdentity(identity, &bad, lease); err == nil {
		t.Fatal("snapshot from another app path accepted")
	}
	badSnapshot := backend
	badSnapshot.OriginalHash = strings.Repeat("f", 64)
	if _, err := prepareAppRotationJournal(context.Background(), lease, identity, &badSnapshot); err == nil {
		t.Fatal("invalid cross-field snapshot was durably published")
	}
	if _, err := lease.root.Lstat(rotationJournalName(lease.key)); err != nil {
		t.Fatal("invalid snapshot replaced the valid journal")
	}
}

func TestAppRotationJournalRetryCompletesDirectorySync(t *testing.T) {
	app, lease := rotationJournalTestLease(t)
	oldSource, newSource := rotationJournalTestKeys()
	backend := rotationJournalTestSnapshot(lease, app, oldSource, newSource)
	identity := rotationJournalTestIdentity()
	first, err := prepareAppRotationJournal(context.Background(), lease, identity, &backend)
	if err != nil {
		t.Fatal(err)
	}
	name := rotationJournalName(lease.key)
	raw, err := lease.root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	originalSync := syncRotationAuthorityDirectory
	t.Cleanup(func() { syncRotationAuthorityDirectory = originalSync })
	calls := 0
	syncRotationAuthorityDirectory = func(l *appMCPAuthorityLease) error { calls++; return originalSync(l) }
	if err := lease.root.Remove(name); err != nil {
		t.Fatal(err)
	}
	stage, err := stageRotationFile(lease.root, ".rotation-stage-", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := publishRotationFile(lease.root, stage, name); err != nil {
		t.Fatal(err)
	}
	retry, err := prepareAppRotationJournal(context.Background(), lease, identity, &backend)
	if err != nil {
		t.Fatalf("identical-intent retry failed: %v", err)
	}
	if retry.digest != first.digest || calls != 1 {
		t.Fatalf("identical-intent retry did not sync and verify existing bytes: digest=%q calls=%d", retry.digest, calls)
	}
	after, err := lease.root.ReadFile(name)
	if err != nil || !bytes.Equal(raw, after) {
		t.Fatal("identical-intent retry changed journal bytes")
	}
}

func TestAppRotationJournalRetrySurfacesDirectorySyncUnknown(t *testing.T) {
	app, lease := rotationJournalTestLease(t)
	oldSource, newSource := rotationJournalTestKeys()
	backend := rotationJournalTestSnapshot(lease, app, oldSource, newSource)
	identity := rotationJournalTestIdentity()
	if _, err := prepareAppRotationJournal(context.Background(), lease, identity, &backend); err != nil {
		t.Fatal(err)
	}
	name := rotationJournalName(lease.key)
	before, err := lease.root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	originalSync := syncRotationAuthorityDirectory
	t.Cleanup(func() { syncRotationAuthorityDirectory = originalSync })
	syncRotationAuthorityDirectory = func(*appMCPAuthorityLease) error { return errors.New("directory sync refused") }
	if _, err := prepareAppRotationJournal(context.Background(), lease, identity, &backend); !errors.Is(err, errAppRotationOutcomeUnknown) {
		t.Fatalf("failed retry durability boundary was not UNKNOWN: %v", err)
	}
	after, err := lease.root.ReadFile(name)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("failed durability retry discarded or changed immutable journal")
	}
}

func TestRotationSnapshotRejectsEmptyValuedYAMLKeySubstitution(t *testing.T) {
	t.Run("unchanged-empty-value", func(t *testing.T) {
		app, lease := rotationJournalTestLease(t)
		oldSource, newSource := rotationJournalTestKeys()
		original := []byte("ENCRYPTION_KEY: " + oldSource + "\nEMPTY: \"\"\n")
		desired := []byte("ENCRYPTION_KEY: " + newSource + "\nEMPTY: \"\"\n")
		snapshot := rotationJournalTestSnapshot(lease, app, oldSource, newSource)
		snapshot.OriginalBytes = original
		snapshot.DesiredBytes = desired
		snapshot.OriginalHash = hashBytesSHA256(original)
		if _, err := prepareAppRotationJournal(context.Background(), lease, rotationJournalTestIdentity(), &snapshot); err != nil {
			t.Fatalf("unchanged empty-valued YAML entry was refused: %v", err)
		}
	})
	t.Run("empty-key-substitution", func(t *testing.T) {
		app, lease := rotationJournalTestLease(t)
		oldSource, newSource := rotationJournalTestKeys()
		original := []byte("ENCRYPTION_KEY: " + oldSource + "\nEMPTY: \"\"\n")
		desired := []byte("ENCRYPTION_KEY: " + newSource + "\nREPLACEMENT: \"\"\n")
		snapshot := rotationJournalTestSnapshot(lease, app, oldSource, newSource)
		snapshot.OriginalBytes = original
		snapshot.DesiredBytes = desired
		snapshot.OriginalHash = hashBytesSHA256(original)
		if _, err := prepareAppRotationJournal(context.Background(), lease, rotationJournalTestIdentity(), &snapshot); err == nil {
			t.Fatal("empty-valued unrelated YAML key substitution was durably accepted")
		}
		if _, err := lease.root.Lstat(rotationJournalName(lease.key)); !os.IsNotExist(err) {
			t.Fatal("invalid empty-key substitution published journal intent")
		}
	})
}

func TestAppRotationJournalBindingRejectsMutableHandlesBeforeBackendWrites(t *testing.T) {
	app, lease := rotationJournalTestLease(t)
	oldSource, newSource := rotationJournalTestKeys()
	rotationUnsetEnv(t, "ENCRYPTION_KEY")
	rotationUnsetEnv(t, "CREDENTIALS_DIRECTORY")
	prior := isolateAppEnvironment.Load()
	isolateAppEnvironment.Store(false)
	t.Cleanup(func() { isolateAppEnvironment.Store(prior) })
	original := []byte("ENCRYPTION_KEY: " + oldSource + "\nKEEP: unchanged\n")
	if err := os.WriteFile(filepath.Join(app, "env.yaml"), original, 0600); err != nil {
		t.Fatal(err)
	}
	snap, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := prepareAppRotationJournal(context.Background(), lease, rotationJournalTestIdentity(), snap)
	if err != nil {
		t.Fatal(err)
	}
	rawBefore, err := lease.root.ReadFile(rotationJournalName(lease.key))
	if err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*appRotationJournal){"new-source": func(j *appRotationJournal) { j.record.Backend.NewSource = strings.Repeat("03", 32) }, "desired-bytes": func(j *appRotationJournal) {
		j.record.Backend.DesiredBytes = append([]byte(nil), j.record.Backend.OriginalBytes...)
	}, "identity": func(j *appRotationJournal) { j.record.Identity.RotationID = strings.Repeat("f", 64) }} {
		handle, err := readAppRotationJournal(context.Background(), lease)
		if err != nil {
			t.Fatal(err)
		}
		mutate(handle)
		if err := persistLocalRotationBackend(context.Background(), lease, handle); err == nil {
			t.Fatalf("mutated in-memory journal %s was used", name)
		}
		got, err := os.ReadFile(filepath.Join(app, "env.yaml"))
		if err != nil || !bytes.Equal(got, original) {
			t.Fatalf("mutated handle %s changed effective source", name)
		}
		current, err := lease.root.ReadFile(rotationJournalName(lease.key))
		if err != nil || !bytes.Equal(current, rawBefore) {
			t.Fatalf("mutated handle %s changed durable journal", name)
		}
	}
	if journal.digest != hashBytesSHA256(rawBefore) {
		t.Fatal("journal digest did not identify the exact durable record")
	}
}

func TestAppRotationJournalRejectsNoncanonicalAndUnsafeFiles(t *testing.T) {
	_, lease := rotationJournalTestLease(t)
	oldSource, newSource := rotationJournalTestKeys()
	backend := rotationJournalTestSnapshot(lease, lease.path, oldSource, newSource)
	j, err := prepareAppRotationJournal(context.Background(), lease, rotationJournalTestIdentity(), &backend)
	if err != nil {
		t.Fatal(err)
	}
	name := rotationJournalName(lease.key)
	original, err := lease.root.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	mutations := [][]byte{append(append([]byte(nil), original...), '\n'), bytes.Replace(original, []byte(`"version":1,`), []byte(`"version":1,"version":1,`), 1), bytes.Replace(original, []byte(`"version":1,`), []byte(`"version":1,"unknown":true,`), 1), append(append([]byte(nil), original...), []byte(` {}`)...)}
	for i, data := range mutations {
		if err := lease.root.WriteFile(name, data, 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := readAppRotationJournal(context.Background(), lease); err == nil {
			t.Fatalf("noncanonical journal mutation %d accepted", i)
		}
	}
	if err := lease.root.WriteFile(name, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := lease.root.Chmod(name, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readAppRotationJournal(context.Background(), lease); err == nil {
		t.Fatal("group-readable journal accepted")
	}
	if err := lease.root.Chmod(name, 0600); err != nil {
		t.Fatal(err)
	}
	if err := lease.root.Remove(name); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "outside")
	if err := os.WriteFile(outside, original, 0600); err != nil {
		t.Fatal(err)
	}
	if err := lease.root.Symlink(outside, name); err != nil {
		t.Fatal(err)
	}
	if _, err := readAppRotationJournal(context.Background(), lease); err == nil {
		t.Fatal("symlink journal accepted")
	}
	_ = lease.root.Remove(name)
	f, err := lease.root.OpenFile(name, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = f.Write(bytes.Repeat([]byte{'x'}, appRotationJournalLimit+1))
	_ = f.Close()
	if _, err := readAppRotationJournal(context.Background(), lease); err == nil {
		t.Fatal("oversized journal accepted")
	}
	_ = lease.root.Remove(name)
	if err := lease.root.Rename(".lock", ".lock.saved"); err != nil {
		t.Fatal(err)
	}
	replacement, err := lease.root.OpenFile(".lock", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		t.Fatal(err)
	}
	_ = replacement.Close()
	if _, err := readAppRotationJournal(context.Background(), lease); err == nil {
		t.Fatal("changed native lease lock accepted")
	}
	_ = j
}

func TestAppRotationJournalChildCrashBoundaries(t *testing.T) {
	if mode := os.Getenv("APP_ROTATION_JOURNAL_CHILD_MODE"); mode != "" {
		authority := os.Getenv("APP_ROTATION_JOURNAL_CHILD_AUTHORITY")
		app := os.Getenv("APP_ROTATION_JOURNAL_CHILD_APP")
		_ = os.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
		lease, err := acquireAppMCPAuthorityLease(context.Background(), app)
		if err != nil {
			os.Exit(31)
		}
		oldSource, newSource := rotationJournalTestKeys()
		backend := rotationJournalTestSnapshot(lease, app, oldSource, newSource)
		identity := rotationJournalTestIdentity()
		record := appRotationJournalRecord{Version: 1, Domain: "benmore.encryption-rotation", Identity: identity, Backend: backend}
		data, err := json.Marshal(record)
		if err != nil {
			os.Exit(32)
		}
		if mode == "directory-synced" {
			if err := syncRotationDirectory(lease.root); err != nil {
				os.Exit(37)
			}
			os.Exit(0)
		}
		if mode == "staged" || mode == "renamed" {
			if err := validateRotationIdentity(identity, &backend, lease); err != nil {
				os.Exit(33)
			}
			if err := validateRotationSnapshot(backend); err != nil {
				os.Exit(34)
			}
			tmp, err := stageRotationFile(lease.root, ".rotation-stage-", data)
			if err != nil {
				os.Exit(35)
			}
			if mode == "staged" {
				os.Exit(0)
			}
			if err := publishRotationFile(lease.root, tmp, rotationJournalName(lease.key)); err != nil {
				os.Exit(36)
			}
			os.Exit(0)
		}
		if mode == "conflict" {
			identity.RotationID = strings.Repeat("f", 64)
			if _, err := prepareAppRotationJournal(context.Background(), lease, identity, &backend); !errors.Is(err, errAppRotationConflict) {
				os.Exit(39)
			}
			os.Exit(0)
		}
		if _, err := prepareAppRotationJournal(context.Background(), lease, identity, &backend); err != nil {
			os.Exit(38)
		}
		os.Exit(0)
	}
	app := t.TempDir()
	authority := t.TempDir()
	if err := os.Chmod(authority, 0700); err != nil {
		t.Fatal(err)
	}
	runChild := func(mode string) {
		t.Helper()
		cmd := exec.Command(os.Args[0], "-test.run=^TestAppRotationJournalChildCrashBoundaries$")
		cmd.Env = append(os.Environ(), "APP_ROTATION_JOURNAL_CHILD_MODE="+mode, "APP_ROTATION_JOURNAL_CHILD_AUTHORITY="+authority, "APP_ROTATION_JOURNAL_CHILD_APP="+app)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("journal child %s failed: %v (%s)", mode, err, out)
		}
	}
	openLease := func() *appMCPAuthorityLease {
		t.Helper()
		t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
		lease, err := acquireAppMCPAuthorityLease(context.Background(), app)
		if err != nil {
			t.Fatal(err)
		}
		return lease
	}
	runChild("staged")
	lease := openLease()
	if _, err := readAppRotationJournal(context.Background(), lease); !os.IsNotExist(err) {
		lease.Close()
		t.Fatal("production stage was treated as a prepared journal")
	}
	lease.Close()
	runChild("renamed")
	lease = openLease()
	renamed, err := readAppRotationJournal(context.Background(), lease)
	if err != nil || renamed == nil {
		lease.Close()
		t.Fatal("fresh process could not read the post-rename journal")
	}
	lease.Close()
	runChild("directory-synced")
	lease = openLease()
	durable, err := readAppRotationJournal(context.Background(), lease)
	if err != nil || !validRotationHex(durable.digest) {
		lease.Close()
		t.Fatal("fresh process could not reopen the directory-synced journal")
	}
	lease.Close()
	runChild("durable")
	lease = openLease()
	j, err := readAppRotationJournal(context.Background(), lease)
	if err != nil || !validRotationHex(j.digest) {
		lease.Close()
		t.Fatal("fresh process could not reopen the durable recovery journal")
	}
	digest := j.digest
	lease.Close()
	runChild("conflict")
	lease = openLease()
	afterConflict, err := readAppRotationJournal(context.Background(), lease)
	if err != nil || afterConflict.digest != digest {
		lease.Close()
		t.Fatal("conflicting fresh-process intent changed the immutable journal")
	}
	_ = lease.Close()
}

func TestRotationFilePrimitivesPropagateNativePublicationFailures(t *testing.T) {
	app, lease := rotationJournalTestLease(t)
	stage, err := stageRotationFile(lease.root, ".rotation-stage-", []byte("closed test fixture bytes"))
	if err != nil {
		t.Fatal(err)
	}
	if err := publishRotationFile(lease.root, stage, "."); err == nil {
		t.Fatal("native rename into a directory unexpectedly succeeded")
	}
	if _, err := lease.root.Lstat(stage); err != nil {
		t.Fatal("failed native rename lost its staged recovery bytes")
	}
	if err := lease.root.Remove(stage); err != nil {
		t.Fatal(err)
	}
	stageDir := filepath.Join(app, "native-stage-create-failure")
	if err := os.Mkdir(stageDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(stageDir, 0700); err != nil {
		t.Fatal(err)
	}
	dirInfo, err := os.Stat(stageDir)
	if err != nil {
		t.Fatal(err)
	}
	if !dirInfo.IsDir() || dirInfo.Mode().Perm() != 0700 {
		t.Fatalf("stage fixture directory mode/type=%v; want directory 0700", dirInfo.Mode())
	}
	stageRoot, err := os.OpenRoot(stageDir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := stageRoot.Close(); err != nil {
			t.Errorf("close native stage root: %v", err)
		}
	}()
	entryNames := func() []string {
		t.Helper()
		entries, err := os.ReadDir(stageDir)
		if err != nil {
			t.Fatal(err)
		}
		names := make([]string, len(entries))
		for i, entry := range entries {
			names[i] = entry.Name()
		}
		return names
	}
	stageAndRemove := func(prefix string, data []byte) {
		t.Helper()
		name, err := stageRotationFile(stageRoot, prefix, data)
		if err != nil || name == "" {
			t.Fatalf("valid stage prefix %q failed: name=%q err=%v", prefix, name, err)
		}
		info, err := stageRoot.Lstat(name)
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
			t.Fatalf("stage mode/type=%v; want regular owner-only 0600", info.Mode())
		}
		actual, err := os.ReadFile(filepath.Join(stageDir, name))
		if err != nil || !bytes.Equal(actual, data) {
			t.Fatalf("staged bytes=%q err=%v; want %q", actual, err, data)
		}
		if err := stageRoot.Remove(name); err != nil {
			t.Fatalf("remove valid stage %q: %v", name, err)
		}
	}
	stageAndRemove(".rotation-before-", []byte("valid stage before native failure"))
	entriesBeforeFailure := entryNames()
	longPrefix := "." + strings.Repeat("x", 4096)
	stageName, stageErr := stageRotationFile(stageRoot, longPrefix, []byte("native create failure"))
	var pathErr *os.PathError
	if stageName != "" || stageErr == nil || !errors.As(stageErr, &pathErr) {
		t.Fatalf("overlong accepted prefix did not reach native create failure: name=%q err=%T %v", stageName, stageErr, stageErr)
	}
	if entriesAfterFailure := entryNames(); strings.Join(entriesAfterFailure, "\x00") != strings.Join(entriesBeforeFailure, "\x00") {
		t.Fatalf("failed native create left directory entries: before=%v after=%v", entriesBeforeFailure, entriesAfterFailure)
	}
	stageAndRemove(".rotation-after-", []byte("valid stage after native failure"))
	if entriesAfterPositive := entryNames(); len(entriesAfterPositive) != 0 {
		t.Fatalf("same-root positive stage cleanup left entries: %v", entriesAfterPositive)
	}
	closed, err := os.OpenRoot(app)
	if err != nil {
		t.Fatal(err)
	}
	if err := closed.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := stageRotationFile(closed, ".rotation-stage-", []byte("unwritable")); err == nil {
		t.Fatal("closed-root stage failure was ignored")
	}
	if err := publishRotationFile(closed, ".stage", "destination"); err == nil {
		t.Fatal("closed-root rename failure was ignored")
	}
	if err := syncRotationDirectory(closed); err == nil {
		t.Fatal("closed-root directory durability failure was ignored")
	}
}

func TestCaptureAndPersistLocalRotationBackendPrecedenceAndCAS(t *testing.T) {
	app, lease := rotationJournalTestLease(t)
	oldSource, newSource := rotationJournalTestKeys()
	oldIsolation := isolateAppEnvironment.Load()
	isolateAppEnvironment.Store(false)
	t.Cleanup(func() { isolateAppEnvironment.Store(oldIsolation) })
	rotationUnsetEnv(t, "ENCRYPTION_KEY")
	rotationUnsetEnv(t, "CREDENTIALS_DIRECTORY")
	yamlBytes := []byte("ENCRYPTION_KEY: " + oldSource + "\nKEEP: original\n")
	if err := os.WriteFile(filepath.Join(app, "env.yaml"), yamlBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource); err != nil {
		t.Fatalf("YAML winning source was not captured: %v", err)
	}
	for i, value := range []string{"", oldSource, strings.Repeat("03", 32)} {
		rotationSetEnv(t, "ENCRYPTION_KEY", value)
		if _, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource); !errors.Is(err, errAppRotationUnsupported) {
			t.Fatalf("process environment winner case %d was accepted", i)
		}
	}
	rotationUnsetEnv(t, "ENCRYPTION_KEY")
	benmore := filepath.Join(app, ".benmore")
	if err := os.Mkdir(benmore, 0700); err != nil {
		t.Fatal(err)
	}
	generated := []byte("OTHER=\"preserved\"\n")
	if err := os.WriteFile(filepath.Join(benmore, "env"), generated, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("ENCRYPTION_KEY", strings.Repeat("03", 32))
	snap, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource)
	if err != nil {
		t.Fatalf("generated file without a key did not suppress process overlay: %v", err)
	}
	if !snap.GuardExists || !bytes.Equal(snap.GuardBytes, generated) {
		t.Fatal("generated-file precedence guard was not captured")
	}
	if err := os.WriteFile(filepath.Join(benmore, "env"), []byte("ENCRYPTION_KEY="+oldSource+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource); !errors.Is(err, errAppRotationUnsupported) {
		t.Fatal("same-value generated key winner was accepted for YAML persistence")
	}
	if err := os.WriteFile(filepath.Join(benmore, "env"), generated, 0600); err != nil {
		t.Fatal(err)
	}
	rotationUnsetEnv(t, "ENCRYPTION_KEY")
	snap, err = captureLocalRotationBackend(context.Background(), lease, oldSource, newSource)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := prepareAppRotationJournal(context.Background(), lease, rotationJournalTestIdentity(), snap)
	if err != nil {
		t.Fatal(err)
	}
	if err := persistLocalRotationBackend(context.Background(), lease, journal); err != nil {
		t.Fatalf("local YAML persistence failed: %v", err)
	}
	if err := verifyLocalRotationBackend(context.Background(), lease, journal); err != nil {
		t.Fatal(err)
	}
	first, err := os.ReadFile(filepath.Join(app, "env.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	vars := map[string]string{}
	if err := decodeConfigYAML(first, &vars); err != nil || vars["ENCRYPTION_KEY"] != newSource || vars["KEEP"] != "original" {
		t.Fatal("local YAML write did not preserve unrelated values")
	}
	if err := persistLocalRotationBackend(context.Background(), lease, journal); err != nil {
		t.Fatalf("exact-new local retry failed: %v", err)
	}
	third := []byte("ENCRYPTION_KEY: third-state\nKEEP: original\n")
	if err := os.WriteFile(filepath.Join(app, "env.yaml"), third, 0600); err != nil {
		t.Fatal(err)
	}
	if err := persistLocalRotationBackend(context.Background(), lease, journal); !errors.Is(err, errAppRotationConflict) {
		t.Fatal("third-state YAML was overwritten")
	}
	after, _ := os.ReadFile(filepath.Join(app, "env.yaml"))
	if !bytes.Equal(after, third) {
		t.Fatal("third-state conflict changed caller bytes")
	}
}

func TestCaptureLocalRotationRejectsCredentialFallbackAndExpectedFileConflict(t *testing.T) {
	app, lease := rotationJournalTestLease(t)
	oldSource, newSource := rotationJournalTestKeys()
	oldIsolation := isolateAppEnvironment.Load()
	isolateAppEnvironment.Store(false)
	t.Cleanup(func() { isolateAppEnvironment.Store(oldIsolation) })
	rotationUnsetEnv(t, "ENCRYPTION_KEY")
	cred := t.TempDir()
	if err := os.WriteFile(filepath.Join(cred, "encryption_key"), []byte(oldSource), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("CREDENTIALS_DIRECTORY", cred)
	if err := os.WriteFile(filepath.Join(app, "env.yaml"), []byte("ENCRYPTION_KEY: \"\"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource); !errors.Is(err, errAppRotationUnsupported) {
		t.Fatal("systemd credential winner was written underneath")
	}
	rotationUnsetEnv(t, "CREDENTIALS_DIRECTORY")
	if err := os.WriteFile(filepath.Join(app, "env.yaml"), []byte("ENCRYPTION_KEY: "+oldSource+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	snap, err := captureLocalRotationBackend(context.Background(), lease, oldSource, newSource)
	if err != nil {
		t.Fatal(err)
	}
	j, err := prepareAppRotationJournal(context.Background(), lease, rotationJournalTestIdentity(), snap)
	if err != nil {
		t.Fatal(err)
	}
	changed := []byte("ENCRYPTION_KEY: " + oldSource + "\nKEEP: external\n")
	if err := os.WriteFile(filepath.Join(app, "env.yaml"), changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err := persistLocalRotationBackend(context.Background(), lease, j); !errors.Is(err, errAppRotationConflict) {
		t.Fatal("changed expected file image was overwritten")
	}
	got, _ := os.ReadFile(filepath.Join(app, "env.yaml"))
	if !bytes.Equal(changed, got) {
		t.Fatal("conflicting local file bytes changed")
	}
}

func TestRotationJournalIdentityHexCanonicality(t *testing.T) {
	for _, bad := range []string{"", strings.Repeat("A", 64), strings.Repeat("a", 63), hex.EncodeToString([]byte("short"))} {
		if validRotationHex(bad) {
			t.Fatalf("accepted noncanonical digest %q", bad)
		}
	}
	app, lease := rotationJournalTestLease(t)
	oldSource, newSource := rotationJournalTestKeys()
	backend := rotationJournalTestSnapshot(lease, app, oldSource, newSource)
	id := rotationJournalTestIdentity()
	id.MarkerVersion = 1
	if err := validateRotationIdentity(id, &backend, lease); err == nil {
		t.Fatal("marker version 1 accepted")
	}
}
