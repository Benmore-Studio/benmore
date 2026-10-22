//go:build !cli && !windows

package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func authorityFoundationTempDir(t *testing.T) string {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestAppMCPAuthorityBindingParentUsesOpenedNativeIdentity(t *testing.T) {
	base := authorityFoundationTempDir(t)
	parentPath := filepath.Join(base, "owner-parent")
	if err := os.Mkdir(parentPath, 0700); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(parentPath)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	opened, err := root.Open(".")
	if err != nil {
		t.Fatal(err)
	}
	expectedInfo, statErr := opened.Stat()
	closeErr := opened.Close()
	if statErr != nil || closeErr != nil {
		t.Fatalf("capture opened parent identity: stat=%v close=%v", statErr, closeErr)
	}
	pathInfo, err := os.Lstat(parentPath)
	if err != nil || !os.SameFile(expectedInfo, pathInfo) {
		t.Fatalf("opened parent identity did not match its path observation: stat=%v err=%v", pathInfo, err)
	}
	if err := validateAppMCPAuthorityBindingParent(root, parentPath, expectedInfo, false); err != nil {
		t.Fatalf("captured opened parent failed unprotected validation: %v", err)
	}
	if err := validateAppMCPAuthorityBindingParent(root, parentPath, expectedInfo, true); err != nil {
		t.Fatalf("captured opened parent failed protected validation: %v", err)
	}

	movedPath := parentPath + ".retained"
	if err := os.Rename(parentPath, movedPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(parentPath, 0700); err != nil {
		if restoreErr := os.Rename(movedPath, parentPath); restoreErr != nil {
			t.Fatalf("create replacement parent: %v; restore original: %v", err, restoreErr)
		}
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = os.Remove(parentPath)
		_ = os.Rename(movedPath, parentPath)
	})
	movedInfo, err := os.Lstat(movedPath)
	if err != nil || !os.SameFile(expectedInfo, movedInfo) {
		t.Fatalf("retained opened root no longer identifies the original parent: stat=%v err=%v", movedInfo, err)
	}
	if err := validateAppMCPAuthorityBindingParent(root, parentPath, expectedInfo, false); err == nil {
		t.Fatal("unprotected absence validation accepted a replacement parent")
	}
	if err := validateAppMCPAuthorityBindingParent(root, parentPath, expectedInfo, true); err == nil {
		t.Fatal("protected validation accepted a replacement parent")
	}
}

func TestAppMCPAuthorityLegacyRelativeEntriesUseAbsoluteOwner(t *testing.T) {
	base := authorityFoundationTempDir(t)
	app := filepath.Join(base, "relative-app")
	if err := os.Mkdir(app, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(base)
	relative := filepath.Base(app)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")

	release, view, err := beginAppMCPPolicyChange(context.Background(), relative)
	if err != nil || release == nil || view != nil {
		if release != nil {
			release()
		}
		t.Fatalf("clean relative unbound policy entry did not preserve the no-op: release=%v view=%v err=%v", release != nil, view, err)
	}
	t.Cleanup(release)
	release()
	if err := invalidateAppMCPForRestore(relative); err != nil {
		t.Fatalf("clean relative unbound restore invalidation did not preserve the no-op: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(base, appMCPAuthorityBindingDirectory)); !os.IsNotExist(err) {
		t.Fatalf("relative no-authority no-op created locator state: %v", err)
	}
	if _, _, err := appMCPAuthorityRoot(relative); err == nil {
		t.Fatal("relative no-authority root discovery unexpectedly selected an owner")
	}
	for _, malformed := range []string{"", "./" + relative, relative + "/../" + relative} {
		if _, _, err := beginAppMCPPolicyChange(context.Background(), malformed); err == nil {
			t.Fatalf("non-clean legacy path was accepted by policy entry: %q", malformed)
		}
		if err := invalidateAppMCPForRestore(malformed); err == nil {
			t.Fatalf("non-clean legacy path was accepted by restore entry: %q", malformed)
		}
		if _, _, _, err := acquireAppMCPWritePolicy(context.Background(), malformed); err == nil {
			t.Fatalf("non-clean legacy path was accepted by write entry: %q", malformed)
		}
	}

	authority := filepath.Join(base, "authority")
	if err := os.Mkdir(authority, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	owner, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, owner)
	if _, err := pinAppMCPAuthorityBindingWithLease(context.Background(), owner); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}

	root, key, err := appMCPAuthorityRoot(relative)
	if err != nil {
		t.Fatalf("configured relative owner did not resolve: %v", err)
	}
	if want := hashBytesSHA256([]byte(app)); key != want {
		_ = root.Close()
		t.Fatalf("relative owner selected a different absolute key: got=%q want=%q", key, want)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}

	writeCtx, writeRelease, writeView, err := acquireAppMCPWritePolicy(context.Background(), relative)
	if err != nil || writeCtx == nil || writeRelease == nil || writeView == nil || writeView.path != app || writeView.key != hashBytesSHA256([]byte(app)) || writeView.owner == nil || writeView.ownsResources {
		if writeRelease != nil {
			writeRelease()
		}
		t.Fatalf("relative write entry did not return an absolute non-owning view: ctx=%v view=%+v err=%v", writeCtx != nil, writeView, err)
	}
	t.Cleanup(writeRelease)
	if err := writeView.Close(); err == nil || !strings.Contains(err.Error(), "cannot close its owner") {
		t.Fatalf("relative borrowed view could close the absolute owner: %v", err)
	}
	if err := validateAppMCPAuthorityLease(writeView); err != nil {
		t.Fatalf("borrowed-view Close disturbed its absolute owner: %v", err)
	}
	writeRelease()
	if err := validateAppMCPAuthorityLease(writeView); err == nil {
		t.Fatal("relative borrowed view remained live after its owner release")
	}

	reacquired, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatalf("relative write release did not free the absolute owner: %v", err)
	}
	cleanupAppMCPAuthorityLease(t, reacquired)
	if err := reacquired.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPAuthorityLegacyRelativeAliasesFailBeforeEffects(t *testing.T) {
	base := authorityFoundationTempDir(t)
	app := filepath.Join(base, "bound-app")
	if err := os.Mkdir(app, 0700); err != nil {
		t.Fatal(err)
	}
	authority := filepath.Join(base, "authority")
	if err := os.Mkdir(authority, 0700); err != nil {
		t.Fatal(err)
	}
	t.Chdir(base)
	relative := filepath.Base(app)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	owner, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, owner)
	if _, err := pinAppMCPAuthorityBindingWithLease(context.Background(), owner); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := updateAppMCPEpoch(app, true, false, true); err != nil {
		t.Fatal(err)
	}
	location, err := appMCPAuthorityBindingLocationFor(app)
	if err != nil {
		t.Fatal(err)
	}
	locatorPath := filepath.Join(location.parentPath, appMCPAuthorityBindingDirectory, hashBytesSHA256([]byte(app))+".json")
	locatorBefore, err := os.ReadFile(locatorPath)
	if err != nil {
		t.Fatal(err)
	}
	locatorInfoBefore, err := os.Lstat(locatorPath)
	if err != nil {
		t.Fatal(err)
	}
	epochPath := filepath.Join(authority, hashBytesSHA256([]byte(app))+".json")
	epochBefore, err := os.ReadFile(epochPath)
	if err != nil {
		t.Fatal(err)
	}
	appInfoBefore, err := os.Lstat(app)
	if err != nil {
		t.Fatal(err)
	}
	authorityEntriesBefore, err := os.ReadDir(authority)
	if err != nil {
		t.Fatal(err)
	}

	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")
	if _, _, err := beginAppMCPPolicyChange(context.Background(), relative); err == nil || !strings.Contains(err.Error(), "configured authority is required for a bound application") {
		t.Fatalf("bound relative policy entry did not refuse missing authority: %v", err)
	}
	if err := invalidateAppMCPForRestore(relative); err == nil || !strings.Contains(err.Error(), "configured authority is required for a bound application") {
		t.Fatalf("bound relative restore entry did not refuse missing authority: %v", err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)

	targetParent := filepath.Join(base, "unbound-target-parent")
	if err := os.Mkdir(targetParent, 0700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(targetParent, "target-app")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	finalAlias := filepath.Join(base, "final-alias")
	if err := os.Symlink(target, finalAlias); err != nil {
		t.Fatal(err)
	}
	parentAlias := filepath.Join(base, "parent-alias")
	if err := os.Symlink(targetParent, parentAlias); err != nil {
		t.Fatal(err)
	}
	targetEntriesBefore, err := os.ReadDir(targetParent)
	if err != nil {
		t.Fatal(err)
	}

	for _, alias := range []string{filepath.Base(finalAlias), filepath.Join(filepath.Base(parentAlias), filepath.Base(target))} {
		if _, _, err := appMCPAuthorityRoot(alias); err == nil || !strings.Contains(err.Error(), "original canonical app path") {
			t.Fatalf("relative alias did not fail strict authority discovery: %q: %v", alias, err)
		}
		release, view, err := beginAppMCPPolicyChange(context.Background(), alias)
		if err == nil {
			if release != nil {
				release()
			}
			t.Fatalf("relative alias entered policy path: %q view=%v", alias, view)
		}
		if release != nil || view != nil || !strings.Contains(err.Error(), "original canonical app path") {
			t.Fatalf("relative policy alias refusal was not canonical-path specific: %q: %v", alias, err)
		}
		if err := invalidateAppMCPForRestore(alias); err == nil || !strings.Contains(err.Error(), "original canonical app path") {
			t.Fatalf("relative restore alias did not fail before invalidation: %q: %v", alias, err)
		}
		writeCtx, writeRelease, writeView, err := acquireAppMCPWritePolicy(context.Background(), alias)
		if err == nil {
			if writeRelease != nil {
				writeRelease()
			}
			t.Fatalf("relative alias entered write policy: %q ctx=%v view=%v", alias, writeCtx, writeView)
		}
		if writeCtx != nil || writeRelease != nil || writeView != nil || !strings.Contains(err.Error(), "original canonical app path") {
			t.Fatalf("relative write alias refusal was not canonical-path specific: %q: %v", alias, err)
		}
	}

	if _, err := os.Lstat(filepath.Join(targetParent, appMCPAuthorityBindingDirectory)); !os.IsNotExist(err) {
		t.Fatalf("relative alias refusal created target locator state: %v", err)
	}
	targetEntriesAfter, err := os.ReadDir(targetParent)
	if err != nil || len(targetEntriesAfter) != len(targetEntriesBefore) {
		t.Fatalf("relative alias refusal changed target namespace: before=%v after=%v err=%v", targetEntriesBefore, targetEntriesAfter, err)
	}
	for i := range targetEntriesBefore {
		if targetEntriesBefore[i].Name() != targetEntriesAfter[i].Name() {
			t.Fatalf("relative alias refusal changed target namespace: before=%v after=%v", targetEntriesBefore, targetEntriesAfter)
		}
	}
	locatorAfter, err := os.ReadFile(locatorPath)
	locatorInfoAfter, infoErr := os.Lstat(locatorPath)
	epochAfter, epochErr := os.ReadFile(epochPath)
	appInfoAfter, appInfoErr := os.Lstat(app)
	authorityEntriesAfter, entriesErr := os.ReadDir(authority)
	if err != nil || infoErr != nil || !os.SameFile(locatorInfoBefore, locatorInfoAfter) || locatorInfoAfter.Mode().Perm() != locatorInfoBefore.Mode().Perm() || !bytes.Equal(locatorBefore, locatorAfter) || epochErr != nil || !bytes.Equal(epochBefore, epochAfter) || appInfoErr != nil || !os.SameFile(appInfoBefore, appInfoAfter) || entriesErr != nil || len(authorityEntriesAfter) != len(authorityEntriesBefore) {
		t.Fatalf("relative alias or empty-env refusal changed owner state: locator=%v stat=%v epoch=%v app=%v authority=%v", err, infoErr, epochErr, appInfoErr, entriesErr)
	}
	for i := range authorityEntriesBefore {
		if authorityEntriesBefore[i].Name() != authorityEntriesAfter[i].Name() {
			t.Fatalf("relative alias refusal changed authority inventory: before=%v after=%v", authorityEntriesBefore, authorityEntriesAfter)
		}
	}
	if err := invalidateAppMCPForRestore(relative); err != nil {
		t.Fatalf("configured clean-relative restore entry did not invalidate the original owner: %v", err)
	}
	if state, err := currentAppMCPEpoch(app); err != nil || state == nil || state.Exposed {
		t.Fatalf("relative restore invalidation did not revoke the absolute owner's epoch: state=%+v err=%v", state, err)
	}

	root, key, err := appMCPAuthorityRoot(relative)
	if err != nil || key != hashBytesSHA256([]byte(app)) {
		if root != nil {
			_ = root.Close()
		}
		t.Fatalf("restored canonical relative path did not recover its original owner: key=%q err=%v", key, err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
	release, view, err := beginAppMCPPolicyChange(context.Background(), relative)
	if err != nil || release == nil || view == nil || view.path != app || view.key != hashBytesSHA256([]byte(app)) || view.ownsResources {
		if release != nil {
			release()
		}
		t.Fatalf("restored relative policy path did not return its original borrowed owner: view=%+v err=%v", view, err)
	}
	t.Cleanup(release)
	release()
}

func TestAppMCPAuthorityBindingPinsCanonicalDurableLocator(t *testing.T) {
	authority := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	app := authorityFoundationTempDir(t)
	dbPath := filepath.Join(app, "data.db")
	db, err := sql.Open("sqlite3", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec("CREATE TABLE prior_snapshot(id INTEGER PRIMARY KEY, value TEXT)"); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if _, err := db.Exec("INSERT INTO prior_snapshot(value) VALUES('old snapshot')"); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dbPath, 0600); err != nil {
		t.Fatal(err)
	}
	priorDB, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	priorSource := []byte("commands: []\n")
	if err := os.WriteFile(filepath.Join(app, "mcp.yaml"), priorSource, 0600); err != nil {
		t.Fatal(err)
	}

	lease, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, lease)
	binding, err := pinAppMCPAuthorityBindingWithLease(context.Background(), lease)
	if err != nil {
		_ = lease.Close()
		t.Fatal(err)
	}
	if binding.Version != 1 || binding.AppPath != app || binding.OwnerHash != hashBytesSHA256([]byte(app)) || binding.AuthorityPath != authority || binding.AuthorityIdentity == "" {
		_ = lease.Close()
		t.Fatalf("locator did not bind the canonical owner and opened root: %+v", binding)
	}
	if err := lease.Close(); err != nil {
		t.Fatal(err)
	}

	location, err := appMCPAuthorityBindingLocationFor(app)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(location.parentPath, appMCPAuthorityBindingDirectory, binding.OwnerHash+".json")
	if pathWithinDir(app, path) {
		t.Fatal("locator was placed inside the app tree")
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		t.Fatalf("locator file metadata: info=%v err=%v", info, err)
	}
	directoryInfo, err := os.Lstat(filepath.Dir(path))
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode().Perm() != 0700 {
		t.Fatalf("locator directory metadata: info=%v err=%v", directoryInfo, err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := decodeAppMCPAuthorityBinding(data)
	if err != nil || decoded == nil || decoded.AuthorityIdentity != binding.AuthorityIdentity {
		t.Fatalf("canonical locator readback: binding=%+v err=%v", decoded, err)
	}
	if bytes.Contains(data, []byte("key")) || len(data) > appMCPAuthorityBindingLimit {
		t.Fatal("locator contains key material or exceeds the fixed bound")
	}
	if got, err := readAppMCPAuthorityBinding(app); err != nil || got == nil {
		t.Fatalf("durable locator was not discovered: %+v %v", got, err)
	}
	preEpochEntries, err := os.ReadDir(authority)
	if err != nil || len(preEpochEntries) != 1 || preEpochEntries[0].Name() != ".lock" {
		t.Fatalf("locator pin created authority/key state: entries=%v err=%v", preEpochEntries, err)
	}
	epoch, err := updateAppMCPEpoch(app, true, false, true)
	if err != nil || epoch == nil || !epoch.Exposed {
		t.Fatalf("explicit post-pin epoch setup failed: epoch=%+v err=%v", epoch, err)
	}
	epochPath := filepath.Join(authority, binding.OwnerHash+".json")
	epochBefore, err := os.ReadFile(epochPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dbPath, priorDB, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(app, "mcp.yaml")); err != nil {
		t.Fatal(err)
	}

	// Exact retry rechecks durability and readback without replacing the file.
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lease, err = acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, lease)
	retry, err := pinAppMCPAuthorityBindingWithLease(context.Background(), lease)
	closeErr := lease.Close()
	if err != nil || closeErr != nil || retry == nil {
		t.Fatalf("exact retry failed: binding=%+v pin=%v close=%v", retry, err, closeErr)
	}
	after, err := os.ReadFile(path)
	afterInfo, infoErr := os.Lstat(path)
	if err != nil || infoErr != nil || !os.SameFile(info, afterInfo) || !bytes.Equal(before, after) {
		t.Fatalf("idempotent retry replaced locator identity or bytes: err=%v info=%v", err, infoErr)
	}

	// The locator remains authoritative if the process configuration disappears.
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")
	if _, _, err := appMCPAuthorityRoot(app); err == nil {
		t.Fatal("bound app accepted a missing configured authority root")
	}
	if _, _, err := beginAppMCPPolicyChange(context.Background(), app); err == nil {
		t.Fatal("bound app accepted an unset authority in the policy coordinator")
	}
	if err := invalidateAppMCPForRestore(app); err == nil {
		t.Fatal("restore bypass accepted a bound app with no configured root")
	}
	changedRoot := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", changedRoot)
	if _, _, err := appMCPAuthorityRoot(app); err == nil {
		t.Fatal("bound app accepted a different configured authority root")
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	root, _, rootErr := appMCPAuthorityRoot(app)
	if rootErr != nil {
		t.Fatalf("bound app did not accept its exact configured root: %v", rootErr)
	}
	if closeErr := root.Close(); closeErr != nil {
		t.Fatal(closeErr)
	}
	if got, err := os.ReadFile(dbPath); err != nil || !bytes.Equal(got, priorDB) {
		t.Fatalf("failed discovery changed the prior database bytes: %q err=%v", got, err)
	}
	if _, err := os.Lstat(filepath.Join(app, "mcp.yaml")); !os.IsNotExist(err) {
		t.Fatalf("failed discovery recreated a removed command source: %v", err)
	}
	rootEntries, err := os.ReadDir(authority)
	if err != nil || len(rootEntries) != 2 || rootEntries[0].Name() != ".lock" || rootEntries[1].Name() != binding.OwnerHash+".json" {
		t.Fatalf("failed discovery changed authority-root record inventory: entries=%v err=%v", rootEntries, err)
	}
	epochAfter, err := os.ReadFile(epochPath)
	if err != nil || !bytes.Equal(epochBefore, epochAfter) {
		t.Fatalf("failed discovery changed the existing authority epoch: err=%v", err)
	}
}

func TestAppMCPAuthorityBindingStrictDecodeAndUnknownPublication(t *testing.T) {
	canonical := []byte(`{"version":1,"app_path":"/tmp/example","owner_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","authority_path":"/tmp/root","authority_identity":"identity"}`)
	if _, err := decodeAppMCPAuthorityBinding(canonical); err != nil {
		t.Fatal(err)
	}
	for name, invalid := range map[string][]byte{
		"duplicate":  []byte(`{"version":1,"version":1,"app_path":"/tmp/example","owner_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","authority_path":"/tmp/root","authority_identity":"identity"}`),
		"unknown":    []byte(`{"version":1,"app_path":"/tmp/example","owner_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","authority_path":"/tmp/root","authority_identity":"identity","extra":true}`),
		"truncated":  canonical[:len(canonical)-1],
		"oversize":   bytes.Repeat([]byte("x"), appMCPAuthorityBindingLimit+1),
		"whitespace": append(append([]byte(nil), canonical...), '\n'),
		"version":    []byte(`{"version":2,"app_path":"/tmp/example","owner_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","authority_path":"/tmp/root","authority_identity":"identity"}`),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeAppMCPAuthorityBinding(invalid); err == nil {
				t.Fatal("invalid locator was accepted")
			}
		})
	}

	authorityForCanceled := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authorityForCanceled)
	canceledApp := authorityFoundationTempDir(t)
	canceledLease, err := acquireAppMCPAuthorityLease(context.Background(), canceledApp)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, canceledLease)
	canceledCtx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := pinAppMCPAuthorityBindingWithLease(canceledCtx, canceledLease); !errors.Is(err, context.Canceled) {
		_ = canceledLease.Close()
		t.Fatalf("canceled pin context was accepted: %v", err)
	}
	if err := canceledLease.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(canceledApp), appMCPAuthorityBindingDirectory)); !os.IsNotExist(err) {
		t.Fatalf("canceled pin created locator directory: %v", err)
	}

	authority := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	app := authorityFoundationTempDir(t)
	lease, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, lease)
	defer lease.Close()
	publicationFault := errors.New("simulated lost response after locator publication")
	previousFault := appMCPAuthorityRecordStoreFault
	t.Cleanup(func() { appMCPAuthorityRecordStoreFault = previousFault })
	appMCPAuthorityRecordStoreFault = func(stage, _, state string) error {
		if stage == "after_publish" && state == "binding" {
			return publicationFault
		}
		return nil
	}
	_, err = pinAppMCPAuthorityBindingWithLease(context.Background(), lease)
	appMCPAuthorityRecordStoreFault = previousFault
	if !errors.Is(err, errAppMCPAuthorityBindingUnknown) || !errors.Is(err, publicationFault) {
		t.Fatalf("post-publication failure was not reported as unknown: %v", err)
	}
	location, err := appMCPAuthorityBindingLocationFor(app)
	if err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(filepath.Join(location.parentPath, appMCPAuthorityBindingDirectory))
	if err != nil || len(entries) != 1 || entries[0].Name() != hashBytesSHA256([]byte(app))+".json" {
		t.Fatalf("post-publication failure did not clean its stage: entries=%v err=%v", entries, err)
	}
	persisted, readErr := readAppMCPAuthorityBinding(app)
	if readErr != nil || persisted == nil {
		t.Fatalf("faulted publication did not preserve discoverable locator: %+v %v", persisted, readErr)
	}
	if _, err := pinAppMCPAuthorityBindingWithLease(context.Background(), lease); err != nil {
		t.Fatalf("exact retry did not converge after unknown publication: %v", err)
	}
}

func TestAppMCPAuthorityBindingFaultBoundariesPreserveClassifiedDiskState(t *testing.T) {
	authority := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	for _, stage := range []struct {
		name      string
		published bool
	}{
		{name: "before_write"},
		{name: "file_sync"},
		{name: "publish"},
		{name: "directory_sync", published: true},
		{name: "readback", published: true},
	} {
		t.Run(stage.name, func(t *testing.T) {
			app := authorityFoundationTempDir(t)
			lease, err := acquireAppMCPAuthorityLease(context.Background(), app)
			if err != nil {
				t.Fatal(err)
			}
			cleanupAppMCPAuthorityLease(t, lease)
			fault := errors.New("injected locator " + stage.name)
			previous := appMCPAuthorityRecordStoreFault
			t.Cleanup(func() { appMCPAuthorityRecordStoreFault = previous })
			reached := false
			appMCPAuthorityRecordStoreFault = func(actual, _, record string) error {
				if actual == stage.name && record == "binding" {
					reached = true
					return fault
				}
				return nil
			}
			_, pinErr := pinAppMCPAuthorityBindingWithLease(context.Background(), lease)
			appMCPAuthorityRecordStoreFault = previous
			if !reached || !errors.Is(pinErr, fault) || errors.Is(pinErr, errAppMCPAuthorityBindingUnknown) != stage.published {
				t.Fatalf("fault was not reached/classified correctly: reached=%v err=%v", reached, pinErr)
			}
			location, err := appMCPAuthorityBindingLocationFor(app)
			if err != nil {
				t.Fatal(err)
			}
			entries, err := os.ReadDir(filepath.Join(location.parentPath, appMCPAuthorityBindingDirectory))
			if err != nil || (stage.published && (len(entries) != 1 || entries[0].Name() != hashBytesSHA256([]byte(app))+".json")) || (!stage.published && len(entries) != 0) {
				t.Fatalf("fault left unexpected stage/locator entries: stage=%s entries=%v err=%v", stage.name, entries, err)
			}
			persisted, readErr := readAppMCPAuthorityBinding(app)
			if stage.published {
				if readErr != nil || persisted == nil {
					t.Fatalf("published locator was lost after %s: %+v %v", stage.name, persisted, readErr)
				}
				if _, err := pinAppMCPAuthorityBindingWithLease(context.Background(), lease); err != nil {
					t.Fatalf("retry failed to resolve uncertain %s result: %v", stage.name, err)
				}
			} else if readErr != nil || persisted != nil {
				t.Fatalf("prepublication %s fault left a locator: %+v %v", stage.name, persisted, readErr)
			}
		})
	}
}

func TestAppMCPAuthorityBindingParentSyncRetriesEveryDurabilityBoundary(t *testing.T) {
	authority := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	app := authorityFoundationTempDir(t)
	lease, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, lease)

	fault := errors.New("parent sync unavailable")
	previous := appMCPAuthorityRecordStoreFault
	var reached int
	appMCPAuthorityRecordStoreFault = func(stage, _, record string) error {
		if stage == "parent_directory_sync" && record == "binding" {
			reached++
			return fault
		}
		return nil
	}
	t.Cleanup(func() { appMCPAuthorityRecordStoreFault = previous })

	_, firstErr := pinAppMCPAuthorityBindingWithLease(context.Background(), lease)
	if !errors.Is(firstErr, fault) || errors.Is(firstErr, errAppMCPAuthorityBindingUnknown) || reached != 1 {
		t.Fatalf("initial parent-sync failure was not reached/classified as prepublication: reached=%d err=%v", reached, firstErr)
	}
	location, err := appMCPAuthorityBindingLocationFor(app)
	if err != nil {
		t.Fatal(err)
	}
	bindingDir := filepath.Join(location.parentPath, appMCPAuthorityBindingDirectory)
	if info, err := os.Lstat(bindingDir); err != nil || !info.IsDir() || info.Mode().Perm() != 0700 {
		t.Fatalf("parent-sync failure did not leave the protected directory for retry: info=%v err=%v", info, err)
	}
	locatorPath := filepath.Join(bindingDir, hashBytesSHA256([]byte(app))+".json")
	if _, err := os.Lstat(locatorPath); !os.IsNotExist(err) {
		t.Fatalf("prepublication parent-sync failure left locator: %v", err)
	}
	entries, err := os.ReadDir(bindingDir)
	if err != nil || len(entries) != 0 {
		t.Fatalf("prepublication parent-sync failure left staged residue: entries=%v err=%v", entries, err)
	}

	_, retryErr := pinAppMCPAuthorityBindingWithLease(context.Background(), lease)
	if !errors.Is(retryErr, fault) || errors.Is(retryErr, errAppMCPAuthorityBindingUnknown) || reached != 2 {
		t.Fatalf("existing-directory retry skipped parent sync or misclassified it: reached=%d err=%v", reached, retryErr)
	}
	appMCPAuthorityRecordStoreFault = nil
	binding, err := pinAppMCPAuthorityBindingWithLease(context.Background(), lease)
	if err != nil || binding == nil {
		t.Fatalf("pin did not succeed after parent sync recovered: binding=%+v err=%v", binding, err)
	}
	beforeInfo, err := os.Lstat(locatorPath)
	if err != nil {
		t.Fatal(err)
	}
	beforeBytes, err := os.ReadFile(locatorPath)
	if err != nil {
		t.Fatal(err)
	}

	appMCPAuthorityRecordStoreFault = func(stage, _, record string) error {
		if stage == "parent_directory_sync" && record == "binding" {
			reached++
			return fault
		}
		return nil
	}
	_, exactErr := pinAppMCPAuthorityBindingWithLease(context.Background(), lease)
	if !errors.Is(exactErr, fault) || !errors.Is(exactErr, errAppMCPAuthorityBindingUnknown) || reached != 3 {
		t.Fatalf("published exact retry did not report unknown parent durability: reached=%d err=%v", reached, exactErr)
	}
	afterInfo, err := os.Lstat(locatorPath)
	if err != nil {
		t.Fatal(err)
	}
	afterBytes, err := os.ReadFile(locatorPath)
	if err != nil || !os.SameFile(beforeInfo, afterInfo) || !bytes.Equal(beforeBytes, afterBytes) {
		t.Fatalf("uncertain exact retry replaced locator identity/bytes: err=%v", err)
	}
	appMCPAuthorityRecordStoreFault = nil
	if _, err := pinAppMCPAuthorityBindingWithLease(context.Background(), lease); err != nil {
		t.Fatalf("exact retry did not recover after parent sync: %v", err)
	}
}

func TestAppMCPAuthorityBindingRejectsLocatorAndRootAliases(t *testing.T) {
	base := authorityFoundationTempDir(t)
	canonicalParent := filepath.Join(base, "parent")
	if err := os.Mkdir(canonicalParent, 0700); err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(canonicalParent, "app")
	if err := os.Mkdir(app, 0700); err != nil {
		t.Fatal(err)
	}
	aliasParent := filepath.Join(base, "parent-alias")
	if err := os.Symlink(canonicalParent, aliasParent); err != nil {
		t.Fatal(err)
	}
	if _, err := appMCPAuthorityBindingLocationFor(filepath.Join(aliasParent, "app")); err != nil {
		t.Fatal(err)
	} else {
		location, _ := appMCPAuthorityBindingLocationFor(filepath.Join(aliasParent, "app"))
		if !location.pathWasAlias {
			t.Fatal("parent symlink alias was not detected")
		}
	}

	authority := filepath.Join(base, "authority")
	if err := os.Mkdir(authority, 0700); err != nil {
		t.Fatal(err)
	}
	aliasAuthority := filepath.Join(base, "authority-alias")
	if err := os.Symlink(authority, aliasAuthority); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", aliasAuthority)
	if _, err := acquireAppMCPAuthorityLease(context.Background(), app); err == nil {
		t.Fatal("authority root alias was accepted")
	}
	if _, err := os.Lstat(filepath.Join(authority, ".lock")); !os.IsNotExist(err) {
		t.Fatalf("rejected authority alias created a lock file: %v", err)
	}

	// A present locator cannot be reached through a file symlink or relaxed mode.
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	lease, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, lease)
	binding, err := pinAppMCPAuthorityBindingWithLease(context.Background(), lease)
	closeErr := lease.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("pin locator for filesystem tamper controls: pin=%v close=%v", err, closeErr)
	}
	if _, err := readAppMCPAuthorityBinding(filepath.Join(aliasParent, "app")); err == nil {
		t.Fatal("parent symlink alias reached a bound application locator")
	}
	location, err := appMCPAuthorityBindingLocationFor(app)
	if err != nil {
		t.Fatal(err)
	}
	locatorPath := filepath.Join(location.parentPath, appMCPAuthorityBindingDirectory, binding.OwnerHash+".json")
	locatorBytes, err := os.ReadFile(locatorPath)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "locator-target")
	if err := os.WriteFile(target, locatorBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(locatorPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, locatorPath); err != nil {
		t.Fatal(err)
	}
	if _, err := readAppMCPAuthorityBinding(app); err == nil {
		t.Fatal("symlinked locator file was accepted")
	}
	if err := os.Remove(locatorPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(locatorPath, locatorBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locatorPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := readAppMCPAuthorityBinding(app); err == nil {
		t.Fatal("world-readable locator file was accepted")
	}
	if err := os.Chmod(locatorPath, 0600); err != nil {
		t.Fatal(err)
	}
	if os.Getuid() == 0 {
		if err := os.Chown(locatorPath, 1, 1); err == nil {
			if _, err := readAppMCPAuthorityBinding(app); err == nil {
				t.Fatal("foreign-owned locator file was accepted")
			}
			if err := os.Chown(locatorPath, os.Getuid(), os.Getgid()); err != nil {
				t.Fatal(err)
			}
		}
	}
	if err := os.Chmod(filepath.Dir(locatorPath), 0755); err != nil {
		t.Fatal(err)
	}
	if _, err := readAppMCPAuthorityBinding(app); err == nil {
		t.Fatal("group/world-accessible locator directory was accepted")
	}
	if err := os.Chmod(filepath.Dir(locatorPath), 0700); err != nil {
		t.Fatal(err)
	}
	targetDir := filepath.Join(base, "locator-directory-target")
	if err := os.Mkdir(targetDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(targetDir, binding.OwnerHash+".json"), locatorBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.RemoveAll(filepath.Dir(locatorPath)); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(targetDir, filepath.Dir(locatorPath)); err != nil {
		t.Fatal(err)
	}
	if _, err := readAppMCPAuthorityBinding(app); err == nil {
		t.Fatal("symlinked locator directory was accepted")
	}
}

func TestAppMCPAuthorityLocatorRejectsAliasesBeforeAbsenceOrInvalidation(t *testing.T) {
	base := authorityFoundationTempDir(t)
	parent := filepath.Join(base, "parent")
	if err := os.Mkdir(parent, 0700); err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(parent, "bound-app")
	if err := os.Mkdir(app, 0700); err != nil {
		t.Fatal(err)
	}
	appDB := filepath.Join(app, "data.db")
	appSource := filepath.Join(app, "mcp.yaml")
	if err := os.WriteFile(appDB, []byte("snapshot bytes"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(appSource, []byte("commands: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	authority := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	owner, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, owner)
	binding, err := pinAppMCPAuthorityBindingWithLease(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := updateAppMCPEpoch(app, true, false, true); err != nil {
		t.Fatal(err)
	}
	location, err := appMCPAuthorityBindingLocationFor(app)
	if err != nil {
		t.Fatal(err)
	}
	locatorPath := filepath.Join(location.parentPath, appMCPAuthorityBindingDirectory, binding.OwnerHash+".json")
	locatorBefore, err := os.ReadFile(locatorPath)
	if err != nil {
		t.Fatal(err)
	}
	locatorInfo, err := os.Lstat(locatorPath)
	if err != nil {
		t.Fatal(err)
	}
	epochPath := filepath.Join(authority, binding.OwnerHash+".json")
	epochBefore, err := os.ReadFile(epochPath)
	if err != nil {
		t.Fatal(err)
	}
	appDBBefore, err := os.ReadFile(appDB)
	if err != nil {
		t.Fatal(err)
	}
	appSourceBefore, err := os.ReadFile(appSource)
	if err != nil {
		t.Fatal(err)
	}
	appEntriesBefore, err := os.ReadDir(app)
	if err != nil {
		t.Fatal(err)
	}
	rootEntriesBefore, err := os.ReadDir(authority)
	if err != nil {
		t.Fatal(err)
	}
	missingApp := app + ".missing"
	if err := os.Rename(app, missingApp); err != nil {
		t.Fatal(err)
	}
	if got, err := readAppMCPAuthorityBinding(app); err != nil || got == nil || got.AppPath != app {
		t.Fatalf("original locator did not resolve with its final app directory absent: %+v %v", got, err)
	}
	missingRoot, _, err := appMCPAuthorityRoot(app)
	if err != nil {
		t.Fatalf("bound authority did not resolve with its final app directory absent: %v", err)
	}
	if err := missingRoot.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(missingApp, app); err != nil {
		t.Fatal(err)
	}

	for _, targetHasLocatorDirectory := range []bool{false, true} {
		targetParent := filepath.Join(base, "unbound-target-parent")
		if targetHasLocatorDirectory {
			targetParent = filepath.Join(base, "target-with-locator-parent")
		}
		if err := os.Mkdir(targetParent, 0700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(targetParent, "app")
		if err := os.Mkdir(target, 0700); err != nil {
			t.Fatal(err)
		}
		targetLocatorDirectory := filepath.Join(targetParent, appMCPAuthorityBindingDirectory)
		if targetHasLocatorDirectory {
			if err := os.Mkdir(targetLocatorDirectory, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.Chmod(targetLocatorDirectory, 0700); err != nil {
				t.Fatal(err)
			}
		}
		if targetHasLocatorDirectory {
			locatorDirectoryInfo, err := os.Lstat(targetLocatorDirectory)
			if err != nil || !locatorDirectoryInfo.IsDir() || locatorDirectoryInfo.Mode().Perm() != 0700 {
				t.Fatalf("target-parent locator directory fixture metadata: info=%v err=%v", locatorDirectoryInfo, err)
			}
		} else if _, err := os.Lstat(targetLocatorDirectory); !os.IsNotExist(err) {
			t.Fatalf("target-parent locator directory should be absent: %v", err)
		}
		targetParentEntriesBefore, err := os.ReadDir(targetParent)
		if err != nil {
			t.Fatal(err)
		}
		var targetLocatorEntriesBefore []os.DirEntry
		if targetHasLocatorDirectory {
			targetLocatorEntriesBefore, err = os.ReadDir(targetLocatorDirectory)
			if err != nil || len(targetLocatorEntriesBefore) != 0 {
				t.Fatalf("target-parent locator directory fixture is not empty: entries=%v err=%v", targetLocatorEntriesBefore, err)
			}
		}
		savedApp := app + ".saved"
		if err := os.Rename(app, savedApp); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, app); err != nil {
			t.Fatal(err)
		}
		t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")
		if got, err := readAppMCPAuthorityBinding(app); err == nil || got != nil || !strings.Contains(err.Error(), "original canonical app path") {
			t.Fatalf("replacement app symlink reached an unbound locator namespace: got=%+v err=%v", got, err)
		}
		if _, _, err := beginAppMCPPolicyChange(context.Background(), app); err == nil || !strings.Contains(err.Error(), "original canonical app path") {
			t.Fatalf("empty-env policy path did not refuse replacement app symlink first: %v", err)
		}
		if _, _, err := appMCPAuthorityRoot(app); err == nil || !strings.Contains(err.Error(), "original canonical app path") {
			t.Fatalf("authority-root discovery did not refuse replacement app symlink first: %v", err)
		}
		if err := invalidateAppMCPForRestore(app); err == nil || !strings.Contains(err.Error(), "original canonical app path") {
			t.Fatalf("restore discovery did not refuse replacement app symlink first: %v", err)
		}
		if err := os.Remove(app); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(savedApp, app); err != nil {
			t.Fatal(err)
		}
		targetParentEntriesAfter, err := os.ReadDir(targetParent)
		if err != nil || len(targetParentEntriesAfter) != len(targetParentEntriesBefore) {
			t.Fatalf("failed alias lookup changed target-parent namespace: before=%v after=%v err=%v", targetParentEntriesBefore, targetParentEntriesAfter, err)
		}
		for i := range targetParentEntriesBefore {
			if targetParentEntriesBefore[i].Name() != targetParentEntriesAfter[i].Name() {
				t.Fatalf("failed alias lookup changed target-parent namespace: before=%v after=%v", targetParentEntriesBefore, targetParentEntriesAfter)
			}
		}
		appEntriesAfter, err := os.ReadDir(app)
		if err != nil || len(appEntriesAfter) != len(appEntriesBefore) {
			t.Fatalf("failed alias lookup changed original app tree: before=%v after=%v err=%v", appEntriesBefore, appEntriesAfter, err)
		}
		for i := range appEntriesBefore {
			if appEntriesBefore[i].Name() != appEntriesAfter[i].Name() {
				t.Fatalf("failed alias lookup changed original app tree: before=%v after=%v", appEntriesBefore, appEntriesAfter)
			}
		}
		if targetHasLocatorDirectory {
			targetLocatorEntriesAfter, err := os.ReadDir(targetLocatorDirectory)
			if err != nil || len(targetLocatorEntriesAfter) != len(targetLocatorEntriesBefore) {
				t.Fatalf("alias lookup created target-parent locator records: entries=%v err=%v", targetLocatorEntriesAfter, err)
			}
		}
		if !targetHasLocatorDirectory {
			if _, err := os.Lstat(targetLocatorDirectory); !os.IsNotExist(err) {
				t.Fatalf("alias lookup created absent target-parent locator directory: %v", err)
			}
		}
		targetDB, err := os.ReadFile(filepath.Join(app, "data.db"))
		if err != nil || !bytes.Equal(targetDB, appDBBefore) {
			t.Fatalf("restored original app snapshot changed: err=%v", err)
		}
		locatorAfter, err := os.ReadFile(locatorPath)
		locatorInfoAfter, infoErr := os.Lstat(locatorPath)
		if err != nil || infoErr != nil || !os.SameFile(locatorInfo, locatorInfoAfter) || locatorInfoAfter.Mode().Perm() != locatorInfo.Mode().Perm() || locatorInfoAfter.Mode().Perm() != 0600 || !bytes.Equal(locatorBefore, locatorAfter) {
			t.Fatalf("alias refusal changed original locator identity/bytes: read=%v stat=%v", err, infoErr)
		}
		epochAfter, err := os.ReadFile(epochPath)
		if err != nil || !bytes.Equal(epochBefore, epochAfter) {
			t.Fatalf("alias refusal changed authority epoch: %v", err)
		}
		appSourceAfter, err := os.ReadFile(appSource)
		if err != nil || !bytes.Equal(appSourceBefore, appSourceAfter) {
			t.Fatalf("alias refusal changed original app source: %v", err)
		}
		rootEntriesAfter, err := os.ReadDir(authority)
		if err != nil || len(rootEntriesAfter) != len(rootEntriesBefore) {
			t.Fatalf("alias refusal changed authority root inventory: before=%v after=%v err=%v", rootEntriesBefore, rootEntriesAfter, err)
		}
		for i := range rootEntriesBefore {
			if rootEntriesBefore[i].Name() != rootEntriesAfter[i].Name() {
				t.Fatalf("alias refusal changed authority root inventory: before=%v after=%v", rootEntriesBefore, rootEntriesAfter)
			}
		}
	}

	otherParent := filepath.Join(base, "other-parent")
	if err := os.Mkdir(otherParent, 0700); err != nil {
		t.Fatal(err)
	}
	parentAlias := filepath.Join(base, "parent-alias")
	if err := os.Symlink(otherParent, parentAlias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")
	aliasedAppPath := filepath.Join(parentAlias, filepath.Base(app))
	if _, err := readAppMCPAuthorityBinding(aliasedAppPath); err == nil || !strings.Contains(err.Error(), "original canonical app path") {
		t.Fatalf("parent alias to an unbound directory did not fail before locator absence: %v", err)
	}
	if _, _, err := beginAppMCPPolicyChange(context.Background(), aliasedAppPath); err == nil || !strings.Contains(err.Error(), "original canonical app path") {
		t.Fatalf("empty-env policy path did not refuse parent alias first: %v", err)
	}
	if _, _, err := appMCPAuthorityRoot(aliasedAppPath); err == nil || !strings.Contains(err.Error(), "original canonical app path") {
		t.Fatalf("authority-root discovery did not refuse parent alias first: %v", err)
	}
	if err := invalidateAppMCPForRestore(aliasedAppPath); err == nil || !strings.Contains(err.Error(), "original canonical app path") {
		t.Fatalf("restore discovery did not refuse parent alias first: %v", err)
	}
	if names, err := os.ReadDir(otherParent); err != nil || len(names) != 0 {
		t.Fatalf("parent alias absence check created target state: entries=%v err=%v", names, err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	if got, err := readAppMCPAuthorityBinding(app); err != nil || got == nil {
		t.Fatalf("original locator was not readable after restoring exact app/root: %+v %v", got, err)
	}
	root, _, err := appMCPAuthorityRoot(app)
	if err != nil {
		t.Fatalf("original authority root did not recover after alias refusal: %v", err)
	}
	if err := root.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPAuthorityMalformedOnDiskLocatorBlocksEmptyEnvDiscovery(t *testing.T) {
	authority := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	app := authorityFoundationTempDir(t)
	dbPath := filepath.Join(app, "data.db")
	sourcePath := filepath.Join(app, "mcp.yaml")
	if err := os.WriteFile(dbPath, []byte("preserved database"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, []byte("commands: []\n"), 0600); err != nil {
		t.Fatal(err)
	}
	owner, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, owner)
	binding, err := pinAppMCPAuthorityBindingWithLease(context.Background(), owner)
	if err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := updateAppMCPEpoch(app, true, false, true); err != nil {
		t.Fatal(err)
	}
	location, err := appMCPAuthorityBindingLocationFor(app)
	if err != nil {
		t.Fatal(err)
	}
	locatorPath := filepath.Join(location.parentPath, appMCPAuthorityBindingDirectory, binding.OwnerHash+".json")
	locatorBefore, err := os.ReadFile(locatorPath)
	if err != nil {
		t.Fatal(err)
	}
	dbBefore, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	sourceBefore, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	epochPath := filepath.Join(authority, binding.OwnerHash+".json")
	epochBefore, err := os.ReadFile(epochPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(locatorPath, []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")
	if _, err := readAppMCPAuthorityBinding(app); err == nil {
		t.Fatal("malformed on-disk locator was accepted")
	}
	if _, _, err := beginAppMCPPolicyChange(context.Background(), app); err == nil {
		t.Fatal("empty-env policy path bypassed malformed on-disk locator")
	}
	if err := invalidateAppMCPForRestore(app); err == nil {
		t.Fatal("empty-env restore discovery bypassed malformed on-disk locator")
	}
	dbAfter, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	sourceAfter, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	epochAfter, err := os.ReadFile(epochPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dbBefore, dbAfter) || !bytes.Equal(sourceBefore, sourceAfter) || !bytes.Equal(epochBefore, epochAfter) {
		t.Fatal("malformed locator refusal changed app or authority state")
	}
	if err := os.WriteFile(locatorPath, locatorBefore, 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	if got, err := readAppMCPAuthorityBinding(app); err != nil || got == nil {
		t.Fatalf("valid locator did not recover after restoration: %+v %v", got, err)
	}
}

func TestAppMCPAuthorityConflictingPreexistingLocatorIsNeverReplaced(t *testing.T) {
	authority := authorityFoundationTempDir(t)
	otherAuthority := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	app := authorityFoundationTempDir(t)
	owner, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, owner)
	if _, err := pinAppMCPAuthorityBindingWithLease(context.Background(), owner); err != nil {
		t.Fatal(err)
	}
	location, err := appMCPAuthorityBindingLocationFor(app)
	if err != nil {
		t.Fatal(err)
	}
	name := hashBytesSHA256([]byte(app)) + ".json"
	locatorPath := filepath.Join(location.parentPath, appMCPAuthorityBindingDirectory, name)
	otherInfo, err := os.Lstat(otherAuthority)
	if err != nil {
		t.Fatal(err)
	}
	conflict := &appMCPAuthorityBinding{Version: 1, AppPath: app, OwnerHash: hashBytesSHA256([]byte(app)), AuthorityPath: otherAuthority, AuthorityIdentity: rotationFileIdentity(otherInfo)}
	conflictBytes, err := json.Marshal(conflict)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(locatorPath, conflictBytes, 0600); err != nil {
		t.Fatal(err)
	}
	beforeInfo, err := os.Lstat(locatorPath)
	if err != nil {
		t.Fatal(err)
	}
	_, err = pinAppMCPAuthorityBindingWithLease(context.Background(), owner)
	if err == nil || !strings.Contains(err.Error(), "application authority locator changed") {
		t.Fatalf("changed preexisting owner locator was not refused by lease validation: %v", err)
	}
	afterInfo, infoErr := os.Lstat(locatorPath)
	afterBytes, readErr := os.ReadFile(locatorPath)
	if infoErr != nil || readErr != nil || !os.SameFile(beforeInfo, afterInfo) || !bytes.Equal(conflictBytes, afterBytes) {
		t.Fatalf("conflicting publication replaced durable locator: stat=%v read=%v", infoErr, readErr)
	}
}
