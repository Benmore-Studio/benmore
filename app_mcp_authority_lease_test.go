//go:build !cli && !windows

package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func cleanupAppMCPAuthorityLease(t *testing.T, lease *appMCPAuthorityLease) {
	t.Helper()
	t.Cleanup(func() { _ = lease.Close() })
}

func TestAppMCPAuthorityBindingAbsentPreservesLegacyNoRootCoordinator(t *testing.T) {
	app := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", "")
	release, lease, err := beginAppMCPPolicyChange(context.Background(), app)
	if release != nil {
		t.Cleanup(release)
	}
	if err != nil || release == nil || lease != nil {
		if release != nil {
			release()
		}
		t.Fatalf("ordinary unbound app lost the no-root policy path: lease=%v err=%v", lease, err)
	}
	release()
	release()
	if _, err := os.Lstat(filepath.Join(filepath.Dir(app), appMCPAuthorityBindingDirectory)); !os.IsNotExist(err) {
		t.Fatalf("ordinary policy coordination created locator state: %v", err)
	}
}

func TestAppMCPAuthorityBorrowedViewsShareOneLiveOwner(t *testing.T) {
	authority := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	appsDir := authorityFoundationTempDir(t)
	appA := filepath.Join(appsDir, "fixture")
	appB := filepath.Join(appsDir, "fixture-dev")
	for _, dir := range []string{appA, appB} {
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := updateAppMCPEpoch(appA, true, false, true); err != nil {
		t.Fatal(err)
	}

	owner, err := acquireAppMCPAuthorityLease(context.Background(), appA)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, owner)
	viewA, err := borrowAppMCPAuthorityLease(context.Background(), owner, appA)
	if err != nil {
		_ = owner.Close()
		t.Fatal(err)
	}
	viewB, err := borrowAppMCPAuthorityLease(context.Background(), owner, appB)
	if err != nil {
		_ = owner.Close()
		t.Fatal(err)
	}
	if viewA.owner != owner || viewB.owner != owner || viewA.root != owner.root || viewB.root != owner.root || viewA.file != owner.file || viewB.file != owner.file {
		t.Fatal("borrowed views did not share the exact native root and lock")
	}
	if viewA.key != hashBytesSHA256([]byte(appA)) || viewB.key != hashBytesSHA256([]byte(appB)) || viewA.key == viewB.key {
		t.Fatal("borrowed instance owner hashes are not distinct and canonical")
	}
	wrongKeyView := &appMCPAuthorityLease{root: owner.root, file: owner.file, key: hashBytesSHA256([]byte(appB)), path: appA, owner: owner, ownerIdentity: owner}
	if _, err := wrongKeyView.read(); err == nil {
		t.Fatal("borrowed view with a mismatched owner hash was accepted")
	}
	wrongPathView := &appMCPAuthorityLease{root: owner.root, file: owner.file, key: viewA.key, path: appB, owner: owner, ownerIdentity: owner}
	if _, err := wrongPathView.read(); err == nil {
		t.Fatal("borrowed view with a mismatched app path was accepted")
	}
	if _, err := borrowAppMCPAuthorityLease(context.Background(), viewA, appB); err == nil {
		t.Fatal("borrow-of-borrow was accepted")
	}
	if _, err := pinAppMCPAuthorityBindingWithLease(context.Background(), viewA); err == nil {
		t.Fatal("borrowed view was accepted as a locator installation owner")
	}
	if _, err := borrowAppMCPAuthorityLease(nil, owner, appA); err == nil {
		t.Fatal("missing borrow context was accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := borrowAppMCPAuthorityLease(ctx, owner, appA); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled borrow context was accepted: %v", err)
	}
	if err := viewA.Close(); err == nil {
		t.Fatal("borrowed view closed the owner")
	}
	if state, err := owner.read(); err != nil || state == nil || !state.Exposed {
		t.Fatalf("borrowed close changed owner state: state=%+v err=%v", state, err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := borrowAppMCPAuthorityLease(context.Background(), owner, appA); err == nil {
		t.Fatal("closed owner was accepted for a new borrowed view")
	}
	if _, err := viewB.read(); err == nil {
		t.Fatal("stale borrowed view remained usable after owner close")
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("owner close was not idempotent: %v", err)
	}

	// The native lock is available to a real contender after the one owner closes.
	contender, err := acquireAppMCPAuthorityLease(context.Background(), appA)
	if err != nil {
		t.Fatalf("owner close leaked the native lock: %v", err)
	}
	cleanupAppMCPAuthorityLease(t, contender)
	if err := contender.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPPolicyCoordinatorReturnsBorrowedViewAndOwnsRelease(t *testing.T) {
	authority := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	app := authorityFoundationTempDir(t)
	if _, err := updateAppMCPEpoch(app, true, false, true); err != nil {
		t.Fatal(err)
	}
	release, view, err := beginAppMCPPolicyChange(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	if release == nil || view == nil || view.owner == nil || view.ownsResources {
		if release != nil {
			release()
		}
		t.Fatalf("policy coordinator did not return a borrowed same-path view: %+v", view)
	}
	if state, err := view.read(); err != nil || state == nil {
		release()
		t.Fatalf("coordinator view could not read owner state: %+v %v", state, err)
	}
	release()
	release()
	if _, err := view.read(); err == nil {
		t.Fatal("coordinator release did not invalidate its borrowed view")
	}
	owner, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatalf("coordinator release did not return the root lock: %v", err)
	}
	cleanupAppMCPAuthorityLease(t, owner)
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	writeCtx, writeRelease, writeView, err := acquireAppMCPWritePolicy(context.Background(), app)
	if err != nil || writeCtx == nil || writeRelease == nil || writeView == nil || writeView.owner == nil || writeView.ownsResources {
		if writeRelease != nil {
			writeRelease()
		}
		t.Fatalf("write coordinator did not return a borrowed owner view: view=%+v err=%v", writeView, err)
	}
	t.Cleanup(writeRelease)
	writeRelease()
	if _, err := writeView.read(); err == nil {
		t.Fatal("write coordinator release left its borrowed view live")
	}
}

func TestAppMCPAuthorityBorrowRejectsAliasesAndChangedRoot(t *testing.T) {
	base := authorityFoundationTempDir(t)
	authority := filepath.Join(base, "authority")
	if err := os.Mkdir(authority, 0700); err != nil {
		t.Fatal(err)
	}
	app := filepath.Join(base, "app")
	if err := os.Mkdir(app, 0700); err != nil {
		t.Fatal(err)
	}
	alias := filepath.Join(base, "app-alias")
	if err := os.Symlink(app, alias); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	owner, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, owner)
	if _, err := borrowAppMCPAuthorityLease(context.Background(), owner, alias); err == nil {
		t.Fatal("application symlink alias was accepted as a borrowed owner")
	}
	otherAuthority := filepath.Join(base, "other-authority")
	if err := os.Mkdir(otherAuthority, 0700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", otherAuthority)
	if _, err := borrowAppMCPAuthorityLease(context.Background(), owner, app); err == nil {
		t.Fatal("changed configured authority root was accepted")
	}
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	if _, err := borrowAppMCPAuthorityLease(context.Background(), owner, app); err != nil {
		t.Fatalf("restored exact authority root did not recover: %v", err)
	}
}

func TestAppMCPAuthorityOwnerWaitCancellationAndRecovery(t *testing.T) {
	authority := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	app := authorityFoundationTempDir(t)
	owner, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, owner)
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	t.Cleanup(cancel)
	done := make(chan error, 1)
	go func() {
		contender, err := acquireAppMCPAuthorityLease(ctx, app)
		if contender != nil {
			err = errors.Join(err, contender.Close())
		}
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			_ = owner.Close()
			t.Fatalf("contender did not honor cancellation: %v", err)
		}
	case <-time.After(2 * time.Second):
		cancel()
		_ = owner.Close()
		select {
		case <-done:
			t.Fatal("contender stayed blocked until owner release after context cancellation")
		case <-time.After(2 * time.Second):
			t.Fatal("contender did not finish after context cancellation and owner release")
		}
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	contender, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatalf("canceled contender leaked the file lock: %v", err)
	}
	cleanupAppMCPAuthorityLease(t, contender)
	if err := contender.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPAuthorityLeaseRejectsReplacedLockPath(t *testing.T) {
	authority := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	app := authorityFoundationTempDir(t)
	owner, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, owner)
	if err := owner.root.Rename(".lock", ".lock-replaced"); err != nil {
		_ = owner.Close()
		t.Fatal(err)
	}
	replacement, err := owner.root.OpenFile(".lock", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
	if err != nil {
		_ = owner.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = replacement.Close() })
	if err := replacement.Close(); err != nil {
		_ = owner.Close()
		t.Fatal(err)
	}
	if _, err := owner.read(); err == nil {
		t.Fatal("owner lease accepted a replaced lock path")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("tampered owner close was not idempotent: %v", err)
	}
	recovered, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatalf("new owner could not recover after lock replacement control: %v", err)
	}
	cleanupAppMCPAuthorityLease(t, recovered)
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPAuthorityLeaseRejectsReplacedRootPath(t *testing.T) {
	authority := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	app := authorityFoundationTempDir(t)
	owner, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, owner)
	oldAuthority := authority + ".old"
	if err := os.Rename(authority, oldAuthority); err != nil {
		_ = owner.Close()
		t.Fatal(err)
	}
	if err := os.Mkdir(authority, 0700); err != nil {
		_ = owner.Close()
		t.Fatal(err)
	}
	if _, err := owner.read(); err == nil {
		t.Fatal("owner lease accepted a replaced authority-root path")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	if err := owner.Close(); err != nil {
		t.Fatalf("replaced-root owner close was not idempotent: %v", err)
	}
	recovered, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatalf("new root at the configured path could not acquire a fresh lease: %v", err)
	}
	cleanupAppMCPAuthorityLease(t, recovered)
	if err := recovered.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestAppMCPAuthorityReconstructedOwnerCannotUseOrReleaseNativeLease(t *testing.T) {
	authority := authorityFoundationTempDir(t)
	t.Setenv("BENMORE_MCP_AUTHORITY_DIR", authority)
	app := authorityFoundationTempDir(t)
	if _, err := updateAppMCPEpoch(app, true, false, true); err != nil {
		t.Fatal(err)
	}
	owner, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatal(err)
	}
	cleanupAppMCPAuthorityLease(t, owner)
	state, err := owner.read()
	if err != nil || state == nil {
		t.Fatalf("native owner could not read its epoch: state=%+v err=%v", state, err)
	}
	stateBytesBefore, err := os.ReadFile(filepath.Join(authority, owner.key+".json"))
	if err != nil {
		t.Fatal(err)
	}

	// Build fresh synchronization fields; retain only the acquired owner's identity.
	forged := &appMCPAuthorityLease{
		root: owner.root, file: owner.file, key: owner.key, path: owner.path,
		requestedPath: owner.requestedPath, authorityPath: owner.authorityPath,
		authorityID: owner.authorityID, ownerIdentity: owner.ownerIdentity, ownsResources: true,
	}
	if err := validateAppMCPAuthorityLease(forged); err == nil {
		t.Fatal("reconstructed owner validated using another owner's native resources")
	}
	if _, err := forged.read(); err == nil {
		t.Fatal("reconstructed owner read using another owner's native resources")
	}
	if _, err := borrowAppMCPAuthorityLease(context.Background(), forged, app); err == nil {
		t.Fatal("reconstructed owner borrowed a view")
	}
	if _, err := pinAppMCPAuthorityBindingWithLease(context.Background(), forged); err == nil {
		t.Fatal("reconstructed owner published a locator")
	}
	if err := storeAppMCPEpochWithLease(forged, state); err == nil {
		t.Fatal("reconstructed owner stored an authority record")
	}
	if err := forged.Close(); err == nil {
		t.Fatal("reconstructed owner closed the actual owner's native resources")
	}
	if _, err := os.Lstat(filepath.Join(filepath.Dir(app), appMCPAuthorityBindingDirectory)); !os.IsNotExist(err) {
		t.Fatalf("reconstructed owner pin created locator directory: %v", err)
	}
	stateBytesAfter, err := os.ReadFile(filepath.Join(authority, owner.key+".json"))
	if err != nil || !bytes.Equal(stateBytesBefore, stateBytesAfter) {
		t.Fatalf("reconstructed owner changed epoch bytes: %v", err)
	}
	if got, err := owner.read(); err != nil || got == nil || !got.Exposed {
		t.Fatalf("reconstructed owner disturbed genuine owner: state=%+v err=%v", got, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	blocked, err := acquireAppMCPAuthorityLease(ctx, app)
	if blocked != nil {
		cleanupAppMCPAuthorityLease(t, blocked)
		_ = blocked.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("forged close released the actual native flock: lease=%v err=%v", blocked, err)
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}

	replacement, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatalf("fresh owner could not acquire after genuine release: %v", err)
	}
	cleanupAppMCPAuthorityLease(t, replacement)
	if err := forged.Close(); err == nil {
		t.Fatal("stale reconstructed close released a fresh owner")
	}
	if got, err := replacement.read(); err != nil || got == nil {
		t.Fatalf("stale close disturbed replacement owner: state=%+v err=%v", got, err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	blocked, err = acquireAppMCPAuthorityLease(ctx, app)
	if blocked != nil {
		cleanupAppMCPAuthorityLease(t, blocked)
		_ = blocked.Close()
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stale reconstructed close released replacement native flock: lease=%v err=%v", blocked, err)
	}
	if err := replacement.Close(); err != nil {
		t.Fatal(err)
	}
	fresh, err := acquireAppMCPAuthorityLease(context.Background(), app)
	if err != nil {
		t.Fatalf("native lock did not release after genuine replacement close: %v", err)
	}
	cleanupAppMCPAuthorityLease(t, fresh)
	if err := fresh.Close(); err != nil {
		t.Fatal(err)
	}
}
