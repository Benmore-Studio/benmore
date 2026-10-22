//go:build !cli

package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type appMCPPolicyGate struct{ slot chan struct{} }

var appMCPPolicyGates = struct {
	sync.Mutex
	byPath map[string]*appMCPPolicyGate
}{byPath: make(map[string]*appMCPPolicyGate)}

type appMCPPolicyContextKey struct{}

func appMCPPolicyGateFor(dir string) (*appMCPPolicyGate, string, error) {
	path, err := filepath.Abs(dir)
	if err != nil {
		return nil, "", err
	}
	path = canonicalDBPath(path)
	appMCPPolicyGates.Lock()
	defer appMCPPolicyGates.Unlock()
	gate := appMCPPolicyGates.byPath[path]
	if gate == nil {
		gate = &appMCPPolicyGate{slot: make(chan struct{}, 1)}
		gate.slot <- struct{}{}
		appMCPPolicyGates.byPath[path] = gate
	}
	return gate, path, nil
}

func acquireAppMCPPolicyGate(ctx context.Context, dir string) (context.Context, func(), error) {
	if ctx == nil {
		return nil, nil, errors.New("missing write context")
	}
	gate, path, err := appMCPPolicyGateFor(dir)
	if err != nil {
		return nil, nil, err
	}
	if held, _ := ctx.Value(appMCPPolicyContextKey{}).(string); held == path {
		return nil, nil, errors.New("connector policy coordinator reentry")
	}
	select {
	case <-ctx.Done():
		return nil, nil, ctx.Err()
	case <-gate.slot:
	}
	ctx = context.WithValue(ctx, appMCPPolicyContextKey{}, path)
	return ctx, func() { gate.slot <- struct{}{} }, nil
}

type appMCPAuthorityLease struct {
	root          *os.Root
	file          *os.File
	key           string
	path          string // checked canonical app path for this view
	requestedPath string
	authorityPath string
	authorityID   string
	owner         *appMCPAuthorityLease // nil only for the owning lease
	ownerIdentity *appMCPAuthorityLease // owning lease address captured at native acquisition
	ownsResources bool
	mu            sync.Mutex // protects owner closed/resources state
	closed        bool
}

func acquireAppMCPAuthorityLease(ctx context.Context, dir string) (*appMCPAuthorityLease, error) {
	if _, err := canonicalConfiguredAppMCPAuthorityPath(); err != nil {
		return nil, err
	}
	root, key, err := appMCPAuthorityRoot(dir)
	if err != nil {
		return nil, err
	}
	info, err := root.Lstat(".lock")
	if os.IsNotExist(err) {
		file, createErr := root.OpenFile(".lock", os.O_CREATE|os.O_EXCL|os.O_RDWR, 0600)
		if os.IsExist(createErr) {
			file, createErr = root.OpenFile(".lock", os.O_RDWR, 0600)
		}
		if createErr != nil {
			root.Close()
			return nil, createErr
		}
		info, err = file.Stat()
		pathInfo, pathErr := root.Lstat(".lock")
		if err != nil || pathErr != nil || !os.SameFile(info, pathInfo) || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !fileOwnedByProcess(info) {
			file.Close()
			root.Close()
			return nil, errors.New("invalid connector authority lock")
		}
		if err := lockAuthorityFileContext(ctx, file); err != nil {
			file.Close()
			root.Close()
			return nil, err
		}
		if err := validateAuthorityLockPath(root, file); err != nil {
			unlockAuthorityFile(file)
			file.Close()
			root.Close()
			return nil, err
		}
		return newAppMCPAuthorityLease(root, file, key, dir)
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !fileOwnedByProcess(info) {
		root.Close()
		if err != nil {
			return nil, err
		}
		return nil, errors.New("invalid connector authority lock")
	}
	file, err := root.OpenFile(".lock", os.O_RDWR, 0600)
	if err != nil {
		root.Close()
		return nil, err
	}
	info, err = file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !fileOwnedByProcess(info) {
		file.Close()
		root.Close()
		return nil, errors.New("invalid connector authority lock")
	}
	if err := lockAuthorityFileContext(ctx, file); err != nil {
		file.Close()
		root.Close()
		return nil, err
	}
	if err := validateAuthorityLockPath(root, file); err != nil {
		unlockAuthorityFile(file)
		file.Close()
		root.Close()
		return nil, err
	}
	return newAppMCPAuthorityLease(root, file, key, dir)
}

func newAppMCPAuthorityLease(root *os.Root, file *os.File, key, dir string) (*appMCPAuthorityLease, error) {
	location, err := appMCPAuthorityBindingLocationFor(dir)
	if err != nil {
		unlockAuthorityFile(file)
		file.Close()
		root.Close()
		return nil, err
	}
	if key != hashBytesSHA256([]byte(location.appPath)) {
		unlockAuthorityFile(file)
		file.Close()
		root.Close()
		return nil, errors.New("connector authority lease path and owner hash differ")
	}
	opened, err := root.Open(".")
	if err != nil {
		unlockAuthorityFile(file)
		file.Close()
		root.Close()
		return nil, err
	}
	info, statErr := opened.Stat()
	closeErr := opened.Close()
	configured := os.Getenv("BENMORE_MCP_AUTHORITY_DIR")
	authorityPath, pathErr := filepath.Abs(filepath.Clean(realPathForContainment(configured)))
	pathInfo, authorityStatErr := os.Lstat(authorityPath)
	if statErr != nil || closeErr != nil || pathErr != nil || authorityStatErr != nil || !os.SameFile(pathInfo, info) || !info.IsDir() || info.Mode().Perm() != 0700 || !fileOwnedByProcess(info) || rotationFileIdentity(info) == "" {
		unlockAuthorityFile(file)
		file.Close()
		root.Close()
		return nil, errors.Join(errors.New("connector authority root changed while acquiring lease"), statErr, closeErr, pathErr)
	}
	lease := &appMCPAuthorityLease{
		root: root, file: file, key: key, path: location.appPath,
		requestedPath: dir, authorityPath: authorityPath,
		authorityID: rotationFileIdentity(info), ownsResources: true,
	}
	lease.ownerIdentity = lease
	if err := validateAppMCPAuthorityLease(lease); err != nil {
		_ = lease.Close()
		return nil, err
	}
	return lease, nil
}

func validateAuthorityLockPath(root *os.Root, file *os.File) error {
	pathInfo, pathErr := root.Lstat(".lock")
	fileInfo, fileErr := file.Stat()
	if pathErr != nil || fileErr != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode().Perm() != 0600 ||
		!fileOwnedByProcess(pathInfo) || !os.SameFile(pathInfo, fileInfo) {
		return errors.New("connector authority lock changed")
	}
	return nil
}

func beginAppMCPPolicyChange(ctx context.Context, dir string) (func(), *appMCPAuthorityLease, error) {
	return beginAppMCPPolicyChangeMode(ctx, dir, false)
}

// beginAppMCPStartupPolicyChange is beginAppMCPPolicyChange for a process
// start: writes still go off before anything else happens, but the digests
// they were approved under are kept so resumeAppMCPApprovedWrites can restore
// them after the same source and a verified enrollment are confirmed. Reloads,
// environment changes and restores never keep that binding.
func beginAppMCPStartupPolicyChange(ctx context.Context, dir string) (func(), *appMCPAuthorityLease, error) {
	return beginAppMCPPolicyChangeMode(ctx, dir, true)
}

func beginAppMCPPolicyChangeMode(ctx context.Context, dir string, keepWriteBinding bool) (func(), *appMCPAuthorityLease, error) {
	var err error
	dir, err = normalizeLegacyAppMCPPath(dir)
	if err != nil {
		return nil, nil, err
	}
	ctx, releaseGate, err := acquireAppMCPPolicyGate(ctx, dir)
	if err != nil {
		return nil, nil, err
	}
	binding, bindingErr := readAppMCPAuthorityBinding(dir)
	if bindingErr != nil {
		releaseGate()
		return nil, nil, bindingErr
	}
	if os.Getenv("BENMORE_MCP_AUTHORITY_DIR") == "" {
		if binding != nil {
			releaseGate()
			return nil, nil, errors.New("configured authority is required for a bound application")
		}
		var once sync.Once
		return func() { once.Do(releaseGate) }, nil, nil
	}
	owner, err := acquireAppMCPAuthorityLease(ctx, dir)
	if err != nil {
		releaseGate()
		return nil, nil, err
	}
	turnOff := invalidateAppMCPWritesWithLease
	if keepWriteBinding {
		turnOff = suspendAppMCPWritesWithLease
	}
	if err := turnOff(owner); err != nil {
		_ = owner.Close()
		releaseGate()
		return nil, nil, err
	}
	lease, err := borrowAppMCPAuthorityLease(ctx, owner, dir)
	if err != nil {
		_ = owner.Close()
		releaseGate()
		return nil, nil, err
	}
	var once sync.Once
	return func() { once.Do(func() { _ = owner.Close(); releaseGate() }) }, lease, nil
}

func beginAppMCPWritePolicyChange(ctx context.Context, dir string) (func(), *appMCPAuthorityLease, error) {
	return beginAppMCPPolicyChange(ctx, dir)
}

func acquireAppMCPWritePolicy(ctx context.Context, dir string) (context.Context, func(), *appMCPAuthorityLease, error) {
	var err error
	dir, err = normalizeLegacyAppMCPPath(dir)
	if err != nil {
		return nil, nil, nil, err
	}
	ctx, releaseGate, err := acquireAppMCPPolicyGate(ctx, dir)
	if err != nil {
		return nil, nil, nil, err
	}
	owner, err := acquireAppMCPAuthorityLease(ctx, dir)
	if err != nil {
		releaseGate()
		return nil, nil, nil, err
	}
	lease, err := borrowAppMCPAuthorityLease(ctx, owner, dir)
	if err != nil {
		_ = owner.Close()
		releaseGate()
		return nil, nil, nil, err
	}
	var once sync.Once
	return ctx, func() { once.Do(func() { _ = owner.Close(); releaseGate() }) }, lease, nil
}

func borrowAppMCPAuthorityLease(ctx context.Context, owner *appMCPAuthorityLease, dir string) (*appMCPAuthorityLease, error) {
	if ctx == nil {
		return nil, errors.New("missing connector authority context")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if owner == nil || owner.owner != nil || !owner.ownsResources || owner.ownerIdentity != owner {
		return nil, errors.New("connector authority view requires an owning lease")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := validateAppMCPAuthorityLeaseLocked(owner, owner); err != nil {
		return nil, err
	}
	location, err := appMCPAuthorityBindingLocationFor(dir)
	if err != nil || location.pathWasAlias || location.appPath == "" {
		return nil, errors.New("connector authority view requires a canonical application path")
	}
	configured, err := canonicalConfiguredAppMCPAuthorityPath()
	if err != nil || configured != owner.authorityPath {
		return nil, errors.New("configured connector authority root changed")
	}
	if binding, err := readAppMCPAuthorityBinding(dir); err != nil {
		return nil, err
	} else if binding != nil && (binding.AuthorityPath != owner.authorityPath || binding.AuthorityIdentity != owner.authorityID) {
		return nil, errors.New("application authority locator changed")
	}
	return &appMCPAuthorityLease{
		root: owner.root, file: owner.file, key: hashBytesSHA256([]byte(location.appPath)),
		path: location.appPath, requestedPath: dir, authorityPath: owner.authorityPath,
		authorityID: owner.authorityID, owner: owner, ownerIdentity: owner,
	}, nil
}

func validateAppMCPAuthorityLease(lease *appMCPAuthorityLease) error {
	if lease == nil || lease.root == nil || lease.file == nil {
		return errors.New("connector authority lease is unavailable")
	}
	owner := lease
	if lease.owner != nil {
		owner = lease.owner
		if owner == lease || owner.owner != nil || !owner.ownsResources || owner.ownerIdentity != owner || lease.ownerIdentity != owner {
			return errors.New("connector authority lease owner is invalid")
		}
	} else if lease.ownerIdentity != lease {
		return errors.New("connector authority lease identity is invalid")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	return validateAppMCPAuthorityLeaseLocked(lease, owner)
}

func validateAppMCPAuthorityLeaseLocked(lease, owner *appMCPAuthorityLease) error {
	if owner == nil || owner.owner != nil || !owner.ownsResources || owner.ownerIdentity != owner || lease == nil || lease.ownerIdentity != owner || (lease != owner && lease.owner != owner) || owner.closed || owner.root == nil || owner.file == nil || owner.authorityID == "" || lease.root != owner.root || lease.file != owner.file {
		return errors.New("connector authority lease is closed")
	}
	location, err := appMCPAuthorityBindingLocationFor(lease.path)
	if err != nil || location.pathWasAlias || location.appPath != lease.path || lease.key == "" || lease.key != hashBytesSHA256([]byte(location.appPath)) {
		return errors.New("connector authority lease owner path changed")
	}
	if err := validateAuthorityLockPath(owner.root, owner.file); err != nil {
		return err
	}
	configured, err := canonicalConfiguredAppMCPAuthorityPath()
	if err != nil || configured != owner.authorityPath {
		return errors.New("configured connector authority root changed")
	}
	opened, err := owner.root.Open(".")
	if err != nil {
		return errors.New("connector authority root cannot be reopened")
	}
	info, statErr := opened.Stat()
	closeErr := opened.Close()
	pathInfo, pathErr := os.Lstat(owner.authorityPath)
	if statErr != nil || closeErr != nil || pathErr != nil || !os.SameFile(pathInfo, info) || !info.IsDir() || info.Mode().Perm() != 0700 || !fileOwnedByProcess(info) || rotationFileIdentity(info) != owner.authorityID {
		return errors.Join(errors.New("connector authority root changed"), statErr, closeErr)
	}
	if binding, err := readAppMCPAuthorityBinding(lease.path); err != nil {
		return err
	} else if binding != nil {
		if binding.AppPath != lease.path || binding.OwnerHash != lease.key || binding.AuthorityPath != owner.authorityPath || binding.AuthorityIdentity != owner.authorityID {
			return errors.New("application authority locator changed")
		}
		if err := validateAppMCPAuthorityBindingRoot(binding, lease.path, owner.root); err != nil {
			return err
		}
	}
	return nil
}

func (l *appMCPAuthorityLease) Close() error {
	if l == nil {
		return nil
	}
	if l.owner != nil || !l.ownsResources || l.ownerIdentity != l {
		return errors.New("borrowed connector authority lease cannot close its owner")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	var err error
	if l.file != nil {
		unlockAuthorityFile(l.file)
		err = l.file.Close()
	}
	if l.root != nil {
		err = errors.Join(err, l.root.Close())
	}
	return err
}

func (l *appMCPAuthorityLease) read() (*appMCPEpochState, error) {
	if l == nil {
		return nil, errors.New("connector authority lease is unavailable")
	}
	owner := l
	if l.owner != nil {
		owner = l.owner
	}
	if owner.ownerIdentity != owner || l.ownerIdentity != owner || (l != owner && l.owner != owner) {
		return nil, errors.New("connector authority lease identity is invalid")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := validateAppMCPAuthorityLeaseLocked(l, owner); err != nil {
		return nil, err
	}
	return readAppMCPEpoch(l.root, l.key)
}

func validateAppMCPWriteLease(lease *appMCPAuthorityLease, pin appMCPWriteAuthorityPin) error {
	if lease == nil {
		return errors.New("connector authority lock changed")
	}
	owner := lease
	if lease.owner != nil {
		owner = lease.owner
	}
	if owner.ownerIdentity != owner || lease.ownerIdentity != owner || (lease != owner && lease.owner != owner) || validateAuthorityLockPath(lease.root, lease.file) != nil {
		return errors.New("connector authority lock changed")
	}
	state, err := lease.read()
	if err != nil {
		return err
	}
	if !state.Exposed || state.Version != 2 || state.ApprovedWrites == nil || !*state.ApprovedWrites ||
		state.App != pin.AppID || !SecureCompare(state.Epoch, pin.Epoch) || !SecureCompare(state.ApprovedWriteEpoch, pin.WriteEpoch) {
		return errors.New("owner write authority changed")
	}
	return nil
}

func lockAuthorityFileContext(ctx context.Context, file *os.File) error {
	if ctx == nil {
		return errors.New("missing connector authority context")
	}
	deadline := time.NewTimer(10 * time.Millisecond)
	defer deadline.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := tryLockAuthorityFile(file); err == nil {
			return nil
		} else if !errors.Is(err, errAuthorityLockBusy) {
			return fmt.Errorf("lock connector authority: %w", err)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			deadline.Reset(10 * time.Millisecond)
		}
	}
}
