//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

// Connector authority never lives in the app tree or its database snapshots.
// Only the service process configuration selects this owner-only directory.
// Missing metadata denies connector calls; it is never reconstructed from a DB.
type appMCPEpochState struct {
	Version            int    `json:"version"`
	App                string `json:"app"`
	Epoch              string `json:"epoch"`
	Exposed            bool   `json:"exposed"`
	ApprovedWrites     *bool  `json:"approved_writes,omitempty"`
	ApprovedWriteEpoch string `json:"approved_write_epoch,omitempty"`
	// The reviewed digests the owner approved writes under. They are kept
	// while writes are on, and through a start-up suspension (so a restart
	// with the same reviewed source and a verified enrollment can resume
	// them). Every explicit owner-off, restore and revoke clears them.
	ApprovedContractDigest  string `json:"approved_contract_digest,omitempty"`
	ApprovedExecutionDigest string `json:"approved_execution_digest,omitempty"`
	// Reserved owner switches with no consumers yet. omitempty keeps every
	// state file written before they existed canonical, so none needs a
	// migration; a restore or a full disable clears them like exposure.
	ExternalExport         bool   `json:"external_export,omitempty"`
	PublicPublication      bool   `json:"public_publication,omitempty"`
	ExternalExportEpoch    string `json:"external_export_epoch,omitempty"`
	PublicPublicationEpoch string `json:"public_publication_epoch,omitempty"`
	// AutoApprove lets a command declared approval: grant run without a
	// per-write browser approval, for a grant whose user ticked the tool at
	// consent. It is valid only while approved writes are on, and every path
	// that rotates the write epoch clears it and rotates its epoch, so turning
	// writes off (or a restore) also ends it and a later enable needs a new one.
	AutoApprove      bool   `json:"auto_approve,omitempty"`
	AutoApproveEpoch string `json:"auto_approve_epoch,omitempty"`
}

// appMCPAuthorityRecordStoreFault injects deterministic errors at the atomic
// owner-record durability boundaries in native tests. Production leaves it nil.
var appMCPAuthorityRecordStoreFault func(stage, name, recordState string) error

// normalizeLegacyAppMCPPath preserves clean relative paths only at legacy outer entries.
func normalizeLegacyAppMCPPath(dir string) (string, error) {
	if dir == "" || filepath.Clean(dir) != dir {
		return "", fmt.Errorf("connector application path must be nonempty and clean")
	}
	if filepath.IsAbs(dir) {
		return dir, nil
	}
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return "", fmt.Errorf("cannot resolve connector application identity")
	}
	return absolute, nil
}

func appMCPAuthorityRoot(dir string) (*os.Root, string, error) {
	var err error
	dir, err = normalizeLegacyAppMCPPath(dir)
	if err != nil {
		return nil, "", err
	}
	// A durable binding is consulted before configuration can take the legacy
	// empty-environment path. It records which authority owns this app; it is
	// not a grant to recreate or select authority on its own.
	binding, err := readAppMCPAuthorityBinding(dir)
	if err != nil {
		return nil, "", err
	}
	stateDir := os.Getenv("BENMORE_MCP_AUTHORITY_DIR")
	if stateDir == "" || !filepath.IsAbs(stateDir) {
		return nil, "", fmt.Errorf("connector authority directory is unavailable")
	}
	stateDir = realPathForContainment(stateDir)
	appDir := realPathForContainment(dir)
	if pathWithinDir(appDir, stateDir) {
		return nil, "", fmt.Errorf("connector authority must be outside app snapshots")
	}
	pathInfo, err := os.Lstat(stateDir)
	if err != nil {
		return nil, "", err
	}
	if !pathInfo.IsDir() || pathInfo.Mode()&os.ModeSymlink != 0 || pathInfo.Mode().Perm() != 0700 || !fileOwnedByProcess(pathInfo) {
		return nil, "", fmt.Errorf("connector authority directory must be owner-only")
	}
	root, err := os.OpenRoot(stateDir)
	if err != nil {
		return nil, "", err
	}
	// Check the opened directory, not just the path observed before opening it.
	f, err := root.Open(".")
	if err != nil {
		return nil, "", errors.Join(err, root.Close())
	}
	openedInfo, statErr := f.Stat()
	closeErr := f.Close()
	currentPathInfo, pathErr := os.Lstat(stateDir)
	if statErr != nil || closeErr != nil || pathErr != nil || !os.SameFile(pathInfo, currentPathInfo) || !os.SameFile(currentPathInfo, openedInfo) || openedInfo.Mode()&os.ModeSymlink != 0 || openedInfo.Mode().Perm() != 0700 || !fileOwnedByProcess(openedInfo) {
		return nil, "", errors.Join(fmt.Errorf("connector authority directory changed"), statErr, closeErr, pathErr, root.Close())
	}
	if binding != nil {
		if err := validateAppMCPAuthorityBindingRoot(binding, dir, root); err != nil {
			return nil, "", errors.Join(err, root.Close())
		}
	}
	return root, hashBytesSHA256([]byte(appDir)), nil
}

func readAppMCPEpoch(root *os.Root, key string) (*appMCPEpochState, error) {
	info, err := root.Lstat(key + ".json")
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !fileOwnedByProcess(info) || info.Size() > 1024 {
		return nil, fmt.Errorf("invalid connector authority metadata")
	}
	f, err := root.Open(key + ".json")
	if err != nil {
		return nil, err
	}
	data, readErr := io.ReadAll(io.LimitReader(f, 1025))
	closeErr := f.Close()
	if readErr != nil || closeErr != nil || len(data) > 1024 {
		return nil, fmt.Errorf("cannot read connector authority metadata")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var state appMCPEpochState
	if decoder.Decode(&state) != nil {
		return nil, fmt.Errorf("invalid connector authority metadata")
	}
	var extra any
	decoded, err := hex.DecodeString(state.Epoch)
	if decoder.Decode(&extra) != io.EOF || (state.Version != 1 && state.Version != 2) || state.App != key || err != nil || len(decoded) != 32 || state.Epoch != hex.EncodeToString(decoded) ||
		!appMCPValidCapabilityEpoch(state.ExternalExportEpoch, state.ExternalExport) || !appMCPValidCapabilityEpoch(state.PublicPublicationEpoch, state.PublicPublication) ||
		!appMCPValidCapabilityEpoch(state.AutoApproveEpoch, state.AutoApprove) {
		return nil, fmt.Errorf("invalid connector authority metadata")
	}
	if state.Version == 1 {
		if state.ApprovedWrites != nil || state.ApprovedWriteEpoch != "" || state.AutoApprove || state.AutoApproveEpoch != "" {
			return nil, fmt.Errorf("invalid connector authority metadata")
		}
	} else {
		writeEpoch, writeErr := hex.DecodeString(state.ApprovedWriteEpoch)
		if state.ApprovedWrites == nil || writeErr != nil || len(writeEpoch) != 32 || state.ApprovedWriteEpoch != hex.EncodeToString(writeEpoch) ||
			state.AutoApprove && (!*state.ApprovedWrites || !state.Exposed) {
			return nil, fmt.Errorf("invalid connector authority metadata")
		}
	}
	if (state.ApprovedContractDigest == "") != (state.ApprovedExecutionDigest == "") || state.Version == 1 && state.ApprovedContractDigest != "" ||
		state.ApprovedContractDigest != "" && (!appMCPValidCapabilityEpoch(state.ApprovedContractDigest, true) || !appMCPValidCapabilityEpoch(state.ApprovedExecutionDigest, true)) {
		return nil, fmt.Errorf("invalid connector authority metadata")
	}
	canonical, err := json.Marshal(state)
	if err != nil || !bytes.Equal(bytes.TrimSpace(data), canonical) {
		return nil, fmt.Errorf("noncanonical connector authority metadata")
	}
	return &state, nil
}

func appMCPValidCapabilityEpoch(epoch string, enabled bool) bool {
	if epoch == "" {
		return !enabled
	}
	decoded, err := hex.DecodeString(epoch)
	return err == nil && len(decoded) == 32 && epoch == hex.EncodeToString(decoded)
}

func rotateAppMCPCapabilityEpoch() (string, error) {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(token[:]), nil
}

func currentAppMCPEpoch(dir string) (*appMCPEpochState, error) {
	root, key, err := appMCPAuthorityRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	return readAppMCPEpoch(root, key)
}

// All writers share a native file lock, including distinct service processes.
// ponytail: one authority lock for all apps; use per-app locks if contention matters.
func updateAppMCPEpoch(dir string, exposed bool, rotate, allowCreate bool) (*appMCPEpochState, error) {
	return updateAppMCPEpochContext(context.Background(), dir, exposed, rotate, allowCreate)
}

// updateAppMCPEpochContext waits for the authority lock only as long as ctx
// allows, so an owner action cannot block unbounded behind a held lease.
func updateAppMCPEpochContext(ctx context.Context, dir string, exposed bool, rotate, allowCreate bool) (*appMCPEpochState, error) {
	return mutateAppMCPEpochContext(ctx, dir, &exposed, rotate, allowCreate, nil)
}

// mutateAppMCPEpochContext serializes an owner-state mutation with exposure
// and restore changes, so independent capability switches cannot overwrite
// each other from stale reads.
func mutateAppMCPEpochContext(ctx context.Context, dir string, exposed *bool, rotate, allowCreate bool, mutate func(*appMCPEpochState) error) (*appMCPEpochState, error) {
	root, key, err := appMCPAuthorityRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if info, err := root.Lstat(".lock"); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !fileOwnedByProcess(info)) {
		return nil, fmt.Errorf("invalid connector authority lock")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	lock, err := root.OpenFile(".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil || !fileOwnedByProcess(info) || info.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("invalid connector authority lock")
	}
	if err := lockAuthorityFileContext(ctx, lock); err != nil {
		return nil, err
	}
	defer unlockAuthorityFile(lock)
	if err := validateAuthorityLockPath(root, lock); err != nil {
		return nil, err
	}
	state, err := readAppMCPEpoch(root, key)
	if os.IsNotExist(err) && allowCreate {
		state = &appMCPEpochState{Version: 1, App: key}
		rotate = true
	} else if err != nil {
		return nil, err
	}
	if rotate {
		var token [32]byte
		if _, err := rand.Read(token[:]); err != nil {
			return nil, err
		}
		state.Epoch = hex.EncodeToString(token[:])
	}
	if exposed != nil {
		state.Exposed = *exposed
		if !*exposed {
			state.ExternalExport, state.PublicPublication = false, false
			if state.ExternalExportEpoch, err = rotateAppMCPCapabilityEpoch(); err != nil {
				return nil, err
			}
			if state.PublicPublicationEpoch, err = rotateAppMCPCapabilityEpoch(); err != nil {
				return nil, err
			}
		}
	}
	if mutate != nil {
		if err := mutate(state); err != nil {
			return nil, err
		}
	}
	if state.Version == 2 && (exposed != nil && !*exposed || rotate) {
		writes := false
		state.ApprovedWrites = &writes
		state.ApprovedContractDigest, state.ApprovedExecutionDigest = "", ""
		if err := rotateAppMCPWriteEpoch(state); err != nil {
			return nil, err
		}
	}
	data, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	staged := ".staged-" + hex.EncodeToString(nonce[:])
	f, err := root.OpenFile(staged, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer root.Remove(staged)
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return nil, err
	}
	if err := validateAuthorityLockPath(root, lock); err != nil {
		return nil, err
	}
	if err := root.Rename(staged, key+".json"); err != nil {
		return nil, err
	}
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
		return nil, err
	}
	return state, nil
}

// rotateAppMCPWriteEpoch is called by every write-authority change (writes on
// or off, disable, epoch rotation, restore). It also ends auto-approval and
// rotates its epoch, so an approval synthesized under the old switch can never
// commit and turning auto-approval on again is always a fresh decision.
func rotateAppMCPWriteEpoch(state *appMCPEpochState) error {
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	autoEpoch, err := rotateAppMCPCapabilityEpoch()
	if err != nil {
		return err
	}
	state.ApprovedWriteEpoch = hex.EncodeToString(token[:])
	state.AutoApprove, state.AutoApproveEpoch = false, autoEpoch
	return nil
}

func storeAppMCPEpochWithLease(lease *appMCPAuthorityLease, state *appMCPEpochState) error {
	if lease == nil || state == nil {
		return errors.New("connector authority lease is unavailable")
	}
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	_, err = storeAppMCPAuthorityRecordWithLease(lease, lease.key+".json", data)
	return err
}

// storeAppMCPAuthorityRecordWithLease atomically persists only the two
// owner-root records that share this lock. renamed reports when directory
// durability failed after the new name became visible.
func storeAppMCPAuthorityRecordWithLease(lease *appMCPAuthorityLease, name string, data []byte) (renamed bool, err error) {
	if lease == nil || lease.root == nil || lease.file == nil || (name != lease.key+".json" && name != lease.key+".revisions.json") {
		return false, errors.New("invalid connector authority record write")
	}
	owner := lease
	if lease.owner != nil {
		owner = lease.owner
	}
	if owner.owner != nil || !owner.ownsResources || owner.ownerIdentity != owner || lease.ownerIdentity != owner {
		return false, errors.New("invalid connector authority lease owner")
	}
	owner.mu.Lock()
	defer owner.mu.Unlock()
	if err := validateAppMCPAuthorityLeaseLocked(lease, owner); err != nil {
		return false, err
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return false, err
	}
	staged := ".staged-" + hex.EncodeToString(nonce[:])
	f, err := lease.root.OpenFile(staged, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return false, err
	}
	defer lease.root.Remove(staged)
	_, writeErr := f.Write(data)
	recordState := ""
	if name == lease.key+".revisions.json" {
		var record struct {
			State string `json:"state"`
		}
		if json.Unmarshal(data, &record) == nil {
			recordState = record.State
		}
	}
	if injected := appMCPAuthorityRecordStoreError("file_sync", name, recordState); injected != nil {
		writeErr = errors.Join(writeErr, injected)
	} else {
		writeErr = errors.Join(writeErr, f.Sync())
	}
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return false, err
	}
	if err := validateAuthorityLockPath(lease.root, lease.file); err != nil {
		return false, err
	}
	if injected := appMCPAuthorityRecordStoreError("before_rename", name, recordState); injected != nil {
		return false, injected
	}
	if err := lease.root.Rename(staged, name); err != nil {
		return false, err
	}
	renamed = true
	directory, err := lease.root.Open(".")
	if err != nil {
		return renamed, err
	}
	if injected := appMCPAuthorityRecordStoreError("directory_sync", name, recordState); injected != nil {
		return renamed, errors.Join(injected, directory.Close())
	}
	return renamed, errors.Join(directory.Sync(), directory.Close())
}

func appMCPAuthorityRecordStoreError(stage, name, recordState string) error {
	if appMCPAuthorityRecordStoreFault == nil {
		return nil
	}
	return appMCPAuthorityRecordStoreFault(stage, name, recordState)
}

// invalidateAppMCPWritesWithLease keeps reviewed reads exposed but makes every
// previously issued write pin stale before policy-related database effects.
// It also forgets the digests writes were approved under, so nothing resumes
// them later.
func invalidateAppMCPWritesWithLease(lease *appMCPAuthorityLease) error {
	return turnOffAppMCPWritesWithLease(lease, false)
}

// suspendAppMCPWritesWithLease is the process-start variant: writes go off and
// the write epoch rotates exactly as above, but the approved digests stay so
// resumeAppMCPApprovedWrites can turn writes back on once the same reviewed
// source and a verified enrollment are confirmed. A crash before that leaves
// writes off with the binding in place, so the next start retries.
func suspendAppMCPWritesWithLease(lease *appMCPAuthorityLease) error {
	return turnOffAppMCPWritesWithLease(lease, true)
}

func turnOffAppMCPWritesWithLease(lease *appMCPAuthorityLease, keepBinding bool) error {
	state, err := lease.read()
	if err != nil {
		if os.IsNotExist(err) {
			return nil // absent authority cannot resolve an approved writer
		}
		return err
	}
	writes := false
	state.Version = 2
	state.ApprovedWrites = &writes
	if !keepBinding {
		state.ApprovedContractDigest, state.ApprovedExecutionDigest = "", ""
	}
	if err := rotateAppMCPWriteEpoch(state); err != nil {
		return err
	}
	return storeAppMCPEpochWithLease(lease, state)
}

// setAppMCPApprovedWrites is an owner-only control-plane primitive. It does
// not expose a request handler or authorize a mutation by itself.
func setAppMCPApprovedWrites(dir string, enabled bool) (*appMCPEpochState, error) {
	return setAppMCPApprovedWritesContext(context.Background(), dir, enabled)
}

func setAppMCPApprovedWritesContext(ctx context.Context, dir string, enabled bool) (*appMCPEpochState, error) {
	root, key, err := appMCPAuthorityRoot(dir)
	if err != nil {
		return nil, err
	}
	defer root.Close()
	if info, err := root.Lstat(".lock"); err == nil && (!info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !fileOwnedByProcess(info)) {
		return nil, fmt.Errorf("invalid connector authority lock")
	} else if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	lock, err := root.OpenFile(".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	defer lock.Close()
	info, err := lock.Stat()
	if err != nil || !fileOwnedByProcess(info) || info.Mode().Perm() != 0600 {
		return nil, fmt.Errorf("invalid connector authority lock")
	}
	if err := lockAuthorityFileContext(ctx, lock); err != nil {
		return nil, err
	}
	defer unlockAuthorityFile(lock)
	if err := validateAuthorityLockPath(root, lock); err != nil {
		return nil, err
	}
	state, err := readAppMCPEpoch(root, key)
	if err != nil {
		return nil, err
	}
	if enabled && !state.Exposed {
		return nil, fmt.Errorf("read authority must be exposed before write authority")
	}
	// An owner-off also clears a start-up suspension (writes already false,
	// binding kept), so it can never be resumed afterwards.
	if state.Version == 2 && *state.ApprovedWrites == enabled && (enabled || state.ApprovedContractDigest == "") {
		return state, nil
	}
	if state.Version == 1 {
		state.Version = 2
	}
	writes := enabled
	state.ApprovedWrites = &writes
	if !enabled {
		state.ApprovedContractDigest, state.ApprovedExecutionDigest = "", ""
	}
	if err := rotateAppMCPWriteEpoch(state); err != nil {
		return nil, err
	}
	data, err := json.Marshal(state)
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	staged := ".staged-" + hex.EncodeToString(nonce[:])
	f, err := root.OpenFile(staged, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	defer root.Remove(staged)
	_, writeErr := f.Write(data)
	if err := errors.Join(writeErr, f.Sync(), f.Close()); err != nil {
		return nil, err
	}
	if err := validateAuthorityLockPath(root, lock); err != nil {
		return nil, err
	}
	if err := root.Rename(staged, key+".json"); err != nil {
		return nil, err
	}
	directory, err := root.Open(".")
	if err != nil {
		return nil, err
	}
	if err := errors.Join(directory.Sync(), directory.Close()); err != nil {
		return nil, err
	}
	return state, nil
}

// setAppMCPAutoApproveContext turns auto-approval on or off. Either way the
// auto-approval epoch rotates, so an operation auto-approved under an earlier
// switch can never commit, even after it is turned on again. Turning it on
// requires exposure and approved writes; it never turns writes on itself.
func setAppMCPAutoApproveContext(ctx context.Context, dir string, enabled bool) (*appMCPEpochState, error) {
	return mutateAppMCPEpochContext(ctx, dir, nil, false, false, func(state *appMCPEpochState) error {
		if enabled && (!state.Exposed || state.Version != 2 || state.ApprovedWrites == nil || !*state.ApprovedWrites) {
			return errors.New("approved writes must be on before auto-approval")
		}
		epoch, err := rotateAppMCPCapabilityEpoch()
		if err != nil {
			return err
		}
		state.AutoApprove = enabled
		if state.Version == 2 { // a version 1 state carries no write fields
			state.AutoApproveEpoch = epoch
		}
		return nil
	})
}

// A restore never re-enables exposure. Rotate before any database replacement;
// if later activation fails, the new epoch remains authoritative.
func invalidateAppMCPForRestore(dir string) error {
	var err error
	dir, err = normalizeLegacyAppMCPPath(dir)
	if err != nil {
		return err
	}
	binding, bindingErr := readAppMCPAuthorityBinding(dir)
	if bindingErr != nil {
		return bindingErr
	}
	if os.Getenv("BENMORE_MCP_AUTHORITY_DIR") == "" {
		if binding != nil {
			return fmt.Errorf("configured authority is required for a bound application")
		}
		return nil
	} // legacy app, no connector authority can resolve
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	release, lease, err := beginAppMCPPolicyChange(ctx, dir)
	if err != nil {
		return err
	}
	defer release()
	return invalidateAppMCPForRestoreWithLease(lease)
}

func beginAppMCPRestorePolicy(ctx context.Context, dir string) (func(), *appMCPAuthorityLease, error) {
	release, lease, err := beginAppMCPPolicyChange(ctx, dir)
	if err != nil {
		return nil, nil, err
	}
	if err := invalidateAppMCPForRestoreWithLease(lease); err != nil {
		release()
		return nil, nil, err
	}
	return release, lease, nil
}

func invalidateAppMCPForRestoreWithLease(lease *appMCPAuthorityLease) error {
	if lease == nil {
		return nil
	}
	state, err := lease.read()
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	state.Exposed = false
	state.ExternalExport, state.PublicPublication = false, false
	var token [32]byte
	if _, err := rand.Read(token[:]); err != nil {
		return err
	}
	state.Epoch = hex.EncodeToString(token[:])
	if state.Version == 1 {
		state.Version = 2
	}
	writes := false
	state.ApprovedWrites = &writes
	state.ApprovedContractDigest, state.ApprovedExecutionDigest = "", ""
	if err := rotateAppMCPWriteEpoch(state); err != nil {
		return err
	}
	return storeAppMCPEpochWithLease(lease, state)
}

func validateAppMCPEpoch(dir, epoch string) error {
	state, err := currentAppMCPEpoch(dir)
	if err != nil || !state.Exposed || !SecureCompare(state.Epoch, epoch) {
		return fmt.Errorf("connector authority is unavailable or revoked")
	}
	return nil
}
