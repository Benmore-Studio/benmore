//go:build !cli

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
)

const (
	appMCPAuthorityBindingDirectory = ".benmore-mcp-authority-bindings"
	appMCPAuthorityBindingLimit     = 16 << 10
)

var (
	errAppMCPAuthorityBindingConflict = errors.New("application authority locator conflicts with existing ownership")
	errAppMCPAuthorityBindingUnknown  = errors.New("application authority locator publication outcome is unknown")
)

// appMCPAuthorityBinding is a private durable locator, not authorization state.
type appMCPAuthorityBinding struct {
	Version           int    `json:"version"`
	AppPath           string `json:"app_path"`
	OwnerHash         string `json:"owner_hash"`
	AuthorityPath     string `json:"authority_path"`
	AuthorityIdentity string `json:"authority_identity"`
}

type appMCPAuthorityBindingLocation struct {
	appPath      string
	parentPath   string
	pathWasAlias bool
}

type appMCPAuthorityBindingRoot struct {
	parent      *os.Root
	binding     *os.Root
	parentPath  string
	parentInfo  os.FileInfo
	directoryID string
}

func (r *appMCPAuthorityBindingRoot) close() error {
	if r == nil {
		return nil
	}
	var err error
	if r.binding != nil {
		err = errors.Join(err, r.binding.Close())
	}
	if r.parent != nil {
		err = errors.Join(err, r.parent.Close())
	}
	return err
}

func appMCPAuthorityBindingLocationFor(dir string) (appMCPAuthorityBindingLocation, error) {
	if dir == "" {
		return appMCPAuthorityBindingLocation{}, errors.New("application locator path is unavailable")
	}
	absolute, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return appMCPAuthorityBindingLocation{}, errors.New("application locator path is invalid")
	}
	absolute = filepath.Clean(absolute)
	name := filepath.Base(absolute)
	if name == "." || name == string(filepath.Separator) || name == "" {
		return appMCPAuthorityBindingLocation{}, errors.New("application locator path is invalid")
	}
	requestedParent := filepath.Dir(absolute)
	parent, err := filepath.EvalSymlinks(requestedParent)
	if err != nil {
		return appMCPAuthorityBindingLocation{}, errors.New("application locator parent is unavailable")
	}
	parent, err = filepath.Abs(filepath.Clean(parent))
	if err != nil {
		return appMCPAuthorityBindingLocation{}, errors.New("application locator parent is invalid")
	}
	canonical := filepath.Join(parent, name)
	pathWasAlias := dir != absolute || filepath.Clean(dir) != dir || requestedParent != parent
	info, err := os.Lstat(absolute)
	if err == nil {
		pathWasAlias = pathWasAlias || info.Mode()&os.ModeSymlink != 0
		if !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			return appMCPAuthorityBindingLocation{}, errors.New("application locator owner is not a directory")
		}
	} else if !os.IsNotExist(err) {
		return appMCPAuthorityBindingLocation{}, errors.New("application locator identity cannot be inspected")
	}
	return appMCPAuthorityBindingLocation{appPath: canonical, parentPath: parent, pathWasAlias: pathWasAlias}, nil
}

func validateAppMCPAuthorityBindingParent(parent *os.Root, parentPath string, expectedInfo os.FileInfo, requireProtected bool) error {
	if parent == nil || expectedInfo == nil {
		return errors.New("application locator parent is unavailable")
	}
	pathInfo, err := os.Lstat(parentPath)
	if err != nil || !pathInfo.IsDir() || pathInfo.Mode()&os.ModeSymlink != 0 || (requireProtected && (pathInfo.Mode().Perm()&0022 != 0 || !fileOwnedByProcess(pathInfo))) {
		return errors.New("application locator parent changed")
	}
	opened, err := parent.Open(".")
	if err != nil {
		return errors.New("application locator parent cannot be reopened")
	}
	openedInfo, statErr := opened.Stat()
	closeErr := opened.Close()
	if statErr != nil || closeErr != nil || !os.SameFile(expectedInfo, openedInfo) || !os.SameFile(pathInfo, openedInfo) || !openedInfo.IsDir() || (requireProtected && (openedInfo.Mode().Perm()&0022 != 0 || !fileOwnedByProcess(openedInfo))) {
		return errors.Join(errors.New("application locator parent identity changed"), statErr, closeErr)
	}
	return nil
}

func validateAppMCPAuthorityBindingLocation(dir string, expected appMCPAuthorityBindingLocation) error {
	current, err := appMCPAuthorityBindingLocationFor(dir)
	if err != nil || current.pathWasAlias || current.appPath != expected.appPath || current.parentPath != expected.parentPath {
		return errors.New("application locator path changed while checking absence")
	}
	return nil
}

func openAppMCPAuthorityBindingRoot(parentPath string, create bool) (*appMCPAuthorityBindingRoot, bool, error) {
	if !filepath.IsAbs(parentPath) || filepath.Clean(parentPath) != parentPath {
		return nil, false, errors.New("application locator parent is not canonical")
	}
	parentInfo, err := os.Lstat(parentPath)
	if err != nil || !parentInfo.IsDir() || parentInfo.Mode()&os.ModeSymlink != 0 {
		return nil, false, errors.New("application locator parent is unavailable")
	}
	parent, err := os.OpenRoot(parentPath)
	if err != nil {
		return nil, false, errors.New("application locator parent cannot be opened")
	}
	parentFile, err := parent.Open(".")
	if err != nil {
		return nil, false, errors.Join(errors.New("application locator parent identity is unavailable"), parent.Close())
	}
	openedParentInfo, statErr := parentFile.Stat()
	closeErr := parentFile.Close()
	if statErr != nil || closeErr != nil || !os.SameFile(parentInfo, openedParentInfo) {
		return nil, false, errors.Join(errors.New("application locator parent changed"), statErr, closeErr, parent.Close())
	}

	parentInfo = openedParentInfo
	directoryInfo, err := parent.Lstat(appMCPAuthorityBindingDirectory)
	if os.IsNotExist(err) && !create {
		if identityErr := validateAppMCPAuthorityBindingParent(parent, parentPath, parentInfo, false); identityErr != nil {
			return nil, false, errors.Join(identityErr, parent.Close())
		}
		if _, checkErr := parent.Lstat(appMCPAuthorityBindingDirectory); !os.IsNotExist(checkErr) {
			return nil, false, errors.Join(errors.New("application locator directory changed while checking absence"), checkErr, parent.Close())
		}
		if closeErr := parent.Close(); closeErr != nil {
			return nil, false, closeErr
		}
		return nil, false, nil
	}
	if parentInfo.Mode().Perm()&0022 != 0 || !fileOwnedByProcess(parentInfo) {
		return nil, false, errors.Join(errors.New("application locator parent is not protected"), parent.Close())
	}
	if os.IsNotExist(err) && create {
		mkdirErr := parent.Mkdir(appMCPAuthorityBindingDirectory, 0700)
		if mkdirErr != nil && !os.IsExist(mkdirErr) {
			return nil, false, errors.Join(errors.New("application locator directory cannot be created"), mkdirErr, parent.Close())
		}
		directoryInfo, err = parent.Lstat(appMCPAuthorityBindingDirectory)
	}
	if err != nil || !directoryInfo.IsDir() || directoryInfo.Mode()&os.ModeSymlink != 0 || directoryInfo.Mode().Perm() != 0700 || !fileOwnedByProcess(directoryInfo) {
		return nil, false, errors.Join(errors.New("application locator directory is invalid"), err, parent.Close())
	}
	binding, err := parent.OpenRoot(appMCPAuthorityBindingDirectory)
	if err != nil {
		return nil, false, errors.Join(errors.New("application locator directory cannot be opened"), err, parent.Close())
	}
	bindingFile, err := binding.Open(".")
	if err != nil {
		return nil, false, errors.Join(errors.New("application locator directory identity is unavailable"), err, binding.Close(), parent.Close())
	}
	openedDirectoryInfo, statErr := bindingFile.Stat()
	closeErr = bindingFile.Close()
	pathInfo, pathErr := parent.Lstat(appMCPAuthorityBindingDirectory)
	if statErr != nil || closeErr != nil || pathErr != nil || !os.SameFile(directoryInfo, openedDirectoryInfo) || !os.SameFile(pathInfo, openedDirectoryInfo) || openedDirectoryInfo.Mode().Perm() != 0700 || !fileOwnedByProcess(openedDirectoryInfo) {
		return nil, false, errors.Join(errors.New("application locator directory changed"), statErr, closeErr, pathErr, binding.Close(), parent.Close())
	}
	return &appMCPAuthorityBindingRoot{
		parent: parent, binding: binding, parentPath: parentPath,
		parentInfo: parentInfo, directoryID: rotationFileIdentity(openedDirectoryInfo),
	}, true, nil
}

func validateAppMCPAuthorityBindingDirectory(root *appMCPAuthorityBindingRoot) error {
	if root == nil || root.parent == nil || root.binding == nil {
		return errors.New("application locator directory is unavailable")
	}
	if err := validateAppMCPAuthorityBindingParent(root.parent, root.parentPath, root.parentInfo, true); err != nil {
		return err
	}
	parentPathInfo, err := root.parent.Lstat(appMCPAuthorityBindingDirectory)
	if err != nil || !parentPathInfo.IsDir() || parentPathInfo.Mode().Perm() != 0700 || !fileOwnedByProcess(parentPathInfo) || rotationFileIdentity(parentPathInfo) != root.directoryID {
		return errors.New("application locator directory changed")
	}
	opened, err := root.binding.Open(".")
	if err != nil {
		return errors.New("application locator directory cannot be reopened")
	}
	openedInfo, statErr := opened.Stat()
	closeErr := opened.Close()
	if statErr != nil || closeErr != nil || rotationFileIdentity(openedInfo) != root.directoryID || !os.SameFile(parentPathInfo, openedInfo) || openedInfo.Mode().Perm() != 0700 || !fileOwnedByProcess(openedInfo) {
		return errors.New("application locator directory identity changed")
	}
	return nil
}

func readAppMCPAuthorityBinding(dir string) (result *appMCPAuthorityBinding, retErr error) {
	location, err := appMCPAuthorityBindingLocationFor(dir)
	if err != nil {
		return nil, err
	}
	if location.pathWasAlias {
		return nil, errors.New("application authority locator requires its original canonical app path")
	}
	root, exists, err := openAppMCPAuthorityBindingRoot(location.parentPath, false)
	if err != nil {
		return nil, err
	}
	if !exists {
		if err := validateAppMCPAuthorityBindingLocation(dir, location); err != nil {
			return nil, err
		}
		return nil, nil
	}
	defer func() {
		if closeErr := root.close(); closeErr != nil {
			result = nil
			retErr = errors.Join(retErr, closeErr)
		}
	}()
	name := hashBytesSHA256([]byte(location.appPath)) + ".json"
	info, err := root.binding.Lstat(name)
	if os.IsNotExist(err) {
		if err := validateAppMCPAuthorityBindingDirectory(root); err != nil {
			return nil, err
		}
		if _, checkErr := root.binding.Lstat(name); !os.IsNotExist(checkErr) {
			return nil, errors.Join(errors.New("application authority locator changed while checking absence"), checkErr)
		}
		if err := validateAppMCPAuthorityBindingDirectory(root); err != nil {
			return nil, err
		}
		if err := validateAppMCPAuthorityBindingLocation(dir, location); err != nil {
			return nil, err
		}
		return nil, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0600 || !fileOwnedByProcess(info) || info.Size() > appMCPAuthorityBindingLimit {
		return nil, errors.New("application authority locator is invalid")
	}
	f, err := root.binding.Open(name)
	if err != nil {
		return nil, errors.New("application authority locator cannot be opened")
	}
	openedInfo, statErr := f.Stat()
	data, readErr := io.ReadAll(io.LimitReader(f, appMCPAuthorityBindingLimit+1))
	closeErr := f.Close()
	pathInfo, pathErr := root.binding.Lstat(name)
	if statErr != nil || readErr != nil || closeErr != nil || pathErr != nil || !os.SameFile(info, openedInfo) || !os.SameFile(openedInfo, pathInfo) || !openedInfo.Mode().IsRegular() || openedInfo.Mode().Perm() != 0600 || !fileOwnedByProcess(openedInfo) || int64(len(data)) > appMCPAuthorityBindingLimit {
		return nil, errors.New("application authority locator changed while reading")
	}
	binding, err := decodeAppMCPAuthorityBinding(data)
	if err != nil || binding.AppPath != location.appPath || binding.OwnerHash != name[:len(name)-len(".json")] || !validRotationHex(binding.OwnerHash) {
		return nil, errors.New("application authority locator is invalid")
	}
	if err := validateAppMCPAuthorityBindingAuthority(binding); err != nil {
		return nil, err
	}
	if err := validateAppMCPAuthorityBindingDirectory(root); err != nil {
		return nil, err
	}
	return binding, nil
}

func decodeAppMCPAuthorityBinding(data []byte) (*appMCPAuthorityBinding, error) {
	if len(data) == 0 || len(data) > appMCPAuthorityBindingLimit {
		return nil, errors.New("application authority locator size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("application authority locator is invalid")
	}
	binding := &appMCPAuthorityBinding{}
	seen := make(map[string]bool, 5)
	for decoder.More() {
		keyToken, err := decoder.Token()
		key, ok := keyToken.(string)
		if err != nil || !ok || seen[key] {
			return nil, errors.New("application authority locator has duplicate or invalid fields")
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, errors.New("application authority locator is invalid")
		}
		switch key {
		case "version":
			err = json.Unmarshal(value, &binding.Version)
		case "app_path":
			err = json.Unmarshal(value, &binding.AppPath)
		case "owner_hash":
			err = json.Unmarshal(value, &binding.OwnerHash)
		case "authority_path":
			err = json.Unmarshal(value, &binding.AuthorityPath)
		case "authority_identity":
			err = json.Unmarshal(value, &binding.AuthorityIdentity)
		default:
			return nil, errors.New("application authority locator has unknown fields")
		}
		if err != nil {
			return nil, errors.New("application authority locator has invalid field values")
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return nil, errors.New("application authority locator is truncated")
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("application authority locator has trailing data")
	}
	if len(seen) != 5 || !seen["version"] || !seen["app_path"] || !seen["owner_hash"] || !seen["authority_path"] || !seen["authority_identity"] || binding.Version != 1 || !filepath.IsAbs(binding.AppPath) || filepath.Clean(binding.AppPath) != binding.AppPath || !validRotationHex(binding.OwnerHash) || !filepath.IsAbs(binding.AuthorityPath) || filepath.Clean(binding.AuthorityPath) != binding.AuthorityPath || binding.AuthorityIdentity == "" {
		return nil, errors.New("application authority locator is incomplete")
	}
	canonical, err := json.Marshal(binding)
	if err != nil || !bytes.Equal(data, canonical) {
		return nil, errors.New("application authority locator is not canonical")
	}
	return binding, nil
}

func validateAppMCPAuthorityBindingAuthority(binding *appMCPAuthorityBinding) error {
	if binding == nil || !filepath.IsAbs(binding.AuthorityPath) || filepath.Clean(binding.AuthorityPath) != binding.AuthorityPath || binding.AuthorityIdentity == "" {
		return errors.New("application authority root binding is invalid")
	}
	resolved, err := filepath.EvalSymlinks(binding.AuthorityPath)
	if err != nil {
		return errors.New("application authority root is unavailable")
	}
	resolved, err = filepath.Abs(filepath.Clean(resolved))
	if err != nil || resolved != binding.AuthorityPath {
		return errors.New("application authority root is not canonical")
	}
	info, err := os.Lstat(binding.AuthorityPath)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm() != 0700 || !fileOwnedByProcess(info) || rotationFileIdentity(info) != binding.AuthorityIdentity {
		return errors.New("application authority root changed")
	}
	root, err := os.OpenRoot(binding.AuthorityPath)
	if err != nil {
		return errors.New("application authority root cannot be opened")
	}
	opened, openErr := root.Open(".")
	if openErr != nil {
		return errors.Join(errors.New("application authority root identity is unavailable"), root.Close())
	}
	openedInfo, statErr := opened.Stat()
	closeErr := errors.Join(opened.Close(), root.Close())
	if statErr != nil || closeErr != nil || !openedInfo.IsDir() || openedInfo.Mode().Perm() != 0700 || !fileOwnedByProcess(openedInfo) || rotationFileIdentity(openedInfo) != binding.AuthorityIdentity || !os.SameFile(info, openedInfo) {
		return errors.Join(errors.New("application authority root identity changed"), statErr, closeErr)
	}
	return nil
}

func validateAppMCPAuthorityBindingRoot(binding *appMCPAuthorityBinding, dir string, root *os.Root) error {
	if binding == nil || root == nil {
		return errors.New("application authority locator is unavailable")
	}
	location, err := appMCPAuthorityBindingLocationFor(dir)
	if err != nil || location.pathWasAlias || location.appPath != binding.AppPath || hashBytesSHA256([]byte(location.appPath)) != binding.OwnerHash {
		return errors.New("application authority locator owner changed")
	}
	if err := validateAppMCPAuthorityBindingAuthority(binding); err != nil {
		return err
	}
	configured, err := canonicalConfiguredAppMCPAuthorityPath()
	if err != nil || configured != binding.AuthorityPath {
		return errors.New("configured application authority root changed")
	}
	opened, err := root.Open(".")
	if err != nil {
		return errors.New("opened application authority root is unavailable")
	}
	openedInfo, statErr := opened.Stat()
	closeErr := opened.Close()
	if statErr != nil || closeErr != nil || !openedInfo.IsDir() || openedInfo.Mode().Perm() != 0700 || !fileOwnedByProcess(openedInfo) || rotationFileIdentity(openedInfo) != binding.AuthorityIdentity {
		return errors.New("opened application authority root changed")
	}
	return nil
}

func canonicalConfiguredAppMCPAuthorityPath() (string, error) {
	configured := os.Getenv("BENMORE_MCP_AUTHORITY_DIR")
	if configured == "" || !filepath.IsAbs(configured) || filepath.Clean(configured) != configured {
		return "", errors.New("configured application authority root is unavailable")
	}
	resolved := realPathForContainment(configured)
	resolved, err := filepath.Abs(filepath.Clean(resolved))
	if err != nil || resolved != configured {
		return "", errors.New("configured application authority root is not canonical")
	}
	return resolved, nil
}

func pinAppMCPAuthorityBindingWithLease(ctx context.Context, lease *appMCPAuthorityLease) (result *appMCPAuthorityBinding, retErr error) {
	if ctx == nil {
		return nil, errors.New("application authority locator context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if lease == nil || lease.owner != nil || !lease.ownsResources || lease.ownerIdentity != lease {
		return nil, errors.New("application authority locator requires an owning lease")
	}
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if err := validateAppMCPAuthorityLeaseLocked(lease, lease); err != nil {
		return nil, err
	}
	location, err := appMCPAuthorityBindingLocationFor(lease.path)
	if err != nil || location.pathWasAlias || location.appPath != lease.path {
		return nil, errors.New("application authority locator requires a canonical app path")
	}
	appInfo, err := os.Lstat(location.appPath)
	if err != nil || !appInfo.IsDir() || appInfo.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("application authority locator requires an existing app directory")
	}
	appRoot, err := os.OpenRoot(location.appPath)
	if err != nil {
		return nil, errors.New("application authority app directory cannot be opened")
	}
	appDirectory, openErr := appRoot.Open(".")
	if openErr != nil {
		return nil, errors.Join(errors.New("application authority app identity is unavailable"), appRoot.Close())
	}
	openedAppInfo, statErr := appDirectory.Stat()
	closeErr := errors.Join(appDirectory.Close(), appRoot.Close())
	currentAppInfo, pathErr := os.Lstat(location.appPath)
	if statErr != nil || closeErr != nil || pathErr != nil || !os.SameFile(appInfo, openedAppInfo) || !os.SameFile(currentAppInfo, openedAppInfo) || !openedAppInfo.IsDir() {
		return nil, errors.Join(errors.New("application authority app directory changed"), statErr, closeErr, pathErr)
	}
	if lease.requestedPath != "" {
		requested, absErr := filepath.Abs(filepath.Clean(lease.requestedPath))
		if absErr != nil || filepath.Clean(requested) != location.appPath {
			return nil, errors.New("application authority locator requires its canonical lease path")
		}
	}
	if err := validateAuthorityLockPath(lease.root, lease.file); err != nil {
		return nil, err
	}
	authorityPath, err := canonicalConfiguredAppMCPAuthorityPath()
	if err != nil || authorityPath != lease.authorityPath {
		return nil, errors.New("configured application authority root changed")
	}
	openedAuthority, err := lease.root.Open(".")
	if err != nil {
		return nil, errors.New("opened application authority root is unavailable")
	}
	authorityInfo, statErr := openedAuthority.Stat()
	closeErr = openedAuthority.Close()
	if statErr != nil || closeErr != nil || rotationFileIdentity(authorityInfo) != lease.authorityID || !authorityInfo.IsDir() || authorityInfo.Mode().Perm() != 0700 || !fileOwnedByProcess(authorityInfo) {
		return nil, errors.New("opened application authority root changed")
	}
	binding := &appMCPAuthorityBinding{
		Version: 1, AppPath: location.appPath, OwnerHash: hashBytesSHA256([]byte(location.appPath)),
		AuthorityPath: authorityPath, AuthorityIdentity: lease.authorityID,
	}
	data, err := json.Marshal(binding)
	if err != nil || len(data) > appMCPAuthorityBindingLimit {
		return nil, errors.New("application authority locator cannot be encoded")
	}

	if current, err := readAppMCPAuthorityBinding(lease.path); err != nil {
		return nil, err
	} else if current != nil {
		if !bytes.Equal(mustMarshalAppMCPAuthorityBinding(current), data) {
			return nil, errAppMCPAuthorityBindingConflict
		}
		root, exists, err := openAppMCPAuthorityBindingRoot(location.parentPath, false)
		if err != nil || !exists {
			return nil, errors.Join(errAppMCPAuthorityBindingUnknown, err)
		}
		if err := validateAppMCPAuthorityBindingDirectory(root); err != nil {
			return nil, errors.Join(errAppMCPAuthorityBindingUnknown, errors.Join(err, root.close()))
		}
		locatorName := hashBytesSHA256([]byte(location.appPath)) + ".json"
		syncErr := syncAppMCPAuthorityBindingParent(root, locatorName)
		if syncErr == nil {
			syncErr = syncAppMCPAuthorityBindingDirectory(root.binding)
		}
		readback, readErr := readAppMCPAuthorityBinding(lease.path)
		closeErr := root.close()
		if injected := appMCPAuthorityRecordStoreError("readback", hashBytesSHA256([]byte(location.appPath))+".json", "binding"); injected != nil {
			readErr = errors.Join(readErr, injected)
		}
		if syncErr != nil || readErr != nil || closeErr != nil || readback == nil || !bytes.Equal(mustMarshalAppMCPAuthorityBinding(readback), data) {
			return nil, errors.Join(errAppMCPAuthorityBindingUnknown, errors.Join(syncErr, readErr, closeErr))
		}
		return readback, nil
	}

	root, exists, err := openAppMCPAuthorityBindingRoot(location.parentPath, true)
	if err != nil || !exists {
		return nil, err
	}
	var stagedName string
	published := false
	defer func() {
		if stagedName != "" {
			if removeErr := root.binding.Remove(stagedName); removeErr != nil && !os.IsNotExist(removeErr) {
				retErr = errors.Join(retErr, removeErr)
				if published {
					retErr = errors.Join(errAppMCPAuthorityBindingUnknown, retErr)
				}
			}
		}
		if closeErr := root.close(); closeErr != nil {
			if published {
				retErr = errors.Join(errAppMCPAuthorityBindingUnknown, retErr, closeErr)
			} else {
				retErr = errors.Join(retErr, closeErr)
			}
		}
	}()
	if err := validateAppMCPAuthorityBindingDirectory(root); err != nil {
		return nil, err
	}
	locatorName := hashBytesSHA256([]byte(location.appPath)) + ".json"
	if err := syncAppMCPAuthorityBindingParent(root, locatorName); err != nil {
		return nil, err
	}
	if _, err := root.binding.Lstat(locatorName); err == nil {
		return nil, errors.New("application authority locator appeared during publication")
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, err
	}
	stagedName = ".binding-stage-" + hex.EncodeToString(nonce[:])
	f, err := root.binding.OpenFile(stagedName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		stagedName = ""
		return nil, err
	}
	stagedInfo, statErr := f.Stat()
	if statErr != nil || !stagedInfo.Mode().IsRegular() || stagedInfo.Mode().Perm() != 0600 || !fileOwnedByProcess(stagedInfo) {
		closeErr := f.Close()
		return nil, errors.Join(errors.New("staged application authority locator is invalid"), statErr, closeErr)
	}
	if injected := appMCPAuthorityRecordStoreError("before_write", hashBytesSHA256([]byte(location.appPath))+".json", "binding"); injected != nil {
		return nil, errors.Join(injected, f.Close())
	}
	remaining := data
	var writeErr error
	for len(remaining) > 0 {
		var n int
		n, writeErr = f.Write(remaining)
		if n > 0 {
			remaining = remaining[n:]
		}
		if writeErr != nil || n == 0 {
			if writeErr == nil {
				writeErr = io.ErrShortWrite
			}
			break
		}
	}
	if injected := appMCPAuthorityRecordStoreError("file_sync", hashBytesSHA256([]byte(location.appPath))+".json", "binding"); injected != nil {
		writeErr = errors.Join(writeErr, injected)
	} else {
		writeErr = errors.Join(writeErr, f.Sync())
	}
	if err := errors.Join(writeErr, f.Close()); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := validateAppMCPAuthorityBindingDirectory(root); err != nil {
		return nil, err
	}
	if err := validateAppMCPAuthorityLeaseLocked(lease, lease); err != nil {
		return nil, err
	}
	if injected := appMCPAuthorityRecordStoreError("before_rename", locatorName, "binding"); injected != nil {
		return nil, injected
	}
	if injected := appMCPAuthorityRecordStoreError("publish", locatorName, "binding"); injected != nil {
		return nil, injected
	}
	// A same-directory hard link publishes atomically without replacing a winner.
	if err := root.binding.Link(stagedName, locatorName); err != nil {
		if os.IsExist(err) {
			return nil, errAppMCPAuthorityBindingConflict
		}
		return nil, err
	}
	published = true
	if injected := appMCPAuthorityRecordStoreError("after_publish", locatorName, "binding"); injected != nil {
		return nil, errors.Join(errAppMCPAuthorityBindingUnknown, injected)
	}
	if err := root.binding.Remove(stagedName); err != nil {
		return nil, errors.Join(errAppMCPAuthorityBindingUnknown, err)
	}
	stagedName = ""
	if err := validateAppMCPAuthorityBindingDirectory(root); err != nil {
		return nil, errors.Join(errAppMCPAuthorityBindingUnknown, err)
	}
	if injected := appMCPAuthorityRecordStoreError("directory_sync", locatorName, "binding"); injected != nil {
		return nil, errors.Join(errAppMCPAuthorityBindingUnknown, injected)
	}
	if err := syncAppMCPAuthorityBindingDirectory(root.binding); err != nil {
		return nil, errors.Join(errAppMCPAuthorityBindingUnknown, err)
	}
	if injected := appMCPAuthorityRecordStoreError("readback", locatorName, "binding"); injected != nil {
		return nil, errors.Join(errAppMCPAuthorityBindingUnknown, injected)
	}
	readback, err := readAppMCPAuthorityBinding(lease.path)
	if err != nil || readback == nil || !bytes.Equal(mustMarshalAppMCPAuthorityBinding(readback), data) {
		return nil, errors.Join(errAppMCPAuthorityBindingUnknown, err)
	}
	if err := validateAppMCPAuthorityBindingRoot(readback, lease.path, lease.root); err != nil {
		return nil, errors.Join(errAppMCPAuthorityBindingUnknown, err)
	}
	return readback, nil
}

func mustMarshalAppMCPAuthorityBinding(binding *appMCPAuthorityBinding) []byte {
	data, _ := json.Marshal(binding)
	return data
}

func syncAppMCPAuthorityBindingDirectory(root *os.Root) error {
	if root == nil {
		return errors.New("application authority locator directory is unavailable")
	}
	directory, err := root.Open(".")
	if err != nil {
		return err
	}
	return errors.Join(directory.Sync(), directory.Close())
}

func syncAppMCPAuthorityBindingParent(root *appMCPAuthorityBindingRoot, locatorName string) error {
	if err := validateAppMCPAuthorityBindingDirectory(root); err != nil {
		return err
	}
	if injected := appMCPAuthorityRecordStoreError("parent_directory_sync", locatorName, "binding"); injected != nil {
		return injected
	}
	if err := syncAppMCPAuthorityBindingDirectory(root.parent); err != nil {
		return err
	}
	return validateAppMCPAuthorityBindingDirectory(root)
}
