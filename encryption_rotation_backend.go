//go:build !cli

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

func captureLocalRotationBackend(ctx context.Context, lease *appMCPAuthorityLease, oldSource, newSource string) (*appRotationBackendSnapshot, error) {
	if ctx == nil {
		return nil, errors.New("rotation context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if lease == nil || lease.root == nil || lease.file == nil || validateRotationAuthorityRoot(lease) != nil {
		return nil, errors.New("rotation authority lease is unavailable")
	}
	if isolateAppEnvironment.Load() {
		return nil, errAppRotationUnsupported
	}
	oldKey, oldErr := cryptoDeriveAppKey(oldSource)
	newKey, newErr := cryptoDeriveAppKey(newSource)
	if oldErr != nil || newErr != nil || len(oldKey) != 32 || len(newKey) != 32 || bytes.Equal(oldKey, newKey) {
		return nil, errors.New("invalid rotation key material")
	}
	dir := lease.path
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return nil, errAppRotationUnsupported
	}
	realDir, err := filepath.EvalSymlinks(absDir)
	if err != nil || filepath.Clean(realDir) != filepath.Clean(absDir) {
		return nil, errAppRotationUnsupported
	}
	dir = absDir
	appRoot, err := os.OpenRoot(dir)
	if err != nil {
		return nil, errAppRotationUnsupported
	}
	defer appRoot.Close()
	appDirectoryID, err := rotationCanonicalDirectoryIdentity(dir, appRoot)
	if err != nil {
		return nil, errAppRotationUnsupported
	}
	yamlBytes, yamlMode, yamlExists, err := readOwnedRotationFile(appRoot, "env.yaml")
	if err != nil || !yamlExists {
		return nil, errAppRotationUnsupported
	}
	vars := map[string]string{}
	if err := decodeConfigYAML(yamlBytes, &vars); err != nil {
		return nil, errAppRotationUnsupported
	}
	if vars == nil {
		vars = map[string]string{}
	}
	for k, v := range vars {
		if !validAppEnvKey(k) || !validAppEnvValue(v) {
			return nil, errAppRotationUnsupported
		}
	}
	if vars["ENCRYPTION_KEY"] != oldSource {
		return nil, errAppRotationUnsupported
	}
	generated, generatedMode, generatedExists, err := readRotationGeneratedFile(appRoot)
	if err != nil {
		return nil, errAppRotationUnsupported
	}
	generatedVars := map[string]string{}
	if generatedExists {
		generatedVars, err = parseAppEnvironmentFile(string(generated))
		if err != nil {
			return nil, errAppRotationUnsupported
		}
		if _, has := generatedVars["ENCRYPTION_KEY"]; has {
			return nil, errAppRotationUnsupported
		}
	} else if _, present := os.LookupEnv("ENCRYPTION_KEY"); present {
		return nil, errAppRotationUnsupported
	}
	effective, err := readAppEnv(dir)
	if err != nil || effective["ENCRYPTION_KEY"] != oldSource {
		return nil, errAppRotationUnsupported
	}
	vars["ENCRYPTION_KEY"] = newSource
	for k, v := range vars {
		if !validAppEnvKey(k) || !validAppEnvValue(v) {
			return nil, errors.New("invalid rotation environment value")
		}
	}
	desired, err := yaml.Marshal(vars)
	if err != nil || len(desired) > appRotationJournalLimit {
		return nil, errors.New("cannot encode rotation environment")
	}
	s := &appRotationBackendSnapshot{Kind: appRotationLocalYAML, OwnerHash: lease.key, AppPath: dir, AppDirectoryID: appDirectoryID, OldSource: oldSource, NewSource: newSource, EffectiveSource: "env.yaml", OriginalExists: true, OriginalMode: uint32(yamlMode.Mode().Perm()), OriginalFileID: rotationFileIdentity(yamlMode), OriginalHash: hashBytesSHA256(yamlBytes), OriginalBytes: yamlBytes, DesiredBytes: desired, GuardExists: generatedExists, GuardBytes: generated}
	if generatedExists {
		s.GuardMode = uint32(generatedMode.Mode().Perm())
		s.GuardFileID = rotationFileIdentity(generatedMode)
	}
	if generatedExists {
		s.GuardHash = hashBytesSHA256(generated)
	}
	if err := validateLocalRotationPrecedence(dir, s, oldSource); err != nil {
		return nil, errAppRotationUnsupported
	}
	return s, nil
}

func persistLocalRotationBackend(ctx context.Context, lease *appMCPAuthorityLease, journal *appRotationJournal) error {
	if err := validateRotationJournalBinding(lease, journal, appRotationLocalYAML); err != nil {
		return err
	}
	if ctx == nil {
		return errors.New("rotation context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s := journal.record.Backend
	if err := validateRotationAuthorityRoot(lease); err != nil {
		return errors.New("rotation authority root changed")
	}
	root, err := os.OpenRoot(s.AppPath)
	if err != nil {
		return errAppRotationConflict
	}
	defer root.Close()
	appDirectoryID, err := rotationCanonicalDirectoryIdentity(s.AppPath, root)
	if err != nil || appDirectoryID != s.AppDirectoryID {
		return errAppRotationConflict
	}
	current, mode, exists, err := readOwnedRotationFile(root, "env.yaml")
	if err != nil {
		return errAppRotationConflict
	}
	if !exists || uint32(mode.Mode().Perm()) != s.OriginalMode {
		return errAppRotationConflict
	}
	generated, generatedMode, generatedExists, err := readRotationGeneratedFile(root)
	if err != nil || generatedExists != s.GuardExists || generatedExists && (uint32(generatedMode.Mode().Perm()) != s.GuardMode || rotationFileIdentity(generatedMode) != s.GuardFileID || !bytes.Equal(generated, s.GuardBytes)) {
		return errAppRotationConflict
	}
	if bytes.Equal(current, s.DesiredBytes) {
		return verifyLocalRotationBackend(ctx, lease, journal)
	}
	if rotationFileIdentity(mode) != s.OriginalFileID {
		return errAppRotationConflict
	}
	if err := validateLocalRotationPrecedence(s.AppPath, &s, s.OldSource); err != nil {
		return errAppRotationConflict
	}
	effective, err := readAppEnv(s.AppPath)
	if err != nil || effective["ENCRYPTION_KEY"] != s.OldSource {
		return errAppRotationConflict
	}
	if hashBytesSHA256(current) != s.OriginalHash || !bytes.Equal(current, s.OriginalBytes) {
		return errAppRotationConflict
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateRotationAuthorityRoot(lease); err != nil {
		return errAppRotationConflict
	}
	tmp, err := stageRotationFile(root, ".env-rotation-", s.DesiredBytes)
	if err != nil {
		return errors.New("cannot persist environment update")
	}
	if err := ctx.Err(); err != nil {
		_ = root.Remove(tmp)
		return err
	}
	if err := validateRotationAuthorityRoot(lease); err != nil {
		_ = root.Remove(tmp)
		return errAppRotationConflict
	}
	current, currentInfo, exists, err := readOwnedRotationFile(root, "env.yaml")
	generated, generatedInfo, generatedExists, generatedErr := readRotationGeneratedFile(root)
	if err != nil || !exists || uint32(currentInfo.Mode().Perm()) != s.OriginalMode || rotationFileIdentity(currentInfo) != s.OriginalFileID || hashBytesSHA256(current) != s.OriginalHash || !bytes.Equal(current, s.OriginalBytes) || generatedErr != nil || generatedExists != s.GuardExists || generatedExists && (uint32(generatedInfo.Mode().Perm()) != s.GuardMode || rotationFileIdentity(generatedInfo) != s.GuardFileID || !bytes.Equal(generated, s.GuardBytes)) || validateLocalRotationPrecedence(s.AppPath, &s, s.OldSource) != nil {
		_ = root.Remove(tmp)
		return errAppRotationConflict
	}
	if err := publishRotationFile(root, tmp, "env.yaml"); err != nil {
		_ = root.Remove(tmp)
		return errAppRotationOutcomeUnknown
	}
	if err := syncRotationDirectory(root); err != nil {
		return errAppRotationOutcomeUnknown
	}
	if err := verifyLocalRotationBackend(ctx, lease, journal); err != nil {
		return errAppRotationOutcomeUnknown
	}
	return nil
}

func verifyLocalRotationBackend(ctx context.Context, lease *appMCPAuthorityLease, journal *appRotationJournal) error {
	if err := validateRotationJournalBinding(lease, journal, appRotationLocalYAML); err != nil {
		return err
	}
	if ctx == nil {
		return errors.New("rotation context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s := journal.record.Backend
	if err := validateRotationAuthorityRoot(lease); err != nil {
		return errors.New("rotation authority root changed")
	}
	root, err := os.OpenRoot(s.AppPath)
	if err != nil {
		return errAppRotationOutcomeUnknown
	}
	defer root.Close()
	appDirectoryID, err := rotationCanonicalDirectoryIdentity(s.AppPath, root)
	if err != nil || appDirectoryID != s.AppDirectoryID {
		return errAppRotationConflict
	}
	data, mode, exists, err := readOwnedRotationFile(root, "env.yaml")
	if err != nil || !exists || mode.Mode().Perm() != 0600 || !bytes.Equal(data, s.DesiredBytes) {
		return errAppRotationConflict
	}
	guard, guardMode, guardExists, err := readRotationGeneratedFile(root)
	if err != nil || guardExists != s.GuardExists || guardExists && (uint32(guardMode.Mode().Perm()) != s.GuardMode || rotationFileIdentity(guardMode) != s.GuardFileID || !bytes.Equal(guard, s.GuardBytes)) {
		return errAppRotationConflict
	}
	if err := validateLocalRotationPrecedence(s.AppPath, &s, s.NewSource); err != nil {
		return errAppRotationConflict
	}
	if err := syncRotationDirectory(root); err != nil {
		return errAppRotationOutcomeUnknown
	}
	effective, err := readAppEnv(s.AppPath)
	if err != nil || effective["ENCRYPTION_KEY"] != s.NewSource {
		return errAppRotationOutcomeUnknown
	}
	return nil
}

func validateRotationJournalBinding(lease *appMCPAuthorityLease, journal *appRotationJournal, kind appRotationBackendKind) error {
	if lease == nil || journal == nil || journal.key != lease.key || journal.root != lease.root || journal.record.Backend.OwnerHash != lease.key || journal.record.Backend.Kind != kind {
		return errors.New("rotation journal does not match owner lease")
	}
	if err := validateRotationAuthorityRoot(lease); err != nil {
		return errors.New("rotation authority root changed")
	}
	encoded, err := json.Marshal(journal.record)
	if err != nil || hashBytesSHA256(encoded) != journal.digest {
		return errors.New("in-memory rotation journal changed")
	}
	leasePath, leaseErr := filepath.Abs(lease.path)
	backendPath, backendErr := filepath.Abs(journal.record.Backend.AppPath)
	if leaseErr != nil || backendErr != nil || filepath.Clean(leasePath) != filepath.Clean(backendPath) {
		return errors.New("rotation journal does not match owner lease")
	}
	current, err := readRotationJournal(lease)
	if err != nil || current.digest != journal.digest || !bytes.Equal(mustRotationJSON(current), encoded) {
		return errors.New("protected rotation journal changed")
	}
	return nil
}

func readOwnedRotationFile(root *os.Root, name string) ([]byte, os.FileInfo, bool, error) {
	info, err := root.Lstat(name)
	if os.IsNotExist(err) {
		return nil, nil, false, nil
	}
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || rotationFileIdentity(info) == "" || !fileOwnedByProcess(info) {
		return nil, nil, false, errors.New("unsafe environment file")
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, nil, false, err
	}
	opened, statErr := f.Stat()
	data, readErr := io.ReadAll(io.LimitReader(f, appRotationJournalLimit+1))
	closeErr := f.Close()
	if statErr != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0600 || !fileOwnedByProcess(opened) || rotationFileIdentity(info) != rotationFileIdentity(opened) || readErr != nil || closeErr != nil || len(data) > appRotationJournalLimit {
		return nil, nil, false, errors.New("cannot read environment file")
	}
	return data, info, true, nil
}

func readRotationGeneratedFile(appRoot *os.Root) ([]byte, os.FileInfo, bool, error) {
	info, err := appRoot.Lstat(".benmore")
	if os.IsNotExist(err) {
		return nil, nil, false, nil
	}
	if err != nil || !info.IsDir() || info.Mode().Perm() != 0700 || !fileOwnedByProcess(info) {
		return nil, nil, false, errors.New("unsafe generated environment directory")
	}
	root, err := appRoot.OpenRoot(".benmore")
	if err != nil {
		return nil, nil, false, err
	}
	defer root.Close()
	return readOwnedRotationFile(root, "env")
}

func rotationOpenedDirectoryIdentity(root *os.Root) (string, error) {
	if root == nil {
		return "", errors.New("application directory is unavailable")
	}
	f, err := root.Open(".")
	if err != nil {
		return "", err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil || !info.IsDir() || !fileOwnedByProcess(info) {
		return "", errors.New("application directory changed")
	}
	identity := rotationFileIdentity(info)
	if identity == "" {
		return "", errors.New("application directory identity is unavailable")
	}
	return identity, nil
}

func rotationCanonicalDirectoryIdentity(path string, root *os.Root) (string, error) {
	abs, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	real, err := filepath.EvalSymlinks(abs)
	if err != nil || filepath.Clean(real) != filepath.Clean(abs) {
		return "", errors.New("application directory alias is unsupported")
	}
	return rotationOpenedDirectoryIdentity(root)
}

func syncRotationDirectory(root *os.Root) error {
	if root == nil {
		return errors.New("rotation directory is unavailable")
	}
	dir, err := root.Open(".")
	if err != nil {
		return err
	}
	syncErr := dir.Sync()
	closeErr := dir.Close()
	if syncErr != nil {
		return syncErr
	}
	return closeErr
}

func validateLocalRotationPrecedence(dir string, s *appRotationBackendSnapshot, expected string) error {
	if s == nil || isolateAppEnvironment.Load() {
		return errAppRotationUnsupported
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return err
	}
	defer root.Close()
	generated, info, exists, err := readRotationGeneratedFile(root)
	if err != nil || exists != s.GuardExists || exists && (uint32(info.Mode().Perm()) != s.GuardMode || rotationFileIdentity(info) != s.GuardFileID || !bytes.Equal(generated, s.GuardBytes)) {
		return errAppRotationUnsupported
	}
	if exists {
		vars, err := parseAppEnvironmentFile(string(generated))
		if err != nil {
			return err
		}
		if _, has := vars["ENCRYPTION_KEY"]; has {
			return errAppRotationUnsupported
		}
	} else if _, present := os.LookupEnv("ENCRYPTION_KEY"); present {
		return errAppRotationUnsupported
	}
	actual, err := readAppEnv(dir)
	if err != nil || actual["ENCRYPTION_KEY"] != expected {
		return errAppRotationUnsupported
	}
	return nil
}
