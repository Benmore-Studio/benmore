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
	"reflect"
	"strings"
)

const appRotationJournalLimit = 4 << 20

var (
	errAppRotationOutcomeUnknown = errors.New("rotation persistence outcome is unknown; protected recovery data was retained")
	errAppRotationConflict       = errors.New("rotation persistence state changed")
	errAppRotationUnsupported    = errors.New("effective encryption key source is not supported by this backend")
)

type appRotationBackendKind uint8

const (
	appRotationLocalYAML appRotationBackendKind = iota + 1
	appRotationPlatformVault
)

type appRotationTransitionIdentity struct {
	OldGeneration   string `json:"old_generation"`
	NewGeneration   string `json:"new_generation"`
	RotationID      string `json:"rotation_id"`
	OldMarkerDigest string `json:"old_marker_digest"`
	WriteEpoch      string `json:"write_epoch"`
	MarkerVersion   int    `json:"marker_version"`
}

// This closed snapshot stores secrets only in the private owner-only journal.
type appRotationBackendSnapshot struct {
	Kind                 appRotationBackendKind `json:"kind"`
	OwnerHash            string                 `json:"owner_hash"`
	AppPath              string                 `json:"app_path"`
	AppDirectoryID       string                 `json:"app_directory_id"`
	OldSource            string                 `json:"old_source"`
	NewSource            string                 `json:"new_source"`
	EffectiveSource      string                 `json:"effective_source"`
	OriginalExists       bool                   `json:"original_exists"`
	OriginalMode         uint32                 `json:"original_mode"`
	OriginalFileID       string                 `json:"original_file_id,omitempty"`
	OriginalHash         string                 `json:"original_hash"`
	OriginalBytes        []byte                 `json:"original_bytes,omitempty"`
	DesiredBytes         []byte                 `json:"desired_bytes,omitempty"`
	GuardExists          bool                   `json:"guard_exists"`
	GuardMode            uint32                 `json:"guard_mode"`
	GuardFileID          string                 `json:"guard_file_id,omitempty"`
	GuardHash            string                 `json:"guard_hash"`
	GuardBytes           []byte                 `json:"guard_bytes,omitempty"`
	PlatformMaster       string                 `json:"platform_master_fingerprint,omitempty"`
	PlatformMasterSource string                 `json:"platform_master_source,omitempty"`
	PlatformSchemaHash   string                 `json:"platform_schema_hash,omitempty"`
	PlatformAppID        int64                  `json:"platform_app_id,omitempty"`
	PlatformOwnerID      int64                  `json:"platform_owner_id,omitempty"`
	PlatformLogical      string                 `json:"platform_logical,omitempty"`
	PlatformInstance     string                 `json:"platform_instance,omitempty"`
	PlatformScope        string                 `json:"platform_scope,omitempty"`
	LegacyOverlay        bool                   `json:"legacy_overlay,omitempty"`
	VaultRows            []appRotationVaultRow  `json:"vault_rows,omitempty"`
	LegacyRow            *appRotationVaultRow   `json:"legacy_row,omitempty"`
	LegacyTable          bool                   `json:"legacy_table,omitempty"`
}

type appRotationVaultRow struct {
	Exists            bool   `json:"exists"`
	ID                int64  `json:"id,omitempty"`
	AppID             int64  `json:"app_id,omitempty"`
	Subdomain         string `json:"subdomain,omitempty"`
	Scope             string `json:"scope,omitempty"`
	Key               string `json:"key"`
	Ciphertext        string `json:"ciphertext,omitempty"`
	UpdatedBy         string `json:"updated_by,omitempty"`
	UpdatedByNull     bool   `json:"updated_by_null,omitempty"`
	UpdatedAt         string `json:"updated_at,omitempty"`
	UpdatedAtBytes    []byte `json:"updated_at_bytes,omitempty"`
	UpdatedAtNull     bool   `json:"updated_at_null,omitempty"`
	NewCiphertext     string `json:"new_ciphertext,omitempty"`
	NewUpdatedBy      string `json:"new_updated_by,omitempty"`
	NewUpdatedAt      string `json:"new_updated_at,omitempty"`
	NewUpdatedAtBytes []byte `json:"new_updated_at_bytes,omitempty"`
}

type appRotationJournalRecord struct {
	Version  int                           `json:"version"`
	Domain   string                        `json:"domain"`
	Identity appRotationTransitionIdentity `json:"identity"`
	Backend  appRotationBackendSnapshot    `json:"backend"`
}

type appRotationJournal struct {
	record appRotationJournalRecord
	digest string
	fileID string
	key    string
	root   *os.Root
}

func (appRotationBackendSnapshot) String() string   { return "<redacted rotation backend snapshot>" }
func (appRotationBackendSnapshot) GoString() string { return "<redacted rotation backend snapshot>" }
func (appRotationJournalRecord) String() string     { return "<redacted rotation journal>" }
func (appRotationJournalRecord) GoString() string   { return "<redacted rotation journal>" }
func (*appRotationJournal) String() string          { return "<redacted rotation journal>" }
func (*appRotationJournal) GoString() string        { return "<redacted rotation journal>" }

func rotationFileIdentity(info os.FileInfo) string {
	if info == nil || info.Sys() == nil {
		return ""
	}
	v := reflect.ValueOf(info.Sys())
	if v.Kind() == reflect.Pointer {
		v = v.Elem()
	}
	if !v.IsValid() || v.Kind() != reflect.Struct {
		return ""
	}
	dev, ino := v.FieldByName("Dev"), v.FieldByName("Ino")
	if !dev.IsValid() || !ino.IsValid() {
		return ""
	}
	return fmt.Sprintf("%T:%v:%v", info.Sys(), dev, ino)
}

func validateRotationAuthorityRoot(lease *appMCPAuthorityLease) error {
	if lease == nil || lease.root == nil || lease.file == nil {
		return errors.New("rotation authority lease is unavailable")
	}
	current, key, err := appMCPAuthorityRoot(lease.path)
	if err != nil {
		return err
	}
	defer current.Close()
	if key != lease.key {
		return errors.New("rotation authority owner changed")
	}
	oldDir, err := lease.root.Open(".")
	if err != nil {
		return err
	}
	defer oldDir.Close()
	newDir, err := current.Open(".")
	if err != nil {
		return err
	}
	defer newDir.Close()
	oldInfo, oldErr := oldDir.Stat()
	newInfo, newErr := newDir.Stat()
	if oldErr != nil || newErr != nil || !os.SameFile(oldInfo, newInfo) || oldInfo.Mode().Perm() != 0700 || newInfo.Mode().Perm() != 0700 || !fileOwnedByProcess(oldInfo) || !fileOwnedByProcess(newInfo) {
		return errors.New("rotation authority directory changed")
	}
	return validateAuthorityLockPath(lease.root, lease.file)
}

func validRotationHex(s string) bool {
	b, err := hex.DecodeString(s)
	return err == nil && len(b) == 32 && s == strings.ToLower(s) && hex.EncodeToString(b) == s
}

func validateRotationIdentity(id appRotationTransitionIdentity, backend *appRotationBackendSnapshot, lease *appMCPAuthorityLease) error {
	if lease == nil || lease.root == nil || lease.file == nil || lease.key == "" || backend == nil || backend.OwnerHash != lease.key || backend.AppPath == "" ||
		!validRotationHex(id.OldGeneration) || !validRotationHex(id.NewGeneration) || !validRotationHex(id.RotationID) ||
		!validRotationHex(id.OldMarkerDigest) || !validRotationHex(id.WriteEpoch) || id.OldGeneration == id.NewGeneration || id.MarkerVersion != 2 {
		return errors.New("invalid rotation transition identity")
	}
	ownerPath, ownerErr := filepath.Abs(lease.path)
	backendPath, backendErr := filepath.Abs(backend.AppPath)
	if ownerErr != nil || backendErr != nil || filepath.Clean(ownerPath) != filepath.Clean(backendPath) {
		return errors.New("rotation snapshot does not match its owner lease")
	}
	oldKey, oldErr := cryptoDeriveAppKey(backend.OldSource)
	newKey, newErr := cryptoDeriveAppKey(backend.NewSource)
	if oldErr != nil || newErr != nil || bytes.Equal(oldKey, newKey) || len(oldKey) != 32 || len(newKey) != 32 {
		return errors.New("invalid rotation key material")
	}
	return nil
}

func rotationJournalName(key string) string { return key + ".rotation.json" }

func prepareAppRotationJournal(ctx context.Context, lease *appMCPAuthorityLease, identity appRotationTransitionIdentity, backend *appRotationBackendSnapshot) (*appRotationJournal, error) {
	if ctx == nil {
		return nil, errors.New("rotation context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	backendBytes, err := json.Marshal(backend)
	if err != nil {
		return nil, errors.New("invalid rotation backend snapshot")
	}
	var frozenBackend appRotationBackendSnapshot
	if err := json.Unmarshal(backendBytes, &frozenBackend); err != nil {
		return nil, errors.New("invalid rotation backend snapshot")
	}
	backend = &frozenBackend
	if err := validateRotationIdentity(identity, backend, lease); err != nil {
		return nil, err
	}
	if err := validateRotationSnapshot(*backend); err != nil {
		return nil, errors.New("invalid rotation backend snapshot")
	}
	if err := validateRotationJournalSnapshot(*backend); err != nil {
		return nil, errAppRotationConflict
	}
	if err := validateRotationAuthorityRoot(lease); err != nil {
		return nil, errors.New("rotation authority root changed")
	}
	if err := validateAuthorityLockPath(lease.root, lease.file); err != nil {
		return nil, errors.New("rotation authority lease changed")
	}
	if existing, err := readRotationJournal(lease); err == nil {
		if existing.record.Identity == identity && sameRotationSnapshot(existing.record.Backend, *backend) {
			if err := syncRotationAuthorityDirectory(lease); err != nil {
				return nil, errAppRotationOutcomeUnknown
			}
			if err := validateRotationAuthorityRoot(lease); err != nil {
				return nil, errAppRotationOutcomeUnknown
			}
			if err := validateAuthorityLockPath(lease.root, lease.file); err != nil {
				return nil, errAppRotationOutcomeUnknown
			}
			verified, err := readRotationJournal(lease)
			if err != nil || verified.digest != existing.digest || verified.fileID == "" || verified.fileID != existing.fileID || !bytes.Equal(mustRotationJSON(verified), mustRotationJSON(existing)) {
				return nil, errAppRotationOutcomeUnknown
			}
			return verified, nil
		}
		return nil, errAppRotationConflict
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	record := appRotationJournalRecord{Version: 1, Domain: "benmore.encryption-rotation", Identity: identity, Backend: frozenBackend}
	data, err := json.Marshal(record)
	if err != nil || len(data) > appRotationJournalLimit {
		return nil, errors.New("rotation journal is invalid or too large")
	}
	tmp, err := stageRotationFile(lease.root, ".rotation-stage-", data)
	if err != nil {
		return nil, errors.New("cannot persist rotation journal stage")
	}
	if err := validateRotationAuthorityRoot(lease); err != nil {
		_ = lease.root.Remove(tmp)
		return nil, errors.New("rotation authority root changed")
	}
	name := rotationJournalName(lease.key)
	if _, err := lease.root.Lstat(name); err == nil {
		_ = lease.root.Remove(tmp)
		return nil, errAppRotationConflict
	} else if !os.IsNotExist(err) {
		_ = lease.root.Remove(tmp)
		return nil, errors.New("cannot inspect rotation journal destination")
	}
	if err := publishRotationFile(lease.root, tmp, name); err != nil {
		_ = lease.root.Remove(tmp)
		return nil, errAppRotationOutcomeUnknown
	}
	if err := syncRotationAuthorityDirectory(lease); err != nil {
		return nil, errAppRotationOutcomeUnknown
	}
	j, err := readRotationJournal(lease)
	if err != nil || !bytes.Equal(data, mustRotationJSON(j)) {
		return nil, errAppRotationOutcomeUnknown
	}
	return j, nil
}

var syncRotationAuthorityDirectory = func(lease *appMCPAuthorityLease) error {
	if lease == nil || lease.root == nil || validateRotationAuthorityRoot(lease) != nil {
		return errors.New("rotation authority root changed")
	}
	dir, err := lease.root.Open(".")
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

func mustRotationJSON(j *appRotationJournal) []byte {
	if j == nil {
		return nil
	}
	b, _ := json.Marshal(j.record)
	return b
}

func sameRotationSnapshot(a, b appRotationBackendSnapshot) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}

func readAppRotationJournal(ctx context.Context, lease *appMCPAuthorityLease) (*appRotationJournal, error) {
	if ctx == nil {
		return nil, errors.New("rotation context is unavailable")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return readRotationJournal(lease)
}

func readRotationJournal(lease *appMCPAuthorityLease) (*appRotationJournal, error) {
	if lease == nil || lease.root == nil || lease.file == nil || lease.key == "" || validateRotationAuthorityRoot(lease) != nil || validateAuthorityLockPath(lease.root, lease.file) != nil {
		return nil, errors.New("rotation authority lease is unavailable")
	}
	name := rotationJournalName(lease.key)
	info, err := lease.root.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !fileOwnedByProcess(info) || info.Size() <= 0 || info.Size() > appRotationJournalLimit {
		return nil, errors.New("invalid protected rotation journal")
	}
	f, err := lease.root.Open(name)
	if err != nil {
		return nil, errors.New("cannot read protected rotation journal")
	}
	opened, statErr := f.Stat()
	data, readErr := io.ReadAll(io.LimitReader(f, appRotationJournalLimit+1))
	closeErr := f.Close()
	if statErr != nil || closeErr != nil || readErr != nil || !os.SameFile(info, opened) || !opened.Mode().IsRegular() || opened.Mode().Perm() != 0600 || !fileOwnedByProcess(opened) || len(data) > appRotationJournalLimit {
		return nil, errors.New("cannot read protected rotation journal")
	}
	var record appRotationJournalRecord
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	if d.Decode(&record) != nil {
		return nil, errors.New("invalid protected rotation journal")
	}
	var extra any
	if d.Decode(&extra) != io.EOF || record.Version != 1 || record.Domain != "benmore.encryption-rotation" || !bytes.Equal(data, mustMarshalRotation(record)) {
		return nil, errors.New("invalid protected rotation journal")
	}
	if err := validateRotationIdentity(record.Identity, &record.Backend, lease); err != nil {
		return nil, errors.New("invalid protected rotation journal")
	}
	if err := validateRotationSnapshot(record.Backend); err != nil {
		return nil, errors.New("invalid protected rotation journal")
	}
	if err := validateRotationAuthorityRoot(lease); err != nil {
		return nil, errors.New("rotation authority root changed")
	}
	if err := validateAuthorityLockPath(lease.root, lease.file); err != nil {
		return nil, errors.New("rotation authority lease changed")
	}
	return &appRotationJournal{record: record, digest: hashBytesSHA256(data), fileID: rotationFileIdentity(info), key: lease.key, root: lease.root}, nil
}

func mustMarshalRotation(record appRotationJournalRecord) []byte {
	b, _ := json.Marshal(record)
	return b
}

func validateRotationSnapshot(s appRotationBackendSnapshot) error {
	if !validRotationHex(s.OwnerHash) || s.AppPath == "" || s.AppDirectoryID == "" || (s.Kind != appRotationLocalYAML && s.Kind != appRotationPlatformVault) || s.OldSource == "" || s.NewSource == "" {
		return errors.New("invalid rotation snapshot")
	}
	if s.OriginalExists && (s.OriginalMode != 0600 || s.OriginalFileID == "" || !validRotationHex(s.OriginalHash) || hashBytesSHA256(s.OriginalBytes) != s.OriginalHash) || !s.OriginalExists && (s.OriginalMode != 0 || s.OriginalFileID != "" || s.OriginalHash != "" || len(s.OriginalBytes) != 0) {
		return errors.New("invalid rotation snapshot")
	}
	if s.GuardExists && (s.GuardMode != 0600 || s.GuardFileID == "" || !validRotationHex(s.GuardHash) || hashBytesSHA256(s.GuardBytes) != s.GuardHash) || !s.GuardExists && (s.GuardMode != 0 || s.GuardFileID != "" || s.GuardHash != "" || len(s.GuardBytes) != 0) {
		return errors.New("invalid rotation snapshot")
	}
	if s.Kind == appRotationLocalYAML {
		if s.EffectiveSource != "env.yaml" || !s.OriginalExists || len(s.DesiredBytes) == 0 || s.PlatformMaster != "" || s.PlatformMasterSource != "" || s.PlatformSchemaHash != "" || s.PlatformAppID != 0 || s.PlatformOwnerID != 0 || s.PlatformLogical != "" || s.PlatformInstance != "" || s.PlatformScope != "" || s.LegacyOverlay || s.LegacyTable || s.LegacyRow != nil || len(s.VaultRows) != 0 {
			return errors.New("invalid local rotation snapshot")
		}
		if err := validateRotationYAMLChange(s.OriginalBytes, s.DesiredBytes, s.OldSource, s.NewSource); err != nil {
			return errors.New("invalid local rotation snapshot")
		}
		if s.GuardExists {
			vars, err := parseAppEnvironmentFile(string(s.GuardBytes))
			if err != nil {
				return errors.New("invalid local rotation snapshot")
			}
			if _, ok := vars["ENCRYPTION_KEY"]; ok {
				return errors.New("invalid local rotation snapshot")
			}
		}
	} else if s.EffectiveSource != "platform_env" && s.EffectiveSource != "builder_env_vars" {
		return errors.New("invalid platform rotation snapshot")
	}
	if len(s.OriginalBytes) > appRotationJournalLimit || len(s.DesiredBytes) > appRotationJournalLimit || len(s.GuardBytes) > appRotationJournalLimit {
		return errors.New("invalid rotation snapshot")
	}
	if s.Kind == appRotationPlatformVault {
		if !validRotationHex(s.PlatformMaster) || !validRotationHex(s.PlatformSchemaHash) || (s.PlatformMasterSource != "environment" && s.PlatformMasterSource != "systemd:benmore_master_key") || s.PlatformAppID <= 0 || s.PlatformLogical == "" || s.PlatformInstance == "" ||
			(s.PlatformScope != string(EnvDev) && s.PlatformScope != string(EnvProd)) || len(s.VaultRows) > 3 {
			return errors.New("invalid platform rotation snapshot")
		}
		if s.PlatformOwnerID <= 0 || len(s.VaultRows) != 3 {
			return errors.New("invalid platform rotation snapshot")
		}
		seen := map[string]bool{}
		selectedFound := false
		for i, row := range s.VaultRows {
			expectedScopes := [...]string{"shared", string(EnvDev), string(EnvProd)}
			absentDirty := !row.Exists && (row.ID != 0 || row.Ciphertext != "" || row.UpdatedBy != "" || row.UpdatedByNull || row.UpdatedAt != "" || len(row.UpdatedAtBytes) != 0 || row.UpdatedAtNull)
			if i >= len(expectedScopes) || row.Scope != expectedScopes[i] || row.Key != "ENCRYPTION_KEY" || row.AppID != s.PlatformAppID || !validPlatformRotationScope(row.Scope) || seen[row.Scope] || row.Exists && (row.Ciphertext == "" || row.ID <= 0 || (row.UpdatedAtNull && (row.UpdatedAt != "" || len(row.UpdatedAtBytes) != 0)) || (!row.UpdatedAtNull && (len(row.UpdatedAtBytes) == 0 || string(row.UpdatedAtBytes) != row.UpdatedAt))) || absentDirty {
				return errors.New("invalid platform rotation snapshot")
			}
			seen[row.Scope] = true
			if row.Scope == s.PlatformScope {
				selectedFound = true
				if row.NewCiphertext == "" || row.NewUpdatedBy != "key-rotation" || row.NewUpdatedAt == "" || len(row.NewUpdatedAtBytes) == 0 || string(row.NewUpdatedAtBytes) != row.NewUpdatedAt {
					return errors.New("invalid platform rotation snapshot")
				}
			} else if row.NewCiphertext != "" || row.NewUpdatedBy != "" || row.NewUpdatedAt != "" || len(row.NewUpdatedAtBytes) != 0 {
				return errors.New("invalid platform rotation snapshot")
			}
		}
		if !selectedFound || s.LegacyRow != nil && (!s.LegacyTable || !s.LegacyRow.Exists || s.LegacyRow.Key != "ENCRYPTION_KEY" || s.LegacyRow.Subdomain != s.PlatformInstance || s.LegacyRow.Ciphertext == "" || s.LegacyRow.ID <= 0 || (s.LegacyRow.UpdatedAtNull && (s.LegacyRow.UpdatedAt != "" || len(s.LegacyRow.UpdatedAtBytes) != 0)) || (!s.LegacyRow.UpdatedAtNull && (len(s.LegacyRow.UpdatedAtBytes) == 0 || string(s.LegacyRow.UpdatedAtBytes) != s.LegacyRow.UpdatedAt))) || !s.LegacyTable && s.LegacyRow != nil || s.EffectiveSource == "builder_env_vars" && (!s.LegacyOverlay || s.LegacyRow == nil) {
			return errors.New("invalid platform rotation snapshot")
		}
		if s.OriginalExists {
			original, err := parseAppEnvironmentFile(string(s.OriginalBytes))
			if err != nil {
				return errors.New("invalid platform rotation snapshot")
			}
			desired, err := parseAppEnvironmentFile(string(s.DesiredBytes))
			oldKey, hasOldKey := original["ENCRYPTION_KEY"]
			wantLen := len(original) + 1
			if hasOldKey {
				wantLen = len(original)
			}
			if err != nil || desired["ENCRYPTION_KEY"] != s.NewSource || len(desired) != wantLen || hasOldKey && oldKey != s.OldSource {
				return errors.New("invalid platform rotation snapshot")
			}
			for key, value := range original {
				if key != "ENCRYPTION_KEY" {
					got, ok := desired[key]
					if !ok || got != value {
						return errors.New("invalid platform rotation snapshot")
					}
				}
			}
		} else if len(s.DesiredBytes) != 0 {
			return errors.New("invalid platform rotation snapshot")
		}
	}
	return nil
}

func validateRotationYAMLChange(original, desired []byte, oldSource, newSource string) error {
	before := map[string]string{}
	after := map[string]string{}
	if err := decodeConfigYAML(original, &before); err != nil {
		return err
	}
	if err := decodeConfigYAML(desired, &after); err != nil {
		return err
	}
	if before["ENCRYPTION_KEY"] != oldSource || after["ENCRYPTION_KEY"] != newSource || len(before) != len(after) {
		return errors.New("invalid key change")
	}
	for key, value := range before {
		if key != "ENCRYPTION_KEY" {
			got, ok := after[key]
			if !ok || got != value {
				return errors.New("invalid unrelated YAML change")
			}
		}
	}
	for k, v := range after {
		if !validAppEnvKey(k) || !validAppEnvValue(v) {
			return errors.New("invalid environment value")
		}
	}
	return nil
}

func validPlatformRotationScope(scope string) bool {
	return scope == "shared" || scope == string(EnvDev) || scope == string(EnvProd)
}

func writeAll(w io.Writer, data []byte) error {
	for len(data) > 0 {
		n, err := w.Write(data)
		if err != nil {
			return err
		}
		if n <= 0 {
			return io.ErrShortWrite
		}
		data = data[n:]
	}
	return nil
}

// stageRotationFile and publishRotationFile are the concrete private-file operations
// used by the journal and both persistence backends. Keeping these boundaries small
// lets native subprocess tests stop at the same durable stage and rename points.
func stageRotationFile(root *os.Root, prefix string, data []byte) (string, error) {
	if root == nil || !strings.HasPrefix(prefix, ".") || strings.ContainsAny(prefix, "/\\") {
		return "", errors.New("invalid rotation stage")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	name := prefix + hex.EncodeToString(nonce[:])
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	writeErr := writeAll(f, data)
	if writeErr == nil {
		writeErr = f.Chmod(0600)
	}
	if writeErr == nil {
		writeErr = f.Sync()
	}
	info, statErr := f.Stat()
	if writeErr == nil && (statErr != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || !fileOwnedByProcess(info)) {
		writeErr = errors.New("unsafe rotation stage")
	}
	closeErr := f.Close()
	if writeErr != nil || statErr != nil || closeErr != nil {
		_ = root.Remove(name)
		return "", errors.New("cannot persist rotation stage")
	}
	return name, nil
}

func publishRotationFile(root *os.Root, staged, destination string) error {
	if root == nil || staged == "" || destination == "" || strings.ContainsAny(staged+destination, "/\\") {
		return errors.New("invalid rotation publication")
	}
	return root.Rename(staged, destination)
}
