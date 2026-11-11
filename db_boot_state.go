//go:build !cli

package main

// What the last pre-migrate snapshot covered: the runtime build and the
// storage configuration a start ran with.
//
// The schema plan (schema_change_plan.go) sees schema DDL only. Later steps of
// a start also rewrite data: versioning re-seals history rows, encryption adds
// blind-index columns and seals plaintext, full-text tables are rebuilt, and
// the framework's own steps after the load (user-table columns, username
// backfill, session-id rekeying, TOTP sealing) change with the runtime. Those
// rewrites follow from two things, so a change in either is a snapshot reason:
//
//   - the runtime build (version plus VCS revision, or the executable's
//     SHA-256 when the build carries no clean revision): each app takes one
//     pre-migrate snapshot on its first start of a new release;
//   - the storage configuration: encrypted fields, versioned tables,
//     computed fields, aggregates, @@fulltext declarations, and whether an
//     ENCRYPTION_KEY is configured.
//
// .benmore/db-boot-state.json records both, with the file's device and inode,
// when a snapshot is taken (or when there was no database to copy). A start
// whose build and configuration match it needs no snapshot for these reasons;
// a missing or unreadable record means "can't tell", so it snapshots. Writing
// it when the snapshot is taken, not when the start succeeds, keeps a start
// that fails and is retried from copying the database again each time: the
// first copy is the true pre-image.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"sync"
)

const (
	dbBootStateName    = "db-boot-state.json"
	dbBootStateVersion = 1
)

type dbBootState struct {
	Version       int    `json:"version"`
	Dev           uint64 `json:"dev"`
	Ino           uint64 `json:"ino"`
	Build         string `json:"build"`
	StorageConfig string `json:"storage_config"`
}

func dbBootStatePath(dir string) string {
	return filepath.Join(dir, ".benmore", dbBootStateName)
}

// runtimeBuildID identifies the running binary, or returns "" when it cannot.
// A variable so tests can stand in a release change.
var runtimeBuildID = sync.OnceValue(computeRuntimeBuildID)

func computeRuntimeBuildID() string {
	id := "benmore " + version
	if info, ok := debug.ReadBuildInfo(); ok {
		revision, modified := "", ""
		for _, s := range info.Settings {
			switch s.Key {
			case "vcs.revision":
				revision = s.Value
			case "vcs.modified":
				modified = s.Value
			}
		}
		if revision != "" && modified != "true" {
			return id + " " + revision
		}
	}
	// No clean revision (a local or test build): the binary's content.
	exe, err := os.Executable()
	if err != nil {
		return ""
	}
	f, err := os.Open(exe)
	if err != nil {
		return ""
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return ""
	}
	return id + " sha256:" + hex.EncodeToString(h.Sum(nil))
}

// storageConfigDigest hashes the configuration whose change makes a start
// rewrite stored data.
func storageConfigDigest(app *App, config *runtimeConfig, env map[string]string) (string, error) {
	fulltext := map[string][][]string{}
	for _, table := range app.Tables {
		if len(table.FullText) > 0 {
			fulltext[table.Name] = table.FullText
		}
	}
	aggregates := app.aggregateConfig()
	sort.Slice(aggregates, func(i, j int) bool { return aggregates[i].Name < aggregates[j].Name })
	data, err := json.Marshal(struct {
		Encrypted     *EncryptedFieldConfig
		Versioned     *VersionedConfig
		Computed      *ComputedFieldConfig
		Aggregates    []AggregateConfig
		FullText      map[string][][]string
		EncryptionKey bool
	}{config.encrypted, app.versionedConfig(), config.computed, aggregates, fulltext, env["ENCRYPTION_KEY"] != ""})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:]), nil
}

// bootStateSnapshotReason says why the build or storage configuration calls
// for a snapshot, or "" when the record shows the last snapshot covered them.
func bootStateSnapshotReason(dir, build, storage string) string {
	if build == "" || storage == "" {
		return "the runtime build or storage configuration could not be identified"
	}
	data, err := os.ReadFile(dbBootStatePath(dir))
	if err != nil {
		return "no record of the build and storage configuration the last snapshot covered"
	}
	var state dbBootState
	if json.Unmarshal(data, &state) != nil || state.Version != dbBootStateVersion {
		return "the boot-state record is malformed"
	}
	dev, ino, err := dbFileDevIno(filepath.Join(dir, "data.db"))
	if err != nil || dev != state.Dev || ino != state.Ino {
		return "the database file changed since the last snapshot"
	}
	if state.Build != build {
		return "the runtime build changed (" + state.Build + " -> " + build + ")"
	}
	if state.StorageConfig != storage {
		return "the storage configuration changed (encrypted, versioned, computed, aggregate or full-text fields, or the encryption key)"
	}
	return ""
}

// recordBootState notes that a snapshot (or a fresh database) covers this
// build and storage configuration. Best effort: without it the next start
// snapshots again.
func recordBootState(dir, build, storage string) error {
	if build == "" || storage == "" {
		return errors.New("build or storage configuration unknown")
	}
	if foreignAppDirs.Load() {
		return errors.New("not recorded from a process that does not own the app directory")
	}
	dev, ino, err := dbFileDevIno(filepath.Join(dir, "data.db"))
	if err != nil {
		return err
	}
	data, err := json.Marshal(dbBootState{Version: dbBootStateVersion, Dev: dev, Ino: ino, Build: build, StorageConfig: storage})
	if err != nil {
		return err
	}
	return writeStateFile(dir, dbBootStateName, data)
}

// writeStateFile replaces .benmore/<name> atomically.
func writeStateFile(dir, name string, data []byte) error {
	stateDir := filepath.Join(dir, ".benmore")
	if err := os.MkdirAll(stateDir, 0700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(stateDir, "."+name+"-*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	if closeErr := tmp.Close(); err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(tmp.Name(), filepath.Join(stateDir, name))
	}
	if err != nil {
		os.Remove(tmp.Name())
	}
	return err
}
