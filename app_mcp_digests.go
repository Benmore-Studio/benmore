//go:build !cli

package main

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

var appMCPDigestWalkCount atomic.Uint64

func appMCPDigestWalks() uint64 { return appMCPDigestWalkCount.Load() }

// appMCPDigests binds reviewed declarations to the complete deployable source
// set. Runtime data and credentials are excluded; static bundle inputs are not.
// It does not authorize exposure or execute source.
//
// A manifest with ExecutionSources "runtime" binds only the files the runtime
// can load, execute or serve (appMCPSourceScope); one without it binds the
// whole tree, as manifests reviewed before that field existed do.
func appMCPDigests(dir string, manifest *AppMCPManifest) (contract, execution string, err error) {
	appMCPDigestWalkCount.Add(1)
	contract, execution, _, err = appMCPSourceDigests(dir, manifest, nil)
	return
}

func appMCPContractDigest(manifest *AppMCPManifest) (string, error) {
	reviewed := *manifest
	reviewed.ContractDigest, reviewed.ExecutionDigest = "", ""
	raw, err := json.Marshal(reviewed)
	if err != nil {
		return "", fmt.Errorf("mcp.yaml: cannot encode reviewed contract")
	}
	return hashBytesSHA256(raw), nil
}

func appMCPSourceDigests(dir string, manifest *AppMCPManifest, captured map[string][]byte) (contract, execution string, sources map[string]string, err error) {
	if manifest == nil {
		return "", "", nil, fmt.Errorf("mcp.yaml: manifest required")
	}
	contract, err = appMCPContractDigest(manifest)
	if err != nil {
		return "", "", nil, err
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return "", "", nil, fmt.Errorf("mcp.yaml: cannot open execution source")
	}
	defer root.Close()
	sources = map[string]string{}
	var files []SourceManifestFile
	var total int64
	// ponytail: hash the whole scoped source set (the whole tree for a manifest without execution_sources), narrow dependency selection only if app size makes this limit impractical.
	const maxBytes = 64 << 20
	scope := appMCPScopeFor(manifest)
	err = appMCPWalkSourceSet(root, scope, func(path string, info fs.FileInfo) error {
		if len(files) >= 10000 || info.Size() > maxBytes-total {
			return fmt.Errorf("execution source limit exceeded")
		}
		f, err := root.Open(filepath.FromSlash(path))
		if err != nil {
			return err
		}
		data, readErr := io.ReadAll(io.LimitReader(f, maxBytes-total+1))
		closeErr := f.Close()
		if readErr != nil {
			return readErr
		}
		if closeErr != nil {
			return closeErr
		}
		if int64(len(data)) > maxBytes-total {
			return fmt.Errorf("execution source limit exceeded")
		}
		total += int64(len(data))
		// Retain requested inputs (or the complete generation), from these exact hashed bytes.
		_, allSources := captured["."]
		_, migrationCapture := captured["migrations/"]
		_, flowCapture := captured["flows/"]
		if _, wanted := captured[path]; wanted || allSources || migrationCapture && strings.HasPrefix(path, "migrations/") || flowCapture && strings.HasPrefix(path, "flows/") {
			captured[path] = data
		}
		sources[path] = hashBytesSHA256(data)
		files = append(files, SourceManifestFile{Path: path, SHA256: sources[path], Size: int64(len(data))})
		return nil
	})
	if err != nil {
		return "", "", nil, fmt.Errorf("mcp.yaml: cannot fingerprint complete execution source")
	}
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	execution, err = appMCPExecutionFingerprint(contract, scope.version(), files)
	return contract, execution, sources, err
}

// appMCPLegacyNamedSources are the top-level names whose case variants and
// wrong-kind entries the whole-tree walk refuses.
var appMCPLegacyNamedSources = []string{"app.yaml", "encrypted.yaml", "schema.prisma", "schema.sql", "schema.yaml", "i18n", "migrations", "hooks.yaml", "workflows.yaml", "cron.yaml", "mcp.yaml", "flows.yaml", "flows", "partials", "layouts", "head.html", "theme.css", "validators.yaml", "admin.yaml", "computed.yaml", "retention.yaml"}

// appMCPWalkSourceSet visits every regular file of the execution source set.
// The content hash and the stat fingerprint (validateAppMCPDigests) both walk
// through here, so they always cover the same files under the same checks.
func appMCPWalkSourceSet(root *os.Root, scope appMCPSourceScope, visit func(path string, info fs.FileInfo) error) error {
	return fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if path == "." {
			return nil
		}
		if scope.runtime {
			// Judged before exclusion: a case variant or a wrong-kind entry named
			// like a runtime source would otherwise be skipped silently, yet is
			// what a case-insensitive file system hands the runtime.
			if err := appMCPCheckRuntimeRoot(path, entry.IsDir()); err != nil {
				return err
			}
		}
		if scope.excluded(path, entry.IsDir()) {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		for _, name := range appMCPLegacyNamedSources {
			if path != name && strings.EqualFold(path, name) {
				return fmt.Errorf("ambiguous authority configuration filename")
			}
			if path == name && name != "migrations" && name != "flows" && name != "partials" && name != "layouts" && name != "i18n" && entry.IsDir() {
				return fmt.Errorf("invalid configuration source file")
			}
		}
		if (path == "migrations" || path == "flows" || path == "partials" || path == "layouts" || path == "i18n") && !entry.IsDir() {
			return fmt.Errorf("invalid execution source directory")
		}
		if path == "mcp.yaml" {
			return nil
		} // declarations are bound by contract above
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("non-regular execution source")
		}
		return visit(path, info)
	})
}

// appMCPSourceExcluded is the floor both digest forms apply (the runtime form
// then narrows with appMCPSourceScope): it reports whether the execution source
// walk skips path (a whole directory when isDir). static/ and flows/ are walked, except for
// editor/agent auto-run config outside static/ (workspaceAutoRunPath), which
// hosted apps refuse and deploy skips, and which never executes in the app.
//
// Desktop metadata sidecars (.DS_Store, `._*`, Thumbs.db) are skipped too: deploy
// never ships them, the runtime never serves or loads them (isMetadataSidecar),
// and hashing one locally made a review unmatchable by the deployed app.
func appMCPSourceExcluded(path string, isDir bool) bool {
	if isMetadataSidecar(path) {
		return true
	}
	executableTree := path == "static" || strings.HasPrefix(path, "static/") || path == "flows" || strings.HasPrefix(path, "flows/")
	return !executableTree && sourceManifestExcluded(path, isDir) || workspaceAutoRunPath(path, isDir)
}

// appMCPSourceCovers reports whether the execution source walk of manifest m
// (nil: the whole-tree form) reaches the file at path: neither it nor a parent
// directory is skipped.
func appMCPSourceCovers(path string, m *AppMCPManifest) bool {
	scope := appMCPScopeFor(m)
	segs := strings.Split(path, "/")
	for i := 1; i < len(segs); i++ {
		if scope.excluded(strings.Join(segs[:i], "/"), true) {
			return false
		}
	}
	return path != "mcp.yaml" && !scope.excluded(path, false)
}

// appMCPUnpulledSources lists (up to limit) the files the execution digest
// covers that `benmore pull` never writes. A review run in a pulled
// workspace cannot reproduce a digest over them, so they are named wherever
// a review is found stale.
func appMCPUnpulledSources(dir string, m *AppMCPManifest, limit int) (paths []string, more int) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, 0
	}
	defer root.Close()
	_ = appMCPWalkSourceSet(root, appMCPScopeFor(m), func(path string, _ fs.FileInfo) error {
		if pullDeniedPath(path) {
			if len(paths) < limit {
				paths = append(paths, path)
			} else {
				more++
			}
		}
		return nil
	})
	return paths, more
}

func appMCPExecutionFingerprint(contract string, version int, files []SourceManifestFile) (string, error) {
	for _, file := range files {
		if !utf8.ValidString(file.Path) {
			return "", fmt.Errorf("mcp.yaml: invalid execution source path")
		}
	}
	raw, err := json.Marshal(struct {
		Version  int                  `json:"version"`
		Contract string               `json:"contract"`
		Files    []SourceManifestFile `json:"files"`
	}{version, contract, files})
	if err != nil {
		return "", fmt.Errorf("mcp.yaml: cannot encode execution source")
	}
	return hashBytesSHA256(raw), nil
}

// validateAppMCPDigests runs several times per connector call. A full re-hash
// reads the whole source set (up to 64 MiB), so a verified result is reused
// while a stat fingerprint of the same file set is unchanged: every path with
// its size, mtime, ctime, inode and device. Rewriting a file changes its ctime
// even when the mtime is restored, and replacing it changes its inode. A
// fingerprint holding a timestamp within appMCPDigestRacyWindow of the walk
// is never cached (a second write in the same timestamp tick would not show),
// and a cached result is re-hashed at least every appMCPDigestCacheMaxAge.
// Builds without these stat fields never cache.
func validateAppMCPDigests(dir string, manifest *AppMCPManifest) error {
	if manifest == nil {
		return nil
	}
	key, keyErr := filepath.Abs(dir)
	before, cacheable := appMCPDigestStatFingerprint(dir, manifest)
	cacheable = cacheable && keyErr == nil
	if cacheable && appMCPDigestCacheHit(key, before, manifest) {
		return nil
	}
	contract, execution, err := appMCPDigests(dir, manifest)
	if err != nil {
		appMCPDigestCacheForget(key)
		return err
	}
	if contract != manifest.ContractDigest || execution != manifest.ExecutionDigest {
		appMCPDigestCacheForget(key)
		return fmt.Errorf("mcp.yaml: reviewed contract or execution digest mismatch")
	}
	// Cache only when nothing changed while the content was read.
	if after, ok := appMCPDigestStatFingerprint(dir, manifest); cacheable && ok && after == before {
		appMCPDigestCache.Lock()
		if appMCPDigestCache.entries == nil || len(appMCPDigestCache.entries) >= appMCPDigestCacheMaxEntries {
			appMCPDigestCache.entries = map[string]appMCPDigestCacheEntry{}
		}
		appMCPDigestCache.entries[key] = appMCPDigestCacheEntry{fingerprint: before, contract: contract, execution: execution, verified: time.Now()}
		appMCPDigestCache.Unlock()
	}
	return nil
}

const (
	appMCPDigestCacheMaxAge     = 60 * time.Second
	appMCPDigestCacheMaxEntries = 4096 // one per app directory; a full map is simply dropped
)

// appMCPDigestRacyWindow is a variable only so tests need not sleep past it.
var appMCPDigestRacyWindow = 2 * time.Second

type appMCPDigestCacheEntry struct {
	fingerprint         [sha256.Size]byte
	contract, execution string
	verified            time.Time
}

var appMCPDigestCache struct {
	sync.Mutex
	entries map[string]appMCPDigestCacheEntry
}

func appMCPDigestCacheHit(key string, fingerprint [sha256.Size]byte, manifest *AppMCPManifest) bool {
	contract, err := appMCPContractDigest(manifest)
	if err != nil {
		return false
	}
	appMCPDigestCache.Lock()
	entry, ok := appMCPDigestCache.entries[key]
	appMCPDigestCache.Unlock()
	return ok && entry.fingerprint == fingerprint && time.Since(entry.verified) < appMCPDigestCacheMaxAge &&
		entry.contract == contract && contract == manifest.ContractDigest && entry.execution == manifest.ExecutionDigest
}

func appMCPDigestCacheForget(key string) {
	appMCPDigestCache.Lock()
	delete(appMCPDigestCache.entries, key)
	appMCPDigestCache.Unlock()
}

// appMCPDigestStatFingerprint hashes the stat identity of the source set the
// content hash covers. ok is false when the set cannot be walked, a file lacks
// stat identity (non-unix builds) or a timestamp is too recent to trust.
func appMCPDigestStatFingerprint(dir string, m *AppMCPManifest) (fingerprint [sha256.Size]byte, ok bool) {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return fingerprint, false
	}
	defer root.Close()
	racy := time.Now().Add(-appMCPDigestRacyWindow).UnixNano()
	h := sha256.New()
	var record [6 * 8]byte
	err = appMCPWalkSourceSet(root, appMCPScopeFor(m), func(path string, info fs.FileInfo) error {
		stamp, ok := appMCPDigestFileStamp(info)
		if !ok || stamp.mtimeNS >= racy || stamp.ctimeNS >= racy {
			return errAppMCPDigestUncacheable
		}
		for i, value := range []uint64{uint64(len(path)), uint64(info.Size()), uint64(stamp.mtimeNS), uint64(stamp.ctimeNS), stamp.inode, stamp.device} {
			binary.BigEndian.PutUint64(record[i*8:], value)
		}
		h.Write(record[:])
		h.Write([]byte(path))
		return nil
	})
	if err != nil {
		return fingerprint, false
	}
	copy(fingerprint[:], h.Sum(nil))
	return fingerprint, true
}

var errAppMCPDigestUncacheable = errors.New("source set is not stat-cacheable")

type appMCPDigestStamp struct {
	mtimeNS, ctimeNS int64
	inode, device    uint64
}
