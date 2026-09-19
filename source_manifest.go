package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const sourceManifestVersion = 1

// SourceManifest is the deployable-code fingerprint for one app instance.
// It intentionally excludes secrets, data, uploads, git state, runtime state,
// logs, and generated bm.d.ts so it can travel between the hosted platform and
// a local workspace without leaking private data.
type SourceManifest struct {
	Version       int                  `json:"version"`
	App           string               `json:"app,omitempty"`
	Env           string               `json:"env,omitempty"`
	Subdomain     string               `json:"subdomain,omitempty"`
	GeneratedAt   string               `json:"generated_at"`
	ServerGitHead string               `json:"server_git_head,omitempty"`
	EnvKeys       []string             `json:"env_keys,omitempty"`
	Files         []SourceManifestFile `json:"files"`
	// Partial is set when the walk skipped one or more files it could not
	// read (permission/IO). A partial manifest under-reports the file set,
	// so pull pruning must NOT treat missing entries as deleted_remote.
	Partial bool `json:"partial,omitempty"`
}

type SourceManifestFile struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type SourceManifestOptions struct {
	App           string
	Env           string
	Subdomain     string
	ServerGitHead string
	EnvKeys       []string
	GeneratedAt   time.Time
}

func BuildSourceManifest(dir string, opts SourceManifestOptions) (SourceManifest, error) {
	if dir == "" {
		return SourceManifest{}, fmt.Errorf("manifest dir is required")
	}
	root, err := filepath.Abs(dir)
	if err != nil {
		return SourceManifest{}, err
	}
	when := opts.GeneratedAt
	if when.IsZero() {
		when = time.Now().UTC()
	}
	m := SourceManifest{
		Version:       sourceManifestVersion,
		App:           opts.App,
		Env:           opts.Env,
		Subdomain:     opts.Subdomain,
		GeneratedAt:   when.UTC().Format(time.RFC3339),
		ServerGitHead: opts.ServerGitHead,
		EnvKeys:       sortedStrings(opts.EnvKeys),
	}
	err = filepath.Walk(root, func(path string, info os.FileInfo, walkErr error) error {
		if walkErr != nil {
			if isTolerableManifestWalkErr(walkErr) {
				m.Partial = true
				if info != nil && info.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			return walkErr
		}
		if info == nil {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil || rel == "." {
			return err
		}
		rel = filepath.ToSlash(rel)
		if sourceManifestExcluded(rel, info.IsDir()) {
			if info.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		h, err := hashFileSHA256Fn(path)
		if err != nil {
			if isTolerableManifestWalkErr(err) {
				m.Partial = true
				return nil
			}
			return err
		}
		m.Files = append(m.Files, SourceManifestFile{Path: rel, SHA256: h, Size: info.Size()})
		return nil
	})
	if err != nil {
		return SourceManifest{}, err
	}
	sort.Slice(m.Files, func(i, j int) bool { return m.Files[i].Path < m.Files[j].Path })
	return m, nil
}

func hashFileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// hashFileSHA256Fn indirects hashFileSHA256 so tests can simulate a file
// disappearing between filepath.Walk's stat and the hash read (e.g. a
// deploy landing mid-request on a live app dir) without a real race.
var hashFileSHA256Fn = hashFileSHA256

// isTolerableManifestWalkErr reports whether an error encountered while
// walking/hashing a file should degrade the manifest to Partial=true rather
// than aborting the whole build. Permission errors (unreadable file/dir) and
// not-exist errors (file removed between being listed and being read - the
// common case during a live deploy) are both tolerated: the manifest just
// under-reports that one file. Anything else (disk errors, etc.) is fatal.
func isTolerableManifestWalkErr(err error) bool {
	return os.IsPermission(err) || os.IsNotExist(err)
}

func hashBytesSHA256(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// SourceManifestContentHash identifies only the deployable file set. Volatile
// metadata such as generation time and git head is deliberately excluded so a
// CLI proof can be compared with a fresh server-side snapshot.
func SourceManifestContentHash(m SourceManifest) (string, error) {
	files := append([]SourceManifestFile(nil), m.Files...)
	sort.Slice(files, func(i, j int) bool { return files[i].Path < files[j].Path })
	raw, err := json.Marshal(files)
	if err != nil {
		return "", err
	}
	return hashBytesSHA256(raw), nil
}

func sourceManifestExcluded(rel string, isDir bool) bool {
	rel = filepath.ToSlash(strings.TrimPrefix(rel, "./"))
	base := filepath.Base(rel)
	if rel == "." || rel == "" {
		return false
	}
	if isDir {
		switch base {
		case ".git", ".benmore", "uploads", "logs", "node_modules", "Benmore", ".claude", ".codex":
			return true
		}
		return strings.HasPrefix(base, "screenshots")
	}
	if strings.HasPrefix(base, "data.db") {
		return true
	}
	switch base {
	case "env.yaml", "secrets.yaml", ".env", ".DS_Store":
		return true
	}
	if strings.HasPrefix(base, ".env.") || strings.HasSuffix(base, ".key") || strings.HasSuffix(base, ".pem") {
		return true
	}
	if strings.HasSuffix(base, ".log") {
		return true
	}
	if rel == "src/bm.d.ts" || strings.HasSuffix(rel, "/src/bm.d.ts") {
		return true
	}
	return false
}

func manifestFileMap(m SourceManifest) map[string]SourceManifestFile {
	out := make(map[string]SourceManifestFile, len(m.Files))
	for _, f := range m.Files {
		if f.Path == "" {
			continue
		}
		ff := f
		ff.Path = filepath.ToSlash(ff.Path)
		out[ff.Path] = ff
	}
	return out
}

func writeRemoteManifest(dir string, m SourceManifest) error {
	if dir == "" {
		return fmt.Errorf("workspace dir is required")
	}
	data, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	meta := filepath.Join(dir, ".benmore")
	if err := os.MkdirAll(meta, 0755); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(meta, "remote.json"), append(data, '\n'), 0644)
}

func readRemoteManifest(dir string) (SourceManifest, bool, error) {
	data, err := os.ReadFile(filepath.Join(dir, ".benmore", "remote.json"))
	if err != nil {
		if os.IsNotExist(err) {
			return SourceManifest{}, false, nil
		}
		return SourceManifest{}, false, err
	}
	var m SourceManifest
	if err := json.Unmarshal(data, &m); err != nil {
		return SourceManifest{}, false, err
	}
	return m, true, nil
}

type SyncFileStatus string

const (
	SyncStatusSynced        SyncFileStatus = "synced"
	SyncStatusLocalChanged  SyncFileStatus = "local_changed"
	SyncStatusRemoteChanged SyncFileStatus = "remote_changed"
	SyncStatusConflict      SyncFileStatus = "conflict"
	SyncStatusLocalOnly     SyncFileStatus = "local_only"
	SyncStatusRemoteOnly    SyncFileStatus = "remote_only"
	SyncStatusDeletedLocal  SyncFileStatus = "deleted_local"
	SyncStatusDeletedRemote SyncFileStatus = "deleted_remote"
)

type SyncFileDiff struct {
	Path       string         `json:"path"`
	Status     SyncFileStatus `json:"status"`
	BaseSHA    string         `json:"base_sha,omitempty"`
	LocalSHA   string         `json:"local_sha,omitempty"`
	RemoteSHA  string         `json:"remote_sha,omitempty"`
	BaseSize   int64          `json:"base_size,omitempty"`
	LocalSize  int64          `json:"local_size,omitempty"`
	RemoteSize int64          `json:"remote_size,omitempty"`
}

type SyncReport struct {
	App           string                 `json:"app,omitempty"`
	Env           string                 `json:"env,omitempty"`
	HasBase       bool                   `json:"has_base"`
	RemoteGitHead string                 `json:"remote_git_head,omitempty"`
	GeneratedAt   string                 `json:"generated_at,omitempty"`
	Files         []SyncFileDiff         `json:"files"`
	Counts        map[SyncFileStatus]int `json:"counts"`
	HasDrift      bool                   `json:"has_drift"`
	HasConflicts  bool                   `json:"has_conflicts"`
}

func DiffSourceManifests(base SourceManifest, hasBase bool, local SourceManifest, remote SourceManifest) SyncReport {
	baseMap := manifestFileMap(base)
	localMap := manifestFileMap(local)
	remoteMap := manifestFileMap(remote)
	pathsSet := map[string]bool{}
	for p := range baseMap {
		pathsSet[p] = true
	}
	for p := range localMap {
		pathsSet[p] = true
	}
	for p := range remoteMap {
		pathsSet[p] = true
	}
	paths := make([]string, 0, len(pathsSet))
	for p := range pathsSet {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	report := SyncReport{
		App:           firstNonEmptyString(remote.App, local.App, base.App),
		Env:           firstNonEmptyString(remote.Env, local.Env, base.Env),
		HasBase:       hasBase,
		RemoteGitHead: remote.ServerGitHead,
		GeneratedAt:   remote.GeneratedAt,
		Counts:        map[SyncFileStatus]int{},
	}
	for _, p := range paths {
		b, bOK := baseMap[p]
		l, lOK := localMap[p]
		r, rOK := remoteMap[p]
		if hasBase && bOK && !lOK && !rOK {
			continue
		}
		status := classifySourceFile(b, bOK && hasBase, l, lOK, r, rOK)
		d := SyncFileDiff{
			Path:       p,
			Status:     status,
			BaseSHA:    maybeSHA(b, bOK && hasBase),
			LocalSHA:   maybeSHA(l, lOK),
			RemoteSHA:  maybeSHA(r, rOK),
			BaseSize:   maybeSize(b, bOK && hasBase),
			LocalSize:  maybeSize(l, lOK),
			RemoteSize: maybeSize(r, rOK),
		}
		report.Files = append(report.Files, d)
		report.Counts[status]++
		if status != SyncStatusSynced {
			report.HasDrift = true
		}
		if status == SyncStatusConflict {
			report.HasConflicts = true
		}
	}
	return report
}

func classifySourceFile(base SourceManifestFile, hasBase bool, local SourceManifestFile, hasLocal bool, remote SourceManifestFile, hasRemote bool) SyncFileStatus {
	if !hasBase {
		switch {
		case hasLocal && hasRemote && local.SHA256 == remote.SHA256:
			return SyncStatusSynced
		case hasLocal && hasRemote:
			return SyncStatusConflict
		case hasLocal:
			return SyncStatusLocalOnly
		case hasRemote:
			return SyncStatusRemoteOnly
		default:
			return SyncStatusSynced
		}
	}

	switch {
	case hasLocal && hasRemote:
		localChanged := local.SHA256 != base.SHA256
		remoteChanged := remote.SHA256 != base.SHA256
		if local.SHA256 == remote.SHA256 {
			return SyncStatusSynced
		}
		switch {
		case localChanged && remoteChanged:
			return SyncStatusConflict
		case localChanged:
			return SyncStatusLocalChanged
		case remoteChanged:
			return SyncStatusRemoteChanged
		default:
			return SyncStatusSynced
		}
	case hasLocal && !hasRemote:
		if local.SHA256 == base.SHA256 {
			return SyncStatusDeletedRemote
		}
		return SyncStatusConflict
	case !hasLocal && hasRemote:
		if remote.SHA256 == base.SHA256 {
			return SyncStatusDeletedLocal
		}
		return SyncStatusConflict
	default:
		return SyncStatusSynced
	}
}

func maybeSHA(f SourceManifestFile, ok bool) string {
	if !ok {
		return ""
	}
	return f.SHA256
}

func maybeSize(f SourceManifestFile, ok bool) int64 {
	if !ok {
		return 0
	}
	return f.Size
}

func pruneDeletedRemoteFiles(root string, report SyncReport) error {
	for _, f := range report.Files {
		if f.Status != SyncStatusDeletedRemote {
			continue
		}
		abs, err := safeManifestJoin(root, f.Path)
		if err != nil {
			return err
		}
		if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return nil
}

func safeManifestJoin(root, rel string) (string, error) {
	return safeJoinUnderRoot(root, rel, "manifest")
}

// safeJoinUnderRoot joins rel under root, refusing empty paths, parent
// segments, and any result that resolves outside root.
func safeJoinUnderRoot(root, rel, label string) (string, error) {
	rel = strings.TrimPrefix(filepath.ToSlash(rel), "/")
	if rel == "" || hasParentPathSegment(rel) {
		return "", fmt.Errorf("path escapes %s root", label)
	}
	joined := filepath.Join(root, filepath.FromSlash(rel))
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	absJoined, err := filepath.Abs(joined)
	if err != nil {
		return "", err
	}
	if absJoined != absRoot && !strings.HasPrefix(absJoined, absRoot+string(filepath.Separator)) {
		return "", fmt.Errorf("path escapes %s root", label)
	}
	return absJoined, nil
}

func hasParentPathSegment(rel string) bool {
	for _, part := range strings.Split(filepath.ToSlash(rel), "/") {
		if part == ".." {
			return true
		}
	}
	return false
}

func firstNonEmptyString(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func sortedStrings(in []string) []string {
	out := append([]string(nil), in...)
	sort.Strings(out)
	return out
}
