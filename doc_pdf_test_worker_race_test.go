//go:build linux && (amd64 || arm64) && !cli && race

package main

import (
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"testing"
	"time"
)

type pdfTestWorkerManifest struct {
	Schema       int      `json:"schema"`
	Binary       string   `json:"binary"`
	SHA256       string   `json:"sha256"`
	SourceCommit string   `json:"source_commit"`
	SourceTree   string   `json:"source_tree"`
	GoVersion    string   `json:"go_version"`
	Edition      string   `json:"edition"`
	GOOS         string   `json:"goos"`
	GOARCH       string   `json:"goarch"`
	Tags         []string `json:"tags"`
}

func appMCPPDFConfigureTestWorker() error {
	path, manifestPath := os.Getenv("BENMORE_PDF_TEST_WORKER"), os.Getenv("BENMORE_PDF_TEST_WORKER_MANIFEST")
	// Focused race tests unrelated to PDF need no extra executable. A complete
	// PDF qualification requires the helper and must never skip if it is absent.
	if path == "" && manifestPath == "" && os.Getenv("BENMORE_REQUIRE_PDF_INTEGRATION") != "1" {
		return nil
	}
	manifest, err := validatePDFTestWorker(path, manifestPath)
	if err != nil {
		return err
	}
	appMCPPDFWorkerExecutable = func() (string, error) { return path, nil }
	fmt.Fprintf(os.Stderr, "PDF test worker verified: path=%s sha256=%s source=%s tree=%s toolchain=%s edition=%s; parent remains race-instrumented\n", path, manifest.SHA256, manifest.SourceCommit, manifest.SourceTree, manifest.GoVersion, manifest.Edition)
	return nil
}

func pdfTestGit(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil {
		return "", fmt.Errorf("source provenance check failed: %w", err)
	}
	return strings.TrimSpace(string(output)), nil
}

func validatePDFTestWorker(path, manifestPath string) (*pdfTestWorkerManifest, error) {
	if path == "" || manifestPath == "" || !filepath.IsAbs(path) || !filepath.IsAbs(manifestPath) || filepath.Clean(path) != path || filepath.Clean(manifestPath) != manifestPath {
		return nil, errors.New("missing or invalid absolute PDF worker/manifest path")
	}
	meta, err := os.Lstat(manifestPath)
	if err != nil || !meta.Mode().IsRegular() || meta.Size() > 64<<10 {
		return nil, errors.New("invalid PDF worker manifest file")
	}
	data, err := os.ReadFile(manifestPath)
	if err != nil {
		return nil, err
	}
	var manifest pdfTestWorkerManifest
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return nil, fmt.Errorf("invalid PDF worker manifest: %w", err)
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF {
		return nil, errors.New("trailing PDF worker manifest data")
	}
	if manifest.Schema != 1 || manifest.Binary != "pdf-worker.test" || filepath.Base(path) != manifest.Binary || manifest.Edition != editionName || manifest.GoVersion != runtime.Version() || manifest.GOOS != runtime.GOOS || manifest.GOARCH != runtime.GOARCH {
		return nil, errors.New("PDF worker manifest edition/toolchain/platform mismatch")
	}
	if decoded, err := hex.DecodeString(manifest.SHA256); err != nil || len(decoded) != sha256.Size || strings.ToLower(manifest.SHA256) != manifest.SHA256 {
		return nil, errors.New("invalid PDF worker digest")
	}
	for _, check := range []struct {
		args []string
		want string
	}{
		{[]string{"rev-parse", "HEAD"}, manifest.SourceCommit},
		{[]string{"rev-parse", "HEAD^{tree}"}, manifest.SourceTree},
		{[]string{"status", "--porcelain", "--untracked-files=all"}, ""},
	} {
		actual, err := pdfTestGit(check.args...)
		if err != nil || actual != check.want {
			return nil, errors.New("PDF worker source does not match the clean test checkout")
		}
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Size() <= 0 || info.Size() > 512<<20 {
		return nil, errors.New("invalid PDF worker executable")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	digest := sha256.New()
	_, copyErr := io.Copy(digest, io.LimitReader(file, (512<<20)+1))
	closeErr := file.Close()
	if copyErr != nil || closeErr != nil || hex.EncodeToString(digest.Sum(nil)) != manifest.SHA256 {
		return nil, errors.New("PDF worker executable digest mismatch")
	}
	child, err := buildinfo.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("PDF worker build metadata unavailable: %w", err)
	}
	parent, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, errors.New("parent test build metadata unavailable")
	}
	if err := validatePDFTestWorkerBuild(child, parent, manifest); err != nil {
		return nil, err
	}
	return &manifest, nil
}

func pdfTestBuildSetting(info *debug.BuildInfo, name string) string {
	for _, setting := range info.Settings {
		if setting.Key == name {
			return setting.Value
		}
	}
	return ""
}

func pdfTestTags(raw string) []string {
	tags := strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' })
	sort.Strings(tags)
	return tags
}

func validatePDFTestWorkerBuild(child, parent *debug.BuildInfo, manifest pdfTestWorkerManifest) error {
	if pdfTestBuildSetting(child, "-race") == "true" {
		return errors.New("PDF worker must not be race-instrumented")
	}
	if pdfTestBuildSetting(parent, "-race") != "true" || child.GoVersion != parent.GoVersion || child.GoVersion != manifest.GoVersion || child.Path != parent.Path || child.Main.Path != parent.Main.Path {
		return errors.New("PDF worker does not match the race parent build")
	}
	// The manifest binds a hash, but the executable must itself attest to the
	// same clean source revision. Both test binaries use -buildvcs=true.
	for _, info := range []*debug.BuildInfo{child, parent} {
		if pdfTestBuildSetting(info, "vcs") != "git" || pdfTestBuildSetting(info, "vcs.revision") != manifest.SourceCommit || pdfTestBuildSetting(info, "vcs.modified") != "false" {
			return errors.New("PDF worker or race parent embedded source provenance mismatch")
		}
	}
	for _, key := range []string{"GOOS", "GOARCH", "GOAMD64", "GOARM64", "CGO_ENABLED", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_LDFLAGS", "-compiler", "-buildmode"} {
		if pdfTestBuildSetting(child, key) != pdfTestBuildSetting(parent, key) {
			return fmt.Errorf("PDF worker %s mismatch", key)
		}
	}
	if !reflect.DeepEqual(pdfTestTags(pdfTestBuildSetting(child, "-tags")), pdfTestTags(pdfTestBuildSetting(parent, "-tags"))) || !reflect.DeepEqual(pdfTestTags(pdfTestBuildSetting(child, "-tags")), manifest.Tags) {
		return errors.New("PDF worker build tags mismatch")
	}
	return nil
}

func TestPDFTestWorkerProvenance(t *testing.T) {
	path, manifestPath := os.Getenv("BENMORE_PDF_TEST_WORKER"), os.Getenv("BENMORE_PDF_TEST_WORKER_MANIFEST")
	valid, err := validatePDFTestWorker(path, manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, pair := range [][2]string{{"", manifestPath}, {path, ""}, {filepath.Join(t.TempDir(), "pdf-worker.test"), manifestPath}, {path, filepath.Join(t.TempDir(), "missing.json")}} {
		if _, err := validatePDFTestWorker(pair[0], pair[1]); err == nil {
			t.Fatal("missing worker or manifest accepted")
		}
	}
	for _, name := range []string{"digest", "edition", "source", "tree", "toolchain", "platform", "tags", "unknown field", "trailing data"} {
		t.Run(name, func(t *testing.T) {
			candidate := *valid
			switch name {
			case "digest":
				candidate.SHA256 = strings.Repeat("0", 64)
			case "edition":
				candidate.Edition = "wrong"
			case "source":
				candidate.SourceCommit = strings.Repeat("0", 40)
			case "tree":
				candidate.SourceTree = strings.Repeat("0", 40)
			case "toolchain":
				candidate.GoVersion = "go0.0.0"
			case "platform":
				candidate.GOARCH = "wrong"
			case "tags":
				candidate.Tags = []string{"wrong"}
			}
			data, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if name == "unknown field" {
				data = append([]byte(`{"unexpected":true,`), data[1:]...)
			}
			if name == "trailing data" {
				data = append(data, []byte(`{}`)...)
			}
			manifestPath := filepath.Join(t.TempDir(), "manifest.json")
			if err := os.WriteFile(manifestPath, data, 0600); err != nil {
				t.Fatal(err)
			}
			if _, err := validatePDFTestWorker(path, manifestPath); err == nil {
				t.Fatal("invalid manifest accepted")
			}
		})
	}
	// Read the actual running race binary's metadata, rather than fabricating
	// a flag, to prove a race-instrumented helper is rejected.
	current, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	raceBuild, err := buildinfo.ReadFile(current)
	if err != nil {
		t.Fatal(err)
	}
	if err := validatePDFTestWorkerBuild(raceBuild, raceBuild, *valid); err == nil || !strings.Contains(err.Error(), "race-instrumented") {
		t.Fatalf("race helper was not refused: %v", err)
	}
	childBuild, err := buildinfo.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"wrong revision", "missing revision", "dirty source", "missing vcs"} {
		t.Run(name, func(t *testing.T) {
			candidate := *childBuild
			candidate.Settings = append([]debug.BuildSetting(nil), childBuild.Settings...)
			for i := range candidate.Settings {
				setting := &candidate.Settings[i]
				switch {
				case name == "wrong revision" && setting.Key == "vcs.revision":
					setting.Value = strings.Repeat("0", 40)
				case name == "missing revision" && setting.Key == "vcs.revision":
					setting.Value = ""
				case name == "dirty source" && setting.Key == "vcs.modified":
					setting.Value = "true"
				case name == "missing vcs" && setting.Key == "vcs":
					setting.Value = ""
				}
			}
			if err := validatePDFTestWorkerBuild(&candidate, raceBuild, *valid); err == nil || !strings.Contains(err.Error(), "embedded source provenance") {
				t.Fatalf("invalid compiled source provenance accepted: %v", err)
			}
		})
	}
}
