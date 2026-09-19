package main

// Feature-pack archive serialization, bounded decoding, and payload limits.

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

func FeaturePackTarGzBytes(pack FeaturePack, files map[string][]byte) ([]byte, error) {
	manifest, err := yaml.Marshal(pack)
	if err != nil {
		return nil, err
	}
	if err := validateFeaturePackPayloadLimits(pack, files, len(manifest)); err != nil {
		return nil, err
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	if err := writeTarFile(tw, "feature.yaml", manifest, 0644); err != nil {
		return nil, err
	}
	paths := make([]string, 0, len(pack.Files))
	for _, f := range pack.Files {
		paths = append(paths, f.Path)
	}
	sort.Strings(paths)
	for _, p := range paths {
		if err := writeTarFile(tw, filepath.ToSlash(filepath.Join("files", p)), files[p], 0644); err != nil {
			return nil, err
		}
	}
	if err := tw.Close(); err != nil {
		return nil, err
	}
	if err := gz.Close(); err != nil {
		return nil, err
	}
	if err := validateFeaturePackArchiveSize(buf.Len()); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

func WriteFeaturePackTarGz(path string, pack FeaturePack, files map[string][]byte) error {
	body, err := FeaturePackTarGzBytes(pack, files)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0644)
}

func validateFeaturePackPayloadLimits(pack FeaturePack, files map[string][]byte, manifestBytes int) error {
	if featurePackLimits.MaxFiles > 0 && len(pack.Files)+1 > featurePackLimits.MaxFiles {
		return fmt.Errorf("feature pack has too many files: max %d", featurePackLimits.MaxFiles)
	}
	if len(files) != len(pack.Files) {
		return fmt.Errorf("feature pack file manifest/body mismatch")
	}
	if featurePackLimits.MaxManifestBytes > 0 && int64(manifestBytes) > featurePackLimits.MaxManifestBytes {
		return fmt.Errorf("feature.yaml exceeds max size %d bytes", featurePackLimits.MaxManifestBytes)
	}
	var total int64
	seen := map[string]bool{}
	for _, f := range pack.Files {
		p := filepath.ToSlash(f.Path)
		if seen[p] {
			return fmt.Errorf("feature pack declares duplicate file %q", p)
		}
		seen[p] = true
		body, ok := files[f.Path]
		if !ok {
			return fmt.Errorf("feature pack missing body for %q", p)
		}
		if featurePackLimits.MaxEntryBytes > 0 && int64(len(body)) > featurePackLimits.MaxEntryBytes {
			return fmt.Errorf("pack entry files/%s exceeds max size %d bytes", filepath.ToSlash(p), featurePackLimits.MaxEntryBytes)
		}
		total += int64(len(body))
	}
	for p := range files {
		if !seen[filepath.ToSlash(p)] {
			return fmt.Errorf("feature pack has undeclared body for %q", filepath.ToSlash(p))
		}
	}
	if featurePackLimits.MaxUncompressedBytes > 0 && total > featurePackLimits.MaxUncompressedBytes {
		return fmt.Errorf("feature pack uncompressed size exceeds max %d bytes", featurePackLimits.MaxUncompressedBytes)
	}
	return nil
}

func validateFeaturePackArchiveSize(n int) error {
	if featurePackLimits.MaxArchiveBytes > 0 && n > featurePackLimits.MaxArchiveBytes {
		return fmt.Errorf("feature pack archive exceeds max %d bytes", featurePackLimits.MaxArchiveBytes)
	}
	return nil
}

func writeTarFile(tw *tar.Writer, name string, body []byte, mode int64) error {
	h := &tar.Header{Name: filepath.ToSlash(name), Mode: mode, Size: int64(len(body)), ModTime: time.Now().UTC()}
	if err := tw.WriteHeader(h); err != nil {
		return err
	}
	_, err := tw.Write(body)
	return err
}

func ReadFeaturePackTarGz(r io.Reader) (FeaturePack, map[string][]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return FeaturePack{}, nil, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	files := map[string][]byte{}
	var pack FeaturePack
	entryCount := 0
	var totalSize int64
	for {
		h, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return FeaturePack{}, nil, err
		}
		name := filepath.ToSlash(h.Name)
		if strings.HasPrefix(name, "/") || hasParentPathSegment(name) {
			return FeaturePack{}, nil, fmt.Errorf("pack contains unsafe path %q", name)
		}
		// Count EVERY header (incl. symlink/hardlink/dir entries that we
		// skip below) against MaxFiles - otherwise a gzip of millions of
		// non-regular headers is a cheap single-request CPU DoS.
		entryCount++
		if featurePackLimits.MaxFiles > 0 && entryCount > featurePackLimits.MaxFiles {
			return FeaturePack{}, nil, fmt.Errorf("feature pack has too many files: max %d", featurePackLimits.MaxFiles)
		}
		if h.Typeflag != tar.TypeReg {
			continue
		}
		if h.Size < 0 {
			return FeaturePack{}, nil, fmt.Errorf("pack contains negative-size entry %q", name)
		}
		entryLimit := featurePackLimits.MaxEntryBytes
		if name == "feature.yaml" && featurePackLimits.MaxManifestBytes > 0 && (entryLimit == 0 || featurePackLimits.MaxManifestBytes < entryLimit) {
			entryLimit = featurePackLimits.MaxManifestBytes
		}
		if entryLimit > 0 && h.Size > entryLimit {
			return FeaturePack{}, nil, fmt.Errorf("pack entry %s exceeds max size %d bytes", name, entryLimit)
		}
		totalSize += h.Size
		if featurePackLimits.MaxUncompressedBytes > 0 && totalSize > featurePackLimits.MaxUncompressedBytes {
			return FeaturePack{}, nil, fmt.Errorf("feature pack uncompressed size exceeds max %d bytes", featurePackLimits.MaxUncompressedBytes)
		}
		body, err := io.ReadAll(tr)
		if err != nil {
			return FeaturePack{}, nil, err
		}
		if name == "feature.yaml" {
			if err := yaml.Unmarshal(body, &pack); err != nil {
				return FeaturePack{}, nil, err
			}
			continue
		}
		if strings.HasPrefix(name, "files/") {
			files[strings.TrimPrefix(name, "files/")] = body
		}
	}
	if pack.APIVersion == "" {
		return FeaturePack{}, nil, fmt.Errorf("feature.yaml missing from pack")
	}
	if pack.APIVersion != featurePackAPIVersion {
		return FeaturePack{}, nil, fmt.Errorf("unsupported feature pack api_version %q", pack.APIVersion)
	}
	if featurePackLimits.MaxFiles > 0 && len(pack.Files)+1 > featurePackLimits.MaxFiles {
		return FeaturePack{}, nil, fmt.Errorf("feature pack has too many files: max %d", featurePackLimits.MaxFiles)
	}
	return pack, files, nil
}
