package main

// Feature-pack export and source metadata discovery.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

func ExportFeaturePackFromDir(dir string, pack FeaturePack, paths, models, flows []string) (FeaturePack, map[string][]byte, error) {
	if dir == "" {
		return FeaturePack{}, nil, fmt.Errorf("source dir is required")
	}
	if pack.APIVersion == "" {
		pack.APIVersion = featurePackAPIVersion
	}
	if pack.Kind == "" {
		pack.Kind = "FeaturePack"
	}
	if pack.Version == "" {
		pack.Version = "1.0.0"
	}
	if pack.CreatedAt == "" {
		pack.CreatedAt = time.Now().UTC().Format(time.RFC3339)
	}
	if pack.Slug == "" {
		pack.Slug = slugifyFeatureName(pack.Name)
	}
	if pack.Slug == "" {
		return FeaturePack{}, nil, fmt.Errorf("pack name/slug is required")
	}
	selected := map[string]bool{}
	explicitSelected := map[string]bool{}
	for _, p := range paths {
		for _, part := range splitCSV(p) {
			part = filepath.ToSlash(strings.TrimSpace(part))
			selected[part] = true
			explicitSelected[part] = true
		}
	}
	for _, f := range flows {
		for _, part := range splitCSV(f) {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if !strings.Contains(part, "/") {
				part = "flows/" + part
			}
			if filepath.Ext(part) == "" {
				part += ".yaml"
			}
			part = filepath.ToSlash(part)
			selected[part] = true
			explicitSelected[part] = true
		}
	}
	modelNames := []string{}
	for _, m := range models {
		modelNames = append(modelNames, splitCSV(m)...)
	}
	if len(selected) == 0 && len(modelNames) == 0 {
		manifest, err := BuildSourceManifest(dir, SourceManifestOptions{})
		if err != nil {
			return FeaturePack{}, nil, err
		}
		for _, f := range manifest.Files {
			selected[f.Path] = true
		}
		pack.WholeSource = true
	}

	// As in the source manifest, hold each directory by handle and match
	// regular-file opens against lstat. An app may rewrite its tree while
	// the router exports it; os.Root alone follows in-root symlink aliases.
	root, err := openTreeDir(dir)
	if err != nil {
		return FeaturePack{}, nil, err
	}
	defer root.Close()
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return FeaturePack{}, nil, err
	}
	files := map[string][]byte{}
	// The pack's limits are enforced while reading, not after: an export
	// runs in the router (viewer-level feature_export) and used to read every
	// selected file whole before FeaturePackTarGzBytes refused an oversized
	// pack. Paths are read in order so a refusal names the same file each
	// time.
	order := make([]string, 0, len(selected))
	for p := range selected {
		order = append(order, p)
	}
	sort.Strings(order)
	var total int64
	for _, p := range order {
		if p == "" || featurePackPathProtected(p) {
			continue
		}
		// feature.yaml is the pack's other entry.
		if featurePackLimits.MaxFiles > 0 && len(files)+2 > featurePackLimits.MaxFiles {
			return FeaturePack{}, nil, fmt.Errorf("feature pack has too many files: max %d", featurePackLimits.MaxFiles)
		}
		abs, err := safeFeatureJoin(dir, p)
		if err != nil {
			return FeaturePack{}, nil, err
		}
		rel, err := filepath.Rel(absDir, abs)
		if err != nil {
			return FeaturePack{}, nil, err
		}
		b, err := readFeaturePackSourceLimited(root, rel, featurePackReadLimit(total))
		if err != nil {
			if !explicitSelected[p] && (os.IsNotExist(err) || errors.Is(err, errTreeNotRegular) || errors.Is(err, errTreeNotDir)) {
				continue
			}
			return FeaturePack{}, nil, fmt.Errorf("read selected path %s: %w", p, err)
		}
		total += int64(len(b))
		files[p] = b
		pack.Files = append(pack.Files, FeaturePackFile{Path: p, SHA256: hashBytesSHA256(b), Size: int64(len(b))})
		if strings.HasPrefix(p, "static/") {
			pack.StaticAssets = appendUnique(pack.StaticAssets, p)
			pack.Routes = appendUnique(pack.Routes, routeForStaticPath(p))
		}
		if strings.HasPrefix(p, "flows/") {
			pack.Flows = appendUnique(pack.Flows, strings.TrimSuffix(strings.TrimPrefix(p, "flows/"), filepath.Ext(p)))
		}
		if strings.HasPrefix(p, "hooks") {
			pack.Hooks = appendUnique(pack.Hooks, p)
		}
		pack.Routes = appendUniqueMany(pack.Routes, scanFeatureRoutes(string(b))...)
		pack.EnvRefs = appendUniqueMany(pack.EnvRefs, scanFeatureEnvRefs(string(b))...)
	}
	if len(modelNames) > 0 {
		modelSrc, err := readFeaturePackSource(root, "schema.prisma")
		if err != nil {
			return FeaturePack{}, nil, fmt.Errorf("read schema.prisma for models: %w", err)
		}
		extracted, err := extractPrismaModels(string(modelSrc), modelNames)
		if err != nil {
			return FeaturePack{}, nil, err
		}
		pack.SchemaModels = append(pack.SchemaModels, extracted...)
	}
	sort.Slice(pack.Files, func(i, j int) bool { return pack.Files[i].Path < pack.Files[j].Path })
	sort.Strings(pack.Flows)
	sort.Strings(pack.Hooks)
	sort.Strings(pack.Routes)
	sort.Strings(pack.StaticAssets)
	sort.Strings(pack.EnvRefs)
	return pack, files, nil
}

// featurePackBeforeRead lets tests deterministically replace a selected file
// or its parent directory just before the file is opened.
var featurePackBeforeRead = func(path string) {}

// errFeaturePackTooLarge: a selected file, or the pack so far, is over the
// pack's size limits.
var errFeaturePackTooLarge = errors.New("feature pack size limit")

// featurePackReadLimit is how many bytes the next file may have: one entry's
// limit, or what is left of the pack's uncompressed budget if less (-1: no
// limit configured).
func featurePackReadLimit(total int64) int64 {
	limit := int64(-1)
	if entry := featurePackLimits.MaxEntryBytes; entry > 0 {
		limit = entry
	}
	if max := featurePackLimits.MaxUncompressedBytes; max > 0 {
		left := max - total
		if left < 0 {
			left = 0
		}
		if limit < 0 || left < limit {
			limit = left
		}
	}
	return limit
}

func readFeaturePackSource(top *treeDir, rel string) ([]byte, error) {
	return readFeaturePackSourceLimited(top, rel, featurePackReadLimit(0))
}

// readFeaturePackSourceLimited reads one source file of at most limit bytes
// (-1: unlimited). The size is judged on the opened handle before anything is
// read and the read itself is capped, so a file that grows meanwhile cannot
// push the reader past it either.
func readFeaturePackSourceLimited(top *treeDir, rel string, limit int64) ([]byte, error) {
	rel = filepath.Clean(filepath.FromSlash(rel))
	if rel == "." || !filepath.IsLocal(rel) {
		return nil, fmt.Errorf("invalid feature source path")
	}
	parts := strings.Split(filepath.ToSlash(rel), "/")
	dir := top
	for _, part := range parts[:len(parts)-1] {
		next, err := dir.openDir(part)
		if dir != top {
			dir.Close()
		}
		if err != nil {
			return nil, err
		}
		dir = next
	}
	if dir != top {
		defer dir.Close()
	}
	featurePackBeforeRead(filepath.ToSlash(rel))
	f, _, err := dir.openRegular(parts[len(parts)-1])
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if limit < 0 {
		return io.ReadAll(f)
	}
	st, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if st.Size() > limit {
		return nil, fmt.Errorf("%w: %s is %d bytes, %d allowed (max %d per file, %d per pack)", errFeaturePackTooLarge, filepath.ToSlash(rel), st.Size(), limit, featurePackLimits.MaxEntryBytes, featurePackLimits.MaxUncompressedBytes)
	}
	b, err := io.ReadAll(io.LimitReader(f, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%w: %s grew past %d bytes while it was read", errFeaturePackTooLarge, filepath.ToSlash(rel), limit)
	}
	return b, nil
}

func extractPrismaModels(src string, names []string) ([]FeaturePackModel, error) {
	want := map[string]bool{}
	for _, n := range names {
		n = strings.TrimSpace(n)
		if n != "" {
			want[n] = true
		}
	}
	blocks := prismaModelBlocks(src)
	var out []FeaturePackModel
	for name, block := range blocks {
		if !want[name] {
			continue
		}
		out = append(out, curatedModel(name, block))
		delete(want, name)
	}
	if len(want) > 0 {
		missing := make([]string, 0, len(want))
		for n := range want {
			missing = append(missing, n)
		}
		sort.Strings(missing)
		return nil, fmt.Errorf("models not found in schema.prisma: %s", strings.Join(missing, ", "))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

func prismaModelBlocks(src string) map[string]string {
	out := map[string]string{}
	re := regexp.MustCompile(`(?m)^model\s+([A-Za-z][A-Za-z0-9_]*)\s*\{`)
	locs := re.FindAllStringSubmatchIndex(src, -1)
	for _, loc := range locs {
		name := src[loc[2]:loc[3]]
		start := loc[0]
		open := strings.Index(src[loc[0]:], "{")
		if open < 0 {
			continue
		}
		i := loc[0] + open
		depth := 0
		end := -1
	scan:
		for ; i < len(src); i++ {
			switch src[i] {
			case '{':
				depth++
			case '}':
				depth--
				if depth == 0 {
					end = i + 1
					break scan
				}
			}
		}
		if end > start {
			out[name] = strings.TrimSpace(src[start:end])
		}
	}
	return out
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

func appendUnique(in []string, v string) []string {
	if v == "" {
		return in
	}
	for _, existing := range in {
		if existing == v {
			return in
		}
	}
	return append(in, v)
}

func appendUniqueMany(in []string, vals ...string) []string {
	for _, v := range vals {
		in = appendUnique(in, v)
	}
	return in
}

func slugifyFeatureName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	var b strings.Builder
	lastDash := false
	for _, r := range s {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
			lastDash = false
			continue
		}
		if !lastDash {
			b.WriteByte('-')
			lastDash = true
		}
	}
	return strings.Trim(b.String(), "-")
}

func scanFeatureEnvRefs(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range envRefRE.FindAllString(s, -1) {
		if !seen[m] {
			seen[m] = true
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

func scanFeatureRoutes(s string) []string {
	seen := map[string]bool{}
	var out []string
	for _, m := range featureRoutePathRE.FindAllStringSubmatch(s, -1) {
		if len(m) < 2 || seen[m[1]] {
			continue
		}
		seen[m[1]] = true
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}
