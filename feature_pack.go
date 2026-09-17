package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gopkg.in/yaml.v3"
)

const featurePackAPIVersion = "benmore.feature/v1"

type featurePackLimitConfig struct {
	MaxArchiveBytes      int
	MaxUncompressedBytes int64
	MaxEntryBytes        int64
	MaxManifestBytes     int64
	MaxFiles             int
}

var featurePackLimits = featurePackLimitConfig{
	MaxArchiveBytes:      64 * 1024 * 1024,
	MaxUncompressedBytes: 128 * 1024 * 1024,
	MaxEntryBytes:        64 * 1024 * 1024,
	MaxManifestBytes:     1 * 1024 * 1024,
	MaxFiles:             2000,
}

type FeaturePack struct {
	APIVersion      string              `yaml:"api_version" json:"api_version"`
	Kind            string              `yaml:"kind" json:"kind"`
	Name            string              `yaml:"name" json:"name"`
	Slug            string              `yaml:"slug" json:"slug"`
	Version         string              `yaml:"version" json:"version"`
	Source          FeaturePackSource   `yaml:"source" json:"source"`
	CreatedAt       string              `yaml:"created_at" json:"created_at"`
	WholeSource     bool                `yaml:"whole_source,omitempty" json:"whole_source,omitempty"`
	Files           []FeaturePackFile   `yaml:"files" json:"files"`
	SchemaModels    []FeaturePackModel  `yaml:"schema_models,omitempty" json:"schema_models,omitempty"`
	Flows           []string            `yaml:"flows,omitempty" json:"flows,omitempty"`
	Hooks           []string            `yaml:"hooks,omitempty" json:"hooks,omitempty"`
	Routes          []string            `yaml:"routes,omitempty" json:"routes,omitempty"`
	StaticAssets    []string            `yaml:"static_assets,omitempty" json:"static_assets,omitempty"`
	EnvRefs         []string            `yaml:"env_refs,omitempty" json:"env_refs,omitempty"`
	RequiredOptions []FeaturePackOption `yaml:"required_options,omitempty" json:"required_options,omitempty"`
}

type FeaturePackSource struct {
	App string `yaml:"app,omitempty" json:"app,omitempty"`
	Env string `yaml:"env,omitempty" json:"env,omitempty"`
}

type FeaturePackFile struct {
	Path   string `yaml:"path" json:"path"`
	SHA256 string `yaml:"sha256" json:"sha256"`
	Size   int64  `yaml:"size" json:"size"`
}

type FeaturePackModel struct {
	Name   string   `yaml:"name" json:"name"`
	Table  string   `yaml:"table,omitempty" json:"table,omitempty"`
	Fields []string `yaml:"fields,omitempty" json:"fields,omitempty"`
	Source string   `yaml:"source,omitempty" json:"source,omitempty"`
}

type FeaturePackOption struct {
	Name        string `yaml:"name" json:"name"`
	Description string `yaml:"description,omitempty" json:"description,omitempty"`
}

type FeatureCatalogEntry struct {
	Slug        string `json:"slug"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

type FeatureInstallPlan struct {
	Pack            string              `json:"pack"`
	Slug            string              `json:"slug"`
	DryRun          bool                `json:"dry_run"`
	Replace         bool                `json:"replace,omitempty"`
	DeleteMissing   bool                `json:"delete_missing,omitempty"`
	RoutePrefix     string              `json:"route_prefix,omitempty"`
	ModelPrefix     string              `json:"model_prefix,omitempty"`
	RouteMap        map[string]string   `json:"route_map,omitempty"`
	ModelMap        map[string]string   `json:"model_map,omitempty"`
	FileRenames     []FeaturePackRename `json:"file_renames,omitempty"`
	RouteRenames    []FeaturePackRename `json:"route_renames,omitempty"`
	ModelRenames    []FeaturePackRename `json:"model_renames,omitempty"`
	FileAdds        []string            `json:"file_adds,omitempty"`
	FileUpdates     []string            `json:"file_updates,omitempty"`
	FileDeletes     []string            `json:"file_deletes,omitempty"`
	SchemaAdds      []string            `json:"schema_adds,omitempty"`
	EnvRefs         []string            `json:"env_refs,omitempty"`
	RequiredOptions []FeaturePackOption `json:"required_options,omitempty"`
	Collisions      []string            `json:"collisions,omitempty"`
	Blocked         bool                `json:"blocked"`
}

type FeatureInstallOptions struct {
	DryRun        bool   `json:"dry_run"`
	Replace       bool   `json:"replace,omitempty"`
	DeleteMissing bool   `json:"delete_missing,omitempty"`
	RoutePrefix   string `json:"route_prefix,omitempty"`
	ModelPrefix   string `json:"model_prefix,omitempty"`
	RouteMap      map[string]string
	ModelMap      map[string]string
}

type FeaturePackRename struct {
	From string `json:"from"`
	To   string `json:"to"`
}

func featureCatalog() []FeatureCatalogEntry {
	return []FeatureCatalogEntry{
		{Slug: "kanban", Name: "Kanban", Version: "1.0.0", Description: "Boards, columns, cards, status history, and a drag/drop page shell."},
		{Slug: "notify-hub", Name: "Notify Hub", Version: "1.0.0", Description: "Notifications inbox, preferences, broadcast flow, and unread counts."},
		{Slug: "foundry", Name: "Foundry Clone", Version: "1.0.0", Description: "Project intake, artifact review, evaluation status, and a foundry-style workspace page."},
		{Slug: "approvals", Name: "Approvals Queue", Version: "1.0.0", Description: "Request/approve/reject workflow starter."},
		{Slug: "crm-pipeline", Name: "CRM Pipeline", Version: "1.0.0", Description: "Leads, stages, activities, and pipeline board starter."},
		{Slug: "audit-feed", Name: "Audit Activity Feed", Version: "1.0.0", Description: "Append-only activity rows and a timeline page."},
	}
}

func featureCatalogSlugs() map[string]FeatureCatalogEntry {
	out := map[string]FeatureCatalogEntry{}
	for _, e := range featureCatalog() {
		out[e.Slug] = e
	}
	return out
}

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

	files := map[string][]byte{}
	for p := range selected {
		if p == "" || sourceManifestExcluded(p, false) {
			continue
		}
		abs, err := safeFeatureJoin(dir, p)
		if err != nil {
			return FeaturePack{}, nil, err
		}
		info, err := os.Stat(abs)
		if err != nil || info.IsDir() {
			if explicitSelected[p] {
				if err == nil {
					err = fmt.Errorf("selected path is a directory")
				}
				return FeaturePack{}, nil, fmt.Errorf("selected path %s not found: %w", p, err)
			}
			continue
		}
		b, err := os.ReadFile(abs)
		if err != nil {
			return FeaturePack{}, nil, err
		}
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
		modelSrc, err := os.ReadFile(filepath.Join(dir, "schema.prisma"))
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

func PlanFeatureInstall(dir string, pack FeaturePack, files map[string][]byte, dryRun bool) (FeatureInstallPlan, error) {
	return PlanFeatureInstallWithOptions(dir, pack, files, FeatureInstallOptions{DryRun: dryRun})
}

func PlanFeatureInstallWithOptions(dir string, pack FeaturePack, files map[string][]byte, opts FeatureInstallOptions) (FeatureInstallPlan, error) {
	pack, files, fileRenames, routeRenames, modelRenames, transformErr := prepareFeaturePackForInstall(pack, files, opts)
	plan := FeatureInstallPlan{
		Pack:            pack.Name,
		Slug:            pack.Slug,
		DryRun:          opts.DryRun,
		Replace:         opts.Replace,
		DeleteMissing:   opts.DeleteMissing,
		RoutePrefix:     normalizedRoutePrefix(opts.RoutePrefix),
		ModelPrefix:     normalizedModelPrefix(opts.ModelPrefix),
		RouteMap:        sortedStringMap(opts.RouteMap),
		ModelMap:        sortedStringMap(opts.ModelMap),
		FileRenames:     fileRenames,
		RouteRenames:    routeRenames,
		ModelRenames:    modelRenames,
		EnvRefs:         sortedStrings(pack.EnvRefs),
		RequiredOptions: pack.RequiredOptions,
	}
	if transformErr != nil {
		plan.Collisions = append(plan.Collisions, transformErr.Error())
	}
	deleteMissingAllowed := opts.DeleteMissing
	if opts.DeleteMissing && !opts.Replace {
		plan.Collisions = append(plan.Collisions, "delete_missing requires replace")
		deleteMissingAllowed = false
	}
	if opts.DeleteMissing && (plan.RoutePrefix != "" || plan.ModelPrefix != "" || len(plan.RouteMap) > 0 || len(plan.ModelMap) > 0) {
		plan.Collisions = append(plan.Collisions, "delete_missing cannot be combined with route/model transforms")
		deleteMissingAllowed = false
	}
	manifestFiles := map[string]FeaturePackFile{}
	for _, f := range pack.Files {
		manifestFiles[filepath.ToSlash(f.Path)] = f
	}
	if opts.DeleteMissing {
		if !pack.WholeSource {
			plan.Collisions = append(plan.Collisions, "delete_missing requires a whole-source pack exported without --paths/--models/--flows")
			deleteMissingAllowed = false
		}
		if !featurePackIncludesWholeSourceRoot(manifestFiles) {
			plan.Collisions = append(plan.Collisions, "delete_missing requires a whole-source pack containing app.yaml and schema.prisma")
			deleteMissingAllowed = false
		}
		if len(pack.SchemaModels) > 0 {
			if _, ok := manifestFiles["schema.prisma"]; !ok {
				plan.Collisions = append(plan.Collisions, "delete_missing cannot prune target source from a schema-model-only pack; include schema.prisma in the pack files")
				deleteMissingAllowed = false
			}
		}
	}
	packFilePresent := map[string]bool{}
	for p, body := range files {
		p = filepath.ToSlash(p)
		packFilePresent[p] = true
		if featurePackPathProtected(p) || strings.HasPrefix(filepath.ToSlash(p), "files/") {
			plan.Collisions = append(plan.Collisions, p+": protected path")
			continue
		}
		// The apply path writes pack bytes directly, bypassing the write_file
		// secret gate. Run the same high-confidence scan here so a pack can't
		// smuggle a provider secret into the target's git history / CDN.
		if !featurePackLooksBinary(body) {
			if msg := validateNoCommittedSecrets(p, string(body)); msg != "" {
				plan.Collisions = append(plan.Collisions, p+": hardcoded secret")
				continue
			}
		}
		declared, ok := manifestFiles[p]
		if !ok {
			plan.Collisions = append(plan.Collisions, p+": missing from feature.yaml")
			continue
		}
		if got := hashBytesSHA256(body); declared.SHA256 != "" && got != declared.SHA256 {
			plan.Collisions = append(plan.Collisions, p+": sha256 mismatch")
			continue
		}
		abs, err := safeFeatureJoin(dir, p)
		if err != nil {
			plan.Collisions = append(plan.Collisions, p+": "+err.Error())
			continue
		}
		if _, err := os.Stat(abs); err == nil {
			if opts.Replace {
				plan.FileUpdates = append(plan.FileUpdates, filepath.ToSlash(p))
			} else {
				plan.Collisions = append(plan.Collisions, p+": file exists")
			}
			continue
		} else if !os.IsNotExist(err) {
			// A stat error that isn't "absent" (permission/IO) must not be
			// treated as a fresh add: apply would overwrite the existing
			// file without replace consent, and a failed install's cleanup
			// would then delete it as a phantom FileAdd.
			plan.Collisions = append(plan.Collisions, p+": "+err.Error())
			continue
		}
		if hashBytesSHA256(body) == "" {
			plan.Collisions = append(plan.Collisions, p+": empty hash")
			continue
		}
		plan.FileAdds = append(plan.FileAdds, filepath.ToSlash(p))
	}
	for p := range manifestFiles {
		if !packFilePresent[p] {
			plan.Collisions = append(plan.Collisions, p+": missing from archive")
		}
	}
	existing := map[string]bool{}
	models, err := LoadSchemaModelsForDrift(dir)
	if err != nil {
		// The schema file exists but couldn't be parsed - failing here
		// beats silently skipping the "model already exists" collision
		// check and appending a duplicate model block.
		return plan, fmt.Errorf("read existing schema for collision check: %w", err)
	}
	for _, m := range models {
		existing[m.Name] = true
	}
	for _, m := range pack.SchemaModels {
		if existing[m.Name] {
			plan.Collisions = append(plan.Collisions, "model "+m.Name+": already exists")
			continue
		}
		if strings.TrimSpace(m.Source) == "" {
			plan.Collisions = append(plan.Collisions, "model "+m.Name+": missing source")
			continue
		}
		plan.SchemaAdds = append(plan.SchemaAdds, m.Name)
	}
	if opts.DeleteMissing && deleteMissingAllowed {
		targetManifest, err := BuildSourceManifest(dir, SourceManifestOptions{})
		if err != nil {
			return plan, err
		}
		for _, f := range targetManifest.Files {
			if _, ok := manifestFiles[f.Path]; !ok {
				plan.FileDeletes = append(plan.FileDeletes, f.Path)
			}
		}
	}
	sort.Strings(plan.FileAdds)
	sort.Strings(plan.FileUpdates)
	sort.Strings(plan.FileDeletes)
	sort.Strings(plan.SchemaAdds)
	sort.Strings(plan.Collisions)
	sortFeaturePackRenames(plan.FileRenames)
	sortFeaturePackRenames(plan.RouteRenames)
	sortFeaturePackRenames(plan.ModelRenames)
	plan.Blocked = len(plan.Collisions) > 0 || len(plan.RequiredOptions) > 0
	return plan, nil
}

func featurePackIncludesWholeSourceRoot(files map[string]FeaturePackFile) bool {
	for _, required := range []string{"app.yaml", "schema.prisma"} {
		if _, ok := files[required]; !ok {
			return false
		}
	}
	return true
}

func ApplyFeaturePackToDir(dir string, pack FeaturePack, files map[string][]byte) (FeatureInstallPlan, error) {
	return ApplyFeaturePackToDirWithOptions(dir, pack, files, FeatureInstallOptions{})
}

var featurePackApplyAfterWriteHook func(dir, rel string) error

func ApplyFeaturePackToDirWithOptions(dir string, pack FeaturePack, files map[string][]byte, opts FeatureInstallOptions) (FeatureInstallPlan, error) {
	opts.DryRun = false
	plan, err := PlanFeatureInstallWithOptions(dir, pack, files, opts)
	if err != nil {
		return plan, err
	}
	if plan.Blocked {
		return plan, fmt.Errorf("feature install blocked")
	}
	preparedPack, preparedFiles, _, _, _, transformErr := prepareFeaturePackForInstall(pack, files, opts)
	if transformErr != nil {
		return plan, transformErr
	}
	pack = preparedPack
	files = preparedFiles
	if len(pack.SchemaModels) > 0 {
		schemaPath := filepath.Join(dir, "schema.prisma")
		var b strings.Builder
		existing, err := os.ReadFile(schemaPath)
		if err != nil && !os.IsNotExist(err) {
			// A read failure that isn't "file absent" (permission/IO) must
			// not be treated as an empty schema - that would replace the
			// app's schema.prisma with only the pack's models.
			return plan, fmt.Errorf("read existing schema.prisma: %w", err)
		}
		if err == nil {
			b.Write(existing)
			if !strings.HasSuffix(string(existing), "\n") {
				b.WriteString("\n")
			}
		}
		for _, m := range pack.SchemaModels {
			b.WriteString("\n")
			b.WriteString(strings.TrimSpace(m.Source))
			b.WriteString("\n")
		}
		if err := os.WriteFile(schemaPath, []byte(b.String()), 0664); err != nil {
			return plan, err
		}
	}
	for p, body := range files {
		abs, err := safeFeatureJoin(dir, p)
		if err != nil {
			return plan, err
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0755); err != nil {
			return plan, err
		}
		if err := os.WriteFile(abs, body, 0664); err != nil {
			return plan, err
		}
		if featurePackApplyAfterWriteHook != nil {
			if err := featurePackApplyAfterWriteHook(dir, p); err != nil {
				return plan, err
			}
		}
	}
	for _, p := range plan.FileDeletes {
		abs, err := safeFeatureJoin(dir, p)
		if err != nil {
			return plan, err
		}
		if err := os.Remove(abs); err != nil && !os.IsNotExist(err) {
			return plan, err
		}
	}
	return plan, nil
}

func prepareFeaturePackForInstall(pack FeaturePack, files map[string][]byte, opts FeatureInstallOptions) (FeaturePack, map[string][]byte, []FeaturePackRename, []FeaturePackRename, []FeaturePackRename, error) {
	pack.Files = append([]FeaturePackFile(nil), pack.Files...)
	pack.SchemaModels = append([]FeaturePackModel(nil), pack.SchemaModels...)
	pack.Flows = append([]string(nil), pack.Flows...)
	pack.Hooks = append([]string(nil), pack.Hooks...)
	pack.Routes = append([]string(nil), pack.Routes...)
	pack.StaticAssets = append([]string(nil), pack.StaticAssets...)
	pack.EnvRefs = append([]string(nil), pack.EnvRefs...)
	pack.RequiredOptions = append([]FeaturePackOption(nil), pack.RequiredOptions...)
	rawRoutePrefix := filepath.ToSlash(strings.TrimSpace(opts.RoutePrefix))
	routePrefix := normalizedRoutePrefix(opts.RoutePrefix)
	modelPrefix := normalizedModelPrefix(opts.ModelPrefix)
	explicitRouteMap, routeMapErr := normalizeFeatureRouteMap(opts.RouteMap)
	explicitModelMap, modelMapErr := normalizeFeatureModelMap(opts.ModelMap)
	var fileRenames []FeaturePackRename
	var routeRenames []FeaturePackRename
	var modelRenames []FeaturePackRename
	if strings.TrimSpace(opts.RoutePrefix) != "" && routePrefix == "" {
		return pack, files, nil, nil, nil, fmt.Errorf("route_prefix must contain at least one safe path segment")
	}
	if strings.TrimSpace(opts.ModelPrefix) != "" && modelPrefix == "" {
		return pack, files, nil, nil, nil, fmt.Errorf("model_prefix must contain at least one identifier character")
	}
	if rawRoutePrefix != "" && hasParentPathSegment(rawRoutePrefix) {
		return pack, files, nil, nil, nil, fmt.Errorf("route_prefix cannot contain ..")
	}
	if routeMapErr != nil {
		return pack, files, nil, nil, nil, routeMapErr
	}
	if modelMapErr != nil {
		return pack, files, nil, nil, nil, modelMapErr
	}

	modelMap := map[string]string{}
	tableMap := map[string]string{}
	routeMap := map[string]string{}
	packModelNames := map[string]bool{}
	for _, m := range pack.SchemaModels {
		if strings.TrimSpace(m.Name) != "" {
			packModelNames[m.Name] = true
		}
	}
	for old := range explicitModelMap {
		if !packModelNames[old] {
			return pack, files, fileRenames, routeRenames, modelRenames, fmt.Errorf("model_map references missing model %s", old)
		}
	}
	for _, m := range pack.SchemaModels {
		if strings.TrimSpace(m.Name) == "" {
			continue
		}
		next := ""
		if explicit := explicitModelMap[m.Name]; explicit != "" {
			next = explicit
		} else if modelPrefix != "" {
			next = modelPrefix + m.Name
		}
		if next != "" {
			modelMap[m.Name] = next
			if next != m.Name {
				modelRenames = append(modelRenames, FeaturePackRename{From: m.Name, To: next})
			}
		}
	}

	if len(modelMap) > 0 {
		seenModels := map[string]bool{}
		for i, m := range pack.SchemaModels {
			if next := modelMap[m.Name]; next != "" {
				src := replaceModelIdentifiers(m.Source, modelMap)
				renamed := curatedModel(next, src)
				if renamed.Source == "" {
					renamed = m
					renamed.Name = next
					renamed.Source = src
				}
				if m.Table != "" && renamed.Table != "" {
					if renamed.Table == m.Table && renamed.Name != m.Name {
						return pack, files, fileRenames, routeRenames, modelRenames, fmt.Errorf("model transform cannot safely rename model %s because table mapping remains %s", m.Name, m.Table)
					}
					tableMap[m.Table] = renamed.Table
				}
				pack.SchemaModels[i] = renamed
			}
			if seenModels[pack.SchemaModels[i].Name] {
				return pack, files, fileRenames, routeRenames, modelRenames, fmt.Errorf("model transforms create duplicate model %s", pack.SchemaModels[i].Name)
			}
			seenModels[pack.SchemaModels[i].Name] = true
		}
	}
	packRouteNames := map[string]bool{}
	for _, route := range pack.Routes {
		packRouteNames[route] = true
	}
	for old := range explicitRouteMap {
		if !packRouteNames[old] {
			return pack, files, fileRenames, routeRenames, modelRenames, fmt.Errorf("route_map references missing route %s", old)
		}
	}
	if routePrefix != "" || len(explicitRouteMap) > 0 {
		for _, route := range pack.Routes {
			next := explicitRouteMap[route]
			if next == "" && routePrefix != "" {
				next = prefixedFeatureRoute(route, routePrefix)
			}
			if next != "" && next != route {
				routeMap[route] = next
				routeRenames = append(routeRenames, FeaturePackRename{From: route, To: next})
			}
		}
	}
	rewriteMap := map[string]string{}
	for old, next := range tableMap {
		rewriteMap[old] = next
	}
	for old, next := range modelMap {
		rewriteMap[old] = next
	}

	preparedFiles := map[string][]byte{}
	transformedBodies := map[string]bool{}
	seenPaths := map[string]bool{}
	for p, body := range files {
		nextPath := filepath.ToSlash(p)
		nextPath = transformedFeatureFilePath(nextPath, body, routeMap, routePrefix)
		if nextPath != filepath.ToSlash(p) {
			fileRenames = append(fileRenames, FeaturePackRename{From: filepath.ToSlash(p), To: nextPath})
		}
		if hasParentPathSegment(nextPath) {
			return pack, files, fileRenames, routeRenames, modelRenames, fmt.Errorf("transformed path escapes feature root: %s", nextPath)
		}
		if seenPaths[nextPath] {
			return pack, files, fileRenames, routeRenames, modelRenames, fmt.Errorf("route transforms create duplicate file path %s", nextPath)
		}
		seenPaths[nextPath] = true
		body = transformFeatureBody(body, nextPath, rewriteMap, routeMap, transformedBodies)
		preparedFiles[nextPath] = body
	}

	var preparedManifestFiles []FeaturePackFile
	for _, f := range pack.Files {
		oldPath := filepath.ToSlash(f.Path)
		nextPath := oldPath
		nextPath = transformedFeatureFilePath(nextPath, files[oldPath], routeMap, routePrefix)
		body, ok := preparedFiles[nextPath]
		if !ok {
			body = transformFeatureBody(files[oldPath], nextPath, rewriteMap, routeMap, transformedBodies)
		}
		sha := f.SHA256
		size := f.Size
		if transformedBodies[nextPath] {
			sha = hashBytesSHA256(body)
			size = int64(len(body))
		}
		preparedManifestFiles = append(preparedManifestFiles, FeaturePackFile{Path: nextPath, SHA256: sha, Size: size})
	}
	pack.Files = preparedManifestFiles
	pack.StaticAssets = nil
	pack.Routes = nil
	for _, f := range pack.Files {
		if strings.HasPrefix(f.Path, "static/") {
			pack.StaticAssets = appendUnique(pack.StaticAssets, f.Path)
			pack.Routes = appendUnique(pack.Routes, routeForStaticPath(f.Path))
		}
	}
	for _, route := range routeMap {
		if strings.HasPrefix(route, "/api/") {
			pack.Routes = appendUnique(pack.Routes, route)
		}
	}
	sort.Slice(pack.Files, func(i, j int) bool { return pack.Files[i].Path < pack.Files[j].Path })
	sort.Strings(pack.StaticAssets)
	sort.Strings(pack.Routes)
	sortFeaturePackRenames(fileRenames)
	sortFeaturePackRenames(routeRenames)
	sortFeaturePackRenames(modelRenames)
	return pack, preparedFiles, fileRenames, routeRenames, modelRenames, nil
}

// transformFeatureBody applies the token/route rewrite maps to a text body,
// recording in transformed whether the content actually changed. Binary
// bodies pass through untouched.
func transformFeatureBody(body []byte, nextPath string, rewriteMap, routeMap map[string]string, transformed map[string]bool) []byte {
	if (len(rewriteMap) == 0 && len(routeMap) == 0) || featurePackLooksBinary(body) {
		return body
	}
	nextBody := []byte(rewriteFeaturePackText(string(body), rewriteMap, routeMap))
	if !bytes.Equal(nextBody, body) {
		transformed[nextPath] = true
	}
	return nextBody
}

func normalizedRoutePrefix(prefix string) string {
	prefix = filepath.ToSlash(strings.TrimSpace(prefix))
	prefix = strings.Trim(prefix, "/")
	if prefix == "" {
		return ""
	}
	parts := strings.Split(prefix, "/")
	var out []string
	for _, part := range parts {
		part = slugifyFeatureName(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return strings.Join(out, "/")
}

func normalizedModelPrefix(prefix string) string {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" {
		return ""
	}
	parts := regexp.MustCompile(`[A-Za-z0-9]+`).FindAllString(prefix, -1)
	if len(parts) == 0 {
		return ""
	}
	var b strings.Builder
	for _, part := range parts {
		if part == "" {
			continue
		}
		b.WriteString(strings.ToUpper(part[:1]))
		if len(part) > 1 {
			b.WriteString(part[1:])
		}
	}
	out := b.String()
	if out == "" {
		return ""
	}
	if out[0] >= '0' && out[0] <= '9' {
		out = "M" + out
	}
	return out
}

var featurePrismaModelNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

func parseFeatureRenameMap(values []string) (map[string]string, error) {
	out := map[string]string{}
	for _, v := range values {
		for _, item := range splitCSV(v) {
			if item == "" {
				continue
			}
			parts := strings.SplitN(item, "=", 2)
			if len(parts) != 2 {
				return nil, fmt.Errorf("mapping %q must use FROM=TO", item)
			}
			from := strings.TrimSpace(parts[0])
			to := strings.TrimSpace(parts[1])
			if from == "" || to == "" {
				return nil, fmt.Errorf("mapping %q must include both FROM and TO", item)
			}
			if existing, ok := out[from]; ok && existing != to {
				return nil, fmt.Errorf("duplicate mapping for %q", from)
			}
			out[from] = to
		}
	}
	return out, nil
}

func mergeFeatureRenameMap(dst, src map[string]string) map[string]string {
	if len(src) == 0 {
		return dst
	}
	if dst == nil {
		dst = map[string]string{}
	}
	for k, v := range src {
		dst[k] = v
	}
	return dst
}

func sortedStringMap(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, len(in))
	for k, v := range in {
		out[k] = v
	}
	return out
}

func normalizeFeatureRouteMap(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := map[string]string{}
	targets := map[string]string{}
	for from, to := range in {
		cleanFrom, err := normalizeFeatureRoutePath(from)
		if err != nil {
			return nil, fmt.Errorf("route_map source %q: %w", from, err)
		}
		cleanTo, err := normalizeFeatureRoutePath(to)
		if err != nil {
			return nil, fmt.Errorf("route_map target %q: %w", to, err)
		}
		if cleanFrom == cleanTo {
			continue
		}
		if strings.HasPrefix(cleanFrom, "/api/") != strings.HasPrefix(cleanTo, "/api/") {
			return nil, fmt.Errorf("route_map cannot change route type between page and api routes: %s -> %s", cleanFrom, cleanTo)
		}
		if prior := targets[cleanTo]; prior != "" && prior != cleanFrom {
			return nil, fmt.Errorf("route_map maps both %s and %s to %s", prior, cleanFrom, cleanTo)
		}
		targets[cleanTo] = cleanFrom
		out[cleanFrom] = cleanTo
	}
	return out, nil
}

func normalizeFeatureRoutePath(route string) (string, error) {
	route = filepath.ToSlash(strings.TrimSpace(route))
	if route == "" {
		return "", fmt.Errorf("route is required")
	}
	if !strings.HasPrefix(route, "/") {
		route = "/" + route
	}
	if strings.ContainsAny(route, " \t\r\n") {
		return "", fmt.Errorf("route cannot contain whitespace")
	}
	if hasParentPathSegment(strings.TrimPrefix(route, "/")) {
		return "", fmt.Errorf("route cannot contain ..")
	}
	return route, nil
}

func normalizeFeatureModelMap(in map[string]string) (map[string]string, error) {
	if len(in) == 0 {
		return nil, nil
	}
	out := map[string]string{}
	targets := map[string]string{}
	for from, to := range in {
		from = strings.TrimSpace(from)
		to = strings.TrimSpace(to)
		if !featurePrismaModelNameRE.MatchString(from) {
			return nil, fmt.Errorf("model_map source %q is not a valid Prisma model name", from)
		}
		if !featurePrismaModelNameRE.MatchString(to) {
			return nil, fmt.Errorf("model_map target %q is not a valid Prisma model name", to)
		}
		if from == to {
			continue
		}
		if prior := targets[to]; prior != "" && prior != from {
			return nil, fmt.Errorf("model_map maps both %s and %s to %s", prior, from, to)
		}
		targets[to] = from
		out[from] = to
	}
	return out, nil
}

func prefixedFeatureFilePath(p, routePrefix string) string {
	p = filepath.ToSlash(p)
	switch {
	case strings.HasPrefix(p, "static/"):
		rest := strings.TrimPrefix(p, "static/")
		return filepath.ToSlash(filepath.Join("static", filepath.FromSlash(routePrefix), filepath.FromSlash(rest)))
	case strings.HasPrefix(p, "flows/") && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")):
		base := filepath.Base(p)
		prefix := strings.ReplaceAll(routePrefix, "/", "-")
		return filepath.ToSlash(filepath.Join("flows", prefix+"-"+base))
	default:
		return p
	}
}

func transformedFeatureFilePath(p string, body []byte, routeMap map[string]string, routePrefix string) string {
	p = filepath.ToSlash(p)
	if strings.HasPrefix(p, "static/") {
		if nextRoute := routeMap[routeForStaticPath(p)]; nextRoute != "" {
			if nextPath := staticPathForRoute(nextRoute, filepath.Ext(p)); nextPath != "" {
				return nextPath
			}
		}
	}
	if strings.HasPrefix(p, "flows/") && (strings.HasSuffix(p, ".yaml") || strings.HasSuffix(p, ".yml")) && len(routeMap) > 0 && !featurePackLooksBinary(body) {
		var mapped []string
		for _, route := range scanFeatureRoutes(string(body)) {
			if nextRoute := routeMap[route]; nextRoute != "" {
				mapped = append(mapped, nextRoute)
			}
		}
		if len(mapped) == 1 {
			if nextPath := flowPathForRoute(mapped[0], filepath.Ext(p)); nextPath != "" {
				return nextPath
			}
		}
	}
	if routePrefix != "" {
		return prefixedFeatureFilePath(p, routePrefix)
	}
	return p
}

func staticPathForRoute(route, ext string) string {
	route = strings.TrimSpace(route)
	if route == "" || strings.HasPrefix(route, "/api/") {
		return ""
	}
	route = strings.Trim(route, "/")
	if route == "" {
		route = "index"
	}
	if hasParentPathSegment(route) {
		return ""
	}
	if ext == "" {
		ext = ".tsx"
	}
	return filepath.ToSlash(filepath.Join("static", filepath.FromSlash(route+ext)))
}

func flowPathForRoute(route, ext string) string {
	route = strings.TrimSpace(route)
	if !strings.HasPrefix(route, "/api/") {
		return ""
	}
	route = strings.TrimPrefix(route, "/api/")
	slug := slugifyFeatureName(route)
	if slug == "" {
		return ""
	}
	if ext == "" {
		ext = ".yaml"
	}
	return filepath.ToSlash(filepath.Join("flows", slug+ext))
}

func prefixedFeatureRoute(route, routePrefix string) string {
	route = strings.TrimSpace(route)
	if route == "" || route == "/" {
		return route
	}
	if strings.HasPrefix(route, "/api/") {
		rest := strings.TrimPrefix(route, "/api/")
		return "/" + filepath.ToSlash(filepath.Join("api", filepath.FromSlash(routePrefix), filepath.FromSlash(rest)))
	}
	if strings.HasPrefix(route, "/") {
		return "/" + filepath.ToSlash(filepath.Join(filepath.FromSlash(routePrefix), filepath.FromSlash(strings.TrimPrefix(route, "/"))))
	}
	return route
}

func rewriteFeaturePackText(s string, tokenMap, routeMap map[string]string) string {
	s = replaceModelIdentifiers(s, tokenMap)
	if len(routeMap) == 0 || s == "" {
		return s
	}
	routes := make([]string, 0, len(routeMap))
	for old := range routeMap {
		routes = append(routes, old)
	}
	sort.Slice(routes, func(i, j int) bool { return len(routes[i]) > len(routes[j]) })
	for _, old := range routes {
		s = replaceRouteLiteral(s, old, routeMap[old])
	}
	return s
}

func replaceRouteLiteral(s, old, replacement string) string {
	if s == "" || old == "" || old == replacement {
		return s
	}
	var b strings.Builder
	pos := 0
	changed := false
	for {
		idx := strings.Index(s[pos:], old)
		if idx < 0 {
			break
		}
		start := pos + idx
		end := start + len(old)
		b.WriteString(s[pos:start])
		if routeLiteralBoundaryBefore(s, start) && routeLiteralBoundaryAfter(s, end) {
			b.WriteString(replacement)
			changed = true
		} else {
			b.WriteString(s[start:end])
		}
		pos = end
	}
	if !changed {
		return s
	}
	b.WriteString(s[pos:])
	return b.String()
}

func routeLiteralBoundaryBefore(s string, start int) bool {
	if start <= 0 {
		return true
	}
	r, _ := utf8.DecodeLastRuneInString(s[:start])
	return !isRouteLiteralPathRune(r)
}

func routeLiteralBoundaryAfter(s string, end int) bool {
	if end >= len(s) {
		return true
	}
	r, _ := utf8.DecodeRuneInString(s[end:])
	return !isRouteLiteralPathRune(r)
}

func isRouteLiteralPathRune(r rune) bool {
	return r == '/' || r == '-' || r == '_' || r == '.' || r == '~' || r == '%' ||
		(r >= '0' && r <= '9') ||
		(r >= 'A' && r <= 'Z') ||
		(r >= 'a' && r <= 'z')
}

func replaceModelIdentifiers(s string, modelMap map[string]string) string {
	if len(modelMap) == 0 || s == "" {
		return s
	}
	names := make([]string, 0, len(modelMap))
	for old := range modelMap {
		names = append(names, old)
	}
	sort.Slice(names, func(i, j int) bool { return len(names[i]) > len(names[j]) })
	for _, old := range names {
		re := regexp.MustCompile(`\b` + regexp.QuoteMeta(old) + `\b`)
		s = re.ReplaceAllString(s, modelMap[old])
	}
	return s
}

func featurePackLooksBinary(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	limit := len(b)
	if limit > 8192 {
		limit = 8192
	}
	for _, c := range b[:limit] {
		if c == 0 {
			return true
		}
	}
	return !utf8.Valid(b)
}

func sortFeaturePackRenames(in []FeaturePackRename) {
	sort.Slice(in, func(i, j int) bool {
		if in[i].From == in[j].From {
			return in[i].To < in[j].To
		}
		return in[i].From < in[j].From
	})
}

func BuildCuratedFeaturePack(slug string) (FeaturePack, map[string][]byte, error) {
	entry, ok := featureCatalogSlugs()[slug]
	if !ok {
		return FeaturePack{}, nil, fmt.Errorf("unknown curated feature pack %q", slug)
	}
	pack := FeaturePack{
		APIVersion: featurePackAPIVersion,
		Kind:       "FeaturePack",
		Name:       entry.Name,
		Slug:       entry.Slug,
		Version:    entry.Version,
		Source:     FeaturePackSource{App: "curated", Env: "catalog"},
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}
	files := map[string][]byte{}
	switch slug {
	case "kanban":
		pack.SchemaModels = []FeaturePackModel{
			curatedModel("Board", `model Board {
  id Int @id @default(autoincrement())
  name String
  created_at DateTime @default(now())
}`),
			curatedModel("BoardColumn", `model BoardColumn {
  id Int @id @default(autoincrement())
  board_id Int
  name String
  position Int @default(0)
  created_at DateTime @default(now())
}`),
			curatedModel("BoardCard", `model BoardCard {
  id Int @id @default(autoincrement())
  board_id Int
  column_id Int
  title String
  description String?
  assignee_id Int?
  priority String @default("normal")
  due_at DateTime?
  position Int @default(0)
  status String @default("open")
  created_at DateTime @default(now())
}`),
			curatedModel("BoardCardStatusHistory", `model BoardCardStatusHistory {
  id Int @id @default(autoincrement())
  card_id Int
  from_column_id Int?
  to_column_id Int?
  from_status String?
  to_status String
  changed_by Int?
  note String?
  created_at DateTime @default(now())
}`),
		}
		files["static/kanban.tsx"] = []byte(curatedKanbanTSX)
		files["flows/kanban-move-card.yaml"] = []byte(curatedKanbanMoveFlowYAML)
	case "notify-hub":
		pack.SchemaModels = []FeaturePackModel{
			curatedModel("Notification", `model Notification {
  id Int @id @default(autoincrement())
  user_id Int?
  broadcast_id Int?
  title String
  body String
  channel String @default("in_app")
  topic String @default("general")
  priority String @default("normal")
  link String?
  read_at DateTime?
  created_at DateTime @default(now())
}`),
			curatedModel("NotificationPreference", `model NotificationPreference {
  id Int @id @default(autoincrement())
  user_id Int
  topic String @default("general")
  in_app_enabled Boolean @default(true)
  email_enabled Boolean @default(false)
  created_at DateTime @default(now())
}`),
			curatedModel("NotificationBroadcast", `model NotificationBroadcast {
  id Int @id @default(autoincrement())
  title String
  body String
  audience String @default("all")
  channel String @default("in_app")
  topic String @default("general")
  sent_by Int?
  sent_at DateTime?
  created_at DateTime @default(now())
}`),
		}
		files["static/notify-hub.tsx"] = []byte(curatedNotifyHubTSX)
		files["flows/notify-hub-broadcast.yaml"] = []byte(curatedNotifyHubBroadcastFlowYAML)
	case "foundry":
		pack.SchemaModels = []FeaturePackModel{
			curatedModel("FoundryProject", `model FoundryProject {
  id Int @id @default(autoincrement())
  name String
  stage String @default("intake")
  owner String?
  priority String @default("normal")
  due_at DateTime?
  created_at DateTime @default(now())
}`),
			curatedModel("FoundryArtifact", `model FoundryArtifact {
  id Int @id @default(autoincrement())
  project_id Int
  title String
  kind String @default("document")
  status String @default("draft")
  reviewer String?
  notes String?
  created_at DateTime @default(now())
}`),
			curatedModel("FoundryEvaluation", `model FoundryEvaluation {
  id Int @id @default(autoincrement())
  project_id Int
  score Int?
  verdict String @default("pending")
  notes String?
  created_at DateTime @default(now())
}`),
			curatedModel("FoundryReview", `model FoundryReview {
  id Int @id @default(autoincrement())
  project_id Int
  artifact_id Int?
  reviewer String?
  status String @default("queued")
  decision String?
  notes String?
  created_at DateTime @default(now())
}`),
		}
		files["static/foundry.tsx"] = []byte(curatedFoundryTSX)
		files["flows/foundry-advance.yaml"] = []byte(curatedFoundryAdvanceFlowYAML)
	default:
		files["static/"+slug+".tsx"] = []byte("export default function Feature(){ return <main><h1>" + entry.Name + "</h1></main>; }\n")
	}
	for p, b := range files {
		pack.Files = append(pack.Files, FeaturePackFile{Path: p, SHA256: hashBytesSHA256(b), Size: int64(len(b))})
		if strings.HasPrefix(p, "static/") {
			pack.StaticAssets = appendUnique(pack.StaticAssets, p)
			pack.Routes = appendUnique(pack.Routes, routeForStaticPath(p))
		}
		if strings.HasPrefix(p, "flows/") {
			pack.Flows = appendUnique(pack.Flows, strings.TrimSuffix(strings.TrimPrefix(p, "flows/"), filepath.Ext(p)))
		}
		pack.Routes = appendUniqueMany(pack.Routes, scanFeatureRoutes(string(b))...)
		pack.EnvRefs = appendUniqueMany(pack.EnvRefs, scanFeatureEnvRefs(string(b))...)
	}
	sort.Slice(pack.Files, func(i, j int) bool { return pack.Files[i].Path < pack.Files[j].Path })
	sort.Strings(pack.Flows)
	sort.Strings(pack.Routes)
	sort.Strings(pack.StaticAssets)
	sort.Strings(pack.EnvRefs)
	return pack, files, nil
}

func curatedModel(name, src string) FeaturePackModel {
	models, err := ParsePrismaSchema(src)
	out := FeaturePackModel{Name: name, Source: src}
	if err == nil && len(models) > 0 {
		out.Table = models[0].Table
		for _, f := range models[0].Fields {
			out.Fields = append(out.Fields, f.Name)
		}
	}
	return out
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

func safeFeatureJoin(root, rel string) (string, error) {
	return safeJoinUnderRoot(root, rel, "feature")
}

// featurePackPathProtected reports whether a pack file path targets a
// protected file or lives under a protected directory. sourceManifestExcluded's
// FILE branch only inspects the basename, so a crafted pack entry like
// ".benmore/server-secret" or ".git/config" would otherwise slip through and
// let an install overwrite the app's HMAC/session/OAuth secret or its git
// history. Reject any path with a protected directory segment as well.
func featurePackPathProtected(rel string) bool {
	rel = filepath.ToSlash(strings.TrimPrefix(rel, "./"))
	if sourceManifestExcluded(rel, false) {
		return true
	}
	for _, seg := range strings.Split(rel, "/") {
		switch seg {
		case ".git", ".benmore", "uploads", "logs", "node_modules", "Benmore", ".claude", ".codex":
			return true
		}
	}
	return false
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

func routeForStaticPath(p string) string {
	p = strings.TrimPrefix(filepath.ToSlash(p), "static/")
	ext := filepath.Ext(p)
	p = strings.TrimSuffix(p, ext)
	if p == "index" {
		return "/"
	}
	return "/" + p
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

var envRefRE = regexp.MustCompile(`\b[A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|WEBHOOK|URL|KEY)\b`)
var featureRoutePathRE = regexp.MustCompile(`(?m)^\s*path:\s*["']?(/[^"'\s#]+)`)

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

const curatedKanbanTSX = `import bm from 'bm';

type Row = Record<string, any>;

const boards = bm.table('boards' as any) as any;
const columns = bm.table('board_columns' as any) as any;
const cards = bm.table('board_cards' as any) as any;
const history = bm.table('board_card_status_histories' as any) as any;

const state: { board: Row | null; columns: Row[]; cards: Row[]; dragging: number | null } = {
  board: null,
  columns: [],
  cards: [],
  dragging: null,
};

function mount(): HTMLElement {
  let el = document.getElementById('kanban-pack');
  if (!el) {
    el = document.createElement('main');
    el.id = 'kanban-pack';
    document.body.appendChild(el);
  }
  el.className = 'mx-auto max-w-7xl p-6 text-slate-950';
  return el;
}

function esc(v: unknown): string {
  return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'} as Record<string, string>)[c]);
}

function cardHtml(card: Row): string {
  return '<article draggable="true" data-card-id="' + card.id + '" class="rounded border border-slate-200 bg-white p-3 shadow-sm">' +
    '<div class="flex items-start justify-between gap-3">' +
      '<h3 class="text-sm font-semibold">' + esc(card.title) + '</h3>' +
      '<span class="rounded bg-slate-100 px-2 py-0.5 text-xs">' + esc(card.priority || 'normal') + '</span>' +
    '</div>' +
    '<p class="mt-2 text-sm text-slate-600">' + esc(card.description || 'No description') + '</p>' +
    '<div class="mt-3 flex items-center justify-between text-xs text-slate-500">' +
      '<span>Status: ' + esc(card.status || 'open') + '</span>' +
      '<button data-action="advance-card" data-card-id="' + card.id + '" class="rounded border px-2 py-1">Advance</button>' +
    '</div>' +
  '</article>';
}

function render() {
  const root = mount();
  const unreadable = state.columns.length === 0;
  root.innerHTML = '<header class="flex flex-wrap items-end justify-between gap-4">' +
    '<div><h1 class="text-2xl font-semibold">Kanban</h1><p class="mt-1 text-sm text-slate-600">Drag cards across columns; every move writes status history.</p></div>' +
    '<div class="flex gap-2"><button data-action="seed-kanban" class="rounded bg-slate-950 px-3 py-2 text-sm text-white">Seed board</button><button data-action="refresh-kanban" class="rounded border px-3 py-2 text-sm">Refresh</button></div>' +
  '</header>' +
  (unreadable ? '<section class="mt-6 rounded border border-dashed p-6 text-sm text-slate-600">No board columns yet. Seed a board to create Backlog, In Progress, Review, and Done.</section>' : '') +
  '<section class="mt-6 flex gap-4 overflow-x-auto pb-4">' + state.columns.map(col => {
    const colCards = state.cards.filter(card => Number(card.column_id) === Number(col.id)).sort((a, b) => Number(a.position || 0) - Number(b.position || 0));
    return '<div data-column-id="' + col.id + '" data-status="' + esc(col.name) + '" class="min-w-[260px] flex-1 rounded border bg-slate-50 p-3">' +
      '<div class="mb-3 flex items-center justify-between"><h2 class="font-medium">' + esc(col.name) + '</h2><span class="text-xs text-slate-500">' + colCards.length + '</span></div>' +
      '<div class="space-y-3 min-h-[80px]">' + colCards.map(cardHtml).join('') + '</div>' +
      '<button data-action="add-card" data-column-id="' + col.id + '" class="mt-3 w-full rounded border border-dashed py-2 text-sm">Add card</button>' +
    '</div>';
  }).join('') + '</section>';
  wireEvents(root);
}

async function load() {
  const [boardRows, columnRows, cardRows] = await Promise.all([
    boards.list({ limit: 10 }).catch(() => []),
    columns.list({ limit: 100 }).catch(() => []),
    cards.list({ limit: 250 }).catch(() => []),
  ]);
  state.board = boardRows[0] || null;
  state.columns = columnRows.sort((a: Row, b: Row) => Number(a.position || 0) - Number(b.position || 0));
  state.cards = cardRows;
  render();
}

async function seed() {
  const board = await boards.create({ name: 'Product Workflow' });
  const names = ['Backlog', 'In Progress', 'Review', 'Done'];
  const created = [];
  for (let i = 0; i < names.length; i++) {
    created.push(await columns.create({ board_id: board.id, name: names[i], position: i }));
  }
  await cards.create({ board_id: board.id, column_id: created[0].id, title: 'Triage intake', description: 'Capture owner, priority, and next action.', priority: 'high', position: 0, status: 'Backlog' });
  await cards.create({ board_id: board.id, column_id: created[1].id, title: 'Draft implementation plan', description: 'Keep scope small and testable.', priority: 'normal', position: 1, status: 'In Progress' });
  await load();
}

async function addCard(columnId: number) {
  const title = window.prompt('Card title');
  if (!title) return;
  const boardId = state.board?.id || state.columns.find(c => Number(c.id) === columnId)?.board_id;
  await cards.create({ board_id: boardId, column_id: columnId, title, status: state.columns.find(c => Number(c.id) === columnId)?.name || 'open', position: Date.now() });
  await load();
}

async function moveCard(cardId: number, toColumnId: number) {
  const card = state.cards.find(c => Number(c.id) === cardId);
  const toColumn = state.columns.find(c => Number(c.id) === toColumnId);
  if (!card || !toColumn || Number(card.column_id) === toColumnId) return;
  await history.create({ card_id: cardId, from_column_id: card.column_id, to_column_id: toColumnId, from_status: card.status, to_status: toColumn.name, note: 'drag/drop move' });
  await cards.update(cardId, { column_id: toColumnId, status: toColumn.name, position: Date.now() });
  await load();
}

function wireEvents(root: HTMLElement) {
  root.querySelectorAll('[data-card-id]').forEach(el => {
    el.addEventListener('dragstart', ev => {
      state.dragging = Number((ev.currentTarget as HTMLElement).dataset.cardId);
    });
  });
  root.querySelectorAll('[data-column-id]').forEach(el => {
    el.addEventListener('dragover', ev => ev.preventDefault());
    el.addEventListener('drop', async ev => {
      ev.preventDefault();
      const id = state.dragging;
      state.dragging = null;
      if (id) await moveCard(id, Number((ev.currentTarget as HTMLElement).dataset.columnId));
    });
  });
  root.querySelectorAll('[data-action]').forEach(el => {
    el.addEventListener('click', async ev => {
      const target = ev.currentTarget as HTMLElement;
      const action = target.dataset.action;
      if (action === 'seed-kanban') await seed();
      if (action === 'refresh-kanban') await load();
      if (action === 'add-card') await addCard(Number(target.dataset.columnId));
      if (action === 'advance-card') {
        const card = state.cards.find(c => Number(c.id) === Number(target.dataset.cardId));
        const current = state.columns.findIndex(c => Number(c.id) === Number(card?.column_id));
        const next = state.columns[Math.min(current + 1, state.columns.length - 1)];
        if (card && next) await moveCard(Number(card.id), Number(next.id));
      }
    });
  });
}

bm.live.scoped('*' as any, load, { debounce: 100 });
void load();
`

const curatedKanbanMoveFlowYAML = `on:
  request:
    method: POST
    path: /api/kanban/cards/:id/move
    auth: required

jobs:
  move:
    steps:
      - id: before
        run: sql
        query: SELECT column_id, status FROM board_cards WHERE id = :id

      - run: sql
        query: INSERT INTO board_card_status_histories (card_id, from_column_id, to_column_id, from_status, to_status, changed_by, note) SELECT id, column_id, :to_column_id, status, :to_status, NULLIF(:changed_by, ''), :note FROM board_cards WHERE id = :id
        with:
          params:
            to_column_id: ${{ params.column_id }}
            to_status: ${{ params.status | default:'open' }}
            changed_by: ${{ user.id | default:'' }}
            note: ${{ params.note | default:'flow move' }}
        expect_rows: ">0"

      - run: sql
        query: UPDATE board_cards SET column_id = :column_id, status = :status, position = :position WHERE id = :id
        with:
          params:
            column_id: ${{ params.column_id }}
            status: ${{ params.status | default:'open' }}
            position: ${{ params.position | default:'0' }}
        expect_rows: ">0"

      - run: respond
        with:
          body:
            ok: true
            card_id: ${{ params.id }}
            to_column_id: ${{ params.column_id }}
`

const curatedNotifyHubTSX = `import bm from 'bm';

type Row = Record<string, any>;

const notifications = bm.table('notifications' as any) as any;
const preferences = bm.table('notification_preferences' as any) as any;

let rows: Row[] = [];
let prefs: Row[] = [];

function mount(): HTMLElement {
  let el = document.getElementById('notify-hub-pack');
  if (!el) {
    el = document.createElement('main');
    el.id = 'notify-hub-pack';
    document.body.appendChild(el);
  }
  el.className = 'mx-auto max-w-6xl p-6 text-slate-950';
  return el;
}

function esc(v: unknown): string {
  return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'} as Record<string, string>)[c]);
}

function rowHtml(n: Row): string {
  const unread = !n.read_at;
  return '<article class="rounded border bg-white p-4 shadow-sm ' + (unread ? 'border-slate-950' : 'border-slate-200') + '">' +
    '<div class="flex items-start justify-between gap-3"><div><h3 class="font-semibold">' + esc(n.title) + '</h3><p class="mt-1 text-sm text-slate-600">' + esc(n.body) + '</p></div>' +
    '<span class="rounded bg-slate-100 px-2 py-1 text-xs">' + esc(n.topic || 'general') + '</span></div>' +
    '<div class="mt-3 flex items-center justify-between text-xs text-slate-500"><span>' + esc(n.channel || 'in_app') + ' · ' + esc(n.priority || 'normal') + '</span>' +
    (unread ? '<button data-action="mark-read" data-id="' + n.id + '" class="rounded border px-2 py-1">Mark read</button>' : '<span>Read</span>') + '</div>' +
  '</article>';
}

function render() {
  const unread = rows.filter(n => !n.read_at).length;
  const root = mount();
  root.innerHTML = '<header class="flex flex-wrap items-end justify-between gap-4">' +
    '<div><h1 class="text-2xl font-semibold">Notify Hub</h1><p class="mt-1 text-sm text-slate-600">Inbox, preferences, broadcast flow, and unread counts.</p></div>' +
    '<div class="grid grid-cols-2 gap-2 text-center"><div class="rounded border p-3"><div class="text-2xl font-semibold">' + unread + '</div><div class="text-xs text-slate-500">unread</div></div><div class="rounded border p-3"><div class="text-2xl font-semibold">' + rows.length + '</div><div class="text-xs text-slate-500">total</div></div></div>' +
  '</header>' +
  '<section class="mt-6 grid gap-6 lg:grid-cols-[360px_1fr]">' +
    '<form id="notify-send" class="rounded border bg-white p-4 shadow-sm"><h2 class="font-semibold">Send broadcast</h2><label class="mt-3 block text-sm">Title<input name="title" required class="mt-1 w-full rounded border px-3 py-2"></label><label class="mt-3 block text-sm">Body<textarea name="body" required class="mt-1 w-full rounded border px-3 py-2"></textarea></label><label class="mt-3 block text-sm">Topic<input name="topic" value="general" class="mt-1 w-full rounded border px-3 py-2"></label><button class="mt-4 rounded bg-slate-950 px-3 py-2 text-sm text-white">Broadcast</button></form>' +
    '<div><div class="mb-3 flex items-center justify-between"><h2 class="font-semibold">Inbox</h2><button data-action="refresh" class="rounded border px-3 py-2 text-sm">Refresh</button></div><div class="space-y-3">' + (rows.length ? rows.map(rowHtml).join('') : '<div class="rounded border border-dashed p-6 text-sm text-slate-600">No notifications yet.</div>') + '</div></div>' +
  '</section>' +
  '<section class="mt-6 rounded border bg-slate-50 p-4"><h2 class="font-semibold">Preferences</h2><p class="mt-1 text-sm text-slate-600">' + (prefs.length ? prefs.length + ' preference rows configured.' : 'No preference rows yet; create rows in notification_preferences to tailor topics/channels.') + '</p></section>';
  wireEvents(root);
}

async function load() {
  const [notificationRows, preferenceRows] = await Promise.all([
    notifications.list({ limit: 100 }).catch(() => []),
    preferences.list({ limit: 100 }).catch(() => []),
  ]);
  rows = notificationRows.sort((a: Row, b: Row) => Number(new Date(b.created_at || 0)) - Number(new Date(a.created_at || 0)));
  prefs = preferenceRows;
  render();
}

async function broadcast(form: HTMLFormElement) {
  const data = new FormData(form);
  const title = String(data.get('title') || '').trim();
  const body = String(data.get('body') || '').trim();
  const topic = String(data.get('topic') || 'general').trim() || 'general';
  if (!title || !body) return;
  try {
    await bm.api.post('/api/notify-hub/broadcast' as any, { title, body, topic });
  } catch {
    await notifications.create({ title, body, topic, channel: 'in_app', priority: 'normal' });
  }
  form.reset();
  await load();
}

function wireEvents(root: HTMLElement) {
  root.querySelector('#notify-send')?.addEventListener('submit', async ev => {
    ev.preventDefault();
    await broadcast(ev.currentTarget as HTMLFormElement);
  });
  root.querySelectorAll('[data-action]').forEach(el => {
    el.addEventListener('click', async ev => {
      const target = ev.currentTarget as HTMLElement;
      if (target.dataset.action === 'refresh') await load();
      if (target.dataset.action === 'mark-read' && target.dataset.id) {
        await notifications.update(target.dataset.id, { read_at: new Date().toISOString() });
        await load();
      }
    });
  });
}

bm.live.scoped('notifications' as any, load, { debounce: 100 });
void load();
`

const curatedNotifyHubBroadcastFlowYAML = `on:
  request:
    method: POST
    path: /api/notify-hub/broadcast
    auth: required

jobs:
  broadcast:
    steps:
      - id: broadcast
        run: sql
        query: INSERT INTO notification_broadcasts (title, body, audience, channel, topic, sent_by, sent_at) VALUES (:title, :body, :audience, 'in_app', :topic, NULLIF(:sent_by, ''), datetime('now')) RETURNING id
        with:
          params:
            title: ${{ params.title }}
            body: ${{ params.body }}
            audience: ${{ params.audience | default:'all' }}
            topic: ${{ params.topic | default:'general' }}
            sent_by: ${{ user.id | default:'' }}

      - id: recipients
        run: sql
        query: SELECT id FROM _benmore_users WHERE verified = 1

      - for_each: ${{ steps.recipients.outputs }}
        as: recipient
        steps:
          - run: sql
            query: INSERT INTO notifications (user_id, broadcast_id, title, body, channel, topic, priority) VALUES (:user_id, :broadcast_id, :title, :body, 'in_app', :topic, :priority)
            with:
              params:
                user_id: ${{ recipient.id }}
                broadcast_id: ${{ steps.broadcast.outputs.id }}
                title: ${{ params.title }}
                body: ${{ params.body }}
                topic: ${{ params.topic | default:'general' }}
                priority: ${{ params.priority | default:'normal' }}

      - run: respond
        with:
          body:
            ok: true
            broadcast_id: ${{ steps.broadcast.outputs.id }}
`

const curatedFoundryTSX = `import bm from 'bm';

type Row = Record<string, any>;

const projects = bm.table('foundry_projects' as any) as any;
const artifacts = bm.table('foundry_artifacts' as any) as any;
const evaluations = bm.table('foundry_evaluations' as any) as any;
const reviews = bm.table('foundry_reviews' as any) as any;

let projectRows: Row[] = [];
let artifactRows: Row[] = [];
let evaluationRows: Row[] = [];
let reviewRows: Row[] = [];
let selectedId: number | null = null;

const stages = ['intake', 'artifact_review', 'evaluation', 'approved'];

function mount(): HTMLElement {
  let el = document.getElementById('foundry-pack');
  if (!el) {
    el = document.createElement('main');
    el.id = 'foundry-pack';
    document.body.appendChild(el);
  }
  el.className = 'mx-auto max-w-7xl p-6 text-slate-950';
  return el;
}

function esc(v: unknown): string {
  return String(v ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'} as Record<string, string>)[c]);
}

function projectCard(p: Row): string {
  const active = Number(p.id) === selectedId;
  return '<button data-action="select-project" data-id="' + p.id + '" class="w-full rounded border p-3 text-left ' + (active ? 'border-slate-950 bg-white' : 'border-slate-200 bg-slate-50') + '">' +
    '<div class="flex items-center justify-between gap-2"><strong>' + esc(p.name) + '</strong><span class="rounded bg-slate-100 px-2 py-1 text-xs">' + esc(p.stage) + '</span></div>' +
    '<div class="mt-2 text-xs text-slate-500">' + esc(p.owner || 'Unassigned') + ' · ' + esc(p.priority || 'normal') + '</div>' +
  '</button>';
}

function render() {
  if (!selectedId && projectRows[0]) selectedId = Number(projectRows[0].id);
  const selected = projectRows.find(p => Number(p.id) === selectedId) || null;
  const selectedArtifacts = artifactRows.filter(a => Number(a.project_id) === selectedId);
  const selectedEvaluations = evaluationRows.filter(e => Number(e.project_id) === selectedId);
  const selectedReviews = reviewRows.filter(r => Number(r.project_id) === selectedId);
  const root = mount();
  root.innerHTML = '<header class="flex flex-wrap items-end justify-between gap-4"><div><h1 class="text-2xl font-semibold">Foundry</h1><p class="mt-1 text-sm text-slate-600">Project intake, artifact review, evaluation, and decision tracking.</p></div><button data-action="seed-foundry" class="rounded bg-slate-950 px-3 py-2 text-sm text-white">Seed foundry</button></header>' +
    '<section class="mt-6 grid gap-6 lg:grid-cols-[320px_1fr]">' +
      '<aside><form id="foundry-intake" class="rounded border bg-white p-4 shadow-sm"><h2 class="font-semibold">New project</h2><input name="name" required placeholder="Project name" class="mt-3 w-full rounded border px-3 py-2"><input name="owner" placeholder="Owner" class="mt-3 w-full rounded border px-3 py-2"><button class="mt-3 rounded border px-3 py-2 text-sm">Create</button></form><div class="mt-4 space-y-2">' + (projectRows.length ? projectRows.map(projectCard).join('') : '<div class="rounded border border-dashed p-4 text-sm text-slate-600">No projects yet.</div>') + '</div></aside>' +
      '<main class="rounded border bg-white p-4 shadow-sm">' + (selected ? detailHtml(selected, selectedArtifacts, selectedEvaluations, selectedReviews) : '<p class="text-sm text-slate-600">Select or create a project.</p>') + '</main>' +
    '</section>';
  wireEvents(root);
}

function detailHtml(project: Row, projectArtifacts: Row[], projectEvaluations: Row[], projectReviews: Row[]): string {
  return '<div class="flex flex-wrap items-start justify-between gap-4"><div><h2 class="text-xl font-semibold">' + esc(project.name) + '</h2><p class="mt-1 text-sm text-slate-600">Stage: ' + esc(project.stage) + '</p></div><div class="flex gap-2">' + stages.map(stage => '<button data-action="advance-project" data-stage="' + stage + '" class="rounded border px-3 py-2 text-sm">' + esc(stage) + '</button>').join('') + '</div></div>' +
    '<div class="mt-6 grid gap-4 md:grid-cols-3"><section><h3 class="font-semibold">Artifacts</h3>' + (projectArtifacts.length ? projectArtifacts.map(a => '<div class="mt-2 rounded border p-3 text-sm"><strong>' + esc(a.title) + '</strong><div class="text-slate-500">' + esc(a.kind) + ' · ' + esc(a.status) + '</div></div>').join('') : '<p class="mt-2 text-sm text-slate-500">No artifacts.</p>') + '<button data-action="add-artifact" class="mt-3 rounded border px-3 py-2 text-sm">Add artifact</button></section>' +
    '<section><h3 class="font-semibold">Reviews</h3>' + (projectReviews.length ? projectReviews.map(r => '<div class="mt-2 rounded border p-3 text-sm"><strong>' + esc(r.status) + '</strong><div class="text-slate-500">' + esc(r.decision || 'pending') + '</div></div>').join('') : '<p class="mt-2 text-sm text-slate-500">No reviews.</p>') + '<button data-action="add-review" class="mt-3 rounded border px-3 py-2 text-sm">Queue review</button></section>' +
    '<section><h3 class="font-semibold">Evaluation</h3>' + (projectEvaluations.length ? projectEvaluations.map(e => '<div class="mt-2 rounded border p-3 text-sm"><strong>' + esc(e.verdict) + '</strong><div class="text-slate-500">Score ' + esc(e.score ?? 'n/a') + '</div></div>').join('') : '<p class="mt-2 text-sm text-slate-500">No evaluation.</p>') + '<button data-action="add-evaluation" class="mt-3 rounded border px-3 py-2 text-sm">Add evaluation</button></section></div>';
}

async function load() {
  const [p, a, e, r] = await Promise.all([
    projects.list({ limit: 100 }).catch(() => []),
    artifacts.list({ limit: 250 }).catch(() => []),
    evaluations.list({ limit: 250 }).catch(() => []),
    reviews.list({ limit: 250 }).catch(() => []),
  ]);
  projectRows = p;
  artifactRows = a;
  evaluationRows = e;
  reviewRows = r;
  render();
}

async function seed() {
  const project = await projects.create({ name: 'Vendor Diligence', owner: 'Operations', stage: 'intake', priority: 'high' });
  await artifacts.create({ project_id: project.id, title: 'Security packet', kind: 'document', status: 'review' });
  await reviews.create({ project_id: project.id, reviewer: 'Compliance', status: 'queued', decision: 'pending' });
  await evaluations.create({ project_id: project.id, score: 72, verdict: 'pending', notes: 'Needs final artifact review.' });
  selectedId = Number(project.id);
  await load();
}

function wireEvents(root: HTMLElement) {
  root.querySelector('#foundry-intake')?.addEventListener('submit', async ev => {
    ev.preventDefault();
    const form = ev.currentTarget as HTMLFormElement;
    const data = new FormData(form);
    const name = String(data.get('name') || '').trim();
    if (!name) return;
    const row = await projects.create({ name, owner: String(data.get('owner') || ''), stage: 'intake', priority: 'normal' });
    selectedId = Number(row.id);
    form.reset();
    await load();
  });
  root.querySelectorAll('[data-action]').forEach(el => el.addEventListener('click', async ev => {
    const target = ev.currentTarget as HTMLElement;
    const action = target.dataset.action;
    if (action === 'seed-foundry') await seed();
    if (action === 'select-project') { selectedId = Number(target.dataset.id); render(); }
    if (!selectedId) return;
    if (action === 'advance-project') { await projects.update(selectedId, { stage: target.dataset.stage }); await load(); }
    if (action === 'add-artifact') { const title = window.prompt('Artifact title'); if (title) { await artifacts.create({ project_id: selectedId, title, kind: 'document', status: 'draft' }); await load(); } }
    if (action === 'add-review') { await reviews.create({ project_id: selectedId, status: 'queued', decision: 'pending' }); await load(); }
    if (action === 'add-evaluation') { await evaluations.create({ project_id: selectedId, score: 0, verdict: 'pending', notes: 'Draft evaluation' }); await load(); }
  }));
}

bm.live.scoped('*' as any, load, { debounce: 100 });
void load();
`

const curatedFoundryAdvanceFlowYAML = `on:
  request:
    method: POST
    path: /api/foundry/projects/:id/advance
    auth: required

jobs:
  advance:
    steps:
      - run: sql
        query: UPDATE foundry_projects SET stage = :stage WHERE id = :id
        with:
          params:
            stage: ${{ params.stage }}
        expect_rows: ">0"

      - run: sql
        query: INSERT INTO foundry_reviews (project_id, reviewer, status, decision, notes) VALUES (:project_id, :reviewer, :status, :decision, :notes)
        with:
          params:
            project_id: ${{ params.id }}
            reviewer: ${{ user.email | default:'' }}
            status: ${{ params.review_status | default:'queued' }}
            decision: ${{ params.decision | default:'pending' }}
            notes: ${{ params.notes | default:'stage advanced' }}

      - run: respond
        with:
          body:
            ok: true
            project_id: ${{ params.id }}
            stage: ${{ params.stage }}
`
