package main

// Feature-pack installation planning, collision checks, and application.

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

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
