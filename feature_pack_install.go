package main

// Feature-pack installation planning, collision checks, and application.

import (
	"bytes"
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
	plan := FeatureInstallPlan{
		Pack:            pack.Name,
		Slug:            pack.Slug,
		DryRun:          opts.DryRun,
		Replace:         opts.Replace,
		DeleteMissing:   opts.DeleteMissing,
		AllowTableDrop:  opts.AllowTableDrop,
		RoutePrefix:     normalizedRoutePrefix(opts.RoutePrefix),
		ModelPrefix:     normalizedModelPrefix(opts.ModelPrefix),
		RouteMap:        sortedStringMap(opts.RouteMap),
		ModelMap:        sortedStringMap(opts.ModelMap),
		EnvRefs:         sortedStrings(pack.EnvRefs),
		RequiredOptions: pack.RequiredOptions,
	}
	// Renaming may change a body and regenerate its manifest hash. Validate the
	// received bytes first, so a transform cannot conceal an original mismatch.
	originalManifest := map[string]FeaturePackFile{}
	for _, f := range pack.Files {
		originalManifest[filepath.ToSlash(f.Path)] = f
	}
	for p, body := range files {
		p = filepath.ToSlash(p)
		if f, ok := originalManifest[p]; ok && f.SHA256 != "" && hashBytesSHA256(body) != f.SHA256 {
			plan.Collisions = append(plan.Collisions, p+": sha256 mismatch")
		}
	}
	if len(plan.Collisions) > 0 {
		sort.Strings(plan.Collisions)
		plan.Blocked = true
		return plan, nil
	}
	pack, files, fileRenames, routeRenames, modelRenames, transformErr := prepareFeaturePackForInstall(pack, files, opts)
	plan.FileRenames, plan.RouteRenames, plan.ModelRenames = fileRenames, routeRenames, modelRenames
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
	packPrismaLoads := false
	// schemaWrites are the pack files the install would write that decide
	// what the app's schema step does at its next load: the root schema.prisma
	// and schema.yaml, and migrations/*.sql.
	schemaWrites := map[string][]byte{}
	for p, body := range files {
		p = filepath.ToSlash(p)
		packFilePresent[p] = true
		clean := filepath.ToSlash(filepath.Clean(p))
		if strings.EqualFold(clean, "schema.prisma") && prismaSourceLoads(body) {
			packPrismaLoads = true
		}
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
		_, isMigration := userMigrationFileName(clean)
		if clean == "schema.prisma" || clean == "schema.yaml" || isMigration {
			schemaWrites[clean] = body
		}
		if _, err := os.Stat(abs); err == nil {
			if opts.Replace {
				plan.FileUpdates = append(plan.FileUpdates, filepath.ToSlash(p))
			} else {
				plan.Collisions = append(plan.Collisions, p+": file exists")
				delete(schemaWrites, clean)
			}
			continue
		} else if !os.IsNotExist(err) {
			// A stat error that isn't "absent" (permission/IO) must not be
			// treated as a fresh add: apply would overwrite the existing
			// file without replace consent, and a failed install's cleanup
			// would then delete it as a phantom FileAdd.
			plan.Collisions = append(plan.Collisions, p+": "+err.Error())
			delete(schemaWrites, clean)
			continue
		}
		if hashBytesSHA256(body) == "" {
			plan.Collisions = append(plan.Collisions, p+": empty hash")
			delete(schemaWrites, clean)
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
		// Model sources are appended to schema.prisma verbatim, so they get
		// the same secret scan as pack files.
		if msg := validateNoCommittedSecrets("schema.prisma", m.Source); msg != "" {
			plan.Collisions = append(plan.Collisions, "model "+m.Name+": hardcoded secret")
			continue
		}
		plan.SchemaAdds = append(plan.SchemaAdds, m.Name)
	}
	// An install never changes which schema file the app loads. The pack's
	// models are appended to schema.prisma, and a schema.prisma that declares
	// a model is loaded instead of schema.sql: in an app whose schema is
	// schema.sql (or schema.yaml) the app's own tables would stop being
	// declared (schema_file_switch.go). Refused here, before any write,
	// whatever replace and delete_missing say.
	if len(pack.SchemaModels) > 0 || packPrismaLoads {
		current, err := readSchemaFileSet(dir)
		if err != nil {
			return plan, fmt.Errorf("read existing schema for install: %w", err)
		}
		if msg := featureInstallSchemaSwitch(current, len(pack.SchemaModels) > 0, packPrismaLoads); msg != "" {
			plan.Collisions = append(plan.Collisions, msg)
		}
	}
	// Nor does a pack's schema.yaml replace a hand-written schema.sql: the
	// next load would write schema.sql from it (schemaYAMLOverwriteProblem).
	if body, ok := schemaWrites["schema.yaml"]; ok {
		current, err := readSchemaFileSet(dir)
		if err != nil {
			return plan, fmt.Errorf("read existing schema for install: %w", err)
		}
		if msg := schemaYAMLOverwriteProblem(current, body); msg != "" {
			plan.Collisions = append(plan.Collisions, msg+" Nothing is installed.")
		}
	}
	// An install never makes the app drop data without the consent a pushed
	// schema.prisma or migrations/ file needs. The pack's schema.prisma takes
	// the place of the app's, and the app drops the table of every model it
	// leaves out when it reloads; it also applies every migrations/ file its
	// ledger lacks. Both are judged by the write gate's own checks against
	// the instance's database (opts.DataDrops): what would be dropped is
	// listed in the plan, and blocks it unless allow_table_drop was given. A
	// file the target already holds unchanged is not the install's doing.
	if opts.DataDrops != nil {
		var rels []string
		migrations := 0
		for rel, body := range schemaWrites {
			if rel == "schema.yaml" || featureInstallTargetHolds(dir, rel, body) {
				continue
			}
			if rel != "schema.prisma" {
				migrations++
			}
			rels = append(rels, rel)
		}
		sort.Strings(rels)
		// More migration files than one install has the instance judge
		// (featureInstallMigrationCheckLimit): none is, and the plan asks
		// for the consent on that ground.
		unchecked := migrations > featureInstallMigrationCheckLimit
		if unchecked {
			plan.TableDrops = append(plan.TableDrops, fmt.Sprintf("migrations/: %d migration files not checked for data loss (an install checks at most %d)", migrations, featureInstallMigrationCheckLimit))
			if !opts.AllowTableDrop {
				plan.Collisions = append(plan.Collisions, fmt.Sprintf("migrations/: the pack adds or changes %d migration files, and an install checks at most %d for data they would drop when the app applies them. Nothing is installed. Push the files first (`benmore push migrations/<file>` checks each one), or install again with allow_table_drop (`--allow-table-drop`) to add them unchecked; a backup is taken before the migrations run.", migrations, featureInstallMigrationCheckLimit))
			}
		}
		for _, rel := range rels {
			if unchecked && rel != "schema.prisma" {
				continue
			}
			body := schemaWrites[rel]
			drops := opts.DataDrops(rel, string(body))
			if len(drops) == 0 {
				continue
			}
			for _, drop := range drops {
				plan.TableDrops = append(plan.TableDrops, rel+": "+drop)
			}
			if !opts.AllowTableDrop {
				plan.Collisions = append(plan.Collisions, featureInstallDropCollision(rel, drops))
			}
		}
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

// featureInstallTargetHolds reports whether the target app already holds body
// at rel, read through the app's root as the regular file it is.
func featureInstallTargetHolds(dir, rel string, body []byte) bool {
	root, err := os.OpenRoot(dir)
	if err != nil {
		return false
	}
	defer root.Close()
	checked, err := featurePackCheckedPath(root, rel)
	if err != nil {
		return false
	}
	existing, err := readRegularInRoot(root, checked, int64(len(body)))
	return err == nil && bytes.Equal(existing, body)
}

// featureInstallDropCollision is the plan collision for data the app would
// drop when it reloads with the pack's file at rel, in the words the write
// gate uses for the same file (schemaWriteDropRefusal).
func featureInstallDropCollision(rel string, drops []string) string {
	if rel == "schema.prisma" {
		return fmt.Sprintf("schema.prisma: the pack's schema.prisma removes the model of a table that still holds data, and the app drops a removed model's table when it reloads: %s. Nothing is installed. To keep the data, keep the model. To drop the table, install again with allow_table_drop (`--allow-table-drop`); a backup is taken before the drop and `benmore restore` can bring it back.", strings.Join(drops, ", "))
	}
	return fmt.Sprintf("%s: it drops data this app still holds, and the app applies a new migration file when it reloads: %s. Nothing is installed. To keep the data, take those statements out of the pack's file. To drop it, install again with allow_table_drop (`--allow-table-drop`); a backup is taken before the migration runs and `benmore restore` can bring it back.", rel, strings.Join(drops, ", "))
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
	root, err := os.OpenRoot(dir)
	if err != nil {
		return plan, err
	}
	defer root.Close()
	if len(pack.SchemaModels) > 0 {
		schemaPath, err := featurePackCheckedPath(root, "schema.prisma")
		if err != nil {
			return plan, err
		}
		var b strings.Builder
		existing, err := root.ReadFile(schemaPath)
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
		if err := root.WriteFile(schemaPath, []byte(b.String()), 0664); err != nil {
			return plan, err
		}
	}
	for p, body := range files {
		if _, err := safeFeatureJoin(dir, p); err != nil {
			return plan, err
		}
		rel, err := featurePackCheckedPath(root, p)
		if err != nil {
			return plan, err
		}
		if err := root.MkdirAll(filepath.Dir(rel), 0755); err != nil {
			return plan, err
		}
		if err := root.WriteFile(rel, body, 0664); err != nil {
			return plan, err
		}
		if featurePackApplyAfterWriteHook != nil {
			if err := featurePackApplyAfterWriteHook(dir, p); err != nil {
				return plan, err
			}
		}
	}
	for _, p := range plan.FileDeletes {
		if err := removeFeaturePackFile(root, dir, p); err != nil {
			return plan, err
		}
	}
	return plan, nil
}

// featurePackCheckedPath returns rel in root-relative form after refusing any
// existing symlink along it. Installs run in the router, and a link planted in
// the tenant tree must not redirect a write outside the app or onto a
// framework path inside it (for example .git/). Callers then operate through
// the os.Root, so a link swapped in mid-install cannot escape either.
func featurePackCheckedPath(root *os.Root, rel string) (string, error) {
	rel = filepath.Clean(filepath.FromSlash(rel))
	if !filepath.IsLocal(rel) {
		return "", fmt.Errorf("path escapes feature root")
	}
	prefix := ""
	for _, seg := range strings.Split(rel, string(filepath.Separator)) {
		prefix = filepath.Join(prefix, seg)
		info, err := root.Lstat(prefix)
		if os.IsNotExist(err) {
			return rel, nil
		}
		if err != nil {
			return "", err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return "", fmt.Errorf("feature install path %q crosses a symlink", filepath.ToSlash(rel))
		}
	}
	return rel, nil
}

// removeFeaturePackFile deletes p under root. Parent directories must not be
// symlinks; a final-component link is removed itself, never its target.
func removeFeaturePackFile(root *os.Root, dir, p string) error {
	if _, err := safeFeatureJoin(dir, p); err != nil {
		return err
	}
	rel := filepath.Clean(filepath.FromSlash(p))
	if parent := filepath.Dir(rel); parent != "." {
		if _, err := featurePackCheckedPath(root, parent); err != nil {
			return err
		}
	}
	if err := root.Remove(rel); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}
