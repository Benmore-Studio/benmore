package main

// Feature-pack data contracts and process-wide configuration. Archive, export, install, transform, path and catalog code live in feature_pack_*.go.

import (
	"regexp"
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
	AllowTableDrop  bool                `json:"allow_table_drop,omitempty"`
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
	// TableDrops is the data the target app would drop when it reloads with
	// the pack's schema.prisma or migrations/ files, each "<file>: <what>
	// (<n> rows)". The plan is blocked on it unless AllowTableDrop.
	TableDrops []string `json:"table_drops,omitempty"`
}

type FeatureInstallOptions struct {
	DryRun        bool   `json:"dry_run"`
	Replace       bool   `json:"replace,omitempty"`
	DeleteMissing bool   `json:"delete_missing,omitempty"`
	RoutePrefix   string `json:"route_prefix,omitempty"`
	ModelPrefix   string `json:"model_prefix,omitempty"`
	RouteMap      map[string]string
	ModelMap      map[string]string
	// AllowTableDrop is the caller's consent to an install that makes the
	// app drop a table or column holding data (allow_table_drop, the write
	// gate's name for it).
	AllowTableDrop bool `json:"allow_table_drop,omitempty"`
	// DataDrops says what the target app would drop when it reloads with
	// content at rel (schema.prisma or a migrations/*.sql file): the write
	// gate's check against the instance's database. nil: not checked (a
	// plan made without an instance).
	DataDrops func(rel, content string) []string `json:"-"`
}

type FeaturePackRename struct {
	From string `json:"from"`
	To   string `json:"to"`
}

// featureInstallMigrationCheckLimit is how many migration files one install
// has the instance judge for data loss. Each is one dry run of the app's
// reload, as the app's user, holding its write lock for up to
// migrationDryRunTimeout; a whole-app pack can carry hundreds of files. A
// pack with more new or changed files than this is not judged file by file:
// the plan says so and asks for the consent instead.
const featureInstallMigrationCheckLimit = 12

var featurePackApplyAfterWriteHook func(dir, rel string) error

var featurePrismaModelNameRE = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*$`)

var envRefRE = regexp.MustCompile(`\b[A-Z][A-Z0-9_]*(?:API_KEY|TOKEN|SECRET|PASSWORD|WEBHOOK|URL|KEY)\b`)

var featureRoutePathRE = regexp.MustCompile(`(?m)^\s*path:\s*["']?(/[^"'\s#]+)`)
