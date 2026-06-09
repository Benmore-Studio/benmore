//go:build !cli

package main

import (
	"fmt"
	"log"
	"path/filepath"
)

// loadApp initializes the full app from a directory.
func loadApp(dir string) (*App, error) {
	app := &App{
		Dir:      dir,
		Sessions: NewSessionStore(),
		Stop:     make(chan struct{}),
	}

	// Cache the owner's plan + accumulated build time onto the App struct
	// so the "Built with Benmore in X minutes" badge can render without
	// a per-request DB query. Subdomain is derived from the dir basename.
	loadAppBuildState(app, filepath.Base(dir))

	// Open database
	db, err := OpenDB(dir)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	app.DB = db

	// Load schema
	tables, deferredDDL, err := LoadSchema(db, dir)
	if err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	app.Tables = tables
	app.UUIDTables = DetectUUIDTables(tables)
	// Annotate tables with @@fulltext metadata from schema.prisma so
	// CRUD ?q= queries can route through SQLite FTS5 instead of LIKE.
	annotateFullTextFromPrisma(dir, app.Tables)
	EnsureFTSTables(db, app.Tables)

	// Run migrations (with pre-migration backup)
	if len(tables) > 0 {
		// Back up database before applying schema migrations
		if _, err := backupDatabase(dir); err != nil {
			log.Printf("  backup warning: %s", err)
		}

		result, err := Migrate(db, tables, false)
		if err != nil {
			return nil, fmt.Errorf("migrate: %w", err)
		}
		// Indexes/views/triggers go in AFTER columns exist (see LoadSchema).
		ApplyDeferredDDL(db, deferredDDL)
		for _, added := range result.Added {
			log.Printf("  migrated: %s", added)
		}
		for _, blocked := range result.Blocked {
			log.Printf("  warning: %s", blocked)
		}

		// Keep only the last 10 backups
		cleanupOldBackups(dir, maxBackups)
	}

	// Post-migration drift check. If schema.prisma is present and the
	// live db doesn't match what was just declared, log a one-line
	// summary so production logs surface manual-ALTER incidents.
	// the schema-drift check shows the full breakdown.
	if models, err := LoadSchemaModelsForDrift(dir); err == nil && len(models) > 0 {
		if drifts, err := DetectSchemaDrift(db, models); err == nil && len(drifts) > 0 {
			log.Printf("  schema drift: %d issue(s) - see the drift report below", len(drifts))
		}
	}

	// Generate schema.sql from schema.yaml if present
	if sql := LoadSchemaShorthand(dir); sql != "" {
		WriteSchemaSQL(dir)
		log.Printf("  schema: generated from schema.yaml")
	}

	// Load environment variables
	LoadEnv(dir)

	// Load design tokens (real YAML parser with fallback)
	app.Design = LoadAppConfigYAML(dir)
	if app.Design == nil {
		app.Design = LoadAppConfig(dir)
	}

	// App ID: auto-generated UUID persisted in .benmore/app_id
	app.AppID = loadOrCreateAppID(dir)
	// External ID: optional, from app.yaml
	if app.Design != nil {
		app.ExternalID = app.Design.SEO["external_id"]
	}

	// Load group scoping config (groups). v2.5.10: TEXT/UUID tenant
	// keys are natively supported - Session.GroupID is a string, the
	// broadcast layer + auto-CRUD filters pass it through as a string
	// against either INTEGER (legacy) or TEXT (UUID) columns thanks to
	// SQLite's dynamic typing. The earlier refuse-to-start guard for
	// non-INTEGER keys (commit a4c4f05) is removed now that the
	// underlying issue is fixed.
	app.Group = LoadGroupConfig(dir)

	// Per-table read-filter overrides from app.yaml `scopes:` -
	// declarative public-feed support without writing a flow.
	app.Scopes = LoadScopes(dir)

	// Declarative per-model access control from app.yaml `access:`.
	// Default-private floor when nil; see access.go.
	app.Access = LoadAccess(dir)

	// Load developer-defined roles with scope mappings
	app.Roles = LoadRolesConfig(dir)

	// Auth paths are discovered from pages after LoadPages (below)

	// Load cross-field validators
	app.Validators = LoadValidators(dir)

	// Load admin.yaml - opt-in customisation for the auto-admin panel
	// (hide tables, restrict columns, mark fields readonly, etc.)
	app.Admin = LoadAdminConfig(dir)

	// Load hooks (real YAML parser with fallback)
	app.Hooks = LoadHooksYAML(dir)
	if app.Hooks == nil {
		app.Hooks = LoadHooks(dir)
	}

	// Synthesize on_insert hooks for any `auto_memberships:` blocks in
	// app.yaml. An earlier app build's #1 schema boilerplate was "on create
	// public channel, bulk-INSERT memberships for every active user" -
	// declarative shorthand collapses that down to a 3-line app.yaml
	// stanza, no hooks.yaml dance needed.
	synthesizeAutoMembershipHooks(app)

	// Load flows (real YAML parser with fallback)
	app.Flows = LoadFlowsYAML(dir)
	if app.Flows == nil {
		app.Flows = LoadFlows(dir)
	}

	// Load workflows (state machines)
	app.Workflows = LoadWorkflowsYAML(dir)

	// Load computed fields and install SQLite triggers
	app.Computed = LoadComputedFieldsYAML(dir)
	if app.Computed != nil {
		InstallComputedTriggers(db, app.Computed)
	}

	// Initialize field-level encryption and install triggers
	encConfig := LoadEncryptedFieldsConfig(dir)
	app.Encrypted = encConfig
	if err := InitFieldEncryption(dir, encConfig); err != nil {
		return nil, err
	}
	if encConfig != nil {
		InstallEncryptionTriggers(db, encConfig)
		// Blind-index machinery: sibling columns, indices, and INSERT/
		// UPDATE triggers that populate them from plaintext. Idempotent
		// - safe to run on every boot. Activated only for fields
		// flagged `blind_index: true` in encrypted.yaml.
		EnsureBlindColumns(db, encConfig)
		InstallBlindIndexTriggers(db, encConfig)
	}

	// Initialize content versioning
	versionConfig := LoadVersionedConfig(dir)
	if versionConfig != nil {
		InstallVersioningTriggers(db, versionConfig)
	}

	// Load i18n translations
	LoadI18n(dir)

	// Run migration files (migrations/ directory)
	if err := RunMigrations(db, dir); err != nil {
		log.Printf("  migration warning: %s", err)
	}

	// Build join map for shorthand engine
	app.JoinMap = BuildJoinMap(db)

	// Load pages
	pages, partials, err := LoadPages(dir)
	if err != nil {
		return nil, fmt.Errorf("pages: %w", err)
	}
	app.Pages = pages
	app.Partials = partials

	// Discover auth paths from page type="" attributes
	app.Paths = DiscoverAuthPaths(pages)

	// Cron jobs declared in cron.yaml. The scheduler is started later
	// from buildAppMux so it has the same lifecycle as other workers.
	app.Cron = LoadCron(dir)

	return app, nil
}
