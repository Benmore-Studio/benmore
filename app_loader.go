//go:build !cli

package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
)

// loadApp initializes the full app from a directory.
func loadApp(dir string) (app *App, err error) {
	trace := newAppLoadTrace(dir)
	defer func() { trace.finish(err) }()
	trace.phase("config")
	config, err := loadRuntimeConfig(dir)
	if err != nil {
		return nil, err
	}
	if err := LoadEnv(dir); err != nil {
		return nil, fmt.Errorf("environment: %w", err)
	}
	app = &App{
		Dir:      dir,
		Sessions: NewSessionStore(),
		Stop:     make(chan struct{}),
	}

	// Cache the owner's plan + accumulated build time onto the App struct
	// so the "Built with Benmore in X minutes" badge can render without
	// a per-request DB query. Subdomain is derived from the dir basename.
	loadAppBuildState(app, filepath.Base(dir))

	hadDBBeforeOpen := false
	if _, err := os.Stat(filepath.Join(dir, "data.db")); err == nil {
		hadDBBeforeOpen = true
	}

	// Open database
	trace.phase("database_open")
	db, err := OpenDB(dir)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	app.DB = db
	// Every error return below abandons this pool. In the ROUTER process that
	// is a permanent leak: MCP write_file/edit_file runs RunCompleteCheck ->
	// tryLoadApp -> loadApp on every edit, and the app DSN carries
	// _cache_size=-64000 (64MB page cache per connection) + a 256MB mmap
	// window, so a repeatedly-failing load grew the router by hundreds of MB
	// and fed the 2026-08-01 MemoryHigh throttling outage.
	defer func() {
		if err != nil {
			db.Close()
		}
	}()

	// Load schema
	trace.phase("schema_load")
	tables, deferredDDL, err := LoadSchema(db, dir)
	if err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	app.Tables = tables
	app.UUIDTables = DetectUUIDTables(tables)
	// Annotate tables with @@fulltext metadata from schema.prisma so
	// CRUD ?q= queries can route through SQLite FTS5 instead of LIKE.
	annotateFullTextFromPrisma(dir, app.Tables)

	// Run migrations (with pre-migration backup)
	if len(tables) > 0 || len(deferredDDL) > 0 {
		// Back up database before applying schema migrations
		trace.phase("schema_backup")
		backupPath, err := preparePreMigrationBackup(dir, hadDBBeforeOpen)
		if err != nil {
			return nil, err
		}

		trace.phase("schema_migrate")
		result, err := Migrate(db, tables, false)
		if err != nil {
			return nil, fmt.Errorf("migrate: %w", err)
		}
		// Indexes/views/triggers go in AFTER columns exist (see LoadSchema).
		if err := ApplyDeferredDDL(db, deferredDDL); err != nil {
			return nil, err
		}
		for _, added := range result.Added {
			log.Printf("  migrated: %s", added)
		}
		for _, blocked := range result.Blocked {
			log.Printf("  warning: %s", blocked)
		}
		trace.phase("schema_verify")
		if err := verifyPostMigrationAndRestore(dir, db, backupPath); err != nil {
			return nil, err
		}

		// Keep only the last 10 backups
		cleanupOldBackups(dir, maxBackups)
	}
	trace.phase("app_config")

	// Generate schema.sql from schema.yaml if present
	if sql := LoadSchemaShorthand(dir); sql != "" {
		WriteSchemaSQL(dir)
		log.Printf("  schema: generated from schema.yaml")
	}

	app.Design, app.Backup = config.design, config.backup

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

	// WS room authorization patterns from app.yaml `ws_rooms:` -
	// membership-gated join for room-name patterns (v2.7.164).
	app.WSRooms = LoadWSRooms(dir)

	// Load developer-defined roles with scope mappings
	app.Roles = LoadRolesConfig(dir)

	// Auth paths are discovered from pages after LoadPages (below)

	// Load cross-field validators
	app.Validators = LoadValidators(dir)

	// Load admin.yaml - opt-in customisation for the auto-admin panel
	// (hide tables, restrict columns, mark fields readonly, etc.)
	app.Admin = LoadAdminConfig(dir)

	app.Hooks = config.hooks

	// Synthesize on_insert hooks for any `auto_memberships:` blocks in
	// app.yaml. An earlier app build's #1 schema boilerplate was "on create
	// public channel, bulk-INSERT memberships for every active user" -
	// declarative shorthand collapses that down to a 3-line app.yaml
	// stanza, no hooks.yaml dance needed.
	synthesizeAutoMembershipHooks(app)

	app.Flows, app.Workflows = config.flows, config.workflows

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

	// Run migration files (migrations/ directory), with a pre-migration backup.
	trace.phase("user_migrations")
	if err := runUserMigrationsWithBackup(db, dir); err != nil {
		return nil, fmt.Errorf("user migration: %w", err)
	}

	// Reconcile search only after schema and user migrations have added columns.
	trace.phase("fulltext")
	if err := EnsureFTSTables(db, app.Tables); err != nil {
		return nil, err
	}

	// Build join map for shorthand engine
	trace.phase("joins")
	app.JoinMap = BuildJoinMap(db)

	// Load pages
	trace.phase("pages")
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
	app.Cron = config.cron

	return app, nil
}
