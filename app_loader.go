//go:build !cli

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"
)

// appLoadOptions tune loadApp for callers that are not booting the app.
type appLoadOptions struct {
	// checkOnly marks a validation load (the router's per-edit RunCompleteCheck).
	// It must not copy the tenant's whole database on every call: at most one
	// pre-migrate snapshot per checkBackupMinInterval.
	checkOnly bool
	// startup marks the one load that begins a served process: connector
	// writes are suspended with their approval binding kept, so the caller can
	// resume them (resumeAppMCPApprovedWrites) once the app has loaded.
	startup bool
}

// loadApp initializes the full app from a directory.
func loadApp(dir string) (app *App, err error) {
	return loadAppWithOptions(dir, appLoadOptions{})
}

func loadAppWithOptions(dir string, opts appLoadOptions) (app *App, err error) {
	trace := newAppLoadTrace(dir)
	defer func() { trace.finish(err) }()
	trace.phase("config")
	config, err := loadServedRuntimeConfig(dir)
	if err != nil {
		return nil, err
	}
	if config.mcpWithheld != "" {
		log.Printf("  MCP connector withheld: %s", config.mcpWithheld)
	}
	nextEnv, err := config.stageEnvironment(dir)
	if err != nil {
		return nil, fmt.Errorf("environment: %w", err)
	}
	// Validation may run as the hosted router, not the app's owning user.
	// Generating a key here can leave an unreadable owner-only env.yaml and
	// install live database triggers under a key the serving process lacks.
	// Refuse before opening/migrating the database; startup owns initialization.
	if opts.checkOnly && nextEnv["ENCRYPTION_KEY"] == "" && config.encrypted != nil {
		for _, fields := range config.encrypted.Fields {
			if len(fields) > 0 {
				return nil, fmt.Errorf("encryption: restart the app to initialize a durable ENCRYPTION_KEY before validating encrypted fields")
			}
		}
	}
	app = &App{
		Dir:               dir,
		sourceFiles:       config.sourceFiles,
		templateEnvSource: config.templateEnvSource,
		environment:       nextEnv,
		Sessions:          NewSessionStore(),
		Stop:              make(chan struct{}),
	}

	// Cache the owner's plan + accumulated build time onto the App struct
	// so the "Built with Benmore in X minutes" badge can render without
	// a per-request DB query. Subdomain is derived from the dir basename.
	loadAppBuildState(app, filepath.Base(dir))

	hadDBBeforeOpen := false
	if _, err := os.Stat(filepath.Join(dir, "data.db")); err == nil {
		hadDBBeforeOpen = true
	}
	policyCtx, cancelPolicy := context.WithTimeout(context.Background(), 30*time.Second)
	beginPolicy := beginAppMCPPolicyChange
	// A check-only load (serve's boot check runs one just before the start-up
	// load) still turns writes off, but must keep the approval binding: with
	// the plain lease it forgot the approved digests, so every hosted start
	// found nothing to resume.
	if opts.startup || opts.checkOnly {
		beginPolicy = beginAppMCPStartupPolicyChange
	}
	policyRelease, policyLease, policyErr := beginPolicy(policyCtx, dir)
	cancelPolicy()
	if policyErr != nil {
		return nil, fmt.Errorf("connector policy lease: %w", policyErr)
	}
	defer policyRelease()

	// Open database
	trace.phase("database_open")
	db, err := openDBWithPolicyLease(dir, nextEnv, policyLease)
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
	// A fresh database has no live routes to protect and its migrations cannot
	// be projected statically (ALTER/DROP), so the manifest is checked against
	// the migrated schema right after user migrations instead. The first boot
	// itself makes the database non-fresh (schema creation), so the decision is
	// recorded in a marker that only a completed load removes: a first boot
	// that fails and is retried stays on this path.
	freshMarker := appMCPFirstBootMarker(dir)
	_, markerErr := os.Lstat(freshMarker)
	freshMCPDatabase := config.mcp != nil && (markerErr == nil || appMCPDatabaseIsFresh(db))
	if freshMCPDatabase && markerErr != nil {
		if os.MkdirAll(filepath.Dir(freshMarker), 0700) == nil {
			os.WriteFile(freshMarker, nil, 0600) // best effort: without it a failed first boot retries strictly
		}
	}
	if !freshMCPDatabase {
		if err := validateAppMCPCandidateRoutes(dir, config, db, nextEnv); err != nil {
			return nil, err
		}
	}
	lifecycleCtx, cancelLifecycle := context.WithTimeout(context.Background(), 30*time.Second)
	lifecyclePlan, err := preflightAppMCPOperationLifecycle(lifecycleCtx, app, config, nextEnv, false)
	cancelLifecycle()
	if err != nil {
		return nil, fmt.Errorf("operation lifecycle preflight: %w", err)
	}

	if config.mcp != nil {
		if err := ensureAppMCPGrantTables(db); err != nil {
			return nil, fmt.Errorf("connector grant migration: %w", err)
		}
	}
	// Load schema
	trace.phase("schema_load")
	tables, deferredDDL, err := config.loadSchema(db, dir)
	if err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	app.Tables = tables
	app.UUIDTables = DetectUUIDTables(tables)
	// Annotate tables with @@fulltext metadata from schema.prisma so
	// CRUD ?q= queries can route through SQLite FTS5 instead of LIKE.
	config.annotateFullText(dir, app.Tables)

	// Run migrations (with pre-migration backup)
	if len(tables) > 0 || len(deferredDDL) > 0 {
		// Back up database before applying schema migrations
		trace.phase("schema_backup")
		backupPath := ""
		if !(opts.checkOnly && recentPreMigrateBackup(dir, checkBackupMinInterval)) {
			var err error
			backupPath, err = preparePreMigrationBackup(dir, hadDBBeforeOpen)
			if err != nil {
				return nil, err
			}
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
		// PRAGMA integrity_check reads the whole database. A validation load
		// that changed nothing has nothing to verify; the app's own boot does.
		if !(opts.checkOnly && len(result.Added) == 0) {
			if err := verifyPostMigrationAndRestoreWithLease(dir, db, backupPath, policyLease); err != nil {
				return nil, err
			}
		}

		// Keep only the last 10 backups
		cleanupOldBackups(dir, maxBackups)
	}
	trace.phase("app_config")

	// Generate schema.sql from schema.yaml if present. Never for an app with
	// mcp.yaml (withheld included): startup must not rewrite reviewed source.
	if config.mcp == nil && config.mcpWithheld == "" {
		if sql := LoadSchemaShorthand(dir); sql != "" {
			WriteSchemaSQL(dir)
			log.Printf("  schema: generated from schema.yaml")
		}
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
	app.Group = config.group

	// Per-table read-filter overrides from app.yaml `scopes:` -
	// declarative public-feed support without writing a flow.
	app.Scopes = config.scopes

	// Declarative per-model access control from app.yaml `access:`.
	// Default-private floor when nil; see access.go.
	app.Access = config.access

	// WS room authorization patterns from app.yaml `ws_rooms:` -
	// membership-gated join for room-name patterns (v2.7.164).
	app.WSRooms = config.wsRooms

	// Load developer-defined roles with scope mappings
	bindRoleTableScopes(config.roles, app.Tables)
	app.Roles = config.roles

	// Auth paths are discovered from pages after LoadPages (below)

	// Load cross-field validators
	app.Validators = config.validators

	// Load admin.yaml - opt-in customisation for the auto-admin panel
	// (hide tables, restrict columns, mark fields readonly, etc.)
	app.Admin = config.admin

	app.Hooks = config.hooks

	// Synthesize on_insert hooks for any `auto_memberships:` blocks in
	// app.yaml. An earlier app build's #1 schema boilerplate was "on create
	// public channel, bulk-INSERT memberships for every active user" -
	// declarative shorthand collapses that down to a 3-line app.yaml
	// stanza, no hooks.yaml dance needed.
	synthesizeAutoMembershipHooks(app)

	app.Flows, app.Workflows = config.flows, config.workflows
	app.MCP, app.mcpWithheld = config.mcp, config.mcpWithheld

	// Load computed fields and install SQLite triggers
	app.Computed = config.computed
	if err := installComputedTriggersChecked(db, app.Computed); err != nil {
		return nil, fmt.Errorf("computed triggers: %w", err)
	}

	// Initialize field-level encryption and install triggers
	encConfig := config.encrypted
	app.Encrypted = encConfig
	if err := initFieldEncryption(dir, encConfig, nextEnv["ENCRYPTION_KEY"]); err != nil {
		return nil, err
	}
	if err := installEncryptionBeforeMigrations(db, encConfig); err != nil {
		return nil, fmt.Errorf("encrypted-field triggers before migrations: %w", err)
	}

	// Initialize content versioning
	versionConfig := app.versionedConfig()
	if err := installVersioningBeforeMigrations(db, versionConfig, encConfig); err != nil {
		return nil, fmt.Errorf("versioning: %w", err)
	}

	// Load i18n translations onto the app (not a process global).
	app.I18n = config.i18n

	// Run migration files (migrations/ directory), with a pre-migration backup.
	trace.phase("user_migrations")
	if err := config.runUserMigrations(context.Background(), db, dir, opts.checkOnly); err != nil {
		return nil, fmt.Errorf("user migration: %w", err)
	}
	if freshMCPDatabase {
		if err := validateAppMCPCandidateRoutes(dir, config, db, nextEnv); err != nil {
			return nil, err
		}
	}

	// User migrations can add source columns after initial reconciliation.
	if err := installReloadStorage(db, versionConfig, encConfig); err != nil {
		return nil, fmt.Errorf("storage after migrations: %w", err)
	}

	// Reconcile search only after schema and user migrations have added columns.
	trace.phase("fulltext")
	if err := EnsureFTSTables(db, app.Tables); err != nil {
		return nil, err
	}

	// Build join map for shorthand engine
	trace.phase("joins")
	app.JoinMap, err = buildJoinMapChecked(db)
	if err != nil {
		return nil, fmt.Errorf("relationships: %w", err)
	}

	// Load pages
	trace.phase("pages")
	pages, partials := config.pages, config.partials
	if pages == nil {
		pages, partials, err = LoadPages(dir)
		if err != nil {
			return nil, fmt.Errorf("pages: %w", err)
		}
	}
	app.Pages = pages
	app.Partials = partials
	lifecycleCtx, cancelLifecycle = context.WithTimeout(context.Background(), 30*time.Second)
	err = finishAppMCPOperationLifecycle(lifecycleCtx, app, lifecyclePlan, opts.checkOnly)
	cancelLifecycle()
	if err != nil {
		return nil, fmt.Errorf("operation lifecycle finalization: %w", err)
	}
	app.mcpGeneration = newAppMCPRuntimeGeneration(app, app.MCP, app.Group, app.Roles, app.Access, app.Scopes, app.Design, app.Tables, app.UUIDTables, app.Encrypted, app.Flows, app.sourceFiles, app.environment, app.templateEnvSource, app.Hooks, app.Validators, app.Computed, app.Workflows, pages)
	if !opts.checkOnly {
		// Connections removed from mcp.yaml lose their stored credentials.
		purgeUndeclaredAppMCPConnectionCredentials(db, app.MCP)
	}

	// Discover auth paths from page type="" attributes
	app.Paths = DiscoverAuthPaths(pages)

	// Cron jobs declared in cron.yaml. The scheduler is started later
	// from buildAppMux so it has the same lifecycle as other workers.
	app.Cron = config.cron

	storeAppEnv(dir, nextEnv)
	if freshMCPDatabase && !opts.checkOnly {
		os.Remove(freshMarker) // routes now serve from this database
	}
	return app, nil
}
