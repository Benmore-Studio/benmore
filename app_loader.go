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
	// checkOnly marks a validation load (tryLoadApp: serve's boot check and
	// `benmore check` in an app directory; never the router, which loads no
	// app). It must not copy the database on every call: at most one
	// pre-migrate snapshot per checkBackupMinInterval.
	checkOnly bool
	// startup marks the one load that begins a served process: connector
	// writes are suspended with their approval binding kept, so the caller can
	// resume them (resumeAppMCPApprovedWrites) once the app has loaded.
	startup bool
	// noErrorDelivery keeps every error report local (`benmore test`), set
	// before anything in the load can report.
	noErrorDelivery bool
}

// loadApp initializes the full app from a directory.
func loadApp(dir string) (app *App, err error) {
	return loadAppWithOptions(dir, appLoadOptions{})
}

func loadAppWithOptions(dir string, opts appLoadOptions) (app *App, err error) {
	if foreignAppDirs.Load() {
		// Refused before anything is read, leased or written (the database
		// open refuses too, errForeignAppLoad).
		return nil, errForeignAppLoad
	}
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
	if config.mcpUnbound != "" {
		log.Printf("  WARNING: MCP %s", config.mcpUnbound)
	}
	for _, problem := range config.mcpToolProblems {
		log.Printf("  WARNING: MCP %s", appMCPToolProblemsNotice(problem))
	}
	// A check load reports these as findings; the load that serves logs them.
	if !opts.checkOnly {
		config.logFlowWarnings()
	}
	nextEnv, err := config.stageEnvironment(dir)
	if err != nil {
		return nil, fmt.Errorf("environment: %w", err)
	}
	// A validation load is not the serving process's start (it may be the
	// boot check, or `benmore check` run by another account). Generating a key
	// here can leave an unreadable owner-only env.yaml and install live
	// database triggers under a key the serving process lacks. Refuse before
	// opening/migrating the database; startup owns initialization.
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
		Stop:              make(chan struct{}),
	}
	app.errorDeliveryOff.Store(opts.noErrorDelivery)

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

	// A restore or refresh-dev that never finished (a router restart, a
	// cancelled request) leaves its database copies behind; nothing else
	// removes them between restores.
	if !opts.checkOnly {
		sweepRestoreStages(dir, "", restoreStageLeftoverAge)
	}

	// Open database
	trace.phase("database_open")
	db, dbCheck, err := openDBWithPolicyLease(dir, nextEnv, policyLease)
	if err != nil {
		return nil, fmt.Errorf("database: %w", err)
	}
	app.DB = db
	app.dbVerifiedAt, app.dbLocalSQLite = dbCheck.verifiedAt, dbCheck.local
	if dbCheck.openedKnown {
		app.dbOpened = dbFileIdentity{Dev: dbCheck.openedDev, Ino: dbCheck.openedIno}
	}
	// The process that serves this database vouches for it when it closes the
	// pool cleanly (db_clean_shutdown.go); so does serve's boot check, whose
	// load runs just before the start-up load in the same process.
	app.markCleanOnClose = opts.startup || (opts.checkOnly && serveBootCheckActive.Load())
	// Read before the schema step builds anything: a database with no
	// application table and no applied migration is new in this load, and its
	// migration files meet it as one (migrate_new_database.go).
	newDatabase := migrationDatabaseIsNew(db)
	// The schema cookie at open: any DDL this load runs bumps it, which is how
	// the schema step below knows whether it changed anything.
	schemaVersionAtOpen, schemaVersionErr := sqliteSchemaVersion(db)
	// Every error return below abandons this pool, so close it. The app DSN
	// carries _cache_size=-64000 (64MB page cache per connection) + a 256MB
	// mmap window; when the router still loaded apps for checks, a
	// repeatedly-failing load grew it by hundreds of MB and fed the 2026-08-01
	// MemoryHigh throttling outage.
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
	schemaCtx, cancelSchema := context.Background(), context.CancelFunc(func() {})
	if opts.checkOnly {
		schemaCtx, cancelSchema = context.WithTimeout(schemaCtx, checkMigrationTimeout)
	}
	loadSnaps := &loadSnapshots{}
	if opts.startup {
		// serve's boot check, just before this load, may already have copied the
		// database before changing it: that copy is this start's pre-image too.
		loadSnaps.first = takeServeBootCheckSnapshot(dir)
	} else if opts.checkOnly && serveBootCheckActive.Load() {
		defer func() {
			if loadSnaps.first != "" {
				handOffServeBootCheckSnapshot(dir, loadSnaps.first)
			}
		}()
	}
	schemaCtx = withLoadSnapshots(schemaCtx, loadSnaps)
	tables, deferredDDL, err := config.loadSchema(schemaCtx, db, dir, opts.checkOnly)
	cancelSchema()
	if err != nil {
		return nil, fmt.Errorf("schema: %w", err)
	}
	app.Tables = tables
	app.UUIDTables = DetectUUIDTables(tables)
	// Annotate tables with @@fulltext metadata from schema.prisma so
	// CRUD ?q= queries can route through SQLite FTS5 instead of LIKE.
	config.annotateFullText(dir, app.Tables)

	// Run migrations (with pre-migration backup)
	schemaManaged := len(tables) > 0 || len(deferredDDL) > 0
	schemaStepApplied, migratedColumns := false, 0
	if schemaManaged {
		// Back up the database before a schema step that will change it. A
		// snapshot is a whole-database copy; a restart that changes nothing
		// has nothing to undo (schema_change_plan.go).
		trace.phase("schema_backup")
		schemaReason := schemaSnapshotReason(db, schemaVersionAtOpen, schemaVersionErr == nil, tables, deferredDDL)
		// Later steps rewrite stored data when the runtime build or the storage
		// configuration changed (db_boot_state.go): one snapshot covers those.
		build := runtimeBuildID()
		storage, digestErr := storageConfigDigest(app, config, nextEnv)
		if digestErr != nil {
			storage = ""
		}
		snapshotReason := schemaReason
		if snapshotReason == "" {
			snapshotReason = bootStateSnapshotReason(dir, build, storage)
		}
		switch {
		case snapshotReason == "":
			log.Printf("  backup: no pre-migrate snapshot needed, the schema step changes nothing")
		case loadSnaps.first != "":
			// The Prisma step copied the database before it changed anything.
			log.Printf("  backup: using the snapshot the schema load took before migrating (%s)", snapshotReason)
		case opts.checkOnly && recentPreMigrateBackup(dir, checkBackupMinInterval):
			log.Printf("  backup: reusing a pre-migrate snapshot from the last %s (%s)", checkBackupMinInterval, snapshotReason)
		default:
			log.Printf("  backup: pre-migrate snapshot (%s)", snapshotReason)
			backupPath, err := preparePreMigrationBackup(dir, hadDBBeforeOpen)
			if err != nil {
				return nil, err
			}
			loadSnaps.first = backupPath
		}
		// The snapshot (or a database too new to need one) covers this build and
		// storage configuration, so a retried start does not copy it again.
		if snapshotReason != "" && (loadSnaps.first != "" || !hadDBBeforeOpen) {
			if err := recordBootState(dir, build, storage); err != nil && !foreignAppDirs.Load() {
				log.Printf("  backup: snapshot taken but its build and configuration could not be recorded (%v); the next start snapshots again", err)
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
		// What the load leaves in place is logged once per change, by a
		// serving load (schema_notice_once.go), not on every start.
		if !opts.checkOnly {
			logSchemaNoticesOnce(dir, schemaNoticesToLog(db, result.Retained))
		}
		// Did the schema step change the schema? A read error counts as yes.
		migratedColumns = len(result.Added)
		schemaStepApplied = migratedColumns > 0
		if versionNow, verr := sqliteSchemaVersion(db); schemaVersionErr != nil || verr != nil || versionNow != schemaVersionAtOpen {
			schemaStepApplied = true
		}
		if schemaStepApplied && schemaReason == "" {
			log.Printf("  WARNING: the schema step changed the schema although its plan found nothing to apply; it is verified without a pre-migrate snapshot")
		}
		// The integrity_check runs after the load's last schema-writing step
		// (schema_verify below), so one check covers what this load changed.
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

	canonicalizeWorkflowColumns(config.workflows, app.Tables)
	app.Flows, app.Workflows = config.flows, config.workflows
	app.MCP, app.mcpWithheld = config.mcp, config.mcpWithheld

	// Load computed fields and install SQLite triggers (a computed column
	// that is also encrypted is written sealed: computedSeal).
	app.Computed = config.computed
	if err := installComputedTriggersSealed(db, app.Computed, config.encrypted); err != nil {
		return nil, fmt.Errorf("computed triggers: %w", err)
	}
	// Declared fields that install no trigger are said out loud.
	logComputedProblems(app.Computed)

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
	versionConfig := withComputedVersionMaintenance(app.versionedConfig(), app.Computed)
	if err := installVersioningBeforeMigrations(db, versionConfig, encConfig); err != nil {
		return nil, fmt.Errorf("versioning: %w", err)
	}

	// Load i18n translations onto the app (not a process global).
	app.I18n = config.i18n

	// Run migration files (migrations/ directory), with a pre-migration backup.
	// The framework tables a file may name are there before the first one
	// (framework_tables_before_migrations.go).
	if err := ensureFrameworkTablesBeforeMigrations(db, config.design, config.pages, signInConfigured(config.design, config.pages)); err != nil {
		return nil, fmt.Errorf("notifications: %w", err)
	}
	trace.phase("user_migrations")
	migrationCtx := withLoadSnapshots(context.Background(), loadSnaps)
	if newDatabase {
		migrationCtx = withMigrationNewDatabase(migrationCtx, db)
	}
	if err := config.runUserMigrations(migrationCtx, db, dir, opts.checkOnly); err != nil {
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
	// Prisma, deferred DDL, user migrations and full-text setup may have
	// created triggers after an enrolled table's revision triggers, which must
	// fire first (app_mcp_revision_order.go).
	if err := reseatAppMCPRevisionTriggersDB(context.Background(), db); err != nil {
		return nil, fmt.Errorf("revision trigger order: %w", err)
	}

	// Verify after the last step that writes schema (Prisma, Migrate, deferred
	// DDL, triggers, history tables, user migrations, full-text tables), so one
	// PRAGMA integrity_check covers everything this load changed; a failure
	// restores the load's first snapshot (db_integrity_ledger.go).
	if schemaManaged {
		trace.phase("schema_verify")
		if err := verifyLoadedSchema(app, opts.checkOnly, schemaStepApplied, migratedColumns, loadSnaps.first, policyLease); err != nil {
			return nil, err
		}
		cleanupOldBackups(dir, maxBackups)
	}

	// Build join map for shorthand engine
	trace.phase("joins")
	app.JoinMap, err = buildJoinMapChecked(db)
	if err != nil {
		return nil, fmt.Errorf("relationships: %w", err)
	}

	// ws_rooms rules whose membership table or column the migrated database
	// does not have: their rooms refuse every join, so say which. A check-only
	// load reports them as findings instead (wsRoomRuleWarnings).
	if !opts.checkOnly {
		logWSRoomRuleReferences(db, app.WSRooms)
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
	publishAppMCPRuntimeGeneration(app, newAppMCPRuntimeGeneration(app, app.MCP, app.Group, app.Roles, app.Access, app.Scopes, app.Design, app.Tables, app.UUIDTables, app.Encrypted, app.Flows, app.sourceFiles, app.environment, app.templateEnvSource, app.Hooks, app.Validators, app.Computed, app.Workflows, pages))
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
