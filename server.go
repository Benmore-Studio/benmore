//go:build !cli

package main

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"
)

// hotHandler wraps a swappable http.Handler. SIGHUP causes the per-app
// server to rebuild the mux + middleware chain and atomically swap the
// stored handler. New requests pick up the new state immediately; the
// listening socket is never closed, so there's zero downtime.
//
// Replaces the prior "systemctl restart" path for content/env reloads
// (which dropped connections, returned 502 at Cloudflare for ~1-2s, and
// re-fired cron jobs on every restart). SIGHUP keeps the socket alive.
type hotHandler struct {
	current atomic.Value // stores http.Handler
}

func (h *hotHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.current.Load().(http.Handler).ServeHTTP(w, r)
}

func (h *hotHandler) swap(next http.Handler) { h.current.Store(next) }

// hostedHotHandler is the singleton hot-swap handler for the per-app
// `benmore serve` process. SIGHUP handler reaches it through this
// package-level variable. Nil when not in per-app server mode.
var hostedHotHandler *hotHandler

// hotReloadOnce ensures we don't install duplicate signal handlers if
// StartServer is called twice in the same process (test code, host
// mode reusing the listener, etc.).
var hotReloadInstalled atomic.Bool

// installHotReloadSignal wires SIGHUP → in-process hot reload. The
// handler:
//   - re-reads YAML configs (app.yaml, hooks.yaml, flows.yaml, cron.yaml,
//     env.yaml + platform_env)
//   - stops the previous cron scheduler goroutine (via app.Stop close)
//     and starts a new one
//   - rebuilds the mux + middleware chain
//   - atomically swaps the served handler
//
// Idempotent CREATE-IF-NOT-EXISTS migrations run again on every reload,
// which is the right shape - they no-op when there's nothing to change.
// Heavy DDL (CREATE UNIQUE INDEX with prechecks) is the only case where
// a reload could surface a new error; that's still better than the old
// behavior (silent restart loop with no log signal).
func installHotReloadSignal(app *App, dev bool) {
	if !hotReloadInstalled.CompareAndSwap(false, true) {
		return
	}
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGHUP)
	go func() {
		for range ch {
			log.Printf("  SIGHUP - hot reloading app config + flows + cron")
			if err := hotReloadApp(app, dev); err != nil {
				log.Printf("  hot reload failed: %s (server kept serving previous config)", err)
				continue
			}
			log.Printf("  hot reload complete")
		}
	}()
}

// hotReloadApp re-runs the per-app loaders in place, stops the old cron
// scheduler, starts a new one, and swaps the served handler. Returns
// nil on success or an error if any loader failed (in which case the
// previous handler is still serving - failure is non-fatal).
//
// What's reloaded:
//   - app.yaml / Design / theme / SEO / auth / features
//   - schema.prisma (re-runs idempotent migrations)
//   - hooks.yaml / flows.yaml / workflows.yaml / cron.yaml
//   - env.yaml + platform_env
//   - the HTTP mux (route table)
//
// What's NOT reloaded (intentional):
//   - the DB connection (db.go would re-open; sessions + WAL state would churn)
//   - the SSE / WS hub (clients are mid-stream; killing them is rude)
//   - the listening socket (the whole point - no 502 window)
func hotReloadApp(app *App, dev bool) error {
	// Re-run the per-app loaders. reloadAppConfig is the in-place
	// variant of loadApp's config-reading section - it does NOT
	// re-open the DB or re-init the SSE hub.
	if err := reloadAppConfig(app); err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Stop any goroutines that listen on app.Stop (cron, jobs worker,
	// retention sweeper). Then refresh the channel so a fresh round of
	// goroutines can restart with the new config. Under app.mu so the swap is
	// serialized against Shutdown's locked read; restarted workers each capture
	// their own copy of app.Stop at spawn, so the old generation observes the
	// close and exits while the new generation gets the fresh channel.
	app.mu.Lock()
	close(app.Stop)
	app.Stop = make(chan struct{})
	app.mu.Unlock()

	baseURL := ""
	if app.Design != nil {
		baseURL = app.Design.SEO["url"]
	}
	if baseURL == "" {
		baseURL = fmt.Sprintf("http://localhost:%d", app.ServerPort)
	}
	mux := buildAppMux(app, dev, baseURL)
	handler := wrapMiddleware(mux, app, dev)
	hostedHotHandler.swap(handler)
	app.reloadGeneration.Add(1)
	if dev || devReloadClientEnabled(app) {
		BroadcastReload(app, "hot-reload")
	}
	return nil
}

// reloadAppConfig re-reads the per-app config files in place. Same
// content as loadApp's middle section but without DB open + first-time
// table creation (those happen exactly once at process start). Configuration
// is published only after checked loaders and migrations succeed. Schema work that
// already committed is not undone when a later operation fails.
func reloadAppConfig(app *App) error {
	config, err := loadServedRuntimeConfig(app.Dir)
	if err != nil {
		return err
	}
	if config.mcpWithheld != "" {
		log.Printf("  MCP connector withheld: %s", config.mcpWithheld)
	}
	nextEnv, err := config.stageEnvironment(app.Dir)
	if err != nil {
		return fmt.Errorf("environment: %w", err)
	}
	return reloadAppConfigStaged(app, config, nextEnv)
}

// Publish already checked values after fallible schema work. Keeping this seam
// value-based prevents deployment-file rereads from replacing staged authority.
func reloadAppConfigStaged(app *App, config *runtimeConfig, nextEnv map[string]string) error {
	if err := validateReloadEncryptionKey(app, config.encrypted, nextEnv); err != nil {
		return err
	}
	policyCtx, cancelPolicy := context.WithTimeout(context.Background(), 30*time.Second)
	policyRelease, _, policyErr := beginAppMCPPolicyChange(policyCtx, app.Dir)
	cancelPolicy()
	if policyErr != nil {
		return fmt.Errorf("connector policy lease: %w", policyErr)
	}
	defer policyRelease()
	if err := validateAppMCPCandidateRoutes(app.Dir, config, app.DB, nextEnv); err != nil {
		return err
	}
	lifecycleCtx, cancelLifecycle := context.WithTimeout(context.Background(), 30*time.Second)
	lifecyclePlan, err := preflightAppMCPOperationLifecycle(lifecycleCtx, app, config, nextEnv, true)
	cancelLifecycle()
	if err != nil {
		return fmt.Errorf("operation lifecycle preflight: %w", err)
	}
	if config.mcp != nil {
		if err := ensureAppMCPGrantTables(app.DB); err != nil {
			return fmt.Errorf("connector grant migration: %w", err)
		}
	}
	// schema - rerun migrations (idempotent).
	//
	// If LoadSchema reports a "disk I/O error" or "file is not a
	// database" the per-app DB handle is wedged - almost always
	// because something (a deploy, a push, manual file-level repair)
	// replaced the data.db file out from under the running process,
	// leaving us pointing at a deleted inode. No amount of SIGHUP can
	// recover this; the only fix is a fresh process with a fresh
	// open. Bail out so systemd's Restart=on-failure respawns us.
	// Pre-v2.7.5 the handler logged the error, kept serving the dead
	// handle, and every subsequent flow execution spammed the journal
	// with `[locks] cleanup error: file is not a database` while
	// returning 5xx on every write path. Agents had no escape hatch
	// because no CLI command shells out to `systemctl restart`.
	tables, deferredDDL, err := config.loadSchema(app.DB, app.Dir)
	if err != nil {
		if isDBHandleWedged(err) {
			log.Fatalf(
				"FATAL: the per-app DB handle is wedged (%s) - the data.db file appears to have been replaced or corrupted under the running process. "+
					"Exiting so systemd restarts us. On restart, OpenDB will detect the corruption and auto-restore from the most recent "+
					"pre-migrate backup at .benmore/backups/pre-migrate-*.db (the original gets moved aside to data.db.corrupt-<timestamp> "+
					"for inspection). If you see this repeatedly without auto-recovery succeeding, every backup is also corrupt - check the "+
					".failed.sql files in migrations/ for the actual root cause.",
				err,
			)
		}
		return fmt.Errorf("schema: %w", err)
	}
	// Compute into locals + annotate the local; published under app.mu below
	// alongside flows/cron so concurrent readers (hasColumn ranging app.Tables,
	// request handlers reading app.Design) never see a mid-reload reassignment.
	uuidTables := DetectUUIDTables(tables)
	config.annotateFullText(app.Dir, tables)
	if _, err := Migrate(app.DB, tables, false); err != nil {
		return fmt.Errorf("migrate: %w", err)
	}
	// Indexes/views/triggers go in AFTER columns exist (see LoadSchema).
	if err := ApplyDeferredDDL(app.DB, deferredDDL); err != nil {
		return err
	}
	// Apply user migrations/*.sql shipped by this deploy. This runs in the
	// per-app process (never router-side); the schema-diff migrate above only
	// handles column adds, not arbitrary SQL. Keep the old handler and workers
	// when a migration fails; do not advertise a completed reload.
	if err := config.runUserMigrations(context.Background(), app.DB, app.Dir, false); err != nil {
		return fmt.Errorf("user migration: %w", err)
	}
	joinMap, err := buildJoinMapChecked(app.DB)
	if err != nil {
		return fmt.Errorf("relationships: %w", err)
	}
	if err := EnsureFTSTables(app.DB, tables); err != nil {
		return err
	}
	if err := installComputedTriggersChecked(app.DB, config.computed); err != nil {
		return fmt.Errorf("computed triggers: %w", err)
	}
	// v2.7.17: re-load the configs that hot-reload was missing.
	// Without these, every change to app.yaml's `roles:` / `access:` /
	// `aggregates:` / `groups:` was invisible until a full systemd
	// restart, and the bm.d.ts generator served stale types reflecting
	// the boot-time state. Same loader functions app_loader.loadApp uses
	// on cold start - keep them in sync if any are added.
	roles := config.roles
	access := config.access
	scopes := config.scopes
	group := config.group
	encrypted := config.encrypted
	stagedHooks := cloneHookConfig(config.hooks)
	stagedApp := &App{Design: config.design, Hooks: stagedHooks}
	synthesizeAutoMembershipHooks(stagedApp)
	stagedHooks = stagedApp.Hooks
	pages := config.pages
	if pages == nil {
		app.mu.RLock()
		pages = app.Pages
		app.mu.RUnlock()
	}
	lifecycleCtx, cancelLifecycle = context.WithTimeout(context.Background(), 30*time.Second)
	err = finishAppMCPOperationLifecycle(lifecycleCtx, app, lifecyclePlan, false)
	cancelLifecycle()
	if err != nil {
		return fmt.Errorf("operation lifecycle finalization: %w", err)
	}
	// Reconcile history last: a later rejected candidate must not replace the
	// active generation's history/encryption policy.
	versionSource := &App{Dir: app.Dir, MCP: config.mcp, sourceFiles: config.sourceFiles}
	if err := installReloadStorage(app.DB, versionSource.versionedConfig(), config.encrypted); err != nil {
		return err
	}

	bindRoleTableScopes(roles, tables) // before the generation captures roles
	generation := newAppMCPRuntimeGeneration(app, config.mcp, group, roles, access, scopes, config.design, tables, uuidTables, encrypted, config.flows, config.sourceFiles, nextEnv, config.templateEnvSource, stagedHooks, config.validators, config.computed, config.workflows, pages)
	generation.view.JoinMap = joinMap
	app.mu.Lock()
	app.Design, app.Backup = config.design, config.backup
	app.Tables = tables
	app.JoinMap = joinMap
	app.UUIDTables = uuidTables
	app.Flows = config.flows
	app.MCP, app.mcpWithheld = config.mcp, config.mcpWithheld
	app.sourceFiles = config.sourceFiles
	app.templateEnvSource = config.templateEnvSource
	app.environment = nextEnv
	if config.pages != nil {
		app.Pages, app.Partials, app.Paths = config.pages, config.partials, config.paths
	}
	app.Hooks = stagedHooks
	app.Workflows = config.workflows
	app.Cron = config.cron
	app.Roles = roles
	app.Access = access
	app.Scopes = scopes
	app.Group = group
	app.Encrypted = encrypted
	app.mcpGeneration = generation
	app.WSRooms, app.Validators, app.Admin, app.Computed = config.wsRooms, config.validators, config.admin, config.computed
	app.I18n = config.i18n
	// Publish the merged environment before generation readers can observe
	// the new manifest, flows and YAML-only template source.
	storeAppEnv(app.Dir, nextEnv)
	app.mu.Unlock()
	// Connections the new manifest no longer declares lose their stored
	// credentials, so re-adding one later does not bring them back.
	purgeUndeclaredAppMCPConnectionCredentials(app.DB, config.mcp)
	// NOTE: cron is (re)started by buildAppMux, which always runs after this on
	// the hot-reload path - starting it here too double-spawned the scheduler
	// each reload (the second start closed the first's channel and respawned),
	// relying entirely on cronUniqueKey dedup to avoid a duplicate fire.
	return nil
}

// isDBHandleWedged reports whether the SQLite error indicates that the
// per-app handle is pointing at a file that no longer exists or is
// otherwise unusable. Two SQLite error messages cover the practical
// failure modes:
//
//   - "disk I/O error" / "no such file or directory" - the underlying
//     data.db file was unlinked while we held the handle.
//   - "file is not a database" - the handle is open but the bytes at
//     that path are no longer a valid SQLite database (truncated,
//     swapped to a different file, etc).
//
// Either way, the handle is irrecoverable in-process; only a fresh
// `os.Open` (i.e. a new process) restores normal operation.
func isDBHandleWedged(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "file is not a database") ||
		strings.Contains(msg, "disk I/O error") ||
		strings.Contains(msg, "database disk image is malformed")
}

// buildAppMux creates the full HTTP mux for an app with all route groups registered.
// This is the single source of truth for route registration - used by both StartServer and HostPlatform.
func buildAppMux(app *App, dev bool, baseURL string) *http.ServeMux {
	return buildAppRouteMux(app, dev, baseURL, true, nil).ServeMux
}

// Candidate and runtime use identical registration order and handler bodies.
// initialize is false only for preflight: no handler is served or startup work run.
func buildAppRouteMux(app *App, dev bool, baseURL string, initialize bool, tables []string) *appRouteMux {
	mux := &appRouteMux{ServeMux: http.NewServeMux()}

	if app.MCP != nil {
		if initialize {
			if err := ensureAppMCPArtifactTables(app.DB); err != nil {
				log.Printf("MCP artifact table unavailable: %v", err)
			}
		}
		registerAppMCPTransport(mux, app, appMCPResourceAt(app, baseURL))
	} else if app.mcpWithheld != "" {
		registerAppMCPWithheldRoutes(mux, app)
	}
	if initialize {
		// Also without mcp.yaml: bytes of artifacts made before it was removed.
		sweepAppMCPOrphanArtifacts(app)
		retireUnusedAppMCPRevisionLedger(app)
	}

	// Prometheus /metrics endpoint - dark unless BENMORE_METRICS_TOKEN
	// is set. Registered first so it doesn't get shadowed by clean-URL
	// fallbacks.
	RegisterMetricsRoute(mux)

	// Framework tables (auto-created)
	if initialize {
		EnsureAuditLogTable(app.DB)
		EnsureScopingIndexes(app) // user_id / tenant key / FK / member-of (scoping_indexes.go)
		StartAuditRetentionWorker(app)
	}
	if initialize {
		EnsureUploadOwnersTable(app.DB)
	}
	// Audit-log shipper: tail _benmore_audit_log → POST to a configured
	// webhook destination. No-op unless BENMORE_AUDIT_WEBHOOK_URL is set.
	// Spawns one background goroutine per app, watched by app.Stop.
	if initialize {
		StartAuditShipper(app)
	}
	// Encryption key rotation endpoint (POST /api/_internal/encryption/rotate,
	// admin-only). Lives on the per-app mux because the rotation has to
	// run inside the per-app process - that's where appEncryptionKey + the
	// per-tenant Encrypted config are loaded; the router process has neither.
	RegisterEncryptionRotationRoute(mux, app)
	// Owner connector switches (router-minted owner token only).
	registerAppMCPConnectorControl(mux, app)
	// Blind-index backfill endpoint - same architectural reason as
	// rotation (per-app process holds the derived key + the
	// `blind_index:` config). Admin-only, audit-logged.
	RegisterBlindIndexRoutes(mux, app)
	if initialize {
		EnsureIdempotencyTable(app.DB)
	}
	if initialize {
		EnsureLocksTable(app.DB)
	}
	if initialize {
		EnsureNotificationsTable(app.DB)
	}
	if initialize {
		EnsureContextGraphTables(app.DB)
	}
	if initialize {
		EnsureRequestLogTable(app.DB)
	}

	// Bulk import - chunked, resumable, all-or-nothing data loading.
	// Registered on the per-app mux so it exists in `benmore serve` and
	// `benmore host` alike; the framework edition gets it without the
	// platform. RegisterImportRoutes calls EnsureImportsTable itself.
	if initialize {
		RegisterImportRoutes(mux, app)
	} else {
		registerImportRoutes(mux, app)
	}
	if initialize {
		RegisterAnalyticsRoutes(mux, app)
	} else {
		registerAnalyticsRoutes(mux, app)
	}
	// Runs once at load; MCP write_file also triggers a rebuild so LLM
	// edits flow into the graph immediately. Extraction is O(pages) and
	// transactional, so the cost is in the tens of ms for typical apps.
	if initialize {
		app.startWorker("contextGraph.rebuild", func(stop <-chan struct{}) {
			select {
			case <-stop:
				return
			default:
				RebuildContextGraph(app)
			}
		})
	}

	// Cluster mode: SQLite-based pub/sub for horizontal scaling
	if IsClusterMode() {
		if initialize {
			EnsureEventsTable(app.DB)
		}
		if initialize {
			EnsureRateLimitsTable(app.DB)
		}
		if initialize {
			StartEventPoller(app)
		}
	}

	// Storage backend (local disk or S3)
	if initialize {
		InitStorage(app.Dir)
	}

	// Framework APIs
	RegisterAuditAPI(mux, app)
	syncAudit := app.Design != nil && app.Design.Auth["read_audit_sync"] == "true"
	if initialize {
		InitReadAudit(app, syncAudit)
	}
	RegisterReadAuditAPI(mux, app)
	// API docs: public in dev, auth-required in production (opt-out via features.docs)
	if app.FeatureEnabled("docs") {
		RegisterAPIDocsRoutes(mux, app)
	}
	if initialize {
		RegisterDeviceRoutes(mux, app)
	} else {
		registerDeviceRoutes(mux, app)
	}
	if initialize {
		RegisterNotificationRoutes(mux, app)
	} else {
		registerNotificationRoutes(mux, app)
	}
	if initialize {
		RegisterCustomFieldRoutes(mux, app)
	} else {
		registerCustomFieldRoutes(mux, app)
	}
	// groups.bootstrap is declared in app.yaml)
	RegisterGroupBootstrapRoute(mux, app)

	// API routes
	if initialize {
		RegisterQueryAPI(mux, app) // POST /api/_query - declarative cross-cut reads (scoped, column-validated)
	} else {
		registerQueryAPI(mux, app) // POST /api/_query - declarative cross-cut reads (scoped, column-validated)
	}
	if initialize {
		RegisterSchedulingAPI(mux, app)
	} else {
		registerSchedulingAPI(mux, app)
	}
	if initialize {
		RegisterLockRoutes(mux, app)
	} else {
		registerLockTables(mux, app, tables)
	}
	if initialize {
		RegisterCRUD(mux, app)
	} else {
		registerCRUDTables(mux, app, tables)
	}
	RegisterFileUploadRoute(mux, app)
	if NeedsAuth(app) {
		if initialize {
			RegisterAuthRoutes(mux, app)
		} else {
			registerAuthRoutes(mux, app)
		}
		if initialize {
			RegisterMFARoutes(mux, app)
		} else {
			registerMFARoutes(mux, app)
		}
		RegisterMFALoginRoute(mux, app)
		if initialize {
			RegisterPasskeyRoutes(mux, app)
		} else {
			registerPasskeyRoutes(mux, app)
		}
		if initialize {
			RegisterOAuthTokensAPI(mux, app)
		} else {
			registerOAuthTokensAPI(mux, app)
		}
		RegisterRoleRoutes(mux, app)
		// Per-app OAuth 2.1 provider: lets external MCP clients (Claude,
		// ChatGPT, Cursor) authenticate an APP user. Reviewed connector apps
		// use distinct audience-bound credentials; legacy API tokens stay separate.
		if initialize {
			appOAuthEnsureTables(app)
		}
		registerAppOAuthProviderAt(mux, app, appMCPResourceAt(app, baseURL))
	}
	// Edge auth consent flow + grants UI live on the parent app's
	// origin. Only relevant when the app declares auth.edge_scopes
	// in app.yaml - without that, edges remain anonymous and these
	// endpoints just refuse all consent requests.
	RegisterEdgeAuthOnApp(mux, app)
	// Auto-create user columns referenced by page require="" attributes
	if initialize {
		EnsureRequiredUserFields(app.DB, app.Pages)
	}
	// Auto-create user columns listed in auth.signup_fields
	if app.Design != nil {
		if initialize {
			EnsureSignupFieldColumns(app.DB, app.Design.Auth["signup_fields"])
		}
	}
	if len(app.Flows) > 0 {
		mux.flows = RegisterFlows(mux, app, app.Flows)
	}
	if app.Workflows != nil && len(app.Workflows.Workflows) > 0 {
		if initialize {
			RegisterWorkflows(mux, app)
		} else {
			registerWorkflows(mux, app)
		}
	}
	// A `when:` that can't be evaluated, or a workflow key/state the
	// runtime ignores, is logged, never refused: the write gate and
	// `benmore check` report it as an error.
	if initialize {
		warnWhenConditions(app)
		warnWorkflowShape(app)
	}
	versionConfig := app.versionedConfig()
	if versionConfig != nil {
		RegisterVersioningAPI(mux, app, versionConfig)
	}
	if HasOAuthProviders(app.Dir) {
		if initialize {
			EnsureRoleColumn(app.DB)
		}
	}
	RegisterOAuthRoutes(mux, app)

	// CLI session-token mint - platform app ONLY. If a benmore.ai browser
	// session is already active, mint a CLI api_token straight from it so the
	// "Continue as <you>" button on /cli-auth finishes auth in one click - no
	// Google/password round-trip. Gated to _platform on purpose: only there is
	// the app session the real platform identity. An arbitrary app's
	// _benmore_users session is NOT a verified platform account, so exposing
	// this on any other app would let someone sign up as victim@example.com and
	// mint a platform CLI token for them (account takeover). The Google path is
	// safe by contrast because Google verifies the email. oauthMintCLIToken is
	// the same validate-port → mint → redirect helper the OAuth callback uses
	// (a no-op stub in the framework build, which then falls back to the form).
	if filepath.Base(app.Dir) == "_platform" {
		mux.HandleFunc("GET /auth/cli-session", cliSessionHandler(app))
		mux.HandleFunc("POST /auth/cli-session", cliSessionHandler(app)) // the confirmation page posts here to mint
		registerCLIDeviceRoutes(mux, app)
	}

	// Admin, billing, settings (admin panel opt-out via features.admin).
	// Auto-admin lives at /_admin (consistent with /_internal). Legacy
	// /admin path redirects to /_admin only when no user-defined page
	// claims /admin - keeps existing apps working while letting new
	// apps own the /admin URL for their own UI.
	if initialize {
		EnsureRoleColumn(app.DB)
	}
	if app.FeatureEnabled("admin") {
		RegisterAdminRoutes(mux, app)
		if _, userOwnsAdmin := app.Pages["/admin"]; !userOwnsAdmin {
			mux.HandleFunc("GET /admin", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/_admin", http.StatusTemporaryRedirect)
			})
		}
	}
	if initialize {
		RegisterSettingsRoutes(mux, app)
	} else {
		registerSettingsRoutes(mux, app)
	}
	//
	// When features.testing is enabled in app.yaml the feedback tables
	// are created so the visitor widget can write to them and so admin
	// tooling can read
	// from them. If a DEMO_PASSWORD is also set, the full demo-mode
	// gate and submission endpoints register on top via
	// RegisterDemoRoutes. If not, the tables are still present and
	// the MCP path works - the submission widget just won't accept
	// anonymous visitors without the gate.
	if app.FeedbackWidgetEnabled() {
		if initialize {
			EnsureFeedbackTables(app.DB)
		}
		demoPassword := appRouteEnv(app, "DEMO_PASSWORD")
		if app.FeatureEnabled("testing") && demoPassword != "" {
			// Demo mode (testing only): password gate + feedback routes that
			// accept demo tokens. Registers the /_demo/login route too.
			if initialize {
				RegisterDemoRoutes(mux, app, demoPassword)
			} else {
				registerDemoRoutes(mux, app, demoPassword)
			}
		} else {
			// Prod feedback (features.feedback) or testing without a demo
			// password: session/anon feedback API. Read is admin-gated on a
			// published app - see RegisterFeedbackAPI.
			RegisterFeedbackAPI(mux, app)
			if demoPassword != "" {
				// DEMO_PASSWORD arms the gate middleware regardless of mode;
				// the login endpoint must exist or every page 404s the gate.
				RegisterDemoLoginRoute(mux, app, demoPassword)
			}
		}
	} else if demoPassword := appRouteEnv(app, "DEMO_PASSWORD"); demoPassword != "" {
		// v2.7.164: the visitor-password gate no longer requires
		// features.testing. Previously set_demo_password returned
		// ok:true on an app without testing enabled and the app stayed
		// fully public - the gate middleware (wrapMiddleware) and this
		// login route were both behind the feature flag. The feedback
		// widget/API stays testing-only; only the gate stands alone.
		RegisterDemoLoginRoute(mux, app, demoPassword)
	}

	// Resource-level permissions (share/revoke API per table)
	if initialize {
		RegisterPermissionRoutes(mux, app)
	} else {
		registerPermissionTables(mux, app, tables)
	}

	// Webhook subscriptions
	if initialize {
		RegisterWebhookRoutes(mux, app)
	} else {
		registerWebhookRoutes(mux, app)
	}
	if initialize {
		StartJobWorker(app)
	}
	if initialize {
		CleanOldJobs(app)
	}
	RegisterJobsAPI(mux, app)

	// Scheduled backups
	if initialize {
		StartBackupWorker(app, app.Backup)
	}
	if initialize {
		StartLockCleanupWorker(app)
	}
	if initialize {
		StartWALShipper(app)
	}
	// Per-app WAL truncation - keeps data.db-wal from bloating to 4MB
	// under continuous read traffic. Issue #1.
	if initialize {
		StartAppWALMaintenance(app)
	}

	// Presence - framework primitive replacing the hand-rolled
	// pagehide+heartbeat+cleanup-cron pattern that every chat / live /
	// huddle app re-derives. See presence.go and bm.presence() in
	// the SDK.
	if initialize {
		EnsurePresenceTable(app.DB)
	}
	RegisterPresenceRoutes(mux, app)
	if initialize {
		StartPresenceSweeper(app)
	}

	// Usage metering
	if initialize {
		InitMetering(app)
	}
	RegisterUsageAPI(mux, app)

	// Data retention / TTL
	retentionPolicies := app.retentionConfig()
	if initialize {
		StartRetentionWorker(app, retentionPolicies)
	}

	// Materialized aggregates
	aggregateConfigs := app.aggregateConfig()
	if len(aggregateConfigs) > 0 {
		if initialize {
			StartAggregateWorker(app, aggregateConfigs)
		}
		RegisterAggregateRoutes(mux, app)
	}

	// Real-time (opt-out via features.sse)
	if app.FeatureEnabled("sse") {
		RegisterSSERoutes(mux, app)
	}
	// WebSocket (bidirectional real-time, opt-out via features.ws)
	if app.FeatureEnabled("ws") {
		RegisterWebSocketRoutes(mux, app)
	}
	// Export and import are CLI-only - not HTTP endpoints
	RegisterFetchRoutes(mux, app)

	// Embedded libraries + PWA + dev tools
	RegisterTailwindRoute(mux)
	RegisterLibRoutes(mux)
	RegisterBMTypesRoute(mux, app) // /_internal/types.d.ts - per-app TS defs
	RegisterI18nRoutes(mux, app)   // /api/_i18n/{lang} - per-app dictionaries
	RegisterUploadRoute(mux, app)  // POST /api/_upload - generic file upload (v2.7.20)
	RegisterWebRTCRoute(mux, app)  // GET /api/_webrtc/ice - STUN/TURN list (v2.7.28)
	if initialize {
		RegisterBroadcastRoutes(mux, app) // POST /api/_broadcast/{publish,subscribe,stop} (v2.7.29)
	} else {
		registerBroadcastRoutes(mux, app) // POST /api/_broadcast/{publish,subscribe,stop} (v2.7.29)
	}
	RegisterPWARoutes(mux, app)

	// Cron - scheduled jobs declared in cron.yaml. Background ticker
	// fires the matching schedule entries; integrates with the same
	// app.Stop channel as other workers so a graceful shutdown drains
	// in-flight jobs cleanly.
	if initialize {
		StartCronScheduler(app)
	}

	// Stripe billing - auto-creates _benmore_subscriptions +
	// _benmore_invoices and mounts /api/_billing/* when app.yaml
	// declares `billing_provider: stripe`. No-op otherwise.
	if initialize {
		RegisterBillingRoutes(mux, app)
	} else {
		registerBillingRoutes(mux, app)
	}
	// returns every row scoped to the current user.
	RegisterDSARRoute(mux, app)

	// Public status page rendered from request log + uptime stats.
	RegisterStatusRoute(mux, app)

	// Client-side error capture. Auto-mounts /api/_errors which
	// inserts into _benmore_client_errors and optionally forwards
	// to Sentry/Slack when configured.
	if initialize {
		RegisterErrorCaptureRoute(mux, app)
	} else {
		registerErrorCaptureRoute(mux, app)
	}
	// any /uploads/* image and returns a resized/re-encoded copy,
	// public derivatives cached outside uploads, after source authorization.
	RegisterImageTransformRoute(mux, app)
	RegisterInstallRoute(mux, app)
	RegisterInstallQRRoute(mux)
	RegisterRecordingRoutes(mux, app)

	// PDF generation (renders any page to PDF via headless Chrome)
	RegisterPDFRoutes(mux, app)

	// Health check
	mux.HandleFunc("GET /health", healthHandler(app))

	registerAppPageRoutes(mux, app, dev)

	// 404 handler - no catch-all. All routes registered explicitly above.
	// This handles truly unmatched paths for ALL methods (not just GET).
	notFound := notFoundHandler(app)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		notFound(w, r)
	})
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		notFound(w, r)
	})
	mux.HandleFunc("PATCH /", func(w http.ResponseWriter, r *http.Request) {
		notFound(w, r)
	})
	mux.HandleFunc("DELETE /", func(w http.ResponseWriter, r *http.Request) {
		notFound(w, r)
	})
	mux.HandleFunc("PUT /", func(w http.ResponseWriter, r *http.Request) {
		notFound(w, r)
	})

	// Static files + uploads + favicon
	// SECURITY: all file paths sanitized to prevent directory traversal
	mux.HandleFunc("GET /static/", func(w http.ResponseWriter, r *http.Request) {
		requested := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/static/"))
		serveStaticAsset(w, r, app, dev, requested)
	})
	mux.HandleFunc("GET /uploads/", func(w http.ResponseWriter, r *http.Request) {
		relativePath := filepath.Clean(strings.TrimPrefix(r.URL.Path, "/uploads/"))
		serveUploadAsset(w, r, app, dev, relativePath)
	})
	if initialize {
		RegisterSignedURLRoutes(mux, app)
	} else {
		registerSignedURLRoutes(mux, app)
	}
	mux.HandleFunc("GET /favicon.ico", func(w http.ResponseWriter, r *http.Request) {
		if appMCPManifestSnapshot(app) != nil {
			for _, name := range []string{"static/favicon.ico", "static/favicon.png", "favicon.ico", "favicon.png"} {
				data, err := app.readSourceFile(name)
				if err == nil {
					w.Header().Set("Cache-Control", "no-store")
					http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
					return
				}
			}
			w.Header().Set("Cache-Control", "no-store")
			http.NotFound(w, r)
			return
		}
		for _, name := range []string{"static/favicon.ico", "static/favicon.png", "favicon.ico", "favicon.png"} {
			path := filepath.Join(app.Dir, name)
			if _, err := os.Stat(path); err == nil {
				http.ServeFile(w, r, path)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	})

	// SEO feeds
	// Hand-authored overrides, as for llms.txt: an app's static/sitemap.xml
	// and static/robots.txt are served verbatim. The generated sitemap lists
	// only server-rendered pages, so a TSX/static app's was empty.
	mux.HandleFunc("GET /sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		if b, err := app.readSourceFile("static/sitemap.xml"); err == nil {
			w.Write(b)
			return
		}
		w.Write([]byte(GenerateSitemap(app, seoBaseURL(app, r, baseURL))))
	})
	mux.HandleFunc("GET /robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if b, err := app.readSourceFile("static/robots.txt"); err == nil {
			w.Write(b)
			return
		}
		w.Write([]byte(GenerateRobots(seoBaseURL(app, r, baseURL))))
	})
	llmsTxtHandler := func(w http.ResponseWriter, r *http.Request) {
		// Respect features.docs visibility for LLM discoverability endpoints
		if app.Design != nil && app.Design.Features != nil && app.Design.Features.DocsRequireAuth() {
			session := getSession(app, r)
			if session == nil {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
		}
		w.Header().Set("Content-Type", "text/plain")
		// Hand-authored override: a static/llms.txt in the app is served
		// verbatim; the auto-generated public-page list is the fallback.
		if b, err := app.readSourceFile("static/llms.txt"); err == nil {
			w.Write(b)
			return
		}
		w.Write([]byte(GenerateLLMsTxt(app, seoBaseURL(app, r, baseURL))))
	}
	mux.HandleFunc("GET /llms.txt", llmsTxtHandler)
	mux.HandleFunc("GET /.well-known/llms.txt", llmsTxtHandler)
	mux.HandleFunc("GET /llms-full.txt", func(w http.ResponseWriter, r *http.Request) {
		// llmstxt.org companion file - served at the root only when the app
		// ships one (static/llms-full.txt). Same visibility gate as /llms.txt.
		if app.Design != nil && app.Design.Features != nil && app.Design.Features.DocsRequireAuth() {
			session := getSession(app, r)
			if session == nil {
				http.Error(w, "authentication required", http.StatusUnauthorized)
				return
			}
		}
		b, err := app.readSourceFile("static/llms-full.txt")
		if err != nil {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Write(b)
	})
	mux.HandleFunc("GET /.well-known/security.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte(GenerateSecurityTxt(app, seoBaseURL(app, r, baseURL))))
	})
	mux.HandleFunc("GET /feed.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/atom+xml")
		w.Write([]byte(GenerateAtomFeed(app, seoBaseURL(app, r, baseURL))))
	})

	return mux
}

// serveStaticAsset serves a file from the app's static/ directory with
// symlink-escape containment (see static_file_security.go).
func serveStaticAsset(w http.ResponseWriter, r *http.Request, app *App, dev bool, requested string) {
	// v2.7.21+: TSX-by-default. When the agent writes static/index.tsx,
	// the HTML still references /static/index.js - we look for a .tsx
	// counterpart, transpile via embedded esbuild (Go API; no Node),
	// serve the JS. Cached in-memory by file mtime.
	if serveTSXIfPresent(w, r, app, requested) {
		return
	}
	// Desktop-metadata sidecars (`._app.js`, `.DS_Store`) are never app
	// content; refuse them even when a sync left them on disk.
	if pathHasMetadataSidecar(requested) {
		w.Header().Set("Cache-Control", "no-store")
		http.NotFound(w, r)
		return
	}
	if appMCPManifestSnapshot(app) != nil {
		name := filepath.Clean(requested)
		if filepath.IsAbs(name) || name == ".." || strings.HasPrefix(name, ".."+string(filepath.Separator)) {
			http.NotFound(w, r)
			return
		}
		data, err := app.readSourceFile(filepath.Join("static", name))
		if err != nil {
			w.Header().Set("Cache-Control", "no-store")
			http.NotFound(w, r)
			return
		}
		serveCapturedStaticAsset(w, r, name, data)
		return
	}
	fullPath := filepath.Join(app.Dir, "static", requested)
	// Verify path stays within static directory, resolving symlinks so a
	// link inside static/ can't point outside it (containment on the
	// EvalSymlinks-resolved real path - see static_file_security.go).
	// ServeMux normalizes `..` before routing, so the lexical part is
	// defense-in-depth, but symlink-escape is not caught by filepath.Clean.
	staticRoot := filepath.Join(app.Dir, "static")
	file, ok := openServableFile(staticRoot, fullPath)
	if !ok {
		// no-store so browsers/CDNs don't pin a deploy-race miss.
		w.Header().Set("Cache-Control", "no-store")
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	if !dev {
		w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	}
	file.serveHTTP(w, r)
}

// serveUploadAsset serves a file from the app's uploads/ directory, enforcing
// signed-URL access for private files (both URL-spelled and symlink-resolved)
// and symlink-escape containment.
func serveUploadAsset(w http.ResponseWriter, r *http.Request, app *App, dev bool, relativePath string) {
	// Legacy transform caches may contain derivatives of private sources.
	// New caches live outside uploads and are served only after source checks.
	if strings.HasPrefix(filepath.ToSlash(filepath.Clean(relativePath)), "_transforms/") {
		w.Header().Set("Cache-Control", "no-store")
		http.NotFound(w, r)
		return
	}
	// Connector artifacts are served only by GET /api/_mcp/artifacts/{id}.
	if appMCPArtifactStorageReference("uploads/" + filepath.ToSlash(relativePath)) {
		w.Header().Set("Cache-Control", "no-store")
		http.NotFound(w, r)
		return
	}
	fullPath := filepath.Join(app.Dir, "uploads", relativePath)
	uploadsRoot := filepath.Join(app.Dir, "uploads")
	// Private files require signed URLs. Gate with the SAME predicate the
	// signer uses so the serve side and sign side agree on what "private"
	// means. relativePath is the path under uploads/ (the signer's
	// isPrivateUploadPath keys off the full logical "uploads/..." path), so
	// re-prefix "uploads/" before the check. This catches BOTH a top-level
	// private/ file and a nested */private/* segment (e.g.
	// userdocs/private/ssn.pdf). Keep this BEFORE file resolution so
	// unsigned callers can't distinguish missing from existing private files.
	private := isPrivateUploadPath("uploads/" + filepath.ToSlash(relativePath))
	if private {
		if !ValidateSignedURL(relativePath, r) {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "Forbidden - invalid or expired signed URL", http.StatusForbidden)
			return
		}
	}
	// Resolve symlinks and confirm containment within uploads/ (filepath.Clean
	// alone does not catch a symlink inside uploads/ pointing elsewhere).
	file, ok := openServableFile(uploadsRoot, fullPath)
	if !ok {
		w.Header().Set("Cache-Control", "no-store")
		http.NotFound(w, r)
		return
	}
	defer file.Close()
	// Re-check the private gate against the symlink-RESOLVED target: a
	// non-private URL (e.g. uploads/public.png) that is a symlink into
	// private/ would pass the URL-based check above yet resolve to a private
	// file. Use the relative path captured while opening the file, rather
	// than resolving the root again after it could have been replaced.
	resolvedRelative := filepath.ToSlash(file.relative)
	if strings.HasPrefix(resolvedRelative, "_transforms/") || appMCPArtifactStorageReference("uploads/"+resolvedRelative) {
		w.Header().Set("Cache-Control", "no-store")
		http.NotFound(w, r)
		return
	}
	if isPrivateUploadPath("uploads/" + resolvedRelative) {
		private = true
		// Use the SAME predicate as the URL gate (matches any /private/
		// segment, not just a top-level one) so a symlink resolving into a
		// NESTED private dir (e.g. public.png -> x/private/secret) can't be
		// served unsigned.
		if !ValidateSignedURL(relativePath, r) {
			w.Header().Set("Cache-Control", "no-store")
			http.Error(w, "Forbidden - invalid or expired signed URL", http.StatusForbidden)
			return
		}
	}
	if private {
		w.Header().Set("Cache-Control", "private, no-store")
	} else if !dev {
		w.Header().Set("Cache-Control", "public, max-age=86400")
	}
	// Force download for active-content types so a user-uploaded
	// .html / .svg / .xml can't execute JS in the app's origin.
	applyUploadFileDispositionHeaders(w, file.path, file)
	file.serveHTTP(w, r)
}

// wrapMiddleware applies the standard middleware chain to a handler.
// Order (outermost first): logger → gzip → CORS → security headers → rate limit
func wrapMiddleware(handler http.Handler, app *App, dev bool) http.Handler {
	handler = passwordChangeMiddleware(handler, app)
	// Per-IP/session request budget per minute for the NON-static
	// surface (static assets + /_internal libs are exempt - see
	// RateLimitMiddleware). 300 gives a data-heavy dashboard plenty of
	// headroom (a page firing 15-20 parallel /api/<table> calls can
	// still navigate ~15 pages/min). Override per-app with
	// the RATE_LIMIT_PER_MIN env var - 0 or negative disables
	// the limiter entirely.
	rateLimit := 300
	if dev {
		rateLimit = 2000
	}
	if v := strings.TrimSpace(GetAppEnv(app.Dir, "RATE_LIMIT_PER_MIN")); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			rateLimit = n
		}
	}
	// rateLimit <= 0 disables HTTP rate limiting entirely (opt-out via
	// RATE_LIMIT_PER_MIN=0). Skip wrapping rather than creating a
	// zero-budget limiter that would 429 every request.
	if rateLimit > 0 {
		var limiter *RateLimiter
		if IsClusterMode() {
			limiter = NewSharedRateLimiter(app.DB, rateLimit, time.Minute, app.Stop)
		} else {
			limiter = NewRateLimiterStoppable(rateLimit, time.Minute, app.Stop)
		}
		handler = RateLimitMiddleware(limiter, handler)
	}
	handler = securityHeaders(handler, dev, app)
	// Global request-body size cap. Handlers json.Decode(r.Body) directly, so
	// without this an attacker can stream an unbounded body and exhaust memory
	// (memory-exhaustion DoS). Applied early in the chain. Multipart uploads
	// are exempt here because the upload path installs its OWN, larger
	// MaxBytesReader (see HandleFileUpload); double-capping would truncate
	// legitimate large uploads.
	handler = serverBodyLimitMiddleware(handler, app)
	handler = corsMiddleware(handler, app)
	if !dev {
		handler = gzipMiddleware(handler)
	}
	// Metrics middleware: counts requests + measures latency. Cheap
	// (atomic counters + a single time.Since per request). Mounted
	// inside compression so the timing doesn't include gzip work.
	handler = MetricsMiddleware(handler)
	handler = requestLogger(handler, dev)
	// _benmore_request_log persistence - powers the Runtime Logs tab
	// in the dashboard. Async insert per request; static assets skipped.
	handler = requestLogMiddleware(app, handler)
	// Per-request session cache (auth_session_cache.go): outside the request
	// log so the password-change gate, the handler and the log share one
	// session lookup.
	handler = requestSessionCacheMiddleware(handler)
	// Outermost: recover from panics in any inner middleware/handler so a
	// single bad request doesn't take down the whole process. Issue #2.
	handler = recoverMiddleware(handler)

	// Demo mode gate: password-protect the entire app. Decoupled from
	// features.testing in v2.7.164 - DEMO_PASSWORD alone arms the gate
	// (see buildAppMux's RegisterDemoLoginRoute branch for the matching
	// login endpoint).
	if demoPassword := GetAppEnv(app.Dir, "DEMO_PASSWORD"); demoPassword != "" {
		handler = DemoGateMiddleware(app, demoPassword, handler)
	}

	return handler
}

// serverDefaultMaxBodyBytes is the default global request-body cap for the
// non-upload surface (JSON APIs, form posts). 10MB is generous for any
// JSON/form payload while preventing an unbounded-body memory-exhaustion DoS.
// Override per-app with MAX_REQUEST_BODY_BYTES (<=0 disables the cap).
const serverDefaultMaxBodyBytes int64 = 10 << 20 // 10MB

// serverResolveMaxBodyBytes reads the configured global body cap for an app.
func serverResolveMaxBodyBytes(app *App) int64 {
	max := serverDefaultMaxBodyBytes
	if app != nil {
		if v := strings.TrimSpace(GetAppEnv(app.Dir, "MAX_REQUEST_BODY_BYTES")); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil {
				max = n
			}
		}
	}
	return max
}

// serverMaxMultipartBodyCeiling bounds MAX_UPLOAD_BODY_BYTES.
const serverMaxMultipartBodyCeiling int64 = 1 << 30 // 1GB

// serverResolveMaxMultipartBytes is the total cap for a multipart request
// body: by default one full-size file plus framing. Forms that post several
// files at once raise it with MAX_UPLOAD_BODY_BYTES (up to 1GB). Each file is
// still held to maxUploadSize.
func serverResolveMaxMultipartBytes(app *App) int64 {
	max := int64(maxUploadSize + uploadBodyOverhead)
	if app != nil {
		if v := strings.TrimSpace(GetAppEnv(app.Dir, "MAX_UPLOAD_BODY_BYTES")); v != "" {
			if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
				max = n
				if max > serverMaxMultipartBodyCeiling {
					max = serverMaxMultipartBodyCeiling
				}
			}
		}
	}
	return max
}

// serverBodyLimitMiddleware caps the request body size. Multipart bodies
// get their own total cap (serverResolveMaxMultipartBytes): net/http spills
// file parts to temporary disk as it parses, so any handler that reads a form
// field of an uncapped multipart body wrote it to disk in full. Other bodies
// get the global cap; a configured cap of <=0 disables that one.
func serverBodyLimitMiddleware(next http.Handler, app *App) http.Handler {
	maxBytes := serverResolveMaxBodyBytes(app)
	maxMultipart := serverResolveMaxMultipartBytes(app)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Bodyless methods carry nothing to cap; skip the wrap.
		if r.Body != nil && r.ContentLength != 0 {
			ct := r.Header.Get("Content-Type")
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(ct)), "multipart/") {
				r.Body = http.MaxBytesReader(w, r.Body, maxMultipart)
				next.ServeHTTP(w, r)
				return
			}
			// Uploads (multipart/form-data) are capped by HandleFileUpload's
			// own MaxBytesReader; don't double-cap and truncate them. Bulk
			// import chunk PUTs (import_http.go) are the same shape: their
			// OWN http.MaxBytesReader is sized to maxImportChunkBytes
			// (32MB) - double-capping with the global default (10MB,
			// serverDefaultMaxBodyBytes) truncated EVERY chunk at the
			// feature's own designed chunk size, making `benmore import`
			// fail on any file needing a full-size chunk. Found via a real
			// `benmore serve` smoke test - the existing import test suite
			// only ever exercises RegisterImportRoutes on a bare mux, which
			// never goes through this middleware, so no test had caught it.
			if maxBytes > 0 && !isImportChunkUploadPath(r) {
				r.Body = http.MaxBytesReader(w, r.Body, maxBytes)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// isImportChunkUploadPath reports whether r targets the bulk-import chunk
// PUT endpoint (PUT /api/_import/{id}/chunk/{n}). Matched by path shape
// rather than through the mux (this middleware runs before routing, so
// r.PathValue isn't populated yet) - precise enough to avoid matching the
// create/status/commit/cancel endpoints on the same /api/_import/ prefix,
// which are small JSON bodies that SHOULD stay under the global cap.
func isImportChunkUploadPath(r *http.Request) bool {
	return r.Method == http.MethodPut &&
		strings.HasPrefix(r.URL.Path, "/api/_import/") &&
		strings.Contains(r.URL.Path, "/chunk/")
}

// StartServer initializes and starts the HTTP server for an app.
func StartServer(app *App, port int, dev bool) error {
	app.DevMode = dev
	app.ServerPort = port
	startPprofListener() // opt-in, loopback + token only (debug_pprof.go)

	baseURL := ""
	if app.Design != nil {
		baseURL = app.Design.SEO["url"]
	}
	if baseURL == "" || app.MCPLocal {
		baseURL = fmt.Sprintf("http://localhost:%d", port)
	}

	mux := buildAppMux(app, dev, baseURL)
	handler := wrapMiddleware(mux, app, dev)
	if app.MCPLocal {
		// After the mux: route registration creates the framework tables
		// the switch audit and grants use.
		status, err := enableMCPLocal(app, app.MCPLocalWrites)
		if err != nil {
			return fmt.Errorf("--mcp-local: connector not enabled: %s", appMCPControlText(err))
		}
		log.Printf("  MCP local: %s/api/_mcp exposed=%v approved_writes=%v command_tools=%d", baseURL, status.Exposed, status.ApprovedWrites, status.CommandTools)
	}

	// Install the hot-swap handler. SIGHUP rebuilds the mux + middleware
	// in place and atomic-swaps. Zero downtime - the listening socket
	// is never closed during a content/env reload.
	hh := &hotHandler{}
	hh.current.Store(handler)
	hostedHotHandler = hh
	installHotReloadSignal(app, dev)

	// Hosted per-app processes sit behind the router, which proxies to
	// 127.0.0.1:<port> (see router.go proxyTo). Binding loopback-only
	// keeps the per-app HTTP port off all external interfaces - defense
	// in depth beyond ufw. The per-app service unit sets BENMORE_BIND_LOOPBACK=1.
	// Standalone `benmore serve` (single-app self-host, local dev) keeps
	// binding all interfaces so it's directly reachable, unless BENMORE_LISTEN
	// names an address (serveListenAddr).
	addr, err := serveListenAddr(port, app.MCPLocal)
	if err != nil {
		log.Fatalf("serve: %v", err)
	}
	server := &http.Server{
		Addr:    addr,
		Handler: hh,
		// ReadHeaderTimeout bounds how long a client may take to send request
		// headers, closing the Slowloris hole where a peer dribbles headers
		// to pin a connection open indefinitely (ReadTimeout alone doesn't
		// cover the header phase on keep-alive conns).
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       15 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		// Bound total header size (default is 1MB) so a flood of oversized
		// headers can't exhaust memory before the body limit even applies.
		MaxHeaderBytes: 1 << 20, // 1MB
	}

	if dev {
		log.Printf("  benmore server running at http://localhost:%d", port)
		log.Printf("  serving app from: %s", app.Dir)
		log.Printf("  press Ctrl+C to stop")
	} else {
		log.Printf("  benmore server (production) on :%d", port)
	}

	return startServerWithGracefulShutdown(server, dev)
}

// applySecurityHeaders sets CSP, X-Frame-Options, and other security headers.
// Called directly in host mode (per-app) or via the middleware wrapper (single-app mode).
func applySecurityHeaders(w http.ResponseWriter, dev bool, app *App) {
	// Origins the Benmore Go desktop app uses for its webview. Allowed
	// to frame every deployed app so the desktop's in-app preview pane
	// can render live URLs. Tauri's `tauri://localhost` (prod) and
	// `http://localhost:1420` (vite dev) are unreachable from the open
	// web - only a Tauri process on the same machine can serve content
	// from them - so this doesn't open clickjacking surface.
	desktopFrameAncestors := "tauri://localhost https://tauri.localhost http://localhost:1420"

	// Allow the platform apex (e.g. benmore.ai) to frame apps so the
	// workspace's live preview pane can iframe the app. The router knows the
	// domain via platformDomain; per-app processes learn it from
	// BENMORE_PLATFORM_DOMAIN (platform.env). Plus the desktop webview origins.
	// `frame-ancestors 'none'` can't be combined with explicit origins, so we
	// list the allowed origins instead - same protection against open-web
	// framing while permitting the workspace + desktop iframes.
	pd := platformDomain
	if pd == "" {
		pd = os.Getenv("BENMORE_PLATFORM_DOMAIN")
	}
	framePolicy := "frame-ancestors " + desktopFrameAncestors
	xframe := "" // X-Frame-Options can't allow specific origins; rely on CSP frame-ancestors.
	if pd != "" {
		framePolicy = fmt.Sprintf("frame-ancestors 'self' https://%s %s", pd, desktopFrameAncestors)
	}
	if dev {
		framePolicy = "frame-ancestors *"
		xframe = "SAMEORIGIN"
	}

	// 'unsafe-inline' stays for now - the framework injects inline
	// initializers (htmxInitScript, CSRF meta-reader, theme bootstrap)
	// without nonces, AND SSR (gotmpl) apps may include user-authored
	// inline scripts in their HTML. A clean nonce-based CSP requires:
	//   1. Per-request nonce threaded through every WrapLayout call
	//      site (~5 sites today) AND every inline-script emit site
	//      in layout.go / template.go / spa_runtime.go / edge_router.go.
	//   2. An app.yaml opt-in flag (security.csp_strict) so SSR apps
	//      with hand-coded inline scripts aren't broken on upgrade.
	//   3. SHA-256 hashes precomputed for the static framework inlines
	//      so the bootloader path doesn't need runtime nonce injection.
	// Scoped to a dedicated session - tracked in MEMORY.md punch list.
	//
	// 'unsafe-eval' was dropped earlier: React SPA mode compiles bundles
	// ahead of time via esbuild, so no app code needs runtime eval.
	d := pageCSPDirectives(app)
	scriptSrc, styleSrc, imgSrc, mediaSrc := d["script_src"], d["style_src"], d["img_src"], d["media_src"]
	fontSrc, connectSrc, frameSrc := d["font_src"], d["connect_src"], d["frame_src"]
	if app != nil && app.Design != nil {
		pick := func(directive string) string {
			if v := app.Design.CSP[directive]; v != "" {
				return v
			}
			return app.Design.SEO[directive]
		}
		// frame_ancestors WIDENS who may iframe this app. Unlike the
		// *-src directives it extends the framing allowlist rather than a
		// fetch allowlist, so it's the one embed-shaped knob: an app that
		// ships an embeddable page (e.g. /embed share views with a
		// made-with watermark) sets `csp.frame_ancestors: "*"` (or a list
		// of specific origins) and third-party sites + LLM-host iframes
		// can render it. Default stays locked down (self + platform +
		// desktop webview) - this is strictly opt-in per app.
		if v := pick("frame_ancestors"); v != "" {
			trimmed := strings.TrimSpace(v)
			if frameAncestorsHasNone(trimmed) {
				// CSP requires 'none' to be the only source expression. Fail
				// closed even for legacy configs that bypass write-time checks.
				framePolicy = "frame-ancestors 'none'"
				xframe = "DENY"
			} else if trimmed == "*" {
				framePolicy = "frame-ancestors *"
			} else {
				framePolicy += " " + v
				xframe = "" // CSP frame-ancestors is authoritative; XFO can't express origin lists
			}
		}
	}

	csp := strings.Join([]string{
		"default-src 'self'",
		"script-src " + scriptSrc,
		"style-src " + styleSrc,
		"img-src " + imgSrc,
		"media-src " + mediaSrc,
		"font-src " + fontSrc,
		"connect-src " + connectSrc,
		"frame-src " + frameSrc,
		// Zero-risk hardening: no app loads plugins/Flash/Java, so block all
		// <object>/<embed> content; and lock <base href> to same-origin so
		// injected markup can't rebase relative URLs onto an attacker origin.
		"object-src 'none'",
		"base-uri 'self'",
		// TODO(csp-strict): drop 'unsafe-inline' from script-src once nonces
		// are threaded through every inline-script emit site (see the
		// security.csp_strict punch list above). Tracked in MEMORY.md.
		framePolicy,
	}, "; ")
	w.Header().Set("Content-Security-Policy", csp)

	if xframe != "" {
		w.Header().Set("X-Frame-Options", xframe)
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	if !dev {
		w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
	}

	// Permissions-Policy: default restrictive, but allow apps to declare needed permissions
	// Apps set permissions_policy in seo: to override (e.g., "camera=*, microphone=*")
	permPolicy := "geolocation=(), payment=()"
	if app != nil && app.Design != nil {
		if v := app.Design.SEO["permissions_policy"]; v != "" {
			permPolicy = v
		}
	}
	w.Header().Set("Permissions-Policy", permPolicy)
}

// pageCSPDirectives returns the fetch-directive source lists for an app's
// pages: framework defaults plus the app's `csp:` (or legacy `seo:`)
// extensions. Keys are the csp: directive names (script_src, style_src,
// img_src, media_src, font_src, connect_src, frame_src). Page responses and
// the PDF render sandbox both derive their policy from it.
func pageCSPDirectives(app *App) map[string]string {
	scriptSrc := "'self' 'unsafe-inline'"
	styleSrc := "'self' 'unsafe-inline'"
	fontSrc := "'self'"
	// `'self'` is supposed to cover ws/wss to same-origin per CSP spec,
	// but several browsers (Firefox <93, Safari <14.1, some Chrome
	// edge cases) treat the scheme jump from https→wss as a CSP
	// violation and silently block the WebSocket. Add explicit
	// `wss:` (and `ws:` for local dev) so `/ws` works everywhere.
	connectSrc := "'self' wss: ws:"
	frameSrc := "'self'"
	// ESM/script CDNs agents are told they MAY import from (build.md names
	// esm.sh). Keep this list in sync with that doc - otherwise a documented
	// `import x from 'https://esm.sh/...'` gets silently CSP-blocked and the
	// whole module fails to load.
	for _, cdn := range []string{"https://unpkg.com", "https://cdn.jsdelivr.net", "https://esm.sh", "https://cdn.skypack.dev"} {
		scriptSrc += " " + cdn
		connectSrc += " " + cdn
	}
	// Cloudflare Web Analytics beacon allowance - opt-in. When serving behind
	// Cloudflare with Web Analytics enabled, the edge injects a beacon that
	// loads static.cloudflareinsights.com and calls home to
	// cloudflareinsights.com; allow both so those pages don't console-spam CSP
	// violations. Off by default (set BENMORE_CF_ANALYTICS=1 to enable) so a
	// self-hosted app never carries a Cloudflare origin in its CSP.
	if os.Getenv("BENMORE_CF_ANALYTICS") != "" {
		scriptSrc += " https://static.cloudflareinsights.com"
		connectSrc += " https://cloudflareinsights.com https://static.cloudflareinsights.com"
	}
	imgSrc := "'self' data:"
	styleSrc += " https://fonts.googleapis.com"
	fontSrc += " https://fonts.gstatic.com https://fonts.googleapis.com"
	// rsms.me hosts the Inter typeface's CSS + woff2 files and is the
	// reference distribution every agent reaches for first (the
	// official inter.style page recommends `<link rel="stylesheet"
	// href="https://rsms.me/inter/inter.css">` as the default install).
	// Several apps tried it, hit a console CSP
	// rejection, and burned a round swapping to Google Fonts. Allow it
	// here so the agent's first instinct works.
	styleSrc += " https://rsms.me"
	fontSrc += " https://rsms.me"

	// Media CDN (isolated user-content origin): allow app pages to
	// load uploaded images/video/audio from usercontent.<domain>. No-op
	// when the CDN backend isn't configured (local-disk media is same-origin).
	mediaSrc := "'self' data: blob:"
	if cfg := getPlatformMedia(); cfg != nil {
		imgSrc += " https://" + cfg.CDNDomain
		mediaSrc += " https://" + cfg.CDNDomain
	}

	// App-specific CSP overrides from seo: section in app.yaml
	// App-specific CSP allowlist extensions. Canonical form is the
	// top-level `csp:` block; values are appended to the framework
	// defaults (they widen the policy, never replace it). The legacy
	// `seo.<directive>_src` shape stays supported so older apps don't
	// regress.
	//
	//   csp:
	//     script_src: "https://maps.googleapis.com https://maps.gstatic.com"
	//     img_src:    "https://*.tile.openstreetmap.org"
	//     connect_src: "https://api.mapbox.com"
	//     frame_src:  "https://www.google.com"
	//     style_src:  "https://api.mapbox.com"
	//     font_src:   "https://fonts.gstatic.com"
	if app != nil && app.Design != nil {
		pick := func(directive string) string {
			if v := app.Design.CSP[directive]; v != "" {
				return v
			}
			return app.Design.SEO[directive]
		}
		if v := pick("frame_src"); v != "" {
			frameSrc += " " + v
		}
		if v := pick("connect_src"); v != "" {
			connectSrc += " " + v
		}
		if v := pick("script_src"); v != "" {
			scriptSrc += " " + v
		}
		if v := pick("style_src"); v != "" {
			styleSrc += " " + v
		}
		if v := pick("img_src"); v != "" {
			imgSrc += " " + v
		}
		if v := pick("font_src"); v != "" {
			fontSrc += " " + v
		}
	}
	return map[string]string{
		"script_src": scriptSrc, "style_src": styleSrc, "img_src": imgSrc, "media_src": mediaSrc,
		"font_src": fontSrc, "connect_src": connectSrc, "frame_src": frameSrc,
	}
}

// securityHeaders wraps applySecurityHeaders as middleware for single-app mode.
func securityHeaders(next http.Handler, dev bool, app *App) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		applySecurityHeaders(w, dev, app)
		if app != nil && !app.FeatureEnabled("analytics") {
			w = noTransformHTMLResponseWriter{ResponseWriter: w}
		}
		next.ServeHTTP(w, r)
	})
}

// frameAncestorsHasNone detects the CSP keyword even in an invalid mixed
// source list. Such a list is rejected by app.yaml validation and denies
// framing here as a fail-closed fallback for already-loaded legacy config.
func frameAncestorsHasNone(value string) bool {
	for _, source := range strings.Fields(value) {
		if strings.EqualFold(source, "'none'") {
			return true
		}
	}
	return false
}

// noTransformHTMLResponseWriter prevents an intermediary such as Cloudflare
// from injecting its own analytics script into HTML when app analytics are
// disabled. It only adds a Cache-Control directive; existing no-store and
// no-cache directives are preserved. Non-HTML responses are unchanged.
type noTransformHTMLResponseWriter struct{ http.ResponseWriter }

func (w noTransformHTMLResponseWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }

func (w noTransformHTMLResponseWriter) WriteHeader(status int) {
	w.ensureHTMLNoTransform()
	w.ResponseWriter.WriteHeader(status)
}

func (w noTransformHTMLResponseWriter) Write(body []byte) (int, error) {
	w.ensureHTMLNoTransform()
	return w.ResponseWriter.Write(body)
}

func (w noTransformHTMLResponseWriter) Flush() {
	_ = w.FlushError()
}

func (w noTransformHTMLResponseWriter) FlushError() error {
	w.ensureHTMLNoTransform()
	if f, ok := w.ResponseWriter.(interface{ FlushError() error }); ok {
		return f.FlushError()
	}
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
		return nil
	}
	return http.ErrNotSupported
}

func (w noTransformHTMLResponseWriter) ensureHTMLNoTransform() {
	if isHTMLResponse(w.Header()) {
		addCacheControlDirective(w.Header(), "no-transform")
	}
}

func (w noTransformHTMLResponseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if h, ok := w.ResponseWriter.(http.Hijacker); ok {
		return h.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

func (w noTransformHTMLResponseWriter) Push(target string, opts *http.PushOptions) error {
	if p, ok := w.ResponseWriter.(http.Pusher); ok {
		return p.Push(target, opts)
	}
	return http.ErrNotSupported
}

func isHTMLResponse(h http.Header) bool {
	return strings.HasPrefix(strings.ToLower(strings.TrimSpace(h.Get("Content-Type"))), "text/html")
}

func addCacheControlDirective(h http.Header, directive string) {
	values := h.Values("Cache-Control")
	for _, value := range values {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), directive) {
				return
			}
		}
	}
	values = append(values, directive)
	h.Set("Cache-Control", strings.Join(values, ", "))
}

// resolveAppRole looks up the user's role from the app's group membership table.
// Returns the role string (e.g., "org", "mgmt", "site") or empty if not found.
//
// The role is the one held in the session's EFFECTIVE tenant (act-as aware).
// A user can belong to several tenants with a different role in each; reading
// any membership row let an approver in one tenant pass role-gated workflow
// transitions and SSR role sections in another.
func resolveAppRole(app *App, session *Session) string {
	if app.Group == nil || session == nil {
		return ""
	}
	roleField := workflowMembershipRoleField(app)
	if roleField == "" {
		return ""
	}
	var lookupVal any
	if emailKeyedColumn(app.Group.UserField) {
		// Email-keyed membership counts only for a verified address.
		if lookupVal = sessionGrantEmail(session); lookupVal == "" {
			return ""
		}
	} else {
		lookupVal = session.UserID
	}
	args := []any{lookupVal}
	tenant := ""
	if app.Group.Key != "" {
		if !session.EffectiveHasGroup() {
			return ""
		}
		tenant = " AND " + quoteColumn(app.Group.Table, app.Group.Key) + " = ?"
		args = append(args, session.EffectiveGroupID())
	}
	var role string
	query := "SELECT " + quoteColumn(app.Group.Table, roleField) + " FROM " + quoteIdent(app.Group.Table) + " WHERE " + quoteColumn(app.Group.Table, app.Group.UserField) + " = ?" + tenant +
		membershipLiveConds(app.Group, app.Group.Table, "", appColumnChecker(app, app.Group.Table)) + " LIMIT 1"
	app.DB.QueryRow(query, args...).Scan(&role)
	return role
}

// sensitiveGETParams are query keys that should NEVER appear in a GET
// URL. Only USER-supplied form values belong here. These are the keys a
// careless <form method="GET"> (instead of POST) on a password page
// would leak into the URL bar, browser history, server access logs,
// referer headers, and CDN logs. The framework strips them server-side.
//
// We deliberately do NOT include `token` here. Server-generated email
// tokens (password-reset, email-verify, OAuth callback) legitimately
// arrive via `?token=…` on a GET - that's how email-link flows work
// across the industry. Stripping it broke the reset flow.
var sensitiveGETParams = []string{"password", "_csrf", "csrf", "current_password", "new_password"}

func servePage(w http.ResponseWriter, r *http.Request, app *App, page *Page, dev bool) {
	// Defense in depth: any GET request that carries a sensitive query
	// param (e.g. ?password=…) means a <form> on a previous page was
	// missing method="POST" and the browser just leaked the password
	// into the URL bar, browser history, server logs, referer headers,
	// and Cloudflare logs. Strip the params and 303-redirect back to
	// the clean URL so the leaked values don't linger in this
	// response's referer/access log line either.
	if r.Method == "GET" {
		q := r.URL.Query()
		hit := false
		for _, k := range sensitiveGETParams {
			if q.Has(k) {
				q.Del(k)
				hit = true
			}
		}
		if hit {
			log.Printf("AUTH WARNING [%s] %s: form submitted via GET - sensitive params stripped. Check that the form has method=\"POST\".", app.Dir, r.URL.Path)
			clean := r.URL.Path
			if encoded := q.Encode(); encoded != "" {
				clean += "?" + encoded
			}
			http.Redirect(w, r, clean, http.StatusSeeOther)
			return
		}
	}
	// In dev mode, re-read the file on each request for hot reload
	if dev {
		app.mu.Lock()
		if app.MCP == nil {
			data, err := os.ReadFile(filepath.Join(app.Dir, page.File))
			if err == nil {
				setPageAttrsFromSource(page, string(data))
			}
			app.Partials = reloadPartials(app.Dir)
		}
		app.mu.Unlock()
	}

	session := getSession(app, r)
	if session != nil {
		Increment(app, meterScope(session), "page_views")
	}

	// Role-based redirect: <page redirect="admin:/admin,user:/dashboard,*:/home">
	// The `*` wildcard applies to ANYONE, including logged-out visitors - so
	// `redirect="*:/"` is the way to take a page offline (e.g. disable /docs).
	// Role-specific entries (admin:…, user:…) still only match a session.
	if page.Redirect != "" {
		role := ""
		if session != nil {
			role = session.Role
		}
		if target := matchRoleRedirect(page.Redirect, role); target != "" {
			http.Redirect(w, r, target, http.StatusSeeOther)
			return
		}
	}

	ctx := &RenderContext{
		Data:    make(map[string]any),
		User:    session,
		Request: r,
		App:     app,
		Page:    page,
	}

	ctx.Data["current_user"] = session
	if session != nil {
		ctx.Data["logged_in"] = true

		// Load ALL user columns into structured "user" object.
		// Enables {{user.email}}, {{user.plan}}, {{user.first_name}}, etc.
		userMap := LoadUserFields(app.DB, session.UserID)
		if userMap == nil {
			userMap = make(map[string]any)
		}
		// Ensure session-derived fields are always present (even if DB query fails)
		userMap["id"] = session.UserID
		userMap["email"] = session.Email
		userMap["role"] = session.Role
		if session.HasGroup() {
			userMap["org_id"] = session.GroupID
		}
		// Resolve app-level role from group membership table (e.g., "org", "mgmt", "site")
		if app.Group != nil && app.Group.Table != "" {
			appRole := resolveAppRole(app, session)
			if appRole != "" {
				userMap["app_role"] = appRole
			}
		}
		ctx.Data["user"] = userMap

		// Legacy flat keys for backwards compatibility
		ctx.Data["user_email"] = session.Email
		ctx.Data["user_id"] = session.UserID
		ctx.Data["user_role"] = session.Role
		// Multi-role: comma-separated list for the SSR `{{#role}}` block
		// and for `{{user_roles}}` lookups inside `<page require>` checks.
		ctx.Data["user_roles"] = strings.Join(session.Roles, ",")
		if session.HasGroup() {
			ctx.Data["user_group_id"] = session.GroupID
		}
		if appRole, ok := userMap["app_role"].(string); ok && appRole != "" {
			ctx.Data["user_app_role"] = appRole
		}
	}
	ctx.Data["page_title"] = page.Title
	ctx.Data["current_path"] = r.URL.Path

	for k, v := range r.URL.Query() {
		if len(v) > 0 {
			ctx.Data["param_"+k] = v[0]
		}
	}

	// Inject materialized aggregate values for {{aggregate.*}} templates
	InjectAggregateData(ctx)

	// Inject unread notification count for {{notification_count}} in templates
	InjectNotificationCount(ctx)

	content, err := RenderTemplate(app, page, ctx)
	if err != nil {
		if dev {
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.WriteHeader(http.StatusInternalServerError)
			fmt.Fprintf(w, `<div class="benmore-error"><strong>Render Error</strong><pre>%s</pre></div>`, err.Error())
		} else {
			// Production: the full error goes to the journal and the
			// request log's `error` column (get_request_logs), the
			// caller gets a generic message with the request id. It
			// stays server-side (a response header reached the client
			// before the middleware could strip it).
			serverError(w, r, app, page.File, err, "Internal Server Error")
		}
		return
	}

	title := page.Title
	if title == "" {
		title = strings.Title(strings.TrimPrefix(page.Route, "/"))
	}

	// engine: raw - the user provided a full <!doctype html> document.
	// Skip the framework's HTML shell wrap AND the InjectCSRF walker -
	// the walker is a regex-based rewrite that finds every "<form" in
	// the response and stamps an <input> right after the opening tag.
	// In a raw page that includes inline <script type="text/babel">
	// blocks with JSX <form> elements, that means injecting an HTML
	// <input> into a JS string context, breaking the JSX parser.
	//
	// `engine: raw` was the legacy React-SPA shell - the framework no
	// longer ships a SPA runtime. Treat raw pages as opaque HTML:
	// inject CSRF + serve as-is. Anything React-specific in the
	// template (bm.mount, /_internal/bm.js, etc.) will load nothing,
	// which is the correct outcome for a stripped framework.
	if page.Engine == "raw" {
		html := injectCSRFMeta([]byte(content))
		html = injectCSRFFormFields(html, "")
		html = versionStaticAssets(html, app)
		html = versionBmInternal(html)
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store, must-revalidate")
		w.Write(html)
		return
	}

	// Inject CSRF tokens into all forms (non-raw pages only)
	content = InjectCSRF(content)

	html := WrapLayoutWithPage(content, title, app, session, page)
	html = string(versionStaticAssets([]byte(html), app))
	html = string(versionBmInternal([]byte(html)))

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	// Every page render is dynamic (session, queries, agg vars).
	// Tell the browser explicitly not to cache so an LLM-driven edit
	// loop never produces phantom "but I just changed it" bugs.
	w.Header().Set("Cache-Control", "no-store, must-revalidate")
	w.Write([]byte(html))
}

// matchRoleRedirect checks a redirect spec like "admin:/admin,user:/dashboard,*:/home"
// against the user's role. Returns the target path if matched, empty string otherwise.
// The * wildcard matches any role. First match wins.
func matchRoleRedirect(spec, role string) string {
	for _, entry := range strings.Split(spec, ",") {
		entry = strings.TrimSpace(entry)
		parts := strings.SplitN(entry, ":", 2)
		if len(parts) != 2 {
			continue
		}
		matchRole := strings.TrimSpace(parts[0])
		target := strings.TrimSpace(parts[1])
		if matchRole == role || matchRole == "*" {
			return target
		}
	}
	return ""
}

func reloadPartials(dir string) map[string]string {
	partials := make(map[string]string)
	partialDir := filepath.Join(dir, "partials")
	entries, err := os.ReadDir(partialDir)
	if err != nil {
		return partials
	}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".html") && !isMetadataSidecar(entry.Name()) {
			data, err := readFileInRoot(partialDir, entry.Name()) // include_root.go: no symlink escape
			if err == nil {
				partials["partials/"+entry.Name()] = string(data)
			}
		}
	}
	return partials
}

func requestLogger(next http.Handler, dev bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if dev {
			start := time.Now()
			rw := &responseWriter{ResponseWriter: w, status: 200}
			next.ServeHTTP(rw, r)
			log.Printf("  %s %s → %d (%s)", r.Method, r.URL.Path, rw.status, time.Since(start).Round(time.Millisecond))
		} else {
			next.ServeHTTP(w, r)
		}
	}
}

type responseWriter struct {
	http.ResponseWriter
	status int
}

func (rw *responseWriter) WriteHeader(code int) {
	rw.status = code
	rw.ResponseWriter.WriteHeader(code)
}

// Flush passes through to the underlying ResponseWriter if it supports Flusher.
// This is needed for SSE (Server-Sent Events) to work through the middleware chain.
func (rw *responseWriter) Flush() {
	if f, ok := rw.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap exposes the underlying ResponseWriter so http.NewResponseController
// can find the conn and call SetReadDeadline / SetWriteDeadline on it. SSE
// uses this to disable the server's 30s WriteTimeout for its long-lived
// stream - without Unwrap, Go's stdlib refuses to walk past this wrapper
// and the deadline call silently fails.
func (rw *responseWriter) Unwrap() http.ResponseWriter {
	return rw.ResponseWriter
}

// Hijack passes through to the underlying ResponseWriter if it supports
// Hijacker. Required for /ws - the WebSocket upgrade hijacks the raw
// TCP connection. Without this method on the middleware wrapper, the
// type assertion `w.(http.Hijacker)` inside wsUpgrade fails and the
// upgrade returns 400 "WebSocket upgrade required" even though the
// request was perfectly valid. Silent footgun: SSE worked because it
// uses Flusher (which we wired); WS broke because Hijacker wasn't.
func (rw *responseWriter) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	if hj, ok := rw.ResponseWriter.(http.Hijacker); ok {
		return hj.Hijack()
	}
	return nil, nil, http.ErrNotSupported
}

// Rendering consumes reviewed bytes when MCP is enabled. Runtime storage and
// environment paths remain anchored to the original app directory.
func (app *App) readSourceFile(name string) ([]byte, error) {
	app.mu.RLock()
	reviewed, sources := app.MCP != nil, app.sourceFiles
	app.mu.RUnlock()
	if !reviewed {
		return readFileFromDir(app.Dir, name)
	}
	if sources == nil {
		return nil, fmt.Errorf("missing captured app source")
	}
	data := sources[filepath.ToSlash(filepath.Clean(name))]
	if data == nil {
		return nil, os.ErrNotExist
	}
	return data, nil
}

func readFileFromDir(dir, name string) ([]byte, error) {
	return os.ReadFile(filepath.Join(dir, name))
}

// serveListenAddr is the address `serve` listens on. Hosted per-app units set
// BENMORE_BIND_LOOPBACK=1 (loopback, and the hosted-tenant guards that come
// with it). A self-hoster behind a local proxy sets BENMORE_LISTEN to an IP
// such as 127.0.0.1 to get the loopback listener without those guards. A
// value that isn't a bare IP is an error, never a silent bind-all. With
// --mcp-local the connector's resource is http://localhost, so the default is
// loopback only; an explicit BENMORE_LISTEN still wins.
func serveListenAddr(port int, mcpLocal bool) (string, error) {
	if os.Getenv("BENMORE_BIND_LOOPBACK") == "1" {
		return fmt.Sprintf("127.0.0.1:%d", port), nil
	}
	host := strings.TrimSpace(os.Getenv("BENMORE_LISTEN"))
	if host == "" && mcpLocal {
		return fmt.Sprintf("127.0.0.1:%d", port), nil
	}
	if host == "" {
		return fmt.Sprintf(":%d", port), nil
	}
	if net.ParseIP(host) == nil {
		return "", fmt.Errorf("BENMORE_LISTEN=%q is not an IP address (use e.g. 127.0.0.1; the port comes from --port)", host)
	}
	return net.JoinHostPort(host, strconv.Itoa(port)), nil
}

// registerAppPageRoutes shares actual page registration with candidate preflight.
// Returned patterns contain only successful registrations; handlers are not invoked.
func registerAppPageRoutes(mux appRouteRegistrar, app *App, dev bool) []string {
	// Page routes - all registered explicitly, including dynamic routes.
	// Dynamic routes use :param in filenames (e.g., contacts-:id.html → /contacts/:id).
	// Converted to Go 1.22 {param} syntax for proper mux registration.
	registered := make([]string, 0, len(app.Pages))
	for route, page := range app.Pages {
		p := page
		// LoadPages already merged the <page> tag with frontmatter; only
		// pages built elsewhere (single-file apps, fixtures) need the tag
		// read here. Overwriting unconditionally dropped a frontmatter
		// require: and left the page with no gate at all.
		if p.Require == "" {
			p.Require = ExtractPageRequire(p.RawHTML)
		}
		p.Auth = normalizePageAuth(p.Auth, p.File)

		// Convert :param to {param} for Go 1.22 mux
		muxPattern := route
		if strings.Contains(route, ":") {
			parts := strings.Split(route, "/")
			for i, part := range parts {
				if strings.HasPrefix(part, ":") {
					parts[i] = "{" + strings.TrimPrefix(part, ":") + "}"
				}
			}
			muxPattern = strings.Join(parts, "/")
		}

		handler := func(w http.ResponseWriter, r *http.Request) {
			// Convert Go 1.22 path values back to query params for template access
			if strings.Contains(route, ":") {
				q := r.URL.Query()
				parts := strings.Split(route, "/")
				for _, part := range parts {
					if strings.HasPrefix(part, ":") {
						paramName := strings.TrimPrefix(part, ":")
						q.Set(paramName, r.PathValue(paramName))
					}
				}
				r.URL.RawQuery = q.Encode()
			}
			servePage(w, r, app, p, dev)
		}
		if p.Require != "" {
			handler = RequireMiddleware(app, p, handler)
		}
		// role="public" means "anyone can view" - don't wrap with middleware.
		if role := pageRole(p); role != "" && role != "public" {
			handler = RoleMiddleware(app, p, handler)
		}
		pattern := fmt.Sprintf("GET %s", muxPattern)
		if route == "/" {
			pattern = "GET /{$}"
		}
		// Recover-wrap the registration so a user page that collides
		// with a framework-reserved route (e.g. /api/_*, internal helpers)
		// doesn't crash the whole hosted process. Framework routes registered
		// earlier in buildAppMux always win on collision; the user page is
		// skipped with a clear log line for the dashboard to surface.
		// Issue #6: framework panics on route collision - this is the fix.
		func() {
			defer func() {
				if rec := recover(); rec != nil {
					log.Printf("  [%s] route conflict: page %q collides with framework route - skipped (%v)", filepath.Base(app.Dir), route, rec)
				}
			}()
			if p.Auth == "required" || p.Require != "" {
				mux.HandleFunc(pattern, AuthMiddleware(app, p, handler))
			} else {
				mux.HandleFunc(pattern, handler)
			}
			registered = append(registered, pattern)
		}()
	}

	return registered
}
